{-# LANGUAGE ForeignFunctionInterface #-}

-- | Low-level FFI client for the Connector Service.
--
-- Loads the UniFFI-scaffolded Rust shared library at runtime via
-- Haskell's FFI and 'System.Posix.DynamicLinker' (dlopen/dlsym).
-- Mirrors the JavaScript SDK's UniffiClient — no UniFFI code generation
-- required since we call the C ABI directly.
--
-- Flow dispatch is generic: 'callReq', 'callRes', and 'callDirect' take
-- a flow name and look up the corresponding C symbol dynamically.
module Payments.FfiClient
  ( FfiClient(..)
  , newFfiClient
  , callReq
  , callRes
  , callDirect
  , freeRustBuffer
  ) where

import qualified Data.ByteString as BS
import Data.Word (Word8, Word64)
import Foreign.Ptr (Ptr, FunPtr, castPtrToFunPtr, nullPtr, castPtr)
import Foreign.Marshal.Alloc (mallocBytes)
import System.Info (os)
import System.FilePath ((</>))
import System.Directory (doesFileExist)

import Payments.Internal.RustBuffer

-- | Dynamic function pointers for FFI calls.
-- We use Haskell's FFI dynamic import to call function pointers obtained via dlsym.

-- Alloc: (u64, *RustCallStatus) -> RustBuffer
foreign import ccall "dynamic"
  mkAlloc :: FunPtr (Word64 -> Ptr RustCallStatus -> IO RustBuffer)
          -> (Word64 -> Ptr RustCallStatus -> IO RustBuffer)

-- Free: (*RustBuffer, *RustCallStatus) -> void
foreign import ccall "dynamic"
  mkFree :: FunPtr (Ptr RustBuffer -> Ptr RustCallStatus -> IO ())
         -> (Ptr RustBuffer -> Ptr RustCallStatus -> IO ())

-- Req transformer: (RustBuffer, RustBuffer, *RustCallStatus) -> RustBuffer
foreign import ccall "dynamic"
  mkReqTransformer :: FunPtr (Ptr RustBuffer -> Ptr RustBuffer -> Ptr RustCallStatus -> IO (Ptr RustBuffer))
                   -> (Ptr RustBuffer -> Ptr RustBuffer -> Ptr RustCallStatus -> IO (Ptr RustBuffer))

-- Res transformer: (RustBuffer, RustBuffer, RustBuffer, *RustCallStatus) -> RustBuffer
foreign import ccall "dynamic"
  mkResTransformer :: FunPtr (Ptr RustBuffer -> Ptr RustBuffer -> Ptr RustBuffer -> Ptr RustCallStatus -> IO (Ptr RustBuffer))
                   -> (Ptr RustBuffer -> Ptr RustBuffer -> Ptr RustBuffer -> Ptr RustCallStatus -> IO (Ptr RustBuffer))

-- Single transformer: (RustBuffer, RustBuffer, *RustCallStatus) -> RustBuffer
foreign import ccall "dynamic"
  mkSingleTransformer :: FunPtr (Ptr RustBuffer -> Ptr RustBuffer -> Ptr RustCallStatus -> IO (Ptr RustBuffer))
                      -> (Ptr RustBuffer -> Ptr RustBuffer -> Ptr RustCallStatus -> IO (Ptr RustBuffer))

-- dlopen / dlsym via Haskell FFI
foreign import ccall "dlopen"  c_dlopen  :: Ptr Word8 -> Int -> IO (Ptr ())
foreign import ccall "dlsym"   c_dlsym   :: Ptr () -> Ptr Word8 -> IO (FunPtr a)
foreign import ccall "dlerror" c_dlerror  :: IO (Ptr Word8)

-- | Opaque handle to the loaded FFI library.
data FfiClient = FfiClient
  { ffiHandle    :: !(Ptr ())
  , ffiAllocFn   :: !FfiAlloc
  , ffiFreeFn    :: !(Ptr RustBuffer -> Ptr RustCallStatus -> IO ())
  }

-- | RTLD_NOW = 2 (resolve all symbols at load time)
rtldNow :: Int
rtldNow = 2

-- | Load the native library and resolve the alloc/free symbols.
newFfiClient :: Maybe FilePath -> IO FfiClient
newFfiClient mbPath = do
  libPath <- case mbPath of
    Just p  -> pure p
    Nothing -> defaultLibPath

  -- dlopen
  handle <- BS.useAsCString (toBS libPath) $ \cstr ->
    c_dlopen (castPtr cstr) rtldNow

  if handle == nullPtr
    then do
      errPtr <- c_dlerror
      errMsg <- if errPtr == nullPtr
                then pure "unknown dlopen error"
                else peekCString errPtr
      error $ "Failed to load FFI library " ++ libPath ++ ": " ++ errMsg
    else pure ()

  -- Resolve alloc and free
  allocPtr <- dlsym handle "ffi_connector_service_ffi_rustbuffer_alloc"
  freePtr  <- dlsym handle "ffi_connector_service_ffi_rustbuffer_free"

  let allocFn = mkAlloc (castPtrToFunPtr allocPtr)
      freeFn  = mkFree (castPtrToFunPtr freePtr)

  -- Wrap allocFn to match FfiAlloc signature (returns RustBuffer not Ptr RustBuffer)
  let wrappedAlloc :: Word64 -> Ptr RustCallStatus -> IO RustBuffer
      wrappedAlloc = allocFn

  pure $ FfiClient handle wrappedAlloc freeFn

-- | Default path to the shared library (platform-dependent).
defaultLibPath :: IO FilePath
defaultLibPath = do
  let ext = case os of
              "darwin" -> "dylib"
              _        -> "so"
  -- Look in src/Payments/Generated/ relative to working directory
  let path = "src" </> "Payments" </> "Generated" </> ("libconnector_service_ffi." ++ ext)
  exists <- doesFileExist path
  if exists
    then pure path
    else pure $ "generated" </> ("libconnector_service_ffi." ++ ext)

-- | Look up a symbol in the loaded library.
dlsym :: Ptr () -> String -> IO (FunPtr a)
dlsym handle name = do
  ptr <- BS.useAsCString (toBS name) $ \cstr ->
    c_dlsym handle (castPtr cstr)
  if ptr == castPtrToFunPtr nullPtr
    then error $ "Symbol not found: " ++ name
    else pure ptr

-- | Helper to convert String to ByteString.
toBS :: String -> BS.ByteString
toBS = BS.pack . map (fromIntegral . fromEnum)

peekCString :: Ptr Word8 -> IO String
peekCString ptr = do
  bs <- BS.packCString (castPtr ptr)
  pure $ map (toEnum . fromIntegral) (BS.unpack bs)

-- | Free a RustBuffer returned by the FFI.
freeRustBuffer :: FfiClient -> RustBuffer -> IO ()
freeRustBuffer client buf
  | rbLen buf == 0 || rbData buf == nullPtr = pure ()
  | otherwise = do
      statusPtr <- mallocBytes rustCallStatusSize
      pokeRustCallStatus statusPtr (RustCallStatus 0 (RustBuffer 0 0 nullPtr))
      bufPtr <- mallocBytes rustBufferSize
      pokeRustBuffer bufPtr buf
      ffiFreeFn client bufPtr statusPtr

-- | Build the connector HTTP request for a flow.
-- Returns protobuf-encoded FfiConnectorHttpRequest bytes.
callReq :: FfiClient -> String -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
callReq client flow requestBytes optionsBytes = do
  let symName = "uniffi_connector_service_ffi_fn_func_" ++ flow ++ "_req_transformer"
  fnPtr <- dlsym (ffiHandle client) symName
  let fn = mkReqTransformer (castPtrToFunPtr fnPtr)

  rbReq  <- lowerBytes (ffiAllocFn client) requestBytes
  rbOpts <- lowerBytes (ffiAllocFn client) optionsBytes

  reqPtr  <- mallocBytes rustBufferSize
  optsPtr <- mallocBytes rustBufferSize
  pokeRustBuffer reqPtr rbReq
  pokeRustBuffer optsPtr rbOpts

  statusPtr <- mallocBytes rustCallStatusSize
  pokeRustCallStatus statusPtr (RustCallStatus 0 (RustBuffer 0 0 nullPtr))

  resultPtr <- fn reqPtr optsPtr statusPtr
  status <- peekRustCallStatus statusPtr
  checkCallStatus status

  result <- peekRustBuffer resultPtr
  bytes <- liftBytes result
  freeRustBuffer client result
  pure bytes

-- | Parse the connector HTTP response for a flow.
-- Returns protobuf-encoded response bytes.
callRes :: FfiClient
        -> String
        -> BS.ByteString  -- ^ response bytes
        -> BS.ByteString  -- ^ original request bytes
        -> BS.ByteString  -- ^ options bytes
        -> IO BS.ByteString
callRes client flow responseBytes requestBytes optionsBytes = do
  let symName = "uniffi_connector_service_ffi_fn_func_" ++ flow ++ "_res_transformer"
  fnPtr <- dlsym (ffiHandle client) symName
  let fn = mkResTransformer (castPtrToFunPtr fnPtr)

  rbRes  <- lowerBytes (ffiAllocFn client) responseBytes
  rbReq  <- lowerBytes (ffiAllocFn client) requestBytes
  rbOpts <- lowerBytes (ffiAllocFn client) optionsBytes

  resPtr  <- mallocBytes rustBufferSize
  reqPtr  <- mallocBytes rustBufferSize
  optsPtr <- mallocBytes rustBufferSize
  pokeRustBuffer resPtr rbRes
  pokeRustBuffer reqPtr rbReq
  pokeRustBuffer optsPtr rbOpts

  statusPtr <- mallocBytes rustCallStatusSize
  pokeRustCallStatus statusPtr (RustCallStatus 0 (RustBuffer 0 0 nullPtr))

  resultPtr <- fn resPtr reqPtr optsPtr statusPtr
  status <- peekRustCallStatus statusPtr
  checkCallStatus status

  result <- peekRustBuffer resultPtr
  bytes <- liftBytes result
  freeRustBuffer client result
  pure bytes

-- | Execute a single-step transformer directly (no HTTP round-trip).
-- Used for inbound flows like webhook processing.
callDirect :: FfiClient -> String -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
callDirect client flow requestBytes optionsBytes = do
  let symName = "uniffi_connector_service_ffi_fn_func_" ++ flow ++ "_transformer"
  fnPtr <- dlsym (ffiHandle client) symName
  let fn = mkSingleTransformer (castPtrToFunPtr fnPtr)

  rbReq  <- lowerBytes (ffiAllocFn client) requestBytes
  rbOpts <- lowerBytes (ffiAllocFn client) optionsBytes

  reqPtr  <- mallocBytes rustBufferSize
  optsPtr <- mallocBytes rustBufferSize
  pokeRustBuffer reqPtr rbReq
  pokeRustBuffer optsPtr rbOpts

  statusPtr <- mallocBytes rustCallStatusSize
  pokeRustCallStatus statusPtr (RustCallStatus 0 (RustBuffer 0 0 nullPtr))

  resultPtr <- fn reqPtr optsPtr statusPtr
  status <- peekRustCallStatus statusPtr
  checkCallStatus status

  result <- peekRustBuffer resultPtr
  bytes <- liftBytes result
  freeRustBuffer client result
  pure bytes
