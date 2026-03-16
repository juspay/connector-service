{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CApiFFI #-}

-- | Low-level RustBuffer and RustCallStatus types matching the UniFFI C ABI.
--
-- UniFFI uses RustBuffer { capacity: u64, len: u64, data: *u8 } for all
-- compound types. This module mirrors that layout for Haskell's FFI.
module Payments.Internal.RustBuffer
  ( RustBuffer(..)
  , RustCallStatus(..)
  , peekRustBuffer
  , pokeRustBuffer
  , peekRustCallStatus
  , pokeRustCallStatus
  , rustBufferSize
  , rustCallStatusSize
  , withRustBuffer
  , rustBufferToByteString
  , byteStringToRustBuffer
  , liftBytes
  , lowerBytes
  , checkCallStatus
  , FfiAlloc
  , FfiFree
  ) where

import Data.Word (Word8, Word64)
import Data.Int (Int8, Int32)
import Data.Bits (shiftR, shiftL, (.&.), (.|.))
import Foreign.Ptr (Ptr, nullPtr, castPtr, plusPtr)
import Foreign.Storable (peek, poke, pokeByteOff, peekByteOff)
import Foreign.Marshal.Alloc (alloca, mallocBytes)
import Foreign.Marshal.Array (copyArray, peekArray)
import Foreign.Marshal.Utils (copyBytes)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU

-- | Mirrors UniFFI's RustBuffer struct: { capacity: u64, len: u64, data: *u8 }
data RustBuffer = RustBuffer
  { rbCapacity :: !Word64
  , rbLen      :: !Word64
  , rbData     :: !(Ptr Word8)
  }

-- | Mirrors UniFFI's RustCallStatus: { code: i8, error_buf: RustBuffer }
data RustCallStatus = RustCallStatus
  { rcsCode     :: !Int8
  , rcsErrorBuf :: !RustBuffer
  }

-- | Size of RustBuffer struct in bytes (u64 + u64 + ptr).
-- On 64-bit: 8 + 8 + 8 = 24 bytes.
rustBufferSize :: Int
rustBufferSize = 24

-- | Size of RustCallStatus struct in bytes (i8 + padding + RustBuffer).
-- Layout: i8 code (1 byte) + 7 bytes padding + RustBuffer (24 bytes) = 32 bytes.
rustCallStatusSize :: Int
rustCallStatusSize = 32

peekRustBuffer :: Ptr RustBuffer -> IO RustBuffer
peekRustBuffer p = do
  cap  <- peekByteOff p 0  :: IO Word64
  len  <- peekByteOff p 8  :: IO Word64
  dat  <- peekByteOff p 16 :: IO (Ptr Word8)
  pure $ RustBuffer cap len dat

pokeRustBuffer :: Ptr RustBuffer -> RustBuffer -> IO ()
pokeRustBuffer p (RustBuffer cap len dat) = do
  pokeByteOff p 0  cap
  pokeByteOff p 8  len
  pokeByteOff p 16 dat

peekRustCallStatus :: Ptr RustCallStatus -> IO RustCallStatus
peekRustCallStatus p = do
  code <- peekByteOff p 0 :: IO Int8
  buf  <- peekRustBuffer (castPtr (p `plusPtr` 8))
  pure $ RustCallStatus code buf

pokeRustCallStatus :: Ptr RustCallStatus -> RustCallStatus -> IO ()
pokeRustCallStatus p (RustCallStatus code buf) = do
  pokeByteOff p 0 code
  pokeRustBuffer (castPtr (p `plusPtr` 8)) buf

-- | Create a zeroed RustCallStatus on the stack and pass it to an action.
withRustBuffer :: (Ptr RustCallStatus -> IO a) -> IO a
withRustBuffer action = do
  p <- mallocBytes rustCallStatusSize
  pokeRustCallStatus p (RustCallStatus 0 (RustBuffer 0 0 nullPtr))
  result <- action p
  pure result

-- | Extract the raw bytes from a RustBuffer into a ByteString.
rustBufferToByteString :: RustBuffer -> IO BS.ByteString
rustBufferToByteString (RustBuffer _ len dat)
  | len == 0 || dat == nullPtr = pure BS.empty
  | otherwise = BS.packCStringLen (castPtr dat, fromIntegral len)

-- | Copy a ByteString into a freshly allocated RustBuffer.
-- The caller must pass the FFI alloc function from the loaded library.
type FfiAlloc = Word64 -> Ptr RustCallStatus -> IO RustBuffer
type FfiFree = Ptr RustBuffer -> Ptr RustCallStatus -> IO ()

byteStringToRustBuffer :: FfiAlloc -> BS.ByteString -> IO RustBuffer
byteStringToRustBuffer allocFn bs = do
  let len = BS.length bs
  status <- mallocBytes rustCallStatusSize
  pokeRustCallStatus status (RustCallStatus 0 (RustBuffer 0 0 nullPtr))
  buf <- allocFn (fromIntegral len) status
  BSU.unsafeUseAsCStringLen bs $ \(src, _) ->
    copyBytes (castPtr (rbData buf)) src len
  let buf' = buf { rbLen = fromIntegral len }
  pure buf'

-- | UniFFI Vec<u8> return values are prefixed with a 4-byte big-endian length.
-- Strips the prefix and returns the payload.
liftBytes :: RustBuffer -> IO BS.ByteString
liftBytes (RustBuffer _ len dat)
  | len == 0 || dat == nullPtr = pure BS.empty
  | otherwise = do
      raw <- BS.packCStringLen (castPtr dat, fromIntegral len)
      let payloadLen = fromIntegral (beWord32 raw)
      pure $ BS.take payloadLen (BS.drop 4 raw)

-- | UniFFI Vec<u8> arguments need a 4-byte big-endian length prefix.
lowerBytes :: FfiAlloc -> BS.ByteString -> IO RustBuffer
lowerBytes allocFn bs = do
  let len = BS.length bs
      prefix = encodeBeWord32 (fromIntegral len)
      prefixed = BS.append prefix bs
  byteStringToRustBuffer allocFn prefixed

-- | Read a big-endian Word32 from the first 4 bytes.
beWord32 :: BS.ByteString -> Int32
beWord32 bs =
  let b0 = fromIntegral (BS.index bs 0) :: Int32
      b1 = fromIntegral (BS.index bs 1) :: Int32
      b2 = fromIntegral (BS.index bs 2) :: Int32
      b3 = fromIntegral (BS.index bs 3) :: Int32
  in (b0 `shiftL` 24) .|. (b1 `shiftL` 16) .|. (b2 `shiftL` 8) .|. b3

-- | Encode a Word32 as 4 big-endian bytes.
encodeBeWord32 :: Int32 -> BS.ByteString
encodeBeWord32 n = BS.pack
  [ fromIntegral ((n `shiftR` 24) .&. 0xff)
  , fromIntegral ((n `shiftR` 16) .&. 0xff)
  , fromIntegral ((n `shiftR` 8)  .&. 0xff)
  , fromIntegral (n .&. 0xff)
  ]

-- | Check the RustCallStatus after an FFI call.
-- Throws an error on Rust panics (code /= 0).
checkCallStatus :: RustCallStatus -> IO ()
checkCallStatus (RustCallStatus 0 _) = pure ()
checkCallStatus (RustCallStatus code errBuf) = do
  msg <- if rbLen errBuf > 0
         then rustBufferToByteString errBuf
         else pure "Unknown Rust panic"
  error $ "Rust FFI error (code " ++ show code ++ "): " ++ show msg
