{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedLabels #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Use newtype instead of data" #-}

module Client (main) where

import Control.Monad.Catch
import Control.Monad.Reader
import qualified Data.Text as T

import Network.GRPC.Client
import Network.GRPC.Client.StreamType.CanCallRPC
import Network.GRPC.Common
import Network.GRPC.Common.Protobuf
import Network.Socket (PortNumber)
import System.Environment (getArgs, getEnv)

import Proto.Payment

newtype Client a = WrapClient
  { unwrapClient :: ReaderT ClientEnv IO a
  }
  deriving newtype
    ( Functor
    , Applicative
    , Monad
    , MonadIO
    , MonadCatch
    , MonadThrow
    , MonadMask
    )

data ClientEnv = ClientEnv
  { conn :: Connection
  }

runClient :: Connection -> Client a -> IO a
runClient conn = flip runReaderT ClientEnv{conn} . unwrapClient

instance CanCallRPC Client where
  getConnection = WrapClient $ asks conn

type Ran = Protobuf PaymentService "paymentAuthorize"

type instance RequestMetadata Ran = NoMetadata
type instance ResponseInitialMetadata Ran = NoMetadata
type instance ResponseTrailingMetadata Ran = NoMetadata

paymentAuthorize :: Client (Output Ran)
paymentAuthorize = do
  let cardData =
        defMessage
          & #cardNumber
          .~ "5123456789012346"
          & #cardExpMonth
          .~ "03"
          & #cardExpYear
          .~ "2030"
          & #cardCvc
          .~ "100"

  let paymentMethodData =
        defMessage
          & #card
          .~ cardData
  apiKey <- liftIO $ getEnv "API_KEY"
  key1 <- liftIO $ getEnv "KEY1"
  let bodyKey =
        defMessage
          & #apiKey
          .~ T.pack apiKey
          & #key1
          .~ T.pack key1

  let authType = defMessage & #bodyKey .~ bodyKey
  let emptyAddress = defMessage
  let req =
        defMessage
          & #amount
          .~ 1000
          & #minorAmount
          .~ 1000
          & #currency
          .~ Proto USD
          & #connector
          .~ Proto RAZORPAY
          & #authCreds
          .~ authType
          & #paymentMethod
          .~ Proto CARD
          & #paymentMethodData
          .~ Proto paymentMethodData
          & #connectorRequestReferenceId
          .~ "ref_12345"
          & #enrolledFor3ds
          .~ True
          & #requestIncrementalAuthorization
          .~ False
          & #authType
          .~ Proto THREE_DS
          & #address
          .~ emptyAddress

  resp <- nonStreaming (rpc @Ran @NonStreaming) req
  -- let resourceId = resp ^. #resourceId ^. #connectorTransactionId
  -- liftIO $ putStrLn $ "Transaction ID: " <> unpack resourceId
  liftIO $ print resp
  pure resp

type Ran1 = Protobuf PaymentService "paymentSync"
type instance RequestMetadata Ran1 = NoMetadata
type instance ResponseInitialMetadata Ran1 = NoMetadata
type instance ResponseTrailingMetadata Ran1 = NoMetadata

paymentSync :: Client (Output Ran1)
paymentSync = do
  apiKey <- liftIO $ getEnv "API_KEY"
  key1 <- liftIO $ getEnv "KEY1"
  resourceId <- liftIO $ getEnv "RESOURCE_ID"
  let bodyKey =
        defMessage
          & #apiKey
          .~ T.pack apiKey
          & #key1
          .~ T.pack key1
  let authType = defMessage & #bodyKey .~ bodyKey
  let req =
        defMessage
          & #connector
          .~ Proto RAZORPAY
          & #authCreds
          .~ authType
          & #resourceId
          .~ T.pack resourceId
          & #connectorRequestReferenceId
          .~ "conn_req_abc"

  nonStreaming (rpc @Ran1 @NonStreaming) req

client :: String -> Client ()
client serviceToCall = do
  case serviceToCall of
    "authorize" -> do
      liftIO $ putStrLn "-------------- Payment Authorize --------------"
      _ <- paymentAuthorize
      liftIO $ putStrLn "--------- Payment Authorize Completed ---------"
    "sync" -> do
      liftIO $ putStrLn "-------------- Payment Sync --------------"
      result <- paymentSync
      liftIO $ print result
      liftIO $ putStrLn "--------- Payment Sync Completed ---------"
    _ -> liftIO $ putStrLn "Unknown service type in SERVICE_TO_CALL"

main :: IO ()
main = do
  args <- getArgs
  let address = if not (null args) then head args else "http://localhost:8000"
  let serviceToCall = if not (null args) then args !! 1 else "authorize"
  let server = parseUrlToServer address
  withConnection def server $ \conn ->
    runClient conn (client serviceToCall)

parseUrlToServer :: String -> Server
parseUrlToServer url =
  let urlText = T.pack url
      fullUrl = if "http://" `T.isPrefixOf` urlText then urlText else "http://" <> urlText
      parts = T.splitOn ":" fullUrl
      host = T.unpack . T.dropWhile (== '/') $ parts !! 1
      port = read (T.unpack (parts !! 2)) :: PortNumber
   in ServerInsecure $ Address host port Nothing
