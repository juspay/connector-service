{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Aeson (ToJSON, object, (.=))
import Data.Aeson.Types (Value (..))
import qualified Data.ByteString.Lazy.Char8 as L8
import Network.HTTP.Simple
import System.Environment (getEnv)

buildPaymentsAuthorizeRequest :: String -> String -> String -> Value
buildPaymentsAuthorizeRequest apiKey key1 apiSecret =
    object
        [ "amount" .= Number 1000
        , "currency" .= (145 :: Int) -- USD
        , "connector" .= (2 :: Int) -- Adyen
        , "auth_creds"
            .= object
                [ "auth_details"
                    .= object
                        [ "SignatureKey"
                            .= object
                                [ "api_key" .= apiKey
                                , "key1" .= key1
                                , "api_secret" .= apiSecret
                                ]
                        ]
                ]
        , "payment_method" .= (0 :: Int) -- Card
        , "payment_method_data"
            .= object
                [ "data"
                    .= object
                        [ "Card"
                            .= object
                                [ "card_number" .= String "4111111111111111"
                                , "card_exp_month" .= String "03"
                                , "card_exp_year" .= String "2030"
                                , "card_cvc" .= String "737"
                                ]
                        ]
                ]
        , "address" .= object [] -- Default empty address
        , "auth_type" .= (0 :: Int) -- ThreeDS
        , "connector_request_reference_id" .= String "ref_12345"
        , "enrolled_for_3ds" .= Bool True
        , "request_incremental_authorization" .= Bool False
        , "minor_amount" .= Number 1000
        ]

paymentAuthorize :: (ToJSON a) => String -> a -> IO L8.ByteString
paymentAuthorize host req = do
    initialRequest <- parseRequest url
    let request =
            setRequestMethod "POST" $
                setRequestBodyJSON req $
                    setRequestHeader "Content-Type" ["application/json"] initialRequest
    response <- httpLBS request
    return $ getResponseBody response
  where
    url = host ++ "/ucs.payments.PaymentService/PaymentAuthorize"

main :: IO ()
main = do
    let host = "http://localhost:8000"
    apiKey <- getEnv "API_KEY"
    key1 <- getEnv "KEY1"
    apiSecret <- getEnv "API_SECRET"
    let request = buildPaymentsAuthorizeRequest apiKey key1 apiSecret
    response <- paymentAuthorize host request
    L8.putStrLn response
