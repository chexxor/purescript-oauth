module App.Network.OAuth.Type where

import App.Data.Jwk.Type (Jwk)
import Data.Either (Either)
import Data.Foreign (F, Foreign)
import Data.Foreign.Class (class IsForeign, read, readEitherR, readProp)
import Data.Foreign.Generic (defaultOptions, readGeneric)
import Data.Generic.Rep (class Generic)
import Data.Maybe (Maybe(Just))
import Data.MediaType.Common (applicationJSON)
import Data.Newtype (class Newtype)
import Data.Tuple (Tuple(..))
import Network.HTTP.Affjax.Response (class Respondable, ResponseType(..))
import Prelude (bind, pure, ($), (<<<), (>>=))

newtype CertsResponse = CertsResponse
  { keys :: Array Jwk
  }
derive instance newtypeCertsResponse :: Newtype CertsResponse _
instance isForeignCertsResponse :: IsForeign CertsResponse where
  read f = do
    keys <- readProp "keys" f
    pure $ CertsResponse { keys }
instance respondableCertsResponse :: Respondable CertsResponse where
  responseType = Tuple (Just applicationJSON) JSONResponse
  fromResponse = read


newtype ValidateTokenResponse = ValidateTokenResponse (Either ValidateTokenResponseFailure ValidateTokenResponseSuccess)
derive instance newtypeValidateTokenResponse :: Newtype ValidateTokenResponse _
instance isForeignValidateTokenResponse :: IsForeign ValidateTokenResponse where
  read f = m
    where
      p = pure f :: F Foreign
      e = (p >>= readEitherR) :: F (Either ValidateTokenResponseFailure ValidateTokenResponseSuccess)
      m = (e >>= (pure <<< ValidateTokenResponse)) :: F ValidateTokenResponse
instance respondableValidateTokenResponse :: Respondable ValidateTokenResponse where
  responseType = Tuple (Just applicationJSON) JSONResponse
  fromResponse = read

newtype ValidateTokenResponseSuccess = ValidateTokenResponseSuccess
  { jti :: String -- "bc443df1-0a6a-49d2-83bf-59adb56e370a"
  , exp :: Int -- 1493859645
  , nbf :: Int -- 0
  , iat :: Int -- 1493859585
  , iss :: String -- "http://SomeAuthIssuer.com/auth"
  , aud :: String -- "someAppName"
  , sub :: String -- "efc6f516-862f-4c8b-ba5a-a501eeb04eb2"
  , typ :: String -- "Bearer"
  , azp :: String -- "someAppName"
  , auth_time :: Int -- 0
  , session_state :: String -- "659dd88f-fb23-45d0-ad35-7e08a1ba2f0c"
  , name :: String -- "SomeFirstName"
  , preferred_username :: String -- "someHandle"
  , acr :: String -- "1"
  , client_session :: String -- "dcac729e-495e-4d79-ad4c-aaf457857c8a"
  , "allowed-origins" :: Array String -- ["localhost:8080", "localhost:3000", "myapp.com" ]
  , client_id :: String -- "someAppName"
  , username :: String -- "someHandle"
  , active :: Boolean -- true
  --, others?
  }
derive instance genericValidateTokenResponseSuccess :: Generic ValidateTokenResponseSuccess _
derive instance newtypeValidateTokenResponseSuccess :: Newtype ValidateTokenResponseSuccess _
instance isForeignValidateTokenResponseSuccess :: IsForeign ValidateTokenResponseSuccess where
  read = readGeneric $ defaultOptions { unwrapSingleConstructors = true }

newtype ValidateTokenResponseFailure = ValidateTokenResponseFailure
  { active :: Boolean
  }
  -- {"error":"invalid_grant","error_description":"Invalid user credentials"}
derive instance genericValidateTokenResponseFailure :: Generic ValidateTokenResponseFailure _
instance isForeignValidateTokenResponseFailure :: IsForeign ValidateTokenResponseFailure where
  read = readGeneric $ defaultOptions { unwrapSingleConstructors = true }


--type AccessTokenRequest =
--  { grant_type :: String
--  , client_id :: String
--  , username :: String
--  , password :: String
--  }

newtype AccessTokenResponse = AccessTokenResponse (Either AccessTokenResponseFailure AccessTokenResponseSuccess)

derive instance newtypeAccessTokenResponse :: Newtype AccessTokenResponse _

newtype AccessTokenResponseSuccess = AccessTokenResponseSuccess
  { access_token :: String
  , expires_in :: Int -- seconds
  , refresh_expires_in :: Int -- seconds
  , refresh_token :: String
  , token_type :: String
  , id_token :: String
  , "not-before-policy" :: Int
  , session_state :: String
  }
derive instance genericAccessTokenResponseSuccess :: Generic AccessTokenResponseSuccess _
derive instance newtypeAccessTokenResponseSuccess :: Newtype AccessTokenResponseSuccess _
instance isForeignAccessTokenResponseSuccess :: IsForeign AccessTokenResponseSuccess where
  read = readGeneric $ defaultOptions { unwrapSingleConstructors = true }

newtype AccessTokenResponseFailure = AccessTokenResponseFailure
  { error :: String
  , error_description :: String
  }
  -- {"error":"invalid_grant","error_description":"Invalid user credentials"}
derive instance genericAccessTokenResponseFailure :: Generic AccessTokenResponseFailure _
derive instance newtypeAccessTokenResponseFailure :: Newtype AccessTokenResponseFailure _
instance isForeignAccessTokenResponseFailure :: IsForeign AccessTokenResponseFailure where
  read = readGeneric $ defaultOptions { unwrapSingleConstructors = true }

instance isForeignAccessTokenResponse :: IsForeign AccessTokenResponse where
  read f = m
    where
      p = pure f :: F Foreign
      e = (p >>= readEitherR) :: F (Either AccessTokenResponseFailure AccessTokenResponseSuccess)
      m = (e >>= (pure <<< AccessTokenResponse)) :: F AccessTokenResponse
instance respondableAccessTokenResponse :: Respondable AccessTokenResponse where
  responseType = Tuple (Just applicationJSON) JSONResponse
  fromResponse = read

