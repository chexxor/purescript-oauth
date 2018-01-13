module Network.OAuth where

import Prelude
import App.Data.Jwt as Jwt
import App.Data.Aff (hushAff)
import App.Formatting (messages)
import App.Network.OAuth.Type (TokenEndpointSuccessResponse, AccessTokenResponseSuccess(..), CertsResponse, ValidateTokenResponse)
import Control.Alt ((<|>))
import Control.Monad.Aff (Aff)
import Control.Monad.Eff (Eff)
import Control.Monad.Eff.Class (liftEff)
import Control.Monad.Eff.Exception (error, message)
import Control.Monad.Eff.Now (now)
import Control.Monad.Error.Class (throwError)
import Control.Monad.Except (runExcept)
import Data.Argonaut.Core (Json)
import Data.Array (intercalate)
import Data.Bifunctor (lmap)
import Data.DateTime.Instant (Instant, instant, unInstant)
import Data.Either (Either(Left), either)
import Data.Foreign (Foreign)
import Data.Foreign.Class (readProp)
import Data.HTTP.Method (Method(..))
import Data.Maybe (Maybe(..), maybe)
import Data.MediaType.Common (applicationFormURLEncoded, applicationJSON)
import Data.Newtype (unwrap)
import Data.String (length)
import Data.Time.Duration (Milliseconds(..))
import Data.Tuple (Tuple(..))
import Debug.Trace (traceAny, traceAnyM)
import Network.HTTP.Affjax (AJAX, affjax, defaultRequest)
import Network.HTTP.RequestHeader (RequestHeader(..))
import Unsafe.Coerce (unsafeCoerce)

-- 4: Obtaining Authorization

sendAuthRequest ::
  forall eff requestType.
     AuthEndpointClient requestType
  -> (AuthRequestArgs requestType)
  -> (Either AuthorizationEndpointErrorResponse (AuthorizationEndpointSuccessResponse requestType) -> Eff eff Unit)
  -> Eff eff Unit
sendAuthRequest
  (AuthEndpointClient openAuth listenForAuth)
  authArgs handleResponse = do
  openAuth authArgs
  listenForAuth handleResponse

sendAuthReqeust'
  :: forall eff requestType.
     AuthEndpointClient requestType
  -> (AuthRequestArgs requestType)
  -> ContT Unit (Eff eff)
       (Either (AuthorizationEndpointErrorResponse (AuthorizationEndpointSuccessResponse requestType)))
sendAuthRequest' = ContT <<< sendAuthRequest


sendTokenRequest ::
  forall eff grantType.
     TokenEndpointClient grantType
  -> TokenRequestArgs grantType
  -> (Either TokenEndpointErrorResponse (TokenEndpointSuccessResponse grantType) -> Eff eff Unit)
  -> Eff eff Unit
sendTokenRequest
  (TokenEndpointClient requestToken)
  (TokenRequestArgs client_id redirect_uri scope state)
  handleResponse = do
  requestToken authReq
  listenForAuth handleResponse

sendTokenRequest'
  :: forall eff grantType.
     TokenEndpointClient grantType
  -> TokenRequestArgs grantType
  -> ContT Unit (Eff eff)
       ((Either TokenEndpointErrorResponse (TokenEndpointSuccessResponse grantType)))
sendTokenRequest' = ContT <<< sendTokenRequest

-- 4.1: Obtaining Authorization

tokenByAuthorizationToken ::
     AuthEndpointClient
  -> TokenEndpointClient
  -> Aff _ (Either TokenEndpointErrorResponse TokenEndpointSuccessResponse)
tokenByAuthorizationToken
  (AuthEndpointClient)
  (TokenEndpointClient)
  = do
  -- !!! to do

-- 4.1.3: Access Token Request
-- https://tools.ietf.org/html/rfc6749#section-4.1.3


-- If client is confidential or the client was issued client credentials
--   or similar, the client must authenticate with Authorization Server.
-- ??? Can we enforce this with types?

-- Authentication Server must:
--  - require client authentication for confidential clients or
--     clients issued client credentials.
--  - authenticate the client, if applicable
--  - ensure the authorization code was issued to the authenticated
--     confidential client, or for public clients ensure it was
--     issued to the `client_id` param in the request
--  - verify the authorization code is valid
--  - ensure the `redirect_uri` param is present if the param was included
--     in initial authorization request, and if included has identical value

-- 4.1.4: Access Token Response
-- https://tools.ietf.org/html/rfc6749#section-4.1.4

-- If request is valid and authorized, responds with `TokenEndpointSuccessResponse`,
--  else responds with `TokenEndpointErrorResponse`.


----------

-- 4.2: Implicit Grant
-- https://tools.ietf.org/html/rfc6749#section-4.2

-- Implicit grant type obtains an access token (no refresh token). It is
--   optimized for public clients which is typically an in-browser JavaScript app.
-- No client authentication, requires resource owner to authenticate
--   and a preregistered redirection URI.

-- 4.2.1: Authorization Request
-- https://tools.ietf.org/html/rfc6749#section-4.2.1

-- Client sends request to Authorization Endpoint having params:
-- - `response_type`: value="token"
-- - `client_id`
-- - `redirect_uri`: optional, the URI on which the client listens to receive grant
-- - `scope`: optional, the scope of the access request
-- - `state`: recommended, to prevent XSRF, client should verify
--      value unchanged between requesting authorization and receiving grant

implicitAuthRequestArgs ::
     ClientId
  -> RedirectURI
  -> Maybe AccessTokenScope
  -> Maybe CSRFStateToken
  -> AuthRequestArgs AccessToken
implicitAuthRequestArgs client_id redirect_uri scope state =
  AuthorizationRequest
    (AuthorizationRequestTypeToken AccessToken) client_id redirect_uri scope state

authTokenByImplicit :: forall eff.
     AuthEndpointClient AccessToken
  -> AuthRequestArgs AccessToken
  -> (Either AuthorizationEndpointErrorResponse (AuthorizationEndpointSuccessResponse AccessToken) -> Eff eff Unit)
  -> Eff eff Unit
authTokenByImplicit
  (AuthEndpointClient openAuth listenForAuth)
  authArgs handleResponse = openAuth authArgs *> listenForAuth handleResponse


-- ??? Where do these two go?

reqTokenEndpoint ::
  forall eff grantType.
     TokenEndpointClient grantType
  -> TokenRequestArgs
  -> (Either TokenEndpointErrorResponse (TokenEndpointSuccessResponse grantType) -> Eff eff Unit)
  -> Eff eff Unit
reqTokenEndpoint
  (TokenEndpointClient reqToken)
  tokenArgs handleResponse = reqToken tokenArgs >>= handleResponse

reqTokenEndpoint'
  :: forall eff grantType.
     TokenEndpointClient grantType
  -> TokenRequestArgs
  -> ContT Unit (Eff eff)
       (Either (TokenEndpointErrorResponse (TokenEndpointSuccessResponse grantType)))
reqTokenEndpoint' client = ContT <<< reqTokenEndpoint client

-- 4.2.2: Access Token Response
-- https://tools.ietf.org/html/rfc6749#section-4.2.2

-- Authorization server issues access token and responds with the following params
--   in the query fragment of the redirection URI using "x-www-form-urlencoded" format:
--  - `token_type`
--  - `access_token`
--  - `expires_in`: optional, the lifetime, in seconds of the access token
--  - `scope`: optional, the scope of the access token, must be identical to the requested scope
--  - `state`: optional, must be identical to `state` param received from client,
--            required if the client included `state` value in the request
-- Must not issue a refresh token.
-- Clients:
--  - Note that some browsers don't support fragment in HTTP "Location" response header.
--  - Must ignore unrecognized response params

-- 4.2.2.1: Access Token Response
-- https://tools.ietf.org/html/rfc6749#section-4.2.2.1

-- If the redirection URI or client ID has errors, the server must not redirect the user-agent.
-- If the resource owner denies access or otherwise fails, the authorization server responds
--   with AuthorizationEndpointErrorResponse in the redirection URI's fragment
--   in "application/x-www-form-urlencoded" format.


-- 4.3: Resource Owner Password Credentials Grant
-- https://tools.ietf.org/html/rfc6749#section-4.3

-- !!!

















-- 5.1 Successful Response
-- https://tools.ietf.org/html/rfc6749#section-5.1

data TokenEndpointSuccessResponse a =
  { access_token :: a -- See 7.1: Access Token Types
  , token_type :: AccessTokenType
  , expires_in :: Maybe Seconds -- recommended
  , refresh_token :: Maybe RefreshToken
  , scope :: Maybe AccessScope
  }

-- 5.2 Error Response
-- https://tools.ietf.org/html/rfc6749#section-5.2

-- Rendered as ASCII string
data TokenEndpointErrorCode
  = InvalidRequest -- invalid_request
  | InvalidClient -- invalid_client
  | InvalidGrant -- invalid_grant
  | UnauthorizedClient -- unauthorized_client
  | UnsupportedGrantType -- unsupported_grant_type
  | InvalidScope -- invalid_scope

data TokenEndpointErrorResponse a =
  { error :: TokenEndpointErrorCode
  , error_description :: Maybe String
  -- ^ optional, details in ASCII to assist client dev.
  , error_uri :: Maybe String -- !!! URI, not String
  -- ^ optional, URI of web page about the error
  }


-- 7.1 Access Token Types
-- https://tools.ietf.org/html/rfc6749#section-7.1

-- ??? Better way?
newtype AccessTokenType = AccessTokenType String






-- OpenID Connect

-- 3.1.2.1: Authorization Endpoint Redirection
-- https://tools.ietf.org/html/rfc6749#section-3.1.2.1

-- Client may send params using GET or POST.
-- Params:
-- - `scope` - Required, must contain "openid", may contain more
-- - `response_type` - Required, AuthorizationEndpointResponseType
-- - `client_id` - Required
-- - `redirect_uri` - Required, ClientTokenReceptionEndpoint, must match
--    one of the URIs preregistered with the OpenId







-- Get a fresh oAuth token.
-- Throws on Aff error channel
freshToken ::
  String -- host
  -> { client_id :: String, client_secret :: Maybe String }
  -> Tuple String String -- access_token refresh_token
  -> Aff _ (Tuple String String) -- Tuple AccessToken RefreshToken
freshToken oauthHost
  { client_id, client_secret }
  (Tuple accessToken refreshToken)
  = do
  freshAccess <|> freshRefresh
  where
    freshAccess :: Aff _ (Tuple String String)
    freshAccess =
      (hushAff "Invalid access token." $ liftEff $ isFresh accessToken)
      >>= if _
        then traceAny "Access token is fresh" \_ -> pure $ Tuple accessToken refreshToken
        else traceAny "Access expired" \_ -> throwError $ error "Access expired."
    freshRefresh :: Aff _ (Tuple String String)
    freshRefresh =
      (hushAff "Invalid refresh token." $ liftEff $ isFresh refreshToken)
      >>= if _
        then refreshSession
        else traceAny "Session expired" \_ -> throwError $ error "Session expired."
    refreshSession :: Aff _ (Tuple String String)
    refreshSession = freshSession >>= formatResponse
    freshSession :: Aff _ TokenEndpointSuccessResponse
    freshSession =
      getTokenByRefresh oauthHost { client_id, client_secret, refresh_token: refreshToken }
    formatResponse :: TokenEndpointSuccessResponse -> Aff _ (Tuple String String)
    formatResponse = either
        (\_ ->
          traceAny "Failed to refresh session" \_ ->
          throwError $ error "Failed to refresh session."
        )
        (\(TokenEndpointSuccessResponseSuccess r) ->
          traceAny "Refreshed session" \_ ->
          pure $ Tuple r.access_token r.refresh_token
        )
        <<< unwrap


-- ??? Map to front-facing error messages?
isFresh :: String -> Eff _ (Either String Boolean)
isFresh accessToken =
  let
    accessTokenDecoded :: Either String Foreign
    accessTokenDecoded = lmap message $ Jwt.decode accessToken
    parseUserInfo :: Foreign -> Either String { exp :: Maybe Instant }
    parseUserInfo f = lmap (intercalate "," <<< messages) $ runExcept do
      --sub :: String <- readProp "sub" f
      exp :: Number <- readProp "exp" f
      pure { exp: (instant <<< Milliseconds) exp }
    accessTokenDecoded' :: Either String { exp :: Maybe Instant }
    accessTokenDecoded' = accessTokenDecoded >>= parseUserInfo
  in do
    --now <- nowUnixEpochMs
    now' <- now
    pure $ accessTokenDecoded' <#>
      \{ exp } ->
        case exp of
          Just exp' ->
            traceAny ("now=" <> show (unInstant now') <> " exp=" <> show (unInstant exp') <> " exp1000=" <> show ((unInstant exp') * (Milliseconds 1000.0)) ) \_->
            traceAny ((unInstant exp') * (Milliseconds 1000.0) < (unInstant now')) \_->
            unInstant now' < unInstant exp' * Milliseconds 1000.0
          Nothing ->
            traceAny "Invalid exp value on accessToken." \_ ->
            false

getCerts :: forall eff.
  String -> -- host
  Aff (ajax :: AJAX | eff) CertsResponse
getCerts host = do
  traceAnyM "getCerts"
  --res <- attempt $ affjax opts
  res <- affjax opts
  traceAnyM "res"
  traceAnyM res
  --pure $ unsafeCoerce (res.response :: Json)
  pure res.response
  where
    opts =
      defaultRequest {
        method = Left GET
      , url = host <> "/protocol/openid-connect/certs"
      , headers =
        [ Accept applicationJSON
        -- , ContentType applicationFormURLEncoded
        -- , RequestHeader "Authorization" ("Bearer " <> accessToken.access_token)
        ]
      , content = Nothing :: Maybe Unit
      }

requestAccessTokenFromCode :: forall e. _ -> String -> String -> String -> Aff (ajax :: AJAX | e) _
requestAccessTokenFromCode config clientState authRedirectUri code = do
  traceAnyM "requestAccessTokenFromCode opts"
  traceAnyM opts
  --res <- attempt $ affjax opts
  res <- affjax opts
  traceAnyM "res"
  traceAnyM res
  pure $ unsafeCoerce (res.response :: Json)
  where
    content =
         "client_session_state=" <> clientState --sessionId
      <> "&client_session_host=" <> config.sessionHost
      <> "&code=" <> code
      <> "&grant_type=authorization_code"
      <> "&client_id=" <> config.clientId
      <> "&redirect_uri=" <> authRedirectUri
    opts =
      defaultRequest {
        method = Left POST
      , url = config.host <> "/protocol/openid-connect/token"
      , headers =
        [ Accept applicationJSON
        , ContentType applicationFormURLEncoded
        , RequestHeader "Content-Length" (show $ length content)
        , RequestHeader "X-Client" "some-client" -- ??? remove?
        ]
      , content = Just content
      }

getTokenByPassword :: forall eff.
  String -> -- host
  { client_id :: String, client_secret :: Maybe String, username :: String, password :: String } ->
  Aff (ajax :: AJAX | eff) TokenEndpointSuccessResponse
getTokenByPassword host tokenRequest =
  do
    traceAnyM "getToken opts"
    traceAnyM opts
    res <- affjax opts
    traceAnyM "res"
    traceAnyM res
    pure res.response
  where
    opts =
      defaultRequest {
        method = Left POST
      , url = host <> "/protocol/openid-connect/token"
      , headers =
        [ Accept applicationJSON
        , ContentType applicationFormURLEncoded
        ]
      , content = Just $
             "client_id=" <> tokenRequest.client_id
          <> (maybe "" (\client_secret -> "&client_secret=" <> client_secret) tokenRequest.client_secret)
          <> "&username=" <> tokenRequest.username
          <> "&password=" <> tokenRequest.password
          <> "&grant_type=password"
      }

getTokenByRefresh :: forall eff.
  String -> -- host
  { client_id :: String, client_secret :: Maybe String, refresh_token :: String } ->
  Aff (ajax :: AJAX | eff) TokenEndpointSuccessResponse
getTokenByRefresh host tokenRequest = do
  res <- affjax opts
  traceAnyM "res"
  traceAnyM res
  pure res.response
  where
    opts =
      defaultRequest {
        method = Left POST
        , url = host <> "/protocol/openid-connect/token"
        , headers =
          [ Accept applicationJSON
          , ContentType applicationFormURLEncoded
          ]
        , content = Just $
             "client_id=" <> tokenRequest.client_id
          <> (maybe "" (\client_secret -> "&client_secret=" <> client_secret) tokenRequest.client_secret)
          <> "&refresh_token=" <> tokenRequest.refresh_token
          <> "&grant_type=refresh_token"
      }

getTokenByClientCredentials :: forall eff.
  String -> -- host
  { client_id :: String, client_secret :: Maybe String } ->
  Aff (ajax :: AJAX | eff) TokenEndpointSuccessResponse
getTokenByClientCredentials host tokenRequest = do
  res <- affjax opts
  traceAnyM "res"
  traceAnyM res
  pure res.response
  where
    opts =
      defaultRequest {
        method = Left POST
        , url = host <> "/protocol/openid-connect/token"
        , headers =
          [ Accept applicationJSON
          , ContentType applicationFormURLEncoded
          ]
        , content = Just $
             "client_id=" <> tokenRequest.client_id
          <> (maybe "" (\client_secret -> "&client_secret=" <> client_secret) tokenRequest.client_secret)
          <> "&grant_type=client_credentials"
      }

--type UserInfoResponse =
--  { sub :: String
--  , name :: String
--  , preferred_username :: String
--  }
--
--userInfo :: forall eff.
--  String -> -- host
--  String -> -- access_token
--  Aff (ajax :: AJAX | eff) UserInfoResponse
--userInfo host access_token = do
--  res <- affjax opts
--  traceAnyM "res"
--  traceAnyM res
--  pure res.response
--  where
--    opts =
--      defaultRequest {
--        method = Left GET
--        , url = host <> "/protocol/openid-connect/userinfo"
--        , headers =
--          [ Accept applicationJSON
--          , ContentType applicationFormURLEncoded
--          , RequestHeader "Authorization" ("Bearer " <> access_token)
--          ]
--        , content = Nothing
--      }

validateToken :: forall eff.
  String -> -- host
  { token :: String, client_secret :: Maybe String, client_id :: String } ->
  Aff (ajax :: AJAX | eff) ValidateTokenResponse
validateToken host tokenRequest = do
  res <- affjax opts
  traceAnyM "res"
  traceAnyM res
  --pure $ unsafeCoerce (res.response :: Json)
  pure res.response
  where
    opts =
      defaultRequest {
        method = Left POST
        , url = host <> "/protocol/openid-connect/token/introspect"
        , headers =
          [ Accept applicationJSON
          , ContentType applicationFormURLEncoded
          ]
        , content = Just $
             "token=" <> tokenRequest.token
          <> (maybe "" (\client_secret -> "&client_secret=" <> client_secret) tokenRequest.client_secret)
          <> "&client_id=" <> tokenRequest.client_id
      }

--endSession :: forall eff.
--  String -> -- host
--  { token :: String, client_secret :: Maybe String, client_id :: String } ->
--  Aff (ajax :: AJAX | eff) ValidateTokenResponse
--endSession host tokenRequest = do
--  res <- affjax opts
--  traceAnyM "res"
--  traceAnyM res
--  --pure $ unsafeCoerce (res.response :: Json)
--  pure res.response
--  where
--    opts =
--      defaultRequest {
--        method = Left POST
--        , url = host <> "/protocol/openid-connect/logout"
--        , headers =
--          [ Accept applicationJSON
--          , ContentType applicationFormURLEncoded
--          ]
--        , content = Just $
--             "token=" <> tokenRequest.token
--          <> (maybe "" (\client_secret -> "&client_secret=" <> client_secret) tokenRequest.client_secret)
--          <> "&client_id=" <> tokenRequest.client_id
--      }
