module Network.OAuth.Type where

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

-- !!! Delete this, it belongs elsewhere.
wellKnownUrl = "https://accounts.google.com/.well-known/openid-configuration"

-- 2.1: Client Types

-- A "ClientType" value describes the client's capability to keep their credentials secret.
-- secure authentication and its acceptable exposure levels of client credentials.
--
-- Example client profiles:
--  - traditional, server-rendered web app (Confidential client)
--  - SPA web app (Public client)
--  - native app (Public client)

data ClientType
  = Confidential
  | Public

-- 2.2: Client Identifier

-- A `ClientId` is a unique string representing the client's registration info provided
--   by the client to the authorization server when it registered.

newtype ClientId = ClientId String

-- 2.3: Client Authentication

-- For Confidential clients, the authentication server can choose any form of
--   secure client authentication, e.g. password or pub/prv keypair.
-- A client may use only one kind of authentication scheme per request.
--
-- Passing ClientCredentials via "Authorization" header (HTTP Basic Authentication) is preferred
--   to via request body. The authorization server must support HTTP Basic Authentication for
--   client authentication.

newtype ClientSecret = ClientSecret String
newtype ConfidentialClient clientId = ConfidentialClient (Tuple clientId ClientSecret)

-- 3: Endpoints

newtype AuthorizationEndpoint = AuthorizationEndpoint String
newtype TokenEndpoint = TokenEndpoint String
newtype ClientReceptionEndpoint = ClientReceptionEndpoint String -- Called "RedirectionEndpoint" in other OAuth implementations

-- 3.1: Authorization Endpoint

newtype AuthEndpointClient (requestType :: AuthorizationRequestType) =
  AuthEndpointClient
    -- AuthorizationEndpoint ??? Include in data type?
    (AuthRequestArgs requestType -> Eff eff Unit)
    -- ^ Spawn browser or child window to send user-agent to authorization server.
    ((Either AuthorizationEndpointErrorResponse (AuthorizationEndpointSuccessResponse requestType) -> Eff eff Unit)
      -> Eff eff Unit
    )
    -- ^ Listen for HTTP request or child window event having authorization token.

-- ??? Move to 10.12?
newtype CSRFStateToken = CSRFStateToken String

-- `RedirectURI` is optional in the OAuth 2.0 spec as a convenience for
--   clients having registered only a single redirect URI
--   optional as a convenience to clients registering a single,
--   non-partial redirect URI.
--   To simplify our client, we simply always require it.
data AuthRequestArgs (requestType :: AuthorizationRequestType)
  = AuthRequestArgs
    (AuthorizationRequestTypeToken requestType)
    ClientId
    RedirectURI
    (Maybe AccessTokenScope)
    (Maybe CSRFStateToken)


-- 3.1.1: Authorization Endpoint Response Type

-- Client must specify the desired response type, as
--   Authorization Endpoint is used for multiple flows.

foreign import kind AuthorizationRequestType
foreign import AuthorizationCode :: AuthorizationRequestType
foreign import AccessToken :: AuthorizationRequestType

foreign import AuthorizationRequestTypeToken :: AuthorizationRequestType -> Type
authTokenRequestCode :: AuthorizationRequestTypeToken -> String
authTokenRequestCode AuthorizationCode = "code"
authTokenRequestCode AccessToken = "token"
parseAuthTokenRequestCode ::
  String -> Either String AuthorizationRequestTypeToken
parseAuthTokenRequestCode str = case str of
  "code" -> Right AuthorizationCode
  "token" -> Right AccessToken
  a -> Left "Unknown auth token type: " <> a

authTokenTypeToken :: AuthorizationRequestTypeToken AuthorizationCode
authTokenTypeToken = unsafePartial fromRight parseAuthTokenRequestCode "code"
authTokenTypeCode :: AuthorizationRequestTypeToken AccessToken
authTokenTypeCode = unsafePartial fromRight parseAuthTokenRequestCode "token"

-- 3.2: Token Endpoint

newtype TokenEndpointClient (grantType :: TokenRequestGrantType) =
  TokenEndpointClient
    -- TokenEndpoint ??? Include in data type?
    (TokenRequestArgs grantType -> Eff eff Unit)
    -- ^ Send HTTP request to get Access Token

-- 3.3: Access Token Scope

newtype AccessScope = AccessScope (Set String)

-- 4: Obtaining Authorization

-- To request an access token, the client obtains an Authorization Grant
--  from the resource owner.

foreign import kind TokenRequestGrantType
foreign import AuthorizationCode :: TokenRequestGrantType
foreign import Password :: TokenRequestGrantType
foreign import ClientCredentials :: TokenRequestGrantType
foreign import RefreshToken :: TokenRequestGrantType
-- foreign import Custom :: TokenRequestGrantType

foreign import TokenRequestGrantTypeToken :: TokenRequestGrantType -> Type

tokenRequestGrantTypeToken :: TokenRequestGrantTypeToken -> String
tokenRequestGrantTypeToken AuthorizationCode = "authorization_code"
tokenRequestGrantTypeToken Password = "password"
tokenRequestGrantTypeToken ClientCredentiasl = "client_credentials"
tokenRequestGrantTypeToken RefreshToken = "refresh_token"
parseTokenRequestGrantTypeToken ::
  String -> Either String TokenRequestGrantTypeToken
parseTokenRequestGrantTypeToken str = case str of
  "authorization_code" -> Right AuthorizationCode
  "password" -> Right Password
  "client_credentials" -> Right ClientCredentials
  "refresh_token" -> Right RefreshToken
  a -> Left "Unknown token grant typ: " <> a

tokenRequestGrantTypeAuthCode :: TokenRequestGrantType AuthorizationCode
tokenRequestGrantTypeAuthCode = unsafePartial fromRight parseTokenRequestGrantTypeToken "code"
tokenRequestGrantTypePassword :: TokenRequestGrantType Password
tokenRequestGrantTypePassword = unsafePartial fromRight parseTokenRequestGrantTypeToken "password"
tokenRequestGrantTypeClientCreds :: TokenRequestGrantType ClientCredentials
tokenRequestGrantTypeClientCreds = unsafePartial fromRight parseTokenRequestGrantTypeToken "client_credentials"
tokenRequestGrantTypeRefreshToken :: TokenRequestGrantType RefreshToken
tokenRequestGrantTypeRefreshToken = unsafePartial fromRight parseTokenRequestGrantTypeToken "refresh_token"


-- 4.1: Authorization Code Grant



-- 4.1.1: Authorization Request
-- https://tools.ietf.org/html/rfc6749#section-4.1.1

-- Client sends request to Authorization Endpoint having params:
-- - `response_type`: value="code"
-- - `client_id`
-- - `redirect_uri`: optional, the URI on which the client listens to receive grant
-- - `scope`: optional, the scope of the access request
-- - `state`: recommended, to prevent XSRF, client should verify
--      value unchanged between requesting authorization and receiving grant

const_auth_request_type_token :: String
const_auth_request_type_token = "token"
const_auth_request_type_code :: String
const_auth_request_type_code = "code"

foreign import kind AuthorizationRequestType
foreign import AuthorizationCode :: AuthorizationRequestType
foreign import AccessToken :: AuthorizationRequestType

foreign import AuthorizationRequestTypeToken :: AuthorizationRequestType -> Type
authTokenRequestCode :: AuthorizationRequestTypeToken -> String
authTokenRequestCode AuthorizationCode = "code"
authTokenRequestCode AccessToken = "token"
parseAuthTokenRequestCode ::
  String -> Either String AuthorizationRequestTypeToken
parseAuthTokenRequestCode str = case str of
  "code" -> Right AuthorizationCode
  "token" -> Right AccessToken
  _ -> Left "Unknown token type in authorization endpoint response."


newtype CSRFStateToken = CSRFStateToken String

-- `RedirectURI` is optional in the OAuth 2.0 spec as a convenience for
--   clients having registered only a single redirect URI
--   optional as a convenience to clients registering a single,
--   non-partial redirect URI.
--   To simplify our client, we simply always require it.
data AuthRequestArgs (requestType :: AuthorizationRequestType)
  = AuthorizationRequest
    (AuthorizationRequestTypeToken requestType)
    ClientId
    RedirectURI
    (Maybe AccessTokenScope)
    (Maybe CSRFStateToken)

authcodeAuthRequestArgs ::
     ClientId
  -> RedirectURI
  -> Maybe AccessTokenScope
  -> Maybe CSRFStateToken
  -> AuthRequestArgs AuthorizationCode
authcodeAuthRequestArgs client_id redirect_uri scope state =
  AuthorizationRequest
    (AuthorizationRequestTypeToken AuthorizationCode) client_id redirect_uri scope state

-- 4.1.2: Authorization Response

-- Authorization Server
--  Responds to authorization success with HTTP redirect response
--    containing the following params in the URI:
--   - `code`: must have short expiration (rec. <10 min),
--       client must use only once
--   - `state`: must be identical to `state` param received from client
--  Must not redirect to invalid redirection URI
--  Should inform resource owner of erroneous request
-- Responds to authorization error with `AuthorizationEndpointErrorResponse`

data AuthorizationEndpointSuccessResponse (tokenType :: AuthorizationRequestType) -- keep for now, possible type safety
  = AuthorizationEndpointSuccessResponseCode
      -- (AuthorizationEndpointResponse tokenType) -- always "code"
      (Maybe CSRFStateToken)
  | AuthorizationEndpointSuccessResponseToken
      -- (AuthorizationEndpointResponse tokenType) -- always "token"
      AccessToken
      (Maybe String) -- expires_in, in seconds
      (Maybe AccessTokenScope)
      (Maybe CSRFStateToken)

-- 4.1.2.1: Error Response

data AuthorizationEndpointErrorCode
  = InvalidRequest -- invalid_request
  | UnauthorizedClient -- unauthorized_client
  | AccessDenied -- access_denied
  | UnsupportedResponseType -- unsupported_response_type
  | InvalidScope -- invalid_scope
  | ServerError -- server_error
  | TemporarilyUnavailable -- temporarily_unavailable

data AuthorizationEndpointErrorResponse a =
  { error :: AuthorizationEndpointErrorCode
  , error_description :: Maybe String
  -- ^ optional, details in ASCII to assist client dev
  , error_uri :: Maybe String -- ??? use URI?
  -- ^ optional, URI of web page about the error
  , state :: Maybe CSRFStateToken
  -- ^ required if `state` was in request. Must be identical
  }

-- Client:
--  - must ignore unrecognized response params

-- 4.1.3: Access Token Request
-- https://tools.ietf.org/html/rfc6749#section-4.1.3

newtype ClientCreds = ClientCreds
  (Tuple
    String -- client_id
    String -- client_secret
  )

data TokenRequestArgs (grantType :: TokenRequestGrantType)
  = TokenByAuthCodeRequestArgs
    (TokenRequestGrantTypeToken grantType)
    AuthCode -- authorization code
    ClientId
    RedirectURI
    (Maybe AccessTokenScope)
  | TokenByPasswordRequestArgs
    (TokenRequestGrantTypeToken grantType)
    (Tuple Username Password)
    ClientId -- not used for refresh
    RedirectURI -- not used for refresh
    (Maybe AccessTokenScope)
  | TokenByRefreshRequestArgs
    (TokenRequestGrantTypeToken grantType)
    (RefreshToken)
    (Maybe AccessTokenScope)
  | TokenByClientCredsRequestArgs
    (TokenRequestGrantTypeToken grantType)
    ClientCreds
    (Maybe AccessTokenScope)


--------

data TokenRequest (requestType :: TokenRequestType)
  = TokenRequest
    ClientId
    RedirectURI
    (Maybe AccessTokenScope)
    (Maybe CSRFStateToken)

tokenRequest ::
     ClientId
  -> RedirectURI
  -> Maybe AccessTokenScope
  -> Maybe CSRFStateToken
  -> TokenRequest AuthorizationCode
tokenRequest client_id redirect_uri scope state =
  TokenRequest
    client_id redirect_uri scope state

sendRequest :: forall a. TokenRequest a
sendRequest 

-- If client is confidential or the client was issued client credentials
--   or similar, the client must authenticate with Authorization Server.
-- !!! Enforce this with types.

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


tokenByAuthorizationtoken ::
     AuthRequest
  -> TokenRequest
  -> Aff _ (Either TokenEndpointErrorResponse TokenEndpointSuccessResponse)
tokenByAuthorizationToken
  (AuthRequest)
  (TokenRequest)
  = do
  let authUri
  reqAuth

----------

-- 4.2: Implicit Grant
-- https://tools.ietf.org/html/rfc6749#section-4.2

-- Implicit grant type obtains an access token (no refresh token).
--   It is optimized for public clients using a particular redirection URI,
--   which is typically an in-browser JavaScript app.
-- No client authentication, requires resource owner to authenticate,
--   and a preregistered redirection URI.

-- 4.2.1: Authorization Request

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



















-- 5.1 Successful Response
-- https://tools.ietf.org/html/rfc6749#section-5.1

data TokenEndpointSuccessResponse a =
  { access_token :: a -- See 7.1: Access Token Types
  , token_type :: AccessTokenType
  , expires_in :: NullOrUndefined Seconds -- recommended
  , refresh_token :: NullOrUndefined RefreshToken
  , scope :: NullOrUndefined AccessScope
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
  , error_description :: NullOrUndefined String
  -- ^ optional, details in ASCII to assist client dev.
  , error_uri :: NullOrUndefined String -- !!! URI, not String
  -- ^ optional, URI of web page about the error
  }


-- 7.1 Access Token Types
-- https://tools.ietf.org/html/rfc6749#section-7.1

-- ??? Better way?
newtype AccessTokenType = AccessTokenType String






