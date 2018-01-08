module App.Network.OAuth where

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


type ResourceOwner = String
type AuthorizationServer = String
type ResourceServer = String

-- 2: Client Registration
-- https://tools.ietf.org/html/rfc6749#section-2
-- Nothing: Outside scope of OAuth2

-- 2.1: Client Types
-- https://tools.ietf.org/html/rfc6749#section-2.1

-- Example client profiles:
-- - traditional web app
-- - SPA web app
-- - native app
-- May use credentials, like password or pub/prv key pair.
data ClientType =
    Confidential
  | Public

-- 2.2: Client Identifier
-- https://tools.ietf.org/html/rfc6749#section-2.2

type ClientId = String

-- 2.3: Client Authentication
-- https://tools.ietf.org/html/rfc6749#section-2.3
-- Passing creds via Header is preferred to via Body.
-- A client may use only one kind of authentication scheme.
data ClientWithAuthentication =
  ClientWithAuthentication String -- password or public key

-- 3: Endpoints
-- https://tools.ietf.org/html/rfc6749#section-3

-- Auth server endpoints
newtype AuthorizationEndpoint = AuthorizationEndpoint String
newtype TokenEndpoint = TokenEndpoint String

-- Client endpoints
type ClientTokenReceptionEndpoint = String
-- Called "RedirectionEndpoint" in other OAuth implementations

-- 3.1: Authorization Endpoint
-- https://tools.ietf.org/html/rfc6749#section-3.1

-- Authorization Server:
-- - must verify identity of resource owner
--     e.g. username & password, session cookies
-- - its URL may include a URL params
-- - its URL may not use URL fragment
-- - must communicate using TLS
-- - may use POST method
-- - must ignore URL params without value
-- - must ignore unrecognized URL params
-- - must not duplicate URL params

-- 3.1.1: Authorization Endpoint Response Type
-- https://tools.ietf.org/html/rfc6749#section-3.1.1

-- Client must specify the desired response type, as
--   Authorization Endpoint is used for multiple flows.
-- Authorization Server must return AuthorizationServerErrorResponse
--   if no response type received.

-- ??? Delete?
-- data AuthorizationEndpointResponseType =
--     AuthorizationCode -- authorization flow
--   | AccessToken -- implicit grant flow
--   -- | CustomResponseType String -- ignore for now

-- 3.1.2: Authorization Endpoint Redirection
-- https://tools.ietf.org/html/rfc6749#section-3.1.2

-- Authorization Endpoint performs authentication of End-User.
-- Authorization Endpoint Server
--  - must use TLS to communicate when `response_type` is
--     "code" or "token" or similarly sensitive
--  - must only respond with pre-registered redirection endpoints
--    - only applies to public and confidential (implicit) clients
--    - but should be required of all clients
--  - may allow client to register multiple redirection endpoints
--  - should require the client to provide a complete URI
--     but, if not possible, may allow variable query string

-- Authorization Endpoint Server accepts a `redirect_uri` param by
--   matching at least one of the pre-registered URIs,
--   and must not redirect client's user-agent to invalid URI,
--   and should inform the resource owner of the error.

-- Client must include `redirect_uri` param if they:
--  - have registered multiple redirection URI
--  - have registered only part of a redirection URI
--  - have not pre-registered a redirection URI

-- 3.2: Token Endpoint
-- https://tools.ietf.org/html/rfc6749#section-3.2

-- The Token Endpoint is used by the client to obtain an access token
--   by presenting its authorization grant or refresh token.

-- A Token Endpoint's URI may include a query string, which must be
--   retained when sending requests, but must not include a URI fragment.

-- A Token Endpoint must listen and respond using TLS.
--  - must ignore params having no value
--  - must ignore unrecognized request params
--  - must not support duplicate params

-- A client:
--  - must use POST to request a token from the Token Endpoint.
--  - must communicate with the Authorization Endpoint when
--     making requests to the Token Endpoint.
--  - may use the `client_id` param
--  - must use the `client_id` param when unauthenticated and
--     requesting an "authorization_code" from the Token Endpoint.

-- 3.3: Access Token Scope
-- https://tools.ietf.org/html/rfc6749#section-3.3

-- The Authorization and Token Endpoints may recognize a `scope` param.
-- The Authorization server:
--  - may respond with a `scope` param to describe the token
--  - must include the `scope` param if the issued access token
--     has different scope than requested, the authorization server
--  - must either fail the request or use a pre-defined default value
--     if the client omits the `scope` param

newtype AccessScope = AccessScope (Set String)

-- 4: Obtaining Authorization
-- https://tools.ietf.org/html/rfc6749#section-4

-- To request an access token, the client obtains an Authorization Grant
--  from the resource owner.
-- Four Authorization Grant types:
-- - Authorization Code
-- - Implicit
-- - Resource Owner Password Credentials
-- - Client Credentials
-- - Custom (extension)

data AuthorizationGrantType
  = AuthorizationCode
  | Implicit
  | ResourceOwnerPasswordCreds
  | ClientCredentials
  -- | Custom -- Implement when have use-case

-- 4.1: Obtaining Authorization
-- https://tools.ietf.org/html/rfc6749#section-4.1

-- Client must be capable of receiving incoming HTTP request
--  and interacting with the resource owner's user-agent
--  to obtain an authorization code grant.

newtype AuthRequest (responseType :: AuthorizationRequestType) =
  AuthRequest
    -- AuthorizationEndpoint ??? Include in data type?
    (AuthRequestArgs responseType)
    (AuthRequestArgs responseType -> Eff eff Unit)
    -- ^ Spawn browser or child window to send user-agent to authorization server.
    ((Either AuthorizationEndpointErrorResponse (AuthorizationEndpointSuccessResponse responseType) -> Eff eff Unit)
      -> Eff eff Unit
    )
    -- ^ Listen for HTTP request or child window event having authorization token.

reqAuthServer ::
  forall eff responseType.
     AuthRequest responseType
  -> (Either AuthorizationEndpointErrorResponse (AuthorizationEndpointSuccessResponse responseType) -> Eff eff Unit)
  -> Eff eff Unit
reqAuthServer
  (AuthRequest
    client_id redirect_uri
    scope state
    openAuth listenForAuth
  ) handleResponse = do
  openAuth authReq
  listenForAuth handleResponse
  where
    authReq = AuthRequestArgs client_id redirect_uri scope state

reqAuthServer'
  :: forall eff responseType.
     AuthRequest responseType
  -> ContT Unit (Eff eff)
       (Either (AuthorizationEndpointErrorResponse (AuthorizationEndpointSuccessResponse responseType)))
reqAuthServer' authRequest =
  ContT $ reqAuthServer authRequest

authRequestForCLIApp ::
  forall eff responseType.
     ClientId
  -> RedirectURI
  -> Maybe AccessTokenScope
  -> Maybe CSRFStateToken
  -> AuthRequest responseType
authRequestForCLIApp client_id redirect_uri scope state =
  AuthRequest
    client_id redirect_uri
    scope state
    spawnBrowser listenForAuth
  where
    spawnBrowser :: AuthRequestArgs responsetype -> Eff (cp :: CHILD_PROCESS | eff) ChildProcess
    spawnBrowser authRequest =
        ChildProcess.spawn (fst openCmd)
          (snd openCmd <> print <<< authReqAsQuery authReq)
          defaultSpawnOptions
        where
          authReqAsQuery :: AuthRequestArgs responseType -> Query
          authReqAsQuery (AuthRequestArgs client_id
            redirect_uri scope state) = Query
              Cons (Tuple "request_type" $ Just "code") -- !!! token?
                $ Cons (Tuple "client_id" $ Just client_id)
                $ Cons (Tuple "redirect_uri" $ Just redirect_uri)
                $ Nil
                <> (maybe mempty (\scope' -> Tuple "scope" $ Just scope') scope)
                <> (maybe mempty (\state' -> Tuple "state" $ Just state') state)
          openCmd = Desktops.browserOpenCmdForDesktop
              $ mostCommonDesktopForPlatform $ fromMaybe Linux platform
    listenForAuth ::
      (Either AuthorizationEndpointErrorResponse (AuthorizationEndpointSuccessResponse tokenType)
        -> Eff eff Unit
      )
      -> Eff eff Unit
    listenForAuth cb = do
      server <- createServer $ listenHandler cb
      !!! Move to util, consider using lens instead.
      let portFromUri (URI _ (HierarchicalPart maybeAuthority) _) _ _) =
            maybeAuthority >>= firstPortFromAuthority
              where
                portFromPair (Tuple _ maybePort) = maybePort
                firstPortFromAuthority (Authority _ hostPorts) =
                  head hostPorts >>= portFromPair
      -- !!! Clean up server when done.
      listen server
          { hostname: "localhost"
          , port: portFromUri redirect_uri
          , backlog: Nothing
          } $ void do
        log "Listening on port 8080 at " <> print redirect_uri
          <> " for Authorization Token."
      where
        listenHandler cb' req res = do
          -- log (requestMethod req <> " " <> requestURL req)
          let outputStream = responseAsStream res
          let parsedUri = parse $ requestURL req
          case requestMethod req, parsedUri of
            "GET" url, Right uri@(URI _ h (Just query) _) -> do
               when $ 0 == indexOf (print redirect_uri) (print h)
               let authRes = authResponseFromQuery query
               _ <- cb' $ Right authRes
               setStatusCode res 200
               end outputStream (pure unit)
            -- !!! Better error messages
            _, _ -> unsafeCrashWith "Failed to receive authorization token."
               setStatusCode res 400
               end outputStream (pure unit)
        authResponseFromQuery :: Query -> Either String (AuthorizationEndpointSuccessResponse tokenType)
        authResponseFromQuery (Query kvs) =
          (find "code" kvs # note "No authorization code in response")
          >>= parseAuthTokenRequestCode
          <$>
          (\code ->
            AuthorizationEndpointSuccessResponse $ Tuple code (find "state" kvs)
          )

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
-- https://tools.ietf.org/html/rfc6749#section-4.1.2

-- Authorization Server
--  Responds to authorization success with HTTP redirect response
--    containing the following params in the URI:
--   - `code`: must have short expiration (rec. <10 min),
--       client must use only once
--   - `state`: must be identical to `state` param received from client
--  Must not redirect to invalid redirection URI
--  Should inform resource owner of erroneous request
-- Responds to authorization error with `AuthorizationEndpointErrorResponse`

newtype AuthorizationEndpointSuccessResponse (tokenType :: AuthorizationRequestType)
  = AuthorizationEndpointSuccessResponse
    (Tuple (AuthorizationRequestTypeToken tokenType) (Maybe CSRFStateToken))

data AuthorizationEndpointErrorCode
  = InvalidRequest -- invalid_request
  | UnauthorizedClient -- unauthorized_client
  | AccessDenied -- access_denied
  | UnsupportedResponseType -- unsupported_response_type
  | InvalidScope -- invalid_scope
  | ServerError -- server_error
  | TemporarilyUnavailable -- temporarily_unavailable

-- !!! Check code to ensure this is handled properly.

data AuthorizationEndpointErrorResponse a =
  { error :: AuthorizationEndpointErrorCode
  , error_description :: NullOrUndefined String
  -- ^ optional, details in ASCII to assist client dev
  , error_uri :: NullOrUndefined String -- !!! URI, not String
  -- ^ optional, URI of web page about the error
  , state :: NullOrUndefined CSRFStateToken
  -- ^ required if `state` was in request. Must be identical
  }

-- Client:
--  - must ignore unrecognized response params

-- 4.1.3: Access Token Request
-- https://tools.ietf.org/html/rfc6749#section-4.1.3

-- Client sends request to Token Endpoint having params:
--  - `grant_type`: value="authorization_code"
--  - `code`: the authorization code received from Authorization Server
--  - `redirect_uri`: required only if this param was included
--      in authorization request. Must be identical to that one.
--  - `client_id`: required only if didn't authenticate with Authorization Server

--foreign import kind TokenRequestType
--foreign import AuthorizationCode :: TokenRequestType
--foreign import AccessToken :: TokenRequestType

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
