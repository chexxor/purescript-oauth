
# OAuth2 Spec

Following [RFC 6749: The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) as the OAuth2 spec.

## 1. Introduction

Not considered; N/A to PS Client code.

## 2: Client Registration

Nothing: Outside scope of OAuth2

### 2.1: Client Types

Defined in `Network.OAuth.Type`

### 2.2: Client Identifier

Defined in `Network.OAuth.Type`

### 2.3: Client Authentication

Defined in `Network.OAuth.Type`

### 2.4: Unregistered Clients

Out of Scope of OAuth 2.0

## 3: Protocol Endpoints

Defined in `Network.OAuth.Type`

### 3.1: Authorization Endpoint

Authorization Server:
 - must verify identity of resource owner
     e.g. username & password, session cookies
 - its URI may include a URI params
 - its URI may not use URI fragment
 - must communicate using TLS
 - may use POST method
 - must ignore URI params without value
 - must ignore unrecognized URI params
 - must not duplicate URL params

#### 3.1.1: Endpoint Response Type

`Network.OAuth.Type.(kind AuthorizationRequestType)`
`Network.OAuth.Type.AuthorizationRequestTypeToken`
`Network.OAuth.Type.authTokenRequestCode`
`Network.OAuth.Type.parseAuthTokenRequestCode`
`Network.OAuth.Type.authTokenTypeToken`
`Network.OAuth.Type.authTokenTypeCode`

Authorization Server must return `AuthorizationServerErrorResponse`
  if no response type received.

#### 3.1.2: Authorization Redirection Endpoint

Authorization Endpoint performs authentication of End-User.

Authorization Endpoint Server
 - must use TLS to communicate when `response_type` is
    "code" or "token" or similarly sensitive
 - must only respond with pre-registered redirection endpoints
   - only applies to public and confidential (implicit) clients
   - but should be required of all clients
 - may allow client to register multiple redirection endpoints
 - should require the client to provide a complete URI
    but, if not possible, may allow variable query string

Authorization Endpoint Server accepts a `redirect_uri` param by
  matching at least one of the pre-registered URIs,
  and must not redirect client's user-agent to invalid URI,
  and should inform the resource owner of the error.

Client must include `redirect_uri` param if they:
 - have registered multiple redirection URI
 - have registered only part of a redirection URI
 - have not pre-registered a redirection URI

#### 3.1.2.x:

To do.

### 3.2: Token Endpoint

`Network.OAuth.Type.TokenEndpointClient(..)`

The Token Endpoint is used by the client to obtain an access token
  by presenting its authorization grant or refresh token.

A Token Endpoint's URI may include a query string, which must be
  retained when sending requests, but must not include a URI fragment.

A Token Endpoint must communicate using TLS.
 - must ignore params having no value
 - must ignore unrecognized request params
 - must not support duplicate params

A client:
 - must use POST to request a token from the Token Endpoint.
 - must communicate with the Authorization Endpoint when
    making requests to the Token Endpoint.
 - may use the `client_id` param
 - must use the `client_id` param when unauthenticated and
    requesting an "authorization_code" from the Token Endpoint.

#### 3.2.x:

To do.

### 3.3: Access Token Scope

`Network.OAuth.Type.AccessScope(..)`

The Authorization and Token Endpoints may recognize a `scope` param.
The Authorization server:
 - may respond with a `scope` param to describe the token
 - must include the `scope` param if the issued access token
    has different scope than requested, the authorization server
 - must either fail the request or use a pre-defined default value
    if the client omits the `scope` param

## 4: Obtaining Authorization

`Network.OAuth.Types.(kind TokenRequestGrantType)`
`Network.OAuth.sendAuthRequest`
`Network.OAuth.sendTokenRequest`

To request an access token, the client obtains authorization from the
resource owner.  The authorization is expressed in the form of an
authorization grant, which the client uses to request the access
token.

Four grant types:
- authorization code
- implicit
- resource owner password credentials
- client credentials

### 4.1: Authorization Code Grant

`Network.OAuth.tokenByAuthorizationToken`

The authorization code grant type is used to obtain both access
  tokens and refresh tokens and is optimized for confidential clients.

Client must be capable of receiving incoming HTTP request
  and interacting with the resource owner's user-agent
  to obtain an authorization code grant.

#### 4.1.1: Authorization Request

`Network.OAuth.Type.AuthRequestArgs(..)`

#### 4.1.2: Authorization Response

`Network.OAuth.Type.AuthorizationEndpointSuccessResponse(..)`

-- Authorization Server:
--  Responds to authorization success with HTTP redirect response
--    containing the following params in the URI:
--   - `code`: must have short expiration (rec. <10 min),
--       client must use only once
--   - `state`: must be identical to `state` param received from client
--  Must not redirect to invalid redirection URI
--  Should inform resource owner of erroneous request
-- Responds to authorization error with `AuthorizationEndpointErrorResponse`

-- Client:
--  Must ignore unrecognized response params

##### 4.1.2.1: Error Response

`Network.OAuth.Type.AuthorizationEndpointErrorResponse(..)`


#### 4.1.3: Access Token Request

`Network.OAuth.Type.TokenRequestArgs(..)`

Client:
 Must encode params using "application/x-www-form-urlencoded" format
   and UTF-8 encoding and send to the Token Endpoint in the request body.

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

#### 4.1.4: Access Token Response

`Network.OAuth.Type.TokenEndpointSuccessResponse(..)`
`Network.OAuth.Type.TokenEndpointErrorResponse(..)`

If request is valid and authorized, responds with `TokenEndpointSuccessResponse`,
 else responds with `TokenEndpointErrorResponse`.


----------

### 4.2: Implicit Grant

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

