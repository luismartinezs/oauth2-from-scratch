# References:
https://apps.abacus.ai/chatllm/?appId=162d480c22&convoId=6e35358c2
https://apps.abacus.ai/chatllm/?appId=13ee9b6d4&convoId=13a08adcc3

# how to run

Run auth server

`cd oauth2-auth-server ; bun i ; bun server.ts`

Run app server

`cd oauth2-client-app ; bun i ; bun client.ts`


# Auth flow (incomplete):

- missing in the below:
  - pass client_id and client_secret in an authorization header as base64 encoded string
  - store auth code along with redirect_uri and verify redirect_uri did not change when requesting access token
  - rotate refresh token after use

- user accesses http://localhost:4000/
- user clicks on "login"
- app server /authorize access
  - set auth params: response_type, client_d, redirect_uri, scope
  - create a `state` (random uuid) to prevent CSRF
- redirect to http://localhost:3000/authorize (auth server)
- auth server /authorize
  - requireLogin middleware
    - checks if request has user session, if it doesn't, redirect to /login with a redirect url search param
  - since there is no user session, we are redirected
- auth /login
  - send login form to client with POST method and action /login
    - with user, password and hidden redirect url input
- user submits form with correct user/password
- auth server /login POST: finds the user in the DB from user and password provided (user and password are somewhere in a DB, both user and password are probably hashed and salted), and adds the user to the request session, then redirects to the redirect url (/authorize)
- auth server /authorize, this time with user session
  - validates the request
  - sends auth form which posts to /authorize to client, with hidden inputs for auth params and a button to approve or deny
- client clicks on "approve"
- auth server /authorize POST:
  - if user had clicked "deny", then the redirect to redirect_uri (http://localhost:4000/callback) with no code and access denied error
  - if user clicked "approve":
    - find client in DB using client_id
    - create auth code and save it in DB along with client_id, user_id, and scope
    - set code and state as search params and redirect to callback url
- app server /callback
  - get code and state from request, if state is valid, delete it
  - fetch access token from auth server:
    - POST request to /token, providing code and other auth params: grant_type = 'authorization_code', redirect_uri, client_id, client_secret, and wait for response
      - auth server /token POST
        - grant type is 'authorization_code' so:
          - check that client credentials are valid
          - check that auth code provided is valid
          - generate access token and refresh token (random uuid) and store in DB
            - access token: user_id, scope and expiration time
            - refresh token: user_id, scope and client_id
          - delete auth code from DB
          - send json response to app server with access token and refresh token
  - store access and refresh tokens in app server, and redirect to /resource or wherever needs to be redirected after auth process
- app server /resource
  - if there is no access token, redirect to /authorize
  - if access token is expired, send POST requeest to /token endpoint with grant_type: 'refresh_token', then wait for response
    - auth server /token POST
      - grant type is 'refresh_token' so:
        - check that the refresh token is valid
        - generate a new access token and save in DB
        - return JSON response with the new access token
  - store access token in app server
  - send request to itself with bearer token (??)
  - if auth flow successful, send protected resource to client


# Security

- Ensure that refresh tokens are stored securely on both client and server sides
- On the client, avoid storing tokens in insecure storage like localStorage in the browser. Use HTTP-only cookies or secure storage mechanisms
- In addition to deleting used refresh tokens, you might maintain a blacklist to track invalidated tokens if using a persistent store, i.e. do not accept a refresh token that has been used before
- user must be able to revoke tokens, ie "logout"
- Since you're dealing with sensitive data (authorization codes, tokens), it's crucial to use HTTPS to encrypt the communication between the client and server. For development purposes, you can use self-signed certificates or tools like ngrok to secure your endpoints

# Prod libs

- Clerk auth
- Lucia auth [deprecated but usable (?)]
- Oslo = lightweight, runtime agnostic, and fully typed generic OAuth 2.0 client
- Artic = TypeScript library that provides OAuth 2.0 and OpenID Connect clients for major providers

# where to store data

## Client

- client_id, client_secret: securely in server, never expose to client. env vars, secure config files, secrets management service (hashicorp vault, aws secrets manager, google secrets manager...)
- oauth endpoints (auth, token): store as env to make sure they are easy to configure for each environment (dev, test, prod). Not sensitive
- redirect uri: store in env, use https
- access token and refresh token
  - server side: session store (encrypted cookie, server side session storage)
  - client side: use only for client only apps (SPA), browser memory, secure http only cookies. Avoid localStorage or sessionStorage (vulnerable to XSS)
  - mobile apps: IOS keychain service, Android encrypted shared preferences or keystore
- best practices: encrypt tokens if stored in client, use short lived access tokens and rotate refresh tokens, secure cookies (httponly, secure, samesite). avoid storing in plain text, browser storage
- state param for CSRF
  - server side: user session
  - SPA: in memory, avoid storing in persistent storage
- PKCE params
  - code verifier: user session on server. for SPA in memory (no browser storage)
  - code challenge: not sensitive

## Server

- user credentials: secure dedicated DB. hash and salt passwords before storing, never store in plain text. limit access to DB
- auth codes: in memory (single server), redis (distributed servers). short lifespan, one time use, store metadata with code (client id, user id, scopes, redirect uri, code challenge). Secure storage (encrypted)
- tokens
  - access tokens
    - stateless: JWT (self contained) + blacklist or list of revoked tokens
    - stateful (opaque, ie not explicitly containing metadata): secure DB or token store (redis)
  - refresh tokens: always in secure DB, include metadata
  - best practices: encryption at rest, secure DB access, token rotation, token expiration, revocation mechanism, audit logging (log token issuance, refresh, revocation)
- oAuth 2 secret / cryptographic keys: secure key management system: AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault..., limit access, rotate keys, backup keys securely
- code challenge: secure DB, in-memory. Associate with auth code, treat it securely, delete or invalidate when auth code expires or is used

# Auth flow (complete?)

- User accesses `http://localhost:4000/`
- User clicks on "Login with OAuth2": request to app server `/authorize` endpoint
  - Client application generates a **code verifier** and **code challenge** for PKCE
    - Uses `generateCodeVerifier()` and `generateCodeChallenge(codeVerifier)`
  - Stores the **code verifier** in the user's session (`req.session.codeVerifier`)
  - Generates a random **state** parameter for CSRF protection
    - Stores the **state** in the user's session (`req.session.state`)
  - Constructs the authorization URL with the following parameters:
    - `response_type=code`
    - `client_id=client123`
    - `redirect_uri=http://localhost:4000/callback`
    - `scope=read write`
    - `state=<generated state>`
    - `code_challenge=<generated code challenge>`
    - `code_challenge_method=S256`
  - Redirects the user's browser to the authorization server's `/authorize` endpoint with the constructed URL
- User's browser navigates to `http://localhost:3000/authorize` with query parameters
  - The URL includes parameters: `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`
- Authorization server checks if the user is logged in (`requireLogin` middleware)
  - Since the user is **not logged in**, the server redirects the user to the login page
    - Redirects to `/login?redirect=<encoded original /authorize URL>`
- User is presented with a login form at `http://localhost:3000/login`
- User enters username and password and submits the form (`POST /login`)
  - Enters `username=user` and `password=pass`
- Authorization server's `/login` handler processes the login
  - Authenticates the user by checking credentials against the in-memory `users` array
  - On successful authentication:
    - Sets `req.session.user` to the authenticated user
    - Redirects the user back to the URL specified in the `redirect` parameter (original `/authorize` URL)
- User is redirected back to `http://localhost:3000/authorize` with the original query parameters
- Authorization server's `/authorize` endpoint processes the request
  - Retrieves the client information based on `client_id`
  - Validates the `redirect_uri` matches one of the client's registered URIs
  - Displays an authorization page to the user asking to approve or deny access
    - Shows:
      - Application name (`Authorize client123`)
      - Requested scopes (`Requested Scopes: read write`)
      - Prompt: `Do you authorize the app to access your data?`
    - Provides "Approve" and "Deny" buttons
- User clicks on the "Approve" button (`POST /authorize` with `approve=yes`)
- Authorization server's `/authorize` POST handler processes the approval
  - Checks that `approve=yes`
  - Generates an **authorization code** (e.g., using `uuidv4()`)
  - Stores the authorization code along with associated data:
    - `client_id`
    - `user_id` (from `req.session.user`)
    - `scope`
    - `redirect_uri`
    - `code_challenge`
    - `code_challenge_method`
    - Stores in `authorizationCodes[code]`
  - Constructs a redirect URL to the client's `redirect_uri` (`http://localhost:4000/callback`) with query parameters:
    - `code=<authorization code>`
    - `state=<original state parameter>`
  - Redirects the user's browser to the constructed URL
- User's browser navigates to `http://localhost:4000/callback` with `code` and `state` query parameters
- Client application's `/callback` endpoint processes the request
  - Retrieves the `code` and `state` from query parameters
  - Verifies that the `state` matches the one stored in the session (`req.session.state`)
    - Protects against CSRF attacks
  - Retrieves the `codeVerifier` from the session (`req.session.codeVerifier`)
  - Constructs a POST request to the authorization server's `/token` endpoint to exchange the authorization code for an access token
    - Includes the following parameters:
      - `grant_type=authorization_code`
      - `code=<authorization code received>`
      - `redirect_uri=http://localhost:4000/callback`
      - `code_verifier=<code verifier from session>`
    - Adds an `Authorization` header with Basic authentication:
      - Encodes `client_id` and `client_secret` using Base64
  - Sends the POST request to `http://localhost:3000/token`
- Authorization server's `/token` endpoint processes the token request
  - Extracts `client_id` and `client_secret` from the `Authorization` header
  - Validates client credentials against the registered clients
  - Checks that only one authentication method is used (does not accept `client_id` in the body if already provided in the header)
  - Processes the request based on `grant_type`
    - Since `grant_type=authorization_code`, proceeds to handle authorization code grant
  - Validates the authorization code provided (`code`)
    - Checks if the code exists in `authorizationCodes` and matches the `client_id`
  - Validates that the `redirect_uri` matches the one stored with the authorization code
  - Validates the `code_verifier` against the stored `code_challenge` using the `code_challenge_method` (PKCE verification)
    - If `code_challenge_method=S256`, computes the code challenge from the `code_verifier` and compares it
  - Upon successful validation:
    - Generates an **access token** (e.g., using `uuidv4()`)
      - Sets an expiration time (e.g., 1 hour from now)
      - Stores the token along with associated data (`user_id`, `scope`, `expiration`)
    - Generates a **refresh token**
      - Stores it with expiration time (e.g., 30 days)
    - Deletes the used authorization code from `authorizationCodes`
    - Returns a JSON response with:
      - `access_token`
      - `token_type` (e.g., `Bearer`)
      - `expires_in` (e.g., `3600` seconds)
      - `refresh_token`
- Client application receives the token response from the authorization server
  - Stores the token data (`access_token`, `refresh_token`, `expires_in`, `expiration_time`)
  - Redirects the user to `/resource` to access the protected resource
- User navigates to `http://localhost:4000/resource`
- Client application's `/resource` endpoint attempts to access the protected resource
  - Checks if the stored access token is valid (not expired)
    - Compares current time with `tokenData.expiration_time`
  - If the access token is expired:
    - Constructs a POST request to the authorization server's `/token` endpoint to refresh the access token
      - Includes the following parameters:
        - `grant_type=refresh_token`
        - `refresh_token=<stored refresh token>`
      - Adds an `Authorization` header with Basic authentication:
        - Encodes `client_id` and `client_secret` using Base64
    - Sends the POST request to `http://localhost:3000/token`
    - Authorization server processes the refresh token grant:
      - Validates client credentials
      - Validates the refresh token
        - Checks if the refresh token exists and matches the `client_id`
        - Checks if the refresh token has expired
      - Generates a new access token and refresh token
      - Deletes the old refresh token (token rotation)
      - Returns a JSON response with the new tokens
    - Client application updates the stored token data with the new access token and refresh token
  - Constructs a GET request to the resource server's protected endpoint (`http://localhost:3000/resource`)
    - Adds an `Authorization` header with the Bearer token:
      - `Authorization: Bearer <access token>`
  - Sends the GET request to the resource server
- Resource server's `/resource` endpoint processes the request
  - Extracts the access token from the `Authorization` header
  - Validates the access token:
    - Checks if the token exists in `accessTokens` and has not expired
  - Checks if the token has the required scope (`read`)
    - If the token's scope does not include `read`, returns a `403 Forbidden` error
  - Retrieves the user data associated with the token
  - Returns the protected resource data in a JSON response
    - Example: `{ data: "Protected data for user" }`
- Client application receives the response from the resource server
  - Displays the protected resource data to the user
    - Renders a page with the resource data (e.g., `<pre>{ data: "Protected data for user" }</pre>`)