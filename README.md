Run auth server

`cd oauth2-auth-server ; bun i ; bun server.ts`

Run app server

`cd oauth2-client-app ; bun i ; bun client.ts`


Auth flow:

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