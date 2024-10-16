import express, { Request, Response } from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

function base64URLEncode(buffer: Buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}


const app = express();
const port = 3000;
const REFRESH_TOKEN_LIFETIME_MS = 1000 * 60 * 60 * 24 * 30; // 30 days

// In-memory storage (for demo purposes)
const users = [{ id: '1', username: 'user', password: 'pass' }];
const clients = [
  {
    client_id: 'client123',
    client_secret: 'secret456',
    redirect_uris: ['http://localhost:4000/callback'],
  },
];
const authorizationCodes: Record<string, any> = {};
const accessTokens: Record<string, any> = {};
const refreshTokens: Record<string, any> = {};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: 'oauth2-secret',
    resave: false,
    saveUninitialized: true,
  })
);

// Middleware to require login
function requireLogin(req: Request, res: Response, next: any) {
  if (!req.session.user) {
    res.redirect(
      `/login?redirect=${encodeURIComponent(req.originalUrl)}`
    );
  } else {
    next();
  }
}

// Login route
app.get('/login', (req: Request, res: Response) => {
  res.send(`
    <h2>Login</h2>
    <form method="POST" action="/login">
      <input type="hidden" name="redirect" value="${req.query.redirect || '/'}" />
      <div><input name="username" placeholder="Username" /></div>
      <div><input name="password" placeholder="Password" type="password" /></div>
      <div><button type="submit">Login</button></div>
    </form>
  `);
});

app.post('/login', (req: Request, res: Response) => {
  const { username, password, redirect } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );
  if (user) {
    req.session.user = user;
    res.redirect(redirect || '/');
  } else {
    res.send('Invalid credentials');
  }
});

// Authorization endpoint
app.get('/authorize', requireLogin, (req: Request, res: Response) => {
  const client = clients.find(
    (c) => c.client_id === req.query.client_id
  );
  if (!client) {
    return res.status(400).send('Unknown client');
  }
  if (
    !client.redirect_uris.includes(req.query.redirect_uri as string)
  ) {
    return res.status(400).send('Invalid redirect URI');
  }
  const scope = req.query.scope || '';
  res.send(`
    <h2>Authorize ${client.client_id}</h2>
    <p>Requested Scopes: ${scope}</p>
    <p>Do you authorize the app to access your data?</p>
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="${client.client_id}" />
      <input type="hidden" name="redirect_uri" value="${req.query.redirect_uri}" />
      <input type="hidden" name="response_type" value="${req.query.response_type}" />
      <input type="hidden" name="state" value="${req.query.state || ''}" />
      <input type="hidden" name="scope" value="${scope}" />
      <input type="hidden" name="code_challenge" value="${req.query.code_challenge || ''}" />
      <input type="hidden" name="code_challenge_method" value="${req.query.code_challenge_method || ''}" />
      <div><button name="approve" value="yes" type="submit">Approve</button></div>
      <div><button name="approve" value="no" type="submit">Deny</button></div>
    </form>
  `);
});

app.post('/authorize', requireLogin, (req: Request, res: Response) => {
  const { client_id, redirect_uri, response_type, state, scope, approve, code_challenge,
    code_challenge_method } = req.body;

  if (approve !== 'yes') {
    const url = new URL(redirect_uri);
    url.searchParams.set('error', 'access_denied');
    if (state) url.searchParams.set('state', state);
    return res.redirect(url.toString());
  }

  const client = clients.find((c) => c.client_id === client_id);
  if (!client) {
    return res.status(400).send('Unknown client');
  }

  const code = uuidv4();
  // Store the authorization code along with redirect_uri
  authorizationCodes[code] = {
    client_id,
    user_id: req.session.user.id,
    scope,
    redirect_uri,
    code_challenge,
    code_challenge_method
  };

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  res.redirect(url.toString());
});

// Token endpoint
app.post('/token', (req: Request, res: Response) => {
  const authHeader = req.headers['authorization']
  let clientId, clientSecret

  if (authHeader) {
    const match = authHeader.match(/^Basic\s+(.*)$/);
    if (match) {
      const token = Buffer.from(match[1], 'base64').toString();
      [clientId, clientSecret] = token.split(':');
    } else {
      return res.status(400).send('Invalid Authorization Header');
    }
  } else {
    // If no Authorization header provided
    return res.status(401).send('Missing Authorization Header');
  }

  if (req.body.client_id || req.body.client_secret) {
    return res.status(400).send('Multiple authentication methods are not allowed');
  }

  const { grant_type, code, redirect_uri, refresh_token, code_verifier } = req.body;

  if (grant_type === 'authorization_code') {
    if (!code || !redirect_uri || !code_verifier) {
      return res.status(400).send('Missing required parameters');
    }

    const client = clients.find(
      (c) =>
        c.client_id === client_id && c.client_secret === client_secret
    );
    if (!client) {
      return res.status(400).send('Invalid client credentials');
    }

    const authCode = authorizationCodes[code];
    if (!authCode || authCode.client_id !== client_id) {
      return res.status(400).send('Invalid authorization code');
    }

    if (authCode.redirect_uri !== redirect_uri) {
      return res.status(400).send('Invalid redirect URI');
    }

    if (authCode.code_challenge) {
      // If code_challenge_method is 'S256'
      if (authCode.code_challenge_method === 'S256') {
        const computedChallenge = base64URLEncode(
          crypto.createHash('sha256').update(code_verifier).digest()
        );
        if (computedChallenge !== authCode.code_challenge) {
          return res.status(400).send('Invalid code verifier');
        }
      } else if (authCode.code_challenge_method === 'plain') {
        // If code_challenge_method is 'plain', code_verifier must match code_challenge
        if (code_verifier !== authCode.code_challenge) {
          return res.status(400).send('Invalid code verifier');
        }
      } else {
        return res.status(400).send('Unsupported code_challenge_method');
      }
    } else {
      // If no code_challenge was stored, PKCE is required
      return res.status(400).send('PKCE verification failed');
    }

    const accessToken = uuidv4();
    const expiresIn = 3600; // Expires in 1 hour
    const expirationTime = Date.now() + expiresIn * 1000;

    accessTokens[accessToken] = {
      user_id: authCode.user_id,
      scope: authCode.scope,
      expiration: expirationTime,
    };

    // Generate refresh token
    const refreshToken = uuidv4();
    refreshTokens[refreshToken] = {
      user_id: authCode.user_id,
      client_id,
      scope: authCode.scope,
      expiration: Date.now() + REFRESH_TOKEN_LIFETIME_MS,
    };

    // Delete the used authorization code
    delete authorizationCodes[code];

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshToken,
    });
  } else if (grant_type === 'refresh_token') {
    // Handle refresh token grant
    const storedRefreshToken = refreshTokens[refresh_token];
    if (!storedRefreshToken || storedRefreshToken.client_id !== client_id) {
      return res.status(400).send('Invalid refresh token');
    }

    if (storedRefreshToken.expiration < Date.now()) {
      delete refreshTokens[refresh_token];
      return res.status(400).send('Refresh token has expired');
    }

    delete refreshTokens[refresh_token];

    // Generate new access token
    const accessToken = uuidv4();
    const expiresIn = 3600; // Expires in 1 hour
    const expirationTime = Date.now() + expiresIn * 1000;

    accessTokens[accessToken] = {
      user_id: storedRefreshToken.user_id,
      scope: storedRefreshToken.scope,
      expiration: expirationTime,
    };

    // rotate refresh token after use
    const newRefreshToken = uuidv4();
    refreshTokens[newRefreshToken] = {
      user_id: storedRefreshToken.user_id,
      client_id,
      scope: storedRefreshToken.scope,
      expiration: Date.now() + REFRESH_TOKEN_LIFETIME_MS,
    };

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: newRefreshToken
    });
  } else {
    return res.status(400).send('Unsupported grant type');
  }
});

// Protected resource endpoint
app.get('/resource', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Missing or invalid authorization header');
  }

  const token = authHeader.slice('Bearer '.length);
  const tokenData = accessTokens[token];

  if (!tokenData) {
    return res.status(401).send('Invalid access token');
  }

  // Check if token has expired
  if (tokenData.expiration < Date.now()) {
    return res.status(401).send('Access token has expired');
  }

  if (!tokenData.scope.includes('read')) {
    return res.status(403).send('Insufficient scope');
  }

  const user = users.find((u) => u.id === tokenData.user_id);
  res.json({ data: `Protected data for ${user?.username}` });
});

app.listen(port, () => {
  console.log(`Authorization server running at http://localhost:${port}`);
});