import express, { Request, Response } from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const port = 3000;

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
      <div><button name="approve" value="yes" type="submit">Approve</button></div>
      <div><button name="approve" value="no" type="submit">Deny</button></div>
    </form>
  `);
});

app.post('/authorize', requireLogin, (req: Request, res: Response) => {
  const { client_id, redirect_uri, response_type, state, scope, approve } = req.body;

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
  authorizationCodes[code] = {
    client_id,
    user_id: req.session.user.id,
    scope,
  };

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  res.redirect(url.toString());
});

// Token endpoint
app.post('/token', (req: Request, res: Response) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;

  if (grant_type === 'authorization_code') {
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
    // Generate new access token
    const accessToken = uuidv4();
    const expiresIn = 3600; // Expires in 1 hour
    const expirationTime = Date.now() + expiresIn * 1000;

    accessTokens[accessToken] = {
      user_id: storedRefreshToken.user_id,
      scope: storedRefreshToken.scope,
      expiration: expirationTime,
    };

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
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