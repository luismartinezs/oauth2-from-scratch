import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import session from 'express-session';

const app = express();
const port = 4000;

const config = {
  client_id: 'client123',
  client_secret: 'secret456',
  authorization_endpoint: 'http://localhost:3000/authorize',
  token_endpoint: 'http://localhost:3000/token',
  redirect_uri: 'http://localhost:4000/callback',
};

interface TokenData {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  expiration_time: number;
}

let tokenData: TokenData | null = null;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: 'client-secret',
    resave: false,
    saveUninitialized: true,
  })
);

// Main page
app.get('/', (req: Request, res: Response) => {
  res.send(`
    <h2>Client Application</h2>
    <a href="/authorize">Login with OAuth2</a>
  `);
});

// Redirect the user to the authorization server
app.get('/authorize', (req: Request, res: Response) => {
  const authorizationUrl = new URL(config.authorization_endpoint);
  authorizationUrl.searchParams.set('response_type', 'code');
  authorizationUrl.searchParams.set('client_id', config.client_id);
  authorizationUrl.searchParams.set('redirect_uri', config.redirect_uri);
  authorizationUrl.searchParams.set('scope', 'read write'); // Requesting 'read' and 'write' scopes
  // Generate a random state parameter for CSRF protection
  const state = uuidv4();
  req.session.state = state;
  authorizationUrl.searchParams.set('state', state);

  res.redirect(authorizationUrl.toString());
});

// Handle the authorization server's response
app.get('/callback', async (req: Request, res: Response) => {
  const { code, state } = req.query;
  if (!code) {
    return res.status(400).send('Authorization code not found');
  }

  if (state !== req.session.state) {
    return res.status(400).send('Invalid state parameter');
  }

  req.session.state = null;

  // Exchange the authorization code for an access token
  try {
    const response = await fetch(config.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: config.redirect_uri,
        client_id: config.client_id,
        client_secret: config.client_secret,
      }),
    });
    const data = await response.json();
    tokenData = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      token_type: data.token_type,
      expires_in: data.expires_in,
      expiration_time: Date.now() + data.expires_in * 1000,
    };

    res.redirect('/resource');
  } catch (error) {
    res.status(500).send('Error exchanging code for token');
  }
});

// Access a protected resource
app.get('/resource', async (req: Request, res: Response) => {
  if (!tokenData) {
    return res.redirect('/authorize');
  }

  if (tokenData.expiration_time < Date.now()) {
    try {
      const response = await fetch(config.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokenData.refresh_token,
          client_id: config.client_id,
          client_secret: config.client_secret,
        }),
      });
      const data = await response.json();

      // Update token data
      tokenData.access_token = data.access_token;
      tokenData.expires_in = data.expires_in;
      tokenData.expiration_time = Date.now() + data.expires_in * 1000;
    } catch (error) {
      return res.status(500).send('Error refreshing access token');
    }
  }

  try {
    const response = await fetch('http://localhost:3000/resource', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });
    if (response.status === 401) {
      // Token might be invalid
      tokenData = null;
      return res.redirect('/authorize');
    }
    const data = await response.json();
    res.send(`<h2>Protected Resource</h2><pre>${JSON.stringify(data)}</pre>`);
  } catch (error) {
    res.status(500).send('Error accessing resource');
  }
});

// Start the client server
try {
  app.listen(port, () => {
    console.log(`Client app running at http://localhost:${port}`);
  });
} catch (error) {
  console.error('Error starting the server:', error);
}