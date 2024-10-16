import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import session from 'express-session';
import crypto from 'crypto';

// PKCE (Proof Key for Code Exchange)
// Function to generate a random code verifier
function generateCodeVerifier(): string {
  return base64URLEncode(crypto.randomBytes(32));
}

// Function to generate a code challenge from the code verifier
function generateCodeChallenge(codeVerifier: string): string {
  return base64URLEncode(sha256(codeVerifier));
}

// Helper functions
function sha256(buffer: string): Buffer {
  return crypto.createHash('sha256').update(buffer).digest();
}

function base64URLEncode(buffer: Buffer | string): string {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

const app = express();
const port = 4000;

const config = {
  // should be stored in a secure location, not hardcoded in client
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
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  req.session.codeVerifier = codeVerifier;

  const authorizationUrl = new URL(config.authorization_endpoint);
  authorizationUrl.searchParams.set('response_type', 'code');
  authorizationUrl.searchParams.set('client_id', config.client_id);
  authorizationUrl.searchParams.set('redirect_uri', config.redirect_uri);
  authorizationUrl.searchParams.set('scope', 'read write'); // Requesting 'read' and 'write' scopes
  // Generate a random state parameter for CSRF protection
  const state = uuidv4();
  req.session.state = state;
  authorizationUrl.searchParams.set('state', state);

  authorizationUrl.searchParams.set('code_challenge', codeChallenge);
  authorizationUrl.searchParams.set('code_challenge_method', 'S256');

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

  const codeVerifier = req.session.codeVerifier;
  req.session.codeVerifier = null;
  if (!codeVerifier) {
    return res.status(400).send('Code verifier not found in session');
  }

  const basicAuth = Buffer.from(`${config.client_id}:${config.client_secret}`).toString('base64')

  // Exchange the authorization code for an access token
  try {
    const response = await fetch(config.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basicAuth}`
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: config.redirect_uri,
        code_verifier: codeVerifier
      }),
    });
    const data = await response.json();

    if (data.error) {
      return res.status(400).send(`Error exchanging code for token: ${data.error_description || data.error}`);
    }

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

  const basicAuth = Buffer.from(`${config.client_id}:${config.client_secret}`).toString('base64');

  if (tokenData.expiration_time < Date.now()) {
    try {
      const response = await fetch(config.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${basicAuth}`,
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokenData.refresh_token,
        }),
      });
      const data = await response.json();

      if (data.error) {
        // Handle error (e.g., invalid refresh token)
        tokenData = null;
        return res.redirect('/authorize');
      }

      // Update token data
      tokenData.access_token = data.access_token;
      tokenData.refresh_token = data.refresh_token
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