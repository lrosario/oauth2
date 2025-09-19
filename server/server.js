const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3001;

// Production CORS configuration
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://oauth-playground-client.onrender.com'] 
    : ['http://localhost:3000'],
  credentials: true
};

// Configuração de middleware
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Chave secreta para assinar JWTs
const JWT_SECRET = process.env.JWT_SECRET || 'oauth-playground-secret-key';

// Determine redirect URI based on environment
const REDIRECT_URI = process.env.CLIENT_REDIRECT_URI || 'http://localhost:3000/callback';

// Armazenamento em memória (em produção seria um banco de dados)
const clients = {
  'demo-client': {
    client_id: 'demo-client',
    client_secret: 'demo-secret',
    redirect_uris: [REDIRECT_URI],
    grant_types: ['authorization_code', 'client_credentials']
  }
};

const authorizationCodes = {};
const accessTokens = {};
const refreshTokens = {};

// Utilitários
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateAuthCode() {
  return crypto.randomBytes(16).toString('hex');
}

function validateClient(client_id, client_secret = null) {
  const client = clients[client_id];
  if (!client) return false;
  if (client_secret && client.client_secret !== client_secret) return false;
  return client;
}

function generateJWT(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

function verifyJWT(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Endpoints OAuth 2.0

// 1. Authorization Endpoint (Authorization Code & PKCE)
app.get('/oauth/authorize', (req, res) => {
  const {
    client_id,
    redirect_uri,
    response_type,
    scope = 'read',
    state,
    code_challenge,
    code_challenge_method
  } = req.query;

  console.log('Authorization request:', req.query);

  // Validações básicas
  if (!client_id || !redirect_uri || response_type !== 'code') {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing or invalid parameters'
    });
  }

  const client = validateClient(client_id);
  if (!client) {
    return res.status(400).json({
      error: 'invalid_client',
      error_description: 'Invalid client_id'
    });
  }

  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Invalid redirect_uri'
    });
  }

  // Gerar código de autorização
  const authCode = generateAuthCode();
  const codeData = {
    client_id,
    redirect_uri,
    scope,
    expires_at: Date.now() + 10 * 60 * 1000, // 10 minutos
    used: false
  };

  // Se for PKCE, armazenar o code_challenge
  if (code_challenge) {
    codeData.code_challenge = code_challenge;
    codeData.code_challenge_method = code_challenge_method || 'S256';
  }

  authorizationCodes[authCode] = codeData;

  console.log('Generated auth code:', authCode, codeData);

  // Simular tela de autorização - em uma aplicação real seria uma página HTML
  const authUrl = `${redirect_uri}?code=${authCode}${state ? `&state=${state}` : ''}`;
  
  // Retornar dados para o playground mostrar o processo
  res.json({
    message: 'Authorization successful',
    authorization_code: authCode,
    redirect_url: authUrl,
    expires_in: 600,
    flow_type: code_challenge ? 'PKCE' : 'Authorization Code'
  });
});

// 2. Token Endpoint
app.post('/oauth/token', (req, res) => {
  const {
    grant_type,
    client_id,
    client_secret,
    code,
    redirect_uri,
    code_verifier,
    scope = 'read'
  } = req.body;

  console.log('Token request:', req.body);

  if (!grant_type) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing grant_type'
    });
  }

  // Authorization Code Flow
  if (grant_type === 'authorization_code') {
    if (!code || !client_id || !redirect_uri) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters'
      });
    }

    const codeData = authorizationCodes[code];
    if (!codeData || codeData.used || codeData.expires_at < Date.now()) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      });
    }

    if (codeData.client_id !== client_id || codeData.redirect_uri !== redirect_uri) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Code was issued to another client'
      });
    }

    // Verificar PKCE se aplicável
    if (codeData.code_challenge) {
      if (!code_verifier) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing code_verifier for PKCE flow'
        });
      }

      const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (hash !== codeData.code_challenge) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid code_verifier'
        });
      }
    } else {
      // Authorization Code tradicional requer client_secret
      if (!validateClient(client_id, client_secret)) {
        return res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials'
        });
      }
    }

    // Marcar código como usado
    codeData.used = true;

    // Gerar tokens
    const accessToken = generateJWT({
      client_id,
      scope: codeData.scope,
      token_type: 'access_token'
    });

    const refreshToken = generateToken();

    accessTokens[accessToken] = {
      client_id,
      scope: codeData.scope,
      expires_at: Date.now() + 3600 * 1000 // 1 hora
    };

    refreshTokens[refreshToken] = {
      client_id,
      scope: codeData.scope,
      access_token: accessToken
    };

    console.log('Generated tokens for authorization code flow');

    return res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: codeData.scope
    });
  }

  // Client Credentials Flow
  if (grant_type === 'client_credentials') {
    if (!client_id || !client_secret) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing client credentials'
      });
    }

    if (!validateClient(client_id, client_secret)) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }

    const accessToken = generateJWT({
      client_id,
      scope,
      token_type: 'access_token'
    });

    accessTokens[accessToken] = {
      client_id,
      scope,
      expires_at: Date.now() + 3600 * 1000 // 1 hora
    };

    console.log('Generated token for client credentials flow');

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope
    });
  }

  res.status(400).json({
    error: 'unsupported_grant_type',
    error_description: 'Unsupported grant type'
  });
});

// 3. Token Introspection
app.post('/oauth/introspect', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.json({ active: false });
  }

  const tokenData = accessTokens[token];
  if (!tokenData || tokenData.expires_at < Date.now()) {
    return res.json({ active: false });
  }

  const payload = verifyJWT(token);
  if (!payload) {
    return res.json({ active: false });
  }

  res.json({
    active: true,
    client_id: tokenData.client_id,
    scope: tokenData.scope,
    exp: Math.floor(tokenData.expires_at / 1000)
  });
});

// 4. Protected Resource Example
app.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Missing or invalid token'
    });
  }

  const token = authHeader.substring(7);
  const tokenData = accessTokens[token];

  if (!tokenData || tokenData.expires_at < Date.now()) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Token expired or invalid'
    });
  }

  const payload = verifyJWT(token);
  if (!payload) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid token signature'
    });
  }

  res.json({
    user_id: 'demo-user',
    name: 'Demo User',
    email: 'demo@example.com',
    scope: tokenData.scope,
    client_id: tokenData.client_id
  });
});

// 5. Client Registration Info (para o playground)
app.get('/oauth/clients/demo', (req, res) => {
  res.json({
    client_id: 'demo-client',
    client_secret: 'demo-secret',
    redirect_uris: [REDIRECT_URI],
    grant_types: ['authorization_code', 'client_credentials'],
    scopes: ['read', 'write']
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', server: 'OAuth Playground Server' });
});

app.listen(PORT, () => {
  console.log(`OAuth Playground Server running on http://localhost:${PORT}`);
  console.log('Available endpoints:');
  console.log('  - GET  /oauth/authorize');
  console.log('  - POST /oauth/token');
  console.log('  - POST /oauth/introspect');
  console.log('  - GET  /api/profile');
  console.log('  - GET  /oauth/clients/demo');
});
