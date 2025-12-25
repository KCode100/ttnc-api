require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const https = require('https');
const crypto = require('crypto');
const { parseStringPromise } = require('xml2js');

// ============ CONFIGURATION ============

const REQUIRED_ENV_VARS = ['TTNC_USERNAME', 'TTNC_PASSWORD', 'TTNC_VKEY', 'TTNC_NUMBER', 'API_KEY'];

function validateEnv() {
  const missing = REQUIRED_ENV_VARS.filter(key => !process.env[key]);
  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:', missing.join(', '));
    process.exit(1);
  }
  
  if (process.env.API_KEY.length < 32) {
    console.error('❌ API_KEY must be at least 32 characters for security');
    process.exit(1);
  }
  
  console.log('✅ Environment validated');
}

const CONFIG = {
  port: parseInt(process.env.PORT, 10) || 3000,
  apiKey: process.env.API_KEY,
  ttnc: {
    username: process.env.TTNC_USERNAME,
    password: process.env.TTNC_PASSWORD,
    vkey: process.env.TTNC_VKEY,
    number: process.env.TTNC_NUMBER,
    endpoint: 'xml.ttnc.co.uk',
    timeoutMs: 30000
  },
  rateLimit: {
    windowMs: 60 * 1000, // 1 minute
    max: 30 // requests per window
  }
};

// ============ LOGGING ============

function log(level, message, meta = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...meta
  };
  console.log(JSON.stringify(entry));
}

// ============ EXPRESS APP ============

const app = express();

// Trust proxy (for rate limiting behind Railway/Render)
app.set('trust proxy', 1);

// Security headers
app.use(helmet());

// CORS - configure for your frontend domain in production
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'X-API-Key']
}));

// Parse JSON with size limit
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: CONFIG.rateLimit.windowMs,
  max: CONFIG.rateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
  handler: (req, res, next, options) => {
    log('warn', 'Rate limit exceeded', { ip: req.ip });
    res.status(429).json(options.message);
  }
});
app.use(limiter);

// Request ID middleware
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.requestId);
  next();
});

// ============ AUTHENTICATION ============

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) {
    // Still do comparison to prevent timing attacks
    crypto.timingSafeEqual(Buffer.from(a), Buffer.from(a));
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    log('warn', 'Missing API key', { requestId: req.requestId, ip: req.ip });
    return res.status(401).json({ error: 'Missing API key' });
  }
  
  if (!timingSafeEqual(apiKey, CONFIG.apiKey)) {
    log('warn', 'Invalid API key', { requestId: req.requestId, ip: req.ip });
    return res.status(403).json({ error: 'Invalid API key' });
  }
  
  next();
}

// ============ TTNC CLIENT ============

let cachedSession = {
  sessionId: null,
  expiresAt: null
};

function makeTTNCRequest(xmlBody) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: CONFIG.ttnc.endpoint,
      port: 443,
      path: '/',
      method: 'POST',
      timeout: CONFIG.ttnc.timeoutMs,
      headers: {
        'Content-Type': 'application/xml',
        'Content-Length': Buffer.byteLength(xmlBody)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('TTNC request timed out'));
    });

    req.on('error', (err) => {
      reject(new Error(`TTNC request failed: ${err.message}`));
    });

    req.write(xmlBody);
    req.end();
  });
}

async function getSessionId(requestId) {
  // Return cached session if still valid (with 2 min buffer)
  if (cachedSession.sessionId && cachedSession.expiresAt > Date.now() + 120000) {
    log('debug', 'Using cached TTNC session', { requestId });
    return cachedSession.sessionId;
  }

  log('info', 'Authenticating with TTNC', { requestId });
  
  const authXml = `<?xml version="1.0"?>
<NoveroRequest>
    <Request target="Auth" name="SessionLogin" id="SessionRequest">
        <Username>${escapeXml(CONFIG.ttnc.username)}</Username>
        <Password>${escapeXml(CONFIG.ttnc.password)}</Password>
        <VKey>${escapeXml(CONFIG.ttnc.vkey)}</VKey>
    </Request>
</NoveroRequest>`;

  const response = await makeTTNCRequest(authXml);
  const parsed = await parseStringPromise(response);
  
  const code = parsed?.NoveroResponse?.Response?.[0]?.$.Code;
  if (code !== '200') {
    const message = parsed?.NoveroResponse?.Response?.[0]?.ResponseMessage?.[0] || 'Authentication failed';
    throw new Error(message);
  }

  const sessionId = parsed.NoveroResponse.Response[0].SessionId?.[0];
  if (!sessionId) {
    throw new Error('No session ID in TTNC response');
  }
  
  // Cache for 28 minutes (session lasts 30 min)
  cachedSession = {
    sessionId,
    expiresAt: Date.now() + 28 * 60 * 1000
  };

  log('info', 'TTNC session obtained', { requestId });
  return sessionId;
}

async function setDestination(destinationNumber, requestId, retryCount = 0) {
  const sessionId = await getSessionId(requestId);

  const setDestXml = `<?xml version="1.0"?>
<NoveroRequest>
    <SessionId>${escapeXml(sessionId)}</SessionId>
    <Request target="NoveroNumbers" name="SetDestination" id="SetDestinationRequest">
        <Number>${escapeXml(CONFIG.ttnc.number)}</Number>
        <Destination>${escapeXml(destinationNumber)}</Destination>
    </Request>
</NoveroRequest>`;

  const response = await makeTTNCRequest(setDestXml);
  const parsed = await parseStringPromise(response);

  const code = parsed?.NoveroResponse?.Response?.[0]?.$.Code;
  const message = parsed?.NoveroResponse?.Response?.[0]?.ResponseMessage?.[0] || 
                  parsed?.NoveroResponse?.Response?.[0]?.Success?.[0] || 
                  'Unknown response';

  if (code !== '200') {
    // Session might have expired - retry once with fresh session
    const isSessionError = message.toLowerCase().includes('session') || 
                          message.toLowerCase().includes('auth') ||
                          code === '401';
    
    if (isSessionError && retryCount === 0) {
      log('warn', 'Session expired, retrying with fresh session', { requestId });
      cachedSession = { sessionId: null, expiresAt: null };
      return setDestination(destinationNumber, requestId, retryCount + 1);
    }
    
    throw new Error(message);
  }

  // Automatically enable route to all (ring all destinations simultaneously)
  await enableRouteToAllInternal(requestId);

  return { success: true, message: 'Destination set successfully (ringing all at once)' };
}

/**
 * Enable Route to All - Ring all destinations simultaneously (internal)
 */
async function enableRouteToAllInternal(requestId) {
  const sessionId = await getSessionId(requestId);

  const enableXml = `<?xml version="1.0"?>
<NoveroRequest>
    <SessionId>${escapeXml(sessionId)}</SessionId>
    <Request target="NoveroNumbers" name="EnableRouteToAll" id="EnableRouteToAllRequest">
        <Number>${escapeXml(CONFIG.ttnc.number)}</Number>
    </Request>
</NoveroRequest>`;

  const response = await makeTTNCRequest(enableXml);
  const parsed = await parseStringPromise(response);

  const code = parsed?.NoveroResponse?.Response?.[0]?.$.Code;
  const message = parsed?.NoveroResponse?.Response?.[0]?.ResponseMessage?.[0] || 
                  parsed?.NoveroResponse?.Response?.[0]?.Success?.[0] || 
                  'Unknown response';

  if (code !== '200') {
    throw new Error(message);
  }

  return { success: true, message: 'Route to all enabled - calls will ring all destinations at once' };
}

/**
 * Get the current configuration for the TTNC number
 */
async function getNumberConfig(requestId) {
  const sessionId = await getSessionId(requestId);

  const getConfigXml = `<?xml version="1.0"?>
<NoveroRequest>
    <SessionId>${escapeXml(sessionId)}</SessionId>
    <Request target="NoveroNumbers" name="GetNumberConfig" id="GetConfigRequest">
        <Number>${escapeXml(CONFIG.ttnc.number)}</Number>
    </Request>
</NoveroRequest>`;

  const response = await makeTTNCRequest(getConfigXml);
  const parsed = await parseStringPromise(response);

  const code = parsed?.NoveroResponse?.Response?.[0]?.$.Code;
  
  if (code !== '200') {
    const message = parsed?.NoveroResponse?.Response?.[0]?.ResponseMessage?.[0] || 'Failed to get config';
    throw new Error(message);
  }

  // Extract destination from the first rule
  const rules = parsed?.NoveroResponse?.Response?.[0]?.Rules?.[0]?.Rule;
  
  if (!rules || rules.length === 0) {
    return { destination: null, rules: [] };
  }

  // Get destination from the first rule (main routing)
  const firstRule = rules[0];
  const destination = firstRule?.Destination?.[0] || null;

  return {
    number: CONFIG.ttnc.number,
    destination: destination,
    destinationNumbers: destination ? destination.split('|') : []
  };
}

// XML escape to prevent injection
function escapeXml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ============ VALIDATION ============

function validateDestination(destination) {
  if (!destination || typeof destination !== 'string') {
    return { valid: false, error: 'Destination number is required' };
  }

  // Remove whitespace around pipes and within numbers
  const cleaned = destination
    .split('|')
    .map(num => num.replace(/[\s\-\(\)\.]/g, '').trim())
    .filter(num => num.length > 0)
    .join('|');

  // Split into individual numbers for validation
  const numbers = cleaned.split('|');

  for (const num of numbers) {
    // Must be digits only, 10-15 characters (international format)
    if (!/^\d{10,15}$/.test(num)) {
      return { 
        valid: false, 
        error: `Invalid destination format: ${num}. Use country code + number without leading 00 or + (e.g., 447500336778)` 
      };
    }

    // Block premium rate numbers (UK 09xx)
    if (/^449/.test(num)) {
      return { valid: false, error: 'Premium rate numbers are not allowed' };
    }
  }

  return { valid: true, cleaned };
}

// ============ API ENDPOINTS ============

/**
 * POST /set-destination
 * Headers: X-API-Key: your-api-key
 * Body: { "destination": "447500336778" }
 */
app.post('/set-destination', authenticateApiKey, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const validation = validateDestination(req.body.destination);
    
    if (!validation.valid) {
      log('warn', 'Invalid destination', { 
        requestId: req.requestId, 
        error: validation.error 
      });
      return res.status(400).json({ error: validation.error });
    }

    log('info', 'Setting destination', { 
      requestId: req.requestId,
      destination: validation.cleaned.slice(0, 6) + '***' // Log partial for privacy
    });

    const result = await setDestination(validation.cleaned, req.requestId);
    
    log('info', 'Destination set successfully', { 
      requestId: req.requestId,
      durationMs: Date.now() - startTime
    });
    
    res.json(result);

  } catch (error) {
    log('error', 'Failed to set destination', { 
      requestId: req.requestId,
      error: error.message,
      durationMs: Date.now() - startTime
    });
    res.status(500).json({ error: 'Failed to set destination. Please try again.' });
  }
});

/**
 * GET /get-destination
 * Headers: X-API-Key: your-api-key
 * Returns current destination number(s)
 */
app.get('/get-destination', authenticateApiKey, async (req, res) => {
  const startTime = Date.now();
  
  try {
    log('info', 'Getting current destination', { requestId: req.requestId });

    const result = await getNumberConfig(req.requestId);
    
    log('info', 'Got destination successfully', { 
      requestId: req.requestId,
      durationMs: Date.now() - startTime
    });
    
    res.json(result);

  } catch (error) {
    log('error', 'Failed to get destination', { 
      requestId: req.requestId,
      error: error.message,
      durationMs: Date.now() - startTime
    });
    res.status(500).json({ error: 'Failed to get destination. Please try again.' });
  }
});

/**
 * POST /enable-route-to-all
 * Headers: X-API-Key: your-api-key
 * Enables ringing all destinations simultaneously
 */
app.post('/enable-route-to-all', authenticateApiKey, async (req, res) => {
  const startTime = Date.now();
  
  try {
    log('info', 'Enabling route to all', { requestId: req.requestId });

    const result = await enableRouteToAllInternal(req.requestId);
    
    log('info', 'Route to all enabled', { 
      requestId: req.requestId,
      durationMs: Date.now() - startTime
    });
    
    res.json(result);

  } catch (error) {
    log('error', 'Failed to enable route to all', { 
      requestId: req.requestId,
      error: error.message,
      durationMs: Date.now() - startTime
    });
    res.status(500).json({ error: 'Failed to enable route to all. Please try again.' });
  }
});

/**
 * GET /health - Health check endpoint (no auth required)
 */
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

/**
 * Catch-all for undefined routes
 */
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

/**
 * Global error handler
 */
app.use((err, req, res, next) => {
  log('error', 'Unhandled error', { 
    requestId: req.requestId,
    error: err.message,
    stack: err.stack
  });
  res.status(500).json({ error: 'Internal server error' });
});

// ============ SERVER STARTUP ============

let server;

function startServer() {
  validateEnv();
  
  server = app.listen(CONFIG.port, () => {
    log('info', 'Server started', { 
      port: CONFIG.port,
      nodeEnv: process.env.NODE_ENV || 'development'
    });
  });

  server.on('error', (err) => {
    log('error', 'Server error', { error: err.message });
    process.exit(1);
  });
}

// ============ GRACEFUL SHUTDOWN ============

function shutdown(signal) {
  log('info', 'Shutdown signal received', { signal });
  
  if (server) {
    server.close(() => {
      log('info', 'Server closed');
      process.exit(0);
    });

    // Force exit after 10 seconds
    setTimeout(() => {
      log('warn', 'Forcing shutdown');
      process.exit(1);
    }, 10000);
  } else {
    process.exit(0);
  }
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (err) => {
  log('error', 'Uncaught exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  log('error', 'Unhandled rejection', { reason: String(reason) });
  process.exit(1);
});

// Start the server
startServer();
