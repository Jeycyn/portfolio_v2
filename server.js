import express from 'express';
import session from 'express-session';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import multer from 'multer';
import { Jimp } from 'jimp';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { ProfileDAO, ProjectsDAO, SkillsDAO, AdminDAO, GatewayDAO, SessionDAO, EvidenceDAO, CommandRolesDAO, CertificationsDAO, SiteSettingsDAO } from './db.js';
import { uploadAsset, deleteAsset, getPrivateSignedUrl, getSignedUploadUrl } from './storage.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// Trust proxy for accurate client IP and protocol in reverse proxies
app.set('trust proxy', 1);

const isProduction = process.env.NODE_ENV === 'production';

// Cryptographic signing secret enforcement
let SIGN_SECRET = process.env.SESSION_SECRET;
if (!SIGN_SECRET) {
  if (isProduction) {
    console.error('[SECURITY FATAL] SESSION_SECRET environment variable is strictly required in production.');
    process.exit(1);
  } else {
    SIGN_SECRET = crypto.randomBytes(32).toString('hex');
    console.warn('[SECURITY NOTICE] Ephemeral random signing secret generated for local development runtime.');
  }
}

function isSecureRequest(req) {
  return isProduction || (req && (req.secure || req.headers['x-forwarded-proto'] === 'https'));
}

function signToken(payloadObj) {
  const payloadStr = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const signature = crypto.createHmac('sha256', SIGN_SECRET).update(payloadStr).digest('base64url');
  return `${payloadStr}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadStr, signature] = parts;
  try {
    const expectedSig = crypto.createHmac('sha256', SIGN_SECRET).update(payloadStr).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return null;
    }
    const data = JSON.parse(Buffer.from(payloadStr, 'base64url').toString('utf8'));
    if (data.exp && data.exp < Date.now()) {
      return null; // Expired
    }
    return data;
  } catch {
    return null;
  }
}

// Constant-time string comparison for secret/override checks — avoids
// leaking match-length information via response timing.
function timingSafeStringEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Still run a comparison of equal length to avoid a short-circuit timing tell.
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function parseCookies(req) {
  const list = {};
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    let [name, ...rest] = cookie.split('=');
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    list[name] = decodeURIComponent(value);
  });
  return list;
}

// Rate limiter state (in-memory fast cache + Supabase database persistence)
const failedAttempts = new Map(); // ip -> { count: number, lockoutUntil: number, backoffMultiplier: number }

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '127.0.0.1';
}

async function checkRateLimit(ip) {
  const now = Date.now();
  // 1. Fast in-memory check
  const record = failedAttempts.get(ip);
  if (record && record.lockoutUntil && record.lockoutUntil > now) {
    const remainingSec = Math.ceil((record.lockoutUntil - now) / 1000);
    return { allowed: false, remainingSec };
  }
  // 2. Distributed Database-backed check (resilient to serverless cold starts on Vercel)
  try {
    const dbLimit = await GatewayDAO.checkIpRateLimit(ip, 5, 5);
    if (!dbLimit.allowed) {
      return dbLimit;
    }
  } catch {
    // Fall back to memory result if DB query fails
  }
  return { allowed: true };
}

async function recordFailedAttempt(ip, type) {
  const now = Date.now();
  let record = failedAttempts.get(ip) || { count: 0, lockoutUntil: 0, backoffMultiplier: 1 };
  record.count += 1;
  if (record.count >= 5) {
    const lockoutDuration = 5 * 60 * 1000 * record.backoffMultiplier; // 5m * multiplier
    record.lockoutUntil = now + lockoutDuration;
    record.backoffMultiplier = Math.min(record.backoffMultiplier * 2, 8); // max 40 mins
    record.count = 0;
    await GatewayDAO.logAudit(ip, type, 'lockout', `Lockout triggered for ${Math.round(lockoutDuration / 60000)} minutes`);
  }
  failedAttempts.set(ip, record);
}

function clearRateLimit(ip) {
  failedAttempts.delete(ip);
}

// Lazy/Periodic cleanup of expired database sessions (runs when long-running dev server is active)
if (!process.env.VERCEL) {
  setInterval(async () => {
    try {
      await SessionDAO.cleanupExpired();
    } catch {
      // Ignore transient cleanup errors
    }
  }, 60 * 60 * 1000);
}

// Ensure upload directory exists — only relevant when Supabase Storage isn't
// configured (see storage.js). On serverless platforms the filesystem
// outside /tmp is read-only, so this must be skipped once Supabase is active.
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const usingSupabaseStorage = Boolean(process.env.SUPABASE_URL && (process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || process.env.SUPABASE_ANON_KEY));
if (!usingSupabaseStorage) {
  try {
    if (!fs.existsSync(UPLOADS_DIR)) {
      fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    }
  } catch (err) {
    console.warn('[SERVER] Local uploads folder unavailable in this environment:', err.message);
  }
}

/**
 * Safe cleanup utility to purge deleted upload artifacts from storage & local disk (SEC-LOW-03)
 */
function safeDeleteUploadedFile(filePath) {
  if (!filePath || typeof filePath !== 'string') return;
  try {
    deleteAsset(filePath);
  } catch (err) {
    console.warn('[STORAGE] Asset cleanup warning:', err.message);
  }
}

// ══════════════════════════════════════════════
// GLOBAL SECURITY HEADERS MIDDLEWARE (SEC-MED-02)
// ══════════════════════════════════════════════
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net data:",
    "img-src 'self' data: https: blob: /uploads/ https://storage.googleapis.com",
    "connect-src 'self' https://generativelanguage.googleapis.com https://storage.googleapis.com",
    "frame-ancestors 'self'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; '));
  next();
});

// ══════════════════════════════════════════════
// STRICT WORKSPACE & SOURCE ACCESS GUARD (SEC-CRIT-01)
// Explicitly deny direct access to database files, code, package configs, environment files, and dotfiles.
// ══════════════════════════════════════════════
app.use((req, res, next) => {
  const p = req.path.toLowerCase();
  if (
    p.startsWith('/data') ||
    p.startsWith('/.env') ||
    p.startsWith('/node_modules') ||
    p.startsWith('/.git') ||
    p.startsWith('/.aistudio') ||
    p.endsWith('.db') ||
    p.endsWith('.sqlite') ||
    p.endsWith('.js') ||
    p.endsWith('.ts') ||
    p.endsWith('.json') ||
    p.endsWith('.lock') ||
    p.endsWith('.env') ||
    p.endsWith('.env.example') ||
    p.endsWith('.md') ||
    p.endsWith('.map') ||
    p.endsWith('.sql')
  ) {
    return res.status(404).json({ error: 'NOT_FOUND' });
  }
  next();
});

// Hardened session configuration (SEC-MED-03)
app.use(session({
  name: 'jeycyn_sys_sid',
  secret: SIGN_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true,
    sameSite: 'strict',
    secure: isProduction
  }
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ══════════════════════════════════════════════
// CSRF PROTECTION MIDDLEWARE (SEC-MED-01)
// Validates origin / custom headers for state-changing operations
// ══════════════════════════════════════════════
app.use((req, res, next) => {
  // Safe HTTP read methods are exempt
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  // If request contains Bearer token in Authorization header, standard CSRF does not apply
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return next();
  }
  // Custom AJAX headers set by authenticated client scripts
  const requestedWith = req.headers['x-requested-with'];
  const csrfHeader = req.headers['x-csrf-token'];
  if (requestedWith === 'XMLHttpRequest' || csrfHeader) {
    return next();
  }
  // Validate Origin / Referer host against Host header
  const origin = req.headers.origin || req.headers.referer;
  if (origin) {
    try {
      const originHost = new URL(origin).host;
      if (originHost === req.get('host')) {
        return next();
      }
    } catch {
      // Invalid URL format
    }
  }
  return res.status(403).json({ error: 'CSRF_VALIDATION_FAILED: Request rejected by security filter.' });
});

// Multer memory storage with SVG rejection & hardened content types (SEC-HIGH-01)
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/x-icon', 'image/vnd.microsoft.icon', 'image/ico',
      'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/plain'
    ];
    const allowedExts = ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.ico', '.pdf', '.doc', '.docx', '.txt'];
    const ext = path.extname(file.originalname).toLowerCase();
    
    // Explicitly reject SVG to prevent stored XSS attacks
    if (ext === '.svg' || file.mimetype === 'image/svg+xml') {
      return cb(new Error('INVALID_FILE_TYPE: SVG files are not permitted for security reasons. Please upload PNG, JPEG, WEBP, or ICO.'));
    }

    if (allowedTypes.includes(file.mimetype) || allowedExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('INVALID_FILE_TYPE: Only raster image files (JPEG, PNG, WEBP, GIF, ICO) and safe documents (PDF, DOC, DOCX, TXT) are permitted.'));
    }
  }
});

/**
 * Validates and returns active admin session information from
 * Bearer header, secure cookie, or express-session.
 * Token in query parameter is strictly disallowed (SEC-LOW-01).
 */
async function getAdminSessionFromReq(req) {
  // 1. Check Authorization Bearer header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    const sessionData = await SessionDAO.validateSession(token);
    if (sessionData) return { ...sessionData, token, authMethod: 'bearer' };
  }

  // 2. Check admin_session_token cookie
  const cookies = parseCookies(req);
  if (cookies.admin_session_token) {
    const sessionData = await SessionDAO.validateSession(cookies.admin_session_token);
    if (sessionData) return { ...sessionData, token: cookies.admin_session_token, authMethod: 'cookie' };
  }

  // 3. Check express-session
  if (req.session && req.session.admin_token) {
    const sessionData = await SessionDAO.validateSession(req.session.admin_token);
    if (sessionData) return { ...sessionData, token: req.session.admin_token, authMethod: 'session' };
  } else if (req.session && req.session.user && req.session.user.id) {
    return { userId: req.session.user.id, username: req.session.user.username, authMethod: 'session' };
  }

  return null;
}

/**
 * Checks whether visitor holds a valid Gateway Clearance token.
 * Note: Gateway clearance NEVER grants admin access; it only unlocks the visitor gateway barrier.
 */
async function isGatewayCleared(req) {
  // 1. Authenticated admins automatically bypass gateway
  const admin = await getAdminSessionFromReq(req);
  if (admin) {
    return true;
  }
  // 2. Check express session gateway verification
  if (req.session && req.session.gateway_verified && req.session.gateway_verified > Date.now()) {
    return true;
  }
  // 3. Check Cookie
  const cookies = parseCookies(req);
  if (cookies.gateway_clearance) {
    const data = verifyToken(cookies.gateway_clearance);
    if (data && data.type === 'gateway_clearance') return true;
  }
  // 4. Check Header or Query Token
  const token = req.headers['x-gateway-token'] || req.query.gt;
  if (token) {
    const data = verifyToken(token);
    if (data && data.type === 'gateway_clearance') return true;
  }
  return false;
}

// Middleware: Admin Auth Check for APIs
async function requireAdminApi(req, res, next) {
  const admin = await getAdminSessionFromReq(req);
  if (admin) {
    req.adminUser = admin;
    if (req.session) {
      req.session.user = { id: admin.userId, username: admin.username };
      if (admin.token) req.session.admin_token = admin.token;
    }
    return next();
  }
  return res.status(401).json({ error: 'UNAUTHORIZED: Valid administrator credentials required.' });
}

// Middleware: Admin Page Guard
async function requireAdminPage(req, res, next) {
  const admin = await getAdminSessionFromReq(req);
  if (admin) {
    if (req.session) {
      req.session.user = { id: admin.userId, username: admin.username };
      if (admin.token) req.session.admin_token = admin.token;
    }
    // Re-anchor the session cookie
    if (admin.token) {
      res.cookie('admin_session_token', admin.token, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'strict',
        secure: isSecureRequest(req),
        path: '/'
      });
    }
    return next();
  }
  return res.redirect('/gateway');
}

// Static asset serving for uploads with nosniff and sandbox protection (SEC-CRIT-01, SEC-HIGH-01)
app.use('/uploads', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
  next();
}, express.static(UPLOADS_DIR, {
  dotfiles: 'ignore',
  index: false
}));

/* ══════════════════════════════════════════════
   CMS-MANAGED SEO, SITEMAP, ROBOTS.TXT & FAVICON
══════════════════════════════════════════════ */
async function getBaseSiteUrl(req) {
  const settings = await SiteSettingsDAO.get();
  if (settings.canonical_url && settings.canonical_url.trim()) {
    return settings.canonical_url.trim().replace(/\/+$/, '');
  }
  const host = req.get('x-forwarded-host') || req.get('host') || 'localhost:3000';
  const proto = req.get('x-forwarded-proto') || req.protocol || 'http';
  return `${proto}://${host}`;
}

// Favicon route - dynamically routes to CMS-managed favicon or falls back gracefully
app.get(['/favicon.ico', '/favicon.png', '/favicon.svg'], async (req, res) => {
  try {
    const settings = await SiteSettingsDAO.get();
    if (settings.favicon_path && typeof settings.favicon_path === 'string' && settings.favicon_path.trim()) {
      const cleanPath = settings.favicon_path.trim();
      // If it starts with /uploads/, serve the file directly
      if (cleanPath.startsWith('/uploads/')) {
        const localFile = path.join(__dirname, cleanPath);
        if (fs.existsSync(localFile)) {
          const ext = path.extname(localFile).toLowerCase();
          const mimeMap = {
            '.ico': 'image/x-icon',
            '.png': 'image/png',
            '.svg': 'image/svg+xml',
            '.webp': 'image/webp',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg'
          };
          res.setHeader('Content-Type', mimeMap[ext] || 'image/x-icon');
          res.setHeader('Cache-Control', 'public, max-age=3600');
          return res.sendFile(localFile);
        }
      } else if (cleanPath.startsWith('http://') || cleanPath.startsWith('https://')) {
        return res.redirect(302, cleanPath);
      }
    }
  } catch (err) {
    console.warn('[FAVICON] Error resolving custom favicon:', err.message);
  }

  // Fallback: Generate or serve default HUD cyber favicon
  const defaultFavicon = path.join(__dirname, 'public', 'favicon.ico');
  if (fs.existsSync(defaultFavicon)) {
    return res.sendFile(defaultFavicon);
  }
  
  // Safe SVG inline fallback favicon
  const svgFavicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="4" fill="#020c1b"/><circle cx="16" cy="16" r="10" fill="none" stroke="#f0a500" stroke-width="2"/><circle cx="16" cy="16" r="4" fill="#4fc3f7"/></svg>`;
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(svgFavicon);
});

// Dynamic robots.txt
app.get('/robots.txt', async (req, res) => {
  const settings = await SiteSettingsDAO.get();
  const baseUrl = await getBaseSiteUrl(req);
  const policy = (settings.robots_policy || 'index, follow').toLowerCase();
  
  let robotsTxt = `User-agent: *\n`;
  if (policy.includes('noindex')) {
    robotsTxt += `Disallow: /\n`;
  } else {
    robotsTxt += `Allow: /\n`;
    robotsTxt += `Disallow: /admin\n`;
    robotsTxt += `Disallow: /admin.html\n`;
    robotsTxt += `Disallow: /gateway\n`;
    robotsTxt += `Disallow: /gateway.html\n`;
    robotsTxt += `Disallow: /login\n`;
    robotsTxt += `Disallow: /api/admin/\n`;
    robotsTxt += `Disallow: /api/auth/\n`;
    robotsTxt += `Disallow: /api/gateway/\n`;
  }

  robotsTxt += `\nSitemap: ${baseUrl}/sitemap.xml\n`;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(robotsTxt);
});

// Dynamic sitemap.xml
app.get('/sitemap.xml', async (req, res) => {
  try {
    const settings = await SiteSettingsDAO.get();
    const baseUrl = await getBaseSiteUrl(req);
    const policy = (settings.robots_policy || 'index, follow').toLowerCase();

    // If noindex is requested by admin, return empty sitemap with note
    if (policy.includes('noindex')) {
      const emptySitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
</urlset>`;
      res.setHeader('Content-Type', 'application/xml; charset=utf-8');
      return res.send(emptySitemap);
    }

    const lastMod = (settings.updated_at ? new Date(settings.updated_at).toISOString().split('T')[0] : new Date().toISOString().split('T')[0]);

    // Public published missions/projects
    const publicProjects = await ProjectsDAO.getAll(false) || [];

    let xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
  <!-- Primary Application Routes -->
  <url>
    <loc>${escapeXml(baseUrl)}/</loc>
    <lastmod>${lastMod}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>${escapeXml(baseUrl)}/cv</loc>
    <lastmod>${lastMod}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
`;

    // Add public project sections anchor links if applicable
    for (const p of publicProjects) {
      if (p.title) {
        xml += `  <url>
    <loc>${escapeXml(baseUrl)}/#missions</loc>
    <lastmod>${lastMod}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.7</priority>
  </url>\n`;
        break; // Single section URL entry
      }
    }

    xml += `</urlset>`;
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(xml);
  } catch (err) {
    console.error('[SITEMAP] Error generating sitemap.xml:', err);
    res.status(500).send('Error generating sitemap');
  }
});

function escapeXml(unsafe) {
  if (!unsafe) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/* ══════════════════════════════════════════════
   EXPLICIT HTML PAGE ROUTES (SEC-CRIT-01 REMEDIATION)
   Directory exposure completely disabled. Only designated routes served.
══════════════════════════════════════════════ */
app.get(['/admin', '/admin.html'], requireAdminPage, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get(['/gateway', '/gateway.html'], async (req, res) => {
  if (await getAdminSessionFromReq(req)) {
    return res.redirect('/admin');
  }
  res.sendFile(path.join(__dirname, 'gateway.html'));
});

app.get(['/login', '/login.html'], async (req, res) => {
  if (await getAdminSessionFromReq(req)) {
    return res.redirect('/admin');
  }
  res.redirect('/gateway');
});

app.get(['/cv', '/cv.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'cv.html'));
});

/* ══════════════════════════════════════════════
   GATEWAY SECURITY API
 ══════════════════════════════════════════════ */
app.get(['/api/gateway/config', '/api/gateway/puzzle'], async (req, res) => {
  try {
    const config = await GatewayDAO.getPublicConfig();
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: 'GATEWAY_ERROR: ' + err.message });
  }
});

app.post('/api/gateway/verify-puzzle', async (req, res) => {
  const ip = getClientIp(req);
  const rateLimit = await checkRateLimit(ip);
  if (!rateLimit.allowed) {
    return res.status(429).json({
      error: `SECURITY_LOCKOUT: Maximum failed attempts exceeded. Retry in ${rateLimit.remainingSec}s.`,
      lockout: true,
      remainingSec: rateLimit.remainingSec
    });
  }

  const { tiles } = req.body;
  if (!tiles || !Array.isArray(tiles)) {
    return res.status(400).json({ error: 'INVALID_PAYLOAD: Rune matrix arrangement required.' });
  }

  const isSolved = await GatewayDAO.verifyPuzzle(tiles);
  if (!isSolved) {
    await recordFailedAttempt(ip, 'puzzle');
    await GatewayDAO.logAudit(ip, 'puzzle', 'failure', 'Mismatched rune matrix sequence');
    return res.status(401).json({ success: false, error: 'CIPHER_MISMATCH: Rune alignment sequence rejected.' });
  }

  // Issue server-signed single-use puzzle clearance token (valid for 10 minutes)
  const puzzleToken = signToken({
    type: 'puzzle_solved',
    ip,
    exp: Date.now() + 10 * 60 * 1000
  });

  if (req.session) {
    req.session.puzzle_solved = true;
  }
  await GatewayDAO.logAudit(ip, 'puzzle', 'success', 'Rune matrix successfully aligned');
  res.json({ success: true, message: 'RUNE_MATRIX_UNLOCKED', puzzle_token: puzzleToken });
});

app.post('/api/gateway/verify-passcode', async (req, res) => {
  const ip = getClientIp(req);
  const rateLimit = await checkRateLimit(ip);
  if (!rateLimit.allowed) {
    return res.status(429).json({
      error: `SECURITY_LOCKOUT: Maximum failed attempts exceeded. Retry in ${rateLimit.remainingSec}s.`,
      lockout: true,
      remainingSec: rateLimit.remainingSec
    });
  }

  // Check puzzle resolution via session or signed token
  const puzzleToken = req.body.puzzle_token || req.headers['x-puzzle-token'];
  const tokenData = verifyToken(puzzleToken);
  const isSessionSolved = req.session && req.session.puzzle_solved;
  const isTokenSolved = tokenData && tokenData.type === 'puzzle_solved';

  if (!isSessionSolved && !isTokenSolved) {
    return res.status(403).json({ error: 'PUZZLE_UNRESOLVED: Rune matrix alignment required prior to cipher entry.' });
  }

  const submittedPasscode = (req.body.passcode || '').trim();
  if (!submittedPasscode) {
    return res.status(400).json({ error: 'Passcode required.' });
  }

  // Emergency Master Override Check via process.env.ADMIN_GATEWAY_OVERRIDE
  const masterOverride = process.env.ADMIN_GATEWAY_OVERRIDE ? process.env.ADMIN_GATEWAY_OVERRIDE.trim() : null;
  let isMatch = false;
  let isOverride = false;

  if (masterOverride && timingSafeStringEqual(submittedPasscode, masterOverride)) {
    isMatch = true;
    isOverride = true;
  } else {
    isMatch = await GatewayDAO.verifyPasscode(submittedPasscode);
  }

  if (!isMatch) {
    await recordFailedAttempt(ip, 'passcode');
    await GatewayDAO.logAudit(ip, 'passcode', 'failure', 'Invalid cipher key entered');
    return res.status(401).json({ success: false, error: 'ACCESS_DENIED: Invalid security cipher.' });
  }

  // Successful Gateway authentication: Issue 15-minute signed clearance token
  clearRateLimit(ip);
  if (req.session) {
    req.session.puzzle_solved = false;
    req.session.gateway_verified = Date.now() + 15 * 60 * 1000;
  }

  const clearanceExp = Date.now() + 15 * 60 * 1000;
  const gatewayToken = signToken({
    type: 'gateway_clearance',
    ip,
    exp: clearanceExp
  });

  // Set HTTP-only clearance cookie
  res.cookie('gateway_clearance', gatewayToken, {
    maxAge: 15 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecureRequest(req),
    path: '/'
  });

  await GatewayDAO.logAudit(ip, isOverride ? 'master_override' : 'passcode', 'success', 'Gateway clearance token granted (15m validity)');
  res.json({
    success: true,
    message: 'GATEWAY_CLEARANCE_GRANTED',
    gateway_token: gatewayToken,
    redirect: `/login?gt=${encodeURIComponent(gatewayToken)}`
  });
});

/* ══════════════════════════════════════════════
   ADMIN GATEWAY CONFIG & AUDIT API
══════════════════════════════════════════════ */
app.get('/api/admin/gateway/config', requireAdminApi, async (req, res) => {
  try {
    const config = await GatewayDAO.getAdminConfig();
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

app.put('/api/admin/gateway/config', requireAdminApi, async (req, res) => {
  try {
    const note = req.body.note || 'Updated via Admin CMS';
    const updated = await GatewayDAO.updateConfig(req.body, note);
    await GatewayDAO.logAudit(getClientIp(req), 'config_update', 'success', `Gateway configuration updated: ${note}`);
    res.json({ success: true, message: 'GATEWAY_CONFIG_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

app.post('/api/admin/gateway/reset', requireAdminApi, async (req, res) => {
  try {
    const reset = await GatewayDAO.resetToDefault('Factory Reset via Admin CMS');
    await GatewayDAO.logAudit(getClientIp(req), 'reset_default', 'success', 'Gateway reset to factory baseline');
    res.json({ success: true, message: 'GATEWAY_RESET_DEFAULT', data: reset });
  } catch (err) {
    res.status(500).json({ error: 'RESET_FAILED: ' + err.message });
  }
});

app.get('/api/admin/gateway/history', requireAdminApi, async (req, res) => {
  try {
    const history = await GatewayDAO.getHistory(30);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

app.post('/api/admin/gateway/rollback', requireAdminApi, async (req, res) => {
  try {
    const historyId = parseInt(req.body.id, 10);
    if (!historyId) return res.status(400).json({ error: 'History ID required.' });
    const restored = await GatewayDAO.rollback(historyId);
    await GatewayDAO.logAudit(getClientIp(req), 'rollback', 'success', `Configuration rolled back to snapshot #${historyId}`);
    res.json({ success: true, message: 'GATEWAY_ROLLED_BACK', data: restored });
  } catch (err) {
    res.status(500).json({ error: 'ROLLBACK_FAILED: ' + err.message });
  }
});

app.get('/api/admin/gateway/audit', requireAdminApi, async (req, res) => {
  try {
    const logs = await GatewayDAO.getAuditLogs(60);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

/* ══════════════════════════════════════════════
   AUTHENTICATION API (SECURE BCRYPT + SESSIONS)
══════════════════════════════════════════════ */
app.post('/api/auth/login', async (req, res) => {
  const ip = getClientIp(req);
  const rateLimit = await checkRateLimit(ip);
  if (!rateLimit.allowed) {
    return res.status(429).json({
      error: `SECURITY_LOCKOUT: Maximum failed attempts exceeded. Retry in ${rateLimit.remainingSec}s.`,
      lockout: true,
      remainingSec: rateLimit.remainingSec
    });
  }

  // Enforce 3-Layer Security Pipeline: Gateway Clearance Required
  // (Visitor must have solved Rune Matrix and entered Gateway Passcode)
  if (!(await isGatewayCleared(req))) {
    const override = process.env.ADMIN_GATEWAY_OVERRIDE ? process.env.ADMIN_GATEWAY_OVERRIDE.trim() : null;
    const providedOverride = (req.body.emergency_override || req.headers['x-admin-override'] || '').trim();
    if (!override || !timingSafeStringEqual(providedOverride, override)) {
      await recordFailedAttempt(ip, 'unauthorized_login_probe');
      await GatewayDAO.logAudit(ip, 'admin_login_probe', 'blocked', 'Direct login access attempt blocked without gateway clearance');
      return res.status(403).json({
        error: 'GATEWAY_CLEARANCE_REQUIRED: Rune matrix and gateway cipher verification required prior to operator login.',
        requires_gateway: true
      });
    }
  }

  const { username, password } = req.body;
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password required.' });
  }

  const cleanUsername = username.trim();
  const valid = await AdminDAO.verifyPassword(cleanUsername, password);
  if (!valid) {
    await recordFailedAttempt(ip, 'admin_login');
    await GatewayDAO.logAudit(getClientIp(req), 'admin_login', 'failure', `Failed login attempt for operator: ${cleanUsername}`);
    return res.status(401).json({ error: 'ACCESS_DENIED: Invalid operator credentials.' });
  }

  // Clear rate limits upon successful credential verification
  clearRateLimit(ip);

  const user = await AdminDAO.findByUsername(cleanUsername);
  const userAgent = req.headers['user-agent'] || '';
  const maxAgeMs = 24 * 60 * 60 * 1000; // 24 hours

  // Issue durable, cryptographically random database session
  const { token, expiresAt } = await SessionDAO.createSession(user.id, user.username, ip, userAgent, maxAgeMs);

  // Regenerate express-session to prevent session fixation attacks
  if (req.session) {
    req.session.regenerate(() => {
      req.session.user = { id: user.id, username: user.username };
      req.session.admin_token = token;
    });
  }

  // Set secure HttpOnly session cookie
  res.cookie('admin_session_token', token, {
    maxAge: maxAgeMs,
    httpOnly: true,
    sameSite: 'strict',
    secure: isSecureRequest(req),
    path: '/'
  });

  await GatewayDAO.logAudit(ip, 'admin_login', 'success', `Operator authenticated: ${user.username}`);

  res.json({
    success: true,
    token,
    expiresAt,
    user: { id: user.id, username: user.username },
    message: 'CLEARANCE GRANTED',
    redirect: '/admin'
  });
});

app.post('/api/auth/logout', async (req, res) => {
  const admin = await getAdminSessionFromReq(req);
  if (admin && admin.token) {
    await SessionDAO.revokeSession(admin.token);
  }
  if (req.session) {
    req.session.destroy(() => {});
  }
  res.clearCookie('jeycyn_sys_sid', { path: '/' });
  res.clearCookie('admin_session_token', { path: '/' });
  res.json({ success: true, message: 'SESSION TERMINATED' });
});

app.get(['/api/auth/verify', '/api/auth/me'], async (req, res) => {
  const admin = await getAdminSessionFromReq(req);
  if (admin) {
    const isDefPass = await AdminDAO.isDefaultPasswordActive();
    const isDefGw = await GatewayDAO.isDefaultPasscodeActive();
    return res.json({
      authenticated: true,
      user: { id: admin.userId || admin.id, username: admin.username },
      expiresAt: admin.expiresAt,
      security_warnings: {
        default_password: isDefPass,
        default_gateway_passcode: isDefGw
      }
    });
  }
  res.json({ authenticated: false, user: null });
});

// Emergency Gateway Override Endpoint (server-side environment variable only)
app.post('/api/gateway/emergency-override', async (req, res) => {
  const ip = getClientIp(req);
  const masterOverride = process.env.ADMIN_GATEWAY_OVERRIDE ? process.env.ADMIN_GATEWAY_OVERRIDE.trim() : null;
  const submittedKey = (req.body.override_key || req.headers['x-admin-override'] || '').trim();

  if (!masterOverride || !submittedKey || !timingSafeStringEqual(submittedKey, masterOverride)) {
    await recordFailedAttempt(ip, 'emergency_override');
    await GatewayDAO.logAudit(ip, 'emergency_override', 'failure', 'Invalid emergency override attempt');
    return res.status(403).json({ error: 'OVERRIDE_DENIED: Invalid master override cipher.' });
  }

  // Grant 15m gateway clearance ONLY (does NOT bypass admin login)
  clearRateLimit(ip);
  const clearanceExp = Date.now() + 15 * 60 * 1000;
  const gatewayToken = signToken({
    type: 'gateway_clearance',
    ip,
    exp: clearanceExp
  });

  res.cookie('gateway_clearance', gatewayToken, {
    maxAge: 15 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecureRequest(req),
    path: '/'
  });

  await GatewayDAO.logAudit(ip, 'emergency_override', 'success', 'Emergency gateway override clearance granted');
  res.json({
    success: true,
    message: 'EMERGENCY_GATEWAY_CLEARANCE_GRANTED',
    gateway_token: gatewayToken,
    redirect: `/login?gt=${encodeURIComponent(gatewayToken)}`
  });
});

app.post(['/api/admin/credentials', '/api/admin/password', '/api/auth/change-credentials'], requireAdminApi, async (req, res) => {
  const { new_username, newUsername, new_password, newPassword, current_password, currentPassword } = req.body;
  const targetUser = (new_username || newUsername || '').trim();
  const nextPass = (new_password || newPassword || '').trim();
  const currPass = (current_password || currentPassword || '').trim();

  if (!currPass) {
    return res.status(400).json({ error: 'CURRENT_PASSWORD_REQUIRED: Current operator cipher is required to confirm identity.' });
  }

  const currentOperator = req.adminUser?.username || req.session?.user?.username || 'admin';
  const userId = req.adminUser?.userId || req.session?.user?.id;

  const isCurrentValid = await AdminDAO.verifyPassword(currentOperator, currPass);
  if (!isCurrentValid) {
    await GatewayDAO.logAudit(getClientIp(req), 'credential_change', 'failure', `Failed credential update attempt for ${currentOperator} (invalid current cipher)`);
    return res.status(401).json({ error: 'INVALID_CURRENT_PASSWORD: Current operator cipher verification failed.' });
  }

  if (nextPass && nextPass.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }

  if (targetUser && targetUser.length < 3) {
    return res.status(400).json({ error: 'Operator callsign/username must be at least 3 characters.' });
  }

  try {
    const updatedUser = await AdminDAO.updateCredentials(userId, targetUser || currentOperator, nextPass);
    if (!updatedUser) {
      return res.status(500).json({ error: 'Failed to update credentials in database.' });
    }

    // Invalidate/revoke other existing sessions for this user for security
    const currentToken = req.adminUser?.token;
    await SessionDAO.revokeOtherUserSessions(userId, currentToken);

    if (req.session && req.session.user) {
      req.session.user.username = updatedUser.username;
    }

    await GatewayDAO.logAudit(getClientIp(req), 'credential_change', 'success', `Credentials successfully updated for operator ${updatedUser.username}`);
    res.json({
      success: true,
      message: 'OPERATOR CREDENTIALS REKEYED',
      user: { id: updatedUser.id, username: updatedUser.username }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ══════════════════════════════════════════════
   SITE SETTINGS & SEO API
══════════════════════════════════════════════ */
app.get('/api/settings', async (req, res) => {
  try {
    const settings = await SiteSettingsDAO.get();
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

app.put('/api/settings', requireAdminApi, async (req, res) => {
  try {
    const oldSettings = await SiteSettingsDAO.get();
    if (req.body.favicon_path && oldSettings?.favicon_path && req.body.favicon_path !== oldSettings.favicon_path) {
      safeDeleteUploadedFile(oldSettings.favicon_path);
    }
    if (req.body.social_image_path && oldSettings?.social_image_path && req.body.social_image_path !== oldSettings.social_image_path) {
      safeDeleteUploadedFile(oldSettings.social_image_path);
    }
    const updated = await SiteSettingsDAO.update(req.body);
    res.json({ success: true, message: 'SETTINGS_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

app.post('/api/settings', requireAdminApi, async (req, res) => {
  try {
    const oldSettings = await SiteSettingsDAO.get();
    if (req.body.favicon_path && oldSettings?.favicon_path && req.body.favicon_path !== oldSettings.favicon_path) {
      safeDeleteUploadedFile(oldSettings.favicon_path);
    }
    if (req.body.social_image_path && oldSettings?.social_image_path && req.body.social_image_path !== oldSettings.social_image_path) {
      safeDeleteUploadedFile(oldSettings.social_image_path);
    }
    const updated = await SiteSettingsDAO.update(req.body);
    res.json({ success: true, message: 'SETTINGS_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

/* ══════════════════════════════════════════════
   PROFILE API
══════════════════════════════════════════════ */
app.get('/api/profile', async (req, res) => {
  try {
    const profile = await ProfileDAO.get();
    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

app.put('/api/profile', requireAdminApi, async (req, res) => {
  try {
    const oldProfile = await ProfileDAO.get();
    if (req.body.photo_path && oldProfile?.photo_path && req.body.photo_path !== oldProfile.photo_path) {
      safeDeleteUploadedFile(oldProfile.photo_path);
    }
    const updated = await ProfileDAO.update(req.body);
    res.json({ success: true, message: 'PROFILE_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

app.post('/api/profile', requireAdminApi, async (req, res) => {
  try {
    const oldProfile = await ProfileDAO.get();
    if (req.body.photo_path && oldProfile?.photo_path && req.body.photo_path !== oldProfile.photo_path) {
      safeDeleteUploadedFile(oldProfile.photo_path);
    }
    const updated = await ProfileDAO.update(req.body);
    res.json({ success: true, message: 'PROFILE_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

/* ══════════════════════════════════════════════
   PROJECTS API
══════════════════════════════════════════════ */
app.get('/api/projects', async (req, res) => {
  try {
    const isAdmin = !!(await getAdminSessionFromReq(req));
    const showAll = req.query.all === '1' && isAdmin;
    const projects = await ProjectsDAO.getAll(showAll);
    res.json(projects);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

app.post('/api/projects', requireAdminApi, async (req, res) => {
  try {
    const project = await ProjectsDAO.create(req.body);
    res.status(201).json({ success: true, message: 'MISSION_CREATED', data: project });
  } catch (err) {
    res.status(500).json({ error: 'CREATION_FAILED: ' + err.message });
  }
});

app.put('/api/projects/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const oldProject = await ProjectsDAO.getById(id);
    if (req.body.image_path && oldProject?.image_path && req.body.image_path !== oldProject.image_path) {
      safeDeleteUploadedFile(oldProject.image_path);
    }
    const updated = await ProjectsDAO.update(id, req.body);
    if (!updated) return res.status(404).json({ error: 'MISSION_NOT_FOUND' });
    res.json({ success: true, message: 'MISSION_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

app.delete('/api/projects/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const project = await ProjectsDAO.getById(id);
    if (project && project.image_path) {
      safeDeleteUploadedFile(project.image_path);
    }
    const success = await ProjectsDAO.delete(id);
    if (!success) return res.status(404).json({ error: 'MISSION_NOT_FOUND' });
    res.json({ success: true, message: 'MISSION_DECOMMISSIONED' });
  } catch (err) {
    res.status(500).json({ error: 'DELETE_FAILED: ' + err.message });
  }
});

/* ══════════════════════════════════════════════
   SKILLS API
══════════════════════════════════════════════ */
app.get('/api/skills', async (req, res) => {
  try {
    const skills = await SkillsDAO.getAll();
    res.json(skills);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

app.post('/api/skills', requireAdminApi, async (req, res) => {
  try {
    const skill = await SkillsDAO.create(req.body);
    res.status(201).json({ success: true, message: 'CAPABILITY_REGISTERED', data: skill });
  } catch (err) {
    res.status(500).json({ error: 'CREATION_FAILED: ' + err.message });
  }
});

app.put('/api/skills/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const updated = await SkillsDAO.update(id, req.body);
    if (!updated) return res.status(404).json({ error: 'CAPABILITY_NOT_FOUND' });
    res.json({ success: true, message: 'CAPABILITY_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

app.delete('/api/skills/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const success = await SkillsDAO.delete(id);
    if (!success) return res.status(404).json({ error: 'CAPABILITY_NOT_FOUND' });
    res.json({ success: true, message: 'CAPABILITY_PURGED' });
  } catch (err) {
    res.status(500).json({ error: 'DELETE_FAILED: ' + err.message });
  }
});

/* ══════════════════════════════════════════════
   COMMAND ROLES API
══════════════════════════════════════════════ */
app.get('/api/command-roles', async (req, res) => {
  try {
    const roles = await CommandRolesDAO.getAll();
    res.json(roles);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

app.post('/api/command-roles', requireAdminApi, async (req, res) => {
  try {
    const role = await CommandRolesDAO.create(req.body);
    res.status(201).json({ success: true, message: 'COMMAND_ROLE_CREATED', data: role });
  } catch (err) {
    res.status(500).json({ error: 'CREATION_FAILED: ' + err.message });
  }
});

app.put('/api/command-roles/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const updated = await CommandRolesDAO.update(id, req.body);
    if (!updated) return res.status(404).json({ error: 'ROLE_NOT_FOUND' });
    res.json({ success: true, message: 'COMMAND_ROLE_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

app.delete('/api/command-roles/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const success = await CommandRolesDAO.delete(id);
    if (!success) return res.status(404).json({ error: 'ROLE_NOT_FOUND' });
    res.json({ success: true, message: 'COMMAND_ROLE_DECOMMISSIONED' });
  } catch (err) {
    res.status(500).json({ error: 'DELETE_FAILED: ' + err.message });
  }
});

/* ══════════════════════════════════════════════
   CERTIFICATIONS API
══════════════════════════════════════════════ */
app.get('/api/certifications', async (req, res) => {
  try {
    const certs = await CertificationsDAO.getAll();
    res.json(certs);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

app.post('/api/certifications', requireAdminApi, async (req, res) => {
  try {
    const cert = await CertificationsDAO.create(req.body);
    res.status(201).json({ success: true, message: 'CERTIFICATION_CREATED', data: cert });
  } catch (err) {
    res.status(500).json({ error: 'CREATION_FAILED: ' + err.message });
  }
});

app.put('/api/certifications/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const updated = await CertificationsDAO.update(id, req.body);
    if (!updated) return res.status(404).json({ error: 'CERT_NOT_FOUND' });
    res.json({ success: true, message: 'CERTIFICATION_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

app.delete('/api/certifications/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const success = await CertificationsDAO.delete(id);
    if (!success) return res.status(404).json({ error: 'CERT_NOT_FOUND' });
    res.json({ success: true, message: 'CERTIFICATION_DECOMMISSIONED' });
  } catch (err) {
    res.status(500).json({ error: 'DELETE_FAILED: ' + err.message });
  }
});

/* ══════════════════════════════════════════════
   EVIDENCE & PROOF ARTIFACTS API
══════════════════════════════════════════════ */
app.get('/api/evidence', async (req, res) => {
  try {
    const { target_type, target_id } = req.query;
    if (target_type && target_id) {
      const items = await EvidenceDAO.getByTarget(target_type, target_id);
      return res.json(items);
    }
    const all = await EvidenceDAO.getAll();
    res.json(all);
  } catch (err) {
    res.status(500).json({ error: 'DATABASE_ERROR: ' + err.message });
  }
});

app.post('/api/evidence', requireAdminApi, async (req, res) => {
  try {
    const { target_type, target_id, title } = req.body;
    if (!target_type || !target_id || !title) {
      return res.status(400).json({ error: 'target_type, target_id, and title are required.' });
    }
    const created = await EvidenceDAO.create(req.body);
    res.status(201).json({ success: true, message: 'EVIDENCE_REGISTERED', data: created });
  } catch (err) {
    res.status(500).json({ error: 'CREATION_FAILED: ' + err.message });
  }
});

app.put('/api/evidence/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const oldEv = await EvidenceDAO.getById(id);
    if (req.body.file_path && oldEv?.file_path && req.body.file_path !== oldEv.file_path) {
      safeDeleteUploadedFile(oldEv.file_path);
    }
    const updated = await EvidenceDAO.update(id, req.body);
    if (!updated) return res.status(404).json({ error: 'EVIDENCE_NOT_FOUND' });
    res.json({ success: true, message: 'EVIDENCE_UPDATED', data: updated });
  } catch (err) {
    res.status(500).json({ error: 'UPDATE_FAILED: ' + err.message });
  }
});

app.delete('/api/evidence/:id', requireAdminApi, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const ev = await EvidenceDAO.getById(id);
    if (ev && ev.file_path) {
      safeDeleteUploadedFile(ev.file_path);
    }
    const success = await EvidenceDAO.delete(id);
    if (!success) return res.status(404).json({ error: 'EVIDENCE_NOT_FOUND' });
    res.json({ success: true, message: 'EVIDENCE_PURGED' });
  } catch (err) {
    res.status(500).json({ error: 'DELETE_FAILED: ' + err.message });
  }
});

/* ══════════════════════════════════════════════
   ROBOT NAVIGATION ASSISTANT API
   (Natural Language NLU + Structured Intents + Gemini Fallback)
══════════════════════════════════════════════ */
let geminiClient = null;
function getGeminiClient() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  if (!geminiClient) {
    geminiClient = new GoogleGenAI({ apiKey });
  }
  return geminiClient;
}

app.post('/api/assistant/query', async (req, res) => {
  try {
    const rawQuery = (req.body?.query || '').trim();
    if (!rawQuery) {
      return res.status(400).json({
        error: 'EMPTY_QUERY',
        reply: 'Standing by for transmission. Please enter your question or choose a navigation route.',
        actions: [
          { label: 'ABOUT', target: 'about' },
          { label: 'SKILLS', target: 'skills' },
          { label: 'MISSIONS', target: 'missions' },
          { label: 'COMMAND', target: 'command' },
          { label: 'UPLINK', target: 'uplink' }
        ]
      });
    }

    const q = rawQuery.toLowerCase();
    const profile = (await ProfileDAO.get()) || {};
    const projects = (await ProjectsDAO.getAll(false)) || [];
    const skills = (await SkillsDAO.getAll()) || [];
    const roles = (await CommandRolesDAO.getAll()) || [];
    const certs = (await CertificationsDAO.getAll()) || [];
    const allEvidence = (await EvidenceDAO.getAll()) || [];

    const name = profile.name || 'J. Byron (Jeycyn Jeff)';
    const location = profile.location || 'Eldoret, Kenya';
    const email = profile.contact_email || 'jeffjeycyn@gmail.com';
    const github = profile.contact_github || 'https://github.com/Jeycyn';
    const linkedin = profile.contact_linkedin || 'https://linkedin.com/in/jeycyn-jeff-3ba769313';
    const web = profile.contact_website || 'https://scarlettechwizards.vercel.app';

    // ──────────────────────────────────────────
    // 1. STRUCTURED INTENT MATCHING (Fast & Offline-Resilient)
    // ──────────────────────────────────────────

    // A. MISSIONS / PROJECTS INTENT
    if (
      q.includes('mission') || q.includes('project') || q.includes('build') ||
      q.includes('portfolio') || q.includes('app') || q.includes('software') ||
      q.includes('doctorscare') || q.includes('multiverse') || q.includes('codejika competition') ||
      q.includes('safebox') || q.includes('work') || q.includes('made')
    ) {
      const projNames = projects.map(p => `• ${p.title} (${p.badge || 'Active'})`).join('\n');
      return res.json({
        intent: 'missions',
        reply: `MISSIONS refers to Jeff's technical projects and software engineering initiatives.\n\nKey featured missions include:\n${projNames || '• DoctorsCare, Multiverse Care, Codejika Competition, Remote Safebox'}\n\nSelect [ OPEN MISSIONS ] to view architecture details, live deployments, repository links, and verified proof artifacts.`,
        actions: [
          { label: 'OPEN MISSIONS', target: 'missions', highlight: true },
          { label: 'VIEW PROOFS', target: 'missions', actionType: 'proof' }
        ]
      });
    }

    // B. COMMAND / LEADERSHIP INTENT
    if (
      q.includes('command') || q.includes('lead') || q.includes('club') ||
      q.includes('organization') || q.includes('mentor') || q.includes('role') ||
      q.includes('scarlet tech') || q.includes('science fair club') || q.includes('junior achiever') ||
      q.includes('peer counselor') || q.includes('position')
    ) {
      const roleList = roles.map(r => `• ${r.title} — ${r.subtitle || 'Leader'}`).join('\n');
      return res.json({
        intent: 'command',
        reply: `COMMAND refers to Jeff's organizational leadership, tech club founding, and mentorship roles.\n\nActive Command Roles:\n${roleList || '• Science Fair Club, Scarlet Tech Wizards, Junior Achievers (JA), Peer Counselor'}\n\nSelect [ OPEN COMMAND ] to inspect leadership records and verified accreditations.`,
        actions: [
          { label: 'OPEN COMMAND', target: 'command', highlight: true },
          { label: 'VIEW CERTIFICATIONS', target: 'command' }
        ]
      });
    }

    // C. CERTIFICATIONS / AWARDS INTENT
    if (
      q.includes('certif') || q.includes('certificate') || q.includes('award') ||
      q.includes('ksef') || q.includes('troph') || q.includes('honor') ||
      q.includes('accredit') || q.includes('win') || q.includes('compet')
    ) {
      const certList = certs.map(c => `• ${c.title} (${c.subtitle || 'Verified'})`).join('\n');
      return res.json({
        intent: 'certifications',
        reply: `CERTIFICATIONS contains documented competition victories and technical honors.\n\nAccredited Records:\n${certList || '• Codejika Project (HTML/JS/CSS), KSEF County Winner 2025'}\n\nSelect [ OPEN CERTIFICATIONS ] to inspect certificates and attached verification proof.`,
        actions: [
          { label: 'OPEN CERTIFICATIONS', target: 'command', highlight: true },
          { label: 'VIEW EVIDENCE PROOF', target: 'command', actionType: 'proof' }
        ]
      });
    }

    // D. SKILLS / CAPABILITIES / RADAR INTENT
    if (
      q.includes('skill') || q.includes('stack') || q.includes('radar') ||
      q.includes('technolog') || q.includes('python') || q.includes('javascript') ||
      q.includes('react') || q.includes('robot') || q.includes('arduino') ||
      q.includes('circuit') || q.includes('cyber') || q.includes('matrix') ||
      q.includes('language') || q.includes('capabilit')
    ) {
      const topSkills = skills.map(s => `${s.name} (${s.proficiency || 80}%)`).join(', ');
      return res.json({
        intent: 'skills',
        reply: `CAPABILITY MATRIX details technical proficiencies across software and hardware engineering:\n• Core proficiencies: ${topSkills || 'HTML5/CSS (92%), Python (85%), Robotics (88%), Git (83%), JavaScript (80%), Circuit Design (78%), React (72%), Cyber Security (45%)'}\n• Features a real-time interactive radar canvas and proficiency telemetry.`,
        actions: [
          { label: 'OPEN SKILLS MATRIX', target: 'skills', highlight: true },
          { label: 'EXPLORE MISSIONS', target: 'missions' }
        ]
      });
    }

    // E. UPLINK / CONTACT / REACH OUT INTENT
    if (
      q.includes('contact') || q.includes('email') || q.includes('hire') ||
      q.includes('uplink') || q.includes('reach') || q.includes('message') ||
      q.includes('linkedin') || q.includes('github') || q.includes('talk') ||
      q.includes('connect') || q.includes('website') || q.includes('call')
    ) {
      return res.json({
        intent: 'uplink',
        reply: `UPLINK is the secure communication channel to contact Jeff:\n• Email: ${email}\n• LinkedIn: ${linkedin}\n• GitHub: ${github}\n• Web: ${web}\n\nSelect [ OPEN UPLINK ] to access direct channels or launch links.`,
        actions: [
          { label: 'OPEN UPLINK', target: 'uplink', highlight: true },
          { label: 'DIRECT EMAIL', externalUrl: `mailto:${email}` },
          { label: 'GITHUB PROFILE', externalUrl: github }
        ]
      });
    }

    // F. PROOF / EVIDENCE / VERIFICATION INTENT
    if (
      q.includes('proof') || q.includes('evidence') || q.includes('verif') ||
      q.includes('document') || q.includes('article') || q.includes('press') ||
      q.includes('validat') || q.includes('claim')
    ) {
      const evCount = allEvidence.length;
      return res.json({
        intent: 'proof',
        reply: `PROOF & EVIDENCE SYSTEM: Verified evidence artifacts (certificates, official documents, press features, media, and external repository links) are attached across:\n• Command Roles\n• Certifications\n• Missions & Projects\n\nThere are currently ${evCount} verified proof records accessible. Click the gold [ 📁 VIEW PROOF ] button on any card on the site to inspect authentic artifacts!`,
        actions: [
          { label: 'VIEW COMMAND PROOFS', target: 'command', actionType: 'proof' },
          { label: 'VIEW MISSION PROOFS', target: 'missions', actionType: 'proof' }
        ]
      });
    }

    // G. ABOUT / WHO IS JEFF / PROFILE INTENT
    if (
      q.includes('who is jeff') || q.includes('who is byron') || q.includes('who are you') ||
      q.includes('about') || q.includes('bio') || q.includes('background') ||
      q.includes('profile') || q.includes('identity') || q.includes('tell me about') ||
      q.includes('location') || q.includes('where is')
    ) {
      return res.json({
        intent: 'about',
        reply: `${name} is an innovative software developer, robotics engineer, and AI systems builder based in ${location}.\n\n• Founder of Scarlet Tech Wizards & creator of Multiverse Care (mental health & emergency response).\n• Winner of County KSEF 2025 and Codejika Coding Competition.\n• Active coding mentor, youth robotics tutor, and science club leader.`,
        actions: [
          { label: 'OPEN OPERATOR PROFILE', target: 'about', highlight: true },
          { label: 'VIEW SKILLS', target: 'skills' },
          { label: 'VIEW MISSIONS', target: 'missions' }
        ]
      });
    }

    // H. SITE NAVIGATION / HELP / GENERAL DIRECTORY INTENT
    if (
      q.includes('help') || q.includes('navigate') || q.includes('lost') ||
      q.includes('find') || q.includes('direction') || q.includes('where') ||
      q.includes('menu') || q.includes('section') || q.includes('start')
    ) {
      return res.json({
        intent: 'help',
        reply: `SYSTEM NAVIGATION DIRECTORY:\n• [ ABOUT ] — Operator profile, biography, and impact stats.\n• [ SKILLS ] — Real-time Capability Matrix & Radar scan.\n• [ MISSIONS ] — Portfolio projects, web apps, and hardware innovations.\n• [ COMMAND ] — Leadership positions, club directorship, and certifications.\n• [ UPLINK ] — Contact coordinates (Email, GitHub, LinkedIn, Website).`,
        actions: [
          { label: 'ABOUT', target: 'about' },
          { label: 'SKILLS', target: 'skills' },
          { label: 'MISSIONS', target: 'missions' },
          { label: 'COMMAND', target: 'command' },
          { label: 'UPLINK', target: 'uplink' }
        ]
      });
    }

    // ──────────────────────────────────────────
    // 2. GEMINI AI SMART FALLBACK (For open-ended natural queries)
    // ──────────────────────────────────────────
    const gemini = getGeminiClient();
    if (gemini) {
      try {
        const systemPrompt = `You are the futuristic Cyber Robot Navigation Assistant for ${name}'s developer portfolio (Scarlet Tech Wizards aesthetic).
Your role is to help visitors understand the website, translate site terminology, find information about Jeff, and navigate to the right sections.

Website Structure:
- ABOUT: Operator profile, bio, statistics (wins, clubs led, drive).
- SKILLS: Technical skills (HTML/CSS, Python, JavaScript, React, Arduino/Robotics, Circuit Design, Git, Cyber Security) and radar chart.
- MISSIONS: Technical projects and hardware solutions (${projects.map(p => p.title).join(', ')}).
- COMMAND: Leadership roles and organizations (${roles.map(r => r.title).join(', ')}), plus Certifications (${certs.map(c => c.title).join(', ')}).
- UPLINK: Contact methods (Email: ${email}, GitHub: ${github}, LinkedIn: ${linkedin}, Web: ${web}).
- PROOF: Evidence artifacts (certificates, articles, documents, photos) attached to command roles, certs, and missions.

Guidelines:
- Speak in a concise, helpful, cyber-tactical tone with terminal formatting.
- Ground all facts strictly in Jeff's public portfolio. Never invent credentials or fake projects.
- NEVER reveal administrative passwords, CMS login details, tokens, backend secrets, or private database fields.
- Keep answers under 3-4 sentences. Suggest where on the site the user should look.`;

        const response = await gemini.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: [
            { role: 'user', parts: [{ text: `System Context:\n${systemPrompt}\n\nVisitor Question: "${rawQuery}"` }] }
          ]
        });

        const textResponse = response.text || '';
        if (textResponse.trim()) {
          // Detect appropriate action targets based on response content
          const actions = [];
          const lowerResp = textResponse.toLowerCase();
          if (lowerResp.includes('mission') || lowerResp.includes('project')) actions.push({ label: 'OPEN MISSIONS', target: 'missions' });
          if (lowerResp.includes('skill') || lowerResp.includes('radar')) actions.push({ label: 'OPEN SKILLS', target: 'skills' });
          if (lowerResp.includes('command') || lowerResp.includes('lead') || lowerResp.includes('certif')) actions.push({ label: 'OPEN COMMAND', target: 'command' });
          if (lowerResp.includes('uplink') || lowerResp.includes('contact') || lowerResp.includes('email')) actions.push({ label: 'OPEN UPLINK', target: 'uplink' });
          if (lowerResp.includes('about') || lowerResp.includes('profile')) actions.push({ label: 'OPEN ABOUT', target: 'about' });
          if (actions.length === 0) {
            actions.push({ label: 'ABOUT', target: 'about' }, { label: 'MISSIONS', target: 'missions' }, { label: 'SKILLS', target: 'skills' });
          }

          return res.json({
            intent: 'ai_response',
            reply: textResponse.trim(),
            actions
          });
        }
      } catch (aiErr) {
        console.warn('[ASSISTANT AI] Gemini API fallback error, using deterministic router:', aiErr.message);
      }
    }

    // Default Safe Fallback
    return res.json({
      intent: 'general_fallback',
      reply: `TRANSMISSION RECEIVED: "${rawQuery}"\n\nI can guide you directly to any operational sector:\n• MISSIONS (Projects & Systems)\n• SKILLS (Capability Matrix)\n• COMMAND (Leadership & Certifications)\n• UPLINK (Contact Channels)\n• ABOUT (Operator Profile)`,
      actions: [
        { label: 'ABOUT', target: 'about' },
        { label: 'SKILLS', target: 'skills' },
        { label: 'MISSIONS', target: 'missions' },
        { label: 'COMMAND', target: 'command' },
        { label: 'UPLINK', target: 'uplink' }
      ]
    });
  } catch (err) {
    console.error('[ASSISTANT] Error handling query:', err);
    res.status(500).json({
      error: 'PROCESSING_ERROR',
      reply: 'SYSTEM RE-ROUTING // Navigation channels available below:',
      actions: [
        { label: 'ABOUT', target: 'about' },
        { label: 'SKILLS', target: 'skills' },
        { label: 'MISSIONS', target: 'missions' },
        { label: 'COMMAND', target: 'command' },
        { label: 'UPLINK', target: 'uplink' }
      ]
    });
  }
});

/* ══════════════════════════════════════════════
   FILE UPLOAD API (Validates, Resizes & Persists to Storage / Local Disk)
══════════════════════════════════════════════ */
app.post('/api/upload', requireAdminApi, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError || (err.message && err.message.includes('INVALID_FILE_TYPE'))) {
        return res.status(400).json({ error: err.message });
      }
      return res.status(400).json({ error: 'UPLOAD_ERROR: ' + (err.message || 'Invalid file') });
    }
    next();
  });
}, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'NO_FILE_UPLOADED' });
    }

    const folder = req.body.folder || 'general';
    const isPrivate = req.body.is_private === 'true' || req.body.is_private === true;

    const result = await uploadAsset({
      buffer: req.file.buffer,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
      folder,
      isPrivate
    });

    res.json({
      success: true,
      message: 'ASSET_STORED',
      url: result.url,
      storagePath: result.storagePath,
      filename: result.filename,
      isPrivate: result.isPrivate,
      size: result.size
    });
  } catch (err) {
    res.status(500).json({ error: 'UPLOAD_FAILED: ' + err.message });
  }
});

// Pre-signed Upload URL endpoint (Bypasses Vercel 4.5MB limits)
app.post('/api/upload/signed-url', requireAdminApi, async (req, res) => {
  try {
    const { filename, mime_type, folder, is_private } = req.body;
    if (!filename || !mime_type) {
      return res.status(400).json({ error: 'Filename and mime_type are required.' });
    }

    const signedData = await getSignedUploadUrl(
      filename,
      mime_type,
      folder || 'evidence',
      Boolean(is_private)
    );

    if (!signedData) {
      return res.status(501).json({ error: 'STORAGE_UNCONFIGURED: Direct signed uploads require Storage configuration.' });
    }

    res.json({
      success: true,
      ...signedData
    });
  } catch (err) {
    res.status(500).json({ error: 'SIGNED_URL_FAILED: ' + err.message });
  }
});

// Private Evidence Artifact Retrieval
app.get('/api/evidence/private/:storagePath', async (req, res) => {
  try {
    const storagePath = decodeURIComponent(req.params.storagePath);
    if (!storagePath || storagePath.includes('..')) {
      return res.status(400).json({ error: 'INVALID_PATH' });
    }

    // Require either active admin session or valid signed clearance
    const admin = await getAdminSessionFromReq(req);
    if (!admin) {
      const clearanceToken = req.query.gt || req.cookies?.gateway_clearance;
      const clearance = verifyToken(clearanceToken);
      if (!clearance || clearance.type !== 'gateway_clearance') {
        return res.status(403).json({ error: 'UNAUTHORIZED_ARTIFACT_ACCESS' });
      }
    }

    const signedUrl = await getPrivateSignedUrl(storagePath, 15);
    if (signedUrl) {
      return res.redirect(signedUrl);
    }

    // Fallback: check local uploads
    const localTarget = path.join(UPLOADS_DIR, path.basename(storagePath));
    if (fs.existsSync(localTarget)) {
      return res.sendFile(localTarget);
    }

    res.status(404).json({ error: 'ARTIFACT_NOT_FOUND' });
  } catch (err) {
    res.status(500).json({ error: 'RETRIEVAL_FAILED: ' + err.message });
  }
});

// Centralized Error Handling Middleware (e.g., Multer validation errors)
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || (err.message && err.message.includes('INVALID_FILE_TYPE'))) {
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(500).json({ error: err.message || 'SERVER_ERROR' });
  }
  next();
});

/* ══════════════════════════════════════════════
   PUBLIC HTML SERVING WITH DYNAMIC SEO INJECTION
══════════════════════════════════════════════ */
async function renderIndexHtmlWithSEO(req) {
  let html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  try {
    const settings = await SiteSettingsDAO.get();
    const profile = (await ProfileDAO.get()) || {};
    const baseUrl = await getBaseSiteUrl(req);

    const pageTitle = escapeXml(settings.site_title || `${profile.name || 'Jeycyn.Jeff'} || ${profile.callsign || 'DEV-001'}`);
    const metaDesc = escapeXml(settings.meta_description || profile.bio || profile.tagline || 'Interactive developer portfolio');
    const robotsPolicy = escapeXml(settings.robots_policy || 'index, follow');
    const canonical = escapeXml(settings.canonical_url ? settings.canonical_url.trim() : `${baseUrl}/`);

    // Favicon URL
    let faviconUrl = '/favicon.ico';
    if (settings.favicon_path && settings.favicon_path.trim()) {
      faviconUrl = escapeXml(settings.favicon_path.trim());
    }

    // Social Share Image
    let socialImg = `${baseUrl}/uploads/social_card.png`;
    if (settings.social_image_path && settings.social_image_path.trim()) {
      const sPath = settings.social_image_path.trim();
      socialImg = sPath.startsWith('http') ? escapeXml(sPath) : escapeXml(`${baseUrl}${sPath.startsWith('/') ? '' : '/'}${sPath}`);
    } else if (profile.photo_path && profile.photo_path.trim()) {
      const pPath = profile.photo_path.trim();
      socialImg = pPath.startsWith('http') ? escapeXml(pPath) : escapeXml(`${baseUrl}${pPath.startsWith('/') ? '' : '/'}${pPath}`);
    }

    // JSON-LD Structured Data for Person & Portfolio
    const structuredData = {
      "@context": "https://schema.org",
      "@type": "Person",
      "name": profile.name || "Jeycyn Jeff",
      "alternateName": profile.callsign || "DEV-001",
      "jobTitle": profile.tagline || "Full-Stack Software Engineer & AI Systems Architect",
      "description": settings.meta_description || profile.bio || "",
      "url": baseUrl,
      "image": socialImg,
      "address": {
        "@type": "PostalAddress",
        "addressLocality": profile.location || "Eldoret",
        "addressCountry": "KE"
      },
      "sameAs": [
        profile.contact_github || "",
        profile.contact_linkedin || "",
        profile.contact_website || ""
      ].filter(Boolean)
    };

    const seoTags = `
<title>${pageTitle}</title>
<meta name="description" content="${metaDesc}"/>
<meta name="robots" content="${robotsPolicy}"/>
<link rel="canonical" href="${canonical}"/>
<link rel="icon" href="${faviconUrl}"/>
<link rel="shortcut icon" href="${faviconUrl}"/>
<link rel="apple-touch-icon" href="${faviconUrl}"/>

<!-- Open Graph / Facebook -->
<meta property="og:type" content="website"/>
<meta property="og:url" content="${canonical}"/>
<meta property="og:title" content="${pageTitle}"/>
<meta property="og:description" content="${metaDesc}"/>
<meta property="og:image" content="${socialImg}"/>

<!-- Twitter / X -->
<meta name="twitter:card" content="summary_large_image"/>
<meta name="twitter:url" content="${canonical}"/>
<meta name="twitter:title" content="${pageTitle}"/>
<meta name="twitter:description" content="${metaDesc}"/>
<meta name="twitter:image" content="${socialImg}"/>

<!-- Schema.org JSON-LD Structured Data -->
<script type="application/ld+json">
${JSON.stringify(structuredData, null, 2)}
</script>
`;

    // Replace <title> tag and insert dynamic SEO block
    if (html.includes('<title>')) {
      html = html.replace(/<title>[\s\S]*?<\/title>/i, '');
    }
    // Remove existing meta description/robots if any to prevent duplicates
    html = html.replace(/<meta\s+name=["']description["'][\s\S]*?>/gi, '');
    html = html.replace(/<meta\s+name=["']robots["'][\s\S]*?>/gi, '');
    html = html.replace(/<link\s+rel=["']canonical["'][\s\S]*?>/gi, '');
    html = html.replace(/<link\s+rel=["'](?:shortcut )?icon["'][\s\S]*?>/gi, '');
    html = html.replace(/<meta\s+property=["']og:[\s\S]*?>/gi, '');
    html = html.replace(/<meta\s+name=["']twitter:[\s\S]*?>/gi, '');

    // Inject into head
    html = html.replace('</head>', `${seoTags}\n</head>`);
  } catch (err) {
    console.error('[SEO] Error injecting SEO tags into HTML:', err);
  }
  return html;
}

/* ══════════════════════════════════════════════
   FALLBACK ROUTE
══════════════════════════════════════════════ */
app.get(['/', '/index.html'], async (req, res) => {
  const html = await renderIndexHtmlWithSEO(req);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

app.get('*', async (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API_ENDPOINT_NOT_FOUND' });
  }
  if (path.extname(req.path)) {
    return res.status(404).json({ error: 'FILE_NOT_FOUND' });
  }
  const html = await renderIndexHtmlWithSEO(req);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// Production & local server listener (conditioned for Vercel serverless)
if (!process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at http://0.0.0.0:${PORT}`);
  });
}

export default app;