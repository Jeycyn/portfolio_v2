import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const { Pool } = pg;

// node:sqlite is only used as a local-dev fallback when no Supabase/Postgres
// credentials are configured. It's a newer Node core module that many
// serverless runtimes (including Vercel's default Node version) don't ship,
// so it must be loaded lazily via require() — wrapped in try/catch — instead
// of a static top-level import. A static import would throw at module load
// time on unsupported runtimes and crash every request, even when the app
// never actually needs the SQLite fallback (e.g. once Supabase is configured).
let DatabaseSync = null;
try {
  const require = createRequire(import.meta.url);
  ({ DatabaseSync } = require('node:sqlite'));
} catch (err) {
  console.warn('[DATABASE] node:sqlite unavailable in this runtime — local SQLite fallback disabled. This is expected on Vercel; fine as long as Supabase/Postgres env vars are set.');
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, 'data');
const SQLITE_DB_PATH = path.join(DATA_DIR, 'content.db');

// ══════════════════════════════════════════════
// SUPABASE & POSTGRESQL CONFIGURATION
// ══════════════════════════════════════════════
const rawUrl = process.env.SUPABASE_URL || process.env.DATABASE_URL;
const SUPABASE_URL = rawUrl && rawUrl.startsWith('http') ? rawUrl.trim() : (process.env.SUPABASE_URL ? process.env.SUPABASE_URL.trim() : null);
const SUPABASE_KEY = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || process.env.SUPABASE_ANON_KEY;

// Check if PostgreSQL direct connection string is provided
const POSTGRES_URL = process.env.DATABASE_URL && (process.env.DATABASE_URL.startsWith('postgres://') || process.env.DATABASE_URL.startsWith('postgresql://'))
  ? process.env.DATABASE_URL.trim()
  : null;

let supabaseClient = null;
let pgPool = null;
let sqliteFallbackDb = null;

let isSupabaseActive = false;
let isPgPoolActive = false;
const warnedTables = new Set();

if (SUPABASE_URL && SUPABASE_KEY) {
  try {
    supabaseClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    });
    isSupabaseActive = true;
    console.log('[DATABASE] Supabase REST client initialized successfully.');
  } catch (err) {
    console.error('[DATABASE] Error initializing Supabase client:', err.message);
  }
}

if (POSTGRES_URL && !isSupabaseActive) {
  try {
    pgPool = new Pool({
      connectionString: POSTGRES_URL,
      ssl: POSTGRES_URL.includes('localhost') || POSTGRES_URL.includes('127.0.0.1')
        ? false
        : { rejectUnauthorized: false },
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    });
    pgPool.on('error', (err) => {
      console.error('[POSTGRES POOL ERROR]', err.message);
    });
    isPgPoolActive = true;
    console.log('[DATABASE] PostgreSQL Pool initialized successfully.');
  } catch (err) {
    console.error('[DATABASE] Error initializing PostgreSQL pool:', err.message);
  }
}

if (!isSupabaseActive && !isPgPoolActive) {
  console.warn('[DATABASE] Notice: SUPABASE_URL/SUPABASE_SECRET_KEY not set. Operating in local SQLite fallback mode.');
}

export function getDatabaseStatus() {
  return {
    isSupabase: isSupabaseActive,
    isPostgresPool: isPgPoolActive,
    isSqliteFallback: !isSupabaseActive && !isPgPoolActive,
    supabaseUrl: SUPABASE_URL ? `${SUPABASE_URL.substring(0, 18)}...` : null
  };
}

// Fallback SQLite database accessor
function getSqliteDb() {
  if (!sqliteFallbackDb) {
    if (!DatabaseSync) {
      throw new Error('SQLite fallback is unavailable in this runtime and no Supabase/Postgres connection is configured. Set SUPABASE_URL/SUPABASE_SECRET_KEY (or DATABASE_URL) in your environment.');
    }
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    sqliteFallbackDb = new DatabaseSync(SQLITE_DB_PATH);
    sqliteFallbackDb.exec('PRAGMA journal_mode = WAL;');
    sqliteFallbackDb.exec('PRAGMA synchronous = NORMAL;');
  }
  return sqliteFallbackDb;
}

/**
 * Checks if an error from Supabase is due to uninitialized schema/table
 */
function isSupabaseSchemaError(error) {
  if (!error) return false;
  const msg = (error.message || '').toLowerCase();
  const code = (error.code || '').toUpperCase();
  return (
    msg.includes('could not find the table') ||
    msg.includes('schema cache') ||
    msg.includes('relation') ||
    msg.includes('does not exist') ||
    msg.includes('fetch failed') ||
    code === 'PGRST200' ||
    code === 'PGRST204' ||
    code === '42P01'
  );
}

function logSupabaseFallbackWarning(tableName, error) {
  if (!warnedTables.has(tableName)) {
    warnedTables.add(tableName);
    console.warn(`[SUPABASE FALLBACK] Remote table '${tableName}' uninitialized in Supabase (${error?.message || 'schema cache'}). Serving seamlessly from local SQLite store.`);
  }
}

/**
 * Execute parameterized query for Postgres pool or SQLite fallback
 */
export async function query(text, params = []) {
  if (isPgPoolActive && pgPool) {
    return await pgPool.query(text, params);
  }

  // SQLite query translation
  const sqlite = getSqliteDb();
  let sqliteSql = text;
  let counter = 1;
  while (sqliteSql.includes(`$${counter}`)) {
    sqliteSql = sqliteSql.replace(new RegExp(`\\$${counter}\\b`, 'g'), '?');
    counter++;
  }

  sqliteSql = sqliteSql
    .replace(/RETURNING \*/gi, '')
    .replace(/TIMESTAMPTZ/gi, 'TEXT')
    .replace(/NOW\(\)/gi, "datetime('now')")
    .replace(/CURRENT_TIMESTAMP/gi, "datetime('now')");

  const trimmed = sqliteSql.trim().toUpperCase();
  if (trimmed.startsWith('SELECT')) {
    const stmt = sqlite.prepare(sqliteSql);
    const rows = stmt.all(...params);
    return { rows, rowCount: rows.length };
  } else {
    const stmt = sqlite.prepare(sqliteSql);
    const result = stmt.run(...params);
    return {
      rows: result.lastInsertRowid ? [{ id: Number(result.lastInsertRowid) }] : [],
      rowCount: result.changes,
      lastInsertRowid: result.lastInsertRowid
    };
  }
}

// ══════════════════════════════════════════════
// DATABASE INITIALIZATION & SEEDING
// ══════════════════════════════════════════════
export async function initDatabase() {
  // Only initialize the local SQLite fallback when Supabase isn't configured.
  // On serverless platforms like Vercel, the filesystem outside /tmp is
  // read-only — attempting to mkdir a local data/uploads folder there always
  // throws, so this must never run when Supabase is already handling storage.
  if (!isSupabaseActive || !supabaseClient) {
    try {
      initSqliteSchema();
      seedSqliteBaseline();
    } catch (err) {
      console.warn('[DATABASE] Local SQLite fallback unavailable in this environment:', err.message);
    }
  }

  if (isSupabaseActive && supabaseClient) {
    try {
      await seedOrMigrateSupabase();
    } catch (err) {
      console.warn('[DATABASE] Supabase check notice:', err.message);
    }
    return;
  }

  if (isPgPoolActive && pgPool) {
    try {
      await initPostgresSchema();
      console.log('[DATABASE] PostgreSQL Pool schema verified.');
    } catch (err) {
      console.error('[DATABASE] PostgreSQL schema error:', err.message);
    }
  }
}

function initSqliteSchema() {
  const sqlite = getSqliteDb();
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS profile (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      name TEXT NOT NULL,
      callsign TEXT NOT NULL,
      secondary_handle TEXT,
      tagline TEXT,
      bio TEXT,
      stat_wins TEXT,
      stat_clubs TEXT,
      stat_drive TEXT,
      command_roles TEXT,
      certifications TEXT,
      contact_email TEXT,
      contact_github TEXT,
      contact_linkedin TEXT,
      contact_website TEXT,
      location TEXT,
      status TEXT,
      photo_path TEXT,
      updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      badge TEXT,
      badge_type TEXT DEFAULT 'badge-g',
      description TEXT NOT NULL,
      project_url TEXT,
      repo_url TEXT,
      image_path TEXT,
      display_order INTEGER DEFAULT 0,
      visibility INTEGER DEFAULT 1,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS skills (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      proficiency INTEGER NOT NULL,
      category TEXT DEFAULT 'breakdown',
      radar_label TEXT,
      is_radar INTEGER DEFAULT 0,
      display_order INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS command_roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      subtitle TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS certifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      subtitle TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_type TEXT NOT NULL,
      target_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      url TEXT,
      file_path TEXT,
      source_label TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target_type, target_id);

    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS admin_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      ip TEXT,
      user_agent TEXT,
      created_at TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked INTEGER DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES admin_users(id)
    );

    CREATE TABLE IF NOT EXISTS gateway_config (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      grid_size INTEGER DEFAULT 3,
      symbols TEXT NOT NULL,
      solution TEXT NOT NULL,
      initial_scramble TEXT NOT NULL,
      passcode_hash TEXT NOT NULL,
      updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS gateway_config_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      config_snapshot TEXT NOT NULL,
      note TEXT,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS gateway_audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      ip TEXT NOT NULL,
      attempt_type TEXT NOT NULL,
      outcome TEXT NOT NULL,
      details TEXT
    );

    CREATE TABLE IF NOT EXISTS site_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      site_title TEXT NOT NULL DEFAULT 'Jeycyn.Jeff || DEV-001',
      meta_description TEXT NOT NULL DEFAULT 'Innovative software developer, robotics engineer, and AI systems builder based in Eldoret, Kenya. Founder of Scarlet Tech Wizards.',
      favicon_path TEXT DEFAULT '',
      social_image_path TEXT DEFAULT '',
      canonical_url TEXT DEFAULT '',
      robots_policy TEXT NOT NULL DEFAULT 'index, follow',
      updated_at TEXT
    );
  `);
}

function seedSqliteBaseline() {
  const sqlite = getSqliteDb();

  // Admin user — never seed a known/default password. Use ADMIN_INITIAL_PASSWORD
  // if provided, otherwise generate a strong random one and print it ONCE so
  // it can be captured and stored (e.g. in a password manager).
  const admin = sqlite.prepare('SELECT id FROM admin_users LIMIT 1').get();
  if (!admin) {
    const initialPassword = process.env.ADMIN_INITIAL_PASSWORD || crypto.randomBytes(12).toString('base64url');
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(initialPassword, salt);
    sqlite.prepare('INSERT INTO admin_users (id, username, password_hash, created_at) VALUES (1, ?, ?, datetime(\'now\'))').run('admin', hash);
    if (!process.env.ADMIN_INITIAL_PASSWORD) {
      console.warn(`[DATABASE] Generated initial admin password (shown once): admin / ${initialPassword}`);
    }
  }

  // Profile
  const profile = sqlite.prepare('SELECT id FROM profile WHERE id = 1').get();
  if (!profile) {
    const defaultBio = "Innovative software developer and robotics engineer based in Eldoret, Kenya. Founder of Scarlet Tech Wizards and creator of Multiverse Care, a futuristic mental health and emergency response platform integrating AI-powered healthcare systems. Builder of scalable, impact-driven systems across healthcare, security hardware, robotics, and education technology. Passionate about developing smart automation systems, embedded electronics, and futuristic human-centered innovations. Active coding tutor and robotics mentor — engineering the next generation of African tech innovators. Winner of the Codejika Coding Competition and recognized science fair innovator. Currently expanding into Cyber Security, AI, Machine Learning, and next-generation intelligent systems.";
    sqlite.prepare(`
      INSERT INTO profile (
        id, name, callsign, secondary_handle, tagline, bio,
        stat_wins, stat_clubs, stat_drive, command_roles, certifications,
        contact_email, contact_github, contact_linkedin, contact_website,
        location, status, photo_path, updated_at
      ) VALUES (
        1, 'J.BYRON', 'DEV-001', '[JEYCYN JEFF]', 'SOFTWARE DEVELOPER · ROBOTICS ENGINEER · AI SYSTEMS', ?,
        '2+', '4', '∞', '[]', '[]',
        'jeffjeycyn@gmail.com', 'https://github.com/Jeycyn', 'https://linkedin.com/in/jeycyn-jeff-3ba769313', 'https://scarlettechwizards.vercel.app',
        'ELDORET-KE', 'ARMED', '', datetime('now')
      )
    `).run(defaultBio);
  }

  // Gateway config
  const gw = sqlite.prepare('SELECT id FROM gateway_config WHERE id = 1').get();
  if (!gw) {
    const defaultSymbols = JSON.stringify(["ᚠ", "ᚢ", "ᚦ", "ᚨ", "ᚱ", "ᚲ", "ᚷ", "ᚹ"]);
    const defaultSolution = JSON.stringify([0, 1, 2, 3, 4, 5, 6, 7, null]);
    const defaultScramble = JSON.stringify([3, 0, 2, 6, 1, 4, 7, null, 5]);
    const salt = bcrypt.genSaltSync(10);
    const initialPasscode = process.env.GATEWAY_INITIAL_PASSCODE || crypto.randomBytes(9).toString('base64url');
    const defaultPassHash = bcrypt.hashSync(initialPasscode, salt);
    sqlite.prepare(`
      INSERT INTO gateway_config (id, grid_size, symbols, solution, initial_scramble, passcode_hash, updated_at)
      VALUES (1, 3, ?, ?, ?, ?, datetime('now'))
    `).run(defaultSymbols, defaultSolution, defaultScramble, defaultPassHash);
    if (!process.env.GATEWAY_INITIAL_PASSCODE) {
      console.warn(`[DATABASE] Generated initial gateway passcode (shown once): ${initialPasscode}`);
    }
  }

  // Site settings
  const site = sqlite.prepare('SELECT id FROM site_settings WHERE id = 1').get();
  if (!site) {
    sqlite.prepare(`
      INSERT INTO site_settings (id, site_title, meta_description, favicon_path, social_image_path, canonical_url, robots_policy, updated_at)
      VALUES (1, 'Jeycyn.Jeff || DEV-001', 'Innovative software developer, robotics engineer, and AI systems builder based in Eldoret, Kenya. Founder of Scarlet Tech Wizards.', '', '', '', 'index, follow', datetime('now'))
    `).run();
  }
}

async function initPostgresSchema() {
  await query(`
    CREATE TABLE IF NOT EXISTS profile (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      name TEXT NOT NULL,
      callsign TEXT NOT NULL,
      secondary_handle TEXT,
      tagline TEXT,
      bio TEXT,
      stat_wins TEXT,
      stat_clubs TEXT,
      stat_drive TEXT,
      command_roles TEXT,
      certifications TEXT,
      contact_email TEXT,
      contact_github TEXT,
      contact_linkedin TEXT,
      contact_website TEXT,
      location TEXT,
      status TEXT,
      photo_path TEXT,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      badge TEXT,
      badge_type TEXT DEFAULT 'badge-g',
      description TEXT NOT NULL,
      project_url TEXT,
      repo_url TEXT,
      image_path TEXT,
      display_order INTEGER DEFAULT 0,
      visibility INTEGER DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS skills (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      proficiency INTEGER NOT NULL,
      category TEXT DEFAULT 'breakdown',
      radar_label TEXT,
      is_radar INTEGER DEFAULT 0,
      display_order INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS command_roles (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      subtitle TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS certifications (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      subtitle TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS evidence (
      id SERIAL PRIMARY KEY,
      target_type TEXT NOT NULL,
      target_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      url TEXT,
      file_path TEXT,
      source_label TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target_type, target_id);

    CREATE TABLE IF NOT EXISTS admin_users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS admin_sessions (
      id SERIAL PRIMARY KEY,
      token_hash TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
      username TEXT NOT NULL,
      ip TEXT,
      user_agent TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      expires_at BIGINT NOT NULL,
      revoked INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(token_hash);

    CREATE TABLE IF NOT EXISTS gateway_config (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      grid_size INTEGER DEFAULT 3,
      symbols TEXT NOT NULL,
      solution TEXT NOT NULL,
      initial_scramble TEXT NOT NULL,
      passcode_hash TEXT NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS gateway_config_history (
      id SERIAL PRIMARY KEY,
      config_snapshot TEXT NOT NULL,
      note TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS gateway_audit_logs (
      id SERIAL PRIMARY KEY,
      timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      ip TEXT NOT NULL,
      attempt_type TEXT NOT NULL,
      outcome TEXT NOT NULL,
      details TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_gateway_audit_time ON gateway_audit_logs(timestamp DESC);

    CREATE TABLE IF NOT EXISTS site_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      site_title TEXT NOT NULL DEFAULT 'Jeycyn.Jeff || DEV-001',
      meta_description TEXT NOT NULL DEFAULT 'Innovative software developer, robotics engineer, and AI systems builder based in Eldoret, Kenya. Founder of Scarlet Tech Wizards.',
      favicon_path TEXT DEFAULT '',
      social_image_path TEXT DEFAULT '',
      canonical_url TEXT DEFAULT '',
      robots_policy TEXT NOT NULL DEFAULT 'index, follow',
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

async function seedOrMigrateSupabase() {
  if (!supabaseClient) return;

  const { data: users, error } = await supabaseClient.from('admin_users').select('id').limit(1);
  if (error) {
    if (isSupabaseSchemaError(error)) {
      console.warn('[SUPABASE NOTICE] Supabase PostgreSQL tables not detected yet. To initialize remote tables, run `supabase_schema.sql` in Supabase SQL Editor. App will seamlessly serve from local fallback.');
    } else {
      console.warn('[SUPABASE] Notice on admin_users query:', error.message);
    }
    return;
  }

  if (!users || users.length === 0) {
    console.log('[SUPABASE] Fresh database detected. Hydrating initial baseline from SQLite / defaults...');

    // If SQLite exists, transfer all tables
    if (DatabaseSync && fs.existsSync(SQLITE_DB_PATH)) {
      try {
        const sqlite = new DatabaseSync(SQLITE_DB_PATH);

        // 1. Profile
        const prof = sqlite.prepare('SELECT * FROM profile WHERE id = 1').get();
        if (prof) {
          await supabaseClient.from('profile').upsert({
            id: 1,
            name: prof.name,
            callsign: prof.callsign,
            secondary_handle: prof.secondary_handle,
            tagline: prof.tagline,
            bio: prof.bio,
            stat_wins: prof.stat_wins,
            stat_clubs: prof.stat_clubs,
            stat_drive: prof.stat_drive,
            command_roles: prof.command_roles,
            certifications: prof.certifications,
            contact_email: prof.contact_email,
            contact_github: prof.contact_github,
            contact_linkedin: prof.contact_linkedin,
            contact_website: prof.contact_website,
            location: prof.location,
            status: prof.status,
            photo_path: prof.photo_path
          });
        }

        // 2. Admin Users
        const adminUsers = sqlite.prepare('SELECT * FROM admin_users').all();
        if (adminUsers.length > 0) {
          await supabaseClient.from('admin_users').upsert(adminUsers);
        }

        // 3. Projects
        const projects = sqlite.prepare('SELECT * FROM projects').all();
        if (projects.length > 0) {
          await supabaseClient.from('projects').upsert(projects);
        }

        // 4. Skills
        const skills = sqlite.prepare('SELECT * FROM skills').all();
        if (skills.length > 0) {
          await supabaseClient.from('skills').upsert(skills);
        }

        // 5. Command Roles
        const roles = sqlite.prepare('SELECT * FROM command_roles').all();
        if (roles.length > 0) {
          await supabaseClient.from('command_roles').upsert(roles);
        }

        // 6. Certifications
        const certs = sqlite.prepare('SELECT * FROM certifications').all();
        if (certs.length > 0) {
          await supabaseClient.from('certifications').upsert(certs);
        }

        // 7. Evidence
        const evidence = sqlite.prepare('SELECT * FROM evidence').all();
        if (evidence.length > 0) {
          await supabaseClient.from('evidence').upsert(evidence);
        }

        // 8. Gateway Config
        const gwConfig = sqlite.prepare('SELECT * FROM gateway_config WHERE id = 1').get();
        if (gwConfig) {
          await supabaseClient.from('gateway_config').upsert({
            id: 1,
            grid_size: gwConfig.grid_size,
            symbols: gwConfig.symbols,
            solution: gwConfig.solution,
            initial_scramble: gwConfig.initial_scramble,
            passcode_hash: gwConfig.passcode_hash
          });
        }

        // 9. Site Settings
        const site = sqlite.prepare('SELECT * FROM site_settings WHERE id = 1').get();
        if (site) {
          await supabaseClient.from('site_settings').upsert({
            id: 1,
            site_title: site.site_title,
            meta_description: site.meta_description,
            favicon_path: site.favicon_path,
            social_image_path: site.social_image_path,
            canonical_url: site.canonical_url,
            robots_policy: site.robots_policy
          });
        }

        console.log('[SUPABASE] Successfully hydrated all SQLite records into Supabase.');
      } catch (e) {
        console.error('[SUPABASE] Error copying from SQLite:', e.message);
      }
    }
  }
}

// ══════════════════════════════════════════════
// DATA ACCESS OBJECTS (DAOs)
// Unified Supabase REST / PostgreSQL / SQLite Engine
// ══════════════════════════════════════════════

export const EvidenceDAO = {
  async getByTarget(targetType, targetId) {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('evidence')
          .select('*')
          .eq('target_type', targetType)
          .eq('target_id', Number(targetId))
          .order('display_order', { ascending: true })
          .order('id', { ascending: true });
        if (!error && data) return data;
        if (error) logSupabaseFallbackWarning('evidence', error);
      } catch (err) {
        logSupabaseFallbackWarning('evidence', err);
      }
    }
    const res = await query(
      'SELECT * FROM evidence WHERE target_type = $1 AND target_id = $2 ORDER BY display_order ASC, id ASC',
      [targetType, Number(targetId)]
    );
    return res.rows;
  },
  async getAll() {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('evidence')
          .select('*')
          .order('target_type', { ascending: true })
          .order('target_id', { ascending: true })
          .order('display_order', { ascending: true })
          .order('id', { ascending: true });
        if (!error && data) return data;
        if (error) logSupabaseFallbackWarning('evidence', error);
      } catch (err) {
        logSupabaseFallbackWarning('evidence', err);
      }
    }
    const res = await query(
      'SELECT * FROM evidence ORDER BY target_type, target_id, display_order ASC, id ASC'
    );
    return res.rows;
  },
  async getById(id) {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('evidence')
          .select('*')
          .eq('id', Number(id))
          .maybeSingle();
        if (!error && data) return data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('evidence', error);
      } catch (err) {
        logSupabaseFallbackWarning('evidence', err);
      }
    }
    const res = await query('SELECT * FROM evidence WHERE id = $1', [Number(id)]);
    return res.rows[0] || null;
  },
  async create(data) {
    const payload = {
      target_type: data.target_type,
      target_id: Number(data.target_id),
      type: data.type || 'link',
      title: data.title || 'Evidence Artifact',
      description: data.description || '',
      url: data.url || '',
      file_path: data.file_path || '',
      source_label: data.source_label || '',
      display_order: Number(data.display_order) || 0
    };

    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: created, error } = await supabaseClient
          .from('evidence')
          .insert(payload)
          .select()
          .single();
        if (!error && created) return created;
        if (error) logSupabaseFallbackWarning('evidence', error);
      } catch (err) {
        logSupabaseFallbackWarning('evidence', err);
      }
    }

    const res = await query(`
      INSERT INTO evidence (
        target_type, target_id, type, title, description,
        url, file_path, source_label, display_order, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
      RETURNING *
    `, [
      payload.target_type, payload.target_id, payload.type,
      payload.title, payload.description, payload.url,
      payload.file_path, payload.source_label, payload.display_order
    ]);
    return res.rows[0] || null;
  },
  async update(id, data) {
    const current = await EvidenceDAO.getById(id);
    if (!current) return null;

    const payload = {
      target_type: data.target_type !== undefined ? data.target_type : current.target_type,
      target_id: data.target_id !== undefined ? Number(data.target_id) : current.target_id,
      type: data.type !== undefined ? data.type : current.type,
      title: data.title !== undefined ? data.title : current.title,
      description: data.description !== undefined ? data.description : current.description,
      url: data.url !== undefined ? data.url : current.url,
      file_path: data.file_path !== undefined ? data.file_path : current.file_path,
      source_label: data.source_label !== undefined ? data.source_label : current.source_label,
      display_order: data.display_order !== undefined ? Number(data.display_order) : current.display_order
    };

    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: updated, error } = await supabaseClient
          .from('evidence')
          .update(payload)
          .eq('id', Number(id))
          .select()
          .single();
        if (!error && updated) return updated;
        if (error) logSupabaseFallbackWarning('evidence', error);
      } catch (err) {
        logSupabaseFallbackWarning('evidence', err);
      }
    }

    const res = await query(`
      UPDATE evidence SET
        target_type = $1, target_id = $2, type = $3, title = $4, description = $5,
        url = $6, file_path = $7, source_label = $8, display_order = $9
      WHERE id = $10
      RETURNING *
    `, [
      payload.target_type, payload.target_id, payload.type,
      payload.title, payload.description, payload.url,
      payload.file_path, payload.source_label, payload.display_order,
      Number(id)
    ]);
    return res.rows[0] || null;
  },
  async delete(id) {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('evidence').delete().eq('id', Number(id));
        if (!error) return true;
        if (error) logSupabaseFallbackWarning('evidence', error);
      } catch (err) {
        logSupabaseFallbackWarning('evidence', err);
      }
    }
    const res = await query('DELETE FROM evidence WHERE id = $1', [Number(id)]);
    return res.rowCount > 0;
  },
  async deleteByTarget(targetType, targetId) {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient
          .from('evidence')
          .delete()
          .eq('target_type', targetType)
          .eq('target_id', Number(targetId));
        if (!error) return true;
        if (error) logSupabaseFallbackWarning('evidence', error);
      } catch (err) {
        logSupabaseFallbackWarning('evidence', err);
      }
    }
    const res = await query(
      'DELETE FROM evidence WHERE target_type = $1 AND target_id = $2',
      [targetType, Number(targetId)]
    );
    return res.rowCount;
  }
};

export const CommandRolesDAO = {
  async getAll() {
    let roles = [];
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('command_roles')
          .select('*')
          .order('display_order', { ascending: true })
          .order('id', { ascending: true });
        if (!error && data) {
          roles = data;
        } else if (error) {
          logSupabaseFallbackWarning('command_roles', error);
        }
      } catch (err) {
        logSupabaseFallbackWarning('command_roles', err);
      }
    }

    if (roles.length === 0) {
      const res = await query('SELECT * FROM command_roles ORDER BY display_order ASC, id ASC');
      roles = res.rows;
    }

    const enriched = await Promise.all(roles.map(async (r) => {
      const evidence = await EvidenceDAO.getByTarget('role', r.id);
      return { ...r, evidence };
    }));
    return enriched;
  },
  async getById(id) {
    let row = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('command_roles')
          .select('*')
          .eq('id', Number(id))
          .maybeSingle();
        if (!error && data) row = data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('command_roles', error);
      } catch (err) {
        logSupabaseFallbackWarning('command_roles', err);
      }
    }
    if (!row) {
      const res = await query('SELECT * FROM command_roles WHERE id = $1', [Number(id)]);
      row = res.rows[0];
    }
    if (!row) return null;
    const evidence = await EvidenceDAO.getByTarget('role', row.id);
    return { ...row, evidence };
  },
  async create(data) {
    const payload = {
      title: data.title || 'ROLE',
      subtitle: data.subtitle || '',
      display_order: Number(data.display_order) || 0
    };

    let created = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: resData, error } = await supabaseClient
          .from('command_roles')
          .insert(payload)
          .select()
          .single();
        if (!error && resData) created = resData;
        if (error) logSupabaseFallbackWarning('command_roles', error);
      } catch (err) {
        logSupabaseFallbackWarning('command_roles', err);
      }
    }
    if (!created) {
      const res = await query(`
        INSERT INTO command_roles (title, subtitle, display_order, created_at)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
        RETURNING *
      `, [payload.title, payload.subtitle, payload.display_order]);
      created = res.rows[0];
    }
    if (!created) return null;
    return { ...created, evidence: [] };
  },
  async update(id, data) {
    const current = await CommandRolesDAO.getById(id);
    if (!current) return null;

    const payload = {
      title: data.title !== undefined ? data.title : current.title,
      subtitle: data.subtitle !== undefined ? data.subtitle : current.subtitle,
      display_order: data.display_order !== undefined ? Number(data.display_order) : current.display_order
    };

    let updated = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: resData, error } = await supabaseClient
          .from('command_roles')
          .update(payload)
          .eq('id', Number(id))
          .select()
          .single();
        if (!error && resData) updated = resData;
        if (error) logSupabaseFallbackWarning('command_roles', error);
      } catch (err) {
        logSupabaseFallbackWarning('command_roles', err);
      }
    }
    if (!updated) {
      const res = await query(`
        UPDATE command_roles SET
          title = $1, subtitle = $2, display_order = $3
        WHERE id = $4
        RETURNING *
      `, [payload.title, payload.subtitle, payload.display_order, Number(id)]);
      updated = res.rows[0];
    }
    if (!updated) return null;
    const evidence = await EvidenceDAO.getByTarget('role', updated.id);
    return { ...updated, evidence };
  },
  async delete(id) {
    await EvidenceDAO.deleteByTarget('role', Number(id));
    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('command_roles').delete().eq('id', Number(id));
        if (!error) return true;
        if (error) logSupabaseFallbackWarning('command_roles', error);
      } catch (err) {
        logSupabaseFallbackWarning('command_roles', err);
      }
    }
    const res = await query('DELETE FROM command_roles WHERE id = $1', [Number(id)]);
    return res.rowCount > 0;
  }
};

export const CertificationsDAO = {
  async getAll() {
    let certs = [];
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('certifications')
          .select('*')
          .order('display_order', { ascending: true })
          .order('id', { ascending: true });
        if (!error && data) {
          certs = data;
        } else if (error) {
          logSupabaseFallbackWarning('certifications', error);
        }
      } catch (err) {
        logSupabaseFallbackWarning('certifications', err);
      }
    }

    if (certs.length === 0) {
      const res = await query('SELECT * FROM certifications ORDER BY display_order ASC, id ASC');
      certs = res.rows;
    }

    const enriched = await Promise.all(certs.map(async (c) => {
      const evidence = await EvidenceDAO.getByTarget('cert', c.id);
      return { ...c, evidence };
    }));
    return enriched;
  },
  async getById(id) {
    let row = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('certifications')
          .select('*')
          .eq('id', Number(id))
          .maybeSingle();
        if (!error && data) row = data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('certifications', error);
      } catch (err) {
        logSupabaseFallbackWarning('certifications', err);
      }
    }
    if (!row) {
      const res = await query('SELECT * FROM certifications WHERE id = $1', [Number(id)]);
      row = res.rows[0];
    }
    if (!row) return null;
    const evidence = await EvidenceDAO.getByTarget('cert', row.id);
    return { ...row, evidence };
  },
  async create(data) {
    const payload = {
      title: data.title || 'CERTIFICATION',
      subtitle: data.subtitle || '',
      display_order: Number(data.display_order) || 0
    };

    let created = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: resData, error } = await supabaseClient
          .from('certifications')
          .insert(payload)
          .select()
          .single();
        if (!error && resData) created = resData;
        if (error) logSupabaseFallbackWarning('certifications', error);
      } catch (err) {
        logSupabaseFallbackWarning('certifications', err);
      }
    }
    if (!created) {
      const res = await query(`
        INSERT INTO certifications (title, subtitle, display_order, created_at)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
        RETURNING *
      `, [payload.title, payload.subtitle, payload.display_order]);
      created = res.rows[0];
    }
    if (!created) return null;
    return { ...created, evidence: [] };
  },
  async update(id, data) {
    const current = await CertificationsDAO.getById(id);
    if (!current) return null;

    const payload = {
      title: data.title !== undefined ? data.title : current.title,
      subtitle: data.subtitle !== undefined ? data.subtitle : current.subtitle,
      display_order: data.display_order !== undefined ? Number(data.display_order) : current.display_order
    };

    let updated = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: resData, error } = await supabaseClient
          .from('certifications')
          .update(payload)
          .eq('id', Number(id))
          .select()
          .single();
        if (!error && resData) updated = resData;
        if (error) logSupabaseFallbackWarning('certifications', error);
      } catch (err) {
        logSupabaseFallbackWarning('certifications', err);
      }
    }
    if (!updated) {
      const res = await query(`
        UPDATE certifications SET
          title = $1, subtitle = $2, display_order = $3
        WHERE id = $4
        RETURNING *
      `, [payload.title, payload.subtitle, payload.display_order, Number(id)]);
      updated = res.rows[0];
    }
    if (!updated) return null;
    const evidence = await EvidenceDAO.getByTarget('cert', updated.id);
    return { ...updated, evidence };
  },
  async delete(id) {
    await EvidenceDAO.deleteByTarget('cert', Number(id));
    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('certifications').delete().eq('id', Number(id));
        if (!error) return true;
        if (error) logSupabaseFallbackWarning('certifications', error);
      } catch (err) {
        logSupabaseFallbackWarning('certifications', err);
      }
    }
    const res = await query('DELETE FROM certifications WHERE id = $1', [Number(id)]);
    return res.rowCount > 0;
  }
};

export const ProfileDAO = {
  async get() {
    let row = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('profile')
          .select('*')
          .eq('id', 1)
          .maybeSingle();
        if (!error && data) {
          row = data;
        } else if (error) {
          logSupabaseFallbackWarning('profile', error);
        }
      } catch (err) {
        logSupabaseFallbackWarning('profile', err);
      }
    }

    if (!row) {
      const res = await query('SELECT * FROM profile WHERE id = 1');
      row = res.rows[0];
    }

    if (!row) {
      row = {
        id: 1,
        name: 'J.BYRON',
        callsign: 'DEV-001',
        secondary_handle: '[JEYCYN JEFF]',
        tagline: 'SOFTWARE DEVELOPER · ROBOTICS ENGINEER · AI SYSTEMS',
        bio: 'Innovative software developer and robotics engineer based in Eldoret, Kenya.',
        stat_wins: '2+',
        stat_clubs: '4',
        stat_drive: '∞',
        command_roles: '[]',
        certifications: '[]',
        contact_email: 'jeffjeycyn@gmail.com',
        contact_github: 'https://github.com/Jeycyn',
        contact_linkedin: 'https://linkedin.com/in/jeycyn-jeff-3ba769313',
        contact_website: 'https://scarlettechwizards.vercel.app',
        location: 'ELDORET-KE',
        status: 'ARMED',
        photo_path: ''
      };
    }

    const roles = await CommandRolesDAO.getAll();
    const certs = await CertificationsDAO.getAll();

    return {
      ...row,
      command_roles: roles.length > 0 ? roles : (row.command_roles ? (typeof row.command_roles === 'string' ? JSON.parse(row.command_roles) : row.command_roles) : []),
      certifications: certs.length > 0 ? certs : (row.certifications ? (typeof row.certifications === 'string' ? JSON.parse(row.certifications) : row.certifications) : [])
    };
  },
  async update(data) {
    const current = (await ProfileDAO.get()) || {};

    // Synchronize command_roles
    if (Array.isArray(data.command_roles)) {
      const existingRoles = await CommandRolesDAO.getAll();
      const existingIds = new Set(existingRoles.map(r => r.id));
      const incomingIds = new Set();

      for (let idx = 0; idx < data.command_roles.length; idx++) {
        const r = data.command_roles[idx];
        if (r.id && existingIds.has(Number(r.id))) {
          incomingIds.add(Number(r.id));
          await CommandRolesDAO.update(Number(r.id), {
            title: r.title,
            subtitle: r.subtitle,
            display_order: r.display_order !== undefined ? r.display_order : idx + 1
          });
        } else {
          const created = await CommandRolesDAO.create({
            title: r.title,
            subtitle: r.subtitle,
            display_order: r.display_order !== undefined ? r.display_order : idx + 1
          });
          if (created) incomingIds.add(created.id);
        }
      }

      for (const r of existingRoles) {
        if (!incomingIds.has(r.id)) {
          await CommandRolesDAO.delete(r.id);
        }
      }
    }

    // Synchronize certifications
    if (Array.isArray(data.certifications)) {
      const existingCerts = await CertificationsDAO.getAll();
      const existingIds = new Set(existingCerts.map(c => c.id));
      const incomingIds = new Set();

      for (let idx = 0; idx < data.certifications.length; idx++) {
        const c = data.certifications[idx];
        if (c.id && existingIds.has(Number(c.id))) {
          incomingIds.add(Number(c.id));
          await CertificationsDAO.update(Number(c.id), {
            title: c.title,
            subtitle: c.subtitle,
            display_order: c.display_order !== undefined ? c.display_order : idx + 1
          });
        } else {
          const created = await CertificationsDAO.create({
            title: c.title,
            subtitle: c.subtitle,
            display_order: c.display_order !== undefined ? c.display_order : idx + 1
          });
          if (created) incomingIds.add(created.id);
        }
      }

      for (const c of existingCerts) {
        if (!incomingIds.has(c.id)) {
          await CertificationsDAO.delete(c.id);
        }
      }
    }

    const payload = {
      id: 1,
      name: data.name ?? current.name ?? 'J.BYRON',
      callsign: data.callsign ?? current.callsign ?? 'DEV-001',
      secondary_handle: data.secondary_handle ?? current.secondary_handle ?? '[JEYCYN JEFF]',
      tagline: data.tagline ?? current.tagline ?? '',
      bio: data.bio ?? current.bio ?? '',
      stat_wins: data.stat_wins ?? current.stat_wins ?? '2+',
      stat_clubs: data.stat_clubs ?? current.stat_clubs ?? '4',
      stat_drive: data.stat_drive ?? current.stat_drive ?? '∞',
      command_roles: typeof data.command_roles === 'string' ? data.command_roles : JSON.stringify(data.command_roles ?? current.command_roles ?? []),
      certifications: typeof data.certifications === 'string' ? data.certifications : JSON.stringify(data.certifications ?? current.certifications ?? []),
      contact_email: data.contact_email ?? current.contact_email ?? '',
      contact_github: data.contact_github ?? current.contact_github ?? '',
      contact_linkedin: data.contact_linkedin ?? current.contact_linkedin ?? '',
      contact_website: data.contact_website ?? current.contact_website ?? '',
      location: data.location ?? current.location ?? 'ELDORET-KE',
      status: data.status ?? current.status ?? 'ARMED',
      photo_path: data.photo_path ?? current.photo_path ?? ''
    };

    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('profile').upsert(payload);
        if (error) logSupabaseFallbackWarning('profile', error);
      } catch (err) {
        logSupabaseFallbackWarning('profile', err);
      }
    }

    await query(`
      INSERT INTO profile (
        id, name, callsign, secondary_handle, tagline, bio,
        stat_wins, stat_clubs, stat_drive, command_roles, certifications,
        contact_email, contact_github, contact_linkedin, contact_website,
        location, status, photo_path, updated_at
      ) VALUES (
        1, $1, $2, $3, $4, $5,
        $6, $7, $8, $9, $10,
        $11, $12, $13, $14,
        $15, $16, $17, CURRENT_TIMESTAMP
      ) ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        callsign = EXCLUDED.callsign,
        secondary_handle = EXCLUDED.secondary_handle,
        tagline = EXCLUDED.tagline,
        bio = EXCLUDED.bio,
        stat_wins = EXCLUDED.stat_wins,
        stat_clubs = EXCLUDED.stat_clubs,
        stat_drive = EXCLUDED.stat_drive,
        command_roles = EXCLUDED.command_roles,
        certifications = EXCLUDED.certifications,
        contact_email = EXCLUDED.contact_email,
        contact_github = EXCLUDED.contact_github,
        contact_linkedin = EXCLUDED.contact_linkedin,
        contact_website = EXCLUDED.contact_website,
        location = EXCLUDED.location,
        status = EXCLUDED.status,
        photo_path = EXCLUDED.photo_path,
        updated_at = CURRENT_TIMESTAMP
    `, [
      payload.name, payload.callsign, payload.secondary_handle, payload.tagline, payload.bio,
      payload.stat_wins, payload.stat_clubs, payload.stat_drive, payload.command_roles, payload.certifications,
      payload.contact_email, payload.contact_github, payload.contact_linkedin, payload.contact_website,
      payload.location, payload.status, payload.photo_path
    ]);

    return ProfileDAO.get();
  }
};

export const ProjectsDAO = {
  async getAll(includeHidden = false) {
    let projects = [];
    if (isSupabaseActive && supabaseClient) {
      try {
        let q = supabaseClient.from('projects').select('*');
        if (!includeHidden) {
          q = q.eq('visibility', 1);
        }
        const { data, error } = await q
          .order('display_order', { ascending: true })
          .order('id', { ascending: true });
        if (!error && data) {
          projects = data;
        } else if (error) {
          logSupabaseFallbackWarning('projects', error);
        }
      } catch (err) {
        logSupabaseFallbackWarning('projects', err);
      }
    }

    if (projects.length === 0) {
      let res;
      if (includeHidden) {
        res = await query('SELECT * FROM projects ORDER BY display_order ASC, id ASC');
      } else {
        res = await query('SELECT * FROM projects WHERE visibility = 1 ORDER BY display_order ASC, id ASC');
      }
      projects = res.rows;
    }

    const enriched = await Promise.all(projects.map(async (p) => {
      const evidence = await EvidenceDAO.getByTarget('project', p.id);
      return { ...p, evidence };
    }));
    return enriched;
  },
  async getById(id) {
    let row = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('projects')
          .select('*')
          .eq('id', Number(id))
          .maybeSingle();
        if (!error && data) row = data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('projects', error);
      } catch (err) {
        logSupabaseFallbackWarning('projects', err);
      }
    }
    if (!row) {
      const res = await query('SELECT * FROM projects WHERE id = $1', [Number(id)]);
      row = res.rows[0];
    }
    if (!row) return null;
    const evidence = await EvidenceDAO.getByTarget('project', row.id);
    return { ...row, evidence };
  },
  async create(data) {
    const payload = {
      title: data.title || 'NEW MISSION',
      badge: data.badge || '',
      badge_type: data.badge_type || 'badge-g',
      description: data.description || '',
      project_url: data.project_url || '',
      repo_url: data.repo_url || '',
      image_path: data.image_path || '',
      display_order: Number(data.display_order) || 0,
      visibility: data.visibility !== undefined ? Number(data.visibility) : 1
    };

    let created = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: resData, error } = await supabaseClient
          .from('projects')
          .insert(payload)
          .select()
          .single();
        if (!error && resData) created = resData;
        if (error) logSupabaseFallbackWarning('projects', error);
      } catch (err) {
        logSupabaseFallbackWarning('projects', err);
      }
    }
    if (!created) {
      const res = await query(`
        INSERT INTO projects (title, badge, badge_type, description, project_url, repo_url, image_path, display_order, visibility, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
        RETURNING *
      `, [
        payload.title, payload.badge, payload.badge_type, payload.description,
        payload.project_url, payload.repo_url, payload.image_path,
        payload.display_order, payload.visibility
      ]);
      created = res.rows[0];
    }
    if (!created) return null;
    return { ...created, evidence: [] };
  },
  async update(id, data) {
    const current = await ProjectsDAO.getById(id);
    if (!current) return null;

    const payload = {
      title: data.title !== undefined ? data.title : current.title,
      badge: data.badge !== undefined ? data.badge : current.badge,
      badge_type: data.badge_type !== undefined ? data.badge_type : current.badge_type,
      description: data.description !== undefined ? data.description : current.description,
      project_url: data.project_url !== undefined ? data.project_url : current.project_url,
      repo_url: data.repo_url !== undefined ? data.repo_url : current.repo_url,
      image_path: data.image_path !== undefined ? data.image_path : current.image_path,
      display_order: data.display_order !== undefined ? Number(data.display_order) : current.display_order,
      visibility: data.visibility !== undefined ? Number(data.visibility) : current.visibility
    };

    let updated = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: resData, error } = await supabaseClient
          .from('projects')
          .update(payload)
          .eq('id', Number(id))
          .select()
          .single();
        if (!error && resData) updated = resData;
        if (error) logSupabaseFallbackWarning('projects', error);
      } catch (err) {
        logSupabaseFallbackWarning('projects', err);
      }
    }
    if (!updated) {
      const res = await query(`
        UPDATE projects SET
          title = $1, badge = $2, badge_type = $3, description = $4,
          project_url = $5, repo_url = $6, image_path = $7,
          display_order = $8, visibility = $9
        WHERE id = $10
        RETURNING *
      `, [
        payload.title, payload.badge, payload.badge_type, payload.description,
        payload.project_url, payload.repo_url, payload.image_path,
        payload.display_order, payload.visibility, Number(id)
      ]);
      updated = res.rows[0];
    }
    if (!updated) return null;
    const evidence = await EvidenceDAO.getByTarget('project', updated.id);
    return { ...updated, evidence };
  },
  async delete(id) {
    await EvidenceDAO.deleteByTarget('project', Number(id));
    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('projects').delete().eq('id', Number(id));
        if (!error) return true;
        if (error) logSupabaseFallbackWarning('projects', error);
      } catch (err) {
        logSupabaseFallbackWarning('projects', err);
      }
    }
    const res = await query('DELETE FROM projects WHERE id = $1', [Number(id)]);
    return res.rowCount > 0;
  }
};

export const SkillsDAO = {
  async getAll() {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('skills')
          .select('*')
          .order('display_order', { ascending: true })
          .order('id', { ascending: true });
        if (!error && data) return data;
        if (error) logSupabaseFallbackWarning('skills', error);
      } catch (err) {
        logSupabaseFallbackWarning('skills', err);
      }
    }
    const res = await query('SELECT * FROM skills ORDER BY display_order ASC, id ASC');
    return res.rows;
  },
  async getById(id) {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('skills')
          .select('*')
          .eq('id', Number(id))
          .maybeSingle();
        if (!error && data) return data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('skills', error);
      } catch (err) {
        logSupabaseFallbackWarning('skills', err);
      }
    }
    const res = await query('SELECT * FROM skills WHERE id = $1', [Number(id)]);
    return res.rows[0] || null;
  },
  async create(data) {
    const payload = {
      name: data.name || 'Skill',
      proficiency: Number(data.proficiency) || 50,
      category: data.category || 'general',
      radar_label: data.radar_label || data.name || '',
      is_radar: data.is_radar ? 1 : 0,
      display_order: Number(data.display_order) || 0
    };

    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: created, error } = await supabaseClient
          .from('skills')
          .insert(payload)
          .select()
          .single();
        if (!error && created) return created;
        if (error) logSupabaseFallbackWarning('skills', error);
      } catch (err) {
        logSupabaseFallbackWarning('skills', err);
      }
    }

    const res = await query(`
      INSERT INTO skills (name, proficiency, category, radar_label, is_radar, display_order)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [
      payload.name, payload.proficiency, payload.category,
      payload.radar_label, payload.is_radar, payload.display_order
    ]);
    return res.rows[0] || null;
  },
  async update(id, data) {
    const current = await SkillsDAO.getById(id);
    if (!current) return null;

    const payload = {
      name: data.name !== undefined ? data.name : current.name,
      proficiency: data.proficiency !== undefined ? Number(data.proficiency) : current.proficiency,
      category: data.category !== undefined ? data.category : current.category,
      radar_label: data.radar_label !== undefined ? data.radar_label : current.radar_label,
      is_radar: data.is_radar !== undefined ? (data.is_radar ? 1 : 0) : current.is_radar,
      display_order: data.display_order !== undefined ? Number(data.display_order) : current.display_order
    };

    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: updated, error } = await supabaseClient
          .from('skills')
          .update(payload)
          .eq('id', Number(id))
          .select()
          .single();
        if (!error && updated) return updated;
        if (error) logSupabaseFallbackWarning('skills', error);
      } catch (err) {
        logSupabaseFallbackWarning('skills', err);
      }
    }

    const res = await query(`
      UPDATE skills SET
        name = $1, proficiency = $2, category = $3,
        radar_label = $4, is_radar = $5, display_order = $6
      WHERE id = $7
      RETURNING *
    `, [
      payload.name, payload.proficiency, payload.category,
      payload.radar_label, payload.is_radar, payload.display_order,
      Number(id)
    ]);
    return res.rows[0] || null;
  },
  async delete(id) {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('skills').delete().eq('id', Number(id));
        if (!error) return true;
        if (error) logSupabaseFallbackWarning('skills', error);
      } catch (err) {
        logSupabaseFallbackWarning('skills', err);
      }
    }
    const res = await query('DELETE FROM skills WHERE id = $1', [Number(id)]);
    return res.rowCount > 0;
  }
};

export const AdminDAO = {
  async findByUsername(username) {
    if (!username) return null;
    const cleanUser = username.trim();

    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('admin_users')
          .select('*')
          .eq('username', cleanUser)
          .maybeSingle();
        if (!error && data) return data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('admin_users', error);
      } catch (err) {
        logSupabaseFallbackWarning('admin_users', err);
      }
    }

    const res = await query('SELECT * FROM admin_users WHERE username = $1', [cleanUser]);
    return res.rows[0] || null;
  },
  async findById(id) {
    if (!id) return null;

    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('admin_users')
          .select('*')
          .eq('id', Number(id))
          .maybeSingle();
        if (!error && data) return data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('admin_users', error);
      } catch (err) {
        logSupabaseFallbackWarning('admin_users', err);
      }
    }

    const res = await query('SELECT * FROM admin_users WHERE id = $1', [Number(id)]);
    return res.rows[0] || null;
  },
  async verifyPassword(username, password) {
    if (!username || !password) return false;
    const user = await AdminDAO.findByUsername(username);
    if (!user || !user.password_hash) return false;

    if (user.password_hash.startsWith('$2a$') || user.password_hash.startsWith('$2b$') || user.password_hash.startsWith('$2y$')) {
      try {
        return bcrypt.compareSync(password, user.password_hash);
      } catch {
        return false;
      }
    }

    if (user.password_hash.includes(':')) {
      const [salt, storedHash] = user.password_hash.split(':');
      if (salt && storedHash) {
        try {
          const testHash = crypto.createHmac('sha256', salt).update(password).digest('hex');
          if (crypto.timingSafeEqual(Buffer.from(testHash, 'hex'), Buffer.from(storedHash, 'hex'))) {
            await AdminDAO.updatePassword(username, password);
            return true;
          }
        } catch {
          return false;
        }
      }
    }

    return false;
  },
  async updatePassword(username, newPassword) {
    if (!username || !newPassword) return false;
    const salt = bcrypt.genSaltSync(12);
    const hash = bcrypt.hashSync(newPassword, salt);

    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient
          .from('admin_users')
          .update({ password_hash: hash })
          .eq('username', username.trim());
        if (error) logSupabaseFallbackWarning('admin_users', error);
      } catch (err) {
        logSupabaseFallbackWarning('admin_users', err);
      }
    }

    const res = await query('UPDATE admin_users SET password_hash = $1 WHERE username = $2', [hash, username.trim()]);
    return res.rowCount > 0;
  },
  async updateCredentials(userId, newUsername, newPassword) {
    if (!userId) return false;
    const user = await AdminDAO.findById(userId);
    if (!user) return false;

    let targetUsername = user.username;
    if (newUsername && typeof newUsername === 'string') {
      const cleanUser = newUsername.trim();
      if (cleanUser.length >= 3) {
        if (cleanUser !== user.username) {
          const existing = await AdminDAO.findByUsername(cleanUser);
          if (existing && existing.id !== userId) {
            throw new Error('USERNAME_TAKEN: Operator callsign is already assigned.');
          }
          if (isSupabaseActive && supabaseClient) {
            try {
              await supabaseClient.from('admin_users').update({ username: cleanUser }).eq('id', Number(userId));
              await supabaseClient.from('admin_sessions').update({ username: cleanUser }).eq('user_id', Number(userId));
            } catch (err) {
              logSupabaseFallbackWarning('admin_users', err);
            }
          }
          await query('UPDATE admin_users SET username = $1 WHERE id = $2', [cleanUser, userId]);
          await query('UPDATE admin_sessions SET username = $1 WHERE user_id = $2', [cleanUser, userId]);
          targetUsername = cleanUser;
        }
      }
    }

    const weakPasswords = ['admin123', 'admin', 'password', '123456', '12345678'];
    if (newPassword && typeof newPassword === 'string') {
      const cleanPass = newPassword.trim();
      if (cleanPass.length < 6) {
        throw new Error('PASSWORD_TOO_SHORT: Password must be at least 6 characters.');
      }
      if (weakPasswords.includes(cleanPass.toLowerCase())) {
        throw new Error('INSECURE_PASSWORD: Known default and weak passwords are not permitted.');
      }
      const salt = bcrypt.genSaltSync(12);
      const hash = bcrypt.hashSync(cleanPass, salt);

      if (isSupabaseActive && supabaseClient) {
        try {
          await supabaseClient.from('admin_users').update({ password_hash: hash }).eq('id', Number(userId));
        } catch (err) {
          logSupabaseFallbackWarning('admin_users', err);
        }
      }
      await query('UPDATE admin_users SET password_hash = $1 WHERE id = $2', [hash, userId]);
    }

    return AdminDAO.findById(userId);
  },
  async isDefaultPasswordActive() {
    const admin = await AdminDAO.findByUsername('admin');
    if (!admin || !admin.password_hash) return false;
    try {
      return bcrypt.compareSync('admin123', admin.password_hash);
    } catch {
      return false;
    }
  }
};

export const SessionDAO = {
  async createSession(userId, username, ip = '', userAgent = '', maxAgeMs = 24 * 60 * 60 * 1000) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = Date.now() + maxAgeMs;

    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('admin_sessions').insert({
          token_hash: tokenHash,
          user_id: Number(userId),
          username,
          ip,
          user_agent: userAgent,
          expires_at: expiresAt,
          revoked: 0
        });
        if (error) logSupabaseFallbackWarning('admin_sessions', error);
      } catch (err) {
        logSupabaseFallbackWarning('admin_sessions', err);
      }
    }

    await query(`
      INSERT INTO admin_sessions (token_hash, user_id, username, ip, user_agent, created_at, expires_at, revoked)
      VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6, 0)
    `, [tokenHash, Number(userId), username, ip, userAgent, expiresAt]);

    return { token: rawToken, expiresAt, userId, username };
  },
  async validateSession(token) {
    if (!token || typeof token !== 'string') return null;
    const tokenHash = crypto.createHash('sha256').update(token.trim()).digest('hex');

    let row = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('admin_sessions')
          .select('*')
          .eq('token_hash', tokenHash)
          .eq('revoked', 0)
          .maybeSingle();
        if (!error && data) row = data;
      } catch {}
    }

    if (!row) {
      const res = await query(`
        SELECT * FROM admin_sessions
        WHERE token_hash = $1 AND revoked = 0
      `, [tokenHash]);
      row = res.rows[0];
    }

    if (!row) return null;

    const expiresAtNum = Number(row.expires_at);
    if (expiresAtNum < Date.now()) {
      if (isSupabaseActive && supabaseClient) {
        try {
          await supabaseClient.from('admin_sessions').update({ revoked: 1 }).eq('id', row.id);
        } catch {}
      }
      await query('UPDATE admin_sessions SET revoked = 1 WHERE id = $1', [row.id]);
      return null;
    }

    return {
      userId: row.user_id,
      username: row.username,
      expiresAt: expiresAtNum,
      createdAt: row.created_at
    };
  },
  async revokeSession(token) {
    if (!token || typeof token !== 'string') return false;
    const tokenHash = crypto.createHash('sha256').update(token.trim()).digest('hex');

    if (isSupabaseActive && supabaseClient) {
      try {
        await supabaseClient.from('admin_sessions').update({ revoked: 1 }).eq('token_hash', tokenHash);
      } catch {}
    }

    const res = await query('UPDATE admin_sessions SET revoked = 1 WHERE token_hash = $1', [tokenHash]);
    return res.rowCount > 0;
  },
  async revokeAllUserSessions(userId) {
    if (!userId) return false;
    if (isSupabaseActive && supabaseClient) {
      try {
        await supabaseClient.from('admin_sessions').update({ revoked: 1 }).eq('user_id', Number(userId));
      } catch {}
    }
    const res = await query('UPDATE admin_sessions SET revoked = 1 WHERE user_id = $1', [Number(userId)]);
    return res.rowCount > 0;
  },
  async revokeOtherUserSessions(userId, currentRawToken = null) {
    if (!userId) return false;
    if (currentRawToken) {
      const currentHash = crypto.createHash('sha256').update(currentRawToken.trim()).digest('hex');
      if (isSupabaseActive && supabaseClient) {
        try {
          await supabaseClient
            .from('admin_sessions')
            .update({ revoked: 1 })
            .eq('user_id', Number(userId))
            .neq('token_hash', currentHash);
        } catch {}
      }
      const res = await query(
        'UPDATE admin_sessions SET revoked = 1 WHERE user_id = $1 AND token_hash != $2',
        [Number(userId), currentHash]
      );
      return res.rowCount > 0;
    } else {
      return SessionDAO.revokeAllUserSessions(userId);
    }
  },
  async cleanupExpired() {
    const now = Date.now();
    if (isSupabaseActive && supabaseClient) {
      try {
        await supabaseClient.from('admin_sessions').delete().lt('expires_at', now);
      } catch {}
    }
    await query('DELETE FROM admin_sessions WHERE expires_at < $1 OR revoked = 1', [now]);
  }
};

export const GatewayDAO = {
  async getRaw() {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('gateway_config')
          .select('*')
          .eq('id', 1)
          .maybeSingle();
        if (!error && data) return data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('gateway_config', error);
      } catch (err) {
        logSupabaseFallbackWarning('gateway_config', err);
      }
    }
    const res = await query('SELECT * FROM gateway_config WHERE id = 1');
    return res.rows[0] || null;
  },
  async getPublicConfig() {
    const row = await GatewayDAO.getRaw();
    if (!row) return null;
    return {
      grid_size: row.grid_size || 3,
      symbols: row.symbols ? (typeof row.symbols === 'string' ? JSON.parse(row.symbols) : row.symbols) : [],
      initial_scramble: row.initial_scramble ? (typeof row.initial_scramble === 'string' ? JSON.parse(row.initial_scramble) : row.initial_scramble) : []
    };
  },
  async getAdminConfig() {
    const row = await GatewayDAO.getRaw();
    if (!row) return null;
    return {
      grid_size: row.grid_size || 3,
      symbols: row.symbols ? (typeof row.symbols === 'string' ? JSON.parse(row.symbols) : row.symbols) : [],
      solution: row.solution ? (typeof row.solution === 'string' ? JSON.parse(row.solution) : row.solution) : [],
      initial_scramble: row.initial_scramble ? (typeof row.initial_scramble === 'string' ? JSON.parse(row.initial_scramble) : row.initial_scramble) : [],
      has_passcode: Boolean(row.passcode_hash),
      updated_at: row.updated_at
    };
  },
  async verifyPuzzle(submittedTiles) {
    if (!Array.isArray(submittedTiles)) return false;
    const row = await GatewayDAO.getRaw();
    if (!row || !row.solution) return false;
    try {
      const storedSolution = typeof row.solution === 'string' ? JSON.parse(row.solution) : row.solution;
      if (submittedTiles.length !== storedSolution.length) return false;

      for (let i = 0; i < storedSolution.length; i++) {
        const expected = storedSolution[i];
        const actual = submittedTiles[i];
        if (expected === null || expected === undefined || expected === '') {
          if (actual !== null && actual !== undefined && actual !== '') return false;
        } else {
          if (String(actual) !== String(expected)) return false;
        }
      }
      return true;
    } catch {
      return false;
    }
  },
  async verifyPasscode(passcode) {
    if (!passcode || typeof passcode !== 'string') return false;
    const row = await GatewayDAO.getRaw();
    if (!row || !row.passcode_hash) return false;
    return bcrypt.compareSync(passcode.trim(), row.passcode_hash);
  },
  async updateConfig(data, note = 'Updated via CMS') {
    const current = await GatewayDAO.getRaw();
    if (current) {
      const snapshot = JSON.stringify({
        grid_size: current.grid_size,
        symbols: typeof current.symbols === 'string' ? JSON.parse(current.symbols || '[]') : current.symbols,
        solution: typeof current.solution === 'string' ? JSON.parse(current.solution || '[]') : current.solution,
        initial_scramble: typeof current.initial_scramble === 'string' ? JSON.parse(current.initial_scramble || '[]') : current.initial_scramble,
        passcode_hash: current.passcode_hash
      });

      if (isSupabaseActive && supabaseClient) {
        try {
          await supabaseClient.from('gateway_config_history').insert({
            config_snapshot: snapshot,
            note
          });
        } catch (err) {
          logSupabaseFallbackWarning('gateway_config_history', err);
        }
      }
      await query(`
        INSERT INTO gateway_config_history (config_snapshot, note, created_at)
        VALUES ($1, $2, CURRENT_TIMESTAMP)
      `, [snapshot, note]);
    }

    const gridSize = Number(data.grid_size) || current?.grid_size || 3;
    const symbols = typeof data.symbols === 'string' ? data.symbols : JSON.stringify(data.symbols || []);
    const solution = typeof data.solution === 'string' ? data.solution : JSON.stringify(data.solution || []);
    const initialScramble = typeof data.initial_scramble === 'string' ? data.initial_scramble : JSON.stringify(data.initial_scramble || []);

    let passcodeHash = current ? current.passcode_hash : '';
    if (data.passcode && typeof data.passcode === 'string' && data.passcode.trim().length > 0) {
      const salt = bcrypt.genSaltSync(10);
      passcodeHash = bcrypt.hashSync(data.passcode.trim(), salt);
    }

    const payload = {
      id: 1,
      grid_size: gridSize,
      symbols,
      solution,
      initial_scramble: initialScramble,
      passcode_hash: passcodeHash
    };

    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('gateway_config').upsert(payload);
        if (error) logSupabaseFallbackWarning('gateway_config', error);
      } catch (err) {
        logSupabaseFallbackWarning('gateway_config', err);
      }
    }

    await query(`
      INSERT INTO gateway_config (id, grid_size, symbols, solution, initial_scramble, passcode_hash, updated_at)
      VALUES (1, $1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
      ON CONFLICT (id) DO UPDATE SET
        grid_size = EXCLUDED.grid_size,
        symbols = EXCLUDED.symbols,
        solution = EXCLUDED.solution,
        initial_scramble = EXCLUDED.initial_scramble,
        passcode_hash = EXCLUDED.passcode_hash,
        updated_at = CURRENT_TIMESTAMP
    `, [gridSize, symbols, solution, initialScramble, passcodeHash]);

    return GatewayDAO.getAdminConfig();
  },
  async resetToDefault(note = 'Reset to Factory Default') {
    const defaultSymbols = JSON.stringify(["ᚠ", "ᚢ", "ᚦ", "ᚨ", "ᚱ", "ᚲ", "ᚷ", "ᚹ"]);
    const defaultSolution = JSON.stringify([0, 1, 2, 3, 4, 5, 6, 7, null]);
    const defaultScramble = JSON.stringify([3, 0, 2, 6, 1, 4, 7, null, 5]);
    const salt = bcrypt.genSaltSync(10);
    const defaultPassHash = bcrypt.hashSync('RUNE-GATE-2026', salt);

    const current = await GatewayDAO.getRaw();
    if (current) {
      const snapshot = JSON.stringify({
        grid_size: current.grid_size,
        symbols: typeof current.symbols === 'string' ? JSON.parse(current.symbols || '[]') : current.symbols,
        solution: typeof current.solution === 'string' ? JSON.parse(current.solution || '[]') : current.solution,
        initial_scramble: typeof current.initial_scramble === 'string' ? JSON.parse(current.initial_scramble || '[]') : current.initial_scramble,
        passcode_hash: current.passcode_hash
      });

      if (isSupabaseActive && supabaseClient) {
        try {
          await supabaseClient.from('gateway_config_history').insert({
            config_snapshot: snapshot,
            note
          });
        } catch (err) {
          logSupabaseFallbackWarning('gateway_config_history', err);
        }
      }
      await query(`
        INSERT INTO gateway_config_history (config_snapshot, note, created_at)
        VALUES ($1, $2, CURRENT_TIMESTAMP)
      `, [snapshot, note]);
    }

    const payload = {
      id: 1,
      grid_size: 3,
      symbols: defaultSymbols,
      solution: defaultSolution,
      initial_scramble: defaultScramble,
      passcode_hash: defaultPassHash
    };

    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('gateway_config').upsert(payload);
        if (error) logSupabaseFallbackWarning('gateway_config', error);
      } catch (err) {
        logSupabaseFallbackWarning('gateway_config', err);
      }
    }

    await query(`
      INSERT INTO gateway_config (id, grid_size, symbols, solution, initial_scramble, passcode_hash, updated_at)
      VALUES (1, 3, $1, $2, $3, $4, CURRENT_TIMESTAMP)
      ON CONFLICT (id) DO UPDATE SET
        grid_size = 3,
        symbols = EXCLUDED.symbols,
        solution = EXCLUDED.solution,
        initial_scramble = EXCLUDED.initial_scramble,
        passcode_hash = EXCLUDED.passcode_hash,
        updated_at = CURRENT_TIMESTAMP
    `, [defaultSymbols, defaultSolution, defaultScramble, defaultPassHash]);

    return GatewayDAO.getAdminConfig();
  },
  async getHistory(limit = 20) {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('gateway_config_history')
          .select('id, note, created_at, config_snapshot')
          .order('id', { ascending: false })
          .limit(Number(limit));
        if (!error && data) {
          return data.map(row => {
            let parsed = {};
            try {
              parsed = typeof row.config_snapshot === 'string' ? JSON.parse(row.config_snapshot) : row.config_snapshot;
            } catch {}
            return {
              id: row.id,
              note: row.note,
              created_at: row.created_at,
              grid_size: parsed.grid_size,
              symbols_count: Array.isArray(parsed.symbols) ? parsed.symbols.length : 0
            };
          });
        }
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('gateway_config_history', error);
      } catch (err) {
        logSupabaseFallbackWarning('gateway_config_history', err);
      }
    }

    const res = await query(
      'SELECT id, note, created_at, config_snapshot FROM gateway_config_history ORDER BY id DESC LIMIT $1',
      [Number(limit)]
    );
    return res.rows.map(row => {
      let parsed = {};
      try {
        parsed = typeof row.config_snapshot === 'string' ? JSON.parse(row.config_snapshot) : row.config_snapshot;
      } catch {}
      return {
        id: row.id,
        note: row.note,
        created_at: row.created_at,
        grid_size: parsed.grid_size,
        symbols_count: Array.isArray(parsed.symbols) ? parsed.symbols.length : 0
      };
    });
  },
  async rollback(historyId) {
    let historyRow = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('gateway_config_history')
          .select('*')
          .eq('id', Number(historyId))
          .maybeSingle();
        if (!error && data) historyRow = data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('gateway_config_history', error);
      } catch (err) {
        logSupabaseFallbackWarning('gateway_config_history', err);
      }
    }
    if (!historyRow) {
      const res = await query('SELECT * FROM gateway_config_history WHERE id = $1', [Number(historyId)]);
      historyRow = res.rows[0];
    }

    if (!historyRow) throw new Error('History record not found.');

    const snapshot = typeof historyRow.config_snapshot === 'string'
      ? JSON.parse(historyRow.config_snapshot)
      : historyRow.config_snapshot;

    const current = await GatewayDAO.getRaw();
    if (current) {
      const archiveSnap = JSON.stringify({
        grid_size: current.grid_size,
        symbols: typeof current.symbols === 'string' ? JSON.parse(current.symbols || '[]') : current.symbols,
        solution: typeof current.solution === 'string' ? JSON.parse(current.solution || '[]') : current.solution,
        initial_scramble: typeof current.initial_scramble === 'string' ? JSON.parse(current.initial_scramble || '[]') : current.initial_scramble,
        passcode_hash: current.passcode_hash
      });

      if (isSupabaseActive && supabaseClient) {
        try {
          await supabaseClient.from('gateway_config_history').insert({
            config_snapshot: archiveSnap,
            note: `Archived before Rollback to Record #${historyId}`
          });
        } catch (err) {
          logSupabaseFallbackWarning('gateway_config_history', err);
        }
      }
      await query(`
        INSERT INTO gateway_config_history (config_snapshot, note, created_at)
        VALUES ($1, $2, CURRENT_TIMESTAMP)
      `, [archiveSnap, `Archived before Rollback to Record #${historyId}`]);
    }

    const payload = {
      id: 1,
      grid_size: snapshot.grid_size || 3,
      symbols: JSON.stringify(snapshot.symbols || []),
      solution: JSON.stringify(snapshot.solution || []),
      initial_scramble: JSON.stringify(snapshot.initial_scramble || []),
      passcode_hash: snapshot.passcode_hash
    };

    if (isSupabaseActive && supabaseClient) {
      try {
        const { error } = await supabaseClient.from('gateway_config').upsert(payload);
        if (error) logSupabaseFallbackWarning('gateway_config', error);
      } catch (err) {
        logSupabaseFallbackWarning('gateway_config', err);
      }
    }

    await query(`
      INSERT INTO gateway_config (id, grid_size, symbols, solution, initial_scramble, passcode_hash, updated_at)
      VALUES (1, $1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
      ON CONFLICT (id) DO UPDATE SET
        grid_size = EXCLUDED.grid_size,
        symbols = EXCLUDED.symbols,
        solution = EXCLUDED.solution,
        initial_scramble = EXCLUDED.initial_scramble,
        passcode_hash = EXCLUDED.passcode_hash,
        updated_at = CURRENT_TIMESTAMP
    `, [
      payload.grid_size,
      payload.symbols,
      payload.solution,
      payload.initial_scramble,
      payload.passcode_hash
    ]);

    return GatewayDAO.getAdminConfig();
  },
  async logAudit(ip, attempt_type, outcome, details = '') {
    try {
      if (isSupabaseActive && supabaseClient) {
        await supabaseClient.from('gateway_audit_logs').insert({
          ip: ip || '0.0.0.0',
          attempt_type,
          outcome,
          details
        });
        return;
      }
      await query(`
        INSERT INTO gateway_audit_logs (timestamp, ip, attempt_type, outcome, details)
        VALUES (CURRENT_TIMESTAMP, $1, $2, $3, $4)
      `, [ip || '0.0.0.0', attempt_type, outcome, details]);
    } catch (err) {
      console.warn('[GATEWAY AUDIT LOG WARNING]', err.message);
    }
  },
  async getAuditLogs(limit = 50) {
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('gateway_audit_logs')
          .select('*')
          .order('id', { ascending: false })
          .limit(Number(limit));
        if (!error && data) return data;
        if (error && !isSupabaseSchemaError(error)) logSupabaseFallbackWarning('gateway_audit_logs', error);
      } catch (err) {
        logSupabaseFallbackWarning('gateway_audit_logs', err);
      }
    }
    const res = await query(
      'SELECT * FROM gateway_audit_logs ORDER BY id DESC LIMIT $1',
      [Number(limit)]
    );
    return res.rows;
  },
  async isDefaultPasscodeActive() {
    const row = await GatewayDAO.getRaw();
    if (!row || !row.passcode_hash) return false;
    try {
      return bcrypt.compareSync('RUNE-GATE-2026', row.passcode_hash);
    } catch {
      return false;
    }
  },
  async checkIpRateLimit(ip, maxFailures = 5, windowMinutes = 5) {
    const cleanIp = ip || '0.0.0.0';
    const windowMs = windowMinutes * 60 * 1000;
    const windowIso = new Date(Date.now() - windowMs).toISOString();

    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('gateway_audit_logs')
          .select('id, timestamp, outcome')
          .eq('ip', cleanIp)
          .gte('timestamp', windowIso)
          .order('id', { ascending: false });

        if (!error && Array.isArray(data)) {
          const failures = data.filter(d => d.outcome === 'failure' || d.outcome === 'blocked' || d.outcome === 'lockout');
          if (failures.length >= maxFailures) {
            const oldestFailureTime = new Date(failures[maxFailures - 1].timestamp || Date.now()).getTime();
            const unlockTime = oldestFailureTime + windowMs;
            const remainingSec = Math.max(1, Math.ceil((unlockTime - Date.now()) / 1000));
            if (remainingSec > 0) {
              return { allowed: false, remainingSec };
            }
          }
          return { allowed: true };
        }
      } catch (err) {
        // Continue to SQLite/Postgres fallback
      }
    }

    try {
      const res = await query(
        `SELECT id, timestamp, outcome FROM gateway_audit_logs
         WHERE ip = $1 AND (outcome = 'failure' OR outcome = 'blocked' OR outcome = 'lockout')
         ORDER BY id DESC LIMIT $2`,
        [cleanIp, maxFailures]
      );
      if (res.rows && res.rows.length >= maxFailures) {
        return { allowed: false, remainingSec: windowMinutes * 60 };
      }
    } catch {
      // Allow if table query fails
    }

    return { allowed: true };
  }
};

export const SiteSettingsDAO = {
  async get() {
    let row = null;
    if (isSupabaseActive && supabaseClient) {
      try {
        const { data, error } = await supabaseClient
          .from('site_settings')
          .select('*')
          .eq('id', 1)
          .maybeSingle();
        if (!error && data) {
          row = data;
        } else if (error) {
          logSupabaseFallbackWarning('site_settings', error);
        }
      } catch (err) {
        logSupabaseFallbackWarning('site_settings', err);
      }
    }

    if (!row) {
      const res = await query('SELECT * FROM site_settings WHERE id = 1');
      row = res.rows[0];
    }

    if (!row) {
      return {
        id: 1,
        site_title: 'Jeycyn.Jeff || DEV-001',
        meta_description: 'Innovative software developer, robotics engineer, and AI systems builder based in Eldoret, Kenya. Founder of Scarlet Tech Wizards.',
        favicon_path: '',
        social_image_path: '',
        canonical_url: '',
        robots_policy: 'index, follow',
        updated_at: null
      };
    }
    return row;
  },
  async update(data) {
    const current = await SiteSettingsDAO.get();
    const payload = {
      id: 1,
      site_title: (data.site_title !== undefined ? String(data.site_title).trim() : current.site_title) || 'Jeycyn.Jeff || DEV-001',
      meta_description: data.meta_description !== undefined ? String(data.meta_description).trim() : current.meta_description,
      favicon_path: data.favicon_path !== undefined ? String(data.favicon_path).trim() : current.favicon_path,
      social_image_path: data.social_image_path !== undefined ? String(data.social_image_path).trim() : current.social_image_path,
      canonical_url: data.canonical_url !== undefined ? String(data.canonical_url).trim() : current.canonical_url,
      robots_policy: (data.robots_policy !== undefined ? String(data.robots_policy).trim() : current.robots_policy) || 'index, follow'
    };

    if (isSupabaseActive && supabaseClient) {
      try {
        const { data: updated, error } = await supabaseClient
          .from('site_settings')
          .upsert(payload)
          .select()
          .single();
        if (!error && updated) return updated;
        if (error) logSupabaseFallbackWarning('site_settings', error);
      } catch (err) {
        logSupabaseFallbackWarning('site_settings', err);
      }
    }

    const res = await query(`
      INSERT INTO site_settings (
        id, site_title, meta_description, favicon_path,
        social_image_path, canonical_url, robots_policy, updated_at
      ) VALUES (
        1, $1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP
      ) ON CONFLICT (id) DO UPDATE SET
        site_title = EXCLUDED.site_title,
        meta_description = EXCLUDED.meta_description,
        favicon_path = EXCLUDED.favicon_path,
        social_image_path = EXCLUDED.social_image_path,
        canonical_url = EXCLUDED.canonical_url,
        robots_policy = EXCLUDED.robots_policy,
        updated_at = CURRENT_TIMESTAMP
      RETURNING *
    `, [
      payload.site_title,
      payload.meta_description,
      payload.favicon_path,
      payload.social_image_path,
      payload.canonical_url,
      payload.robots_policy
    ]);

    return res.rows[0] || null;
  }
};

// Initialize database
initDatabase().catch(err => {
  console.error('[DB INIT ERROR]', err);
});