-- ══════════════════════════════════════════════════════════════════════
-- JEYCYN QUANTUM HUD - SUPABASE POSTGRESQL SCHEMA INITIALIZER
-- Run this script in the Supabase SQL Editor (Dashboard -> SQL Editor)
-- ══════════════════════════════════════════════════════════════════════

-- 1. Profile Table
CREATE TABLE IF NOT EXISTS public.profile (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  name TEXT NOT NULL DEFAULT 'J.BYRON',
  callsign TEXT NOT NULL DEFAULT 'DEV-001',
  secondary_handle TEXT DEFAULT '[JEYCYN JEFF]',
  tagline TEXT DEFAULT 'SOFTWARE DEVELOPER · ROBOTICS ENGINEER · AI SYSTEMS',
  bio TEXT DEFAULT 'Innovative software developer and robotics engineer based in Eldoret, Kenya. Founder of Scarlet Tech Wizards and creator of Multiverse Care, a futuristic mental health and emergency response platform integrating AI-powered healthcare systems. Builder of scalable, impact-driven systems across healthcare, security hardware, robotics, and education technology. Passionate about developing smart automation systems, embedded electronics, and futuristic human-centered innovations. Active coding tutor and robotics mentor — engineering the next generation of African tech innovators. Winner of the Codejika Coding Competition and recognized science fair innovator. Currently expanding into Cyber Security, AI, Machine Learning, and next-generation intelligent systems.',
  stat_wins TEXT DEFAULT '2+',
  stat_clubs TEXT DEFAULT '4',
  stat_drive TEXT DEFAULT '∞',
  command_roles TEXT DEFAULT '[]',
  certifications TEXT DEFAULT '[]',
  contact_email TEXT DEFAULT 'jeffjeycyn@gmail.com',
  contact_github TEXT DEFAULT 'https://github.com/Jeycyn',
  contact_linkedin TEXT DEFAULT 'https://linkedin.com/in/jeycyn-jeff-3ba769313',
  contact_website TEXT DEFAULT 'https://scarlettechwizards.vercel.app',
  location TEXT DEFAULT 'ELDORET-KE',
  status TEXT DEFAULT 'ARMED',
  photo_path TEXT DEFAULT '',
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Projects / Missions Table
CREATE TABLE IF NOT EXISTS public.projects (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  badge TEXT DEFAULT '',
  badge_type TEXT DEFAULT 'badge-g',
  description TEXT NOT NULL,
  project_url TEXT DEFAULT '',
  repo_url TEXT DEFAULT '',
  image_path TEXT DEFAULT '',
  display_order INTEGER DEFAULT 0,
  visibility INTEGER DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. Skills Table
CREATE TABLE IF NOT EXISTS public.skills (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  proficiency INTEGER NOT NULL DEFAULT 50,
  category TEXT DEFAULT 'breakdown',
  radar_label TEXT DEFAULT '',
  is_radar INTEGER DEFAULT 0,
  display_order INTEGER DEFAULT 0
);

-- 4. Command Roles Table
CREATE TABLE IF NOT EXISTS public.command_roles (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  subtitle TEXT DEFAULT '',
  display_order INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 5. Certifications Table
CREATE TABLE IF NOT EXISTS public.certifications (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  subtitle TEXT DEFAULT '',
  display_order INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 6. Evidence Artifacts Table
CREATE TABLE IF NOT EXISTS public.evidence (
  id BIGSERIAL PRIMARY KEY,
  target_type TEXT NOT NULL,
  target_id BIGINT NOT NULL,
  type TEXT NOT NULL DEFAULT 'link',
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  url TEXT DEFAULT '',
  file_path TEXT DEFAULT '',
  source_label TEXT DEFAULT '',
  display_order INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_evidence_target ON public.evidence(target_type, target_id);

-- 7. Admin Users Table
CREATE TABLE IF NOT EXISTS public.admin_users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 8. Admin Sessions Table
CREATE TABLE IF NOT EXISTS public.admin_sessions (
  id BIGSERIAL PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  user_id BIGINT NOT NULL REFERENCES public.admin_users(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  ip TEXT DEFAULT '',
  user_agent TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  expires_at BIGINT NOT NULL,
  revoked INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON public.admin_sessions(token_hash);

-- 9. Gateway Rune Matrix Configuration Table
CREATE TABLE IF NOT EXISTS public.gateway_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  grid_size INTEGER DEFAULT 3,
  symbols TEXT NOT NULL,
  solution TEXT NOT NULL,
  initial_scramble TEXT NOT NULL,
  passcode_hash TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 10. Gateway History Table
CREATE TABLE IF NOT EXISTS public.gateway_config_history (
  id BIGSERIAL PRIMARY KEY,
  config_snapshot TEXT NOT NULL,
  note TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 11. Gateway Audit Logs Table
CREATE TABLE IF NOT EXISTS public.gateway_audit_logs (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  ip TEXT NOT NULL,
  attempt_type TEXT NOT NULL,
  outcome TEXT NOT NULL,
  details TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_gateway_audit_time ON public.gateway_audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_ip_time ON public.gateway_audit_logs(ip, timestamp DESC);

-- 12. Site Settings Table
CREATE TABLE IF NOT EXISTS public.site_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  site_title TEXT NOT NULL DEFAULT 'Jeycyn.Jeff || DEV-001',
  meta_description TEXT NOT NULL DEFAULT 'Innovative software developer, robotics engineer, and AI systems builder based in Eldoret, Kenya. Founder of Scarlet Tech Wizards.',
  favicon_path TEXT DEFAULT '',
  social_image_path TEXT DEFAULT '',
  canonical_url TEXT DEFAULT '',
  robots_policy TEXT NOT NULL DEFAULT 'index, follow',
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ══════════════════════════════════════════════
-- SEED INITIAL BASELINE (IF NOT EXISTS)
-- ══════════════════════════════════════════════

-- admin_users is intentionally NOT seeded here. Seeding a hardcoded
-- password hash into a schema file means every deployment ships with a
-- known credential. Run `node scripts/setup-production.js` once after
-- applying this schema to create the real admin account and gateway
-- passcode with a strong, unique secret.

INSERT INTO public.profile (
  id, name, callsign, secondary_handle, tagline, bio,
  stat_wins, stat_clubs, stat_drive, command_roles, certifications,
  contact_email, contact_github, contact_linkedin, contact_website,
  location, status, photo_path
) VALUES (
  1,
  'J.BYRON',
  'DEV-001',
  '[JEYCYN JEFF]',
  'SOFTWARE DEVELOPER · ROBOTICS ENGINEER · AI SYSTEMS',
  'Innovative software developer and robotics engineer based in Eldoret, Kenya. Founder of Scarlet Tech Wizards and creator of Multiverse Care, a futuristic mental health and emergency response platform integrating AI-powered healthcare systems. Builder of scalable, impact-driven systems across healthcare, security hardware, robotics, and education technology. Passionate about developing smart automation systems, embedded electronics, and futuristic human-centered innovations. Active coding tutor and robotics mentor — engineering the next generation of African tech innovators. Winner of the Codejika Coding Competition and recognized science fair innovator. Currently expanding into Cyber Security, AI, Machine Learning, and next-generation intelligent systems.',
  '2+',
  '4',
  '∞',
  '[]',
  '[]',
  'jeffjeycyn@gmail.com',
  'https://github.com/Jeycyn',
  'https://linkedin.com/in/jeycyn-jeff-3ba769313',
  'https://scarlettechwizards.vercel.app',
  'ELDORET-KE',
  'ARMED',
  ''
) ON CONFLICT (id) DO NOTHING;

-- gateway_config's grid layout is safe to seed (it's not a secret), but
-- passcode_hash is intentionally left out — run scripts/setup-production.js
-- to set a real passcode. This INSERT is split so the puzzle grid exists
-- immediately; the script below will UPDATE the passcode_hash afterward.
INSERT INTO public.gateway_config (
  id, grid_size, symbols, solution, initial_scramble, passcode_hash
) VALUES (
  1,
  3,
  '["ᚠ","ᚢ","ᚦ","ᚨ","ᚱ","ᚲ","ᚷ","ᚹ"]',
  '[0,1,2,3,4,5,6,7,null]',
  '[3,0,2,6,1,4,7,null,5]',
  -- valid bcrypt hash of an unknown random value — matches no real passcode;
  -- overwritten by scripts/setup-production.js
  '$2b$10$sP49La2a2wyEBrRi1nEGDOKmri.SLWd2grUl/s4vk0XJqIHbauT42'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO public.site_settings (
  id, site_title, meta_description, favicon_path, social_image_path, canonical_url, robots_policy
) VALUES (
  1,
  'Jeycyn.Jeff || DEV-001',
  'Innovative software developer, robotics engineer, and AI systems builder based in Eldoret, Kenya. Founder of Scarlet Tech Wizards.',
  '',
  '',
  '',
  'index, follow'
) ON CONFLICT (id) DO NOTHING;

-- Storage buckets setup (run in Supabase dashboard or storage API)
-- INSERT INTO storage.buckets (id, name, public) VALUES ('portfolio-public', 'portfolio-public', true) ON CONFLICT (id) DO NOTHING;
-- INSERT INTO storage.buckets (id, name, public) VALUES ('portfolio-private', 'portfolio-private', false) ON CONFLICT (id) DO NOTHING;
