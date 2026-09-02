// One-time setup script: creates the real admin account and gateway
// passcode in your Supabase database. Run this ONCE after applying
// supabase_schema.sql, then store the printed credentials somewhere safe
// (a password manager) — they are only ever shown here, once.
//
// Usage:
//   node scripts/setup-production.js
//
// Optional env vars (set them in your shell for this one run only, not
// in .env.local, so they don't linger on disk):
//   ADMIN_USERNAME            (default: "admin")
//   ADMIN_PASSWORD            (default: randomly generated)
//   GATEWAY_PASSCODE          (default: randomly generated)
//
// Requires SUPABASE_URL and SUPABASE_SECRET_KEY to already be set
// (same as your app's production env vars).

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ SUPABASE_URL and SUPABASE_SECRET_KEY must be set in your environment before running this script.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

function randomSecret(bytes = 12) {
  return crypto.randomBytes(bytes).toString('base64url');
}

async function main() {
  const username = process.env.ADMIN_USERNAME || 'admin';
  const adminPassword = process.env.ADMIN_PASSWORD || randomSecret(12);
  const gatewayPasscode = process.env.GATEWAY_PASSCODE || randomSecret(9);

  // Refuse to run twice against an already-configured admin account,
  // to avoid accidentally overwriting a password you've already changed
  // via the CMS.
  const { data: existing, error: fetchErr } = await supabase
    .from('admin_users')
    .select('id, created_at')
    .eq('username', username)
    .maybeSingle();

  if (fetchErr) {
    console.error('❌ Error checking existing admin_users row:', fetchErr.message);
    process.exit(1);
  }

  if (existing) {
    console.error(`❌ An admin user "${username}" already exists (created ${existing.created_at}). Refusing to overwrite.`);
    console.error('   If you really need to reset it, do so via the CMS "change password" flow instead of this script.');
    process.exit(1);
  }

  const adminHash = bcrypt.hashSync(adminPassword, 10);
  const gatewayHash = bcrypt.hashSync(gatewayPasscode, 10);

  const { error: adminErr } = await supabase.from('admin_users').insert({
    id: 1,
    username,
    password_hash: adminHash
  });
  if (adminErr) {
    console.error('❌ Failed to create admin user:', adminErr.message);
    process.exit(1);
  }

  const { error: gwErr } = await supabase
    .from('gateway_config')
    .update({ passcode_hash: gatewayHash })
    .eq('id', 1);
  if (gwErr) {
    console.error('❌ Failed to set gateway passcode (admin user was already created):', gwErr.message);
    process.exit(1);
  }

  console.log('\n✅ Production credentials created. These are shown ONCE — save them now:\n');
  console.log(`   Admin username:   ${username}`);
  console.log(`   Admin password:   ${adminPassword}`);
  console.log(`   Gateway passcode: ${gatewayPasscode}\n`);
  console.log('Store both in a password manager, then close this terminal.');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
