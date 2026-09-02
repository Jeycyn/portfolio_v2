import path from 'path';
import fs from 'fs';
import { Jimp } from 'jimp';
import { createClient } from '@supabase/supabase-js';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const LOCAL_UPLOADS_DIR = path.join(__dirname, 'uploads');

// ══════════════════════════════════════════════
// SUPABASE CLIENT & STORAGE CONFIGURATION
// ══════════════════════════════════════════════
const SUPABASE_URL = process.env.SUPABASE_URL || (process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith('http') ? process.env.DATABASE_URL.trim() : null);
const SUPABASE_KEY = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || process.env.SUPABASE_ANON_KEY;

// Only create a local uploads folder when Supabase Storage isn't configured.
// On serverless platforms (Vercel, etc.) the filesystem outside /tmp is
// read-only, so this must never run once Supabase is handling storage.
if (!(SUPABASE_URL && SUPABASE_KEY)) {
  try {
    if (!fs.existsSync(LOCAL_UPLOADS_DIR)) {
      fs.mkdirSync(LOCAL_UPLOADS_DIR, { recursive: true });
    }
  } catch (err) {
    console.warn('[STORAGE] Local uploads folder unavailable in this environment:', err.message);
  }
}

export const PUBLIC_BUCKET = 'portfolio-public';
export const PRIVATE_BUCKET = 'portfolio-private';

let supabaseClient = null;
let bucketsChecked = false;

export function getSupabaseClient() {
  if (!supabaseClient && SUPABASE_URL && SUPABASE_KEY) {
    try {
      supabaseClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      });
    } catch (err) {
      console.error('[STORAGE] Error initializing Supabase client:', err.message);
    }
  }
  return supabaseClient;
}

export function isSupabaseStorageConfigured() {
  return Boolean(SUPABASE_URL && SUPABASE_KEY);
}

/**
 * Ensures required storage buckets exist in Supabase Storage.
 */
async function ensureBucketsExist() {
  if (bucketsChecked) return;
  const client = getSupabaseClient();
  if (!client) return;

  try {
    const { data: buckets, error } = await client.storage.listBuckets();
    if (!error && Array.isArray(buckets)) {
      const bucketNames = buckets.map(b => b.name);
      
      if (!bucketNames.includes(PUBLIC_BUCKET)) {
        await client.storage.createBucket(PUBLIC_BUCKET, {
          public: true,
          fileSizeLimit: 20 * 1024 * 1024
        });
        console.log(`[STORAGE] Created Supabase public bucket: ${PUBLIC_BUCKET}`);
      }

      if (!bucketNames.includes(PRIVATE_BUCKET)) {
        await client.storage.createBucket(PRIVATE_BUCKET, {
          public: false,
          fileSizeLimit: 20 * 1024 * 1024
        });
        console.log(`[STORAGE] Created Supabase private bucket: ${PRIVATE_BUCKET}`);
      }
    }
    bucketsChecked = true;
  } catch (err) {
    console.warn('[STORAGE] Buckets check warning:', err.message);
  }
}

/**
 * Uploads an asset buffer to Supabase Storage (or falls back to local disk if unconfigured).
 * Enforces image resizing, rasterization, and security bucket partitioning.
 *
 * Partitions:
 * - Public Bucket: profile/, projects/, branding/, evidence/
 * - Private Bucket: evidence/
 */
export async function uploadAsset({
  buffer,
  originalName,
  mimeType,
  category = 'public',
  folder = 'general',
  isPrivate = false
}) {
  const ext = path.extname(originalName).toLowerCase() || '.jpg';
  const cleanExt = ext.replace(/[^a-z0-9.]/gi, '');
  const timestamp = Date.now();
  const randomSuffix = Math.random().toString(36).substring(2, 8);
  const baseFilename = `asset_${timestamp}_${randomSuffix}${cleanExt}`;

  // Process raster images with Jimp (max 1200x1200px)
  let processedBuffer = buffer;
  let contentType = mimeType || 'application/octet-stream';

  const isRasterImage = ['.jpg', '.jpeg', '.png', '.webp'].includes(cleanExt);
  if (isRasterImage) {
    try {
      const image = await Jimp.read(buffer);
      const width = image.bitmap.width;
      const height = image.bitmap.height;
      if (width > 1200 || height > 1200) {
        if (width > height) {
          image.resize({ w: 1200 });
        } else {
          image.resize({ h: 1200 });
        }
      }
      processedBuffer = await image.getBuffer(cleanExt === '.png' ? 'image/png' : 'image/jpeg');
      contentType = cleanExt === '.png' ? 'image/png' : 'image/jpeg';
    } catch {
      // Keep original buffer if codec fails
      processedBuffer = buffer;
    }
  }

  const client = getSupabaseClient();

  if (client && isSupabaseStorageConfigured()) {
    await ensureBucketsExist();

    const targetBucket = isPrivate ? PRIVATE_BUCKET : PUBLIC_BUCKET;
    const storagePath = `${folder}/${baseFilename}`;

    const { data, error } = await client.storage
      .from(targetBucket)
      .upload(storagePath, processedBuffer, {
        contentType,
        cacheControl: isPrivate ? 'no-cache' : 'max-age=31536000',
        upsert: true
      });

    if (error) {
      console.error('[STORAGE] Supabase upload failed:', error.message);
      throw new Error(`STORAGE_UPLOAD_ERROR: ${error.message}`);
    }

    if (!isPrivate) {
      const { data: urlData } = client.storage.from(PUBLIC_BUCKET).getPublicUrl(storagePath);
      const publicUrl = urlData.publicUrl;
      return {
        url: publicUrl,
        storagePath,
        bucket: PUBLIC_BUCKET,
        filename: baseFilename,
        isPrivate: false,
        size: processedBuffer.length
      };
    } else {
      return {
        url: `/api/evidence/private/${encodeURIComponent(storagePath)}`,
        storagePath,
        bucket: PRIVATE_BUCKET,
        filename: baseFilename,
        isPrivate: true,
        size: processedBuffer.length
      };
    }
  }

  // Local filesystem fallback
  const localTarget = path.join(LOCAL_UPLOADS_DIR, baseFilename);
  fs.writeFileSync(localTarget, processedBuffer);
  return {
    url: `/uploads/${baseFilename}`,
    storagePath: `uploads/${baseFilename}`,
    filename: baseFilename,
    isPrivate: false,
    size: processedBuffer.length
  };
}

/**
 * Generates a signed URL for temporary access to a private evidence file (valid for maxAgeMinutes).
 */
export async function getPrivateSignedUrl(storagePath, maxAgeMinutes = 15) {
  const client = getSupabaseClient();
  if (!client || !isSupabaseStorageConfigured()) {
    return null;
  }

  try {
    const { data, error } = await client.storage
      .from(PRIVATE_BUCKET)
      .createSignedUrl(storagePath, maxAgeMinutes * 60);

    if (error || !data) {
      console.error('[STORAGE] Error creating signed URL:', error?.message);
      return null;
    }
    return data.signedUrl;
  } catch (err) {
    console.error('[STORAGE] Exception generating signed URL:', err.message);
    return null;
  }
}

/**
 * Generates a pre-signed upload URL for direct client-to-storage uploads.
 */
export async function getSignedUploadUrl(filename, mimeType, folder = 'evidence', isPrivate = false) {
  const client = getSupabaseClient();
  if (!client || !isSupabaseStorageConfigured()) {
    return null;
  }

  try {
    await ensureBucketsExist();
    const ext = path.extname(filename).toLowerCase() || '.dat';
    const cleanExt = ext.replace(/[^a-z0-9.]/gi, '');
    const uniqueName = `asset_${Date.now()}_${Math.random().toString(36).substring(2, 8)}${cleanExt}`;
    const storagePath = `${folder}/${uniqueName}`;
    const targetBucket = isPrivate ? PRIVATE_BUCKET : PUBLIC_BUCKET;

    const { data, error } = await client.storage
      .from(targetBucket)
      .createSignedUploadUrl(storagePath);

    if (error || !data) {
      console.error('[STORAGE] Error creating signed upload URL:', error?.message);
      return null;
    }

    let publicUrl = '';
    if (isPrivate) {
      publicUrl = `/api/evidence/private/${encodeURIComponent(storagePath)}`;
    } else {
      const { data: urlData } = client.storage.from(PUBLIC_BUCKET).getPublicUrl(storagePath);
      publicUrl = urlData.publicUrl;
    }

    return {
      uploadUrl: data.signedUrl,
      publicUrl,
      storagePath,
      bucket: targetBucket,
      filename: uniqueName
    };
  } catch (err) {
    console.error('[STORAGE] Error in getSignedUploadUrl:', err.message);
    return null;
  }
}

/**
 * Safely removes a file from Supabase Storage and local disk.
 */
export async function deleteAsset(assetPath) {
  if (!assetPath || typeof assetPath !== 'string') return;

  const client = getSupabaseClient();

  // 1. Delete from Supabase Storage if matching URL or path
  if (client && isSupabaseStorageConfigured()) {
    try {
      let bucket = PUBLIC_BUCKET;
      let filePath = null;

      if (assetPath.includes('/storage/v1/object/public/')) {
        const parts = assetPath.split('/storage/v1/object/public/');
        if (parts[1]) {
          const subParts = parts[1].split('/');
          bucket = subParts[0];
          filePath = subParts.slice(1).join('/');
        }
      } else if (assetPath.includes('/api/evidence/private/')) {
        bucket = PRIVATE_BUCKET;
        filePath = decodeURIComponent(assetPath.split('/api/evidence/private/')[1]);
      } else if (assetPath.startsWith('public/')) {
        bucket = PUBLIC_BUCKET;
        filePath = assetPath.replace(/^public\//, '');
      } else if (assetPath.startsWith('private/')) {
        bucket = PRIVATE_BUCKET;
        filePath = assetPath.replace(/^private\//, '');
      }

      if (filePath) {
        const { error } = await client.storage.from(bucket).remove([filePath]);
        if (!error) {
          console.log(`[STORAGE] Deleted Supabase asset from ${bucket}: ${filePath}`);
        }
      }
    } catch (err) {
      console.warn('[STORAGE] Error deleting Supabase storage file:', err.message);
    }
  }

  // 2. Delete from local disk if it exists
  try {
    const filename = path.basename(assetPath);
    if (filename) {
      const localFile = path.join(LOCAL_UPLOADS_DIR, filename);
      if (fs.existsSync(localFile)) {
        fs.unlinkSync(localFile);
        console.log(`[STORAGE] Deleted local fallback file: ${localFile}`);
      }
    }
  } catch (err) {
    console.warn('[STORAGE] Error deleting local file:', err.message);
  }
}git