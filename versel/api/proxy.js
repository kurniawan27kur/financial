// Vercel Serverless Function Proxy
// High-Performance & Hardened Enterprise Security Bridge to Google Apps Script

const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 120;
const MAX_PAYLOAD_BYTES = 64 * 1024; // 64 KB payload limit (Anti-DoS)
const ipRequestCounts = new Map();

// Quick response cache for read-only requests (Stale-While-Revalidate pattern)
const responseCache = new Map();
const CACHE_TTL_MS = 30 * 1000; // 30 seconds cache for rapid reads

// Strict action whitelist to reject unexpected / dangerous actions at the edge
const ALLOWED_ACTIONS = new Set([
  'login',
  'loginDemo',
  'getAppData',
  'addTransaction',
  'updateTransaction',
  'deleteTransaction',
  'saveSettings',
  'saveProfiles',
  'changePassword',
  'logout',
  'ping'
]);

function isRateLimited(ip) {
  const now = Date.now();
  const record = ipRequestCounts.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW_MS };

  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + RATE_LIMIT_WINDOW_MS;
    ipRequestCounts.set(ip, record);
    return false;
  }

  record.count++;
  ipRequestCounts.set(ip, record);

  // Periodic memory cleanup to prevent memory leaks in serverless warm containers
  if (ipRequestCounts.size > 5000) {
    for (const [key, val] of ipRequestCounts.entries()) {
      if (now > val.resetTime) ipRequestCounts.delete(key);
    }
  }

  return record.count > MAX_REQUESTS_PER_WINDOW;
}

export default async function handler(req, res) {
  // Determine origin for safe CORS
  const origin = req.headers.origin || '*';

  // Strict Security Headers
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Content-Type, Authorization'
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      error: 'Metode HTTP tidak diizinkan. Gunakan metode POST.'
    });
  }

  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  if (isRateLimited(clientIp)) {
    return res.status(429).json({
      success: false,
      error: 'Terlalu banyak permintaan. Silakan tunggu sebentar sebelum mencoba lagi.'
    });
  }

  const gasUrl = process.env.GAS_API_URL;
  if (!gasUrl) {
    return res.status(500).json({
      success: false,
      error: 'Konfigurasi Environment Variable GAS_API_URL belum diatur di Vercel Dashboard.'
    });
  }

  try {
    let payloadObj = {};
    if (typeof req.body === 'object' && req.body !== null) {
      payloadObj = req.body;
    } else if (typeof req.body === 'string') {
      if (Buffer.byteLength(req.body, 'utf8') > MAX_PAYLOAD_BYTES) {
        return res.status(413).json({
          success: false,
          error: 'Ukuran data permintaan melebihi batas maksimum yang diizinkan (64 KB).'
        });
      }
      try {
        payloadObj = JSON.parse(req.body || '{}');
      } catch (e) {
        return res.status(400).json({
          success: false,
          error: 'Format JSON permintaan tidak valid.'
        });
      }
    }

    const action = String(payloadObj.action || '').trim();
    if (!action || !ALLOWED_ACTIONS.has(action)) {
      return res.status(400).json({
        success: false,
        error: 'Aksi yang diminta tidak valid atau tidak diizinkan.'
      });
    }

    const payloadStr = JSON.stringify(payloadObj);
    if (Buffer.byteLength(payloadStr, 'utf8') > MAX_PAYLOAD_BYTES) {
      return res.status(413).json({
        success: false,
        error: 'Ukuran data permintaan melebihi batas maksimum yang diizinkan (64 KB).'
      });
    }

    // Cache lookup for read-only actions to maximize response speed
    const isCacheable = (action === 'getAppData' || action === 'loginDemo');
    const cacheKey = isCacheable ? `${action}_${payloadObj.authToken || ''}` : null;
    const now = Date.now();

    if (cacheKey && responseCache.has(cacheKey)) {
      const cached = responseCache.get(cacheKey);
      if (now < cached.expiry) {
        return res.status(200).json(cached.data);
      }
    }

    // Explicit Content-Length is required by Google Apps Script proxy redirect
    const contentLength = Buffer.byteLength(payloadStr, 'utf8').toString();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout

    let gasResponse;
    try {
      gasResponse = await fetch(gasUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': contentLength
        },
        body: payloadStr,
        redirect: 'follow',
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeoutId);
    }

    const responseText = await gasResponse.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (parseErr) {
      return res.status(502).json({
        success: false,
        error: 'Google Apps Script merespons dengan format non-JSON. Pastikan Web App di-deploy dengan opsi "Execute as: Me" dan "Who has access: Anyone".'
      });
    }

    // Invalidate or update cache on modifications
    if (data && data.success) {
      if (isCacheable && cacheKey) {
        responseCache.set(cacheKey, { data, expiry: now + CACHE_TTL_MS });
      } else if (action === 'addTransaction' || action === 'updateTransaction' || action === 'deleteTransaction' || action === 'saveSettings' || action === 'saveProfiles' || action === 'changePassword') {
        responseCache.clear();
      }
    }

    return res.status(200).json(data);
  } catch (error) {
    if (error.name === 'AbortError') {
      return res.status(504).json({
        success: false,
        error: 'Koneksi ke database backend melebihi batas waktu (15 detik). Silakan coba lagi.'
      });
    }
    return res.status(502).json({
      success: false,
      error: 'Gagal terhubung ke server database. Silakan coba beberapa saat lagi.'
    });
  }
}
