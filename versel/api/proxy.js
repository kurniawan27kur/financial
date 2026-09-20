// Vercel Serverless Function Proxy
// High-Performance & Hardened Secure Bridge to Google Apps Script Backend

const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 60;
const ipRequestCounts = new Map();

// Quick response cache for read-only requests (Stale-While-Revalidate pattern)
const responseCache = new Map();
const CACHE_TTL_MS = 8 * 1000; // 8 seconds cache for rapid consecutive reads

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

  if (ipRequestCounts.size > 5000) {
    for (const [key, val] of ipRequestCounts.entries()) {
      if (now > val.resetTime) ipRequestCounts.delete(key);
    }
  }

  return record.count > MAX_REQUESTS_PER_WINDOW;
}

export default async function handler(req, res) {
  // CORS & Strict Security Headers
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
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

  const clientIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
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
    if (req.method === 'POST') {
      payloadObj = typeof req.body === 'object' && req.body !== null ? req.body : (JSON.parse(req.body || '{}'));
    } else if (req.method === 'GET') {
      payloadObj = req.query || {};
    }

    const action = payloadObj.action || '';
    const payloadStr = JSON.stringify(payloadObj);

    // Cache lookup for getAppData to maximize response speed
    const isCacheable = (action === 'getAppData' && req.method === 'POST');
    const cacheKey = isCacheable ? `getAppData_${payloadObj.authToken || ''}` : null;
    const now = Date.now();

    if (cacheKey && responseCache.has(cacheKey)) {
      const cached = responseCache.get(cacheKey);
      if (now < cached.expiry) {
        return res.status(200).json(cached.data);
      }
    }

    // Explicit Content-Length is required by Google Apps Script proxy redirect
    const contentLength = Buffer.byteLength(payloadStr, 'utf8').toString();

    const gasResponse = await fetch(gasUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': contentLength
      },
      body: payloadStr,
      redirect: 'follow'
    });

    const responseText = await gasResponse.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (parseErr) {
      console.error('GAS non-JSON response:', responseText.slice(0, 300));
      return res.status(502).json({
        success: false,
        error: 'Google Apps Script merespons dengan format non-JSON. Pastikan Web App di-deploy dengan opsi "Execute as: Me" dan "Who has access: Anyone".'
      });
    }

    // Invalidate or update cache on modifications
    if (data && data.success) {
      if (isCacheable && cacheKey) {
        responseCache.set(cacheKey, { data, expiry: now + CACHE_TTL_MS });
      } else if (action === 'addTransaction' || action === 'updateTransaction' || action === 'deleteTransaction' || action === 'saveSettings' || action === 'saveProfiles') {
        responseCache.clear();
      }
    }

    return res.status(200).json(data);
  } catch (error) {
    console.error('GAS Proxy Error:', error);
    return res.status(502).json({
      success: false,
      error: 'Gagal terhubung ke database Google Apps Script: ' + (error.message || String(error))
    });
  }
}
