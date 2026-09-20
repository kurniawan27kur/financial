// Vercel Serverless Function Proxy
// Secure Bridge to Google Apps Script Backend (Hides backend URL & Enforces Rate Limiting)

// Simple in-memory rate limiter for serverless instance
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 40;
const ipRequestCounts = new Map();

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

  // Periodic map pruning
  if (ipRequestCounts.size > 5000) {
    for (const [key, val] of ipRequestCounts.entries()) {
      if (now > val.resetTime) ipRequestCounts.delete(key);
    }
  }

  return record.count > MAX_REQUESTS_PER_WINDOW;
}

export default async function handler(req, res) {
  // CORS & Security Headers
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

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method Not Allowed' });
  }

  // Client IP Rate Limiting Defense
  const clientIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  if (isRateLimited(clientIp)) {
    return res.status(429).json({
      success: false,
      error: 'Terlalu banyak permintaan dari IP ini. Silakan tunggu 1 menit sebelum mencoba lagi.'
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
    const payload = typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {});

    const gasResponse = await fetch(gasUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: payload,
      redirect: 'follow'
    });

    if (!gasResponse.ok) {
      throw new Error(`Google Apps Script merespons dengan status HTTP ${gasResponse.status}`);
    }

    const data = await gasResponse.json();
    return res.status(200).json(data);
  } catch (error) {
    console.error('GAS Proxy Error:', error);
    return res.status(502).json({
      success: false,
      error: 'Gagal terhubung ke database backend: ' + (error.message || String(error))
    });
  }
}
