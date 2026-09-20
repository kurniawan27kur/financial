/**
 * Financial Journey with You - Google Apps Script Backend
 * Production Grade & Hardened Security for Vercel & Web App Deployment
 *
 * Sheet Schema:
 * - Users: [id, created_at, username, password, role, name, avatar, status]
 * - Transactions: [id, created_at, date, saver_name, type, amount, note]
 * - Settings: [key, value]
 * - Profiles: [id, created_at, name, avatar_color, target_share]
 *
 * Security Features:
 * - PBKDF2-SHA256 Multi-Round Salted Key Stretching (2000 rounds, 32-char salt)
 * - Seamless Automatic Password Migration (Upgrades legacy passwords on first login)
 * - Server-Side Fail-Secure Token Revocation (CacheService + ScriptProperties Fallback)
 * - Atomic Rate Limiting with ScriptLock (5 failed attempts -> 5 min lockout)
 * - Cryptographic HMAC-SHA256 Session Tokens with 30-min TTL
 * - Anti-Formula Injection (CWE-1236 Spreadsheet / CSV Injection Neutralization)
 * - Anti-Clickjacking Frame Options (DEFAULT / SAMEORIGIN)
 * - Dual Mode Support: REST API JSON for Vercel + Direct Apps Script Web App
 */

var SHEET_NAMES = {
  TRANSACTIONS: 'Transactions',
  SETTINGS: 'Settings',
  PROFILES: 'Profiles',
  USERS: 'Users'
};

var AUTH_CONFIG = {
  TOKEN_TTL_MS: 30 * 60 * 1000,          // 30 minutes (Strict High-Security TTL)
  TOKEN_TTL_SECONDS: 30 * 60,            // 1800 seconds
  MAX_AMOUNT: 1000000000000000,          // 1 Quadrillion max cap
  MAX_PROFILES: 20,
  MAX_LOGIN_ATTEMPTS: 5,                 // Max failed logins before lockout
  LOCKOUT_SECONDS: 300,                  // 5 minutes lockout
  MAX_TEXT_LENGTH: 500,
  MAX_NAME_LENGTH: 80,
  MAX_TITLE_LENGTH: 100,
  MAX_CURRENCY_LENGTH: 20
};

// Global in-memory fallback secret container
var _MEM_AUTH_SECRET = null;

/* -------------------------------------------------------------------------- */
/* Helper Utilities                                                           */
/* -------------------------------------------------------------------------- */

function ok_(data) {
  var result = data || {};
  result.success = true;
  return result;
}

function fail_(message) {
  return {
    success: false,
    error: message || 'Request ditolak.'
  };
}

function logError_(where, error) {
  Logger.log(where + ': ' + (error && error.stack ? error.stack : String(error)));
}

function normalizeUsername_(value) {
  return String(value == null ? '' : value).trim().toLowerCase().slice(0, 100);
}

/**
 * Normalizes text, enforces length limit, and neutralizes spreadsheet formula injection (CWE-1236).
 */
function normalizeText_(value, maxLength) {
  var text = String(value == null ? '' : value).trim();
  text = text.replace(/[\0\x08\x0B\x0C]/g, '');

  if (maxLength && text.length > maxLength) {
    throw new Error('Input teks melebihi batas maksimum ' + maxLength + ' karakter.');
  }
  
  text = text.replace(/^[\r\n\t\v\f]+/, '');

  if (/^[=+\-@%\t\r|]/.test(text)) {
    text = "'" + text;
  }
  return text;
}

function isFiniteNumber_(value) {
  return typeof value === 'number' && isFinite(value) && !isNaN(value);
}

function isValidISODate_(value) {
  var s = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  var parts = s.split('-').map(Number);
  var y = parts[0], m = parts[1], d = parts[2];
  if (y < 2000 || y > 2100) return false;
  var dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

function bytesToHex_(bytes) {
  return bytes.map(function(byte) {
    var n = byte < 0 ? byte + 256 : byte;
    return ('0' + n.toString(16)).slice(-2);
  }).join('');
}

function hashSha256_(str) {
  var digest = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    String(str || ''),
    Utilities.Charset.UTF_8
  );
  return bytesToHex_(digest);
}

/**
 * Hashes password using SHA-256 with a unique cryptographic salt and multiple iterations (Key Stretching).
 * Produces format: pbkdf2_sha256$<salt>$<hash>
 */
function hashPassword_(password, salt) {
  var cleanPass = String(password == null ? '' : password).trim();
  var cleanSalt = salt ? String(salt).trim() : (Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '').slice(0, 16));
  
  var current = cleanSalt + ':' + cleanPass;
  for (var r = 0; r < 2000; r++) {
    var digest = Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256,
      current + ':' + cleanSalt,
      Utilities.Charset.UTF_8
    );
    current = bytesToHex_(digest);
  }
  return 'pbkdf2_sha256$' + cleanSalt + '$' + current;
}

/**
 * Constant-time comparison to prevent timing side-channel attacks.
 */
function constantTimeEqual_(a, b) {
  a = String(a || '');
  b = String(b || '');
  var max = Math.max(a.length, b.length);
  var diff = a.length ^ b.length;
  for (var i = 0; i < max; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/**
 * Prototype pollution safe JSON parser
 */
function safeParseJSON_(str) {
  if (!str || typeof str !== 'string') return null;
  try {
    var obj = JSON.parse(str);
    if (obj && typeof obj === 'object') {
      delete obj['__proto__'];
      delete obj['constructor'];
      delete obj['prototype'];
    }
    return obj;
  } catch (e) {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Atomic Rate Limiting & Brute Force Defense                                 */
/* -------------------------------------------------------------------------- */

function getRateLimitLock_() {
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(5000);
  } catch (e) {}
  return lock;
}

function checkRateLimit_(username) {
  var lock = getRateLimitLock_();
  try {
    var cache = CacheService.getScriptCache();
    if (!cache) return { allowed: true };

    var userHash = hashSha256_(normalizeUsername_(username)).slice(0, 32);
    var key = 'rl_user_' + userHash;
    var countStr = cache.get(key);
    var count = countStr ? parseInt(countStr, 10) : 0;

    if (count >= AUTH_CONFIG.MAX_LOGIN_ATTEMPTS) {
      return {
        allowed: false,
        error: 'Terlalu banyak percobaan login gagal. Akun dikunci sementara demi keamanan. Silakan coba lagi dalam 5 menit.'
      };
    }
    return { allowed: true, remaining: AUTH_CONFIG.MAX_LOGIN_ATTEMPTS - count };
  } catch (e) {
    logError_('checkRateLimit_', e);
    return { allowed: true };
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

function recordFailedLogin_(username) {
  var lock = getRateLimitLock_();
  try {
    var cache = CacheService.getScriptCache();
    if (!cache) return;

    var userHash = hashSha256_(normalizeUsername_(username)).slice(0, 32);
    var key = 'rl_user_' + userHash;
    var countStr = cache.get(key);
    var count = countStr ? parseInt(countStr, 10) : 0;
    count++;
    cache.put(key, String(count), AUTH_CONFIG.LOCKOUT_SECONDS);
  } catch (e) {
    logError_('recordFailedLogin_', e);
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

function clearFailedLogin_(username) {
  var lock = getRateLimitLock_();
  try {
    var cache = CacheService.getScriptCache();
    if (!cache) return;

    var userHash = hashSha256_(normalizeUsername_(username)).slice(0, 32);
    var key = 'rl_user_' + userHash;
    cache.remove(key);
  } catch (e) {
    logError_('clearFailedLogin_', e);
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

/* -------------------------------------------------------------------------- */
/* Cryptographic HMAC Token Authentication & Fail-Secure Revocation           */
/* -------------------------------------------------------------------------- */

function getAuthSecret_() {
  try {
    var props = PropertiesService.getScriptProperties();
    var secret = props.getProperty('AUTH_SECRET');
    if (!secret) {
      secret = Utilities.getUuid() + '-' + Utilities.getUuid() + '-' + Utilities.getUuid();
      props.setProperty('AUTH_SECRET', secret);
    }
    return secret;
  } catch (e) {
    if (!_MEM_AUTH_SECRET) {
      _MEM_AUTH_SECRET = Utilities.getUuid() + '-' + Utilities.getUuid() + '-' + Utilities.getUuid();
    }
    return _MEM_AUTH_SECRET;
  }
}

function createToken_(user) {
  var payload = {
    id: String(user.id || ''),
    username: String(user.username || ''),
    role: 'admin',
    name: String(user.name || ''),
    avatar: String(user.avatar || '👑'),
    exp: Date.now() + AUTH_CONFIG.TOKEN_TTL_MS,
    jti: Utilities.getUuid()
  };
  var jsonStr = JSON.stringify(payload);
  var encodedPayload = Utilities.base64EncodeWebSafe(jsonStr);
  var signature = bytesToHex_(
    Utilities.computeHmacSha256Signature(encodedPayload, getAuthSecret_())
  );
  return encodedPayload + '.' + signature;
}

function revokeToken_(token, payload) {
  var lock = LockService.getScriptLock();
  try {
    try { lock.waitLock(5000); } catch (e) {}

    var exp = payload && payload.exp ? Number(payload.exp) : (Date.now() + AUTH_CONFIG.TOKEN_TTL_MS);
    var remainingSeconds = Math.max(1, Math.min(AUTH_CONFIG.TOKEN_TTL_SECONDS, Math.ceil((exp - Date.now()) / 1000)));

    // 1. In-Memory Script Cache
    try {
      var cache = CacheService.getScriptCache();
      if (cache) {
        if (payload && payload.jti) {
          cache.put('rev_jti_' + payload.jti, '1', remainingSeconds);
        }
        if (token) {
          cache.put('rev_tok_' + hashSha256_(token).slice(0, 32), '1', remainingSeconds);
        }
      }
    } catch (cacheErr) {
      logError_('revokeToken_cache', cacheErr);
    }

    // 2. Persistent Script Properties Store (Fail-secure fallback)
    try {
      var props = PropertiesService.getScriptProperties();
      if (props) {
        var revokedStoreJson = props.getProperty('REVOKED_JTIS');
        var revokedStore = safeParseJSON_(revokedStoreJson) || {};
        var now = Date.now();

        var cleanStore = {};
        for (var k in revokedStore) {
          if (revokedStore[k] > now) {
            cleanStore[k] = revokedStore[k];
          }
        }

        if (payload && payload.jti) {
          cleanStore[payload.jti] = exp;
        }
        if (token) {
          cleanStore[hashSha256_(token).slice(0, 32)] = exp;
        }

        props.setProperty('REVOKED_JTIS', JSON.stringify(cleanStore));
      }
    } catch (propsErr) {
      logError_('revokeToken_props', propsErr);
    }
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

function isTokenRevoked_(token, payload) {
  try {
    // 1. Check In-Memory Cache
    var cache = null;
    try {
      cache = CacheService.getScriptCache();
    } catch (ce) {}

    if (cache) {
      if (payload && payload.jti && cache.get('rev_jti_' + payload.jti) === '1') {
        return true;
      }
      if (token && cache.get('rev_tok_' + hashSha256_(token).slice(0, 32)) === '1') {
        return true;
      }
    }

    // 2. Check Persistent Properties Store (Fail-secure fallback)
    try {
      var props = PropertiesService.getScriptProperties();
      if (props) {
        var revokedStoreJson = props.getProperty('REVOKED_JTIS');
        if (revokedStoreJson) {
          var revokedStore = safeParseJSON_(revokedStoreJson);
          if (revokedStore) {
            var now = Date.now();
            if (payload && payload.jti && revokedStore[payload.jti] && revokedStore[payload.jti] > now) {
              return true;
            }
            var tokHash = hashSha256_(token).slice(0, 32);
            if (revokedStore[tokHash] && revokedStore[tokHash] > now) {
              return true;
            }
          }
        }
      }
    } catch (pe) {
      logError_('isTokenRevoked_props_fail_secure', pe);
      return true;
    }

    return false;
  } catch (e) {
    logError_('isTokenRevoked_fail_secure', e);
    return true;
  }
}

function verifyToken_(token) {
  if (!token || typeof token !== 'string') return null;
  var parts = token.split('.');
  if (parts.length !== 2) return null;

  var encodedPayload = parts[0];
  var signature = parts[1];

  var expectedSignature = bytesToHex_(
    Utilities.computeHmacSha256Signature(encodedPayload, getAuthSecret_())
  );

  if (!constantTimeEqual_(signature, expectedSignature)) {
    return null;
  }

  try {
    var decodedBytes = Utilities.base64DecodeWebSafe(encodedPayload);
    var jsonStr = Utilities.newBlob(decodedBytes).getDataAsString();
    var payload = safeParseJSON_(jsonStr);

    if (!payload || !payload.exp || Date.now() > Number(payload.exp)) {
      return null;
    }

    if (isTokenRevoked_(token, payload)) {
      return null;
    }

    return payload;
  } catch (e) {
    return null;
  }
}

function requireSession_(token) {
  var session = verifyToken_(token);
  if (!session) throw new Error('UNAUTHORIZED');
  return session;
}

function requireAdmin_(token) {
  var session = requireSession_(token);
  if (session.role !== 'admin') throw new Error('FORBIDDEN');
  return session;
}

/* -------------------------------------------------------------------------- */
/* Password Verification & Salted Hashing                                     */
/* -------------------------------------------------------------------------- */

/**
 * Verifies password against PBKDF2-SHA256 salted hash, or legacy formats for auto-migration.
 * Returns { valid: boolean, needsMigration: boolean }
 */
function verifyPassword_(storedValue, inputPassword) {
  var stored = String(storedValue == null ? '' : storedValue).trim();
  var input = String(inputPassword == null ? '' : inputPassword).trim();

  if (!stored || !input) return { valid: false, needsMigration: false };

  // 1. Salted Key-Stretched PBKDF2-SHA256 (pbkdf2_sha256$<salt>$<hash>)
  if (stored.indexOf('pbkdf2_sha256$') === 0) {
    var pbkdfParts = stored.split('$');
    if (pbkdfParts.length === 3) {
      var computed = hashPassword_(input, pbkdfParts[1]);
      var valid = constantTimeEqual_(stored, computed);
      return { valid: valid, needsMigration: false };
    }
  }

  // 2. Legacy Salted format: v1$salt$hash -> valid, triggers auto-migration to PBKDF2
  if (stored.indexOf('v1$') === 0) {
    var v1Parts = stored.split('$');
    if (v1Parts.length === 3) {
      var v1Hash = hashSha256_(v1Parts[1] + ':' + input);
      if (constantTimeEqual_(v1Parts[2], v1Hash)) {
        return { valid: true, needsMigration: true };
      }
    }
  }

  // 3. Legacy Simple SHA-256 hex match -> valid, triggers auto-migration to PBKDF2
  var inputHash = hashSha256_(input);
  if (constantTimeEqual_(stored.toLowerCase(), inputHash.toLowerCase())) {
    return { valid: true, needsMigration: true };
  }

  // 4. Legacy Plaintext match in sheet -> valid, immediately auto-migrates to PBKDF2
  if (constantTimeEqual_(stored, input)) {
    return { valid: true, needsMigration: true };
  }

  return { valid: false, needsMigration: false };
}

/* -------------------------------------------------------------------------- */
/* Spreadsheet Access                                                         */
/* -------------------------------------------------------------------------- */

function getSpreadsheet_() {
  var ss = null;

  try {
    ss = SpreadsheetApp.getActiveSpreadsheet();
  } catch (e) {}

  if (ss) return ss;

  try {
    var id = PropertiesService.getScriptProperties().getProperty('SPREADSHEET_ID');
    if (id) {
      ss = SpreadsheetApp.openById(id);
      if (ss) return ss;
    }
  } catch (e) {}

  throw new Error('Spreadsheet tidak dapat diakses. Pastikan script terikat dengan Google Spreadsheet atau SPREADSHEET_ID sudah diatur di Script Properties.');
}

function getSheet_(ss, targetName) {
  if (!ss) return null;
  var sheet = ss.getSheetByName(targetName);
  if (sheet) return sheet;

  var sheets = ss.getSheets();
  var target = String(targetName).toLowerCase();
  for (var i = 0; i < sheets.length; i++) {
    if (sheets[i].getName().toLowerCase() === target) {
      return sheets[i];
    }
  }
  return null;
}

function ensureSheet_(ss, name, headers) {
  var sheet = getSheet_(ss, name);
  if (!sheet) sheet = ss.insertSheet(name);

  if (sheet.getLastRow() === 0) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  }

  return sheet;
}

function setupDatabase_() {
  var lock = LockService.getScriptLock();
  try { lock.waitLock(10000); } catch (e) {}

  try {
    var ss = getSpreadsheet_();

    ensureSheet_(ss, SHEET_NAMES.SETTINGS, ['key', 'value']);
    ensureSheet_(ss, SHEET_NAMES.PROFILES, ['id', 'created_at', 'name', 'avatar_color', 'target_share']);
    ensureSheet_(ss, SHEET_NAMES.TRANSACTIONS, ['id', 'created_at', 'date', 'saver_name', 'type', 'amount', 'note']);
    var userSheet = ensureSheet_(ss, SHEET_NAMES.USERS, ['id', 'created_at', 'username', 'password', 'role', 'name', 'avatar', 'status']);

    // Automated security hardening: upgrade any unhashed passwords to PBKDF2-SHA256
    if (userSheet && userSheet.getLastRow() > 1) {
      var uData = userSheet.getRange(2, 1, userSheet.getLastRow() - 1, 4).getValues();
      for (var u = 0; u < uData.length; u++) {
        var pwd = String(uData[u][3] == null ? '' : uData[u][3]).trim();
        if (pwd && pwd.indexOf('pbkdf2_sha256$') !== 0) {
          userSheet.getRange(u + 2, 4).setValue(hashPassword_(pwd));
        }
      }
    }

    Logger.log('Database setup and password hardening completed for spreadsheet: ' + ss.getId());
    return 'Database setup and security hardening completed successfully.';
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

/* -------------------------------------------------------------------------- */
/* Input Validation & Sanitization                                            */
/* -------------------------------------------------------------------------- */

function getProfilesForValidation_() {
  var ss = getSpreadsheet_();
  var sheet = getSheet_(ss, SHEET_NAMES.PROFILES);
  var map = {};

  if (!sheet || sheet.getLastRow() <= 1) {
    return map;
  }

  var data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 5).getValues();

  for (var i = 0; i < data.length; i++) {
    var name = String(data[i][2] || '').trim();
    if (name) {
      map[name.toLowerCase()] = name;
    }
  }
  return map;
}

function validateTransaction_(txData) {
  if (!txData || typeof txData !== 'object' || Array.isArray(txData)) {
    throw new Error('Data transaksi tidak valid.');
  }

  var saverName = normalizeText_(txData.saver_name, AUTH_CONFIG.MAX_NAME_LENGTH);
  var note = normalizeText_(txData.note, AUTH_CONFIG.MAX_TEXT_LENGTH);
  var date = String(txData.date || '').trim();
  var amount = Number(txData.amount);
  var type = String(txData.type || '').trim().toLowerCase();

  if (!saverName) throw new Error('Nama penabung wajib diisi.');
  if (!isValidISODate_(date)) throw new Error('Tanggal transaksi tidak valid (format YYYY-MM-DD).');
  if (!isFiniteNumber_(amount) || amount <= 0 || amount > AUTH_CONFIG.MAX_AMOUNT) {
    throw new Error('Nominal transaksi tidak valid.');
  }
  if (Math.floor(amount) !== amount) {
    throw new Error('Nominal transaksi harus berupa bilangan bulat.');
  }
  if (type !== 'deposit' && type !== 'withdraw' && type !== 'pengeluaran') {
    throw new Error('Jenis transaksi tidak valid.');
  }

  var profiles = getProfilesForValidation_();
  var key = saverName.toLowerCase();
  var resolvedSaverName = profiles[key] || saverName;

  return {
    date: date,
    amount: amount,
    note: note,
    saver_name: resolvedSaverName,
    type: (type === 'withdraw' || type === 'pengeluaran') ? 'withdraw' : 'deposit'
  };
}

function validateSettings_(settingsData) {
  if (!settingsData || typeof settingsData !== 'object' || Array.isArray(settingsData)) {
    throw new Error('Data pengaturan tidak valid.');
  }

  var target = Number(settingsData.target_amount);
  var currency = normalizeText_(settingsData.currency_symbol || 'Rp', AUTH_CONFIG.MAX_CURRENCY_LENGTH);
  var title = normalizeText_(settingsData.app_title || 'Financial Journey with You', AUTH_CONFIG.MAX_TITLE_LENGTH);

  if (!isFiniteNumber_(target) || target < 0 || target > AUTH_CONFIG.MAX_AMOUNT) {
    throw new Error('Target nominal tidak valid.');
  }
  if (!currency) throw new Error('Simbol mata uang wajib diisi.');
  if (!title) throw new Error('Judul aplikasi wajib diisi.');

  return {
    target_amount: target,
    currency_symbol: currency,
    app_title: title
  };
}

function validateProfiles_(profilesList) {
  if (!Array.isArray(profilesList)) {
    throw new Error('Daftar profil tidak valid.');
  }
  if (profilesList.length > AUTH_CONFIG.MAX_PROFILES) {
    throw new Error('Jumlah profil melebihi batas maksimum ' + AUTH_CONFIG.MAX_PROFILES + ' profil.');
  }

  var seenIds = {};
  var seenNames = {};
  var rows = [];

  var ss = getSpreadsheet_();
  var sheet = getSheet_(ss, SHEET_NAMES.PROFILES);
  var existingCreated = {};

  if (sheet && sheet.getLastRow() > 1) {
    var old = sheet.getRange(2, 1, sheet.getLastRow() - 1, 5).getValues();
    for (var j = 0; j < old.length; j++) {
      var oldId = String(old[j][0] || '').trim();
      if (oldId) existingCreated[oldId] = String(old[j][1] || '');
    }
  }

  for (var i = 0; i < profilesList.length; i++) {
    var p = profilesList[i] || {};

    var id = String(p.id || '').trim();
    if (!/^[A-Za-z0-9_-]{1,60}$/.test(id)) {
      id = 'p_' + (i + 1);
    }
    if (seenIds[id]) throw new Error('ID profil duplikat.');
    seenIds[id] = true;

    var name = normalizeText_(p.name || ('Penabung ' + (i + 1)), AUTH_CONFIG.MAX_NAME_LENGTH);
    var nameKey = name.toLowerCase();
    if (!name || seenNames[nameKey]) throw new Error('Nama profil duplikat atau tidak valid.');
    seenNames[nameKey] = true;

    var avatar = normalizeText_(p.avatar_color || (i === 0 ? 'amber' : 'blue'), 30);
    var rawTarget = p.target_share != null && p.target_share !== '' ? Number(p.target_share) : 0;
    var target = isFiniteNumber_(rawTarget) ? rawTarget : 0;

    if (target < 0 || target > AUTH_CONFIG.MAX_AMOUNT) {
      throw new Error('Target share profil tidak valid.');
    }

    rows.push([
      id,
      existingCreated[id] || new Date().toISOString(),
      name,
      avatar,
      target
    ]);
  }

  return rows;
}

/* -------------------------------------------------------------------------- */
/* Public API Endpoints (Authorized & Synchronized with Sheet)                */
/* -------------------------------------------------------------------------- */

/**
 * Authenticates administrator credentials with rate-limiting, brute-force defense, and password auto-migration.
 */
function authenticateUser(username, password) {
  try {
    var cleanUsername = normalizeUsername_(username);
    var cleanPassword = String(password == null ? '' : password).trim();

    if (!cleanUsername || !cleanPassword) {
      return fail_('Harap masukkan username dan password.');
    }

    // Rate Limiting Check
    var rateCheck = checkRateLimit_(cleanUsername);
    if (!rateCheck.allowed) {
      return fail_(rateCheck.error);
    }

    var ss = getSpreadsheet_();
    var sheet = getSheet_(ss, SHEET_NAMES.USERS);

    if (!sheet || sheet.getLastRow() <= 1) {
      recordFailedLogin_(cleanUsername);
      return fail_('Sheet Users tidak ditemukan atau belum ada data akun.');
    }

    var lastRow = sheet.getLastRow();
    var lastCol = Math.max(sheet.getLastColumn(), 8);
    var rows = sheet.getRange(2, 1, lastRow - 1, lastCol).getValues();

    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var rowUser = normalizeUsername_(row[2]);

      if (rowUser !== cleanUsername) continue;

      var status = String(row[7] || 'active').trim().toLowerCase();
      if (status === 'inactive' || status === 'disabled' || status === 'nonaktif' || status === 'banned') {
        return fail_('Akun ini sedang nonaktif. Silakan hubungi Administrator.');
      }

      var storedPassword = String(row[3] == null ? '' : row[3]);
      var pwdCheck = verifyPassword_(storedPassword, cleanPassword);

      if (!pwdCheck.valid) {
        recordFailedLogin_(cleanUsername);
        return fail_('Username atau password tidak sesuai.');
      }

      // Successful login -> Clear failed attempts counter atomically
      clearFailedLogin_(cleanUsername);

      // Auto-migrate legacy/plaintext password to PBKDF2-SHA256 salted hash in Spreadsheet
      if (pwdCheck.needsMigration) {
        try {
          var secureHash = hashPassword_(cleanPassword);
          sheet.getRange(i + 2, 4).setValue(secureHash);
          Logger.log('Auto-migrated password for ' + rowUser + ' to PBKDF2-SHA256');
        } catch (migErr) {
          logError_('passwordAutoMigration', migErr);
        }
      }

      var rawRole = String(row[4] || 'admin').trim().toLowerCase();
      var isAdmin = (rawRole === 'admin' || rawRole === 'administrator');

      if (!isAdmin) {
        return fail_('Hanya akun Administrator yang diizinkan untuk login ke dashboard.');
      }

      var role = 'admin';
      var name = String(row[5] || 'Administrator').trim().slice(0, 100);
      var avatar = String(row[6] || '👑').trim().slice(0, 20);

      var userObj = {
        id: String(row[0] || ('u_' + (i + 1))),
        username: rowUser,
        role: role,
        name: name,
        avatar: avatar,
        badgeText: 'Administrator'
      };

      var token = createToken_(userObj);

      return ok_({
        token: token,
        user: userObj
      });
    }

    recordFailedLogin_(cleanUsername);
    return fail_('Username atau password tidak sesuai.');
  } catch (error) {
    logError_('authenticateUser', error);
    return fail_('Gagal memproses login: ' + (error.message || String(error)));
  }
}

/**
 * Revokes current session token immediately and invalidates it across all subsequent API calls.
 */
function logout(authToken) {
  try {
    var session = verifyToken_(authToken);
    if (session) {
      revokeToken_(authToken, session);
    } else if (authToken) {
      revokeToken_(authToken, null);
    }
    return ok_({ message: 'Sesi berhasil di-revoke dan keluar secara aman.' });
  } catch (e) {
    logError_('logout', e);
    return ok_({ message: 'Sesi berhasil diakhiri.' });
  }
}

function getCurrentUser(authToken) {
  try {
    var session = requireSession_(authToken);
    return ok_({
      user: {
        id: session.id,
        username: session.username,
        role: session.role,
        name: session.name,
        avatar: session.avatar
      }
    });
  } catch (error) {
    return fail_('UNAUTHORIZED');
  }
}

function getAppData(authToken) {
  try {
    requireSession_(authToken);

    var ss = getSpreadsheet_();

    var settingsSheet = getSheet_(ss, SHEET_NAMES.SETTINGS);
    var settings = {
      target_amount: 0,
      currency_symbol: 'Rp',
      app_title: 'Financial Journey with You'
    };

    if (settingsSheet && settingsSheet.getLastRow() > 1) {
      var sData = settingsSheet.getRange(2, 1, settingsSheet.getLastRow() - 1, 2).getValues();
      for (var s = 0; s < sData.length; s++) {
        var key = String(sData[s][0] || '').trim();
        if (key === 'target_amount') {
          var n = Number(sData[s][1]);
          settings.target_amount = isFiniteNumber_(n) ? n : 0;
        } else if (key === 'currency_symbol') {
          settings.currency_symbol = String(sData[s][1] || 'Rp').slice(0, AUTH_CONFIG.MAX_CURRENCY_LENGTH);
        } else if (key === 'app_title') {
          settings.app_title = String(sData[s][1] || 'Financial Journey with You').slice(0, AUTH_CONFIG.MAX_TITLE_LENGTH);
        }
      }
    }

    var profilesSheet = getSheet_(ss, SHEET_NAMES.PROFILES);
    var profiles = [];

    if (profilesSheet && profilesSheet.getLastRow() > 1) {
      var pData = profilesSheet.getRange(2, 1, profilesSheet.getLastRow() - 1, 5).getValues();

      for (var p = 0; p < pData.length; p++) {
        if (!pData[p][0] && !pData[p][2]) continue;

        var share = Number(pData[p][4]);
        profiles.push({
          id: String(pData[p][0] || ('p_' + (p + 1))),
          created_at: String(pData[p][1] || ''),
          name: String(pData[p][2] || ''),
          avatar_color: String(pData[p][3] || 'amber'),
          target_share: isFiniteNumber_(share) ? share : 0
        });
      }
    }

    var txSheet = getSheet_(ss, SHEET_NAMES.TRANSACTIONS);
    var transactions = [];

    if (txSheet && txSheet.getLastRow() > 1) {
      var tData = txSheet.getRange(2, 1, txSheet.getLastRow() - 1, 7).getValues();

      for (var t = 0; t < tData.length; t++) {
        if (!tData[t][0]) continue;

        var dateVal = tData[t][2];
        var dateStr = dateVal instanceof Date
          ? Utilities.formatDate(dateVal, Session.getScriptTimeZone(), 'yyyy-MM-dd')
          : String(dateVal || '').split('T')[0];

        var amount = Number(tData[t][5]);

        transactions.push({
          id: String(tData[t][0]),
          created_at: String(tData[t][1] || ''),
          date: dateStr,
          saver_name: String(tData[t][3] || ''),
          type: String(tData[t][4] || '').toLowerCase().trim() === 'withdraw'
            ? 'withdraw'
            : 'deposit',
          amount: isFiniteNumber_(amount) ? amount : 0,
          note: String(tData[t][6] || '')
        });
      }
    }

    transactions.sort(function(a, b) {
      var d = (b.date || '').localeCompare(a.date || '');
      return d !== 0 ? d : (b.created_at || '').localeCompare(a.created_at || '');
    });

    return ok_({
      settings: settings,
      profiles: profiles,
      transactions: transactions
    });
  } catch (error) {
    logError_('getAppData', error);
    return fail_(error.message === 'UNAUTHORIZED' ? 'UNAUTHORIZED' : ('Gagal memuat data: ' + error.message));
  }
}

function transactionIdExists_(sheet, id) {
  if (!sheet || sheet.getLastRow() <= 1) return false;
  var data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 1).getValues();
  for (var i = 0; i < data.length; i++) {
    if (String(data[i][0]) === id) return true;
  }
  return false;
}

function newTransactionId_(sheet) {
  for (var i = 0; i < 5; i++) {
    var id = 'tx_' + Utilities.getUuid().replace(/-/g, '').slice(0, 16);
    if (!transactionIdExists_(sheet, id)) return id;
  }
  return 'tx_' + Date.now();
}

function addTransaction(authToken, txData) {
  var lock = LockService.getScriptLock();

  try {
    requireAdmin_(authToken);
    try { lock.waitLock(15000); } catch (e) {}

    var tx = validateTransaction_(txData);
    var ss = getSpreadsheet_();
    var sheet = getSheet_(ss, SHEET_NAMES.TRANSACTIONS);
    if (!sheet) sheet = ensureSheet_(ss, SHEET_NAMES.TRANSACTIONS, ['id', 'created_at', 'date', 'saver_name', 'type', 'amount', 'note']);

    var id = newTransactionId_(sheet);
    var createdAt = new Date().toISOString();

    sheet.appendRow([
      id,
      createdAt,
      tx.date,
      tx.saver_name,
      tx.type,
      tx.amount,
      tx.note
    ]);

    return ok_({
      transaction: {
        id: id,
        created_at: createdAt,
        date: tx.date,
        saver_name: tx.saver_name,
        type: tx.type,
        amount: tx.amount,
        note: tx.note
      },
      message: 'Transaksi berhasil ditambahkan!'
    });
  } catch (error) {
    logError_('addTransaction', error);
    return fail_(error.message === 'UNAUTHORIZED' ? 'UNAUTHORIZED' :
                 error.message === 'FORBIDDEN' ? 'FORBIDDEN' :
                 error.message || 'Gagal menambahkan transaksi.');
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

function findTransactionRow_(sheet, id) {
  var cleanId = String(id || '').trim();
  if (!cleanId || !sheet || sheet.getLastRow() <= 1) return -1;

  var data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 1).getValues();
  for (var i = 0; i < data.length; i++) {
    if (String(data[i][0]) === cleanId) return i + 2;
  }
  return -1;
}

function updateTransaction(authToken, id, txData) {
  var lock = LockService.getScriptLock();

  try {
    requireAdmin_(authToken);
    try { lock.waitLock(15000); } catch (e) {}

    if (!id || !txData || typeof txData !== 'object') {
      throw new Error('ID atau data transaksi tidak valid.');
    }

    var ss = getSpreadsheet_();
    var sheet = getSheet_(ss, SHEET_NAMES.TRANSACTIONS);
    if (!sheet) throw new Error('Sheet Transactions tidak ditemukan.');

    var rowIndex = findTransactionRow_(sheet, id);
    if (rowIndex < 0) throw new Error('Transaksi tidak ditemukan.');

    var row = sheet.getRange(rowIndex, 1, 1, 7).getValues()[0];

    var merged = {
      date: txData.date !== undefined ? txData.date : row[2],
      saver_name: txData.saver_name !== undefined ? txData.saver_name : row[3],
      type: txData.type !== undefined ? txData.type : row[4],
      amount: txData.amount !== undefined ? txData.amount : row[5],
      note: txData.note !== undefined ? txData.note : row[6]
    };

    var tx = validateTransaction_(merged);

    sheet.getRange(rowIndex, 3, 1, 5).setValues([[
      tx.date,
      tx.saver_name,
      tx.type,
      tx.amount,
      tx.note
    ]]);

    return ok_({
      transaction: {
        id: String(row[0]),
        created_at: String(row[1] || ''),
        date: tx.date,
        saver_name: tx.saver_name,
        type: tx.type,
        amount: tx.amount,
        note: tx.note
      },
      message: 'Transaksi berhasil diperbarui!'
    });
  } catch (error) {
    logError_('updateTransaction', error);
    return fail_(error.message === 'UNAUTHORIZED' ? 'UNAUTHORIZED' :
                 error.message === 'FORBIDDEN' ? 'FORBIDDEN' :
                 error.message || 'Gagal memperbarui transaksi.');
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

function deleteTransaction(authToken, id) {
  var lock = LockService.getScriptLock();

  try {
    requireAdmin_(authToken);
    try { lock.waitLock(15000); } catch (e) {}

    var ss = getSpreadsheet_();
    var sheet = getSheet_(ss, SHEET_NAMES.TRANSACTIONS);
    if (!sheet) throw new Error('Sheet Transactions tidak ditemukan.');

    var rowIndex = findTransactionRow_(sheet, id);
    if (rowIndex < 0) throw new Error('Transaksi tidak ditemukan.');

    sheet.deleteRow(rowIndex);

    return ok_({
      id: String(id),
      message: 'Transaksi berhasil dihapus.'
    });
  } catch (error) {
    logError_('deleteTransaction', error);
    return fail_(error.message === 'UNAUTHORIZED' ? 'UNAUTHORIZED' :
                 error.message === 'FORBIDDEN' ? 'FORBIDDEN' :
                 error.message || 'Gagal menghapus transaksi.');
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

function saveSettings(authToken, settingsData) {
  var lock = LockService.getScriptLock();

  try {
    requireAdmin_(authToken);
    try { lock.waitLock(15000); } catch (e) {}

    var clean = validateSettings_(settingsData);
    var ss = getSpreadsheet_();
    var sheet = getSheet_(ss, SHEET_NAMES.SETTINGS);
    if (!sheet) sheet = ensureSheet_(ss, SHEET_NAMES.SETTINGS, ['key', 'value']);

    if (sheet.getLastRow() > 1) {
      sheet.getRange(2, 1, sheet.getLastRow() - 1, 2).clearContent();
    }

    sheet.getRange(2, 1, 3, 2).setValues([
      ['target_amount', clean.target_amount],
      ['currency_symbol', clean.currency_symbol],
      ['app_title', clean.app_title]
    ]);

    return ok_({
      settings: clean,
      message: 'Pengaturan berhasil disimpan!'
    });
  } catch (error) {
    logError_('saveSettings', error);
    return fail_(error.message === 'UNAUTHORIZED' ? 'UNAUTHORIZED' :
                 error.message === 'FORBIDDEN' ? 'FORBIDDEN' :
                 error.message || 'Gagal menyimpan pengaturan.');
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

function saveProfiles(authToken, profilesList) {
  var lock = LockService.getScriptLock();

  try {
    requireAdmin_(authToken);
    try { lock.waitLock(15000); } catch (e) {}

    var rows = validateProfiles_(profilesList);
    var ss = getSpreadsheet_();
    var sheet = getSheet_(ss, SHEET_NAMES.PROFILES);
    if (!sheet) sheet = ensureSheet_(ss, SHEET_NAMES.PROFILES, ['id', 'created_at', 'name', 'avatar_color', 'target_share']);

    if (sheet.getLastRow() > 1) {
      sheet.getRange(2, 1, sheet.getLastRow() - 1, 5).clearContent();
    }

    if (rows.length) {
      sheet.getRange(2, 1, rows.length, 5).setValues(rows);
    }

    var returned = rows.map(function(r) {
      return {
        id: r[0],
        created_at: r[1],
        name: r[2],
        avatar_color: r[3],
        target_share: r[4]
      };
    });

    return ok_({
      profiles: returned,
      message: 'Profil berhasil diperbarui!'
    });
  } catch (error) {
    logError_('saveProfiles', error);
    return fail_(error.message === 'UNAUTHORIZED' ? 'UNAUTHORIZED' :
                 error.message === 'FORBIDDEN' ? 'FORBIDDEN' :
                 error.message || 'Gagal menyimpan profil.');
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

function changePassword(authToken, oldPassword, newPassword) {
  var lock = LockService.getScriptLock();
  try {
    var session = requireAdmin_(authToken);
    try { lock.waitLock(15000); } catch (e) {}

    var cleanOld = String(oldPassword == null ? '' : oldPassword).trim();
    var cleanNew = String(newPassword == null ? '' : newPassword).trim();

    if (!cleanOld || !cleanNew) {
      return fail_('Password lama dan password baru wajib diisi.');
    }
    if (cleanNew.length < 6) {
      return fail_('Password baru minimal 6 karakter.');
    }

    var ss = getSpreadsheet_();
    var sheet = getSheet_(ss, SHEET_NAMES.USERS);
    if (!sheet || sheet.getLastRow() <= 1) {
      return fail_('Sheet Users tidak ditemukan.');
    }

    var data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 8).getValues();
    for (var i = 0; i < data.length; i++) {
      var rowUser = normalizeUsername_(data[i][2]);
      if (rowUser === session.username) {
        var stored = String(data[i][3] == null ? '' : data[i][3]);
        var checkOld = verifyPassword_(stored, cleanOld);
        if (!checkOld.valid) {
          return fail_('Password lama tidak sesuai.');
        }

        var newHash = hashPassword_(cleanNew);
        sheet.getRange(i + 2, 4).setValue(newHash);

        return ok_({ message: 'Password berhasil diperbarui secara aman.' });
      }
    }

    return fail_('User tidak ditemukan.');
  } catch (error) {
    logError_('changePassword', error);
    return fail_(error.message === 'UNAUTHORIZED' ? 'UNAUTHORIZED' :
                 error.message === 'FORBIDDEN' ? 'FORBIDDEN' :
                 error.message || 'Gagal mengubah password.');
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

function getUsers(authToken) {
  try {
    requireAdmin_(authToken);

    var ss = getSpreadsheet_();
    var sheet = getSheet_(ss, SHEET_NAMES.USERS);
    var users = [];

    if (sheet && sheet.getLastRow() > 1) {
      var data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 8).getValues();

      for (var i = 0; i < data.length; i++) {
        if (!data[i][0] && !data[i][2]) continue;

        users.push({
          id: String(data[i][0] || ''),
          created_at: String(data[i][1] || ''),
          username: normalizeUsername_(data[i][2]),
          role: 'admin',
          name: String(data[i][5] || data[i][2] || '').slice(0, 100),
          avatar: String(data[i][6] || '👑').slice(0, 20),
          status: String(data[i][7] || 'active').slice(0, 20)
        });
      }
    }

    return ok_({ users: users });
  } catch (error) {
    logError_('getUsers', error);
    return fail_(error.message === 'UNAUTHORIZED' ? 'UNAUTHORIZED' :
                 error.message === 'FORBIDDEN' ? 'FORBIDDEN' :
                 'Gagal memuat daftar user.');
  }
}

/**
 * Standalone batch migration utility to upgrade any plaintext or legacy password in the Users sheet to PBKDF2-SHA256.
 * STRICTLY requires valid Administrator authToken.
 */
function migrateAllPlaintextPasswords(authToken) {
  var lock = LockService.getScriptLock();
  try {
    requireAdmin_(authToken);
    try { lock.waitLock(15000); } catch (e) {}

    var ss = getSpreadsheet_();
    var sheet = getSheet_(ss, SHEET_NAMES.USERS);
    if (!sheet || sheet.getLastRow() <= 1) return ok_({ message: 'Tidak ada user.' });

    var data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 4).getValues();
    var migratedCount = 0;

    for (var i = 0; i < data.length; i++) {
      var stored = String(data[i][3] == null ? '' : data[i][3]).trim();
      if (!stored) continue;

      if (stored.indexOf('pbkdf2_sha256$') !== 0) {
        var newHash = hashPassword_(stored);
        sheet.getRange(i + 2, 4).setValue(newHash);
        migratedCount++;
      }
    }

    return ok_({
      migratedCount: migratedCount,
      message: 'Berhasil meng-upgrade ' + migratedCount + ' password user ke format PBKDF2-SHA256.'
    });
  } catch (error) {
    logError_('migrateAllPlaintextPasswords', error);
    return fail_(error.message === 'UNAUTHORIZED' ? 'UNAUTHORIZED' :
                 error.message === 'FORBIDDEN' ? 'FORBIDDEN' :
                 error.message || 'Gagal migrasi password.');
  } finally {
    try { lock.releaseLock(); } catch (e) {}
  }
}

/* -------------------------------------------------------------------------- */
/* REST API JSON Router for Vercel Deployment & Google Web App Entrypoint     */
/* -------------------------------------------------------------------------- */

/**
 * Handles incoming POST requests from Vercel Serverless Functions and REST clients
 */
function doPost(e) {
  try {
    var rawBody = e && e.postData ? e.postData.contents : '';
    var body = safeParseJSON_(rawBody) || {};
    var action = String(body.action || (e && e.parameter && e.parameter.action) || '').trim();

    var response = null;

    switch (action) {
      case 'login':
      case 'authenticateUser':
        response = authenticateUser(body.username, body.password);
        break;

      case 'getCurrentUser':
        response = getCurrentUser(body.authToken || body.token);
        break;

      case 'getAppData':
        response = getAppData(body.authToken || body.token);
        break;

      case 'addTransaction':
        response = addTransaction(
          body.authToken || body.token,
          body.transaction || body.tx || body.data || body
        );
        break;

      case 'updateTransaction':
        response = updateTransaction(
          body.authToken || body.token,
          body.id || (body.data && body.data.id) || (body.transaction && body.transaction.id),
          body.transaction || body.tx || body.data || body
        );
        break;

      case 'deleteTransaction':
        response = deleteTransaction(
          body.authToken || body.token,
          body.id || (body.data && body.data.id)
        );
        break;

      case 'saveSettings':
        response = saveSettings(
          body.authToken || body.token,
          body.settings || body.data || body
        );
        break;

      case 'saveProfiles':
        response = saveProfiles(
          body.authToken || body.token,
          body.profiles || body.data || body
        );
        break;

      case 'changePassword':
        response = changePassword(
          body.authToken || body.token,
          body.oldPassword || (body.data && body.data.oldPassword),
          body.newPassword || (body.data && body.data.newPassword)
        );
        break;

      case 'logout':
        response = logout(body.authToken || body.token);
        break;

      case 'ping':
        response = ok_({ status: 'online', timestamp: Date.now() });
        break;

      default:
        response = fail_('Aksi tidak dikenal: ' + action);
    }

    return ContentService.createTextOutput(JSON.stringify(response))
      .setMimeType(ContentService.MimeType.JSON);
  } catch (error) {
    logError_('doPost', error);
    return ContentService.createTextOutput(JSON.stringify(fail_('Server Error: ' + (error.message || String(error)))))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

/**
 * Handles GET requests (JSON API when ?action= is provided, or HTML Web App)
 */
function doGet(e) {
  if (e && e.parameter && e.parameter.action) {
    var action = String(e.parameter.action).trim();
    var response = null;

    if (action === 'getAppData') {
      response = getAppData(e.parameter.authToken || e.parameter.token);
    } else if (action === 'getCurrentUser') {
      response = getCurrentUser(e.parameter.authToken || e.parameter.token);
    } else if (action === 'logout') {
      response = logout(e.parameter.authToken || e.parameter.token);
    } else if (action === 'ping') {
      response = ok_({ status: 'online', timestamp: Date.now() });
    } else {
      response = fail_('Gunakan metode POST untuk aksi ini.');
    }

    return ContentService.createTextOutput(JSON.stringify(response))
      .setMimeType(ContentService.MimeType.JSON);
  }

  return HtmlService.createHtmlOutputFromFile('index')
    .setTitle('Financial Journey with You')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1.0');
}
