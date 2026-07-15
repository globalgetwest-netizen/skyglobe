/* SkyGlobe Group — pure utility helpers (#24 testable core)
   No Express, no DB, no side effects. Safe to unit-test in isolation. */
const crypto = require('crypto');

// Strip/escape user input and cap its length.
function sanitize(val, maxLen = 1000) {
  if (val === null || val === undefined) return '';
  return String(val).trim().slice(0, maxLen)
    .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Lower-cased, validated email — returns '' when invalid.
function sanitizeEmail(val) {
  const e = String(val || '').trim().toLowerCase().slice(0, 254);
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? e : '';
}

// Human-readable application reference, e.g. SKY-2026-AB12.
function genRef() {
  const year = new Date().getFullYear();
  const rand = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `SKY-${year}-${rand}`;
}

// scrypt salted password hash (salt:hash hex).
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(test));
}

// HMAC-signed session tokens. Secret is injected so this stays pure/testable.
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
function signToken(email, secret) {
  const payload = Buffer.from(JSON.stringify({ email, iat: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  if (sig !== expected) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() - data.iat > TOKEN_TTL_MS) return null;
    return data.email;
  } catch { return null; }
}

// HTML-entity escape (used in generated documents/emails).
function esc2(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

module.exports = {
  sanitize, sanitizeEmail, genRef,
  hashPassword, verifyPassword,
  signToken, verifyToken, TOKEN_TTL_MS,
  esc2,
};
