const crypto = require('crypto');

class InvalidPhone extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidPhone';
  }
}

const KENYAN_MOBILE_REGEX = /^\+254[71]\d{8}$/;

function normalisePhone(phone) {
  if (typeof phone !== 'string') {
    throw new InvalidPhone('Phone number must be a string');
  }

  let cleaned = phone.trim().replace(/[\s\-\.\(\)]/g, '');

  if (/^0\d{9}$/.test(cleaned)) {
    cleaned = '+254' + cleaned.slice(1);
  } else if (/^254\d{9}$/.test(cleaned)) {
    cleaned = '+' + cleaned;
  } else if (/^[71]\d{8}$/.test(cleaned)) {
    cleaned = '+254' + cleaned;
  }

  if (!KENYAN_MOBILE_REGEX.test(cleaned)) {
    throw new InvalidPhone(`Invalid Kenyan phone number format: '${phone}'`);
  }

  return cleaned;
}

function hashPhone(phone, partnerKey) {
  const norm = normalisePhone(phone);
  const message = `ke-farmer:v1:${norm}`;
  return crypto.createHmac('sha256', partnerKey).update(message).digest('hex');
}

function signRequest({
  apiKey,
  method,
  path,
  query = '',
  body = '',
  timestamp = null,
  nonce = null
}) {
  const ts = timestamp !== null ? String(timestamp) : String(Math.floor(Date.now() / 1000));
  const n = nonce !== null ? String(nonce) : crypto.randomBytes(16).toString('hex');
  const bodyBuffer = Buffer.isBuffer(body) ? body : Buffer.from(body || '', 'utf-8');
  const bodyHash = crypto.createHash('sha256').update(bodyBuffer).digest('hex');

  const canonical = `${method.toUpperCase()}\n${path}\n${query}\n${ts}\n${n}\n${bodyHash}`;
  const sig = crypto.createHmac('sha256', apiKey.trim()).update(canonical).digest('hex');

  return {
    'X-Partner-Key': apiKey,
    'X-Timestamp': ts,
    'X-Nonce': n,
    'X-Signature': sig
  };
}

module.exports = {
  normalisePhone,
  hashPhone,
  signRequest,
  InvalidPhone,
};
