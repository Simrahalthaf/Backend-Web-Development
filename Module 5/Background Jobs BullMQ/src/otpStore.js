
'use strict';

const crypto = require('crypto');

const store = new Map();
const verified = new Set();

// Generate a random 6-digit OTP
function generateOTP() {
  return String(crypto.randomInt(100000, 1000000));
}

// Store OTP for 10 minutes
function storeOTP(email, otp) {
  store.set(email, {
    otp: otp,
    expiresAt: Date.now() + 10 * 60 * 1000,
    attempts: 0
  });
}

// Verify OTP
function verifyOTP(email, code) {

  // 1. Check if OTP exists
  if (!store.has(email)) {
    return { ok: false, reason: 'not_found' };
  }

  const entry = store.get(email);

  // 2. Check if OTP has expired
  if (Date.now() > entry.expiresAt) {
    store.delete(email);
    return { ok: false, reason: 'expired' };
  }

  // 3. Check maximum attempts
  if (entry.attempts >= 3) {
    return { ok: false, reason: 'too_many_attempts' };
  }

  // 4. Check if OTP is incorrect
  if (entry.otp !== code) {
    entry.attempts++;
    return { ok: false, reason: 'wrong_code' };
  }

  // 5. Correct OTP - delete it
  store.delete(email);

  return { ok: true };
}

// Mark email as verified
function markVerified(email) {
  verified.add(email);
  console.log(`Email verified: ${email}`);
}

// Export functions and Map
module.exports = {
  generateOTP,
  storeOTP,
  verifyOTP,
  markVerified,
  _store: store
};
