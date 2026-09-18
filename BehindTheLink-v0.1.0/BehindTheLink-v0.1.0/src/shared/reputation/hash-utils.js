/**
 * Utilities for hashing expressions according to Web Risk requirements.
 */

// Handle both Node.js (crypto module) and Browser (window.crypto)
const getCryptoSubtle = () => {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    return crypto.subtle;
  }
  if (typeof require !== 'undefined') {
    return require('crypto').webcrypto.subtle;
  }
  throw new Error("No Web Crypto API available");
};

/**
 * Computes the full 32-byte SHA-256 hash for a given string.
 * @param {string} str
 * @returns {Promise<Uint8Array>}
 */
async function computeHash(str) {
  const subtle = getCryptoSubtle();
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

/**
 * Extracts the 4-byte prefix from a full hash.
 * Returns as a hex string for easy deduplication and transmission,
 * or can be returned as Uint8Array depending on API preference.
 * We'll use hex string or base64 for the API request.
 * Web Risk API expects base64 encoded prefixes.
 * We will return a Uint8Array of length 4.
 * 
 * @param {Uint8Array} fullHash 
 * @returns {Uint8Array} 4-byte prefix
 */
function getPrefix(fullHash) {
  return fullHash.slice(0, 4);
}

/**
 * Converts a Uint8Array to a Base64 string.
 */
function toBase64(bytes) {
  // Using btoa in browser, or Buffer in Node
  if (typeof btoa !== 'undefined') {
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  throw new Error("No Base64 encoder available");
}

/**
 * Compares two Uint8Arrays for byte-for-byte equality.
 */
function isHashEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// UMD-style export
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.BehindTheLink = root.BehindTheLink || {};
    root.BehindTheLink.hashUtils = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  return {
    computeHash,
    getPrefix,
    toBase64,
    isHashEqual
  };
}));
