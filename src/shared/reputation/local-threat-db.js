/**
 * BehindTheLink — Local Threat Database Manager
 *
 * Provides fast, offline, privacy-preserving threat intelligence lookups
 * against bundled SHA-256 hash sets.
 *
 * Guarantees:
 * 1. 100% offline: zero network requests during URL lookups.
 * 2. Exact match only: full 32-byte (64 hex char) hash comparison; never flags on prefix alone.
 * 3. Fail-safe: missing or corrupted database reports UNAVAILABLE, never clean.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js environment
    module.exports = factory();
  } else {
    // Browser / Service Worker environment
    root.BehindTheLink = root.BehindTheLink || {};
    root.BehindTheLink.localThreatDb = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {

  let activeDatabase = null;
  let isLoaded = false;
  let lastError = null;

  function validateDatabaseSchema(data) {
    if (!data || typeof data !== 'object') {
      return { valid: false, reason: 'Database is not a valid JSON object' };
    }
    if (typeof data.formatVersion !== 'number') {
      return { valid: false, reason: 'Missing or invalid formatVersion' };
    }
    if (!data.hashes || typeof data.hashes !== 'object' || Array.isArray(data.hashes)) {
      return { valid: false, reason: 'Missing or malformed hashes dictionary' };
    }
    return { valid: true };
  }

  function loadDatabase(data) {
    const validation = validateDatabaseSchema(data);
    if (!validation.valid) {
      activeDatabase = null;
      isLoaded = false;
      lastError = validation.reason;
      return false;
    }

    activeDatabase = data;
    isLoaded = true;
    lastError = null;
    return true;
  }

  function resetDatabase() {
    activeDatabase = null;
    isLoaded = false;
    lastError = null;
  }

  function isReady() {
    return isLoaded && activeDatabase !== null;
  }

  function getStatus() {
    return {
      loaded: isLoaded,
      isFixture: activeDatabase ? !!activeDatabase.isFixture : false,
      source: activeDatabase ? activeDatabase.source : null,
      uniqueHashCount: activeDatabase ? Object.keys(activeDatabase.hashes).length : 0,
      generatedAt: activeDatabase ? activeDatabase.generatedAt : null,
      error: lastError
    };
  }

  function lookupHash(hashHex) {
    if (!isReady()) {
      return null; // Database unavailable
    }

    if (typeof hashHex !== 'string') {
      return { matched: false };
    }

    const normalized = hashHex.trim().toLowerCase();
    // Strict SHA-256 hex string validation (must be exactly 64 lowercase hex characters)
    if (normalized.length !== 64 || !/^[0-9a-f]{64}$/.test(normalized)) {
      return { matched: false };
    }

    if (Object.prototype.hasOwnProperty.call(activeDatabase.hashes, normalized)) {
      const entry = activeDatabase.hashes[normalized];
      return {
        matched: true,
        threatTypes: (entry && Array.isArray(entry.threatTypes)) ? entry.threatTypes : ['MALWARE'],
        isFixture: !!activeDatabase.isFixture
      };
    }

    return { matched: false };
  }

  // Attempt auto-load in Node.js environment if bundled file is present on disk
  if (typeof require !== 'undefined' && typeof module === 'object' && module.exports) {
    try {
      const path = require('path');
      const fs = require('fs');
      const bundledPath = path.join(__dirname, '../../data/bundled-threat-db.json');
      if (fs.existsSync(bundledPath)) {
        const raw = fs.readFileSync(bundledPath, 'utf8');
        loadDatabase(JSON.parse(raw));
      }
    } catch (e) {
      lastError = 'Auto-load failed: ' + e.message;
    }
  }

  return {
    loadDatabase,
    resetDatabase,
    isReady,
    getStatus,
    lookupHash
  };
}));
