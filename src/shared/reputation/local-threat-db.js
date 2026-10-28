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
  let initPromise = null;

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
    if (typeof data.isFixture !== 'boolean') {
      return { valid: false, reason: 'Missing or invalid isFixture flag (must be boolean)' };
    }
    if (typeof data.source !== 'string' || !data.source.trim()) {
      return { valid: false, reason: 'Missing or invalid database source identifier' };
    }
    // Validate source and fixture consistency
    if (data.isFixture && data.source === 'URLHAUS_DATASET') {
      return { valid: false, reason: 'Contradictory metadata: isFixture is true but source is URLHAUS_DATASET' };
    }
    if (!data.isFixture && data.source === 'OFFLINE_SYNTHETIC_FIXTURE') {
      return { valid: false, reason: 'Contradictory metadata: isFixture is false but source is OFFLINE_SYNTHETIC_FIXTURE' };
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
    initPromise = Promise.resolve(true);
    return true;
  }

  function resetDatabase() {
    activeDatabase = null;
    isLoaded = false;
    lastError = null;
    initPromise = null;
  }

  function isReady() {
    return isLoaded && activeDatabase !== null;
  }

  function ensureInitialized(customLoader) {
    if (isReady()) {
      return Promise.resolve(true);
    }
    if (initPromise) {
      return initPromise;
    }

    if (typeof customLoader === 'function') {
      initPromise = Promise.resolve()
        .then(() => customLoader())
        .then(data => {
          const loaded = loadDatabase(data);
          if (!loaded) throw new Error(lastError || 'Invalid database schema');
          return true;
        })
        .catch(err => {
          lastError = 'Initialization failed: ' + err.message;
          return false;
        })
        .finally(() => {
          if (!isReady()) {
            initPromise = null;
          }
        });
      return initPromise;
    }

    // Default loader in Chrome extension environment
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL && typeof fetch === 'function') {
      initPromise = fetch(chrome.runtime.getURL('src/data/bundled-threat-db.json'))
        .then(res => {
          if (!res.ok) throw new Error('HTTP ' + res.status);
          return res.json();
        })
        .then(data => {
          const loaded = loadDatabase(data);
          if (!loaded) throw new Error(lastError || 'Invalid database schema');
          return true;
        })
        .catch(err => {
          lastError = 'Fetch failed: ' + err.message;
          return false;
        })
        .finally(() => {
          if (!isReady()) {
            initPromise = null;
          }
        });
      return initPromise;
    }

    return Promise.resolve(isReady());
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
    ensureInitialized,
    getStatus,
    lookupHash
  };
}));
