// BehindTheLink — Reputation Engine (Local-First Architecture)
// UMD-style export and dependency resolution
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js environment
    const canonicalization = require('../shared/reputation/canonicalization.js');
    const expressionGenerator = require('../shared/reputation/expression-generator.js');
    const hashUtils = require('../shared/reputation/hash-utils.js');
    const localThreatDb = require('../shared/reputation/local-threat-db.js');
    module.exports = factory(canonicalization, expressionGenerator, hashUtils, localThreatDb);
  } else {
    // Browser / Service Worker environment
    root.BehindTheLink = root.BehindTheLink || {};
    root.BehindTheLink.reputationEngine = factory(
      root.BehindTheLink.canonicalization,
      root.BehindTheLink.expressionGenerator,
      root.BehindTheLink.hashUtils,
      root.BehindTheLink.localThreatDb
    );
  }
}(typeof self !== 'undefined' ? self : this, function (canonicalization, expressionGenerator, hashUtils, localThreatDb) {

  const { parseAndCanonicalize } = canonicalization;
  const { generateExpressions } = expressionGenerator;
  const { computeHash, toHex } = hashUtils;

  const SUPPORTED_THREATS = new Set(['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE']);

  function bytesToHex(bytes) {
    if (typeof toHex === 'function') {
      return toHex(bytes);
    }
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      const h = bytes[i].toString(16);
      hex += (h.length === 1 ? '0' + h : h);
    }
    return hex;
  }

  async function isOptedIn() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return new Promise(resolve => {
        chrome.storage.local.get(['reputationEnabled'], (res) => {
          // Fresh installation default: enabled (true) unless explicitly set to false
          resolve(res.reputationEnabled !== false);
        });
      });
    }
    // For Node.js tests, assume true unless mocked
    return true;
  }

  function getActiveDb() {
    if (localThreatDb) return localThreatDb;
    if (typeof self !== 'undefined' && self.BehindTheLink && self.BehindTheLink.localThreatDb) {
      return self.BehindTheLink.localThreatDb;
    }
    return null;
  }

  async function checkReputation(targetUrl, redirectTarget) {
    const enabled = await isOptedIn();
    if (!enabled) {
      return { status: 'REPUTATION_NOT_ENABLED' };
    }

    const db = getActiveDb();
    if (!db) {
      return { status: 'REPUTATION_UNAVAILABLE' };
    }

    // Await database initialization if in progress or not ready
    if (!db.isReady() && typeof db.ensureInitialized === 'function') {
      await db.ensureInitialized();
    }

    if (!db.isReady()) {
      return { status: 'REPUTATION_UNAVAILABLE' };
    }

    const urlsToCheck = [];
    if (targetUrl && typeof targetUrl === 'string') {
      urlsToCheck.push(targetUrl);
    }
    if (redirectTarget && typeof redirectTarget === 'string' && redirectTarget !== targetUrl) {
      urlsToCheck.push(redirectTarget);
    }

    const allExpressions = [];
    for (const url of urlsToCheck) {
      if (!url || typeof url !== 'string') continue;
      try {
        const can = parseAndCanonicalize(url);
        const exprs = generateExpressions(can);
        allExpressions.push(...exprs);
      } catch (e) {
        // Malformed URL, skip expression generation for this URL
      }
    }

    const uniqueExprs = Array.from(new Set(allExpressions));
    if (uniqueExprs.length === 0) {
      return { status: 'REPUTATION_NO_MATCH' };
    }

    const confirmedThreats = [];
    let isFixture = false;

    for (const expr of uniqueExprs) {
      const hashBytes = await computeHash(expr);
      const hashHex = bytesToHex(hashBytes);

      const match = db.lookupHash(hashHex);
      if (match === null) {
        // Database became unavailable during lookup
        return { status: 'REPUTATION_UNAVAILABLE' };
      }

      if (match && match.matched) {
        if (Array.isArray(match.threatTypes)) {
          for (const t of match.threatTypes) {
            if (SUPPORTED_THREATS.has(t)) {
              confirmedThreats.push(t);
            }
          }
        } else {
          confirmedThreats.push('MALWARE');
        }

        if (match.isFixture) {
          isFixture = true;
        }
      }
    }

    if (confirmedThreats.length > 0) {
      return {
        status: 'REPUTATION_CONFIRMED_THREAT',
        threatTypes: Array.from(new Set(confirmedThreats)),
        isFixture: isFixture
      };
    }

    return { status: 'REPUTATION_NO_MATCH' };
  }

  return {
    checkReputation,
    isOptedIn,
    setDatabase: (data) => {
      const db = getActiveDb();
      return db ? db.loadDatabase(data) : false;
    },
    resetDatabase: () => {
      const db = getActiveDb();
      if (db) db.resetDatabase();
    },
    getDatabaseStatus: () => {
      const db = getActiveDb();
      return db ? db.getStatus() : null;
    },
    // Backwards compatibility with test harness
    __setCache: () => {},
    __clearCache: () => {},
    __getCache: () => null
  };
}));
