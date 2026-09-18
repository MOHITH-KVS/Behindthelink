// UMD-style export and dependency resolution
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js environment
    const canonicalization = require('../shared/reputation/canonicalization.js');
    const expressionGenerator = require('../shared/reputation/expression-generator.js');
    const hashUtils = require('../shared/reputation/hash-utils.js');
    module.exports = factory(canonicalization, expressionGenerator, hashUtils);
  } else {
    // Browser / Service Worker environment
    root.BehindTheLink = root.BehindTheLink || {};
    root.BehindTheLink.reputationEngine = factory(
      root.BehindTheLink.canonicalization,
      root.BehindTheLink.expressionGenerator,
      root.BehindTheLink.hashUtils
    );
  }
}(typeof self !== 'undefined' ? self : this, function (canonicalization, expressionGenerator, hashUtils) {

  const { parseAndCanonicalize } = canonicalization;
  const { generateExpressions } = expressionGenerator;
  const { computeHash, getPrefix, toBase64, isHashEqual } = hashUtils;

  const PROXY_URL = 'https://reputation.behindthelink.net/v1/hashes.search';

  // Cache structure: Map<prefixBase64, { negativeExpireAt: number, positiveMatches: Array<{hashBase64, threatTypes: Array, expireAt: number}> }>
  let cache = new Map();
  const MAX_CACHE_SIZE = 1000;

  // Deduplication map for in-flight requests: Map<prefixBase64, Promise>
  const inFlightRequests = new Map(); 

  const SUPPORTED_THREATS = new Set(['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE']);

  function bytesToBase64(bytes) {
    return toBase64(bytes);
  }

  function base64ToBytes(base64) {
    if (typeof atob !== 'undefined') {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    }
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(base64, 'base64'));
    }
    throw new Error("No Base64 decoder available");
  }

  function parseRFC3339(timeStr) {
    const d = new Date(timeStr);
    return isNaN(d.getTime()) ? 0 : d.getTime();
  }

  function fetchPrefixes(prefixesB64) {
    const toFetch = [];
    const promises = [];

    for (const p of prefixesB64) {
      if (inFlightRequests.has(p)) {
        promises.push(inFlightRequests.get(p));
      } else {
        toFetch.push(p);
      }
    }

    if (toFetch.length > 0) {
      const fetchPromise = (async () => {
        try {
          const response = await fetch(PROXY_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prefixes: toFetch })
          });
          
          if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
          }
          
          const data = await response.json();
          if (!data || !Array.isArray(data.results)) {
            throw new Error("Malformed proxy response");
          }

          for (const result of data.results) {
            if (!result.prefix) continue;
            
            try {
              const prefixBytes = base64ToBytes(result.prefix);
              if (prefixBytes.length !== 4) continue;
            } catch (e) {
              continue;
            }

            const prefixB64 = result.prefix;
            const negativeExpireAt = parseRFC3339(result.negativeExpireTime);
            
            const positiveMatches = [];
            if (Array.isArray(result.threats)) {
              for (const t of result.threats) {
                if (!t.hash || !Array.isArray(t.threatTypes)) continue;
                
                try {
                  const hashBytes = base64ToBytes(t.hash);
                  if (hashBytes.length !== 32) continue; // strict hash validation
                } catch(e) {
                  continue; // malformed base64
                }

                // Filter supported threats
                const validThreats = t.threatTypes.filter(type => SUPPORTED_THREATS.has(type));
                if (validThreats.length > 0) {
                  positiveMatches.push({
                    hashBase64: t.hash,
                    threatTypes: validThreats,
                    expireAt: parseRFC3339(t.expireTime)
                  });
                }
              }
            }

            if (cache.size >= MAX_CACHE_SIZE && !cache.has(prefixB64)) {
              const firstKey = cache.keys().next().value;
              cache.delete(firstKey);
            }
            cache.set(prefixB64, {
              negativeExpireAt,
              positiveMatches
            });
          }
          
          return { success: true };
        } catch (e) {
          console.error("Reputation fetch failed:", e);
          return { success: false, error: e.message };
        } finally {
          for (const p of toFetch) {
            inFlightRequests.delete(p);
          }
        }
      })();
      
      for (const p of toFetch) {
        inFlightRequests.set(p, fetchPromise);
      }
      promises.push(fetchPromise);
    }

    return Promise.all(promises).then(results => results.every(r => r.success));
  }

  async function isOptedIn() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return new Promise(resolve => {
        chrome.storage.local.get(['reputationEnabled'], (res) => {
          resolve(!!res.reputationEnabled);
        });
      });
    }
    // For Node.js tests, assume true unless mocked
    return true; 
  }

  async function checkReputation(targetUrl, redirectTarget) {
    const enabled = await isOptedIn();
    if (!enabled) {
      return { status: 'REPUTATION_NOT_ENABLED' };
    }

    const urlsToCheck = [targetUrl];
    if (redirectTarget) {
      urlsToCheck.push(redirectTarget);
    }

    const allExpressions = [];
    for (const url of urlsToCheck) {
      const can = parseAndCanonicalize(url);
      const exprs = generateExpressions(can);
      allExpressions.push(...exprs);
    }

    const uniqueExprs = Array.from(new Set(allExpressions));
    const prefixToFullHashes = new Map();
    const prefixesB64 = new Set();

    for (const expr of uniqueExprs) {
      const fullHash = await computeHash(expr);
      const fullHashB64 = bytesToBase64(fullHash);
      const prefix = getPrefix(fullHash);
      const prefixB64 = bytesToBase64(prefix);
      
      prefixesB64.add(prefixB64);
      if (!prefixToFullHashes.has(prefixB64)) {
        prefixToFullHashes.set(prefixB64, new Set());
      }
      prefixToFullHashes.get(prefixB64).add(fullHashB64);
    }

    const prefixesToFetch = [];
    const now = Date.now();

    for (const pB64 of prefixesB64) {
      const entry = cache.get(pB64);
      if (!entry) {
        prefixesToFetch.push(pB64);
      } else {
        // Check if negative cache is expired, or if ANY positive match is expired
        let isStale = false;
        if (now > entry.negativeExpireAt) {
          isStale = true;
        } else {
          for (const pMatch of entry.positiveMatches) {
            if (now > pMatch.expireAt) {
              isStale = true;
              break;
            }
          }
        }
        
        if (isStale) {
          prefixesToFetch.push(pB64);
        }
      }
    }

    let fetchSuccess = true;
    if (prefixesToFetch.length > 0) {
      fetchSuccess = await fetchPrefixes(prefixesToFetch);
    }

    if (!fetchSuccess && prefixesToFetch.length > 0) {
      return { status: 'REPUTATION_UNAVAILABLE' };
    }

    let confirmedThreats = [];
    const currentNow = Date.now();
    
    for (const pB64 of prefixesB64) {
      const entry = cache.get(pB64);
      if (entry) {
        const localHashesForPrefix = prefixToFullHashes.get(pB64);
        for (const threat of entry.positiveMatches) {
          if (currentNow <= threat.expireAt && localHashesForPrefix.has(threat.hashBase64)) {
            confirmedThreats.push(...threat.threatTypes);
          }
        }
      }
    }

    if (confirmedThreats.length > 0) {
      confirmedThreats = Array.from(new Set(confirmedThreats));
      return { 
        status: 'REPUTATION_CONFIRMED_THREAT', 
        threatTypes: confirmedThreats 
      };
    }

    return { status: 'REPUTATION_NO_MATCH' };
  }

  return {
    checkReputation,
    __setCache: (p, data) => cache.set(p, data),
    __clearCache: () => { cache.clear(); inFlightRequests.clear(); },
    __getCache: (p) => cache.get(p)
  };
}));
