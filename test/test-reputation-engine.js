const { checkReputation, __setCache, __clearCache, __getCache } = require('../src/background/reputation-engine.js');
const { computeHash, getPrefix, toBase64 } = require('../src/shared/reputation/hash-utils.js');
const { parseAndCanonicalize } = require('../src/shared/reputation/canonicalization.js');
const { generateExpressions } = require('../src/shared/reputation/expression-generator.js');

async function runTests() {
  let passed = 0;
  let total = 0;
  
  function assertEqual(actual, expected, msg) {
    total++;
    if (JSON.stringify(actual) === JSON.stringify(expected)) {
      console.log('[PASS] ' + msg);
      passed++;
    } else {
      console.error(`[FAIL] ${msg}\n  Expected: ${JSON.stringify(expected)}\n  Got:      ${JSON.stringify(actual)}`);
      process.exitCode = 1;
    }
  }
  
  function assertCondition(cond, msg) {
    total++;
    if (cond) {
      console.log('[PASS] ' + msg);
      passed++;
    } else {
      console.error(`[FAIL] ${msg}`);
      process.exitCode = 1;
    }
  }

  console.log("=== REPUTATION ENGINE TESTS ===");

  let fetchCallCount = 0;
  let mockFetchResponse = null;
  let lastRequestBody = null;
  
  // Set up opt-in mock
  global.chrome = {
    storage: {
      local: {
        get: (keys, cb) => cb({ reputationEnabled: true })
      }
    }
  };

  global.fetch = async (url, options) => {
    fetchCallCount++;
    lastRequestBody = JSON.parse(options.body);
    await new Promise(r => setTimeout(r, 50)); // Force async overlap
    if (mockFetchResponse) {
      if (mockFetchResponse.throws) throw new Error("Network error");
      return {
        ok: mockFetchResponse.ok !== false,
        status: mockFetchResponse.status || 200,
        json: async () => mockFetchResponse.body
      };
    }
    return { ok: true, json: async () => ({ results: [] }) };
  };

  // Test 1: PROXY REQUEST VALIDATION
  __clearCache();
  fetchCallCount = 0;
  lastRequestBody = null;
  await checkReputation("http://example.com/path?q=1", "http://redirect.com");
  
  assertCondition(lastRequestBody !== null, "Proxy fetch occurred");
  assertCondition(Array.isArray(lastRequestBody.prefixes), "Request contains prefixes array");
  
  let validPrefixes = true;
  for (const p of lastRequestBody.prefixes) {
    const buf = Buffer.from(p, 'base64');
    if (buf.length !== 4) validPrefixes = false;
  }
  assertCondition(validPrefixes, "Proxy Request Validation: ALL prefixes are exactly 4 bytes");
  assertCondition(JSON.stringify(lastRequestBody).indexOf("example.com") === -1, "Proxy Request Validation: full hostname is NEVER sent");

  // Test 2: In-flight deduplication
  __clearCache();
  fetchCallCount = 0;
  const p1 = checkReputation("http://dedup.com");
  const p2 = checkReputation("http://dedup.com");
  const p3 = checkReputation("http://dedup.com");
  await Promise.all([p1, p2, p3]);
  assertEqual(fetchCallCount, 1, "In-flight Request Deduplication: Rapid identical lookups result in exactly 1 fetch");

  // Test 3: Reputation Disabled Guarantee
  __clearCache();
  fetchCallCount = 0;
  global.chrome.storage.local.get = (keys, cb) => cb({ reputationEnabled: false });
  let result = await checkReputation("http://malware.com");
  assertEqual(result.status, "REPUTATION_NOT_ENABLED", "Reputation Disabled: returns correct status");
  assertEqual(fetchCallCount, 0, "Reputation Disabled: Zero network requests occurred");
  global.chrome.storage.local.get = (keys, cb) => cb({ reputationEnabled: true }); // Re-enable

  // Test 4: Stale Negative Cache handling
  __clearCache();
  fetchCallCount = 0;
  const can = parseAndCanonicalize("http://cachetest.com");
  const exprs = generateExpressions(can);
  const fullHashBytes = await computeHash(exprs[0]);
  const fullHashB64 = toBase64(fullHashBytes);
  const prefixB64 = toBase64(getPrefix(fullHashBytes));
  
  __setCache(prefixB64, {
    negativeExpireAt: Date.now() - 1000, // expired
    positiveMatches: []
  });
  
  mockFetchResponse = {
    body: {
      results: []
    }
  };
  await checkReputation("http://cachetest.com");
  assertEqual(fetchCallCount, 1, "Expired negative cache triggers fresh lookup");

  // Test 5: Stale Positive Cache handling
  __clearCache();
  fetchCallCount = 0;
  __setCache(prefixB64, {
    negativeExpireAt: Date.now() + 10000,
    positiveMatches: [
      { hashBase64: fullHashB64, threatTypes: ["MALWARE"], expireAt: Date.now() - 1000 } // expired positive
    ]
  });
  await checkReputation("http://cachetest.com");
  assertEqual(fetchCallCount, 1, "Expired positive match triggers fresh lookup");
  
  // Test 6: Stale Positive Threat does NOT produce STRONG_WARNING if offline
  __clearCache();
  fetchCallCount = 0;
  __setCache(prefixB64, {
    negativeExpireAt: Date.now() + 10000,
    positiveMatches: [
      { hashBase64: fullHashB64, threatTypes: ["MALWARE"], expireAt: Date.now() - 1000 } // expired positive
    ]
  });
  mockFetchResponse = { throws: true }; // network failure
  result = await checkReputation("http://cachetest.com");
  assertEqual(result.status, "REPUTATION_UNAVAILABLE", "Stale positive threat with network failure returns UNAVAILABLE, not STRONG_WARNING");

  // Test 7: Positive cache hit (Fresh)
  __clearCache();
  fetchCallCount = 0;
  __setCache(prefixB64, {
    negativeExpireAt: Date.now() + 10000,
    positiveMatches: [
      { hashBase64: fullHashB64, threatTypes: ["MALWARE"], expireAt: Date.now() + 10000 } // fresh
    ]
  });
  result = await checkReputation("http://cachetest.com");
  assertEqual(result.status, "REPUTATION_CONFIRMED_THREAT", "Fresh positive match returns CONFIRMED_THREAT");
  assertEqual(fetchCallCount, 0, "Fresh positive match does NOT trigger network request");

  // Test 8: Strict Hash Validation (Malformed Prefix)
  __clearCache();
  fetchCallCount = 0;
  mockFetchResponse = {
    body: {
      results: [
        {
          prefix: "abcd", // not 4 bytes when decoded
          negativeExpireTime: new Date(Date.now() + 10000).toISOString(),
          threats: []
        }
      ]
    }
  };
  await checkReputation("http://cachetest.com");
  const cached = __getCache(prefixB64);
  assertCondition(!cached, "Strict Hash Validation: Malformed prefix was rejected from cache");

  // Test 9: Strict Hash Validation (Malformed Full Hash)
  __clearCache();
  fetchCallCount = 0;
  mockFetchResponse = {
    body: {
      results: [
        {
          prefix: prefixB64,
          negativeExpireTime: new Date(Date.now() + 10000).toISOString(),
          threats: [
            { hash: "malformedHashThatIsNot32BytesLong", threatTypes: ["MALWARE"], expireTime: new Date(Date.now() + 10000).toISOString() }
          ]
        }
      ]
    }
  };
  result = await checkReputation("http://cachetest.com");
  assertEqual(result.status, "REPUTATION_NO_MATCH", "Strict Hash Validation: Malformed full hash does not trigger threat");
  const cached2 = __getCache(prefixB64);
  assertEqual(cached2.positiveMatches.length, 0, "Malformed full hash was excluded from positiveMatches");

  // Test 10: Supported Threat Types filter
  __clearCache();
  fetchCallCount = 0;
  mockFetchResponse = {
    body: {
      results: [
        {
          prefix: prefixB64,
          negativeExpireTime: new Date(Date.now() + 10000).toISOString(),
          threats: [
            { hash: fullHashB64, threatTypes: ["UNKNOWN_FUTURE_THREAT", "SOCIAL_ENGINEERING"], expireTime: new Date(Date.now() + 10000).toISOString() }
          ]
        }
      ]
    }
  };
  result = await checkReputation("http://cachetest.com");
  assertEqual(result.status, "REPUTATION_CONFIRMED_THREAT", "Supported Threat Types: Unknown threats ignored, recognized threats processed");
  assertEqual(result.threatTypes, ["SOCIAL_ENGINEERING"], "Unknown threat type filtered out");

  // Test 11: Network Failure
  __clearCache();
  fetchCallCount = 0;
  mockFetchResponse = { throws: true };
  result = await checkReputation("http://example.com");
  assertEqual(result.status, "REPUTATION_UNAVAILABLE", "Network failure returns UNAVAILABLE");

  // Test 12: Prefix Collision
  __clearCache();
  fetchCallCount = 0;
  const dummyHashBytes = await computeHash("http://some-other-url.com");
  const dummyHashB64 = toBase64(dummyHashBytes);
  
  mockFetchResponse = {
    body: {
      results: [
        {
          prefix: prefixB64, // match prefix
          negativeExpireTime: new Date(Date.now() + 10000).toISOString(),
          threats: [
            { hash: dummyHashB64, threatTypes: ["MALWARE"], expireTime: new Date(Date.now() + 10000).toISOString() } // WRONG FULL HASH
          ]
        }
      ]
    }
  };
  result = await checkReputation("http://cachetest.com");
  assertEqual(result.status, "REPUTATION_NO_MATCH", "Prefix collision without exact full-hash match does NOT trigger threat");
  
  console.log(`\nRESULTS: ${passed}/${total} passed`);
  if (passed !== total) process.exitCode = 1;
}

runTests().catch(e => {
  console.error(e);
  process.exitCode = 1;
});
