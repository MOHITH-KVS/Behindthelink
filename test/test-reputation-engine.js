const { checkReputation, setDatabase, resetDatabase, getDatabaseStatus } = require('../src/background/reputation-engine.js');
const localThreatDb = require('../src/shared/reputation/local-threat-db.js');
const { computeHash, toHex } = require('../src/shared/reputation/hash-utils.js');
const { parseAndCanonicalize } = require('../src/shared/reputation/canonicalization.js');
const { generateExpressions } = require('../src/shared/reputation/expression-generator.js');
const fs = require('fs');
const path = require('path');

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

  console.log("=== REPUTATION ENGINE TESTS (LOCAL-FIRST) ===");

  let networkCallCount = 0;
  global.fetch = async () => {
    networkCallCount++;
    throw new Error("SECURITY VIOLATION: Network request attempted during local reputation check");
  };

  // Mock chrome.storage.local for opt-in testing
  let mockStorage = { reputationEnabled: true };
  global.chrome = {
    storage: {
      local: {
        get: (keys, cb) => cb(mockStorage)
      }
    }
  };

  function reloadBundledDb() {
    const dbPath = path.join(__dirname, '../src/data/bundled-threat-db.json');
    const raw = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
    setDatabase(raw);
  }

  // Ensure bundled DB is loaded
  reloadBundledDb();

  // Test 1: Zero network requests on lookup
  networkCallCount = 0;
  const res1 = await checkReputation("http://example.com/test");
  assertEqual(res1.status, "REPUTATION_NO_MATCH", "Benign URL returns REPUTATION_NO_MATCH");
  assertEqual(networkCallCount, 0, "Zero network requests occurred during lookup");

  // Test 2: Reputation Disabled Guarantee
  mockStorage.reputationEnabled = false;
  const disabledRes = await checkReputation("http://malware.test/payload.exe");
  assertEqual(disabledRes.status, "REPUTATION_NOT_ENABLED", "Reputation Disabled: returns correct status");
  assertEqual(networkCallCount, 0, "Reputation Disabled: Zero network requests occurred");
  mockStorage.reputationEnabled = true; // Re-enable

  // Test 3: Fixture match returns CONFIRMED_THREAT
  const hitRes = await checkReputation("http://malware.test/payload.exe");
  assertEqual(hitRes.status, "REPUTATION_CONFIRMED_THREAT", "Exact fixture matches CONFIRMED_THREAT");
  assertEqual(hitRes.threatTypes, ["MALWARE"], "Threat types match MALWARE");
  assertEqual(hitRes.isFixture, true, "isFixture flag correctly set");

  // Test 4: Path-specific precision
  const safePathRes = await checkReputation("http://malware.test/safe-page.html");
  assertEqual(safePathRes.status, "REPUTATION_NO_MATCH", "Different path on host does not match path-specific threat");

  // Test 5: Query-specific matching
  const queryHit = await checkReputation("http://malware-gate.test/download.php?aff=123");
  assertEqual(queryHit.status, "REPUTATION_CONFIRMED_THREAT", "Query-specific threat matches exact query parameters");

  const queryMiss = await checkReputation("http://malware-gate.test/download.php?aff=999");
  assertEqual(queryMiss.status, "REPUTATION_NO_MATCH", "Mismatched query parameter does not trigger threat");

  // Test 6: Root C2 matching covers subpaths
  const rootHit = await checkReputation("http://botnet-c2.test/command/exec");
  assertEqual(rootHit.status, "REPUTATION_CONFIRMED_THREAT", "Root-level threat matches subpaths");

  // Test 7: Redirect destination detection
  const redirectHit = await checkReputation("http://clean-shortener.test/xyz", "http://malware.test/payload.exe");
  assertEqual(redirectHit.status, "REPUTATION_CONFIRMED_THREAT", "Redirect destination threat detected");

  // Test 8: Hash-prefix collision resistance (CRITICAL)
  // Construct a collision: shares first 4 bytes (8 hex chars) with a threat, but differs in 28 bytes
  const threatBytes = await computeHash("malware.test/payload.exe");
  const threatHex = toHex(threatBytes);
  const prefixHex = threatHex.substring(0, 8);
  const collidingFakeHash = prefixHex + "99999999999999999999999999999999999999999999999999999999";

  setDatabase({
    formatVersion: 1,
    source: 'COLLISION_TEST',
    isFixture: true,
    hashes: {
      [collidingFakeHash]: { threatTypes: ['MALWARE'] }
    }
  });

  const collisionResult = await checkReputation("http://malware.test/payload.exe");
  assertEqual(collisionResult.status, "REPUTATION_NO_MATCH", "Prefix collision without exact full hash does NOT match");

  // Restore bundled database
  reloadBundledDb();

  // Test 9: Supported Threat Types filtering
  setDatabase({
    formatVersion: 1,
    source: 'FILTER_TEST',
    isFixture: true,
    hashes: {
      [threatHex]: { threatTypes: ["UNKNOWN_FUTURE_THREAT", "SOCIAL_ENGINEERING"] }
    }
  });
  const filterResult = await checkReputation("http://malware.test/payload.exe");
  assertEqual(filterResult.status, "REPUTATION_CONFIRMED_THREAT", "Threat matches recognized types");
  assertEqual(filterResult.threatTypes, ["SOCIAL_ENGINEERING"], "Unknown threat type filtered out");

  // Test 10: Unloaded database returns UNAVAILABLE (never safe)
  resetDatabase();
  const unavailResult = await checkReputation("http://malware.test/payload.exe");
  assertEqual(unavailResult.status, "REPUTATION_UNAVAILABLE", "Unloaded database returns UNAVAILABLE");

  // Test 11: Malformed database returns UNAVAILABLE
  setDatabase({ formatVersion: "invalid" });
  const malformedResult = await checkReputation("http://malware.test/payload.exe");
  assertEqual(malformedResult.status, "REPUTATION_UNAVAILABLE", "Malformed database returns UNAVAILABLE");

  // Restore bundled database
  reloadBundledDb();

  // Test 12: Malformed URL input does not crash
  const malformedUrlResult = await checkReputation("not a valid url at all %zz %%%");
  assertEqual(malformedUrlResult.status, "REPUTATION_NO_MATCH", "Malformed URL handled gracefully");

  // Final network call check
  assertEqual(networkCallCount, 0, "Zero network requests occurred throughout all tests");

  console.log(`\nRESULTS: ${passed}/${total} passed`);
  if (passed !== total) process.exitCode = 1;
}

runTests().catch(e => {
  console.error("Test execution failed:", e);
  process.exitCode = 1;
});
