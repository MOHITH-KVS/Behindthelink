/**
 * BehindTheLink — Phase 2A Local Threat Database Test Suite
 *
 * Deterministic offline tests covering:
 * - Exact full-hash threat matching (never prefix-alone).
 * - Path-specific and query-specific matching.
 * - Root C2, non-standard ports, and subdomain expression matching.
 * - URL variants (fragments, trailing slashes, case normalization).
 * - Hash prefix collision resistance (false-positive prevention).
 * - Benign URL safety (Wikipedia, Google, Amazon).
 * - Malformed, corrupt, or missing database handling (UNAVAILABLE, never safe).
 * - Opt-in handling (disabled returns REPUTATION_NOT_ENABLED).
 * - Redirect target detection.
 * - Zero network activity invariant.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

// Setup environment for browser/worker modules in Node
global.self = global;
global.window = global;
global.BehindTheLink = global.BehindTheLink || {};

const canonicalization = require('../src/shared/reputation/canonicalization.js');
const expressionGenerator = require('../src/shared/reputation/expression-generator.js');
const hashUtils = require('../src/shared/reputation/hash-utils.js');
const localThreatDb = require('../src/shared/reputation/local-threat-db.js');
const reputationEngine = require('../src/background/reputation-engine.js');
require('../src/shared/safety-analyzer.js');
require('../src/shared/assessment-aggregator.js');
const { buildThreatFeed } = require('../scripts/build-threat-feed.js');

async function runTestSuite() {
  console.log("=== PHASE 2A LOCAL THREAT DATABASE TESTS ===");
  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${name}`);
      console.error(err);
      process.exitCode = 1;
    }
  }

  async function asyncTest(name, fn) {
    total++;
    try {
      await fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${name}`);
      console.error(err);
      process.exitCode = 1;
    }
  }

  // Ensure clean opt-in state (reputation enabled by default in test harness)
  global.chrome = {
    storage: {
      local: {
        get: (keys, cb) => cb({ reputationEnabled: true })
      }
    }
  };

  // Zero-network guard: global.fetch MUST NOT be called!
  let networkCallCount = 0;
  global.fetch = async () => {
    networkCallCount++;
    throw new Error("SECURITY VIOLATION: Network request attempted during local threat check!");
  };

  // Test 1: Bundled Database schema and file verification
  test("1. Bundled database schema and file integrity", () => {
    const dbPath = path.join(__dirname, '../src/data/bundled-threat-db.json');
    assert.ok(fs.existsSync(dbPath), "bundled-threat-db.json must exist");
    
    const content = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
    assert.strictEqual(content.formatVersion, 1);
    assert.strictEqual(content.isFixture, true);
    assert.strictEqual(content.source, 'OFFLINE_SYNTHETIC_FIXTURE');
    assert.ok(content.uniqueHashCount > 0, "Must contain compiled hashes");
    assert.ok(typeof content.hashes === 'object', "hashes must be a dictionary");

    const sampleHash = Object.keys(content.hashes)[0];
    assert.strictEqual(sampleHash.length, 64, "Hash must be 64-char lowercase hex string");
    assert.ok(/^[0-9a-f]{64}$/.test(sampleHash), "Hash must be valid hexadecimal");
  });

  // Test 2: Compiler script determinism
  await asyncTest("2. build-threat-feed.js deterministic compilation", async () => {
    const fixtureCsv = path.join(__dirname, '../data/fixtures/sample-threat-fixtures.csv');
    const tempOutput = path.join(__dirname, '../scratch/temp-compiled-db.json');
    
    const compiled = await buildThreatFeed(fixtureCsv, tempOutput);
    assert.strictEqual(compiled.uniqueHashCount, 5, "Fixture must produce expected exact threat records");
    
    // Clean up scratch file
    if (fs.existsSync(tempOutput)) {
      fs.unlinkSync(tempOutput);
    }
  });

  // Test 3: Path-specific threat matching
  await asyncTest("3. Path-specific threat fixture matches exact path only", async () => {
    // Re-verify database is loaded
    localThreatDb.resetDatabase();
    const raw = JSON.parse(fs.readFileSync(path.join(__dirname, '../src/data/bundled-threat-db.json'), 'utf8'));
    localThreatDb.loadDatabase(raw);

    // Exact path fixture: http://malware.test/payload.exe
    const hit = await reputationEngine.checkReputation("http://malware.test/payload.exe");
    assert.strictEqual(hit.status, "REPUTATION_CONFIRMED_THREAT");
    assert.ok(hit.threatTypes.includes("MALWARE"));
    assert.strictEqual(hit.isFixture, true);

    // Unrelated path on same host: http://malware.test/safe-page.html (MUST NOT MATCH)
    const miss = await reputationEngine.checkReputation("http://malware.test/safe-page.html");
    assert.strictEqual(miss.status, "REPUTATION_NO_MATCH", "Different path on host must not match path-specific threat");

    // Root path on same host: http://malware.test/ (MUST NOT MATCH)
    const rootMiss = await reputationEngine.checkReputation("http://malware.test/");
    assert.strictEqual(rootMiss.status, "REPUTATION_NO_MATCH", "Root path must not match path-specific threat");
  });

  // Test 4: Query-specific threat matching
  await asyncTest("4. Query-specific threat fixture matches exact query parameters", async () => {
    // Fixture: http://malware-gate.test/download.php?aff=123
    const hit = await reputationEngine.checkReputation("http://malware-gate.test/download.php?aff=123");
    assert.strictEqual(hit.status, "REPUTATION_CONFIRMED_THREAT");
    assert.ok(hit.threatTypes.includes("MALWARE"));

    // Different query parameter: http://malware-gate.test/download.php?aff=999 (MUST NOT MATCH)
    const miss = await reputationEngine.checkReputation("http://malware-gate.test/download.php?aff=999");
    assert.strictEqual(miss.status, "REPUTATION_NO_MATCH", "Different query string must not trigger query-specific threat");

    // Path without query: http://malware-gate.test/download.php (MUST NOT MATCH)
    const noQueryMiss = await reputationEngine.checkReputation("http://malware-gate.test/download.php");
    assert.strictEqual(noQueryMiss.status, "REPUTATION_NO_MATCH", "Missing query parameters must not trigger query-specific threat");
  });

  // Test 5: Root-level C2 threat matching covers subpaths
  await asyncTest("5. Root-level C2 fixture matches all subpaths under domain", async () => {
    // Fixture: http://botnet-c2.test/
    const hitRoot = await reputationEngine.checkReputation("http://botnet-c2.test/");
    assert.strictEqual(hitRoot.status, "REPUTATION_CONFIRMED_THREAT");

    const hitSubpath = await reputationEngine.checkReputation("http://botnet-c2.test/command/ping");
    assert.strictEqual(hitSubpath.status, "REPUTATION_CONFIRMED_THREAT", "Root threat expression matches subpaths");
  });

  // Test 6: Port handling per canonicalization spec (ports stripped during canonicalization)
  await asyncTest("6. Non-default and default ports canonicalize consistently per specification", async () => {
    // Fixture: http://port-malware.test:8080/drop.bin (canonicalizes to port-malware.test/drop.bin)
    const hitPort = await reputationEngine.checkReputation("http://port-malware.test:8080/drop.bin");
    assert.strictEqual(hitPort.status, "REPUTATION_CONFIRMED_THREAT", "Exact fixture with port matches");

    // Standard port or no port: canonicalizes to same host/path
    const hitDefault = await reputationEngine.checkReputation("http://port-malware.test/drop.bin");
    assert.strictEqual(hitDefault.status, "REPUTATION_CONFIRMED_THREAT", "Port-stripped canonical expression matches");

    // Explicit port :80 canonicalizes to same host/path
    const hitPort80 = await reputationEngine.checkReputation("http://port-malware.test:80/drop.bin");
    assert.strictEqual(hitPort80.status, "REPUTATION_CONFIRMED_THREAT", "Explicit port 80 canonical expression matches");

    // Different path on same host: MUST NOT MATCH
    const missPath = await reputationEngine.checkReputation("http://port-malware.test:8080/safe-page.html");
    assert.strictEqual(missPath.status, "REPUTATION_NO_MATCH", "Different path on host must not match");
  });

  // Test 7: URL variants, fragments, and canonicalization
  await asyncTest("7. URL variants (fragments, casing, trailing slashes) normalize properly", async () => {
    // Fragment stripped: http://malware.test/payload.exe#section1
    const hitFrag = await reputationEngine.checkReputation("http://malware.test/payload.exe#section1");
    assert.strictEqual(hitFrag.status, "REPUTATION_CONFIRMED_THREAT", "URL fragment must be stripped before matching");

    // Host casing normalization: http://MALWARE.TEST/payload.exe
    const hitCase = await reputationEngine.checkReputation("http://MALWARE.TEST/payload.exe");
    assert.strictEqual(hitCase.status, "REPUTATION_CONFIRMED_THREAT", "Hostname casing must be normalized");

    // Path hex percent-encoding: http://malware.test/%70%61%79%6c%6f%61%64%2e%65%78%65
    const hitEncoded = await reputationEngine.checkReputation("http://malware.test/%70%61%79%6c%6f%61%64%2e%65%78%65");
    assert.strictEqual(hitEncoded.status, "REPUTATION_CONFIRMED_THREAT", "Percent-encoded path must be fully unescaped");
  });

  // Test 8: Hash-prefix collision resistance (CRITICAL FALSE-POSITIVE GUARD)
  await asyncTest("8. 4-byte hash-prefix collision without exact full hash DOES NOT match", async () => {
    // Compute full hash for a known threat expression: malware.test/payload.exe
    const threatExpr = "malware.test/payload.exe";
    const threatHashBytes = await hashUtils.computeHash(threatExpr);
    const threatHashHex = hashUtils.toHex(threatHashBytes);
    const prefixHex = threatHashHex.substring(0, 8); // 4 bytes = 8 hex chars

    // Synthetic collision object: shares same 4-byte prefix, but different remaining 28 bytes
    const fakeFullHashHex = prefixHex + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    
    // Inject custom database containing ONLY the fake hash
    localThreatDb.loadDatabase({
      formatVersion: 1,
      source: 'COLLISION_TEST',
      isFixture: true,
      hashes: {
        [fakeFullHashHex]: { threatTypes: ['MALWARE'] }
      }
    });

    // Query the actual URL: its prefix matches fakeFullHashHex prefix, but full hash differs!
    const result = await reputationEngine.checkReputation("http://malware.test/payload.exe");
    assert.strictEqual(result.status, "REPUTATION_NO_MATCH", "Prefix collision alone MUST NEVER trigger a threat match");

    // Restore standard fixture database
    const raw = JSON.parse(fs.readFileSync(path.join(__dirname, '../src/data/bundled-threat-db.json'), 'utf8'));
    localThreatDb.loadDatabase(raw);
  });

  // Test 9: Benign URLs stay clean
  await asyncTest("9. Popular benign URLs return REPUTATION_NO_MATCH", async () => {
    const benignUrls = [
      "https://en.wikipedia.org/wiki/Computer_security",
      "https://www.google.com/search?q=test",
      "https://www.amazon.com/dp/B08N5WRWNW",
      "https://github.com/torvalds/linux",
      "https://mozilla.org/firefox"
    ];

    for (const url of benignUrls) {
      const res = await reputationEngine.checkReputation(url);
      assert.strictEqual(res.status, "REPUTATION_NO_MATCH", `Benign site ${url} must return REPUTATION_NO_MATCH`);
    }
  });

  // Test 10: Redirect target detection
  await asyncTest("10. Redirect destination checking detects threat at destination URL", async () => {
    // Hovered link is benign shortener, but redirect target is threat fixture
    const shortUrl = "https://tinyurl.com/safe-shortener";
    const destUrl = "http://malware.test/payload.exe";

    const res = await reputationEngine.checkReputation(shortUrl, destUrl);
    assert.strictEqual(res.status, "REPUTATION_CONFIRMED_THREAT", "Resolved redirect destination must trigger threat");
  });

  // Test 11: Missing, corrupt, or unready database returns REPUTATION_UNAVAILABLE
  await asyncTest("11. Corrupted or unloaded database returns REPUTATION_UNAVAILABLE (never clean)", async () => {
    // Reset database to unloaded state
    localThreatDb.resetDatabase();
    assert.strictEqual(localThreatDb.isReady(), false);

    const unloadedRes = await reputationEngine.checkReputation("http://malware.test/payload.exe");
    assert.strictEqual(unloadedRes.status, "REPUTATION_UNAVAILABLE", "Unloaded database must yield UNAVAILABLE");

    // Load malformed database
    const corruptLoaded = localThreatDb.loadDatabase({ invalid: "not a valid schema" });
    assert.strictEqual(corruptLoaded, false, "Malformed schema must fail validation");
    assert.strictEqual(localThreatDb.isReady(), false);

    const corruptRes = await reputationEngine.checkReputation("http://malware.test/payload.exe");
    assert.strictEqual(corruptRes.status, "REPUTATION_UNAVAILABLE", "Corrupted database must yield UNAVAILABLE");

    // Restore standard fixture database
    const raw = JSON.parse(fs.readFileSync(path.join(__dirname, '../src/data/bundled-threat-db.json'), 'utf8'));
    localThreatDb.loadDatabase(raw);
  });

  // Test 12: Reputation Disabled Opt-in handling
  await asyncTest("12. Disabled reputation returns REPUTATION_NOT_ENABLED", async () => {
    global.chrome.storage.local.get = (keys, cb) => cb({ reputationEnabled: false });

    const disabledRes = await reputationEngine.checkReputation("http://malware.test/payload.exe");
    assert.strictEqual(disabledRes.status, "REPUTATION_NOT_ENABLED");

    // Restore enabled state
    global.chrome.storage.local.get = (keys, cb) => cb({ reputationEnabled: true });
  });

  // Test 13: End-to-end integration with Safety Analyzer
  await asyncTest("13. Safety Analyzer integration labels fixture transparently", async () => {
    const repResult = await reputationEngine.checkReputation("http://malware.test/payload.exe");
    
    const computeEvidence = global.BehindTheLink.safetyAnalyzer.computeSafetyEvidence;
    const safetyResult = computeEvidence(
      "http://malware.test/payload.exe",
      { isShortened: false, isHttps: false, hostname: "malware.test" },
      { signals: [] },
      null,
      null,
      { status: "NO_REDIRECT_OBSERVED" },
      null,
      repResult,
      null
    );

    assert.strictEqual(safetyResult.verdict, "KNOWN_THREAT");
    assert.strictEqual(safetyResult.reputationStatus, "KNOWN_THREAT");
    assert.strictEqual(safetyResult.status, "STRONG_WARNING");
    assert.strictEqual(safetyResult.isFixture, true, "Safety result must flag isFixture as true");

    const repSignal = safetyResult.signals.find(s => s.id === "REPUTATION_CONFIRMED_THREAT");
    assert.ok(repSignal, "Must include REPUTATION_CONFIRMED_THREAT signal");
    assert.strictEqual(repSignal.isFixture, true, "Signal must indicate fixture status");
    assert.ok(repSignal.label.includes("Test fixture"), "Label must indicate test fixture");
    assert.ok(repSignal.detail.includes("Synthetic test fixture"), "Detail must clearly state synthetic test fixture");

    assert.ok(safetyResult.userGuidance, "userGuidance must exist");
    assert.ok(safetyResult.userGuidance.whyText.includes("Synthetic test fixture"), "whyText must indicate synthetic test fixture");
    assert.ok(safetyResult.userGuidance.actionText.includes("Test fixture match"), "actionText must indicate test fixture match");

    // Non-fixture threat must NOT include fixture disclaimers
    const nonFixtureRep = {
      status: "REPUTATION_CONFIRMED_THREAT",
      threatTypes: ["MALWARE"],
      isFixture: false
    };
    const nonFixtureSafety = computeEvidence(
      "http://malware.test/payload.exe",
      { isShortened: false, isHttps: false, hostname: "malware.test" },
      { signals: [] },
      null,
      null,
      { status: "NO_REDIRECT_OBSERVED" },
      null,
      nonFixtureRep,
      null
    );
    assert.strictEqual(nonFixtureSafety.isFixture, false);
    const nonFixSignal = nonFixtureSafety.signals.find(s => s.id === "REPUTATION_CONFIRMED_THREAT");
    assert.strictEqual(nonFixSignal.isFixture, false);
    assert.strictEqual(nonFixSignal.label, "Known threat detected");
    assert.ok(nonFixtureSafety.userGuidance.whyText.includes("flagged as a known threat"));
    assert.ok(!nonFixtureSafety.userGuidance.whyText.includes("fixture"));
  });

  // Test 14: Zero-network invariant verification
  test("14. Zero network activity invariant during all threat checks", () => {
    assert.strictEqual(networkCallCount, 0, "No external network requests must have occurred during any test");
  });

  console.log(`\nLocal Threat DB Results: ${passed}/${total} passed`);
  if (passed !== total) {
    process.exitCode = 1;
  }
}

runTestSuite().catch(e => {
  console.error("Test execution failed:", e);
  process.exitCode = 1;
});
