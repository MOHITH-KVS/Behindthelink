/**
 * BehindTheLink — Threat Feed Compiler Test Suite
 *
 * Deterministic offline tests covering:
 * - RFC 4180 CSV parser edge cases (quoted fields, commas inside quotes, escaped quotes, multiline).
 * - Comments and header detection.
 * - Malformed row and invalid URL rejection.
 * - Threat category normalization and unsupported category rejection.
 * - Deterministic deduplication and sorted output.
 * - Fixture transparency and safety disclaimers.
 * - Exact SHA-256 runtime/build-time consistency.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

const {
  buildThreatFeed,
  parseCsvText,
  parseCsvLine,
  normalizeThreatCategory,
  isValidThreatUrl,
  isSyntheticFixture
} = require('../scripts/build-threat-feed.js');

const { parseAndCanonicalize } = require('../src/shared/reputation/canonicalization.js');
const { generateExpressions } = require('../src/shared/reputation/expression-generator.js');
const { computeHash, toHex } = require('../src/shared/reputation/hash-utils.js');
const localThreatDb = require('../src/shared/reputation/local-threat-db.js');

async function runCompilerTestSuite() {
  console.log("=== THREAT FEED COMPILER & CSV INGESTION TESTS ===");
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

  // Test 1: RFC 4180 parsing — Quoted fields with internal commas
  test("1. CSV: Quoted fields with internal commas", () => {
    const csv = '1,2026-10-28,"http://malware.test/path,with,commas",online,2026-10-28,malware_download,tag1,link,rep';
    const { rows, malformedCount } = parseCsvText(csv);
    assert.strictEqual(malformedCount, 0);
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(rows[0].fields.length, 9);
    assert.strictEqual(rows[0].fields[2], 'http://malware.test/path,with,commas');
    assert.strictEqual(rows[0].fields[3], 'online');
  });

  // Test 2: RFC 4180 parsing — Escaped double quotes ("")
  test("2. CSV: Escaped double quotes inside quoted fields", () => {
    const csv = '1,2026-10-28,"http://malware.test/download.php?name=""trojan""",online,2026-10-28,malware_download,exe,link,rep';
    const { rows, malformedCount } = parseCsvText(csv);
    assert.strictEqual(malformedCount, 0);
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(rows[0].fields[2], 'http://malware.test/download.php?name="trojan"');
  });

  // Test 3: RFC 4180 parsing — Multiline quoted fields
  test("3. CSV: Multiline quoted field handling", () => {
    const csv = '1,2026-10-28,"http://malware.test/multiline\npath\nsegment",online,2026-10-28,malware_download,exe,link,rep\n2,2026-10-28,http://malware.test/second,online,2026-10-28,malware_download,exe,link,rep';
    const { rows, malformedCount } = parseCsvText(csv);
    assert.strictEqual(malformedCount, 0);
    assert.strictEqual(rows.length, 2);
    assert.strictEqual(rows[0].fields[2], 'http://malware.test/multiline\npath\nsegment');
    assert.strictEqual(rows[1].fields[2], 'http://malware.test/second');
  });

  // Test 4: Comments and header mapping
  test("4. CSV: Comments and comment-based headers (# Fields: ...)", () => {
    const csv = [
      '# URLhaus Database Export',
      '# Fields: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter',
      '1,2026-10-28,http://malware.test/one.exe,online,2026-10-28,malware_download,exe,link,rep',
      '# Interspersed comment line',
      '2,2026-10-28,http://malware.test/two.exe,online,2026-10-28,malware_download,exe,link,rep'
    ].join('\n');

    const { rows, malformedCount } = parseCsvText(csv);
    assert.strictEqual(malformedCount, 0);
    const dataRows = rows.filter(r => r.type === 'data');
    const commentRows = rows.filter(r => r.type === 'comment');
    assert.strictEqual(dataRows.length, 2);
    assert.strictEqual(commentRows.length, 3);
  });

  // Test 5: Category normalization
  test("5. Category normalization: maps realistic threat strings to supported categories", () => {
    assert.strictEqual(normalizeThreatCategory('malware_download'), 'MALWARE');
    assert.strictEqual(normalizeThreatCategory('trojan'), 'MALWARE');
    assert.strictEqual(normalizeThreatCategory('botnet_c2'), 'MALWARE');
    assert.strictEqual(normalizeThreatCategory('ransomware_payload'), 'MALWARE');
    assert.strictEqual(normalizeThreatCategory('infostealer'), 'MALWARE');

    assert.strictEqual(normalizeThreatCategory('phishing'), 'SOCIAL_ENGINEERING');
    assert.strictEqual(normalizeThreatCategory('credential_harvesting'), 'SOCIAL_ENGINEERING');
    assert.strictEqual(normalizeThreatCategory('social_engineering_page'), 'SOCIAL_ENGINEERING');

    assert.strictEqual(normalizeThreatCategory('adware'), 'UNWANTED_SOFTWARE');
    assert.strictEqual(normalizeThreatCategory('pup_installer'), 'UNWANTED_SOFTWARE');
    assert.strictEqual(normalizeThreatCategory('pua'), 'UNWANTED_SOFTWARE');

    // Tag fallback
    assert.strictEqual(normalizeThreatCategory('download', 'redline_stealer'), 'MALWARE');
    assert.strictEqual(normalizeThreatCategory('landing_page', 'phishing_kit'), 'SOCIAL_ENGINEERING');

    // Unsupported
    assert.strictEqual(normalizeThreatCategory('unknown_noise_xyz'), null);
    assert.strictEqual(normalizeThreatCategory('benign_page'), null);
  });

  // Test 6: URL format validation
  test("6. URL format validation: accepts valid HTTP(S) and rejects malformed strings", () => {
    assert.strictEqual(isValidThreatUrl('http://malware.test/payload.exe'), true);
    assert.strictEqual(isValidThreatUrl('https://malware.test/gate.php?aff=1'), true);
    assert.strictEqual(isValidThreatUrl('http://192.168.1.100:8080/drop.bin'), true);

    assert.strictEqual(isValidThreatUrl(''), false);
    assert.strictEqual(isValidThreatUrl('not_a_url_at_all'), false);
    assert.strictEqual(isValidThreatUrl('ftp://unsupported-scheme.test/file'), false);
    assert.strictEqual(isValidThreatUrl('javascript:alert(1)'), false);
  });

  // Test 7: End-to-end compilation with edge cases, deduplication, and summary reporting
  await asyncTest("7. End-to-end compilation with edge cases and statistics", async () => {
    const scratchDir = path.join(__dirname, '../scratch');
    if (!fs.existsSync(scratchDir)) fs.mkdirSync(scratchDir, { recursive: true });

    const fixtureContent = [
      '# Synthetic Threat Feed Test Dataset',
      '# Fields: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter',
      '1,2026-10-28,http://malware.test/payload.exe,online,2026-10-28,malware_download,exe,link,rep',
      '2,2026-10-28,http://malware.test/payload.exe,online,2026-10-28,trojan,exe,link,rep2', // Duplicate URL with different threat
      '3,2026-10-28,http://offline.test/dead.exe,offline,2026-10-28,malware_download,exe,link,rep', // Offline URL (must reject)
      '4,2026-10-28,http://phish.test/login.html,online,2026-10-28,credential_harvesting,phish,link,rep', // Social engineering
      '5,2026-10-28,http://adware.test/bundle.dmg,online,2026-10-28,pup_installer,adware,link,rep', // Unwanted software
      '6,2026-10-28,invalid_url_string,online,2026-10-28,malware_download,exe,link,rep', // Malformed URL (must reject)
      '7,2026-10-28,http://unsupported.test/file,online,2026-10-28,unknown_exotic_category,none,link,rep', // Unsupported category (must reject)
      '8,2026-10-28,"http://malware.test/quoted,comma/test.exe",online,2026-10-28,malware_download,exe,link,rep', // Quoted comma
      '9,too_few_columns' // Malformed row (must reject)
    ].join('\n');

    const testCsvPath = path.join(scratchDir, 'test-compiler-edgecases.csv');
    const testJsonPath = path.join(scratchDir, 'test-compiled-output.json');
    fs.writeFileSync(testCsvPath, fixtureContent, 'utf8');

    const result = await buildThreatFeed(testCsvPath, testJsonPath, { quiet: true });

    // Validate summary metrics
    const summary = result.summary;
    assert.strictEqual(summary.totalRows, 9, "9 total data rows (5 accepted + 4 rejected)");
    assert.strictEqual(summary.acceptedRecords, 5, "5 valid online records accepted");
    assert.strictEqual(summary.duplicateRecords, 1, "1 duplicate URL merged");
    assert.strictEqual(summary.rejectedStatusNotOnline, 1, "1 offline record rejected");
    assert.strictEqual(summary.rejectedInvalidUrl, 1, "1 invalid URL rejected");
    assert.strictEqual(summary.rejectedUnsupportedThreat, 1, "1 unsupported category rejected");
    assert.strictEqual(summary.rejectedMalformedRow, 1, "1 malformed row rejected");

    // Validate merged threat types on duplicate URL
    const canonicalPayload = parseAndCanonicalize('http://malware.test/payload.exe');
    const hashBytes = await computeHash(canonicalPayload.host + canonicalPayload.path);
    const hashHex = toHex(hashBytes);

    assert.ok(result.hashes[hashHex], "Hash must exist in compiled database");
    assert.deepStrictEqual(result.hashes[hashHex].threatTypes, ['MALWARE'], "Duplicate malware threat consolidated");

    // Validate isFixture transparency
    assert.strictEqual(result.isFixture, true, "Dataset using .test domains must be marked isFixture: true");
    assert.strictEqual(result.source, 'OFFLINE_SYNTHETIC_FIXTURE');
    assert.ok(result.absenceDisclaimer.includes('does not guarantee safety'), "Absence disclaimer must be present");

    // Validate database loads cleanly in localThreatDb
    const loaded = localThreatDb.loadDatabase(result);
    assert.strictEqual(loaded, true, "Compiled database must load cleanly in localThreatDb");
    assert.strictEqual(localThreatDb.isReady(), true);

    // Clean up scratch files
    if (fs.existsSync(testCsvPath)) fs.unlinkSync(testCsvPath);
    if (fs.existsSync(testJsonPath)) fs.unlinkSync(testJsonPath);
  });

  // Test 8: Deterministic sorting guarantee
  await asyncTest("8. Deterministic compiler output across multiple runs", async () => {
    const scratchDir = path.join(__dirname, '../scratch');
    const fixtureCsv = path.join(__dirname, '../data/fixtures/sample-threat-fixtures.csv');
    const out1 = path.join(scratchDir, 'det-out-1.json');
    const out2 = path.join(scratchDir, 'det-out-2.json');

    const res1 = await buildThreatFeed(fixtureCsv, out1, { quiet: true });
    const res2 = await buildThreatFeed(fixtureCsv, out2, { quiet: true });

    const hashes1 = Object.keys(res1.hashes);
    const hashes2 = Object.keys(res2.hashes);

    // Verify hashes are alphabetically sorted
    const sortedCopy = [...hashes1].sort();
    assert.deepStrictEqual(hashes1, sortedCopy, "Hashes must be sorted alphabetically");
    assert.deepStrictEqual(hashes1, hashes2, "Two compilation runs must produce identical hash orders");

    // Clean up
    if (fs.existsSync(out1)) fs.unlinkSync(out1);
    if (fs.existsSync(out2)) fs.unlinkSync(out2);
  });

  // Test 9: Exact SHA-256 runtime/build-time consistency
  await asyncTest("9. Runtime and build-time SHA-256 hashes are identical", async () => {
    const testUrl = "http://malware.test/payload.exe";

    // Build-time expression & hash
    const canonical = parseAndCanonicalize(testUrl);
    const buildExpr = canonical.host + canonical.path;
    const buildHash = toHex(await computeHash(buildExpr));

    // Runtime expressions & hashes
    const runtimeExprs = generateExpressions(canonical);
    assert.ok(runtimeExprs.includes(buildExpr), "Runtime expression generator must include exact build expression");

    const runtimeHashes = [];
    for (const expr of runtimeExprs) {
      runtimeHashes.push(toHex(await computeHash(expr)));
    }
    assert.ok(runtimeHashes.includes(buildHash), "Runtime hash list must contain exact build hash");
  });

  console.log(`\nThreat Feed Compiler Results: ${passed}/${total} passed`);
  if (passed !== total) process.exitCode = 1;
}

runCompilerTestSuite().catch(e => {
  console.error("Test execution failed:", e);
  process.exitCode = 1;
});
