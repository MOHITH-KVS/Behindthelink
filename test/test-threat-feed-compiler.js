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

  // Test 5: Category normalization & exact tag matching (no substring collisions)
  test("5. Category normalization: maps realistic threat strings and prevents substring collisions", () => {
    // Valid categories
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

    // Discrete tag tokens
    assert.strictEqual(normalizeThreatCategory('download', 'redline_stealer'), 'MALWARE');
    assert.strictEqual(normalizeThreatCategory('landing_page', 'phishing_kit'), 'SOCIAL_ENGINEERING');
    assert.strictEqual(normalizeThreatCategory('installer', 'pup'), 'UNWANTED_SOFTWARE');
    assert.strictEqual(normalizeThreatCategory('payload', 'rat'), 'MALWARE');

    // Fix 3: Substring collision prevention
    // 'popup' must NOT match 'pup'
    assert.strictEqual(normalizeThreatCategory('unknown_category', 'popup'), null);
    // 'corporate', 'accurate', 'pirated' must NOT match 'rat'
    assert.strictEqual(normalizeThreatCategory('unknown_category', 'corporate'), null);
    assert.strictEqual(normalizeThreatCategory('unknown_category', 'accurate'), null);
    assert.strictEqual(normalizeThreatCategory('unknown_category', 'pirated'), null);
    assert.strictEqual(normalizeThreatCategory('unknown_category', 'operating_system'), null);

    // Legitimate trojan with 'popup' tag must remain MALWARE, not UNWANTED_SOFTWARE
    assert.strictEqual(normalizeThreatCategory('trojan', 'popup'), 'MALWARE');

    // Unsupported and empty
    assert.strictEqual(normalizeThreatCategory('unknown_noise_xyz'), null);
    assert.strictEqual(normalizeThreatCategory('benign_page'), null);
    assert.strictEqual(normalizeThreatCategory('', ''), null);
  });

  // Test 6: URL format validation with IPv6 support
  test("6. URL format validation: accepts valid HTTP(S), IPv4, and IPv6 literals while rejecting malformed inputs", () => {
    // Standard domain names
    assert.strictEqual(isValidThreatUrl('http://malware.test/payload.exe'), true);
    assert.strictEqual(isValidThreatUrl('https://malware.test/gate.php?aff=1'), true);

    // Localhost
    assert.strictEqual(isValidThreatUrl('http://localhost/path'), true);
    assert.strictEqual(isValidThreatUrl('http://localhost:8080/test'), true);

    // IPv4 addresses
    assert.strictEqual(isValidThreatUrl('http://192.168.1.100:8080/drop.bin'), true);
    assert.strictEqual(isValidThreatUrl('https://10.0.0.1/malware'), true);

    // Fix 2: Valid IPv6 addresses
    assert.strictEqual(isValidThreatUrl('http://[::1]/'), true);
    assert.strictEqual(isValidThreatUrl('http://[2001:db8::1]/payload.exe'), true);
    assert.strictEqual(isValidThreatUrl('https://[2001:db8::1]:8080/path?q=1'), true);
    assert.strictEqual(isValidThreatUrl('http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/'), true);

    // Fix 2: Malformed IPv6 addresses
    assert.strictEqual(isValidThreatUrl('http://[invalid_ipv6]/path'), false);
    assert.strictEqual(isValidThreatUrl('http://[12345::1]/path'), false);
    assert.strictEqual(isValidThreatUrl('http://[:::1]/path'), false);

    // Fix 2: Invalid bracket syntax
    assert.strictEqual(isValidThreatUrl('http://[2001:db8::1/path'), false);
    assert.strictEqual(isValidThreatUrl('http://[2001:db8::1]]:80/path'), false);
    assert.strictEqual(isValidThreatUrl('http://[[2001:db8::1]]/path'), false);

    // Non-HTTP and invalid strings
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

    const result = await buildThreatFeed(testCsvPath, testJsonPath, { mode: 'fixture', quiet: true });

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

    const res1 = await buildThreatFeed(fixtureCsv, out1, { mode: 'fixture', quiet: true });
    const res2 = await buildThreatFeed(fixtureCsv, out2, { mode: 'fixture', quiet: true });

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

  // Test 10: Fix 1.5 — Missing or invalid build mode throws closed error
  await asyncTest("10. Fix 1.5: Missing or invalid build mode fails closed", async () => {
    const scratchDir = path.join(__dirname, '../scratch');
    const fixtureCsv = path.join(__dirname, '../data/fixtures/sample-threat-fixtures.csv');
    const dummyOut = path.join(scratchDir, 'dummy-out.json');

    // Missing options
    await assert.rejects(
      async () => await buildThreatFeed(fixtureCsv, dummyOut),
      /Build mode must be explicitly specified/
    );

    // Missing mode in options
    await assert.rejects(
      async () => await buildThreatFeed(fixtureCsv, dummyOut, { quiet: true }),
      /Build mode must be explicitly specified/
    );

    // Invalid mode
    await assert.rejects(
      async () => await buildThreatFeed(fixtureCsv, dummyOut, { mode: 'arbitrary_mode' }),
      /Invalid build mode/
    );
  });

  // Test 11: Fix 1.1 — Fixture build containing synthetic records
  await asyncTest("11. Fix 1.1: Fixture build produces isFixture: true and OFFLINE_SYNTHETIC_FIXTURE source", async () => {
    const scratchDir = path.join(__dirname, '../scratch');
    const fixtureCsv = path.join(__dirname, '../data/fixtures/sample-threat-fixtures.csv');
    const out = path.join(scratchDir, 'fix-1-1.json');

    const result = await buildThreatFeed(fixtureCsv, out, { mode: 'fixture', quiet: true });
    assert.strictEqual(result.isFixture, true);
    assert.strictEqual(result.source, 'OFFLINE_SYNTHETIC_FIXTURE');
    assert.ok(result.description.includes('offline test fixture dataset'));

    if (fs.existsSync(out)) fs.unlinkSync(out);
  });

  // Test 12: Fix 1.2 — Production build containing ordinary records
  await asyncTest("12. Fix 1.2: Production build produces isFixture: false and URLHAUS_DATASET source", async () => {
    const scratchDir = path.join(__dirname, '../scratch');
    const prodCsv = path.join(scratchDir, 'prod-ordinary.csv');
    const out = path.join(scratchDir, 'fix-1-2.json');

    const content = [
      '# URLhaus Export',
      '# Fields: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter',
      '1,2026-10-28,http://malicious-active-site.com/payload.exe,online,2026-10-28,malware_download,exe,link,rep'
    ].join('\n');
    fs.writeFileSync(prodCsv, content, 'utf8');

    const result = await buildThreatFeed(prodCsv, out, { mode: 'production', quiet: true });
    assert.strictEqual(result.isFixture, false);
    assert.strictEqual(result.source, 'URLHAUS_DATASET');
    assert.ok(result.description.includes('URLhaus verified malware indicators'));

    if (fs.existsSync(prodCsv)) fs.unlinkSync(prodCsv);
    if (fs.existsSync(out)) fs.unlinkSync(out);
  });

  // Test 13: Fix 1.3 — Production build containing a reserved-domain record remains production
  await asyncTest("13. Fix 1.3: Production build containing a reserved domain remains production (never inverts)", async () => {
    const scratchDir = path.join(__dirname, '../scratch');
    const mixedCsv = path.join(scratchDir, 'prod-with-reserved.csv');
    const out = path.join(scratchDir, 'fix-1-3.json');

    // Contains 1 ordinary record and 1 record targeting .test
    const content = [
      '# URLhaus Export with single test domain submitted',
      '# Fields: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter',
      '1,2026-10-28,http://live-c2-server.org/bot.exe,online,2026-10-28,malware_download,exe,link,rep',
      '2,2026-10-28,http://malware-sample.test/bin.exe,online,2026-10-28,malware_download,exe,link,rep'
    ].join('\n');
    fs.writeFileSync(mixedCsv, content, 'utf8');

    const result = await buildThreatFeed(mixedCsv, out, { mode: 'production', quiet: true });
    assert.strictEqual(result.isFixture, false, "Production build must NOT flip to isFixture: true due to one reserved domain");
    assert.strictEqual(result.source, 'URLHAUS_DATASET');

    if (fs.existsSync(mixedCsv)) fs.unlinkSync(mixedCsv);
    if (fs.existsSync(out)) fs.unlinkSync(out);
  });

  // Test 14: Fix 1.4 — Production feed whose comment contains "fixture" remains production
  await asyncTest("14. Fix 1.4: Production feed with 'fixture' in comment remains production", async () => {
    const scratchDir = path.join(__dirname, '../scratch');
    const commentCsv = path.join(scratchDir, 'prod-comment-fixture.csv');
    const out = path.join(scratchDir, 'fix-1-4.json');

    const content = [
      '# URLhaus Feed - Notes: Automated fixture pipeline run',
      '# Fields: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter',
      '1,2026-10-28,http://real-active-threat.net/trojan.exe,online,2026-10-28,malware_download,exe,link,rep'
    ].join('\n');
    fs.writeFileSync(commentCsv, content, 'utf8');

    const result = await buildThreatFeed(commentCsv, out, { mode: 'production', quiet: true });
    assert.strictEqual(result.isFixture, false, "Production build must NOT flip to isFixture: true due to comment containing 'fixture'");
    assert.strictEqual(result.source, 'URLHAUS_DATASET');

    if (fs.existsSync(commentCsv)) fs.unlinkSync(commentCsv);
    if (fs.existsSync(out)) fs.unlinkSync(out);
  });

  console.log(`\nThreat Feed Compiler Results: ${passed}/${total} passed`);
  if (passed !== total) process.exitCode = 1;
}

runCompilerTestSuite().catch(e => {
  console.error("Test execution failed:", e);
  process.exitCode = 1;
});
