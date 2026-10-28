/**
 * BehindTheLink — Dataset Scaling Benchmark
 *
 * Measures compile time, output database size, load/parse latency,
 * memory consumption, and lookup throughput across synthetic datasets
 * of increasing sizes (100 to 50,000 records).
 *
 * All URLs strictly use reserved RFC 2606 special-use domains (.test)
 * to ensure 100% offline and deterministic benchmarking.
 */

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { buildThreatFeed } = require('./build-threat-feed.js');
const localThreatDb = require('../src/shared/reputation/local-threat-db.js');
const { computeHash, toHex } = require('../src/shared/reputation/hash-utils.js');
const { parseAndCanonicalize } = require('../src/shared/reputation/canonicalization.js');

const SCRATCH_DIR = path.join(__dirname, '../scratch/benchmark');

function ensureScratchDir() {
  if (!fs.existsSync(SCRATCH_DIR)) {
    fs.mkdirSync(SCRATCH_DIR, { recursive: true });
  }
}

/**
 * Generates synthetic CSV data using RFC 2606 reserved domains (.test).
 */
function generateSyntheticCsv(recordCount) {
  const lines = [
    '# BehindTheLink Synthetic Scaling Benchmark Fixture',
    '# All domains use RFC 2606 reserved .test TLD',
    '# Fields: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter'
  ];

  const threatTypes = ['malware_download', 'trojan', 'credential_harvesting', 'pup_installer', 'botnet_c2'];

  for (let i = 1; i <= recordCount; i++) {
    const domainNum = Math.floor(i / 10) + 1;
    const pathNum = i % 10;
    const threat = threatTypes[i % threatTypes.length];
    
    // Mix paths, queries, and ports realistically
    let url;
    if (i % 5 === 0) {
      url = `http://sub-${domainNum}.malware-gate.test/download.php?aff=${pathNum}&id=${i}`;
    } else if (i % 7 === 0) {
      url = `http://port-server-${domainNum}.test:8080/drop-${pathNum}.bin`;
    } else {
      url = `http://host-${domainNum}.threat.test/path-${pathNum}/payload-${i}.exe`;
    }

    lines.push(`${i},2026-10-28 00:00:00,${url},online,2026-10-28 00:00:00,${threat},exe,https://urlhaus.abuse.ch/,benchmark`);
  }

  return lines.join('\n');
}

async function runBenchmark() {
  ensureScratchDir();
  console.log("=== BEHINDTHELINK DATASET SCALING BENCHMARK ===");
  console.log("Testing synthetic datasets: 100, 1,000, 5,000, 10,000, 25,000, 50,000 records.\n");

  const sizes = [100, 1000, 5000, 10000, 25000, 50000];
  const results = [];

  for (const size of sizes) {
    process.stdout.write(`Benchmarking dataset size ${size.toLocaleString()}... `);
    const csvContent = generateSyntheticCsv(size);
    const csvPath = path.join(SCRATCH_DIR, `synthetic-${size}.csv`);
    const jsonPath = path.join(SCRATCH_DIR, `compiled-${size}.json`);

    fs.writeFileSync(csvPath, csvContent, 'utf8');
    const csvSizeBytes = fs.statSync(csvPath).size;

    // 1. Measure Compilation Time
    const buildStart = performance.now();
    const compiledDb = await buildThreatFeed(csvPath, jsonPath, { quiet: true });
    const buildDurationMs = performance.now() - buildStart;

    const jsonSizeBytes = fs.statSync(jsonPath).size;
    const jsonSizeKb = (jsonSizeBytes / 1024).toFixed(1);
    const jsonSizeMb = (jsonSizeBytes / (1024 * 1024)).toFixed(2);

    // 2. Measure Cold Load & Parse Time
    if (global.gc) global.gc();
    const heapBefore = process.memoryUsage().heapUsed;

    const loadStart = performance.now();
    const rawJsonText = fs.readFileSync(jsonPath, 'utf8');
    const parsedObj = JSON.parse(rawJsonText);
    localThreatDb.loadDatabase(parsedObj);
    const loadDurationMs = performance.now() - loadStart;

    const heapAfter = process.memoryUsage().heapUsed;
    const heapDiffMb = Math.max(0, (heapAfter - heapBefore) / (1024 * 1024)).toFixed(2);

    // 3. Measure Lookup Performance (1,000 lookups against the compiled DB)
    // Pick 500 existing hashes and 500 non-existent hashes
    const existingHashes = Object.keys(compiledDb.hashes);
    const testHashes = [];
    for (let i = 0; i < 500; i++) {
      testHashes.push(existingHashes[i % existingHashes.length]);
      testHashes.push(`00000000000000000000000000000000000000000000000000000000${String(i).padStart(8, '0')}`);
    }

    const lookupStart = performance.now();
    for (let i = 0; i < testHashes.length; i++) {
      localThreatDb.lookupHash(testHashes[i]);
    }
    const totalLookupDurationMs = performance.now() - lookupStart;
    const avgLookupUs = ((totalLookupDurationMs / testHashes.length) * 1000).toFixed(2);
    const lookupsPerSec = Math.round((testHashes.length / totalLookupDurationMs) * 1000);

    // Clean up temporary files
    if (fs.existsSync(csvPath)) fs.unlinkSync(csvPath);
    if (fs.existsSync(jsonPath)) fs.unlinkSync(jsonPath);

    results.push({
      records: size,
      uniqueHashes: compiledDb.uniqueHashCount,
      csvSizeKb: (csvSizeBytes / 1024).toFixed(1),
      jsonSizeMb: jsonSizeMb,
      jsonSizeKb: jsonSizeKb,
      buildTimeMs: Math.round(buildDurationMs),
      loadTimeMs: loadDurationMs.toFixed(1),
      heapMb: heapDiffMb,
      avgLookupUs: avgLookupUs,
      lookupsPerSec: lookupsPerSec.toLocaleString()
    });

    console.log(`Done. (Build: ${Math.round(buildDurationMs)}ms, Size: ${jsonSizeMb}MB, Load: ${loadDurationMs.toFixed(1)}ms)`);
  }

  // Print results table
  console.log("\n### MEASURED PERFORMANCE BENCHMARK RESULTS\n");
  console.log("| Dataset Size | Unique Hashes | Compiled JSON Size | Build Time | Cold Parse & Load | In-Memory Heap | Avg Lookup Latency | Throughput |");
  console.log("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |");
  for (const r of results) {
    console.log(`| ${r.records.toLocaleString()} URLs | ${r.uniqueHashes.toLocaleString()} hashes | ${r.jsonSizeMb} MB (${r.jsonSizeKb} KB) | ${r.buildTimeMs} ms | ${r.loadTimeMs} ms | ~${r.heapMb} MB | ${r.avgLookupUs} µs | ${r.lookupsPerSec} lookups/sec |`);
  }

  console.log("\nBenchmark complete.");
  return results;
}

if (require.main === module) {
  runBenchmark().catch(err => {
    console.error("Benchmark failed:", err);
    process.exit(1);
  });
}

module.exports = {
  runBenchmark
};
