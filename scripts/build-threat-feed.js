/**
 * BehindTheLink — Threat Feed Compiler
 *
 * Compiles URL threat records (from a CSV fixture or URLhaus export)
 * into a compact, sorted, deterministic JSON threat database for local matching.
 *
 * Uses the exact canonicalization, expression-generation, and SHA-256 hashing
 * rules used by BehindTheLink at runtime.
 */

const fs = require('fs');
const path = require('path');
const { parseAndCanonicalize } = require('../src/shared/reputation/canonicalization.js');
const { generateExpressions } = require('../src/shared/reputation/expression-generator.js');
const { computeHash, toHex } = require('../src/shared/reputation/hash-utils.js');

const DEFAULT_INPUT = path.join(__dirname, '../data/fixtures/sample-threat-fixtures.csv');
const DEFAULT_OUTPUT = path.join(__dirname, '../src/data/bundled-threat-db.json');

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    input: DEFAULT_INPUT,
    output: DEFAULT_OUTPUT,
    download: false
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--input' && args[i + 1]) {
      options.input = path.resolve(args[++i]);
    } else if (args[i] === '--output' && args[i + 1]) {
      options.output = path.resolve(args[++i]);
    } else if (args[i] === '--download') {
      options.download = true;
    }
  }

  return options;
}

function parseCsvLine(line) {
  // Simple CSV parser supporting standard unquoted or quoted URLhaus columns:
  // id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
  const parts = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      parts.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current.trim());
  return parts;
}

async function buildThreatFeed(inputPath, outputPath) {
  if (!fs.existsSync(inputPath)) {
    throw new Error(`Input file does not exist: ${inputPath}`);
  }

  const content = fs.readFileSync(inputPath, 'utf8');
  const lines = content.split(/\r?\n/);

  let isFixture = false;
  let parsedUrlCount = 0;
  const threatEntries = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith('#')) {
      if (trimmed.toLowerCase().includes('fixture') || trimmed.toLowerCase().includes('synthetic')) {
        isFixture = true;
      }
      continue;
    }

    const cols = parseCsvLine(trimmed);
    if (cols.length < 4) continue;

    const url = cols[2];
    const status = cols[3];
    const threatRaw = cols[5] || 'malware_download';

    // Only process online malware indicators
    if (status !== 'online') {
      continue;
    }

    const threatType = (threatRaw.toLowerCase().includes('malware') || threatRaw === 'malware_download')
      ? 'MALWARE'
      : (threatRaw.toLowerCase().includes('phish') ? 'SOCIAL_ENGINEERING' : 'UNWANTED_SOFTWARE');

    threatEntries.push({ url, threatType });
    parsedUrlCount++;
  }

  // Generate canonical expressions and SHA-256 hashes
  const hashesMap = new Map();

  for (const entry of threatEntries) {
    try {
      const canonicalObj = parseAndCanonicalize(entry.url);
      const { host, path: urlPath, query } = canonicalObj;
      const targetExpressions = [];

      // Threat feed records define specific threat endpoints.
      // If a query string is present in the feed, index the exact path + query.
      // If no query string is present, index the exact path.
      if (query) {
        targetExpressions.push(host + urlPath + query);
      } else {
        targetExpressions.push(host + urlPath);
      }

      for (const expr of targetExpressions) {
        const hashBytes = await computeHash(expr);
        const hashHex = toHex(hashBytes);

        if (!hashesMap.has(hashHex)) {
          hashesMap.set(hashHex, new Set());
        }
        hashesMap.get(hashHex).add(entry.threatType);
      }
    } catch (e) {
      console.warn(`[WARN] Skipping malformed URL in feed: ${entry.url} (${e.message})`);
    }
  }

  // Sort hashes deterministically
  const sortedHashes = Array.from(hashesMap.keys()).sort();
  const sortedRecordMap = {};

  for (const h of sortedHashes) {
    sortedRecordMap[h] = {
      threatTypes: Array.from(hashesMap.get(h)).sort()
    };
  }

  const database = {
    formatVersion: 1,
    source: isFixture ? 'OFFLINE_SYNTHETIC_FIXTURE' : 'URLHAUS_DATASET',
    isFixture: isFixture,
    description: isFixture
      ? 'Deterministic offline test fixture dataset for BehindTheLink Phase 2A local threat matching. Contains synthetic safe test URLs only; not live URLhaus threat intelligence.'
      : 'Compiled local threat database generated from URLhaus verified malware indicators.',
    generatedAt: new Date().toISOString(),
    sourceUrlCount: parsedUrlCount,
    uniqueHashCount: sortedHashes.length,
    hashes: sortedRecordMap
  };

  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  fs.writeFileSync(outputPath, JSON.stringify(database, null, 2), 'utf8');

  console.log(`[OK] Successfully compiled threat database:`);
  console.log(`     Input:             ${inputPath}`);
  console.log(`     Output:            ${outputPath}`);
  console.log(`     Is Fixture:        ${database.isFixture}`);
  console.log(`     Source URLs:       ${database.sourceUrlCount}`);
  console.log(`     Unique Hashes:     ${database.uniqueHashCount}`);
  console.log(`     File Size:         ${fs.statSync(outputPath).size} bytes`);

  return database;
}

if (require.main === module) {
  const options = parseArgs();
  if (options.download) {
    console.error(`[ERROR] Live feed download requires an Auth-Key from https://auth.abuse.ch/ (URLHAUS_AUTH_KEY).`);
    console.error(`        In Phase 2A, live downloads are disabled. Use offline fixtures (--input <file.csv>).`);
    process.exit(1);
  }

  buildThreatFeed(options.input, options.output).catch(err => {
    console.error(`[FATAL] Threat compilation failed:`, err);
    process.exit(1);
  });
}

module.exports = {
  buildThreatFeed,
  parseCsvLine
};
