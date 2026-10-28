/**
 * BehindTheLink — Threat Feed Compiler
 *
 * Compiles URL threat records (from an offline CSV fixture or URLhaus export)
 * into a compact, sorted, deterministic JSON threat database for local matching.
 *
 * Uses the exact canonicalization, expression-generation, and SHA-256 hashing
 * rules used by BehindTheLink at runtime.
 *
 * Guarantees:
 * 1. 100% offline: zero external network requests during compilation.
 * 2. Robust RFC 4180 parsing: handles quotes, commas inside quotes, escaped quotes,
 *    multiline fields, comments, and headers.
 * 3. Transparent categorization: validates URLs, normalizes threat types, rejects malformed
 *    records, and strictly separates synthetic test fixtures from live threat feeds.
 * 4. Exact full SHA-256 matching: ensures build-time and runtime hashes are identical.
 * 5. Safety disclaimer: absence from the database never implies a guarantee of safety.
 */

const fs = require('fs');
const path = require('path');
const { parseAndCanonicalize } = require('../src/shared/reputation/canonicalization.js');
const { computeHash, toHex } = require('../src/shared/reputation/hash-utils.js');

const DEFAULT_INPUT = path.join(__dirname, '../data/fixtures/sample-threat-fixtures.csv');
const DEFAULT_OUTPUT = path.join(__dirname, '../src/data/bundled-threat-db.json');

const SUPPORTED_THREATS = new Set(['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE']);
const RESERVED_TEST_TLDS = new Set(['test', 'example', 'invalid', 'localhost']);
const RESERVED_TEST_HOSTS = new Set(['example.com', 'example.org', 'example.net']);

/**
 * Robust RFC 4180 character-by-character CSV state-machine parser.
 * Handles:
 * - Comments starting with '#'
 * - Quoted fields enclosing commas or newlines
 * - Escaped quotes ("") inside quoted fields
 * - Unquoted fields with trimming
 * - Windows (CRLF), Unix (LF), and legacy Mac (CR) line endings
 */
function parseCsvText(text) {
  const rows = [];
  let currentRow = [];
  let currentField = '';
  let inQuotes = false;
  let isRowStart = true;
  let isCommentRow = false;
  let i = 0;
  const len = text.length;
  let malformedCount = 0;

  while (i < len) {
    const ch = text[i];

    if (isRowStart && !inQuotes) {
      if (ch === '#') {
        isCommentRow = true;
      }
    }

    if (isCommentRow) {
      if (ch === '\n' || ch === '\r') {
        if (ch === '\r' && i + 1 < len && text[i + 1] === '\n') {
          i++;
        }
        rows.push({ type: 'comment', text: currentField.trim() });
        currentField = '';
        isCommentRow = false;
        isRowStart = true;
      } else {
        currentField += ch;
      }
      i++;
      continue;
    }

    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < len && text[i + 1] === '"') {
          // Escaped quote ("")
          currentField += '"';
          i += 2;
          continue;
        } else {
          // End of quoted field
          inQuotes = false;
          i++;
          continue;
        }
      } else {
        currentField += ch;
        i++;
        continue;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
        isRowStart = false;
        i++;
        continue;
      } else if (ch === ',') {
        currentRow.push(currentField.trim());
        currentField = '';
        isRowStart = false;
        i++;
        continue;
      } else if (ch === '\r' || ch === '\n') {
        if (ch === '\r' && i + 1 < len && text[i + 1] === '\n') {
          i++;
        }
        currentRow.push(currentField.trim());
        currentField = '';
        if (currentRow.length > 1 || (currentRow.length === 1 && currentRow[0] !== '')) {
          rows.push({ type: 'data', fields: currentRow });
        }
        currentRow = [];
        isRowStart = true;
        i++;
        continue;
      } else {
        currentField += ch;
        isRowStart = false;
        i++;
        continue;
      }
    }
  }

  if (inQuotes) {
    malformedCount++;
    currentRow.push(currentField.trim());
    rows.push({ type: 'malformed', fields: currentRow, error: 'Unterminated quote at EOF' });
  } else if (isCommentRow) {
    rows.push({ type: 'comment', text: currentField.trim() });
  } else if (currentRow.length > 0 || currentField.length > 0) {
    currentRow.push(currentField.trim());
    if (currentRow.length > 1 || (currentRow.length === 1 && currentRow[0] !== '')) {
      rows.push({ type: 'data', fields: currentRow });
    }
  }

  return { rows, malformedCount };
}

/**
 * Backward-compatible single line parser.
 */
function parseCsvLine(line) {
  const result = parseCsvText(line);
  if (result.rows.length > 0 && result.rows[0].fields) {
    return result.rows[0].fields;
  }
  return [];
}

/**
 * Normalizes threat categories into BehindTheLink supported types:
 * - MALWARE
 * - SOCIAL_ENGINEERING
 * - UNWANTED_SOFTWARE
 * Returns null if the category is unsupported.
 */
function normalizeThreatCategory(rawThreat, rawTags = '') {
  const threatStr = (rawThreat || '').toLowerCase().trim();
  const tagsStr = (rawTags || '').toLowerCase().trim();
  const combined = threatStr + ' ' + tagsStr;

  // 1. Phishing / Social Engineering
  if (
    combined.includes('phish') ||
    combined.includes('credential') ||
    combined.includes('social_engineering') ||
    combined.includes('scam') ||
    combined.includes('spoof')
  ) {
    return 'SOCIAL_ENGINEERING';
  }

  // 2. Unwanted Software / Adware / PUP
  if (
    combined.includes('adware') ||
    combined.includes('pup') ||
    combined.includes('pua') ||
    combined.includes('unwanted') ||
    combined.includes('riskware') ||
    combined.includes('spyware') ||
    combined.includes('bundle')
  ) {
    return 'UNWANTED_SOFTWARE';
  }

  // 3. Malware (executables, trojans, C2, botnets, downloaders, etc.)
  if (
    combined.includes('malware') ||
    combined.includes('trojan') ||
    combined.includes('botnet') ||
    combined.includes('c2') ||
    combined.includes('ransomware') ||
    combined.includes('backdoor') ||
    combined.includes('stealer') ||
    combined.includes('miner') ||
    combined.includes('dropper') ||
    combined.includes('virus') ||
    combined.includes('rootkit') ||
    combined.includes('infostealer') ||
    combined.includes('exploit') ||
    combined.includes('rat') ||
    combined.includes('worm') ||
    combined.includes('loader') ||
    combined.includes('payload')
  ) {
    return 'MALWARE';
  }

  return null;
}

/**
 * Validates that a candidate string is a parseable HTTP(S) URL.
 */
function isValidThreatUrl(urlStr) {
  if (typeof urlStr !== 'string' || !urlStr.trim()) {
    return false;
  }
  const trimmed = urlStr.trim();
  // Threat feeds must explicitly provide http:// or https:// URLs
  if (!/^https?:\/\//i.test(trimmed)) {
    return false;
  }
  try {
    const u = new URL(trimmed);
    const host = u.hostname;
    if (!host || host.length < 3) {
      return false;
    }
    // Hostname must contain at least one dot or be localhost / valid IP
    if (!host.includes('.') && host !== 'localhost') {
      return false;
    }
    const canonical = parseAndCanonicalize(trimmed);
    if (!canonical || !canonical.host) {
      return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Inspects content comments and records to determine if dataset is a synthetic fixture.
 */
function isSyntheticFixture(content, records) {
  const lowerContent = content.toLowerCase();
  if (
    lowerContent.includes('# fixture') ||
    lowerContent.includes('# synthetic') ||
    lowerContent.includes('# test fixture') ||
    lowerContent.includes('rfc 2606')
  ) {
    return true;
  }

  for (const r of records) {
    try {
      const u = new URL(r.url);
      const host = u.hostname.toLowerCase();
      const parts = host.split('.');
      const tld = parts[parts.length - 1];
      if (RESERVED_TEST_TLDS.has(tld) || RESERVED_TEST_HOSTS.has(host)) {
        return true;
      }
    } catch (e) {}
  }

  return false;
}

/**
 * Extracts column index mapping from headers or comments.
 */
function resolveColumnIndices(rows) {
  // Check comments for "# Fields: id,dateadded,url,..."
  for (const row of rows) {
    if (row.type === 'comment') {
      const match = row.text.match(/^#?\s*fields:\s*(.+)$/i);
      if (match) {
        const headerNames = match[1].split(',').map(s => s.trim().toLowerCase());
        return {
          url: headerNames.indexOf('url'),
          status: headerNames.indexOf('url_status'),
          threat: headerNames.indexOf('threat'),
          tags: headerNames.indexOf('tags'),
          headerRowFound: false
        };
      }
    }
  }

  // Check first data row for standard header names
  if (rows.length > 0) {
    const firstData = rows.find(r => r.type === 'data');
    if (firstData && firstData.fields) {
      const lowerFields = firstData.fields.map(f => f.toLowerCase());
      const uIdx = lowerFields.indexOf('url');
      if (uIdx !== -1) {
        return {
          url: uIdx,
          status: lowerFields.indexOf('url_status'),
          threat: lowerFields.indexOf('threat'),
          tags: lowerFields.indexOf('tags'),
          headerRowFound: true
        };
      }
    }
  }

  // Fallback to URLhaus standard positions
  return {
    url: 2,
    status: 3,
    threat: 5,
    tags: 6,
    headerRowFound: false
  };
}

async function buildThreatFeed(inputPath, outputPath, options = {}) {
  if (!fs.existsSync(inputPath)) {
    throw new Error(`Input file does not exist: ${inputPath}`);
  }

  const content = fs.readFileSync(inputPath, 'utf8');
  const { rows, malformedCount } = parseCsvText(content);
  const colIndices = resolveColumnIndices(rows);

  const summary = {
    totalRows: 0,
    acceptedRecords: 0,
    uniqueHashes: 0,
    duplicateRecords: 0,
    rejectedMalformedRow: malformedCount,
    rejectedInvalidUrl: 0,
    rejectedStatusNotOnline: 0,
    rejectedUnsupportedThreat: 0
  };

  const threatEntries = [];
  const seenUrls = new Set();
  let isFirstDataRow = true;

  for (const row of rows) {
    if (row.type === 'comment') {
      continue;
    }

    if (row.type === 'malformed') {
      continue;
    }

    summary.totalRows++;

    // Skip header row if identified
    if (isFirstDataRow && colIndices.headerRowFound) {
      isFirstDataRow = false;
      summary.totalRows--; // Do not count header in data rows
      continue;
    }
    isFirstDataRow = false;

    const cols = row.fields;
    const minCols = Math.max(colIndices.url, colIndices.status, colIndices.threat) + 1;
    if (cols.length < minCols) {
      summary.rejectedMalformedRow++;
      continue;
    }

    const rawUrl = cols[colIndices.url];
    const rawStatus = (colIndices.status !== -1 && cols[colIndices.status]) ? cols[colIndices.status].toLowerCase() : 'online';
    const rawThreat = (colIndices.threat !== -1 && cols[colIndices.threat]) ? cols[colIndices.threat] : 'malware_download';
    const rawTags = (colIndices.tags !== -1 && cols[colIndices.tags]) ? cols[colIndices.tags] : '';

    // 1. Validate status: only compile online indicators
    if (rawStatus !== 'online') {
      summary.rejectedStatusNotOnline++;
      continue;
    }

    // 2. Validate URL format
    if (!isValidThreatUrl(rawUrl)) {
      summary.rejectedInvalidUrl++;
      continue;
    }

    // 3. Normalize and validate threat category
    const threatType = normalizeThreatCategory(rawThreat, rawTags);
    if (!threatType || !SUPPORTED_THREATS.has(threatType)) {
      summary.rejectedUnsupportedThreat++;
      continue;
    }

    // 4. Track duplicate URLs
    if (seenUrls.has(rawUrl)) {
      summary.duplicateRecords++;
    } else {
      seenUrls.add(rawUrl);
    }

    threatEntries.push({ url: rawUrl, threatType });
    summary.acceptedRecords++;
  }

  const isFixture = isSyntheticFixture(content, threatEntries);

  // Generate canonical expressions and SHA-256 hashes
  const hashesMap = new Map();

  for (const entry of threatEntries) {
    try {
      const canonicalObj = parseAndCanonicalize(entry.url);
      const { host, path: urlPath, query } = canonicalObj;
      const targetExpressions = [];

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
      summary.rejectedInvalidUrl++;
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

  summary.uniqueHashes = sortedHashes.length;

  const database = {
    formatVersion: 1,
    source: isFixture ? 'OFFLINE_SYNTHETIC_FIXTURE' : 'URLHAUS_DATASET',
    isFixture: isFixture,
    description: isFixture
      ? 'Deterministic offline test fixture dataset for BehindTheLink Phase 2A/2B local threat matching. Contains synthetic safe test URLs only; not live URLhaus threat intelligence.'
      : 'Compiled local threat database generated from URLhaus verified malware indicators.',
    absenceDisclaimer: 'Absence of a URL from this database does not guarantee safety. The database only contains records of known reported threats at the time of compilation.',
    generatedAt: new Date().toISOString(),
    sourceUrlCount: summary.acceptedRecords,
    uniqueHashCount: summary.uniqueHashes,
    hashes: sortedRecordMap
  };

  database.summary = summary;

  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  fs.writeFileSync(outputPath, JSON.stringify(database, null, 2), 'utf8');

  if (!options.quiet) {
    console.log(`[OK] Successfully compiled threat database:`);
    console.log(`     Input:             ${inputPath}`);
    console.log(`     Output:            ${outputPath}`);
    console.log(`     Is Fixture:        ${database.isFixture}`);
    console.log(`     Accepted Records:  ${summary.acceptedRecords}`);
    console.log(`     Unique Hashes:     ${summary.uniqueHashes}`);
    console.log(`     Duplicates Merged: ${summary.duplicateRecords}`);
    console.log(`     Rejected Malformed:${summary.rejectedMalformedRow}`);
    console.log(`     Rejected Invalid:  ${summary.rejectedInvalidUrl}`);
    console.log(`     Rejected Offline:  ${summary.rejectedStatusNotOnline}`);
    console.log(`     Rejected Unsupp.:  ${summary.rejectedUnsupportedThreat}`);
    console.log(`     File Size:         ${fs.statSync(outputPath).size} bytes`);
  }

  return database;
}

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    input: DEFAULT_INPUT,
    output: DEFAULT_OUTPUT,
    download: false,
    quiet: false
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--input' && args[i + 1]) {
      options.input = path.resolve(args[++i]);
    } else if (args[i] === '--output' && args[i + 1]) {
      options.output = path.resolve(args[++i]);
    } else if (args[i] === '--download') {
      options.download = true;
    } else if (args[i] === '--quiet') {
      options.quiet = true;
    }
  }

  return options;
}

if (require.main === module) {
  const options = parseArgs();
  if (options.download) {
    console.error(`[ERROR] Live feed download requires an Auth-Key from https://auth.abuse.ch/ (URLHAUS_AUTH_KEY).`);
    console.error(`        In Phase 2A/2B offline mode, live downloads are disabled. Use offline fixtures (--input <file.csv>).`);
    process.exit(1);
  }

  buildThreatFeed(options.input, options.output, options).catch(err => {
    console.error(`[FATAL] Threat compilation failed:`, err);
    process.exit(1);
  });
}

module.exports = {
  buildThreatFeed,
  parseCsvText,
  parseCsvLine,
  normalizeThreatCategory,
  isValidThreatUrl,
  isSyntheticFixture
};
