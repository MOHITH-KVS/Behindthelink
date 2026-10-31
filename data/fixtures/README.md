# BehindTheLink — Phase 2A Threat Feed Fixtures & Compilation Guide

## 1. Overview & Dataset Integrity

This directory contains deterministic offline test fixtures used by BehindTheLink for Phase 2A local threat intelligence matching.

> **CRITICAL NOTICE**:
> The entries in `sample-threat-fixtures.csv` are **SYNTHETIC, RESERVED** test fixtures using RFC 2606 / RFC 6761 special-use domains (`.test`).
> - They are used **exclusively for offline deterministic testing and development**.
> - They are **NOT** live malicious URLs.
> - They are **NOT** real-world threat intelligence.
> - They **MUST NEVER** be labeled or represented in documentation or user interfaces as verified live URLhaus intelligence.

## 2. Fixture Dataset Schema

The fixture CSV (`sample-threat-fixtures.csv`) mirrors the standard CSV export schema provided by abuse.ch URLhaus:

| Column | Description | Example |
|---|---|---|
| `id` | Synthetic integer identifier | `1` |
| `dateadded` | Timestamp string (UTC) | `2026-10-26 00:00:00` |
| `url` | Synthetic test URL using `.test` domain | `http://malware.test/payload.exe` |
| `url_status` | Status (`online`, `offline`) — only `online` entries are indexed | `online` |
| `last_online` | Timestamp string of last online activity | `2026-10-26 00:00:00` |
| `threat` | Threat categorization (`malware_download`, etc.) | `malware_download` |
| `tags` | Indicator tags or file extension tags | `exe` |
| `urlhaus_link` | Informational reference link | `https://urlhaus.abuse.ch/` |
| `reporter` | Reporter attribution tag | `fixture` |

Lines starting with `#` are treated as comments. Any line containing the keywords `fixture` or `synthetic` causes the compiler to flag the resulting database with `"isFixture": true`.

## 3. Threat Feed Compilation (`scripts/build-threat-feed.js`)

The compilation script processes threat URLs and produces a sorted, deterministic JSON database of complete 32-byte SHA-256 hashes (`src/data/bundled-threat-db.json`):

```bash
# Build the default bundled fixture database
node scripts/build-threat-feed.js --input data/fixtures/sample-threat-fixtures.csv --output src/data/bundled-threat-db.json
```

### Exact Matching & Canonicalization Pipeline:
1. **Canonicalization**: Matches the exact Google Web Risk / RFC canonicalization used at runtime in `src/shared/reputation/canonicalization.js` (strips tabs/CRLF, strips fragments, unescapes recursive percent-encoding, normalizes hostnames and IPv4/IPv6 addresses, normalizes directory paths, and normalizes ports).
2. **Expression Generation**: Preserves exact path and query targeting (`src/shared/reputation/expression-generator.js`).
3. **Hashing**: Computes complete 32-byte SHA-256 hashes (`src/shared/reputation/hash-utils.js`). Prefix matching is NEVER used alone; the entire 64-character hex hash must match.
4. **Deterministic Sorting**: Hashes are stored in lexicographical order in the output JSON.

## 4. Procedure for Compiling a Future Permitted URLhaus Dataset (Phase 2B)

When live threat feed integration is authorized and access credentials are provided in a future phase:

1. **Obtain Permitted API Access**:
   Register and obtain an `Auth-Key` from abuse.ch (https://auth.abuse.ch/).
2. **Download Verified Threat Export**:
   Download the permitted online URLhaus CSV feed (e.g., recent or full export) via authorized tools or authenticated cURL request:
   ```bash
   curl -H "Auth-Key: YOUR_URLHAUS_AUTH_KEY" https://urlhaus.abuse.ch/downloads/csv_recent/ -o data/urlhaus-recent.csv
   ```
3. **Compile the Threat Database**:
   Run the offline feed compiler on the downloaded CSV:
   ```bash
   node scripts/build-threat-feed.js --input data/urlhaus-recent.csv --output src/data/bundled-threat-db.json
   ```
   The compiler will detect that comments do not contain `fixture`/`synthetic` and will generate a production database with `"isFixture": false`.
4. **Verify Hash Counts and File Budget**:
   Ensure the output JSON fits within Chrome extension packaging limits (typically < 10–15 MB bundled).
5. **Run Offline Test Suites**:
   Execute `node test/run-all.js` to verify that local matching integrity, fail-safe unavailability handling, and zero-network invariants remain intact.
