/**
 * Evidence line tests.
 *
 *  1. The reputation engine reports which database answered (source, entry
 *     count, build date, fixture or real).
 *  2. The safety analyzer carries that through to the card.
 *  3. The card shows "Checked against <source> · N entries · updated <date>",
 *     warns when the database is old, shows nothing for fixture data, and
 *     explains private-address destinations.
 */
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

// ---------- Engine environment (module style, like test-local-threat-db.js) ----------
global.self = global;
global.window = global;
global.BehindTheLink = global.BehindTheLink || {};
const canonicalization = require('../src/shared/reputation/canonicalization.js');
const expressionGenerator = require('../src/shared/reputation/expression-generator.js');
const hashUtils = require('../src/shared/reputation/hash-utils.js');
const localThreatDb = require('../src/shared/reputation/local-threat-db.js');
const reputationEngine = require('../src/background/reputation-engine.js');
require('../src/shared/safety-analyzer.js');
global.chrome = { storage: { local: { get: (keys, cb) => cb({ reputationEnabled: true }) } } };

// ---------- Card environment (vm sandbox, like test-trust-fixes.js) ----------
const documentMock = {
  createElement: function (tag) {
    return {
      tagName: tag, className: '', _textContent: '',
      get textContent() {
        if (this.children.length > 0) return this.children.map(c => c.textContent).join('');
        return this._textContent;
      },
      set textContent(v) { this._textContent = v; },
      style: {}, children: [],
      classList: { add: function (c) { this.className += ' ' + c; }, remove: function () {} },
      appendChild: function (child) { this.children.push(child); },
      replaceChildren: function () { this.children = []; },
      setAttribute: function (k, v) { this[k] = v; },
      addEventListener: function () {},
      attachShadow: function () { return this; }
    };
  },
  createTextNode: function (text) { return { textContent: text }; },
  body: { appendChild: function () {} }
};
let UI_BTL = {};
const sandbox = {
  window: Object.assign({ BehindTheLink: UI_BTL }, { innerWidth: 320, innerHeight: 768, requestAnimationFrame: (cb) => cb() }),
  self: { BehindTheLink: UI_BTL }, BTL: UI_BTL, document: documentMock, URL: URL,
  console: { log: () => {}, error: console.error }, Date: Date,
  requestAnimationFrame: (cb) => cb()
};
vm.createContext(sandbox);
[
  './src/shared/constants.js', './src/shared/brand-registry.js', './src/shared/domain-utils.js',
  './src/shared/lookalike-analyzer.js', './src/content/tracking-registry.js', './src/content/shortener-registry.js',
  './src/content/affiliate-registry.js', './src/content/url-analyzer.js', './src/content/context-extractor.js',
  './src/shared/deception-analyzer.js', './src/shared/claim-destination-analyzer.js', './src/shared/safety-analyzer.js',
  './src/shared/assessment-aggregator.js', './src/content/preview-ui.js'
].forEach(m => vm.runInContext(fs.readFileSync(m, 'utf8'), sandbox));
UI_BTL = sandbox.window.BehindTheLink;
UI_BTL.getResolvedUrl = () => 'https://example.com';
const linkMock = { getBoundingClientRect: () => ({ top: 100, left: 100, bottom: 120, right: 200 }) };

function findByClass(el, className, acc) {
  acc = acc || [];
  if (el.className && el.className.split(' ').includes(className)) acc.push(el);
  (el.children || []).forEach(c => findByClass(c, className, acc));
  return acc;
}
function getCard(payload) {
  UI_BTL.previewUI.show(linkMock, payload, false, payload.context);
  return findByClass(UI_BTL.previewUI.getHost(), 'btl-card')[0];
}
function cardFor(reputationSignals, networkEvidence) {
  const net = networkEvidence || { status: 'NO_REDIRECT_OBSERVED' };
  const local = { isShortened: false, isHttps: true, hostname: 'files.example.net' };
  const evidence = UI_BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://files.example.net/app.zip', local, { signals: [] }, null, null, net, null, reputationSignals, null
  );
  return getCard({ originalUrl: 'https://files.example.net/app.zip', localSignals: local, networkEvidence: net, safetyEvidence: evidence });
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString();
const dateText = (iso) => { const d = new Date(iso); return d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()] + ' ' + d.getUTCFullYear(); };
const prodInfo = (iso) => ({ source: 'URLHAUS_DATASET', isFixture: false, generatedAt: iso, entryCount: 12430 });

const queue = [];
const runTest = (name, fn) => queue.push({ name, fn });

// ---------- 1. Engine ----------
const BAD_URL = 'http://evil-download.example.net/payload.exe';
async function buildProductionDb(generatedAt) {
  const exprs = expressionGenerator.generateExpressions(canonicalization.parseAndCanonicalize(BAD_URL));
  const hex = hashUtils.toHex(await hashUtils.computeHash(exprs[0]));
  const hashes = {};
  hashes[hex] = { threatTypes: ['MALWARE'] };
  hashes['a'.repeat(64)] = { threatTypes: ['MALWARE'] };
  hashes['b'.repeat(64)] = { threatTypes: ['SOCIAL_ENGINEERING'] };
  return { formatVersion: 1, source: 'URLHAUS_DATASET', isFixture: false, generatedAt: generatedAt, hashes: hashes };
}

runTest('EV-001: engine reports the database behind a no-match result', async () => {
  localThreatDb.resetDatabase();
  const when = daysAgo(2);
  assert.ok(localThreatDb.loadDatabase(await buildProductionDb(when)));
  const r = await reputationEngine.checkReputation('https://www.wikipedia.org/');
  assert.strictEqual(r.status, 'REPUTATION_NO_MATCH');
  assert.deepStrictEqual(r.dbInfo, { source: 'URLHAUS_DATASET', isFixture: false, generatedAt: when, entryCount: 3 });
});

runTest('EV-002: engine reports the database behind a confirmed threat', async () => {
  localThreatDb.resetDatabase();
  const when = daysAgo(1);
  assert.ok(localThreatDb.loadDatabase(await buildProductionDb(when)));
  const r = await reputationEngine.checkReputation(BAD_URL);
  assert.strictEqual(r.status, 'REPUTATION_CONFIRMED_THREAT');
  assert.strictEqual(r.dbInfo.source, 'URLHAUS_DATASET');
  assert.strictEqual(r.dbInfo.isFixture, false);
  assert.strictEqual(r.dbInfo.entryCount, 3);
});

runTest('EV-003: bundled fixture database is labelled as a fixture', async () => {
  localThreatDb.resetDatabase();
  const raw = JSON.parse(fs.readFileSync('./src/data/bundled-threat-db.json', 'utf8'));
  assert.ok(localThreatDb.loadDatabase(raw));
  const r = await reputationEngine.checkReputation('https://www.wikipedia.org/');
  assert.strictEqual(r.dbInfo.isFixture, true);
  assert.strictEqual(r.dbInfo.source, 'OFFLINE_SYNTHETIC_FIXTURE');
});

// ---------- 2. Analyzer pass-through ----------
runTest('EV-004: safety evidence carries the database facts', () => {
  const info = prodInfo(daysAgo(1));
  const ev = UI_BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://example.com/', { isShortened: false, isHttps: true, hostname: 'example.com' }, { signals: [] }, null, null,
    { status: 'NO_REDIRECT_OBSERVED' }, null, { status: 'REPUTATION_NO_MATCH', isFixture: false, source: info.source, dbInfo: info }, null);
  assert.deepStrictEqual(ev.reputationDb, info);
  assert.strictEqual(ev.reputationStatus, 'NO_KNOWN_THREAT');
});

// ---------- 3. Card ----------
runTest('EV-005: fresh real database shows source, entry count and date', () => {
  const when = daysAgo(2);
  const card = cardFor({ status: 'REPUTATION_NO_MATCH', isFixture: false, source: 'URLHAUS_DATASET', dbInfo: prodInfo(when) });
  const lines = findByClass(card, 'btl-rep-source');
  assert.strictEqual(lines.length, 1);
  assert.strictEqual(lines[0].textContent, 'Checked against URLhaus (abuse.ch) \u00b7 12,430 entries \u00b7 updated ' + dateText(when));
  assert.ok(!lines[0].className.includes('stale'));
});

runTest('EV-006: an old database is flagged with its age', () => {
  const when = daysAgo(20);
  const card = cardFor({ status: 'REPUTATION_NO_MATCH', isFixture: false, source: 'URLHAUS_DATASET', dbInfo: prodInfo(when) });
  const line = findByClass(card, 'btl-rep-source')[0];
  assert.ok(line.textContent.includes('20 days old'), line.textContent);
  assert.ok(line.className.includes('btl-rep-source-stale'));
});

runTest('EV-007: a confirmed threat names the list and says how to verify it', () => {
  const card = cardFor({ status: 'REPUTATION_CONFIRMED_THREAT', isFixture: false, source: 'URLHAUS_DATASET', threatTypes: ['MALWARE'], dbInfo: prodInfo(daysAgo(1)) });
  const text = card.textContent;
  assert.ok(text.includes('Listed in URLhaus (abuse.ch)'));
  assert.ok(text.includes('search this link at urlhaus.abuse.ch'));
  assert.ok(text.includes('Known threat reported'));
  const anchors = [];
  (function walk(el) { if (el.tagName === 'a') anchors.push(el); (el.children || []).forEach(walk); })(card);
  assert.strictEqual(anchors.length, 1, 'exactly one verify link');
  assert.strictEqual(anchors[0].href, 'https://urlhaus.abuse.ch/browse.php?search=' + encodeURIComponent('https://files.example.net/app.zip'));
  assert.strictEqual(anchors[0].target, '_blank');
  assert.strictEqual(anchors[0].rel, 'noopener noreferrer');
});

runTest('EV-008: fixture data shows no source line and no false claim', () => {
  const card = cardFor({ status: 'REPUTATION_NO_MATCH', isFixture: true, source: 'OFFLINE_SYNTHETIC_FIXTURE',
    dbInfo: { source: 'OFFLINE_SYNTHETIC_FIXTURE', isFixture: true, generatedAt: daysAgo(1), entryCount: 5 } });
  assert.strictEqual(findByClass(card, 'btl-rep-source').length, 0);
  assert.ok(card.textContent.includes('Not checked against a live threat database'));
  assert.ok(!card.textContent.includes('Checked against'));
});

runTest('EV-009: "What we checked" reflects the real database state', () => {
  const real = cardFor({ status: 'REPUTATION_NO_MATCH', isFixture: false, source: 'URLHAUS_DATASET', dbInfo: prodInfo(daysAgo(1)) });
  assert.ok(real.textContent.includes('Known-threat list: URLhaus (abuse.ch)'));
  const fixture = cardFor({ status: 'REPUTATION_NO_MATCH', isFixture: true, source: 'OFFLINE_SYNTHETIC_FIXTURE',
    dbInfo: { source: 'OFFLINE_SYNTHETIC_FIXTURE', isFixture: true, generatedAt: daysAgo(1), entryCount: 5 } });
  assert.ok(fixture.textContent.includes('only offline test data is loaded'));
});

runTest('EV-010: a private-address destination is explained, not called a failure', () => {
  const card = cardFor({ status: 'REPUTATION_NO_MATCH', isFixture: true, source: 'OFFLINE_SYNTHETIC_FIXTURE', dbInfo: null },
    { status: 'FAILED', errorReason: 'PRIVATE_ADDRESS' });
  const text = card.textContent;
  assert.ok(text.includes('Points to a private or local network address (not inspected)'));
  assert.ok(text.includes('Destination is a private or local network address (not inspected)'));
});

(async () => {
  console.log('=== EVIDENCE LINE TESTS ===');
  let passed = 0;
  for (const t of queue) {
    try {
      await t.fn();
      console.log(`[PASS] ${t.name}`);
      passed++;
    } catch (e) {
      console.error(`[FAIL] ${t.name}\n       ${e.message}`);
    }
  }
  console.log(`\nEvidence line results: ${passed}/${queue.length} passed`);
  if (passed !== queue.length) process.exit(1);
})();
