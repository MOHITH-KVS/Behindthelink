/**
 * Phase 0 trust-fix regression tests.
 *
 *  1. t.me / telegram.me / telegram.dog are Telegram's own domains, not URL
 *     shorteners, and must never produce "shortened link" or
 *     "destination unresolved" results.
 *  2. Telegram links are classified by structure (bot, invite, channel...).
 *  3. A "no match" against the synthetic fixture threat database must never
 *     render as a green "No known threat reported" check.
 */
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

// ---- Minimal DOM mock (same shape as test-ux-refinement.js) ----
const documentMock = {
  createElement: function (tag) {
    return {
      tagName: tag,
      className: '',
      _textContent: '',
      get textContent() {
        if (this.children.length > 0) return this.children.map(c => c.textContent).join('');
        return this._textContent;
      },
      set textContent(v) { this._textContent = v; },
      style: {},
      children: [],
      classList: {
        add: function (c) { this.className += ' ' + c; },
        remove: function (c) { this.className = this.className.replace(c, '').trim(); }
      },
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
const windowMock = {
  innerWidth: 320,
  innerHeight: 768,
  requestAnimationFrame: (cb) => cb()
};

let BTL = {};
const sandbox = {
  window: Object.assign({ BehindTheLink: BTL }, windowMock),
  self: { BehindTheLink: BTL },
  BTL: BTL,
  document: documentMock,
  URL: URL,
  console: { log: () => {}, error: console.error },
  Date: Date,
  requestAnimationFrame: windowMock.requestAnimationFrame
};
vm.createContext(sandbox);

[
  './src/shared/constants.js',
  './src/shared/brand-registry.js',
  './src/shared/domain-utils.js',
  './src/shared/lookalike-analyzer.js',
  './src/content/tracking-registry.js',
  './src/content/shortener-registry.js',
  './src/content/affiliate-registry.js',
  './src/content/url-analyzer.js',
  './src/content/context-extractor.js',
  './src/shared/deception-analyzer.js',
  './src/shared/claim-destination-analyzer.js',
  './src/shared/safety-analyzer.js',
  './src/shared/assessment-aggregator.js',
  './src/content/preview-ui.js'
].forEach(mod => vm.runInContext(fs.readFileSync(mod, 'utf8'), sandbox));
BTL = sandbox.window.BehindTheLink;

let passed = 0;
let total = 0;
function runTest(name, fn) {
  total++;
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (e) {
    console.error(`[FAIL] ${name}\n       ${e.message}`);
  }
}

function findByClass(el, className, acc) {
  acc = acc || [];
  if (el.className && el.className.split(' ').includes(className)) acc.push(el);
  (el.children || []).forEach(c => findByClass(c, className, acc));
  return acc;
}

const linkMock = { getBoundingClientRect: () => ({ top: 100, left: 100, bottom: 120, right: 200 }) };
BTL.getResolvedUrl = () => 'https://example.com';
function getCard(payload) {
  BTL.previewUI.show(linkMock, payload, false, payload.context);
  return findByClass(BTL.previewUI.getHost(), 'btl-card')[0];
}

console.log('=== PHASE 0 TRUST FIX TESTS ===');

// ---------- 1. Telegram is not a shortener ----------
['t.me', 'telegram.me', 'www.t.me'].forEach(host => {
  runTest(`TF-001: ${host} is not classified as a URL shortener`, () => {
    assert.strictEqual(BTL.shortenerRegistry.isShortener(host), false);
  });
});

runTest('TF-002: real shorteners are still detected', () => {
  ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly'].forEach(h =>
    assert.strictEqual(BTL.shortenerRegistry.isShortener(h), true, h));
});

runTest('TF-003: the t.me bot link from the field report is not shortened', () => {
  const a = BTL.urlAnalyzer.analyzeUrl('https://t.me/finding?start=a_3J9DWNF&text=ramayana+part+1');
  assert.strictEqual(a.localSignals.isShortened, false);
  assert.strictEqual(a.localSignals.isStructurallyDirect, true);
});

// ---------- 2. Telegram link classification ----------
const tg = (u) => BTL.urlAnalyzer.parseTelegramLink(u);

runTest('TF-004: start parameter => bot link with username', () => {
  const r = tg('https://t.me/finding?start=a_3J9DWNF&text=ramayana+part+1');
  assert.strictEqual(r.kind, 'BOT');
  assert.strictEqual(r.username, 'finding');
  assert.strictEqual(r.hasStartParameter, true);
  assert.strictEqual(r.label, 'Telegram bot link');
});

runTest('TF-005: username ending in "bot" => bot link', () => {
  assert.strictEqual(tg('https://t.me/SomeHelperBot').kind, 'BOT');
});

runTest('TF-006: invite links (+hash and joinchat) => invite, no username', () => {
  const a = tg('https://t.me/+AbCdEf123456');
  const b = tg('https://t.me/joinchat/AbCdEf123456');
  assert.strictEqual(a.kind, 'INVITE');
  assert.strictEqual(b.kind, 'INVITE');
  assert.strictEqual(a.username, null);
});

runTest('TF-007: plain username => channel or profile (no claim it is a bot)', () => {
  const r = tg('https://t.me/durov');
  assert.strictEqual(r.kind, 'CHANNEL_OR_PROFILE');
  assert.strictEqual(r.hasStartParameter, false);
});

runTest('TF-008: message link, share link, proxy link, channel web preview', () => {
  assert.strictEqual(tg('https://t.me/somechannel/1234').kind, 'MESSAGE');
  assert.strictEqual(tg('https://t.me/share/url?url=https%3A%2F%2Fexample.com').kind, 'SHARE');
  assert.strictEqual(tg('https://t.me/proxy?server=1.2.3.4&port=443&secret=abc').kind, 'PROXY');
  const s = tg('https://t.me/s/somechannel');
  assert.strictEqual(s.kind, 'CHANNEL');
  assert.strictEqual(s.username, 'somechannel');
});

runTest('TF-009: non-Telegram hosts are never classified (including lookalikes)', () => {
  assert.strictEqual(tg('https://example.com/finding?start=1'), null);
  assert.strictEqual(tg('https://t.me.evil.com/finding?start=1'), null);
  assert.strictEqual(tg('https://nott.me/finding?start=1'), null);
});

// ---------- 3. UI: link type and destination wording ----------
const linkTypeText = (card) => {
  const labels = findByClass(card, 'btl-label');
  const idx = labels.findIndex(l => l.textContent === 'LINK TYPE');
  assert.ok(idx >= 0, 'LINK TYPE section present');
  const mains = findByClass(card, 'btl-text-main');
  return mains[mains.length - 1].textContent;
};

runTest('TF-010: Telegram bot link card says "Telegram bot link (@finding)", not "Shortened link"', () => {
  const url = 'https://t.me/finding?start=a_3J9DWNF&text=ramayana+part+1';
  const a = BTL.urlAnalyzer.analyzeUrl(url);
  const card = getCard({
    originalUrl: url,
    localSignals: a.localSignals,
    riskSignals: a.riskSignals,
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [] }
  });
  const text = linkTypeText(card);
  assert.strictEqual(text, 'Telegram bot link (@finding)');
  assert.ok(!text.includes('Shortened'));
  const evidence = findByClass(card, 'btl-evidence')[0].textContent;
  assert.ok(!evidence.includes('shortener'), 'destination wording must not mention a shortener');
});

// ---------- 4. Fixture database must not produce a green check ----------
function evidenceFor(reputationSignals) {
  return BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://www.5movierulz.supplies',
    { isShortened: false, isHttps: true, hostname: 'www.5movierulz.supplies' },
    { signals: [] }, null, null,
    { status: 'NO_REDIRECT_OBSERVED' }, null,
    reputationSignals, null
  );
}

runTest('TF-011: fixture-only "no match" => NO_LIVE_DATABASE, not NO_KNOWN_THREAT', () => {
  const ev = evidenceFor({ status: 'REPUTATION_NO_MATCH', isFixture: true, source: 'OFFLINE_SYNTHETIC_FIXTURE' });
  assert.strictEqual(ev.reputationStatus, 'NO_LIVE_DATABASE');
});

runTest('TF-012: production "no match" is unchanged (NO_KNOWN_THREAT)', () => {
  const ev = evidenceFor({ status: 'REPUTATION_NO_MATCH', isFixture: false, source: 'URLHAUS_DATASET' });
  assert.strictEqual(ev.reputationStatus, 'NO_KNOWN_THREAT');
});

runTest('TF-013: a confirmed threat still reports KNOWN_THREAT', () => {
  const ev = evidenceFor({ status: 'REPUTATION_CONFIRMED_THREAT', isFixture: false, threatTypes: ['MALWARE'], source: 'URLHAUS_DATASET' });
  assert.strictEqual(ev.reputationStatus, 'KNOWN_THREAT');
});

runTest('TF-014: card never shows the green check or "No known threat reported" for fixture-only data', () => {
  const ev = evidenceFor({ status: 'REPUTATION_NO_MATCH', isFixture: true, source: 'OFFLINE_SYNTHETIC_FIXTURE' });
  const card = getCard({
    originalUrl: 'https://www.5movierulz.supplies',
    localSignals: { isShortened: false, isHttps: true, hostname: 'www.5movierulz.supplies' },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    safetyEvidence: ev
  });
  const text = card.textContent;
  assert.ok(!text.includes('No known threat reported'), 'must not claim "No known threat reported"');
  assert.ok(text.includes('Not checked against a live threat database'), 'must state the true situation');
  const statuses = findByClass(card, 'btl-safety-status');
  statuses.forEach(s => assert.ok(!s.textContent.includes('✓'), 'no green check'));
});

runTest('TF-015: card still shows the check for a production database with no match', () => {
  const ev = evidenceFor({ status: 'REPUTATION_NO_MATCH', isFixture: false, source: 'URLHAUS_DATASET' });
  const card = getCard({
    originalUrl: 'https://example.com',
    localSignals: { isShortened: false, isHttps: true, hostname: 'example.com' },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    safetyEvidence: ev
  });
  assert.ok(card.textContent.includes('No known threat reported'));
});

console.log(`\nTrust fix results: ${passed}/${total} passed`);
if (passed !== total) process.exit(1);
