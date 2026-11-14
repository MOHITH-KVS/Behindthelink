/**
 * Verified-official and fallback-card tests.
 *
 *  1. A destination on a brand's official domain list is reported as a verified
 *     official site, and lookalikes, unknown sites, shorteners and known threats are not.
 *  2. The card shows "Verified official site" and drops the generic
 *     "does not guarantee" text for verified sites only.
 *  3. When the background checker does not answer, the card is complete
 *     (domain, clear message) instead of blank.
 */
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const queue = [];
const runTest = (name, fn) => queue.push({ name, fn });
const plain = (x) => JSON.parse(JSON.stringify(x));

// ---------- Card environment ----------
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
let BTL = {};
const sandbox = {
  window: { BehindTheLink: BTL, innerWidth: 320, innerHeight: 768, requestAnimationFrame: (cb) => cb() },
  self: { BehindTheLink: BTL }, BTL: BTL, document: documentMock, URL: URL,
  console: { log: () => {}, error: console.error }, Date: Date, requestAnimationFrame: (cb) => cb()
};
vm.createContext(sandbox);
[
  './src/shared/constants.js', './src/shared/brand-registry.js', './src/shared/domain-utils.js',
  './src/shared/lookalike-analyzer.js', './src/content/tracking-registry.js', './src/content/shortener-registry.js',
  './src/content/affiliate-registry.js', './src/content/url-analyzer.js', './src/content/context-extractor.js',
  './src/shared/deception-analyzer.js', './src/shared/claim-destination-analyzer.js', './src/shared/safety-analyzer.js',
  './src/shared/assessment-aggregator.js', './src/content/preview-ui.js'
].forEach(m => vm.runInContext(fs.readFileSync(m, 'utf8'), sandbox));
BTL = sandbox.window.BehindTheLink;
BTL.getResolvedUrl = () => 'https://example.com';
const linkMock = { getBoundingClientRect: () => ({ top: 100, left: 100, bottom: 120, right: 200 }) };

function findByClass(el, className, acc) {
  acc = acc || [];
  if (el.className && el.className.split(' ').includes(className)) acc.push(el);
  (el.children || []).forEach(c => findByClass(c, className, acc));
  return acc;
}
function getCard(payload) {
  BTL.previewUI.show(linkMock, payload, false, payload.context);
  return findByClass(BTL.previewUI.getHost(), 'btl-card')[0];
}

const CLEAN_REP = { status: 'REPUTATION_NO_MATCH', isFixture: true, source: 'OFFLINE_SYNTHETIC_FIXTURE', dbInfo: null };
function evidenceFor(url, opts) {
  opts = opts || {};
  const a = BTL.urlAnalyzer.analyzeUrl(url);
  return {
    local: a.localSignals,
    evidence: BTL.safetyAnalyzer.computeSafetyEvidence(
      url, a.localSignals, a.riskSignals, null, opts.targetLocal || null,
      opts.net || { status: 'NO_REDIRECT_OBSERVED' }, null, opts.rep || CLEAN_REP, null)
  };
}
function cardFor(url, opts) {
  const r = evidenceFor(url, opts);
  return getCard({ originalUrl: url, localSignals: r.local, networkEvidence: (opts && opts.net) || { status: 'NO_REDIRECT_OBSERVED' }, safetyEvidence: r.evidence });
}

// ---------- 1. Analyzer ----------
runTest('VO-001: official domains of known brands are verified (the three sites from the field report)', () => {
  const cases = [
    ['https://onlinesbi.sbi.bank.in/', 'SBI'],
    ['https://www.amazon.in/', 'AMAZON'],
    ['https://web.telegram.org/', 'TELEGRAM'],
    ['https://www.google.com/search?q=x', 'GOOGLE']
  ];
  cases.forEach(([url, brandId]) => {
    const v = evidenceFor(url).evidence.verifiedOfficial;
    assert.ok(v, url + ' should be verified');
    assert.strictEqual(v.brandId, brandId, url);
    assert.ok(v.displayName.length > 0);
  });
});

runTest('VO-002: lookalikes, unknown and user-content hosts are never verified', () => {
  [
    'https://sbi.bank.in.fake-site.com/', 'https://login.amazon.com.evil.net/', 'https://evilsbi.bank.in.attacker.io/',
    'https://amazon-secure-login.in/', 'https://kickcharm.com/offer/', 'https://someone.github.io/amazon.in/',
    'https://telegram-web-login.org/'
  ].forEach(url => assert.strictEqual(evidenceFor(url).evidence.verifiedOfficial, null, url));
});

runTest('VO-003: a confirmed threat on an official domain is never labelled verified', () => {
  const rep = { status: 'REPUTATION_CONFIRMED_THREAT', isFixture: false, source: 'URLHAUS_DATASET', threatTypes: ['MALWARE'],
    dbInfo: { source: 'URLHAUS_DATASET', isFixture: false, generatedAt: new Date().toISOString(), entryCount: 10 } };
  const r = evidenceFor('https://www.amazon.in/payload.exe', { rep: rep });
  assert.strictEqual(r.evidence.reputationStatus, 'KNOWN_THREAT');
  assert.strictEqual(r.evidence.verifiedOfficial, null);
});

runTest('VO-004: an unresolved shortener is not verified; a resolved one is judged by its destination', () => {
  const unresolved = evidenceFor('https://bit.ly/abc123', { net: { status: 'FAILED', errorReason: 'DESTINATION_UNRESOLVED' } });
  assert.strictEqual(unresolved.evidence.verifiedOfficial, null);
  const target = BTL.urlAnalyzer.analyzeUrl('https://www.amazon.in/dp/B000');
  const resolved = evidenceFor('https://bit.ly/abc123', {
    net: { status: 'HTTP_REDIRECT_OBSERVED', redirectTarget: 'https://www.amazon.in/dp/B000' }, targetLocal: target.localSignals });
  assert.ok(resolved.evidence.verifiedOfficial, 'destination on an official domain is verified');
  assert.strictEqual(resolved.evidence.verifiedOfficial.brandId, 'AMAZON');
  const toEvil = BTL.urlAnalyzer.analyzeUrl('https://amazon-gift.example-prize.com/');
  const evil = evidenceFor('https://bit.ly/abc123', {
    net: { status: 'HTTP_REDIRECT_OBSERVED', redirectTarget: 'https://amazon-gift.example-prize.com/' }, targetLocal: toEvil.localSignals });
  assert.strictEqual(evil.evidence.verifiedOfficial, null, 'a shortener that lands on a lookalike is not verified');
});

// ---------- 2. Card ----------
runTest('VO-005: verified card shows the verified line and no generic "does not guarantee" text', () => {
  const text = cardFor('https://onlinesbi.sbi.bank.in/').textContent;
  assert.ok(text.includes('Verified official site'), text);
  assert.ok(text.includes('State Bank of India'));
  assert.ok(text.includes('Pages on it are not inspected'));
  assert.ok(!text.includes('does not guarantee'));
  assert.ok(text.includes('Official domain list: matches'), 'listed under what we checked');
});

runTest('VO-006: unknown sites keep the careful wording and get no verified line', () => {
  const text = cardFor('https://kickcharm.com/apply/').textContent;
  assert.ok(!text.includes('Verified official site'));
  assert.ok(text.includes('does not guarantee the site is safe'));
});

runTest('VO-007: a verified site that also has a warning still shows the warning', () => {
  const url = 'https://www.amazon.in/gp/video/movie-download-apk';
  const r = evidenceFor(url);
  assert.ok(r.evidence.verifiedOfficial);
  const card = getCard({ originalUrl: url, localSignals: r.local, networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    safetyEvidence: Object.assign({}, r.evidence, { verdict: 'CONTEXTUAL_CAUTION', status: 'CONTEXTUAL_CAUTION' }) });
  assert.ok(card.textContent.includes('Verified official site'));
  assert.ok(card.textContent.includes('Contextual caution'), 'the caution must not be hidden by the verified label');
});

// ---------- 3. Fallback card ----------
function loadHover(sendBehaviour) {
  const timers = [];
  const calls = { update: [], show: [], messages: [] };
  const B = {};
  const sb = {
    window: { BehindTheLink: B, getComputedStyle: () => ({ display: 'inline', visibility: 'visible', opacity: '1' }) },
    self: { BehindTheLink: B }, BTL: B, URL, location: { hostname: 'www.google.com' },
    document: { baseURI: 'https://www.google.com/' },
    chrome: { runtime: { lastError: null, sendMessage: (msg, cb) => { calls.messages.push(msg.type); sendBehaviour(sb.chrome.runtime, cb); } } },
    setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimeout: () => {},
    console: { log: () => {}, warn: () => {}, error: () => {} }
  };
  vm.createContext(sb);
  ['src/shared/constants.js', 'src/shared/brand-registry.js', 'src/shared/domain-utils.js', 'src/content/link-eligibility.js',
   'src/content/tracking-registry.js', 'src/content/shortener-registry.js', 'src/content/affiliate-registry.js', 'src/content/url-analyzer.js']
    .forEach(f => vm.runInContext(fs.readFileSync(f, 'utf8'), sb));
  const BT = sb.window.BehindTheLink;
  BT.previewUI = {
    getHost: () => null, hide: () => {}, setReputationLoading: () => {}, updateReputationResult: () => {},
    show: (...a) => calls.show.push(a), updateNetworkResult: (p) => calls.update.push(plain(p))
  };
  vm.runInContext(fs.readFileSync('src/content/hover-manager.js', 'utf8'), sb);
  return { hm: BT.hoverManager, timers, calls };
}
const anchorTo = (href) => ({ nodeType: 1, tagName: 'A', offsetWidth: 80, offsetHeight: 18,
  matches: (s) => s === 'a[href]', getAttribute: (n) => (n === 'href' ? href : null), href: href });

runTest('VO-008: when the checker does not answer, the card gets the real link and a clear reason', () => {
  const { hm, timers, calls } = loadHover((runtime, cb) => { runtime.lastError = { message: 'Extension context invalidated.' }; cb(undefined); });
  const a = anchorTo('https://www.amazon.in/');
  hm.handleMouseOver({ target: a, composedPath: () => [a] });
  timers.find(t => t.ms === 450).fn();
  assert.strictEqual(calls.update.length, 1, 'card updated once');
  const p = calls.update[0];
  assert.strictEqual(p.originalUrl, 'https://www.amazon.in/', 'link is not blank');
  assert.strictEqual(p.networkEvidence.status, 'FAILED');
  assert.strictEqual(p.networkEvidence.errorReason, 'EXTENSION_UNAVAILABLE');
  assert.strictEqual(p.safetyEvidence.verdict, 'INSPECTION_INCOMPLETE');
  assert.ok(calls.messages.includes('RESOLVE_DESTINATION'));
  assert.ok(!calls.messages.includes('CHECK_REPUTATION'), 'no reputation lookup after a failure');
  assert.strictEqual(timers.filter(t => t.ms === 600).length, 0, 'no delayed reputation check scheduled');
});

runTest('VO-009: the fallback card shows the domain, the refresh message, and no false reassurance', () => {
  const url = 'https://web.telegram.org/';
  const a = BTL.urlAnalyzer.analyzeUrl(url);
  const card = getCard({
    originalUrl: url, localSignals: a.localSignals, riskSignals: a.riskSignals,
    networkEvidence: { status: 'FAILED', errorReason: 'EXTENSION_UNAVAILABLE', redirectTarget: null },
    safetyEvidence: { status: 'INSPECTION_INCOMPLETE', verdict: 'INSPECTION_INCOMPLETE', signals: [], limitations: [], assessmentBasis: 'LOCAL_ONLY' }
  });
  const text = card.textContent;
  assert.ok(text.includes('web.telegram.org'), 'domain shown');
  assert.ok(text.includes('Refresh the page and try again'));
  assert.ok(text.includes('Inspection incomplete'));
  assert.ok(!text.includes('No obvious warning signals'), 'must not reassure when nothing was checked');
});

runTest('VO-010: a normal answer from the checker is unaffected', () => {
  const { hm, timers, calls } = loadHover((runtime, cb) => {
    cb({ originalUrl: 'https://www.amazon.in/', networkEvidence: { status: 'NO_REDIRECT_OBSERVED' }, safetyEvidence: { verdict: 'NO_KNOWN_THREAT', signals: [] } });
  });
  const a = anchorTo('https://www.amazon.in/');
  hm.handleMouseOver({ target: a, composedPath: () => [a] });
  timers.find(t => t.ms === 450).fn();
  assert.strictEqual(calls.update.length, 1);
  assert.strictEqual(calls.update[0].networkEvidence.status, 'NO_REDIRECT_OBSERVED');
});

(async () => {
  console.log('=== VERIFIED OFFICIAL + FALLBACK CARD TESTS ===');
  let passed = 0;
  for (const t of queue) {
    try { await t.fn(); console.log(`[PASS] ${t.name}`); passed++; }
    catch (e) { console.error(`[FAIL] ${t.name}\n       ${e.message}`); }
  }
  console.log(`\nVerified-official results: ${passed}/${queue.length} passed`);
  if (passed !== queue.length) process.exit(1);
})();
