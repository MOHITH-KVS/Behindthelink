/**
 * BehindTheLink — Stage 1 Overhaul Regression Test Suite
 *
 * Validates the four key improvements of Stage 1:
 * A. Fix Amazon and shopping false positives
 * B. Improve media/download context detection
 * C. Improve shortener and redirect inspection
 * D. Explicit mutually exclusive inspection verdicts
 */

const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

// DOM and Environment Mock
const documentMock = {
  createElement: function (tag) {
    return {
      tagName: tag.toUpperCase(),
      className: '',
      _textContent: '',
      get textContent() {
        if (this.children.length > 0) {
          return this.children.map(c => c.textContent).join('');
        }
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
      getAttribute: function (k) { return this[k] || null; },
      addEventListener: function () {},
      attachShadow: function () { return this; }
    };
  },
  createTextNode: function (text) {
    return { textContent: text };
  },
  body: { appendChild: function () {} }
};

const windowMock = {
  innerWidth: 320,
  innerHeight: 768,
  requestAnimationFrame: (cb) => cb()
};

global.requestAnimationFrame = (cb) => cb();

let BTL = {};
const sandbox = {
  window: Object.assign({ BehindTheLink: BTL }, windowMock),
  self: { BehindTheLink: BTL },
  BTL: BTL,
  document: documentMock,
  URL: URL,
  console: { log: () => {}, error: console.error },
  Date: Date,
  fetch: global.fetch,
  AbortController: AbortController,
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  TextDecoder: TextDecoder,
  requestAnimationFrame: (cb) => cb(),
  chrome: {
    runtime: { onMessage: { addListener: () => {} } },
    storage: { local: { get: async () => ({}), set: async () => {}, remove: async () => {} } }
  }
};

vm.createContext(sandbox);

const modulesToLoad = [
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
];

for (const mod of modulesToLoad) {
  vm.runInContext(fs.readFileSync(mod, 'utf8'), sandbox);
}

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
    console.error(`[FAIL] ${name}\n       ${e.message}\n${e.stack}`);
  }
}

async function runAsyncTest(name, fn) {
  total++;
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (e) {
    console.error(`[FAIL] ${name}\n       ${e.message}\n${e.stack}`);
  }
}

function findElementsByClass(el, className) {
  let results = [];
  if (el.className && el.className.split(' ').includes(className)) results.push(el);
  if (!el.children) return results;
  for (let child of el.children) {
    results = results.concat(findElementsByClass(child, className));
  }
  return results;
}

const linkMock = { getBoundingClientRect: () => ({ top: 100, left: 100, bottom: 120, right: 200 }) };
BTL.getResolvedUrl = () => "https://example.com";

function getCard(payload, contextObj) {
  BTL.previewUI.show(linkMock, payload, false, contextObj || (payload && payload.context));
  const host = BTL.previewUI.getHost();
  function findCard(el) {
    if (el.className && el.className.split(' ').includes('btl-card')) return el;
    if (!el.children) return null;
    for (let c of el.children) {
      const res = findCard(c);
      if (res) return res;
    }
    return null;
  }
  return findCard(host);
}

console.log("=== STAGE 1 SECURITY DETECTION OVERHAUL REGRESSION TESTS ===");

// ============================================================================
// PART A: AMAZON AND SHOPPING FALSE POSITIVES
// ============================================================================

runTest("A1: Normal Amazon product link does not receive payment-action warning", () => {
  // Context extractor mock of an Amazon product card
  const link = {
    tagName: 'A',
    textContent: 'Sony WH-1000XM5 Wireless Noise Canceling Headphones',
    href: 'https://www.amazon.com/Sony-WH-1000XM5-Canceling-Headphones/dp/B09XS7JWHH',
    getAttribute: (k) => k === 'href' ? 'https://www.amazon.com/Sony-WH-1000XM5-Canceling-Headphones/dp/B09XS7JWHH' : null,
    parentElement: {
      tagName: 'DIV',
      textContent: 'Sony WH-1000XM5 Wireless Headphones. $348.00. FREE delivery Friday, Oct 25. Checkout with Amazon Prime Store Card for 5% back. Add to Cart. Buy now.',
      parentElement: null
    }
  };

  const extracted = BTL.contextExtractor.extract(link);
  assert.strictEqual(extracted.category, 'UNKNOWN', 'Product link must not be categorized as PAYMENT from parent card');

  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://www.amazon.com/Sony-WH-1000XM5-Canceling-Headphones/dp/B09XS7JWHH',
    { isShortened: false, isHttps: true, hostname: 'www.amazon.com' },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    extracted
  );

  assert.strictEqual(safetyResult.verdict, 'NO_KNOWN_THREAT');
  assert.ok(safetyResult.status === 'NO_KNOWN_THREAT' || safetyResult.status === 'NO_SIGNALS_DETECTED');
  assert.ok(!safetyResult.signals.some(s => s.id === 'PAYMENT_ACTION'), 'Must not have PAYMENT_ACTION');
  assert.ok(!safetyResult.signals.some(s => s.id === 'DELIVERY_ACTION'), 'Must not have DELIVERY_ACTION');
  assert.strictEqual(safetyResult.userGuidance.whyText, null);
  assert.strictEqual(safetyResult.userGuidance.actionText, null);
});

runTest("A2: Amazon search and catalog links stay clean without payment warning", () => {
  const contextObj = {
    visibleText: 'Explore deals on Electronics & Accessories',
    nearbyText: 'Save up to 40%. Pricing and delivery options available at checkout.',
    category: 'UNKNOWN'
  };

  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://www.amazon.com/s?k=electronics',
    { isShortened: false, isHttps: true, hostname: 'www.amazon.com' },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    contextObj
  );

  assert.strictEqual(safetyResult.verdict, 'NO_KNOWN_THREAT');
  assert.ok(!safetyResult.signals.some(s => s.id === 'PAYMENT_ACTION'));
});

runTest("A3: Amazon genuine checkout link detects payment intent appropriately", () => {
  const checkoutLink = {
    tagName: 'A',
    textContent: 'Proceed to Checkout',
    href: 'https://www.amazon.com/gp/buy/spc/handlers/display.html',
    getAttribute: (k) => k === 'href' ? 'https://www.amazon.com/gp/buy/spc/handlers/display.html' : null,
    parentElement: null
  };

  const extracted = BTL.contextExtractor.extract(checkoutLink);
  assert.strictEqual(extracted.category, 'PAYMENT', 'Explicit checkout button must be categorized as PAYMENT');

  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://www.amazon.com/gp/buy/spc/handlers/display.html',
    { isShortened: false, isHttps: true, hostname: 'www.amazon.com' },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    extracted
  );

  assert.ok(safetyResult.signals.some(s => s.id === 'PAYMENT_ACTION'), 'Must detect PAYMENT_ACTION for genuine checkout link');
  assert.strictEqual(safetyResult.verdict, 'NO_KNOWN_THREAT', 'Official checkout link without risk signals does not falsely escalate');
});

runTest("A4: Benign third-party shopping product page stays clean", () => {
  const productLink = {
    tagName: 'A',
    textContent: 'Leather Running Shoes - Brown Size 10',
    href: 'https://myshop.com/products/shoes-brown',
    getAttribute: (k) => k === 'href' ? 'https://myshop.com/products/shoes-brown' : null,
    parentElement: {
      tagName: 'DIV',
      textContent: '$89.00. Add to cart. Checkout with card or PayPal.',
      parentElement: null
    }
  };

  const extracted = BTL.contextExtractor.extract(productLink);
  assert.strictEqual(extracted.category, 'UNKNOWN');

  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://myshop.com/products/shoes-brown',
    { isShortened: false, isHttps: true, hostname: 'myshop.com' },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    extracted
  );

  assert.strictEqual(safetyResult.verdict, 'NO_KNOWN_THREAT');
  assert.ok(!safetyResult.signals.some(s => s.id === 'PAYMENT_ACTION'));
});

runTest("A5: Genuinely suspicious cross-domain payment link retains appropriate warning behavior", () => {
  const phishContext = {
    visibleText: 'Pay invoice now with Amazon Pay',
    possibleClaimedBrand: 'AMAZON',
    category: 'PAYMENT'
  };

  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://amazon-billing-update.attacker.com/checkout',
    { isShortened: false, isHttps: true, hostname: 'amazon-billing-update.attacker.com' },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    phishContext
  );

  assert.strictEqual(safetyResult.verdict, 'UNUSUAL_CHARACTERISTICS');
  assert.ok(safetyResult.signals.some(s => s.id === 'PAYMENT_ACTION'));
  assert.ok(safetyResult.signals.some(s => s.id === 'CLAIM_DESTINATION_MISMATCH' || s.dimension === 'brand_identity'));
  assert.ok(safetyResult.userGuidance.actionText.includes('destination'));
});

// ============================================================================
// PART B: MEDIA / DOWNLOAD CONTEXT DETECTION
// ============================================================================

runTest("B1: 5movierulz.green receives CONTEXTUAL_CAUTION with no claims of malware", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://5movierulz.green/',
    { isShortened: false, isHttps: true, hostname: '5movierulz.green' },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    null // Bare link, no context
  );

  assert.strictEqual(safetyResult.verdict, 'CONTEXTUAL_CAUTION');
  assert.strictEqual(safetyResult.status, 'CONTEXTUAL_CAUTION');
  assert.ok(safetyResult.signals.some(s => s.id === 'UNOFFICIAL_STREAMING_OR_DOWNLOAD_CONTEXT'));

  const whyText = safetyResult.userGuidance.whyText || '';
  assert.strictEqual(whyText.toLowerCase().includes('malware'), false, 'Must not claim malware');
  assert.strictEqual(whyText.toLowerCase().includes('phishing'), false, 'Must not claim phishing');
  assert.strictEqual(whyText.toLowerCase().includes('malicious'), false, 'Must not claim malicious');

  const card = getCard({
    originalUrl: 'https://5movierulz.green/',
    safetyEvidence: safetyResult,
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' }
  });
  const statuses = findElementsByClass(card, 'btl-safety-status').map(s => s.textContent);
  assert.ok(statuses.some(s => s.includes('Contextual caution')));
});

runTest("B2: Joined piracy domain names receive CONTEXTUAL_CAUTION", () => {
  const testDomains = [
    'https://123movies.net/',
    'https://torrentgalaxy.to/browse',
    'https://movierulzfree.is/',
    'https://piratebay.org/'
  ];

  for (const url of testDomains) {
    const res = BTL.safetyAnalyzer.computeSafetyEvidence(
      url,
      { isShortened: false, isHttps: true },
      { signals: [] },
      null,
      null,
      { status: 'NO_REDIRECT_OBSERVED' },
      null,
      { status: 'REPUTATION_NOT_ENABLED' },
      null
    );
    assert.strictEqual(res.verdict, 'CONTEXTUAL_CAUTION', `${url} must receive CONTEXTUAL_CAUTION`);
    assert.ok(res.signals.some(s => s.id === 'UNOFFICIAL_STREAMING_OR_DOWNLOAD_CONTEXT'));
  }
});

runTest("B3: Generic media websites without piracy tokens receive NO_KNOWN_THREAT", () => {
  const benignMediaUrls = [
    'https://www.themoviedb.org/movie/top-rated',
    'https://www.rogerebert.com/reviews/dune-2021',
    'https://www.boxofficemojo.com/year/'
  ];

  for (const url of benignMediaUrls) {
    const res = BTL.safetyAnalyzer.computeSafetyEvidence(
      url,
      { isShortened: false, isHttps: true },
      { signals: [] },
      null,
      null,
      { status: 'NO_REDIRECT_OBSERVED' },
      null,
      { status: 'REPUTATION_NOT_ENABLED' },
      { visibleText: 'Read movie reviews and cast details', category: 'UNKNOWN' }
    );
    assert.strictEqual(res.verdict, 'NO_KNOWN_THREAT', `${url} must receive NO_KNOWN_THREAT`);
    assert.ok(!res.signals.some(s => s.id === 'UNOFFICIAL_STREAMING_OR_DOWNLOAD_CONTEXT'));
  }
});

runTest("B4: Legitimate mainstream streaming services are exempted from streaming caution", () => {
  const mainstreamUrls = [
    { url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ', brand: 'YOUTUBE' },
    { url: 'https://www.netflix.com/title/80057281', brand: 'NETFLIX' },
    { url: 'https://www.primevideo.com/detail/0TIX7', brand: 'AMAZON' },
    { url: 'https://www.disneyplus.com/movies/star-wars', brand: null }
  ];

  for (const item of mainstreamUrls) {
    const res = BTL.safetyAnalyzer.computeSafetyEvidence(
      item.url,
      { isShortened: false, isHttps: true },
      { signals: [] },
      null,
      null,
      { status: 'NO_REDIRECT_OBSERVED' },
      null,
      { status: 'REPUTATION_NOT_ENABLED' },
      { visibleText: 'Watch movies and stream online free trailer', category: 'MEDIA_OR_DOWNLOAD', possibleClaimedBrand: item.brand }
    );
    assert.strictEqual(res.verdict, 'NO_KNOWN_THREAT', `${item.url} must remain NO_KNOWN_THREAT`);
    assert.ok(!res.signals.some(s => s.id === 'UNOFFICIAL_STREAMING_OR_DOWNLOAD_CONTEXT'));
  }
});

runTest("B5: Unrelated benign domains receive NO_KNOWN_THREAT", () => {
  const res = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://docs.github.com/en/get-started',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    { visibleText: 'Documentation and quickstart guides', category: 'UNKNOWN' }
  );
  assert.strictEqual(res.verdict, 'NO_KNOWN_THREAT');
});

// ============================================================================
// PART C: SHORTENER AND REDIRECT INSPECTION
// ============================================================================

runTest("C1: Unresolved TinyURL is explicitly marked INSPECTION_INCOMPLETE", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://tinyurl.com/abc123xyz',
    { isShortened: true, isHttps: true, hostname: 'tinyurl.com' },
    { signals: [] },
    null,
    null,
    { status: 'FAILED', errorReason: 'DESTINATION_UNRESOLVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    null
  );

  assert.strictEqual(safetyResult.verdict, 'INSPECTION_INCOMPLETE');
  assert.strictEqual(safetyResult.status, 'INSPECTION_INCOMPLETE');
  assert.strictEqual(safetyResult.assessmentBasis, 'INCOMPLETE');
  assert.ok(safetyResult.limitations.some(l => l.includes('shortener')));

  const card = getCard({
    originalUrl: 'https://tinyurl.com/abc123xyz',
    safetyEvidence: safetyResult,
    networkEvidence: { status: 'FAILED', errorReason: 'DESTINATION_UNRESOLVED' }
  });

  const statuses = findElementsByClass(card, 'btl-safety-status').map(s => s.textContent);
  assert.ok(statuses.some(s => s.includes('Inspection incomplete — destination could not be verified')));
  const evidences = findElementsByClass(card, 'btl-evidence').map(e => e.textContent);
  assert.ok(evidences.some(e => e.includes('Destination unresolved (shortener did not provide a destination)')));
});

runTest("C2: Blocked / Interstitial challenge marked as INSPECTION_INCOMPLETE", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://bit.ly/blocked-link',
    { isShortened: true, isHttps: true, hostname: 'bit.ly' },
    { signals: [] },
    null,
    null,
    { status: 'FAILED', errorReason: 'BLOCKED_INTERSTITIAL' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    null
  );

  assert.strictEqual(safetyResult.verdict, 'INSPECTION_INCOMPLETE');
  assert.strictEqual(safetyResult.status, 'INSPECTION_INCOMPLETE');

  const card = getCard({
    originalUrl: 'https://bit.ly/blocked-link',
    safetyEvidence: safetyResult,
    networkEvidence: { status: 'FAILED', errorReason: 'BLOCKED_INTERSTITIAL' }
  });

  const evidences = findElementsByClass(card, 'btl-evidence').map(e => e.textContent);
  assert.ok(evidences.some(e => e.includes('interstitial challenge or blocked by site')));
});

runTest("C3: Meta-refresh target parsing extracts HTTP destination without JavaScript", () => {
  // Test the helper functions injected into service-worker sandbox
  const swCode = fs.readFileSync('./src/background/service-worker.js', 'utf8');
  const swSandbox = {
    self: { BehindTheLink: BTL },
    window: { BehindTheLink: BTL },
    URL: URL,
    TextDecoder: TextDecoder,
    importScripts: () => {},
    chrome: { runtime: { onMessage: { addListener: () => {} } } }
  };
  vm.createContext(swSandbox);
  vm.runInContext(swCode, swSandbox);

  const sampleHtml = `
    <html>
      <head>
        <meta http-equiv="refresh" content="0; url=https://destination.org/final-article">
      </head>
      <body>Redirecting...</body>
    </html>
  `;

  // Verify extractMetaRefreshTarget function exists and works
  assert.strictEqual(typeof swSandbox.extractMetaRefreshTarget, 'function');
  const target = swSandbox.extractMetaRefreshTarget(sampleHtml, 'https://short.link/123');
  assert.strictEqual(target, 'https://destination.org/final-article');
});

runTest("C4: Redirect loop detected and marked as INSPECTION_INCOMPLETE", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://shortener.com/loop1',
    { isShortened: true, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'FAILED', errorReason: 'REDIRECT_LOOP' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    null
  );

  assert.strictEqual(safetyResult.verdict, 'INSPECTION_INCOMPLETE');
  assert.strictEqual(safetyResult.status, 'INSPECTION_INCOMPLETE');

  const card = getCard({
    originalUrl: 'https://shortener.com/loop1',
    safetyEvidence: safetyResult,
    networkEvidence: { status: 'FAILED', errorReason: 'REDIRECT_LOOP' }
  });
  const evidences = findElementsByClass(card, 'btl-evidence').map(e => e.textContent);
  assert.ok(evidences.some(e => e.includes('redirect loop detected')));
});

runTest("C5: Malformed destination / unsafe scheme rejected as MALFORMED_DESTINATION", () => {
  const swCode = fs.readFileSync('./src/background/service-worker.js', 'utf8');
  const swSandbox = {
    self: { BehindTheLink: BTL },
    window: { BehindTheLink: BTL },
    URL: URL,
    importScripts: () => {},
    chrome: { runtime: { onMessage: { addListener: () => {} } } }
  };
  vm.createContext(swSandbox);
  vm.runInContext(swCode, swSandbox);

  assert.strictEqual(swSandbox.isValidHttpUrl('javascript:alert(document.cookie)'), false);
  assert.strictEqual(swSandbox.isValidHttpUrl('data:text/html,<script>evil()</script>'), false);
  assert.strictEqual(swSandbox.isValidHttpUrl('file:///etc/passwd'), false);
  assert.strictEqual(swSandbox.isValidHttpUrl('https://valid-target.com/page'), true);
});

// ============================================================================
// PART D: EXPLICIT MUTUALLY EXCLUSIVE INSPECTION VERDICTS
// ============================================================================

runTest("D1: KNOWN_THREAT verdict strictly generated by threat intelligence source", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://malware-sample.com/',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_CONFIRMED_THREAT', threatTypes: ['MALWARE'] },
    null
  );

  assert.strictEqual(safetyResult.verdict, 'KNOWN_THREAT');
  assert.strictEqual(safetyResult.status, 'STRONG_WARNING');
  assert.strictEqual(safetyResult.reputationStatus, 'KNOWN_THREAT');
  assert.ok(safetyResult.signals.some(s => s.id === 'REPUTATION_CONFIRMED_THREAT'));
});

runTest("D2: UNUSUAL_CHARACTERISTICS verdict on objective structural / lookalike evidence", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'http://192.168.1.1/admin',
    { isShortened: false, isHttps: false },
    { signals: [{ type: 'IP_HOST' }, { type: 'HTTP_NOT_HTTPS' }] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    null
  );

  assert.strictEqual(safetyResult.verdict, 'UNUSUAL_CHARACTERISTICS');
  assert.strictEqual(safetyResult.status, 'UNUSUAL_CHARACTERISTICS');
  assert.ok(safetyResult.signals.some(s => s.id === 'IP_HOST'));
});

runTest("D3: CONTEXTUAL_CAUTION verdict on movie download context without malware claim", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://5movierulz.green/movie',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    { visibleText: 'Watch and download full movie HD', category: 'MEDIA_OR_DOWNLOAD' }
  );

  assert.strictEqual(safetyResult.verdict, 'CONTEXTUAL_CAUTION');
  assert.strictEqual(safetyResult.status, 'CONTEXTUAL_CAUTION');
  assert.ok(safetyResult.signals.some(s => s.dimension === 'media_download_action'));
  assert.strictEqual(safetyResult.userGuidance.actionText, 'Avoid installing APKs or executable files from untrusted sources.');
});

runTest("D4: NO_KNOWN_THREAT verdict explicitly states it does not guarantee safety", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://example.com/clean-article',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    null
  );

  assert.strictEqual(safetyResult.verdict, 'NO_KNOWN_THREAT');
  assert.strictEqual(safetyResult.signals.length, 0);

  const card = getCard({
    originalUrl: 'https://example.com/clean-article',
    safetyEvidence: safetyResult,
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' }
  });
  const statuses = findElementsByClass(card, 'btl-safety-status').map(s => s.textContent);
  assert.ok(statuses.some(s => s.includes('No obvious warning signals were detected in the information inspected. This does not guarantee the site is safe.')));
});

runTest("D5: INSPECTION_INCOMPLETE verdict on network resolution failure", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://tinyurl.com/unresolved',
    { isShortened: true, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'FAILED', errorReason: 'TIMEOUT' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    null
  );

  assert.strictEqual(safetyResult.verdict, 'INSPECTION_INCOMPLETE');
  assert.strictEqual(safetyResult.status, 'INSPECTION_INCOMPLETE');

  const card = getCard({
    originalUrl: 'https://tinyurl.com/unresolved',
    safetyEvidence: safetyResult,
    networkEvidence: { status: 'FAILED', errorReason: 'TIMEOUT' }
  });
  const statuses = findElementsByClass(card, 'btl-safety-status').map(s => s.textContent);
  assert.ok(statuses.some(s => s.includes('Inspection incomplete — destination could not be verified')));
});

console.log(`\nStage 1 Results: ${passed}/${total} passed`);
if (passed !== total) process.exit(1);
