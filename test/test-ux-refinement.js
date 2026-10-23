const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

// DOM Mock
const documentMock = {
  createElement: function(tag) {
    return {
      tagName: tag,
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
        add: function(c) { this.className += ' ' + c; },
        remove: function(c) { this.className = this.className.replace(c, '').trim(); }
      },
      appendChild: function(child) { this.children.push(child); },
      replaceChildren: function() { this.children = []; },
      setAttribute: function(k, v) { this[k] = v; },
      addEventListener: function() {},
      attachShadow: function() { return this; }
    };
  },
  createTextNode: function(text) {
    return { textContent: text };
  },
  body: { appendChild: function() {} }
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
const modulesToLoad = [
  './src/shared/constants.js',
  './src/shared/brand-registry.js',
  './src/shared/domain-utils.js',
  './src/shared/lookalike-analyzer.js',
  './src/content/shortener-registry.js',
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

function findElementByClass(el, className) {
  if (el.className && el.className.split(' ').includes(className)) return el;
  if (!el.children) return null;
  for (let child of el.children) {
    let found = findElementByClass(child, className);
    if (found) return found;
  }
  return null;
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

console.log("=== UX REFINEMENT TESTS ===");

const linkMock = { getBoundingClientRect: () => ({ top: 100, left: 100, bottom: 120, right: 200 }) };
BTL.getResolvedUrl = () => "https://example.com";

function getCard(payload) {
  BTL.previewUI.show(linkMock, payload, false);
  const host = BTL.previewUI.getHost();
  return findElementByClass(host, 'btl-card');
}

// 1. Normal link renders compactly and correctly
runTest("UX-001: Normal link hierarchy and quiet state", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [] }
  });
  
  const labels = findElementsByClass(card, 'btl-label').map(l => l.textContent);
  assert.deepStrictEqual(labels, ['DESTINATION', 'SAFETY', 'LINK TYPE']); // No WHY/WHAT blocks

  const evidenceEl = findElementsByClass(card, 'btl-evidence')[0];
  const evidence = evidenceEl.textContent;
  assert.ok(evidence.includes('Redirect not observed'));
  assert.ok(evidenceEl.className.includes('btl-evidence-neutral'));

  const status = findElementsByClass(card, 'btl-safety-status')[0].textContent;
  assert.ok(status.includes('No obvious warning signals were detected'), 'Should display quiet state fallback text');
  
  const typeText = findElementsByClass(card, 'btl-text-main')[0].textContent;
  assert.strictEqual(typeText, 'Direct link');
});

// 2. Informational State
runTest("UX-002: Informational state rendering", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      status: 'INFORMATIONAL', 
      userGuidance: {
        displaySignals: [{ label: 'Account or sign-in action' }],
        whyText: 'This link appears to involve an account action.',
        actionText: 'Check the destination domain before signing in.'
      }
    }
  });
  
  const status = findElementsByClass(card, 'btl-safety-status')[0].textContent;
  assert.ok(status.includes('Some things to know'));
  
  const bullets = findElementsByClass(card, 'btl-bullet-list')[0].children;
  assert.strictEqual(bullets[0].textContent, 'Account or sign-in action');
  
  const whyTexts = findElementsByClass(card, 'btl-why-text');
  assert.strictEqual(whyTexts[0].textContent, 'This link appears to involve an account action.');
  assert.strictEqual(whyTexts[1].textContent, 'Check the destination domain before signing in.');
});

// 3. Unusual State
runTest("UX-003: Unusual characteristics rendering", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      status: 'UNUSUAL_CHARACTERISTICS'
    }
  });
  
  const status = findElementsByClass(card, 'btl-safety-status')[0].textContent;
  assert.ok(status.includes('Some unusual characteristics'));
});

// 4. Unverified destination
runTest("UX-004: Unverified destination clear string", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    networkEvidence: { status: 'FAILED' }
  });
  
  const evidence = findElementsByClass(card, 'btl-evidence')[0].textContent;
  assert.ok(evidence.includes('Destination unresolved or inspection incomplete'));
});

// 5. Predicted destination
runTest("UX-005: Predicted destination distinct string", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    localSignals: { embeddedCandidates: ['https://target.com'] },
    networkEvidence: { status: 'FAILED' }
  });
  
  const destUrl = findElementsByClass(card, 'btl-dest-url')[0].textContent;
  assert.strictEqual(destUrl, 'target.com');
  
  const evidence = findElementsByClass(card, 'btl-evidence')[0].textContent;
  assert.ok(evidence.includes('Likely destination'));
});

// 6. Link Type formatting (dot separator)
runTest("UX-006: Link type combinations use dot separator", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      signals: [{ id: 'REDIRECTS_THROUGH_SHORTENER' }, { id: 'HAS_TRACKING_PARAMS' }]
    }
  });
  
  const typeText = findElementsByClass(card, 'btl-text-main')[0].textContent;
  assert.strictEqual(typeText, 'Shortened link · Tracking link');
});

// 7. Popup has maximum height and overflow-y
runTest("UX-007: Popup has maximum height and overflow-y enabled", () => {
  const code = fs.readFileSync('./src/content/preview-ui.js', 'utf8');
  assert.ok(code.includes('max-height:min(480px, 70vh)'));
  assert.ok(code.includes('overflow-y:auto'));
});

// 8. Progressive Disclosure sections collapsed by default
runTest("UX-008: Progressive disclosure sections are collapsed by default", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [] }
  });
  
  const detailsElements = findElementsByClass(card, 'btl-details');
  assert.strictEqual(detailsElements.length, 2);
  
  detailsElements.forEach(details => {
    // Check that 'open' attribute is not present
    assert.strictEqual(details.open, undefined);
  });
});

// 9. Phase 4A Dual State Rendering (No Threat)
runTest("UX-009: Phase 4A dual state renders Clean Reputation + Local Warnings", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      status: 'UNUSUAL_CHARACTERISTICS',
      localStatus: 'UNUSUAL_CHARACTERISTICS',
      reputationStatus: 'NO_KNOWN_THREAT'
    }
  });
  
  const statuses = findElementsByClass(card, 'btl-safety-status').map(e => e.textContent);
  assert.strictEqual(statuses.length, 2);
  assert.ok(statuses[0].includes('No known threat reported'));
  assert.ok(statuses[1].includes('Some unusual characteristics'));
});

// 10. Phase 4A Known Threat overrides
runTest("UX-010: Phase 4A Known Threat suppresses redundant local status", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      status: 'STRONG_WARNING',
      localStatus: 'UNUSUAL_CHARACTERISTICS',
      reputationStatus: 'KNOWN_THREAT'
    }
  });
  
  const statuses = findElementsByClass(card, 'btl-safety-status').map(e => e.textContent);
  // KNOWN_THREAT overrides the local status in the UI completely to avoid clutter
  assert.strictEqual(statuses.length, 1);
  assert.ok(statuses[0].includes('Known threat reported'));
});

runTest("UX-011: Direct URL + brand mismatch is NOT a redirecting link", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      status: 'UNUSUAL_CHARACTERISTICS',
      localStatus: 'UNUSUAL_CHARACTERISTICS',
      signals: [{ id: 'CLAIM_DESTINATION_MISMATCH' }]
    },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' }
  });
  const typeText = findElementsByClass(card, 'btl-text-main')[0].textContent;
  assert.strictEqual(typeText, 'Direct link');
});

runTest("UX-012: Actual HTTP redirect produces Redirecting link", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      status: 'NO_SIGNALS_DETECTED',
      localStatus: 'NO_SIGNALS_DETECTED',
      signals: []
    },
    networkEvidence: { status: 'HTTP_REDIRECT_OBSERVED', redirectTarget: 'https://target.com' }
  });
  const typeText = findElementsByClass(card, 'btl-text-main')[0].textContent;
  assert.strictEqual(typeText, 'Redirecting link');
});

runTest("UX-013: Shortened link with NO_REDIRECT_OBSERVED marks destination unresolved", () => {
  const card = getCard({
    originalUrl: 'https://t.me/invitegroup',
    localSignals: { hostname: 't.me', isShortened: true },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [] }
  });
  const evidence = findElementsByClass(card, 'btl-evidence')[0].textContent;
  assert.ok(evidence.includes('destination unresolved'), 'Shortened link must state destination is unresolved');
});

runTest("UX-014: Disabled reputation renders non-spinning informational text", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      status: 'NO_SIGNALS_DETECTED',
      reputationStatus: 'REPUTATION_NOT_ENABLED'
    }
  });
  const statuses = findElementsByClass(card, 'btl-safety-status').map(e => e.textContent);
  assert.ok(statuses[0].includes('External reputation checking is not enabled'));
  assert.ok(!statuses[0].includes('Checking reputation'));
});

runTest("UX-015: Ordinary Amazon shopping link with payment and delivery stays INFORMATIONAL", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://amazon.in/checkout',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    {
      category: 'PAYMENT',
      visibleText: 'Confirm delivery address and make payment for your order'
    }
  );

  assert.strictEqual(safetyResult.status, 'INFORMATIONAL', 'Ordinary shopping intent must not become UNUSUAL_CHARACTERISTICS');
  assert.strictEqual(safetyResult.localStatus, 'INFORMATIONAL');
  assert.strictEqual(safetyResult.reputationStatus, 'REPUTATION_NOT_ENABLED');
});

runTest("UX-016: Legitimate job application stays INFORMATIONAL", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://careers.google.com/jobs/results/',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    {
      category: 'JOB_HIRING',
      visibleText: 'Apply now for this career opportunity'
    }
  );

  assert.strictEqual(safetyResult.status, 'INFORMATIONAL', 'Job application link must stay INFORMATIONAL');
});

runTest("UX-017: Sensitive action context strengthens lookalike concern to UNUSUAL_CHARACTERISTICS", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://g00gle.com',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    {
      category: 'LOGIN_ACCOUNT',
      visibleText: 'Please sign in to update your account'
    }
  );

  assert.strictEqual(safetyResult.status, 'UNUSUAL_CHARACTERISTICS', 'Lookalike + sensitive context must escalate');
});

runTest("UX-018: Brand mismatch with claimed brand and observed destination domain", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://phishing-site.com',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    {
      possibleClaimedBrand: 'AMAZON',
      category: 'LOGIN_ACCOUNT',
      visibleText: 'Sign in to Amazon'
    }
  );

  assert.strictEqual(safetyResult.status, 'UNUSUAL_CHARACTERISTICS', 'Brand mismatch must be UNUSUAL_CHARACTERISTICS');
  assert.ok(safetyResult.userGuidance.whyText.includes('Amazon') && safetyResult.userGuidance.whyText.includes('phishing-site.com'), 'Must name claimed brand and observed destination');
});

// 19. Unverified destination without independent risk signals (e.g. 5movierulz.green)
runTest("UX-019: Unverified destination without independent risk signals", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://5movierulz.green',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    null
  );

  assert.strictEqual(safetyResult.status, 'NO_SIGNALS_DETECTED');
  assert.strictEqual(safetyResult.localStatus, 'NO_SIGNALS_DETECTED');
  assert.strictEqual(safetyResult.userGuidance.displaySignals.length, 0);
  assert.strictEqual(safetyResult.userGuidance.whyText, null);

  const card = getCard({
    originalUrl: 'https://5movierulz.green',
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    safetyEvidence: safetyResult
  });
  const statuses = findElementsByClass(card, 'btl-safety-status').map(s => s.textContent);
  assert.ok(statuses.some(t => t.includes('No obvious warning signals were detected')));
  assert.ok(statuses.some(t => t.includes('does not guarantee the site is safe')));
});

// 20. Suspicious download context without unsupported malware claims
runTest("UX-020: Suspicious download context without unsupported malware claims", () => {
  const contextObj = {
    category: 'MEDIA_OR_DOWNLOAD',
    visibleText: 'Download movie torrent now for free'
  };
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://5movierulz.green/watch',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    contextObj
  );

  // Must remain INFORMATIONAL (not escalated to UNUSUAL_CHARACTERISTICS without independent technical concern)
  assert.strictEqual(safetyResult.status, 'INFORMATIONAL');
  assert.strictEqual(safetyResult.localStatus, 'INFORMATIONAL');
  assert.ok(safetyResult.signals.some(s => s.id === 'DOWNLOAD_OR_MEDIA_CONTEXT'));
  assert.strictEqual(safetyResult.userGuidance.actionText, null, 'Must not issue alarmist malware or action warning on context alone');
  assert.ok(safetyResult.userGuidance.whyText.includes('media or download context'));
});

// 21. Download context WITH independent technical risk escalates
runTest("UX-021: Download context with independent technical risk escalates", () => {
  const contextObj = {
    category: 'MEDIA_OR_DOWNLOAD',
    visibleText: 'Download movie now'
  };
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'http://5movierulz.green/movie.exe',
    { isShortened: false, isHttps: false, pathname: '/movie.exe' },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    contextObj
  );

  // Combines SUSPICIOUS_FILE_EXT (Tier B path_content) + HTTP_NOT_HTTPS (connection) + MEDIA_OR_DOWNLOAD -> UNUSUAL_CHARACTERISTICS
  assert.strictEqual(safetyResult.status, 'UNUSUAL_CHARACTERISTICS');
  assert.strictEqual(safetyResult.localStatus, 'UNUSUAL_CHARACTERISTICS');
});

// 22. Genuine lookalike domains with explicit evidence
runTest("UX-022: Genuine lookalike domains with explicit evidence", () => {
  const safetyResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://g00gle.com',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    null
  );

  assert.strictEqual(safetyResult.userGuidance.displaySignals.length, 1);
  const label = safetyResult.userGuidance.displaySignals[0].label;
  assert.ok(label.includes('digit substitutions'), 'Label must state the exact detection reason');
  assert.ok(label.includes('Google'), 'Label must name the target brand');
  assert.ok(safetyResult.userGuidance.whyText.includes('Google') && safetyResult.userGuidance.whyText.includes('Lookalike domains'));
  assert.ok(safetyResult.userGuidance.actionText.includes('Check the domain spelling'));
});

// 23. Ordinary shopping and job links have calm informational instructions (actionText is null)
runTest("UX-023: Ordinary shopping and job links have calm informational instructions", () => {
  const shoppingResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://amazon.com/item',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    { category: 'PAYMENT', visibleText: 'Confirm delivery and pay now' }
  );
  assert.strictEqual(shoppingResult.status, 'INFORMATIONAL');
  assert.strictEqual(shoppingResult.userGuidance.actionText, null, 'Shopping context must not have alarmist action directive');

  const jobResult = BTL.safetyAnalyzer.computeSafetyEvidence(
    'https://careers.google.com',
    { isShortened: false, isHttps: true },
    { signals: [] },
    null,
    null,
    { status: 'NO_REDIRECT_OBSERVED' },
    null,
    { status: 'REPUTATION_NOT_ENABLED' },
    { category: 'JOB_HIRING', visibleText: 'Apply now for this role' }
  );
  assert.strictEqual(jobResult.status, 'INFORMATIONAL');
  assert.strictEqual(jobResult.userGuidance.actionText, null, 'Job context must not have alarmist action directive');
});

// 24. Freshly resolved redirect explains routing and content disclaimer
runTest("UX-024: Freshly resolved redirect explains routing and content disclaimer", () => {
  const card = getCard({
    originalUrl: 'https://youtu.be/dQw4w9WgXcQ',
    networkEvidence: {
      status: 'HTTP_REDIRECT_OBSERVED',
      redirectTarget: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'
    },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [] }
  });
  const evidence = findElementsByClass(card, 'btl-evidence')[0].textContent;
  assert.ok(evidence.includes('Redirect observed: youtu.be → www.youtube.com'), 'Must name origin and target');
  assert.ok(evidence.includes('page content and media are not inspected'), 'Must disclaim content/video safety');
});

// 25. Previously observed destination states history observation
runTest("UX-025: Previously observed destination states history observation", () => {
  const card = getCard({
    originalUrl: 'https://example.com/short',
    browserObservation: {
      status: 'STRONG_CORRELATION',
      observedLatestUrl: 'https://example.com/destination'
    },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [] }
  });
  const evidence = findElementsByClass(card, 'btl-evidence')[0].textContent;
  assert.ok(evidence.includes('Previously observed destination'));
  assert.ok(evidence.includes('content is not inspected'));
});

// 26. Resolution failure: TIMEOUT
runTest("UX-026: Destination resolution timeout displays timeout reason", () => {
  const card = getCard({
    originalUrl: 'https://slow-site.com',
    networkEvidence: {
      status: 'FAILED',
      errorReason: 'TIMEOUT'
    },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [] }
  });
  const evidence = findElementsByClass(card, 'btl-evidence')[0].textContent;
  assert.ok(evidence.includes('Destination could not be verified (request timed out)'));

  const detailValues = findElementsByClass(card, 'btl-detail-value').map(v => v.textContent);
  assert.ok(detailValues.includes('Request timed out'));
});

// 27. Resolution failure: NETWORK_ERROR
runTest("UX-027: Destination resolution network error displays blocked/network error", () => {
  const card = getCard({
    originalUrl: 'https://blocked-site.com',
    networkEvidence: {
      status: 'FAILED',
      errorReason: 'NETWORK_ERROR'
    },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [] }
  });
  const evidence = findElementsByClass(card, 'btl-evidence')[0].textContent;
  assert.ok(evidence.includes('network error or blocked by site'));

  const detailValues = findElementsByClass(card, 'btl-detail-value').map(v => v.textContent);
  assert.ok(detailValues.includes('Network error or blocked by site'));
});

// 28. YouTube short link preserves query parameter in target destination formatting
runTest("UX-028: Target URL formatting preserves video query parameter", () => {
  const card = getCard({
    originalUrl: 'https://youtu.be/dQw4w9WgXcQ',
    networkEvidence: {
      status: 'HTTP_REDIRECT_OBSERVED',
      redirectTarget: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'
    },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [] }
  });
  const destUrl = findElementsByClass(card, 'btl-dest-url')[0].textContent;
  assert.ok(destUrl.includes('watch?v=dQw4w9WgXcQ'), 'Must preserve video query parameter in target formatting');
});

console.log(`\nResults: ${passed}/${total} passed`);
if (passed !== total) process.exit(1);

