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

const BTL = {};
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
const uiCode = fs.readFileSync('./src/content/preview-ui.js', 'utf8');
vm.runInContext(uiCode, sandbox);

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
  assert.ok(evidence.includes('Destination verified'));
  assert.ok(evidenceEl.className.includes('btl-evidence-neutral'));

  const status = findElementsByClass(card, 'btl-safety-status')[0].textContent;
  assert.ok(status.includes('Nothing unusual found'));
  
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
  assert.ok(evidence.includes('Could not verify destination'));
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

console.log(`\nResults: ${passed}/${total} passed`);
if (passed !== total) process.exit(1);
