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
  innerWidth: 1024,
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
  if (el.className && el.className.includes(className)) return el;
  if (!el.children) return null;
  for (let child of el.children) {
    let found = findElementByClass(child, className);
    if (found) return found;
  }
  return null;
}

function findElementsByClass(el, className) {
  let results = [];
  if (el.className && el.className.includes(className)) results.push(el);
  if (!el.children) return results;
  for (let child of el.children) {
    results = results.concat(findElementsByClass(child, className));
  }
  return results;
}

console.log("=== SAFETY-UI TESTS ===");

const linkMock = { getBoundingClientRect: () => ({ top: 100, left: 100, bottom: 120, right: 200 }) };
BTL.getResolvedUrl = () => "https://example.com";

function getCard(payload) {
  BTL.previewUI.show(linkMock, null, false);
  BTL.previewUI.updateNetworkResult(payload);
  const host = BTL.previewUI.getHost();
  return findElementByClass(host, 'btl-card');
}

runTest("UI-001: Renders Header, Dest, Link Type, Safety", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  
  const labels = findElementsByClass(card, 'btl-label').map(e => e.textContent);
  assert.ok(labels.includes('WHERE IT GOES') || labels.includes('OPENS'));
  assert.ok(labels.includes('LINK TYPE'));
  assert.ok(labels.includes('SAFETY'));
});

runTest("UI-002: Link Type shows Direct link when no signals", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  const textMains = findElementsByClass(card, 'btl-text-main');
  assert.ok(textMains.some(t => t.textContent.includes('Direct link')));
});

runTest("UI-003: Safety bullet list renders correctly", () => {
  const card = getCard({
    originalUrl: 'http://example.com/file.exe',
    safetyEvidence: { 
      status: 'UNUSUAL_CHARACTERISTICS', 
      signals: [],
      userGuidance: {
        displaySignals: [{ id: 'SUSPICIOUS_FILE_EXT', label: 'Suspicious file extension' }],
        whyText: null,
        actionText: null
      }
    }
  });
  const lists = findElementsByClass(card, 'btl-bullet-list');
  const bullets = lists[0].children.map(c => c.textContent);
  assert.ok(bullets.some(t => t.includes('Suspicious file extension')));
});

runTest("UI-004: Why should I care renders correctly", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      status: 'UNUSUAL_CHARACTERISTICS', 
      signals: [],
      userGuidance: {
        displaySignals: [],
        whyText: 'This is a test rationale.',
        actionText: null
      }
    }
  });
  const labels = findElementsByClass(card, 'btl-label');
  assert.ok(labels.some(l => l.textContent === 'WHY SHOULD I CARE?'));
  
  const whyTexts = findElementsByClass(card, 'btl-why-text');
  assert.ok(whyTexts.some(t => t.textContent === 'This is a test rationale.'));
});

runTest("UI-005: What should I do renders correctly", () => {
  const card = getCard({
    originalUrl: 'https://example.com',
    safetyEvidence: { 
      status: 'UNUSUAL_CHARACTERISTICS', 
      signals: [],
      userGuidance: {
        displaySignals: [],
        whyText: null,
        actionText: 'Check the destination domain before continuing.'
      }
    }
  });
  const labels = findElementsByClass(card, 'btl-label');
  assert.ok(labels.some(l => l.textContent === 'WHAT SHOULD I DO?'));
  
  const actionTexts = findElementsByClass(card, 'btl-why-text'); // They use the same class for text rendering
  assert.ok(actionTexts.some(t => t.textContent === 'Check the destination domain before continuing.'));
});

console.log(`\nResults: ${passed}/${total} passed`);
if (passed !== total) process.exit(1);
