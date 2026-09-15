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
  for (let child of el.children) {
    let found = findElementByClass(child, className);
    if (found) return found;
  }
  return null;
}

function findElementsByClass(el, className) {
  let results = [];
  if (el.className && el.className.includes(className)) results.push(el);
  for (let child of el.children) {
    results = results.concat(findElementsByClass(child, className));
  }
  return results;
}

console.log("=== SAFETY-UI TESTS ===");

const linkMock = { getBoundingClientRect: () => ({ top: 100, left: 100, bottom: 120, right: 200 }) };
BTL.getResolvedUrl = () => "https://example.com";

// Helper to extract the safety section and its details
function getSafetyUI(payload) {
  BTL.previewUI.show(linkMock, null, false);
  BTL.previewUI.updateNetworkResult(payload);
  const host = BTL.previewUI.getHost();
  const card = findElementByClass(host, 'btl-card');
  const safetySection = findElementByClass(card, 'btl-safety-section');
  if (!safetySection) return null;
  
  const statusEl = findElementByClass(safetySection, 'btl-safety-status');
  const whyPanel = findElementByClass(safetySection, 'btl-why-panel');
  
  return { safetySection, statusEl, whyPanel };
}

runTest("UI-001: NO_SIGNALS_DETECTED uses dash and Nothing unusual found", () => {
  const ui = getSafetyUI({
    originalUrl: 'https://example.com',
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  assert.ok(ui);
  assert.ok(ui.statusEl.textContent.includes('—'));
  assert.ok(ui.statusEl.textContent.includes('Nothing unusual found'));
  assert.ok(!ui.whyPanel.open);
});

runTest("UI-002: INFORMATIONAL uses ℹ icon", () => {
  const ui = getSafetyUI({
    originalUrl: 'https://example.com',
    safetyEvidence: { status: 'INFORMATIONAL', signals: [{ tier: 'A', detail: 'test' }], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  assert.ok(ui.statusEl.textContent.includes('ℹ'));
  assert.ok(ui.statusEl.textContent.includes('Some things to know'));
  assert.ok(!ui.whyPanel.open);
});

runTest("UI-003: UNUSUAL_CHARACTERISTICS uses ⚠ icon and is expanded", () => {
  const ui = getSafetyUI({
    originalUrl: 'https://example.com',
    safetyEvidence: { status: 'UNUSUAL_CHARACTERISTICS', signals: [{ tier: 'B', detail: 'test' }], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  assert.ok(ui.statusEl.textContent.includes('⚠'));
  assert.ok(ui.statusEl.textContent.includes('Some unusual characteristics'));
  assert.strictEqual(ui.whyPanel.open, 'true');
});

runTest("UI-004: STRONG_WARNING uses 🚨 icon and is expanded", () => {
  const ui = getSafetyUI({
    originalUrl: 'https://example.com',
    safetyEvidence: { status: 'STRONG_WARNING', signals: [{ tier: 'D', detail: 'threat' }], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  assert.ok(ui.statusEl.textContent.includes('🚨'));
  assert.ok(ui.statusEl.textContent.includes('Known threat reported'));
  assert.strictEqual(ui.whyPanel.open, 'true');
});

runTest("UI-005: Why panel lists signals with bullet points", () => {
  const ui = getSafetyUI({
    originalUrl: 'https://example.com',
    safetyEvidence: { status: 'INFORMATIONAL', signals: [{ tier: 'A', detail: 'Sig 1' }], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  const liElements = findElementsByClass(ui.whyPanel, 'btl-why-li');
  assert.ok(liElements.some(li => li.textContent.includes('Sig 1')));
});

console.log(`\nResults: ${passed}/${total} passed`);
if (passed !== total) process.exit(1);
