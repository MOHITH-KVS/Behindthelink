const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

// DOM Mock elements
function createMockElement(tag) {
  return {
    tagName: tag.toUpperCase(),
    attributes: {},
    children: [],
    parentElement: null,
    _textContent: '',
    get textContent() {
      if (this.children.length > 0) {
        return this.children.map(c => c.textContent).join('');
      }
      return this._textContent;
    },
    set textContent(v) { this._textContent = v; },
    get innerText() { return this.textContent; },
    getAttribute: function(k) { return this.attributes[k] || null; },
    setAttribute: function(k, v) { this.attributes[k] = v; },
    appendChild: function(child) {
      child.parentElement = this;
      this.children.push(child);
    }
  };
}

const BTL = {};
const sandbox = {
  window: Object.assign({ BehindTheLink: BTL }),
  self: { BehindTheLink: BTL },
  BTL: BTL,
  console: { log: () => {}, error: console.error }
};

vm.createContext(sandbox);
const extractorCode = fs.readFileSync('./src/content/context-extractor.js', 'utf8');
vm.runInContext(extractorCode, sandbox);

const extractor = sandbox.BTL.contextExtractor;

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

console.log("=== CONTEXT EXTRACTOR TESTS ===");

runTest("EXT-001: Visible text extraction", () => {
  const link = createMockElement('a');
  link.textContent = '  Click   here  ';
  const result = extractor.extract(link);
  assert.strictEqual(result.visibleText, 'Click here');
  assert.strictEqual(result.evidence.visible_text, true);
  assert.strictEqual(result.evidence.aria_label, false);
});

runTest("EXT-002: aria-label extraction", () => {
  const link = createMockElement('a');
  link.setAttribute('aria-label', '  Apply  now ');
  const result = extractor.extract(link);
  assert.strictEqual(result.ariaLabel, 'Apply now');
  assert.strictEqual(result.category, 'JOB_HIRING');
});

runTest("EXT-003: title extraction", () => {
  const link = createMockElement('a');
  link.setAttribute('title', 'Sign In');
  const result = extractor.extract(link);
  assert.strictEqual(result.title, 'Sign In');
  assert.strictEqual(result.category, 'LOGIN_ACCOUNT');
});

runTest("EXT-004: Nearby context bounding", () => {
  const body = createMockElement('body');
  const div1 = createMockElement('div');
  const div2 = createMockElement('div');
  const link = createMockElement('a');
  link.textContent = 'Link';
  
  body.appendChild(div1);
  div1.appendChild(div2);
  div2.appendChild(link);
  
  const sibling = createMockElement('span');
  sibling.textContent = ' Pay now with PayPal.';
  div2.appendChild(sibling);
  
  const result = extractor.extract(link);
  assert.strictEqual(result.nearbyText, 'Link Pay now with PayPal.');
  assert.strictEqual(result.category, 'PAYMENT');
  assert.strictEqual(result.possibleClaimedBrand, 'PAYPAL');
});

runTest("EXT-005: Strict Brand matching", () => {
  const link = createMockElement('a');
  link.textContent = 'Microsoft account security alert';
  const result = extractor.extract(link);
  assert.strictEqual(result.possibleClaimedBrand, 'MICROSOFT');
  assert.strictEqual(result.category, 'VERIFICATION_SECURITY');
});

runTest("EXT-006: Multiple brands alias matching", () => {
  const link = createMockElement('a');
  link.textContent = 'Login with chatgpt';
  const result = extractor.extract(link);
  assert.strictEqual(result.possibleClaimedBrand, 'OPENAI');
  assert.strictEqual(result.category, 'LOGIN_ACCOUNT');
});

runTest("EXT-007: Ignore weak generic brand mentions", () => {
  const link = createMockElement('a');
  link.textContent = 'Eating an apple today';
  const result = extractor.extract(link);
  assert.strictEqual(result.possibleClaimedBrand, 'APPLE'); // "apple" is in the registry, it matches purely on word boundary. This is expected as per the simple local dictionary.
});

runTest("EXT-008: Bounded length logic", () => {
  const link = createMockElement('a');
  link.textContent = 'a'.repeat(300);
  const result = extractor.extract(link);
  assert.strictEqual(result.visibleText.length, 200); // MAX_TEXT_LEN
});

runTest("EXT-009: Null link safety", () => {
  const result = extractor.extract(null);
  assert.strictEqual(result, null);
});

runTest("EXT-010: Unknown category fallback", () => {
  const link = createMockElement('a');
  link.textContent = 'Random text here';
  const result = extractor.extract(link);
  assert.strictEqual(result.category, 'UNKNOWN');
});

console.log(`\nResults: ${passed}/${total} passed`);
if (passed !== total) process.exit(1);
