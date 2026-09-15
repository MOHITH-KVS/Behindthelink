const fs = require('fs');
const vm = require('vm');

function createMockElement(tag, id = '') {
  return {
    tagName: tag.toUpperCase(),
    id,
    href: tag === 'a' ? 'https://example.com' : '',
    children: [],
    appendChild(child) { this.children.push(child); child.parentNode = this; },
    closest(selector) {
      if (selector === 'a[href]' && this.tagName === 'A') return this;
      return null;
    },
    contains(child) {
      if (!child) return false;
      if (this === child) return true;
      let p = child.parentNode;
      while (p) {
        if (p === this) return true;
        p = p.parentNode;
      }
      return false;
    },
    setAttribute(k, v) { this[k] = v; },
    getAttribute(attr) { return this[attr] || null; }
  };
}

const mockDoc = {
  createElement: createMockElement,
  body: createMockElement('body')
};

const linkA = createMockElement('a', 'linkA');
const linkB = createMockElement('a', 'linkB');
mockDoc.body.appendChild(linkA);
mockDoc.body.appendChild(linkB);

const chromeMock = {
  runtime: {
    sendMessage: (msg, cb) => { if (cb) cb(); },
    lastError: null
  }
};

const sandbox = {
  window: {},
  document: mockDoc,
  Date: Date,
  Math: Math,
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  chrome: chromeMock,
  console: console,
  BehindTheLink: {
    HOVER_DELAY: 450,
    getResolvedUrl: (el) => el.href,
    isEligible: (el) => true,
    shouldInspectLink: () => true,
    urlAnalyzer: { analyzeUrl: () => ({}) },
    previewUI: {
      show: () => { sandbox.cardVisible = true; },
      hide: () => { sandbox.cardVisible = false; },
      updateNetworkResult: () => {},
      getHost: () => sandbox.hostElement
    }
  },
  cardVisible: false,
  hostElement: createMockElement('div')
};
sandbox.hostElement.setAttribute('data-behindthelink', 'host');
mockDoc.body.appendChild(sandbox.hostElement);
sandbox.window.BehindTheLink = sandbox.BehindTheLink;
vm.createContext(sandbox);

const hoverCode = fs.readFileSync('./src/content/hover-manager.js', 'utf8');
vm.runInContext(hoverCode, sandbox);

async function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function dispatchEvent(type, target, relatedTarget) {
  const ev = { target, relatedTarget, closest: target.closest.bind(target) };
  if (type === 'mouseover') sandbox.BehindTheLink.hoverManager.handleMouseOver(ev);
  if (type === 'mouseout') sandbox.BehindTheLink.hoverManager.handleMouseOut(ev);
  if (type === 'click') sandbox.BehindTheLink.hoverManager.handleClick(ev);
}

async function runTests() {
  let passed = 0; let total = 0;
  function assert(actual, expected, msg) {
    total++;
    if (actual === expected) { console.log('[PASS] ' + msg); passed++; }
    else { console.error('[FAIL] ' + msg + ' | Expected ' + expected + ', got ' + actual); }
  }

  const host = sandbox.hostElement;
  const body = mockDoc.body;

  console.log("--- RUNNING HOVER LIFECYCLE TESTS ---");

  // CASE A: anchor hover -> card hover -> remains open
  sandbox.cardVisible = false;
  dispatchEvent('mouseover', linkA, body);
  await sleep(500); // let showTimer expire
  assert(sandbox.cardVisible, true, 'CASE A: Card shows on anchor hover');
  
  dispatchEvent('mouseout', linkA, host); // moving to card
  dispatchEvent('mouseover', host, linkA);
  await sleep(300); // wait past grace period
  assert(sandbox.cardVisible, true, 'CASE A: Card remains open after moving from anchor to card');

  // CASE C: card hover -> anchor hover -> remains open
  dispatchEvent('mouseout', host, linkA); // moving back to anchor
  dispatchEvent('mouseover', linkA, host);
  await sleep(300);
  assert(sandbox.cardVisible, true, 'CASE C: Card remains open after moving from card back to anchor');

  // CASE D: leaving both anchor and card -> closes after grace period
  dispatchEvent('mouseout', linkA, body); // leaving anchor to body
  dispatchEvent('mouseover', body, linkA);
  await sleep(100);
  assert(sandbox.cardVisible, true, 'CASE D: Card remains open during grace period');
  await sleep(200); // 100+200 > 200ms grace period
  assert(sandbox.cardVisible, false, 'CASE D: Card closes after grace period expires');

  // CASE E: leave anchor -> enter card before grace period -> close timer cancelled
  dispatchEvent('mouseover', linkA, body);
  await sleep(500);
  dispatchEvent('mouseout', linkA, body); // leaves to body accidentally
  dispatchEvent('mouseover', body, linkA);
  await sleep(100); // 100ms < 200ms
  dispatchEvent('mouseout', body, host);
  dispatchEvent('mouseover', host, body); // enters card
  await sleep(200);
  assert(sandbox.cardVisible, true, 'CASE E: Close timer cancelled upon entering card');

  // CASE F: Details click does not navigate the underlying page
  let intentTriggered = false;
  sandbox.chrome.runtime.sendMessage = (msg) => { if (msg.type === 'LINK_CLICK_INTENT') intentTriggered = true; };
  dispatchEvent('click', host, null);
  assert(intentTriggered, false, 'CASE F: Click inside card does not trigger LINK_CLICK_INTENT');

  // CASE G: rapid hover between different links does not leave stale cards
  sandbox.cardVisible = false;
  dispatchEvent('mouseover', linkA, body);
  await sleep(100); // hover linkA briefly
  dispatchEvent('mouseout', linkA, linkB);
  dispatchEvent('mouseover', linkB, linkA); // immediately hover linkB
  await sleep(500);
  assert(sandbox.cardVisible, true, 'CASE G: New link card is visible');

  // Clean up
  dispatchEvent('mouseout', linkB, body);
  await sleep(300);

  console.log(`\nRESULTS: ${passed}/${total} passed`);
}

runTests().catch(console.error);
