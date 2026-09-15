const fs = require('fs');
const vm = require('vm');

const serviceWorkerCode = fs.readFileSync('./src/background/service-worker.js', 'utf8');

const chromeMock = {
  storage: {
    local: {
      get: async () => ({}),
      set: async () => {},
      remove: async () => {}
    }
  },
  webNavigation: {
    onCreatedNavigationTarget: { addListener: (cb) => { sandbox.global.onCreatedNavigationTarget = cb; } },
    onBeforeNavigate: { addListener: (cb) => { sandbox.global.onBeforeNavigate = cb; } },
    onCommitted: { addListener: (cb) => { sandbox.global.onCommitted = cb; } },
    onErrorOccurred: { addListener: (cb) => { sandbox.global.onErrorOccurred = cb; } },
    onHistoryStateUpdated: { addListener: (cb) => { sandbox.global.onHistoryStateUpdated = cb; } }
  }
};

const BTL = {};
const sandbox = {
  window: { BehindTheLink: BTL },
  self: { BehindTheLink: BTL },
  URL: URL,
  decodeURIComponent: decodeURIComponent,
  chrome: chromeMock,
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  console: console,
  Map: Map,
  Set: Set,
  global: {}
};

vm.createContext(sandbox);
vm.runInContext('function normalizeUrl(u) { return u; }', sandbox);

let swExtract = serviceWorkerCode.substring(serviceWorkerCode.indexOf('// PHASE 1H.3 — BROWSER OBSERVATION ENGINE'));
swExtract += `
  // EXPOSE FOR TESTING
  global.clickIntents = clickIntents;
  global.activeSessions = activeSessions;
  global.newTabMappings = newTabMappings;
  global.evaluateAndConcludeSession = evaluateAndConcludeSession;
`;
vm.runInContext(swExtract, sandbox);

async function runCorrelationTests() {
  let passed = 0; let total = 0;
  function assert(actual, expected, msg) {
    total++;
    if (actual === expected) { console.log('[PASS] ' + msg); passed++; } 
    else { console.error('[FAIL] ' + msg + ' | Expected ' + expected + ', got ' + actual); }
  }

  let lastStored = null;
  sandbox.storeStrongObservation = async (sourceUrl, observedLatestUrl, evidence) => {
    lastStored = { sourceUrl, observedLatestUrl, evidence };
  };

  const simulateClick = (url, sourceTabId, timestampOffset = 0) => {
    sandbox.global.clickIntents.set(sourceTabId, { url, timestamp: Date.now() + timestampOffset });
  };

  const clear = () => { 
    lastStored = null; 
    sandbox.global.activeSessions.clear(); 
    sandbox.global.clickIntents.clear(); 
    sandbox.global.newTabMappings.clear(); 
  };

  console.log("--- RUNNING CORRELATION TESTS ---");

  // CASE A - Direct navigation
  clear();
  simulateClick('https://example.com/page', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com/page' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://example.com/page', transitionType: 'link' });
  sandbox.global.evaluateAndConcludeSession(1, 'timeout');
  assert(lastStored !== null, true, 'CASE A: Direct navigation accepted');
  assert(lastStored && lastStored.observedLatestUrl, 'https://example.com/page', 'CASE A: Latest URL correct');

  // CASE B - HTTP redirect
  clear();
  simulateClick('https://short.example/abc', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://short.example/abc' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://real.example/page', transitionType: 'link', transitionQualifiers: ['server_redirect'] });
  sandbox.global.evaluateAndConcludeSession(1, 'timeout');
  assert(lastStored !== null, true, 'CASE B: HTTP redirect accepted');

  // CASE C - Client redirect
  clear();
  simulateClick('https://example.com/go', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com/go' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://example.com/go', transitionType: 'link' });
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com/final' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://example.com/final', transitionType: 'link', transitionQualifiers: ['client_redirect'] });
  sandbox.global.evaluateAndConcludeSession(1, 'timeout');
  assert(lastStored !== null, true, 'CASE C: Client redirect accepted');
  assert(lastStored && lastStored.observedLatestUrl, 'https://example.com/final', 'CASE C: observedLatestUrl is final');

  // CASE D - Target=_blank
  clear();
  simulateClick('https://example.com', 1);
  sandbox.global.onCreatedNavigationTarget({ sourceTabId: 1, tabId: 2 });
  sandbox.global.onBeforeNavigate({ tabId: 2, frameId: 0, url: 'https://example.com' });
  sandbox.global.onCommitted({ tabId: 2, frameId: 0, url: 'https://google.com', transitionType: 'link', transitionQualifiers: ['server_redirect'] });
  sandbox.global.evaluateAndConcludeSession(2, 'timeout');
  assert(lastStored !== null, true, 'CASE D: Target=_blank accepted');

  // CASE E - Typed URL interruption
  clear();
  simulateClick('https://example.com', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://google.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://google.com', transitionType: 'typed' });
  assert(sandbox.global.activeSessions.has(1), false, 'CASE E: Session destroyed immediately on typed navigation');
  sandbox.global.evaluateAndConcludeSession(1, 'timeout');
  assert(lastStored, null, 'CASE E: Unrelated typed navigation NOT stored');

  // CASE F - Bookmark interruption
  clear();
  simulateClick('https://example.com', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://bookmark.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://bookmark.com', transitionType: 'auto_bookmark' });
  assert(lastStored, null, 'CASE F: Unrelated bookmark NOT stored');

  // CASE G - Generated navigation interruption
  clear();
  simulateClick('https://example.com', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://generated.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://generated.com', transitionType: 'generated' });
  assert(lastStored, null, 'CASE G: Generated navigation NOT stored');

  // CASE H - Different tab
  clear();
  simulateClick('https://example.com', 1);
  sandbox.global.onBeforeNavigate({ tabId: 2, frameId: 0, url: 'https://example.com' });
  sandbox.global.onCommitted({ tabId: 2, frameId: 0, url: 'https://example.com', transitionType: 'link' });
  sandbox.global.evaluateAndConcludeSession(2, 'timeout');
  assert(lastStored, null, 'CASE H: Different tab without onCreatedNavigationTarget NOT stored');

  // CASE I - Main-frame navigation only
  clear();
  simulateClick('https://example.com', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 1, url: 'https://example.com' });
  assert(sandbox.global.activeSessions.has(1), false, 'CASE I: Sub-frame navigation does not start session');

  // CASE J - Broken continuity (URL mismatch/no redirect qualifier on second commit)
  clear();
  simulateClick('https://example.com', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://example.com', transitionType: 'link' });
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://other.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://other.com', transitionType: 'link' });
  assert(lastStored !== null && lastStored.observedLatestUrl === 'https://example.com', true, 'CASE J: First valid commit is stored, subsequent unrelated commits ignored');

  // CASE K - URL mismatch on start
  clear();
  simulateClick('https://example.com', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://other.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://other.com', transitionType: 'link' });
  sandbox.global.evaluateAndConcludeSession(1, 'timeout');
  assert(lastStored, null, 'CASE K: URL mismatch without redirect qualifier on start is NOT stored');

  // CASE M - Click intent expiration
  clear();
  simulateClick('https://example.com', 1, -4000); // 4 seconds ago
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com' });
  assert(sandbox.global.activeSessions.has(1), false, 'CASE M: Expired click intent does not start session');

  // CASE N - Multiple rapid click intents cross contamination
  clear();
  simulateClick('https://example.com/one', 1);
  sandbox.global.onCreatedNavigationTarget({ sourceTabId: 1, tabId: 2 });
  simulateClick('https://example.com/two', 1);
  sandbox.global.onCreatedNavigationTarget({ sourceTabId: 1, tabId: 3 });
  sandbox.global.onBeforeNavigate({ tabId: 2, frameId: 0, url: 'https://example.com/three' });
  assert(sandbox.global.activeSessions.has(2), false, 'CASE N: Unmatched target URL is not associated with new tab');

  // CASE P - Navigation error
  clear();
  simulateClick('https://example.com', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com' });
  sandbox.global.onErrorOccurred({ tabId: 1, frameId: 0, url: 'https://example.com', error: 'net::ERR_FAILED' });
  assert(lastStored, null, 'CASE P: Navigation error destroys session');
  assert(sandbox.global.activeSessions.has(1), false, 'CASE P: Session destroyed');

  // CASE Q - Successful navigation finalizes immediately
  clear();
  simulateClick('https://example.com/q', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com/q' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://example.com/q', transitionType: 'link', transitionQualifiers: [] });
  assert(lastStored !== null, true, 'CASE Q: Observation stored immediately on strong commit');
  assert(sandbox.global.activeSessions.has(1), false, 'CASE Q: Session closed immediately');

  // CASE R - Back after successful navigation cannot overwrite
  clear();
  simulateClick('https://example.com/r', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com/r' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://example.com/r', transitionType: 'link', transitionQualifiers: [] });
  let savedR = lastStored;
  // Simulate Back button (onBeforeNavigate/onCommitted without click intent)
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com/test-lab.html' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://example.com/test-lab.html', transitionType: 'link', transitionQualifiers: ['forward_back'] });
  assert(lastStored === savedR, true, 'CASE R: Back button navigation ignored after session finalization');

  // CASE S - Typed navigation after successful navigation cannot overwrite
  clear();
  simulateClick('https://example.com/s', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com/s' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://example.com/s', transitionType: 'link', transitionQualifiers: [] });
  let savedS = lastStored;
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://google.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://google.com', transitionType: 'typed', transitionQualifiers: [] });
  assert(lastStored === savedS, true, 'CASE S: Typed navigation ignored after session finalization');

  // CASE T - Bookmark after successful navigation cannot overwrite
  clear();
  simulateClick('https://example.com/t', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com/t' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://example.com/t', transitionType: 'link', transitionQualifiers: [] });
  let savedT = lastStored;
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://bookmark.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://bookmark.com', transitionType: 'auto_bookmark', transitionQualifiers: [] });
  assert(lastStored === savedT, true, 'CASE T: Bookmark ignored after session finalization');

  // CASE U - Timeout still cleans up weak/unresolved sessions
  clear();
  simulateClick('https://example.com/u', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://other.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://other.com', transitionType: 'link', transitionQualifiers: [] }); // not strong
  assert(lastStored, null, 'CASE U: Weak correlation not stored immediately');
  sandbox.global.evaluateAndConcludeSession(1, 'session_timeout');
  assert(lastStored, null, 'CASE U: Weak correlation discarded on timeout');
  assert(sandbox.global.activeSessions.has(1), false, 'CASE U: Session cleaned up by timeout');

  // CASE V - target=_blank remains isolated
  clear();
  simulateClick('https://example.com/v', 1);
  sandbox.global.onCreatedNavigationTarget({ sourceTabId: 1, tabId: 2 });
  sandbox.global.onBeforeNavigate({ tabId: 2, frameId: 0, url: 'https://example.com/v' });
  sandbox.global.onCommitted({ tabId: 2, frameId: 0, url: 'https://example.com/v', transitionType: 'link', transitionQualifiers: [] });
  assert(lastStored !== null, true, 'CASE V: target=_blank stored immediately');
  let savedV = lastStored;
  sandbox.global.onBeforeNavigate({ tabId: 3, frameId: 0, url: 'https://unrelated.com' });
  sandbox.global.onCommitted({ tabId: 3, frameId: 0, url: 'https://unrelated.com', transitionType: 'link', transitionQualifiers: [] });
  assert(lastStored === savedV, true, 'CASE V: Unrelated tab navigation ignored');

  // CASE W - redirect remains continuous
  clear();
  simulateClick('https://example.com/w', 1);
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example.com/w' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://final.com', transitionType: 'link', transitionQualifiers: ['server_redirect'] });
  assert(lastStored !== null, true, 'CASE W: Redirect stored immediately');
  let savedW = lastStored;
  sandbox.global.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://other.com' });
  sandbox.global.onCommitted({ tabId: 1, frameId: 0, url: 'https://other.com', transitionType: 'link', transitionQualifiers: [] });
  assert(lastStored === savedW, true, 'CASE W: Unrelated navigation after completion ignored');

  console.log('\\nRESULTS: ' + passed + '/' + total + ' passed');
}

runCorrelationTests().catch(console.error);
