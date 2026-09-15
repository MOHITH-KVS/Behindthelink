const fs = require('fs');
const vm = require('vm');

function createMockElement(tag) {
  return {
    tagName: tag.toUpperCase(),
    className: '',
    style: {},
    children: [],
    textContent: '',
    appendChild(child) { this.children.push(child); child.parentNode = this; },
    replaceChildren() { this.children = []; },
    classList: {
      add(c) { this.addedClass = c; },
      remove(c) { this.removedClass = c; }
    },
    setAttribute(k, v) { this[k] = v; },
    getBoundingClientRect() { return { top: 0, left: 0, bottom: 0, right: 0, width: 0, height: 0 }; },
    attachShadow() { return this; }
  };
}

const mockDoc = {
  createElement: createMockElement,
  body: createMockElement('body')
};

const sandbox = {
  window: { innerWidth: 1000, innerHeight: 1000 },
  document: mockDoc,
  URL: URL,
  requestAnimationFrame: (cb) => setTimeout(cb, 0),
  Date: Date,
  Math: Math,
  setTimeout: setTimeout,
  BehindTheLink: {
    CARD_WIDTH: 320,
    ANIMATION_DURATION: 150,
    CARD_GAP: 8,
    VIEWPORT_PADDING: 12,
    getResolvedUrl: (el) => el.href || 'https://example.com/start'
  }
};

sandbox.window.BehindTheLink = sandbox.BehindTheLink;
vm.createContext(sandbox);

const uiCode = fs.readFileSync('./src/content/preview-ui.js', 'utf8');
vm.runInContext(uiCode, sandbox);

async function runUITests() {
  let passed = 0; let total = 0;
  function assert(actual, expected, msg) {
    total++;
    if (actual === expected) { console.log('[PASS] ' + msg); passed++; }
    else { console.error('[FAIL] ' + msg + ' | Expected ' + expected + ', got ' + actual); }
  }

  const BTL = sandbox.BehindTheLink;
  const link = createMockElement('a');
  link.href = 'https://example.com/start';
  
  function getCard() {
    const host = mockDoc.body.children.find(c => c.tagName === 'DIV' && c['data-behindthelink'] === 'host');
    if (!host) return null;
    return host.children.find(c => c.className === 'btl-card');
  }

  function getCardTextContent(element) {
    if (!element) return '';
    let text = element.textContent || '';
    for (const child of element.children) {
      text += ' ' + getCardTextContent(child);
    }
    return text;
  }

  function getPrimaryText(card) {
    // text content minus details
    let text = '';
    for (const child of card.children) {
      if (child.className !== 'btl-details' && child.tagName !== 'DETAILS') {
        text += ' ' + getCardTextContent(child);
      }
    }
    return text;
  }

  function getDetailsText(card) {
    let details = card.children.find(c => c.className === 'btl-details' || c.tagName === 'DETAILS');
    return details ? getCardTextContent(details) : '';
  }

  console.log("--- RUNNING UX RESET UI COMPONENT TESTS ---");

  // CASE 1: Normal Link (No redirect detected, no signals)
  BTL.previewUI.show(link, { hostname: 'example.com' }, true);
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://example.com/page',
    localSignals: { hostname: 'example.com' },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    browserObservation: { status: 'NONE' }
  });
  let primary = getPrimaryText(getCard());
  let details = getDetailsText(getCard());
  assert(primary.includes('🌐 example.com'), true, '9. Source domain always visible');
  assert(primary.includes('OPENS'), true, '1. normal link shows OPENS');
  assert(primary.includes('✓ Destination checked'), true, '1. normal link explanation');
  assert(primary.includes('No redirect detected'), false, '2. No redirect detected removed from primary UI');
  assert(primary.includes('LINK SIGNALS'), false, '14. no empty Signals section');
  assert(details.includes('More info ▾'), true, '12. "More info" is present and optional');

  // CASE 2: Tracking Link
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://example.com/page?utm_source=test',
    localSignals: { hostname: 'example.com', trackingParams: ['utm_source'] },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    browserObservation: { status: 'NONE' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes('LINK SIGNALS'), true, '2. tracking link shows LINK SIGNALS');
  assert(primary.includes('Contains tracking information'), true, '2. tracking link shows tracking text');

  // CASE 3 & 5: Shortened + Confirmed Redirect
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://youtu.be/abc',
    localSignals: { hostname: 'youtu.be', isShortener: true },
    networkEvidence: { status: 'HTTP_REDIRECT_OBSERVED', redirectTarget: 'https://www.youtube.com/watch?v=abc' },
    browserObservation: { status: 'NONE' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes('www.youtube.com/watch'), true, '10. actual redirect target path is represented correctly');
  assert(primary.includes('Destination checked'), true, '3. confirmed redirect uses "Destination checked"');
  assert(primary.includes('Shortened link'), true, '5. shortened + confirmed shows shortener signal');
  assert(!primary.includes('HTTP_REDIRECT_OBSERVED'), true, '11. internal status enums are absent from primary UI');

  // CASE 4 & 6: Shortener + Cannot verify
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://tinyurl.com/abc',
    localSignals: { hostname: 'tinyurl.com', isShortener: true },
    networkEvidence: { status: 'FAILED' },
    browserObservation: { status: 'NONE' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes("WHERE IT GOES"), true, '4. failed verification uses WHERE IT GOES');
  assert(primary.includes("Destination couldn't be verified"), true, '4. failed verification says Destination couldn\'t be verified');
  assert(primary.includes("We couldn't verify where this link leads."), true, '13. important explanation is visible without opening More info');
  assert(primary.includes("Shortened link"), true, '6. shortened + failed shows shortener signal');

  // CASE 7: Embedded URL
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://linkedin.com/safety?url=https://example.org',
    localSignals: { hostname: 'linkedin.com', embeddedCandidates: ['https://example.org'] },
    networkEvidence: { status: 'FAILED' },
    browserObservation: { status: 'NONE' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes('THIS LINK CONTAINS ANOTHER LINK'), true, '7. embedded candidate header is correct');
  assert(primary.includes('example.org'), true, '7. embedded candidate URL is shown');
  assert(primary.includes("We found another link inside this URL, but couldn't confirm that you'll be sent there."), true, '7. embedded candidate shows proper disclaimer');

  // CASE 8: Browser Observed
  const yesterday = Date.now() - (24 * 60 * 60 * 1000) - 1000;
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://example.com/login',
    localSignals: { hostname: 'example.com' },
    networkEvidence: { status: 'FAILED' },
    browserObservation: { status: 'STRONG_CORRELATION', observedLatestUrl: 'https://example.com/dashboard' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes('OPENS'), true, '8. browser observed shows OPENS');
  assert(primary.includes('example.com/dashboard'), true, '8. browser observed shows target with path');
  assert(primary.includes('✓ Previously observed'), true, '8. browser observed uses correct text');

  // CASE 8B: Priority of HTTP over Browser Observation
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://example.com/login',
    localSignals: { hostname: 'example.com' },
    networkEvidence: { status: 'HTTP_REDIRECT_OBSERVED', redirectTarget: 'https://example.com/fresh' },
    browserObservation: { status: 'STRONG_CORRELATION', observedLatestUrl: 'https://example.com/stale' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes('example.com/fresh'), true, '8B. HTTP evidence overrides browser observation URL');
  assert(primary.includes('✓ Destination checked'), true, '8B. HTTP evidence overrides browser observation text');

  // CASE 9: Risk LOW
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://xn--example.com',
    localSignals: { hostname: 'xn--example.com' },
    riskSignals: { severity: 'LOW', signals: [{ type: 'PUNYCODE_DOMAIN', label: 'Uses an encoded domain name' }] },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    browserObservation: { status: 'NONE' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes('SECURITY'), true, 'Risk LOW shows SECURITY block');
  assert(primary.includes('Uses an encoded domain name'), true, 'Risk LOW lists specific signal');
  assert(!primary.includes('⚠ This link has a few unusual characteristics'), true, 'Risk LOW does NOT show MEDIUM warning');

  // CASE 10: Risk MEDIUM
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://192.168.1.10/login',
    localSignals: { hostname: '192.168.1.10' },
    riskSignals: { 
      severity: 'MEDIUM', 
      signals: [
        { type: 'IP_HOST', label: 'Uses an IP address' },
        { type: 'SENSITIVE_ACTION_PATH', label: 'Contains a sign-in or account action' }
      ] 
    },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    browserObservation: { status: 'NONE' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes('SECURITY'), true, 'Risk MEDIUM shows SECURITY block');
  assert(primary.includes('⚠ This link has a few unusual characteristics'), true, 'Risk MEDIUM shows proper warning text');
  assert(primary.includes('Uses an IP address'), true, 'Risk MEDIUM lists specific signal 1');
  assert(primary.includes('Contains a sign-in or account action'), true, 'Risk MEDIUM lists specific signal 2');

  // CASE 11: Network Failure + Clean URL (Case M)
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://example.com',
    localSignals: { hostname: 'example.com' },
    riskSignals: { severity: 'NONE', signals: [] },
    networkEvidence: { status: 'FAILED' },
    browserObservation: { status: 'NONE' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes("Destination couldn't be verified"), true, 'Case M: Clean network failure shows correct dest wording');
  assert(!primary.includes('SECURITY'), true, 'Case M: Clean network failure does NOT show SECURITY block');

  // CASE 12: Network Failure + Local Risk Signal (Case L)
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://xn--example.com',
    localSignals: { hostname: 'xn--example.com' },
    riskSignals: { severity: 'LOW', signals: [{ type: 'PUNYCODE_DOMAIN', label: 'Uses an encoded domain name' }] },
    networkEvidence: { status: 'FAILED' },
    browserObservation: { status: 'NONE' }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes("Destination couldn't be verified"), true, 'Case L: Risk network failure shows correct dest wording');
  assert(primary.includes('SECURITY'), true, 'Case L: Risk network failure still shows SECURITY block');
  assert(primary.includes('Uses an encoded domain name'), true, 'Case L: Risk network failure preserves evidence');

  console.log(`\nRESULTS: ${passed}/${total} passed`);
}

runUITests().catch(console.error);
