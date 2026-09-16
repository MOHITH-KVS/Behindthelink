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
    addEventListener() {},
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
    let text = '';
    for (const child of card.children) {
      if (child.className !== 'btl-details' && child.tagName !== 'DETAILS' && child.className !== 'btl-why-panel') {
        text += ' ' + getCardTextContent(child);
      }
    }
    return text;
  }

  function getDetailsText(card) {
    let details = card.children.find(c => c.className === 'btl-details' || c.tagName === 'DETAILS');
    return details ? getCardTextContent(details) : '';
  }
  
  function getWhyPanelText(card) {
    let safetySec = card.children.find(c => c.className && c.className.includes('btl-safety-section'));
    if (!safetySec) return '';
    let why = safetySec.children.find(c => c.className === 'btl-why-panel');
    return why ? getCardTextContent(why) : '';
  }

  console.log("--- RUNNING UX RESET UI COMPONENT TESTS ---");

  // CASE 1: Normal Link (No redirect detected, no signals)
  BTL.previewUI.show(link, { hostname: 'example.com' }, true);
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://example.com/page',
    localSignals: { hostname: 'example.com' },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  let primary = getPrimaryText(getCard());
  let details = getDetailsText(getCard());
  let why = getWhyPanelText(getCard());
  
  assert(primary.includes('🌐 example.com'), true, '9. Source domain always visible');
  assert(primary.includes('OPENS'), true, '1. normal link shows OPENS');
  assert(primary.includes('✓ Destination checked'), true, '1. normal link explanation');
  assert(primary.includes('No redirect detected'), false, '2. No redirect detected removed from primary UI');
  assert(primary.includes('SAFETY'), true, 'SAFETY section exists');
  assert(primary.includes('LINK SIGNALS'), false, 'LINK SIGNALS is NOT rendered');
  assert(primary.includes('SECURITY'), false, 'SECURITY is NOT rendered as a separate block');
  assert(details.includes('More info ▾'), true, '12. "More info" is present and optional');

  // CASE 2: Tracking Link
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://example.com/page?utm_source=test',
    localSignals: { hostname: 'example.com', trackingParams: ['utm_source'] },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { status: 'INFORMATIONAL', signals: [{ tier: 'A', detail: 'Contains tracking information' }], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  primary = getPrimaryText(getCard());
  why = getWhyPanelText(getCard());
  assert(primary.includes('SAFETY'), true, '2. tracking link shows SAFETY section');
  assert(primary.includes('Some things to know'), true, '2. tracking link shows informational status');
  assert(why.includes('Contains tracking information'), true, '2. tracking link shows tracking text in Why panel');

  // CASE 3 & 5: Shortened + Confirmed Redirect
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://youtu.be/abc',
    localSignals: { hostname: 'youtu.be', isShortener: true },
    networkEvidence: { status: 'HTTP_REDIRECT_OBSERVED', redirectTarget: 'https://www.youtube.com/watch?v=abc' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { status: 'INFORMATIONAL', signals: [{ tier: 'A', detail: 'Shortened link' }], assessmentBasis: 'LOCAL_WITH_NETWORK', limitations: [] }
  });
  primary = getPrimaryText(getCard());
  why = getWhyPanelText(getCard());
  assert(primary.includes('www.youtube.com/watch'), true, '10. actual redirect target path is represented correctly');
  assert(primary.includes('Destination checked'), true, '3. confirmed redirect uses "Destination checked"');
  assert(why.includes('Shortened link'), true, '5. shortened + confirmed shows shortener signal in Why panel');
  assert(!primary.includes('HTTP_REDIRECT_OBSERVED'), true, '11. internal status enums are absent from primary UI');

  // CASE 4 & 6: Shortener + Cannot verify
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://tinyurl.com/abc',
    localSignals: { hostname: 'tinyurl.com', isShortener: true },
    networkEvidence: { status: 'FAILED' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { status: 'INFORMATIONAL', signals: [{ tier: 'A', detail: 'Shortened link' }], assessmentBasis: 'INCOMPLETE', limitations: ["Destination is hidden behind a shortener and could not be confirmed"] }
  });
  primary = getPrimaryText(getCard());
  why = getWhyPanelText(getCard());
  assert(primary.includes("WHERE IT GOES"), true, '4. failed verification uses WHERE IT GOES');
  assert(primary.includes("Destination couldn't be verified"), true, '4. failed verification says Destination couldn\'t be verified');
  assert(primary.includes("We couldn't verify where this link leads."), true, '13. important explanation is visible without opening More info');
  assert(why.includes("Shortened link"), true, '6. shortened + failed shows shortener signal in Why panel');
  assert(why.includes("Destination is hidden"), true, 'Why? panel remains available and shows limitations');

  // CASE 7: Embedded URL
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://linkedin.com/safety?url=https://example.org',
    localSignals: { hostname: 'linkedin.com', embeddedCandidates: ['https://example.org'] },
    networkEvidence: { status: 'FAILED' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
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
    browserObservation: { status: 'STRONG_CORRELATION', observedLatestUrl: 'https://example.com/dashboard' },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [], assessmentBasis: 'LOCAL_WITH_OBSERVATION', limitations: [] }
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
    browserObservation: { status: 'STRONG_CORRELATION', observedLatestUrl: 'https://example.com/stale' },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [], assessmentBasis: 'LOCAL_WITH_NETWORK_AND_OBSERVATION', limitations: [] }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes('example.com/fresh'), true, '8B. HTTP evidence overrides browser observation URL');
  assert(primary.includes('✓ Destination checked'), true, '8B. HTTP evidence overrides browser observation text');

  // CASE 9: Risk LOW -> INFORMATIONAL
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://xn--example.com',
    localSignals: { hostname: 'xn--example.com' },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { status: 'INFORMATIONAL', signals: [{ tier: 'B', detail: 'Uses an encoded domain name' }], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  primary = getPrimaryText(getCard());
  why = getWhyPanelText(getCard());
  assert(primary.includes('SAFETY'), true, 'Risk LOW shows SAFETY block');
  assert(why.includes('Uses an encoded domain name'), true, 'Risk LOW lists specific signal in Why panel');
  assert(!primary.includes('Some unusual characteristics'), true, 'Risk LOW does NOT show MEDIUM warning');
  assert(primary.includes('Some things to know'), true, 'Risk LOW shows informational text');

  // CASE 10: Risk MEDIUM -> UNUSUAL_CHARACTERISTICS
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://192.168.1.10/login',
    localSignals: { hostname: '192.168.1.10' },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { 
      status: 'UNUSUAL_CHARACTERISTICS', 
      signals: [
        { tier: 'B', detail: 'Uses an IP address' },
        { tier: 'B', detail: 'Contains a sign-in or account action' }
      ],
      assessmentBasis: 'LOCAL_ONLY', limitations: []
    }
  });
  primary = getPrimaryText(getCard());
  why = getWhyPanelText(getCard());
  assert(primary.includes('SAFETY'), true, 'Risk MEDIUM shows SAFETY block');
  assert(primary.includes('Some unusual characteristics'), true, 'Risk MEDIUM shows proper warning text');
  assert(why.includes('Uses an IP address'), true, 'Risk MEDIUM lists specific signal 1 in Why panel');
  assert(why.includes('Contains a sign-in or account action'), true, 'Risk MEDIUM lists specific signal 2 in Why panel');

  // CASE 11: Network Failure + Clean URL (Case M)
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://example.com',
    localSignals: { hostname: 'example.com' },
    networkEvidence: { status: 'FAILED' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { status: 'NO_SIGNALS_DETECTED', signals: [], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  primary = getPrimaryText(getCard());
  assert(primary.includes("Destination couldn't be verified"), true, 'Case M: Clean network failure shows correct dest wording');
  assert(primary.includes('Nothing unusual found'), true, 'Case M: Clean network failure does NOT show unusual characteristics');

  // CASE 12: Network Failure + Local Risk Signal (Case L)
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://xn--example.com',
    localSignals: { hostname: 'xn--example.com' },
    networkEvidence: { status: 'FAILED' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { status: 'INFORMATIONAL', signals: [{ tier: 'B', detail: 'Uses an encoded domain name' }], assessmentBasis: 'LOCAL_ONLY', limitations: [] }
  });
  primary = getPrimaryText(getCard());
  why = getWhyPanelText(getCard());
  assert(primary.includes("Destination couldn't be verified"), true, 'Case L: Risk network failure shows correct dest wording');
  assert(primary.includes('SAFETY'), true, 'Case L: Risk network failure still shows SAFETY block');
  assert(why.includes('Uses an encoded domain name'), true, 'Case L: Risk network failure preserves evidence in Why panel');

  // CASE 13: Reputation STRONG_WARNING
  BTL.previewUI.updateNetworkResult({
    originalUrl: 'https://malware.com',
    localSignals: { hostname: 'malware.com' },
    networkEvidence: { status: 'NO_REDIRECT_OBSERVED' },
    browserObservation: { status: 'NONE' },
    safetyEvidence: { 
      status: 'STRONG_WARNING', 
      signals: [
        { tier: 'D', detail: 'This link was flagged as a known threat (MALWARE).' }
      ],
      assessmentBasis: 'LOCAL_ONLY', limitations: []
    }
  });
  primary = getPrimaryText(getCard());
  why = getWhyPanelText(getCard());
  assert(primary.includes('Known threat reported'), true, 'Reputation threat shows STRONG_WARNING text');
  assert(why.includes('This link was flagged as a known threat'), true, 'Reputation threat shows details in Why panel');

  // EXPLICIT REGRESSION TESTS
  let card = getCard();
  let text = getCardTextContent(card);
  let safetyBlockCount = card.children.filter(c => c.className && c.className.includes('btl-safety-section')).length;
  assert(safetyBlockCount, 1, 'SAFETY is rendered exactly once');
  assert(text.includes('LINK SIGNALS'), false, 'LINK SIGNALS is completely absent');
  assert(text.includes('SECURITY'), false, 'SECURITY is completely absent');

  console.log(`\nRESULTS: ${passed}/${total} passed`);
}

runUITests().catch(console.error);
