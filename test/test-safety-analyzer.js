const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const BTL = {};
const sandbox = {
  window: { BehindTheLink: BTL },
  self: { BehindTheLink: BTL },
  BTL: BTL,
  URL: URL
};

vm.createContext(sandbox);

const safetyAnalyzerCode = fs.readFileSync('./src/shared/safety-analyzer.js', 'utf8');
vm.runInContext(safetyAnalyzerCode, sandbox);

const compute = BTL.safetyAnalyzer.computeSafetyEvidence;

function createLocalSignals(isShortened, trackingParams, hasAffiliate, embedded, pathname, isHttps) {
  return {
    isShortened: !!isShortened,
    trackingParams: trackingParams || [],
    hasAffiliate: !!hasAffiliate,
    embeddedCandidates: embedded || [],
    pathname: pathname || '/',
    isHttps: isHttps !== undefined ? isHttps : true
  };
}

function createRiskSignals(signalsArr) {
  return { signals: signalsArr || [] };
}

function createNetworkEvidence(status, redirectTarget) {
  return { status: status || 'NO_REDIRECT_OBSERVED', redirectTarget: redirectTarget || null };
}

function createBrowserObservation(status) {
  return { status: status || 'NONE' };
}

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

console.log("=== SAFETY-ANALYZER TESTS ===");

// 21.1 Anti-Snowball / False-Positive Tests
runTest("SAFETY-001: Clean URL + NO_REDIRECT + STRONG_CORRELATION", () => {
  const result = compute(
    "https://bbc.com", createLocalSignals(), createRiskSignals(),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('STRONG_CORRELATION')
  );
  assert.strictEqual(result.status, 'NO_SIGNALS_DETECTED');
});

runTest("SAFETY-004: Single Tier B (unusual port) stays INFORMATIONAL", () => {
  const result = compute(
    "https://example.com:8080", createLocalSignals(), createRiskSignals([{ type: 'UNUSUAL_PORT' }]),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'INFORMATIONAL');
});

runTest("SAFETY-007: Shortener + cross-domain redirect -> Tier A only", () => {
  const result = compute(
    "https://bit.ly/abc", createLocalSignals(true), createRiskSignals(),
    createRiskSignals(), createLocalSignals(), createNetworkEvidence('HTTP_REDIRECT_OBSERVED', 'https://youtube.com'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'INFORMATIONAL');
  assert.ok(result.signals.find(s => s.id === 'REDIRECTS_TO_DIFFERENT_DOMAIN'));
});

runTest("SAFETY-010: Legitimate login page stays INFORMATIONAL", () => {
  const result = compute(
    "https://github.com/login", createLocalSignals(), createRiskSignals([{ type: 'SENSITIVE_ACTION_PATH' }]),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'INFORMATIONAL');
});

runTest("SAFETY-013: Punycode alone stays INFORMATIONAL", () => {
  const result = compute(
    "https://xn--mnchen-3ya.de", createLocalSignals(), createRiskSignals([{ type: 'PUNYCODE_DOMAIN' }]),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'INFORMATIONAL');
});

runTest("SAFETY-017: HTTP + unusual port -> INFORMATIONAL", () => {
  const result = compute(
    "http://example.com:8080", createLocalSignals(false, [], false, [], '/', false), 
    createRiskSignals([{ type: 'UNUSUAL_PORT' }]),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'INFORMATIONAL');
});

runTest("SAFETY-019: HTTP + punycode -> UNUSUAL_CHARACTERISTICS", () => {
  const result = compute(
    "http://xn--exmple.com", createLocalSignals(false, [], false, [], '/', false), 
    createRiskSignals([{ type: 'PUNYCODE_DOMAIN' }]),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'UNUSUAL_CHARACTERISTICS');
});

// 21.2 Escalation Tests
runTest("SAFETY-020: PUNYCODE + USERINFO -> UNUSUAL_CHARACTERISTICS", () => {
  const result = compute(
    "https://user@xn--paypa1.com", createLocalSignals(), 
    createRiskSignals([{ type: 'PUNYCODE_DOMAIN' }, { type: 'USERINFO_IN_URL' }]),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'UNUSUAL_CHARACTERISTICS');
});

runTest("SAFETY-024: SUSPICIOUS_FILE_EXT + UNUSUAL_PORT -> UNUSUAL_CHARACTERISTICS", () => {
  const result = compute(
    "https://example.com:8080/file.exe", createLocalSignals(false, [], false, [], '/file.exe'), 
    createRiskSignals([{ type: 'UNUSUAL_PORT' }]),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'UNUSUAL_CHARACTERISTICS');
});

// 21.3 Redirect Target Analysis Tests
runTest("DEST-TARGET-001: HTTP_REDIRECT_OBSERVED + target has IP_HOST_V4", () => {
  const result = compute(
    "https://example.com", createLocalSignals(), createRiskSignals(),
    createRiskSignals([{ type: 'IP_HOST_V4' }]), createLocalSignals(), 
    createNetworkEvidence('HTTP_REDIRECT_OBSERVED', 'https://192.168.1.1'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'INFORMATIONAL'); // Only 1 dimension
  const sig = result.signals.find(s => s.id === 'IP_HOST_V4');
  assert.ok(sig);
  assert.strictEqual(sig.urlContext, 'network_target_url');
  assert.strictEqual(sig.epistemic, 'VERIFIED');
});

runTest("DEST-TARGET-005: Original has HTTP_NOT_HTTPS + target has IP_HOST_V4 -> UNUSUAL_CHARACTERISTICS", () => {
  const result = compute(
    "http://example.com", createLocalSignals(false, [], false, [], '/', false), createRiskSignals(),
    createRiskSignals([{ type: 'IP_HOST_V4' }]), createLocalSignals(false, [], false, [], '/', true), 
    createNetworkEvidence('HTTP_REDIRECT_OBSERVED', 'https://192.168.1.1'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.status, 'UNUSUAL_CHARACTERISTICS');
});

// 21.6 assessmentBasis Tests
runTest("BASIS-005: Shortener + FAILED + no obs -> INCOMPLETE", () => {
  const result = compute(
    "https://bit.ly/abc", createLocalSignals(true), createRiskSignals(),
    null, null, createNetworkEvidence('FAILED'), createBrowserObservation('NONE')
  );
  assert.strictEqual(result.limitations.length, 3);
});

// Phase 3 Reputation Tests
runTest("SAFETY-REP-001: REPUTATION_CONFIRMED_THREAT triggers STRONG_WARNING", () => {
  const result = compute(
    "https://malware.com", createLocalSignals(), createRiskSignals(),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('NONE'),
    { status: 'REPUTATION_CONFIRMED_THREAT', threatTypes: ['MALWARE'] }
  );
  assert.strictEqual(result.status, 'STRONG_WARNING');
  const repSignal = result.signals.find(s => s.id === 'REPUTATION_CONFIRMED_THREAT');
  assert.ok(repSignal);
  assert.strictEqual(repSignal.tier, 'D');
});

runTest("SAFETY-REP-002: REPUTATION_NO_MATCH falls back to Tier B logic", () => {
  const result = compute(
    "https://example.com:8080", createLocalSignals(), createRiskSignals([{ type: 'UNUSUAL_PORT' }]),
    null, null, createNetworkEvidence('NO_REDIRECT_OBSERVED'), createBrowserObservation('NONE'),
    { status: 'REPUTATION_NO_MATCH' }
  );
  assert.strictEqual(result.status, 'INFORMATIONAL'); // Single tier B
});

console.log(`\nRESULTS: ${passed}/${total} passed`);
if (passed !== total) process.exit(1);
