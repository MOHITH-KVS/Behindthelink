const fs = require('fs');
const vm = require('vm');

// 1. Mock Chrome API and browser environment
const chromeMock = {
  storage: {
    local: {
      get: async () => ({}),
      set: async () => {},
      remove: async () => {}
    }
  },
  crypto: {
    subtle: {
      digest: function() {
        return Promise.resolve(new ArrayBuffer(16));
      }
    }
  },
  logDiagnostic: function() {}
};

const BTL = {};
const sandbox = {
  window: { BehindTheLink: BTL },
  self: { BehindTheLink: BTL },
  BTL: BTL,
  URL: URL,
  decodeURIComponent: decodeURIComponent,
  chrome: chromeMock,
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  fetch: async (url) => {
    // Mock fetch behavior based on URL
    if (url.includes('fail')) throw new Error('NETWORK_ERROR');
    if (url.includes('timeout')) throw 'timeout';
    if (url.includes('redirect')) {
      return { url: 'https://redirected.com' };
    }
    return { url: url }; // 200 OK no redirect
  },
  AbortController: class AbortController {
    constructor() { this.signal = {}; }
    abort() {}
  },
  console: console,
  Map: Map,
  Set: Set
};

vm.createContext(sandbox);

// 2. Load necessary extension files into the sandbox
const shortenerCode = fs.readFileSync('./src/content/shortener-registry.js', 'utf8');
const trackingCode = fs.readFileSync('./src/content/tracking-registry.js', 'utf8');
const affiliateCode = fs.readFileSync('./src/content/affiliate-registry.js', 'utf8');
const analyzerCode = fs.readFileSync('./src/content/url-analyzer.js', 'utf8');
const safetyAnalyzerCode = fs.readFileSync('./src/shared/safety-analyzer.js', 'utf8');
const serviceWorkerCode = fs.readFileSync('./src/background/service-worker.js', 'utf8');

vm.runInContext(shortenerCode, sandbox);
vm.runInContext(trackingCode, sandbox);
vm.runInContext(affiliateCode, sandbox);
vm.runInContext(analyzerCode, sandbox);
vm.runInContext(safetyAnalyzerCode, sandbox);

// Inject activeRequests Map for service-worker.js
vm.runInContext('const activeRequests = new Map();', sandbox);
// Inject TIMEOUT_MS and normalizeUrl
vm.runInContext('const TIMEOUT_MS = 5000; function normalizeUrl(u) { return u; } function logDiagnostic() {}', sandbox);

// Run service worker code (extracting resolveDestination)
const swExtract = `
  ${serviceWorkerCode.substring(serviceWorkerCode.indexOf('async function resolveDestination'), serviceWorkerCode.indexOf('// ============================================================================'))}
  self.BehindTheLink.resolveDestination = resolveDestination;
`;
vm.runInContext(swExtract, sandbox);

// 3. Test Runner
async function runDataModelTests() {
  let passed = 0; let total = 0;

  function assertObjProp(obj, propName, expectedValue, msg) {
    total++;
    const val = propName.split('.').reduce((o, i) => o ? o[i] : undefined, obj);
    if (val === expectedValue) {
      console.log(`[PASS] ${msg}`);
      passed++;
    } else {
      console.error(`[FAIL] ${msg} | Expected ${expectedValue}, got ${val}`);
    }
  }

  function assertSchema(res, testName) {
    total++;
    let ok = true;
    if (res.prediction) { console.error(`[FAIL] ${testName} - old 'prediction' field exists`); ok = false; }
    if (res.status) { console.error(`[FAIL] ${testName} - old 'status' field exists`); ok = false; }
    if (res.finalUrl) { console.error(`[FAIL] ${testName} - old 'finalUrl' field exists`); ok = false; }
    if (res.candidateUrl) { console.error(`[FAIL] ${testName} - old 'candidateUrl' field exists`); ok = false; }
    
    if (!res.originalUrl) { console.error(`[FAIL] ${testName} - originalUrl missing`); ok = false; }
    if (!res.localSignals) { console.error(`[FAIL] ${testName} - localSignals missing`); ok = false; }
    else if (res.localSignals.isDirect !== undefined) { console.error(`[FAIL] ${testName} - old 'isDirect' exists in localSignals`); ok = false; }
    
    if (!res.networkEvidence) { console.error(`[FAIL] ${testName} - networkEvidence missing`); ok = false; }
    if (!res.browserObservation) { console.error(`[FAIL] ${testName} - browserObservation missing`); ok = false; }
    if (!res.riskSignals) { console.error(`[FAIL] ${testName} - riskSignals missing`); ok = false; }
    if (!res.safetyEvidence) { console.error(`[FAIL] ${testName} - safetyEvidence missing`); ok = false; }
    
    if (ok) {
      console.log(`[PASS] ${testName} - Schema matches`);
      passed++;
    }
  }

  console.log("--- RUNNING DATA MODEL TESTS ---");

  // 1. Clean direct URL
  const res1 = await sandbox.BTL.resolveDestination('https://example.com/', 1);
  assertSchema(res1, 'Clean direct URL');
  assertObjProp(res1, 'localSignals.isStructurallyDirect', true, 'Clean URL is structurally direct');
  assertObjProp(res1, 'localSignals.isClean', true, 'Clean URL is clean');
  assertObjProp(res1, 'networkEvidence.status', 'NO_REDIRECT_OBSERVED', 'Clean URL network status');

  // 2. Tracking URL
  const res2 = await sandbox.BTL.resolveDestination('https://example.com/?utm_source=test', 2);
  assertSchema(res2, 'Tracking URL');
  assertObjProp(res2, 'localSignals.isStructurallyDirect', true, 'Tracking URL is structurally direct');
  assertObjProp(res2, 'localSignals.isClean', false, 'Tracking URL is NOT clean');

  // 3. Affiliate URL
  const res3 = await sandbox.BTL.resolveDestination('https://amazon.com/?tag=123', 3);
  assertObjProp(res3, 'localSignals.isStructurallyDirect', true, 'Affiliate URL is structurally direct');
  assertObjProp(res3, 'localSignals.hasAffiliate', true, 'Affiliate URL has affiliate');

  // 4. Shortener
  const res4 = await sandbox.BTL.resolveDestination('https://tinyurl.com/abc', 4);
  assertObjProp(res4, 'localSignals.isStructurallyDirect', false, 'Shortener is NOT structurally direct');
  assertObjProp(res4, 'localSignals.isShortened', true, 'Shortener identified');

  // 5. Embedded URL
  const res5 = await sandbox.BTL.resolveDestination('https://example.com/?url=https://dest.com', 5);
  assertObjProp(res5, 'localSignals.isStructurallyDirect', false, 'Embedded URL is NOT structurally direct');
  assertObjProp(res5, 'localSignals.embeddedCandidates.length', 1, 'Embedded candidate extracted');

  // 6. Shortener + Tracking
  const res6 = await sandbox.BTL.resolveDestination('https://tinyurl.com/abc?utm_source=test', 6);
  assertObjProp(res6, 'localSignals.isStructurallyDirect', false, 'Shortener+Tracking NOT structurally direct');
  assertObjProp(res6, 'localSignals.isClean', false, 'Shortener+Tracking NOT clean');

  // 8. HTTP redirect
  const res8 = await sandbox.BTL.resolveDestination('https://example.com/redirect', 8);
  assertObjProp(res8, 'networkEvidence.status', 'HTTP_REDIRECT_OBSERVED', 'HTTP Redirect correctly observed');

  // 10. Network failure
  const res10 = await sandbox.BTL.resolveDestination('https://example.com/fail', 10);
  assertSchema(res10, 'Network failure schema');
  assertObjProp(res10, 'networkEvidence.status', 'FAILED', 'Network failure correctly marked');
  assertObjProp(res10, 'localSignals.isStructurallyDirect', true, 'Local signals STILL POPULATED on failure');

  // --- PHASE 2A RISK SIGNAL TESTS ---
  
  // 11. IP Host
  const res11 = await sandbox.BTL.resolveDestination('https://192.168.1.10/login', 11);
  assertObjProp(res11, 'riskSignals.severity', 'LOW', 'IP host alone is LOW');
  assertObjProp(res11, 'riskSignals.signals.0.type', 'IP_HOST', 'IP host detected');

  // 12. Sensitive Path
  const res12 = await sandbox.BTL.resolveDestination('https://example.com/login', 12);
  assertObjProp(res12, 'riskSignals.severity', 'NONE', '/login alone contributes zero severity');
  assertObjProp(res12, 'riskSignals.signals.0.type', 'SENSITIVE_ACTION_PATH', 'Sensitive path detected');

  // 13. Deep Subdomain
  const res13 = await sandbox.BTL.resolveDestination('https://a.b.c.example.com/', 13);
  assertObjProp(res13, 'riskSignals.severity', 'LOW', 'Deep subdomain is LOW');
  assertObjProp(res13, 'riskSignals.signals.0.type', 'DEEP_SUBDOMAIN', 'Deep subdomain detected');

  // 14. Punycode
  const res14 = await sandbox.BTL.resolveDestination('https://xn--example-domain.test/', 14);
  assertObjProp(res14, 'riskSignals.severity', 'LOW', 'Punycode alone is LOW');
  assertObjProp(res14, 'riskSignals.signals.0.type', 'PUNYCODE_DOMAIN', 'Punycode detected');

  // 15. Userinfo
  const res15 = await sandbox.BTL.resolveDestination('https://example.com@google.com/', 15);
  assertObjProp(res15, 'riskSignals.severity', 'LOW', 'Userinfo alone is LOW');
  assertObjProp(res15, 'riskSignals.signals.0.type', 'USERINFO_IN_URL', 'Userinfo detected');

  // 16. Unusual Port
  const res16 = await sandbox.BTL.resolveDestination('https://example.com:8080/login', 16);
  assertObjProp(res16, 'riskSignals.severity', 'LOW', 'Unusual port + /login is only LOW');
  assertObjProp(res16, 'riskSignals.signals.0.type', 'UNUSUAL_PORT', 'Unusual port detected');

  // 17. Normal URL Encoding
  const res17 = await sandbox.BTL.resolveDestination('https://example.com/search?q=hello%20world', 17);
  assertObjProp(res17, 'riskSignals.severity', 'NONE', 'Normal encoding is NONE');
  assertObjProp(res17, 'riskSignals.signals.length', 0, 'No heavy encoding detected');

  // 18. Heavy Encoding
  const res18 = await sandbox.BTL.resolveDestination('https://example.com/%68%74%74%70', 18);
  assertObjProp(res18, 'riskSignals.severity', 'LOW', 'Heavy encoding is LOW');
  assertObjProp(res18, 'riskSignals.signals.0.type', 'HEAVY_ENCODING', 'Heavy encoding detected');

  // 19. Tracking doesn't cause security warning
  assertObjProp(res2, 'riskSignals.severity', 'NONE', 'Tracking is NONE severity');

  // 20. Shortener doesn't cause security warning
  assertObjProp(res4, 'riskSignals.severity', 'NONE', 'Shortener is NONE severity');

  // 21. Strong combination (Punycode + Userinfo)
  const res21 = await sandbox.BTL.resolveDestination('https://example.com@xn--example-domain.test/', 21);
  assertObjProp(res21, 'riskSignals.severity', 'MEDIUM', 'Punycode + Userinfo is MEDIUM');

  // 22. Sensitive path + normal URL (Case K)
  const res22 = await sandbox.BTL.resolveDestination('https://example.com/account/verify', 22);
  assertObjProp(res22, 'riskSignals.severity', 'NONE', 'Sensitive path + normal URL is NONE');

  // 23. Network failure + local risk signal (Case L)
  const res23 = await sandbox.BTL.resolveDestination('https://xn--example-domain.test/fail', 23);
  assertObjProp(res23, 'networkEvidence.status', 'FAILED', 'Network failure correctly marked');
  assertObjProp(res23, 'riskSignals.severity', 'LOW', 'Risk signals STILL POPULATED on network failure');

  console.log(`\nRESULTS: ${passed}/${total} passed`);
}

runDataModelTests().catch(console.error);
