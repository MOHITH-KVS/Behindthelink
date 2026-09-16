const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadModule() {
  const filePath = path.join(__dirname, '..', 'src', 'shared', 'claim-destination-analyzer.js');
  const code = fs.readFileSync(filePath, 'utf8');
  
  const sandbox = {
    self: {},
    window: {},
    URL: URL
  };
  
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  
  return sandbox.self.BehindTheLink.claimDestinationAnalyzer;
}

function runTests() {
  console.log("--- claim-destination-analyzer tests ---");
  const analyzer = loadModule();

  // Test 1: Strong Microsoft claim + official Microsoft destination -> no mismatch
  const t1Context = { possibleClaimedBrand: 'MICROSOFT', category: 'LOGIN_ACCOUNT' };
  const t1Mismatch = analyzer.evaluateMismatch(t1Context, 'https://login.microsoftonline.com/auth');
  assert.strictEqual(t1Mismatch, null, 'Test 1 Failed: Should not mismatch on official domain');

  // Test 2: Strong Microsoft claim + unrelated verified destination -> mismatch
  const t2Mismatch = analyzer.evaluateMismatch(t1Context, 'https://example-login.com');
  assert.notStrictEqual(t2Mismatch, null, 'Test 2 Failed: Should mismatch on unrelated domain');
  assert.strictEqual(t2Mismatch.mismatch, true);
  assert.strictEqual(t2Mismatch.brandId, 'MICROSOFT');
  assert.strictEqual(t2Mismatch.strength, 'STRONG');

  // Test 3: Weak Microsoft mention + unrelated destination -> no mismatch
  const t3Context = { possibleClaimedBrand: 'MICROSOFT', category: 'GENERAL' };
  const t3Mismatch = analyzer.evaluateMismatch(t3Context, 'https://news-site.com');
  assert.strictEqual(t3Mismatch, null, 'Test 3 Failed: Weak claim should not mismatch');

  // Test 4: No brand claim + unrelated destination -> no mismatch
  const t4Context = { category: 'GENERAL' };
  const t4Mismatch = analyzer.evaluateMismatch(t4Context, 'https://example.com');
  assert.strictEqual(t4Mismatch, null, 'Test 4 Failed: No brand claim should not mismatch');

  // Test 5: Strong PayPal claim + unrelated destination -> mismatch
  const t5Context = { possibleClaimedBrand: 'PAYPAL', category: 'PAYMENT' };
  const t5Mismatch = analyzer.evaluateMismatch(t5Context, 'https://secure-payment-gateway.info');
  assert.notStrictEqual(t5Mismatch, null, 'Test 5 Failed: Strong PayPal claim should mismatch');

  // Test 6: Strong claim + unverified destination -> no mismatch
  const t6Mismatch = analyzer.evaluateMismatch(t1Context, null);
  assert.strictEqual(t6Mismatch, null, 'Test 6 Failed: Unverified destination should not mismatch');

  // Test 8: Strict destination-domain matching (fake brand-containing domain)
  const t8Mismatch = analyzer.evaluateMismatch(t1Context, 'https://microsoft-login-support.com');
  assert.notStrictEqual(t8Mismatch, null, 'Test 8 Failed: Substring match should not be allowed');

  // Test 10: Case-insensitive brand matching
  const t10Mismatch = analyzer.evaluateMismatch({ possibleClaimedBrand: 'apple', category: 'LOGIN_ACCOUNT' }, 'https://apple.com');
  assert.strictEqual(t10Mismatch, null, 'Test 10 Failed: Case-insensitive brand matching failed');

  // Display Brand formatting checks
  const paypalMismatch = analyzer.evaluateMismatch({ possibleClaimedBrand: 'PAYPAL', category: 'PAYMENT' }, 'https://evil.com');
  assert.strictEqual(paypalMismatch.displayBrand, 'PayPal', 'Test Display Brand Failed');

  console.log("All claim-destination-analyzer tests passed (" + 9 + " tests).");
}

module.exports = runTests;

if (require.main === module) {
  runTests();
}
