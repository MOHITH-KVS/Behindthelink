const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadModule() {
  const registryPath = path.join(__dirname, '..', 'src', 'shared', 'brand-registry.js');
  const registryCode = fs.readFileSync(registryPath, 'utf8');

  const filePath = path.join(__dirname, '..', 'src', 'shared', 'claim-destination-analyzer.js');
  const code = fs.readFileSync(filePath, 'utf8');

  const sandbox = {
    self: {},
    window: {},
    URL: URL
  };

  vm.createContext(sandbox);
  vm.runInContext(registryCode, sandbox);
  vm.runInContext(code, sandbox);

  return sandbox.self.BehindTheLink.claimDestinationAnalyzer;
}

function runTests() {
  console.log("--- claim-destination-analyzer tests ---");
  const analyzer = loadModule();
  let testCount = 0;

  function countTest(desc, fn) {
    testCount++;
    try {
      fn();
    } catch (e) {
      console.error(`FAILED: ${desc}`);
      throw e;
    }
  }

  const t1Context = { possibleClaimedBrand: 'MICROSOFT', category: 'LOGIN_ACCOUNT' };

  // Test 1: Strong Microsoft claim + official Microsoft destination -> no mismatch
  countTest("Test 1: Official subdomain match", () => {
    const t1Mismatch = analyzer.evaluateMismatch(t1Context, 'https://login.microsoftonline.com/auth');
    assert.strictEqual(t1Mismatch, null, 'Test 1 Failed: Should not mismatch on official domain');
  });

  // Test 2: Strong Microsoft claim + unrelated verified destination -> mismatch
  countTest("Test 2: Unrelated domain mismatch", () => {
    const t2Mismatch = analyzer.evaluateMismatch(t1Context, 'https://example-login.com');
    assert.notStrictEqual(t2Mismatch, null, 'Test 2 Failed: Should mismatch on unrelated domain');
    assert.strictEqual(t2Mismatch.mismatch, true);
    assert.strictEqual(t2Mismatch.brandId, 'MICROSOFT');
    assert.strictEqual(t2Mismatch.strength, 'STRONG');
  });

  // Test 3: Weak Microsoft mention + unrelated destination -> no mismatch
  countTest("Test 3: Weak claim suppression", () => {
    const t3Context = { possibleClaimedBrand: 'MICROSOFT', category: 'GENERAL' };
    const t3Mismatch = analyzer.evaluateMismatch(t3Context, 'https://news-site.com');
    assert.strictEqual(t3Mismatch, null, 'Test 3 Failed: Weak claim should not mismatch');
  });

  // Test 4: No brand claim + unrelated destination -> no mismatch
  countTest("Test 4: No brand claim suppression", () => {
    const t4Context = { category: 'GENERAL' };
    const t4Mismatch = analyzer.evaluateMismatch(t4Context, 'https://example.com');
    assert.strictEqual(t4Mismatch, null, 'Test 4 Failed: No brand claim should not mismatch');
  });

  // Test 5: Strong PayPal claim + unrelated destination -> mismatch
  countTest("Test 5: Strong PayPal claim mismatch", () => {
    const t5Context = { possibleClaimedBrand: 'PAYPAL', category: 'PAYMENT' };
    const t5Mismatch = analyzer.evaluateMismatch(t5Context, 'https://secure-payment-gateway.info');
    assert.notStrictEqual(t5Mismatch, null, 'Test 5 Failed: Strong PayPal claim should mismatch');
  });

  // Test 6: Strong claim + unverified destination -> no mismatch
  countTest("Test 6: Inconclusive destination suppression", () => {
    const t6Mismatch = analyzer.evaluateMismatch(t1Context, null);
    assert.strictEqual(t6Mismatch, null, 'Test 6 Failed: Unverified destination should not mismatch');
    const t6Empty = analyzer.evaluateMismatch(t1Context, '');
    assert.strictEqual(t6Empty, null, 'Test 6 Failed: Empty destination should not mismatch');
  });

  // Test 7: Strict destination-domain matching (fake brand-containing domain)
  countTest("Test 7: Substring match rejection", () => {
    const t7Mismatch = analyzer.evaluateMismatch(t1Context, 'https://microsoft-login-support.com');
    assert.notStrictEqual(t7Mismatch, null, 'Test 7 Failed: Substring match should not be allowed');
  });

  // Test 8: Misleading suffix spoofing
  countTest("Test 8: Host boundary integrity (misleading suffix)", () => {
    const t8Suffix = analyzer.evaluateMismatch(t1Context, 'https://microsoft.com.attacker.test');
    assert.notStrictEqual(t8Suffix, null, 'Test 8 Failed: Suffix spoofing should be rejected');
    assert.strictEqual(t8Suffix.mismatch, true);

    const paypalSuffix = analyzer.evaluateMismatch({ possibleClaimedBrand: 'PAYPAL', category: 'PAYMENT' }, 'https://paypal.com.phishing.org');
    assert.notStrictEqual(paypalSuffix, null, 'Test 8b Failed: PayPal suffix spoofing rejected');
  });

  // Test 9: Case-insensitive brand matching
  countTest("Test 9: Case-insensitive brand matching", () => {
    const t9Mismatch = analyzer.evaluateMismatch({ possibleClaimedBrand: 'apple', category: 'LOGIN_ACCOUNT' }, 'https://apple.com');
    assert.strictEqual(t9Mismatch, null, 'Test 9 Failed: Case-insensitive brand matching failed');
  });

  // Test 10: Display Brand formatting checks
  countTest("Test 10: Display brand formatting", () => {
    const paypalMismatch = analyzer.evaluateMismatch({ possibleClaimedBrand: 'PAYPAL', category: 'PAYMENT' }, 'https://evil.com');
    assert.strictEqual(paypalMismatch.displayBrand, 'PayPal', 'Test Display Brand Failed');

    const sbiMismatch = analyzer.evaluateMismatch({ possibleClaimedBrand: 'SBI', category: 'PAYMENT' }, 'https://evil.com');
    assert.strictEqual(sbiMismatch.displayBrand, 'State Bank of India (SBI)', 'Test SBI Display Brand Failed');
  });

  // Test 11: Trailing-root-dot normalization
  countTest("Test 11: Trailing dot normalization", () => {
    const dotMatch1 = analyzer.evaluateMismatch(t1Context, 'https://microsoft.com./login');
    assert.strictEqual(dotMatch1, null, 'Test 11a Failed: Trailing dot on apex domain should be stripped');

    const dotMatch2 = analyzer.evaluateMismatch(t1Context, 'https://login.microsoftonline.com./');
    assert.strictEqual(dotMatch2, null, 'Test 11b Failed: Trailing dot on subdomain should be stripped');
  });

  // Test 12: Verified Regional Domains
  countTest("Test 12: Verified regional domain matching", () => {
    const amazonIn = analyzer.evaluateMismatch({ possibleClaimedBrand: 'AMAZON', category: 'DELIVERY_ORDER' }, 'https://www.amazon.in/dp/item');
    assert.strictEqual(amazonIn, null, 'Test 12a Failed: Amazon India should match');

    const amazonUk = analyzer.evaluateMismatch({ possibleClaimedBrand: 'AMAZON', category: 'DELIVERY_ORDER' }, 'https://amazon.co.uk');
    assert.strictEqual(amazonUk, null, 'Test 12b Failed: Amazon UK should match');

    const googleIn = analyzer.evaluateMismatch({ possibleClaimedBrand: 'GOOGLE', category: 'LOGIN_ACCOUNT' }, 'https://google.co.in');
    assert.strictEqual(googleIn, null, 'Test 12c Failed: Google India should match');
  });

  // Test 13: Indian Banking Domains (Dual TLD reality)
  countTest("Test 13: Indian banking multi-domain matching", () => {
    const sbiContext = { possibleClaimedBrand: 'SBI', category: 'LOGIN_ACCOUNT' };
    assert.strictEqual(analyzer.evaluateMismatch(sbiContext, 'https://sbi.bank.in'), null, 'SBI .bank.in failed');
    assert.strictEqual(analyzer.evaluateMismatch(sbiContext, 'https://sbi.co.in'), null, 'SBI .co.in failed');
    assert.strictEqual(analyzer.evaluateMismatch(sbiContext, 'https://bank.sbi'), null, 'SBI .sbi failed');
    assert.strictEqual(analyzer.evaluateMismatch(sbiContext, 'https://retail.onlinesbi.sbi'), null, 'SBI retail portal failed');
    assert.strictEqual(analyzer.evaluateMismatch(sbiContext, 'https://onlinesbi.com'), null, 'SBI legacy online portal failed');

    const hdfcContext = { possibleClaimedBrand: 'HDFC', category: 'LOGIN_ACCOUNT' };
    assert.strictEqual(analyzer.evaluateMismatch(hdfcContext, 'https://hdfcbank.com'), null, 'HDFC .com failed');
    assert.strictEqual(analyzer.evaluateMismatch(hdfcContext, 'https://hdfc.bank.in'), null, 'HDFC .bank.in failed');
    assert.strictEqual(analyzer.evaluateMismatch(hdfcContext, 'https://netbanking.hdfcbank.com'), null, 'HDFC netbanking failed');

    const axisContext = { possibleClaimedBrand: 'AXIS', category: 'LOGIN_ACCOUNT' };
    assert.strictEqual(analyzer.evaluateMismatch(axisContext, 'https://axis.bank.in'), null, 'Axis .bank.in failed');
    assert.strictEqual(analyzer.evaluateMismatch(axisContext, 'https://axisbank.com'), null, 'Axis .com failed');
  });

  // Test 14: Brand-Specific User-Hosting Exclusions
  countTest("Test 14: Brand-specific user hosting exclusions", () => {
    const githubContext = { possibleClaimedBrand: 'GITHUB', category: 'LOGIN_ACCOUNT' };
    // GitHub apex & subdomains
    assert.strictEqual(analyzer.evaluateMismatch(githubContext, 'https://github.com/login'), null, 'GitHub official failed');
    assert.strictEqual(analyzer.evaluateMismatch(githubContext, 'https://docs.github.com'), null, 'GitHub docs failed');

    // GitHub Pages user hosting MUST be rejected
    const ghPagesMismatch = analyzer.evaluateMismatch(githubContext, 'https://malicious-user.github.io/login');
    assert.notStrictEqual(ghPagesMismatch, null, 'GitHub Pages user hosting was not excluded!');
    assert.strictEqual(ghPagesMismatch.mismatch, true);

    // Microsoft Azure user websites MUST be rejected
    const msAzureMismatch = analyzer.evaluateMismatch(t1Context, 'https://phishing-site.azurewebsites.net');
    assert.notStrictEqual(msAzureMismatch, null, 'Azure user hosting was not excluded!');

    // Amazon S3 user buckets MUST be rejected
    const amzS3Mismatch = analyzer.evaluateMismatch({ possibleClaimedBrand: 'AMAZON', category: 'LOGIN_ACCOUNT' }, 'https://bucket.s3.amazonaws.com/login.html');
    assert.notStrictEqual(amzS3Mismatch, null, 'AWS S3 user storage was not excluded!');

    // Google Firebase user apps MUST be rejected
    const gFirebaseMismatch = analyzer.evaluateMismatch({ possibleClaimedBrand: 'GOOGLE', category: 'LOGIN_ACCOUNT' }, 'https://fake-login.firebaseapp.com');
    assert.notStrictEqual(gFirebaseMismatch, null, 'Firebase user apps were not excluded!');
  });

  // Test 15: Scoped Legitimate Third-Party Services
  countTest("Test 15: Scoped legitimate third-party services", () => {
    const waContext = { possibleClaimedBrand: 'WHATSAPP', category: 'LOGIN_ACCOUNT' };
    assert.strictEqual(analyzer.evaluateMismatch(waContext, 'https://whatsapp.com'), null, 'WhatsApp official failed');
    assert.strictEqual(analyzer.evaluateMismatch(waContext, 'https://wa.me/919999999999'), null, 'WhatsApp wa.me click-to-chat failed');

    const ppContext = { possibleClaimedBrand: 'PAYPAL', category: 'PAYMENT' };
    assert.strictEqual(analyzer.evaluateMismatch(ppContext, 'https://paypal.com'), null, 'PayPal official failed');
    assert.strictEqual(analyzer.evaluateMismatch(ppContext, 'https://paypal.me/recipient'), null, 'PayPal paypal.me service failed');
  });

  // Test 16: Destination Evidence Helper Contract (getVerifiedDestination)
  countTest("Test 16: Destination evidence contract helper", () => {
    // 1. HTTP Redirect Target
    const r1 = analyzer.getVerifiedDestination(
      { status: 'HTTP_REDIRECT_OBSERVED', redirectTarget: 'https://redirected.com' },
      null,
      'https://original.com'
    );
    assert.notStrictEqual(r1, null);
    assert.strictEqual(r1.url, 'https://redirected.com');
    assert.strictEqual(r1.source, 'network');

    // 2. Direct Target (No Redirect)
    const r2 = analyzer.getVerifiedDestination(
      { status: 'NO_REDIRECT_OBSERVED' },
      null,
      'https://direct.com'
    );
    assert.notStrictEqual(r2, null);
    assert.strictEqual(r2.url, 'https://direct.com');
    assert.strictEqual(r2.source, 'network');

    // 3. Observed Browser Navigation
    const r3 = analyzer.getVerifiedDestination(
      { status: 'FAILED' },
      { status: 'STRONG_CORRELATION', observedLatestUrl: 'https://observed.com' },
      'https://original.com'
    );
    assert.notStrictEqual(r3, null);
    assert.strictEqual(r3.url, 'https://observed.com');
    assert.strictEqual(r3.source, 'browser_observation');

    // 4. Inconclusive (Network Failed, No Observation)
    const r4 = analyzer.getVerifiedDestination(
      { status: 'FAILED' },
      { status: 'NONE' },
      'https://original.com'
    );
    assert.strictEqual(r4, null, 'Inconclusive network failure should return null');
  });

  console.log(`All claim-destination-analyzer tests passed (${testCount} test blocks).`);
}

module.exports = runTests;

if (require.main === module) {
  runTests();
}
