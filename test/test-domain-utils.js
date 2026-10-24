/**
 * BehindTheLink — Domain Utilities Tests
 *
 * Validates domain normalization, Public Suffix List parsing,
 * IPv4/IPv6 handling, Punycode decoding, and cross-script homoglyphs.
 */
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const BTL = {};
const sandbox = {
  window: { BehindTheLink: BTL },
  self: { BehindTheLink: BTL },
  URL: URL,
  BehindTheLink: BTL
};

vm.createContext(sandbox);
vm.runInContext(fs.readFileSync('./src/shared/domain-utils.js', 'utf8'), sandbox);

const du = BTL.domainUtils;

console.log('--- RUNNING DOMAIN UTILITIES TESTS ---');

// 1. PSL Version
assert.strictEqual(du.PSL_VERSION, '2026.1-compact', 'PSL_VERSION must be 2026.1-compact');
console.log('[PASS] PSL Version check');

// 2. normalizeHostname
assert.strictEqual(du.normalizeHostname('https://www.google.com/path?arg=1'), 'www.google.com');
assert.strictEqual(du.normalizeHostname('http://example.com:8080/'), 'example.com');
assert.strictEqual(du.normalizeHostname('EXAMPLE.COM.'), 'example.com');
assert.strictEqual(du.normalizeHostname('https://user:pass@sub.domain.org/test'), 'sub.domain.org');
assert.strictEqual(du.normalizeHostname('http://192.168.1.1:3000/'), '192.168.1.1');
assert.strictEqual(du.normalizeHostname('http://[2001:db8::1]:80/'), '[2001:db8::1]');
// Rejection of non-HTTP(S) schemes
assert.strictEqual(du.normalizeHostname('ftp://microsoft.com'), '', 'ftp scheme must be rejected');
assert.strictEqual(du.normalizeHostname('javascript:alert(1)'), '', 'javascript scheme must be rejected');
assert.strictEqual(du.normalizeHostname('data:text/html,test'), '', 'data scheme must be rejected');
assert.strictEqual(du.normalizeHostname('mailto:user@domain.com'), '', 'mailto scheme must be rejected');
assert.strictEqual(du.normalizeHostname('file:///C:/test.txt'), '', 'file scheme must be rejected');
assert.strictEqual(du.normalizeHostname('   '), '', 'whitespace must be rejected');
assert.strictEqual(du.normalizeHostname(null), '', 'null must return empty string');
console.log('[PASS] normalizeHostname validation & scheme rejection');

// 3. isIpAddress
assert.strictEqual(du.isIpAddress('192.168.1.1'), true, 'IPv4 should be recognized');
assert.strictEqual(du.isIpAddress('8.8.8.8'), true, 'IPv4 should be recognized');
assert.strictEqual(du.isIpAddress('256.1.1.1'), false, 'Invalid IPv4 octet should fail');
assert.strictEqual(du.isIpAddress('[2001:db8::1]'), true, 'Bracketed IPv6 should be recognized');
assert.strictEqual(du.isIpAddress('2001:db8::1'), true, 'Raw IPv6 should be recognized');
assert.strictEqual(du.isIpAddress('google.com'), false, 'Domain name should not be recognized as IP');
console.log('[PASS] isIpAddress IPv4 & IPv6 detection');

// 4. parseDomain with standard & multi-part public suffixes
const pCom = du.parseDomain('https://sub.example.com');
assert.strictEqual(pCom.registrableDomain, 'example.com');
assert.strictEqual(pCom.domainStem, 'example');
assert.strictEqual(pCom.subdomain, 'sub');
assert.strictEqual(pCom.publicSuffix, 'com');
assert.strictEqual(pCom.publicSuffixKnown, true);
assert.strictEqual(pCom.isInconclusive, false);

// .co.uk
const pUk = du.parseDomain('https://news.bbc.co.uk');
assert.strictEqual(pUk.registrableDomain, 'bbc.co.uk');
assert.strictEqual(pUk.domainStem, 'bbc');
assert.strictEqual(pUk.subdomain, 'news');
assert.strictEqual(pUk.publicSuffix, 'co.uk');

// .co.in
const pIn = du.parseDomain('https://www.google.co.in');
assert.strictEqual(pIn.registrableDomain, 'google.co.in');
assert.strictEqual(pIn.domainStem, 'google');
assert.strictEqual(pIn.subdomain, 'www');
assert.strictEqual(pIn.publicSuffix, 'co.in');

// .bank.in
const pBank = du.parseDomain('https://sbi.bank.in');
assert.strictEqual(pBank.registrableDomain, 'sbi.bank.in');
assert.strictEqual(pBank.domainStem, 'sbi');
assert.strictEqual(pBank.subdomain, '');
assert.strictEqual(pBank.publicSuffix, 'bank.in');

// .com.au
const pAu = du.parseDomain('https://sub.domain.com.au');
assert.strictEqual(pAu.registrableDomain, 'domain.com.au');
assert.strictEqual(pAu.domainStem, 'domain');
assert.strictEqual(pAu.subdomain, 'sub');
assert.strictEqual(pAu.publicSuffix, 'com.au');

console.log('[PASS] Multi-part ccTLDs (.co.uk, .co.in, .bank.in, .com.au) parsed accurately');

// 5. Multi-tenant hosting platforms (PSL Private Domains)
const pGit = du.parseDomain('https://alice.github.io/project');
assert.strictEqual(pGit.registrableDomain, 'alice.github.io');
assert.strictEqual(pGit.domainStem, 'alice');
assert.strictEqual(pGit.publicSuffix, 'github.io');

const pFirebase = du.parseDomain('https://my-app.firebaseapp.com');
assert.strictEqual(pFirebase.registrableDomain, 'my-app.firebaseapp.com');
assert.strictEqual(pFirebase.publicSuffix, 'firebaseapp.com');

console.log('[PASS] Multi-tenant hosting platforms (github.io, firebaseapp.com) parsed as public suffixes');

// 6. PSL Wildcard and Exception rules
// Wildcard *.ck (Cook Islands)
const pWc = du.parseDomain('https://test.foo.ck');
assert.strictEqual(pWc.publicSuffix, 'foo.ck');
assert.strictEqual(pWc.registrableDomain, 'test.foo.ck');

// Exception !www.ck
const pEx = du.parseDomain('https://www.ck');
assert.strictEqual(pEx.publicSuffix, 'ck');
assert.strictEqual(pEx.registrableDomain, 'www.ck');

console.log('[PASS] PSL Wildcards (*.ck) and Exceptions (!www.ck) handled correctly');

// 7. IP Addresses in parseDomain
const pIp4 = du.parseDomain('http://192.168.1.1/admin');
assert.strictEqual(pIp4.isIp, true);
assert.strictEqual(pIp4.ip, '192.168.1.1');
assert.strictEqual(pIp4.registrableDomain, null, 'IP addresses must not produce registrableDomain');
assert.strictEqual(pIp4.isInconclusive, false);

const pIp6 = du.parseDomain('http://[2001:db8::1]:8080');
assert.strictEqual(pIp6.isIp, true);
assert.strictEqual(pIp6.registrableDomain, null);

console.log('[PASS] IPv4 and IPv6 parsed without creating false registrable domains');

// 8. Inconclusive fallback & unlisted multi-part ccTLDs
const pLocal = du.parseDomain('http://localhost');
assert.strictEqual(pLocal.publicSuffixKnown, false);
assert.strictEqual(pLocal.isInconclusive, true);
assert.strictEqual(pLocal.registrableDomain, null);

const pInvalid = du.parseDomain('');
assert.strictEqual(pInvalid.isInconclusive, true);
assert.strictEqual(pInvalid.registrableDomain, null);

// Unlisted multi-part ccTLD (e.g. .co.rw) must produce inconclusive result
const pRw = du.parseDomain('https://example.co.rw');
assert.strictEqual(pRw.publicSuffixKnown, false, 'Unlisted multi-part .co.rw must be marked unknown');
assert.strictEqual(pRw.isInconclusive, true, 'Unlisted multi-part .co.rw must be marked inconclusive');
assert.strictEqual(pRw.registrableDomain, null, 'Unlisted multi-part .co.rw must not produce false registrable domain');

console.log('[PASS] Inconclusive fallback for single-label, malformed, and unlisted multi-part ccTLDs (.co.rw)');

// 9. differentRegistrableDomain
assert.strictEqual(du.differentRegistrableDomain('https://a.google.co.uk', 'https://b.google.co.uk'), false);
assert.strictEqual(du.differentRegistrableDomain('https://a.google.co.uk', 'https://b.yahoo.co.uk'), true);
assert.strictEqual(du.differentRegistrableDomain('https://user1.github.io', 'https://user2.github.io'), true);
assert.strictEqual(du.differentRegistrableDomain('http://192.168.1.1', 'http://192.168.1.1'), false);
assert.strictEqual(du.differentRegistrableDomain('http://192.168.1.1', 'http://192.168.1.2'), true);

// Unlisted multi-part ccTLDs: different hostnames must be treated as different domains
assert.strictEqual(du.differentRegistrableDomain('https://alice.co.rw', 'https://bob.co.rw'), true, 'Different hosts under unlisted ccTLD must be treated as different domains');
assert.strictEqual(du.differentRegistrableDomain('https://alice.co.rw', 'https://alice.co.rw'), false, 'Identical hosts under unlisted ccTLD must be treated as same');
console.log('[PASS] differentRegistrableDomain comparison across multi-part TLDs, IPs, and inconclusive domains');

// 10. decodePunycode & mapHomoglyphs
assert.strictEqual(du.decodePunycode('example.com'), 'example.com');
assert.strictEqual(du.decodePunycode('xn--80ak6aa92e.com'), 'аррӏе.com');

const hMap = du.mapHomoglyphs('xn--80ak6aa92e.com');
assert.strictEqual(hMap.hasConfusable, true);
assert.strictEqual(hMap.normalized, 'apple.com');

const hClean = du.mapHomoglyphs('google.com');
assert.strictEqual(hClean.hasConfusable, false);
assert.strictEqual(hClean.normalized, 'google.com');

const hGreek = du.mapHomoglyphs('gοοgle.com'); // Greek omicron U+03BF
assert.strictEqual(hGreek.hasConfusable, true);
assert.strictEqual(hGreek.normalized, 'google.com');

console.log('[PASS] RFC 3492 Punycode decode and cross-script homoglyph mapping');

console.log('\nAll domain-utils tests passed successfully!');
