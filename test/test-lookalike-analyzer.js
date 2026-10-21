/**
 * BehindTheLink — Lookalike Analyzer Tests
 *
 * Validates the 5 lookalike detection vectors, false-positive protections,
 * and end-to-end integration into safety analysis and aggregation.
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
vm.runInContext(fs.readFileSync('./src/shared/constants.js', 'utf8'), sandbox);
vm.runInContext(fs.readFileSync('./src/shared/brand-registry.js', 'utf8'), sandbox);
vm.runInContext(fs.readFileSync('./src/shared/domain-utils.js', 'utf8'), sandbox);
vm.runInContext(fs.readFileSync('./src/shared/lookalike-analyzer.js', 'utf8'), sandbox);
vm.runInContext(fs.readFileSync('./src/shared/claim-destination-analyzer.js', 'utf8'), sandbox);
vm.runInContext(fs.readFileSync('./src/shared/deception-analyzer.js', 'utf8'), sandbox);
vm.runInContext(fs.readFileSync('./src/shared/assessment-aggregator.js', 'utf8'), sandbox);
vm.runInContext(fs.readFileSync('./src/shared/safety-analyzer.js', 'utf8'), sandbox);

const app = sandbox.window.BehindTheLink;
const la = app.lookalikeAnalyzer;
const sa = app.safetyAnalyzer;

console.log('--- RUNNING LOOKALIKE ANALYZER TESTS ---');

// ==========================================
// 1. Vector 1: Misleading Subdomain Structure
// ==========================================
const sub1 = la.detectLookalike('https://paypal.com.account-update.xyz');
assert(sub1, 'paypal.com.account-update.xyz must be flagged');
assert.strictEqual(sub1.signalId, 'MISLEADING_SUBDOMAIN_STRUCTURE');
assert.strictEqual(sub1.detectionType, 'SUBDOMAIN_BRAND_MASQUERADE');
assert.strictEqual(sub1.brandId, 'PAYPAL');

const sub2 = la.detectLookalike('https://login.microsoft.com.attacker.com');
assert(sub2, 'login.microsoft.com.attacker.com must be flagged');
assert.strictEqual(sub2.signalId, 'MISLEADING_SUBDOMAIN_STRUCTURE');
assert.strictEqual(sub2.brandId, 'MICROSOFT');

const sub3 = la.detectLookalike('https://paypal-com.attacker.com');
assert(sub3, 'paypal-com.attacker.com must be flagged');
assert.strictEqual(sub3.signalId, 'MISLEADING_SUBDOMAIN_STRUCTURE');

console.log('[PASS] Vector 1: Misleading Subdomain Structure detected');

// ==========================================
// 2. Vector 2: Unicode Homoglyphs & Punycode
// ==========================================
const uni1 = la.detectLookalike('https://xn--80ak6aa92e.com'); // Cyrillic аррӏе.com
assert(uni1, 'Cyrillic apple punycode must be flagged');
assert.strictEqual(uni1.signalId, 'LOOKALIKE_DOMAIN_SIMILARITY');
assert.strictEqual(uni1.detectionType, 'UNICODE_CONFUSABLE');
assert.strictEqual(uni1.brandId, 'APPLE');

const uni2 = la.detectLookalike('https://gοοgle.com'); // Greek omicrons
assert(uni2, 'Greek omicron google must be flagged');
assert.strictEqual(uni2.signalId, 'LOOKALIKE_DOMAIN_SIMILARITY');
assert.strictEqual(uni2.detectionType, 'UNICODE_CONFUSABLE');
assert.strictEqual(uni2.brandId, 'GOOGLE');

console.log('[PASS] Vector 2: Unicode homoglyphs and Punycode confusables detected');

// ==========================================
// 3. Vector 3: Bounded Digit Substitution
// ==========================================
const dig1 = la.detectLookalike('https://g00gle.com');
assert(dig1, 'g00gle.com must be flagged');
assert.strictEqual(dig1.detectionType, 'DIGIT_SUBSTITUTION');
assert.strictEqual(dig1.brandId, 'GOOGLE');

const dig2 = la.detectLookalike('https://paypa1.com');
assert(dig2, 'paypa1.com must be flagged');
assert.strictEqual(dig2.detectionType, 'DIGIT_SUBSTITUTION');
assert.strictEqual(dig2.brandId, 'PAYPAL');

const dig3 = la.detectLookalike('https://micros0ft.com');
assert(dig3, 'micros0ft.com must be flagged');
assert.strictEqual(dig3.detectionType, 'DIGIT_SUBSTITUTION');
assert.strictEqual(dig3.brandId, 'MICROSOFT');

const dig4 = la.detectLookalike('https://amaz0n.com');
assert(dig4, 'amaz0n.com must be flagged');
assert.strictEqual(dig4.detectionType, 'DIGIT_SUBSTITUTION');
assert.strictEqual(dig4.brandId, 'AMAZON');

console.log('[PASS] Vector 3: Bounded digit substitutions detected');

// ==========================================
// 4. Vector 4: Bounded Edit Distance
// ==========================================
const ed1 = la.detectLookalike('https://gooogle.com'); // Insertion
assert(ed1, 'gooogle.com must be flagged');
assert.strictEqual(ed1.detectionType, 'TYPOSQUAT_EDIT_DISTANCE');
assert.strictEqual(ed1.brandId, 'GOOGLE');

const ed2 = la.detectLookalike('https://gogle.com'); // Deletion
assert(ed2, 'gogle.com must be flagged');
assert.strictEqual(ed2.detectionType, 'TYPOSQUAT_EDIT_DISTANCE');
assert.strictEqual(ed2.brandId, 'GOOGLE');

const ed3 = la.detectLookalike('https://googel.com'); // Transposition
assert(ed3, 'googel.com must be flagged');
assert.strictEqual(ed3.detectionType, 'TYPOSQUAT_EDIT_DISTANCE');
assert.strictEqual(ed3.brandId, 'GOOGLE');

const ed4 = la.detectLookalike('https://microsft.com'); // Deletion
assert(ed4, 'microsft.com must be flagged');
assert.strictEqual(ed4.detectionType, 'TYPOSQUAT_EDIT_DISTANCE');
assert.strictEqual(ed4.brandId, 'MICROSOFT');

console.log('[PASS] Vector 4: Bounded edit-distance typosquatting detected');

// ==========================================
// 5. Vector 5: Brand Tokens Embedded in Unrelated Domains
// ==========================================
const emb1 = la.detectLookalike('https://paypal-security.com');
assert(emb1, 'paypal-security.com must be flagged');
assert.strictEqual(emb1.signalId, 'BRAND_EMBEDDED_IN_UNRELATED_DOMAIN');
assert.strictEqual(emb1.brandId, 'PAYPAL');

const emb2 = la.detectLookalike('https://netflix-billing.com');
assert(emb2, 'netflix-billing.com must be flagged');
assert.strictEqual(emb2.brandId, 'NETFLIX');

const emb3 = la.detectLookalike('https://apple-security.com');
assert(emb3, 'apple-security.com must be flagged');
assert.strictEqual(emb3.brandId, 'APPLE');

const emb4 = la.detectLookalike('https://sbi-login.com');
assert(emb4, 'sbi-login.com must be flagged');
assert.strictEqual(emb4.brandId, 'SBI');

const emb5 = la.detectLookalike('https://axis-banking.com');
assert(emb5, 'axis-banking.com must be flagged');
assert.strictEqual(emb5.brandId, 'AXIS');

console.log('[PASS] Vector 5: Embedded brand tokens with sensitive keywords detected');

// ==========================================
// 6. False-Positive Protections: Official & Regional Domains
// ==========================================
assert.strictEqual(la.detectLookalike('https://www.google.com'), null);
assert.strictEqual(la.detectLookalike('https://www.google.co.in'), null);
assert.strictEqual(la.detectLookalike('https://microsoft.com'), null);
assert.strictEqual(la.detectLookalike('https://apple.com'), null);
assert.strictEqual(la.detectLookalike('https://sbi.bank.in'), null);
assert.strictEqual(la.detectLookalike('https://hdfc.bank.in'), null);
assert.strictEqual(la.detectLookalike('https://axis.bank.in'), null);
assert.strictEqual(la.detectLookalike('https://amazon.co.uk'), null);
assert.strictEqual(la.detectLookalike('https://amazon.in'), null);
console.log('[PASS] Official primary and regional domains are never flagged');

// ==========================================
// 7. False-Positive Protections: Scoped Services & Hosting Exclusions
// ==========================================
assert.strictEqual(la.detectLookalike('https://paypal.me/john'), null);
assert.strictEqual(la.detectLookalike('https://wa.me/919876543210'), null);
assert.strictEqual(la.detectLookalike('https://t.me/telegram_channel'), null);
assert.strictEqual(la.detectLookalike('https://pay.google.com/intl/en'), null);
assert.strictEqual(la.detectLookalike('https://alice.github.io'), null);
console.log('[PASS] Approved scoped services and legitimate hosting platforms not flagged');

// ==========================================
// 8. False-Positive Protections: Generic Words & Short Stems
// ==========================================
// Generic word 'apple' should NOT trigger on close words or benign combinations
assert.strictEqual(la.detectLookalike('https://apply.com'), null, 'apply.com must not be flagged for apple');
assert.strictEqual(la.detectLookalike('https://maple.com'), null, 'maple.com must not be flagged for apple');
assert.strictEqual(la.detectLookalike('https://apple-pie.com'), null, 'apple-pie.com must not be flagged without sensitive keyword');
assert.strictEqual(la.detectLookalike('https://pineapple.com'), null, 'pineapple must not be flagged (no token boundary)');

// Short stems without sensitive keywords or substring collisions
assert.strictEqual(la.detectLookalike('https://sb1.com'), null, 'sb1.com without sensitive keyword should not be flagged');
assert.strictEqual(la.detectLookalike('https://metallic.com'), null, 'metallic must not match meta');
assert.strictEqual(la.detectLookalike('https://broadway.com'), null, 'broadway must not match aws');
console.log('[PASS] Generic words and short stems protected against false positives');

// ==========================================
// 9. False-Positive Protections: Third-Party OAuth & Inputs
// ==========================================
assert.strictEqual(la.detectLookalike('https://legit-saas.com/auth/google'), null);
assert.strictEqual(la.detectLookalike('https://developer.service.org/oauth2/v2/microsoft'), null);
assert.strictEqual(la.detectLookalike('https://münchen.de'), null);
assert.strictEqual(la.detectLookalike('http://192.168.1.1'), null);
assert.strictEqual(la.detectLookalike('http://[2001:db8::1]'), null);
assert.strictEqual(la.detectLookalike('ftp://microsoft.com'), null);
assert.strictEqual(la.detectLookalike(''), null);
assert.strictEqual(la.detectLookalike(null), null);
console.log('[PASS] Third-party OAuth routes, IPs, IDNs, and non-HTTP(S) inputs protected');

// ==========================================
// 10. End-to-End Safety Analyzer Integration
// ==========================================

// 10a. Lookalike alone on ordinary link: must be INFORMATIONAL, never STRONG_WARNING
const netEvDirect = { status: 'NO_REDIRECT_OBSERVED' };
const resAlone = sa.computeSafetyEvidence(
  'https://g00gle.com',
  { isShortened: false, isHttps: true },
  { signals: [] },
  null,
  null,
  netEvDirect,
  null,
  null,
  null
);

assert.strictEqual(resAlone.status, 'INFORMATIONAL', 'Standalone lookalike must produce INFORMATIONAL status');
assert.strictEqual(resAlone.localStatus, 'INFORMATIONAL');
const lookalikeSig = resAlone.signals.find(s => s.id === 'LOOKALIKE_DOMAIN_SIMILARITY');
assert(lookalikeSig, 'LOOKALIKE_DOMAIN_SIMILARITY signal must be present');
assert.strictEqual(lookalikeSig.tier, 'C');
assert.strictEqual(lookalikeSig.dimension, 'brand_identity');
assert.strictEqual(lookalikeSig.epistemic, 'HEURISTIC');

// 10b. Lookalike on sensitive link (e.g. ACCOUNT_ACTION context): 2 dimensions -> UNUSUAL_CHARACTERISTICS
const resSensitive = sa.computeSafetyEvidence(
  'https://g00gle.com',
  { isShortened: false, isHttps: true },
  { signals: [] },
  null,
  null,
  netEvDirect,
  null,
  null,
  {
    category: 'LOGIN_ACCOUNT',
    visibleText: 'Please sign in to update your account'
  }
);

assert.strictEqual(resSensitive.status, 'UNUSUAL_CHARACTERISTICS', 'Lookalike with sensitive action context must escalate to UNUSUAL_CHARACTERISTICS');
assert.strictEqual(resSensitive.localStatus, 'UNUSUAL_CHARACTERISTICS');

// 10c. Lookalike + Known Threat reputation: STRONG_WARNING comes STRICTLY from reputation
const resThreat = sa.computeSafetyEvidence(
  'https://g00gle.com',
  { isShortened: false, isHttps: true },
  { signals: [] },
  null,
  null,
  netEvDirect,
  null,
  { status: 'REPUTATION_CONFIRMED_THREAT', threatTypes: ['MALWARE'] },
  null
);

assert.strictEqual(resThreat.status, 'STRONG_WARNING', 'Known threat must produce STRONG_WARNING');
assert.strictEqual(resThreat.localStatus, 'INFORMATIONAL', 'Local status must remain INFORMATIONAL without threat engine');

// 10d. Unresolved shortener: lookalike detection must NOT evaluate unverified destination
const resShortener = sa.computeSafetyEvidence(
  'https://bit.ly/xyz123',
  { isShortened: true, isHttps: true },
  { signals: [] },
  null,
  null,
  { status: 'FAILED' },
  { status: 'NONE' },
  null,
  null
);

assert.strictEqual(resShortener.assessmentBasis, 'INCOMPLETE');
assert.strictEqual(resShortener.signals.some(s => s.id === 'LOOKALIKE_DOMAIN_SIMILARITY'), false, 'Lookalike must not run on unresolved shorteners');

console.log('[PASS] Safety Analyzer end-to-end status determination & dimension constraints');

// ==========================================
// 11. User Guidance & Aggregation Output
// ==========================================
assert(resAlone.userGuidance, 'userGuidance must be generated');
assert.strictEqual(resAlone.userGuidance.displaySignals.length, 1);
assert.strictEqual(resAlone.userGuidance.displaySignals[0].label, 'The destination domain closely resembles a known brand.');
assert.strictEqual(resAlone.userGuidance.whyText, 'The destination domain closely resembles a known brand, but is not verified as official.');
assert.strictEqual(resAlone.userGuidance.actionText, 'Check the domain spelling carefully before proceeding or signing in.');

assert(resSensitive.userGuidance, 'userGuidance for sensitive link must be generated');
assert.strictEqual(resSensitive.userGuidance.whyText, 'The destination closely resembles a known brand and requests account or sensitive actions.');

console.log('[PASS] Assessment Aggregator user guidance and human-readable text verified');

console.log('\nAll lookalike-analyzer tests passed successfully!');
