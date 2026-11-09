const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadModule() {
  const filePath = path.join(__dirname, '..', 'src', 'shared', 'assessment-aggregator.js');
  const code = fs.readFileSync(filePath, 'utf8');
  
  const sandbox = {
    self: {},
    window: {}
  };
  
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  
  return sandbox.self.BehindTheLink.assessmentAggregator;
}

function runTests() {
  console.log("--- combined-assessment tests ---");
  const aggregator = loadModule();

  // Test 1: No signals -> NO_SIGNALS_DETECTED
  const t1 = aggregator.aggregate([], 'NO_SIGNALS_DETECTED');
  assert.strictEqual(t1.displaySignals.length, 0);
  assert.strictEqual(t1.whyText, null);
  assert.strictEqual(t1.actionText, null);

  // Test 2: One informational signal -> INFORMATIONAL
  const t2 = aggregator.aggregate([{ id: 'ACCOUNT_ACTION', tier: 'C', label: 'Account action' }], 'INFORMATIONAL');
  assert.strictEqual(t2.displaySignals.length, 1);
  assert.strictEqual(t2.displaySignals[0].id, 'ACCOUNT_ACTION');
  assert.strictEqual(t2.whyText, 'This link leads to an account or sign-in action.');
  assert.strictEqual(t2.actionText, 'Check the destination domain before signing in.');

  // Test 3: Two independent contextual dimensions -> UNUSUAL_CHARACTERISTICS
  const sigs3 = [
    { id: 'ACCOUNT_ACTION', tier: 'C', dimension: 'account_action', label: 'Account action' },
    { id: 'URGENT_LANGUAGE', tier: 'C', dimension: 'pressure', label: 'Urgent language' }
  ];
  const t3 = aggregator.aggregate(sigs3, 'UNUSUAL_CHARACTERISTICS');
  assert.strictEqual(t3.displaySignals.length, 2);
  assert.strictEqual(t3.whyText, "This link combines time pressure with an action involving your account or information.");
  assert.strictEqual(t3.actionText, "Check the destination domain before signing in.");

  // Test 4: Claim-destination mismatch -> UNUSUAL_CHARACTERISTICS
  const sigs4 = [{ id: 'CLAIM_DESTINATION_MISMATCH', tier: 'C', label: 'Mismatch' }];
  const t4 = aggregator.aggregate(sigs4, 'UNUSUAL_CHARACTERISTICS');
  assert.strictEqual(t4.displaySignals.length, 1);
  assert.strictEqual(t4.whyText, "The link mentions a brand, but the destination is not an official domain.");
  assert.strictEqual(t4.actionText, "Check the destination domain before entering sensitive information.");

  // Test 5: Strong-warning input
  const sigs5 = [{ id: 'REPUTATION_CONFIRMED_THREAT', tier: 'D', label: 'Threat' }];
  const t5 = aggregator.aggregate(sigs5, 'STRONG_WARNING');
  assert.strictEqual(t5.displaySignals.length, 1);
  assert.strictEqual(t5.displaySignals[0].id, 'REPUTATION_CONFIRMED_THREAT');
  
  // Test 6: Repeated pressure phrases (multiple URGENT_LANGUAGE signals) -> one displayed
  const sigs6 = [
    { id: 'URGENT_LANGUAGE', tier: 'C', dimension: 'pressure', label: 'Urgent' },
    { id: 'URGENT_LANGUAGE', tier: 'C', dimension: 'pressure', label: 'Urgent' }
  ];
  const t6 = aggregator.aggregate(sigs6, 'INFORMATIONAL');
  assert.strictEqual(t6.displaySignals.length, 1);

  // Test 7: Multiple account phrases -> one account signal
  const sigs7 = [
    { id: 'ACCOUNT_ACTION', tier: 'C', dimension: 'account_action', label: 'Account' },
    { id: 'ACCOUNT_ACTION', tier: 'C', dimension: 'account_action', label: 'Account' }
  ];
  const t7 = aggregator.aggregate(sigs7, 'INFORMATIONAL');
  assert.strictEqual(t7.displaySignals.length, 1);

  // Test 8: More than three signals -> maximum 3 displayed
  const sigs8 = [
    { id: 'DEEP_SUBDOMAIN', tier: 'B', dimension: 'hostname_depth', label: 'Deep' },
    { id: 'ACCOUNT_ACTION', tier: 'C', dimension: 'account_action', label: 'Account' },
    { id: 'URGENT_LANGUAGE', tier: 'C', dimension: 'pressure', label: 'Urgent' },
    { id: 'CLAIM_DESTINATION_MISMATCH', tier: 'C', dimension: 'claim_destination', label: 'Mismatch' }
  ];
  const t8 = aggregator.aggregate(sigs8, 'UNUSUAL_CHARACTERISTICS');
  assert.strictEqual(t8.displaySignals.length, 3);
  // Priority: Mismatch (2) > Deep Subdomain (7) > Urgent (20)
  assert.strictEqual(t8.displaySignals[0].id, 'CLAIM_DESTINATION_MISMATCH');
  assert.strictEqual(t8.displaySignals[1].id, 'DEEP_SUBDOMAIN');
  assert.strictEqual(t8.displaySignals[2].id, 'URGENT_LANGUAGE');
  
  // Also checking why text for combo
  assert.strictEqual(t8.whyText, "This link combines a service claim, a verified destination mismatch, and time pressure.");

  // Test 9: Link-type metadata does not automatically become a safety warning
  const sigs9 = [{ id: 'REDIRECTS_THROUGH_SHORTENER', tier: 'A', label: 'Shortener' }];
  const t9 = aggregator.aggregate(sigs9, 'NO_SIGNALS_DETECTED'); // No signals detected because it doesn't escalate on its own
  assert.strictEqual(t9.displaySignals.length, 0);

  // Even if status is INFORMATIONAL, we filter it out of display signals
  const t9b = aggregator.aggregate(sigs9, 'INFORMATIONAL');
  assert.strictEqual(t9b.displaySignals.length, 0);

  // Test 13: Technical signals are humanized
  const sigs13 = [{ id: 'PUNYCODE_DOMAIN', tier: 'B', label: 'Original Label' }];
  const t13 = aggregator.aggregate(sigs13, 'INFORMATIONAL');
  assert.strictEqual(t13.displaySignals[0].label, 'Unusual domain characteristics');

  console.log("All combined-assessment tests passed!");
}

module.exports = runTests;

if (require.main === module) {
  runTests();
}
