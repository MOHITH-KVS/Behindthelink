// Automated logic test for Phase 1H.2.1 result prioritization

function getUiPriority(networkResult) {
  var pred = networkResult.prediction || networkResult;
  var obs = networkResult.browserObservation || null;

  if (pred.status === 'HTTP_CONFIRMED') return 'HTTP_CONFIRMED';
  if (obs && obs.observedLatestUrl) return 'BROWSER_OBSERVED';
  if (pred.status === 'EMBEDDED_CANDIDATE') return 'EMBEDDED_CANDIDATE';
  if (pred.status === 'LOCAL_ONLY') return 'LOCAL_ONLY';
  if (pred.status === 'DIRECT') return 'DIRECT';
  return 'UNCONFIRMED';
}

function runTests() {
  let passed = 0;
  let total = 0;

  function assertEqual(actual, expected, name) {
    total++;
    if (actual === expected) {
      console.log(`[PASS] ${name}`);
      passed++;
    } else {
      console.error(`[FAIL] ${name} - Expected ${expected}, got ${actual}`);
    }
  }

  // A. Network success + same URL
  assertEqual(getUiPriority({ prediction: { status: 'DIRECT' } }), 'DIRECT', 'A. Network success + same URL → DIRECT');

  // B. Network success + redirect
  assertEqual(getUiPriority({ prediction: { status: 'HTTP_CONFIRMED' } }), 'HTTP_CONFIRMED', 'B. Network success + redirect → HTTP_CONFIRMED');

  // C. Network failure + clean URL
  assertEqual(getUiPriority({ prediction: { status: 'LOCAL_ONLY' } }), 'LOCAL_ONLY', 'C. Network failure + clean URL → LOCAL_ONLY');

  // D. Network failure + tracking parameters
  assertEqual(getUiPriority({ prediction: { status: 'UNCONFIRMED' } }), 'UNCONFIRMED', 'D. Network failure + tracking parameters → UNCONFIRMED');

  // E. Network failure + known shortener
  assertEqual(getUiPriority({ prediction: { status: 'UNCONFIRMED' } }), 'UNCONFIRMED', 'E. Network failure + known shortener → UNCONFIRMED');

  // F. Network failure + embedded candidate
  assertEqual(getUiPriority({ prediction: { status: 'EMBEDDED_CANDIDATE' } }), 'EMBEDDED_CANDIDATE', 'F. Network failure + embedded candidate → EMBEDDED_CANDIDATE');

  // G. Network failure + no useful local information
  assertEqual(getUiPriority({ prediction: { status: 'UNCONFIRMED' } }), 'UNCONFIRMED', 'G. Network failure + no useful local info → UNCONFIRMED');

  // H. Existing BROWSER_OBSERVED + network failure (e.g. LOCAL_ONLY or UNCONFIRMED)
  assertEqual(getUiPriority({
    prediction: { status: 'LOCAL_ONLY' },
    browserObservation: { observedLatestUrl: 'example.com' }
  }), 'BROWSER_OBSERVED', 'H1. BROWSER_OBSERVED overrides LOCAL_ONLY');

  assertEqual(getUiPriority({
    prediction: { status: 'UNCONFIRMED' },
    browserObservation: { observedLatestUrl: 'example.com' }
  }), 'BROWSER_OBSERVED', 'H2. BROWSER_OBSERVED overrides UNCONFIRMED');

  console.log(`\nResults: ${passed}/${total} passed`);
}

runTests();
