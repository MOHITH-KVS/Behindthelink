const { computeHash, getPrefix, toBase64, isHashEqual } = require('../src/shared/reputation/hash-utils.js');

async function runTests() {
  let passed = 0;
  function assertEqual(actual, expected, msg) {
    if (actual === expected) {
      console.log('[PASS] ' + msg);
      passed++;
    } else {
      console.error(`[FAIL] ${msg}\n  Expected: ${expected}\n  Got:      ${actual}`);
      process.exitCode = 1;
    }
  }

  console.log("=== HASH UTILS TESTS ===");

  const hash = await computeHash("test");
  assertEqual(hash.length, 32, "Hash is 32 bytes");

  // SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  const expectedHex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
  const actualHex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  assertEqual(actualHex, expectedHex, "Hash matches standard SHA-256");

  const prefix = getPrefix(hash);
  assertEqual(prefix.length, 4, "Prefix is 4 bytes");
  
  const prefixHex = Array.from(prefix).map(b => b.toString(16).padStart(2, '0')).join('');
  assertEqual(prefixHex, "9f86d081", "Prefix matches first 4 bytes");

  const b64 = toBase64(prefix);
  assertEqual(b64, "n4bQgQ==", "Base64 encoding matches");

  const equal1 = isHashEqual(hash, hash);
  assertEqual(equal1, true, "Hash equality matches same arrays");

  const hash2 = await computeHash("test2");
  const equal2 = isHashEqual(hash, hash2);
  assertEqual(equal2, false, "Hash equality fails different arrays");

  if (process.exitCode !== 1) {
    console.log(`\nRESULTS: ${passed} passed`);
  }
}

runTests().catch(e => {
  console.error(e);
  process.exitCode = 1;
});
