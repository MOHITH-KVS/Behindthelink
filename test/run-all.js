const { execSync } = require('child_process');
const tests = [
  'test/test-data-model.js',
  'test/test-safety-analyzer.js',
  'test/test-safety-ui.js',
  'test/test-canonicalization.js',
  'test/test-expression-generator.js',
  'test/test-reputation-engine.js'
];

let allPassed = true;
for (const t of tests) {
  try {
    const output = execSync(`node ${t}`, { encoding: 'utf8' });
    console.log(`=== Output from ${t} ===\n${output.trim()}\n`);
  } catch(e) {
    console.log(`=== Output from ${t} (FAILED) ===\n${e.stdout}\n${e.stderr}\n`);
    allPassed = false;
  }
}

if (!allPassed) process.exit(1);
