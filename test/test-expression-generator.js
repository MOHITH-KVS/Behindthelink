const { getHostSuffixes, getPathPrefixes, generateExpressions } = require('../src/shared/reputation/expression-generator.js');

function assertEqual(actual, expected, msg) {
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    console.log('[PASS] ' + msg);
  } else {
    console.error(`[FAIL] ${msg}\n  Expected: ${JSON.stringify(expected)}\n  Got:      ${JSON.stringify(actual)}`);
    process.exitCode = 1;
  }
}

console.log("=== EXPRESSION GENERATOR TESTS ===");

const hostTest1 = getHostSuffixes("a.b.c.d.e.f.g");
assertEqual(hostTest1, ["a.b.c.d.e.f.g", "c.d.e.f.g", "d.e.f.g", "e.f.g", "f.g"], "Host suffixes for >5 components");

const hostTest2 = getHostSuffixes("192.168.1.1");
assertEqual(hostTest2, ["192.168.1.1"], "Host suffixes for IP address");

const hostTest3 = getHostSuffixes("example.com");
assertEqual(hostTest3, ["example.com"], "Host suffixes for 2 components");

const pathTest1 = getPathPrefixes("/1/2/3/4/5/6.html", "?param=1");
assertEqual(pathTest1, [
  "/1/2/3/4/5/6.html?param=1",
  "/1/2/3/4/5/6.html",
  "/",
  "/1/",
  "/1/2/",
  "/1/2/3/"
], "Path prefixes with query and >4 segments");

const pathTest2 = getPathPrefixes("/1/", "");
assertEqual(pathTest2, [
  "/1/",
  "/"
], "Path prefixes for simple path");

const exprsTest = generateExpressions({ host: "a.b.c", path: "/1/2.html", query: "?param=1" });
const expectedExprsTest = [
  "a.b.c/1/2.html?param=1",
  "a.b.c/1/2.html",
  "a.b.c/",
  "a.b.c/1/",
  "b.c/1/2.html?param=1",
  "b.c/1/2.html",
  "b.c/",
  "b.c/1/"
];
assertEqual(exprsTest, expectedExprsTest, "Exact Web Risk example expressions match");

const exprs = generateExpressions({ host: "a.b.c.d.e.f.g", path: "/1/2/3/4/5/6.html", query: "?param=1" });
assertEqual(exprs.length, 30, "Max expressions should be 30");

if (process.exitCode !== 1) {
  console.log(`\nRESULTS: 7 passed`);
}
