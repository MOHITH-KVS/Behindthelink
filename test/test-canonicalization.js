const { parseAndCanonicalize } = require('../src/shared/reputation/canonicalization.js');

let testCases = 0;
let assertions = 0;
let passedAssertions = 0;

function assertEqual(actual, expected, msg) {
  assertions++;
  if (actual === expected) {
    passedAssertions++;
  } else {
    console.error(`[FAIL] ${msg}\n  Expected: ${expected}\n  Got:      ${actual}`);
    process.exitCode = 1;
  }
}

function assertThrows(fn, msg) {
  assertions++;
  try {
    fn();
    console.error(`[FAIL] ${msg}\n  Expected an error to be thrown`);
    process.exitCode = 1;
  } catch(e) {
    passedAssertions++;
  }
}

console.log("=== CANONICALIZATION TESTS ===");

const vectors = [
  // Repeated percent unescaping
  { url: "http://host/%25%32%35", expectedHost: "host", expectedPath: "/%25", expectedQuery: "", desc: "Repeated percent unescaping" },
  { url: "http://host/%25%32%35%25%32%35", expectedHost: "host", expectedPath: "/%25%25", expectedQuery: "", desc: "Repeated percent unescaping 2" },
  { url: "http://host/%2525252525252525", expectedHost: "host", expectedPath: "/%25", expectedQuery: "", desc: "Repeated percent unescaping 3" },
  { url: "http://host/asdf%25%32%35asd", expectedHost: "host", expectedPath: "/asdf%25asd", expectedQuery: "", desc: "Percent unescaping with text" },
  { url: "http://host/%%%25%32%35asd%%", expectedHost: "host", expectedPath: "/%25%25%25asd%25%25", expectedQuery: "", desc: "Percent unescaping with multiple %" },
  
  // Normal URL
  { url: "http://www.google.com/", expectedHost: "www.google.com", expectedPath: "/", expectedQuery: "", desc: "Normal URL" },
  
  // IPs and DOT resolution
  { url: "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%2E/%2E%2E/%2E%2E/%2E%2E/", expectedHost: "168.188.99.26", expectedPath: "/", expectedQuery: "", desc: "IP address and extensive dot dot resolution" },
  { url: "http://192.168.1.1/foo/bar/../", expectedHost: "192.168.1.1", expectedPath: "/foo/", expectedQuery: "", desc: "Dot dot resolution in path" },
  { url: "http://1.2.3.4/foo/bar/../../", expectedHost: "1.2.3.4", expectedPath: "/", expectedQuery: "", desc: "Double dot dot resolution in path" },
  { url: "http://1.2.3.4/foo/bar/./././", expectedHost: "1.2.3.4", expectedPath: "/foo/bar/", expectedQuery: "", desc: "Dot resolution in path" },
  
  // Queries and Fragments
  { url: "http://host.com/a/b?q=../..", expectedHost: "host.com", expectedPath: "/a/b", expectedQuery: "?q=../..", desc: "Query is NOT path normalized" },
  { url: "http://host.com/path#fragment", expectedHost: "host.com", expectedPath: "/path", expectedQuery: "", desc: "Remove fragment" },
  
  // Path slashes
  { url: "http://host.com/a//b///c", expectedHost: "host.com", expectedPath: "/a/b/c", expectedQuery: "", desc: "Collapse consecutive slashes" },
  
  // Hostname dots
  { url: "http://..host.com../path", expectedHost: "host.com", expectedPath: "/path", expectedQuery: "", desc: "Strip leading trailing dots in host" },
  { url: "http://host...com/path", expectedHost: "host.com", expectedPath: "/path", expectedQuery: "", desc: "Collapse consecutive dots in host" },
  { url: "http://HoSt.cOm/PaTh", expectedHost: "host.com", expectedPath: "/PaTh", expectedQuery: "", desc: "Lowercase host, preserve path case" },
  
  // Cleanups
  { url: "http://host.com/pa\rth\n", expectedHost: "host.com", expectedPath: "/path", expectedQuery: "", desc: "Remove CR/LF" },
  { url: "http://user:pass@host.com:8080/path", expectedHost: "host.com", expectedPath: "/path", expectedQuery: "", desc: "Discard user/pass/port" },
  
  // IPv4 alternatives
  { url: "http://3279880203/path", expectedHost: "195.127.0.11", expectedPath: "/path", expectedQuery: "", desc: "Dword IP format normalization" },
  
  // IPv6
  { url: "http://[2001:db8::1]:8080/path", expectedHost: "2001:db8::1", expectedPath: "/path", expectedQuery: "", desc: "IPv6 format normalization" },
  { url: "http://[2001:db8:85a3:8d3:1319:8a2e:370:7348]/", expectedHost: "2001:db8:85a3:8d3:1319:8a2e:370:7348", expectedPath: "/", expectedQuery: "", desc: "IPv6 format normalization 2" },
  
  // Edge cases
  { url: "http://host.com", expectedHost: "host.com", expectedPath: "/", expectedQuery: "", desc: "Empty path becomes slash" }
];

vectors.forEach(v => {
  testCases++;
  const result = parseAndCanonicalize(v.url);
  assertEqual(result.host, v.expectedHost, `${v.desc} - Host`);
  assertEqual(result.path, v.expectedPath, `${v.desc} - Path`);
  assertEqual(result.query, v.expectedQuery, `${v.desc} - Query`);
});

// Negative Tests (Malformed URLs)
console.log("\n=== NEGATIVE TESTS ===");

const negativeVectors = [
  { url: "http://[2001:db8::1/path", desc: "Malformed IPv6 (missing closing bracket)" },
  { url: "http://host.com:6553600000000/path", desc: "Invalid port number" },
  { url: "http://a b.com/", desc: "Invalid space in hostname" },
  { url: "http://%zz.com/", desc: "Invalid percent encoding in hostname" }
];

negativeVectors.forEach(v => {
  testCases++;
  assertThrows(() => {
    parseAndCanonicalize(v.url);
  }, v.desc);
});

if (process.exitCode !== 1) {
  console.log(`\nRESULTS: ${testCases} Test Cases passed. (${passedAssertions}/${assertions} Assertions)`);
}
