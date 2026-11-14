/**
 * Network guard tests.
 *
 *  1. isPrivateOrLocalHost recognises loopback, private, link-local, CGNAT,
 *     IPv6 local ranges and internal names, and leaves public hosts alone.
 *  2. The hover resolver never contacts private/local destinations, reports
 *     them as PRIVATE_ADDRESS, and sends requests without cookies or referrer.
 */
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

let passed = 0;
let total = 0;
const queue = [];
function runTest(name, fn) {
  queue.push({ name, fn });
}

function makeSandbox(fetchImpl, calls) {
  const BTL = {};
  const sandbox = {
    window: { BehindTheLink: BTL },
    self: { BehindTheLink: BTL },
    BTL: BTL,
    URL: URL,
    TextDecoder: TextDecoder,
    decodeURIComponent: decodeURIComponent,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    Map: Map,
    Set: Set,
    console: { log: () => {}, warn: () => {}, error: console.error },
    chrome: {
      storage: { local: { get: async () => ({}), set: async () => {}, remove: async () => {} } },
      runtime: { onMessage: { addListener: () => {} } }
    },
    AbortController: class AbortController {
      constructor() { this.signal = {}; }
      abort() {}
    },
    fetch: async (url, opts) => {
      calls.push({ url: String(url), opts: opts || {} });
      return fetchImpl(String(url), opts || {});
    }
  };
  vm.createContext(sandbox);
  [
    './src/shared/constants.js',
    './src/shared/brand-registry.js',
    './src/shared/domain-utils.js',
    './src/content/tracking-registry.js',
    './src/content/shortener-registry.js',
    './src/content/affiliate-registry.js',
    './src/content/url-analyzer.js'
  ].forEach(f => vm.runInContext(fs.readFileSync(f, 'utf8'), sandbox));

  vm.runInContext(
    'const activeRequests = new Map(); const TIMEOUT_MS = 5000; const MAX_HOPS = 5; function logDiagnostic() {}',
    sandbox
  );
  const sw = fs.readFileSync('./src/background/service-worker.js', 'utf8');
  const helperStart = sw.indexOf('const MAX_BYTES =');
  const resolverStart = sw.indexOf('async function resolveDestination');
  assert.ok(helperStart >= 0 && resolverStart > helperStart, 'service worker slice located');
  const helpers = sw.substring(helperStart, resolverStart);
  const resolver = sw.substring(resolverStart, sw.indexOf('// ============================================================================', resolverStart));
  vm.runInContext(helpers + '\n' + resolver + '\nself.BehindTheLink.resolveDestination = resolveDestination;', sandbox);
  return sandbox.self.BehindTheLink;
}

const domainBtl = makeSandbox(async (u) => ({ url: u, status: 200 }), []);
const isPrivate = (h) => domainBtl.domainUtils.isPrivateOrLocalHost(h);

// ---------- 1. Host classification ----------
runTest('NG-001: loopback, private, link-local, CGNAT and reserved IPv4 are private', () => {
  ['127.0.0.1', '127.1.2.3', '10.0.0.5', '172.16.0.1', '172.31.255.255', '192.168.1.1',
   '169.254.169.254', '100.64.0.1', '100.127.255.255', '0.0.0.0', '224.0.0.1', '255.255.255.255']
    .forEach(h => assert.strictEqual(isPrivate(h), true, h));
});

runTest('NG-002: public IPv4 addresses next to private ranges are not private', () => {
  ['8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1', '100.63.255.255', '100.128.0.1', '193.168.1.1', '192.169.0.1']
    .forEach(h => assert.strictEqual(isPrivate(h), false, h));
});

runTest('NG-003: IPv6 loopback, unique-local, link-local and mapped private addresses', () => {
  ['[::1]', '[::]', '[fd12:3456::1]', '[fc00::1]', '[fe80::1]', '[ff02::1]', '[::ffff:7f00:1]', '[::ffff:c0a8:101]']
    .forEach(h => assert.strictEqual(isPrivate(h), true, h));
  assert.strictEqual(isPrivate('[2001:4860:4860::8888]'), false);
  assert.strictEqual(isPrivate('[::ffff:808:808]'), false, 'mapped 8.8.8.8 is public');
});

runTest('NG-004: internal names and single-label hosts are private', () => {
  ['localhost', 'LOCALHOST', 'host.localhost', 'router', 'printer.lan', 'nas.local', 'app.internal',
   'box.home.arpa', 'wiki.intranet', 'files.corp', 'localhost.']
    .forEach(h => assert.strictEqual(isPrivate(h), true, h));
});

runTest('NG-005: ordinary public hostnames are not private', () => {
  ['example.com', 'www.amazon.in', 't.me', 'a.b.co.in', 'localhost.example.com', 'notlocal.com', 'internal.example.org']
    .forEach(h => assert.strictEqual(isPrivate(h), false, h));
});

runTest('NG-006: empty and non-string input is not treated as private', () => {
  [undefined, null, '', 42, {}].forEach(h => assert.strictEqual(isPrivate(h), false));
});

runTest('NG-007: numeric host tricks are caught after URL normalization', () => {
  ['http://2130706433/', 'http://0x7f.1/', 'http://017700000001/', 'http://[::ffff:127.0.0.1]/']
    .forEach(u => assert.strictEqual(isPrivate(new URL(u).hostname), true, u));
});

// ---------- 2. Resolver behaviour ----------
runTest('NG-008: a link to a private address is never fetched', async () => {
  const calls = [];
  const BTL = makeSandbox(async (u) => ({ url: u, status: 200 }), calls);
  for (const target of ['http://192.168.1.1/reset', 'http://localhost:8080/admin', 'http://169.254.169.254/latest/meta-data/', 'http://router/']) {
    const res = await BTL.resolveDestination(target, 1);
    assert.strictEqual(res.networkEvidence.status, 'FAILED', target);
    assert.strictEqual(res.networkEvidence.errorReason, 'PRIVATE_ADDRESS', target);
  }
  assert.strictEqual(calls.length, 0, 'no network request may be made to private targets');
});

runTest('NG-009: public links are still checked, without cookies or referrer', async () => {
  const calls = [];
  const BTL = makeSandbox(async (u) => ({ url: u, status: 200 }), calls);
  const res = await BTL.resolveDestination('https://example.com/', 2);
  assert.strictEqual(res.networkEvidence.status, 'NO_REDIRECT_OBSERVED');
  assert.ok(calls.length > 0, 'public link is still checked');
  calls.forEach(c => {
    assert.strictEqual(c.opts.credentials, 'omit', 'cookies must not be sent');
    assert.strictEqual(c.opts.referrerPolicy, 'no-referrer', 'referrer must not be sent');
  });
});

runTest('NG-010: a public link that redirects into a private address is reported as PRIVATE_ADDRESS', async () => {
  const calls = [];
  const BTL = makeSandbox(async (u) => {
    if (u.startsWith('https://short.example.org/')) return { url: 'http://192.168.0.1/admin', status: 200 };
    return { url: u, status: 200 };
  }, calls);
  const res = await BTL.resolveDestination('https://short.example.org/abc', 3);
  assert.strictEqual(res.networkEvidence.status, 'FAILED');
  assert.strictEqual(res.networkEvidence.errorReason, 'PRIVATE_ADDRESS');
  assert.strictEqual(res.networkEvidence.redirectTarget, null, 'private redirect target is not surfaced as a destination');
});

runTest('NG-011: a normal redirect to a public site is unchanged', async () => {
  const calls = [];
  const BTL = makeSandbox(async (u) => {
    if (u.startsWith('https://bit.ly/')) return { url: 'https://www.wikipedia.org/', status: 200 };
    return { url: u, status: 200 };
  }, calls);
  const res = await BTL.resolveDestination('https://bit.ly/abc', 4);
  assert.strictEqual(res.networkEvidence.status, 'HTTP_REDIRECT_OBSERVED');
  assert.strictEqual(res.networkEvidence.redirectTarget, 'https://www.wikipedia.org/');
});

(async () => {
  console.log('=== NETWORK GUARD TESTS ===');
  for (const t of queue) {
    total++;
    try {
      await t.fn();
      console.log(`[PASS] ${t.name}`);
      passed++;
    } catch (e) {
      console.error(`[FAIL] ${t.name}\n       ${e.message}`);
    }
  }
  console.log(`\nNetwork guard results: ${passed}/${total} passed`);
  if (passed !== total) process.exit(1);
})();
