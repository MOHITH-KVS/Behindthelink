/**
 * "Works for everyone" tests.
 *
 *  1. Fresh installs add the content scripts to tabs that are already open,
 *     but updates and reloads do not (to avoid duplicate cards).
 *  2. Loading the content scripts twice in one page attaches listeners once.
 *  3. Links inside open shadow roots (web components) are found.
 *  4. The manifest is complete, every referenced file exists, and every icon
 *     really has the size in its name and a small file size.
 */
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const queue = [];
const runTest = (name, fn) => queue.push({ name, fn });
// Objects made inside a vm sandbox have a different prototype; compare them as plain data.
const plain = (x) => JSON.parse(JSON.stringify(x));

// ---------- 1. Install-time injection ----------
const MANIFEST = JSON.parse(fs.readFileSync('./manifest.json', 'utf8'));
const CONTENT_FILES = MANIFEST.content_scripts[0].js;
const SW_CODE = fs.readFileSync('./src/background/service-worker.js', 'utf8');

function loadServiceWorker(opts) {
  const log = { queries: [], injections: [] };
  const state = { installedHandler: null };
  const BTL = {};
  const chromeMock = {
    runtime: {
      onMessage: { addListener: () => {} },
      onInstalled: { addListener: (fn) => { state.installedHandler = fn; } },
      getManifest: () => MANIFEST
    },
    tabs: opts.noTabs ? undefined : {
      query: async (q) => { log.queries.push(q); return opts.tabs || []; }
    },
    scripting: opts.noScripting ? undefined : {
      executeScript: async (o) => {
        log.injections.push(o);
        if (opts.failFor && opts.failFor.includes(o.target.tabId)) throw new Error('Cannot access this page');
        return [];
      }
    },
    storage: { local: { get: async () => ({}), set: async () => {}, remove: async () => {} } }
  };
  const sandbox = {
    self: { BehindTheLink: BTL }, window: { BehindTheLink: BTL }, URL, TextDecoder,
    importScripts: () => {}, chrome: chromeMock, setTimeout, clearTimeout, Map, Set,
    console: { log: () => {}, warn: () => {}, error: () => {} }
  };
  vm.createContext(sandbox);
  vm.runInContext(SW_CODE, sandbox);
  return { sandbox, log, state };
}

const TABS = [
  { id: 11, url: 'https://web.telegram.org/a/' },
  { id: 12, url: 'https://www.google.com/search?q=x', discarded: true },
  { id: 13, url: 'https://mail.example.com/' },
  { id: 14, url: 'https://blocked.example.com/' }
];

runTest('ER-001: first install adds the content scripts to open tabs', async () => {
  const { sandbox, log } = loadServiceWorker({ tabs: TABS });
  const r = await sandbox.injectIntoOpenTabs({ reason: 'install' });
  assert.deepStrictEqual(plain(log.queries), [{ url: ['http://*/*', 'https://*/*'] }]);
  assert.strictEqual(r.injected, 3);
  assert.strictEqual(r.skipped, 1, 'discarded tab skipped');
  assert.deepStrictEqual(log.injections.map(i => i.target.tabId), [11, 13, 14]);
  log.injections.forEach(i => assert.deepStrictEqual(plain(i.files), CONTENT_FILES, 'same files, same order as the manifest'));
});

runTest('ER-002: a tab that refuses injection does not stop the others', async () => {
  const { sandbox, log } = loadServiceWorker({ tabs: TABS, failFor: [11] });
  const r = await sandbox.injectIntoOpenTabs({ reason: 'install' });
  assert.strictEqual(r.injected, 2);
  assert.strictEqual(r.skipped, 2);
  assert.deepStrictEqual(log.injections.map(i => i.target.tabId), [11, 13, 14]);
});

runTest('ER-003: updates, reloads and browser updates never inject (avoids duplicate cards)', async () => {
  for (const reason of ['update', 'chrome_update', 'shared_module_update', undefined]) {
    const { sandbox, log } = loadServiceWorker({ tabs: TABS });
    const r = await sandbox.injectIntoOpenTabs({ reason });
    assert.strictEqual(r.injected, 0, String(reason));
    assert.strictEqual(log.injections.length, 0, String(reason));
    assert.strictEqual(log.queries.length, 0, String(reason));
  }
});

runTest('ER-004: the install event is wired to the injection', async () => {
  const { state, log } = loadServiceWorker({ tabs: TABS });
  assert.strictEqual(typeof state.installedHandler, 'function', 'onInstalled listener registered');
  state.installedHandler({ reason: 'install' });
  await new Promise(r => setTimeout(r, 20));
  assert.strictEqual(log.injections.length, 3);
});

runTest('ER-005: missing browser APIs never throw', async () => {
  for (const opts of [{ noScripting: true }, { noTabs: true }]) {
    const { sandbox } = loadServiceWorker(opts);
    const r = await sandbox.injectIntoOpenTabs({ reason: 'install' });
    assert.deepStrictEqual(plain(r), { injected: 0, skipped: 0 });
  }
});

// ---------- 2. Double load ----------
runTest('ER-006: loading the content script twice attaches the listeners once', () => {
  const added = [];
  const sandbox = {
    window: { BehindTheLink: { hoverManager: { handleMouseOver() {}, handleMouseOut() {}, handleClick() {} } } },
    document: { addEventListener: (type) => added.push(type) }
  };
  vm.createContext(sandbox);
  const code = fs.readFileSync('./src/content/content.js', 'utf8');
  vm.runInContext(code, sandbox);
  assert.deepStrictEqual(plain(added), ['mouseover', 'mouseout', 'click']);
  vm.runInContext(code, sandbox);
  assert.strictEqual(added.length, 3, 'second load must not add listeners again');
});

// ---------- 3. Shadow DOM ----------
function loadHover() {
  const timers = [];
  const BTL = {
    HOVER_DELAY: 450,
    isEligible: () => true,
    getResolvedUrl: (a) => a.href,
    previewUI: new Proxy({}, { get: (_, p) => (p === 'getHost' ? () => null : () => {}) })
  };
  const sandbox = {
    window: { BehindTheLink: BTL }, chrome: { runtime: {} },
    setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimeout: () => {},
    console: { log: () => {}, warn: () => {}, error: () => {} }
  };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync('./src/content/hover-manager.js', 'utf8'), sandbox);
  return { hm: sandbox.window.BehindTheLink.hoverManager, timers };
}
const el = (tag, isLink) => ({ nodeType: 1, tagName: tag, matches: (sel) => sel === 'a[href]' && !!isLink });

runTest('ER-007: a link inside an open shadow root is found through the event path', () => {
  const { hm } = loadHover();
  const anchor = el('A', true);
  const hostDiv = el('DIV', false);
  const event = { target: hostDiv, composedPath: () => [el('SPAN', false), anchor, { nodeType: 11 }, hostDiv, el('BODY', false)] };
  assert.strictEqual(hm.findLink(event), anchor);
});

runTest('ER-008: the nearest link wins, and non-links give null', () => {
  const { hm } = loadHover();
  const inner = el('A', true), outer = el('A', true);
  assert.strictEqual(hm.findLink({ target: inner, composedPath: () => [inner, outer] }), inner);
  assert.strictEqual(hm.findLink({ target: el('DIV', false), composedPath: () => [el('DIV', false), el('BODY', false)] }), null);
});

runTest('ER-009: ordinary events without a path still use closest()', () => {
  const { hm } = loadHover();
  const anchor = el('A', true);
  assert.strictEqual(hm.findLink({ target: { closest: (s) => (s === 'a[href]' ? anchor : null) } }), anchor);
  assert.strictEqual(hm.findLink({ target: { closest: () => null } }), null);
});

runTest('ER-010: hovering a shadow-DOM link starts the hover timer', () => {
  const { hm, timers } = loadHover();
  const anchor = el('A', true);
  anchor.href = 'https://example.com/';
  hm.handleMouseOver({ target: el('DIV', false), composedPath: () => [anchor, el('BODY', false)] });
  assert.ok(timers.some(t => t.ms === 450), 'show timer started with the normal hover delay');
});

// ---------- 4. Manifest and icons ----------
runTest('ER-011: manifest is complete and every referenced file exists', () => {
  assert.strictEqual(MANIFEST.manifest_version, 3);
  ['storage', 'webNavigation', 'scripting'].forEach(p => assert.ok(MANIFEST.permissions.includes(p), p));
  CONTENT_FILES.forEach(f => assert.ok(fs.existsSync(f), 'content script missing: ' + f));
  assert.ok(fs.existsSync(MANIFEST.background.service_worker), 'service worker missing');
  assert.ok(fs.existsSync(MANIFEST.options_page), 'options page missing');
});

runTest('ER-012: every icon has the size in its name and a small file', () => {
  const sizes = Object.keys(MANIFEST.icons);
  assert.deepStrictEqual(sizes.sort((a, b) => a - b), ['16', '32', '48', '128']);
  sizes.forEach(size => {
    const file = MANIFEST.icons[size];
    assert.ok(fs.existsSync(file), 'icon missing: ' + file);
    const buf = fs.readFileSync(file);
    assert.strictEqual(buf.toString('ascii', 1, 4), 'PNG', file + ' is a PNG');
    const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
    assert.strictEqual(w, Number(size), file + ' width ' + w);
    assert.strictEqual(h, Number(size), file + ' height ' + h);
    assert.ok(buf.length < 60 * 1024, file + ' should be small, is ' + buf.length + ' bytes');
  });
});

(async () => {
  console.log('=== WORKS-FOR-EVERYONE TESTS ===');
  let passed = 0;
  for (const t of queue) {
    try {
      await t.fn();
      console.log(`[PASS] ${t.name}`);
      passed++;
    } catch (e) {
      console.error(`[FAIL] ${t.name}\n       ${e.message}`);
    }
  }
  console.log(`\nWorks-for-everyone results: ${passed}/${queue.length} passed`);
  if (passed !== queue.length) process.exit(1);
})();
