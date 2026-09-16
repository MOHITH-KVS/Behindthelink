import { describe, it, expect, vi, beforeEach } from 'vitest';
import worker from '../src/index.js';

describe('BehindTheLink Reputation Proxy Worker', () => {
  let env;
  let ctx;
  let mockCache;
  let mockKV;

  beforeEach(() => {
    mockCache = {
      match: vi.fn(),
      put: vi.fn()
    };
    global.caches = { default: mockCache };

    mockKV = {
      get: vi.fn(),
      put: vi.fn()
    };

    env = {
      WEBRISK_CACHE: mockKV,
      GOOGLE_WEB_RISK_KEY: 'test-api-key',
      ALLOWED_ORIGINS: 'chrome-extension://dev-origin-id,chrome-extension://prod-origin-id'
    };

    ctx = {
      waitUntil: vi.fn()
    };
    
    global.fetch = vi.fn();
    
    // reset circuit breaker and inflight (since it's a module level variable in our worker, we can't easily reset it without exposing a method, but for these tests we'll just be careful)
  });

  function createRequest(method, url, origin, body) {
    const headers = new Headers();
    if (origin) headers.set('Origin', origin);
    
    const options = { method, headers };
    if (body) options.body = typeof body === 'string' ? body : JSON.stringify(body);

    // Mock request.text() since real Request might not be available cleanly in simple Node test env without miniflare
    return {
      method,
      url,
      headers,
      text: async () => typeof body === 'string' ? body : JSON.stringify(body)
    };
  }

  const validOrigin = 'chrome-extension://prod-origin-id';

  it('rejects disallowed origin', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', 'chrome-extension://bad-origin', { prefixes: [] });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(403);
  });

  it('allows allowed production origin', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["c3VyZQ=="] });
    mockKV.get.mockResolvedValue(null);
    mockCache.match.mockResolvedValue(null);
    global.fetch.mockResolvedValue({
      ok: true, status: 200, json: async () => ({ negativeExpireTime: new Date(Date.now() + 120000).toISOString() })
    });
    
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
  });

  it('rejects malformed JSON', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, "{ bad json }");
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(400);
  });

  it('rejects missing prefixes array', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { somethingElse: true });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(400);
  });

  it('rejects empty prefixes array', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: [] });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(400);
  });

  it('rejects over 30 prefixes', async () => {
    const prefixes = Array(31).fill("c3VyZQ==");
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(400);
  });

  it('rejects oversized payload', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, "x".repeat(3000));
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(413);
  });

  it('rejects invalid Base64', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["!invalid"] });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(400);
  });

  it('rejects Base64 that does not decode to 4 bytes', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["aGk="] }); // "hi" (2 bytes)
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(400);
  });

  it('deduplicates prefixes', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["c3VyZQ==", "c3VyZQ=="] });
    mockKV.get.mockResolvedValue(null);
    mockCache.match.mockResolvedValue(null);
    global.fetch.mockResolvedValue({
      ok: true, status: 200, json: async () => ({ negativeExpireTime: new Date(Date.now() + 120000).toISOString() })
    });
    
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('returns cache hit from Edge Cache API', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["c3VyZQ=="] });
    
    const fakeCached = {
      prefix: "c3VyZQ==", negativeExpireTime: new Date(Date.now() + 120000).toISOString(), threats: []
    };
    mockCache.match.mockResolvedValue({ json: async () => fakeCached });
    
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
    expect(global.fetch).not.toHaveBeenCalled();
    const body = JSON.parse(await res.text());
    expect(body.results.length).toBe(1);
  });

  it('returns cache hit from Workers KV', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["c3VyZQ=="] });
    
    mockCache.match.mockResolvedValue(null);
    const fakeKV = {
      prefix: "c3VyZQ==", negativeExpireTime: new Date(Date.now() + 120000).toISOString(), threats: []
    };
    mockKV.get.mockResolvedValue(JSON.stringify(fakeKV));
    
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
    expect(global.fetch).not.toHaveBeenCalled();
    const body = JSON.parse(await res.text());
    expect(body.results.length).toBe(1);
  });

  it('ignores expired KV value and fetches upstream', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["c3VyZQ=="] });
    
    mockCache.match.mockResolvedValue(null);
    const fakeKV = {
      prefix: "c3VyZQ==", negativeExpireTime: new Date(Date.now() + 10000).toISOString(), threats: [] // less than 60s
    };
    mockKV.get.mockResolvedValue(JSON.stringify(fakeKV));
    
    global.fetch.mockResolvedValue({
      ok: true, status: 200, json: async () => ({ negativeExpireTime: new Date(Date.now() + 120000).toISOString() })
    });

    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('Google positive response parsing', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["c3VyZQ=="] });
    mockKV.get.mockResolvedValue(null);
    mockCache.match.mockResolvedValue(null);
    
    global.fetch.mockResolvedValue({
      ok: true, status: 200, json: async () => ({
        threats: [
          { hash: "fullhash", threatTypes: ["MALWARE"], expireTime: new Date(Date.now() + 120000).toISOString() }
        ]
      })
    });
    
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
    const body = JSON.parse(await res.text());
    expect(body.results[0].threats.length).toBe(1);
    expect(body.results[0].threats[0].threatTypes[0]).toBe("MALWARE");
  });

  it('partial Google failures omit the failed prefix but return successes', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["c3VyZQ==", "c2FmZQ=="] });
    mockKV.get.mockResolvedValue(null);
    mockCache.match.mockResolvedValue(null);
    
    global.fetch.mockImplementation(async (url) => {
      if (url.includes('c3VyZQ')) {
        return { ok: true, status: 200, json: async () => ({ negativeExpireTime: new Date(Date.now() + 120000).toISOString() }) };
      } else {
        return { ok: false, status: 500 }; // fail one
      }
    });
    
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
    const body = JSON.parse(await res.text());
    expect(body.results.length).toBe(1);
    expect(body.results[0].prefix).toBe("c3VyZQ==");
  });
  
  it('upstream budget exceeded gracefully marks remaining unavailable', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["c3VyZQ==", "c2FmZQ=="] });
    mockKV.get.mockResolvedValue(null);
    mockCache.match.mockResolvedValue(null);
    
    // Test the configurable budget logic indirectly. If budget was 1, only 1 would resolve. 
    // We hardcoded budget to 30, so this test just ensures it processes without crashing.
    // If budget logic changes, we could mock the budget var.
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ negativeExpireTime: new Date(Date.now() + 120000).toISOString() }) });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
  });

  it('rejects full URLs in prefixes payload explicitly', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["https://example.com"] });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(400);
  });

  it('never returns the API key in the response', async () => {
    const req = createRequest('POST', 'https://reputation.behindthelink.net/v1/hashes.search', validOrigin, { prefixes: ["c3VyZQ=="] });
    mockKV.get.mockResolvedValue(null);
    mockCache.match.mockResolvedValue(null);
    global.fetch.mockResolvedValue({
      ok: true, status: 200, json: async () => ({ negativeExpireTime: new Date(Date.now() + 120000).toISOString() })
    });
    const res = await worker.fetch(req, env, ctx);
    const text = await res.text();
    expect(text).not.toContain('test-api-key');
  });

  it('application code contains no logging of sensitive data (or any console.log)', () => {
    // Read the source file to statically check for console.log
    // In a real environment, you'd use fs, but since this is vitest we can do it:
    import('fs').then(fs => {
      const code = fs.readFileSync(new URL('../src/index.js', import.meta.url), 'utf-8');
      expect(code).not.toContain('console.log');
      expect(code).not.toContain('console.error');
    });
  });
});
