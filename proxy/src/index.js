const MAX_PREFIXES = 30;
const MAX_PAYLOAD_SIZE = 2048; // 2KB
const CIRCUIT_BREAKER_MAX_ERRORS = 10;
const CIRCUIT_BREAKER_TIMEOUT = 60000; // 1 min

// Module-level state for in-flight coalescing and circuit breaker
const inFlightRequests = new Map();
let circuitBreakerErrors = 0;
let circuitBreakerResetTime = 0;

function isCircuitOpen() {
  if (circuitBreakerErrors >= CIRCUIT_BREAKER_MAX_ERRORS) {
    if (Date.now() > circuitBreakerResetTime) {
      // Half-open / reset
      circuitBreakerErrors = 0;
      return false;
    }
    return true;
  }
  return false;
}

function recordGoogleError() {
  circuitBreakerErrors++;
  if (circuitBreakerErrors >= CIRCUIT_BREAKER_MAX_ERRORS && circuitBreakerResetTime <= Date.now()) {
    circuitBreakerResetTime = Date.now() + CIRCUIT_BREAKER_TIMEOUT;
  }
}

function getCorsHeaders(origin, env) {
  const headers = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
  
  const allowedOrigins = env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',') : [];
  
  if (allowedOrigins.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
  }
  return headers;
}

function isValidBase64Prefix(str) {
  if (typeof str !== 'string') return false;
  // basic base64 check
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(str)) return false;
  try {
    const decoded = atob(str);
    return decoded.length === 4;
  } catch(e) {
    return false;
  }
}

async function fetchGoogleWebRisk(prefix, apiKey) {
  const url = `https://webrisk.googleapis.com/v1/hashes:search?hashPrefix=${encodeURIComponent(prefix)}&threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&key=${apiKey}`;
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3000); // 3-second timeout
  
  try {
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    
    if (response.status === 429) {
      recordGoogleError();
      throw new Error('Google_429');
    }
    if (!response.ok) {
      recordGoogleError();
      throw new Error('Google_5xx');
    }
    return await response.json();
  } catch (e) {
    clearTimeout(timeoutId);
    recordGoogleError();
    throw e;
  }
}


function isFresh(data) {
  let latestExp = 0;
  if (data.negativeExpireTime) {
    latestExp = new Date(data.negativeExpireTime).getTime();
  }
  if (data.threats) {
    for (const t of data.threats) {
      const exp = new Date(t.expireTime).getTime();
      if (exp > latestExp) latestExp = exp;
    }
  }
  // If it's less than 60s away from expiration, consider it stale for KV read
  return (latestExp - Date.now()) > 60000;
}

const ipRateLimiter = new Map();
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_MAX = 100;

function checkRateLimit(ip) {
  if (!ip) return true;
  const now = Date.now();
  let data = ipRateLimiter.get(ip);
  if (!data || now - data.startTime > RATE_LIMIT_WINDOW) {
    data = { count: 0, startTime: now };
  }
  data.count++;
  ipRateLimiter.set(ip, data);
  return data.count <= RATE_LIMIT_MAX;
}

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get('Origin') || '';
    const corsHeaders = getCorsHeaders(origin, env);
    const allowedOrigins = env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',') : [];

    // OPTIONS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders, status: 204 });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: corsHeaders });
    }

    if (!allowedOrigins.includes(origin)) {
      return new Response('Forbidden', { status: 403, headers: corsHeaders });
    }

    // Isolate-local IP Rate Limiter
    // NOTE: This is a best-effort Worker-level protection, not a global WAF.
    // A globally consistent rate limiter requires Cloudflare WAF Rate Limiting rules.
    const ip = request.headers.get('CF-Connecting-IP');
    if (!checkRateLimit(ip)) {
      return new Response('Too Many Requests', { status: 429, headers: corsHeaders });
    }

    const url = new URL(request.url);
    if (url.pathname !== '/v1/hashes.search') {
      return new Response('Not Found', { status: 404, headers: corsHeaders });
    }

    let payloadText = '';
    try {
      payloadText = await request.text();
    } catch(e) {
      return new Response('Bad Request', { status: 400, headers: corsHeaders });
    }

    if (payloadText.length > MAX_PAYLOAD_SIZE) {
      return new Response('Payload Too Large', { status: 413, headers: corsHeaders });
    }

    let payload;
    try {
      payload = JSON.parse(payloadText);
    } catch(e) {
      return new Response('Malformed JSON', { status: 400, headers: corsHeaders });
    }

    if (!payload.prefixes || !Array.isArray(payload.prefixes)) {
      return new Response('Bad Request: prefixes array missing', { status: 400, headers: corsHeaders });
    }

    if (payload.prefixes.length === 0 || payload.prefixes.length > MAX_PREFIXES) {
      return new Response(`Bad Request: exactly 1-${MAX_PREFIXES} prefixes required`, { status: 400, headers: corsHeaders });
    }

    // Deduplicate array
    const uniquePrefixes = Array.from(new Set(payload.prefixes));

    // Validate prefixes
    for (const p of uniquePrefixes) {
      if (!isValidBase64Prefix(p)) {
        return new Response('Bad Request: invalid base64 prefix length', { status: 400, headers: corsHeaders });
      }
    }

    // Process all prefixes concurrently
    const results = [];
    
    // Budget check: configurable maximum uncached Google calls per proxy request, capped at 30.
    const configuredLimit = env.MAX_UNCACHED_CALLS ? parseInt(env.MAX_UNCACHED_CALLS, 10) : MAX_PREFIXES;
    let upstreamBudget = Math.min(configuredLimit, MAX_PREFIXES);

    const settled = await Promise.allSettled(uniquePrefixes.map(async (prefix) => {
      // 1. In-flight coalescing
      if (inFlightRequests.has(prefix)) {
        return inFlightRequests.get(prefix);
      }

      const promise = (async () => {
        const cache = caches.default;
        const cacheUrl = new URL(`https://reputation.behindthelink.net/cache/${prefix}`);
        
        const cachedResponse = await cache.match(cacheUrl);
        if (cachedResponse) {
          const cachedData = await cachedResponse.json();
          if (isFresh(cachedData)) return cachedData;
        }

        if (env.WEBRISK_CACHE) {
          const kvDataStr = await env.WEBRISK_CACHE.get(`prefix:${prefix}`);
          if (kvDataStr) {
            const kvData = JSON.parse(kvDataStr);
            if (isFresh(kvData)) {
              ctx.waitUntil(cache.put(cacheUrl, new Response(JSON.stringify(kvData), {
                headers: { 'Cache-Control': 'max-age=60' }
              })));
              return kvData;
            }
          }
        }

        // Budget check BEFORE hitting google
        if (upstreamBudget <= 0) {
          throw new Error('BudgetExceeded');
        }
        upstreamBudget--;

        if (isCircuitOpen()) throw new Error('CircuitOpen');
        if (!env.GOOGLE_WEB_RISK_KEY) throw new Error('MissingApiKey');

        const googleRes = await fetchGoogleWebRisk(prefix, env.GOOGLE_WEB_RISK_KEY);
        
        const result = { prefix: prefix, threats: [] };
        let maxExpirationTime = 0;

        if (googleRes.threats && googleRes.threats.length > 0) {
          for (const t of googleRes.threats) {
            result.threats.push({
              hash: t.hash,
              threatTypes: t.threatTypes,
              expireTime: t.expireTime
            });
            const expMs = new Date(t.expireTime).getTime();
            if (expMs > maxExpirationTime) maxExpirationTime = expMs;
          }
        } else {
          if (googleRes.negativeExpireTime) {
            result.negativeExpireTime = googleRes.negativeExpireTime;
            maxExpirationTime = new Date(googleRes.negativeExpireTime).getTime();
          }
        }

        if (maxExpirationTime - Date.now() > 60000) {
          const ttl = Math.floor((maxExpirationTime - Date.now()) / 1000);
          const toCache = JSON.stringify(result);
          ctx.waitUntil(Promise.all([
            cache.put(cacheUrl, new Response(toCache, { headers: { 'Cache-Control': `max-age=${ttl}` }})),
            env.WEBRISK_CACHE ? env.WEBRISK_CACHE.put(`prefix:${prefix}`, toCache, { expirationTtl: ttl }) : Promise.resolve()
          ]));
        }

        return result;
      })();

      inFlightRequests.set(prefix, promise);
      try {
        return await promise;
      } finally {
        inFlightRequests.delete(prefix);
      }
    }));

    for (const res of settled) {
      if (res.status === 'fulfilled') {
        results.push(res.value);
      } else {
        // Handle partial failure / rejection gracefully.
        // The prefix simply won't be in the results array, meaning UNAVAILABLE for the extension.
      }
    }

    return new Response(JSON.stringify({ results }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
};
