/**
 * Implements strict Google Web Risk URL canonicalization.
 */

function removeTabsCRLF(url) {
  return url.replace(/[\x09\x0d\x0a]/g, '');
}

function removeFragment(url) {
  const hashIdx = url.indexOf('#');
  return hashIdx >= 0 ? url.slice(0, hashIdx) : url;
}

function fullyUnescape(str) {
  let prev;
  let curr = str;
  // A robust unescaper that only unescapes valid %XX hex sequences.
  // Google Web Risk spec: Repeatedly percent-unescape the URL until there are no more percent-escapes.
  const regex = /%([0-9a-fA-F]{2})/g;
  do {
    prev = curr;
    curr = curr.replace(regex, (match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  } while (curr !== prev);
  return curr;
}

function normalizeHostname(host) {
  // 1. Remove leading and trailing dots
  host = host.replace(/^\.+|\.+$/g, '');
  // 2. Collapse consecutive dots
  host = host.replace(/\.{2,}/g, '.');
  // 3. Lowercase
  host = host.toLowerCase();

  // 4. IP normalization
  // Simple check for IPv4 octets
  const ipv4Match = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1).map(Number);
    if (octets.every(o => o >= 0 && o <= 255)) {
      return octets.join('.');
    }
  }
  if (/^\d+$/.test(host)) {
    const num = BigInt(host);
    if (num <= 0xffffffffn) {
      return [
        Number((num >> 24n) & 0xffn),
        Number((num >> 16n) & 0xffn),
        Number((num >> 8n) & 0xffn),
        Number(num & 0xffn)
      ].join('.');
    }
  }

  return host;
}

function normalizePath(path) {
  const segments = path.split('/');
  const resolved = [];
  
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (seg === '.') {
      continue;
    } else if (seg === '..') {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== '') {
        resolved.pop();
      }
    } else {
      resolved.push(seg);
    }
  }
  
  let newPath = resolved.join('/');
  newPath = newPath.replace(/\/+/g, '/');
  
  if (!newPath.startsWith('/')) {
    newPath = '/' + newPath;
  }
  
  return newPath;
}

function escapeChar(char) {
  const code = char.charCodeAt(0);
  if (code <= 32 || code >= 127 || char === '#' || char === '%') {
    let hex = code.toString(16).toUpperCase();
    if (hex.length < 2) hex = '0' + hex;
    return '%' + hex;
  }
  return char;
}

function escapeHost(host) {
  let escaped = '';
  for (let i = 0; i < host.length; i++) {
    escaped += escapeChar(host[i]);
  }
  return escaped;
}

function escapePath(path) {
  let escaped = '';
  for (let i = 0; i < path.length; i++) {
    escaped += escapeChar(path[i]);
  }
  return escaped;
}

function parseAndCanonicalize(urlStr) {
  let raw = removeTabsCRLF(urlStr);
  raw = removeFragment(raw);
  raw = fullyUnescape(raw);

  let parseTarget = raw;
  if (!/^[a-zA-Z0-9+-.]+:\/\//.test(parseTarget)) {
    parseTarget = 'http://' + parseTarget;
  }

  let u;
  try {
    u = new URL(parseTarget);
  } catch(e) {
    throw new Error("Invalid URL structure");
  }

  let host = u.hostname;
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.substring(1, host.length - 1);
  }
  
  // URL parser might re-encode characters or leave some encoded.
  // Web Risk requires extracting the unescaped path and query before re-escaping.
  // Using u.pathname and u.search provides the structural truth, but we must fully unescape them.
  let path = fullyUnescape(u.pathname);
  let query = fullyUnescape(u.search);

  host = normalizeHostname(host);
  host = escapeHost(host);

  path = normalizePath(path);
  path = escapePath(path);

  let escapedQuery = '';
  if (query) {
    escapedQuery = escapePath(query);
  }

  return { host, path, query: escapedQuery };
}

// UMD-style export
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.BehindTheLink = root.BehindTheLink || {};
    root.BehindTheLink.canonicalization = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  return {
    parseAndCanonicalize,
    normalizeHostname,
    normalizePath,
    fullyUnescape
  };
}));
