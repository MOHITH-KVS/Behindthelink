/**
 * Implements Google Web Risk suffix/prefix expression generation.
 */

function isIPAddress(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function getHostSuffixes(host) {
  if (isIPAddress(host)) {
    return [host];
  }

  const parts = host.split('.');
  const suffixes = [host];

  // We want up to 4 additional suffixes based on the last 5 components.
  const startIdx = Math.max(1, parts.length - 5);
  for (let i = startIdx; i < parts.length - 1; i++) {
    suffixes.push(parts.slice(i).join('.'));
  }
  
  return suffixes;
}

function getPathPrefixes(path, query) {
  const expressions = [];
  
  // 1. Exact path + query
  if (query) {
    expressions.push(path + query);
  }
  
  // 2. Exact path
  expressions.push(path);
  
  // 3. Up to 4 path prefixes
  const parts = path.split('/');
  let prefix = '/';
  
  // Add root prefix if not already the exact path
  if (path !== '/') {
    expressions.push(prefix);
  }
  
  // A path like /a/b/c/d/e
  // parts = ['', 'a', 'b', 'c', 'd', 'e']
  for (let i = 1; i < parts.length - 1; i++) {
    if (expressions.length >= (query ? 6 : 5)) {
      // Max 6 total if query exists (1 exact+query, 1 exact, 4 prefixes)
      break; 
    }
    if (parts[i]) {
      prefix += parts[i] + '/';
      if (prefix !== path) {
        expressions.push(prefix);
      }
    }
  }
  
  // Remove duplicates just in case
  return Array.from(new Set(expressions));
}

function generateExpressions(canonicalObj) {
  const { host, path, query } = canonicalObj;
  
  const hosts = getHostSuffixes(host);
  const paths = getPathPrefixes(path, query);
  
  const expressions = [];
  
  for (let i = 0; i < hosts.length; i++) {
    for (let j = 0; j < paths.length; j++) {
      expressions.push(hosts[i] + paths[j]);
    }
  }
  
  return expressions;
}

// UMD-style export
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.BehindTheLink = root.BehindTheLink || {};
    root.BehindTheLink.expressionGenerator = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  return {
    generateExpressions,
    getHostSuffixes,
    getPathPrefixes
  };
}));
