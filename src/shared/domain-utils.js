/**
 * BehindTheLink — Domain Utilities
 *
 * Deterministic domain normalization, Public Suffix List parsing,
 * IP detection, RFC 3492 Punycode decoding, and cross-script homoglyph mapping.
 *
 * Local-first, zero-dependency, and network-free.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink || {};
  if (typeof window !== 'undefined') window.BehindTheLink = BTL;
  if (typeof self !== 'undefined') self.BehindTheLink = BTL;

  var PSL_VERSION = '2026.1-compact';

  // PSL Wildcards (*.<parent>)
  var PSL_WILDCARDS = [
    'ck', // Cook Islands (*.ck)
    'er'  // Eritrea (*.er)
  ];

  // PSL Exceptions (!<rule>)
  // If rule matches !www.ck, the exception applies and suffix is 'ck'
  var PSL_EXCEPTIONS = {
    'www.ck': 'ck'
  };

  // Known multi-part public suffixes (ccTLD second-level & major multi-tenant private domains)
  var MULTI_PART_SUFFIXES = [
    // United Kingdom
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'sch.uk', 'gov.uk', 'police.uk',
    // India
    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'bank.in', 'ac.in', 'edu.in', 'res.in', 'gov.in', 'mil.in',
    // Australia
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au', 'asn.au',
    // New Zealand
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz', 'iwi.nz', 'mil.nz',
    // Brazil
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'mil.br', 'art.br',
    // Japan
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'ed.jp', 'ad.jp', 'gr.jp', 'lg.jp',
    // China
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'mil.cn',
    // Singapore
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg', 'per.sg',
    // Mexico
    'com.mx', 'org.mx', 'net.mx', 'edu.mx', 'gob.mx',
    // South Africa
    'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za', 'web.za',
    // Turkey
    'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'bel.tr', 'pol.tr',
    // South Korea
    'co.kr', 'ne.kr', 'or.kr', 're.kr', 'go.kr', 'mil.kr', 'ac.kr', 'hs.kr', 'ms.kr', 'es.kr',
    // Taiwan
    'com.tw', 'net.tw', 'org.tw', 'idv.tw', 'gov.tw', 'edu.tw', 'club.tw',
    // Hong Kong
    'com.hk', 'net.hk', 'org.hk', 'idv.hk', 'gov.hk', 'edu.hk',
    // Argentina
    'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar', 'int.ar', 'mil.ar', 'tur.ar',
    // Colombia
    'com.co', 'net.co', 'org.co', 'nom.co', 'gov.co', 'edu.co', 'mil.co',
    // Canada regional
    'gc.ca', 'qc.ca', 'on.ca', 'bc.ca', 'ab.ca', 'sk.ca', 'mb.ca', 'ns.ca', 'nb.ca', 'pe.ca', 'nl.ca',
    // Nigeria, Pakistan, Malaysia, Philippines, Vietnam, Thailand, Indonesia, Ukraine, Israel
    'com.ng', 'org.ng', 'gov.ng', 'edu.ng', 'net.ng',
    'com.pk', 'org.pk', 'net.pk', 'edu.pk', 'gov.pk',
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
    'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
    'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn',
    'co.th', 'ac.th', 'go.th', 'net.th', 'or.th',
    'co.id', 'net.id', 'or.id', 'ac.id', 'sch.id', 'go.id', 'web.id', 'my.id',
    'com.ua', 'net.ua', 'org.ua', 'edu.ua', 'gov.ua',
    'co.il', 'net.il', 'org.il', 'ac.il', 'gov.il',
    // Multi-tenant hosting platforms (PSL Private Domains)
    'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
    'azurewebsites.net', 'herokuapp.com', 'vercel.app', 'netlify.app',
    'cloudfront.net', 's3.amazonaws.com'
  ];

  var MULTI_PART_SET = {};
  for (var m = 0; m < MULTI_PART_SUFFIXES.length; m++) {
    MULTI_PART_SET[MULTI_PART_SUFFIXES[m]] = true;
  }

  var WILDCARD_SET = {};
  for (var w = 0; w < PSL_WILDCARDS.length; w++) {
    WILDCARD_SET[PSL_WILDCARDS[w]] = true;
  }

  // IPv4 regex (strict 4 octets between 0 and 255)
  var IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  /**
   * Checks if a string represents an IPv4 or IPv6 address.
   * @param {string} hostname
   * @returns {boolean}
   */
  function isIpAddress(hostname) {
    if (!hostname || typeof hostname !== 'string') return false;
    var clean = hostname.trim();
    if (IPV4_REGEX.test(clean)) return true;
    if (clean.startsWith('[') && clean.endsWith(']')) {
      clean = clean.slice(1, -1);
    }
    // IPv6 contains at least two colons
    if (clean.indexOf(':') !== -1) {
      var colons = clean.split(':');
      if (colons.length >= 3 && colons.length <= 8) {
        return /^[0-9a-fA-F:]+$/.test(clean);
      }
    }
    return false;
  }

  /**
   * Safely extracts and normalizes the hostname from a URL or bare hostname string.
   * Rejects non-HTTP(S) schemes. Returns empty string if invalid or non-web.
   *
   * @param {string} urlOrHost
   * @returns {string}
   */
  function normalizeHostname(urlOrHost) {
    if (!urlOrHost || typeof urlOrHost !== 'string') return '';
    var input = urlOrHost.trim();
    if (!input) return '';

    // Check for explicit URI scheme
    var schemeMatch = input.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
    if (schemeMatch) {
      var scheme = schemeMatch[1].toLowerCase();
      if (scheme !== 'http' && scheme !== 'https') {
        return ''; // Reject non-HTTP(S) schemes (ftp, mailto, javascript, data, file, etc.)
      }
    }

    var hostCandidate = '';
    var URLClass = (typeof URL !== 'undefined') ? URL : (typeof window !== 'undefined' && window.URL ? window.URL : (typeof self !== 'undefined' && self.URL ? self.URL : null));

    if (URLClass) {
      try {
        var toParse = input.indexOf('://') === -1 ? 'http://' + input : input;
        var parsed = new URLClass(toParse);
        hostCandidate = parsed.hostname;
      } catch (e) {
        hostCandidate = '';
      }
    }

    if (!hostCandidate) {
      // Regex fallback for host extraction
      var noScheme = input.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
      // Strip credentials if present (user:pass@host)
      var atIdx = noScheme.indexOf('@');
      if (atIdx !== -1) {
        noScheme = noScheme.slice(atIdx + 1);
      }
      hostCandidate = noScheme.split('/')[0].split('?')[0].split('#')[0];
      // Strip port if not an IPv6 address
      if (hostCandidate.indexOf(':') !== -1 && !hostCandidate.startsWith('[')) {
        hostCandidate = hostCandidate.split(':')[0];
      }
    }

    var cleanHost = hostCandidate.toLowerCase().replace(/\.+$/, '');
    // Validate characters: must contain valid domain/IP characters only
    if (!cleanHost || !/^[a-z0-9_.\-[\]%:]+$/.test(cleanHost)) {
      return '';
    }
    return cleanHost;
  }

  /**
   * Resolves the public suffix for a normalized hostname using PSL rules.
   * Returns { suffix: string, known: boolean } or null if invalid / inconclusive.
   *
   * @param {string} hostname
   * @returns {{ suffix: string, known: boolean }|null}
   */
  function findPublicSuffix(hostname) {
    if (!hostname || isIpAddress(hostname)) return null;
    var labels = hostname.split('.');
    if (labels.length < 2) return null; // Single-label hostnames have no public suffix

    // 1. Check PSL Exceptions (!www.ck)
    for (var i = 0; i < labels.length; i++) {
      var candidate = labels.slice(i).join('.');
      if (PSL_EXCEPTIONS[candidate]) {
        return { suffix: PSL_EXCEPTIONS[candidate], known: true };
      }
    }

    // 2. Check PSL Wildcards (*.ck, *.er)
    for (var j = 1; j < labels.length; j++) {
      var parent = labels.slice(j).join('.');
      if (WILDCARD_SET[parent]) {
        // In *.parent, the suffix is <label-before-parent>.<parent>
        return { suffix: labels.slice(j - 1).join('.'), known: true };
      }
    }

    // 3. Check Known Multi-Part Suffixes (longest match first)
    for (var len = 3; len >= 2; len--) {
      if (labels.length >= len) {
        var multiCandidate = labels.slice(-len).join('.');
        if (MULTI_PART_SET[multiCandidate]) {
          return { suffix: multiCandidate, known: true };
        }
      }
    }

    // 4. Single-label TLD fallback
    var tld = labels[labels.length - 1];
    // Must be valid ASCII TLD characters (2 to 24 letters)
    if (/^[a-z]{2,24}$/.test(tld)) {
      return { suffix: tld, known: true };
    }

    // Unsupported or unrecognized suffix -> Inconclusive
    return { suffix: tld, known: false };
  }

  /**
   * Parses a URL or hostname into its constituent domain parts:
   * subdomain, registrableDomain, domainStem, publicSuffix.
   *
   * @param {string} urlOrHost
   * @returns {Object}
   */
  function parseDomain(urlOrHost) {
    var hostname = normalizeHostname(urlOrHost);

    if (!hostname) {
      return {
        hostname: '',
        isIp: false,
        ip: null,
        registrableDomain: null,
        domainStem: null,
        subdomain: null,
        publicSuffix: null,
        publicSuffixKnown: false,
        isInconclusive: true
      };
    }

    if (isIpAddress(hostname)) {
      return {
        hostname: hostname,
        isIp: true,
        ip: hostname,
        registrableDomain: null,
        domainStem: null,
        subdomain: null,
        publicSuffix: null,
        publicSuffixKnown: true,
        isInconclusive: false
      };
    }

    var suffixInfo = findPublicSuffix(hostname);
    if (!suffixInfo || !suffixInfo.known) {
      return {
        hostname: hostname,
        isIp: false,
        ip: null,
        registrableDomain: null,
        domainStem: null,
        subdomain: null,
        publicSuffix: suffixInfo ? suffixInfo.suffix : null,
        publicSuffixKnown: false,
        isInconclusive: true
      };
    }

    var suffix = suffixInfo.suffix;
    var suffixLabels = suffix.split('.');
    var hostLabels = hostname.split('.');

    var prefixLength = hostLabels.length - suffixLabels.length;
    if (prefixLength < 1) {
      // The hostname is identical to the public suffix itself (e.g. 'co.uk' or 'com')
      return {
        hostname: hostname,
        isIp: false,
        ip: null,
        registrableDomain: null,
        domainStem: null,
        subdomain: null,
        publicSuffix: suffix,
        publicSuffixKnown: true,
        isInconclusive: true
      };
    }

    var stem = hostLabels[prefixLength - 1];
    var registrableDomain = stem + '.' + suffix;
    var subdomain = hostLabels.slice(0, prefixLength - 1).join('.');

    return {
      hostname: hostname,
      isIp: false,
      ip: null,
      registrableDomain: registrableDomain,
      domainStem: stem,
      subdomain: subdomain || '',
      publicSuffix: suffix,
      publicSuffixKnown: true,
      isInconclusive: false
    };
  }

  /**
   * Compares whether two URLs or hostnames belong to different registrable domains.
   * Handles IPs and multi-label public suffixes safely.
   *
   * @param {string} url1
   * @param {string} url2
   * @returns {boolean}
   */
  function differentRegistrableDomain(url1, url2) {
    var p1 = parseDomain(url1);
    var p2 = parseDomain(url2);

    if (!p1.hostname || !p2.hostname) return false;
    if (p1.hostname === p2.hostname) return false;

    if (p1.isIp || p2.isIp) {
      return p1.hostname !== p2.hostname;
    }

    if (p1.registrableDomain && p2.registrableDomain) {
      return p1.registrableDomain !== p2.registrableDomain;
    }

    // Inconclusive fallback: if hostnames differ and cannot be proven identical domain, treat as different
    return p1.hostname !== p2.hostname;
  }

  // RFC 3492 Punycode Parameters
  var BASE = 36;
  var TMIN = 1;
  var TMAX = 26;
  var SKEW = 38;
  var DAMP = 700;
  var INITIAL_BIAS = 72;
  var INITIAL_N = 128;

  function adapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
    delta += Math.floor(delta / numPoints);
    var k = 0;
    while (delta > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
      delta = Math.floor(delta / (BASE - TMIN));
      k += BASE;
    }
    return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
  }

  /**
   * Decodes a single RFC 3492 Punycode label ('xn--...').
   * Returns original string if not punycode or if decoding fails.
   *
   * @param {string} label
   * @returns {string}
   */
  function decodePunycodeLabel(label) {
    if (!label || typeof label !== 'string' || !label.startsWith('xn--')) {
      return label;
    }
    var str = label.slice(4).toLowerCase();
    var output = [];
    var delim = str.lastIndexOf('-');
    var b = 0;

    if (delim > 0) {
      for (var j = 0; j < delim; j++) {
        output.push(str.charCodeAt(j));
      }
      b = delim + 1;
    }

    var n = INITIAL_N;
    var i = 0;
    var bias = INITIAL_BIAS;

    for (var inIdx = b; inIdx < str.length;) {
      var oldi = i;
      var w = 1;
      for (var k = BASE; ; k += BASE) {
        if (inIdx >= str.length) return label; // Malformed
        var cp = str.charCodeAt(inIdx++);
        var digit = cp - 48 < 10 ? cp - 22 : cp - 97 < 26 ? cp - 97 : BASE;
        if (digit >= BASE) return label;
        i += digit * w;
        var t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
        if (digit < t) break;
        w *= (BASE - t);
      }
      bias = adapt(i - oldi, output.length + 1, oldi === 0);
      n += Math.floor(i / (output.length + 1));
      i %= (output.length + 1);
      output.splice(i, 0, n);
      i++;
    }

    try {
      return String.fromCodePoint.apply(null, output);
    } catch (e) {
      return label;
    }
  }

  /**
   * Decodes an entire hostname with potential Punycode labels.
   * @param {string} hostname
   * @returns {string}
   */
  function decodePunycode(hostname) {
    if (!hostname || typeof hostname !== 'string') return '';
    var labels = hostname.split('.');
    var decoded = [];
    for (var i = 0; i < labels.length; i++) {
      decoded.push(decodePunycodeLabel(labels[i]));
    }
    return decoded.join('.');
  }

  // Cross-Script Homoglyph Table (Cyrillic, Greek, Latin Lookalikes -> ASCII Latin)
  var HOMOGLYPH_MAP = {
    // Cyrillic small letters
    '\u0430': 'a', // Cyrillic Small Letter A
    '\u0435': 'e', // Cyrillic Small Letter Ie
    '\u043E': 'o', // Cyrillic Small Letter O
    '\u0440': 'p', // Cyrillic Small Letter Er
    '\u0441': 'c', // Cyrillic Small Letter Es
    '\u0443': 'y', // Cyrillic Small Letter U
    '\u0445': 'x', // Cyrillic Small Letter Ha
    '\u0456': 'i', // Cyrillic Small Letter Byelorussian-Ukrainian I
    '\u0458': 'j', // Cyrillic Small Letter Je
    '\u0455': 's', // Cyrillic Small Letter Dze
    '\u0432': 'v', // Cyrillic Small Letter Ve
    '\u0433': 'r', // Cyrillic Small Letter Ghe
    '\u043C': 'm', // Cyrillic Small Letter Em
    '\u043D': 'h', // Cyrillic Small Letter En
    '\u0442': 't', // Cyrillic Small Letter Te
    '\u04CF': 'l', // Cyrillic Small Letter Palochka
    // Cyrillic capital letters
    '\u0410': 'a', '\u0412': 'b', '\u0415': 'e', '\u041A': 'k',
    '\u041C': 'm', '\u041D': 'h', '\u041E': 'o', '\u0420': 'p',
    '\u0421': 'c', '\u0422': 't', '\u0423': 'y', '\u0425': 'x',
    // Greek letters
    '\u03B1': 'a', // Alpha
    '\u03B2': 'b', // Beta
    '\u03B3': 'y', // Gamma
    '\u03B5': 'e', // Epsilon
    '\u03B9': 'i', // Iota
    '\u03BA': 'k', // Kappa
    '\u03BD': 'v', // Nu
    '\u03BF': 'o', // Omicron
    '\u03C1': 'p', // Rho
    '\u03C4': 't', // Tau
    '\u03C5': 'u', // Upsilon
    '\u03C7': 'x', // Chi
    '\u03C9': 'w', // Omega
    // Latin Accented / Diacritic Lookalikes
    'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'ā': 'a',
    'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'ē': 'e',
    'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ī': 'i',
    'ó': 'o', 'ò': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o', 'ō': 'o',
    'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ū': 'u',
    'ý': 'y', 'ÿ': 'y',
    'ñ': 'n',
    'ç': 'c'
  };

  /**
   * Maps cross-script homoglyphs in a Unicode string to canonical Latin ASCII.
   * Returns { normalized: string, hasConfusable: boolean, confusableChars: array }
   *
   * @param {string} str
   * @returns {{ normalized: string, hasConfusable: boolean, confusableChars: Array<string> }}
   */
  function mapHomoglyphs(str) {
    if (!str || typeof str !== 'string') {
      return { normalized: '', hasConfusable: false, confusableChars: [] };
    }
    // If the input has punycode labels, decode them first
    var decoded = decodePunycode(str);
    var normalizedChars = [];
    var confusableChars = [];
    var hasConfusable = false;

    for (var i = 0; i < decoded.length; i++) {
      var ch = decoded[i];
      if (HOMOGLYPH_MAP[ch]) {
        normalizedChars.push(HOMOGLYPH_MAP[ch]);
        confusableChars.push(ch);
        hasConfusable = true;
      } else {
        normalizedChars.push(ch);
      }
    }

    return {
      normalized: normalizedChars.join(''),
      hasConfusable: hasConfusable,
      confusableChars: confusableChars
    };
  }

  BTL.domainUtils = {
    PSL_VERSION: PSL_VERSION,
    isIpAddress: isIpAddress,
    normalizeHostname: normalizeHostname,
    findPublicSuffix: findPublicSuffix,
    parseDomain: parseDomain,
    differentRegistrableDomain: differentRegistrableDomain,
    decodePunycode: decodePunycode,
    decodePunycodeLabel: decodePunycodeLabel,
    mapHomoglyphs: mapHomoglyphs
  };

})();
