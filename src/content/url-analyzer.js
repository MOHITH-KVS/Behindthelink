/**
 * BehindTheLink — URL Analyzer
 *
 * Local-only URL parser that extracts human-readable signals
 * (shortener, tracking parameters, affiliate indicators)
 * without making any network requests.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink;

  /**
   * Analyzes a URL string and returns a structured object of signals.
   *
   * @param {string} urlString - The fully resolved URL to analyze.
   * @returns {Object|null} The analysis result, or null if parsing fails.
   */
  function analyzeUrl(urlString) {
    var urlObj;
    try {
      urlObj = new URL(urlString);
    } catch (e) {
      return null;
    }

    // Ignore non-web protocols. The eligibility filter should catch this,
    // but we enforce it here as well for safety.
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
      return null;
    }

    var result = {
      originalUrl: urlString,
      localSignals: {
        hostname: urlObj.hostname,
        isHttps: urlObj.protocol === 'https:',
        isShortened: false,
        trackingParams: [],
        hasAffiliate: false,
        embeddedCandidates: [],
        isStructurallyDirect: false,
        isClean: false
      },
      riskSignals: {
        severity: 'NONE',
        signals: []
      }
    };

    var localSignals = result.localSignals;

    // Check Shortener
    if (BTL.shortenerRegistry && BTL.shortenerRegistry.isShortener(localSignals.hostname)) {
      localSignals.isShortened = true;
    }

    var WRAPPER_PARAMS = ['url', 'target', 'dest', 'destination', 'redirect', 'redirect_url', 'u', 'targeturl', 'redirecturl'];
    
    // Analyze Query Parameters
    var params = urlObj.searchParams;
    params.forEach(function (value, key) {
      // Tracking detection
      if (BTL.trackingRegistry && BTL.trackingRegistry.isTracker(key)) {
        if (localSignals.trackingParams.indexOf(key) === -1) {
          localSignals.trackingParams.push(key);
        }
      }
      // Affiliate detection
      if (BTL.affiliateRegistry && BTL.affiliateRegistry.isAffiliate(key)) {
        localSignals.hasAffiliate = true;
      }
      
      // Embedded destination wrapper detection
      if (WRAPPER_PARAMS.indexOf(key.toLowerCase()) !== -1) {
        var decodedValue = value;
        for (var i = 0; i < 3; i++) {
          try {
            var embeddedObj = new URL(decodedValue);
            if (embeddedObj.protocol === 'http:' || embeddedObj.protocol === 'https:') {
              if (localSignals.embeddedCandidates.indexOf(embeddedObj.href) === -1) {
                localSignals.embeddedCandidates.push(embeddedObj.href);
              }
              break; // Success
            }
          } catch (e) {
            // Not a valid URL yet
          }
          
          try {
            var nextDecoded = decodeURIComponent(decodedValue);
            if (nextDecoded === decodedValue) break; // No further decoding possible
            decodedValue = nextDecoded;
          } catch (e) {
            break; // Malformed percent-encoding, stop trying
          }
        }
      }
    });

    // Evaluate clean status (zero tracking/affiliate/obfuscation)
    if (!localSignals.isShortened && localSignals.trackingParams.length === 0 && !localSignals.hasAffiliate && localSignals.embeddedCandidates.length === 0) {
      localSignals.isClean = true;
    }

    // Evaluate structural directness (not obfuscated, even if tracking is present)
    if (!localSignals.isShortened && localSignals.embeddedCandidates.length === 0) {
      localSignals.isStructurallyDirect = true;
    }

    // --- PHASE 2A: RISK SIGNALS ---
    var ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    var isIpHost = ipRegex.test(urlObj.hostname);
    var hasUserInfo = !!(urlObj.username || urlObj.password);
    var isPunycode = urlObj.hostname.indexOf('xn--') !== -1;
    var isUnusualPort = !!(urlObj.port && urlObj.port !== '80' && urlObj.port !== '443');
    var isDeepSubdomain = urlObj.hostname.split('.').length >= 5;
    
    var encodedProtocolRegex = /(%68%74%74%70|%48%54%54%50)/i;
    var consecutiveEncoding = /(?:%[0-9A-Fa-f]{2}){4,}/; 
    var isHeavyEncoding = encodedProtocolRegex.test(urlString) || consecutiveEncoding.test(urlString);

    var sensitiveRegex = /\/(login|signin|account|verify|verification|password|reset|auth|secure-login)\b/i;
    var isSensitivePath = sensitiveRegex.test(urlObj.pathname) || sensitiveRegex.test(urlObj.search);

    var signals = result.riskSignals.signals;

    if (isIpHost) {
      signals.push({ type: 'IP_HOST', label: 'Uses an IP address', reason: 'This link points directly to an IP address instead of a domain name.' });
    }
    if (hasUserInfo) {
      signals.push({ type: 'USERINFO_IN_URL', label: 'Contains an unusual URL format', reason: 'This URL contains information before the actual domain.' });
    }
    if (isPunycode) {
      signals.push({ type: 'PUNYCODE_DOMAIN', label: 'Uses an encoded domain name', reason: 'The domain uses an encoded form that can make names harder to recognize.' });
    }
    if (isUnusualPort) {
      signals.push({ type: 'UNUSUAL_PORT', label: 'Uses a non-standard port', reason: 'This link connects through a port other than the usual web ports.' });
    }
    if (isDeepSubdomain && !isIpHost) {
      signals.push({ type: 'DEEP_SUBDOMAIN', label: 'Uses a deeply nested domain', reason: 'The address contains several levels of subdomains.' });
    }
    if (isHeavyEncoding) {
      signals.push({ type: 'HEAVY_ENCODING', label: 'Contains heavily encoded text', reason: 'Parts of this URL are encoded and harder to read.' });
    }
    if (isSensitivePath) {
      signals.push({ type: 'SENSITIVE_ACTION_PATH', label: 'Contains a sign-in or account action', reason: 'The URL refers to a sign-in, verification, password, or account action.' });
    }

    // Evaluate severity based on Phase 2B model:
    // NONE = no meaningful risk combination or only contextual signals (e.g. SENSITIVE_ACTION_PATH alone).
    // LOW = one meaningful structural risk signal.
    // MEDIUM = strong specific combinations (Punycode + Userinfo, Punycode + Heavy Encoding, IP Host + Userinfo).
    // HIGH is explicitly NOT introduced yet to prevent arbitrary escalation of weak signals.
    if (signals.length > 0) {
      result.riskSignals.severity = 'LOW';
      if (signals.length === 1 && isSensitivePath) {
        result.riskSignals.severity = 'NONE'; // contextual signal with zero severity contribution by itself
      }
    }

    if ((isPunycode && hasUserInfo) ||
        (isPunycode && isHeavyEncoding) ||
        (isIpHost && hasUserInfo)) {
      result.riskSignals.severity = 'MEDIUM';
    }

    return result;
  }

  // Expose on the shared namespace
  BTL.urlAnalyzer = {
    analyzeUrl: analyzeUrl
  };

})();
