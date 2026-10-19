/**
 * BehindTheLink — Claim Destination Analyzer
 *
 * Level 3B: Compares strong contextual claims (brands/intents) against verified destinations.
 * Built to prevent phishing by finding inconsistencies, rather than absolute classification.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink || {};
  if (typeof window !== 'undefined') window.BehindTheLink = BTL;
  if (typeof self !== 'undefined') self.BehindTheLink = BTL;

  /**
   * Normalizes a URL string or raw hostname:
   * - Parses URL to extract hostname (or handles raw hostname)
   * - Converts to lowercase
   * - Strips trailing root dots (e.g. 'example.com.' -> 'example.com')
   * - Strips non-standard ports if present in raw strings
   *
   * @param {string} urlOrHost
   * @returns {string} Clean normalized hostname or empty string on failure
   */
  function normalizeHostname(urlOrHost) {
    if (!urlOrHost || typeof urlOrHost !== 'string') return '';
    var trimmed = urlOrHost.trim();
    var host = '';

    try {
      var u = new URL(trimmed);
      host = u.hostname;
    } catch (e) {
      // If not a full URL with protocol, attempt parsing by adding dummy protocol
      try {
        var u2 = new URL('https://' + trimmed);
        host = u2.hostname;
      } catch (e2) {
        // Strip path, query, hash, port manually
        host = trimmed.split('/')[0].split('?')[0].split('#')[0].split(':')[0];
      }
    }

    return host.toLowerCase().replace(/\.+$/, '');
  }

  /**
   * Helper extracting a verified destination from available evidence channels.
   * Explicit destination-evidence contract preserving v1.0 evidence paths:
   * 1. HTTP_REDIRECT_OBSERVED with redirectTarget
   * 2. NO_REDIRECT_OBSERVED with originalUrl
   * 3. STRONG_CORRELATION with observedLatestUrl
   *
   * If evidence is missing, FAILED, or inconclusive, returns null.
   *
   * @param {Object} networkEvidence
   * @param {Object} browserObservation
   * @param {string} originalUrl
   * @returns {{ url: string, source: string }|null}
   */
  function getVerifiedDestination(networkEvidence, browserObservation, originalUrl) {
    if (networkEvidence && networkEvidence.status === 'HTTP_REDIRECT_OBSERVED' && networkEvidence.redirectTarget) {
      return { url: networkEvidence.redirectTarget, source: 'network' };
    }
    if (networkEvidence && networkEvidence.status === 'NO_REDIRECT_OBSERVED' && originalUrl) {
      return { url: originalUrl, source: 'network' };
    }
    if (browserObservation && browserObservation.status === 'STRONG_CORRELATION' && browserObservation.observedLatestUrl) {
      return { url: browserObservation.observedLatestUrl, source: 'browser_observation' };
    }
    return null;
  }

  /**
   * Evaluates if a given URL or hostname belongs to the official domains of a specific brand.
   * Enforces exact-domain matching, dot-boundary subdomains, brand-specific exclusions,
   * and scoped third-party services via BTL.brandRegistry.
   *
   * @param {string} brandId
   * @param {string} destinationUrl - The destination URL or hostname to verify
   * @param {string} [contextCategory] - Context category (e.g. 'LOGIN_ACCOUNT', 'PAYMENT')
   * @returns {boolean}
   */
  function isOfficialDestination(brandId, destinationUrl, contextCategory) {
    if (!brandId || !destinationUrl) return false;
    var destHost = normalizeHostname(destinationUrl);
    if (!destHost) return false;

    // Delegate to unified Brand Registry when available
    if (BTL.brandRegistry && typeof BTL.brandRegistry.isOfficialDomain === 'function') {
      return BTL.brandRegistry.isOfficialDomain(brandId, destHost, contextCategory);
    }

    // Defensive fallback if brandRegistry is not yet loaded in context
    var lookupBrand = brandId.toUpperCase();
    var fallbackDomains = {
      'GOOGLE': ['google.com'],
      'MICROSOFT': ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'outlook.com'],
      'APPLE': ['apple.com', 'icloud.com'],
      'AMAZON': ['amazon.com', 'aws.amazon.com', 'amazon.in'],
      'META': ['meta.com', 'facebook.com'],
      'PAYPAL': ['paypal.com'],
      'NETFLIX': ['netflix.com'],
      'LINKEDIN': ['linkedin.com'],
      'WHATSAPP': ['whatsapp.com'],
      'INSTAGRAM': ['instagram.com'],
      'FACEBOOK': ['facebook.com'],
      'TELEGRAM': ['telegram.org', 't.me'],
      'YOUTUBE': ['youtube.com'],
      'GITHUB': ['github.com'],
      'OPENAI': ['openai.com', 'chatgpt.com'],
      'SBI': ['sbi.bank.in', 'sbi.co.in', 'bank.sbi', 'onlinesbi.sbi'],
      'HDFC': ['hdfcbank.com', 'hdfc.bank.in'],
      'AXIS': ['axis.bank.in', 'axisbank.com']
    };

    var domains = fallbackDomains[lookupBrand];
    if (!domains) return false;

    for (var i = 0; i < domains.length; i++) {
      var d = domains[i].toLowerCase().replace(/\.+$/, '');
      if (destHost === d || destHost.endsWith('.' + d)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Determines the strength of the context claim based on the detected brand and category.
   *
   * @param {Object} contextObj
   * @returns {'STRONG'|'MODERATE'|'WEAK'|'NONE'}
   */
  function getClaimStrength(contextObj) {
    if (!contextObj || !contextObj.possibleClaimedBrand) return 'NONE';

    var cat = contextObj.category;
    var strongCategories = ['LOGIN_ACCOUNT', 'PAYMENT', 'VERIFICATION_SECURITY', 'DELIVERY_ORDER'];
    var moderateCategories = ['REWARD_OFFER', 'JOB_HIRING', 'GOVERNMENT_SERVICE'];

    if (strongCategories.indexOf(cat) !== -1) {
      return 'STRONG';
    }

    if (moderateCategories.indexOf(cat) !== -1) {
      return 'MODERATE';
    }

    return 'WEAK';
  }

  /**
   * Compares the extracted context against the verified destination.
   * Returns a mismatch object if a STRONG claim conflicts with the verified destination.
   * Returns null if official, claim is weak, or destination is unverified/inconclusive.
   *
   * @param {Object} contextObj
   * @param {string} verifiedDestinationUrl
   * @returns {Object|null}
   */
  function evaluateMismatch(contextObj, verifiedDestinationUrl) {
    if (!contextObj || !contextObj.possibleClaimedBrand) return null;
    if (!verifiedDestinationUrl) return null; // Inconclusive / unverified destination produces no mismatch

    var strength = getClaimStrength(contextObj);
    if (strength !== 'STRONG') return null; // Only mismatch on STRONG claims to prevent false positives

    var brandId = contextObj.possibleClaimedBrand;
    var isOfficial = isOfficialDestination(brandId, verifiedDestinationUrl, contextObj.category);

    if (!isOfficial) {
      var brand = BTL.brandRegistry ? BTL.brandRegistry.getBrand(brandId) : null;
      var displayBrand = brand ? brand.displayName : (brandId.charAt(0) + brandId.slice(1).toLowerCase());

      // Standardize proper brand capitalization if fallback
      var upper = brandId.toUpperCase();
      if (upper === 'PAYPAL') displayBrand = 'PayPal';
      if (upper === 'LINKEDIN') displayBrand = 'LinkedIn';
      if (upper === 'YOUTUBE') displayBrand = 'YouTube';
      if (upper === 'GITHUB') displayBrand = 'GitHub';
      if (upper === 'OPENAI') displayBrand = 'OpenAI';
      if (upper === 'WHATSAPP') displayBrand = 'WhatsApp';
      if (upper === 'SBI') displayBrand = 'State Bank of India (SBI)';
      if (upper === 'HDFC') displayBrand = 'HDFC Bank';
      if (upper === 'AXIS') displayBrand = 'Axis Bank';

      return {
        brandId: brand ? brand.id : brandId.toUpperCase(),
        displayBrand: displayBrand,
        strength: strength,
        mismatch: true
      };
    }

    return null; // Official destination confirmed
  }

  BTL.claimDestinationAnalyzer = {
    evaluateMismatch: evaluateMismatch,
    isOfficialDestination: isOfficialDestination,
    getClaimStrength: getClaimStrength,
    getVerifiedDestination: getVerifiedDestination,
    normalizeHostname: normalizeHostname
  };

})();
