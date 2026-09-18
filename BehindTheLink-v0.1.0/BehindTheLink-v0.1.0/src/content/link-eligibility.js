/**
 * BehindTheLink — Link Eligibility Filter
 *
 * Determines whether a DOM element is an eligible navigational link.
 * Filters out mailto:, tel:, javascript:, fragment-only, and other
 * non-web protocols so the hover system only activates for real URLs.
 */
(function () {
  'use strict';

  var BTL = window.BehindTheLink;

  var IGNORED_PROTOCOLS = new Set([
    'javascript:',
    'mailto:',
    'tel:',
    'data:',
    'blob:',
    'chrome:',
    'chrome-extension:',
    'about:',
    'file:',
    'ftp:',
  ]);

  /**
   * Check if an element is an eligible link for BehindTheLink inspection.
   *
   * Eligible = <a> with an href that resolves to http: or https:.
   * Fragment-only links and non-web protocols are excluded.
   *
   * @param {Element} element
   * @returns {boolean}
   */
  function isEligible(element) {
    if (!element || element.tagName !== 'A') return false;

    var href = element.getAttribute('href');
    if (!href || href.trim() === '') return false;

    // Fragment-only links (#section, #top, etc.)
    if (href.trim().charAt(0) === '#') return false;

    // Fast check against ignored protocols (case-insensitive)
    var lower = href.trim().toLowerCase();
    for (var proto of IGNORED_PROTOCOLS) {
      if (lower.startsWith(proto)) return false;
    }

    // Resolve and validate — only http/https pass
    try {
      var resolved = new URL(href, document.baseURI);
      return resolved.protocol === 'http:' || resolved.protocol === 'https:';
    } catch (_) {
      return false;
    }
  }

  /**
   * Resolve a link element's href to a full absolute URL string.
   *
   * @param {HTMLAnchorElement} element
   * @returns {string}
   */
  function getResolvedUrl(element) {
    try {
      return new URL(element.getAttribute('href'), document.baseURI).href;
    } catch (_) {
      return element.getAttribute('href') || '';
    }
  }

  /**
   * Extract the hostname from a URL string.
   *
   * @param {string} url
   * @returns {string}
   */
  function getDomain(url) {
    try {
      return new URL(url).hostname;
    } catch (_) {
      return url;
    }
  }

  /**
   * Determine if a link should be inspected and show a popup.
   * Runs *after* the 450ms debounce to avoid rapid reflows.
   *
   * @param {HTMLAnchorElement} element
   * @param {string} resolvedUrl
   * @param {Object|null} analysisResult
   * @returns {boolean}
   */
  function shouldInspectLink(element, resolvedUrl, analysisResult) {
    if (!element || !resolvedUrl) return false;

    // 1. Invisible Links
    // fast size check
    if (element.offsetWidth === 0 || element.offsetHeight === 0) return false;
    
    // computed style check
    var style = window.getComputedStyle(element);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;

    // 2. Obvious UI / Navigation
    var role = (element.getAttribute('role') || '').toLowerCase();
    if (['button', 'tab', 'menuitem', 'switch', 'checkbox', 'radio'].indexOf(role) !== -1) {
      return false; // strongly semantic non-navigational controls
    }
    
    // 3. Same-Site vs External
    var currentHost = normalizeHostname(location.hostname);
    var targetHost = normalizeHostname(getDomain(resolvedUrl));
    
    var isSameSite = (currentHost === targetHost);

    if (isSameSite) {
      // Same-site + ordinary -> SUPPRESS
      // Same-site + strong signal -> INSPECT
      if (!analysisResult) return false;
      
      var hasStrongSignal = (
        analysisResult.localSignals.isShortened ||
        analysisResult.localSignals.hasAffiliate ||
        analysisResult.localSignals.trackingParams.length > 0 ||
        analysisResult.localSignals.embeddedCandidates.length > 0 ||
        analysisResult.riskSignals.severity !== 'NONE'
      );

      return hasStrongSignal;
    } else {
      // External -> INSPECT
      // Note: We intentionally do NOT aggressively filter external links with generic class="btn"
      // because an external CTA link should still be analyzed.
      return true;
    }
  }

  function normalizeHostname(hostname) {
    if (!hostname) return '';
    var lower = hostname.toLowerCase();
    if (lower.indexOf('www.') === 0) {
      return lower.substring(4);
    }
    return lower;
  }

  // Expose on the shared namespace
  BTL.isEligible = isEligible;
  BTL.getResolvedUrl = getResolvedUrl;
  BTL.getDomain = getDomain;
  BTL.shouldInspectLink = shouldInspectLink;
})();
