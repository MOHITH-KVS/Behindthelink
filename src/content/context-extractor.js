/**
 * BehindTheLink — Context Extractor
 *
 * Extracts and conservatively categorizes local context surrounding a hovered link.
 * Built for Level 3A Context Extraction.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink || {};
  if (typeof window !== 'undefined') window.BehindTheLink = BTL;
  if (typeof self !== 'undefined') self.BehindTheLink = BTL;

  var MAX_TEXT_LEN = 200;
  var MAX_NEARBY_LEN = 500;
  var MAX_TRAVERSAL_DEPTH = 3;

  var CATEGORY_RULES = [
    { cat: 'JOB_HIRING', regex: /\b(apply now|job description|careers|hiring|job opening)\b/i },
    { cat: 'LOGIN_ACCOUNT', regex: /\b(sign in|log in|login|create account|forgot password|my account)\b/i },
    { cat: 'PAYMENT', regex: /\b(pay now|checkout|credit card|billing|invoice|make payment)\b/i },
    { cat: 'VERIFICATION_SECURITY', regex: /\b(verify account|confirm identity|security alert|update password|2fa)\b/i },
    { cat: 'REWARD_OFFER', regex: /\b(claim reward|special offer|winner|free gift|discount)\b/i },
    { cat: 'DELIVERY_ORDER', regex: /\b(track package|order status|delivery update|shipping)\b/i },
    { cat: 'GOVERNMENT_SERVICE', regex: /\b(tax return|medicare|government|official portal)\b/i },
    { cat: 'GENERAL', regex: /\b(click here|read more|continue|learn more)\b/i }
  ];

  var BRAND_REGISTRY = [
    { id: 'GOOGLE', aliases: ['google'] },
    { id: 'MICROSOFT', aliases: ['microsoft', 'windows', 'office365', 'outlook', 'onedrive'] },
    { id: 'APPLE', aliases: ['apple', 'icloud'] },
    { id: 'AMAZON', aliases: ['amazon', 'aws'] },
    { id: 'META', aliases: ['meta'] },
    { id: 'PAYPAL', aliases: ['paypal'] },
    { id: 'NETFLIX', aliases: ['netflix'] },
    { id: 'LINKEDIN', aliases: ['linkedin'] },
    { id: 'WHATSAPP', aliases: ['whatsapp'] },
    { id: 'INSTAGRAM', aliases: ['instagram'] },
    { id: 'FACEBOOK', aliases: ['facebook'] },
    { id: 'TELEGRAM', aliases: ['telegram'] },
    { id: 'YOUTUBE', aliases: ['youtube'] },
    { id: 'GITHUB', aliases: ['github'] },
    { id: 'OPENAI', aliases: ['openai', 'chatgpt'] }
  ];

  function normalize(str) {
    if (!str) return '';
    return str.replace(/\s+/g, ' ').trim();
  }

  function getVisibleText(link) {
    return normalize(link.textContent || link.innerText || '').substring(0, MAX_TEXT_LEN);
  }

  function getNearbyText(link) {
    var text = '';
    var current = link.parentElement;
    var depth = 0;
    while (current && depth < MAX_TRAVERSAL_DEPTH) {
      if (current.tagName === 'BODY' || current.tagName === 'HTML') break;
      var candidate = normalize(current.textContent || current.innerText || '');
      if (candidate.length > text.length) {
        text = candidate;
      }
      if (text.length > MAX_NEARBY_LEN) break;
      current = current.parentElement;
      depth++;
    }
    return text.substring(0, MAX_NEARBY_LEN);
  }

  function categorize(contextStr) {
    for (var i = 0; i < CATEGORY_RULES.length; i++) {
      if (CATEGORY_RULES[i].regex.test(contextStr)) {
        return CATEGORY_RULES[i].cat;
      }
    }
    return 'UNKNOWN';
  }

  function extractBrand(contextStr) {
    var lower = contextStr.toLowerCase();
    for (var i = 0; i < BRAND_REGISTRY.length; i++) {
      for (var j = 0; j < BRAND_REGISTRY[i].aliases.length; j++) {
        var regex = new RegExp('\\b' + BRAND_REGISTRY[i].aliases[j] + '\\b');
        if (regex.test(lower)) {
          return BRAND_REGISTRY[i].id;
        }
      }
    }
    return null;
  }

  function extract(link) {
    if (!link) return null;

    var visibleText = getVisibleText(link);
    var ariaLabel = normalize(link.getAttribute('aria-label') || '').substring(0, MAX_TEXT_LEN);
    var title = normalize(link.getAttribute('title') || '').substring(0, MAX_TEXT_LEN);
    var nearbyText = getNearbyText(link);

    var fullContext = [visibleText, ariaLabel, title, nearbyText].join(' ');
    var category = categorize(fullContext);
    var brand = extractBrand(fullContext);

    return {
      visibleText: visibleText,
      ariaLabel: ariaLabel,
      title: title,
      nearbyText: nearbyText,
      category: category,
      possibleClaimedBrand: brand,
      evidence: {
        visible_text: visibleText.length > 0,
        aria_label: ariaLabel.length > 0,
        title: title.length > 0,
        nearby_text: nearbyText.length > 0
      }
    };
  }

  BTL.contextExtractor = {
    extract: extract,
    _normalize: normalize,
    _categorize: categorize,
    _extractBrand: extractBrand
  };

})();
