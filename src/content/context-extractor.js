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
  var MAX_TRAVERSAL_DEPTH = 6;

  var CATEGORY_RULES = [
    { cat: 'JOB_HIRING', regex: /\b(apply now|job description|careers|hiring|job opening)\b/i },
    { cat: 'LOGIN_ACCOUNT', regex: /\b(sign in|log in|login|create account|forgot password|my account)\b/i },
    { cat: 'PAYMENT', regex: /\b(pay now|checkout|credit card|billing|invoice|make payment)\b/i },
    { cat: 'VERIFICATION_SECURITY', regex: /\b(verify account|confirm identity|security alert|update password|2fa)\b/i },
    { cat: 'REWARD_OFFER', regex: /\b(claim reward|special offer|winner|free gift|discount)\b/i },
    { cat: 'DELIVERY_ORDER', regex: /\b(track package|order status|delivery update|shipping)\b/i },
    { cat: 'GOVERNMENT_SERVICE', regex: /\b(tax return|medicare|government|official portal)\b/i },
    { cat: 'MEDIA_OR_DOWNLOAD', regex: /(?:\b(?:download|torrent|stream)\b[\w\s,–\-|]{0,35}\b(?:movies?|films?|episodes?|series|cinema|apk)\b|\b(?:movies?|films?|episodes?|series|cinema)\b[\w\s,–\-|]{0,35}\b(?:download|torrent)\b|\b(?:watch|stream)\b[\w\s,–\-|]{0,35}\b(?:movies?|films?|cinema|episodes?|shows?)\b[\w\s,–\-|]{0,35}\b(?:online|free)\b|\b(?:free\s+movie\s+download|watch\s+movies?\s+online|download\s+movies?|torrent\s+download|download\s+movie\s+torrent|download\s+apk|install\s+apk|install\s+(?:this\s+)?app(?:lication)?\s+to\s+watch)\b)/i },
    { cat: 'GENERAL', regex: /\b(click here|read more|continue|learn more)\b/i }
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

    // Stop climbing past known search result container boundaries to keep context bounded
    var searchItem = (link.closest && typeof link.closest === 'function')
      ? link.closest('.g, .MjjYud, .b_algo, article, [data-sokoban-container], [data-hveid]')
      : null;

    while (current && depth < MAX_TRAVERSAL_DEPTH) {
      if (current.tagName === 'BODY' || current.tagName === 'HTML') break;
      var candidate = normalize(current.textContent || current.innerText || '');
      if (candidate.length > text.length) {
        text = candidate;
      }
      if (searchItem && current === searchItem) break;
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

  function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function extractBrand(contextStr, category) {
    if (!contextStr) return null;

    // Primary: Consume unified Brand Registry
    if (BTL.brandRegistry && typeof BTL.brandRegistry.getAllAliases === 'function') {
      var allAliases = BTL.brandRegistry.getAllAliases();
      var lower = contextStr.toLowerCase();

      for (var i = 0; i < allAliases.length; i++) {
        var item = allAliases[i];
        var textToSearch = item.matchCase ? contextStr : lower;
        var pattern = item.matchCase ? escapeRegex(item.text) : escapeRegex(item.text.toLowerCase());
        var regex = new RegExp('\\b' + pattern + '\\b');

        if (regex.test(textToSearch)) {
          return item.brandId;
        }
      }
      return null;
    }

    // Defensive fallback if Brand Registry is not loaded in sandbox
    var lowerFallback = contextStr.toLowerCase();
    var FALLBACK_REGISTRY = [
      { id: 'GOOGLE', aliases: ['google', 'gmail'] },
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
      { id: 'OPENAI', aliases: ['openai', 'chatgpt'] },
      { id: 'SBI', aliases: ['state bank of india', 'sbi', 'onlinesbi'] },
      { id: 'HDFC', aliases: ['hdfc bank', 'hdfc', 'hdfcbank'] },
      { id: 'AXIS', aliases: ['axis bank', 'axis', 'axisbank'] }
    ];

    for (var f = 0; f < FALLBACK_REGISTRY.length; f++) {
      for (var a = 0; a < FALLBACK_REGISTRY[f].aliases.length; a++) {
        var fbRegex = new RegExp('\\b' + escapeRegex(FALLBACK_REGISTRY[f].aliases[a]) + '\\b');
        if (fbRegex.test(lowerFallback)) {
          return FALLBACK_REGISTRY[f].id;
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
    var brand = extractBrand(fullContext, category);

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
