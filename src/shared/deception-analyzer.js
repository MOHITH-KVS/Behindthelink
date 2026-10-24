/**
 * BehindTheLink — Deception Analyzer
 *
 * Level 3C: Local heuristic detection of pressure and sensitive-action phrasing.
 * Does NOT generate false positives for generic words (e.g. "action").
 * Uses bounded context inputs strictly extracted by Level 3A.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink || {};
  if (typeof window !== 'undefined') window.BehindTheLink = BTL;
  if (typeof self !== 'undefined') self.BehindTheLink = BTL;

  // Curated regexes using strict word boundaries (\b)
  var PHRASES = {
    URGENT_STRONG: /\b(act now|verify now|claim now|expires (soon|today)|last chance|limited time|within 24 hours|account will be suspended|account will be closed|respond immediately|action required)\b/i,
    URGENT_CONTEXTUAL: /\b(urgent|immediately|now)\b/i,
    ACCOUNT: /\b(sign in|login|verify account|confirm account|reset password|security verification)\b/i,
    PAYMENT: /\b(pay now|make payment|confirm payment|update billing|billing information|payment required|invoice|refund)\b/i,
    REWARD: /\b(you won|claim your reward|claim prize|free gift|exclusive reward|cash reward|bonus|winner|congratulations)\b/i,
    DELIVERY: /\b(package|delivery|shipment|delivery failed|track your order|confirm delivery|delivery address|customs payment)\b/i,
    JOB: /\b(job offer|interview|application|salary|career opportunity|selected for interview|complete application)\b/i
  };

  var MEDIA_PHRASES = {
    APP_OR_APK: /(?:\bdownload\s+apk\b|\binstall\s+apk\b|\bapk\s+download\b|\binstall\s+(?:this\s+)?app(?:lication)?\s+to\s+watch\b)/i,
    UNOFFICIAL_STREAMING: /(?:\b(?:torrent|torrents|magnet|pirat(?:ed|e|y)|leaks?|leaked)\b|\bfree\s+(?:full\s+)?movies?\s+download\b|\bdownload\s+(?:[\w\s,–\-|]{0,35}\b)?(?:movies?|films?)\s+(?:free|hd)\b|\b(?:movies?|films?)\s+free\s+download\b|\bdownload\s+movie\s+torrent\b|\btorrent\s+download\b|\bwatch\s+(?:[\w\s,–\-|]{0,35}\b)?movies?\s+online\s+free\b|\bwatch\s+free\s+movies?\b|\bfree\s+movies?\s+online\b)/i,
    GENERAL_MEDIA: /(?:\b(?:download|torrent|stream)\b[\w\s,–\-|]{0,35}\b(?:movies?|films?|episodes?|series|cinema)\b|\b(?:movies?|films?|episodes?|series|cinema)\b[\w\s,–\-|]{0,35}\b(?:download|torrent)\b|\b(?:watch|stream)\b[\w\s,–\-|]{0,35}\b(?:movies?|films?|cinema|episodes?|shows?)\b[\w\s,–\-|]{0,35}\b(?:online|free)\b|\b(?:download\s+movies?|watch\s+movies?\s+online|stream\s+movies?|download\s+movie)\b)/i
  };

  var SPECIFIC_MEDIA_DOMAINS = /(?:^|\d*)(?:movierulz|123movies?|fmovies?|bmovies?|yesmovies?|solarmovie|putlocker|tamilrockers|filmywap|bolly4u|khatrimaza|torrentgalaxy|piratebay|limetorrents?|yts|1337x|todaypk|worldfree4u|mkvcage|rarbg)/i;
  var JOINED_MEDIA_DOMAINS = /(?:^|[a-z0-9])(?:freemovies?|movies?free|watchmovies?|downloadmovies?|movies?download)/i;
  var JOINED_RULZ = /(?:^|\d+)(?:movie|film|cinema)rulz/i;

  function extractDomainMediaIntent(hostname) {
    if (!hostname) return false;
    var host = hostname.toLowerCase();
    var parts = host.split('.');
    var stem = (parts.length > 1) ? parts[parts.length - 2] : host;
    return SPECIFIC_MEDIA_DOMAINS.test(host) || SPECIFIC_MEDIA_DOMAINS.test(stem) ||
           JOINED_MEDIA_DOMAINS.test(host) || JOINED_MEDIA_DOMAINS.test(stem) ||
           JOINED_RULZ.test(host) || JOINED_RULZ.test(stem);
  }

  var MAINSTREAM_STREAMING_DOMAINS = [
    'youtube.com', 'youtu.be', 'netflix.com', 'primevideo.com', 'amazon.com',
    'hulu.com', 'disneyplus.com', 'apple.com', 'max.com', 'hbomax.com',
    'paramountplus.com', 'peacocktv.com', 'imdb.com', 'rottentomatoes.com', 'wikipedia.org',
    'vimeo.com', 'twitch.tv', 'spotify.com', 'soundcloud.com', 'dailymotion.com',
    'crunchyroll.com', 'hotstar.com', 'tubitv.com', 'plex.tv', 'pluto.tv', 'archive.org'
  ];

  function isMainstreamStreaming(destUrl, contextObj) {
    if (contextObj && contextObj.possibleClaimedBrand) {
      var claimed = (contextObj.possibleClaimedBrand || '').toUpperCase();
      if (claimed === 'YOUTUBE' || claimed === 'NETFLIX' || claimed === 'AMAZON' || claimed === 'APPLE') {
        return true;
      }
    }
    if (!destUrl) return false;
    try {
      var host = new URL(destUrl).hostname.toLowerCase();
      for (var i = 0; i < MAINSTREAM_STREAMING_DOMAINS.length; i++) {
        var d = MAINSTREAM_STREAMING_DOMAINS[i];
        if (host === d || host.endsWith('.' + d)) {
          return true;
        }
      }
    } catch (e) {}
    return false;
  }

  function normalize(str) {
    if (!str) return '';
    return str.toLowerCase().replace(/\s+/g, ' ').trim();
  }

  function analyzeDeception(contextObj, destinationUrl) {
    contextObj = contextObj || {};
    
    // Combine all textual context limits to search
    var fullText = normalize(
      [contextObj.visibleText, contextObj.title, contextObj.ariaLabel, contextObj.nearbyText].join(' ')
    );

    var linkOwnText = normalize(
      [contextObj.visibleText, contextObj.title, contextObj.ariaLabel].join(' ')
    );
    var isGenericLink = !linkOwnText || /^(link|click here|read more|continue|here|details|view|more)$/i.test(linkOwnText);

    var destHost = '';
    var destPath = '';
    if (destinationUrl) {
      try {
        var dUrl = new URL(destinationUrl);
        destHost = dUrl.hostname.toLowerCase();
        destPath = dUrl.pathname || '';
      } catch (e) {}
    }
    
    var signals = [];
    var hasSensitive = false;

    // Account Action
    if (contextObj.category === 'LOGIN_ACCOUNT' || contextObj.category === 'VERIFICATION_SECURITY' || PHRASES.ACCOUNT.test(fullText)) {
      hasSensitive = true;
      signals.push({
        id: 'ACCOUNT_ACTION',
        tier: 'C',
        label: 'Account or sign-in action',
        detail: 'This link appears to request an account or sign-in action.',
        source: 'local_url',
        epistemic: 'OBSERVED',
        dimension: 'account_action'
      });
    }

    // Scoped Payment Action
    var isPaymentPath = /(?:^|\/)(?:checkout|pay|payment|billing|gp\/buy|buy-now|make-payment|cart\/checkout)(?:[\/?#]|$)/i.test(destPath);
    var isOwnPaymentText = PHRASES.PAYMENT.test(linkOwnText);

    var isAmazonOrShoppingCatalog = false;
    if (/(?:^|\.)amazon\.[a-z.]+$/i.test(destHost)) {
      if (!isPaymentPath && !isOwnPaymentText) {
        isAmazonOrShoppingCatalog = true;
      }
    }

    var isCrossDomainPayment = false;
    if (contextObj.possibleClaimedBrand) {
      var claimed = (contextObj.possibleClaimedBrand || '').toUpperCase();
      if (claimed === 'AMAZON' && !/(?:^|\.)amazon\.[a-z.]+$/i.test(destHost)) {
        isCrossDomainPayment = true;
      } else if (claimed === 'PAYPAL' && !/(?:^|\.)paypal\.[a-z.]+$/i.test(destHost)) {
        isCrossDomainPayment = true;
      }
    }

    var hasPaymentIntent = false;
    if (isOwnPaymentText || isPaymentPath) {
      hasPaymentIntent = true;
    } else if (isCrossDomainPayment && (contextObj.category === 'PAYMENT' || PHRASES.PAYMENT.test(fullText))) {
      hasPaymentIntent = true;
    } else if (isGenericLink && contextObj.category === 'PAYMENT' && !isAmazonOrShoppingCatalog) {
      hasPaymentIntent = true;
    }

    if (hasPaymentIntent) {
      hasSensitive = true;
      signals.push({
        id: 'PAYMENT_ACTION',
        tier: 'C',
        label: 'Payment-related action',
        detail: 'This link appears to involve a payment or financial action.',
        source: 'local_url',
        epistemic: 'OBSERVED',
        dimension: 'payment_action'
      });
    }

    // Reward / Offer
    if (contextObj.category === 'REWARD_OFFER' || PHRASES.REWARD.test(fullText)) {
      hasSensitive = true;
      signals.push({
        id: 'REWARD_OFFER_ACTION',
        tier: 'C',
        label: 'Reward or offer language',
        detail: 'This link appears to promote a reward, prize, or special offer.',
        source: 'local_url',
        epistemic: 'OBSERVED',
        dimension: 'reward_offer'
      });
    }

    // Scoped Delivery / Order
    var isOwnDeliveryText = PHRASES.DELIVERY.test(linkOwnText);
    var isDeliveryPath = /(?:^|\/)(?:track|order-status|delivery|shipment)(?:[\/?#]|$)/i.test(destPath);
    var hasDeliveryIntent = isOwnDeliveryText || isDeliveryPath || (isGenericLink && contextObj.category === 'DELIVERY_ORDER' && !isAmazonOrShoppingCatalog);

    if (hasDeliveryIntent) {
      hasSensitive = true;
      signals.push({
        id: 'DELIVERY_ACTION',
        tier: 'C',
        label: 'Delivery or order action',
        detail: 'This link appears to relate to a delivery or order.',
        source: 'local_url',
        epistemic: 'OBSERVED',
        dimension: 'delivery_action'
      });
    }

    // Job / Hiring
    if (contextObj.category === 'JOB_HIRING' || PHRASES.JOB.test(fullText)) {
      hasSensitive = true;
      signals.push({
        id: 'JOB_ACTION',
        tier: 'C',
        label: 'Job-related action',
        detail: 'This link appears to relate to a job or application.',
        source: 'local_url',
        epistemic: 'OBSERVED',
        dimension: 'job_action'
      });
    }

    // Media / Download Context (including joined domain tokens)
    if (!isMainstreamStreaming(destinationUrl, contextObj)) {
      var isDomainMedia = extractDomainMediaIntent(destHost);

      if (MEDIA_PHRASES.APP_OR_APK.test(fullText)) {
        signals.push({
          id: 'APP_OR_APK_DOWNLOAD_CONTEXT',
          tier: 'C',
          label: 'App or APK download context',
          detail: 'This link suggests downloading an application or APK to stream or watch content.',
          source: 'local_url',
          epistemic: 'OBSERVED',
          dimension: 'media_download_action'
        });
      } else if (MEDIA_PHRASES.UNOFFICIAL_STREAMING.test(fullText) || isDomainMedia) {
        signals.push({
          id: 'UNOFFICIAL_STREAMING_OR_DOWNLOAD_CONTEXT',
          tier: 'C',
          label: 'Movie-download or unofficial streaming context',
          detail: 'This link appears to lead to a movie-download or unofficial streaming page.',
          source: 'local_url',
          epistemic: 'OBSERVED',
          dimension: 'media_download_action'
        });
      } else if (contextObj.category === 'MEDIA_OR_DOWNLOAD' || MEDIA_PHRASES.GENERAL_MEDIA.test(fullText)) {
        signals.push({
          id: 'DOWNLOAD_OR_MEDIA_CONTEXT',
          tier: 'C',
          label: 'Movie-download context detected',
          detail: 'This link relates to a movie-download or media streaming action. Page content and downloadable files were not inspected.',
          source: 'local_url',
          epistemic: 'OBSERVED',
          dimension: 'media_download_action'
        });
      }
    }

    // Urgency / Pressure (Evaluated last to check context)
    if (PHRASES.URGENT_STRONG.test(fullText) || (hasSensitive && PHRASES.URGENT_CONTEXTUAL.test(fullText))) {
      signals.push({
        id: 'URGENT_LANGUAGE',
        tier: 'C',
        label: 'Urgent language',
        detail: 'This link uses language that encourages immediate action.',
        source: 'local_url',
        epistemic: 'OBSERVED',
        dimension: 'pressure'
      });
    }

    return signals;
  }

  BTL.deceptionAnalyzer = {
    analyzeDeception: analyzeDeception
  };

})();
