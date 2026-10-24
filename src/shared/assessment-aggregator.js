/**
 * BehindTheLink — Assessment Aggregator
 *
 * Level 3D: Deterministic centralized prioritization and explanation layer.
 * Aggregates Tier A/B/C/D signals into a user-facing structure without fear-mongering.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink || {};
  if (typeof window !== 'undefined') window.BehindTheLink = BTL;
  if (typeof self !== 'undefined') self.BehindTheLink = BTL;

  // Signal priority ordering
  var PRIORITY_MAP = {
    'REPUTATION_CONFIRMED_THREAT': 1,
    'CLAIM_DESTINATION_MISMATCH': 2,
    'MISLEADING_SUBDOMAIN_STRUCTURE': 2.1,
    'LOOKALIKE_DOMAIN_SIMILARITY': 2.2,
    'BRAND_EMBEDDED_IN_UNRELATED_DOMAIN': 2.3,
    
    // Structural characteristics (Level 2)
    'IP_HOST': 3,
    'IP_HOST_V4': 3,
    'IP_HOST_V6': 3,
    'PUNYCODE_DOMAIN': 4,
    'USERINFO_IN_URL': 5,
    'UNUSUAL_PORT': 6,
    'DEEP_SUBDOMAIN': 7,
    'HTTP_NOT_HTTPS': 8,
    'HEAVY_ENCODING': 9,
    'SUSPICIOUS_FILE_EXT': 10,
    
    // Contextual characteristics (Level 3C)
    'URGENT_LANGUAGE': 20,
    'ACCOUNT_ACTION': 21,
    'PAYMENT_ACTION': 22,
    'REWARD_OFFER_ACTION': 23,
    'DELIVERY_ACTION': 24,
    'VERIFICATION_ACTION': 25,
    'JOB_ACTION': 26,
    'APP_OR_APK_DOWNLOAD_CONTEXT': 27,
    'UNOFFICIAL_STREAMING_OR_DOWNLOAD_CONTEXT': 28,
    'DOWNLOAD_OR_MEDIA_CONTEXT': 29
  };

  function getPriority(signalId) {
    return PRIORITY_MAP[signalId] || 999;
  }

  // Technical -> Human translation
  function humanizeLabel(signalId, defaultLabel, sig) {
    if (sig) {
      if (sig.id === 'CLAIM_DESTINATION_MISMATCH' && sig.detail) {
        return sig.detail;
      }
      if ((sig.id === 'LOOKALIKE_DOMAIN_SIMILARITY' ||
           sig.id === 'BRAND_EMBEDDED_IN_UNRELATED_DOMAIN' ||
           sig.id === 'MISLEADING_SUBDOMAIN_STRUCTURE') && sig.detail) {
        return sig.detail;
      }
    }
    var map = {
      'IP_HOST': 'IP-address destination',
      'IP_HOST_V4': 'IP-address destination',
      'IP_HOST_V6': 'IPv6-address destination',
      'PUNYCODE_DOMAIN': 'Unusual domain characteristics',
      'USERINFO_IN_URL': 'Embedded login information in the URL',
      'UNUSUAL_PORT': 'Unusual connection port',
      'DEEP_SUBDOMAIN': 'Unusually deep domain structure',
      'HEAVY_ENCODING': 'Heavy URL encoding',
      'SENSITIVE_ACTION_PATH': 'Sensitive action in the URL',
      'HTTP_NOT_HTTPS': 'Unencrypted connection (HTTP)',
      'CLAIM_DESTINATION_MISMATCH': 'The link mentions a brand, but the destination is not an official domain.',
      'LOOKALIKE_DOMAIN_SIMILARITY': 'The destination domain closely resembles a known brand.',
      'BRAND_EMBEDDED_IN_UNRELATED_DOMAIN': 'A brand name is included in an unrelated domain.',
      'MISLEADING_SUBDOMAIN_STRUCTURE': 'The destination uses a brand name in a misleading subdomain.',
      'APP_OR_APK_DOWNLOAD_CONTEXT': 'App or APK download context',
      'UNOFFICIAL_STREAMING_OR_DOWNLOAD_CONTEXT': 'Movie-download or unofficial streaming context',
      'DOWNLOAD_OR_MEDIA_CONTEXT': 'Movie-download context detected'
    };
    return map[signalId] || defaultLabel;
  }

  function hasSignal(signals, id) {
    for (var i = 0; i < signals.length; i++) {
      if (signals[i].id === id) return true;
    }
    return false;
  }

  function generateWhyText(signals, rawSignals) {
    var hasMismatch = hasSignal(signals, 'CLAIM_DESTINATION_MISMATCH');
    var hasLookalike = hasSignal(signals, 'LOOKALIKE_DOMAIN_SIMILARITY') ||
                       hasSignal(signals, 'BRAND_EMBEDDED_IN_UNRELATED_DOMAIN') ||
                       hasSignal(signals, 'MISLEADING_SUBDOMAIN_STRUCTURE');
    var hasPressure = hasSignal(signals, 'URGENT_LANGUAGE');
    var hasAccount = hasSignal(signals, 'ACCOUNT_ACTION');
    var hasPayment = hasSignal(signals, 'PAYMENT_ACTION');
    var hasReward = hasSignal(signals, 'REWARD_OFFER_ACTION');
    var hasDelivery = hasSignal(signals, 'DELIVERY_ACTION');
    var hasJob = hasSignal(signals, 'JOB_ACTION');
    var hasApk = hasSignal(signals, 'APP_OR_APK_DOWNLOAD_CONTEXT');
    var hasUnofficial = hasSignal(signals, 'UNOFFICIAL_STREAMING_OR_DOWNLOAD_CONTEXT');
    var hasMedia = hasSignal(signals, 'DOWNLOAD_OR_MEDIA_CONTEXT') || hasUnofficial || hasApk;
    var hasThreat = hasSignal(signals, 'REPUTATION_CONFIRMED_THREAT');
    var hasTracking = rawSignals && hasSignal(rawSignals, 'HAS_TRACKING_PARAMS');
    var hasSensitive = hasAccount || hasPayment || hasReward || hasDelivery || hasJob || hasMedia;
    
    var hasStructural = false;
    for (var i = 0; i < signals.length; i++) {
      if (signals[i].tier === 'B' && signals[i].id !== 'HTTP_NOT_HTTPS' && signals[i].id !== 'SUSPICIOUS_FILE_EXT') {
        hasStructural = true;
        break;
      }
    }

    if (hasThreat) {
      return "This destination has been flagged as a known threat.";
    }

    if (hasMismatch && hasPressure && hasSensitive) {
      return "This link combines a service claim, a verified destination mismatch, and time pressure.";
    }
    
    if (hasMismatch) {
      for (var m = 0; m < signals.length; m++) {
        if (signals[m].id === 'CLAIM_DESTINATION_MISMATCH' && signals[m].detail) {
          return signals[m].detail + " Links that claim a trusted service but lead to an unrelated domain are frequently used in phishing.";
        }
      }
      return "The link mentions a brand, but the destination is not an official domain.";
    }

    if (hasLookalike && hasSensitive) {
      for (var ls = 0; ls < signals.length; ls++) {
        if ((signals[ls].id === 'LOOKALIKE_DOMAIN_SIMILARITY' ||
             signals[ls].id === 'BRAND_EMBEDDED_IN_UNRELATED_DOMAIN' ||
             signals[ls].id === 'MISLEADING_SUBDOMAIN_STRUCTURE') && signals[ls].detail) {
          return signals[ls].detail + " The link also involves account or sensitive actions, increasing the risk of credential theft.";
        }
      }
      return "The destination closely resembles a known brand and requests account or sensitive actions.";
    }

    if (hasLookalike) {
      for (var lk = 0; lk < signals.length; lk++) {
        if ((signals[lk].id === 'LOOKALIKE_DOMAIN_SIMILARITY' ||
             signals[lk].id === 'BRAND_EMBEDDED_IN_UNRELATED_DOMAIN' ||
             signals[lk].id === 'MISLEADING_SUBDOMAIN_STRUCTURE') && signals[lk].detail) {
          return signals[lk].detail + " Lookalike domains are commonly used to deceive visitors into trusting an unofficial site.";
        }
      }
      return "The destination domain closely resembles a known brand, but is not verified as official.";
    }

    if (hasPressure && hasSensitive) {
      return "This link combines time pressure with an action involving your account or information.";
    }
    
    if (hasStructural) {
      for (var s = 0; s < signals.length; s++) {
        if (signals[s].tier === 'B' && signals[s].detail) {
          return signals[s].detail;
        }
      }
      return "The destination has characteristics that are worth checking before continuing.";
    }

    if (hasPayment && hasDelivery) {
      return "This link relates to shopping, payment, or delivery context observed on the page.";
    }
    
    // Default fallback to single signal's detail if available and nothing else matched
    if (hasAccount) return "This link leads to an account or sign-in action.";
    if (hasPayment) return "This link appears to involve a payment action.";
    if (hasReward) return "This link appears to promote a reward or offer.";
    if (hasDelivery) return "This link appears to relate to a delivery.";
    if (hasJob) return "This link relates to a job application or career opportunity observed on the page.";
    if (hasUnofficial) return "This link appears to lead to a movie-download or unofficial streaming page. The destination's reputation and downloaded files have not been verified.";
    if (hasApk) return "This link suggests downloading an application or APK to stream or watch content. Downloaded files have not been verified.";
    if (hasMedia) return "Movie-download context detected. Page content and downloadable files were not inspected.";
    if (hasTracking) return "This link contains tracking information. The destination itself was not changed by this.";
    
    if (signals.length > 0 && signals[0].detail) {
      return signals[0].detail;
    }

    return null; 
  }

  function generateActionText(signals, status) {
    var hasMismatch = hasSignal(signals, 'CLAIM_DESTINATION_MISMATCH');
    var hasLookalike = hasSignal(signals, 'LOOKALIKE_DOMAIN_SIMILARITY') ||
                       hasSignal(signals, 'BRAND_EMBEDDED_IN_UNRELATED_DOMAIN') ||
                       hasSignal(signals, 'MISLEADING_SUBDOMAIN_STRUCTURE');
    var hasAccount = hasSignal(signals, 'ACCOUNT_ACTION');
    var hasPayment = hasSignal(signals, 'PAYMENT_ACTION');
    var hasReward = hasSignal(signals, 'REWARD_OFFER_ACTION');
    var hasDelivery = hasSignal(signals, 'DELIVERY_ACTION');
    var hasJob = hasSignal(signals, 'JOB_ACTION');
    var hasApk = hasSignal(signals, 'APP_OR_APK_DOWNLOAD_CONTEXT');
    var hasUnofficial = hasSignal(signals, 'UNOFFICIAL_STREAMING_OR_DOWNLOAD_CONTEXT');
    var hasThreat = hasSignal(signals, 'REPUTATION_CONFIRMED_THREAT');
    
    var hasStructural = false;
    for (var i = 0; i < signals.length; i++) {
      if (signals[i].tier === 'B' && signals[i].id !== 'HTTP_NOT_HTTPS' && signals[i].id !== 'SUSPICIOUS_FILE_EXT') {
        hasStructural = true;
        break;
      }
    }

    if (hasThreat) {
      return "Do not visit this destination or provide any information.";
    }

    if (hasMismatch) {
      return "Check the destination domain before entering sensitive information.";
    }

    if (hasLookalike) {
      return "Check the domain spelling carefully before proceeding or signing in.";
    }

    // When status is INFORMATIONAL and there is NO independent risk concern,
    // do not issue alarmist action directives for ordinary shopping, jobs, delivery, or general media context.
    if (status === 'INFORMATIONAL' && !hasStructural && !hasMismatch && !hasLookalike && !hasThreat) {
      if (hasUnofficial || hasApk) {
        return "Avoid installing APKs or executable files from untrusted sources.";
      }
      if (hasAccount) {
        return "Check the destination domain before signing in.";
      }
      return null;
    }

    if (hasUnofficial || hasApk) {
      return "Avoid installing APKs or executable files from untrusted sources.";
    }

    if (hasPayment && hasDelivery) {
      return "Verify the destination before entering payment or delivery details.";
    }
    
    var sensitiveCount = 0;
    if (hasAccount) sensitiveCount++;
    if (hasPayment) sensitiveCount++;
    if (hasReward) sensitiveCount++;
    if (hasDelivery) sensitiveCount++;
    if (hasJob) sensitiveCount++;

    if (sensitiveCount > 1) {
      return "Pause and check the destination before entering personal or financial information.";
    }
    
    if (hasAccount) {
      return "Check the destination domain before signing in.";
    }
    if (hasPayment) {
      return "Check the destination before entering payment information.";
    }
    if (hasReward) {
      return "Check the destination before providing personal information.";
    }
    if (hasDelivery) {
      return "Verify the destination before entering delivery details.";
    }
    if (hasJob) {
      return "Check the destination before submitting personal information.";
    }

    return null;
  }

  function aggregate(rawSignals, status) {
    if (!rawSignals) rawSignals = [];
    
    // 1. Separate Link Metadata from Safety Signals
    var safetySignals = [];
    
    for (var i = 0; i < rawSignals.length; i++) {
      var s = rawSignals[i];
      if (s.id === 'REDIRECTS_THROUGH_SHORTENER' || 
          s.id === 'HAS_TRACKING_PARAMS' || 
          s.id === 'HAS_AFFILIATE' ||
          s.id === 'REDIRECTS_TO_DIFFERENT_DOMAIN') {
        continue;
      }
      
      safetySignals.push(s);
    }
    
    // If status is NO_SIGNALS_DETECTED, we shouldn't show safety bullets that didn't escalate
    if (status === 'NO_SIGNALS_DETECTED') {
      safetySignals = [];
    }
    
    // 2. Deduplicate
    var seen = {};
    var deduped = [];
    for (var j = 0; j < safetySignals.length; j++) {
      var sig = safetySignals[j];
      var key = sig.dimension || sig.id;
      if (!seen[key]) {
        seen[key] = true;
        // Apply technical translation mapping with concrete signal details preserved
        var newSig = Object.assign({}, sig);
        newSig.label = humanizeLabel(newSig.id, newSig.label, newSig);
        deduped.push(newSig);
      }
    }
    
    // 3. Prioritize
    deduped.sort(function(a, b) {
      return getPriority(a.id) - getPriority(b.id);
    });
    
    // 4. Cap at 3
    var displaySignals = deduped.slice(0, 3);
    
    // 5. Generate Explanations
    var whyText = null;
    var actionText = null;
    if (status !== 'NO_SIGNALS_DETECTED') {
       whyText = generateWhyText(deduped, rawSignals);
       actionText = generateActionText(deduped, status);
    }
    
    return {
      displaySignals: displaySignals,
      whyText: whyText,
      actionText: actionText
    };
  }

  BTL.assessmentAggregator = {
    aggregate: aggregate,
    _getPriority: getPriority, 
    _humanizeLabel: humanizeLabel
  };

})();
