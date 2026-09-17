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
    'JOB_ACTION': 26
  };

  function getPriority(signalId) {
    return PRIORITY_MAP[signalId] || 999;
  }

  // Technical -> Human translation
  function humanizeLabel(signalId, defaultLabel) {
    var map = {
      'IP_HOST': 'IP-address destination',
      'IP_HOST_V4': 'IP-address destination',
      'IP_HOST_V6': 'IPv6-address destination',
      'PUNYCODE_DOMAIN': 'Unusual domain characteristics',
      'USERINFO_IN_URL': 'Embedded login information in the URL',
      'UNUSUAL_PORT': 'Unusual connection port',
      'DEEP_SUBDOMAIN': 'Unusually deep domain structure',
      'HEAVY_ENCODING': 'Heavily encoded URL',
      'SENSITIVE_ACTION_PATH': 'Sensitive action in the URL',
      'HTTP_NOT_HTTPS': 'Unencrypted connection (HTTP)'
    };
    return map[signalId] || defaultLabel;
  }

  function hasSignal(signals, id) {
    for (var i = 0; i < signals.length; i++) {
      if (signals[i].id === id) return true;
    }
    return false;
  }

  function generateWhyText(signals) {
    var hasMismatch = hasSignal(signals, 'CLAIM_DESTINATION_MISMATCH');
    var hasPressure = hasSignal(signals, 'URGENT_LANGUAGE');
    var hasAccount = hasSignal(signals, 'ACCOUNT_ACTION');
    var hasPayment = hasSignal(signals, 'PAYMENT_ACTION');
    var hasReward = hasSignal(signals, 'REWARD_OFFER_ACTION');
    var hasDelivery = hasSignal(signals, 'DELIVERY_ACTION');
    var hasJob = hasSignal(signals, 'JOB_ACTION');
    var hasThreat = hasSignal(signals, 'REPUTATION_CONFIRMED_THREAT');
    var hasSensitive = hasAccount || hasPayment || hasReward || hasDelivery || hasJob;
    
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
      return "The link's description doesn't match its verified destination.";
    }

    if (hasPressure && hasSensitive) {
      return "This link combines time pressure with an action involving your account or information.";
    }
    
    if (hasStructural) {
      return "The destination has characteristics that are worth checking before continuing.";
    }
    
    // Default fallback to single signal's detail if available and nothing else matched
    if (hasAccount) return "This link appears to involve an account action.";
    if (hasPayment) return "This link appears to involve a payment action.";
    if (hasReward) return "This link appears to promote a reward or offer.";
    if (hasDelivery) return "This link appears to relate to a delivery.";
    if (hasJob) return "This link appears to relate to a job or application.";
    
    if (signals.length > 0 && signals[0].detail) {
      return signals[0].detail;
    }

    return null; 
  }

  function generateActionText(signals) {
    var hasMismatch = hasSignal(signals, 'CLAIM_DESTINATION_MISMATCH');
    var hasAccount = hasSignal(signals, 'ACCOUNT_ACTION');
    var hasPayment = hasSignal(signals, 'PAYMENT_ACTION');
    var hasReward = hasSignal(signals, 'REWARD_OFFER_ACTION');
    var hasDelivery = hasSignal(signals, 'DELIVERY_ACTION');
    var hasJob = hasSignal(signals, 'JOB_ACTION');
    var hasThreat = hasSignal(signals, 'REPUTATION_CONFIRMED_THREAT');
    
    var sensitiveCount = 0;
    if (hasAccount) sensitiveCount++;
    if (hasPayment) sensitiveCount++;
    if (hasReward) sensitiveCount++;
    if (hasDelivery) sensitiveCount++;
    if (hasJob) sensitiveCount++;

    if (hasThreat) {
      return "Do not visit this destination or provide any information.";
    }

    if (hasMismatch) {
      return "Check the destination domain before continuing.";
    }
    
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
      // Do not treat these as safety bullets unless they are part of a larger structural combo that escalated status
      // (Wait, actually we should never show these in the Safety bullet list. They go in LINK TYPE.)
      if (s.id === 'REDIRECTS_THROUGH_SHORTENER' || 
          s.id === 'HAS_TRACKING_PARAMS' || 
          s.id === 'HAS_AFFILIATE' ||
          s.id === 'REDIRECTS_TO_DIFFERENT_DOMAIN' ||
          s.id === 'SUSPICIOUS_FILE_EXT' || // Note: Suspicious File Ext is safety but it's low priority
          s.id === 'HTTP_NOT_HTTPS') {
          // Actually, if HTTP_NOT_HTTPS is present but status is INFORMATIONAL, we can show it, but the prompt says:
          // "do not automatically feel dangerous." But let's allow it if it's tier B. 
          // Wait! The user says: "Link-type information is different. Do not mix ordinary link metadata with safety warnings."
          // So let's exclude purely link metadata.
      }
      
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
        // Apply technical translation mapping
        var newSig = Object.assign({}, sig);
        newSig.label = humanizeLabel(newSig.id, newSig.label);
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
       whyText = generateWhyText(deduped);
       actionText = generateActionText(deduped);
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
