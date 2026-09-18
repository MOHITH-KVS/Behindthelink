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

  function normalize(str) {
    if (!str) return '';
    return str.toLowerCase().replace(/\s+/g, ' ').trim();
  }

  function analyzeDeception(contextObj) {
    if (!contextObj) return [];
    
    // Combine all textual context limits to search
    var fullText = normalize(
      [contextObj.visibleText, contextObj.title, contextObj.ariaLabel, contextObj.nearbyText].join(' ')
    );
    
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

    // Payment Action
    if (contextObj.category === 'PAYMENT' || PHRASES.PAYMENT.test(fullText)) {
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

    // Delivery / Order
    if (contextObj.category === 'DELIVERY_ORDER' || PHRASES.DELIVERY.test(fullText)) {
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
