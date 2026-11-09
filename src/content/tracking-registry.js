/**
 * BehindTheLink — Tracking Registry
 *
 * Centralized list of recognized tracking query parameters.
 * Kept conservative to avoid false positives on legitimate app state parameters.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink;

  var TRACKING_PARAMS = new Set([
    // Google
    'utm_source',
    'utm_medium',
    'utm_campaign',
    'utm_term',
    'utm_content',
    'utm_id',
    'gclid',
    'dclid',
    'gbraid',
    'wbraid',
    '_gl',

    // Facebook
    'fbclid',

    // Microsoft / Bing
    'msclkid',

    // TikTok
    'ttclid',

    // Twitter
    'twclid',

    // LinkedIn
    'li_fat_id',

    // Mailchimp
    'mc_cid',
    'mc_eid',

    // HubSpot
    '_hsenc',
    '_hsmi',

    // Yandex
    'yclid'
  ]);

  BTL.trackingRegistry = {
    /**
     * Checks if a given query parameter key is a known tracker.
     * @param {string} key
     * @returns {boolean}
     */
    isTracker: function(key) {
      return TRACKING_PARAMS.has(key.toLowerCase());
    }
  };

})();
