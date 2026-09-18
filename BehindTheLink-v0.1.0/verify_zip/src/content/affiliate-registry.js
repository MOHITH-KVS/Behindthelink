/**
 * BehindTheLink — Affiliate Registry
 *
 * Centralized list of known affiliate indicator parameters.
 * Highly conservative. We avoid generic terms like 'ref' which are 
 * often used for benign internal routing.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink;

  var AFFILIATE_PARAMS = new Set([
    'affiliate',
    'affiliate_id',
    'affiliateid',
    'aff_id',
    'affid',
    'tag' // Common on Amazon, but we will rely on it only if it's there
  ]);

  BTL.affiliateRegistry = {
    /**
     * Checks if a given query parameter key is a known high-confidence affiliate indicator.
     * @param {string} key
     * @returns {boolean}
     */
    isAffiliate: function(key) {
      return AFFILIATE_PARAMS.has(key.toLowerCase());
    }
  };

})();
