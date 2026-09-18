/**
 * BehindTheLink — Shortener Registry
 *
 * Centralized list of known URL shortener domains.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink;

  var SHORTENER_DOMAINS = new Set([
    'bit.ly',
    'tinyurl.com',
    't.co',
    'is.gd',
    'ow.ly',
    'buff.ly',
    'cutt.ly',
    'rebrand.ly',
    'shorturl.at',
    'tiny.cc',
    'goo.gl',
    'tr.im',
    'cli.gs',
    'trib.al',
    'sh.st',
    'bc.vc',
    'po.st',
    'v.gd',
    'lnkd.in',
    'youtu.be',
    't.me',
    'telegram.me',
    'link.district.in',
    'smarturl.it'
  ]);

  BTL.shortenerRegistry = {
    /**
     * Checks if a given hostname is a known URL shortener.
     * @param {string} hostname
     * @returns {boolean}
     */
    isShortener: function(hostname) {
      // Remove 'www.' prefix if it exists for checking
      var cleanHost = hostname.toLowerCase();
      if (cleanHost.startsWith('www.')) {
        cleanHost = cleanHost.substring(4);
      }
      return SHORTENER_DOMAINS.has(cleanHost);
    }
  };

})();
