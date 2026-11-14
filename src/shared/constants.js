/**
 * BehindTheLink — Shared Constants
 *
 * Single source of truth for all configurable values.
 * Change timing, sizing, and layout values here — not in individual modules.
 */
(function () {
  'use strict';

  var root = (typeof window !== 'undefined' ? window : self);
  root.BehindTheLink = root.BehindTheLink || {};

  // Hover timing (ms)
  root.BehindTheLink.HOVER_DELAY = 450;

  // Card dimensions and positioning (px)
  root.BehindTheLink.CARD_WIDTH = 300;
  root.BehindTheLink.CARD_GAP = 8;
  root.BehindTheLink.VIEWPORT_PADDING = 12;

  // Animation duration (ms)
  root.BehindTheLink.ANIMATION_DURATION = 120;

  // Timeout for destination resolution (ms)
  root.BehindTheLink.DESTINATION_TIMEOUT = 5000;

  // Evidence Model Check Categories
  root.BehindTheLink.CHECK_CATEGORIES = {
    DESTINATION: 'destination',
    THREAT_INTELLIGENCE: 'threat_intelligence',
    DOMAIN: 'domain',
    BUSINESS_IDENTITY: 'business_identity',
    BEHAVIORAL: 'behavioral'
  };

  // Evidence Check Statuses
  root.BehindTheLink.CHECK_STATUSES = {
    MATCH: 'MATCH',
    NO_MATCH: 'NO_MATCH',
    WARNING: 'WARNING',
    UNAVAILABLE: 'UNAVAILABLE',
    NOT_CHECKED: 'NOT_CHECKED'
  };

  // Conceptual Verdicts
  root.BehindTheLink.VERDICTS = {
    MALICIOUS: 'MALICIOUS',
    SUSPICIOUS: 'SUSPICIOUS',
    UNVERIFIED: 'UNVERIFIED',
    NO_KNOWN_THREATS_FOUND: 'NO_KNOWN_THREATS_FOUND'
  };
})();
