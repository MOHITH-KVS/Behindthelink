/**
 * BehindTheLink — Shared Constants
 *
 * Single source of truth for all configurable values.
 * Change timing, sizing, and layout values here — not in individual modules.
 */
(typeof window !== 'undefined' ? window : self).BehindTheLink = {

  // Hover timing (ms)
  HOVER_DELAY: 450,

  // Card dimensions and positioning (px)
  CARD_WIDTH: 300,
  CARD_GAP: 8,
  VIEWPORT_PADDING: 12,

  // Animation duration (ms)
  ANIMATION_DURATION: 120,

  // Timeout for destination resolution (ms)
  DESTINATION_TIMEOUT: 5000,
};
