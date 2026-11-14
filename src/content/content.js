/**
 * BehindTheLink — Content Script Entry Point
 *
 * Wires up document-level event delegation for the hover-based
 * link preview system. This is the only file that touches the DOM
 * event bus directly; all logic lives in the individual modules.
 *
 * Loaded last (after constants, link-eligibility, preview-ui, hover-manager).
 */
(function () {
  'use strict';

  var BTL = window.BehindTheLink;

  // The scripts can be loaded twice in one page (for example when they are added to
  // an already-open tab at install time). Attach the listeners only once.
  if (window.__btlListenersAttached) return;
  window.__btlListenersAttached = true;

  // Document-level delegation in the capturing phase (capture: true)
  // This ensures we receive events BEFORE page scripts can call stopPropagation(),
  // which fixes false popups on dynamic sites like LinkedIn and Telegram.
  document.addEventListener('mouseover', BTL.hoverManager.handleMouseOver, { passive: true, capture: true });
  document.addEventListener('mouseout',  BTL.hoverManager.handleMouseOut,  { passive: true, capture: true });
  document.addEventListener('click',     BTL.hoverManager.handleClick,     { passive: true, capture: true });
})();
