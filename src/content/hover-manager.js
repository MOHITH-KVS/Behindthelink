/**
 * BehindTheLink — Hover Manager
 *
 * Manages the hover timer, debounce, and cancellation logic.
 *
 * Key behaviours:
 *  - Tracks the currently-hovered link so child-element mouseover/mouseout
 *    events inside the same <a> don't cause false enter/leave cycles.
 *  - Uses a single trailing-edge timer (HOVER_DELAY ms).
 *  - Supports a grace period so the user can move the pointer from the
 *    anchor to the interactive preview card.
 *  - Delegates all event handling to document (no per-link listeners).
 */
(function () {
  'use strict';

  var BTL = window.BehindTheLink;

  /** @type {HTMLAnchorElement|null} */
  var currentLink = null;
  var currentRequestId = 0;

  var showTimerId = null;
  var closeTimerId = null;

  function isCard(element) {
    if (!element) return false;
    var host = typeof BTL.previewUI.getHost === 'function' ? BTL.previewUI.getHost() : null;
    return host && (element === host || host.contains(element));
  }

  // ───────────────────────────────────────────────────
  //  Event handlers (attached via document delegation)
  // ───────────────────────────────────────────────────

  function handleMouseOver(event) {
    // If entering the preview card, cancel any pending close
    if (isCard(event.target)) {
      cancelCloseTimer();
      return;
    }

    var link = event.target.closest('a[href]');

    // Still inside the same valid link — cancel any pending close
    if (link && link === currentLink) {
      cancelCloseTimer();
      return;
    }

    // Pointer moved to a new eligible link -> instantly abort the old, show the new
    if (link && BTL.isEligible(link)) {
      forceClose();
      currentLink = link;
      startShowTimer(link);
      return;
    }
  }

  function handleMouseOut(event) {
    if (!currentLink) return;

    // Pointer left the document window completely
    if (!event.relatedTarget) {
      forceClose();
      return;
    }

    var leavingCard = isCard(event.target);
    var enteringCard = isCard(event.relatedTarget);
    var leavingLink = event.target === currentLink || currentLink.contains(event.target);
    var enteringLink = event.relatedTarget === currentLink || currentLink.contains(event.relatedTarget);

    if (leavingCard && !enteringLink) {
      scheduleClose();
      return;
    }

    if (leavingLink && !enteringLink && !enteringCard) {
      scheduleClose();
      return;
    }
  }

  // ───────────────────────────────────────────────────
  //  Timer helpers
  // ───────────────────────────────────────────────────

  function safeSendMessage(message, callback) {
    var invokeError = function() {
      if (callback) callback({ status: 'network_error' });
    };

    try {
      if (!chrome.runtime || !chrome.runtime.sendMessage) {
        return invokeError();
      }
      
      chrome.runtime.sendMessage(message, function(response) {
        try {
          if (chrome.runtime.lastError) {
            return invokeError();
          }
        } catch (e) {
          return invokeError();
        }
        
        if (callback) {
          if (typeof response === 'undefined') {
            callback({ status: 'network_error' });
          } else {
            callback(response);
          }
        }
      });
    } catch (e) {
      invokeError();
    }
  }

  function startShowTimer(link) {
    cancelShowTimer();
    cancelCloseTimer();
    
    currentRequestId++;
    var activeReqId = currentRequestId;
    
    showTimerId = setTimeout(function () {
      showTimerId = null;
      var url = BTL.getResolvedUrl(link);
      var analysisResult = BTL.urlAnalyzer ? BTL.urlAnalyzer.analyzeUrl(url) : null;
      var contextObj = BTL.contextExtractor ? BTL.contextExtractor.extract(link) : null;
      
      if (!BTL.shouldInspectLink(link, url, analysisResult)) {
        return; // Suppress popup and network requests
      }

      // Show immediately with local results and loading state
      BTL.previewUI.show(link, analysisResult, true, contextObj);
      
      var isResolved = false;
      var uiDeadlineTimer = setTimeout(function() {
        if (activeReqId === currentRequestId && !isResolved) {
          isResolved = true;
          BTL.previewUI.updateNetworkResult({
            originalUrl: url,
            localSignals: analysisResult ? analysisResult.localSignals : {},
            riskSignals: analysisResult ? analysisResult.riskSignals : { severity: 'NONE', signals: [] },
            networkEvidence: { status: 'FAILED', errorReason: 'TIMEOUT', redirectTarget: null },
            browserObservation: { status: 'NONE', observedLatestUrl: null, observedAt: null, correlationEvidence: null }
          }, analysisResult);
        }
      }, 6000); // 6 seconds hard UI deadline
      
      // Begin background network resolution
      safeSendMessage({
        type: 'RESOLVE_DESTINATION',
        url: url,
        requestId: activeReqId,
        contextObj: contextObj
      }, function(response) {
        clearTimeout(uiDeadlineTimer);
        if (activeReqId === currentRequestId && !isResolved && response) {
          isResolved = true;
          BTL.previewUI.updateNetworkResult(response, analysisResult);
        }
      });
      
    }, BTL.HOVER_DELAY);
  }

  function cancelShowTimer() {
    if (showTimerId !== null) {
      clearTimeout(showTimerId);
      showTimerId = null;
    }
  }

  function cancelCloseTimer() {
    if (closeTimerId !== null) {
      clearTimeout(closeTimerId);
      closeTimerId = null;
    }
  }

  function cancelResolution() {
    currentRequestId++;
    safeSendMessage({
      type: 'CANCEL_RESOLUTION',
      requestId: currentRequestId - 1
    });
  }

  function forceClose() {
    cancelShowTimer();
    cancelCloseTimer();
    if (BTL.previewUI) BTL.previewUI.hide();
    currentLink = null;
    cancelResolution();
  }

  function scheduleClose() {
    if (closeTimerId) return; // already closing
    cancelShowTimer();
    
    closeTimerId = setTimeout(function() {
      closeTimerId = null;
      if (BTL.previewUI) BTL.previewUI.hide();
      currentLink = null;
      cancelResolution();
    }, 200); // Grace period
  }

  function handleClick(event) {
    // If the click is inside the preview card (e.g. details dropdown), don't navigate!
    if (isCard(event.target)) {
      // The browser natively handles <details> toggle. We just don't want to navigate or close.
      return;
    }

    var link = event.target.closest('a[href]');
    if (!link) return;

    safeSendMessage({
      type: 'LINK_CLICK_INTENT',
      url: BTL.getResolvedUrl(link),
      target: link.getAttribute('target') || '_self',
      timestamp: Date.now()
    });
  }

  // Expose on the shared namespace
  BTL.hoverManager = {
    handleMouseOver: handleMouseOver,
    handleMouseOut: handleMouseOut,
    handleClick: handleClick,
  };
})();
