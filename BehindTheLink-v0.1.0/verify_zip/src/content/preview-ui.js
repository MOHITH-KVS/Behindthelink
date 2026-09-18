/**
 * BehindTheLink — Preview UI
 *
 * Shadow DOM-based floating preview card mapping multi-layered evidence.
 */
(function () {
  'use strict';

  var BTL = window.BehindTheLink;
  var BTL_RUNTIME_MARKER = "Phase1H4-runtime-20260912-A";
  console.log('[BehindTheLink] Runtime renderer:', BTL_RUNTIME_MARKER);
  console.log('[BehindTheLink] Source file: src/content/preview-ui.js');

  var hostElement = null;
  var shadowRoot = null;
  var cardElement = null;
  var shouldBeVisible = false;
  var currentLinkElement = null;

  // ───────────────────────────────────────────────────
  //  Public API
  // ───────────────────────────────────────────────────

  function show(linkElement, analysisResult, isLoading, contextObj) {
    currentLinkElement = linkElement;
    ensureHost();
    
    var url = BTL.getResolvedUrl(linkElement);
    var payload = {
      originalUrl: url,
      localSignals: analysisResult ? analysisResult.localSignals : {},
      riskSignals: analysisResult ? analysisResult.riskSignals : { severity: 'NONE', signals: [] },
      networkEvidence: analysisResult ? analysisResult.networkEvidence : null,
      browserObservation: analysisResult ? analysisResult.browserObservation : null,
      safetyEvidence: analysisResult ? analysisResult.safetyEvidence : null,
      context: contextObj || null
    };

    render(payload, isLoading);
    positionCard(linkElement);

    shouldBeVisible = true;
    requestAnimationFrame(function () {
      if (shouldBeVisible && cardElement) {
        cardElement.classList.add('btl-visible');
      }
    });
  }

  function hide() {
    shouldBeVisible = false;
    if (cardElement) {
      cardElement.classList.remove('btl-visible');
    }
  }

  var lastPayload = null;

  function updateNetworkResult(payload) {
    if (!cardElement || !shouldBeVisible || !currentLinkElement) return;
    lastPayload = payload;
    render(payload, false);
    positionCard(currentLinkElement);
  }

  function setReputationLoading() {
    if (!lastPayload || !cardElement || !shouldBeVisible) return;
    if (lastPayload.safetyEvidence) {
      lastPayload.safetyEvidence.reputationStatus = 'REPUTATION_PENDING';
    }
    render(lastPayload, false);
    positionCard(currentLinkElement);
  }

  function updateReputationResult(repResponse) {
    if (!lastPayload || !cardElement || !shouldBeVisible) return;
    if (repResponse && repResponse.safetyEvidence) {
      lastPayload.safetyEvidence = repResponse.safetyEvidence;
    }
    render(lastPayload, false);
    positionCard(currentLinkElement);
  }

  // ───────────────────────────────────────────────────
  //  Internals
  // ───────────────────────────────────────────────────

  function ensureHost() {
    if (hostElement) return;

    hostElement = document.createElement('div');
    hostElement.setAttribute('data-behindthelink', 'host');
    hostElement.style.cssText = 'position:fixed;top:0;left:0;z-index:2147483647;pointer-events:none;padding:0;margin:0;border:none;background:none;width:auto;height:auto;';

    shadowRoot = hostElement.attachShadow({ mode: 'closed' });

    var style = document.createElement('style');
    style.textContent = getStyles();
    shadowRoot.appendChild(style);

    cardElement = document.createElement('div');
    cardElement.className = 'btl-card';
    shadowRoot.appendChild(cardElement);

    (document.body || document.documentElement).appendChild(hostElement);
  }

  function formatTargetUrl(urlStr) {
    try {
      var u = new URL(urlStr);
      var pathname = u.pathname === '/' ? '' : u.pathname;
      var result = u.hostname + pathname;
      if (result.length > 40) {
        result = result.substring(0, 37) + '...';
      }
      return result;
    } catch(e) {
      return urlStr;
    }
  }

  function getHostname(urlStr) {
    try { return new URL(urlStr).hostname; } catch(e) { return urlStr; }
  }

  function hasSignal(signals, id) {
    for (var i = 0; i < signals.length; i++) {
      if (signals[i].id === id) return true;
    }
    return false;
  }

  function render(payload, isLoading) {
    cardElement.replaceChildren();

    var url = payload.originalUrl || '';
    var domain = getHostname(url);
    if (payload.localSignals && payload.localSignals.hostname) {
      domain = payload.localSignals.hostname;
    }

    var locals = payload.localSignals || {};
    var net = payload.networkEvidence || {};
    var obs = payload.browserObservation || {};
    var safety = payload.safetyEvidence || { status: 'NO_SIGNALS_DETECTED', signals: [], limitations: [], assessmentBasis: 'LOCAL_ONLY' };
    var signals = safety.signals || [];
    var hasEmbedded = locals.embeddedCandidates && locals.embeddedCandidates.length > 0;

    // 1. Header
    var header = document.createElement('div');
    header.className = 'btl-header';
    header.textContent = '🌐 ' + domain;
    cardElement.appendChild(header);

    // 2. Destination Block
    var destBlock = document.createElement('div');
    destBlock.className = 'btl-section';
    var destLabel = document.createElement('div');
    destLabel.className = 'btl-label';
    destLabel.textContent = 'DESTINATION';
    var destUrl = document.createElement('div');
    destUrl.className = 'btl-dest-url';
    var destEvidence = document.createElement('div');
    
    if (isLoading) {
      destUrl.textContent = 'Checking destination…';
      destUrl.style.color = '#6b7280';
      destEvidence.className = 'btl-evidence';
    } else if (net.status === 'HTTP_REDIRECT_OBSERVED' && net.redirectTarget) {
      destUrl.textContent = formatTargetUrl(net.redirectTarget);
      destEvidence.textContent = '✓ Redirect destination confirmed';
      destEvidence.className = 'btl-evidence btl-evidence-neutral';
    } else if (net.status === 'NO_REDIRECT_OBSERVED') {
      destUrl.textContent = domain;
      destEvidence.textContent = '✓ Destination verified';
      destEvidence.className = 'btl-evidence btl-evidence-neutral';
    } else if (obs.status === 'STRONG_CORRELATION' && obs.observedLatestUrl) {
      destUrl.textContent = formatTargetUrl(obs.observedLatestUrl);
      destEvidence.textContent = 'Previously observed destination';
      destEvidence.className = 'btl-evidence btl-evidence-neutral';
    } else if (hasEmbedded) {
      destUrl.textContent = formatTargetUrl(locals.embeddedCandidates[0]);
      destEvidence.textContent = 'Likely destination';
      destEvidence.className = 'btl-evidence btl-evidence-neutral';
    } else {
      destUrl.textContent = domain;
      destEvidence.textContent = 'Could not verify destination';
      destEvidence.className = 'btl-evidence btl-evidence-neutral';
    }
    
    destBlock.appendChild(destLabel);
    destBlock.appendChild(destUrl);
    if (!isLoading) {
      destBlock.appendChild(destEvidence);
    }
    cardElement.appendChild(destBlock);

    if (isLoading) {
      cardElement.style.pointerEvents = 'none';
      return;
    }

    cardElement.style.pointerEvents = 'auto';

    // 3. Safety
    var safetyBlock = document.createElement('div');
    safetyBlock.className = 'btl-section';
    var safetyLabel = document.createElement('div');
    safetyLabel.className = 'btl-label';
    safetyLabel.textContent = 'SAFETY';
    safetyBlock.appendChild(safetyLabel);
    
    if (safety.reputationStatus && safety.reputationStatus !== 'REPUTATION_NOT_ENABLED') {
      var repStatusEl = document.createElement('div');
      repStatusEl.className = 'btl-safety-status';
      var repIcon = document.createElement('span');
      var repText = document.createElement('span');
      
      switch (safety.reputationStatus) {
        case 'KNOWN_THREAT':
          repIcon.textContent = '🚨'; repIcon.style.color = '#dc2626';
          repText.textContent = 'Known threat reported'; repText.style.color = '#dc2626';
          break;
        case 'NO_KNOWN_THREAT':
          repIcon.textContent = '✓'; repIcon.style.color = '#10b981';
          repText.textContent = 'No known threat reported'; repText.style.color = '#6b7280';
          break;
        case 'REPUTATION_PENDING':
          repIcon.textContent = '⟳'; repIcon.style.color = '#6b7280';
          repText.textContent = 'Checking reputation…'; repText.style.color = '#6b7280';
          break;
        case 'REPUTATION_UNAVAILABLE':
        case 'NO_REPUTATION_VERDICT':
        default:
          repIcon.textContent = '—'; repIcon.style.color = '#9ca3af';
          repText.textContent = 'No safety verdict'; repText.style.color = '#9ca3af';
          break;
      }
      repStatusEl.appendChild(repIcon);
      repStatusEl.appendChild(repText);
      safetyBlock.appendChild(repStatusEl);
    }

    var localStatusEl = document.createElement('div');
    localStatusEl.className = 'btl-safety-status';
    
    var sIcon = document.createElement('span');
    var sText = document.createElement('span');
    
    var localStatus = safety.localStatus || safety.status;
    
    switch (localStatus) {
      case 'NO_SIGNALS_DETECTED':
        sIcon.textContent = '—'; sIcon.style.color = '#9ca3af';
        sText.textContent = 'No obvious warning signs were found in the link or surrounding context.'; sText.style.color = '#6b7280';
        break;
      case 'INFORMATIONAL':
        sIcon.textContent = 'ℹ'; sIcon.style.color = '#64748b';
        sText.textContent = 'Some things to know'; sText.style.color = '#64748b';
        break;
      case 'UNUSUAL_CHARACTERISTICS':
        sIcon.textContent = '⚠'; sIcon.style.color = '#d97706';
        sText.textContent = 'Some unusual characteristics'; sText.style.color = '#d97706';
        break;
      case 'STRONG_WARNING':
        sIcon.textContent = '🚨'; sIcon.style.color = '#dc2626';
        sText.textContent = 'Known threat reported'; sText.style.color = '#dc2626';
        break;
    }
    localStatusEl.appendChild(sIcon);
    localStatusEl.appendChild(sText);
    
    // Only append localStatus if we don't have a KNOWN_THREAT overriding everything, 
    // or if we want to show it alongside. The spec says:
    // "An unusual local result must not be overridden by a clean reputation result."
    // "KNOWN_THREAT always supersedes all other UI states"
    if (safety.reputationStatus !== 'KNOWN_THREAT') {
      safetyBlock.appendChild(localStatusEl);
    }

    var userGuidance = payload.safetyEvidence ? payload.safetyEvidence.userGuidance : null;
    
    if (userGuidance && userGuidance.displaySignals && userGuidance.displaySignals.length > 0) {
      var displayList = document.createElement('ul');
      displayList.className = 'btl-bullet-list';
      displayList.style.marginTop = '6px';
      displayList.style.color = '#4b5563';
      
      userGuidance.displaySignals.forEach(function(s) {
        var li = document.createElement('li');
        li.textContent = s.label;
        displayList.appendChild(li);
      });
      safetyBlock.appendChild(displayList);
    }
    
    cardElement.appendChild(safetyBlock);

    // 4. Why should I care?
    if (userGuidance && userGuidance.whyText) {
      var whyBlock = document.createElement('div');
      whyBlock.className = 'btl-section';
      var whyLabel = document.createElement('div');
      whyLabel.className = 'btl-label';
      whyLabel.textContent = 'WHY SHOULD I CARE?';
      whyBlock.appendChild(whyLabel);
      
      var whyText = document.createElement('div');
      whyText.className = 'btl-why-text';
      whyText.textContent = userGuidance.whyText;
      whyBlock.appendChild(whyText);
      cardElement.appendChild(whyBlock);
    }
    
    // 5. What should I do?
    if (userGuidance && userGuidance.actionText) {
      var actionBlock = document.createElement('div');
      actionBlock.className = 'btl-section';
      var actionLabel = document.createElement('div');
      actionLabel.className = 'btl-label';
      actionLabel.textContent = 'WHAT SHOULD I DO?';
      actionBlock.appendChild(actionLabel);
      
      var actionText = document.createElement('div');
      actionText.className = 'btl-why-text';
      actionText.textContent = userGuidance.actionText;
      actionBlock.appendChild(actionText);
      
      cardElement.appendChild(actionBlock);
    }

    // 6. Link Type
    var linkTypes = [];
    if (hasSignal(signals, 'REDIRECTS_THROUGH_SHORTENER')) linkTypes.push('Shortened link');
    
    var hasRedirect = hasSignal(signals, 'REDIRECTS_TO_DIFFERENT_DOMAIN') || (net.status === 'HTTP_REDIRECT_OBSERVED' && net.redirectTarget);
    if (hasRedirect) linkTypes.push('Redirecting link');
    
    if (hasSignal(signals, 'HAS_TRACKING_PARAMS')) linkTypes.push('Tracking link');
    if (hasSignal(signals, 'HAS_AFFILIATE')) linkTypes.push('Affiliate-style link');
    
    var typeText = linkTypes.length > 0 ? linkTypes.join(' · ') : 'Direct link';
    
    var typeBlock = document.createElement('div');
    typeBlock.className = 'btl-section';
    var typeLabel = document.createElement('div');
    typeLabel.className = 'btl-label';
    typeLabel.textContent = 'LINK TYPE';
    var typeVal = document.createElement('div');
    typeVal.className = 'btl-text-main';
    typeVal.textContent = typeText;
    typeBlock.appendChild(typeLabel);
    typeBlock.appendChild(typeVal);
    cardElement.appendChild(typeBlock);

    // 7. What we checked / More info (Progressive Disclosure)
    var checksWrapper = document.createElement('details');
    checksWrapper.className = 'btl-details';
    var checksSummary = document.createElement('summary');
    checksSummary.textContent = 'What we checked ▾';
    checksWrapper.appendChild(checksSummary);
    
    var checksContent = document.createElement('div');
    checksContent.className = 'btl-details-content';
    
    var cList = document.createElement('ul');
    cList.className = 'btl-bullet-list';
    cList.appendChild(createLi('Link text and surrounding context'));
    if (net.status === 'FAILED') {
      cList.appendChild(createLi('! Destination could not be verified'));
    } else {
      cList.appendChild(createLi('Destination'));
      cList.appendChild(createLi('Redirect behavior'));
    }
    cList.appendChild(createLi('URL characteristics'));
    checksContent.appendChild(cList);
    
    var limitsLabel = document.createElement('div');
    limitsLabel.className = 'btl-limits-label';
    limitsLabel.textContent = 'Limitations:';
    checksContent.appendChild(limitsLabel);
    
    var limList = document.createElement('ul');
    limList.className = 'btl-bullet-list';
    limList.appendChild(createLi('BehindTheLink checks the link and available redirect information before you click.'));
    limList.appendChild(createLi('Some websites prevent automated checks or use redirects that cannot be observed.'));
    limList.appendChild(createLi('Local checks cannot determine whether a website is completely safe.'));
    checksContent.appendChild(limList);
    
    checksWrapper.appendChild(checksContent);
    cardElement.appendChild(checksWrapper);

    // 8. More info
    var moreWrapper = document.createElement('details');
    moreWrapper.className = 'btl-details';
    moreWrapper.style.marginTop = '4px';
    moreWrapper.style.borderTop = 'none';
    var moreSummary = document.createElement('summary');
    moreSummary.textContent = 'More info ▾';
    moreWrapper.appendChild(moreSummary);
    
    var moreContent = document.createElement('div');
    moreContent.className = 'btl-details-content';
    moreContent.appendChild(createDetailRow('Original URL', payload.originalUrl));
    if (net.status === 'HTTP_REDIRECT_OBSERVED' && net.redirectTarget) {
      moreContent.appendChild(createDetailRow('Redirect Target', net.redirectTarget));
    }
    if (obs.status === 'STRONG_CORRELATION' && obs.observedLatestUrl) {
      moreContent.appendChild(createDetailRow('Observed URL', obs.observedLatestUrl));
    }
    moreWrapper.appendChild(moreContent);
    cardElement.appendChild(moreWrapper);
  }
  
  function createLi(text) {
    var li = document.createElement('li');
    li.textContent = text;
    return li;
  }

  function createDetailRow(label, value) {
    var row = document.createElement('div');
    row.className = 'btl-detail-row';
    var l = document.createElement('div');
    l.className = 'btl-detail-label';
    l.textContent = label;
    var v = document.createElement('div');
    v.className = 'btl-detail-value';
    v.textContent = value;
    row.appendChild(l);
    row.appendChild(v);
    return row;
  }

  function positionCard(linkElement) {
    var linkRect = linkElement.getBoundingClientRect();
    var cardW = cardElement.offsetWidth || BTL.CARD_WIDTH || 320;
    // Important: We must use offsetHeight to get the true rendered height
    var cardH = cardElement.offsetHeight || 300;
    
    var gap = BTL.CARD_GAP || 8;
    var pad = BTL.VIEWPORT_PADDING || 12; // Adjusted to a safe 12px
    var vw = window.innerWidth;
    var vh = window.innerHeight;

    var spaceBelow = vh - linkRect.bottom;
    var spaceAbove = linkRect.top;

    var top;
    // 1. If there is enough space below, put it below
    if (spaceBelow >= cardH + gap + pad) {
      top = linkRect.bottom + gap;
    } 
    // 2. If not enough space below, but enough space above, put it above
    else if (spaceAbove >= cardH + gap + pad) {
      top = linkRect.top - gap - cardH;
    } 
    // 3. Neither has enough space. Choose the side with more space
    else {
      if (spaceBelow >= spaceAbove) {
        top = linkRect.bottom + gap;
      } else {
        top = linkRect.top - gap - cardH;
      }
    }

    // Clamp top to viewport bounds
    top = Math.max(pad, Math.min(top, vh - pad - cardH));

    // Handle horizontal bounds
    var left = linkRect.left;
    left = Math.max(pad, Math.min(left, vw - pad - cardW));

    hostElement.style.top = Math.round(top) + 'px';
    hostElement.style.left = Math.round(left) + 'px';
  }

  function getStyles() {
    var w = BTL.CARD_WIDTH || 320;
    var dur = BTL.ANIMATION_DURATION || 150;

    return (
      ':host{all:initial;}' +
      '.btl-card{width:' + w + 'px;max-height:min(480px, 70vh);overflow-y:auto;background:#ffffff;border:1px solid rgba(0,0,0,0.08);border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08),0 8px 24px rgba(0,0,0,0.06);padding:16px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:13px;line-height:1.4;color:#1f2937;box-sizing:border-box;opacity:0;transform:translateY(4px);transition:opacity ' + dur + 'ms ease-out,transform ' + dur + 'ms ease-out;}' +
      '.btl-card::-webkit-scrollbar{width:6px;}' +
      '.btl-card::-webkit-scrollbar-track{background:transparent;}' +
      '.btl-card::-webkit-scrollbar-thumb{background:rgba(0,0,0,0.15);border-radius:4px;}' +
      '.btl-card.btl-visible{opacity:1;transform:translateY(0);}' +
      '.btl-header{display:flex;align-items:center;gap:6px;font-size:14px;font-weight:600;color:#111827;margin-bottom:12px;overflow-wrap:break-word;word-break:break-all;}' +
      '.btl-section{margin-bottom:12px;}' +
      '.btl-label{font-size:10px;font-weight:700;color:#6b7280;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:4px;}' +
      '.btl-dest-url{font-size:14px;font-weight:500;color:#111827;margin-bottom:4px;word-break:break-all;}' +
      '.btl-text-main{font-size:13px;color:#111827;font-weight:500;}' +
      '.btl-evidence{font-size:12px;margin-bottom:2px;}' +
      '.btl-evidence-success{color:#10b981;font-weight:500;}' +
      '.btl-evidence-warning{color:#d97706;font-weight:500;}' +
      '.btl-evidence-neutral{color:#6b7280;font-weight:500;}' +
      '.btl-callout{margin-bottom:8px;padding:8px;background:#f9fafb;border-radius:6px;border-left:3px solid transparent;}' +
      '.btl-callout-title{font-size:12px;font-weight:600;margin-bottom:2px;}' +
      '.btl-callout-desc{font-size:12px;color:#4b5563;}' +
      '.btl-safety-status{font-size:14px;font-weight:500;margin-bottom:4px;display:flex;align-items:center;gap:6px;}' +
      '.btl-bullet-list{margin:4px 0 0 0;padding-left:16px;font-size:12px;color:#4b5563;}' +
      '.btl-bullet-list li{margin-bottom:4px;}' +
      '.btl-limits-label{margin-top:8px;font-weight:600;font-size:12px;color:#4b5563;}' +
      '.btl-details{margin-top:12px;border-top:1px solid #f3f4f6;padding-top:8px;}' +
      'summary{font-size:12px;font-weight:500;color:#6b7280;cursor:pointer;user-select:none;}' +
      '.btl-details-content{margin-top:8px;font-size:11px;color:#4b5563;}' +
      '.btl-detail-row{margin-bottom:6px;}' +
      '.btl-detail-label{font-weight:600;color:#9ca3af;}' +
      '.btl-detail-value{word-break:break-all;}'
    );
  }

  // Expose on the shared namespace
  BTL.previewUI = { 
    show: show, 
    hide: hide, 
    updateNetworkResult: updateNetworkResult,
    setReputationLoading: setReputationLoading,
    updateReputationResult: updateReputationResult,
    getHost: function() { return hostElement; }
  };
})();
