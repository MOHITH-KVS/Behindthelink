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

  // ───────────────────────────────────────────────────
  //  Public API
  // ───────────────────────────────────────────────────

  function show(linkElement, analysisResult, isLoading, contextObj) {
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

  function updateNetworkResult(payload) {
    if (!cardElement || !shouldBeVisible) return;
    render(payload, false);
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
    var destUrl = document.createElement('div');
    destUrl.className = 'btl-dest-url';
    var destEvidence = document.createElement('div');
    
    if (isLoading) {
      destLabel.textContent = 'WHERE IT GOES';
      destUrl.textContent = 'Checking destination…';
      destUrl.style.color = '#6b7280';
      destEvidence.className = 'btl-evidence';
    } else if (net.status === 'HTTP_REDIRECT_OBSERVED' && net.redirectTarget) {
      destLabel.textContent = 'OPENS';
      destUrl.textContent = formatTargetUrl(net.redirectTarget);
      destEvidence.textContent = '✓ HTTP verified';
      destEvidence.className = 'btl-evidence btl-evidence-success';
    } else if (net.status === 'NO_REDIRECT_OBSERVED') {
      destLabel.textContent = 'OPENS';
      destUrl.textContent = domain;
      destEvidence.textContent = '✓ HTTP verified';
      destEvidence.className = 'btl-evidence btl-evidence-success';
    } else if (obs.status === 'STRONG_CORRELATION' && obs.observedLatestUrl) {
      destLabel.textContent = 'OPENS';
      destUrl.textContent = formatTargetUrl(obs.observedLatestUrl);
      destEvidence.textContent = '✓ Previously observed';
      destEvidence.className = 'btl-evidence btl-evidence-success';
    } else if (hasEmbedded) {
      destLabel.textContent = 'WHERE IT GOES';
      destUrl.textContent = formatTargetUrl(locals.embeddedCandidates[0]);
      destEvidence.textContent = '⚠ Predicted/likely';
      destEvidence.className = 'btl-evidence btl-evidence-warning';
    } else {
      destLabel.textContent = 'WHERE IT GOES';
      destUrl.textContent = domain;
      destEvidence.textContent = '❌ Could not verify';
      destEvidence.className = 'btl-evidence btl-evidence-neutral';
    }
    
    destBlock.appendChild(destLabel);
    destBlock.appendChild(destUrl);
    destBlock.appendChild(destEvidence);
    cardElement.appendChild(destBlock);

    if (isLoading) {
      cardElement.style.pointerEvents = 'none';
      return;
    }

    cardElement.style.pointerEvents = 'auto';

    // 3. Link Type
    var linkTypes = [];
    if (hasSignal(signals, 'REDIRECTS_THROUGH_SHORTENER')) linkTypes.push('Shortened link');
    if (hasSignal(signals, 'REDIRECTS_TO_DIFFERENT_DOMAIN')) linkTypes.push('Redirecting link');
    if (hasSignal(signals, 'HAS_TRACKING_PARAMS')) linkTypes.push('Tracking link');
    if (hasSignal(signals, 'HAS_AFFILIATE')) linkTypes.push('Affiliate-style link');
    
    var typeText = linkTypes.length > 0 ? linkTypes.join(' + ') : 'Direct link';
    
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

    // 4. Specific Callouts
    var callouts = [];
    if (!hasSignal(signals, 'HTTP_NOT_HTTPS')) {
      callouts.push({ icon: '✓', title: 'HTTPS', desc: 'The connection is encrypted. HTTPS does not by itself prove that the website is legitimate.', color: '#10b981' });
    }
    if (hasSignal(signals, 'SUSPICIOUS_FILE_EXT')) {
      callouts.push({ icon: '⚠', title: 'Executable download', desc: 'This link appears to point to an executable file. Only open it if you expected this download.', color: '#d97706' });
    }
    if (hasSignal(signals, 'USERINFO_IN_URL')) {
      callouts.push({ icon: '⚠', title: 'Embedded credentials', desc: 'This URL contains username/password information.', color: '#d97706' });
    }
    if (hasSignal(signals, 'SENSITIVE_ACTION_PATH') || hasSignal(signals, 'CONTEXT_LOGIN') || hasSignal(signals, 'CONTEXT_PAYMENT') || hasSignal(signals, 'CONTEXT_VERIFY') || hasSignal(signals, 'CONTEXT_PASSWORD') || hasSignal(signals, 'CONTEXT_ACCOUNT')) {
      callouts.push({ icon: 'ℹ', title: 'Sensitive action', desc: 'This destination appears to involve login, verification, payment, or another sensitive action.', color: '#3b82f6' });
    }

    callouts.forEach(function(c) {
      var cb = document.createElement('div');
      cb.className = 'btl-callout';
      
      var cTitle = document.createElement('div');
      cTitle.className = 'btl-callout-title';
      cTitle.style.color = c.color;
      var cIcon = document.createElement('span');
      cIcon.textContent = c.icon + ' ';
      cTitle.appendChild(cIcon);
      cTitle.appendChild(document.createTextNode(c.title));
      
      var cDesc = document.createElement('div');
      cDesc.className = 'btl-callout-desc';
      cDesc.textContent = c.desc;
      
      cb.appendChild(cTitle);
      cb.appendChild(cDesc);
      cardElement.appendChild(cb);
    });

    // 5. Safety
    var safetyBlock = document.createElement('div');
    safetyBlock.className = 'btl-section';
    var safetyLabel = document.createElement('div');
    safetyLabel.className = 'btl-label';
    safetyLabel.textContent = 'SAFETY';
    safetyBlock.appendChild(safetyLabel);
    
    var statusEl = document.createElement('div');
    statusEl.className = 'btl-safety-status';
    
    var sIcon = document.createElement('span');
    var sText = document.createElement('span');
    
    var mismatchSignal = null;
    for (var k = 0; k < signals.length; k++) {
      if (signals[k].id === 'CLAIM_DESTINATION_MISMATCH') {
        mismatchSignal = signals[k];
        break;
      }
    }

    if (mismatchSignal) {
      sIcon.textContent = '⚠'; sIcon.style.color = '#d97706';
      sText.textContent = mismatchSignal.label; sText.style.color = '#d97706';
      
      statusEl.appendChild(sIcon);
      statusEl.appendChild(sText);
      safetyBlock.appendChild(statusEl);

      var mismatchDesc = document.createElement('div');
      mismatchDesc.className = 'btl-mismatch-desc';
      mismatchDesc.style.marginTop = '6px';
      mismatchDesc.style.fontSize = '12px';
      mismatchDesc.style.color = '#4b5563';
      mismatchDesc.textContent = mismatchSignal.detail;
      safetyBlock.appendChild(mismatchDesc);
    } else {
      switch (safety.status) {
        case 'NO_SIGNALS_DETECTED':
          sIcon.textContent = '✓'; sIcon.style.color = '#10b981';
          sText.textContent = 'Nothing unusual found'; sText.style.color = '#6b7280';
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
      statusEl.appendChild(sIcon);
      statusEl.appendChild(sText);
      safetyBlock.appendChild(statusEl);
    }
    
    cardElement.appendChild(safetyBlock);

    // 6. Why should I care?
    if (signals.length > 0) {
      var whyBlock = document.createElement('div');
      whyBlock.className = 'btl-section';
      var whyLabel = document.createElement('div');
      whyLabel.className = 'btl-label';
      whyLabel.textContent = 'WHY SHOULD I CARE?';
      whyBlock.appendChild(whyLabel);
      
      var whyText = document.createElement('div');
      whyText.className = 'btl-why-text';
      
      var reasons = [];
      if (hasSignal(signals, 'REDIRECTS_THROUGH_SHORTENER')) {
        reasons.push("The final destination is hidden behind a URL-shortening service.");
      }
      if (hasSignal(signals, 'HAS_TRACKING_PARAMS')) {
        reasons.push("Parameters in the URL are commonly used for campaign/attribution tracking.");
      }
      var hasStructural = false;
      for (var j = 0; j < signals.length; j++) {
        if (signals[j].tier === 'B' && signals[j].id !== 'HTTP_NOT_HTTPS' && signals[j].id !== 'SUSPICIOUS_FILE_EXT') {
          hasStructural = true;
          break;
        }
      }
      if (hasStructural) {
        reasons.push("The URL contains unusual characteristics. This does not prove it is malicious.");
      }
      
      if (hasSignal(signals, 'CLAIM_DESTINATION_MISMATCH')) {
        reasons.push("The text of a link can describe one service while the link leads somewhere else.");
      }
      
      if (reasons.length === 0 && signals.length > 0) {
        reasons.push(signals[0].detail); // Fallback to raw human-readable signal detail
      }
      
      var ul = document.createElement('ul');
      ul.className = 'btl-bullet-list';
      reasons.forEach(function(r) {
        var li = document.createElement('li');
        li.textContent = r;
        ul.appendChild(li);
      });
      whyBlock.appendChild(ul);
      cardElement.appendChild(whyBlock);
    }
    
    // 6b. What should I do?
    if (hasSignal(signals, 'CLAIM_DESTINATION_MISMATCH')) {
      var actionBlock = document.createElement('div');
      actionBlock.className = 'btl-section';
      var actionLabel = document.createElement('div');
      actionLabel.className = 'btl-label';
      actionLabel.textContent = 'WHAT SHOULD I DO?';
      actionBlock.appendChild(actionLabel);
      
      var actionText = document.createElement('div');
      actionText.className = 'btl-why-text';
      actionText.textContent = "Check the destination domain before entering information.";
      actionBlock.appendChild(actionText);
      
      cardElement.appendChild(actionBlock);
    }

    // 7. What we checked
    var checksWrapper = document.createElement('details');
    checksWrapper.className = 'btl-details';
    var checksSummary = document.createElement('summary');
    checksSummary.textContent = 'What we checked ▾';
    checksWrapper.appendChild(checksSummary);
    
    var checksContent = document.createElement('div');
    checksContent.className = 'btl-details-content';
    
    var cList = document.createElement('ul');
    cList.className = 'btl-bullet-list';
    cList.appendChild(createLi('Link text'));
    cList.appendChild(createLi('Link context'));
    cList.appendChild(createLi('URL structure'));
    cList.appendChild(createLi('Tracking parameters'));
    if (net.status !== 'FAILED') {
      cList.appendChild(createLi('Redirect behavior'));
      cList.appendChild(createLi('Destination'));
    }
    if (obs.status !== 'NONE') {
      cList.appendChild(createLi('Browser navigation'));
    }
    checksContent.appendChild(cList);
    
    var limitsLabel = document.createElement('div');
    limitsLabel.className = 'btl-limits-label';
    limitsLabel.textContent = 'Limitations:';
    checksContent.appendChild(limitsLabel);
    
    var limList = document.createElement('ul');
    limList.className = 'btl-bullet-list';
    limList.appendChild(createLi('We do not guarantee that a website is safe.'));
    limList.appendChild(createLi('We do not determine whether a page contains malware.'));
    limList.appendChild(createLi('We do not currently use an external reputation database.'));
    checksContent.appendChild(limList);
    
    checksWrapper.appendChild(checksContent);
    cardElement.appendChild(checksWrapper);

    // 8. More info
    var moreWrapper = document.createElement('details');
    moreWrapper.className = 'btl-details';
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
    var cardH = cardElement.offsetHeight || 300;
    var gap = BTL.CARD_GAP || 8;
    var pad = BTL.VIEWPORT_PADDING || 16;
    var vw = window.innerWidth;
    var vh = window.innerHeight;

    var top = linkRect.bottom + gap;
    if (top + cardH > vh - pad) top = linkRect.top - gap - cardH;
    if (top < pad) top = pad;

    var left = linkRect.left;
    if (left + cardW > vw - pad) left = vw - pad - cardW;
    if (left < pad) left = pad;

    hostElement.style.top = Math.round(top) + 'px';
    hostElement.style.left = Math.round(left) + 'px';
  }

  function getStyles() {
    var w = BTL.CARD_WIDTH || 320;
    var dur = BTL.ANIMATION_DURATION || 150;

    return (
      ':host{all:initial;}' +
      '.btl-card{width:' + w + 'px;background:#ffffff;border:1px solid rgba(0,0,0,0.08);border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08),0 8px 24px rgba(0,0,0,0.06);padding:16px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:13px;line-height:1.4;color:#1f2937;box-sizing:border-box;opacity:0;transform:translateY(4px);transition:opacity ' + dur + 'ms ease-out,transform ' + dur + 'ms ease-out;}' +
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
    getHost: function() { return hostElement; }
  };
})();
