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
  var isClosing = false;
  var shouldBeVisible = false;

  // ───────────────────────────────────────────────────
  //  Public API
  // ───────────────────────────────────────────────────

  function show(linkElement, analysisResult, isLoading) {
    ensureHost();
    
    // Create a temporary mock payload for loading state
    var url = BTL.getResolvedUrl(linkElement);
    var payload = {
      originalUrl: url,
      localSignals: analysisResult ? analysisResult.localSignals : {},
      riskSignals: analysisResult ? analysisResult.riskSignals : { severity: 'NONE', signals: [] },
      networkEvidence: null,
      browserObservation: null
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

  function render(payload, isLoading) {
    cardElement.replaceChildren();

    var url = payload.originalUrl || '';
    var domain = '';
    try { domain = new URL(url).hostname; } catch(e) { domain = url; }
    if (payload.localSignals && payload.localSignals.hostname) {
      domain = payload.localSignals.hostname;
    }

    // ── Source Domain Header ──
    var header = document.createElement('div');
    header.className = 'btl-header';
    var icon = document.createElement('span');
    icon.className = 'btl-header-icon';
    icon.textContent = '🌐';
    header.appendChild(icon);
    var title = document.createElement('span');
    title.textContent = domain;
    header.appendChild(title);
    cardElement.appendChild(header);

    // ── Destination Block ──
    var destBlock = document.createElement('div');
    destBlock.className = 'btl-section';
    
    var destLabel = document.createElement('div');
    destLabel.className = 'btl-label';
    destBlock.appendChild(destLabel);
    
    var destUrl = document.createElement('div');
    destUrl.className = 'btl-dest-url';
    destBlock.appendChild(destUrl);
    
    var destEvidence = document.createElement('div');
    destEvidence.className = 'btl-evidence';
    destBlock.appendChild(destEvidence);

    var locals = payload.localSignals || {};
    var net = payload.networkEvidence || {};
    var obs = payload.browserObservation || {};
    var hasEmbedded = locals.embeddedCandidates && locals.embeddedCandidates.length > 0;

    if (isLoading) {
      destLabel.textContent = 'WHERE IT GOES';
      destUrl.textContent = 'Checking destination…';
      destUrl.style.color = '#6b7280';
    } else if (net.status === 'HTTP_REDIRECT_OBSERVED' && net.redirectTarget) {
      destLabel.textContent = 'OPENS';
      destUrl.textContent = formatTargetUrl(net.redirectTarget);
      destEvidence.textContent = '✓ Destination checked';
      destEvidence.className = 'btl-evidence btl-evidence-success';
    } else if (net.status === 'NO_REDIRECT_OBSERVED') {
      destLabel.textContent = 'OPENS';
      destUrl.textContent = domain;
      destEvidence.textContent = '✓ Destination checked';
      destEvidence.className = 'btl-evidence btl-evidence-success';
    } else if (obs.status === 'STRONG_CORRELATION' && obs.observedLatestUrl) {
      destLabel.textContent = 'OPENS';
      destUrl.textContent = formatTargetUrl(obs.observedLatestUrl);
      destEvidence.textContent = '✓ Previously observed';
      destEvidence.className = 'btl-evidence btl-evidence-success';
    } else if (hasEmbedded) {
      destLabel.textContent = 'THIS LINK CONTAINS ANOTHER LINK';
      destLabel.className = 'btl-label btl-label-warning';
      destUrl.textContent = formatTargetUrl(locals.embeddedCandidates[0]);
      destEvidence.textContent = "We found another link inside this URL, but couldn't confirm that you'll be sent there.";
    } else { // FAILED or anything else
      destLabel.textContent = 'WHERE IT GOES';
      destUrl.textContent = "Destination couldn't be verified";
      destUrl.style.color = '#6b7280';
      destEvidence.textContent = "We couldn't verify where this link leads.";
    }

    cardElement.appendChild(destBlock);

    // ── Signals Block ──
    var signalsBlock = document.createElement('div');
    signalsBlock.className = 'btl-section';
    var hasSignals = false;

    var sigLabel = document.createElement('div');
    sigLabel.className = 'btl-label';
    sigLabel.textContent = 'LINK SIGNALS';
    signalsBlock.appendChild(sigLabel);

    if (locals.isShortener) {
      signalsBlock.appendChild(createSignalItem('• Shortened link'));
      hasSignals = true;
    }
    if (locals.trackingParams && locals.trackingParams.length > 0) {
      signalsBlock.appendChild(createSignalItem('• Contains tracking information'));
      hasSignals = true;
    }
    if (locals.hasAffiliate) {
      signalsBlock.appendChild(createSignalItem('• Affiliate link detected'));
      hasSignals = true;
    }

    if (hasSignals) {
      cardElement.appendChild(signalsBlock);
    }

    // ── Security Block ──
    var risk = payload.riskSignals || { severity: 'NONE', signals: [] };
    if (risk.severity !== 'NONE') {
      var securityBlock = document.createElement('div');
      securityBlock.className = 'btl-section';

      var secLabel = document.createElement('div');
      secLabel.className = 'btl-label btl-label-warning';
      secLabel.textContent = 'SECURITY';
      securityBlock.appendChild(secLabel);

      if (risk.severity === 'MEDIUM') {
        var warningEl = document.createElement('div');
        warningEl.textContent = '⚠ This link has a few unusual characteristics';
        warningEl.style.fontWeight = 'bold';
        warningEl.style.color = '#b91c1c'; // Tailwind red-700
        warningEl.style.marginBottom = '4px';
        warningEl.style.fontSize = '12px';
        securityBlock.appendChild(warningEl);
      }

      risk.signals.forEach(function(sig) {
        securityBlock.appendChild(createSignalItem('• ' + sig.label));
      });

      cardElement.appendChild(securityBlock);
    }

    // ── Details Block ──
    if (!isLoading) {
      var detailsWrapper = document.createElement('details');
      detailsWrapper.className = 'btl-details';
      detailsWrapper.style.pointerEvents = 'auto'; 
      
      var summary = document.createElement('summary');
      summary.textContent = 'More info ▾';
      detailsWrapper.appendChild(summary);
      
      var detailsContent = document.createElement('div');
      detailsContent.className = 'btl-details-content';
      
      detailsContent.appendChild(createDetailRow('Original URL', payload.originalUrl));
      if (net.status === 'HTTP_REDIRECT_OBSERVED') detailsContent.appendChild(createDetailRow('Redirect Target', net.redirectTarget));
      if (obs.status === 'STRONG_CORRELATION') {
        detailsContent.appendChild(createDetailRow('Observed URL', obs.observedLatestUrl));
        detailsContent.appendChild(createDetailRow('Observed At', new Date(obs.observedAt).toLocaleString()));
      }
      if (hasEmbedded) {
        detailsContent.appendChild(createDetailRow('Embedded Candidate', locals.embeddedCandidates[0]));
      }
      
      detailsWrapper.appendChild(detailsContent);
      cardElement.appendChild(detailsWrapper);
      
      cardElement.style.pointerEvents = 'auto';
    } else {
      cardElement.style.pointerEvents = 'none';
    }
  }

  function createSignalItem(text) {
    var el = document.createElement('div');
    el.className = 'btl-signal-item';
    el.textContent = text;
    return el;
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

  function humanizeTime(timestamp) {
    if (!timestamp) return '';
    var diff = Date.now() - timestamp;
    if (diff < 60000) return 'just now';
    var mins = Math.floor(diff / 60000);
    if (mins < 60) return mins === 1 ? '1 minute ago' : mins + ' minutes ago';
    var hours = Math.floor(mins / 60);
    if (hours < 24) return hours === 1 ? '1 hour ago' : hours + ' hours ago';
    var days = Math.floor(hours / 24);
    if (days === 1) return 'yesterday';
    return days + ' days ago';
  }

  function positionCard(linkElement) {
    var linkRect = linkElement.getBoundingClientRect();
    var cardW = cardElement.offsetWidth || BTL.CARD_WIDTH;
    var cardH = cardElement.offsetHeight || 120;
    var gap = BTL.CARD_GAP;
    var pad = BTL.VIEWPORT_PADDING;
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
    var w = BTL.CARD_WIDTH;
    var dur = BTL.ANIMATION_DURATION;

    return (
      ':host{all:initial;}' +

      '.btl-card{' +
        'width:' + w + 'px;' +
        'background:#ffffff;' +
        'border:1px solid rgba(0,0,0,0.08);' +
        'border-radius:12px;' +
        'box-shadow:0 4px 12px rgba(0,0,0,0.08), 0 8px 24px rgba(0,0,0,0.06);' +
        'padding:16px;' +
        'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;' +
        'font-size:13px;' +
        'line-height:1.4;' +
        'color:#1f2937;' +
        'box-sizing:border-box;' +
        'opacity:0;' +
        'transform:translateY(4px);' +
        'transition:opacity ' + dur + 'ms ease-out,transform ' + dur + 'ms ease-out;' +
      '}' +

      '.btl-card.btl-visible{' +
        'opacity:1;' +
        'transform:translateY(0);' +
      '}' +

      '.btl-header{' +
        'display:flex;' +
        'align-items:center;' +
        'gap:6px;' +
        'font-size:14px;' +
        'font-weight:600;' +
        'color:#111827;' +
        'margin-bottom:12px;' +
        'overflow-wrap:break-word;' +
        'word-break:break-all;' +
      '}' +

      '.btl-section{' +
        'margin-bottom:12px;' +
      '}' +

      '.btl-label{' +
        'font-size:10px;' +
        'font-weight:700;' +
        'color:#6b7280;' +
        'letter-spacing:0.5px;' +
        'text-transform:uppercase;' +
        'margin-bottom:4px;' +
      '}' +

      '.btl-label-warning{' +
        'color:#d97706;' +
      '}' +

      '.btl-dest-url{' +
        'font-size:14px;' +
        'font-weight:500;' +
        'color:#111827;' +
        'margin-bottom:4px;' +
        'word-break:break-all;' +
      '}' +

      '.btl-evidence{' +
        'font-size:12px;' +
        'color:#6b7280;' +
        'margin-bottom:2px;' +
      '}' +

      '.btl-evidence-success{' +
        'color:#10b981;' +
        'font-weight:500;' +
      '}' +

      '.btl-evidence-browser{' +
        'color:#6366f1;' +
        'font-weight:500;' +
      '}' +

      '.btl-evidence-structural{' +
        'color:#6b7280;' +
        'margin-top:4px;' +
      '}' +
      
      '.btl-evidence-browser-sub{' +
        'margin-top:2px;' +
      '}' +

      '.btl-signal-item{' +
        'font-size:12px;' +
        'color:#d97706;' +
        'margin-bottom:2px;' +
      '}' +

      '.btl-details{' +
        'margin-top:12px;' +
        'border-top:1px solid #f3f4f6;' +
        'padding-top:8px;' +
      '}' +

      'summary{' +
        'font-size:11px;' +
        'color:#6b7280;' +
        'cursor:pointer;' +
        'user-select:none;' +
      '}' +

      '.btl-details-content{' +
        'margin-top:8px;' +
        'font-size:11px;' +
        'color:#4b5563;' +
      '}' +

      '.btl-detail-row{' +
        'margin-bottom:6px;' +
      '}' +

      '.btl-detail-label{' +
        'font-weight:600;' +
        'color:#9ca3af;' +
      '}' +

      '.btl-detail-value{' +
        'word-break:break-all;' +
      '}'
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
