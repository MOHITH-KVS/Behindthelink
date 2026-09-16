/**
 * BehindTheLink — Safety Analyzer
 *
 * Implements the Phase 2B Core Safety Model.
 * Computes safetyEvidence from local signals, network evidence, and browser observation.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink || {};
  if (typeof window !== 'undefined') window.BehindTheLink = BTL;
  if (typeof self !== 'undefined') self.BehindTheLink = BTL;

  var STRUCTURAL_SIGNAL_TYPES = [
    'IP_HOST', 'IP_HOST_V4', 'IP_HOST_V6',
    'PUNYCODE_DOMAIN',
    'USERINFO_IN_URL',
    'DEEP_SUBDOMAIN',
    'UNUSUAL_PORT',
    'HTTP_NOT_HTTPS',
    'HEAVY_ENCODING',
    'SUSPICIOUS_FILE_EXT'
  ];

  var DIMENSION_MAP = {
    'IP_HOST':           'hostname_identity',
    'IP_HOST_V4':        'hostname_identity',
    'IP_HOST_V6':        'hostname_identity',
    'PUNYCODE_DOMAIN':   'hostname_identity',
    'USERINFO_IN_URL':   'url_authority',
    'DEEP_SUBDOMAIN':    'hostname_depth',
    'UNUSUAL_PORT':      'connection',
    'HTTP_NOT_HTTPS':    'connection',
    'HEAVY_ENCODING':    'encoding',
    'SUSPICIOUS_FILE_EXT': 'path_content'
  };

  function getLabel(signalType, urlContext) {
    var isTarget = urlContext === 'network_target_url';
    switch (signalType) {
      case 'IP_HOST':
      case 'IP_HOST_V4':
        return isTarget ? 'Destination uses an IP address' : 'Uses an IP address';
      case 'IP_HOST_V6':
        return isTarget ? 'Destination uses an IPv6 address' : 'Uses an IPv6 address';
      case 'PUNYCODE_DOMAIN':
        return isTarget ? 'Destination domain uses an encoded form' : 'Domain uses an encoded form';
      case 'USERINFO_IN_URL':
        return isTarget ? 'Destination URL contains an unusual format' : 'Contains an unusual URL format (user info)';
      case 'UNUSUAL_PORT':
        return isTarget ? 'Destination uses a non-standard port' : 'Uses a non-standard port';
      case 'HTTP_NOT_HTTPS':
        return isTarget ? 'Destination uses an unencrypted connection' : 'Unencrypted connection (HTTP)';
      case 'HEAVY_ENCODING':
        return isTarget ? 'Destination URL contains heavily encoded text' : 'Contains heavily encoded text';
      case 'DEEP_SUBDOMAIN':
        return isTarget ? 'Destination uses a deeply nested domain' : 'Uses a deeply nested domain';
      case 'SUSPICIOUS_FILE_EXT':
        return isTarget ? 'Destination appears to be a file download' : 'Link appears to lead to a file download';
      case 'REDIRECTS_TO_DIFFERENT_DOMAIN':
        return 'Redirects to a different website';
      case 'REDIRECTS_THROUGH_SHORTENER':
        return 'Shortened link';
      case 'HAS_TRACKING_PARAMS':
        return 'Contains tracking parameters';
      case 'HAS_AFFILIATE':
        return 'Contains affiliate/referral parameter';
      case 'SENSITIVE_ACTION_PATH':
      case 'CONTEXT_LOGIN':
        return 'URL appears related to login';
      case 'CONTEXT_PAYMENT':
        return 'URL appears related to payment';
      case 'CONTEXT_VERIFY':
        return 'URL appears related to verification';
      case 'CONTEXT_PASSWORD':
        return 'URL appears related to password reset';
      case 'CONTEXT_ACCOUNT':
        return 'URL appears related to account';
      case 'PREDICTED_ARCHIVE_DOWNLOAD':
        return isTarget ? 'Destination appears to be an archive download' : 'Link appears to lead to an archive download';
      case 'PREDICTED_DOCUMENT_DOWNLOAD':
        return isTarget ? 'Destination appears to be a document download' : 'Link appears to lead to a document download';
      default:
        return 'Unusual characteristic';
    }
  }

  function getDetail(signalType, urlContext, extra) {
    var isTarget = urlContext === 'network_target_url';
    switch (signalType) {
      case 'IP_HOST':
      case 'IP_HOST_V4':
        return isTarget ? 'The verified destination uses an IP address instead of a domain name.' : 'Uses an IP address instead of a domain name.';
      case 'IP_HOST_V6':
        return isTarget ? 'The verified destination uses an IPv6 address instead of a domain name.' : 'Uses an IPv6 address instead of a domain name.';
      case 'PUNYCODE_DOMAIN':
        return isTarget ? 'The verified destination domain uses an encoded form (xn-- prefix).' : 'Domain uses an encoded form (xn-- prefix — international domain encoding).';
      case 'USERINFO_IN_URL':
        return isTarget ? 'The verified destination URL includes user information before the domain name.' : 'Includes user information before the domain name.';
      case 'UNUSUAL_PORT':
        return isTarget ? 'The verified destination uses a non-standard port.' : 'Uses a non-standard port — most websites use port 80 or 443.';
      case 'HTTP_NOT_HTTPS':
        return isTarget ? 'The verified destination uses an unencrypted HTTP connection.' : 'Unencrypted connection (HTTP) — this connection does not use HTTPS encryption.';
      case 'HEAVY_ENCODING':
        return isTarget ? 'The verified destination URL contains heavily encoded text.' : 'Parts of this URL are encoded and harder to read.';
      case 'DEEP_SUBDOMAIN':
        return isTarget ? 'The verified destination uses a deeply nested domain.' : 'The address contains several levels of subdomains.';
      case 'SUSPICIOUS_FILE_EXT':
        return isTarget ? 'The verified destination URL suggests a file download (extension: ' + (extra || '') + '). The file itself was not inspected.' : 'The URL path suggests a file download (extension: ' + (extra || '') + '). This is a prediction — the file was not inspected.';
      case 'REDIRECTS_TO_DIFFERENT_DOMAIN':
        return 'This link redirects to ' + (extra || '') + ', which has a different domain than the original link.';
      case 'REDIRECTS_THROUGH_SHORTENER':
        return 'The link uses a URL shortening service — the destination was hidden in the original link.';
      case 'HAS_TRACKING_PARAMS':
        return 'The link contains recognized tracking query parameters' + (extra ? ' (' + extra + ')' : '') + '.';
      case 'HAS_AFFILIATE':
        return 'The link contains a recognized affiliate or referral parameter.';
      case 'SENSITIVE_ACTION_PATH':
      case 'CONTEXT_LOGIN':
      case 'CONTEXT_PAYMENT':
      case 'CONTEXT_VERIFY':
      case 'CONTEXT_PASSWORD':
      case 'CONTEXT_ACCOUNT':
        return 'This describes what the URL text suggests, not what the page contains.';
      case 'PREDICTED_ARCHIVE_DOWNLOAD':
      case 'PREDICTED_DOCUMENT_DOWNLOAD':
        return isTarget ? 'The verified destination URL suggests a download (extension: ' + (extra || '') + ').' : 'The URL path suggests a download (extension: ' + (extra || '') + ').';
      default:
        return 'An unusual characteristic was detected in the URL structure.';
    }
  }

  function getFileExtension(pathname) {
    if (!pathname) return '';
    var match = pathname.match(/\.([a-zA-Z0-9]+)$/);
    return match ? match[1].toLowerCase() : '';
  }

  function isExecutableExtension(ext) {
    return ['exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'dmg', 'pkg', 'apk', 'jar', 'scr', 'pif'].indexOf(ext) !== -1;
  }

  function isArchiveExtension(ext) {
    return ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'].indexOf(ext) !== -1;
  }

  function isDocumentExtension(ext) {
    return ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].indexOf(ext) !== -1;
  }

  function getHostname(urlStr) {
    try {
      return new URL(urlStr).hostname;
    } catch (e) {
      return '';
    }
  }

  // Basic e2LD comparison. Does not handle complex public suffixes perfectly but handles typical cases.
  function differentRegistrableDomain(url1, url2) {
    var host1 = getHostname(url1);
    var host2 = getHostname(url2);
    if (!host1 || !host2) return false;
    
    // Exact match
    if (host1 === host2) return false;

    // Simple e2LD extraction: get last two parts (e.g., 'example.com')
    // Exception for IPs (regex match)
    var ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegex.test(host1) || ipRegex.test(host2)) {
      return host1 !== host2;
    }
    
    var parts1 = host1.split('.');
    var parts2 = host2.split('.');
    
    // Very naive, fallback logic
    var e2ld1 = parts1.slice(-2).join('.');
    var e2ld2 = parts2.slice(-2).join('.');
    
    return e2ld1 !== e2ld2;
  }

  /**
   * Computes the final safetyEvidence object.
   */
  function computeSafetyEvidence(
    originalUrl,
    localSignals,
    riskSignals,
    targetRiskSignals,
    targetLocalSignals,
    networkEvidence,
    browserObservation,
    reputationSignals,
    contextObj
  ) {
    var tierA = [];
    var tierB = [];
    var tierC = []; // For mismatch, treat as tier C structurally
    var tierD = [];
    var limitations = [
      "Analysis based on URL structure — page content was not inspected",
      "Local heuristics cannot confirm safety or malicious intent"
    ];


    // --- STEP 1: Map ORIGINAL URL riskSignals to tiers ---
    if (riskSignals && riskSignals.signals) {
      riskSignals.signals.forEach(function (rawSignal) {
        if (STRUCTURAL_SIGNAL_TYPES.indexOf(rawSignal.type) !== -1) {
          tierB.push({
            id: rawSignal.type,
            tier: 'B',
            dimension: DIMENSION_MAP[rawSignal.type],
            urlContext: 'original_url',
            source: 'local_url',
            epistemic: 'OBSERVED',
            label: getLabel(rawSignal.type, 'original_url'),
            detail: getDetail(rawSignal.type, 'original_url')
          });
        } else {
          tierA.push({
            id: rawSignal.type,
            tier: 'A',
            dimension: null,
            urlContext: 'original_url',
            source: 'local_url',
            epistemic: 'INFERRED',
            label: getLabel(rawSignal.type, 'original_url'),
            detail: getDetail(rawSignal.type, 'original_url')
          });
        }
      });
    }

    // Additional original URL structural signals not directly emitted by url-analyzer.js riskSignals
    if (localSignals && !localSignals.isHttps) {
      tierB.push({
        id: 'HTTP_NOT_HTTPS',
        tier: 'B',
        dimension: 'connection',
        urlContext: 'original_url',
        source: 'local_url',
        epistemic: 'OBSERVED',
        label: getLabel('HTTP_NOT_HTTPS', 'original_url'),
        detail: getDetail('HTTP_NOT_HTTPS', 'original_url')
      });
    }

    try {
      var origUrlObj = new URL(originalUrl);
      if (origUrlObj.hostname.startsWith('[') && origUrlObj.hostname.endsWith(']')) {
        tierB.push({
          id: 'IP_HOST_V6',
          tier: 'B',
          dimension: 'hostname_identity',
          urlContext: 'original_url',
          source: 'local_url',
          epistemic: 'OBSERVED',
          label: getLabel('IP_HOST_V6', 'original_url'),
          detail: getDetail('IP_HOST_V6', 'original_url')
        });
      }
    } catch (e) {}

    // --- STEP 2: Add Tier A signals from localSignals (original URL) ---
    if (localSignals) {
      if (localSignals.isShortened) {
        tierA.push({
          id: 'REDIRECTS_THROUGH_SHORTENER', tier: 'A', urlContext: 'original_url',
          source: 'local_url', epistemic: 'OBSERVED',
          label: getLabel('REDIRECTS_THROUGH_SHORTENER', 'original_url'),
          detail: getDetail('REDIRECTS_THROUGH_SHORTENER', 'original_url')
        });
      }

      if (localSignals.trackingParams && localSignals.trackingParams.length > 0) {
        tierA.push({
          id: 'HAS_TRACKING_PARAMS', tier: 'A', urlContext: 'original_url',
          source: 'local_url', epistemic: 'OBSERVED',
          label: getLabel('HAS_TRACKING_PARAMS', 'original_url'),
          detail: getDetail('HAS_TRACKING_PARAMS', 'original_url', localSignals.trackingParams.join(', '))
        });
      }

      if (localSignals.hasAffiliate) {
        tierA.push({
          id: 'HAS_AFFILIATE', tier: 'A', urlContext: 'original_url',
          source: 'local_url', epistemic: 'OBSERVED',
          label: getLabel('HAS_AFFILIATE', 'original_url'),
          detail: getDetail('HAS_AFFILIATE', 'original_url')
        });
      }

      var origPathname = localSignals.pathname;
      if (!origPathname) {
        try { origPathname = new URL(originalUrl).pathname; } catch (e) {}
      }
      var originalPathExt = getFileExtension(origPathname);
      
      if (isExecutableExtension(originalPathExt)) {
        tierB.push({
          id: 'SUSPICIOUS_FILE_EXT', tier: 'B', dimension: 'path_content',
          urlContext: 'original_url', source: 'local_url', epistemic: 'PREDICTED',
          label: getLabel('SUSPICIOUS_FILE_EXT', 'original_url'),
          detail: getDetail('SUSPICIOUS_FILE_EXT', 'original_url', '.' + originalPathExt)
        });
      } else if (isArchiveExtension(originalPathExt)) {
        tierA.push({
          id: 'PREDICTED_ARCHIVE_DOWNLOAD', tier: 'A', dimension: null,
          urlContext: 'original_url', source: 'local_url', epistemic: 'PREDICTED',
          label: getLabel('PREDICTED_ARCHIVE_DOWNLOAD', 'original_url'),
          detail: getDetail('PREDICTED_ARCHIVE_DOWNLOAD', 'original_url', '.' + originalPathExt)
        });
      } else if (isDocumentExtension(originalPathExt)) {
        tierA.push({
          id: 'PREDICTED_DOCUMENT_DOWNLOAD', tier: 'A', dimension: null,
          urlContext: 'original_url', source: 'local_url', epistemic: 'PREDICTED',
          label: getLabel('PREDICTED_DOCUMENT_DOWNLOAD', 'original_url'),
          detail: getDetail('PREDICTED_DOCUMENT_DOWNLOAD', 'original_url', '.' + originalPathExt)
        });
      }
    }

    // --- STEP 3: Map VERIFIED REDIRECT TARGET riskSignals to tiers ---
    if (networkEvidence && networkEvidence.status === 'HTTP_REDIRECT_OBSERVED' &&
        networkEvidence.redirectTarget && targetRiskSignals) {
      
      if (differentRegistrableDomain(originalUrl, networkEvidence.redirectTarget)) {
        tierA.push({
          id: 'REDIRECTS_TO_DIFFERENT_DOMAIN', tier: 'A', dimension: null,
          urlContext: 'network_target_url', source: 'network',
          epistemic: 'VERIFIED',
          label: getLabel('REDIRECTS_TO_DIFFERENT_DOMAIN', 'network_target_url'),
          detail: getDetail('REDIRECTS_TO_DIFFERENT_DOMAIN', 'network_target_url', getHostname(networkEvidence.redirectTarget))
        });
      }

      targetRiskSignals.signals.forEach(function (rawSignal) {
        if (STRUCTURAL_SIGNAL_TYPES.indexOf(rawSignal.type) !== -1) {
          tierB.push({
            id: rawSignal.type,
            tier: 'B',
            dimension: DIMENSION_MAP[rawSignal.type],
            urlContext: 'network_target_url',
            source: 'network_target_url',
            epistemic: 'VERIFIED',
            label: getLabel(rawSignal.type, 'network_target_url'),
            detail: getDetail(rawSignal.type, 'network_target_url')
          });
        } else {
          tierA.push({
            id: rawSignal.type,
            tier: 'A',
            dimension: null,
            urlContext: 'network_target_url',
            source: 'network_target_url',
            epistemic: 'VERIFIED',
            label: getLabel(rawSignal.type, 'network_target_url'),
            detail: getDetail(rawSignal.type, 'network_target_url')
          });
        }
      });

      if (targetLocalSignals && !targetLocalSignals.isHttps) {
        tierB.push({
          id: 'HTTP_NOT_HTTPS',
          tier: 'B',
          dimension: 'connection',
          urlContext: 'network_target_url',
          source: 'network_target_url',
          epistemic: 'VERIFIED',
          label: getLabel('HTTP_NOT_HTTPS', 'network_target_url'),
          detail: getDetail('HTTP_NOT_HTTPS', 'network_target_url')
        });
      }

      try {
        var targetUrlObj = new URL(networkEvidence.redirectTarget);
        if (targetUrlObj.hostname.startsWith('[') && targetUrlObj.hostname.endsWith(']')) {
          tierB.push({
            id: 'IP_HOST_V6',
            tier: 'B',
            dimension: 'hostname_identity',
            urlContext: 'network_target_url',
            source: 'network_target_url',
            epistemic: 'VERIFIED',
            label: getLabel('IP_HOST_V6', 'network_target_url'),
            detail: getDetail('IP_HOST_V6', 'network_target_url')
          });
        }
      } catch (e) {}

      if (targetLocalSignals) {
        var targetPathname = targetLocalSignals.pathname;
        if (!targetPathname) {
          try { targetPathname = new URL(networkEvidence.redirectTarget).pathname; } catch (e) {}
        }
        var targetPathExt = getFileExtension(targetPathname);
        
        if (isExecutableExtension(targetPathExt)) {
          tierB.push({
            id: 'SUSPICIOUS_FILE_EXT', tier: 'B', dimension: 'path_content',
            urlContext: 'network_target_url', source: 'network_target_url',
            epistemic: 'VERIFIED',
            label: getLabel('SUSPICIOUS_FILE_EXT', 'network_target_url'),
            detail: getDetail('SUSPICIOUS_FILE_EXT', 'network_target_url', '.' + targetPathExt)
          });
        }
      }
    }

    // --- STEP 4: Determine assessmentBasis ---
    var networkAvailable = (networkEvidence && networkEvidence.status !== 'FAILED');
    var observationExists = (browserObservation && browserObservation.status === 'STRONG_CORRELATION');
    var shortenerNoResolve = (localSignals && localSignals.isShortened && 
                              (!networkEvidence || networkEvidence.status === 'FAILED') && 
                              (!browserObservation || browserObservation.status === 'NONE'));
    
    var assessmentBasis;
    if (shortenerNoResolve) {
      assessmentBasis = 'INCOMPLETE';
      limitations.push("Destination is hidden behind a shortener and could not be confirmed");
    } else if (networkAvailable && observationExists) {
      assessmentBasis = 'LOCAL_WITH_NETWORK_AND_OBSERVATION';
    } else if (networkAvailable) {
      assessmentBasis = 'LOCAL_WITH_NETWORK';
    } else if (observationExists) {
      assessmentBasis = 'LOCAL_WITH_OBSERVATION';
      limitations.push("Network unavailable — destination could not be verified");
    } else {
      assessmentBasis = 'LOCAL_ONLY';
      limitations.push("Network unavailable — destination could not be verified");
      limitations.push("No prior browser navigation observation available");
    }

    if (!observationExists && assessmentBasis !== 'INCOMPLETE' && assessmentBasis !== 'LOCAL_ONLY') {
      limitations.push("No prior browser navigation observation available");
    }

    // --- STEP 4.2: Evaluate Claim ↔ Destination Mismatch ---
    var verifiedDestination = null;
    var mismatchSource = null;
    if (networkEvidence && networkEvidence.status === 'HTTP_REDIRECT_OBSERVED' && networkEvidence.redirectTarget) {
      verifiedDestination = networkEvidence.redirectTarget;
      mismatchSource = 'network';
    } else if (browserObservation && browserObservation.status === 'STRONG_CORRELATION' && browserObservation.observedLatestUrl) {
      verifiedDestination = browserObservation.observedLatestUrl;
      mismatchSource = 'browser_observation';
    }

    if (verifiedDestination && contextObj && BTL.claimDestinationAnalyzer) {
      var mismatch = BTL.claimDestinationAnalyzer.evaluateMismatch(contextObj, verifiedDestination);
      if (mismatch) {
        tierC.push({
          id: 'CLAIM_DESTINATION_MISMATCH',
          tier: 'C',
          dimension: 'claim_destination',
          urlContext: 'network_target_url',
          source: mismatchSource,
          epistemic: 'VERIFIED',
          label: "Link and destination don't match",
          detail: "The link mentions " + mismatch.displayBrand + ", but the verified destination is " + getHostname(verifiedDestination) + "."
        });
      }
    }

    // --- STEP 5: Determine status from Tier B/C signals ---
    var activeDimensions = {};
    tierB.forEach(function (s) {
      if (s.dimension) activeDimensions[s.dimension] = true;
    });
    tierC.forEach(function (s) {
      if (s.dimension) activeDimensions[s.dimension] = true;
    });
    var dimensionCount = Object.keys(activeDimensions).length;

    var status;
    
    // --- STEP 4.5: Check Reputation (Tier D) ---
    if (reputationSignals && reputationSignals.status === 'REPUTATION_CONFIRMED_THREAT') {
      status = 'STRONG_WARNING';
      tierD.push({
        id: 'REPUTATION_CONFIRMED_THREAT',
        tier: 'D',
        dimension: 'reputation',
        urlContext: 'reputation_check',
        source: 'reputation_engine',
        epistemic: 'VERIFIED',
        label: 'Known threat detected',
        detail: 'This link was flagged as a known threat (' + (reputationSignals.threatTypes ? reputationSignals.threatTypes.join(', ') : 'malicious') + ').'
      });
    } else if (tierB.length === 0 && tierC.length === 0) {
      status = (tierA.length > 0) ? 'INFORMATIONAL' : 'NO_SIGNALS_DETECTED';
    } else if (dimensionCount >= 2 || tierC.length > 0) {
      status = 'UNUSUAL_CHARACTERISTICS';
    } else {
      status = 'INFORMATIONAL';
    }

    // --- STEP 6: Assemble and return ---
    var allSignals = []
      .concat(tierD)
      .concat(tierC)
      .concat(tierB.filter(function(s) { return s.urlContext === 'original_url'; }))
      .concat(tierB.filter(function(s) { return s.urlContext === 'network_target_url'; }))
      .concat(tierA.filter(function(s) { return s.urlContext === 'original_url'; }))
      .concat(tierA.filter(function(s) { return s.urlContext === 'network_target_url'; }));

    return {
      status: status,
      signals: allSignals,
      assessmentBasis: assessmentBasis,
      limitations: limitations,
      checkedAt: Date.now()
    };
  }

  BTL.safetyAnalyzer = {
    computeSafetyEvidence: computeSafetyEvidence
  };

})();
