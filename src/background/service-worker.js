/**
 * BehindTheLink — Background Service Worker
 *
 * Handles cross-origin network inspection to resolve actual destinations.
 * Keeps a map of active AbortControllers to allow robust cancellation
 * when the user moves their mouse away.
 */

importScripts(
  '../shared/constants.js',
  '../shared/brand-registry.js',
  '../shared/domain-utils.js',
  '../shared/lookalike-analyzer.js',
  '../content/tracking-registry.js',
  '../content/shortener-registry.js',
  '../content/affiliate-registry.js',
  '../content/url-analyzer.js',
  '../shared/claim-destination-analyzer.js',
  '../shared/deception-analyzer.js',
  '../shared/safety-analyzer.js',
  '../shared/assessment-aggregator.js',
  '../shared/reputation/canonicalization.js',
  '../shared/reputation/expression-generator.js',
  '../shared/reputation/hash-utils.js',
  '../shared/reputation/local-threat-db.js',
  './reputation-engine.js'
);

// Initialize bundled local threat database on service worker startup using shared initialization promise
if (typeof self !== 'undefined' && self.BehindTheLink && self.BehindTheLink.localThreatDb && typeof self.BehindTheLink.localThreatDb.ensureInitialized === 'function') {
  self.BehindTheLink.localThreatDb.ensureInitialized().catch(err => {
    console.warn('BehindTheLink: Bundled threat database initialization failed:', err);
  });
}

const activeRequests = new Map();
const TIMEOUT_MS = (typeof self !== 'undefined' ? self : window).BehindTheLink.DESTINATION_TIMEOUT || 5000;
const MAX_HOPS = 5;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'RESOLVE_DESTINATION') {
    const { url, requestId, contextObj } = message;
    
    // Start resolution
    resolveDestination(url, requestId, contextObj).then(sendResponse);
    return true; // Keep message channel open for async response
  }

  if (message.type === 'CHECK_REPUTATION') {
    const { url, requestId, originalUrl, contextObj, networkResponse } = message;
    checkReputationAndAnalyze(url, requestId, originalUrl, contextObj, networkResponse).then(sendResponse);
    return true;
  }

  if (message.type === 'CANCEL_RESOLUTION') {
    const { requestId } = message;
    if (activeRequests.has(requestId)) {
      activeRequests.get(requestId).abort();
      activeRequests.delete(requestId);
    }
    sendResponse({ status: 'cancelled' });
  }
  if (message.type === 'LINK_CLICK_INTENT') {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      clickIntents.set(tabId, {
        url: message.url,
        timestamp: message.timestamp
      });
      logDiagnostic('CLICK_INTENT', {
        tab: tabId,
        url: message.url
      });
    }
  }
});

const MAX_BYTES = 4096;

function isValidHttpUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') return false;
  try {
    const parsed = new URL(urlString);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (e) {
    return false;
  }
}

function extractMetaRefreshTarget(htmlText, baseUrl) {
  if (!htmlText || typeof htmlText !== 'string') return null;
  const match = htmlText.match(/<meta[^>]*?http-equiv\s*=\s*["']?refresh["']?[^>]*?content\s*=\s*["']?\s*\d*\s*;\s*url=([^"'>\s]+)/i) ||
                htmlText.match(/<meta[^>]*?content\s*=\s*["']?\s*\d*\s*;\s*url=([^"'>\s]+)[^>]*?http-equiv\s*=\s*["']?refresh["']?/i);
  if (!match || !match[1]) return null;
  const rawTarget = match[1].trim().replace(/^['"]|['"]$/g, '');
  try {
    const resolved = new URL(rawTarget, baseUrl).href;
    return resolved;
  } catch (e) {
    return rawTarget;
  }
}

function isBlockedOrInterstitial(status, bodyText) {
  if (status === 403 || status === 429 || status === 503) return true;
  if (!bodyText) return false;
  const lower = bodyText.toLowerCase();
  return lower.includes('cf-browser-verification') ||
         lower.includes('challenge-platform') ||
         lower.includes('turnstile') ||
         lower.includes('just a moment...') ||
         lower.includes('attention required! | cloudflare') ||
         lower.includes('ddos-guard') ||
         lower.includes('security check to continue');
}

async function readBoundedBody(response, maxBytes) {
  try {
    if (!response.body) {
      if (typeof response.text === 'function') {
        const text = await response.text();
        return text ? text.substring(0, maxBytes) : '';
      }
      return '';
    }
    if (typeof response.body.getReader === 'function') {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let result = '';
      let bytesRead = 0;
      while (bytesRead < maxBytes) {
        const { done, value } = await reader.read();
        if (done) break;
        bytesRead += value.byteLength;
        result += decoder.decode(value, { stream: true });
        if (bytesRead >= maxBytes) {
          reader.cancel();
          break;
        }
      }
      return result;
    }
    const fullText = await response.text();
    return fullText ? fullText.substring(0, maxBytes) : '';
  } catch (e) {
    return '';
  }
}

function normalizeUrl(urlString) {
  try {
    const obj = new URL(urlString);
    obj.hash = '';
    return obj.href.replace(/\/$/, '');
  } catch (e) {
    return urlString;
  }
}

async function resolveDestination(originalUrlString, requestId, contextObj) {
  const controller = new AbortController();
  activeRequests.set(requestId, controller);

  const timeoutId = setTimeout(() => {
    controller.abort('timeout');
  }, TIMEOUT_MS);

  const BTL = (typeof self !== 'undefined' ? self : window).BehindTheLink;
  
  const analysisResult = BTL.urlAnalyzer ? BTL.urlAnalyzer.analyzeUrl(originalUrlString) : null;
  const localSignals = analysisResult ? analysisResult.localSignals : {
    hostname: '', isStructurallyDirect: false, isClean: false, isShortener: false, trackingParams: [], hasAffiliate: false, embeddedCandidates: []
  };
  const riskSignals = analysisResult ? analysisResult.riskSignals : {
    severity: 'NONE', signals: []
  };

  const isShortener = localSignals.isShortened || (BTL.shortenerRegistry && BTL.shortenerRegistry.isShortener(localSignals.hostname));

  let networkEvidence = {
    status: 'FAILED',
    redirectTarget: null,
    errorReason: 'UNCONFIRMED'
  };

  if (!isValidHttpUrl(originalUrlString)) {
    networkEvidence.status = 'FAILED';
    networkEvidence.errorReason = 'MALFORMED_DESTINATION';
    clearTimeout(timeoutId);
    activeRequests.delete(requestId);
  } else {
    try {
      let currentUrl = originalUrlString;
      const visitedUrls = new Set();
      let hops = 0;
      let resolvedTarget = null;
      let isTerminated = false;

      while (hops < MAX_HOPS && !isTerminated) {
        hops++;
        const normCurrent = normalizeUrl(currentUrl);
        if (visitedUrls.has(normCurrent)) {
          networkEvidence.status = 'FAILED';
          networkEvidence.errorReason = 'REDIRECT_LOOP';
          isTerminated = true;
          break;
        }
        visitedUrls.add(normCurrent);

        // Attempt HEAD first
        let headRes = null;
        let headFailed = false;
        try {
          headRes = await fetch(currentUrl, {
            method: 'HEAD',
            redirect: 'follow',
            signal: controller.signal
          });
          if (headRes.status === 405 || headRes.status === 501 || headRes.status === 403) {
            headFailed = true;
          }
        } catch (e) {
          headFailed = true;
        }

        // If HEAD succeeded and followed a redirect to a different destination
        if (!headFailed && headRes && headRes.url && normalizeUrl(headRes.url) !== normCurrent) {
          if (!isValidHttpUrl(headRes.url)) {
            networkEvidence.status = 'FAILED';
            networkEvidence.errorReason = 'MALFORMED_DESTINATION';
            isTerminated = true;
            break;
          }
          resolvedTarget = headRes.url;
          currentUrl = headRes.url;
          const nextAnalysis = BTL.urlAnalyzer ? BTL.urlAnalyzer.analyzeUrl(currentUrl) : null;
          const nextIsShortener = nextAnalysis && nextAnalysis.localSignals && nextAnalysis.localSignals.isShortened;
          if (!nextIsShortener) {
            isTerminated = true;
            break;
          }
          continue;
        }

        // Fall back to bounded GET (if HEAD failed or produced no redirect on shortener/page)
        let getRes = null;
        try {
          getRes = await fetch(currentUrl, {
            method: 'GET',
            redirect: 'follow',
            signal: controller.signal
          });
        } catch (e) {
          throw e;
        }

        const normGetUrl = normalizeUrl(getRes.url);
        if (normGetUrl !== normCurrent) {
          if (!isValidHttpUrl(getRes.url)) {
            networkEvidence.status = 'FAILED';
            networkEvidence.errorReason = 'MALFORMED_DESTINATION';
            isTerminated = true;
            break;
          }
          resolvedTarget = getRes.url;
          currentUrl = getRes.url;
        }

        // Read strictly bounded response body (up to 4KB)
        const bodyChunk = await readBoundedBody(getRes, MAX_BYTES);

        // Detect blocked or interstitial challenge pages
        if (isBlockedOrInterstitial(getRes.status, bodyChunk)) {
          networkEvidence.status = 'FAILED';
          networkEvidence.errorReason = 'BLOCKED_INTERSTITIAL';
          isTerminated = true;
          break;
        }

        // Parse meta-refresh redirect (without executing JavaScript)
        const metaTarget = extractMetaRefreshTarget(bodyChunk, getRes.url);
        if (metaTarget) {
          if (!isValidHttpUrl(metaTarget)) {
            networkEvidence.status = 'FAILED';
            networkEvidence.errorReason = 'MALFORMED_DESTINATION';
            isTerminated = true;
            break;
          }
          if (normalizeUrl(metaTarget) !== normCurrent) {
            resolvedTarget = metaTarget;
            currentUrl = metaTarget;
            continue;
          }
        }

        isTerminated = true;
      }

      if (hops >= MAX_HOPS && !resolvedTarget && !networkEvidence.errorReason) {
        networkEvidence.status = 'FAILED';
        networkEvidence.errorReason = 'REDIRECT_LOOP';
      }

      if (!networkEvidence.errorReason) {
        if (resolvedTarget && normalizeUrl(resolvedTarget) !== normalizeUrl(originalUrlString)) {
          networkEvidence.status = 'HTTP_REDIRECT_OBSERVED';
          networkEvidence.redirectTarget = resolvedTarget;
          networkEvidence.errorReason = null;
        } else if (isShortener) {
          // Never report a shortener as safe merely because its destination could not be resolved
          networkEvidence.status = 'FAILED';
          networkEvidence.redirectTarget = null;
          networkEvidence.errorReason = 'DESTINATION_UNRESOLVED';
        } else {
          networkEvidence.status = 'NO_REDIRECT_OBSERVED';
          networkEvidence.redirectTarget = null;
          networkEvidence.errorReason = null;
        }
      }
    } catch (error) {
      if (error === 'timeout' || (error && error.name === 'AbortError') || (error && error.message && error.message.includes('timeout'))) {
        networkEvidence.errorReason = 'TIMEOUT';
      } else {
        networkEvidence.errorReason = 'NETWORK_ERROR';
      }
    }

    clearTimeout(timeoutId);
    activeRequests.delete(requestId);
  }

  let browserObservation = {
    status: 'NONE',
    observedLatestUrl: null,
    observedAt: null,
    correlationEvidence: null
  };

  if (chrome.storage && chrome.storage.local) {
    try {
      const storageKey = 'obs_' + normalizeUrl(originalUrlString);
      const data = await chrome.storage.local.get(storageKey);
      if (data && data[storageKey]) {
        const obs = data[storageKey];
        if (Date.now() - obs.observedAt < 7 * 24 * 60 * 60 * 1000) {
          browserObservation.status = 'STRONG_CORRELATION';
          // Use observedFinalUrl if we had one from previous implementation, fallback to latest
          browserObservation.observedLatestUrl = obs.observedFinalUrl || obs.observedLatestUrl;
          browserObservation.observedAt = obs.observedAt;
          browserObservation.correlationEvidence = obs.evidence;
          logDiagnostic('OBSERVATION_LOOKUP', { status: 'FOUND', sourceUrl: originalUrlString, key: storageKey, age: Date.now() - obs.observedAt, browserObservation });
        } else {
          logDiagnostic('OBSERVATION_LOOKUP', { status: 'EXPIRED', sourceUrl: originalUrlString, key: storageKey, age: Date.now() - obs.observedAt });
          chrome.storage.local.remove(storageKey);
        }
      } else {
        logDiagnostic('OBSERVATION_LOOKUP', { status: 'NOT_FOUND', sourceUrl: originalUrlString, key: storageKey });
      }
    } catch (e) {
      logDiagnostic('OBSERVATION_LOOKUP', { status: 'ERROR', error: e.toString() });
    }
  }

  let targetRiskSignals = null;
  let targetLocalSignals = null;
  if (networkEvidence.status === 'HTTP_REDIRECT_OBSERVED' && networkEvidence.redirectTarget) {
    const targetAnalysis = BTL.urlAnalyzer ? BTL.urlAnalyzer.analyzeUrl(networkEvidence.redirectTarget) : null;
    if (targetAnalysis) {
      targetRiskSignals = targetAnalysis.riskSignals;
      targetLocalSignals = targetAnalysis.localSignals;
    }
  }

  let reputationSignals = { status: 'REPUTATION_NOT_ENABLED' };
  if (BTL.reputationEngine && typeof BTL.reputationEngine.isOptedIn === 'function') {
    const enabled = await BTL.reputationEngine.isOptedIn();
    if (enabled) {
      reputationSignals = { status: 'REPUTATION_PENDING' };
    }
  }
  
  const safetyEvidence = BTL.safetyAnalyzer ? BTL.safetyAnalyzer.computeSafetyEvidence(
    originalUrlString,
    localSignals,
    riskSignals,
    targetRiskSignals,
    targetLocalSignals,
    networkEvidence,
    browserObservation,
    reputationSignals,
    contextObj
  ) : null;

  return {
    originalUrl: originalUrlString,
    localSignals: localSignals,
    riskSignals: riskSignals,
    networkEvidence: networkEvidence,
    browserObservation: browserObservation,
    safetyEvidence: safetyEvidence
  };
}

async function checkReputationAndAnalyze(targetUrl, requestId, originalUrlString, contextObj, networkResponse) {
  const BTL = (typeof self !== 'undefined' ? self : window).BehindTheLink;
  let reputationSignals = { status: 'REPUTATION_NOT_ENABLED' };
  
  if (BTL.reputationEngine) {
    const redirectTarget = (networkResponse && networkResponse.networkEvidence && networkResponse.networkEvidence.status === 'HTTP_REDIRECT_OBSERVED' && networkResponse.networkEvidence.redirectTarget)
      ? networkResponse.networkEvidence.redirectTarget
      : ((targetUrl && targetUrl !== originalUrlString) ? targetUrl : null);

    reputationSignals = await BTL.reputationEngine.checkReputation(originalUrlString, redirectTarget);
  }

  const { localSignals, riskSignals, networkEvidence, browserObservation } = networkResponse;
  
  let targetRiskSignals = null;
  let targetLocalSignals = null;
  if (networkEvidence.status === 'HTTP_REDIRECT_OBSERVED' && networkEvidence.redirectTarget) {
    const targetAnalysis = BTL.urlAnalyzer ? BTL.urlAnalyzer.analyzeUrl(networkEvidence.redirectTarget) : null;
    if (targetAnalysis) {
      targetRiskSignals = targetAnalysis.riskSignals;
      targetLocalSignals = targetAnalysis.localSignals;
    }
  }

  const safetyEvidence = BTL.safetyAnalyzer ? BTL.safetyAnalyzer.computeSafetyEvidence(
    originalUrlString,
    localSignals,
    riskSignals,
    targetRiskSignals,
    targetLocalSignals,
    networkEvidence,
    browserObservation,
    reputationSignals,
    contextObj
  ) : null;

  return {
    reputationSignals: reputationSignals,
    safetyEvidence: safetyEvidence
  };
}

// ============================================================================
// PHASE 1H.3 — BROWSER OBSERVATION ENGINE
// ============================================================================

const clickIntents = new Map();
const newTabMappings = new Map();
const activeSessions = new Map();

const CLICK_INTENT_TIMEOUT = 3000; 
const SESSION_TIMEOUT = 10000;
const MAX_STORAGE_ITEMS = 500;

function logDiagnostic(tag, data) {
  let str = `[BehindTheLink][${tag}]`;
  for (const key in data) {
    let val = data[key];
    if (Array.isArray(val) || typeof val === 'object') val = JSON.stringify(val);
    str += `\n${key}=${val}`;
  }
  console.log(str + '\n');
}

async function storeStrongObservation(sourceUrl, observedLatestUrl, correlationEvidence) {
  if (!chrome.storage || !chrome.storage.local) return;
  
  try {
    const storageKey = 'obs_' + normalizeUrl(sourceUrl);
    const observation = {
      sourceUrl: sourceUrl,
      observedLatestUrl: observedLatestUrl,
      observedAt: Date.now(),
      evidence: correlationEvidence
    };

    const allData = await chrome.storage.local.get(null);
    let obsKeys = Object.keys(allData).filter(k => k.startsWith('obs_'));
    
    if (obsKeys.length >= MAX_STORAGE_ITEMS && !obsKeys.includes(storageKey)) {
      obsKeys.sort((a, b) => allData[a].observedAt - allData[b].observedAt);
      const toDelete = obsKeys.slice(0, obsKeys.length - MAX_STORAGE_ITEMS + 1);
      await chrome.storage.local.remove(toDelete);
    }

    const toStore = {};
    toStore[storageKey] = observation;
    await chrome.storage.local.set(toStore);
    logDiagnostic('OBSERVATION_STORE', { sourceUrl, observedLatestUrl, evidence: correlationEvidence, key: storageKey });
  } catch (e) {
    console.error("Storage error:", e);
  }
}

function evaluateAndConcludeSession(tabId, reason) {
  const session = activeSessions.get(tabId);
  if (!session) return;
  
  // We will selectively delete it in the function, not here unconditionally
  // activeSessions.delete(tabId);
  
  const chain = session.chain;
  if (chain.length === 0) return;

  if (reason === 'navigation_error') {
    logDiagnostic('DISCARDED_SESSION', { reason: reason, url: session.sourceUrl });
    activeSessions.delete(tabId);
    clearTimeout(session.timeoutId);
    return;
  }
  
  const sourceUrl = session.sourceUrl;
  const initialNav = chain[0];
  const latestNav = chain[chain.length - 1];
  
  let correlationEvidence = {
    explicitClick: true,
    sameTab: !session.isNewTab,
    mainFrame: true,
    initialUrlMatch: false,
    transitionType: null,
    transitionQualifiers: [],
    documentId: latestNav.documentId,
    targetCreatedFromSource: session.isNewTab
  };
  
  // Try to find the initial commit transition
  const firstCommit = chain.find(n => n.event === 'onCommitted');
  if (firstCommit) {
    correlationEvidence.transitionType = firstCommit.transition;
    correlationEvidence.transitionQualifiers = firstCommit.qualifiers;
  }

  const normalizedClicked = normalizeUrl(sourceUrl);
  const normalizedNav = normalizeUrl(initialNav.url);
  
  if (normalizedNav === normalizedClicked || initialNav.url.includes(encodeURIComponent(normalizedClicked))) {
    correlationEvidence.initialUrlMatch = true;
  }
  
  // Evaluate strength based on the latest commit (if any)
  // or based on the chain so far
  let isStrong = false;
  
  if (correlationEvidence.initialUrlMatch) {
    isStrong = true;
  } else if (correlationEvidence.transitionQualifiers.includes('server_redirect') || correlationEvidence.transitionQualifiers.includes('client_redirect')) {
    isStrong = true;
  } else if (chain.some(n => n.event === 'onBeforeNavigate' && (normalizeUrl(n.url) === normalizedClicked || n.url.includes(encodeURIComponent(normalizedClicked))))) {
    isStrong = true;
    correlationEvidence.initialUrlMatch = true;
  }
  
  // If not strong, DO NOT close the session yet unless it's a timeout or explicit error
  if (!isStrong) {
    if (reason === 'session_timeout' || reason === 'navigation_error') {
      logDiagnostic('WEAK_CORRELATION_DISCARD', { reason: reason, clicked: sourceUrl, firstNav: initialNav.url });
      activeSessions.delete(tabId);
      clearTimeout(session.timeoutId);
    } else {
      // It's a commit but weak. Let it stay in the session until timeout.
      // E.g., maybe a client redirect will follow? Or it's an unrelated navigation.
      // But wait! If it's a typed/bookmark navigation, we shouldn't wait for timeout!
      const lastCommit = chain[chain.length - 1];
      if (lastCommit && lastCommit.event === 'onCommitted') {
         if (lastCommit.transition === 'typed' || lastCommit.transition === 'auto_bookmark' || lastCommit.transition === 'generated' || lastCommit.transition === 'reload') {
            logDiagnostic('UNRELATED_NAVIGATION_DISCARD', { transition: lastCommit.transition });
            activeSessions.delete(tabId);
            clearTimeout(session.timeoutId);
         }
      }
    }
    return; // Do not store
  }
  
  // Strong correlation!
  activeSessions.delete(tabId);
  clearTimeout(session.timeoutId);
  
  const validEnds = chain.filter(n => n.event === 'onCommitted' || n.event === 'onHistoryStateUpdated');
  let observedLatestUrl = validEnds.length > 0 ? validEnds[validEnds.length - 1].url : latestNav.url;
  
  logDiagnostic('CORRELATION', { decision: 'STRONG', sourceUrl, observedLatestUrl });
  storeStrongObservation(sourceUrl, observedLatestUrl, correlationEvidence);
}

if (chrome.webNavigation) {
  
  chrome.webNavigation.onCreatedNavigationTarget.addListener((details) => {
    newTabMappings.set(details.tabId, details.sourceTabId);
    
    const intent = clickIntents.get(details.sourceTabId);
    if (intent && (Date.now() - intent.timestamp < CLICK_INTENT_TIMEOUT)) {
      clickIntents.set(details.tabId, intent);
    }
  });

  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    
    let sourceTabId = details.tabId;
    let isNewTab = false;
    
    logDiagnostic('NAV_BEFORE', { tabId: details.tabId, frameId: details.frameId, url: details.url });
    if (newTabMappings.has(details.tabId)) {
      sourceTabId = newTabMappings.get(details.tabId);
      isNewTab = true;
    }
    
    const intent = clickIntents.get(sourceTabId);
    
    if (intent) {
      if (Date.now() - intent.timestamp >= CLICK_INTENT_TIMEOUT) {
        clickIntents.delete(sourceTabId);
        if (isNewTab) clickIntents.delete(details.tabId);
      } else {
        if (isNewTab) {
        const normalizedClicked = normalizeUrl(intent.url);
        const normalizedNav = normalizeUrl(details.url);
        if (normalizedNav !== normalizedClicked && !details.url.includes(encodeURIComponent(normalizedClicked))) {
          return; // Ignore unrelated new tab
        }
      }
      
      if (!activeSessions.has(details.tabId)) {
        activeSessions.set(details.tabId, {
          sourceUrl: intent.url,
          chain: [],
          startTime: Date.now(),
          isNewTab: isNewTab
        });
      }
      
      const timeoutHandle = setTimeout(() => {
        if (activeSessions.has(details.tabId)) {
          evaluateAndConcludeSession(details.tabId, 'session_timeout');
        }
      }, SESSION_TIMEOUT);
      activeSessions.get(details.tabId).timeoutId = timeoutHandle;
    }
    }
    
    const session = activeSessions.get(details.tabId);
    if (session) {
      session.chain.push({
        event: 'onBeforeNavigate',
        url: details.url,
        timestamp: Date.now(),
        documentId: details.documentId || 'unknown'
      });
    }
  });

  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    
    logDiagnostic('NAV_COMMITTED', { tabId: details.tabId, frameId: details.frameId, url: details.url, transitionType: details.transitionType, transitionQualifiers: details.transitionQualifiers });

    const session = activeSessions.get(details.tabId);
    if (session) {
      session.chain.push({
        event: 'onCommitted',
        url: details.url,
        timestamp: Date.now(),
        transition: details.transitionType,
        qualifiers: details.transitionQualifiers || [],
        documentId: details.documentId || 'unknown'
      });
      
      evaluateAndConcludeSession(details.tabId, 'commit');
    }
  });

  chrome.webNavigation.onErrorOccurred.addListener((details) => {
    if (details.frameId !== 0) return;
    
    const session = activeSessions.get(details.tabId);
    if (session) {
      session.chain.push({
        event: 'onErrorOccurred',
        url: details.url,
        timestamp: Date.now(),
        error: details.error,
        documentId: details.documentId || 'unknown'
      });
      evaluateAndConcludeSession(details.tabId, 'navigation_error');
    }
  });

  chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
    if (details.frameId !== 0) return;
    const session = activeSessions.get(details.tabId);
    if (session) {
      session.chain.push({
        event: 'onHistoryStateUpdated',
        url: details.url,
        timestamp: Date.now(),
        transition: details.transitionType,
        qualifiers: details.transitionQualifiers || [],
        documentId: details.documentId || 'unknown'
      });
    }
  });
}
