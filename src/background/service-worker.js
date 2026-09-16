/**
 * BehindTheLink — Background Service Worker
 *
 * Handles cross-origin network inspection to resolve actual destinations.
 * Keeps a map of active AbortControllers to allow robust cancellation
 * when the user moves their mouse away.
 */

importScripts(
  '../shared/constants.js',
  '../content/tracking-registry.js',
  '../content/shortener-registry.js',
  '../content/affiliate-registry.js',
  '../content/url-analyzer.js',
  '../shared/safety-analyzer.js',
  '../shared/reputation/canonicalization.js',
  '../shared/reputation/expression-generator.js',
  '../shared/reputation/hash-utils.js',
  './reputation-engine.js'
);

const activeRequests = new Map();
const TIMEOUT_MS = (typeof self !== 'undefined' ? self : window).BehindTheLink.DESTINATION_TIMEOUT || 5000;
const MAX_HOPS = 5;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'RESOLVE_DESTINATION') {
    const { url, requestId } = message;
    
    // Start resolution
    resolveDestination(url, requestId).then(sendResponse);
    return true; // Keep message channel open for async response
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

function normalizeUrl(urlString) {
  try {
    const obj = new URL(urlString);
    obj.hash = '';
    return obj.href.replace(/\/$/, '');
  } catch (e) {
    return urlString;
  }
}

async function resolveDestination(originalUrlString, requestId) {
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

  let networkEvidence = {
    status: 'FAILED',
    redirectTarget: null,
    errorReason: 'UNCONFIRMED'
  };

  try {
    const normalizedOriginal = normalizeUrl(originalUrlString);
    
    const response = await fetch(originalUrlString, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal
    });

    const normalizedResponse = normalizeUrl(response.url);

    if (normalizedResponse !== normalizedOriginal) {
      networkEvidence.status = 'HTTP_REDIRECT_OBSERVED';
      networkEvidence.redirectTarget = response.url;
      networkEvidence.errorReason = null;
    } else {
      networkEvidence.status = 'NO_REDIRECT_OBSERVED';
      networkEvidence.redirectTarget = null;
      networkEvidence.errorReason = null;
    }
  } catch (error) {
    if (error === 'timeout' || error.name === 'AbortError' || (error.message && error.message.includes('timeout'))) {
      networkEvidence.errorReason = 'TIMEOUT';
    } else {
      networkEvidence.errorReason = 'NETWORK_ERROR';
    }
    
    if (networkEvidence.errorReason === 'TIMEOUT' && (!error || error.name !== 'AbortError')) {
      // Actually handled above, but if it was truly aborted by something else, we could use CANCELLED
      // For now keep it TIMEOUT/NETWORK_ERROR
    }
  }

  clearTimeout(timeoutId);
  activeRequests.delete(requestId);

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

  let reputationSignals = { status: 'REPUTATION_UNAVAILABLE' };
  if (BTL.reputationEngine) {
    const repTarget = networkEvidence.status === 'HTTP_REDIRECT_OBSERVED' ? networkEvidence.redirectTarget : null;
    reputationSignals = await BTL.reputationEngine.checkReputation(originalUrlString, repTarget);
  }

  const safetyEvidence = BTL.safetyAnalyzer ? BTL.safetyAnalyzer.computeSafetyEvidence(
    originalUrlString,
    localSignals,
    riskSignals,
    targetRiskSignals,
    targetLocalSignals,
    networkEvidence,
    browserObservation,
    reputationSignals
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
