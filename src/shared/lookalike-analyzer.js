/**
 * BehindTheLink — Lookalike Domain Analyzer
 *
 * Implements Phase 3A: Local Lookalike-Domain Detection.
 * Detects:
 *   Vector 1: Misleading Subdomain Structure (official domain / brand in subdomain of unrelated domain)
 *   Vector 2: Unicode Homoglyphs & Punycode (cross-script confusables)
 *   Vector 3: Bounded Typosquatting: Digit Substitution ('0'->'o', '1'->'l'/'i', '3'->'e', '5'->'s', '8'->'b')
 *   Vector 4: Bounded Typosquatting: Edit Distance (Damerau-Levenshtein <= 1, disabled for short/generic stems)
 *   Vector 5: Brand Tokens Embedded in Unrelated Registrable Domains (delimited + sensitive keywords)
 *
 * Local-first, zero-dependency, and strictly bounded.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink || {};
  if (typeof window !== 'undefined') window.BehindTheLink = BTL;
  if (typeof self !== 'undefined') self.BehindTheLink = BTL;

  // Sensitive keywords that indicate security, credential, or account operations
  var SENSITIVE_KEYWORDS = [
    'login', 'signin', 'sign-in', 'auth', 'authentication',
    'account', 'verify', 'verification', 'secure', 'security',
    'portal', 'update', 'billing', 'support', 'help', 'service',
    'banking', 'pay', 'payment', 'wallet', 'confirm', 'confirmation',
    'recovery', 'passcode', 'password', 'credential', 'alert',
    'protect', 'validation', 'validate', 'online', 'access'
  ];

  var SENSITIVE_KEYWORD_SET = {};
  for (var k = 0; k < SENSITIVE_KEYWORDS.length; k++) {
    SENSITIVE_KEYWORD_SET[SENSITIVE_KEYWORDS[k]] = true;
  }

  /**
   * Calculates bounded Damerau-Levenshtein distance between strings a and b.
   * Handles insertion, deletion, substitution, and adjacent transposition.
   * Returns distance, or 999 if length difference > 1.
   *
   * @param {string} a
   * @param {string} b
   * @returns {number}
   */
  function damerauLevenshteinDistance(a, b) {
    if (a === b) return 0;
    var al = a.length;
    var bl = b.length;
    if (Math.abs(al - bl) > 1) return 999;

    var d = [];
    for (var i = 0; i <= al; i++) {
      d[i] = [i];
    }
    for (var j = 0; j <= bl; j++) {
      d[0][j] = j;
    }

    for (var r = 1; r <= al; r++) {
      for (var c = 1; c <= bl; c++) {
        var cost = (a[r - 1] === b[c - 1]) ? 0 : 1;
        d[r][c] = Math.min(
          d[r - 1][c] + 1,      // deletion
          d[r][c - 1] + 1,      // insertion
          d[r - 1][c - 1] + cost // substitution
        );
        if (r > 1 && c > 1 && a[r - 1] === b[c - 2] && a[r - 2] === b[c - 1]) {
          d[r][c] = Math.min(d[r][c], d[r - 2][c - 2] + 1); // transposition
        }
      }
    }
    return d[al][bl];
  }

  /**
   * Generates candidate strings from digit substitutions.
   * Maps '0'->'o', '1'->'l' or 'i', '3'->'e', '5'->'s', '8'->'b'.
   * Returns array of de-digitized strings, or empty array if no digits.
   *
   * @param {string} stem
   * @returns {Array<string>}
   */
  function getDigitSubstitutions(stem) {
    if (!stem || !/\d/.test(stem)) return [];

    // Common variant with 1->l
    var variantL = stem
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/5/g, 's')
      .replace(/8/g, 'b');

    // Variant with 1->i
    var variantI = stem
      .replace(/0/g, 'o')
      .replace(/1/g, 'i')
      .replace(/3/g, 'e')
      .replace(/5/g, 's')
      .replace(/8/g, 'b');

    var results = [variantL];
    if (variantI !== variantL) {
      results.push(variantI);
    }
    return results;
  }

  /**
   * Helper to check if any token in an array matches sensitive keywords.
   * @param {Array<string>} tokens
   * @returns {boolean}
   */
  function containsSensitiveKeyword(tokens) {
    for (var i = 0; i < tokens.length; i++) {
      if (SENSITIVE_KEYWORD_SET[tokens[i].toLowerCase()]) {
        return true;
      }
    }
    return false;
  }

  /**
   * Extracts target stems for a brand from its primary domains and primary aliases.
   * @param {Object} brand
   * @returns {Array<{ stem: string, isGeneric: boolean, isShort: boolean }>}
   */
  function getBrandTargetStems(brand) {
    var targets = [];
    var seen = {};

    function addTarget(stem, isGeneric) {
      if (!stem) return;
      var clean = stem.toLowerCase().trim();
      if (clean && !seen[clean]) {
        seen[clean] = true;
        targets.push({
          stem: clean,
          isGeneric: !!isGeneric,
          isShort: clean.length < 5
        });
      }
    }

    // Extract stems from primary domains (e.g. 'google' from 'google.com', 'microsoft' from 'microsoft.com')
    var primaryDomains = (brand.domains && brand.domains.primary) ? brand.domains.primary : [];
    for (var i = 0; i < primaryDomains.length; i++) {
      var d = primaryDomains[i];
      var stemPart = d.split('.')[0];
      // Check if any alias marks it as generic
      var generic = false;
      if (brand.aliases) {
        for (var a = 0; a < brand.aliases.length; a++) {
          if (brand.aliases[a].text.toLowerCase() === stemPart && brand.aliases[a].isGenericWord) {
            generic = true;
            break;
          }
        }
      }
      addTarget(stemPart, generic);
    }

    // Extract stems from aliases
    if (brand.aliases) {
      for (var j = 0; j < brand.aliases.length; j++) {
        var alias = brand.aliases[j];
        // Only consider single-word aliases as stem targets
        if (alias.text && alias.text.indexOf(' ') === -1) {
          addTarget(alias.text, alias.isGenericWord);
        }
      }
    }

    return targets;
  }

  /**
   * Detects lookalike characteristics in a validated destination URL or hostname.
   *
   * @param {string} destinationUrl
   * @param {Object} [contextObj]
   * @returns {Object|null} Structured evidence object or null if clean / inconclusive
   */
  function detectLookalike(destinationUrl, contextObj) {
    if (!destinationUrl || typeof destinationUrl !== 'string') return null;
    if (!BTL.domainUtils || !BTL.brandRegistry) return null;

    var parsed = BTL.domainUtils.parseDomain(destinationUrl);
    // Ignore IP addresses, inconclusive parsing, or missing registrable domains
    if (parsed.isIp || parsed.isInconclusive || !parsed.registrableDomain || !parsed.domainStem) {
      return null;
    }

    // Computational work bounds
    if (parsed.hostname.length > 253 || parsed.domainStem.length > 63) {
      return null;
    }

    var hostname = parsed.hostname;
    var domainStem = parsed.domainStem.toLowerCase();
    var registrableDomain = parsed.registrableDomain.toLowerCase();
    var subdomain = (parsed.subdomain || '').toLowerCase();

    var allBrands = BTL.brandRegistry.getAllBrands();

    // STEP 1: If hostname is an official domain or scoped service for ANY brand, it is NOT a lookalike
    for (var b = 0; b < allBrands.length; b++) {
      if (BTL.brandRegistry.isOfficialDomain(allBrands[b].id, hostname)) {
        return null;
      }
    }

    // STEP 2: VECTOR 1 — Misleading Subdomain Structure
    if (subdomain) {
      var subLabels = subdomain.split('.');
      for (var b1 = 0; b1 < allBrands.length; b1++) {
        var brand1 = allBrands[b1];
        var officialDomains = (brand1.domains && brand1.domains.primary ? brand1.domains.primary : [])
          .concat(brand1.domains && brand1.domains.regional ? brand1.domains.regional : []);

        // Check 1a: Subdomain contains an official domain of the brand (e.g., 'paypal.com.account-update.xyz')
        for (var od = 0; od < officialDomains.length; od++) {
          var officialDomain = officialDomains[od].toLowerCase();
          var isOfficialMatch = false;
          if (subdomain === officialDomain || subdomain.endsWith('.' + officialDomain)) {
            isOfficialMatch = true;
          } else {
            // Also check hyphenated replacement like 'paypal-com' in subdomain
            var hyphenatedOfficial = officialDomain.replace(/\./g, '-');
            for (var sl = 0; sl < subLabels.length; sl++) {
              if (subLabels[sl] === hyphenatedOfficial) {
                isOfficialMatch = true;
                break;
              }
            }
          }

          if (isOfficialMatch && !BTL.brandRegistry.isOfficialDomain(brand1.id, registrableDomain)) {
            return {
              signalId: 'MISLEADING_SUBDOMAIN_STRUCTURE',
              brandId: brand1.id,
              brandName: brand1.displayName,
              detectionType: 'SUBDOMAIN_BRAND_MASQUERADE',
              detectedDomain: hostname,
              matchedStem: officialDomain,
              targetStem: officialDomain,
              reason: 'Destination domain uses "' + officialDomain + '" in a subdomain of an unrelated domain ("' + registrableDomain + '")',
              detail: 'The destination domain uses "' + officialDomain + '" in a subdomain of an unrelated domain ("' + registrableDomain + '").'
            };
          }
        }

        // Check 1b: Subdomain label equals a brand stem
        var brandStems1 = getBrandTargetStems(brand1);
        for (var bs1 = 0; bs1 < brandStems1.length; bs1++) {
          var targetInfo1 = brandStems1[bs1];
          var stem1 = targetInfo1.stem;

          for (var sIdx = 0; sIdx < subLabels.length; sIdx++) {
            var subLabel = subLabels[sIdx];
            var subTokens = subLabel.split(/[-_]+/);

            // Exact brand stem in subdomain
            if (subTokens.indexOf(stem1) !== -1) {
              // For short stems or generic words, require a sensitive keyword
              var requireSensitive = targetInfo1.isShort || targetInfo1.isGeneric;
              var hasSensitive = containsSensitiveKeyword(subTokens) || containsSensitiveKeyword(subLabels);

              if (!requireSensitive || hasSensitive) {
                if (!BTL.brandRegistry.isOfficialDomain(brand1.id, registrableDomain)) {
                  return {
                    signalId: 'MISLEADING_SUBDOMAIN_STRUCTURE',
                    brandId: brand1.id,
                    brandName: brand1.displayName,
                    detectionType: 'SUBDOMAIN_BRAND_MASQUERADE',
                    detectedDomain: hostname,
                    matchedStem: stem1,
                    targetStem: stem1,
                    reason: 'Destination domain uses brand name "' + stem1 + '" in a subdomain of an unrelated domain',
                    detail: 'The destination domain uses the brand name "' + stem1 + '" in a subdomain on an unrelated domain ("' + registrableDomain + '").'
                  };
                }
              }
            }
          }
        }
      }
    }

    // STEP 3: VECTOR 2 — Unicode Homoglyphs & Punycode Indicators
    var homoglyphResult = BTL.domainUtils.mapHomoglyphs(domainStem);
    if (homoglyphResult.hasConfusable) {
      var mappedStem = homoglyphResult.normalized.toLowerCase();
      for (var b2 = 0; b2 < allBrands.length; b2++) {
        var brand2 = allBrands[b2];
        var stems2 = getBrandTargetStems(brand2);
        for (var s2 = 0; s2 < stems2.length; s2++) {
          var targetStem2 = stems2[s2].stem;
          if (mappedStem === targetStem2 && domainStem !== targetStem2) {
            return {
              signalId: 'LOOKALIKE_DOMAIN_SIMILARITY',
              brandId: brand2.id,
              brandName: brand2.displayName,
              detectionType: 'UNICODE_CONFUSABLE',
              detectedDomain: registrableDomain,
              matchedStem: domainStem,
              targetStem: targetStem2,
              reason: 'Domain "' + registrableDomain + '" uses Unicode confusable characters resembling "' + targetStem2 + '"',
              detail: 'The destination domain uses Unicode characters that visually imitate ' + brand2.displayName + ' ("' + targetStem2 + '").'
            };
          }
        }
      }
    }

    // STEP 4: VECTOR 3 — Bounded Typosquatting: Digit Substitution
    var digitSubstitutions = getDigitSubstitutions(domainStem);
    if (digitSubstitutions.length > 0) {
      for (var b3 = 0; b3 < allBrands.length; b3++) {
        var brand3 = allBrands[b3];
        var stems3 = getBrandTargetStems(brand3);
        for (var s3 = 0; s3 < stems3.length; s3++) {
          var targetInfo3 = stems3[s3];
          var targetStem3 = targetInfo3.stem;

          // For short stems (< 4 chars), disable bare digit substitution to prevent false positives
          if (targetStem3.length < 4) continue;

          for (var ds = 0; ds < digitSubstitutions.length; ds++) {
            if (digitSubstitutions[ds] === targetStem3 && domainStem !== targetStem3) {
              return {
                signalId: 'LOOKALIKE_DOMAIN_SIMILARITY',
                brandId: brand3.id,
                brandName: brand3.displayName,
                detectionType: 'DIGIT_SUBSTITUTION',
                detectedDomain: registrableDomain,
                matchedStem: domainStem,
                targetStem: targetStem3,
                reason: 'Domain "' + registrableDomain + '" uses digit substitutions resembling "' + targetStem3 + '"',
                detail: 'The destination domain uses digit substitutions resembling ' + brand3.displayName + ' ("' + targetStem3 + '").'
              };
            }
          }
        }
      }
    }

    // STEP 5: VECTOR 4 — Bounded Typosquatting: Edit Distance (Damerau-Levenshtein <= 1)
    for (var b4 = 0; b4 < allBrands.length; b4++) {
      var brand4 = allBrands[b4];
      var stems4 = getBrandTargetStems(brand4);
      for (var s4 = 0; s4 < stems4.length; s4++) {
        var targetInfo4 = stems4[s4];
        var targetStem4 = targetInfo4.stem;

        // GUARD: Strictly disable fuzzy matching for short stems (< 5 chars: sbi, hdfc, axis, meta, aws)
        if (targetInfo4.isShort) continue;

        // GUARD: Strictly disable fuzzy matching for generic brand words (e.g. apple -> apply, maple)
        if (targetInfo4.isGeneric) continue;

        // GUARD: Length bound: only compare if lengths differ by at most 1
        if (Math.abs(domainStem.length - targetStem4.length) > 1) continue;

        var dist = damerauLevenshteinDistance(domainStem, targetStem4);
        if (dist === 1 && domainStem !== targetStem4) {
          return {
            signalId: 'LOOKALIKE_DOMAIN_SIMILARITY',
            brandId: brand4.id,
            brandName: brand4.displayName,
            detectionType: 'TYPOSQUAT_EDIT_DISTANCE',
            detectedDomain: registrableDomain,
            matchedStem: domainStem,
            targetStem: targetStem4,
            reason: 'Domain "' + registrableDomain + '" is a close spelling variation of "' + targetStem4 + '"',
            detail: 'The destination domain is a close spelling variation of ' + brand4.displayName + ' ("' + targetStem4 + '").'
          };
        }
      }
    }

    // STEP 6: VECTOR 5 — Brand Tokens Embedded in Unrelated Registrable Domains
    // Must respect strict delimiter boundaries (hyphens or underscores)
    if (domainStem.indexOf('-') !== -1 || domainStem.indexOf('_') !== -1) {
      var tokens = domainStem.split(/[-_]+/);
      for (var b5 = 0; b5 < allBrands.length; b5++) {
        var brand5 = allBrands[b5];
        var stems5 = getBrandTargetStems(brand5);
        for (var s5 = 0; s5 < stems5.length; s5++) {
          var targetInfo5 = stems5[s5];
          var targetStem5 = targetInfo5.stem;

          // Check if any delimited token matches the brand stem
          if (tokens.indexOf(targetStem5) !== -1) {
            // For short stems (< 5 chars) or generic words ('apple'): MUST be accompanied by a sensitive keyword
            var requiresSensitive = targetInfo5.isShort || targetInfo5.isGeneric;
            var hasSensitiveKeyword = containsSensitiveKeyword(tokens);

            if (!requiresSensitive || hasSensitiveKeyword) {
              // If it's a regular brand (e.g. paypal-security.com) or has sensitive keywords:
              if (hasSensitiveKeyword || tokens.length > 1) {
                // If it's not official for this brand
                if (!BTL.brandRegistry.isOfficialDomain(brand5.id, registrableDomain)) {
                  return {
                    signalId: 'BRAND_EMBEDDED_IN_UNRELATED_DOMAIN',
                    brandId: brand5.id,
                    brandName: brand5.displayName,
                    detectionType: 'BRAND_TOKEN_EMBEDDED',
                    detectedDomain: registrableDomain,
                    matchedStem: targetStem5,
                    targetStem: targetStem5,
                    reason: 'Domain "' + registrableDomain + '" includes brand name "' + targetStem5 + '" combined with other terms',
                    detail: 'The destination domain includes the brand name "' + targetStem5 + '" on an unrelated domain ("' + registrableDomain + '").'
                  };
                }
              }
            }
          }
        }
      }
    }

    return null;
  }

  BTL.lookalikeAnalyzer = {
    detectLookalike: detectLookalike,
    _damerauLevenshteinDistance: damerauLevenshteinDistance,
    _getDigitSubstitutions: getDigitSubstitutions,
    _getBrandTargetStems: getBrandTargetStems
  };

})();
