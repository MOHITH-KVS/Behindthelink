/**
 * BehindTheLink — Claim Destination Analyzer
 *
 * Level 3B: Compares strong contextual claims (brands/intents) against verified destinations.
 * Built to prevent phishing by finding inconsistencies, rather than absolute classification.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink || {};
  if (typeof window !== 'undefined') window.BehindTheLink = BTL;
  if (typeof self !== 'undefined') self.BehindTheLink = BTL;

  // Curated list of official domains for supported brands
  var OFFICIAL_DOMAINS = {
    'GOOGLE': ['google.com'],
    'MICROSOFT': ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com'],
    'APPLE': ['apple.com', 'icloud.com'],
    'AMAZON': ['amazon.com', 'aws.amazon.com'],
    'META': ['meta.com'],
    'PAYPAL': ['paypal.com'],
    'NETFLIX': ['netflix.com'],
    'LINKEDIN': ['linkedin.com'],
    'WHATSAPP': ['whatsapp.com'],
    'INSTAGRAM': ['instagram.com'],
    'FACEBOOK': ['facebook.com'],
    'TELEGRAM': ['telegram.org', 't.me'],
    'YOUTUBE': ['youtube.com', 'youtu.be'],
    'GITHUB': ['github.com'],
    'OPENAI': ['openai.com', 'chatgpt.com']
  };

  /**
   * Evaluates if a given URL belongs to the official domains of a specific brand.
   */
  function isOfficialDestination(brandId, destinationUrl) {
    if (!brandId || !destinationUrl) return false;
    var lookupBrand = brandId.toUpperCase();
    var domains = OFFICIAL_DOMAINS[lookupBrand];
    if (!domains) return false;
    
    try {
      var destHost = new URL(destinationUrl).hostname.toLowerCase();
      for (var i = 0; i < domains.length; i++) {
        var d = domains[i].toLowerCase();
        // Match exact domain or standard subdomain (e.g., login.microsoftonline.com)
        if (destHost === d || destHost.endsWith('.' + d)) {
          return true;
        }
      }
    } catch(e) {}
    return false;
  }

  /**
   * Determines the strength of the context claim based on the detected brand and category.
   */
  function getClaimStrength(contextObj) {
    if (!contextObj || !contextObj.possibleClaimedBrand) return 'NONE';
    
    var cat = contextObj.category;
    var strongCategories = ['LOGIN_ACCOUNT', 'PAYMENT', 'VERIFICATION_SECURITY', 'DELIVERY_ORDER'];
    var moderateCategories = ['REWARD_OFFER', 'JOB_HIRING', 'GOVERNMENT_SERVICE'];
    
    if (strongCategories.indexOf(cat) !== -1) {
      return 'STRONG';
    }
    
    if (moderateCategories.indexOf(cat) !== -1) {
      return 'MODERATE';
    }
    
    return 'WEAK';
  }

  /**
   * Compares the extracted context against the verified destination.
   * Returns a mismatch object if a STRONG claim conflicts with the verified destination.
   */
  function evaluateMismatch(contextObj, verifiedDestinationUrl) {
    if (!contextObj || !contextObj.possibleClaimedBrand) return null;
    if (!verifiedDestinationUrl) return null; // No assessment if unverified

    var strength = getClaimStrength(contextObj);
    if (strength !== 'STRONG') return null; // Only mismatch on STRONG claims to prevent false positives

    var brandId = contextObj.possibleClaimedBrand;
    var isOfficial = isOfficialDestination(brandId, verifiedDestinationUrl);
    
    if (!isOfficial) {
      // Find the original brand name for display purposes (Title Case)
      var displayBrand = brandId.charAt(0) + brandId.slice(1).toLowerCase();
      // Adjust standard capitalization
      if (brandId === 'PAYPAL') displayBrand = 'PayPal';
      if (brandId === 'LINKEDIN') displayBrand = 'LinkedIn';
      if (brandId === 'YOUTUBE') displayBrand = 'YouTube';
      if (brandId === 'GITHUB') displayBrand = 'GitHub';
      if (brandId === 'OPENAI') displayBrand = 'OpenAI';
      if (brandId === 'WHATSAPP') displayBrand = 'WhatsApp';

      return {
        brandId: brandId,
        displayBrand: displayBrand,
        strength: strength,
        mismatch: true
      };
    }
    
    return null; // No mismatch (it is official)
  }

  BTL.claimDestinationAnalyzer = {
    evaluateMismatch: evaluateMismatch,
    isOfficialDestination: isOfficialDestination,
    getClaimStrength: getClaimStrength
  };

})();
