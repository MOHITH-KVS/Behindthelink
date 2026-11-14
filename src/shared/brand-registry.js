/**
 * BehindTheLink — Brand Registry
 *
 * Centralized registry of recognized brands, aliases, official domains,
 * regional domains, brand-specific hosting exclusions, and scoped services.
 * Single source of truth for brand-based link analysis.
 *
 * Local-first and dependency-free.
 */
(function () {
  'use strict';

  var BTL = (typeof window !== 'undefined' ? window : self).BehindTheLink || {};
  if (typeof window !== 'undefined') window.BehindTheLink = BTL;
  if (typeof self !== 'undefined') self.BehindTheLink = BTL;

  /**
   * Helper to test if a hostname matches a wildcard pattern.
   * Supports '*.example.com' (matching example.com and any subdomains).
   */
  function matchesSubdomainPattern(hostname, pattern) {
    if (!hostname || !pattern) return false;
    var cleanHost = hostname.toLowerCase().replace(/\.+$/, '');
    var cleanPattern = pattern.toLowerCase().replace(/\.+$/, '');

    if (cleanPattern.startsWith('*.')) {
      var root = cleanPattern.slice(2);
      if (cleanHost === root || cleanHost.endsWith('.' + root)) {
        return true;
      }
    }

    if (cleanPattern.indexOf('*') !== -1) {
      var escaped = cleanPattern.split('*').map(function (part) {
        return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      }).join('.*');
      return new RegExp('^' + escaped + '$').test(cleanHost);
    }

    return cleanHost === cleanPattern;
  }

  /**
   * Core brand registry entries.
   * Tier 1 verified brands + core compatibility set.
   */
  var BRANDS = [
    {
      id: 'GOOGLE',
      displayName: 'Google',
      category: 'TECH_ECOSYSTEM',
      aliases: [
        { text: 'google', matchCase: false, isGenericWord: false },
        { text: 'gmail', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['google.com'],
        regional: [
          'google.co.in', 'google.co.uk', 'google.de', 'google.fr',
          'google.ca', 'google.com.au', 'google.co.jp', 'google.es',
          'google.it', 'google.nl', 'google.com.br'
        ],
        subdomainPolicy: {
          mode: 'RESTRICTED',
          excludedSubdomains: [
            '*.firebaseapp.com',
            '*.web.app',
            '*.appspot.com',
            '*.googleusercontent.com'
          ]
        }
      },
      legitimateServices: [
        { hostname: 'pay.google.com', scope: 'PAYMENT' }
      ]
    },
    {
      id: 'MICROSOFT',
      displayName: 'Microsoft',
      category: 'TECH_ECOSYSTEM',
      aliases: [
        { text: 'microsoft', matchCase: false, isGenericWord: false },
        { text: 'office365', matchCase: false, isGenericWord: false },
        { text: 'onedrive', matchCase: false, isGenericWord: false },
        { text: 'outlook', matchCase: false, isGenericWord: false },
        { text: 'windows', matchCase: true, isGenericWord: true, minIntent: 'LOGIN_ACCOUNT' },
        { text: 'office', matchCase: false, isGenericWord: true, minIntent: 'LOGIN_ACCOUNT' }
      ],
      domains: {
        primary: [
          'microsoft.com',
          'microsoftonline.com',
          'office.com',
          'live.com',
          'outlook.com',
          'bing.com',
          'msn.com',
          'office365.com'
        ],
        regional: ['microsoft.com.cn'],
        subdomainPolicy: {
          mode: 'RESTRICTED',
          excludedSubdomains: [
            '*.azurewebsites.net',
            '*.cloudapp.net',
            '*.blob.core.windows.net',
            '*.trafficmanager.net'
          ]
        }
      },
      legitimateServices: []
    },
    {
      id: 'AMAZON',
      displayName: 'Amazon',
      category: 'E_COMMERCE',
      aliases: [
        { text: 'amazon', matchCase: false, isGenericWord: false },
        { text: 'aws', matchCase: true, isGenericWord: false }
      ],
      domains: {
        primary: ['amazon.com', 'aws.amazon.com'],
        regional: [
          'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr',
          'amazon.es', 'amazon.it', 'amazon.ca', 'amazon.co.jp', 'amazon.com.au'
        ],
        subdomainPolicy: {
          mode: 'RESTRICTED',
          excludedSubdomains: [
            '*.s3.amazonaws.com',
            '*.s3-website.*.amazonaws.com'
          ]
        }
      },
      legitimateServices: []
    },
    {
      id: 'OPENAI',
      displayName: 'OpenAI',
      category: 'TECH_ECOSYSTEM',
      aliases: [
        { text: 'openai', matchCase: false, isGenericWord: false },
        { text: 'chatgpt', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['openai.com', 'chatgpt.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'GITHUB',
      displayName: 'GitHub',
      category: 'TECH_ECOSYSTEM',
      aliases: [
        { text: 'github', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['github.com'],
        regional: [],
        subdomainPolicy: {
          mode: 'RESTRICTED',
          excludedSubdomains: ['*.github.io']
        }
      },
      legitimateServices: []
    },
    {
      id: 'PAYPAL',
      displayName: 'PayPal',
      category: 'PAYMENT',
      aliases: [
        { text: 'paypal', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['paypal.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: [
        { hostname: 'paypal.me', scope: 'PEER_PAYMENT' }
      ]
    },
    {
      id: 'WHATSAPP',
      displayName: 'WhatsApp',
      category: 'MESSAGING',
      aliases: [
        { text: 'whatsapp', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['whatsapp.com', 'whatsapp.net'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: [
        { hostname: 'wa.me', scope: 'CLICK_TO_CHAT' }
      ]
    },
    {
      id: 'SBI',
      displayName: 'State Bank of India (SBI)',
      category: 'BANKING',
      aliases: [
        { text: 'state bank of india', matchCase: false, isGenericWord: false },
        { text: 'sbi', matchCase: true, isGenericWord: false },
        { text: 'onlinesbi', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: [
          'sbi.bank.in',
          'sbi.co.in',
          'bank.sbi',
          'onlinesbi.sbi',
          'onlinesbi.com',
          'statebankofindia.com'
        ],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'HDFC',
      displayName: 'HDFC Bank',
      category: 'BANKING',
      aliases: [
        { text: 'hdfc bank', matchCase: false, isGenericWord: false },
        { text: 'hdfc', matchCase: true, isGenericWord: false },
        { text: 'hdfcbank', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['hdfcbank.com', 'hdfc.bank.in'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'AXIS',
      displayName: 'Axis Bank',
      category: 'BANKING',
      aliases: [
        { text: 'axis bank', matchCase: false, isGenericWord: false },
        { text: 'axis', matchCase: true, isGenericWord: true, minIntent: 'LOGIN_ACCOUNT' },
        { text: 'axisbank', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['axis.bank.in', 'axisbank.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'APPLE',
      displayName: 'Apple',
      category: 'TECH_ECOSYSTEM',
      aliases: [
        { text: 'apple', matchCase: false, isGenericWord: true, minIntent: 'LOGIN_ACCOUNT' },
        { text: 'icloud', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['apple.com', 'icloud.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'META',
      displayName: 'Meta',
      category: 'SOCIAL',
      aliases: [
        { text: 'meta', matchCase: true, isGenericWord: true, minIntent: 'LOGIN_ACCOUNT' }
      ],
      domains: {
        primary: ['meta.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'FACEBOOK',
      displayName: 'Facebook',
      category: 'SOCIAL',
      aliases: [
        { text: 'facebook', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['facebook.com', 'messenger.com', 'meta.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'NETFLIX',
      displayName: 'Netflix',
      category: 'MEDIA',
      aliases: [
        { text: 'netflix', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['netflix.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'LINKEDIN',
      displayName: 'LinkedIn',
      category: 'SOCIAL',
      aliases: [
        { text: 'linkedin', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['linkedin.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'YOUTUBE',
      displayName: 'YouTube',
      category: 'MEDIA',
      aliases: [
        { text: 'youtube', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['youtube.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'INSTAGRAM',
      displayName: 'Instagram',
      category: 'SOCIAL',
      aliases: [
        { text: 'instagram', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['instagram.com'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: []
    },
    {
      id: 'TELEGRAM',
      displayName: 'Telegram',
      category: 'MESSAGING',
      aliases: [
        { text: 'telegram', matchCase: false, isGenericWord: false }
      ],
      domains: {
        primary: ['telegram.org'],
        regional: [],
        subdomainPolicy: { mode: 'ALLOW_ALL', excludedSubdomains: [] }
      },
      legitimateServices: [
        { hostname: 't.me', scope: 'CLICK_TO_CHAT' }
      ]
    }
  ];

  // Quick lookup index by uppercase ID
  var BRAND_MAP = {};
  for (var i = 0; i < BRANDS.length; i++) {
    BRAND_MAP[BRANDS[i].id.toUpperCase()] = BRANDS[i];
  }

  /**
   * Retrieves a brand entry by its ID (case-insensitive).
   * @param {string} brandId
   * @returns {Object|null}
   */
  function getBrand(brandId) {
    if (!brandId) return null;
    return BRAND_MAP[brandId.toUpperCase()] || null;
  }

  /**
   * Returns all brand entries.
   * @returns {Array<Object>}
   */
  function getAllBrands() {
    return BRANDS;
  }

  /**
   * Returns a flattened list of all brand aliases with matching metadata.
   * @returns {Array<Object>}
   */
  function getAllAliases() {
    var result = [];
    for (var i = 0; i < BRANDS.length; i++) {
      var brand = BRANDS[i];
      for (var j = 0; j < brand.aliases.length; j++) {
        var alias = brand.aliases[j];
        result.push({
          text: alias.text,
          brandId: brand.id,
          matchCase: !!alias.matchCase,
          isGenericWord: !!alias.isGenericWord,
          minIntent: alias.minIntent || null
        });
      }
    }
    return result;
  }

  /**
   * Checks if a given hostname matches an excluded subdomain pattern for a brand.
   * @param {string} brandId
   * @param {string} hostname
   * @returns {boolean}
   */
  function isExcludedSubdomain(brandId, hostname) {
    var brand = getBrand(brandId);
    if (!brand || !brand.domains || !brand.domains.subdomainPolicy) return false;
    var exclusions = brand.domains.subdomainPolicy.excludedSubdomains || [];
    for (var i = 0; i < exclusions.length; i++) {
      if (matchesSubdomainPattern(hostname, exclusions[i])) {
        return true;
      }
    }
    return false;
  }

  /**
   * Evaluates if a given hostname matches the official domains or scoped services of a brand.
   * Does NOT rely on substring matching; enforces exact or dot-boundary matching.
   *
   * @param {string} brandId
   * @param {string} hostname - Normalized hostname (lowercase, trailing dots stripped)
   * @param {string} [contextCategory] - Context category (e.g. 'PAYMENT', 'LOGIN_ACCOUNT')
   * @returns {boolean}
   */
  function isOfficialDomain(brandId, hostname, contextCategory) {
    if (!brandId || !hostname) return false;
    var brand = getBrand(brandId);
    if (!brand) return false;

    var cleanHost = hostname.toLowerCase().replace(/\.+$/, '');

    // Step 1: Check brand-specific excluded hosting subdomains (highest precedence rejection)
    if (isExcludedSubdomain(brandId, cleanHost)) {
      return false;
    }

    // Step 2: Check primary and regional domains
    var primary = brand.domains.primary || [];
    var regional = brand.domains.regional || [];
    var allOfficial = primary.concat(regional);

    for (var i = 0; i < allOfficial.length; i++) {
      var d = allOfficial[i].toLowerCase().replace(/\.+$/, '');
      if (cleanHost === d || cleanHost.endsWith('.' + d)) {
        return true;
      }
    }

    // Step 3: Check scoped legitimate services
    var services = brand.legitimateServices || [];
    for (var j = 0; j < services.length; j++) {
      var s = services[j];
      var sHost = s.hostname.toLowerCase().replace(/\.+$/, '');
      if (cleanHost === sHost || cleanHost.endsWith('.' + sHost)) {
        return true;
      }
    }

    return false;
  }

  BTL.brandRegistry = {
    getBrand: getBrand,
    getAllBrands: getAllBrands,
    getAllAliases: getAllAliases,
    isExcludedSubdomain: isExcludedSubdomain,
    isOfficialDomain: isOfficialDomain,
    _matchesSubdomainPattern: matchesSubdomainPattern
  };

})();
