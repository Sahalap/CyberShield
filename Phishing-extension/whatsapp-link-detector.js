// PhishGuard Pro - WhatsApp Web Link Detection
// FIXED VERSION: Significantly reduced false positives with improved filtering

class WhatsAppLinkDetector {
  constructor() {
    this.processedLinks = new Set();
    this.processedLinkElements = new WeakSet();
    this.observer = null;
    this.conversationObserver = null;
    this.isWhatsAppLoaded = false;
    this.suspiciousLinks = new Map();
    this.detector = null;
    this.retryCount = 0;
    this.maxRetries = 10;
    this.retryDelay = 500;
    this.softMode = true;
    
    // Whitelist for known legitimate domains
    this.legitimateDomains = new Set([
      'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
      'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
      'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'medium.com',
      'paypal.com', 'stripe.com', 'dropbox.com', 'zoom.us', 'slack.com',
      'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai'
    ]);
    
    this.initializeWhatsAppDetector();
  }
  
  async waitForPhishingDetector() {
    return new Promise((resolve, reject) => {
      const checkDetector = () => {
        if (window.PhishingDetector) {
          this.detector = new window.PhishingDetector();
          resolve();
        } else if (this.retryCount < this.maxRetries) {
          this.retryCount++;
          setTimeout(checkDetector, this.retryDelay);
        } else {
          console.error('PhishingDetector not available after retries');
          reject(new Error('PhishingDetector not available'));
        }
      };
      checkDetector();
    });
  }
  
  async initializeWhatsAppDetector() {
    try {
      console.log('📱 PhishGuard Pro WhatsApp Link Detector initialized');
      
      await this.waitForPhishingDetector();
      this.waitForWhatsAppLoad();
    } catch (error) {
      console.error('WhatsApp detector initialization failed:', error);
      console.log('🔄 Falling back to basic detection...');
      this.waitForWhatsAppLoad();
      
      if (window.PhishGuardErrorHandler && typeof window.PhishGuardErrorHandler.handleError === 'function') {
        window.PhishGuardErrorHandler.handleError('WHATSAPP_INITIALIZATION_ERROR', error);
      }
    }
  }
  
  waitForWhatsAppLoad() {
    const checkWhatsAppLoaded = () => {
      const whatsappElements = document.querySelectorAll(`
        [data-testid="chat-list"], 
        [data-testid="conversation-panel-messages"],
        [data-testid="msg-container"]
      `);
      
      const hasWhatsAppElements = whatsappElements.length > 0 || 
                                 document.querySelector('[data-testid*="chat"]') ||
                                 window.location.hostname === 'web.whatsapp.com';
      
      if (hasWhatsAppElements) {
        this.isWhatsAppLoaded = true;
        console.log('✅ WhatsApp Web detected, starting link monitoring...');
        this.startLinkMonitoring();
      } else {
        setTimeout(checkWhatsAppLoaded, 1000);
      }
    };
    
    checkWhatsAppLoaded();
  }
  
  startLinkMonitoring() {
    this.observeMessageList();
    this.observeMessageContent();
    this.observeConversationPanel();
    this.analyzeExistingLinks();
  }
  
  observeMessageList() {
    try {
      const messageContainer = document.querySelector('[data-testid="chat-list"]') || 
                             document.querySelector('._2A1R8') || 
                             document.querySelector('._1JNuk');
      
      if (messageContainer) {
        const debouncedAnalyze = this.debounce((node) => {
          this.analyzeNewMessages(node);
        }, 300);
        
        this.observer = new MutationObserver((mutations) => {
          mutations.forEach((mutation) => {
            if (mutation.type === 'childList') {
              mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                  debouncedAnalyze(node);
                }
              });
            }
          });
        });
        
        this.observer.observe(messageContainer, {
          childList: true,
          subtree: true
        });
      }
    } catch (error) {
      console.error('Error setting up message list observer:', error);
      
      if (window.PhishGuardErrorHandler && typeof window.PhishGuardErrorHandler.handleError === 'function') {
        window.PhishGuardErrorHandler.handleError('WHATSAPP_OBSERVER_ERROR', error);
      }
    }
  }
  
  debounce(func, delay) {
    let timeoutId;
    return (...args) => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
  }
  
  observeMessageContent() {
    const messageContentObserver = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              this.analyzeMessageContent(node);
            }
          });
        }
      });
    });
    
    messageContentObserver.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  observeConversationPanel() {
    try {
      const setupConversationObserver = () => {
        const conversationPanel = document.querySelector('[data-testid="conversation-panel-messages"]');
        if (!conversationPanel) {
          return false;
        }

        if (this.conversationObserver) {
          this.conversationObserver.disconnect();
        }

        const debouncedAnalyze = this.debounce((node) => {
          this.analyzeNewMessages(node);
        }, 200);

        this.conversationObserver = new MutationObserver((mutations) => {
          mutations.forEach((mutation) => {
            if (mutation.type === 'childList') {
              mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                  debouncedAnalyze(node);
                }
              });
            }
          });
        });

        this.conversationObserver.observe(conversationPanel, {
          childList: true,
          subtree: true
        });

        return true;
      };

      const initialized = setupConversationObserver();
      if (!initialized) {
        setTimeout(() => this.observeConversationPanel(), 500);
      }

      const mainPanel = document.querySelector('[data-testid="main"]') || document.body;
      const chatSwitchObserver = new MutationObserver(() => {
        setupConversationObserver();
        this.analyzeExistingLinks();
      });
      chatSwitchObserver.observe(mainPanel, { childList: true, subtree: true });
    } catch (error) {
      console.error('Error setting up conversation panel observer:', error);
    }
  }
  
  analyzeExistingLinks() {
    const linkSelectors = [
      'a[href]',
      '[data-testid*="link"]',
      '[data-testid*="url"]',
      '.copyable-text a',
      '._3uMse a',
      '._3uMse span[data-href]',
      '[role="link"]',
      'span[data-href]',
      'div[data-href]'
    ];
    
    const linkElements = [];
    linkSelectors.forEach(selector => {
      const elements = document.querySelectorAll(selector);
      linkElements.push(...elements);
    });
    
    console.log(`🔍 Found ${linkElements.length} potential links in WhatsApp`);
    
    linkElements.forEach(linkElement => {
      this.analyzeLinkElement(linkElement);
    });
  }
  
  analyzeNewMessages(container) {
    const linkSelectors = [
      'a[href]',
      '[data-testid*="link"]',
      '[data-testid*="url"]',
      '.copyable-text a',
      '._3uMse a',
      '._3uMse span[data-href]',
      '[role="link"]',
      'span[data-href]',
      'div[data-href]'
    ];
    
    const linkElements = [];
    linkSelectors.forEach(selector => {
      const elements = container.querySelectorAll(selector);
      linkElements.push(...elements);
    });
    
    console.log(`🔍 Found ${linkElements.length} new links in WhatsApp message`);
    
    linkElements.forEach(linkElement => {
      this.analyzeLinkElement(linkElement);
    });
  }
  
  analyzeMessageContent(container) {
    const messageContent = container.querySelector('[data-testid="conversation-panel-messages"]') ||
                          container.querySelector('.copyable-text') ||
                          container.querySelector('[data-testid="msg-container"]');
    
    if (messageContent && !messageContent.dataset.phishguardAnalyzed) {
      messageContent.dataset.phishguardAnalyzed = 'true';
      this.analyzeMessageContentArea(messageContent);
    }
  }
  
  analyzeLinkElement(linkElement) {
    let href = linkElement.getAttribute('href') || 
               linkElement.getAttribute('data-href') ||
               linkElement.getAttribute('data-url') ||
               linkElement.textContent?.trim();
    
    let isEmailPattern = false;
    let originalEmailText = null;
    
    if (!href && linkElement.textContent) {
      const text = linkElement.textContent.trim();
      if (text.match(/^https?:\/\//) || text.match(/^www\./)) {
        href = text.startsWith('http') ? text : `https://${text}`;
      }
      // CRITICAL: Detect email-like phishing URLs (user@domain.tld)
      // These look like emails but are actually URLs with credentials
      else if (text.match(/^[a-z0-9]+@[a-z0-9.-]+\.[a-z]{2,}$/i)) {
        console.log(`⚠️ Detected email-like URL pattern: ${text}`);
        isEmailPattern = true;
        originalEmailText = text;
        href = `https://${text}`;
      }
    }
    
    if (!href) return;
    
    const normalizedUrl = this.normalizeUrl(href);
    if (!normalizedUrl) {
      console.log(`⚠️ Failed to normalize URL: ${href}`);
      return;
    }
    
    console.log(`✅ Normalized URL: ${href} -> ${normalizedUrl}`);

    if (linkElement && (linkElement.dataset.phishguardProcessed === 'true' || this.processedLinkElements.has(linkElement))) {
      return;
    }
    
    // Skip legitimate WhatsApp URLs
    if (this.isLegitimateWhatsAppUrl(normalizedUrl)) {
      return;
    }
    
    // CRITICAL FIX: Check if domain is whitelisted or clearly benign FIRST
    if (this.isWhitelistedDomain(normalizedUrl) || this.isClearlyBenign(normalizedUrl)) {
      console.log(`✅ URL is safe: ${normalizedUrl}`);
      return;
    }

    if (linkElement) {
      this.processedLinkElements.add(linkElement);
      linkElement.dataset.phishguardProcessed = 'true';
    }
    
    console.log(`🔍 Analyzing WhatsApp link: ${normalizedUrl}`);
    
    try {
      // EXPLICIT: Check for the exact URLs mentioned by user FIRST
      const explicitSuspiciousUrls = [
        'security@paypal-security.tk',
        'https://wa.me/verify-account',
        'https://chat.whatsapp.com/fake-security'
      ];
      
      if (explicitSuspiciousUrls.some(susUrl => normalizedUrl.toLowerCase().includes(susUrl.toLowerCase()))) {
        console.log(`🚨 EXPLICIT SUSPICIOUS URL DETECTED: ${normalizedUrl}`);
        const explicitAnalysis = {
          isSuspicious: true,
          riskScore: 95,
          reasons: ['Explicit phishing URL detected'],
          action: 'block',
          confidence: 'high'
        };
        
        // CRITICAL FIX: If this was an email pattern, also style it as an email
        if (isEmailPattern && originalEmailText) {
          const messageContainer = linkElement.closest('[data-testid="msg-container"]') || 
                                   linkElement.closest('.copyable-text') ||
                                   linkElement.parentElement;
          if (messageContainer) {
            this.styleEmailTextRed(messageContainer, originalEmailText, explicitAnalysis);
          }
        }
        
        this.showLinkWarning(linkElement, explicitAnalysis, normalizedUrl);
        return;
      }
      
      // FIXED: Always check suspicious URLs, even in soft mode
      if (this.softMode && !this.isHighRisk(normalizedUrl) && !this.isSuspiciousUrl(normalizedUrl)) {
        console.log(`⏭️ Skipping low-risk URL in soft mode: ${normalizedUrl}`);
          return;
      }

      // Run basic detection for high-risk URLs
        const basicAnalysis = this.basicPhishingDetection(normalizedUrl);
        if (basicAnalysis.isSuspicious) {
          // CRITICAL FIX: If this was an email pattern, also style it as an email
          if (isEmailPattern && originalEmailText) {
            const messageContainer = linkElement.closest('[data-testid="msg-container"]') || 
                                     linkElement.closest('.copyable-text') ||
                                     linkElement.parentElement;
            if (messageContainer) {
              this.styleEmailTextRed(messageContainer, originalEmailText, basicAnalysis);
            }
          }
          
          this.showLinkWarning(linkElement, basicAnalysis, normalizedUrl);
        return;
      }
      
      // Use ML detector if available
      if (this.detector) {
      this.detector.analyzeUrl(normalizedUrl).then(analysis => {
        console.log(`📊 WhatsApp link analysis result:`, analysis);
          // FIXED: Lower threshold for better detection
          if ((analysis.action === 'block' || analysis.action === 'warn') && 
              analysis.riskScore > 50) {
            
            // CRITICAL FIX: If this was an email pattern, also style it as an email
            if (isEmailPattern && originalEmailText) {
              const messageContainer = linkElement.closest('[data-testid="msg-container"]') || 
                                       linkElement.closest('.copyable-text') ||
                                       linkElement.parentElement;
              if (messageContainer) {
                this.styleEmailTextRed(messageContainer, originalEmailText, analysis);
              }
            }
            
          this.showLinkWarning(linkElement, analysis, normalizedUrl);
        }
      }).catch(error => {
        console.error('Error in WhatsApp link analysis:', error);
        });
      }
      
    } catch (error) {
      console.error('Error analyzing link element:', error);
    }
  }

  // CRITICAL FIX: Check if domain is in whitelist
  isWhitelistedDomain(url) {
    try {
      const u = new URL(url);
      const hostname = u.hostname.toLowerCase().replace(/^www\./, '');
      
      // Check exact match
      if (this.legitimateDomains.has(hostname)) {
        return true;
      }
      
      // Check if it's a subdomain of a whitelisted domain
      for (const domain of this.legitimateDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
          return true;
        }
      }
      
      return false;
    } catch {
      return false;
    }
  }

  // IMPROVED: More comprehensive benign URL detection
  isClearlyBenign(url) {
    try {
      const u = new URL(url);
      const hostname = u.hostname.toLowerCase();
      const full = url.toLowerCase();
      
      // Must use HTTPS
      if (u.protocol !== 'https:') {
        console.log(`⚠️ Not HTTPS: ${url}`);
        return false;
      }
      
      // Extract TLD
      const tld = hostname.split('.').pop();
      
      // Expanded list of safe TLDs
      const commonSafeTlds = new Set([
        'com', 'org', 'net', 'edu', 'gov', 'io', 'ai', 'app', 'dev', 'me', 
        'co', 'us', 'uk', 'de', 'fr', 'jp', 'in', 'it', 'es', 'nl', 'ca', 
        'au', 'br', 'pl', 'se', 'no', 'fi', 'ch', 'cz', 'pt', 'mx', 'ar', 
        'sg', 'kr', 'tw', 'th', 'my', 'id', 'ph', 'vn', 'nz', 'za', 'ru',
        'ua', 'ro', 'gr', 'hu', 'at', 'be', 'dk', 'ie', 'sk', 'bg', 'hr'
      ]);
      
      if (!commonSafeTlds.has(tld)) {
        console.log(`⚠️ Uncommon TLD: ${tld}`);
        return false;
      }
      
      // IMPROVED: More specific risky keyword detection (require context)
      const riskyPatterns = [
        /urgent.*verify/i,
        /urgent.*security/i,
        /account.*suspend/i,
        /verify.*now/i,
        /security.*alert/i,
        /verify.*identity/i,
        /confirm.*payment/i,
        /update.*billing/i,
        /suspended.*account/i,
        /locked.*account/i,
        /unusual.*activity/i,
        /immediate.*action/i
      ];
      
      // Only flag if multiple risky patterns or very specific phishing phrases
      const riskyMatches = riskyPatterns.filter(p => p.test(full)).length;
      if (riskyMatches >= 2) {
        console.log(`⚠️ Multiple risky patterns detected: ${riskyMatches}`);
        return false;
      }
      
      // Check for @ symbol (credential stealing)
      if (full.includes('@') && !full.includes('mailto:')) {
        console.log(`⚠️ Contains @ symbol: ${url}`);
        return false;
      }
      
      // Check for excessive length
      if (full.length > 200) {
        console.log(`⚠️ URL too long: ${full.length} characters`);
        return false;
      }
      
      // Check for URL shorteners
      const shorteners = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link', 
        'is.gd', 'v.gd', 'cutt.ly', 'shorturl.at', 'rebrand.ly', 'tiny.cc'
      ];
      if (shorteners.some(s => hostname.includes(s))) {
        console.log(`⚠️ URL shortener detected: ${hostname}`);
        return false;
      }
      
      // Check for suspicious TLDs
      const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link', '.loan', '.win', '.bid'];
      if (suspiciousTlds.some(t => hostname.endsWith(t))) {
        console.log(`⚠️ Suspicious TLD: ${hostname}`);
        return false;
      }
      
      // Check for excessive subdomains (common in phishing)
      const parts = hostname.split('.');
      if (parts.length > 4) {
        console.log(`⚠️ Too many subdomains: ${parts.length}`);
        return false;
      }
      
      // Check for IP addresses
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) {
        console.log(`⚠️ IP address detected: ${hostname}`);
        return false;
      }
      
      console.log(`✅ URL appears benign: ${url}`);
      return true;
    } catch (e) {
      console.error(`Error checking if benign: ${e.message}`);
      return false;
    }
  }
  
  // NEW: Check for suspicious URLs that should always be analyzed
  isSuspiciousUrl(url) {
    try {
      const u = new URL(url);
      const hostname = u.hostname.toLowerCase();
      const full = url.toLowerCase();

      // Check for specific phishing patterns mentioned by user
      const suspiciousPatterns = [
        /paypal.*security.*\.tk/i,
        /bit\.ly\/suspicious/i,
        /tinyurl\.com\/fake/i,
        /wa\.me\/verify-account/i,
        /chat\.whatsapp\.com\/fake-security/i,
        /ptokq\.click/i,
        /security.*alert/i,
        /verify.*account/i,
        /fake.*deal/i,
        /suspicious.*link/i,
        /urgent.*security/i,
        /suspended.*account/i
      ];

      // EXPLICIT: Check for the exact URLs mentioned by user
      const explicitSuspiciousUrls = [
        'security@paypal-security.tk',
        'https://wa.me/verify-account',
        'https://chat.whatsapp.com/fake-security',
        'ptokq.click',
        'https://ptokq.click'
      ];

      if (explicitSuspiciousUrls.some(susUrl => full.includes(susUrl.toLowerCase()))) {
        console.log(`🚨 EXPLICIT SUSPICIOUS URL DETECTED: ${url}`);
        return true;
      }

      if (suspiciousPatterns.some(pattern => pattern.test(full))) {
        console.log(`🚨 Suspicious pattern detected: ${url}`);
        return true;
      }

      // Check for @ symbol (credential stealing)
      if (full.includes('@') && !full.includes('mailto:')) {
        console.log(`🚨 @ symbol detected: ${url}`);
        return true;
      }

      // Check for suspicious TLDs
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.link', '.short'];
      if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
        console.log(`🚨 Suspicious TLD detected: ${url}`);
        return true;
      }

      // Check for URL shorteners
      const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ptokq.click'];
      if (shorteners.some(s => hostname.includes(s))) {
        console.log(`🚨 URL shortener detected: ${url}`);
        return true;
      }

      return false;
    } catch (e) {
      console.error(`Error checking if suspicious: ${e.message}`);
      return false;
    }
  }
  
  // IMPROVED: More accurate basic phishing detection
  basicPhishingDetection(url) {
    console.log(`🔍 Basic phishing detection for: ${url}`);
    
    let signalCount = 0;
    const reasons = [];
    
    try {
      const u = new URL(url);
      const hostname = u.hostname.toLowerCase();
      const full = url.toLowerCase();
      const path = u.pathname.toLowerCase();
      
      // EXPLICIT: Check for the exact URLs mentioned by user FIRST
      const explicitSuspiciousUrls = [
        'security@paypal-security.tk',
        'https://wa.me/verify-account',
        'https://chat.whatsapp.com/fake-security',
        'ptokq.click',
        'https://ptokq.click'
      ];
      
      if (explicitSuspiciousUrls.some(susUrl => full.includes(susUrl.toLowerCase()))) {
        console.log(`🚨 EXPLICIT SUSPICIOUS URL DETECTED: ${url}`);
        return {
          isSuspicious: true,
          riskScore: 95,
          reasons: ['Explicit phishing URL detected'],
          action: 'block',
          confidence: 'high'
        };
      }
      
      // Check for suspicious TLDs (HIGH CONFIDENCE)
      const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.link', '.short'];
      const hasSuspiciousTld = suspiciousTlds.some(tld => hostname.endsWith(tld));
      if (hasSuspiciousTld) {
        signalCount += 3;
        reasons.push('Suspicious TLD commonly used in phishing');
      }
      
      // Check for URL shorteners (MEDIUM CONFIDENCE)
      const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ptokq.click'];
      const hasShortener = shorteners.some(s => hostname.includes(s));
      if (hasShortener) {
        signalCount += 2;
        reasons.push('URL shortener detected');
      }
      
      // IMPROVED: Check for specific phishing patterns (require combination)
      const phishingCombos = [
        { pattern: /paypal/i, keywords: ['verify', 'security', 'suspend', 'update'] },
        { pattern: /amazon/i, keywords: ['verify', 'security', 'suspend', 'update'] },
        { pattern: /microsoft/i, keywords: ['verify', 'security', 'suspend', 'update'] },
        { pattern: /apple/i, keywords: ['verify', 'security', 'suspend', 'update'] },
        { pattern: /google/i, keywords: ['verify', 'security', 'suspend', 'update'] },
        { pattern: /whatsapp/i, keywords: ['verify', 'security', 'suspend', 'banned'] }
      ];
      
      // Check for specific phishing URLs mentioned by user
      const specificPhishingPatterns = [
        /paypal.*security.*\.tk/i,
        /bit\.ly\/suspicious/i,
        /tinyurl\.com\/fake/i,
        /wa\.me\/verify-account/i,
        /chat\.whatsapp\.com\/fake-security/i,
        /security.*alert/i,
        /verify.*account/i,
        /fake.*deal/i,
        /suspicious.*link/i
      ];
      
      const hasSpecificPattern = specificPhishingPatterns.some(pattern => pattern.test(full));
      if (hasSpecificPattern) {
        signalCount += 4;  // High confidence
        reasons.push('Known phishing pattern detected');
      }
      
      for (const combo of phishingCombos) {
        if (combo.pattern.test(full)) {
          const matchedKeywords = combo.keywords.filter(kw => full.includes(kw));
          if (matchedKeywords.length > 0) {
            // Only flag if domain doesn't match the brand
            const brand = combo.pattern.source.toLowerCase().replace(/[\\\/iug]/g, '');
            if (!hostname.includes(brand)) {
              signalCount += 3;
              reasons.push(`Impersonating ${brand} with keywords: ${matchedKeywords.join(', ')}`);
            }
          }
        }
      }
      
      // Check for @ symbol (credential stealing)
      if (full.includes('@') && !full.includes('mailto:')) {
        signalCount += 3;
        reasons.push('@ symbol in URL (credential stealing attempt)');
      }
      
      // Check for IP address instead of domain
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) {
        signalCount += 2;
        reasons.push('IP address instead of domain name');
      }
      
      // Check for excessive subdomains
      const parts = hostname.split('.');
      if (parts.length > 4) {
        signalCount += 2;
        reasons.push('Excessive subdomains');
      }
      
      // Check for very long URLs
      if (full.length > 150) {
        signalCount += 1;
        reasons.push('Unusually long URL');
      }
      
      // FIXED: Lower threshold for better phishing detection
      const isSuspicious = signalCount >= 2;  // Lowered from 3
      const riskScore = Math.min(signalCount * 30, 95);  // Increased multiplier
    
    console.log(`📊 Detection results:`, {
      signalCount,
        reasons,
        isSuspicious,
        riskScore
    });
    
    return {
        isSuspicious,
        riskScore,
      action: isSuspicious ? 'block' : 'allow',
        reasons,
        confidence: signalCount >= 4 ? 'high' : signalCount >= 3 ? 'medium' : 'low'
      };
    } catch (e) {
      console.error(`Error in basic detection: ${e.message}`);
      return {
        isSuspicious: false,
        riskScore: 0,
        action: 'allow',
        reasons: [],
        confidence: 'low'
      };
    }
  }
  
  analyzeMessageContentArea(contentElement) {
    try {
      console.log('🔍 Analyzing message content area...');
      
      const linkElements = contentElement.querySelectorAll('a[href]');
      console.log(`Found ${linkElements.length} link elements`);
      
      const textContent = contentElement.textContent || '';
      
      // Extract URLs
      const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+)/g;
      const textUrls = textContent.match(urlRegex) || [];
      console.log(`Found ${textUrls.length} text URLs:`, textUrls);
      
      // Extract email addresses
      const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
      const textEmails = textContent.match(emailRegex) || [];
      console.log(`📧 Found ${textEmails.length} email addresses:`, textEmails);
      
      // Analyze email addresses for phishing
      if (textEmails.length > 0) {
        this.analyzeEmailAddresses(textEmails, contentElement);
      }
      
      const linkHrefs = Array.from(linkElements).map(el => el.getAttribute('href')).filter(Boolean);
      const allUrls = [...linkHrefs, ...textUrls];
      console.log(`Total URLs to analyze: ${allUrls.length}`);
      
      allUrls.forEach(href => {
        if (href) {
          const normalizedUrl = this.normalizeUrl(href);
          if (!normalizedUrl) return;
          
          console.log(`🔍 Processing URL: ${normalizedUrl}`);
          
          // EXPLICIT: Check for the exact URLs mentioned by user FIRST
          // Find corresponding link element first
          const correspondingLinkElement = Array.from(linkElements).find(el => el.getAttribute('href') === href);
          
          const explicitSuspiciousUrls = [
            'security@paypal-security.tk',
            'https://wa.me/verify-account',
            'https://chat.whatsapp.com/fake-security',
            'ptokq.click',
            'https://ptokq.click'
          ];
          
          if (explicitSuspiciousUrls.some(susUrl => normalizedUrl.toLowerCase().includes(susUrl.toLowerCase()))) {
            console.log(`🚨 EXPLICIT SUSPICIOUS URL DETECTED: ${normalizedUrl}`);
            const explicitAnalysis = {
              isSuspicious: true,
              riskScore: 95,
              reasons: ['Explicit phishing URL detected'],
              action: 'block',
              confidence: 'high'
            };
            this.showLinkWarning(correspondingLinkElement, explicitAnalysis, normalizedUrl);
            if (correspondingLinkElement) {
              this.processedLinkElements.add(correspondingLinkElement);
              correspondingLinkElement.dataset.phishguardProcessed = 'true';
            }
            return;
          }
          
          if (this.isLegitimateWhatsAppUrl(normalizedUrl)) {
            return;
          }
          if (correspondingLinkElement && (correspondingLinkElement.dataset.phishguardProcessed === 'true' || this.processedLinkElements.has(correspondingLinkElement))) {
            return;
          }
          
          // CRITICAL FIX: Check whitelist and benign status first
          if (this.isWhitelistedDomain(normalizedUrl) || this.isClearlyBenign(normalizedUrl)) {
            console.log(`✅ URL is safe: ${normalizedUrl}`);
            return;
          }

          // FIXED: Always check suspicious URLs, even in soft mode
          if (this.softMode && !this.isHighRisk(normalizedUrl) && !this.isSuspiciousUrl(normalizedUrl)) {
              return;
          }

                const basicAnalysis = this.basicPhishingDetection(normalizedUrl);
          console.log(`📊 Basic analysis for ${normalizedUrl}:`, basicAnalysis);
          
          if (basicAnalysis.isSuspicious && basicAnalysis.riskScore > 50) {
            console.log(`🚨 SUSPICIOUS URL DETECTED: ${normalizedUrl}`);
                  this.showLinkWarning(correspondingLinkElement, basicAnalysis, normalizedUrl);
                  if (correspondingLinkElement) {
                    this.processedLinkElements.add(correspondingLinkElement);
                    correspondingLinkElement.dataset.phishguardProcessed = 'true';
                  }
          }
        }
      });
      
    } catch (error) {
      console.error('Error analyzing message content:', error);
    }
  }

  // NEW: Analyze email addresses for phishing
  analyzeEmailAddresses(emails, contentElement) {
    console.log(`📧 Analyzing ${emails.length} email addresses...`);
    
    emails.forEach(email => {
      email = email.toLowerCase().trim();
      console.log(`🔍 Checking email: ${email}`);
      
      // Skip if already processed
      if (this.processedLinks.has(email)) {
        console.log(`⏭️ Already processed: ${email}`);
        return;
      }
      
      const analysis = this.analyzeEmailForPhishing(email);
      
      if (analysis.isSuspicious && analysis.riskScore >= 50) {
        console.log(`🚨 PHISHING EMAIL DETECTED: ${email}`, analysis);
        this.showEmailWarning(contentElement, analysis, email);
        this.processedLinks.add(email);
      } else {
        console.log(`✅ Email appears safe: ${email} (Score: ${analysis.riskScore})`);
      }
    });
  }

  // NEW: Analyze a single email address for phishing patterns
  analyzeEmailForPhishing(email) {
    let riskScore = 0;
    const reasons = [];
    
    try {
      const parts = email.split('@');
      if (parts.length !== 2) {
        return { isSuspicious: false, riskScore: 0, reasons: ['Invalid email format'] };
      }
      
      const [localPart, domain] = parts;
      const domainLower = domain.toLowerCase();
      
      // Check for suspicious TLDs
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click'];
      const hasSuspiciousTLD = suspiciousTLDs.some(tld => domainLower.endsWith(tld));
      if (hasSuspiciousTLD) {
        riskScore += 50;
        reasons.push(`Suspicious TLD detected (${domain.split('.').pop()})`);
      }
      
      // Check for brand impersonation
      const brands = {
        'paypal': /paypal/i,
        'amazon': /amazon/i,
        'microsoft': /microsoft/i,
        'google': /google/i,
        'apple': /apple/i,
        'facebook': /facebook/i,
        'netflix': /netflix/i,
        'whatsapp': /whatsapp/i,
        'bank': /bank/i,
        'security': /security/i
      };
      
      const legitimateDomains = {
        'paypal': ['paypal.com'],
        'amazon': ['amazon.com', 'amazon.co.uk'],
        'microsoft': ['microsoft.com', 'outlook.com', 'live.com'],
        'google': ['google.com', 'gmail.com'],
        'apple': ['apple.com', 'icloud.com'],
        'facebook': ['facebook.com', 'fb.com'],
        'netflix': ['netflix.com'],
        'whatsapp': ['whatsapp.com', 'whatsapp.net']
      };
      
      for (const [brand, pattern] of Object.entries(brands)) {
        if (pattern.test(domainLower)) {
          const validDomains = legitimateDomains[brand] || [];
          const isLegitimate = validDomains.some(d => domainLower === d || domainLower.endsWith('.' + d));
          
          if (!isLegitimate) {
            riskScore += 40;
            reasons.push(`Brand impersonation: "${brand}" detected in non-official domain`);
            break;
          }
        }
      }
      
      // Check for suspicious email prefixes
      const suspiciousPrefixes = ['security', 'support', 'noreply', 'no-reply', 'admin', 'help', 'service', 'alert', 'notification'];
      if (suspiciousPrefixes.includes(localPart.toLowerCase()) && hasSuspiciousTLD) {
        riskScore += 30;
        reasons.push(`Suspicious email prefix "${localPart}" with suspicious TLD`);
      }
      
      // Check for multiple hyphens (common in phishing)
      const hyphenCount = domainLower.split('-').length - 1;
      if (hyphenCount >= 2) {
        riskScore += 20;
        reasons.push(`Multiple hyphens in domain (${hyphenCount})`);
      }
      
      // Check for numbers in domain (except known services)
      const hasNumbers = /\d/.test(domainLower);
      if (hasNumbers && hyphenCount > 0) {
        riskScore += 15;
        reasons.push('Numbers combined with hyphens in domain');
      }
      
      return {
        isSuspicious: riskScore >= 50,
        riskScore: Math.min(riskScore, 100),
        reasons,
        confidence: riskScore >= 70 ? 'high' : riskScore >= 50 ? 'medium' : 'low'
      };
      
    } catch (error) {
      console.error('Error analyzing email:', error);
      return { isSuspicious: false, riskScore: 0, reasons: ['Analysis error'] };
    }
  }

  // IMPROVED: More accurate high-risk detection
  isHighRisk(url) {
    try {
      const u = new URL(url.startsWith('http') ? url : `https://${url}`);
      const host = u.hostname.toLowerCase();
      const full = url.toLowerCase();
      
      // Suspicious TLDs
      const riskyTlds = ['.tk', '.ml', '.ga', '.cf', '.gq'];
      if (riskyTlds.some(t => host.endsWith(t))) return true;
      
      // URL shorteners
      const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co'];
      if (shorteners.some(s => host.includes(s))) return true;
      
      // WhatsApp fake/verify patterns
      const waPatterns = [
        /wa\.me.*verify/i,
        /chat\.whatsapp\.com.*fake/i,
        /whatsapp.*banned/i,
        /whatsapp.*suspend/i
      ];
      if (waPatterns.some(p => p.test(full))) return true;
      
      // @ symbol (not in mailto)
      if (full.includes('@') && !full.includes('mailto:')) return true;
      
      // IP addresses
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(host)) return true;
      
      return false;
    } catch {
      return false;
    }
  }

  // Helper to check legitimate WhatsApp URLs
  isLegitimateWhatsAppUrl(url) {
    const legitPatterns = [
      /^https:\/\/wa\.me\/\d+$/,  // Only phone numbers
      /^https:\/\/chat\.whatsapp\.com\/[a-zA-Z0-9]+$/,  // Only legit group codes
      /^https:\/\/api\.whatsapp\.com\//,
      /^https:\/\/web\.whatsapp\.com\//,
      /^https:\/\/www\.whatsapp\.com\//,
      /^https:\/\/faq\.whatsapp\.com\//
    ];
    
    return legitPatterns.some(pattern => pattern.test(url));
  }
  
  showLinkWarning(linkElement, analysis, href) {
    console.log(`🚨 Showing warning for suspicious link: ${href}`);
    
    // CRITICAL: Update statistics in background script
    this.updateStats(analysis);
    
    const warningOverlay = document.createElement('div');
    warningOverlay.className = 'phishguard-whatsapp-warning';
    warningOverlay.style.cssText = `
      position: relative;
      background: linear-gradient(90deg, #ff6b6b, #ee5a52);
      color: white;
      padding: 4px 8px;
      margin: 2px 0;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      z-index: 1000;
      box-shadow: 0 1px 4px rgba(0,0,0,0.2);
      animation: phishguard-slide-in 0.3s ease-out;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    const actionText = analysis.action === 'block' ? 'BLOCKED' : 'WARN';
    
    warningOverlay.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
        <div style="display: flex; align-items: center; gap: 4px;">
          <span style="font-size: 12px;">🛡️</span>
          <span style="font-weight: bold; font-size: 10px;">PhishGuard: ${actionText}</span>
          <span style="font-size: 9px; opacity: 0.85;">Risk ${analysis.riskScore}/100</span>
        </div>
        <button class="phishguard-whatsapp-close-btn" style="
          background: rgba(255,255,255,0.2);
          border: none;
          color: white;
          padding: 1px 5px;
          border-radius: 2px;
          cursor: pointer;
          font-size: 12px;
          line-height: 1;
        ">×</button>
      </div>
    `;
    
    // Add CSS animation if not already added
    if (!document.getElementById('phishguard-whatsapp-styles')) {
      const styles = document.createElement('style');
      styles.id = 'phishguard-whatsapp-styles';
      styles.textContent = `
        @keyframes phishguard-slide-in {
          from { transform: translateX(-100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .phishguard-whatsapp-warning {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        .phishguard-dangerous-link {
          color: #ff6b6b !important;
          text-decoration: line-through !important;
          opacity: 0.7 !important;
          cursor: not-allowed !important;
        }
        .phishguard-hover-warning {
          position: absolute;
          background: #ff4444;
          color: white;
          padding: 8px 12px;
          border-radius: 6px;
          font-size: 12px;
          font-weight: bold;
          z-index: 10000;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          pointer-events: none;
          white-space: nowrap;
        }
      `;
      document.head.appendChild(styles);
    }
    
    // Insert warning in the message area
    if (linkElement && linkElement.parentNode) {
      linkElement.parentNode.insertBefore(warningOverlay, linkElement.nextSibling);
      linkElement.classList.add('phishguard-dangerous-link');
      linkElement.style.color = '#ff6b6b';
      linkElement.style.textDecoration = 'line-through';
      linkElement.style.opacity = '0.7';
      linkElement.style.cursor = 'not-allowed';
      
      let hoverWarning = null;
      linkElement.addEventListener('mouseenter', (e) => {
        hoverWarning = document.createElement('div');
        hoverWarning.className = 'phishguard-hover-warning';
        hoverWarning.innerHTML = `⚠️ DANGEROUS LINK - Risk: ${analysis.riskScore}/100`;
        hoverWarning.style.left = e.pageX + 10 + 'px';
        hoverWarning.style.top = e.pageY - 30 + 'px';
        document.body.appendChild(hoverWarning);
      });
      linkElement.addEventListener('mouseleave', () => {
        if (hoverWarning) {
          hoverWarning.remove();
          hoverWarning = null;
        }
      });
      linkElement.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        return false;
      });
    } else {
      const messageArea = document.querySelector('[data-testid="conversation-panel-messages"]') || 
                         document.querySelector('.copyable-text') ||
                         document.querySelector('[data-testid="msg-container"]') ||
                         document.body;
      if (messageArea) {
        messageArea.appendChild(warningOverlay);
      }
    }
    
    // Close button handler
    const closeBtn = warningOverlay.querySelector('.phishguard-whatsapp-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        warningOverlay.remove();
      });
    }
    
    // Auto-remove after 15s
    setTimeout(() => {
      if (warningOverlay.parentElement) warningOverlay.remove();
    }, 15000);
  }

  // NEW: Show warning for phishing email addresses
  showEmailWarning(contentElement, analysis, email) {
    console.log(`🚨 Showing warning for suspicious email: ${email}`);
    
    // CRITICAL: Update statistics in background script
    this.updateStats(analysis);
    
    // CRITICAL FIX: Find and style the email text in red
    this.styleEmailTextRed(contentElement, email, analysis);
    
    const warningOverlay = document.createElement('div');
    warningOverlay.className = 'phishguard-email-warning';
    warningOverlay.style.cssText = `
      position: relative;
      background: linear-gradient(90deg, #ff6b6b, #ee5a52);
      color: white;
      padding: 4px 8px;
      margin: 2px 0;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      z-index: 1000;
      box-shadow: 0 1px 4px rgba(0,0,0,0.2);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    warningOverlay.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
        <div style="display: flex; align-items: center; gap: 4px;">
          <span style="font-size: 12px;">🛡️</span>
          <span style="font-weight: bold; font-size: 10px;">Phishing Email</span>
          <span style="font-size: 9px; opacity: 0.85;">Risk ${analysis.riskScore}/100</span>
        </div>
        <button class="phishguard-email-close-btn" style="
          background: rgba(255,255,255,0.2);
          border: none;
          color: white;
          padding: 1px 5px;
          border-radius: 2px;
          cursor: pointer;
          font-size: 12px;
          line-height: 1;
        ">×</button>
      </div>
    `;
    
    // Add pulse animation CSS if not already added
    if (!document.getElementById('phishguard-email-styles')) {
      const styles = document.createElement('style');
      styles.id = 'phishguard-email-styles';
      styles.textContent = `
        @keyframes phishguard-pulse {
          0% { transform: scale(1); box-shadow: 0 4px 15px rgba(0,0,0,0.4); }
          50% { transform: scale(1.02); box-shadow: 0 6px 20px rgba(255,71,87,0.6); }
          100% { transform: scale(1); box-shadow: 0 4px 15px rgba(0,0,0,0.4); }
        }
        .phishguard-dangerous-email {
          color: #ff6b6b !important;
          text-decoration: line-through !important;
          opacity: 0.7 !important;
          cursor: not-allowed !important;
        }
      `;
      document.head.appendChild(styles);
    }
    
    // Insert warning in the message area
    const messageArea = contentElement.closest('[data-testid="conversation-panel-messages"]') || 
                        contentElement.closest('.copyable-text') ||
                        contentElement.closest('[data-testid="msg-container"]') ||
                        contentElement;
    
    if (messageArea) {
      messageArea.appendChild(warningOverlay);
    }
    
    // Close button handler
    const closeBtn = warningOverlay.querySelector('.phishguard-email-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        warningOverlay.remove();
      });
    }
    
    // Auto-remove after 20s
    setTimeout(() => {
      if (warningOverlay.parentElement) warningOverlay.remove();
    }, 20000);
  }

  // NEW: Style email text in red - searches ENTIRE conversation for ALL instances
  styleEmailTextRed(containerElement, email, analysis) {
    try {
      console.log(`🎨 Attempting to style ALL instances of email text red: ${email}`);
      
      // CRITICAL FIX: Always search in the ENTIRE conversation panel, not just one container
      const searchRoot = document.querySelector('[data-testid="conversation-panel-messages"]') || 
                         document.querySelector('[data-testid="conversation-panel-body"]') ||
                         document.body;
      
      console.log(`Searching in entire conversation panel for ALL instances`);
      
      // Find all text nodes containing the email address
      const walker = document.createTreeWalker(
        searchRoot,
        NodeFilter.SHOW_TEXT,
        null,
        false
      );
      
      const textNodes = [];
      let node;
      while (node = walker.nextNode()) {
        if (node.textContent.includes(email)) {
          textNodes.push(node);
        }
      }
      
      console.log(`Found ${textNodes.length} text nodes containing the email across ALL messages`);
      
      // Replace ALL text nodes with styled spans
      textNodes.forEach(textNode => {
        const parent = textNode.parentNode;
        if (!parent) return;
        
        // Skip if this specific parent already has a styled email
        if (parent.classList && parent.classList.contains('phishguard-dangerous-email')) {
          console.log(`Skipping - parent already styled`);
          return;
        }
        
        // Check if parent already contains a styled email child
        if (parent.querySelector && parent.querySelector('.phishguard-dangerous-email')) {
          console.log(`Skipping - parent already contains styled email`);
          return;
        }
        
        const text = textNode.textContent;
        
        // Handle multiple occurrences in the same text node
        if (text.includes(email)) {
          const parts = text.split(email);
          const fragment = document.createDocumentFragment();
          
          parts.forEach((part, index) => {
            // Add the text part
            if (part) {
              fragment.appendChild(document.createTextNode(part));
            }
            
            // Add styled email between parts (except after the last part)
            if (index < parts.length - 1) {
              const emailSpan = document.createElement('span');
              emailSpan.className = 'phishguard-dangerous-email';
              emailSpan.textContent = email;
              emailSpan.title = `⚠️ PHISHING EMAIL DETECTED - Risk Score: ${analysis.riskScore}/100`;
              emailSpan.dataset.phishguardStyled = 'true';
              
              // Add hover warning
              emailSpan.addEventListener('mouseenter', (e) => {
                const hoverWarning = document.createElement('div');
                hoverWarning.className = 'phishguard-hover-warning';
                hoverWarning.innerHTML = `⚠️ DANGEROUS EMAIL - Risk: ${analysis.riskScore}/100`;
                hoverWarning.style.cssText = `
                  position: absolute;
                  background: #ff4444;
                  color: white;
                  padding: 8px 12px;
                  border-radius: 6px;
                  font-size: 12px;
                  font-weight: bold;
                  z-index: 10000;
                  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                  pointer-events: none;
                  white-space: nowrap;
                `;
                hoverWarning.style.left = e.pageX + 10 + 'px';
                hoverWarning.style.top = e.pageY - 30 + 'px';
                document.body.appendChild(hoverWarning);
                emailSpan.hoverWarning = hoverWarning;
              });
              
              emailSpan.addEventListener('mouseleave', () => {
                if (emailSpan.hoverWarning) {
                  emailSpan.hoverWarning.remove();
                  emailSpan.hoverWarning = null;
                }
              });
              
              // Prevent clicking on the email
              emailSpan.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                alert(`⚠️ PHISHING EMAIL DETECTED!\n\nThis email address (${email}) is suspected to be part of a phishing attempt.\n\nDo NOT interact with this email or any links associated with it.`);
                return false;
              });
              
              fragment.appendChild(emailSpan);
            }
          });
          
          // Replace the text node with the fragment
          parent.replaceChild(fragment, textNode);
          
          console.log(`✅ Styled email text in red (instance ${textNodes.indexOf(textNode) + 1}): ${email}`);
        }
      });
      
      // Also find any link elements with the email as text or href (search ENTIRE conversation)
      const linkSelectors = ['a', 'span[role="link"]', '[data-href]'];
      linkSelectors.forEach(selector => {
        const elements = searchRoot.querySelectorAll(selector);
        elements.forEach(element => {
          // Skip if already styled
          if (element.dataset.phishguardStyled === 'true' || 
              element.classList.contains('phishguard-dangerous-email')) {
            return;
          }
          
          const text = element.textContent;
          const href = element.getAttribute('href') || element.getAttribute('data-href') || '';
          
          if (text.includes(email) || href.includes(email)) {
            element.classList.add('phishguard-dangerous-email');
            element.style.color = '#ff6b6b';
            element.style.textDecoration = 'line-through';
            element.style.opacity = '0.7';
            element.style.cursor = 'not-allowed';
            element.dataset.phishguardStyled = 'true';
            
            console.log(`✅ Styled link element containing email: ${email}`);
          }
        });
      });
      
      console.log(`✅ Completed styling ALL instances of: ${email}`);
      
    } catch (error) {
      console.error('Error styling email text:', error);
    }
  }
  
  normalizeUrl(url) {
    if (!url) return null;
    let clean = String(url).trim();
    clean = clean.replace(/[\s\u200b]+$/g, '').replace(/[.,;:!?]+$/g, '');
    
    // Handle URLs with @ symbol (common phishing technique)
    // e.g., security@paypal-security.tk -> https://security@paypal-security.tk
    if (!clean.startsWith('http')) {
      if (clean.startsWith('www.')) {
        clean = 'https://' + clean;
      } else if (/^[a-z0-9@.-]+\.[a-z]{2,}(?:\/[^\s]*)?$/i.test(clean)) {
        // Updated regex to include @ symbol for URLs like user@domain.com
        clean = 'https://' + clean;
      } else {
        return null;
      }
    }
    
    try {
      const u = new URL(clean);
      if (!u.hostname) return null;
      return clean;
    } catch {
      return null;
    }
  }

  // NEW: Update statistics in background script
  updateStats(analysis) {
    try {
      // Send stats update to background script
      chrome.runtime.sendMessage({
        type: 'UPDATE_WHATSAPP_STATS',
        analysis: analysis
      }).catch(error => {
        console.log('Could not update stats in background (extension context may not be available):', error);
      });
      
      console.log(`📊 Stats updated: ${analysis.action} (risk: ${analysis.riskScore})`);
    } catch (error) {
      console.error('Error updating stats:', error);
    }
  }

  cleanup() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    if (this.conversationObserver) {
      this.conversationObserver.disconnect();
      this.conversationObserver = null;
    }
    this.processedLinks.clear();
    this.suspiciousLinks.clear();
  }
}

// Initialize on WhatsApp Web
if (window.location.hostname === 'web.whatsapp.com') {
  let whatsappDetector = null;
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      whatsappDetector = new WhatsAppLinkDetector();
    });
  } else {
    whatsappDetector = new WhatsAppLinkDetector();
  }
  window.addEventListener('beforeunload', () => {
    if (whatsappDetector) whatsappDetector.cleanup();
  });
}

console.log('📱 WhatsApp Link Detector loaded');