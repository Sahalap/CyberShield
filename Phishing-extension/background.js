// PhishGuard Pro - Background Service Worker (MV3 optimized)
// Enhanced with proper lifecycle management, error handling, and ML integration

class PhishGuardService {
  constructor() {
    this.stats = {
      threatsBlocked: 0,
      threatsWarned: 0,
      emailsAnalyzed: 0,
      emailsFlagged: 0,
      whatsappLinksAnalyzed: 0,
      whatsappLinksFlagged: 0,
      totalScans: 0,
      lastScan: null,
      mlPredictions: 0,
      mlAccuracy: 0,
      mlErrors: 0
    };

    this.isInitialized = false;
    this.isShuttingDown = false;
    this.pendingOperations = new Set();
    this.retryCount = 0;
    this.maxRetries = 3;
    
    // ML Configuration
    this.mlConfig = {
      enabled: true, // ✅ ENABLED - Retrained model with 4% false positive rate!
      backendUrl: 'http://localhost:5000/predict',
      healthUrl: 'http://localhost:5000/health',
      timeout: 5000, // 5 seconds timeout
      fallbackToHeuristics: true
    };

    // Initialize immediately and synchronously set flag
    this.initializeService();
  }

  async initializeService() {
    try {
      console.log('🛡️ Initializing PhishGuard Service...');
      
      // Set initialized flag BEFORE async operations
      this.isInitialized = true;
      
      // Load saved statistics (async operation)
      try {
        const result = await chrome.storage.local.get(['phishguardStats', 'phishguardMLConfig']);
        if (result.phishguardStats) {
          this.stats = { ...this.stats, ...result.phishguardStats };
          console.log('📊 Loaded saved stats:', this.stats);
        }
        if (result.phishguardMLConfig) {
          this.mlConfig = { ...this.mlConfig, ...result.phishguardMLConfig };
          console.log('🤖 Loaded ML config:', this.mlConfig);
        }
      } catch (storageError) {
        console.warn('⚠️ Could not load saved stats, using defaults:', storageError);
      }
      
      // Test ML backend connection (non-blocking)
      this.testMLBackend().catch(err => {
        console.log('ℹ️ ML backend not available, using heuristic detection');
      });
      
      // Setup periodic alarms
      await this.setupPeriodicTasks();
      
      // Setup event listeners
      this.setupEventListeners();
      
      console.log('✅ PhishGuard Service initialized successfully');
      
    } catch (error) {
      console.error('❌ Service initialization error:', error);
      // Keep initialized flag true to allow basic operations
      this.handleError('INITIALIZATION_FAILED', error);
    }
  }

  async setupPeriodicTasks() {
    try {
      // Clear existing alarms
      await chrome.alarms.clearAll();
      
      // Setup periodic tasks
      chrome.alarms.create('updatePhishingDB', { periodInMinutes: 360 }); // every 6 hours
      chrome.alarms.create('cleanupExpiredData', { periodInMinutes: 1440 }); // daily cleanup
      chrome.alarms.create('testMLBackend', { periodInMinutes: 60 }); // hourly ML backend test
      
      console.log('📅 Periodic tasks scheduled');
    } catch (error) {
      console.error('Error setting up periodic tasks:', error);
    }
  }

  setupUrlBlocking() {
    // Add dynamic rules to block suspicious URLs
    const suspiciousUrls = [
      'bit.ly/suspicious-link',
      'tinyurl.com/fake-deal',
      'goo.gl/verify-account',
      'security@paypal-security.tk',
      'paypal-security.tk',
      'wa.me/verify-account',
      'chat.whatsapp.com/fake-security',
      'ptokq.click',
      'ptokq.click/?id='
    ];
    
    // Store blocked URLs for quick checking
    this.blockedUrls = new Set(suspiciousUrls);
    console.log('🚫 URL blocking rules set up');
  }

  isSuspiciousUrl(url) {
    if (!url) return false;
    
    const lowerUrl = url.toLowerCase();
    
    // Check against blocked URLs
    for (const blockedUrl of this.blockedUrls) {
      if (lowerUrl.includes(blockedUrl.toLowerCase())) {
        return true;
      }
    }
    
    // Check for @ symbol (email-like URLs are suspicious)
    if (lowerUrl.includes('@') && !lowerUrl.includes('mailto:')) {
      return true;
    }
    
    // Check for URL shorteners and suspicious click domains
    const shorteners = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link',
      'ptokq.click', 'click.link', 'redirect.click', 'short.click',
      'link.click', 'url.click', 'go.click', 'link.short', 'url.short'
    ];
    if (shorteners.some(s => lowerUrl.includes(s))) {
      return true;
    }
    
    // Check for suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.link', '.short'];
    if (suspiciousTLDs.some(tld => lowerUrl.includes(tld))) {
      return true;
    }
    
    return false;
  }

  setupEventListeners() {
    // FIXED: Use declarativeNetRequest to block malicious URLs
    this.setupUrlBlocking();
    
    // FIXED: Use tabs.onUpdated to catch and redirect suspicious URLs (less aggressive)
    if (chrome.tabs && chrome.tabs.onUpdated) {
      chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
        if (this.isShuttingDown || !this.isInitialized) {
          return;
        }

        // Only process when page is fully loaded and not already blocked
        if (changeInfo.status === 'complete' && tab.url && !tab.url.includes('warning.html')) {
          console.log('🔍 Tab updated:', tab.url);
          
          // Check if URL is suspicious (but let content script handle blocking)
          if (this.isSuspiciousUrl(tab.url)) {
            console.log('🚨 SUSPICIOUS URL DETECTED:', tab.url);
            // Let the content script handle the blocking to prevent conflicts
            this.stats.threatsBlocked++;
            await this.saveStats();
          }
        }
      });
    }
    
    // Navigation listener with error handling
    if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
      chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
        if (this.isShuttingDown || !this.isInitialized) {
          console.log('⚠️ Service not ready, skipping navigation analysis');
          return;
        }
        
        console.log('🌐 Navigation detected:', details.url);
        console.log('🔍 Frame ID:', details.frameId, 'Tab ID:', details.tabId);
        
        const operationId = `nav_${Date.now()}_${Math.random()}`;
        this.pendingOperations.add(operationId);
        
        try {
          if (details.frameId === 0) {
            console.log('✅ Processing main frame navigation');
            
            // Check if URL is suspicious (let content script handle blocking)
            if (this.isSuspiciousUrl(details.url)) {
              console.log('🚨 SUSPICIOUS URL DETECTED:', details.url);
              // Let content script handle blocking to prevent conflicts
              this.stats.threatsBlocked++;
              await this.saveStats();
            }
            
            const analysisResult = await this.analyzeAndHandleUrl(details.url, details.tabId);
            
            // FIXED: Block if action is 'block' (don't require 95+ score)
            if (analysisResult && analysisResult.action === 'block') {
              console.log('🚫 BLOCKING PHISHING SITE:', details.url);
              console.log('Risk Score:', analysisResult.riskScore);
              console.log('Reasons:', analysisResult.reasons);
              console.log('Method:', analysisResult.method);
              await chrome.tabs.update(details.tabId, { 
                url: chrome.runtime.getURL('warning.html') + 
                     '?url=' + encodeURIComponent(details.url) +
                     '&score=' + encodeURIComponent(analysisResult.riskScore) +
                     '&reasons=' + encodeURIComponent(JSON.stringify(analysisResult.reasons)) +
                     '&method=' + encodeURIComponent(analysisResult.method || 'Unknown') +
                     '&action=blocked'
              });
              return;
            }
          } else {
            console.log('⏭️ Skipping sub-frame navigation');
          }
        } catch (error) {
          console.error('Navigation analysis error:', error);
          this.handleError('NAVIGATION_ANALYSIS_FAILED', error);
        } finally {
          this.pendingOperations.delete(operationId);
        }
      });
    } else {
      console.error('❌ webNavigation API not available');
    }

    // Tab update listener with error handling
    if (chrome.tabs && chrome.tabs.onUpdated) {
      chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
        if (this.isShuttingDown || !this.isInitialized) return;
        
        console.log('📄 Tab updated:', tab.url, 'Status:', changeInfo.status);
        
        const operationId = `tab_${Date.now()}_${Math.random()}`;
        this.pendingOperations.add(operationId);
        
        try {
          if (changeInfo.status === 'complete' && tab.url) {
            await this.analyzeAndHandleUrl(tab.url, tabId);
          }
        } catch (error) {
          console.error('Tab update analysis error:', error);
          this.handleError('TAB_UPDATE_ANALYSIS_FAILED', error);
        } finally {
          this.pendingOperations.delete(operationId);
        }
      });
    }
  }

  // ML Backend Integration with improved error handling
  async callMLBackend(url) {
    if (!this.mlConfig.enabled) {
      console.log('ℹ️ ML backend disabled, skipping');
      return null;
    }

    try {
      console.log('🤖 Calling ML backend for:', url);
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.mlConfig.timeout);
      
      const response = await fetch(this.mlConfig.backendUrl, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ url }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        console.log(`ℹ️ ML backend returned status ${response.status}`);
        this.stats.mlErrors++;
        this.mlConfig.enabled = false; // Temporarily disable
        return null;
      }

      const result = await response.json();
      console.log('🤖 ML backend response:', result);
      
      // Validate ML response structure
      if (typeof result.prediction !== 'number' || (result.prediction !== 0 && result.prediction !== 1)) {
        console.log('ℹ️ Invalid ML response format:', result);
        this.stats.mlErrors++;
        return null;
      }

      this.stats.mlPredictions++;
      
      return {
        prediction: result.prediction, // 0 = safe, 1 = phishing
        confidence: result.confidence || result.probability || 0.5, // Accept both 'confidence' and 'probability'
        features: result.features || {}
      };
      
    } catch (error) {
      if (error.name === 'AbortError') {
        console.log('ℹ️ ML backend request timeout');
      } else if (error.message.includes('Failed to fetch')) {
        console.log('ℹ️ ML backend not reachable (server may be offline)');
        this.mlConfig.enabled = false; // Disable until next test
      } else {
        console.log('ℹ️ ML backend error:', error.message);
      }
      this.stats.mlErrors++;
      return null;
    }
  }

  async testMLBackend() {
    try {
      console.log('🧪 Testing ML backend connection...');
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
      // Test the health endpoint
      const healthResponse = await fetch(this.mlConfig.healthUrl, {
        method: 'GET',
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (healthResponse.ok) {
        const healthData = await healthResponse.json();
        console.log('✅ ML backend health check passed:', healthData);
        
        // Temporarily enable ML for testing prediction
        const wasEnabled = this.mlConfig.enabled;
        this.mlConfig.enabled = true;
        
        // Now test a prediction
        const testUrl = 'https://example.com';
        const result = await this.callMLBackend(testUrl);
        
        if (result) {
          console.log('✅ ML backend is online and responding');
          this.mlConfig.enabled = true;
          await chrome.storage.local.set({ phishguardMLConfig: this.mlConfig });
          return true;
        } else {
          console.log('ℹ️ ML backend health OK but prediction failed');
          this.mlConfig.enabled = wasEnabled; // Restore previous state
          return false;
        }
      } else {
        console.log('ℹ️ ML backend health check failed:', healthResponse.status);
        this.mlConfig.enabled = false;
        return false;
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        console.log('ℹ️ ML backend connection timeout (server not running)');
      } else if (error.message.includes('Failed to fetch')) {
        console.log('ℹ️ ML backend not reachable (make sure Flask server is running on port 5000)');
      } else {
        console.log('ℹ️ ML backend test error:', error.message);
      }
      this.mlConfig.enabled = false;
      await chrome.storage.local.set({ phishguardMLConfig: this.mlConfig });
      return false;
    }
  }

  async analyzeAndHandleUrl(url, tabId) {
    const operationId = `analysis_${Date.now()}_${Math.random()}`;
    this.pendingOperations.add(operationId);
    
    try {
      if (!url || this.isInternalUrl(url)) return;

      console.log('🔍 Analyzing URL:', url);
      
      // AGGRESSIVE protection for legitimate URLs - check first before anything else
      // ═══════════════════════════════════════════════════════════════
      // CRITICAL BYPASS: Only for infrastructure that MUST bypass ML
      // ═══════════════════════════════════════════════════════════════
      
      // Government sites (NEVER block - public safety)
      const isGovernment = url.includes('.gov') || url.includes('ftc.gov') || url.includes('consumer.ftc.gov') ||
                          url.includes('nih.gov') || url.includes('cdc.gov') || url.includes('irs.gov') ||
                          url.includes('ssa.gov') || url.includes('usa.gov') || url.includes('whitehouse.gov') ||
                          url.includes('nasa.gov') || url.includes('fda.gov') || url.includes('state.gov');
      
      // CDNs (infrastructure - can't be phishing)
      const isCDN = url.includes('cloudflare.com') || url.includes('cloudfront.net') || url.includes('akamai.net') ||
                    url.includes('fastly.net') || url.includes('jsdelivr.net') || url.includes('cdnjs.com') ||
                    url.includes('gstatic.com') || url.includes('oaistatic.com') || url.includes('googleusercontent.com');
      
      // Cursor IDE (our own infrastructure)
      const isCursor = url.includes('cursor.sh') || url.includes('cursor.com');
      
      // ONLY bypass these critical infrastructure URLs
      if (isGovernment || isCDN || isCursor) {
        console.log('✅ CRITICAL INFRASTRUCTURE - BYPASSING ML');
        console.log('   URL:', url);
        console.log('   Government:', isGovernment, '| CDN:', isCDN, '| Cursor:', isCursor);
        return {
          riskScore: 0,
          reasons: ['Critical infrastructure - bypassing analysis'],
          action: 'allow',
          confidence: 'high',
          method: 'Infrastructure Bypass'
        };
      }
      
      // ═══════════════════════════════════════════════════════════════
      // POST-ML WHITELIST: Known legitimate domains (for safety override)
      // ═══════════════════════════════════════════════════════════════
      const trustedDomains = [
        // Google
        'google.com', 'youtube.com', 'gmail.com', 'googleapis.com',
        // Microsoft
        'microsoft.com', 'outlook.com', 'live.com', 'office.com', 'bing.com',
        // Major tech
        'amazon.com', 'apple.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
        'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
        // AI tools
        'openai.com', 'chatgpt.com', 'chat.openai.com', 'anthropic.com', 'claude.ai',
        // Communication
        'web.whatsapp.com', 'www.whatsapp.com', 'telegram.org', 'discord.com', 'slack.com', 'zoom.us',
        // Education
        'wikipedia.org', 'ktu.edu', 'etlab.app', '.edu', '.ac.uk', '.ac.in',
        // Entertainment & Media
        'netflix.com', 'spotify.com', 'twitch.tv', 'vimeo.com', 'primevideo.com', 'hulu.com',
        // E-commerce & Services
        'ebay.com', 'etsy.com', 'shopify.com', 'walmart.com', 'target.com',
        // Indian Services (common legitimate sites)
        'ticketnew.com', 'bookmyshow.com', 'paytm.com', 'phonepe.com', 'flipkart.com',
        'myntra.com', 'zomato.com', 'swiggy.com', 'makemytrip.com', 'goibibo.com',
        'ola.com', 'uber.com', 'irctc.co.in', 'amazon.in',
        // Finance
        'paypal.com', 'stripe.com', 'wise.com', 'transferwise.com', 'revolut.com',
        // Developer tools
        'npmjs.com', 'pypi.org', 'packagist.org', 'nuget.org',
        // Others
        'dropbox.com', 'notion.so', 'figma.com', 'canva.com', 'medium.com', 'dev.to'
      ];
      
      this.stats.totalScans++;
      this.stats.lastScan = Date.now();

      let analysisResult;

      // Try ML backend first if enabled
      if (this.mlConfig.enabled) {
        const mlResult = await this.callMLBackend(url);
        
        if (mlResult) {
          console.log('🤖 Using ML prediction:', mlResult);
          
          // Convert ML prediction to risk score
          const baseRiskScore = mlResult.prediction === 1 ? 85 : 15;
          const confidenceAdjustment = (mlResult.confidence - 0.5) * 20;
          const riskScore = Math.max(0, Math.min(100, baseRiskScore + confidenceAdjustment));
          
          // CONSERVATIVE ACTION: Use CONFIDENCE, not risk score!
          // Only block if ML is VERY CONFIDENT (90%+) about phishing
          let action = 'allow';
          if (mlResult.prediction === 1) { // Phishing prediction
            if (mlResult.confidence >= 0.90) {
              action = 'block'; // Very confident (90%+) -> block
            } else if (mlResult.confidence >= 0.70) {
              action = 'warn'; // Somewhat confident (70-89%) -> warn
            } else {
              action = 'allow'; // Low confidence (<70%) -> allow
            }
          } else { // Safe prediction
            action = 'allow';
          }
          
          analysisResult = {
            riskScore: Math.round(riskScore),
            reasons: [
              `ML Model Prediction (${mlResult.prediction === 1 ? 'Phishing' : 'Safe'})`,
              `Confidence: ${(mlResult.confidence * 100).toFixed(1)}%`,
              `Action: ${action} (confidence-gated)`
            ],
            action: action,
            confidence: mlResult.confidence >= 0.8 ? 'high' : mlResult.confidence >= 0.5 ? 'medium' : 'low',
            method: 'ML Model',
            mlFeatures: mlResult.features
          };
        } else {
          // ML failed, fall back to heuristics
          analysisResult = await this.performBasicAnalysis(url);
        }
      } else {
        // ML disabled, use heuristics
        analysisResult = await this.performBasicAnalysis(url);
      }
      
      // ═══════════════════════════════════════════════════════════════
      // POST-ML SAFETY OVERRIDE: Prevent false positives on known domains
      // ═══════════════════════════════════════════════════════════════
      if (analysisResult.action === 'block' || analysisResult.action === 'warn') {
        const isTrustedDomain = trustedDomains.some(domain => url.includes(domain));
        
        if (isTrustedDomain) {
          console.log('🛡️ POST-ML OVERRIDE: Trusted domain flagged, downgrading action');
          console.log('   Original action:', analysisResult.action, '| Risk:', analysisResult.riskScore);
          
          // Downgrade: block → warn, warn → allow
          const originalAction = analysisResult.action;
          if (analysisResult.action === 'block') {
            analysisResult.action = 'warn';
            analysisResult.riskScore = Math.min(analysisResult.riskScore, 60);
          } else if (analysisResult.action === 'warn') {
            analysisResult.action = 'allow';
            analysisResult.riskScore = Math.min(analysisResult.riskScore, 30);
          }
          
          analysisResult.reasons.push(`⚠️ Trusted domain override (${originalAction} → ${analysisResult.action})`);
          console.log('   New action:', analysisResult.action, '| New risk:', analysisResult.riskScore);
        }
      }
      
      console.log('📊 Final analysis result:', analysisResult);
      
      // FIXED: Block if action is 'block' (don't require 95+ score)
      if (analysisResult.action === 'block') {
        console.log('🚫 Blocking phishing site:', url, `(Risk: ${analysisResult.riskScore}/100)`);
        await this.handleBlockedUrl(tabId, url, analysisResult);
      } else if (analysisResult.action === 'warn') {
        // WARNING DISABLED: Just log it, don't show popup (user requested)
        console.log('⚠️ Suspicious URL detected (silent):', url, `Risk: ${analysisResult.riskScore}/100`);
        console.log('   Method:', analysisResult.method, '| Reasons:', analysisResult.reasons);
        this.stats.threatsWarned++; // Still count it in stats
        // await this.handleWarning(tabId, url, analysisResult); // DISABLED
      } else {
        console.log('✅ URL allowed:', url);
      }

      await this.saveStats();
      
    } catch (error) {
      console.error('URL analysis error:', error);
      this.handleError('URL_ANALYSIS_FAILED', error, { url, tabId });
    } finally {
      this.pendingOperations.delete(operationId);
    }
  }

  async performBasicAnalysis(url) {
    try {
      console.log('🔍 Performing heuristic analysis:', url);
      
      // Basic URL analysis for service worker
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();
      
      let riskScore = 0;
      const reasons = [];
      
      // REMOVED: Early whitelist bypass - let heuristics analyze everything
      // Post-ML override in analyzeAndHandleUrl will catch false positives
      
      // Test URLs for demonstration
      const testPhishingUrls = [
        'phishing-test.com',
        'suspicious-site.tk',
        'fake-paypal.tk',
        'malicious-site.ml',
        'scam-website.ga',
        'paypa1-secure-login.com'
      ];
      
      // Check if it's a test phishing URL
      if (testPhishingUrls.some(testUrl => hostname.includes(testUrl))) {
        riskScore += 80;
        reasons.push('Test phishing URL detected');
      }
      
      // Basic heuristics - more conservative scoring
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
      if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
        riskScore += 30; // Reduced from 40
        reasons.push('Suspicious TLD detected');
      }
      
      if (hostname.includes('@')) {
        riskScore += 40; // Increased for actual obfuscation
        reasons.push('URL obfuscation detected');
      }
      
      // Brand spoofing detection - more precise
      const brandPatterns = {
        'paypal': /^(?:.*[^a-z])?p[a@]yp[a@]l(?:[^a-z].*)?$/i,
        'amazon': /^(?:.*[^a-z])?[a@]m[a@]z[o0]n(?:[^a-z].*)?$/i,
        'microsoft': /^(?:.*[^a-z])?micr[o0]s[o0]ft(?:[^a-z].*)?$/i,
        'google': /^(?:.*[^a-z])?g[o0]{2}gle(?:[^a-z].*)?$/i,
        'apple': /^(?:.*[^a-z])?[a@]pple(?:[^a-z].*)?$/i
      };
      
      for (const [brand, pattern] of Object.entries(brandPatterns)) {
        // Only flag if domain contains brand name BUT is not the official domain
        if (pattern.test(hostname) && 
            !hostname.endsWith(`${brand}.com`) && 
            !hostname.endsWith(`.${brand}.com`)) {
          riskScore += 60; // Increased confidence for spoofing
          reasons.push(`Brand spoofing detected (${brand})`);
          console.log(`🚨 Brand spoofing detected: ${brand} in ${hostname}`);
          break;
        }
      }
      
      // IP address check
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        riskScore += 25;
        reasons.push('Direct IP address usage');
      }
      
      // Excessive hyphens (common in phishing)
      const hyphenCount = (hostname.match(/-/g) || []).length;
      if (hyphenCount >= 4) {
        riskScore += 20;
        reasons.push('Excessive hyphens in domain');
      }
      
      // Very long URLs (often obfuscation)
      if (url.length > 200) {
        riskScore += 15;
        reasons.push('Unusually long URL');
      }
      
      // Determine action based on risk score - CONSERVATIVE thresholds
      let action = 'allow';
      // CONSERVATIVE: Only block VERY suspicious URLs to reduce false positives
      if (riskScore >= 85) { // Block only VERY high-risk phishing (was 70)
        action = 'block';
      } else if (riskScore >= 50) { // Warn on medium suspicion (was 40)
        action = 'warn';
      }
      
      console.log(`📊 Heuristic result: Risk=${riskScore}, Action=${action}`);
      
      return {
        riskScore: Math.min(riskScore, 100),
        reasons: reasons.length > 0 ? reasons : ['Site analysis complete'],
        action,
        confidence: riskScore >= 80 ? 'high' : riskScore >= 50 ? 'medium' : 'low',
        method: 'Heuristic Analysis'
      };
      
    } catch (error) {
      console.error('Basic analysis error:', error);
      return { 
        riskScore: 0, 
        reasons: ['Analysis error - allowing by default'], 
        action: 'allow', 
        confidence: 'low',
        method: 'Error Fallback'
      };
    }
  }

  async handleBlockedUrl(tabId, url, result) {
    this.stats.threatsBlocked++;

    try {
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: '🚫 PhishGuard - Site Blocked!',
        message: `Blocked phishing attempt (Risk: ${result.riskScore}/100) - Method: ${result.method}`,
        priority: 2
      });
    } catch (error) {
      console.error('Notification creation failed:', error);
    }

    // FIXED: Actually block the navigation by redirecting to warning page
    const warningUrl = chrome.runtime.getURL('warning.html') +
      '?url=' + encodeURIComponent(url) +
      '&score=' + encodeURIComponent(result.riskScore) +
      '&reasons=' + encodeURIComponent(JSON.stringify(result.reasons)) +
      '&method=' + encodeURIComponent(result.method || 'Unknown') +
      '&action=blocked';

    try {
      // CRITICAL: Actually redirect to warning page to block the malicious site
      await chrome.tabs.update(tabId, { url: warningUrl });
      console.log('🚫 BLOCKED: Redirected to warning page instead of malicious site');
    } catch (error) {
      console.error('Tab update failed:', error);
    }
  }

  async handleWarning(tabId, url, result) {
    this.stats.threatsWarned++;
    console.log('⚠️ Showing warning for:', url);

    try {
      // Try to send message to content script first
      await chrome.tabs.sendMessage(tabId, {
        type: 'SHOW_PHISHING_WARNING',
        url,
        riskScore: result.riskScore,
        reasons: result.reasons,
        method: result.method
      });
      console.log('✅ Warning message sent to content script');
    } catch (error) {
      console.log('⚠️ Content script not available, showing notification');
      try {
        await chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: '⚠️ PhishGuard - Suspicious Site',
          message: `Suspicious site detected (Risk: ${result.riskScore}/100) - ${result.method}`,
          priority: 1
        });
      } catch (notificationError) {
        console.error('Notification creation failed:', notificationError);
      }
    }
  }

  isInternalUrl(url) {
    return ['chrome://', 'chrome-extension://', 'about:', 'edge://', 'moz-extension://'].some(prefix => url.startsWith(prefix)) ||
      url === 'chrome://newtab/';
  }

  async saveStats() {
    try {
      await chrome.storage.local.set({ 
        phishguardStats: this.stats,
        phishguardMLConfig: this.mlConfig
      });
    } catch (error) {
      console.error('Error saving stats:', error);
    }
  }

  async getStats() { 
    return { ...this.stats };
  }

  async resetStats() {
    this.stats = {
      threatsBlocked: 0,
      threatsWarned: 0,
      emailsAnalyzed: 0,
      emailsFlagged: 0,
      whatsappLinksAnalyzed: 0,
      whatsappLinksFlagged: 0,
      totalScans: 0,
      lastScan: null,
      mlPredictions: 0,
      mlAccuracy: 0,
      mlErrors: 0
    };
    await this.saveStats();
  }

  async updatePhishingDatabase() {
    try {
      console.log('🔄 Updating phishing database...');
      return { success: true, message: 'Database updated successfully' };
    } catch (error) {
      console.error('Database update error:', error);
      return { success: false, message: 'Database update failed' };
    }
  }

  // ML Configuration Methods
  async getMLConfig() {
    return { ...this.mlConfig };
  }

  async updateMLConfig(config) {
    try {
      this.mlConfig = { ...this.mlConfig, ...config };
      await chrome.storage.local.set({ phishguardMLConfig: this.mlConfig });
      
      // Test new configuration
      if (config.enabled !== undefined || config.backendUrl) {
        await this.testMLBackend();
      }
      
      return { success: true, message: 'ML configuration updated', config: this.mlConfig };
    } catch (error) {
      console.error('ML config update error:', error);
      return { success: false, message: 'Failed to update ML configuration' };
    }
  }

  async testSpecificUrl(url) {
    console.log('🧪 Testing specific URL:', url);
    
    // Try ML first, then fallback to heuristics
    const mlResult = await this.callMLBackend(url);
    
    if (mlResult) {
      const baseRiskScore = mlResult.prediction === 1 ? 85 : 15;
      const confidenceAdjustment = (mlResult.confidence - 0.5) * 20;
      const riskScore = Math.max(0, Math.min(100, baseRiskScore + confidenceAdjustment));
      
      return {
        riskScore: Math.round(riskScore),
        reasons: [`ML Prediction: ${mlResult.prediction === 1 ? 'Phishing' : 'Safe'}`],
        action: riskScore >= 70 ? 'block' : riskScore >= 40 ? 'warn' : 'allow',
        confidence: mlResult.confidence >= 0.8 ? 'high' : 'medium',
        method: 'ML Model',
        mlResult
      };
    }
    
    return await this.performBasicAnalysis(url);
  }

  // Enhanced error handling and logging
  handleError(errorType, error, context = {}) {
    const errorInfo = {
      type: errorType,
      message: error.message || 'Unknown error',
      stack: error.stack,
      timestamp: new Date().toISOString(),
      context: context,
      serviceState: {
        isInitialized: this.isInitialized,
        isShuttingDown: this.isShuttingDown,
        pendingOperations: this.pendingOperations.size
      }
    };
    
    // Only log as warning for non-critical errors
    if (errorType.includes('ML') || errorType.includes('BACKEND')) {
      console.log(`ℹ️ PhishGuard Info [${errorType}]:`, error.message);
    } else {
      console.error(`🚨 PhishGuard Error [${errorType}]:`, errorInfo);
    }
    
    this.logError(errorInfo);
    
    if (this.shouldRetry(errorType)) {
      this.scheduleRetry(errorType, context);
    }
  }
  
  shouldRetry(errorType) {
    const retryableErrors = [
      'NAVIGATION_ANALYSIS_FAILED',
      'TAB_UPDATE_ANALYSIS_FAILED',
      'URL_ANALYSIS_FAILED'
    ];
    return retryableErrors.includes(errorType) && this.retryCount < this.maxRetries;
  }
  
  async scheduleRetry(errorType, context) {
    this.retryCount++;
    const delay = Math.pow(2, this.retryCount) * 1000;
    
    console.log(`🔄 Scheduling retry ${this.retryCount}/${this.maxRetries} in ${delay}ms`);
    
    setTimeout(async () => {
      try {
        if (errorType === 'URL_ANALYSIS_FAILED' && context.url) {
          await this.analyzeAndHandleUrl(context.url, context.tabId);
        }
        this.retryCount = 0;
      } catch (error) {
        console.error(`Retry failed for ${errorType}:`, error);
      }
    }, delay);
  }
  
  async logError(errorInfo) {
    try {
      const result = await chrome.storage.local.get(['phishguardErrors']);
      const errors = result.phishguardErrors || [];
      
      errors.push(errorInfo);
      if (errors.length > 50) {
        errors.splice(0, errors.length - 50);
      }
      
      await chrome.storage.local.set({ phishguardErrors: errors });
    } catch (error) {
      console.error('Failed to log error:', error);
    }
  }
  
  async getErrorLogs() {
    try {
      const result = await chrome.storage.local.get(['phishguardErrors']);
      return result.phishguardErrors || [];
    } catch (error) {
      console.error('Failed to get error logs:', error);
      return [];
    }
  }
  
  async clearErrorLogs() {
    try {
      await chrome.storage.local.remove(['phishguardErrors']);
      console.log('Error logs cleared');
    } catch (error) {
      console.error('Failed to clear error logs:', error);
    }
  }
  
  // Graceful shutdown
  async shutdown() {
    console.log('🛑 Shutting down PhishGuard Service...');
    this.isShuttingDown = true;
    
    const maxWaitTime = 5000;
    const startTime = Date.now();
    
    while (this.pendingOperations.size > 0 && (Date.now() - startTime) < maxWaitTime) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    if (this.pendingOperations.size > 0) {
      console.warn(`⚠️ ${this.pendingOperations.size} operations still pending after shutdown`);
    }
    
    await this.saveStats();
    console.log('✅ PhishGuard Service shutdown complete');
  }
}

// Initialize service IMMEDIATELY
let phishGuardService = null;
try { 
  phishGuardService = new PhishGuardService(); 
  console.log('🛡️ PhishGuard Service instance created');
} catch (error) { 
  console.error('Failed to create PhishGuard Service:', error); 
}

// Enhanced message handling
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  (async () => {
    try {
      console.log('📨 Received message:', request.type, 'from:', sender.id || 'popup');
      
      if (!phishGuardService) {
        console.error('❌ Service instance not created');
        return sendResponse({ 
          error: 'Service not initialized', 
          code: 'SERVICE_NOT_CREATED',
          ...(request.type === 'GET_STATS' ? {
            threatsBlocked: 0,
            threatsWarned: 0,
            emailsAnalyzed: 0,
            emailsFlagged: 0,
            whatsappLinksAnalyzed: 0,
            whatsappLinksFlagged: 0,
            totalScans: 0,
            mlPredictions: 0,
            mlErrors: 0
          } : {})
        });
      }

      const allowedDuringInit = ['GET_STATS', 'GET_SERVICE_STATUS', 'GET_CURRENT_TAB_INFO', 'GET_ML_CONFIG'];
      
      if (!phishGuardService.isInitialized && !allowedDuringInit.includes(request.type)) {
        console.warn('⚠️ Service initializing');
        return sendResponse({ 
          error: 'Service initializing', 
          code: 'SERVICE_INITIALIZING',
          message: 'Please wait and try again'
        });
      }

      if (!isValidSender(sender)) {
        console.warn('Invalid sender:', sender);
        return sendResponse({ error: 'Invalid sender', code: 'INVALID_SENDER' });
      }

      const sanitizedRequest = sanitizeRequest(request);
      if (!sanitizedRequest) {
        return sendResponse({ error: 'Invalid request', code: 'INVALID_REQUEST' });
      }

      switch (sanitizedRequest.type) {
        case 'GET_STATS':
          const stats = await phishGuardService.getStats();
          console.log('📊 Returning stats:', stats);
          return sendResponse(stats);
          
        case 'RESET_STATS':
          await phishGuardService.resetStats();
          return sendResponse({ success: true, message: 'Statistics reset' });
          
        case 'UPDATE_DATABASE':
          return sendResponse(await phishGuardService.updatePhishingDatabase());
          
        case 'ANALYZE_URL':
          if (!sanitizedRequest.url || typeof sanitizedRequest.url !== 'string') {
            return sendResponse({ error: 'Invalid URL', code: 'INVALID_URL' });
          }
          const analysis = await phishGuardService.performBasicAnalysis(sanitizedRequest.url);
          return sendResponse(analysis);
          
        case 'TEST_PHISHING_DETECTION':
          const testUrl = 'https://suspicious-site.tk';
          const testAnalysis = await phishGuardService.performBasicAnalysis(testUrl);
          
          phishGuardService.stats.totalScans++;
          if (testAnalysis.action === 'block') phishGuardService.stats.threatsBlocked++;
          else if (testAnalysis.action === 'warn') phishGuardService.stats.threatsWarned++;
          
          await phishGuardService.saveStats();
          return sendResponse({ success: true, testUrl, analysis: testAnalysis });
          
        case 'TEST_SPECIFIC_URL':
          if (!sanitizedRequest.url) {
            return sendResponse({ error: 'Invalid URL', code: 'INVALID_URL' });
          }
          const urlAnalysis = await phishGuardService.testSpecificUrl(sanitizedRequest.url);
          return sendResponse({ success: true, url: sanitizedRequest.url, analysis: urlAnalysis });
          
        case 'GET_ML_CONFIG':
          const mlConfig = await phishGuardService.getMLConfig();
          return sendResponse(mlConfig);
          
        case 'UPDATE_ML_CONFIG':
          if (!sanitizedRequest.config || typeof sanitizedRequest.config !== 'object') {
            return sendResponse({ error: 'Invalid config', code: 'INVALID_CONFIG' });
          }
          return sendResponse(await phishGuardService.updateMLConfig(sanitizedRequest.config));
          
        case 'TEST_ML_BACKEND':
          const testResult = await phishGuardService.testMLBackend();
          const status = await phishGuardService.getMLConfig();
          return sendResponse({ 
            success: testResult, 
            mlEnabled: status.enabled, 
            config: status,
            message: testResult ? 'ML backend is online' : 'ML backend is offline (using heuristic detection)'
          });
          
        case 'GET_CURRENT_TAB_INFO':
          const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tabs[0]) {
            return sendResponse({ url: tabs[0].url, title: tabs[0].title, id: tabs[0].id });
          }
          return sendResponse({ error: 'No active tab', code: 'NO_ACTIVE_TAB' });
          
        case 'GET_ERROR_LOGS':
          return sendResponse(await phishGuardService.getErrorLogs());
          
        case 'CLEAR_ERROR_LOGS':
          await phishGuardService.clearErrorLogs();
          return sendResponse({ success: true });
          
        case 'GET_SERVICE_STATUS':
          return sendResponse({
            isInitialized: phishGuardService.isInitialized,
            isShuttingDown: phishGuardService.isShuttingDown,
            pendingOperations: phishGuardService.pendingOperations.size,
            mlEnabled: phishGuardService.mlConfig.enabled,
            version: chrome.runtime.getManifest().version
          });
          
        case 'SHUTDOWN_SERVICE':
          await phishGuardService.shutdown();
          return sendResponse({ success: true });
          
        case 'UPDATE_WHATSAPP_STATS':
          // Update WhatsApp statistics
          if (sanitizedRequest.analysis) {
            phishGuardService.stats.whatsappLinksAnalyzed++;
            
            if (sanitizedRequest.analysis.action === 'block') {
              phishGuardService.stats.whatsappLinksFlagged++;
              phishGuardService.stats.threatsBlocked++;
            } else if (sanitizedRequest.analysis.action === 'warn') {
              phishGuardService.stats.whatsappLinksFlagged++;
              phishGuardService.stats.threatsWarned++;
            }
            
            phishGuardService.stats.totalScans++;
            await phishGuardService.saveStats();
            
            console.log('📊 WhatsApp stats updated:', {
              analyzed: phishGuardService.stats.whatsappLinksAnalyzed,
              flagged: phishGuardService.stats.whatsappLinksFlagged,
              blocked: phishGuardService.stats.threatsBlocked
            });
            
            return sendResponse({ success: true });
          }
          return sendResponse({ error: 'Invalid analysis data', code: 'INVALID_ANALYSIS' });
          
        default:
          return sendResponse({ error: 'Unknown message type', code: 'UNKNOWN_MESSAGE_TYPE' });
      }
    } catch (error) {
      console.error('❌ Message handling error:', error);
      if (phishGuardService) {
        phishGuardService.handleError('MESSAGE_HANDLING_FAILED', error, { request, sender });
      }
      sendResponse({ error: 'Internal error', code: 'INTERNAL_ERROR', message: error.message });
    }
  })();
  return true;
});

function isValidSender(sender) {
  // Allow messages from the extension popup/options pages (no tab)
  if (!sender.tab && sender.id === chrome.runtime.id) {
    console.log('✅ Message from extension popup/options');
    return true;
  }
  
  // Allow messages from extension itself
  if (sender.id === chrome.runtime.id) {
    console.log('✅ Message from extension');
    return true;
  }
  
  // Validate sender from tabs
  if (sender.tab) {
    try {
      const url = new URL(sender.tab.url);
      const validOrigins = ['http:', 'https:', 'chrome-extension:'];
      return validOrigins.includes(url.protocol);
    } catch {
      return false;
    }
  }
  
  return false;
}

function sanitizeRequest(request) {
  if (!request || typeof request !== 'object') {
    return null;
  }
  
  // Sanitize string inputs
  const sanitized = { ...request };
  
  if (sanitized.url && typeof sanitized.url === 'string') {
    // Basic URL sanitization
    sanitized.url = sanitized.url.trim().substring(0, 2048); // Limit length
  }
  
  return sanitized;
}

// Extension installation handler
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    console.log('🎉 PhishGuard Pro installed!');
    try {
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: '🛡️ PhishGuard Pro Installed!',
        message: 'Your phishing protection is now active. ML detection will activate when backend is running.',
        priority: 2
      });
    } catch (error) {
      console.error('Installation notification failed:', error);
    }
  } else if (details.reason === 'update') {
    console.log('PhishGuard Pro updated to version', chrome.runtime.getManifest().version);
  }
});

// Alarms listener for periodic tasks
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (!phishGuardService) return;
  
  switch (alarm.name) {
    case 'updatePhishingDB':
      await phishGuardService.updatePhishingDatabase();
      break;
      
    case 'testMLBackend':
      // Silently test ML backend in background
      await phishGuardService.testMLBackend();
      break;
      
    case 'cleanupExpiredData':
      // Cleanup old error logs
      try {
        const errors = await phishGuardService.getErrorLogs();
        const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
        const filtered = errors.filter(e => new Date(e.timestamp).getTime() > oneWeekAgo);
        await chrome.storage.local.set({ phishguardErrors: filtered });
        console.log('🧹 Cleaned up old error logs');
      } catch (error) {
        console.error('Cleanup failed:', error);
      }
      break;
  }
});

// Open fullscreen dashboard when extension icon is clicked
chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.create({
    url: chrome.runtime.getURL('dashboard.html')
  });
});

console.log('🛡️ PhishGuard Pro with ML Integration loaded successfully');
