// PhishGuard Pro - Email Phishing Detection
// Lightweight email analysis for Gmail integration

class EmailPhishingDetector {
  constructor() {
    // ML Detector Integration
    this.mlDetector = null;
    this.mlEnabled = true;
    this.initializeMLDetector();
    
    this.suspiciousPatterns = {
      urgency: /urgent|immediate|expire|suspend|verify now|act fast|limited time|deadline|asap|right away/i,
      threats: /account locked|security alert|unusual activity|suspended|blocked|terminated|deactivated/i,
      requests: /verify|confirm|update|validate|authenticate|restore|reactivate|unlock/i,
      socialPressure: /friends|family|colleagues|team|everyone|share with|forward to/i,
      financial: /payment|billing|invoice|refund|transaction|credit card|bank account/i,
      prizes: /winner|congratulations|prize|reward|claim now|free gift|lottery/i
    };
    
    this.legitimateDomains = new Set([
      'gmail.com', 'outlook.com', 'yahoo.com', 'apple.com', 'microsoft.com',
      'amazon.com', 'paypal.com', 'google.com', 'facebook.com', 'twitter.com',
      'netflix.com', 'spotify.com', 'linkedin.com', 'instagram.com', 'youtube.com',
      'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org'
    ]);
    
    // Common phishing sender patterns - comprehensive coverage
    this.suspiciousSenders = [
      // Generic patterns for suspicious TLDs
      /noreply@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      /no-reply@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      /support@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      /security@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      /admin@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      /service@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      /help@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      /info@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      /alert@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      /notification@.*\.(tk|ml|ga|cf|gq|xyz)$/i,
      
      // Brand-specific suspicious patterns (any TLD that's not the real one)
      /.*paypal.*@(?!.*paypal\.com$)/i,
      /.*amazon.*@(?!.*amazon\.com$)/i,
      /.*microsoft.*@(?!.*microsoft\.com$)/i,
      /.*google.*@(?!.*google\.com$|.*gmail\.com$)/i,
      /.*apple.*@(?!.*apple\.com$|.*icloud\.com$)/i,
      /.*netflix.*@(?!.*netflix\.com$)/i,
      /.*facebook.*@(?!.*facebook\.com$)/i
    ];
    
    this.initializeDetector();
  }
  
  // Initialize ML Detector
  initializeMLDetector() {
    try {
      if (typeof window !== 'undefined' && window.MLPhishingDetector) {
        this.mlDetector = new window.MLPhishingDetector();
        console.log('✅ ML Detector integrated into EmailPhishingDetector');
      } else {
        console.log('⚠️ ML Detector not available for EmailPhishingDetector');
        this.mlEnabled = false;
      }
    } catch (error) {
      console.error('ML Detector initialization failed in EmailPhishingDetector:', error);
      this.mlEnabled = false;
    }
  }
  
  async initializeDetector() {
    console.log('📧 Email Phishing Detector initialized');
  }
  
  async analyzeEmail(emailData) {
    const { from, subject, body, links } = emailData;
    let riskScore = 0;
    const reasons = [];
    
    try {
      // Check sender domain and patterns
      if (from) {
        const senderDomain = from.split('@')[1]?.toLowerCase();
        
        // Check for suspicious sender patterns
        if (this.suspiciousSenders.some(pattern => pattern.test(from))) {
          riskScore += 30;
          reasons.push('Suspicious sender email pattern');
        }
        
        // Check for suspicious TLD in sender domain
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'];
        if (senderDomain && suspiciousTLDs.some(tld => senderDomain.endsWith(tld))) {
          riskScore += 40;
          reasons.push('Sender using suspicious TLD (commonly used for phishing)');
        }
        
        // Check sender domain against legitimate domains
        if (senderDomain && !this.legitimateDomains.has(senderDomain)) {
          riskScore += 20;
          reasons.push('Suspicious sender domain');
        }
        
        // Check for brand impersonation in sender
        const brandImpersonation = this.checkBrandImpersonation(from);
        if (brandImpersonation) {
          riskScore += 35;
          reasons.push(`Brand impersonation detected: ${brandImpersonation}`);
        }
      }
      
      // Check subject for urgency
      if (subject) {
        const urgencyCount = Object.values(this.suspiciousPatterns).reduce((count, pattern) => {
          return count + (pattern.test(subject) ? 1 : 0);
        }, 0);
        
        if (urgencyCount > 0) {
          riskScore += urgencyCount * 10;
          reasons.push(`${urgencyCount} urgency indicators in subject`);
        }
      }
      
      // Check body content
      if (body) {
        const bodyAnalysis = this.analyzeBodyContent(body);
        riskScore += bodyAnalysis.score;
        reasons.push(...bodyAnalysis.reasons);
      }
      
      // Check links
      if (links && links.length > 0) {
        const linkAnalysis = await this.analyzeLinks(links);
        riskScore += linkAnalysis.score;
        reasons.push(...linkAnalysis.reasons);
      }
      
      return {
        riskScore: Math.min(riskScore, 100),
        reasons,
        isPhishing: riskScore >= 50,
        confidence: riskScore >= 70 ? 'high' : riskScore >= 40 ? 'medium' : 'low'
      };
      
    } catch (error) {
      console.error('Email analysis error:', error);
      return {
        riskScore: 0,
        reasons: ['Error analyzing email'],
        isPhishing: false,
        confidence: 'low'
      };
    }
  }
  
  analyzeBodyContent(body) {
    let score = 0;
    const reasons = [];
    
    // Check for urgency language
    const urgencyMatches = body.match(this.suspiciousPatterns.urgency);
    if (urgencyMatches) {
      score += 15;
      reasons.push('Urgent language detected in email body');
    }
    
    // Check for threat language
    const threatMatches = body.match(this.suspiciousPatterns.threats);
    if (threatMatches) {
      score += 20;
      reasons.push('Threatening language detected');
    }
    
    // Check for poor grammar/spelling
    const grammarIssues = [
      'recieve', 'seperate', 'occured', 'loose', 'there account', 'you\'re account',
      'click hear', 'your account has been', 'we has detected'
    ];
    
    const grammarCount = grammarIssues.filter(issue => 
      body.toLowerCase().includes(issue)
    ).length;
    
    if (grammarCount > 0) {
      score += grammarCount * 5;
      reasons.push(`${grammarCount} grammar/spelling issues detected`);
    }
    
    // Check for excessive use of "click here" or similar phrases
    const clickPhrases = /click here|click now|click below|click link|click button|tap here/i;
    const clickMatches = body.match(clickPhrases);
    if (clickMatches && clickMatches.length > 2) {
      score += 10;
      reasons.push('Excessive "click here" phrases');
    }
    
    // Check for suspicious phone numbers or addresses
    const phonePattern = /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/;
    if (phonePattern.test(body)) {
      score += 5;
      reasons.push('Suspicious phone number in email');
    }
    
    // Check for excessive exclamation marks (common in phishing)
    const exclamationCount = (body.match(/!/g) || []).length;
    if (exclamationCount > 5) {
      score += 8;
      reasons.push('Excessive exclamation marks (phishing indicator)');
    }
    
    return { score, reasons };
  }
  
  async analyzeLinks(links) {
    let score = 0;
    const reasons = [];
    
    for (const link of links) {
      // ========== ML DETECTION (PRIMARY) ==========
      if (this.mlEnabled && this.mlDetector) {
        try {
          const mlResult = await this.mlDetector.predictPhishing(link);
          if (mlResult && mlResult.riskScore !== undefined) {
            console.log(`🤖 ML Email Link Detection: ${mlResult.riskScore}/100`);
            score += Math.round(mlResult.riskScore * 0.5); // Scale down for email scoring
            if (mlResult.reasons) {
              reasons.push(...mlResult.reasons);
            }
            continue; // Skip rule-based for this link
          }
        } catch (mlError) {
          console.warn('ML link detection failed, using rule-based:', mlError);
        }
      }
      
      // ========== RULE-BASED DETECTION (FALLBACK) ==========
      try {
        const urlObj = new URL(link);
        const hostname = urlObj.hostname.toLowerCase();
        const pathname = urlObj.pathname.toLowerCase();
        const fullUrl = link.toLowerCase();
        
        // Check for IP addresses (CRITICAL)
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipPattern.test(hostname)) {
          score += 50;
          reasons.push(`IP address used instead of domain (${hostname})`);
        }
        
        // Check for brand impersonation in path
        const brandKeywords = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'netflix', 'facebook', 'bank'];
        const brandInPath = brandKeywords.find(brand => pathname.includes(brand));
        if (brandInPath) {
          const legitimateDomains = [
            'paypal.com', 'amazon.com', 'microsoft.com', 'google.com',
            'apple.com', 'netflix.com', 'facebook.com'
          ];
          const isLegitimate = legitimateDomains.some(domain =>
            hostname === domain || hostname.endsWith('.' + domain)
          );
          
          if (!isLegitimate) {
            score += 45;
            reasons.push(`Brand impersonation: "${brandInPath}" in URL path but not on official domain`);
          }
        }
        
        // Check for HTTP with sensitive keywords
        if (urlObj.protocol === 'http:') {
          const sensitiveKeywords = ['login', 'signin', 'password', 'account', 'verify', 'payment'];
          if (sensitiveKeywords.some(keyword => fullUrl.includes(keyword))) {
            score += 35;
            reasons.push('Insecure HTTP used for sensitive operations');
          }
        }
        
        // Check for suspicious URL patterns (general)
        if (this.isSuspiciousUrl(link)) {
          score += 25;
          reasons.push('Suspicious link pattern detected');
        }
        
        // Check for URL shorteners
        const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'];
        if (shorteners.some(shortener => link.includes(shortener))) {
          score += 15;
          reasons.push('URL shortener detected');
        }
        
      } catch (error) {
        // Invalid link
        score += 10;
        reasons.push('Invalid link format');
      }
    }
    
    return { score, reasons };
  }
  
  checkBrandImpersonation(sender) {
    const brandPatterns = {
      'paypal': /paypal|paypa1|p[a@]yp[a@]l/i,
      'amazon': /amazon|amaz0n|[a@]m[a@]z[o0]n/i,
      'microsoft': /microsoft|micr[o0]s[o0]ft|micr0soft/i,
      'google': /google|g[o0]{2}gle|g00gle/i,
      'apple': /apple|[a@]pple|app1e/i,
      'facebook': /facebook|f[a@]ceb[o0]{2}k/i,
      'netflix': /netflix|netf1ix|netfl1x/i,
      'bank': /bank|banking/i,
      'secure': /secure|security/i
    };
    
    // Legitimate domains for each brand
    const legitimateBrandDomains = {
      'paypal': ['paypal.com'],
      'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de'],
      'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'office.com'],
      'google': ['google.com', 'gmail.com'],
      'apple': ['apple.com', 'icloud.com'],
      'facebook': ['facebook.com', 'fb.com'],
      'netflix': ['netflix.com'],
      'bank': [], // No legitimate generic "bank" emails
      'secure': [] // No legitimate generic "secure" emails
    };
    
    for (const [brand, pattern] of Object.entries(brandPatterns)) {
      if (pattern.test(sender)) {
        const senderDomain = sender.split('@')[1]?.toLowerCase();
        
        if (!senderDomain) continue;
        
        // Check if domain is in legitimate list for this brand
        const validDomains = legitimateBrandDomains[brand] || [];
        const isLegitimate = validDomains.some(domain => 
          senderDomain === domain || senderDomain.endsWith('.' + domain)
        );
        
        if (!isLegitimate) {
          return brand;
        }
      }
    }
    
    return null;
  }
  
  isSuspiciousUrl(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();
      const pathname = urlObj.pathname.toLowerCase();
      const protocol = urlObj.protocol;
      
      // Check for IP addresses (major phishing indicator)
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(hostname)) {
        return true; // Any IP address is suspicious in emails
      }
      
      // Check for private/local IP addresses
      const privateIpPattern = /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/;
      if (privateIpPattern.test(hostname)) {
        return true; // Local IPs are definitely phishing
      }
      
      // Check for suspicious TLDs
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click'];
      if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
        return true;
      }
      
      // Check for brand names in URL path (like /~paypal/ or /amazon/)
      const brandKeywords = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'netflix', 'facebook', 'bank', 'login', 'signin', 'account', 'verify'];
      const hasBrandInPath = brandKeywords.some(brand => pathname.includes(brand));
      
      if (hasBrandInPath) {
        // Check if the hostname is legitimate for that brand
        const legitimateDomains = [
          'paypal.com', 'amazon.com', 'microsoft.com', 'google.com', 
          'apple.com', 'netflix.com', 'facebook.com', 'gmail.com'
        ];
        
        const isLegitimateHost = legitimateDomains.some(domain => 
          hostname === domain || hostname.endsWith('.' + domain)
        );
        
        if (!isLegitimateHost) {
          return true; // Brand name in path but not on legitimate domain
        }
      }
      
      // Check for HTTP (insecure) with sensitive keywords
      if (protocol === 'http:') {
        const sensitiveKeywords = ['login', 'signin', 'password', 'account', 'verify', 'payment', 'bank', 'paypal', 'amazon'];
        if (sensitiveKeywords.some(keyword => fullUrl.includes(keyword))) {
          return true; // HTTP for sensitive operations is suspicious
        }
      }
      
      // Check for character substitution in hostname
      const brandPatterns = {
        'paypal': /p[a@]yp[a@]l|paypa1/i,
        'amazon': /[a@]m[a@]z[o0]n|amaz0n/i,
        'microsoft': /micr[o0]s[o0]ft/i,
        'google': /g[o0]{2}gle|g00gle/i
      };
      
      for (const [brand, pattern] of Object.entries(brandPatterns)) {
        if (pattern.test(hostname) && !hostname.endsWith(`${brand}.com`)) {
          return true;
        }
      }
      
      // Check for @ symbol in URL (credential phishing)
      if (fullUrl.includes('@') && !fullUrl.startsWith('mailto:')) {
        return true;
      }
      
      // Check for URL shorteners
      const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'];
      if (shorteners.some(shortener => hostname.includes(shortener))) {
        return true;
      }
      
      return false;
      
    } catch (error) {
      return true; // Invalid URLs are suspicious
    }
  }
}

// Export for use in other scripts
if (typeof window !== 'undefined') {
  window.EmailPhishingDetector = EmailPhishingDetector;
}

console.log('📧 EmailPhishingDetector class loaded');