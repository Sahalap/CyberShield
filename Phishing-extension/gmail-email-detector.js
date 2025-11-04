// PhishGuard Pro - Gmail Email Phishing Detection
// Specialized content script for Gmail integration

// REMOVED: importScripts('email-phishing-detector.js');
// Classes are available through window object since all scripts are loaded together

class GmailEmailDetector {
  constructor() {
    this.processedEmails = new Set();
    this.observer = null;
    this.isGmailLoaded = false;
    this.emailDetector = null;
    this.retryCount = 0;
    this.maxRetries = 10;
    this.retryDelay = 500;
    
    this.initializeGmailDetector();
  }
  
  async waitForEmailDetector() {
    return new Promise((resolve, reject) => {
      const checkDetector = () => {
        if (window.EmailPhishingDetector) {
          this.emailDetector = new window.EmailPhishingDetector();
          resolve();
        } else if (this.retryCount < this.maxRetries) {
          this.retryCount++;
          setTimeout(checkDetector, this.retryDelay);
        } else {
          console.error('EmailPhishingDetector not available after retries');
          reject(new Error('EmailPhishingDetector not available'));
        }
      };
      checkDetector();
    });
  }
  
  async initializeGmailDetector() {
    try {
      console.log('📧 PhishGuard Pro Gmail Email Detector initialized');
      
      // Wait for EmailPhishingDetector to be available
      await this.waitForEmailDetector();
      
      // Wait for Gmail to fully load
      this.waitForGmailLoad();
    } catch (error) {
      console.error('Gmail detector initialization failed:', error);
      
      // Notify error handler
      if (window.PhishGuardErrorHandler) {
        window.PhishGuardErrorHandler.handleError('GMAIL_INITIALIZATION_ERROR', error);
      }
    }
  }
  
  waitForGmailLoad() {
    const checkGmailLoaded = () => {
      // Check for Gmail-specific elements
      const gmailElements = document.querySelectorAll('[role="main"], .nH, .nH .if');
      
      if (gmailElements.length > 0) {
        this.isGmailLoaded = true;
        console.log('✅ Gmail detected, starting email monitoring...');
        this.startEmailMonitoring();
      } else {
        // Retry after 1 second
        setTimeout(checkGmailLoaded, 1000);
      }
    };
    
    checkGmailLoaded();
  }
  
  startEmailMonitoring() {
    // Monitor for email list changes
    this.observeEmailList();
    
    // Monitor for email content changes
    this.observeEmailContent();
    
    // Check existing emails on load
    this.analyzeExistingEmails();
  }
  
  observeEmailList() {
    try {
      // Target the email list container
      const emailListContainer = document.querySelector('[role="main"]') || document.querySelector('.nH');
      
      if (emailListContainer) {
        // Debounced analysis function
        const debouncedAnalyze = this.debounce((node) => {
          this.analyzeNewEmails(node);
        }, 300);
        
        this.observer = new MutationObserver((mutations) => {
          mutations.forEach((mutation) => {
            if (mutation.type === 'childList') {
              mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                  // Check if new emails were added
                  debouncedAnalyze(node);
                }
              });
            }
          });
        });
        
        this.observer.observe(emailListContainer, {
          childList: true,
          subtree: true
        });
      }
    } catch (error) {
      console.error('Error setting up email list observer:', error);
      
      // Notify error handler
      if (window.PhishGuardErrorHandler) {
        window.PhishGuardErrorHandler.handleError('GMAIL_OBSERVER_ERROR', error);
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
  
  observeEmailContent() {
    // Monitor for email content changes (when user opens an email)
    const emailContentObserver = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Check if email content was loaded
              this.analyzeEmailContent(node);
            }
          });
        }
      });
    });
    
    // Observe the entire document for email content
    emailContentObserver.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
  
  analyzeExistingEmails() {
    // Find all email elements in the current view
    const emailElements = document.querySelectorAll('[role="listitem"], .zA, .yW');
    
    emailElements.forEach(emailElement => {
      this.analyzeEmailElement(emailElement);
    });
  }
  
  analyzeNewEmails(container) {
    // Look for email elements in the new container
    const emailElements = container.querySelectorAll('[role="listitem"], .zA, .yW');
    
    emailElements.forEach(emailElement => {
      this.analyzeEmailElement(emailElement);
    });
  }
  
  analyzeEmailContent(container) {
    // Check if this is an email content area
    const emailContent = container.querySelector('.a3s, .ii.gt, .a3s.aiL');
    
    if (emailContent && !emailContent.dataset.phishguardAnalyzed) {
      emailContent.dataset.phishguardAnalyzed = 'true';
      this.analyzeEmailContentArea(emailContent);
    }
  }
  
  analyzeEmailElement(emailElement) {
    if (emailElement.dataset.phishguardAnalyzed) return;
    emailElement.dataset.phishguardAnalyzed = 'true';
    
    try {
      // Check if emailDetector is available
      if (!this.emailDetector) {
        console.warn('EmailPhishingDetector not available yet');
        return;
      }
      
      // Extract email data from Gmail elements
      const emailData = this.extractEmailData(emailElement);
      
      if (emailData) {
        // Analyze the email
        const analysis = this.emailDetector.analyzeEmail(emailData);
        
        // Show warning if phishing detected (lowered threshold)
        if (analysis.isPhishing || analysis.riskScore >= 30) {
          this.showEmailWarning(emailElement, analysis, emailData);
        }
      }
      
    } catch (error) {
      console.error('Error analyzing email element:', error);
    }
  }
  
  extractEmailData(emailElement) {
    try {
      // Extract sender information
      const senderElement = emailElement.querySelector('.yW .yP, .yW span[email], .zF');
      const sender = senderElement ? senderElement.textContent.trim() : '';
      
      // Extract subject
      const subjectElement = emailElement.querySelector('.bog, .y6 span');
      const subject = subjectElement ? subjectElement.textContent.trim() : '';
      
      // Extract preview text
      const previewElement = emailElement.querySelector('.y2, .yP');
      const preview = previewElement ? previewElement.textContent.trim() : '';
      
      // Extract links from preview
      const linkElements = emailElement.querySelectorAll('a[href]');
      const links = Array.from(linkElements).map(link => link.href);
      
      return {
        from: sender,
        subject: subject,
        body: preview,
        links: links
      };
      
    } catch (error) {
      console.error('Error extracting email data:', error);
      return null;
    }
  }
  
  analyzeEmailContentArea(contentElement) {
    try {
      // Extract all links from email content
      const linkElements = contentElement.querySelectorAll('a[href]');
      const links = Array.from(linkElements).map(link => link.href);
      
      // Get email body text
      const bodyText = contentElement.textContent || contentElement.innerText || '';
      
      // Analyze links in the email
      const suspiciousLinks = links.filter(link => {
        try {
          const url = new URL(link);
          return this.isSuspiciousUrl(url.href);
        } catch {
          return true; // Invalid URLs are suspicious
        }
      });
      
      if (suspiciousLinks.length > 0) {
        this.showEmailContentWarning(contentElement, suspiciousLinks);
      }
      
    } catch (error) {
      console.error('Error analyzing email content:', error);
    }
  }
  
  isSuspiciousUrl(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();
      const pathname = urlObj.pathname.toLowerCase();
      const protocol = urlObj.protocol;
      
      // CRITICAL: Check for IP addresses (major phishing indicator)
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(hostname)) {
        console.log(`🚨 IP address detected in Gmail link: ${hostname}`);
        return true; // Any IP address is suspicious
      }
      
      // CRITICAL: Check for private/local IP addresses
      const privateIpPattern = /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/;
      if (privateIpPattern.test(hostname)) {
        console.log(`🚨 Private IP address detected in Gmail link: ${hostname}`);
        return true; // Local IPs are definitely phishing
      }
      
      // CRITICAL: Check for brand names in URL path (like /~paypal/ or /amazon/)
      const brandKeywords = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'netflix', 'facebook', 'bank', 'login', 'signin', 'account', 'verify'];
      const hasBrandInPath = brandKeywords.some(brand => pathname.includes(brand));
      
      if (hasBrandInPath) {
        console.log(`🚨 Brand keyword in path detected: ${pathname}`);
        // Check if the hostname is legitimate for that brand
        const legitimateDomains = [
          'paypal.com', 'amazon.com', 'microsoft.com', 'google.com', 
          'apple.com', 'netflix.com', 'facebook.com', 'gmail.com'
        ];
        
        const isLegitimateHost = legitimateDomains.some(domain => 
          hostname === domain || hostname.endsWith('.' + domain)
        );
        
        if (!isLegitimateHost) {
          console.log(`🚨 Brand in path but not on legitimate domain!`);
          return true; // Brand name in path but not on legitimate domain
        }
      }
      
      // CRITICAL: Check for HTTP (insecure) with sensitive keywords
      if (protocol === 'http:') {
        const sensitiveKeywords = ['login', 'signin', 'password', 'account', 'verify', 'payment', 'bank', 'paypal', 'amazon'];
        if (sensitiveKeywords.some(keyword => fullUrl.includes(keyword))) {
          console.log(`🚨 HTTP with sensitive keyword detected: ${fullUrl}`);
          return true; // HTTP for sensitive operations is suspicious
        }
      }
      
      // Check for suspicious TLDs
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'];
      if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
        return true;
      }
      
      // Check for URL shorteners
      const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link'];
      if (shorteners.some(s => hostname.includes(s))) {
        return true;
      }
      
      // Check for character substitution in brands
      const brandPatterns = {
        'paypal': /p[a@]yp[a@]l|paypa1|p4ypal/i,
        'amazon': /[a@]m[a@]z[o0]n|amaz0n|amazom/i,
        'microsoft': /micr[o0]s[o0]ft|micros0ft|micr0soft/i,
        'google': /g[o0]{2}gle|g00gle|gooogle/i,
        'apple': /[a@]pple|app1e|appl3/i,
        'facebook': /f[a@]ceb[o0]{2}k|facebo0k/i,
        'netflix': /netf1ix|netfl1x/i
      };
      
      for (const [brand, pattern] of Object.entries(brandPatterns)) {
        if (pattern.test(hostname) && !hostname.endsWith(`${brand}.com`)) {
          return true;
        }
      }
      
      // Check for specific phishing patterns
      const phishingPatterns = [
        // PayPal phishing
        /paypal.*security.*\.tk/i,
        /paypal.*secure.*\.(tk|ml|ga|cf|gq)/i,
        /paypal-.*\.(tk|ml|ga|cf|gq)/i,
        /security.*paypal.*\.(tk|ml|ga|cf|gq)/i,
        
        // Other brand phishing
        /amazon.*verify.*\.(tk|ml|ga|cf|gq)/i,
        /microsoft.*security.*\.(tk|ml|ga|cf|gq)/i,
        /google.*security.*\.(tk|ml|ga|cf|gq)/i,
        /apple.*id.*\.(tk|ml|ga|cf|gq)/i,
        /netflix.*billing.*\.(tk|ml|ga|cf|gq)/i,
        
        // Generic phishing patterns
        /bit\.ly\/suspicious/i,
        /tinyurl\.com\/fake/i,
        /security.*alert/i,
        /verify.*account/i,
        /fake.*deal/i,
        /suspicious.*link/i,
        /urgent.*security/i,
        /suspended.*account/i,
        /account.*verify.*\.(tk|ml|ga|cf|gq)/i,
        /secure.*login.*\.(tk|ml|ga|cf|gq)/i
      ];
      
      if (phishingPatterns.some(pattern => pattern.test(fullUrl))) {
        return true;
      }
      
      // Check for @ symbol (credential stealing)
      if (fullUrl.includes('@') && !fullUrl.includes('mailto:')) {
        return true;
      }
      
      return false;
      
    } catch (error) {
      console.error('Error checking suspicious URL:', error);
      return true; // Invalid URLs are suspicious
    }
  }
  
  showEmailWarning(emailElement, analysis, emailData) {
    // Create warning overlay
    const warningOverlay = document.createElement('div');
    warningOverlay.className = 'phishguard-email-warning';
    warningOverlay.style.cssText = `
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      background: linear-gradient(90deg, #ff6b6b, #ee5a52);
      color: white;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: bold;
      z-index: 1000;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
      animation: phishguard-slide-in 0.3s ease-out;
    `;
    
    warningOverlay.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 18px;">🚨</span>
          <div>
            <div style="font-weight: bold; font-size: 13px;">PHISHING EMAIL DETECTED!</div>
            <div style="font-size: 11px; opacity: 0.9;">Risk Score: ${analysis.riskScore}/100</div>
          </div>
        </div>
        <button class="phishguard-email-close-btn" style="
          background: rgba(255,255,255,0.2);
          border: none;
          color: white;
          padding: 4px 8px;
          border-radius: 3px;
          cursor: pointer;
          font-size: 11px;
        ">×</button>
      </div>
    `;
    
    // Add CSS animation
    if (!document.getElementById('phishguard-styles')) {
      const styles = document.createElement('style');
      styles.id = 'phishguard-styles';
      styles.textContent = `
        @keyframes phishguard-slide-in {
          from { transform: translateY(-100%); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        .phishguard-email-warning {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
      `;
      document.head.appendChild(styles);
    }
    
    // Make email element relatively positioned
    emailElement.style.position = 'relative';
    
    // Insert warning at the top of the email element
    emailElement.insertBefore(warningOverlay, emailElement.firstChild);
    
    // Add detailed warning on click
    warningOverlay.addEventListener('click', (e) => {
      if (e.target.tagName !== 'BUTTON') {
        this.showDetailedEmailWarning(analysis, emailData);
      }
    });
    
    // Add close button handler
    const closeBtn = warningOverlay.querySelector('.phishguard-email-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        warningOverlay.remove();
      });
    }
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
      if (warningOverlay.parentElement) {
        warningOverlay.remove();
      }
    }, 10000);
  }
  
  showEmailContentWarning(contentElement, suspiciousLinks) {
    // Create warning for email content
    const warningBanner = document.createElement('div');
    warningBanner.style.cssText = `
      background: linear-gradient(90deg, #ff6b6b, #ee5a52);
      color: white;
      padding: 15px;
      margin: 15px 0;
      border-radius: 10px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      box-shadow: 0 4px 15px rgba(0,0,0,0.4);
      border: 2px solid #ff4757;
      animation: phishguard-pulse 2s infinite;
    `;
    
    warningBanner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
        <span style="font-size: 24px;">🚨</span>
        <div>
          <div style="font-weight: bold; font-size: 16px;">PhishGuard Pro - PHISHING EMAIL DETECTED!</div>
          <div style="font-size: 13px; opacity: 0.9;">${suspiciousLinks.length} suspicious link(s) found in this email</div>
        </div>
      </div>
      <div style="font-size: 13px; margin-bottom: 12px; line-height: 1.4;">
        <strong>⚠️ CRITICAL WARNING:</strong> This email contains suspicious links that may lead to phishing websites designed to steal your personal information, passwords, or financial data.
      </div>
      <div style="font-size: 12px; margin-bottom: 12px; background: rgba(255,255,255,0.1); padding: 8px; border-radius: 4px;">
        <strong>Suspicious Links:</strong><br>
        ${suspiciousLinks.slice(0, 3).map(link => `• ${link}`).join('<br>')}
        ${suspiciousLinks.length > 3 ? `<br>• ... and ${suspiciousLinks.length - 3} more` : ''}
      </div>
      <div style="display: flex; gap: 10px;">
        <button class="phishguard-close-btn" style="
          background: rgba(255,255,255,0.2);
          border: none;
          padding: 8px 16px;
          border-radius: 4px;
          color: white;
          cursor: pointer;
          font-size: 12px;
        ">I Understand</button>
        <button class="phishguard-report-btn" style="
          background: rgba(255,255,255,0.3);
          border: none;
          padding: 8px 16px;
          border-radius: 4px;
          color: white;
          cursor: pointer;
          font-size: 12px;
        ">Report as Phishing</button>
      </div>
    `;
    
    // Add CSS animation
    if (!document.getElementById('phishguard-email-styles')) {
      const styles = document.createElement('style');
      styles.id = 'phishguard-email-styles';
      styles.textContent = `
        @keyframes phishguard-pulse {
          0% { transform: scale(1); box-shadow: 0 4px 15px rgba(0,0,0,0.4); }
          50% { transform: scale(1.02); box-shadow: 0 6px 20px rgba(255,71,87,0.6); }
          100% { transform: scale(1); box-shadow: 0 4px 15px rgba(0,0,0,0.4); }
        }
      `;
      document.head.appendChild(styles);
    }
    
    // Insert warning at the top of email content
    contentElement.insertBefore(warningBanner, contentElement.firstChild);
    
    // Add close button handler
    const closeBtn = warningBanner.querySelector('.phishguard-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        warningBanner.remove();
      });
    }
    
    // Add report button handler
    const reportBtn = warningBanner.querySelector('.phishguard-report-btn');
    if (reportBtn) {
      reportBtn.addEventListener('click', () => {
        // Show confirmation
        if (confirm('Report this email as phishing? This will help improve PhishGuard Pro detection.')) {
          alert('Thank you! This email has been reported as phishing.');
          warningBanner.remove();
        }
      });
    }
  }
  
  showDetailedEmailWarning(analysis, emailData) {
    // Create detailed warning modal
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    modal.innerHTML = `
      <div style="
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 30px;
        border-radius: 15px;
        max-width: 500px;
        margin: 20px;
        max-height: 80vh;
        overflow-y: auto;
      ">
        <div style="display: flex; align-items: center; margin-bottom: 20px;">
          <div style="font-size: 48px; margin-right: 15px;">📧</div>
          <div>
            <h2 style="margin: 0; font-size: 24px;">Phishing Email Detected</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.8;">Risk Score: ${analysis.riskScore}/100</p>
          </div>
        </div>
        
        <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin: 15px 0;">
          <h3 style="margin: 0 0 10px 0; font-size: 16px;">Email Details:</h3>
          <div style="font-size: 14px;">
            <div><strong>From:</strong> ${emailData.from || 'Unknown'}</div>
            <div><strong>Subject:</strong> ${emailData.subject || 'No subject'}</div>
          </div>
        </div>
        
        <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin: 15px 0;">
          <h3 style="margin: 0 0 10px 0; font-size: 16px;">Detected Threats:</h3>
          <ul style="margin: 0; padding-left: 20px;">
            ${analysis.reasons.map(reason => `<li style="margin: 5px 0;">${reason}</li>`).join('')}
          </ul>
        </div>
        
        <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin: 15px 0;">
          <h3 style="margin: 0 0 10px 0; font-size: 16px;">Recommended Actions:</h3>
          <ul style="margin: 0; padding-left: 20px;">
            <li style="margin: 5px 0;">Do not click any links in this email</li>
            <li style="margin: 5px 0;">Do not reply to this email</li>
            <li style="margin: 5px 0;">Delete this email immediately</li>
            <li style="margin: 5px 0;">Report it as phishing if possible</li>
            <li style="margin: 5px 0;">Contact the organization directly through official channels</li>
          </ul>
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
          <button class="phishguard-email-close-btn" style="
            background: linear-gradient(90deg, #4ade80, #22c55e);
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            color: white;
            cursor: pointer;
            font-size: 14px;
          ">
            I Understand
          </button>
        </div>
      </div>
    `;
    
    document.body.appendChild(modal);
    
    // Add event listeners for close buttons
    const closeBtns = modal.querySelectorAll('.phishguard-email-close-btn');
    closeBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        modal.remove();
      });
    });
    
    // Close modal when clicking outside
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
  }
  
  cleanup() {
    // Clean up observers
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    
    // Clear processed emails set
    this.processedEmails.clear();
    
    console.log('🧹 Gmail Email Detector cleaned up');
  }
}

// Initialize Gmail email detector
if (window.location.hostname === 'mail.google.com') {
  let gmailDetector = null;
  
  // Wait for DOM to be ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      gmailDetector = new GmailEmailDetector();
    });
  } else {
    gmailDetector = new GmailEmailDetector();
  }
  
  // Clean up on page unload
  window.addEventListener('beforeunload', () => {
    if (gmailDetector) {
      gmailDetector.cleanup();
    }
  });
}

console.log('📧 Gmail Email Detector loaded');
console.log('📧 Gmail Email Detector loaded');