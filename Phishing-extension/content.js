// PhishGuard Pro - Lightweight Content Script
// Focused on phishing detection and user warnings

class ContentAnalyzer {
  constructor() {
    this.warningShown = false;
    this.pageAnalyzed = false;
    this.currentUrl = window.location.href;
    
    // Only initialize if we're in a valid web context
    if (this.isValidContext()) {
      this.init();
    }
  }
  
  isValidContext() {
    const url = window.location.href;
    return !url.startsWith('chrome://') && 
           !url.startsWith('chrome-extension://') && 
           !url.startsWith('moz-extension://') &&
           !url.startsWith('about:');
  }
  
  init() {
    // Analyze current page
    this.analyzeCurrentPage();
    
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse);
    });
    
    // Monitor for dynamic content changes
    this.observePageChanges();
  }
  
  async analyzeCurrentPage() {
    if (this.pageAnalyzed || !document.body) return;
    this.pageAnalyzed = true;
    
    try {
      // Quick page analysis for phishing indicators
      const pageAnalysis = this.analyzePageContent();
      
      if (pageAnalysis.riskScore > 30) {
        // Send analysis to background script
        chrome.runtime.sendMessage({
          type: 'PAGE_ANALYSIS_RESULT',
          url: window.location.href,
          analysis: pageAnalysis
        }).catch(() => {
          console.log('Background script not available for page analysis');
        });
      }
      
      // Monitor for suspicious form submissions
      this.monitorForms();
      
    } catch (error) {
      console.error('PhishGuard page analysis error:', error);
    }
  }
  
  analyzePageContent() {
    let riskScore = 0;
    const reasons = [];
    
    try {
      if (!document.body) {
        return { riskScore: 0, reasons: ['Page not fully loaded'] };
      }
      
      // Check for suspicious forms
      const forms = document.querySelectorAll('form');
      forms.forEach(form => {
        try {
          const action = form.getAttribute('action');
          const inputs = form.querySelectorAll('input[type="password"], input[type="email"]');
          
          if (inputs.length > 0 && action && action.startsWith('http')) {
            try {
              const actionUrl = new URL(action, window.location.href);
              if (actionUrl.hostname !== window.location.hostname) {
                riskScore += 40;
              reasons.push('Form submits to external domain');
              }
            } catch (e) {
              // Invalid action URL
            }
            }
            
            // Check for suspicious input names
          const suspiciousNames = ['ssn', 'social', 'pin', 'cvv', 'cardnumber'];
            inputs.forEach(input => {
            const name = (input.name || input.id || '').toLowerCase();
                if (suspiciousNames.some(sus => name.includes(sus))) {
              riskScore += 25;
                  reasons.push('Suspicious form field detected');
            }
          });
          
        } catch (e) {
          // Skip this form if there's an error
        }
      });
      
      // Check for suspicious links
      const links = document.querySelectorAll('a[href]');
      let misleadingLinks = 0;
      
      links.forEach(link => {
        try {
        const href = link.getAttribute('href');
        if (href && href.startsWith('http')) {
            const linkUrl = new URL(href);
            if (linkUrl.hostname !== window.location.hostname) {
              const linkText = link.textContent.toLowerCase();
              const hostname = linkUrl.hostname.toLowerCase();
              
              // Check for misleading link text
              const brandNames = ['paypal', 'amazon', 'microsoft', 'google', 'apple'];
              brandNames.forEach(brand => {
                if (linkText.includes(brand) && !hostname.includes(brand)) {
                  misleadingLinks++;
                }
              });
              }
            }
          } catch (e) {
          // Invalid link URL
        }
      });
      
      if (misleadingLinks > 0) {
        riskScore += misleadingLinks * 15;
        reasons.push(`${misleadingLinks} misleading links detected`);
      }
      
      // Check for urgency indicators
      const pageText = document.body.textContent.toLowerCase();
      const urgencyWords = [
        'urgent', 'immediate', 'expire', 'suspend', 'verify now', 'act fast', 
        'limited time', 'click here now', 'update immediately'
      ];
      
      const urgencyCount = urgencyWords.filter(word => pageText.includes(word)).length;
      if (urgencyCount >= 3) {
        riskScore += 25;
        reasons.push('Multiple urgency indicators detected');
      } else if (urgencyCount >= 1) {
        riskScore += 10;
        reasons.push('Urgency language detected');
      }
      
      // Check for poor grammar/spelling
      const grammarIssues = [
        'recieve', 'seperate', 'occured', 'loose', 'there account', 'you\'re account'
      ];
      
      const grammarCount = grammarIssues.filter(issue => pageText.includes(issue)).length;
      if (grammarCount > 0) {
        riskScore += 15;
        reasons.push('Poor grammar/spelling detected');
      }
      
      // Check for missing HTTPS on forms
      if (window.location.protocol !== 'https:' && forms.length > 0) {
        riskScore += 30;
        reasons.push('Insecure form on HTTP page');
      }
      
    } catch (error) {
      console.error('Content analysis error:', error);
    }
    
    return { riskScore: Math.min(riskScore, 100), reasons };
  }
  
  monitorForms() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
      form.addEventListener('submit', (e) => {
        const passwordFields = form.querySelectorAll('input[type="password"]');
        const emailFields = form.querySelectorAll('input[type="email"], input[name*="email"]');
        
        if (passwordFields.length > 0 || emailFields.length > 0) {
          const action = form.getAttribute('action') || window.location.href;
          
          try {
            const actionUrl = new URL(action, window.location.href);
            if (actionUrl.hostname !== window.location.hostname) {
              // External form submission - show warning
              if (this.showFormWarning(actionUrl.hostname)) {
                e.preventDefault();
                return false;
              }
            }
          } catch (error) {
            console.error('Form analysis error:', error);
          }
        }
      });
    });
  }
  
  showFormWarning(externalDomain) {
    const proceed = confirm(
      `⚠️ PhishGuard Pro Warning!\n\n` +
      `This form will send your credentials to "${externalDomain}" which is different from the current website.\n\n` +
      `This could be a phishing attempt designed to steal your login information.\n\n` +
      `Are you sure you want to continue?`
    );
    
    if (!proceed) {
      this.showEducationalMessage('Good security decision! You avoided a potential phishing attempt.');
    }
    
    return !proceed;
  }
  
  showEducationalMessage(message) {
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 15px 20px;
      border-radius: 10px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
      z-index: 10000;
      max-width: 350px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      animation: slideIn 0.3s ease-out;
    `;
    
    notification.innerHTML = `
      <style>
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
      </style>
      <div style="display: flex; align-items: center; margin-bottom: 10px;">
        <div style="font-size: 24px; margin-right: 10px;">🛡️</div>
        <div>
          <h4 style="margin: 0; font-size: 16px;">PhishGuard Pro</h4>
          <p style="margin: 0; font-size: 12px; opacity: 0.8;">Security Alert</p>
        </div>
      </div>
      <p style="margin: 0 0 15px 0; font-size: 14px; line-height: 1.4;">
        ${message}
      </p>
      <button class="phishguard-close-btn" style="
        background: rgba(255,255,255,0.2);
        border: none;
        padding: 8px 16px;
        border-radius: 6px;
        color: white;
        cursor: pointer;
        font-size: 12px;
        float: right;
      ">Got it!</button>
      <div style="clear: both;"></div>
    `;
    
    document.body.appendChild(notification);
    
    // Add event listener for close button
    const closeBtn = notification.querySelector('.phishguard-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        notification.remove();
      });
    }
    
    // Auto-remove after 8 seconds
    setTimeout(() => {
      if (notification.parentElement) {
        notification.remove();
      }
    }, 8000);
  }
  
  showPhishingWarning(data) {
    if (this.warningShown) return;
    this.warningShown = true;
    
    const warningBanner = document.createElement('div');
    warningBanner.id = 'phishguard-warning-banner';
    warningBanner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: linear-gradient(90deg, #ff6b6b, #ee5a52);
      color: white;
      padding: 15px;
      text-align: center;
      z-index: 10001;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      box-shadow: 0 2px 10px rgba(0,0,0,0.3);
      animation: warningSlide 0.3s ease-out;
    `;
    
    warningBanner.innerHTML = `
      <style>
        @keyframes warningSlide {
          from { transform: translateY(-100%); }
          to { transform: translateY(0); }
        }
        #phishguard-warning-banner .warning-details {
          font-size: 12px;
          margin-top: 5px;
          opacity: 0.9;
        }
        #phishguard-warning-banner .warning-actions {
          margin-top: 10px;
        }
        #phishguard-warning-banner button {
          background: rgba(255,255,255,0.2);
          border: none;
          padding: 5px 12px;
          border-radius: 4px;
          color: white;
          cursor: pointer;
          margin: 0 5px;
          font-size: 12px;
        }
        #phishguard-warning-banner button:hover {
          background: rgba(255,255,255,0.3);
        }
      </style>
      <div style="display: flex; align-items: center; justify-content: center; gap: 15px; flex-wrap: wrap;">
        <div style="font-size: 24px;">⚠️</div>
        <div style="flex: 1; min-width: 200px;">
          <div style="font-weight: bold;">PhishGuard Pro Security Warning!</div>
          <div class="warning-details">
            Risk Score: ${data.riskScore}/100 • 
            ${data.reasons.slice(0, 2).join(', ')}
          </div>
        </div>
        <div class="warning-actions">
          <button id="phishguard-dismiss-btn">
            Dismiss
          </button>
          <button id="phishguard-details-btn">
            Details
          </button>
        </div>
      </div>
    `;
    
    // Add to page
    document.body.insertBefore(warningBanner, document.body.firstChild);
    
    // Adjust page content
    document.body.style.paddingTop = '70px';
    
    // Add event listeners for buttons
    const dismissBtn = document.getElementById('phishguard-dismiss-btn');
    const detailsBtn = document.getElementById('phishguard-details-btn');
    
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => {
        warningBanner.style.display = 'none';
        document.body.style.paddingTop = '0';
      });
    }
    
    if (detailsBtn) {
      detailsBtn.addEventListener('click', () => {
        this.showDetailedWarning(data);
      });
    }
    
    // Auto-hide after 20 seconds
    setTimeout(() => {
      if (warningBanner.parentElement) {
        warningBanner.style.display = 'none';
        document.body.style.paddingTop = '0';
      }
    }, 20000);
  }
  
  showDetailedWarning(data) {
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
      z-index: 10002;
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
          <div style="font-size: 48px; margin-right: 15px;">⚠️</div>
          <div>
            <h2 style="margin: 0; font-size: 24px;">Security Threat Details</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.8;">Risk Score: ${data.riskScore}/100</p>
          </div>
        </div>
        
        <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin: 15px 0;">
          <h3 style="margin: 0 0 10px 0; font-size: 16px;">Detected Threats:</h3>
          <ul style="margin: 0; padding-left: 20px;">
            ${data.reasons.map(reason => `<li style="margin: 5px 0;">${reason}</li>`).join('')}
          </ul>
        </div>
        
        <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin: 15px 0;">
          <h3 style="margin: 0 0 10px 0; font-size: 16px;">Recommended Actions:</h3>
          <ul style="margin: 0; padding-left: 20px;">
            <li style="margin: 5px 0;">Do not enter personal information on this site</li>
            <li style="margin: 5px 0;">Verify the website URL carefully</li>
            <li style="margin: 5px 0;">Contact the organization directly through official channels</li>
            <li style="margin: 5px 0;">Report this site if you believe it's malicious</li>
          </ul>
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
          <button class="phishguard-modal-close-btn" style="
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
    
    // Add event listener for close button
    const closeBtn = modal.querySelector('.phishguard-modal-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        modal.remove();
      });
    }
  }
  
  observePageChanges() {
    // Monitor for dynamic content changes
    const observer = new MutationObserver((mutations) => {
      let shouldReanalyze = false;
      
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Check if new forms were added
              if (node.tagName === 'FORM' || (node.querySelector && node.querySelector('form'))) {
                shouldReanalyze = true;
              }
            }
          });
        }
      });
      
      if (shouldReanalyze) {
        // Debounce reanalysis
        clearTimeout(this.reanalysisTimeout);
        this.reanalysisTimeout = setTimeout(() => {
          this.monitorForms();
        }, 1000);
      }
    });
    
    // Start observing
    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
    }
  }
  
  handleMessage(request, sender, sendResponse) {
    try {
      console.log('📨 Content script received message:', request.type);
      
      switch (request.type) {
        case 'SHOW_PHISHING_WARNING':
          // WARNING DISABLED: Just log it, don't show popup (user requested)
          console.log('⚠️ Phishing warning detected (silent mode):', request);
          console.log('   Risk:', request.riskScore, '| Reasons:', request.reasons);
          // this.showPhishingWarning({ ... }); // DISABLED
          sendResponse({ success: true });
          break;
          
        case 'GET_PAGE_INFO':
          sendResponse({
            url: window.location.href,
            title: document.title,
            forms: document.querySelectorAll('form').length,
            links: document.querySelectorAll('a[href]').length,
            hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0
          });
          break;
          
        case 'ANALYZE_PAGE':
          const analysis = this.analyzePageContent();
          sendResponse(analysis);
          break;
          
        default:
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Content script message handling error:', error);
      sendResponse({ error: error.message });
    }
  }
}

// Initialize content analyzer only if in valid context
if (typeof chrome !== 'undefined' && chrome.runtime) {
  try {
    new ContentAnalyzer();
  } catch (error) {
    console.error('PhishGuard Pro content script initialization error:', error);
  }
} else {
  console.log('PhishGuard Pro: Not running in Chrome extension context');
}
