// PhishGuard Pro - Warning Page Event Handlers
// Separate file to avoid CSP violations

class WarningPageController {
    constructor() {
        this.urlParams = new URLSearchParams(window.location.search);
        this.init();
    }

    async init() {
        try {
            this.updatePageContent();
            await this.loadAdditionalData();
            this.setupEventListeners();
            this.startCountdown();
        } catch (error) {
            console.error('Warning page initialization error:', error);
        }
    }

    updatePageContent() {
        const blockedUrl = this.urlParams.get('url');
        const riskScore = this.urlParams.get('score');
        const reasons = this.urlParams.get('reasons');
        const method = this.urlParams.get('method');
        const action = this.urlParams.get('action');

        // Update risk score
        document.getElementById('risk-score').textContent = `Risk Score: ${riskScore || 'Unknown'}/100`;

        // Update URL display
        if (blockedUrl) {
            try {
                document.getElementById('blocked-url').textContent = decodeURIComponent(blockedUrl);
            } catch (e) {
                document.getElementById('blocked-url').textContent = blockedUrl;
            }
        }

        // Update threat reasons with improved error handling
        if (reasons) {
            try {
                // Try multiple decoding strategies
                let threatReasons;
                
                // Strategy 1: Try direct JSON parse (if already decoded)
                try {
                    threatReasons = JSON.parse(reasons);
                } catch (e1) {
                    // Strategy 2: Try decoding then parsing
                    try {
                        const decodedReasons = decodeURIComponent(reasons);
                        threatReasons = JSON.parse(decodedReasons);
                    } catch (e2) {
                        // Strategy 3: Try double decoding (in case of double encoding)
                        try {
                            const doubleDecoded = decodeURIComponent(decodeURIComponent(reasons));
                            threatReasons = JSON.parse(doubleDecoded);
                        } catch (e3) {
                            // Strategy 4: Manual parsing as fallback
                            console.warn('All parsing strategies failed, using fallback');
                            threatReasons = ['Security threat detected'];
                        }
                    }
                }
                
                const threatList = document.getElementById('warning-reasons');
                if (threatList && Array.isArray(threatReasons)) {
                    threatList.innerHTML = '';
                    
                    threatReasons.forEach(reason => {
                        const li = document.createElement('li');
                        // Clean up the reason text
                        const cleanReason = String(reason).replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
                        li.textContent = cleanReason;
                        threatList.appendChild(li);
                    });
                }
            } catch (error) {
                console.error('Error parsing threat reasons:', error);
                const threatList = document.getElementById('warning-reasons');
                if (threatList) {
                    threatList.innerHTML = '<li>Multiple security indicators detected</li>';
                }
            }
        }

        // Update method display if available
        if (method) {
            const methodBadge = document.createElement('div');
            methodBadge.style.cssText = `
                display: inline-block;
                background: rgba(127, 90, 240, 0.2);
                border: 1px solid rgba(127, 90, 240, 0.3);
                padding: 5px 12px;
                border-radius: 15px;
                font-size: 12px;
                margin: 10px 0;
            `;
            methodBadge.textContent = `Detection Method: ${decodeURIComponent(method)}`;
            
            const riskScoreElement = document.getElementById('risk-score');
            if (riskScoreElement && riskScoreElement.parentNode) {
                riskScoreElement.parentNode.insertBefore(methodBadge, riskScoreElement.nextSibling);
            }
        }
    }

    async loadAdditionalData() {
        try {
            // Load statistics
            const response = await this.sendMessage({ type: 'GET_STATS' });
            if (response && !response.error) {
                this.updateStatsDisplay(response);
            }
        } catch (error) {
            console.error('Error loading additional data:', error);
        }
    }

    updateStatsDisplay(stats) {
        const elements = {
            'threats-blocked': stats.threatsBlocked || 0,
            'user-level': stats.totalScans || 0
        };

        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                if (id === 'threats-blocked') {
                    element.textContent = `${value} Threats Blocked`;
                } else if (id === 'user-level') {
                    element.textContent = `Total Scans: ${value}`;
                }
            }
        });
    }

    setupEventListeners() {
        // Go home button
        const goHomeBtn = document.getElementById('go-home-btn');
        if (goHomeBtn) {
            goHomeBtn.addEventListener('click', () => this.goHome());
        }

        // Learn more button
        const learnMoreBtn = document.getElementById('learn-more-btn');
        if (learnMoreBtn) {
            learnMoreBtn.addEventListener('click', () => this.openExtension());
        }

        // Continue anyway button
        const continueBtn = document.getElementById('continue-btn');
        if (continueBtn) {
            continueBtn.addEventListener('click', () => this.continueAnyway());
        }

        // Auto-focus on the go home button for accessibility
        if (goHomeBtn) {
            goHomeBtn.focus();
        }
    }

    startCountdown() {
        let countdown = 10;
        const continueBtn = document.getElementById('continue-btn');
        if (!continueBtn) return;
        
        const originalText = continueBtn.textContent;
        
        const countdownInterval = setInterval(() => {
            if (countdown > 0) {
                continueBtn.textContent = `⚠️ Continue Anyway (${countdown}s)`;
                continueBtn.disabled = true;
                continueBtn.style.opacity = '0.5';
                countdown--;
            } else {
                continueBtn.textContent = originalText;
                continueBtn.disabled = false;
                continueBtn.style.opacity = '1';
                clearInterval(countdownInterval);
            }
        }, 1000);
    }

    goHome() {
        window.location.href = 'https://www.google.com';
    }

    openExtension() {
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage({
                type: 'OPEN_POPUP'
            });
        }
        // Fallback: show educational content
        this.showEducationalModal();
    }

    continueAnyway() {
        const confirmed = confirm(
            'WARNING: This site has been flagged as potentially dangerous.\n\n' +
            'Continuing may expose you to:\n' +
            '• Identity theft\n' +
            '• Credential harvesting\n' +
            '• Malware infection\n' +
            '• Financial fraud\n\n' +
            'Are you absolutely sure you want to continue?'
        );
        
        if (confirmed) {
            // Log risky decision
            if (typeof chrome !== 'undefined' && chrome.runtime) {
                chrome.runtime.sendMessage({
                    type: 'LOG_RISKY_DECISION',
                    url: this.urlParams.get('url'),
                    riskScore: this.urlParams.get('score')
                }).catch(err => console.log('Failed to log decision:', err));
            }
            
            const targetUrl = this.urlParams.get('url');
            if (targetUrl) {
                try {
                    window.location.href = decodeURIComponent(targetUrl);
                } catch (e) {
                    window.location.href = targetUrl;
                }
            }
        }
    }

    showEducationalModal() {
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
        `;
        
        modal.innerHTML = `
            <div style="
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 15px;
                max-width: 500px;
                margin: 20px;
            ">
                <h3 style="margin-bottom: 20px;">🎓 Phishing Education</h3>
                <div style="text-align: left; line-height: 1.6; margin-bottom: 20px;">
                    <p style="margin-bottom: 15px;"><strong>What is Phishing?</strong></p>
                    <p style="margin-bottom: 10px;">Phishing is a type of cyberattack where criminals impersonate legitimate organizations to steal sensitive information like passwords, credit card numbers, or personal data.</p>
                    
                    <p style="margin: 15px 0;"><strong>Common Signs of Phishing:</strong></p>
                    <ul style="margin-left: 20px;">
                        <li>Urgent or threatening language</li>
                        <li>Suspicious sender addresses</li>
                        <li>Requests for sensitive information</li>
                        <li>Poor grammar and spelling</li>
                        <li>Mismatched URLs and branding</li>
                    </ul>
                    
                    <p style="margin: 15px 0;"><strong>How to Stay Safe:</strong></p>
                    <ul style="margin-left: 20px;">
                        <li>Always verify the sender's identity</li>
                        <li>Check URLs carefully before clicking</li>
                        <li>Use two-factor authentication</li>
                        <li>Keep software updated</li>
                        <li>Trust your instincts - if something feels off, it probably is</li>
                    </ul>
                </div>
                <button id="close-educational-modal" style="
                    background: linear-gradient(90deg, #4ade80, #22c55e);
                    border: none;
                    padding: 10px 20px;
                    border-radius: 8px;
                    color: white;
                    cursor: pointer;
                ">Got it! (+10 XP)</button>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Add event listener for close button
        const closeBtn = document.getElementById('close-educational-modal');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                modal.remove();
            });
        }
        
        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
        
        // Log educational interaction
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage({
                type: 'LOG_EDUCATIONAL_INTERACTION',
                action: 'phishing_education_viewed'
            }).catch(err => console.log('Failed to log interaction:', err));
        }
    }

    async sendMessage(message) {
        return new Promise((resolve) => {
            if (typeof chrome !== 'undefined' && chrome.runtime) {
                chrome.runtime.sendMessage(message, (response) => {
                    if (chrome.runtime.lastError) {
                        console.error('Message error:', chrome.runtime.lastError);
                        resolve({ error: chrome.runtime.lastError.message });
                    } else {
                        resolve(response);
                    }
                });
            } else {
                resolve({ error: 'Chrome runtime not available' });
            }
        });
    }
}

// Initialize warning page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new WarningPageController();
});