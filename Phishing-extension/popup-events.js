// PhishGuard Pro - Popup Event Handlers
// Separate file to avoid CSP violations

document.addEventListener('DOMContentLoaded', function() {
    // Initialize event listeners after DOM is loaded
    initializePopupEvents();
});

function initializePopupEvents() {
    // Toggle switches
    setupToggleSwitches();
    
    // Educational buttons
    const trainingBtn = document.getElementById('security-training');
    if (trainingBtn) {
        trainingBtn.addEventListener('click', handleSecurityTraining);
    }
    
    const learnBtn = document.getElementById('learn-phishing');
    if (learnBtn) {
        learnBtn.addEventListener('click', handleLearnPhishing);
    }
    
    const tipsBtn = document.getElementById('security-tips');
    if (tipsBtn) {
        tipsBtn.addEventListener('click', handleSecurityTips);
    }
}

function setupToggleSwitches() {
    const toggles = [
        { id: 'toggle-protection', setting: 'realTimeProtection' },
        { id: 'toggle-forms', setting: 'formMonitoring' },
        { id: 'toggle-notifications', setting: 'notifications' }
    ];
    
    toggles.forEach(({ id, setting }) => {
        const toggle = document.getElementById(id);
        if (toggle) {
            toggle.addEventListener('click', () => toggleSetting(setting, toggle));
        }
    });
}

function handleSecurityTraining() {
    // Open interactive phishing training
    chrome.tabs.create({
        url: 'https://phishingquiz.withgoogle.com/'
    });
    showNotification('Opening Google\'s phishing quiz...', 'info');
}

function handleLearnPhishing() {
    // Open comprehensive phishing education resource
    chrome.tabs.create({
        url: 'https://www.consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams'
    });
    showNotification('Opening phishing education guide...', 'info');
}

function handleSecurityTips() {
    // Show security tips modal or open resource
    showSecurityTipsModal();
}

function toggleSetting(setting, toggle) {
    // Get current settings from popup instance or use defaults
    const settings = window.phishGuardPopup?.settings || {
        realTimeProtection: true,
        formMonitoring: true,
        notifications: true
    };
    
    settings[setting] = !settings[setting];
    updateToggleState(toggle, settings[setting]);
    
    // Save settings if popup instance exists
    if (window.phishGuardPopup) {
        window.phishGuardPopup.settings = settings;
        window.phishGuardPopup.saveSettings();
    }
    
    const settingNames = {
        realTimeProtection: 'Real-time Protection',
        formMonitoring: 'Form Monitoring',
        notifications: 'Notifications'
    };
    
    showNotification(
        `${settingNames[setting]} ${settings[setting] ? 'enabled' : 'disabled'}`,
        'info'
    );
}

function updateToggleState(toggle, isActive) {
    if (isActive) {
        toggle.classList.add('active');
    } else {
        toggle.classList.remove('active');
    }
}


function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existing = document.querySelector('.notification');
    if (existing) {
        existing.remove();
    }
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 3000);
}

async function sendMessage(message) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(message, (response) => {
            if (chrome.runtime.lastError) {
                console.error('Message error:', chrome.runtime.lastError);
                resolve({ error: chrome.runtime.lastError.message });
            } else {
                resolve(response);
            }
        });
    });
}

function showSecurityTipsModal() {
    // Create modal overlay
    const modalOverlay = document.createElement('div');
    modalOverlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
        animation: fadeIn 0.3s ease;
    `;
    
    // Create modal content
    const modalContent = document.createElement('div');
    modalContent.style.cssText = `
        background: linear-gradient(135deg, #161B22 0%, #1C2128 100%);
        border: 2px solid rgba(11, 163, 96, 0.3);
        border-radius: 20px;
        padding: 30px;
        max-width: 500px;
        max-height: 80vh;
        overflow-y: auto;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        animation: slideUp 0.3s ease;
    `;
    
    modalContent.innerHTML = `
        <h2 style="color: #0BA360; margin-bottom: 20px; font-size: 24px; display: flex; align-items: center; gap: 10px;">
            <span>🛡️</span> Essential Security Tips
        </h2>
        
        <div style="color: #E6EDF3; line-height: 1.8;">
            <div style="margin-bottom: 20px; padding: 15px; background: rgba(11, 163, 96, 0.1); border-radius: 10px; border-left: 4px solid #0BA360;">
                <h3 style="color: #3CBA92; font-size: 16px; margin-bottom: 10px;">🔍 Check URLs Carefully</h3>
                <p style="font-size: 14px; color: #C9D1D9;">Always verify the website address before entering sensitive information. Look for misspellings like "g00gle.com" or "paypa1.com".</p>
            </div>
            
            <div style="margin-bottom: 20px; padding: 15px; background: rgba(11, 163, 96, 0.1); border-radius: 10px; border-left: 4px solid #0BA360;">
                <h3 style="color: #3CBA92; font-size: 16px; margin-bottom: 10px;">🔐 Look for HTTPS</h3>
                <p style="font-size: 14px; color: #C9D1D9;">Legitimate sites use HTTPS (padlock icon). However, phishing sites can also have HTTPS, so check the full URL carefully.</p>
            </div>
            
            <div style="margin-bottom: 20px; padding: 15px; background: rgba(11, 163, 96, 0.1); border-radius: 10px; border-left: 4px solid #0BA360;">
                <h3 style="color: #3CBA92; font-size: 16px; margin-bottom: 10px;">⏰ Don't Rush</h3>
                <p style="font-size: 14px; color: #C9D1D9;">Phishing attacks create false urgency ("Your account will be closed!"). Take time to verify requests, especially for passwords or payment info.</p>
            </div>
            
            <div style="margin-bottom: 20px; padding: 15px; background: rgba(11, 163, 96, 0.1); border-radius: 10px; border-left: 4px solid #0BA360;">
                <h3 style="color: #3CBA92; font-size: 16px; margin-bottom: 10px;">📧 Verify Email Senders</h3>
                <p style="font-size: 14px; color: #C9D1D9;">Check the sender's email address carefully. Phishing emails often come from addresses like "security@paypal-verify.tk" instead of official domains.</p>
            </div>
            
            <div style="margin-bottom: 20px; padding: 15px; background: rgba(11, 163, 96, 0.1); border-radius: 10px; border-left: 4px solid #0BA360;">
                <h3 style="color: #3CBA92; font-size: 16px; margin-bottom: 10px;">🔑 Use Strong Passwords</h3>
                <p style="font-size: 14px; color: #C9D1D9;">Use unique passwords for each account and enable two-factor authentication (2FA) wherever possible.</p>
            </div>
            
            <div style="margin-bottom: 20px; padding: 15px; background: rgba(11, 163, 96, 0.1); border-radius: 10px; border-left: 4px solid #0BA360;">
                <h3 style="color: #3CBA92; font-size: 16px; margin-bottom: 10px;">🚨 Suspicious TLDs</h3>
                <p style="font-size: 14px; color: #C9D1D9;">Be extra cautious with domains ending in .tk, .ml, .ga, .cf - these are commonly used for phishing attacks.</p>
            </div>
        </div>
        
        <button id="close-tips-modal" style="
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #0BA360, #3CBA92);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
            transition: all 0.3s ease;
        ">
            Got It! 👍
        </button>
    `;
    
    modalOverlay.appendChild(modalContent);
    document.body.appendChild(modalOverlay);
    
    // Add animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes slideUp {
            from { transform: translateY(50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
    `;
    document.head.appendChild(style);
    
    // Close button handler
    const closeBtn = modalContent.querySelector('#close-tips-modal');
    closeBtn.addEventListener('click', () => {
        modalOverlay.style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => modalOverlay.remove(), 300);
    });
    
    // Close on overlay click
    modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) {
            modalOverlay.style.animation = 'fadeOut 0.3s ease';
            setTimeout(() => modalOverlay.remove(), 300);
        }
    });
    
    // Add hover effect to button
    closeBtn.addEventListener('mouseenter', () => {
        closeBtn.style.transform = 'translateY(-2px)';
        closeBtn.style.boxShadow = '0 8px 20px rgba(11, 163, 96, 0.5)';
    });
    closeBtn.addEventListener('mouseleave', () => {
        closeBtn.style.transform = 'translateY(0)';
        closeBtn.style.boxShadow = 'none';
    });
}
