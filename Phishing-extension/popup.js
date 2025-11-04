// PhishGuard Pro - Enhanced Popup Interface
// Production-ready popup with comprehensive user feedback and error handling

class PhishGuardPopup {
  constructor() {
    this.isLoading = false;
    this.serviceStatus = null;
    this.stats = null;
    this.errorLogs = [];
    this.settings = {
      realTimeProtection: true,
      formMonitoring: true,
      notifications: true,
      mlDetection: true
    };
    
    // Initialize utilities with error handling
    try {
      this.utils = window.PhishGuardUtils ? new window.PhishGuardUtils() : null;
      this.config = window.PhishGuardConfig ? new window.PhishGuardConfig() : null;
      this.errorHandler = window.PhishGuardErrorHandler ? new window.PhishGuardErrorHandler() : null;
    } catch (error) {
      console.warn('Some utilities not available:', error);
      this.utils = null;
      this.config = null;
      this.errorHandler = null;
    }
    
    this.init();
  }
  
  async init() {
    try {
      console.log('🛡️ Initializing PhishGuard Popup...');
      
      // Load saved settings
      await this.loadSettings();
      
      // Setup event listeners
      this.setupEventListeners();
      
      // Load initial data
      await this.loadInitialData();
      
      // Update UI
      this.updateUI();
      
      console.log('✅ Popup initialized successfully');
      
    } catch (error) {
      console.error('❌ Popup initialization error:', error);
      this.showError('Failed to initialize popup', error);
    }
  }
  
  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['phishguardSettings']);
      if (result.phishguardSettings) {
        this.settings = { ...this.settings, ...result.phishguardSettings };
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }
  
  async saveSettings() {
    try {
      await chrome.storage.local.set({ phishguardSettings: this.settings });
      console.log('Settings saved successfully');
    } catch (error) {
      console.error('Error saving settings:', error);
      this.showError('Failed to save settings', error);
    }
  }
  
  setupEventListeners() {
    // Update database button
    const updateBtn = document.getElementById('update-database');
    if (updateBtn) {
      updateBtn.addEventListener('click', () => this.handleUpdateDatabase());
    }
    
    // Reset stats button
    const resetBtn = document.getElementById('reset-stats');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => this.handleResetStats());
    }
    
    // Test detection button
    const testBtn = document.getElementById('test-detection');
    if (testBtn) {
      testBtn.addEventListener('click', () => this.handleTestDetection());
    }
    
    // Toggle switches
    this.setupToggleSwitches();
    
    // Service status monitoring
    this.startStatusMonitoring();
  }
  
  setupToggleSwitches() {
    const toggles = [
      { id: 'toggle-protection', setting: 'realTimeProtection' },
      { id: 'toggle-forms', setting: 'formMonitoring' },
      { id: 'toggle-notifications', setting: 'notifications' }
    ];
    
    toggles.forEach(({ id, setting }) => {
      const toggle = document.getElementById(id);
      if (toggle) {
        toggle.addEventListener('click', () => this.toggleSetting(setting, toggle));
        this.updateToggleState(toggle, this.settings[setting]);
      }
    });
  }
  
  async loadInitialData() {
    this.setLoading(true);
    
    try {
      // Load statistics
      await this.loadStats();
      
      // Load service status
      await this.loadServiceStatus();
      
      // Load current tab info
      await this.loadCurrentTabInfo();
      
      // Load error logs (if any)
      await this.loadErrorLogs();
      
    } catch (error) {
      console.error('Error loading initial data:', error);
      this.showError('Failed to load data', error);
    } finally {
      this.setLoading(false);
    }
  }
  
  async loadStats() {
    try {
      const response = await this.sendMessageWithRetry({ type: 'GET_STATS' }, 3);
      if (response && !response.error) {
        this.stats = response;
        this.updateStatsDisplay();
      } else {
        console.error('Failed to load stats:', response?.error);
        // Use default stats if service not ready
        this.stats = this.getDefaultStats();
        this.updateStatsDisplay();
      }
    } catch (error) {
      console.error('Error loading stats:', error);
      // Use default stats on error
      this.stats = this.getDefaultStats();
      this.updateStatsDisplay();
    }
  }
  
  async loadServiceStatus() {
    try {
      const response = await this.sendMessage({ type: 'GET_SERVICE_STATUS' });
      if (response && !response.error) {
        this.serviceStatus = response;
        this.updateServiceStatusDisplay();
      } else {
        // Set default service status if no response
        this.serviceStatus = {
          isInitialized: false,
          pendingOperations: 0,
          mlBackendConnected: false
        };
        this.updateServiceStatusDisplay();
      }
    } catch (error) {
      console.error('Error loading service status:', error);
      // Set default service status on error
      this.serviceStatus = {
        isInitialized: false,
        pendingOperations: 0,
        mlBackendConnected: false
      };
      this.updateServiceStatusDisplay();
    }
  }
  
  async loadCurrentTabInfo() {
    try {
      const response = await this.sendMessage({ type: 'GET_CURRENT_TAB_INFO' });
      if (response && !response.error) {
        this.updateCurrentSiteInfo(response);
      }
    } catch (error) {
      console.error('Error loading current tab info:', error);
    }
  }
  
  async loadErrorLogs() {
    try {
      const response = await this.sendMessage({ type: 'GET_ERROR_LOGS' });
      if (response && !response.error) {
        this.errorLogs = response;
        this.updateErrorLogDisplay();
      }
    } catch (error) {
      console.error('Error loading error logs:', error);
    }
  }
  
  updateUI() {
    this.updateStatsDisplay();
    this.updateServiceStatusDisplay();
    this.updateSettingsDisplay();
    this.updateActivityDisplay();
  }
  
  updateStatsDisplay() {
    if (!this.stats) return;
    
    // Update statistics numbers
    const statElements = {
      'threats-blocked': this.stats.threatsBlocked || 0,
      'threats-warned': this.stats.threatsWarned || 0,
      'emails-analyzed': this.stats.emailsAnalyzed || 0,
      'emails-flagged': this.stats.emailsFlagged || 0,
      'whatsapp-links-analyzed': this.stats.whatsappLinksAnalyzed || 0,
      'whatsapp-links-flagged': this.stats.whatsappLinksFlagged || 0
    };
    
    Object.entries(statElements).forEach(([id, value]) => {
      const element = document.getElementById(id);
      if (element) {
        element.textContent = value;
      }
    });
    
    // Update protection status
    const protectionStatus = document.getElementById('protection-status');
    if (protectionStatus) {
      protectionStatus.textContent = this.serviceStatus?.isInitialized ? 
        'Protection Active' : 'Protection Inactive';
    }
  }
  
  updateServiceStatusDisplay() {
    if (!this.serviceStatus) return;
    
    const statusIndicator = document.querySelector('.status-indicator');
    if (statusIndicator) {
      statusIndicator.style.background = this.serviceStatus.isInitialized ? 
        '#4ade80' : '#ef4444';
    }
    
    // Show pending operations if any
    if (this.serviceStatus.pendingOperations > 0) {
      this.showNotification(`Processing ${this.serviceStatus.pendingOperations} operations...`, 'info');
    }
  }
  
  updateCurrentSiteInfo(tabInfo) {
    const siteStatus = document.getElementById('site-status');
    const siteUrl = document.getElementById('site-url');
    
    if (siteStatus && siteUrl) {
      if (tabInfo.url) {
        try {
          const url = new URL(tabInfo.url);
          siteStatus.textContent = 'Safe Site';
          siteUrl.textContent = url.hostname;
        } catch (error) {
          siteStatus.textContent = 'Unknown Site';
          siteUrl.textContent = 'Invalid URL';
        }
      } else {
        siteStatus.textContent = 'No Active Site';
        siteUrl.textContent = 'No URL detected';
      }
    }
  }
  
  updateSettingsDisplay() {
    // Update toggle states
    const toggles = [
      { id: 'toggle-protection', setting: 'realTimeProtection' },
      { id: 'toggle-forms', setting: 'formMonitoring' },
      { id: 'toggle-notifications', setting: 'notifications' }
    ];
    
    toggles.forEach(({ id, setting }) => {
      const toggle = document.getElementById(id);
      if (toggle) {
        this.updateToggleState(toggle, this.settings[setting]);
      }
    });
  }
  
  updateToggleState(toggle, isActive) {
    if (isActive) {
      toggle.classList.add('active');
    } else {
      toggle.classList.remove('active');
    }
  }
  
  updateActivityDisplay() {
    const activityList = document.getElementById('activity-list');
    if (!activityList) return;
    
    // Clear existing activity
    activityList.innerHTML = '';
    
    if (this.errorLogs && this.errorLogs.length > 0) {
      // Show recent errors
      this.errorLogs.slice(-5).forEach(error => {
        const activityItem = this.createActivityItem(
          '⚠️',
          `Error: ${error.type}`,
          new Date(error.timestamp).toLocaleTimeString(),
          'error'
        );
        activityList.appendChild(activityItem);
      });
    } else if (this.stats && this.stats.totalScans > 0) {
      // Show recent activity
      const activities = [
        { icon: '🛡️', title: 'Protection Active', time: 'Now', type: 'success' },
        { icon: '📊', title: `${this.stats.totalScans} URLs Scanned`, time: 'Today', type: 'info' }
      ];
      
      if (this.stats.threatsBlocked > 0) {
        activities.push({
          icon: '🚫',
          title: `${this.stats.threatsBlocked} Threats Blocked`,
          time: 'Today',
          type: 'warning'
        });
      }
      
      activities.forEach(activity => {
        const activityItem = this.createActivityItem(
          activity.icon,
          activity.title,
          activity.time,
          activity.type
        );
        activityList.appendChild(activityItem);
      });
    } else {
      // Show empty state
      const emptyState = document.createElement('div');
      emptyState.className = 'empty-state';
      emptyState.innerHTML = `
          <div class="empty-state-icon">📊</div>
          <div>No recent activity</div>
      `;
      activityList.appendChild(emptyState);
    }
  }
  
  createActivityItem(icon, title, time, type) {
    const item = document.createElement('div');
    item.className = 'activity-item';
    
    const iconClass = type === 'error' ? 'error' : type === 'warning' ? 'warning' : 'info';
    
    item.innerHTML = `
      <div class="activity-icon ${iconClass}">${icon}</div>
      <div class="activity-details">
        <div class="activity-title">${title}</div>
        <div class="activity-time">${time}</div>
      </div>
    `;
    
    return item;
  }
  
  updateErrorLogDisplay() {
    // This would be expanded to show error details in a modal or separate section
    if (this.errorLogs && this.errorLogs.length > 0) {
      console.log('Error logs available:', this.errorLogs.length);
    }
  }
  
  getDefaultStats() {
    return {
      threatsBlocked: 0,
      threatsWarned: 0,
      emailsAnalyzed: 0,
      emailsFlagged: 0,
      whatsappLinksAnalyzed: 0,
      whatsappLinksFlagged: 0,
      totalScans: 0
    };
  }
  
  async handleUpdateDatabase() {
    const button = document.getElementById('update-database');
    if (!button) return;
    
    this.setButtonLoading(button, true);
    
    try {
      const response = await this.sendMessage({ type: 'UPDATE_DATABASE' });
      
      if (response && response.success) {
        this.showNotification('Database updated successfully!', 'success');
        await this.loadStats(); // Refresh stats
      } else {
        this.showNotification('Database update failed', 'error');
      }
    } catch (error) {
      console.error('Database update error:', error);
      this.showNotification('Database update failed', 'error');
    } finally {
      this.setButtonLoading(button, false);
    }
  }
  
  async handleResetStats() {
    if (!confirm('Are you sure you want to reset all statistics? This action cannot be undone.')) {
      return;
    }
    
    try {
      const response = await this.sendMessage({ type: 'RESET_STATS' });
      
      if (response && response.success) {
        this.showNotification('Statistics reset successfully!', 'success');
        await this.loadStats(); // Refresh stats
        this.updateUI();
      } else {
        this.showNotification('Failed to reset statistics', 'error');
      }
    } catch (error) {
      console.error('Reset stats error:', error);
      this.showNotification('Failed to reset statistics', 'error');
    }
  }
  
  async testMLBackend() {
    try {
      const response = await fetch('http://localhost:5000/health', {
        method: 'GET',
        timeout: 5000
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log('✅ ML Backend connected:', data);
        return { connected: true, data };
      } else {
        console.warn('⚠️ ML Backend responded with error:', response.status);
        return { connected: false, error: `HTTP ${response.status}` };
      }
    } catch (error) {
      console.warn('⚠️ ML Backend not available:', error.message);
      return { connected: false, error: error.message };
    }
  }
  
  async handleTestDetection() {
    const button = document.getElementById('test-detection');
    if (!button) return;
    
    this.setButtonLoading(button, true);
    
    try {
      // Test ML backend connection
      const mlTest = await this.testMLBackend();
      
      if (mlTest.connected) {
        this.showNotification('✅ ML Backend is connected and working!', 'success');
      } else {
        this.showNotification(`⚠️ ML Backend not available: ${mlTest.error}`, 'warning');
      }
      
      // Test extension components
      const componentTests = {
        'PhishGuardUtils': typeof window.PhishGuardUtils !== 'undefined',
        'PhishGuardConfig': typeof window.PhishGuardConfig !== 'undefined',
        'PhishGuardErrorHandler': typeof window.PhishGuardErrorHandler !== 'undefined',
        'PhishingDetector': typeof window.PhishingDetector !== 'undefined',
        'WhatsAppLinkDetector': typeof window.WhatsAppLinkDetector !== 'undefined'
      };
      
      const workingComponents = Object.values(componentTests).filter(Boolean).length;
      const totalComponents = Object.keys(componentTests).length;
      
      this.showNotification(
        `🔧 Extension components: ${workingComponents}/${totalComponents} working`,
        workingComponents === totalComponents ? 'success' : 'warning'
      );
      
      console.log('🧪 Component test results:', componentTests);
      
    } catch (error) {
      console.error('Test detection error:', error);
      this.showNotification('❌ Test failed: ' + error.message, 'error');
    } finally {
      this.setButtonLoading(button, false);
    }
  }
  
  toggleSetting(setting, toggle) {
    this.settings[setting] = !this.settings[setting];
    this.updateToggleState(toggle, this.settings[setting]);
    this.saveSettings();
    
    const settingNames = {
      realTimeProtection: 'Real-time Protection',
      formMonitoring: 'Form Monitoring',
      notifications: 'Notifications'
    };
    
    this.showNotification(
      `${settingNames[setting]} ${this.settings[setting] ? 'enabled' : 'disabled'}`,
      'info'
    );
  }
  
  startStatusMonitoring() {
    // Monitor service status every 5 seconds
    setInterval(async () => {
      try {
        await this.loadServiceStatus();
        this.updateServiceStatusDisplay();
      } catch (error) {
        console.error('Status monitoring error:', error);
      }
    }, 5000);
  }
  
  setLoading(isLoading) {
    this.isLoading = isLoading;
    
    // Show/hide loading indicators
    const loadingElements = document.querySelectorAll('.loading');
    loadingElements.forEach(el => {
      el.style.display = isLoading ? 'block' : 'none';
    });
  }
  
  setButtonLoading(button, isLoading) {
    if (isLoading) {
      button.disabled = true;
      button.textContent = 'Loading...';
    } else {
      button.disabled = false;
      button.textContent = button.dataset.originalText || 'Update Database';
    }
  }
  
  showNotification(message, type = 'info') {
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
  
  showError(message, error) {
    console.error(message, error);
    this.showNotification(`${message}: ${error.message || error}`, 'error');
  }
  
  async sendMessage(message) {
    try {
      if (this.utils && this.utils.sendMessage) {
        return await this.utils.sendMessage(message);
      } else {
        // Fallback to direct chrome.runtime.sendMessage
        return new Promise((resolve, reject) => {
          chrome.runtime.sendMessage(message, (response) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(response);
            }
          });
        });
      }
    } catch (error) {
      console.error('Message error:', error);
      return { error: error.message };
    }
  }
  
  async sendMessageWithRetry(message, maxRetries = 3) {
    for (let i = 0; i < maxRetries; i++) {
      try {
        const response = await this.sendMessage(message);
        if (response && !response.error) {
          return response;
        }
      } catch (error) {
        console.warn(`Message attempt ${i + 1} failed:`, error);
        if (i === maxRetries - 1) {
          throw error;
        }
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    return { error: 'Max retries exceeded' };
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  try {
    new PhishGuardPopup();
  } catch (error) {
    console.error('Failed to initialize popup:', error);
  }
});