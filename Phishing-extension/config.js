// PhishGuard Pro - Configuration Management
// Centralized configuration for the extension

class PhishGuardConfig {
  constructor() {
    this.defaultConfig = {
      // ML Configuration
      ml: {
        enabled: true,
        backendUrl: 'http://localhost:5000/predict',
        timeout: 5000,
        retryAttempts: 3,
        fallbackToHeuristics: true
      },
      
      // Detection Settings
      detection: {
        sensitivity: 'medium', // low, medium, high
        realTimeProtection: true,
        formMonitoring: true,
        emailAnalysis: true,
        whatsappProtection: true
      },
      
      // UI Settings
      ui: {
        notifications: true,
        showWarnings: true,
        darkMode: true,
        compactMode: false
      },
      
      // Performance Settings
      performance: {
        cacheExpiry: 24 * 60 * 60 * 1000, // 24 hours
        maxCacheSize: 1000,
        batchSize: 10,
        debounceDelay: 300
      },
      
      // Security Settings
      security: {
        whitelist: [
          'google.com', 'microsoft.com', 'amazon.com', 'paypal.com',
          'apple.com', 'facebook.com', 'twitter.com', 'github.com',
          'netflix.com', 'linkedin.com', 'instagram.com', 'youtube.com'
        ],
        blacklist: [],
        suspiciousTLDs: ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'],
        enableHomographDetection: true,
        enableBrandSpoofingDetection: true
      }
    };
    
    this.config = { ...this.defaultConfig };
    this.loadConfig();
  }
  
  async loadConfig() {
    try {
      const result = await chrome.storage.local.get(['phishguardConfig']);
      if (result.phishguardConfig) {
        this.config = this.mergeConfig(this.defaultConfig, result.phishguardConfig);
        console.log('📋 Configuration loaded:', this.config);
      }
    } catch (error) {
      console.error('Error loading configuration:', error);
      this.config = { ...this.defaultConfig };
    }
  }
  
  async saveConfig() {
    try {
      await chrome.storage.local.set({ phishguardConfig: this.config });
      console.log('💾 Configuration saved');
    } catch (error) {
      console.error('Error saving configuration:', error);
    }
  }
  
  mergeConfig(defaultConfig, userConfig) {
    const merged = { ...defaultConfig };
    
    for (const key in userConfig) {
      if (typeof userConfig[key] === 'object' && !Array.isArray(userConfig[key])) {
        merged[key] = { ...merged[key], ...userConfig[key] };
      } else {
        merged[key] = userConfig[key];
      }
    }
    
    return merged;
  }
  
  get(key) {
    return this.config[key];
  }
  
  set(key, value) {
    this.config[key] = value;
    this.saveConfig();
  }
  
  update(updates) {
    this.config = this.mergeConfig(this.config, updates);
    this.saveConfig();
  }
  
  reset() {
    this.config = { ...this.defaultConfig };
    this.saveConfig();
  }
}

// Export for use in other scripts
if (typeof window !== 'undefined') {
  window.PhishGuardConfig = PhishGuardConfig;
}

console.log('⚙️ PhishGuard Config loaded');
