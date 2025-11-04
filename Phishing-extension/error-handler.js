// PhishGuard Pro - Error Handler
// Centralized error handling and logging

class PhishGuardErrorHandler {
  constructor() {
    this.errorLogs = [];
    this.maxLogs = 100;
    this.retryAttempts = 3;
    this.retryDelay = 1000;
  }
  
  async handleError(errorType, error, context = {}) {
    const errorLog = {
      type: errorType,
      message: error.message || error,
      stack: error.stack,
      timestamp: Date.now(),
      context: context,
      userAgent: navigator.userAgent,
      url: window.location?.href || 'unknown'
    };
    
    // Add to error logs
    this.errorLogs.unshift(errorLog);
    if (this.errorLogs.length > this.maxLogs) {
      this.errorLogs = this.errorLogs.slice(0, this.maxLogs);
    }
    
    // Log to console
    console.error(`❌ PhishGuard Error [${errorType}]:`, error, context);
    
    // Save to storage
    await this.saveErrorLogs();
    
    // Handle specific error types
    switch (errorType) {
      case 'ML_BACKEND_ERROR':
        return this.handleMLBackendError(error, context);
      case 'STORAGE_ERROR':
        return this.handleStorageError(error, context);
      case 'NETWORK_ERROR':
        return this.handleNetworkError(error, context);
      case 'INITIALIZATION_FAILED':
        return this.handleInitializationError(error, context);
      default:
        return this.handleGenericError(error, context);
    }
  }
  
  async handleMLBackendError(error, context) {
    console.warn('🤖 ML backend unavailable, falling back to heuristics');
    
    // Notify background script
    try {
      await chrome.runtime.sendMessage({
        type: 'ML_BACKEND_ERROR',
        error: error.message,
        fallback: true
      });
    } catch (e) {
      console.error('Failed to notify background script:', e);
    }
    
    return { fallback: true, error: error.message };
  }
  
  async handleStorageError(error, context) {
    console.warn('💾 Storage error, using memory fallback');
    
    // Try to clear storage and retry
    try {
      await chrome.storage.local.clear();
      console.log('Storage cleared, retrying...');
    } catch (e) {
      console.error('Failed to clear storage:', e);
    }
    
    return { retry: true, error: error.message };
  }
  
  async handleNetworkError(error, context) {
    console.warn('🌐 Network error, will retry');
    
    // Implement exponential backoff
    const delay = this.retryDelay * Math.pow(2, context.attempt || 0);
    
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({ retry: true, delay: delay });
      }, delay);
    });
  }
  
  async handleInitializationError(error, context) {
    console.error('🚨 Critical initialization error');
    
    // Try to recover by resetting configuration
    try {
      await chrome.storage.local.clear();
      console.log('Configuration reset, please reload extension');
    } catch (e) {
      console.error('Failed to reset configuration:', e);
    }
    
    return { critical: true, error: error.message };
  }
  
  handleGenericError(error, context) {
    console.error('⚠️ Generic error occurred:', error);
    return { error: error.message };
  }
  
  async saveErrorLogs() {
    try {
      await chrome.storage.local.set({ 
        phishguardErrorLogs: this.errorLogs
      });
    } catch (error) {
      console.error('Failed to save error logs:', error);
    }
  }
  
  async loadErrorLogs() {
    try {
      const result = await chrome.storage.local.get(['phishguardErrorLogs']);
      if (result.phishguardErrorLogs) {
        this.errorLogs = result.phishguardErrorLogs;
      }
    } catch (error) {
      console.error('Failed to load error logs:', error);
    }
  }
  
  getErrorLogs() {
    return this.errorLogs;
  }
  
  clearErrorLogs() {
    this.errorLogs = [];
    this.saveErrorLogs();
  }
  
  async retryOperation(operation, context = {}) {
    let attempt = 0;
    
    while (attempt < this.retryAttempts) {
      try {
        return await operation();
    } catch (error) {
        attempt++;
        context.attempt = attempt;
        
        const result = await this.handleError('RETRY_ERROR', error, context);
        
        if (!result.retry || attempt >= this.retryAttempts) {
          throw error;
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, result.delay || this.retryDelay));
      }
    }
  }
  
  createErrorBoundary(componentName) {
    return (error, errorInfo) => {
      this.handleError('COMPONENT_ERROR', error, {
        component: componentName,
        errorInfo: errorInfo
      });
    };
  }
}

// Export for use in other scripts
if (typeof window !== 'undefined') {
  window.PhishGuardErrorHandler = PhishGuardErrorHandler;
}

console.log('🛠️ PhishGuard Error Handler loaded');