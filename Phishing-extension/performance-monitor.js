// PhishGuard Pro - Performance Monitoring
// Production-ready performance tracking and optimization

class PerformanceMonitor {
  constructor() {
    this.metrics = {
      urlAnalysis: [],
      emailAnalysis: [],
      whatsappAnalysis: [],
      backgroundTasks: [],
      memoryUsage: [],
      responseTimes: []
    };
    
    this.thresholds = {
      maxAnalysisTime: 1000, // 1 second
      maxMemoryUsage: 50 * 1024 * 1024, // 50MB
      maxResponseTime: 500 // 500ms
    };
    
    this.isMonitoring = false;
    this.startMonitoring();
  }
  
  startMonitoring() {
    this.isMonitoring = true;
    
    // Monitor memory usage
    this.monitorMemoryUsage();
    
    // Monitor performance metrics
    this.monitorPerformanceMetrics();
    
    // Clean up old metrics
    this.cleanupOldMetrics();
    
    console.log('📊 Performance monitoring started');
  }
  
  stopMonitoring() {
    this.isMonitoring = false;
    console.log('📊 Performance monitoring stopped');
  }
  
  // Track URL analysis performance
  trackUrlAnalysis(url, startTime, endTime, result) {
    const duration = endTime - startTime;
    const metric = {
      url: url.substring(0, 100), // Truncate for privacy
      duration,
      timestamp: Date.now(),
      result: result.action,
      riskScore: result.riskScore,
      memoryUsage: this.getCurrentMemoryUsage()
    };
    
    this.metrics.urlAnalysis.push(metric);
    
    // Check for performance issues
    if (duration > this.thresholds.maxAnalysisTime) {
      this.reportPerformanceIssue('SLOW_URL_ANALYSIS', metric);
    }
    
    return metric;
  }
  
  // Track email analysis performance
  trackEmailAnalysis(emailData, startTime, endTime, result) {
    const duration = endTime - startTime;
    const metric = {
      sender: emailData.from?.substring(0, 50) || 'Unknown',
      duration,
      timestamp: Date.now(),
      result: result.isPhishing,
      riskScore: result.riskScore,
      memoryUsage: this.getCurrentMemoryUsage()
    };
    
    this.metrics.emailAnalysis.push(metric);
    
    if (duration > this.thresholds.maxAnalysisTime) {
      this.reportPerformanceIssue('SLOW_EMAIL_ANALYSIS', metric);
    }
    
    return metric;
  }
  
  // Track WhatsApp analysis performance
  trackWhatsAppAnalysis(link, startTime, endTime, result) {
    const duration = endTime - startTime;
    const metric = {
      link: link.substring(0, 100),
      duration,
      timestamp: Date.now(),
      result: result.action,
      riskScore: result.riskScore,
      memoryUsage: this.getCurrentMemoryUsage()
    };
    
    this.metrics.whatsappAnalysis.push(metric);
    
    if (duration > this.thresholds.maxAnalysisTime) {
      this.reportPerformanceIssue('SLOW_WHATSAPP_ANALYSIS', metric);
    }
    
    return metric;
  }
  
  // Track background task performance
  trackBackgroundTask(taskName, startTime, endTime, success) {
    const duration = endTime - startTime;
    const metric = {
      task: taskName,
      duration,
      timestamp: Date.now(),
      success,
      memoryUsage: this.getCurrentMemoryUsage()
    };
    
    this.metrics.backgroundTasks.push(metric);
    
    if (duration > this.thresholds.maxResponseTime) {
      this.reportPerformanceIssue('SLOW_BACKGROUND_TASK', metric);
    }
    
    return metric;
  }
  
  // Monitor memory usage
  monitorMemoryUsage() {
    if (!this.isMonitoring) return;
    
    const memoryInfo = this.getCurrentMemoryUsage();
    this.metrics.memoryUsage.push({
      usage: memoryInfo,
      timestamp: Date.now()
    });
    
    // Check for memory leaks
    if (memoryInfo > this.thresholds.maxMemoryUsage) {
      this.reportPerformanceIssue('HIGH_MEMORY_USAGE', { usage: memoryInfo });
    }
    
    // Schedule next check
    setTimeout(() => this.monitorMemoryUsage(), 30000); // Every 30 seconds
  }
  
  // Monitor performance metrics
  monitorPerformanceMetrics() {
    if (!this.isMonitoring) return;
    
    // Track response times
    const startTime = performance.now();
    
    // Simulate some work to measure overhead
    setTimeout(() => {
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      this.metrics.responseTimes.push({
        time: responseTime,
        timestamp: Date.now()
      });
      
      if (responseTime > this.thresholds.maxResponseTime) {
        this.reportPerformanceIssue('SLOW_RESPONSE_TIME', { time: responseTime });
      }
      
      // Schedule next check
      setTimeout(() => this.monitorPerformanceMetrics(), 60000); // Every minute
    }, 0);
  }
  
  // Get current memory usage
  getCurrentMemoryUsage() {
    if (performance.memory) {
      return performance.memory.usedJSHeapSize;
    }
    return 0;
  }
  
  // Report performance issues
  reportPerformanceIssue(type, data) {
    const issue = {
      type,
      data,
      timestamp: Date.now(),
      severity: this.getSeverityLevel(type, data)
    };
    
    console.warn(`⚠️ Performance issue detected:`, issue);
    
    // Store issue for analysis
    this.storePerformanceIssue(issue);
  }
  
  // Get severity level
  getSeverityLevel(type, data) {
    if (type.includes('MEMORY') && data.usage > this.thresholds.maxMemoryUsage * 2) {
      return 'CRITICAL';
    }
    if (type.includes('SLOW') && data.duration > this.thresholds.maxAnalysisTime * 2) {
      return 'HIGH';
    }
    return 'MEDIUM';
  }
  
  // Store performance issue
  async storePerformanceIssue(issue) {
    try {
      const result = await chrome.storage.local.get(['phishguardPerformanceIssues']);
      const issues = result.phishguardPerformanceIssues || [];
      
      issues.push(issue);
      
      // Keep only last 50 issues
      if (issues.length > 50) {
        issues.splice(0, issues.length - 50);
      }
      
      await chrome.storage.local.set({ phishguardPerformanceIssues: issues });
    } catch (error) {
      console.error('Failed to store performance issue:', error);
    }
  }
  
  // Clean up old metrics
  cleanupOldMetrics() {
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    
    Object.keys(this.metrics).forEach(key => {
      this.metrics[key] = this.metrics[key].filter(metric => 
        metric.timestamp > oneHourAgo
      );
    });
    
    // Schedule next cleanup
    setTimeout(() => this.cleanupOldMetrics(), 300000); // Every 5 minutes
  }
  
  // Get performance statistics
  getPerformanceStats() {
    const stats = {};
    
    Object.keys(this.metrics).forEach(key => {
      const metrics = this.metrics[key];
      if (metrics.length > 0) {
        stats[key] = {
          count: metrics.length,
          average: this.calculateAverage(metrics, 'duration'),
          max: Math.max(...metrics.map(m => m.duration || 0)),
          min: Math.min(...metrics.map(m => m.duration || 0))
        };
      }
    });
    
    return stats;
  }
  
  // Calculate average
  calculateAverage(metrics, property) {
    if (metrics.length === 0) return 0;
    
    const sum = metrics.reduce((acc, metric) => acc + (metric[property] || 0), 0);
    return Math.round(sum / metrics.length);
  }
  
  // Get performance report
  async getPerformanceReport() {
    const stats = this.getPerformanceStats();
    const issues = await this.getPerformanceIssues();
    
    return {
      stats,
      issues: issues.slice(-10), // Last 10 issues
      memoryUsage: this.getCurrentMemoryUsage(),
      isHealthy: this.isPerformanceHealthy()
    };
  }
  
  // Get performance issues
  async getPerformanceIssues() {
    try {
      const result = await chrome.storage.local.get(['phishguardPerformanceIssues']);
      return result.phishguardPerformanceIssues || [];
    } catch (error) {
      console.error('Failed to get performance issues:', error);
      return [];
    }
  }
  
  // Check if performance is healthy
  isPerformanceHealthy() {
    const recentMetrics = this.getRecentMetrics(300000); // Last 5 minutes
    const avgResponseTime = this.calculateAverage(recentMetrics, 'duration');
    const currentMemory = this.getCurrentMemoryUsage();
    
    return avgResponseTime < this.thresholds.maxResponseTime && 
           currentMemory < this.thresholds.maxMemoryUsage;
  }
  
  // Get recent metrics
  getRecentMetrics(timeWindow) {
    const cutoff = Date.now() - timeWindow;
    const recent = [];
    
    Object.values(this.metrics).forEach(metricArray => {
      recent.push(...metricArray.filter(metric => metric.timestamp > cutoff));
    });
    
    return recent;
  }
  
  // Clear all metrics
  clearMetrics() {
    Object.keys(this.metrics).forEach(key => {
      this.metrics[key] = [];
    });
    
    console.log('📊 Performance metrics cleared');
  }
}

// Export for use in other scripts
if (typeof window !== 'undefined') {
  window.PerformanceMonitor = PerformanceMonitor;
}

console.log('📊 Performance Monitor loaded');
