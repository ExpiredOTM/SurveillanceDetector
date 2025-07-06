// Corporate Surveillance Reverse-Engineering Tool - Popup Script
class SurveillancePopup {
  constructor() {
    this.report = null;
    this.forensicData = null;
    this.currentTab = 'overview';
    this.init();
  }

  async init() {
    this.setupEventListeners();
    await this.setupRealtimeListeners();
    this.switchTab('overview');
  }

  setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.switchTab(e.target.dataset.tab);
      });
    });

    // Refresh, export, and clear buttons
    document.getElementById('refresh-btn').addEventListener('click', () => {
      this.loadReport();
    });

    document.getElementById('export-btn').addEventListener('click', () => {
      this.exportData();
    });

    document.getElementById('clear-btn').addEventListener('click', () => {
      this.clearData();
    });
  }

  async setupRealtimeListeners() {
    // Signal to the background script that the popup is open and get initial data
    try {
      console.log('Popup opened, requesting initial data...');
      const initialData = await chrome.runtime.sendMessage({ type: 'popup-opened' });
      console.log('Received initial data:', initialData);
      
      // Load initial data for all tabs
      if (initialData && typeof initialData === 'object') {
        this.forensicData = initialData;
        this.renderTimelineData(initialData);
        this.renderForensicData(initialData);
      } else {
        console.warn('No initial data received from background script');
        // Initialize with empty data structure
        this.forensicData = {
          totalDomains: 0,
          totalAttributes: 0,
          recentActivity: [],
          mostActiveFingerprinters: [],
          attributeProgression: {}
        };
      }
    } catch (error) {
      console.error('Error during popup initialization:', error);
      // Initialize with empty data structure even on error
      this.forensicData = {
        totalDomains: 0,
        totalAttributes: 0,
        recentActivity: [],
        mostActiveFingerprinters: [],
        attributeProgression: {}
      };
      this.showError('Failed to connect to background service.');
    }
    
    // Listen for real-time updates from the background script
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      console.log('Popup received message:', request.type);
      
      switch(request.type) {
        case 'fingerprint-activity-update':
          this.addTimelineEntry(request.data);
          // Update forensic stats if we're on the forensic tab
          if (this.currentTab === 'forensic') {
            this.updateForensicStats();
          }
          break;
        case 'exfiltration-data-update':
          this.renderExfiltrationData(request.data);
          break;
      }
    });
  }

  switchTab(tabName) {
    console.log('Switching to tab:', tabName);
    this.currentTab = tabName;
    
    // Update tab buttons
    const tabButtons = document.querySelectorAll('.tab-btn');
    console.log('Found tab buttons:', tabButtons.length);
    
    tabButtons.forEach(btn => {
      btn.classList.remove('active');
    });
    
    const tabButton = document.querySelector(`[data-tab="${tabName}"]`);
    console.log('Found tab button for', tabName, ':', tabButton);
    if (tabButton) {
      tabButton.classList.add('active');
    } else {
      console.error('Tab button not found for:', tabName);
    }
    
    // Update tab content
    const tabContents = document.querySelectorAll('.tab-content');
    console.log('Found tab contents:', tabContents.length);
    
    tabContents.forEach(content => {
      content.classList.remove('active');
    });
    
    const tabContentId = `${tabName}-tab`;
    const tabContent = document.getElementById(tabContentId);
    console.log('Found tab content for', tabContentId, ':', tabContent);
    if (tabContent) {
      tabContent.classList.add('active');
    } else {
      console.error('Tab content not found for:', tabContentId);
    }
    
    // Load tab-specific data
    this.loadTabData(tabName);
  }

  async loadTabData(tabName) {
    switch (tabName) {
      case 'overview':
        await this.loadReport();
        break;
      case 'timeline':
        this.renderTimelineData(this.forensicData);
        break;
      case 'forensic':
        this.renderForensicData(this.forensicData);
        break;
      case 'exfiltration':
        await this.loadExfiltrationData();
        break;
    }
  }

  async loadReport() {
    try {
      document.getElementById('loading').style.display = 'block';
      document.getElementById('content').style.display = 'none';

      const response = await chrome.runtime.sendMessage({ type: 'getReport' });
      this.report = response;
      
      this.renderReport();
      
      document.getElementById('loading').style.display = 'none';
      document.getElementById('content').style.display = 'block';
    } catch (error) {
      console.error('Failed to load report:', error);
      this.showError('Failed to load surveillance report');
    }
  }

  renderReport() {
    if (!this.report) return;

    // Privacy Score
    const privacyScore = Math.max(0, Math.min(100, this.report.privacyScore));
    document.getElementById('privacy-score').textContent = privacyScore;

    // Statistics
    document.getElementById('tracker-count').textContent = this.report.totalTrackers;
    document.getElementById('fingerprint-count').textContent = this.report.totalFingerprinters;

    // Warnings
    this.renderWarnings();

    // High Risk Trackers
    this.renderHighRiskTrackers();

    // Tracking Methods
    this.renderTrackingMethods();
  }

  renderWarnings() {
    const fingerprintWarning = document.getElementById('fingerprint-warning');
    const priceAlert = document.getElementById('price-alert');

    fingerprintWarning.style.display = this.report.totalFingerprinters > 0 ? 'block' : 'none';
    
    // Check for price tracking (simplified logic)
    const hasPriceTracking = this.report.trackingMethods.includes('price-tracking');
    priceAlert.style.display = hasPriceTracking ? 'block' : 'none';
  }

  renderHighRiskTrackers() {
    const container = document.getElementById('high-risk-trackers');
    container.innerHTML = '';

    if (this.report.highRiskDomains.length === 0) {
      container.innerHTML = '<div class="empty-state">No high-risk trackers detected</div>';
      return;
    }

    this.report.highRiskDomains.forEach(tracker => {
      const item = document.createElement('div');
      item.className = 'tracker-item';
      
      const riskClass = this.getRiskClass(tracker.riskScore);
      
      item.innerHTML = `
        <div>
          <div class="tracker-domain">${tracker.domain}</div>
          <div class="methods-list">
            ${tracker.methods.map(method => `<span class="method-tag">${method}</span>`).join('')}
          </div>
        </div>
        <div class="tracker-score ${riskClass}">${tracker.riskScore}</div>
      `;
      
      container.appendChild(item);
    });
  }

  renderTrackingMethods() {
    const container = document.getElementById('tracking-methods');
    container.innerHTML = '';

    if (this.report.trackingMethods.length === 0) {
      container.innerHTML = '<div class="empty-state">No tracking methods detected</div>';
      return;
    }

    this.report.trackingMethods.forEach(method => {
      const tag = document.createElement('span');
      tag.className = 'method-tag';
      tag.textContent = method.replace(/-/g, ' ');
      container.appendChild(tag);
    });
  }

  getRiskClass(score) {
    if (score >= 70) return 'risk-high';
    if (score >= 40) return 'risk-medium';
    return 'risk-low';
  }

  renderTimelineData(forensicData) {
    const container = document.getElementById('timeline-container');
    if (!container) {
      console.error('Timeline container not found');
      return;
    }
    
    container.innerHTML = '';

    console.log('Rendering timeline data:', forensicData);
    console.log('Recent activity available:', forensicData?.recentActivity?.length || 0);

    if (!forensicData || !forensicData.recentActivity || forensicData.recentActivity.length === 0) {
      container.innerHTML = '<div class="empty-state">No fingerprinting activity detected yet</div>';
      return;
    }

    forensicData.recentActivity.forEach(entry => {
      const timelineEntry = document.createElement('div');
      timelineEntry.className = `timeline-entry ${entry.isNewAttribute ? 'new-attribute' : ''}`;
      
      // Safety check for severity
      const severity = entry.details?.severity || 'MEDIUM';
      const severityClass = `severity-${severity.toLowerCase()}`;
      
      timelineEntry.innerHTML = `
        <div class="timeline-time">${entry.timeFormatted}</div>
        <div class="timeline-domain">${entry.domain}</div>
        <div class="timeline-attribute">${entry.attribute}</div>
        <div class="timeline-severity ${severityClass}">${severity}</div>
        ${entry.isNewAttribute ? '<div class="timeline-badge">NEW</div>' : ''}
      `;
      
      container.appendChild(timelineEntry);
    });

    // Show realtime indicator if there are new attributes
    const hasNewAttributes = forensicData.recentActivity.some(entry => entry.isNewAttribute);
    if (hasNewAttributes) {
      this.showRealtimeIndicator();
    }
  }

  renderForensicData(forensicData) {
    if (!forensicData) {
      console.warn('No forensic data provided to renderForensicData');
      return;
    }
    
    // Update forensic stats
    document.getElementById('total-domains').textContent = forensicData.totalDomains || 0;
    document.getElementById('total-attributes').textContent = forensicData.totalAttributes || 0;
    
    // Count new attributes today
    const today = new Date().toDateString();
    const newToday = (forensicData.recentActivity || []).filter(entry => 
      new Date(entry.timestamp).toDateString() === today && entry.isNewAttribute
    ).length;
    document.getElementById('new-attributes').textContent = newToday;

    // Render attribute progression
    const progressContainer = document.getElementById('attribute-progress');
    progressContainer.innerHTML = '';
    
    if (forensicData.attributeProgression && Object.keys(forensicData.attributeProgression).length > 0) {
      Object.entries(forensicData.attributeProgression).forEach(([domain, data]) => {
        const progressItem = document.createElement('div');
        progressItem.className = 'attribute-progress-item';
        progressItem.innerHTML = `
          <div class="attribute-progress-domain">${domain}</div>
          <div class="attribute-progress-count">${data.totalAttributes}</div>
        `;
        progressContainer.appendChild(progressItem);
      });
    } else {
      progressContainer.innerHTML = '<div class="empty-state">No attribute data available</div>';
    }

    // Render most active fingerprinters
    const activeContainer = document.getElementById('active-fingerprinters');
    activeContainer.innerHTML = '';
    
    if (forensicData.mostActiveFingerprinters && forensicData.mostActiveFingerprinters.length > 0) {
      forensicData.mostActiveFingerprinters.forEach(fingerprinter => {
        const item = document.createElement('div');
        item.className = 'tracker-item';
        item.innerHTML = `
          <div>
            <div class="tracker-domain">${fingerprinter.domain}</div>
            <div class="methods-list">
              <span class="method-tag">${fingerprinter.count} attempts</span>
              <span class="method-tag">${fingerprinter.newAttributes} new</span>
            </div>
          </div>
          <div class="tracker-score risk-high">${fingerprinter.count}</div>
        `;
        activeContainer.appendChild(item);
      });
    } else {
      activeContainer.innerHTML = '<div class="empty-state">No active fingerprinters detected</div>';
    }
  }

  showRealtimeIndicator() {
    const indicator = document.getElementById('realtime-indicator');
    if (!indicator) {
      console.warn('Realtime indicator element not found');
      return;
    }
    
    indicator.classList.add('show', 'pulse');
    
    setTimeout(() => {
      indicator.classList.remove('show', 'pulse');
    }, 2000);
  }

  async loadExfiltrationData() {
    try {
      console.log('Loading exfiltration data...');
      const exfiltrationData = await chrome.runtime.sendMessage({ type: 'getExfiltrationData' });
      console.log('Received exfiltration data:', exfiltrationData);
      this.renderExfiltrationData(exfiltrationData);
    } catch (error) {
      console.error('Failed to load exfiltration data:', error);
    }
  }

  renderExfiltrationData(data) {
    if (!data) {
      console.warn('No exfiltration data received');
      return;
    }

    // Update stats
    document.getElementById('total-exfiltration-domains').textContent = data.totalDomains || 0;
    document.getElementById('total-exfiltration-attempts').textContent = data.totalAttempts || 0;
    document.getElementById('critical-alerts').textContent = data.criticalAlerts || 0;

    // Render exfiltration attempts
    this.renderExfiltrationAttempts(data.exfiltrationAttempts || []);

    // Render beaconing patterns
    this.renderBeaconingPatterns(data.beaconingPatterns || []);

    // Render security alerts
    this.renderSecurityAlerts(data.securityAlerts || []);
  }

  renderExfiltrationAttempts(attempts) {
    const container = document.getElementById('exfiltration-list');
    container.innerHTML = '';

    if (attempts.length === 0) {
      container.innerHTML = '<div class="empty-state">No data exfiltration detected</div>';
      return;
    }

    attempts.forEach(attempt => {
      const item = document.createElement('div');
      item.className = 'tracker-item';
      
      const severityClass = this.getSeverityClass(attempt.severity);
      
      item.innerHTML = `
        <div>
          <div class="tracker-domain">${attempt.domain}</div>
          <div class="methods-list">
            ${attempt.dataTypes.map(type => `<span class="method-tag">${type}</span>`).join('')}
          </div>
        </div>
        <div class="tracker-score ${severityClass}">${attempt.severity}</div>
      `;
      
      container.appendChild(item);
    });
  }

  renderBeaconingPatterns(patterns) {
    const container = document.getElementById('beaconing-list');
    container.innerHTML = '';

    if (patterns.length === 0) {
      container.innerHTML = '<div class="empty-state">No beaconing patterns detected</div>';
      return;
    }

    patterns.forEach(pattern => {
      const item = document.createElement('div');
      item.className = 'tracker-item';
      
      const intervalSeconds = Math.round(pattern.interval / 1000);
      const confidencePercent = Math.round(pattern.confidence * 100);
      
      item.innerHTML = `
        <div>
          <div class="tracker-domain">${pattern.domain}</div>
          <div class="methods-list">
            <span class="method-tag">Interval: ${intervalSeconds}s</span>
            <span class="method-tag">Confidence: ${confidencePercent}%</span>
          </div>
        </div>
        <div class="tracker-score risk-medium">BEACON</div>
      `;
      
      container.appendChild(item);
    });
  }

  renderSecurityAlerts(alerts) {
    const container = document.getElementById('security-alerts');
    container.innerHTML = '';

    if (alerts.length === 0) {
      container.innerHTML = '<div class="empty-state">No security alerts</div>';
      return;
    }

    alerts.forEach(alert => {
      const item = document.createElement('div');
      item.className = 'timeline-entry';
      
      const time = new Date(alert.timestamp).toLocaleTimeString();
      const severityClass = this.getSeverityClass(alert.severity);
      
      item.innerHTML = `
        <div class="timeline-time">${time}</div>
        <div class="timeline-attribute">${this.getAlertTitle(alert.type)}</div>
        <div class="timeline-severity ${severityClass}">${alert.severity}</div>
      `;
      
      container.appendChild(item);
    });
  }

  getSeverityClass(severity) {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return 'severity-high';
      case 'MEDIUM':
        return 'severity-medium';
      case 'LOW':
        return 'severity-low';
      default:
        return 'severity-medium';
    }
  }

  getAlertTitle(type) {
    const titles = {
      'data-exfiltration': 'Data Exfiltration',
      'beaconing-detected': 'Beaconing Pattern',
      'high-risk-fingerprinting': 'High-Risk Fingerprinting'
    };
    return titles[type] || type;
  }

  async exportData() {
    try {
      // Show loading state
      const exportBtn = document.getElementById('export-btn');
      const originalText = exportBtn.textContent;
      exportBtn.textContent = 'Exporting...';
      exportBtn.disabled = true;

      // Get all surveillance data from background
      const exportData = await chrome.runtime.sendMessage({ type: 'exportData' });
      
      // Add metadata
      const timestamp = new Date().toISOString();
      const filename = `surveillance-data-${timestamp.split('T')[0]}.json`;
      
      const dataWithMetadata = {
        ...exportData,
        exportMetadata: {
          exportedAt: timestamp,
          extensionVersion: '1.0.0',
          format: 'surveillance-data-v1'
        }
      };

      // Create and download the file
      const blob = new Blob([JSON.stringify(dataWithMetadata, null, 2)], { 
        type: 'application/json' 
      });
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.style.display = 'none';
      
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      
      URL.revokeObjectURL(url);

      // Show success message
      this.showExportSuccess(filename);
      
      // Restore button state
      exportBtn.textContent = originalText;
      exportBtn.disabled = false;
      
    } catch (error) {
      console.error('Failed to export data:', error);
      this.showError('Failed to export surveillance data');
      
      // Restore button state
      const exportBtn = document.getElementById('export-btn');
      exportBtn.textContent = 'Export Data';
      exportBtn.disabled = false;
    }
  }

  showExportSuccess(filename) {
    // Create a temporary success message
    const successMsg = document.createElement('div');
    successMsg.style.cssText = `
      position: fixed;
      top: 10px;
      right: 10px;
      background: #26de81;
      color: #000;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 1000;
      animation: fadeInOut 3s ease-in-out;
    `;
    successMsg.textContent = `Exported: ${filename}`;
    
    // Add fade animation
    const style = document.createElement('style');
    style.textContent = `
      @keyframes fadeInOut {
        0% { opacity: 0; transform: translateY(-10px); }
        15% { opacity: 1; transform: translateY(0); }
        85% { opacity: 1; transform: translateY(0); }
        100% { opacity: 0; transform: translateY(-10px); }
      }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(successMsg);
    
    setTimeout(() => {
      if (successMsg.parentNode) {
        successMsg.parentNode.removeChild(successMsg);
      }
      if (style.parentNode) {
        style.parentNode.removeChild(style);
      }
    }, 3000);
  }

  async clearData() {
    try {
      await chrome.runtime.sendMessage({ type: 'clearData' });
      this.loadTabData(this.currentTab); // Refresh current tab
    } catch (error) {
      console.error('Failed to clear data:', error);
    }
  }

  showError(message) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('content').innerHTML = `
      <div class="empty-state">
        <h3>Error</h3>
        <p>${message}</p>
      </div>
    `;
    document.getElementById('content').style.display = 'block';
  }

  addTimelineEntry(entry) {
    const container = document.getElementById('timeline-container');
    if (!container) {
      console.error('Timeline container not found for addTimelineEntry');
      return;
    }
    
    // Remove empty state if it exists
    const emptyState = container.querySelector('.empty-state');
    if (emptyState) {
      emptyState.remove();
    }

    const timelineEntry = document.createElement('div');
    timelineEntry.className = `timeline-entry ${entry.isNewAttribute ? 'new-attribute' : ''}`;
    
    // Safety check for severity
    const severity = entry.details?.severity || 'MEDIUM';
    const severityClass = `severity-${severity.toLowerCase()}`;
    
    timelineEntry.innerHTML = `
      <div class="timeline-time">${entry.timeFormatted}</div>
      <div class="timeline-domain">${entry.domain}</div>
      <div class="timeline-attribute">${entry.attribute}</div>
      <div class="timeline-severity ${severityClass}">${severity}</div>
      ${entry.isNewAttribute ? '<div class="timeline-badge">NEW</div>' : ''}
    `;
    
    // Prepend to show the latest entry at the top
    container.prepend(timelineEntry);
    
    // Also update the forensic data object
    if (this.forensicData && this.forensicData.recentActivity) {
      this.forensicData.recentActivity.unshift(entry);
    }
    
    this.showRealtimeIndicator();
  }

  updateForensicStats() {
    // Update forensic stats based on current forensicData
    if (this.forensicData) {
      // Recalculate stats
      this.forensicData.totalAttributes = this.forensicData.recentActivity?.length || 0;
      
      // Re-render forensic data
      this.renderForensicData(this.forensicData);
    }
  }
}

// Initialize popup when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new SurveillancePopup();
});

// Notify background script when popup is closing
window.addEventListener('beforeunload', () => {
  chrome.runtime.sendMessage({ type: 'popup-closed' }).catch(() => {
    // Ignore errors if background script is not available
  });
}); 