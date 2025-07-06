// Corporate Surveillance Reverse-Engineering Tool - Options Script
class SurveillanceOptions {
  constructor() {
    this.defaultSettings = {
      enableTrackingDetection: true,
      enableFingerprintingDetection: true,
      enablePriceTracking: true,
      enableNetworkAnalysis: true,
      riskThreshold: 50,
      dataRetentionDays: 30,
      customTrackers: []
    };
    
    this.settings = { ...this.defaultSettings };
    this.init();
  }

  init() {
    this.loadSettings();
    this.setupEventListeners();
    this.renderCustomTrackers();
  }

  setupEventListeners() {
    // Save settings
    document.getElementById('save-settings-btn').addEventListener('click', () => {
      this.saveSettings();
    });

    // Reset settings
    document.getElementById('reset-settings-btn').addEventListener('click', () => {
      this.resetSettings();
    });

    // Clear all data
    document.getElementById('clear-all-data-btn').addEventListener('click', () => {
      this.clearAllData();
    });

    // Add custom tracker
    document.getElementById('add-tracker-btn').addEventListener('click', () => {
      this.addCustomTracker();
    });

    // Export data
    document.getElementById('export-data-btn').addEventListener('click', () => {
      this.exportData();
    });

    // Risk threshold slider
    const riskThreshold = document.getElementById('risk-threshold');
    riskThreshold.addEventListener('input', (e) => {
      document.getElementById('risk-threshold-value').textContent = e.target.value;
    });

    // Enter key for adding trackers
    document.getElementById('new-tracker-domain').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.addCustomTracker();
      }
    });
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.sync.get('surveillanceSettings');
      if (result.surveillanceSettings) {
        this.settings = { ...this.defaultSettings, ...result.surveillanceSettings };
      }
      this.applySettingsToUI();
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }

  applySettingsToUI() {
    document.getElementById('enable-tracking-detection').checked = this.settings.enableTrackingDetection;
    document.getElementById('enable-fingerprinting-detection').checked = this.settings.enableFingerprintingDetection;
    document.getElementById('enable-price-tracking').checked = this.settings.enablePriceTracking;
    document.getElementById('enable-network-analysis').checked = this.settings.enableNetworkAnalysis;
    document.getElementById('risk-threshold').value = this.settings.riskThreshold;
    document.getElementById('risk-threshold-value').textContent = this.settings.riskThreshold;
    document.getElementById('data-retention').value = this.settings.dataRetentionDays;
    
    this.renderCustomTrackers();
  }

  collectSettingsFromUI() {
    this.settings.enableTrackingDetection = document.getElementById('enable-tracking-detection').checked;
    this.settings.enableFingerprintingDetection = document.getElementById('enable-fingerprinting-detection').checked;
    this.settings.enablePriceTracking = document.getElementById('enable-price-tracking').checked;
    this.settings.enableNetworkAnalysis = document.getElementById('enable-network-analysis').checked;
    this.settings.riskThreshold = parseInt(document.getElementById('risk-threshold').value);
    this.settings.dataRetentionDays = parseInt(document.getElementById('data-retention').value);
  }

  async saveSettings() {
    try {
      this.collectSettingsFromUI();
      await chrome.storage.sync.set({ surveillanceSettings: this.settings });
      
      // Notify background script of settings change
      chrome.runtime.sendMessage({ type: 'settingsUpdated', settings: this.settings });
      
      this.showNotification('Settings saved successfully', 'success');
    } catch (error) {
      console.error('Failed to save settings:', error);
      this.showNotification('Failed to save settings', 'error');
    }
  }

  async resetSettings() {
    try {
      this.settings = { ...this.defaultSettings };
      await chrome.storage.sync.set({ surveillanceSettings: this.settings });
      this.applySettingsToUI();
      this.showNotification('Settings reset to defaults', 'success');
    } catch (error) {
      console.error('Failed to reset settings:', error);
      this.showNotification('Failed to reset settings', 'error');
    }
  }

  async clearAllData() {
    if (!confirm('Are you sure you want to clear all surveillance data? This action cannot be undone.')) {
      return;
    }

    try {
      await chrome.runtime.sendMessage({ type: 'clearData' });
      this.showNotification('All surveillance data cleared', 'success');
    } catch (error) {
      console.error('Failed to clear data:', error);
      this.showNotification('Failed to clear data', 'error');
    }
  }

  addCustomTracker() {
    const input = document.getElementById('new-tracker-domain');
    const domain = input.value.trim();
    
    if (!domain) {
      this.showNotification('Please enter a domain', 'error');
      return;
    }

    if (this.settings.customTrackers.includes(domain)) {
      this.showNotification('Domain already exists', 'error');
      return;
    }

    this.settings.customTrackers.push(domain);
    input.value = '';
    this.renderCustomTrackers();
    this.showNotification('Custom tracker added', 'success');
  }

  removeCustomTracker(domain) {
    const index = this.settings.customTrackers.indexOf(domain);
    if (index > -1) {
      this.settings.customTrackers.splice(index, 1);
      this.renderCustomTrackers();
      this.showNotification('Custom tracker removed', 'success');
    }
  }

  renderCustomTrackers() {
    const container = document.getElementById('custom-trackers');
    container.innerHTML = '';

    if (this.settings.customTrackers.length === 0) {
      container.innerHTML = '<div style="padding: 10px; color: #888; text-align: center;">No custom trackers added</div>';
      return;
    }

    this.settings.customTrackers.forEach(domain => {
      const item = document.createElement('div');
      item.className = 'tracker-item';
      item.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span>${domain}</span>
          <button class="btn btn-danger" style="padding: 2px 8px; font-size: 12px;" onclick="surveillanceOptions.removeCustomTracker('${domain}')">Remove</button>
        </div>
      `;
      container.appendChild(item);
    });
  }

  async exportData() {
    try {
      const data = await chrome.runtime.sendMessage({ type: 'exportData' });
      const exportContainer = document.getElementById('export-data');
      exportContainer.textContent = JSON.stringify(data, null, 2);
      exportContainer.style.display = 'block';
      this.showNotification('Data exported successfully', 'success');
    } catch (error) {
      console.error('Failed to export data:', error);
      this.showNotification('Failed to export data', 'error');
    }
  }

  showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.classList.add('show');
    
    setTimeout(() => {
      notification.classList.remove('show');
    }, 3000);
  }
}

// Initialize options when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.surveillanceOptions = new SurveillanceOptions();
}); 