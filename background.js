// Corporate Surveillance Reverse-Engineering Tool - Background Script

// Fingerprint Delta Tracker - Forensic Timeline Analysis
class FingerprintDeltaTracker {
  constructor() {
    this.fingerprintTimeline = new Map(); // domain -> timeline entries
    this.attributeDatabase = new Map(); // domain -> set of accessed attributes
    this.sessionStartTime = Date.now();
    this.realtimeCallbacks = new Set();
  }

  recordFingerprintAccess(domain, attribute, details) {
    const timestamp = Date.now();
    const timelineKey = `${domain}_${new Date().toDateString()}`;
    
    // Initialize timeline for this domain/day
    if (!this.fingerprintTimeline.has(timelineKey)) {
      this.fingerprintTimeline.set(timelineKey, []);
    }
    
    // Initialize attribute set for this domain
    if (!this.attributeDatabase.has(domain)) {
      this.attributeDatabase.set(domain, new Set());
    }
    
    const existingAttributes = this.attributeDatabase.get(domain);
    const isNewAttribute = !existingAttributes.has(attribute);
    
    // Add to attribute database
    existingAttributes.add(attribute);
    
    // Create timeline entry
    const entry = {
      timestamp,
      timeFormatted: new Date(timestamp).toLocaleTimeString(),
      domain,
      attribute,
      isNewAttribute,
      details: details || {},
      totalFingerprints: existingAttributes.size,
      sessionDuration: timestamp - this.sessionStartTime
    };
    
    // Add to timeline
    this.fingerprintTimeline.get(timelineKey).push(entry);
    
    // Trigger real-time callbacks for immediate UI updates
    this.triggerRealtimeCallbacks(entry);
    
    return entry;
  }

  getTimelineForDomain(domain) {
    const today = new Date().toDateString();
    const timelineKey = `${domain}_${today}`;
    return this.fingerprintTimeline.get(timelineKey) || [];
  }

  getNewAttributesForDomain(domain, since = null) {
    const timeline = this.getTimelineForDomain(domain);
    const cutoff = since || this.sessionStartTime;
    
    return timeline
      .filter(entry => entry.timestamp > cutoff && entry.isNewAttribute)
      .map(entry => entry.attribute);
  }

  getForensicSummary() {
    console.log('Building forensic summary...');
    console.log('Timeline size:', this.fingerprintTimeline.size);
    console.log('Attribute database size:', this.attributeDatabase.size);
    
    const summary = {
      totalDomains: this.attributeDatabase.size,
      totalAttributes: 0,
      recentActivity: [],
      mostActiveFingerprinters: [],
      attributeProgression: {},
      timelineEntries: []
    };
    
    // Calculate total attributes across all domains
    this.attributeDatabase.forEach((attributes, domain) => {
      summary.totalAttributes += attributes.size;
      
      // Track attribute progression per domain (convert Map to Object)
      summary.attributeProgression[domain] = {
        domain,
        totalAttributes: attributes.size,
        attributes: Array.from(attributes)
      };
    });
    
    // Get recent activity (last 10 minutes)
    const recentCutoff = Date.now() - (10 * 60 * 1000);
    const allEntries = [];
    
    this.fingerprintTimeline.forEach((timeline, key) => {
      timeline.forEach(entry => {
        if (entry.timestamp > recentCutoff) {
          allEntries.push(entry);
        }
      });
    });
    
    // Sort by timestamp (most recent first)
    allEntries.sort((a, b) => b.timestamp - a.timestamp);
    summary.recentActivity = allEntries.slice(0, 20);
    summary.timelineEntries = allEntries;
    
    // Find most active fingerprinters
    const domainActivity = {};
    allEntries.forEach(entry => {
      if (!domainActivity[entry.domain]) {
        domainActivity[entry.domain] = { domain: entry.domain, count: 0, newAttributes: 0 };
      }
      const activity = domainActivity[entry.domain];
      activity.count++;
      if (entry.isNewAttribute) activity.newAttributes++;
    });
    
    summary.mostActiveFingerprinters = Object.values(domainActivity)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    
    console.log('Final summary:', summary);
    return summary;
  }

  addRealtimeCallback(callback) {
    this.realtimeCallbacks.add(callback);
  }

  removeRealtimeCallback(callback) {
    this.realtimeCallbacks.delete(callback);
  }

  triggerRealtimeCallbacks(entry) {
    this.realtimeCallbacks.forEach(callback => {
      try {
        callback(entry);
      } catch (error) {
        console.error('Error in realtime callback:', error);
      }
    });
  }

  exportTimelineData() {
    return {
      fingerprintTimeline: Array.from(this.fingerprintTimeline.entries()),
      attributeDatabase: Array.from(this.attributeDatabase.entries()).map(([domain, attributes]) => 
        [domain, Array.from(attributes)]
      ),
      sessionStartTime: this.sessionStartTime,
      exportTimestamp: Date.now()
    };
  }

  importTimelineData(data) {
    if (data.fingerprintTimeline) {
      this.fingerprintTimeline = new Map(data.fingerprintTimeline);
    }
    if (data.attributeDatabase) {
      this.attributeDatabase = new Map(data.attributeDatabase.map(([domain, attributes]) => 
        [domain, new Set(attributes)]
      ));
    }
    if (data.sessionStartTime) {
      this.sessionStartTime = data.sessionStartTime;
    }
  }

  clearTimelineData() {
    this.fingerprintTimeline.clear();
    this.attributeDatabase.clear();
    this.sessionStartTime = Date.now();
  }
}

class SurveillanceAnalyzer {
  constructor() {
    this.trackingDatabase = new Map();
    this.fingerprints = new Map();
    this.priceHistory = new Map();
    this.networkRequests = new Map();
    this.adNetworks = new Set();
    this.knownTrackers = new Set();
    this.exfiltrationData = new Map();
    this.beaconingPatterns = new Map();
    this.securityAlerts = [];
    this.settings = {
      blockTrackers: false,
      showNotifications: true,
      realTimeAlerts: true,
      logLevel: 'info'
    };
    
    // Initialize forensic fingerprint tracking
    this.fingerprintDeltaTracker = new FingerprintDeltaTracker();
    
    this.initializeKnownTrackers();
    this.setupNetworkListeners();
    this.setupTabListeners();
  }

  initializeKnownTrackers() {
    // Known tracking domains and patterns
    const trackers = [
      'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
      'facebook.com', 'connect.facebook.net', 'fbcdn.net',
      'amazon-adsystem.com', 'googlesyndication.com', 'googleadservices.com',
      'scorecardresearch.com', 'quantserve.com', 'outbrain.com',
      'taboola.com', 'adsystem.amazon.com', 'ads.yahoo.com',
      'bing.com', 'linkedin.com', 'twitter.com', 'pinterest.com',
      'hotjar.com', 'fullstory.com', 'logrocket.com', 'mouseflow.com'
    ];
    
    trackers.forEach(tracker => this.knownTrackers.add(tracker));
  }

  setupNetworkListeners() {
    // Intercept all network requests
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => this.analyzeRequest(details),
      { urls: ["<all_urls>"] },
      ["requestBody"]
    );

    chrome.webRequest.onResponseStarted.addListener(
      (details) => this.analyzeResponse(details),
      { urls: ["<all_urls>"] },
      ["responseHeaders"]
    );

    chrome.webRequest.onBeforeSendHeaders.addListener(
      (details) => this.analyzeHeaders(details),
      { urls: ["<all_urls>"] },
      ["requestHeaders"]
    );
  }

  setupTabListeners() {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url) {
        this.analyzePageLoad(tab);
      }
    });
  }

  analyzeRequest(details) {
    const url = new URL(details.url);
    const domain = url.hostname;
    const timestamp = Date.now();
    
    // Check if this is a tracking request
    const isTracker = this.isTrackingDomain(domain);
    const hasTrackingParams = this.hasTrackingParameters(url);
    
    if (isTracker || hasTrackingParams) {
      this.recordTrackingActivity({
        domain,
        url: details.url,
        type: 'request',
        method: details.method,
        timestamp,
        initiator: details.initiator,
        tabId: details.tabId,
        frameId: details.frameId,
        isTracker,
        hasTrackingParams,
        requestBody: details.requestBody
      });
    }

    // Analyze for data exfiltration
    const exfiltrationData = this.analyzeForExfiltration(details);
    if (exfiltrationData) {
      this.recordDataExfiltration({
        domain,
        url: details.url,
        method: details.method,
        timestamp,
        tabId: details.tabId,
        dataTypes: exfiltrationData.dataTypes,
        severity: exfiltrationData.severity,
        size: details.requestBody ? this.estimatePayloadSize(details.requestBody) : 0
      });
      
      // Trigger high-risk alert
      this.triggerSecurityAlert('data-exfiltration', {
        domain: domain,
        url: details.url,
        dataTypes: exfiltrationData.dataTypes,
        severity: exfiltrationData.severity
      });
    }

    // Analyze for price tracking
    if (this.isPriceRequest(url)) {
      this.recordPriceData(details);
    }

    // Detect beaconing patterns
    this.detectBeaconingPattern(domain, details);

    // Store network request data
    this.networkRequests.set(details.requestId, {
      url: details.url,
      domain,
      timestamp,
      tabId: details.tabId,
      method: details.method,
      type: details.type
    });
  }

  analyzeResponse(details) {
    const headers = details.responseHeaders || [];
    const trackingHeaders = this.findTrackingHeaders(headers);
    
    if (trackingHeaders.length > 0) {
      this.recordTrackingActivity({
        domain: new URL(details.url).hostname,
        url: details.url,
        type: 'response',
        timestamp: Date.now(),
        tabId: details.tabId,
        trackingHeaders
      });
    }

    // Analyze cookies and tracking pixels
    this.analyzeCookies(headers, details);
  }

  analyzeHeaders(details) {
    const headers = details.requestHeaders || [];
    const fingerprinting = this.detectFingerprinting(headers);
    
    if (fingerprinting.detected) {
      this.recordFingerprintingAttempt({
        domain: new URL(details.url).hostname,
        url: details.url,
        timestamp: Date.now(),
        tabId: details.tabId,
        fingerprinting
      });
    }
  }

  isTrackingDomain(domain) {
    return Array.from(this.knownTrackers).some(tracker => 
      domain.includes(tracker) || domain.endsWith(tracker)
    );
  }

  hasTrackingParameters(url) {
    const trackingParams = [
      'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
      'gclid', 'fbclid', 'mc_cid', 'mc_eid', '_ga', '_gid', 'msclkid',
      'ttclid', 'twclid', 'li_source', 'trk', 'ref', 'referrer'
    ];
    
    return trackingParams.some(param => url.searchParams.has(param));
  }

  isPriceRequest(url) {
    const priceIndicators = [
      'price', 'cost', 'amount', 'total', 'checkout', 'cart',
      'product', 'item', 'buy', 'purchase', 'payment'
    ];
    
    const urlString = url.toString().toLowerCase();
    return priceIndicators.some(indicator => urlString.includes(indicator));
  }

  findTrackingHeaders(headers) {
    const trackingHeaders = [];
    const suspiciousHeaders = [
      'x-forwarded-for', 'x-real-ip', 'x-client-ip',
      'set-cookie', 'x-tracking-id', 'x-visitor-id',
      'x-session-id', 'x-correlation-id'
    ];
    
    headers.forEach(header => {
      if (suspiciousHeaders.includes(header.name.toLowerCase())) {
        trackingHeaders.push(header);
      }
    });
    
    return trackingHeaders;
  }

  detectFingerprinting(headers) {
    const fingerprinting = { detected: false, methods: [] };
    
    headers.forEach(header => {
      const name = header.name.toLowerCase();
      const value = header.value;
      
      // Check for common fingerprinting headers
      if (name === 'user-agent' && value.length > 200) {
        fingerprinting.detected = true;
        fingerprinting.methods.push('detailed-user-agent');
      }
      
      if (name === 'accept' && value.includes('*/*')) {
        fingerprinting.detected = true;
        fingerprinting.methods.push('accept-header-analysis');
      }
      
      if (name === 'accept-language' && value.split(',').length > 3) {
        fingerprinting.detected = true;
        fingerprinting.methods.push('language-fingerprinting');
      }
    });
    
    return fingerprinting;
  }

  analyzeCookies(headers, details) {
    headers.forEach(header => {
      if (header.name.toLowerCase() === 'set-cookie') {
        const cookieData = this.parseCookie(header.value);
        if (this.isTrackingCookie(cookieData)) {
          this.recordTrackingActivity({
            domain: new URL(details.url).hostname,
            url: details.url,
            type: 'cookie',
            timestamp: Date.now(),
            tabId: details.tabId,
            cookieData
          });
        }
      }
    });
  }

  parseCookie(cookieString) {
    const parts = cookieString.split(';');
    const cookie = {};
    
    parts.forEach(part => {
      const [key, value] = part.trim().split('=');
      cookie[key] = value;
    });
    
    return cookie;
  }

  isTrackingCookie(cookieData) {
    const trackingCookieNames = [
      '_ga', '_gid', '_gat', '__utma', '__utmb', '__utmc', '__utmz',
      'fbp', 'fbc', '_fbp', 'fr', 'datr', 'sb', 'c_user',
      'id', 'uuid', 'visitor_id', 'session_id', 'tracking_id'
    ];
    
    return Object.keys(cookieData).some(key => 
      trackingCookieNames.some(trackingName => 
        key.toLowerCase().includes(trackingName.toLowerCase())
      )
    );
  }

  recordTrackingActivity(activity) {
    const domain = activity.domain;
    
    if (!this.trackingDatabase.has(domain)) {
      this.trackingDatabase.set(domain, {
        domain,
        firstSeen: activity.timestamp,
        lastSeen: activity.timestamp,
        activities: [],
        trackingMethods: new Set(),
        dataPoints: new Set(),
        riskScore: 0
      });
    }
    
    const tracker = this.trackingDatabase.get(domain);
    tracker.activities.push(activity);
    tracker.lastSeen = activity.timestamp;
    
    // Categorize tracking methods
    if (activity.type === 'request' && activity.isTracker) {
      tracker.trackingMethods.add('third-party-tracker');
    }
    if (activity.hasTrackingParams) {
      tracker.trackingMethods.add('url-parameters');
    }
    if (activity.type === 'cookie') {
      tracker.trackingMethods.add('cookies');
    }
    if (activity.type === 'response' && activity.trackingHeaders) {
      tracker.trackingMethods.add('response-headers');
    }
    
    // Update risk score
    tracker.riskScore = this.calculateRiskScore(tracker);
    
    // Store updated data
    this.trackingDatabase.set(domain, tracker);
    this.saveToStorage();
  }

  recordFingerprintingAttempt(attempt) {
    const domain = attempt.domain;
    
    if (!this.fingerprints.has(domain)) {
      this.fingerprints.set(domain, {
        domain,
        attempts: [],
        methods: new Set(),
        riskScore: 0
      });
    }
    
    const fingerprint = this.fingerprints.get(domain);
    fingerprint.attempts.push(attempt);
    
    // Safety check for fingerprinting methods
    if (attempt.fingerprinting && attempt.fingerprinting.methods && Array.isArray(attempt.fingerprinting.methods)) {
      attempt.fingerprinting.methods.forEach(method => {
        fingerprint.methods.add(method);
        
        // Record each method in the delta tracker
        this.fingerprintDeltaTracker.recordFingerprintAccess(domain, method, {
          type: 'fingerprinting-method',
          url: attempt.url,
          timestamp: attempt.timestamp,
          details: attempt.fingerprinting
        });
      });
    }
    
    fingerprint.riskScore = fingerprint.methods.size * 10;
    this.fingerprints.set(domain, fingerprint);
    this.saveToStorage();
  }

  recordPriceData(details) {
    const domain = new URL(details.url).hostname;
    const key = `${domain}_${details.tabId}`;
    
    if (!this.priceHistory.has(key)) {
      this.priceHistory.set(key, {
        domain,
        tabId: details.tabId,
        pricePoints: [],
        personalizedPricing: false
      });
    }
    
    const priceData = this.priceHistory.get(key);
    priceData.pricePoints.push({
      timestamp: Date.now(),
      url: details.url,
      method: details.method
    });
    
    // Simple personalized pricing detection
    if (priceData.pricePoints.length > 2) {
      priceData.personalizedPricing = this.detectPersonalizedPricing(priceData);
    }
    
    this.priceHistory.set(key, priceData);
    this.saveToStorage();
  }

  detectPersonalizedPricing(priceData) {
    // Simple heuristic: multiple price requests in short time
    const recent = priceData.pricePoints.filter(point => 
      Date.now() - point.timestamp < 300000 // 5 minutes
    );
    
    return recent.length > 3;
  }

  calculateRiskScore(tracker) {
    let score = 0;
    
    // Base score for tracking methods
    score += tracker.trackingMethods.size * 10;
    
    // Activity frequency
    score += Math.min(tracker.activities.length, 50);
    
    // Known bad actors
    if (this.knownTrackers.has(tracker.domain)) {
      score += 25;
    }
    
    // Time span (longer tracking = higher risk)
    const timeSpan = tracker.lastSeen - tracker.firstSeen;
    score += Math.min(timeSpan / (1000 * 60 * 60), 24); // Hours, max 24
    
    return Math.min(score, 100);
  }

  async analyzePageLoad(tab) {
    try {
      // Skip analysis for certain URLs that can't be analyzed
      if (!tab.url || 
          tab.url.startsWith('chrome://') || 
          tab.url.startsWith('chrome-extension://') ||
          tab.url.startsWith('moz-extension://') ||
          tab.url.startsWith('edge://') ||
          tab.url === 'about:blank') {
        console.log('Skipping analysis for restricted URL:', tab.url);
        return;
      }

      // For file:// URLs, add additional logging
      if (tab.url.startsWith('file://')) {
        console.log('Analyzing local file:', tab.url);
      }

      // Inject analysis script
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: this.analyzePageContent
      });
    } catch (error) {
      // Don't log errors for URLs we can't access (this is normal)
      if (error.message.includes('Cannot access contents of url') ||
          error.message.includes('Extension manifest must request permission') ||
          error.message.includes('The extensions gallery cannot be scripted')) {
        console.log('Cannot analyze URL (access restricted):', tab.url);
      } else {
        console.error('Failed to analyze page:', error);
      }
    }
  }

  analyzePageContent() {
    // This function runs in the page context
    const analysis = {
      trackingPixels: [],
      socialWidgets: [],
      adNetworks: [],
      fingerprinting: []
    };
    
    // Find tracking pixels
    const images = document.querySelectorAll('img[src*="track"], img[src*="pixel"], img[width="1"][height="1"]');
    images.forEach(img => {
      analysis.trackingPixels.push({
        src: img.src,
        dimensions: `${img.width}x${img.height}`,
        hidden: img.width <= 1 || img.height <= 1
      });
    });
    
    // Find social widgets
    const socialSelectors = [
      'iframe[src*="facebook"]', 'iframe[src*="twitter"]',
      'iframe[src*="linkedin"]', 'iframe[src*="instagram"]',
      'div[class*="fb-"]', 'div[class*="twitter-"]'
    ];
    
    socialSelectors.forEach(selector => {
      const elements = document.querySelectorAll(selector);
      elements.forEach(el => {
        analysis.socialWidgets.push({
          type: selector,
          src: el.src || el.className,
          visible: el.offsetWidth > 0 && el.offsetHeight > 0
        });
      });
    });
    
    // Detect canvas fingerprinting
    const canvases = document.querySelectorAll('canvas');
    canvases.forEach(canvas => {
      if (canvas.getContext) {
        analysis.fingerprinting.push({
          type: 'canvas',
          size: `${canvas.width}x${canvas.height}`,
          hidden: canvas.style.display === 'none'
        });
      }
    });
    
    // Send analysis back to background script
    chrome.runtime.sendMessage({
      type: 'pageAnalysis',
      data: analysis,
      url: window.location.href
    });
  }

  async saveToStorage() {
    try {
      await chrome.storage.local.set({
        trackingDatabase: Array.from(this.trackingDatabase.entries()),
        fingerprints: Array.from(this.fingerprints.entries()),
        priceHistory: Array.from(this.priceHistory.entries()),
        fingerprintTimeline: this.fingerprintDeltaTracker.exportTimelineData(),
        lastUpdated: Date.now()
      });
    } catch (error) {
      console.error('Failed to save to storage:', error);
    }
  }

  async loadFromStorage() {
    try {
      const result = await chrome.storage.local.get([
        'trackingDatabase', 'fingerprints', 'priceHistory', 'fingerprintTimeline'
      ]);
      
      if (result.trackingDatabase) {
        this.trackingDatabase = new Map(result.trackingDatabase.map(([domain, tracker]) => [
          domain,
          {
            ...tracker,
            trackingMethods: new Set(tracker.trackingMethods || []),
            dataPoints: new Set(tracker.dataPoints || [])
          }
        ]));
      }
      
      if (result.fingerprints) {
        this.fingerprints = new Map(result.fingerprints.map(([domain, fingerprint]) => [
          domain,
          {
            ...fingerprint,
            methods: new Set(fingerprint.methods || [])
          }
        ]));
      }
      
      if (result.priceHistory) {
        this.priceHistory = new Map(result.priceHistory);
      }
      
      if (result.fingerprintTimeline) {
        this.fingerprintDeltaTracker.importTimelineData(result.fingerprintTimeline);
      }
    } catch (error) {
      console.error('Failed to load from storage:', error);
    }
  }

  async generateSurveillanceReport() {
    const report = {
      timestamp: Date.now(),
      totalTrackers: this.trackingDatabase.size,
      totalFingerprinters: this.fingerprints.size,
      highRiskDomains: [],
      trackingMethods: new Set(),
      dataFlowMap: {},
      privacyScore: 0
    };
    
    // Analyze tracking data
    this.trackingDatabase.forEach((tracker, domain) => {
      if (tracker.riskScore > 50) {
        report.highRiskDomains.push({
          domain,
          riskScore: tracker.riskScore,
          methods: Array.from(tracker.trackingMethods),
          activities: tracker.activities.length
        });
      }
      
      tracker.trackingMethods.forEach(method => 
        report.trackingMethods.add(method)
      );
    });
    
    // Calculate privacy score
    report.privacyScore = Math.max(0, 100 - (
      report.totalTrackers * 2 + 
      report.totalFingerprinters * 5 + 
      report.highRiskDomains.length * 10
    ));
    
    report.trackingMethods = Array.from(report.trackingMethods);
    
    return report;
  }

  updateSettings(settings) {
    // Update analyzer settings
    this.settings = settings;
    
    // Add custom trackers to known trackers
    if (settings.customTrackers && settings.customTrackers.length > 0) {
      settings.customTrackers.forEach(tracker => {
        this.knownTrackers.add(tracker);
      });
    }
    
    // Save settings to storage
    chrome.storage.sync.set({ surveillanceSettings: settings });
  }

  // Advanced Data Exfiltration Analysis
  analyzeForExfiltration(details) {
    const url = new URL(details.url);
    const domain = url.hostname;
    const method = details.method;
    const requestBody = details.requestBody;
    
    const suspiciousIndicators = [];
    let severity = 'LOW';
    
    // Check URL parameters for sensitive data
    const urlParams = url.searchParams;
    const sensitiveParams = [
      'email', 'phone', 'name', 'address', 'ssn', 'credit', 'card',
      'fingerprint', 'canvas', 'webgl', 'screen', 'timezone', 'browser',
      'device', 'hardware', 'user-agent', 'fonts', 'plugins', 'language'
    ];
    
    sensitiveParams.forEach(param => {
      if (urlParams.toString().toLowerCase().includes(param)) {
        suspiciousIndicators.push(`url-param-${param}`);
        severity = 'MEDIUM';
      }
    });
    
    // Analyze request body for fingerprint data
    if (requestBody) {
      const bodyData = this.extractRequestBodyData(requestBody);
      if (bodyData) {
        const fingerprintPatterns = [
          'canvas', 'webgl', 'screen', 'timezone', 'fonts', 'plugins',
          'useragent', 'language', 'platform', 'hardware', 'audio',
          'battery', 'devicememory', 'connection', 'geolocation'
        ];
        
        fingerprintPatterns.forEach(pattern => {
          if (bodyData.toLowerCase().includes(pattern)) {
            suspiciousIndicators.push(`body-${pattern}`);
            severity = 'HIGH';
          }
        });
      }
    }
    
    // Check for known data collection endpoints
    const dataCollectionPatterns = [
      'collect', 'track', 'analytics', 'beacon', 'pixel', 'event',
      'fingerprint', 'profile', 'identity', 'visitor', 'session'
    ];
    
    dataCollectionPatterns.forEach(pattern => {
      if (url.pathname.toLowerCase().includes(pattern)) {
        suspiciousIndicators.push(`endpoint-${pattern}`);
        severity = severity === 'LOW' ? 'MEDIUM' : severity;
      }
    });
    
    // Check for large data payloads (potential bulk exfiltration)
    if (requestBody && this.estimatePayloadSize(requestBody) > 1000) {
      suspiciousIndicators.push('large-payload');
      severity = 'HIGH';
    }
    
    if (suspiciousIndicators.length > 0) {
      return {
        dataTypes: suspiciousIndicators,
        severity: severity,
        method: method,
        timestamp: Date.now()
      };
    }
    
    return null;
  }

  extractRequestBodyData(requestBody) {
    if (!requestBody) return null;
    
    try {
      if (requestBody.formData) {
        // Safely stringify formData by creating a simple object
        const formObj = {};
        Object.entries(requestBody.formData).forEach(([key, value]) => {
          // Only include simple values to avoid circular references
          if (typeof value === 'string' || typeof value === 'number') {
            formObj[key] = value;
          } else if (Array.isArray(value)) {
            formObj[key] = value.slice(0, 10).map(v => 
              typeof v === 'string' ? v : String(v)
            ); // Limit array size and convert to strings
          }
        });
        return JSON.stringify(formObj);
      }
      
      if (requestBody.raw && requestBody.raw[0] && requestBody.raw[0].bytes) {
        const bytes = requestBody.raw[0].bytes;
        // Limit the size to prevent memory issues
        const maxSize = Math.min(bytes.length, 1000);
        const limitedBytes = bytes.slice(0, maxSize);
        return String.fromCharCode.apply(null, new Uint8Array(limitedBytes));
      }
    } catch (error) {
      console.error('Error extracting request body:', error);
    }
    
    return null;
  }

  estimatePayloadSize(requestBody) {
    if (!requestBody) return 0;
    
    try {
      if (requestBody.formData) {
        return JSON.stringify(requestBody.formData).length;
      }
      if (requestBody.raw && requestBody.raw[0] && requestBody.raw[0].bytes) {
        return requestBody.raw[0].bytes.length;
      }
    } catch (error) {
      console.error('Error estimating payload size:', error);
    }
    
    return 0;
  }

  recordDataExfiltration(exfiltrationData) {
    const domain = exfiltrationData.domain;
    
    if (!this.exfiltrationData.has(domain)) {
      this.exfiltrationData.set(domain, {
        domain: domain,
        attempts: [],
        totalAttempts: 0,
        dataTypes: new Set(),
        severity: 'LOW',
        firstSeen: exfiltrationData.timestamp,
        lastSeen: exfiltrationData.timestamp
      });
    }
    
    const domainData = this.exfiltrationData.get(domain);
    domainData.attempts.push(exfiltrationData);
    domainData.totalAttempts++;
    domainData.lastSeen = exfiltrationData.timestamp;
    
    // Track unique data types
    exfiltrationData.dataTypes.forEach(type => {
      domainData.dataTypes.add(type);
    });
    
    // Update severity to highest seen
    if (exfiltrationData.severity === 'HIGH' || 
        (exfiltrationData.severity === 'MEDIUM' && domainData.severity === 'LOW')) {
      domainData.severity = exfiltrationData.severity;
    }
    
    // Save to storage
    this.saveToStorage();
  }

  detectBeaconingPattern(domain, details) {
    const now = Date.now();
    
    if (!this.beaconingPatterns.has(domain)) {
      this.beaconingPatterns.set(domain, {
        requests: [],
        intervals: [],
        isBeaconing: false,
        pattern: null
      });
    }
    
    const pattern = this.beaconingPatterns.get(domain);
    pattern.requests.push({
      timestamp: now,
      url: details.url,
      method: details.method
    });
    
    // Keep only last 50 requests for analysis
    if (pattern.requests.length > 50) {
      pattern.requests = pattern.requests.slice(-50);
    }
    
    // Analyze intervals between requests
    if (pattern.requests.length >= 3) {
      const recent = pattern.requests.slice(-3);
      const interval1 = recent[1].timestamp - recent[0].timestamp;
      const interval2 = recent[2].timestamp - recent[1].timestamp;
      
      // Check if intervals are consistent (within 20% tolerance)
      const tolerance = 0.2;
      const avgInterval = (interval1 + interval2) / 2;
      const deviation = Math.abs(interval1 - interval2) / avgInterval;
      
      if (deviation <= tolerance && avgInterval >= 1000 && avgInterval <= 300000) {
        pattern.isBeaconing = true;
        pattern.pattern = {
          interval: avgInterval,
          detected: now,
          confidence: 1 - deviation
        };
        
        // Trigger beaconing alert
        this.triggerSecurityAlert('beaconing-detected', {
          domain: domain,
          interval: avgInterval,
          confidence: pattern.pattern.confidence
        });
      }
    }
  }

  triggerSecurityAlert(type, data) {
    const alert = {
      type: type,
      data: data,
      timestamp: Date.now(),
      severity: data.severity || 'MEDIUM'
    };
    
    // Store alert
    if (!this.securityAlerts) {
      this.securityAlerts = [];
    }
    this.securityAlerts.push(alert);
    
    // Keep only last 100 alerts
    if (this.securityAlerts.length > 100) {
      this.securityAlerts = this.securityAlerts.slice(-100);
    }
    
    // Show browser notification for high-severity alerts
    if (this.settings.realTimeAlerts && (data.severity === 'HIGH' || type === 'beaconing-detected')) {
      this.showBrowserNotification(alert);
    }
    
    // Save to storage
    this.saveToStorage();
  }

  showBrowserNotification(alert) {
    const title = this.getAlertTitle(alert.type);
    const message = this.getAlertMessage(alert);
    
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: title,
      message: message,
      priority: alert.severity === 'HIGH' ? 2 : 1
    });
  }

  getAlertTitle(type) {
    const titles = {
      'data-exfiltration': 'Data Exfiltration Detected',
      'beaconing-detected': 'Beaconing Pattern Detected',
      'high-risk-fingerprinting': 'High-Risk Fingerprinting'
    };
    return titles[type] || 'Security Alert';
  }

  getAlertMessage(alert) {
    switch (alert.type) {
      case 'data-exfiltration':
        return `${alert.data.domain} is exfiltrating: ${alert.data.dataTypes.join(', ')}`;
      case 'beaconing-detected':
        return `${alert.data.domain} is beaconing every ${Math.round(alert.data.interval / 1000)}s`;
      default:
        return `Security issue detected on ${alert.data.domain}`;
    }
  }

  async exportAllData() {
    const exportData = {
      timestamp: Date.now(),
      version: '1.0.0',
      trackingDatabase: Array.from(this.trackingDatabase.entries()),
      fingerprints: Array.from(this.fingerprints.entries()),
      priceHistory: Array.from(this.priceHistory.entries()),
      fingerprintTimeline: this.fingerprintDeltaTracker.exportTimelineData(),
      forensicSummary: this.fingerprintDeltaTracker.getForensicSummary(),
      knownTrackers: Array.from(this.knownTrackers),
      exfiltrationData: Array.from(this.exfiltrationData.entries()),
      securityAlerts: this.securityAlerts || [],
      settings: this.settings || {}
    };
    
    return exportData;
  }
}

// Initialize the surveillance analyzer
const surveillanceAnalyzer = new SurveillanceAnalyzer();

// Load existing data
surveillanceAnalyzer.loadFromStorage();

// Notify popup when it opens to send initial data
let isPopupOpen = false;

// Handle messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Check if the message is from our extension's popup
  const isFromPopup = sender.url.includes(chrome.runtime.id) && sender.url.includes('popup.html');

  if (request.type === 'popup-opened' && isFromPopup) {
    isPopupOpen = true;
    console.log('Popup opened, sending initial forensic summary.');
    const forensicSummary = surveillanceAnalyzer.fingerprintDeltaTracker.getForensicSummary();
    sendResponse(forensicSummary);
    return true; // Keep message channel open for async response
  }

  // Handle popup closing
  if (request.type === 'popup-closed' && isFromPopup) {
    isPopupOpen = false;
    console.log('Popup closed.');
    sendResponse({ success: true });
    return true;
  }

  // Function to notify the popup if it's open
  const notifyPopup = (message) => {
    if (isPopupOpen) {
      console.log('Notifying open popup:', message.type);
      chrome.runtime.sendMessage(message).catch(error => {
        if (error.message.includes('Receiving end does not exist')) {
          // This can happen if the popup closes right as we send a message
          isPopupOpen = false;
          console.log('Popup closed before notification could be sent.');
        } else {
          console.error('Error notifying popup:', error);
        }
      });
    }
  };

  switch (request.type) {
    case 'getReport':
      surveillanceAnalyzer.generateSurveillanceReport()
        .then(report => sendResponse(report));
      return true;
    
    case 'pageAnalysis':
      // Handle page analysis data from content script
      console.log('Page analysis received:', request.data);
      break;
    
    case 'clearData':
      surveillanceAnalyzer.trackingDatabase.clear();
      surveillanceAnalyzer.fingerprints.clear();
      surveillanceAnalyzer.priceHistory.clear();
      surveillanceAnalyzer.fingerprintDeltaTracker.clearTimelineData();
      surveillanceAnalyzer.saveToStorage();
      sendResponse({ success: true });
      break;
    
    case 'settingsUpdated':
      // Handle settings updates
      surveillanceAnalyzer.updateSettings(request.settings);
      sendResponse({ success: true });
      break;
    
    case 'exportData':
      // Export all surveillance data
      surveillanceAnalyzer.exportAllData()
        .then(data => sendResponse(data));
      return true;
    
    case 'getDomainTimeline':
      // Get timeline for specific domain
      const domainTimeline = surveillanceAnalyzer.fingerprintDeltaTracker.getTimelineForDomain(request.domain);
      sendResponse(domainTimeline);
      break;
    
    case 'recordFingerprintAccess':
      // Record fingerprint access from content script
      console.log('Recording fingerprint access:', request);
      const entry = surveillanceAnalyzer.fingerprintDeltaTracker.recordFingerprintAccess(
        request.domain, 
        request.attribute, 
        request.details
      );
      
      // Notify the popup with the new entry
      notifyPopup({ type: 'fingerprint-activity-update', data: entry });

      // Save to storage after recording
      surveillanceAnalyzer.saveToStorage();
      sendResponse({ success: true, entry });
      break;
    
    case 'getExfiltrationData':
      // Get exfiltration and security data
      console.log('Getting exfiltration data...');
      const exfiltrationData = {
        totalDomains: surveillanceAnalyzer.exfiltrationData.size,
        totalAttempts: Array.from(surveillanceAnalyzer.exfiltrationData.values()).reduce((sum, data) => sum + data.totalAttempts, 0),
        criticalAlerts: surveillanceAnalyzer.securityAlerts.filter(alert => alert.severity === 'HIGH' || alert.severity === 'CRITICAL').length,
        exfiltrationAttempts: Array.from(surveillanceAnalyzer.exfiltrationData.entries()).map(([domain, data]) => ({
          domain: domain,
          dataTypes: Array.from(data.dataTypes),
          severity: data.severity,
          totalAttempts: data.totalAttempts,
          lastSeen: data.lastSeen
        })),
        beaconingPatterns: Array.from(surveillanceAnalyzer.beaconingPatterns.entries())
          .filter(([domain, pattern]) => pattern.isBeaconing)
          .map(([domain, pattern]) => ({
            domain: domain,
            interval: pattern.pattern.interval,
            confidence: pattern.pattern.confidence,
            detected: pattern.pattern.detected
          })),
        securityAlerts: surveillanceAnalyzer.securityAlerts.slice(-20) // Last 20 alerts
      };
      
      // Notify popup with security updates
      notifyPopup({ type: 'exfiltration-data-update', data: exfiltrationData });
      
      console.log('Exfiltration data:', exfiltrationData);
      sendResponse(exfiltrationData);
      break;
  }
  
  return true; // Default to keeping message channel open for async responses
}); 