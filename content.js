// Corporate Surveillance Reverse-Engineering Tool - Content Script
class PageSurveillanceAnalyzer {
  constructor() {
    this.observers = [];
    this.analysisData = {
      trackingPixels: [],
      socialWidgets: [],
      adNetworks: [],
      fingerprinting: [],
      priceElements: [],
      behaviorTracking: []
    };
    
    this.init();
  }

  init() {
    // Setup message listener first
    this.setupInjectedScriptListener();
    
    // Inject the injected script as early as possible
    this.injectScript();
    
    // Start analysis when DOM is ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.analyzePageContent());
    } else {
      this.analyzePageContent();
    }
    
    // Monitor for dynamic content
    this.setupMutationObserver();
    
    // Hook into JavaScript APIs commonly used for fingerprinting
    this.setupAPIHooks();
    
    // Monitor network requests from the page
    this.setupNetworkMonitoring();
  }

  analyzePageContent() {
    this.findTrackingPixels();
    this.findSocialWidgets();
    this.findAdNetworks();
    this.detectFingerprinting();
    this.findPriceElements();
    this.detectBehaviorTracking();
    
    // Send analysis to background script
    this.sendAnalysisToBackground();
  }

  findTrackingPixels() {
    // Look for 1x1 pixel images and known tracking patterns
    const images = document.querySelectorAll('img');
    
    images.forEach(img => {
      const isTrackingPixel = (
        (img.width === 1 && img.height === 1) ||
        (img.style.width === '1px' && img.style.height === '1px') ||
        img.src.includes('track') ||
        img.src.includes('pixel') ||
        img.src.includes('beacon') ||
        img.src.includes('analytics')
      );
      
      if (isTrackingPixel) {
        this.analysisData.trackingPixels.push({
          src: img.src,
          dimensions: `${img.width}x${img.height}`,
          hidden: img.width <= 1 || img.height <= 1 || img.style.display === 'none',
          domain: this.extractDomain(img.src),
          timestamp: Date.now()
        });
      }
    });
    
    // Look for tracking pixels in CSS background images
    const elementsWithBg = document.querySelectorAll('*');
    elementsWithBg.forEach(el => {
      const bgImage = window.getComputedStyle(el).backgroundImage;
      if (bgImage && bgImage !== 'none') {
        const match = bgImage.match(/url\(["']?([^"')]+)["']?\)/);
        if (match) {
          const url = match[1];
          if (url.includes('track') || url.includes('pixel') || url.includes('beacon')) {
            this.analysisData.trackingPixels.push({
              src: url,
              type: 'css-background',
              element: el.tagName.toLowerCase(),
              domain: this.extractDomain(url),
              timestamp: Date.now()
            });
          }
        }
      }
    });
  }

  findSocialWidgets() {
    const socialPatterns = [
      { name: 'Facebook', selectors: ['iframe[src*="facebook"]', 'div[class*="fb-"]', 'div[id*="fb-"]'] },
      { name: 'Twitter', selectors: ['iframe[src*="twitter"]', 'div[class*="twitter-"]', 'blockquote[class*="twitter-"]'] },
      { name: 'LinkedIn', selectors: ['iframe[src*="linkedin"]', 'div[class*="linkedin-"]'] },
      { name: 'Instagram', selectors: ['iframe[src*="instagram"]', 'div[class*="instagram-"]'] },
      { name: 'YouTube', selectors: ['iframe[src*="youtube"]', 'iframe[src*="youtu.be"]'] },
      { name: 'Pinterest', selectors: ['iframe[src*="pinterest"]', 'div[class*="pinterest-"]'] }
    ];
    
    socialPatterns.forEach(pattern => {
      pattern.selectors.forEach(selector => {
        const elements = document.querySelectorAll(selector);
        elements.forEach(el => {
          this.analysisData.socialWidgets.push({
            platform: pattern.name,
            type: el.tagName.toLowerCase(),
            src: el.src || el.className,
            visible: el.offsetWidth > 0 && el.offsetHeight > 0,
            domain: el.src ? this.extractDomain(el.src) : null,
            timestamp: Date.now()
          });
        });
      });
    });
  }

  findAdNetworks() {
    const adNetworkPatterns = [
      'googlesyndication.com', 'doubleclick.net', 'googleadservices.com',
      'amazon-adsystem.com', 'adsystem.amazon.com', 'media.net',
      'outbrain.com', 'taboola.com', 'revcontent.com', 'contentad.net'
    ];
    
    // Check iframes
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      const src = iframe.src;
      adNetworkPatterns.forEach(pattern => {
        if (src.includes(pattern)) {
          this.analysisData.adNetworks.push({
            network: pattern,
            type: 'iframe',
            src: src,
            dimensions: `${iframe.width}x${iframe.height}`,
            visible: iframe.offsetWidth > 0 && iframe.offsetHeight > 0,
            timestamp: Date.now()
          });
        }
      });
    });
    
    // Check scripts
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
      const src = script.src;
      adNetworkPatterns.forEach(pattern => {
        if (src.includes(pattern)) {
          this.analysisData.adNetworks.push({
            network: pattern,
            type: 'script',
            src: src,
            async: script.async,
            defer: script.defer,
            timestamp: Date.now()
          });
        }
      });
    });
  }

  detectFingerprinting() {
    // Canvas fingerprinting detection
    const canvases = document.querySelectorAll('canvas');
    canvases.forEach(canvas => {
      if (canvas.getContext) {
        this.analysisData.fingerprinting.push({
          type: 'canvas',
          size: `${canvas.width}x${canvas.height}`,
          hidden: canvas.style.display === 'none' || canvas.offsetWidth === 0,
          contextTypes: this.getCanvasContextTypes(canvas),
          timestamp: Date.now()
        });
      }
    });
    
    // Font fingerprinting detection
    const fontTestElements = document.querySelectorAll('span[style*="font-family"], div[style*="font-family"]');
    if (fontTestElements.length > 20) {
      this.analysisData.fingerprinting.push({
        type: 'font-fingerprinting',
        elementCount: fontTestElements.length,
        timestamp: Date.now()
      });
    }
    
    // WebGL fingerprinting detection
    const webglElements = document.querySelectorAll('canvas');
    webglElements.forEach(canvas => {
      if (canvas.getContext && (canvas.getContext('webgl') || canvas.getContext('experimental-webgl'))) {
        this.analysisData.fingerprinting.push({
          type: 'webgl',
          size: `${canvas.width}x${canvas.height}`,
          hidden: canvas.style.display === 'none',
          timestamp: Date.now()
        });
      }
    });
  }

  getCanvasContextTypes(canvas) {
    const contexts = [];
    try {
      if (canvas.getContext('2d')) contexts.push('2d');
      if (canvas.getContext('webgl')) contexts.push('webgl');
      if (canvas.getContext('experimental-webgl')) contexts.push('experimental-webgl');
      if (canvas.getContext('webgl2')) contexts.push('webgl2');
    } catch (e) {
      // Ignore errors
    }
    return contexts;
  }

  findPriceElements() {
    const priceSelectors = [
      '[class*="price"]', '[id*="price"]', '[data-price]',
      '[class*="cost"]', '[id*="cost"]', '[data-cost]',
      '[class*="amount"]', '[id*="amount"]', '[data-amount]',
      '.currency', '.money', '.total', '.subtotal'
    ];
    
    priceSelectors.forEach(selector => {
      const elements = document.querySelectorAll(selector);
      elements.forEach(el => {
        const text = el.textContent.trim();
        const hasPrice = /[\$£€¥₹][\d,.]|\d+[\.,]\d+/.test(text);
        
        if (hasPrice) {
          this.analysisData.priceElements.push({
            selector: selector,
            text: text,
            innerHTML: el.innerHTML,
            className: el.className,
            id: el.id,
            timestamp: Date.now()
          });
        }
      });
    });
  }

  detectBehaviorTracking() {
    // Look for common behavior tracking libraries
    const behaviorLibraries = [
      'hotjar', 'fullstory', 'logrocket', 'mouseflow', 'crazyegg',
      'heatmap', 'clicktale', 'inspectlet', 'sessioncam', 'userreplay'
    ];
    
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      const src = script.src;
      const content = script.textContent;
      
      behaviorLibraries.forEach(lib => {
        if (src.includes(lib) || content.includes(lib)) {
          this.analysisData.behaviorTracking.push({
            library: lib,
            type: src ? 'external-script' : 'inline-script',
            src: src,
            timestamp: Date.now()
          });
        }
      });
    });
  }

  setupMutationObserver() {
    try {
      const observer = new MutationObserver((mutations) => {
        try {
          mutations.forEach((mutation) => {
            if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
              // Check for dynamically added tracking elements
              mutation.addedNodes.forEach(node => {
                if (node && node.nodeType === Node.ELEMENT_NODE) {
                  this.analyzeDynamicContent(node);
                }
              });
            }
          });
        } catch (error) {
          console.error('Error in MutationObserver callback:', error);
        }
      });
      
      // Wait for document.body to be available
      const startObserving = () => {
        try {
          if (document && document.body && document.body.nodeType === Node.ELEMENT_NODE) {
            console.log('Setting up MutationObserver on document.body');
            observer.observe(document.body, {
              childList: true,
              subtree: true
            });
            this.observers.push(observer);
            console.log('MutationObserver successfully set up');
          } else {
            // Retry after a short delay
            console.log('document.body not ready, retrying...');
            setTimeout(startObserving, 100);
          }
        } catch (error) {
          console.error('Error setting up MutationObserver:', error);
          // Try again after a longer delay
          setTimeout(startObserving, 500);
        }
      };
      
      // Start observing with a small delay to ensure DOM is ready
      setTimeout(startObserving, 50);
    } catch (error) {
      console.error('Failed to create MutationObserver:', error);
    }
  }

  analyzeDynamicContent(element) {
    try {
      // Check for tracking pixels in dynamically added content
      if (!element || !element.querySelectorAll) {
        console.warn('Invalid element passed to analyzeDynamicContent:', element);
        return;
      }
      
      const images = element.querySelectorAll('img');
      images.forEach(img => {
        if (img.width === 1 && img.height === 1) {
          this.analysisData.trackingPixels.push({
            src: img.src,
            type: 'dynamic',
            dimensions: '1x1',
            hidden: true,
            domain: this.extractDomain(img.src),
            timestamp: Date.now()
          });
        }
      });
    } catch (error) {
      console.error('Error in analyzeDynamicContent:', error);
    }
  }

  setupAPIHooks() {
    // Hook into common fingerprinting APIs
    const originalCreateElement = document.createElement;
    document.createElement = function(tagName) {
      const element = originalCreateElement.call(document, tagName);
      
      if (tagName.toLowerCase() === 'canvas') {
        // Track canvas creation
        window.postMessage({
          type: 'surveillance-canvas-created',
          timestamp: Date.now()
        }, '*');
      }
      
      return element;
    };
    
    // Hook into Navigator APIs commonly used for fingerprinting
    if (navigator.userAgent) {
      const originalUserAgent = navigator.userAgent;
      Object.defineProperty(navigator, 'userAgent', {
        get: function() {
          window.postMessage({
            type: 'surveillance-useragent-accessed',
            timestamp: Date.now()
          }, '*');
          return originalUserAgent;
        }
      });
    }
  }

  setupNetworkMonitoring() {
    // Monitor fetch API
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
      const url = args[0];
      window.postMessage({
        type: 'surveillance-fetch-request',
        url: url,
        timestamp: Date.now()
      }, '*');
      return originalFetch.apply(this, args);
    };
    
    // Monitor XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
      window.postMessage({
        type: 'surveillance-xhr-request',
        method: method,
        url: url,
        timestamp: Date.now()
      }, '*');
      return originalXHROpen.apply(this, arguments);
    };
  }

  setupInjectedScriptListener() {
    window.addEventListener('message', (event) => {
      // Only accept messages from the same window
      if (event.source !== window) return;
      
      // Handle messages from injected script
      if (event.data.type && event.data.type.startsWith('surveillance-')) {
        this.handleInjectedScriptMessage(event.data);
      }
    });
  }

  handleInjectedScriptMessage(data) {
    const domain = this.extractDomain(window.location.href);
    
    console.log('Content script received message:', data.type, data.data);
    
    switch (data.type) {
      case 'surveillance-canvas-created':
      case 'surveillance-canvas-access':
        this.processFingerprinting('canvas', data.data || data, domain);
        break;
      
      case 'surveillance-canvas-fingerprint':
        this.processFingerprinting('canvas-fingerprint', data.data || data, domain);
        break;
      
      case 'surveillance-navigator-fingerprint':
        this.processFingerprinting('navigator', data.data || data, domain);
        break;
      
      case 'surveillance-screen-fingerprint':
        this.processFingerprinting('screen', data.data || data, domain);
        break;
      
      case 'surveillance-webgl-fingerprint':
      case 'surveillance-webgl2-fingerprint':
        this.processFingerprinting('webgl', data.data || data, domain);
        break;
      
      case 'surveillance-audio-fingerprint':
        this.processFingerprinting('audio', data.data || data, domain);
        break;
      
      case 'surveillance-performance-fingerprint':
        this.processFingerprinting('performance', data.data || data, domain);
        break;
      
      case 'surveillance-media-fingerprint':
        this.processFingerprinting('media', data.data || data, domain);
        break;
      
      case 'surveillance-font-fingerprint':
        this.processFingerprinting('font', data.data || data, domain);
        break;
      
      case 'surveillance-timezone-fingerprint':
        this.processFingerprinting('timezone', data.data || data, domain);
        break;
      
      case 'surveillance-api-call':
        // Handle API calls from injected script
        this.analysisData.behaviorTracking.push({
          api: (data.data && data.data.api) || data.api,
          url: (data.data && data.data.url) || data.url,
          method: (data.data && data.data.method) || data.method,
          timestamp: (data.data && data.data.timestamp) || data.timestamp
        });
        break;
      
      case 'surveillance-tracking-pixel':
        this.analysisData.trackingPixels.push({
          src: (data.data && data.data.src) || data.src,
          type: 'dynamic-injected',
          timestamp: (data.data && data.data.timestamp) || data.timestamp
        });
        break;
        
      default:
        console.log('Unknown surveillance message type:', data.type);
        break;
    }
    
    // Send updated analysis to background
    this.sendAnalysisToBackground();
  }

  processFingerprinting(type, data, domain) {
    console.log('Processing fingerprinting:', type, data, domain);
    
    // Create fingerprint entry
    const fingerprintEntry = {
      type: type,
      method: data.method || data.property || data.paramName || type,
      severity: data.severity || 'MEDIUM',
      category: data.category || type,
      timestamp: data.timestamp || Date.now(),
      details: data
    };
    
    console.log('Fingerprint entry created:', fingerprintEntry);
    
    // Add to analysis data
    this.analysisData.fingerprinting.push(fingerprintEntry);
    
    // Send to background for delta tracking
    const message = {
      type: 'recordFingerprintAccess',
      domain: domain,
      attribute: `${type}.${fingerprintEntry.method}`,
      details: {
        severity: fingerprintEntry.severity,
        category: fingerprintEntry.category,
        timestamp: fingerprintEntry.timestamp,
        method: fingerprintEntry.method,
        type: type,
        raw: data
      }
    };
    
    console.log('Sending message to background:', message);
    
    chrome.runtime.sendMessage(message).then(response => {
      console.log('Background response:', response);
    }).catch(error => {
      if (error.message.includes('Extension context invalidated')) {
        console.log('Extension was reloaded, stopping content script.');
        return;
      }
      console.error('Error sending to background:', error);
    });
  }

  extractDomain(url) {
    try {
      return new URL(url).hostname;
    } catch (e) {
      return url;
    }
  }

  injectScript() {
    try {
      console.log('Injecting surveillance script...');
      // Use external script to avoid CSP issues
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('injected.js');
      script.onload = function() {
        console.log('Surveillance script injected successfully');
        this.remove();
      };
      script.onerror = function() {
        console.error('Failed to load surveillance script');
      };
      
      // Inject into document as early as possible
      (document.head || document.documentElement).appendChild(script);
    } catch (error) {
      console.error('Failed to inject surveillance script:', error);
    }
  }

  sendAnalysisToBackground() {
    chrome.runtime.sendMessage({
      type: 'pageAnalysis',
      data: this.analysisData,
      url: window.location.href,
      timestamp: Date.now()
    }).catch(error => {
      if (error.message.includes('Extension context invalidated')) {
        console.log('Extension was reloaded, stopping content script.');
        return;
      }
      console.error('Error sending analysis to background:', error);
    });
  }

  cleanup() {
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
  }
}

// Initialize page surveillance analyzer
const pageSurveillanceAnalyzer = new PageSurveillanceAnalyzer();

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'analyzeCurrentPage') {
    pageSurveillanceAnalyzer.analyzePageContent();
    sendResponse({ success: true });
  }
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  pageSurveillanceAnalyzer.cleanup();
}); 