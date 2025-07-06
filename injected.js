// Corporate Surveillance Reverse-Engineering Tool - Injected Script
// This script runs in the page context to hook into native APIs

(function() {
  'use strict';
  
  console.log('Surveillance script loaded - monitoring API access...');
  console.log('Hooking fingerprinting APIs...');

  // Store original functions
  const originalFetch = window.fetch;
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  const originalCreateElement = document.createElement;
  const originalGetContext = HTMLCanvasElement.prototype.getContext;

  // Track API usage
  const apiUsage = {
    fetch: [],
    xhr: [],
    canvas: [],
    fingerprinting: []
  };

  // Hook fetch API
  window.fetch = function(resource, options = {}) {
    const url = typeof resource === 'string' ? resource : resource.url;
    
    apiUsage.fetch.push({
      url: url,
      method: options.method || 'GET',
      timestamp: Date.now(),
      headers: options.headers || {},
      stack: new Error().stack
    });

    // Send data to content script
    window.postMessage({
      type: 'surveillance-api-call',
      data: {
        api: 'fetch',
        url: url,
        method: options.method || 'GET',
        timestamp: Date.now()
      }
    }, '*');

    return originalFetch.apply(this, arguments);
  };

  // Hook XMLHttpRequest
  XMLHttpRequest.prototype.open = function(method, url) {
    this._surveillanceData = {
      method: method,
      url: url,
      timestamp: Date.now()
    };

    apiUsage.xhr.push({
      method: method,
      url: url,
      timestamp: Date.now(),
      stack: new Error().stack
    });

    window.postMessage({
      type: 'surveillance-api-call',
      data: {
        api: 'xhr',
        method: method,
        url: url,
        timestamp: Date.now()
      }
    }, '*');

    return originalXHROpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function(data) {
    if (this._surveillanceData) {
      window.postMessage({
        type: 'surveillance-xhr-send',
        data: {
          ...this._surveillanceData,
          requestData: data,
          timestamp: Date.now()
        }
      }, '*');
    }

    return originalXHRSend.apply(this, arguments);
  };

  // Hook canvas API for fingerprinting detection
  HTMLCanvasElement.prototype.getContext = function(contextType) {
    apiUsage.canvas.push({
      contextType: contextType,
      timestamp: Date.now(),
      dimensions: `${this.width}x${this.height}`,
      stack: new Error().stack
    });

    window.postMessage({
      type: 'surveillance-canvas-access',
      data: {
        contextType: contextType,
        timestamp: Date.now(),
        dimensions: `${this.width}x${this.height}`
      }
    }, '*');

    return originalGetContext.apply(this, arguments);
  };

  // Hook Canvas.toDataURL - the most common fingerprinting method
  const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(type, encoderOptions) {
    apiUsage.canvas.push({
      method: 'toDataURL',
      type: type || 'image/png',
      timestamp: Date.now(),
      dimensions: `${this.width}x${this.height}`,
      stack: new Error().stack
    });

    console.log('Canvas toDataURL called - fingerprinting detected!');
    window.postMessage({
      type: 'surveillance-canvas-fingerprint',
      data: {
        method: 'toDataURL',
        type: type || 'image/png',
        timestamp: Date.now(),
        dimensions: `${this.width}x${this.height}`,
        severity: 'HIGH' // toDataURL is direct fingerprinting
      }
    }, '*');

    return originalToDataURL.apply(this, arguments);
  };

  // Hook Canvas.getImageData - another fingerprinting vector
  const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh, settings) {
    apiUsage.canvas.push({
      method: 'getImageData',
      timestamp: Date.now(),
      area: `${sw}x${sh}`,
      stack: new Error().stack
    });

    window.postMessage({
      type: 'surveillance-canvas-fingerprint',
      data: {
        method: 'getImageData',
        timestamp: Date.now(),
        area: `${sw}x${sh}`,
        severity: 'HIGH'
      }
    }, '*');

    return originalGetImageData.apply(this, arguments);
  };

  // Hook createElement for dynamic tracking pixel detection
  document.createElement = function(tagName) {
    const element = originalCreateElement.call(document, tagName);
    
    if (tagName.toLowerCase() === 'img') {
      // Monitor for tracking pixels
      const originalSetAttribute = element.setAttribute;
      element.setAttribute = function(name, value) {
        if (name === 'src') {
          // Check if this looks like a tracking pixel
          const isTracking = (
            value.includes('track') ||
            value.includes('pixel') ||
            value.includes('beacon') ||
            value.includes('analytics')
          );
          
          if (isTracking) {
            window.postMessage({
              type: 'surveillance-tracking-pixel',
              data: {
                src: value,
                timestamp: Date.now(),
                stack: new Error().stack
              }
            }, '*');
          }
        }
        return originalSetAttribute.apply(this, arguments);
      };
    }
    
    return element;
  };

  // Hook navigator properties commonly used for fingerprinting
  const navigatorProps = {
    // Core fingerprinting properties
    'userAgent': { severity: 'HIGH', category: 'browser' },
    'platform': { severity: 'HIGH', category: 'system' },
    'language': { severity: 'MEDIUM', category: 'locale' },
    'languages': { severity: 'MEDIUM', category: 'locale' },
    'hardwareConcurrency': { severity: 'HIGH', category: 'hardware' },
    'deviceMemory': { severity: 'HIGH', category: 'hardware' },
    'maxTouchPoints': { severity: 'MEDIUM', category: 'input' },
    'cookieEnabled': { severity: 'LOW', category: 'browser' },
    'onLine': { severity: 'LOW', category: 'network' },
    'doNotTrack': { severity: 'LOW', category: 'privacy' },
    'productSub': { severity: 'MEDIUM', category: 'browser' },
    'vendor': { severity: 'MEDIUM', category: 'browser' },
    'vendorSub': { severity: 'MEDIUM', category: 'browser' },
    'oscpu': { severity: 'HIGH', category: 'system' },
    'buildID': { severity: 'HIGH', category: 'browser' }
  };
  
  // Properties to skip on file:// URLs to avoid warnings
  const isFileProtocol = window.location.protocol === 'file:';
  const skipPropsForFile = ['cookieEnabled', 'serviceWorker'];
  
  Object.keys(navigatorProps).forEach(prop => {
    try {
      // Skip problematic properties on file:// URLs
      if (isFileProtocol && skipPropsForFile.includes(prop)) {
        return;
      }
      
      // Check if property exists without triggering warnings
      if (navigator.hasOwnProperty(prop) || prop in navigator) {
        let originalValue;
        try {
          originalValue = navigator[prop];
        } catch (error) {
          // Skip properties that throw errors when accessed
          console.warn(`Skipping navigator.${prop} due to access error:`, error.message);
          return;
        }
        
        const propInfo = navigatorProps[prop];
        
        Object.defineProperty(navigator, prop, {
          get: function() {
            apiUsage.fingerprinting.push({
              property: prop,
              value: typeof originalValue === 'function' ? '[Function]' : originalValue,
              category: propInfo.category,
              severity: propInfo.severity,
              timestamp: Date.now(),
              stack: new Error().stack
            });

            console.log(`Navigator ${prop} accessed - fingerprinting detected!`);
            window.postMessage({
              type: 'surveillance-navigator-fingerprint',
              data: {
                property: prop,
                category: propInfo.category,
                severity: propInfo.severity,
                timestamp: Date.now()
              }
            }, '*');

            return originalValue;
          },
          configurable: true
        });
      }
    } catch (error) {
      console.warn(`Failed to hook navigator.${prop}:`, error.message);
    }
  });

  // Hook screen properties with detailed categorization
  const screenProps = {
    'width': { severity: 'HIGH', category: 'display' },
    'height': { severity: 'HIGH', category: 'display' },
    'availWidth': { severity: 'HIGH', category: 'display' },
    'availHeight': { severity: 'HIGH', category: 'display' },
    'colorDepth': { severity: 'HIGH', category: 'display' },
    'pixelDepth': { severity: 'HIGH', category: 'display' },
    'orientation': { severity: 'MEDIUM', category: 'display' }
  };
  
  Object.keys(screenProps).forEach(prop => {
    try {
      // Check if property exists safely
      if (screen.hasOwnProperty(prop) || prop in screen) {
        let originalValue;
        try {
          originalValue = screen[prop];
        } catch (error) {
          console.warn(`Skipping screen.${prop} due to access error:`, error.message);
          return;
        }
        
        const propInfo = screenProps[prop];
        
        Object.defineProperty(screen, prop, {
          get: function() {
            apiUsage.fingerprinting.push({
              property: `screen.${prop}`,
              value: originalValue,
              category: propInfo.category,
              severity: propInfo.severity,
              timestamp: Date.now(),
              stack: new Error().stack
            });

            window.postMessage({
              type: 'surveillance-screen-fingerprint',
              data: {
                property: prop,
                value: originalValue,
                category: propInfo.category,
                severity: propInfo.severity,
                timestamp: Date.now()
              }
            }, '*');

            return originalValue;
          },
          configurable: true
        });
      }
    } catch (error) {
      console.warn(`Failed to hook screen.${prop}:`, error.message);
    }
  });

  // Hook WebGL for fingerprinting detection
  if (window.WebGLRenderingContext && WebGLRenderingContext.prototype.getParameter) {
    try {
      const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(parameter) {
    const paramNames = {
      37445: 'UNMASKED_VENDOR_WEBGL',
      37446: 'UNMASKED_RENDERER_WEBGL',
      34047: 'MAX_TEXTURE_SIZE',
      34076: 'MAX_VIEWPORT_DIMS',
      35660: 'MAX_VERTEX_ATTRIBS',
      35661: 'MAX_VERTEX_UNIFORM_VECTORS',
      35379: 'MAX_VARYING_VECTORS',
      35657: 'MAX_VERTEX_TEXTURE_IMAGE_UNITS',
      35658: 'MAX_TEXTURE_IMAGE_UNITS',
      35659: 'MAX_FRAGMENT_UNIFORM_VECTORS',
      34921: 'MAX_CUBE_MAP_TEXTURE_SIZE'
    };
    
    const paramName = paramNames[parameter] || `PARAM_${parameter}`;
    const severity = (parameter === 37445 || parameter === 37446) ? 'HIGH' : 'MEDIUM';
    
    apiUsage.fingerprinting.push({
      property: `webgl.${paramName}`,
      parameter: parameter,
      severity: severity,
      timestamp: Date.now(),
      stack: new Error().stack
    });

    window.postMessage({
      type: 'surveillance-webgl-fingerprint',
      data: {
        parameter: parameter,
        paramName: paramName,
        severity: severity,
        timestamp: Date.now()
      }
    }, '*');

      return originalGetParameter.apply(this, arguments);
    };
    } catch (error) {
      console.warn('Failed to hook WebGL getParameter:', error.message);
    }
  }

  // Hook WebGL2 if available
  if (window.WebGL2RenderingContext && WebGL2RenderingContext.prototype.getParameter) {
    try {
    const originalGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(parameter) {
      window.postMessage({
        type: 'surveillance-webgl2-fingerprint',
        data: {
          parameter: parameter,
          timestamp: Date.now()
        }
      }, '*');

      return originalGetParameter2.apply(this, arguments);
    };
    } catch (error) {
      console.warn('Failed to hook WebGL2 getParameter:', error.message);
    }
  }

  // Hook audio context for audio fingerprinting
  if (window.AudioContext) {
    try {
      const originalAudioContext = window.AudioContext;
      window.AudioContext = function() {
        apiUsage.fingerprinting.push({
          property: 'AudioContext',
          severity: 'HIGH',
          category: 'audio',
          timestamp: Date.now(),
          stack: new Error().stack
        });

        window.postMessage({
          type: 'surveillance-audio-fingerprint',
          data: {
            method: 'AudioContext',
            severity: 'HIGH',
            timestamp: Date.now()
          }
        }, '*');

        return new originalAudioContext();
      };
    } catch (error) {
      console.warn('Failed to hook AudioContext:', error.message);
    }
  }

  // Hook performance timing APIs
  if (window.performance && performance.now) {
    try {
      const originalPerformanceNow = performance.now;
      performance.now = function() {
        // High-resolution timing can be used for fingerprinting
        apiUsage.fingerprinting.push({
          property: 'performance.now',
          severity: 'MEDIUM',
          category: 'timing',
          timestamp: Date.now(),
          stack: new Error().stack
        });

        // Only log if called frequently (potential fingerprinting)
        if (Math.random() < 0.1) { // Sample 10% of calls to avoid spam
          window.postMessage({
            type: 'surveillance-performance-fingerprint',
            data: {
              method: 'performance.now',
              severity: 'MEDIUM',
              timestamp: Date.now()
            }
          }, '*');
        }

        return originalPerformanceNow.apply(this, arguments);
      };
    } catch (error) {
      console.warn('Failed to hook performance.now:', error.message);
    }
  }

  // Hook MediaDevices API
  if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    try {
      const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices;
    navigator.mediaDevices.enumerateDevices = function() {
      apiUsage.fingerprinting.push({
        property: 'mediaDevices.enumerateDevices',
        severity: 'HIGH',
        category: 'media',
        timestamp: Date.now(),
        stack: new Error().stack
      });

      window.postMessage({
        type: 'surveillance-media-fingerprint',
        data: {
          method: 'enumerateDevices',
          severity: 'HIGH',
          timestamp: Date.now()
        }
      }, '*');

      return originalEnumerateDevices.apply(this, arguments);
    };
    } catch (error) {
      console.warn('Failed to hook MediaDevices.enumerateDevices:', error.message);
    }
  }

  // Hook font detection methods
  if (document.fonts && document.fonts.check) {
    try {
    const originalFontsCheck = document.fonts.check;
    document.fonts.check = function(font, text) {
      apiUsage.fingerprinting.push({
        property: 'fonts.check',
        font: font,
        severity: 'HIGH',
        category: 'fonts',
        timestamp: Date.now(),
        stack: new Error().stack
      });

      window.postMessage({
        type: 'surveillance-font-fingerprint',
        data: {
          method: 'fonts.check',
          font: font,
          severity: 'HIGH',
          timestamp: Date.now()
        }
      }, '*');

      return originalFontsCheck.apply(this, arguments);
    };
    } catch (error) {
      console.warn('Failed to hook document.fonts.check:', error.message);
    }
  }

  // Hook Date.getTimezoneOffset for timezone fingerprinting
  try {
  const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
  Date.prototype.getTimezoneOffset = function() {
    apiUsage.fingerprinting.push({
      property: 'Date.getTimezoneOffset',
      severity: 'MEDIUM',
      category: 'timezone',
      timestamp: Date.now(),
      stack: new Error().stack
    });

    window.postMessage({
      type: 'surveillance-timezone-fingerprint',
      data: {
        method: 'getTimezoneOffset',
        severity: 'MEDIUM',
        timestamp: Date.now()
      }
    }, '*');

    return originalGetTimezoneOffset.apply(this, arguments);
  };
  } catch (error) {
    console.warn('Failed to hook Date.getTimezoneOffset:', error.message);
  }

  // Export API usage data for debugging
  window.surveillanceAPIUsage = apiUsage;

  console.log('Corporate Surveillance Reverse-Engineering Tool: Injected script loaded');
  console.log('Available APIs hooked:', {
    fetch: !!window.fetch,
    XMLHttpRequest: !!window.XMLHttpRequest,
    HTMLCanvasElement: !!window.HTMLCanvasElement,
    navigator: !!window.navigator,
    screen: !!window.screen,
    WebGLRenderingContext: !!window.WebGLRenderingContext,
    AudioContext: !!(window.AudioContext || window.webkitAudioContext),
    performance: !!window.performance
  });

  // Advanced fingerprinting detection
  hookAdvancedFingerprinting();

  // Test the hooks after a short delay
  setTimeout(() => {
    console.log('Testing hooks...');
    console.log('Testing navigator.userAgent access...');
    const ua = navigator.userAgent;
    console.log('User agent retrieved:', ua.substring(0, 50) + '...');
    
    console.log('Testing screen.width access...');
    const width = screen.width;
    console.log('Screen width retrieved:', width);
  }, 500);

  // Advanced fingerprinting detection functions
  function hookAdvancedFingerprinting() {
    // CPU/GPU benchmarking detection
    hookPerformanceBenchmarking();
    
    // Battery level fingerprinting
    hookBatteryAPI();
    
    // Network connection fingerprinting
    hookNetworkConnection();
    
    // Device memory fingerprinting
    hookDeviceMemory();
    
    // Geolocation fingerprinting
    hookGeolocation();
    
    // Gamepad API fingerprinting
    hookGamepadAPI();
    
    // WebRTC fingerprinting
    hookWebRTC();
    
    // Clipboard API fingerprinting
    hookClipboardAPI();
    
    // Sensor APIs fingerprinting
    hookSensorAPIs();
  }

  function hookPerformanceBenchmarking() {
    // Hook performance.now() for timing attacks
    if (window.performance && performance.now) {
      try {
        const originalPerformanceNow = performance.now;
        performance.now = function() {
          window.postMessage({
            type: 'surveillance-performance-fingerprint',
            data: {
              category: 'cpu-benchmarking',
              severity: 'MEDIUM',
              method: 'performance.now',
              property: 'timing',
              timestamp: Date.now()
            }
          }, '*');
          return originalPerformanceNow.apply(this, arguments);
        };
      } catch (error) {
        console.warn('Failed to hook performance.now for benchmarking:', error.message);
      }
    }
    
    // Hook requestAnimationFrame for GPU benchmarking
    if (window.requestAnimationFrame) {
      try {
        const originalRAF = window.requestAnimationFrame;
        window.requestAnimationFrame = function(callback) {
          window.postMessage({
            type: 'surveillance-performance-fingerprint',
            data: {
              category: 'gpu-benchmarking',
              severity: 'HIGH',
              method: 'requestAnimationFrame',
              property: 'gpu-timing',
              timestamp: Date.now()
            }
          }, '*');
          return originalRAF.apply(this, arguments);
        };
      } catch (error) {
        console.warn('Failed to hook requestAnimationFrame for benchmarking:', error.message);
      }
    }
  }

  function hookBatteryAPI() {
    if (navigator.getBattery) {
      try {
        const originalGetBattery = navigator.getBattery;
        navigator.getBattery = function() {
          window.postMessage({
            type: 'surveillance-navigator-fingerprint',
            data: {
              category: 'hardware',
              severity: 'HIGH',
              method: 'getBattery',
              property: 'battery-level',
              timestamp: Date.now()
            }
          }, '*');
          return originalGetBattery.apply(this, arguments);
        };
      } catch (error) {
        console.warn('Failed to hook navigator.getBattery:', error.message);
      }
    }
  }

  function hookNetworkConnection() {
    if (navigator.connection) {
      try {
        const connection = navigator.connection;
        const originalEffectiveType = connection.effectiveType;
        
        Object.defineProperty(connection, 'effectiveType', {
          get: function() {
            window.postMessage({
              type: 'surveillance-navigator-fingerprint',
              data: {
                category: 'network',
                severity: 'MEDIUM',
                method: 'connection.effectiveType',
                property: 'network-speed',
                timestamp: Date.now()
              }
            }, '*');
            return originalEffectiveType;
          }
        });
      } catch (error) {
        console.warn('Failed to hook navigator.connection:', error.message);
      }
    }
  }

  function hookDeviceMemory() {
    if (navigator.deviceMemory !== undefined) {
      try {
        const originalDeviceMemory = navigator.deviceMemory;
        Object.defineProperty(navigator, 'deviceMemory', {
          get: function() {
            window.postMessage({
              type: 'surveillance-navigator-fingerprint',
              data: {
                category: 'hardware',
                severity: 'HIGH',
                method: 'navigator.deviceMemory',
                property: 'device-memory',
                timestamp: Date.now()
              }
            }, '*');
            return originalDeviceMemory;
          }
        });
      } catch (error) {
        console.warn('Failed to hook navigator.deviceMemory:', error.message);
      }
    }
  }

  function hookGeolocation() {
    if (navigator.geolocation && navigator.geolocation.getCurrentPosition) {
      try {
        const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition;
        navigator.geolocation.getCurrentPosition = function() {
          window.postMessage({
            type: 'surveillance-navigator-fingerprint',
            data: {
              category: 'location',
              severity: 'CRITICAL',
              method: 'geolocation.getCurrentPosition',
              property: 'location-data',
              timestamp: Date.now()
            }
          }, '*');
          return originalGetCurrentPosition.apply(this, arguments);
        };
      } catch (error) {
        console.warn('Failed to hook navigator.geolocation:', error.message);
      }
    }
  }

  function hookGamepadAPI() {
    if (navigator.getGamepads) {
      try {
        const originalGetGamepads = navigator.getGamepads;
        navigator.getGamepads = function() {
          window.postMessage({
            type: 'surveillance-navigator-fingerprint',
            data: {
              category: 'hardware',
              severity: 'MEDIUM',
              method: 'navigator.getGamepads',
              property: 'gamepad-list',
              timestamp: Date.now()
            }
          }, '*');
          return originalGetGamepads.apply(this, arguments);
        };
      } catch (error) {
        console.warn('Failed to hook navigator.getGamepads:', error.message);
      }
    }
  }

  function hookWebRTC() {
    if (window.RTCPeerConnection) {
      try {
        const originalRTCPC = window.RTCPeerConnection;
        window.RTCPeerConnection = function() {
          window.postMessage({
            type: 'surveillance-navigator-fingerprint',
            data: {
              category: 'network',
              severity: 'HIGH',
              method: 'RTCPeerConnection',
              property: 'webrtc-ips',
              timestamp: Date.now()
            }
          }, '*');
          return new originalRTCPC(...arguments);
        };
      } catch (error) {
        console.warn('Failed to hook RTCPeerConnection:', error.message);
      }
    }
  }

  function hookClipboardAPI() {
    if (navigator.clipboard && navigator.clipboard.readText) {
      try {
        const originalReadText = navigator.clipboard.readText;
        navigator.clipboard.readText = function() {
          window.postMessage({
            type: 'surveillance-navigator-fingerprint',
            data: {
              category: 'privacy',
              severity: 'CRITICAL',
              method: 'clipboard.readText',
              property: 'clipboard-content',
              timestamp: Date.now()
            }
          }, '*');
          return originalReadText.apply(this, arguments);
        };
      } catch (error) {
        console.warn('Failed to hook navigator.clipboard.readText:', error.message);
      }
    }
  }

  function hookSensorAPIs() {
    // Accelerometer
    if (window.Accelerometer) {
      try {
        const originalAccelerometer = window.Accelerometer;
        window.Accelerometer = function() {
          window.postMessage({
            type: 'surveillance-navigator-fingerprint',
            data: {
              category: 'sensors',
              severity: 'HIGH',
              method: 'Accelerometer',
              property: 'motion-data',
              timestamp: Date.now()
            }
          }, '*');
          return new originalAccelerometer(...arguments);
        };
      } catch (error) {
        console.warn('Failed to hook Accelerometer:', error.message);
      }
    }
    
    // Gyroscope
    if (window.Gyroscope) {
      try {
        const originalGyroscope = window.Gyroscope;
        window.Gyroscope = function() {
          window.postMessage({
            type: 'surveillance-navigator-fingerprint',
            data: {
              category: 'sensors',
              severity: 'HIGH',
              method: 'Gyroscope',
              property: 'motion-data',
              timestamp: Date.now()
            }
          }, '*');
          return new originalGyroscope(...arguments);
        };
      } catch (error) {
        console.warn('Failed to hook Gyroscope:', error.message);
      }
    }
  }
})(); 