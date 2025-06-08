// Background service worker for the extension
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.sync.set({ 
      backendUrl: 'http://localhost:8000',
      scanEmailContent: true 
    });
  });
  
  // Listen for messages from content script
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scanUrl") {
      scanUrlWithBackend(request.url)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ error: error.message }));
      return true;
    }
    
    if (request.action === "scanEmail") {
      scanEmailWithBackend(request.content)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ error: error.message }));
      return true;
    }
  });
  
  async function scanUrlWithBackend(url) {
    const { backendUrl } = await chrome.storage.sync.get('backendUrl');
    
    try {
      const response = await fetch(`${backendUrl}/scan-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message: url })
      });
      
      if (!response.ok) {
        throw new Error(`Backend error: ${response.status}`);
      }
      
      const data = await response.json();
      return {
        url: data.url,
        threat_level: data.threat_level,
        result: data.result
      };
    } catch (error) {
      console.error('Error scanning URL:', error);
      throw error;
    }
  }
  
  async function scanEmailWithBackend(content) {
    const { backendUrl, scanEmailContent } = await chrome.storage.sync.get(['backendUrl', 'scanEmailContent']);
    
    try {
      const response = await fetch(`${backendUrl}/scan_email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          message: content,
          analyze_content: scanEmailContent
        })
      });
      
      if (!response.ok) {
        throw new Error(`Backend error: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error scanning email:', error);
      throw error;
    }
  }