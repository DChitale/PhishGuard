document.addEventListener('DOMContentLoaded', function() {
    const scanPageButton = document.getElementById('scanPage');
    const scanClipboardButton = document.getElementById('scanClipboard');
    const scanResults = document.getElementById('scanResults');
    const emailResults = document.getElementById('emailResults');
    const totalLinks = document.getElementById('totalLinks');
    const maliciousLinks = document.getElementById('maliciousLinks');
    const safeLinks = document.getElementById('safeLinks');
    const emailAnalysisContent = document.getElementById('emailAnalysisContent');
    
    scanPageButton.addEventListener('click', async () => {
      await scanPage();
    });
    
    scanClipboardButton.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          await scanEmailContent(text);
        } else {
          alert('No text found in clipboard');
        }
      } catch (error) {
        console.error('Error reading clipboard:', error);
        alert('Could not read clipboard contents. Make sure you have clipboard permissions.');
      }
    });
    
    async function scanPage() {
      scanPageButton.disabled = true;
      scanPageButton.textContent = 'Scanning...';
      scanPageButton.classList.add('opacity-50');
      scanResults.classList.add('hidden');
      
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            return window.PhishGuard ? window.PhishGuard.scanAllLinks() : null;
          }
        });
        
        if (results && results[0] && results[0].result) {
          const { total, malicious, safe } = results[0].result;
          
          totalLinks.textContent = total;
          maliciousLinks.textContent = malicious;
          safeLinks.textContent = safe;
          
          scanResults.classList.remove('hidden');
          
          if (malicious > 0) {
            chrome.notifications.create({
              type: 'basic',
              iconUrl: chrome.runtime.getURL('icons/icon-48.png'),
              title: 'PhishGuard Alert',
              message: `Found ${malicious} malicious links on this page.`
            });
          }
        } else {
          alert('Unable to scan this page. Try refreshing and scanning again.');
        }
      } catch (error) {
        console.error('Error scanning page:', error);
        alert('Error scanning page. Make sure you have permission to scan this page.');
      } finally {
        scanPageButton.disabled = false;
        scanPageButton.textContent = 'Scan Current Page';
        scanPageButton.classList.remove('opacity-50');
      }
    }
    
    async function scanEmailContent(content) {
      scanClipboardButton.disabled = true;
      scanClipboardButton.textContent = 'Analyzing...';
      scanClipboardButton.classList.add('opacity-50');
      emailResults.classList.add('hidden');
      
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        const result = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: (content) => {
            return window.PhishGuard ? window.PhishGuard.scanEmailContent(content) : null;
          },
          args: [content]
        });
        
        if (result && result[0] && result[0].result) {
          const analysis = result[0].result;
          displayEmailAnalysis(analysis);
          emailResults.classList.remove('hidden');
        } else {
          alert('Unable to analyze email content.');
        }
      } catch (error) {
        console.error('Error analyzing email:', error);
        alert('Error analyzing email content.');
      } finally {
        scanClipboardButton.disabled = false;
        scanClipboardButton.textContent = 'Scan Clipboard Content';
        scanClipboardButton.classList.remove('opacity-50');
      }
    }
    
    function displayEmailAnalysis(analysis) {
      let html = '';
      
      if (analysis.safe === false) {
        html += `<div class="p-2 mb-2 bg-red-100 text-red-800 rounded">
          <strong>Warning:</strong> ${analysis.recommendation}
        </div>`;
      } else {
        html += `<div class="p-2 mb-2 bg-green-100 text-green-800 rounded">
          ${analysis.recommendation}
        </div>`;
      }
      
      if (analysis.url_scan && Object.keys(analysis.url_scan).length > 0) {
        html += `<div class="mb-3">
          <h4 class="font-medium mb-1">URL Scan Results:</h4>
          <ul class="text-xs space-y-1">`;
        
        for (const [url, result] of Object.entries(analysis.url_scan)) {
          const isUnsafe = result === 'UNSAFE';
          html += `<li class="${isUnsafe ? 'text-red-600' : 'text-green-600'}">
            ${url.substring(0, 50)}... - <strong>${result}</strong>
          </li>`;
        }
        
        html += `</ul></div>`;
      }
      
      if (analysis.content_analysis) {
        const ca = analysis.content_analysis;
        html += `<div class="mb-3">
          <h4 class="font-medium mb-1">Content Analysis:</h4>
          <div class="text-xs space-y-2">`;
        
        if (ca.suspicious_phrases.length > 0) {
          html += `<div>
            <p>Suspicious phrases found (${ca.suspicious_phrases.length}):</p>
            <ul class="list-disc pl-4">`;
          ca.suspicious_phrases.forEach(phrase => {
            html += `<li>${phrase}</li>`;
          });
          html += `</ul></div>`;
        }
        
        if (ca.urgency_indicators > 0) {
          html += `<p>Urgency indicators: ${ca.urgency_indicators}</p>`;
        }
        
        if (ca.grammar_issues > 0) {
          html += `<p>Grammar issues: ${ca.grammar_issues}</p>`;
        }
        
        html += `</div></div>`;
      }
      
      emailAnalysisContent.innerHTML = html;
    }
  });