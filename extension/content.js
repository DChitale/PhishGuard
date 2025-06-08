// Content script to scan links on the page
document.addEventListener('mouseover', handleLinkHover, true);
document.addEventListener('click', handleLinkClick, true);

// Dictionary to store URL analysis results
const urlAnalysisCache = {};

function handleLinkHover(event) {
  const link = event.target.closest('a');
  if (!link || !link.href) return;

  checkLinkSafety(link.href).then(result => {
    if (result.threat_level === 'malicious') {
      showWarningTooltip(link, result);
    }
  });
}

function handleLinkClick(event) {
  const link = event.target.closest('a');
  if (!link || !link.href) return;

  checkLinkSafety(link.href).then(result => {
    if (result.threat_level === 'malicious') {
      event.preventDefault();
      showWarningPopup(link, result);
    }
  });
}

async function checkLinkSafety(url) {
  // Check cache first
  if (urlAnalysisCache[url]) {
    return urlAnalysisCache[url];
  }

  try {
    const response = await chrome.runtime.sendMessage({
      action: "scanUrl",
      url: url
    });

    if (response.error) {
      console.error('Error scanning URL:', response.error);
      return { threat_level: 'unknown', result: 'Error' };
    }

    // Cache the result
    urlAnalysisCache[url] = response;
    return response;
  } catch (error) {
    console.error('Error:', error);
    return { threat_level: 'unknown', result: 'Error' };
  }
}

function showWarningTooltip(element, result) {
  // Remove any existing tooltip
  const existingTooltip = document.getElementById('phishguard-tooltip');
  if (existingTooltip) existingTooltip.remove();

  const tooltip = document.createElement('div');
  tooltip.id = 'phishguard-tooltip';
  tooltip.innerHTML = `
    <div class="phishguard-tooltip-content">
      <strong>PhishGuard Warning</strong>
      <p>This link is ${result.threat_level} (${result.result})!</p>
      <p>${getWarningMessage(result)}</p>
    </div>
  `;

  // Style the tooltip
  tooltip.style.position = 'absolute';
  tooltip.style.zIndex = '9999';
  tooltip.style.backgroundColor = getBackgroundColor(result.threat_level);
  tooltip.style.color = 'white';
  tooltip.style.padding = '8px 12px';
  tooltip.style.borderRadius = '4px';
  tooltip.style.boxShadow = '0 2px 10px rgba(0,0,0,0.2)';
  tooltip.style.maxWidth = '300px';
  tooltip.style.fontSize = '14px';

  // Position the tooltip near the element
  const rect = element.getBoundingClientRect();
  tooltip.style.top = `${rect.bottom + window.scrollY + 5}px`;
  tooltip.style.left = `${rect.left + window.scrollX}px`;

  document.body.appendChild(tooltip);

  // Remove tooltip after delay
  setTimeout(() => {
    if (tooltip.parentNode) {
      tooltip.parentNode.removeChild(tooltip);
    }
  }, 5000);
}

function showWarningPopup(element, result) {
  const popup = document.createElement('div');
  popup.id = 'phishguard-popup';
  popup.innerHTML = `
    <div class="phishguard-popup-content">
      <h3>PhishGuard Warning</h3>
      <p>This link is ${result.threat_level} (${result.result})!</p>
      <p>${getWarningMessage(result)}</p>
      <div class="phishguard-buttons">
        <button id="phishguard-proceed">Proceed Anyway</button>
        <button id="phishguard-cancel">Go Back</button>
      </div>
    </div>
  `;

  // Style the popup
  popup.style.position = 'fixed';
  popup.style.top = '50%';
  popup.style.left = '50%';
  popup.style.transform = 'translate(-50%, -50%)';
  popup.style.zIndex = '9999';
  popup.style.backgroundColor = getBackgroundColor(result.threat_level);
  popup.style.color = 'white';
  popup.style.padding = '20px';
  popup.style.borderRadius = '8px';
  popup.style.boxShadow = '0 4px 20px rgba(0,0,0,0.3)';
  popup.style.maxWidth = '400px';
  popup.style.textAlign = 'center';

  // Add overlay
  const overlay = document.createElement('div');
  overlay.style.position = 'fixed';
  overlay.style.top = '0';
  overlay.style.left = '0';
  overlay.style.width = '100%';
  overlay.style.height = '100%';
  overlay.style.backgroundColor = 'rgba(0,0,0,0.7)';
  overlay.style.zIndex = '9998';

  document.body.appendChild(overlay);
  document.body.appendChild(popup);

  // Add event listeners to buttons
  document.getElementById('phishguard-proceed').addEventListener('click', () => {
    document.body.removeChild(overlay);
    document.body.removeChild(popup);
    window.location.href = element.href;
  });

  document.getElementById('phishguard-cancel').addEventListener('click', () => {
    document.body.removeChild(overlay);
    document.body.removeChild(popup);
  });
}

function getBackgroundColor(threatLevel) {
  switch (threatLevel) {
    case 'malicious': return '#dc3545';
    case 'suspicious': return '#ffc107';
    default: return '#6c757d';
  }
}

function getWarningMessage(result) {
  if (result.threat_level === 'malicious') {
    return 'This URL has been flagged as malicious by the scanning service.';
  }
  return 'This URL appears to be safe.';
}

// Function to scan all links on the page (called from popup)
// Function to scan all links on the page (called from popup)
async function scanAllLinks() {
  const links = Array.from(document.querySelectorAll('a[href]'));

  let maliciousCount = 0;
  let safeCount = 0;

  await Promise.all(
    links.map(async (link) => {
      const result = await checkLinkSafety(link.href);
      if (result.threat_level === 'malicious') {
        maliciousCount++;
        link.style.border = '2px solid red';
      } else {
        safeCount++;
      }
    })
  );

  return { total: links.length, malicious: maliciousCount, safe: safeCount };
}


// Expose functions to the popup
window.PhishGuard = {
  scanAllLinks,
  scanEmailContent: async (content) => {
    try {
      const response = await chrome.runtime.sendMessage({
        action: "scanEmail",
        content: content
      });
      return response;
    } catch (error) {
      console.error('Error scanning email:', error);
      return { error: error.message };
    }
  }
};