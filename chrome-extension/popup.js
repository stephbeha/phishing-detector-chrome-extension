document.addEventListener('DOMContentLoaded', function() {
  const contentDiv = document.getElementById('content');

  // Check if chrome.storage is available
  if (!chrome || !chrome.storage) {
    contentDiv.innerHTML = `
      <div class="error" style="color: #ff6b6b; text-align: center; padding: 20px;">
        Extension error: Storage API not available<br>
        <small>Try reloading the extension</small>
      </div>
    `;
    return;
  }

  chrome.storage.local.get(['lastAnalysis'], function(result) {
    if (chrome.runtime.lastError) {
      contentDiv.innerHTML = `
        <div class="error" style="color: #ff6b6b; text-align: center; padding: 20px;">
            Error loading analysis<br>
      return;
    }

    if (result.lastAnalysis) {
      const analysis = result.lastAnalysis;

      let html = `
        <div class="status" style="border: 2px solid ${analysis.riskColor}">
          <div class="status-score" style="color: ${analysis.riskColor}">Score: ${analysis.riskScore}</div>
          <div class="status-text" style="color: ${analysis.riskColor}">${analysis.riskLevel}</div>
        </div>
      `;

      if (analysis.indicators && analysis.indicators.length > 0) {
        html += '<div class="indicators">';
        html += '<div style="color: #ff9800; margin-bottom: 8px;">Alert: ' + analysis.indicators.length + ' indicator(s) detected:</div>';

        for (const ind of analysis.indicators) {
          html += `
            <div class="indicator ${ind.severity.toLowerCase()}">
              <span class="indicator-name">${ind.name}</span>
              <span class="indicator-severity sev-${ind.severity.toLowerCase()}">${ind.severity}</span>
              <div style="color: #888; font-size: 11px; margin-top: 4px; word-break: break-all;">${ind.value || ''}</div>
            </div>
          `;
        }

        html += '</div>';
      } else {
        html += '<div class="no-data" style="color: #28a745; font-weight: bold;">No phishing indicators detected</div>';
      }

      contentDiv.innerHTML = html;
    } else {
      contentDiv.innerHTML = `
        <div class="no-data">
          Open an email in Gmail to analyze it<br><br>
          <small>The extension will automatically detect phishing attempts</small>
        </div>
      `;
    }
  });
});
