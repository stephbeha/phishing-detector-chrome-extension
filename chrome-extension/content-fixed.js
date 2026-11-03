// Phishing Email Detector - Gmail Integration

(function() {
  'use strict';

  // Phishing detection logic
  function analyzeEmail(content) {
    const indicators = [];
    let riskScore = 0;

    // Urgent/threatening language patterns
    const urgentPatterns = [
      { pattern: /\b(urgent|immediate|asap|emergency)\b/i, name: "Urgent Language", severity: "Medium" },
      { pattern: /\b(verify|confirm|suspended|locked)\b/i, name: "Account Threat Language", severity: "Medium" },
      { pattern: /\b(account|password|credentials)\b/i, name: "Credential Focus", severity: "Medium" },
      { pattern: /\b(will be|must|required|deadline)\b/i, name: "Coercive Language", severity: "Medium" },
      { pattern: /\b(click|act|respond)\s+(now|immediately|today)\b/i, name: "Urgent Action Required", severity: "High" },
      { pattern: /\b(account has been suspended|account will be closed|payment overdue|unauthorized login attempt|security alert|privacy update required)\b/i, name: "Account Threat Phrase", severity: "Medium" },
      { pattern: /\b(verify your identity|confirm your details|update your payment|review your account)\b/i, name: "Verification Request", severity: "Medium" },
      { pattern: /\b(you have won|congratulations, you've been selected|limited time offer|act now to avoid closure)\b/i, name: "Prize / Offer Language", severity: "High" },
    ];

    for (const { pattern, name, severity } of urgentPatterns) {
      const match = content.match(pattern);
      if (match) {
        indicators.push({ name, value: match[0], severity });
        riskScore += severity === "High" ? 15 : 10;
      }
    }

    // Suspicious phishing phrases
    const suspiciousPhrases = [
      { pattern: /\b(click the link below|open the attachment|download the file|review the invoice|verify your identity|confirm your account|update your account)\b/i, name: "Suspicious Phishing Phrase", severity: "High" },
      { pattern: /\b(you have won|congratulations, you've been selected|limited time offer|act now to avoid closure)\b/i, name: "Urgent Offer", severity: "High" },
      { pattern: /\b(unauthorized payment|failed login attempt|account access suspended|security alert)\b/i, name: "Security Alert Phrase", severity: "High" },
    ];

    for (const { pattern, name, severity } of suspiciousPhrases) {
      const match = content.match(pattern);
      if (match) {
        indicators.push({ name, value: match[0], severity });
        riskScore += 20;
      }
    }

    // Check URLs
    const urlPattern = /https?:\/\/[^\s'"<>]+/g;
    const urls = content.match(urlPattern) || [];

    for (const url of urls) {
      try {
        const urlObj = new URL(url);

        if (/^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname)) {
          indicators.push({ name: "IP Address URL", value: url, severity: "High" });
          riskScore += 25;
        }

        const suspiciousTlds = ['.xyz', '.top', '.club', '.work', '.date', '.bid', '.loan'];
        if (suspiciousTlds.some(tld => urlObj.hostname.endsWith(tld))) {
          indicators.push({ name: "Suspicious TLD", value: url, severity: "Medium" });
          riskScore += 15;
        }

        const parts = urlObj.hostname.split('.');
        if (parts.length > 3) {
          indicators.push({ name: "Excessive Subdomains", value: urlObj.hostname, severity: "Medium" });
          riskScore += 10;
        }

        const brandTokens = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 'bankofamerica', 'chase', 'irs'];
        const officialDomains = ['paypal.com', 'apple.com', 'google.com', 'microsoft.com', 'amazon.com', 'facebook.com', 'bankofamerica.com', 'chase.com', 'irs.gov'];
        if (brandTokens.some(token => urlObj.hostname.toLowerCase().includes(token)) && !officialDomains.some(domain => urlObj.hostname.toLowerCase().endsWith(domain))) {
          indicators.push({ name: "Brand Impersonation URL", value: url, severity: "High" });
          riskScore += 25;
        }
      } catch (e) {}
    }

    // Check email addresses
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const emails = content.match(emailPattern) || [];
    const popularDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    const officialKeywords = ['bank', 'official', 'support', 'security', 'verify', 'account'];

    for (const email of emails) {
      const domain = email.split('@')[1]?.toLowerCase();
      const isFreeEmail = popularDomains.includes(domain);
      const hasOfficialContext = officialKeywords.some(kw => content.toLowerCase().includes(kw));

      if (isFreeEmail && hasOfficialContext) {
        indicators.push({ name: "Free Email for Official Business", value: email, severity: "High" });
        riskScore += 20;
      }
    }

    // Generic greetings
    const genericGreetings = [
      /\bdear (customer|user|member|sir|madam|valued)\b/i,
      /\bhello (there|user|customer)\b/i,
    ];

    for (const pattern of genericGreetings) {
      const match = content.match(pattern);
      if (match) {
        indicators.push({ name: "Generic Greeting", value: match[0], severity: "Low" });
        riskScore += 10;
      }
    }

    // Attachment / invoice language
    const attachmentPatterns = [
      { pattern: /\b(attachment|attached|invoice|statement|receipt|document|download)\b/i, name: "Attachment / Invoice Request", severity: "Medium" },
    ];
    for (const { pattern, name, severity } of attachmentPatterns) {
      const match = content.match(pattern);
      if (match) {
        indicators.push({ name, value: match[0], severity });
        riskScore += 10;
      }
    }

    // Requests for sensitive info
    const sensitivePatterns = [
      /\b(send|provide|enter|give)\s+(your\s+)?(password|credit\s*card|ssn|social\s*security)/i,
      /\b(update|verify|confirm)\s+(your\s+)?(account|payment|billing)/i,
    ];

    for (const pattern of sensitivePatterns) {
      const match = content.match(pattern);
      if (match) {
        indicators.push({ name: "Request for Sensitive Info", value: match[0], severity: "High" });
        riskScore += 30;
      }
    }

    // Common typosquatting
    const typos = ['paypa1', 'gmai1', 'micros0ft', 'arnazon', 'facebok', 'app1e', 'amaozn'];
    for (const typo of typos) {
      if (content.toLowerCase().includes(typo)) {
        indicators.push({ name: "Possible Typosquatting", value: typo, severity: "High" });
        riskScore += 25;
      }
    }

    // Normalize score
    riskScore = Math.min(100, riskScore);

    let riskLevel, riskColor;
    if (riskScore >= 70) {
      riskLevel = "HIGH RISK";
      riskColor = "#dc3545";
    } else if (riskScore >= 40) {
      riskLevel = "SUSPICIOUS";
      riskColor = "#ffc107";
    } else {
      riskLevel = "LIKELY SAFE";
      riskColor = "#28a745";
    }

    return { riskScore, riskLevel, riskColor, indicators };
  }

  // Create classification badge
  function createBadge(result) {
    const badge = document.createElement('div');
    badge.className = 'phishing-detector-badge';
    badge.innerHTML = `
      <div class="pd-badge-header">
        <span class="pd-status" style="color: ${result.riskColor}">${result.riskLevel}</span>
        <span class="pd-score">Score: ${result.riskScore}</span>
      </div>
      ${result.indicators.length > 0 ? `
        <div class="pd-indicators">
          <div class="pd-indicator-title">Alert: ${result.indicators.length} indicator(s) detected:</div>
          <ul class="pd-indicator-list">
            ${result.indicators.map(ind => `
              <li class="pd-indicator-item pd-${ind.severity.toLowerCase()}">
                <span class="pd-indicator-name">${ind.name}</span>
                <span class="pd-severity pd-sev-${ind.severity.toLowerCase()}">${ind.severity}</span>
              </li>
            `).join('')}
          </ul>
        </div>
      ` : '<div class="pd-safe">No phishing indicators detected</div>'}
      <button class="pd-dismiss" onclick="this.closest('.phishing-detector-badge').remove()">Close</button>
    `;
    return badge;
  }

  // Inject styles
  function injectStyles() {
    if (document.getElementById('phishing-detector-styles')) return;

    const style = document.createElement('style');
    style.id = 'phishing-detector-styles';
    style.textContent = `
      .phishing-detector-badge {
        position: fixed !important;
        top: 80px !important;
        right: 20px !important;
        max-width: 350px !important;
        min-width: 280px !important;
        background: #1a1a2e !important;
        border: 2px solid #444 !important;
        border-radius: 12px !important;
        padding: 15px !important;
        z-index: 999999 !important;
        font-family: 'Segoe UI', Arial, sans-serif !important;
        font-size: 13px !important;
        box-shadow: 0 8px 32px rgba(0,0,0,0.4) !important;
        animation: pd-slide-in 0.3s ease !important;
        color: #fff !important;
        line-height: 1.4 !important;
      }
      @keyframes pd-slide-in {
        from { transform: translateX(100px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      .pd-badge-header {
        display: flex !important;
        align-items: center !important;
        gap: 10px !important;
        margin-bottom: 10px !important;
        padding-bottom: 10px !important;
        border-bottom: 1px solid #333 !important;
      }
      .pd-icon { font-size: 20px !important; }
      .pd-status { font-weight: bold !important; font-size: 16px !important; flex: 1 !important; }
      .pd-score { background: #333 !important; padding: 4px 8px !important; border-radius: 6px !important; font-weight: bold !important; }
      .pd-indicators { color: #ccc !important; margin-top: 10px !important; }
      .pd-indicator-title { font-weight: bold !important; margin-bottom: 8px !important; color: #ff9800 !important; font-size: 12px !important; }
      .pd-indicator-list {
        list-style: none !important;
        padding: 0 !important;
        margin: 0 !important;
        max-height: 200px !important;
        overflow-y: auto !important;
      }
      .pd-indicator-item {
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
        padding: 6px 8px !important;
        margin: 4px 0 !important;
        background: rgba(255,255,255,0.05) !important;
        border-radius: 6px !important;
        border-left: 3px solid !important;
        gap: 8px !important;
      }
      .pd-indicator-item.pd-high { border-left-color: #dc3545 !important; }
      .pd-indicator-item.pd-medium { border-left-color: #ffc107 !important; }
      .pd-indicator-item.pd-low { border-left-color: #28a745 !important; }
      .pd-indicator-name { flex: 1 !important; word-break: break-word !important; }
      .pd-severity {
        font-size: 9px !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
        font-weight: bold !important;
        text-transform: uppercase !important;
        white-space: nowrap !important;
      }
      .pd-sev-high { background: #dc3545 !important; color: #fff !important; }
      .pd-sev-medium { background: #ffc107 !important; color: #000 !important; }
      .pd-sev-low { background: #28a745 !important; color: #fff !important; }
      .pd-safe {
        text-align: center !important;
        color: #28a745 !important;
        padding: 15px !important;
        font-weight: bold !important;
        font-size: 14px !important;
      }
      .pd-dismiss {
        position: absolute !important;
        top: 8px !important;
        right: 8px !important;
        background: rgba(255,255,255,0.1) !important;
        border: none !important;
        border-radius: 4px !important;
        color: #aaa !important;
        cursor: pointer !important;
        font-size: 14px !important;
        padding: 4px 8px !important;
        line-height: 1 !important;
        transition: all 0.2s !important;
      }
      .pd-dismiss:hover { background: rgba(255,255,255,0.2) !important; color: #fff !important; }
      .pd-error {
        text-align: center !important;
        color: #ff6b6b !important;
        padding: 15px !important;
      }
    `;
    document.head.appendChild(style);
  }

  // Analyze email content
  function analyzeCurrentEmail() {
    try {
      // Try to find email content in Gmail
      const emailSelectors = [
        '.a3s.aiL',           // Gmail message body
        '[role="article"]',   // Article role for email
        '.msg',               // Message container
        'div[aria-label="Message body"]',
        '.nH.h0',             // Gmail conversation view
      ];

      let emailContent = '';
      for (const selector of emailSelectors) {
        const element = document.querySelector(selector);
        if (element) {
          emailContent = element.innerText || element.textContent || '';
          break;
        }
      }

      // Also check for email headers (subject/sender)
      const headerSelectors = ['.hP', '.nH.hL', 'h2[h1]'];
      for (const selector of headerSelectors) {
        const element = document.querySelector(selector);
        if (element) {
          emailContent = element.innerText + ' ' + emailContent;
          break;
        }
      }

      document.querySelectorAll('.phishing-detector-badge').forEach(b => b.remove());

      if (!emailContent || emailContent.trim().length < 50) {
        return;
      }

      const result = analyzeEmail(emailContent);
      if (result.riskScore >= 40) {
        const badge = createBadge(result);
        document.body.appendChild(badge);
      }

      try {
        chrome.storage.local.set({ lastAnalysis: result });
      } catch (e) {
        console.log('[Phishing Detector] Storage not available:', e);
      }
    } catch (e) {
      console.error('[Phishing Detector] Error analyzing email:', e);
    }
  }

  let initialized = false;

  function init() {
    if (initialized) return;
    initialized = true;

    injectStyles();
    setTimeout(analyzeCurrentEmail, 2000);

    const observer = new MutationObserver(() => {
      setTimeout(analyzeCurrentEmail, 1000);
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['class', 'style']
    });
  }

  if (document.readyState === 'complete') {
    init();
  } else {
    window.addEventListener('load', init);
  }
})();
