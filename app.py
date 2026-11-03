from flask import Flask, render_template_string, request
import re
from urllib.parse import urlparse
import sys
from pathlib import Path

# Add model directory to path before importing the detector module
MODEL_DIR = Path(__file__).resolve().parent / 'model'
sys.path.insert(0, str(MODEL_DIR))

try:
    from detector import analyze_email as ml_analyze
    ML_MODEL_AVAILABLE = True
except Exception as e:
    print(f"ML model not loaded: {e}")
    ML_MODEL_AVAILABLE = False

app = Flask(__name__)

def analyze_email(content):
    """Analyze email content for phishing indicators using hybrid approach."""
    indicators = []
    risk_score = 0
    ml_result = None

    # Use ML model if available
    if ML_MODEL_AVAILABLE:
        try:
            # Extract subject (first line) and body
            lines = content.strip().split('\n', 1)
            subject = lines[0] if lines else ''
            body = lines[1] if len(lines) > 1 else content

            ml_result = ml_analyze(subject, body)

            # Add ML prediction as an indicator
            if ml_result['is_phishing']:
                risk_score += int(ml_result['confidence'] * 50)
                indicators.append((
                    "ML Model Prediction",
                    f"Phishing detected ({ml_result['risk_level']}, {ml_result['confidence']:.0%} confidence)",
                    "High" if ml_result['confidence'] > 0.8 else "Medium"
                ))
            else:
                indicators.append((
                    "ML Model Prediction",
                    f"Legitimate email ({ml_result['confidence']:.0%} confidence)",
                    "Low"
                ))
        except Exception as e:
            print(f"ML analysis error: {e}")

    # Rule-based analysis (backup and additional checks)

    # Check for urgent/threatening language
    urgent_patterns = [
        r'\b(urgent|immediate|asap|emergency)\b',
        r'\b(verify|confirm|suspended|locked)\b',
        r'\b(account|password|credentials)\b',
        r'\b(will be|must|required|deadline)\b',
        r'\b(click|act|respond)\s+(now|immediately|today)\b',
        r'\b(account has been suspended|account will be closed|payment overdue|unauthorized login attempt|security alert|privacy update required)\b',
        r'\b(verify your identity|confirm your details|update your payment|review your account)\b',
        r'\b(you have won|congratulations, you\'ve been selected|limited time offer|act now to avoid closure)\b',
    ]
    for pattern in urgent_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            indicators.append(("Urgent Language", re.search(pattern, content, re.IGNORECASE).group(), "Medium"))
            risk_score += 15

    # Check for suspicious URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, content)
    for url in urls:
        parsed = urlparse(url)
        # Check for IP addresses instead of domains
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            indicators.append(("IP Address URL", url, "High"))
            risk_score += 25
        # Check for suspicious TLDs
        if any(tld in parsed.netloc for tld in ['.xyz', '.top', '.club', '.work', '.date', '.bid', '.loan']):
            indicators.append(("Suspicious TLD", url, "Medium"))
            risk_score += 15
        # Check for excessive subdomains
        if parsed.netloc.count('.') > 2:
            indicators.append(("Excessive Subdomains", parsed.netloc, "Medium"))
            risk_score += 10

        # Check for brand impersonation URLs
        brand_tokens = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 'bankofamerica', 'chase', 'irs']
        official_domains = ['paypal.com', 'apple.com', 'google.com', 'microsoft.com', 'amazon.com', 'facebook.com', 'bankofamerica.com', 'chase.com', 'irs.gov']
        if any(token in parsed.netloc.lower() for token in brand_tokens) and not any(parsed.netloc.lower().endswith(d) for d in official_domains):
            indicators.append(("Brand Impersonation URL", url, "High"))
            risk_score += 25

    # Check for email address patterns
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, content)
    for email in emails:
        domain = email.split('@')[1] if '@' in email else ''
        # Check for mismatched sender domain
        if any(d in domain.lower() for d in ['gmail', 'yahoo', 'hotmail']) and any(kw in content.lower() for kw in ['bank', 'official', 'support', 'security']):
            indicators.append(("Free Email for Official Business", email, "High"))
            risk_score += 20

    # Check for generic greetings
    generic_greetings = [
        r'\b(dear (customer|user|member|sir|madam|valued))\b',
        r'\b(hello (there|user|customer))\b',
    ]
    for pattern in generic_greetings:
        if re.search(pattern, content, re.IGNORECASE):
            indicators.append(("Generic Greeting", re.search(pattern, content, re.IGNORECASE).group(), "Low"))
            risk_score += 10

    # Check for suspicious phishing phrases
    suspicious_phrases = [
        r'\b(click the link below|open the attachment|download the file|review the invoice|verify your identity|confirm your account|update your account)\b',
        r'\b(you have won|congratulations, you\'ve been selected|limited time offer|act now to avoid closure)\b',
        r'\b(unauthorized payment|failed login attempt|account access suspended|security alert)\b',
    ]
    for pattern in suspicious_phrases:
        if re.search(pattern, content, re.IGNORECASE):
            indicators.append(("Suspicious Phishing Phrase", re.search(pattern, content, re.IGNORECASE).group(), "High"))
            risk_score += 20

    # Check for attachment and invoice language
    attachment_patterns = [
        r'\b(attachment|attached|invoice|statement|receipt|document|download)\b'
    ]
    for pattern in attachment_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            indicators.append(("Attachment / Invoice Request", re.search(pattern, content, re.IGNORECASE).group(), "Medium"))
            risk_score += 10

    # Check for requests for sensitive information
    sensitive_requests = [
        r'\b(send|provide|enter|give)\s+(your\s+)?(password|credit\s*card|ssn|social\s*security)',
        r'\b(update|verify|confirm)\s+(your\s+)?(account|payment|billing)',
    ]
    for pattern in sensitive_requests:
        if re.search(pattern, content, re.IGNORECASE):
            indicators.append(("Request for Sensitive Info", pattern, "High"))
            risk_score += 30

    # Check for typosquatting
    typos = ['paypa1', 'gmai1', 'micros0ft', 'arnazon', 'facebok', 'app1e', 'amaozn']
    for typo in typos:
        if typo in content.lower():
            indicators.append(("Possible Typosquatting", typo, "High"))
            risk_score += 25

    # Normalize score to 0-100
    risk_score = min(100, risk_score)

    # Determine risk level
    if risk_score >= 70:
        risk_level = "HIGH - Likely Phishing"
        risk_color = "#dc3545"
    elif risk_score >= 40:
        risk_level = "MEDIUM - Suspicious"
        risk_color = "#ffc107"
    else:
        risk_level = "LOW - Probably Safe"
        risk_color = "#28a745"

    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'risk_color': risk_color,
        'indicators': indicators,
        'ml_prediction': ml_result
    }

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Email Detector</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            color: #fff;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        h1 {
            text-align: center;
            color: #00d9ff;
            margin-bottom: 10px;
        }
        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 30px;
        }
        .analyzer {
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        textarea {
            width: 100%;
            min-height: 200px;
            padding: 15px;
            border: 2px solid #444;
            border-radius: 10px;
            background: #1a1a2e;
            color: #fff;
            font-size: 14px;
            resize: vertical;
            box-sizing: border-box;
        }
        textarea::placeholder {
            color: #666;
        }
        button {
            width: 100%;
            padding: 15px;
            margin-top: 15px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(135deg, #00d9ff 0%, #0099cc 100%);
            color: #fff;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: scale(1.02);
        }
        .results {
            margin-top: 30px;
            padding: 20px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
        }
        .risk-summary {
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .risk-score {
            font-size: 48px;
            font-weight: bold;
        }
        .indicators-list {
            list-style: none;
            padding: 0;
        }
        .indicators-list li {
            padding: 12px;
            margin: 8px 0;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            border-left: 4px solid;
        }
        .indicator-name {
            font-weight: bold;
            color: #00d9ff;
        }
        .indicator-value {
            color: #aaa;
            font-size: 13px;
            word-break: break-all;
        }
        .severity {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .severity-high { background: #dc3545; }
        .severity-medium { background: #ffc107; color: #000; }
        .severity-low { background: #28a745; }
        .no-indicators {
            text-align: center;
            color: #28a745;
            padding: 20px;
        }
        .ml-badge {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .ml-badge strong {
            color: #00d9ff;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Phishing Email Detector</h1>
        <p class="subtitle">Powered by Machine Learning + Rule-Based Analysis</p>

        <form method="POST" class="analyzer">
            <textarea name="email_content" placeholder="Paste the email content here...

Include:
- Subject line
- Sender information
- Email body
- Any links or attachments mentioned">{{ email_content }}</textarea>
            <button type="submit">🔍 Analyze Email</button>
        </form>

        {% if result %}
        <div class="results">
            {% if result.ml_prediction %}
            <div class="ml-badge">
                <strong>🤖 ML Model Prediction:</strong>
                {{ '⚠️ PHISHING' if result.ml_prediction.is_phishing else '✅ LEGITIMATE' }}
                ({{ (result.ml_prediction.confidence * 100)|round(1) }}% confidence)
            </div>
            {% endif %}

            <div class="risk-summary" style="background: {{ result.risk_color }}22; border: 2px solid {{ result.risk_color }};">
                <div style="font-size: 18px; margin-bottom: 10px;">Risk Assessment</div>
                <div class="risk-score" style="color: {{ result.risk_color }};">{{ result.risk_score }}%</div>
                <div style="font-size: 24px; font-weight: bold; color: {{ result.risk_color }};">{{ result.risk_level }}</div>
            </div>

            <h3>Detected Indicators ({{ result.indicators|length }})</h3>
            {% if result.indicators %}
            <ul class="indicators-list">
                {% for indicator in result.indicators %}
                <li style="border-left-color: {{ indicator[2] == 'High' and '#dc3545' or indicator[2] == 'Medium' and '#ffc107' or '#28a745' }};">
                    <div class="indicator-name">{{ indicator[0] }}</div>
                    <div class="indicator-value">{{ indicator[1] }}</div>
                    <span class="severity severity-{{ indicator[2]|lower }}">{{ indicator[2] }}</span>
                </li>
                {% endfor %}
            </ul>
            {% else %}
            <div class="no-indicators">✓ No phishing indicators detected</div>
            {% endif %}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    email_content = ''
    result = None

    if request.method == 'POST':
        email_content = request.form.get('email_content', '')
        if email_content:
            result = analyze_email(email_content)

    return render_template_string(HTML_TEMPLATE, email_content=email_content, result=result)

if __name__ == '__main__':
    print("Starting Phishing Email Detector...")
    if ML_MODEL_AVAILABLE:
        print("✓ ML model loaded successfully")
    else:
        print("⚠ Running in rule-based mode only (ML model not available)")
    print("Open http://localhost:5001 in your browser")
    app.run(debug=True, host='0.0.0.0', port=5001)
