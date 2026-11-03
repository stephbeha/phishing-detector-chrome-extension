# Phishing Detector

A hybrid phishing detection application that combines a Flask web interface, a Python machine learning model, and a Gmail Chrome extension.

## Overview

This project detects phishing indicators in email content using both:
- a rule-based analyzer for common phishing patterns,
- a trained ML model for content classification.

It includes:
- `app.py`: Flask app for manual email content analysis,
- `model/detector.py`: ML inference module using `phishing_model.pkl` and `vectorizer.pkl`,
- `model/train.py`: training utilities and dataset handling,
- `chrome-extension/`: Gmail extension UI and content scripts.

## Features

- Web-based phishing email scanner
- ML-powered prediction with confidence and risk level
- Heuristic detection of:
  - urgent language,
  - suspicious URLs,
  - credential requests,
  - generic greetings,
  - typosquatting,
  - free email use in official contexts.
- Chrome extension injects Gmail warnings and stores analysis results.

## Standard Rules for Email Safety

Follow these rules when reading emails:

- Do not click links from unknown or unexpected senders.
- Verify the sender address carefully, especially for official-looking emails.
- Hover over links to confirm the destination URL before clicking.
- Avoid opening attachments from untrusted sources.
- Do not provide passwords, credit card numbers, or personal data via email.
- Be cautious of urgent or threatening language requesting immediate action.
- Look for spelling, grammar, and branding inconsistencies.
- When in doubt, contact the organization directly using a known phone number or website.

## Installation

### 1. Clone the repository

```bash
cd c:/Users/ASUS/Desktop
git clone <your-repo-url> phishing-detector
cd phishing-detector
```

### 2. Create and activate a Python environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Verify model files

The ML inference module requires:
- `model/phishing_model.pkl`
- `model/vectorizer.pkl`

These files are included in the `model/` directory.

## Run the Flask app

Start the application:

```powershell
python app.py
```

Then open your browser at:

```text
http://127.0.0.1:5000/
```

## Using the app

1. Paste or type email text into the analyzer box.
2. Click **Analyze Email**.
3. View the computed risk score and detected phishing indicators.

## Install the Chrome extension

1. Open Chrome and go to `chrome://extensions/`.
2. Enable **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select the `chrome-extension/` folder.
5. Open Gmail and allow the extension to run.

The extension will:
- scan Gmail content for phishing indicators,
- display a badge with risk score and level,
- show detected indicators in the popup.

### Extension phishing detection rules

The Gmail extension detects phishing using the following rules:
- urgent or threatening language such as "verify", "suspended", "locked", and "act now"
- suspicious URLs, including IP-based links, unusual top-level domains, and excessive subdomains
- free email addresses used for official business or security-related messages
- generic greetings like "Dear customer" or "Hello user"
- requests for sensitive information, including passwords, credit card details, or account verification
- typosquatting and misspelled brand names such as "paypa1", "gmai1", or "micros0ft"

### App phishing detection rules

The Flask app uses the same core heuristics and also combines them with ML model predictions:
- urgent or threatening language and account verification requests
- suspicious links and domain anomalies
- free email addresses in messages that appear to be from official organizations
- generic greetings and impersonation indicators
- requests for sensitive personal or financial data
- typosquatting patterns and misspelled service names
- ML-based classification of email subject and body text to improve detection accuracy

## Project structure

```text
phishing-detector/
├── app.py
├── requirements.txt
├── README.md
├── chrome-extension/
│   ├── content.js
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── styles.css
│   └── icons...
└── model/
    ├── detector.py
    ├── phishing_model.pkl
    ├── vectorizer.pkl
    ├── train.py
    ├── datasets/
    │   └── synthetic_phishing.csv
    └── model_info.json
```

## Notes

- If the ML model fails to load, `app.py` falls back to the rule-based analyzer.
- The extension is designed for Gmail pages only and uses `chrome.storage.local` to save the last analysis result.

## Optional: Re-train the model

If you want to retrain the model from scratch:

```powershell
python model/train.py
```

Then update the saved artifacts in the `model/` folder as needed.

## Contact

For improvements or bug reports, update this README or the project files with clearer detection rules and extension behavior.
