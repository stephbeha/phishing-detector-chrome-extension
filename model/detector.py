"""
Phishing Detection Model Module
Auto-generated trained model
"""

import joblib
from pathlib import Path

MODEL_DIR = Path(__file__).parent

# Load model and vectorizer
_model = None
_vectorizer = None

def load_model():
    global _model, _vectorizer
    if _model is None:
        _model = joblib.load(MODEL_DIR / 'phishing_model.pkl')
        _vectorizer = joblib.load(MODEL_DIR / 'vectorizer.pkl')
    return _model, _vectorizer

def predict(text):
    """
    Predict if text is phishing (1) or legitimate (0)
    Returns: (prediction, confidence)
    """
    model, vectorizer = load_model()

    # Transform text
    X = vectorizer.transform([text.lower()])

    # Get prediction and probability
    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    confidence = float(probabilities[prediction])

    return int(prediction), confidence

def analyze_email(subject, body):
    """
    Analyze email for phishing
    Returns dict with prediction, confidence, and risk level
    """
    text = f"{subject} {body}"
    prediction, confidence = predict(text)

    if prediction == 1:
        if confidence >= 0.8:
            risk_level = "HIGH"
        elif confidence >= 0.6:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        'is_phishing': bool(prediction),
        'confidence': confidence,
        'risk_level': risk_level,
        'phishing_probability': float(confidence) if prediction == 1 else float(1 - confidence)
    }

if __name__ == '__main__':
    # Test the model
    test_emails = [
        ("URGENT: Verify Account", "Click here immediately to confirm your password"),
        ("Meeting tomorrow", "Hi team, reminder about our meeting at 3pm"),
    ]

    for subject, body in test_emails:
        result = analyze_email(subject, body)
        print(f"Subject: {subject}")
        print(f"Result: {result}")
        print()
