"""
Phishing Email Detector - Model Training Script
Downloads dataset and trains a machine learning classifier

First run: pip install scikit-learn pandas numpy joblib
"""

import os
import sys
import json
import pickle
import urllib.request
import zipfile
from pathlib import Path

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

# Dataset paths
DATASET_DIR = Path(__file__).parent / 'datasets'
MODEL_DIR = Path(__file__).parent

def download_kaggle_phishing_dataset():
    """Download phishing email dataset from Kaggle"""
    print("\n" + "="*50)
    print("Downloading Phishing Email Dataset...")
    print("="*50)

    DATASET_DIR.mkdir(exist_ok=True)

    # Using the Phishing Email Detection dataset
    # Alternative: Create synthetic dataset if download fails
    try:
        # Try to download from a public source
        url = "https://raw.githubusercontent.com/njiramba/Phishing-Detection/master/Phishing_Legitimate_full.csv"
        output_path = DATASET_DIR / 'phishing_data.csv'

        print(f"Downloading from: {url}")
        urllib.request.urlretrieve(url, output_path)
        print(f"Downloaded to: {output_path}")
        return output_path
    except Exception as e:
        print(f"Download failed: {e}")
        print("Creating synthetic dataset instead...")
        return create_synthetic_dataset()

def create_synthetic_dataset():
    """Create a synthetic phishing detection dataset"""
    print("Generating synthetic phishing dataset...")

    # Phishing email characteristics
    phishing_subjects = [
        "URGENT: Verify Your Account Now",
        "Your account has been suspended",
        "Immediate Action Required",
        "Confirm Your Password",
        "You have won $1,000,000",
        "Security Alert - Login Detected",
        "Update Your Payment Information",
        "Dear Customer, Verify Now",
        "Your PayPal Account Is Limited",
        "Amazon Order Confirmation #FAKE",
        "Microsoft Security Alert",
        "Apple ID Locked - Unlock Now",
        "Bank Account Verification Needed",
        "Tax Refund Pending - Claim Now",
        "Employment Opportunity - Apply Now",
    ]

    phishing_bodies = [
        "Dear Customer, Your account has been suspended. Click here immediately to verify your credentials.",
        "URGENT: We detected suspicious activity. You must confirm your password now or your account will be locked.",
        "Congratulations! You have been selected to receive $1,000,000. Send your bank details to claim.",
        "Your PayPal account has been limited. Please update your billing information to restore access.",
        "We noticed a login from an unknown device. Verify your identity immediately at the link below.",
        "Dear valued customer, Your bank account requires verification. Provide your SSN and account number.",
        "Amazon order #12345 has been placed. If this wasn't you, click here to cancel and receive a refund.",
        "Microsoft detected unusual activity. Enter your credentials to secure your account.",
        "Your Apple ID has been locked for security reasons. Unlock now to avoid permanent suspension.",
        "IRS: You are eligible for a tax refund of $3,500. Click to claim before deadline.",
        "Employment offer: Work from home, earn $5000/week. No experience needed. Reply with your details.",
        "Your credit card will be charged $999. Cancel subscription here if unwanted.",
        "Security breach detected. Change your password immediately using this link.",
        "Hello there, We need to verify your account. Please send your login credentials.",
        "Final notice: Your account will be terminated unless you respond within 24 hours.",
    ]

    legitimate_subjects = [
        "Meeting tomorrow at 3pm",
        "Re: Project update",
        "Weekly team sync",
        "Lunch plans?",
        "Document review needed",
        "Q4 Budget Discussion",
        "Happy Birthday!",
        "Vacation request",
        "Office supplies order",
        "Training session next week",
        "Code review feedback",
        "Sprint planning meeting",
        "Out of office: Dec 20-27",
        "Welcome to the team!",
        "Conference room booking",
    ]

    legitimate_bodies = [
        "Hi team, Just a reminder about our meeting tomorrow at 3pm in conference room B.",
        "Thanks for sending this over. I've reviewed the document and have a few suggestions.",
        "Are you free for lunch this Friday? There's a new restaurant downtown I'd like to try.",
        "Please find attached the quarterly report for your review. Let me know if you have questions.",
        "I'll be out of office from Dec 20-27. For urgent matters, please contact John.",
        "Great work on the presentation! The client was very impressed with our proposal.",
        "Can you help me review this code before I submit it? The PR is ready.",
        "Welcome aboard! We're excited to have you on the team. Your orientation is Monday.",
        "The conference room has been booked for our workshop. Capacity is 20 people.",
        "Here are the notes from today's standup. Action items are highlighted.",
        "Don't forget to submit your timesheets by end of day Friday.",
        "I've scheduled a training session for next Tuesday. Calendar invite attached.",
        "The server maintenance is complete. All systems are back online.",
        "Happy birthday! Hope you have a wonderful day. Cake in the break room!",
        "Please update your availability for the sprint planning session.",
    ]

    data = []

    # Add phishing samples with variations
    for _ in range(500):
        subj = np.random.choice(phishing_subjects)
        body = np.random.choice(phishing_bodies)
        # Add some noise
        if np.random.random() > 0.5:
            body += " http://bit.ly/" + str(np.random.randint(10000, 99999))
        if np.random.random() > 0.5:
            body += " Please respond ASAP."
        data.append({'subject': subj, 'body': body, 'label': 1})  # 1 = phishing

    # Add legitimate samples with variations
    for _ in range(500):
        subj = np.random.choice(legitimate_subjects)
        body = np.random.choice(legitimate_bodies)
        data.append({'subject': subj, 'body': body, 'label': 0})  # 0 = legitimate

    df = pd.DataFrame(data)

    # Save dataset
    output_path = DATASET_DIR / 'synthetic_phishing.csv'
    df.to_csv(output_path, index=False)
    print(f"Created synthetic dataset: {output_path} ({len(df)} samples)")

    return output_path

def load_and_preprocess_data(filepath):
    """Load and preprocess the dataset"""
    print("\n" + "="*50)
    print("Loading and Preprocessing Data...")
    print("="*50)

    df = pd.read_csv(filepath)

    # Handle different column names
    if 'label' not in df.columns:
        # Try to infer label column
        label_cols = [c for c in df.columns if 'label' in c.lower() or 'class' in c.lower()]
        if label_cols:
            df = df.rename(columns={label_cols[0]: 'label'})

    # Combine subject and body
    if 'subject' in df.columns and 'body' in df.columns:
        df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
    elif 'text' in df.columns:
        pass
    elif 'message' in df.columns:
        df['text'] = df['message']
    elif 'content' in df.columns:
        df['text'] = df['content']
    else:
        # Use first text column
        text_cols = df.select_dtypes(include=['object']).columns.tolist()
        if text_cols:
            df['text'] = df[text_cols[0]]

    # Clean text
    df['text'] = df['text'].fillna('').astype(str)
    df['text'] = df['text'].str.lower()

    # Remove rows with missing labels
    df = df.dropna(subset=['label', 'text'])

    # Ensure label is binary
    df['label'] = df['label'].apply(lambda x: 1 if x in [1, 'phishing', 'spam', 1.0] else 0)

    print(f"Total samples: {len(df)}")
    print(f"Phishing: {(df['label'] == 1).sum()}")
    print(f"Legitimate: {(df['label'] == 0).sum()}")

    return df

def train_model(df):
    """Train the phishing detection model"""
    print("\n" + "="*50)
    print("Training Model...")
    print("="*50)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        df['text'], df['label'], test_size=0.2, random_state=42, stratify=df['label']
    )

    # TF-IDF Vectorization
    print("Creating TF-IDF features...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        sublinear_tf=True
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print(f"Feature dimensions: {X_train_vec.shape}")

    # Train multiple models
    models = {
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced'),
        'Random Forest': RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced'),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
    }

    best_model = None
    best_score = 0
    results = []

    for name, model in models.items():
        print(f"\nTraining {name}...")
        model.fit(X_train_vec, y_train)

        y_pred = model.predict(X_test_vec)
        accuracy = accuracy_score(y_test, y_pred)

        print(f"Accuracy: {accuracy:.4f}")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

        results.append({'model': name, 'accuracy': accuracy})

        if accuracy > best_score:
            best_score = accuracy
            best_model = (name, model)

    print(f"\nBest model: {best_model[0]} with accuracy: {best_score:.4f}")

    return best_model[1], vectorizer, best_model[0]

def save_model(model, vectorizer, model_name):
    """Save the trained model and vectorizer"""
    print("\n" + "="*50)
    print("Saving Model...")
    print("="*50)

    MODEL_DIR.mkdir(exist_ok=True)

    # Save model
    model_path = MODEL_DIR / 'phishing_model.pkl'
    joblib.dump(model, model_path)
    print(f"Model saved to: {model_path}")

    # Save vectorizer
    vectorizer_path = MODEL_DIR / 'vectorizer.pkl'
    joblib.dump(vectorizer, vectorizer_path)
    print(f"Vectorizer saved to: {vectorizer_path}")

    # Save model info
    info = {
        'model_name': model_name,
        'features': 5000,
        'ngram_range': [1, 2],
        'accuracy': 'See training output'
    }
    info_path = MODEL_DIR / 'model_info.json'
    with open(info_path, 'w') as f:
        json.dump(info, f, indent=2)
    print(f"Model info saved to: {info_path}")

    # Create Python module for web app
    create_model_module(model_name)

def create_model_module(model_name):
    """Create a Python module for using the model"""
    module_code = '''"""
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
'''

    module_path = MODEL_DIR / 'detector.py'
    with open(module_path, 'w') as f:
        f.write(module_code)
    print(f"Model module created: {module_path}")

def main():
    print("="*60)
    print("PHISHING EMAIL DETECTOR - MODEL TRAINING")
    print("="*60)

    # Download or create dataset
    data_path = download_kaggle_phishing_dataset()

    # Load and preprocess
    df = load_and_preprocess_data(data_path)

    # Train model
    model, vectorizer, model_name = train_model(df)

    # Save model
    save_model(model, vectorizer, model_name)

    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print(f"\nModel files saved to: {MODEL_DIR}")
    print("Files created:")
    print("  - phishing_model.pkl (trained classifier)")
    print("  - vectorizer.pkl (TF-IDF vectorizer)")
    print("  - model_info.json (model metadata)")
    print("  - detector.py (prediction module)")

if __name__ == '__main__':
    main()
