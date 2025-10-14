#!/usr/bin/env python3
"""
Interactive demo of the phishing detection system
"""

from phishing_detector import PhishingDetector
from download_dataset import load_dataset
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

def interactive_demo():
    """
    Interactive demonstration of the phishing detection system
    """
    print("🛡️  PHISHING URL DETECTION SYSTEM DEMO")
    print("=" * 50)
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Load and prepare data
    print("📊 Loading dataset...")
    df = load_dataset()
    
    # Extract features
    print("🔧 Extracting features...")
    X = detector.create_dataset(df['url'].tolist(), df['label'].tolist())
    y = np.array(df['label'].tolist())
    
    # Train model
    print("🤖 Training model...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    detector.train_model(X_train, y_train)
    
    print("\n✅ System ready! Enter URLs to analyze (type 'quit' to exit)")
    print("-" * 60)
    
    while True:
        url = input("\n🌐 Enter URL to analyze: ").strip()
        
        if url.lower() in ['quit', 'exit', 'q']:
            print("👋 Thanks for using the Phishing Detection System!")
            break
            
        if not url:
            print("❌ Please enter a valid URL")
            continue
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        try:
            # Analyze URL
            features = detector.extract_features(url)
            X_sample = pd.DataFrame([features])
            X_scaled = detector.scaler.transform(X_sample)
            
            prediction = detector.model.predict(X_scaled)[0]
            probability = detector.model.predict_proba(X_scaled)[0]
            
            result = "🚨 PHISHING" if prediction == 1 else "✅ LEGITIMATE"
            confidence = probability[1] if prediction == 1 else probability[0]
            
            print(f"\n🔍 Analysis Results:")
            print(f"   URL: {url}")
            print(f"   Result: {result}")
            print(f"   Confidence: {confidence:.3f} ({confidence*100:.1f}%)")
            
            # Show top features
            feature_importance = detector.model.feature_importances_
            feature_names = detector.feature_names
            
            # Get top contributing features for this URL
            feature_values = X_sample.iloc[0]
            feature_contributions = []
            
            for i, (name, importance) in enumerate(zip(feature_names, feature_importance)):
                value = feature_values[name]
                contribution = value * importance
                feature_contributions.append((name, value, contribution, importance))
            
            # Sort by contribution
            feature_contributions.sort(key=lambda x: abs(x[2]), reverse=True)
            
            print(f"\n🔧 Top Contributing Features:")
            for i, (name, value, contribution, importance) in enumerate(feature_contributions[:5]):
                print(f"   {i+1}. {name}: {value} (importance: {importance:.3f})")
            
        except Exception as e:
            print(f"❌ Error analyzing URL: {e}")
            print("   Please check the URL format and try again")

def quick_test():
    """
    Quick test with predefined URLs
    """
    print("🧪 QUICK TEST MODE")
    print("=" * 30)
    
    test_urls = [
        ("https://www.google.com", "Legitimate"),
        ("https://goog1e-security-alert.com/verify", "Phishing"),
        ("https://github.com/microsoft/vscode", "Legitimate"),
        ("https://paypa1-confirm.tk/login", "Phishing"),
        ("https://www.amazon.com", "Legitimate"),
        ("https://amaz0n-login.ml/update", "Phishing")
    ]
    
    # Initialize and train detector
    detector = PhishingDetector()
    df = load_dataset()
    X = detector.create_dataset(df['url'].tolist(), df['label'].tolist())
    y = np.array(df['label'].tolist())
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    detector.train_model(X_train, y_train)
    
    print("Testing on sample URLs:")
    print("-" * 40)
    
    for url, expected in test_urls:
        try:
            features = detector.extract_features(url)
            X_sample = pd.DataFrame([features])
            X_scaled = detector.scaler.transform(X_sample)
            
            prediction = detector.model.predict(X_scaled)[0]
            probability = detector.model.predict_proba(X_scaled)[0]
            
            result = "PHISHING" if prediction == 1 else "LEGITIMATE"
            confidence = probability[1] if prediction == 1 else probability[0]
            
            # Check if correct
            correct = "✅" if (result == "PHISHING" and "Phishing" in expected) or \
                             (result == "LEGITIMATE" and "Legitimate" in expected) else "❌"
            
            print(f"{correct} {url}")
            print(f"   Expected: {expected} | Got: {result} ({confidence:.3f})")
            print()
            
        except Exception as e:
            print(f"❌ Error with {url}: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        quick_test()
    else:
        interactive_demo()

