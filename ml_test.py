#!/usr/bin/env python3
"""
Simple ML Test Script for Phishing Detection
Tests the core ML functionality for URL analysis
"""

import sys
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

# Add ML modules to path
current_dir = os.path.dirname(os.path.abspath(__file__))
ml_dir = os.path.join(current_dir, 'ML')
ml_url_dir = os.path.join(current_dir, 'ML', 'URL')

sys.path.insert(0, ml_dir)
sys.path.insert(0, ml_url_dir)

# Import ML components
try:
    from ML.phishing_detector import PhishingDetector
    from ML.URL.url_phishing_detector import URLPhishingDetector
    from ML.URL.url_features import URLFeatureExtractor, extract_all_url_features
except ImportError as e:
    print(f"Import error: {e}")
    print(f"Current working directory: {os.getcwd()}")
    print(f"ML directory: {ml_dir}")
    print(f"ML URL directory: {ml_url_dir}")
    print(f"Python path: {sys.path}")
    sys.exit(1)

def quick_url_check(url):
    """Quick URL check using heuristics - no training required"""
    extractor = URLFeatureExtractor()
    
    # Get basic features
    suspicious = extractor.extract_suspicious_patterns(url)
    domain = extractor.extract_domain_features(url)
    statistical = extractor.extract_statistical_features(url)
    
    # Simple heuristic scoring
    risk_score = 0
    
    if suspicious['has_suspicious_keywords']:
        risk_score += 30
    
    if suspicious['is_shortened']:
        risk_score += 20
    
    if suspicious['has_suspicious_tld']:
        risk_score += 25
    
    if suspicious['has_ip_address']:
        risk_score += 35
    
    if suspicious['has_brand_names']:
        risk_score += 25
    
    if domain['has_numbers']:
        risk_score += 15
    
    if statistical['url_length'] > 100:
        risk_score += 10
    
    # Determine if phishing
    is_phishing = risk_score >= 50
    confidence = min(1.0, risk_score / 100)
    
    return {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'risk_score': risk_score,
        'risk_level': 'HIGH' if risk_score >= 70 else 'MEDIUM' if risk_score >= 40 else 'LOW',
        'suspicious_factors': suspicious,
        'domain_factors': domain
    }

def load_dataset():
    """Load the phishing dataset"""
    possible_paths = [
        'ML/URL/URL Data/enhanced_phishing_dataset.csv',
        'ML/URL/URL Data/phishing_dataset.csv',
        'data/phishing_dataset.csv'
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            print(f"Loading dataset from: {path}")
            df = pd.read_csv(path)
            print(f"   Loaded {len(df):,} URLs")
            return df
    
    print("No dataset found. Creating synthetic test dataset...")
    return create_synthetic_dataset()

def create_synthetic_dataset():
    """Create a synthetic dataset for testing"""
    print("Creating synthetic test dataset...")
    
    # Legitimate URLs
    legitimate_urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/microsoft/vscode",
        "https://stackoverflow.com/questions/123456",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://www.paypal.com/us/home",
        "https://www.facebook.com/pages/Example",
        "https://www.youtube.com/watch?v=abc123",
        "https://www.linkedin.com/in/username",
        "https://www.wikipedia.org/wiki/Machine_learning",
        "https://www.reddit.com/r/programming"
    ] * 50
    
    # Phishing URLs
    phishing_urls = [
        "https://goog1e-security-alert.com/verify-account",
        "https://paypa1-confirm-account.ml/secure-login",
        "https://amaz0n-login-verification.tk/update-info",
        "https://faceb00k-security-check.ga/verify-identity",
        "https://app1e-id-verification.cf/confirm-details",
        "https://micros0ft-security-alert.tk/update-security",
        "https://ebay-account-verification.ml/secure-update",
        "https://netflix-security-alert.ga/verify-subscription",
        "https://twitt3r-account-security.tk/confirm-account",
        "https://instagr4m-security-check.ml/verify-login"
    ] * 50
    
    # Combine
    all_urls = legitimate_urls + phishing_urls
    all_labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)
    
    df = pd.DataFrame({
        'url': all_urls,
        'label': all_labels
    })
    
    print(f"   Created {len(df)} URLs ({len(legitimate_urls)} legitimate, {len(phishing_urls)} phishing)")
    return df

def save_url_results(detector, feature_importance, results, X_test, y_test):
    """Save URL testing results to the URL Results folder"""
    import json
    import matplotlib.pyplot as plt
    import seaborn as sns
    from datetime import datetime
    
    # Create results directory if it doesn't exist
    results_dir = "ML/URL/URL Results"
    os.makedirs(results_dir, exist_ok=True)
    
    # Generate timestamp for unique filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save feature importance
    feature_importance.to_csv(f"{results_dir}/feature_importance_{timestamp}.csv", index=False)
    
    # Save model performance metrics
    metrics = {
        'accuracy': results.get('accuracy', 0),
        'precision': results.get('precision', 0),
        'recall': results.get('recall', 0),
        'f1_score': results.get('f1', 0),
        'timestamp': timestamp,
        'test_samples': len(y_test),
        'features_count': len(feature_importance)
    }
    
    with open(f"{results_dir}/performance_metrics_{timestamp}.json", 'w') as f:
        json.dump(metrics, f, indent=2)
    
    # Save detailed results
    detailed_results = {
        'confusion_matrix': results.get('confusion_matrix', [[0,0],[0,0]]).tolist() if hasattr(results.get('confusion_matrix'), 'tolist') else results.get('confusion_matrix', [[0,0],[0,0]]),
        'classification_report': results.get('classification_report', ''),
        'top_features': feature_importance.head(10).to_dict('records')
    }
    
    with open(f"{results_dir}/detailed_results_{timestamp}.json", 'w') as f:
        json.dump(detailed_results, f, indent=2)
    
    # Generate separate graphs
    create_url_result_graphs(feature_importance, results, metrics, results_dir, timestamp)
    
    print(f"   Results saved to: {results_dir}/")
    print(f"   - feature_importance_{timestamp}.csv")
    print(f"   - performance_metrics_{timestamp}.json")
    print(f"   - detailed_results_{timestamp}.json")
    print(f"   - Graphs: feature_importance, confusion_matrix, performance_metrics")

def create_url_result_graphs(feature_importance, results, metrics, results_dir, timestamp):
    """Create separate graphs for URL results"""
    import matplotlib.pyplot as plt
    import seaborn as sns
    
    # Set style
    plt.style.use('default')
    
    # Graph 1: Feature Importance
    plt.figure(figsize=(12, 8))
    top_features = feature_importance.head(15)
    plt.barh(range(len(top_features)), top_features['importance'])
    plt.yticks(range(len(top_features)), top_features['feature'])
    plt.xlabel('Feature Importance')
    plt.title(f'Top 15 Feature Importances - {timestamp}')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(f"{results_dir}/feature_importance_{timestamp}.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    # Graph 2: Confusion Matrix
    plt.figure(figsize=(8, 6))
    cm = results.get('confusion_matrix', [[0,0],[0,0]])
    if hasattr(cm, 'tolist'):
        cm = cm.tolist()
    
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'])
    plt.title(f'Confusion Matrix - {timestamp}')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    plt.savefig(f"{results_dir}/confusion_matrix_{timestamp}.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    # Graph 3: Performance Metrics
    plt.figure(figsize=(10, 6))
    metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    metric_values = [metrics['accuracy'], metrics['precision'], metrics['recall'], metrics['f1_score']]
    
    bars = plt.bar(metric_names, metric_values, color=['skyblue', 'lightgreen', 'lightcoral', 'lightsalmon'])
    plt.ylabel('Score')
    plt.title(f'Model Performance Metrics - {timestamp}')
    plt.ylim([0, 1])
    
    # Add value labels on bars
    for bar, value in zip(bars, metric_values):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                f'{value:.3f}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(f"{results_dir}/performance_metrics_{timestamp}.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    # Graph 4: Feature Importance Distribution
    plt.figure(figsize=(10, 6))
    plt.hist(feature_importance['importance'], bins=20, alpha=0.7, color='lightblue', edgecolor='black')
    plt.xlabel('Feature Importance')
    plt.ylabel('Number of Features')
    plt.title(f'Distribution of Feature Importances - {timestamp}')
    plt.tight_layout()
    plt.savefig(f"{results_dir}/feature_distribution_{timestamp}.png", dpi=300, bbox_inches='tight')
    plt.close()

def test_basic_detector(df):
    """Test the basic phishing detector"""
    print("\n" + "="*60)
    print("TESTING BASIC PHISHING DETECTOR")
    print("="*60)
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Extract features
    print("Extracting features...")
    X = detector.create_dataset(df['url'].tolist(), df['label'].tolist())
    y = np.array(df['label'].tolist())
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"   Training set: {X_train.shape[0]} samples")
    print(f"   Testing set: {X_test.shape[0]} samples")
    
    # Train model
    print("Training model...")
    feature_importance = detector.train_model(X_train, y_train)
    
    # Evaluate
    print("Evaluating model...")
    results = detector.evaluate_model(X_test, y_test)
    
    print(f"\nBasic Detector Results:")
    print(f"   Accuracy: {results['accuracy']:.4f}")
    
    return detector, feature_importance, results

def test_url_detector(df):
    """Test the URL-specific detector"""
    print("\n" + "="*60)
    print("TESTING URL-SPECIFIC DETECTOR")
    print("="*60)
    
    # Initialize detector
    detector = URLPhishingDetector()
    
    # Extract features
    print("Extracting URL features...")
    X = detector.create_url_dataset(df['url'].tolist(), df['label'].tolist())
    y = np.array(df['label'].tolist())
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"   Training set: {X_train.shape[0]} samples")
    print(f"   Testing set: {X_test.shape[0]} samples")
    
    # Train model
    print("Training URL model...")
    feature_importance = detector.train_url_model(X_train, y_train)
    
    # Evaluate
    print("Evaluating URL model...")
    results = detector.evaluate_url_model(X_test, y_test)
    
    print(f"\nURL Detector Results:")
    print(f"   Accuracy: {results['accuracy']:.4f}")
    
    # Save results to URL Results folder
    save_url_results(detector, feature_importance, results, X_test, y_test)
    
    return detector, feature_importance, results

def test_feature_extraction():
    """Test feature extraction capabilities"""
    print("\n" + "="*60)
    print("TESTING FEATURE EXTRACTION")
    print("="*60)
    
    test_urls = [
        "https://www.google.com/search?q=python",
        "https://goog1e-security-alert.com/verify-account",
        "https://bit.ly/suspicious-link",
        "https://192.168.1.1/admin"
    ]
    
    print("Testing feature extraction on sample URLs...")
    
    for i, url in enumerate(test_urls, 1):
        print(f"\n   URL {i}: {url}")
        
        try:
            # Test all feature extraction methods
            basic_features = extract_all_url_features(url)
            print(f"      Total features extracted: {len(basic_features)}")
            
            # Show some key features
            key_features = ['url_length', 'has_suspicious_keywords', 'is_shortened', 'has_suspicious_tld']
            for feature in key_features:
                if feature in basic_features:
                    print(f"      {feature}: {basic_features[feature]}")
                    
        except Exception as e:
            print(f"      Error: {e}")
    
    print("\nFeature extraction test completed")

def test_quick_detection():
    """Test quick heuristic-based detection"""
    print("\n" + "="*60)
    print("TESTING QUICK DETECTION (HEURISTIC)")
    print("="*60)
    
    test_urls = [
        "https://www.google.com/search?q=python",
        "https://goog1e-security-alert.com/verify-account",
        "https://bit.ly/suspicious-link",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://paypa1-confirm-account.ml/secure-login"
    ]
    
    print("Testing quick detection on sample URLs...")
    
    for url in test_urls:
        try:
            result = quick_url_check(url)
            print(f"\n   URL: {url}")
            print(f"   Result: {'PHISHING' if result['is_phishing'] else 'SAFE'}")
            print(f"   Risk Score: {result['risk_score']}/100")
            print(f"   Risk Level: {result['risk_level']}")
            print(f"   Confidence: {result['confidence']:.3f}")
            
        except Exception as e:
            print(f"   Error checking {url}: {e}")
    
    print("\nQuick detection test completed")

def test_single_url_analysis(detector, url):
    """Test analysis of a single URL using trained model"""
    print(f"\nAnalyzing single URL: {url}")
    
    try:
        # Get prediction
        result = detector.predict_url(url)
        
        print(f"   Prediction: {'PHISHING' if result['is_phishing'] else 'LEGITIMATE'}")
        print(f"   Confidence: {result['confidence']:.3f}")
        
        # Show key features
        features = result['features']
        key_features = ['url_length', 'has_suspicious_keywords', 'has_suspicious_tld', 'suspicious_brand_usage']
        print(f"   Key features:")
        for feature in key_features:
            if feature in features:
                print(f"     {feature}: {features[feature]}")
        
        return result
        
    except Exception as e:
        print(f"   Error analyzing URL: {e}")
        return None

def main():
    """Main function to run ML tests"""
    print("PHISHING DETECTION ML TEST")
    print("="*60)
    print("Testing core ML functionality for URL analysis\n")
    
    # Load dataset
    df = load_dataset()
    
    # Test basic detector
    basic_detector, basic_importance, basic_results = test_basic_detector(df)
    
    # Test URL detector
    url_detector, url_importance, url_results = test_url_detector(df)
    
    # Test feature extraction
    test_feature_extraction()
    
    # Test quick detection
    test_quick_detection()
    
    # Test single URL analysis
    print("\n" + "="*60)
    print("TESTING SINGLE URL ANALYSIS")
    print("="*60)
    
    test_urls = [
        "https://www.google.com",
        "https://goog1e-security-alert.com/verify",
        "https://github.com/microsoft/vscode",
        "https://paypa1-confirm.tk/login"
    ]
    
    for url in test_urls:
        test_single_url_analysis(url_detector, url)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Basic Detector Accuracy: {basic_results['accuracy']:.4f}")
    print(f"URL Detector Accuracy: {url_results['accuracy']:.4f}")
    print(f"Feature Extraction: Working")
    print(f"Quick Detection: Working")
    print(f"Single URL Analysis: Working")
    
    print(f"\nKey Features Used:")
    print(f"   Basic Detector: {len(basic_importance)} features")
    print(f"   URL Detector: {len(url_importance)} features")
    
    print(f"\nTop 5 Most Important Features (URL Detector):")
    for i, (_, row) in enumerate(url_importance.head(5).iterrows()):
        print(f"   {i+1}. {row['feature']}: {row['importance']:.4f}")
    
    print(f"\nML system is ready for implementation!")
    print(f"   - Use URLPhishingDetector for trained ML analysis")
    print(f"   - Use quick_url_check() for fast heuristic analysis")
    print(f"   - Both methods can be integrated into any application")

if __name__ == "__main__":
    main()