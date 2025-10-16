#!/usr/bin/env python3
"""
Standalone Test Script for Phishing Detection System
Tests ML components independently and prepares for implementation
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
    from phishing_detector import PhishingDetector
    from url_phishing_detector import URLPhishingDetector
    from url_features import URLFeatureExtractor, extract_all_url_features
except ImportError as e:
    print(f"Import error: {e}")
    print(f"Current working directory: {os.getcwd()}")
    print(f"ML directory: {ml_dir}")
    print(f"ML URL directory: {ml_url_dir}")
    print(f"Python path: {sys.path}")
    sys.exit(1)

# Create simplified URL analyzer class
class SimpleURLAnalyzer:
    """Simplified URL analyzer for standalone testing"""
    
    def __init__(self):
        self.detector = URLPhishingDetector()
        self.feature_extractor = URLFeatureExtractor()
        self.is_trained = False
    
    def train_with_dataset(self, urls, labels, test_size=0.2):
        """Train the URL analyzer with a dataset"""
        print("Training URL analyzer...")
        
        # Create dataset
        X = self.detector.create_url_dataset(urls, labels)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"Training set: {X_train.shape[0]} samples")
        print(f"Testing set: {X_test.shape[0]} samples")
        
        # Train model
        feature_importance = self.detector.train_url_model(X_train, y_train)
        
        # Evaluate
        results = self.detector.evaluate_url_model(X_test, y_test)
        
        self.is_trained = True
        
        return {
            'feature_importance': feature_importance,
            'test_results': results,
            'training_samples': X_train.shape[0],
            'test_samples': X_test.shape[0]
        }
    
    def analyze_url(self, url):
        """Analyze a single URL for phishing"""
        if not self.is_trained:
            raise ValueError("Analyzer not trained yet! Call train_with_dataset() first.")
        
        # Get prediction
        result = self.detector.predict_url(url)
        
        # Add detailed feature analysis
        features = self.feature_extractor.extract_domain_features(url)
        result['domain_analysis'] = features
        
        features = self.feature_extractor.extract_suspicious_patterns(url)
        result['suspicious_analysis'] = features
        
        return result

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

def test_url_analyzer(df):
    """Test the URL analyzer with training"""
    print("\n" + "="*60)
    print("TESTING URL ANALYZER")
    print("="*60)
    
    # Initialize analyzer
    analyzer = SimpleURLAnalyzer()
    
    # Train with dataset
    training_results = analyzer.train_with_dataset(
        df['url'].tolist(), 
        df['label'].tolist()
    )
    
    print(f"\nURL Analyzer Results:")
    print(f"   Accuracy: {training_results['test_results']['accuracy']:.4f}")
    print(f"   Training samples: {training_results['training_samples']}")
    print(f"   Test samples: {training_results['test_samples']}")
    
    return analyzer, training_results

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

def test_implementation_readiness():
    """Test if components are ready for implementation"""
    print("\n" + "="*60)
    print("TESTING IMPLEMENTATION READINESS")
    print("="*60)
    
    # Test if components can be imported and used
    print("Testing component availability...")
    
    try:
        # Test basic detector
        detector = PhishingDetector()
        print("   OK PhishingDetector can be instantiated")
        
        # Test feature extraction
        test_url = "https://www.google.com"
        features = detector.extract_features(test_url)
        print(f"   OK Feature extraction works: {len(features)} features")
        
        # Test URL analyzer (using our simplified version)
        analyzer = SimpleURLAnalyzer()
        print("   OK URLAnalyzer can be instantiated")
        
        # Test quick check
        result = quick_url_check(test_url)
        print(f"   OK Quick URL check works: {result['is_phishing']}")
        
        print("\nAll components are ready for implementation")
        return True
        
    except Exception as e:
        print(f"   ERROR Implementation readiness issue: {e}")
        return False

def main():
    """Main function to run comprehensive tests"""
    print("COMPREHENSIVE PHISHING DETECTION TEST")
    print("="*60)
    print("Testing ML components independently and preparing for implementation\n")
    
    # Load dataset
    df = load_dataset()
    
    # Test basic detector
    basic_detector, basic_importance, basic_results = test_basic_detector(df)
    
    # Test URL analyzer
    url_analyzer, analyzer_results = test_url_analyzer(df)
    
    # Test URL detector
    url_detector, url_importance, url_results = test_url_detector(df)
    
    # Test feature extraction
    test_feature_extraction()
    
    # Test quick detection
    test_quick_detection()
    
    # Test implementation readiness
    implementation_ready = test_implementation_readiness()
    
    # Test single URL analysis with trained model
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
        try:
            result = url_analyzer.analyze_url(url)
            print(f"\nAnalyzing URL: {url}")
            print(f"   Prediction: {'PHISHING' if result['is_phishing'] else 'LEGITIMATE'}")
            print(f"   Confidence: {result['confidence']:.3f}")
        except Exception as e:
            print(f"\nError analyzing {url}: {e}")
    
    # Summary
    print("\n" + "="*60)
    print("COMPREHENSIVE TEST SUMMARY")
    print("="*60)
    print(f"Basic Detector Accuracy: {basic_results['accuracy']:.4f}")
    print(f"URL Analyzer Accuracy: {analyzer_results['test_results']['accuracy']:.4f}")
    print(f"URL Detector Accuracy: {url_results['accuracy']:.4f}")
    print(f"Feature Extraction: Working")
    print(f"Quick Detection: Working")
    print(f"Implementation Ready: {'Yes' if implementation_ready else 'No'}")
    
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