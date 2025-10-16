#!/usr/bin/env python3
"""
Example Usage Script for Phishing Detection ML System
Shows how to use the ML components for URL analysis
"""

import sys
import os

# Add ML modules to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'ML'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'ML', 'URL'))

# Import ML components
from url_features import URLFeatureExtractor, extract_all_url_features

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

def analyze_multiple_urls(urls):
    """Analyze multiple URLs at once"""
    print("Analyzing multiple URLs:")
    
    for i, url in enumerate(urls, 1):
        try:
            result = quick_url_check(url)
            status = "PHISHING" if result['is_phishing'] else "SAFE"
            print(f"{i}. {url} -> {status} ({result['risk_score']}/100)")
        except Exception as e:
            print(f"{i}. {url} -> ERROR: {e}")

def main():
    """Main function to demonstrate usage"""
    print("PHISHING DETECTION ML SYSTEM - USAGE EXAMPLES")
    print("="*60)
    print("This script shows how to use the ML components for URL analysis.\n")
    
    # Example 1: Quick Heuristic Detection
    print("="*60)
    print("EXAMPLE 1: Quick Heuristic Detection")
    print("="*60)
    print("This method doesn't require training and works immediately.\n")
    
    test_urls = [
        "https://www.google.com",
        "https://goog1e-security-alert.com/verify",
        "https://bit.ly/suspicious-link",
        "https://paypa1-confirm.tk/login"
    ]
    
    for url in test_urls:
        result = quick_url_check(url)
        print(f"URL: {url}")
        print(f"  Result: {'PHISHING' if result['is_phishing'] else 'SAFE'}")
        print(f"  Risk Score: {result['risk_score']}/100")
        print(f"  Risk Level: {result['risk_level']}")
        print(f"  Confidence: {result['confidence']:.3f}")
        print()
    
    # Example 2: Feature Extraction
    print("="*60)
    print("EXAMPLE 2: Feature Extraction")
    print("="*60)
    print("Extract detailed features from URLs for custom analysis.\n")
    
    test_url = "https://goog1e-security-alert.com/verify-account"
    features = extract_all_url_features(test_url)
    
    print(f"URL: {test_url}")
    print(f"Total features extracted: {len(features)}")
    print("\nKey features:")
    key_features = ['url_length', 'domain_length', 'has_suspicious_keywords', 
                   'is_shortened', 'has_suspicious_tld', 'has_ip_address', 
                   'has_brand_names', 'entropy']
    for feature in key_features:
        if feature in features:
            print(f"  {feature}: {features[feature]}")
    
    # Example 3: ML-Based Detection
    print("\n" + "="*60)
    print("EXAMPLE 3: ML-Based Detection")
    print("="*60)
    print("This method requires training but provides higher accuracy.\n")
    
    print("To use ML-based detection:")
    print("1. Train the model with your dataset:")
    print("   detector = URLPhishingDetector()")
    print("   X = detector.create_url_dataset(urls, labels)")
    print("   detector.train_url_model(X_train, y_train)")
    print()
    print("2. Use the trained model for predictions:")
    print("   result = detector.predict_url(url)")
    print("   print(f'Prediction: {result[\"is_phishing\"]}')")
    print("   print(f'Confidence: {result[\"confidence\"]}')")
    
    # Example 4: Batch Analysis
    print("\n" + "="*60)
    print("EXAMPLE 4: Batch Analysis")
    print("="*60)
    print("Analyze multiple URLs at once.\n")
    
    batch_urls = [
        "https://www.google.com",
        "https://github.com/microsoft/vscode",
        "https://goog1e-security-alert.com/verify",
        "https://paypa1-confirm.tk/login",
        "https://www.amazon.com"
    ]
    
    analyze_multiple_urls(batch_urls)
    
    # Example 5: Custom Integration
    print("\n" + "="*60)
    print("EXAMPLE 5: Custom Integration")
    print("="*60)
    print("How to integrate into your own application.\n")
    
    print("```python")
    print("# Import the components")
    print("from phishing_detector import PhishingDetector")
    print("from url_phishing_detector import URLPhishingDetector")
    print("from url_features import extract_all_url_features")
    print()
    print("# For quick detection (no training needed)")
    print("def check_url_safety(url):")
    print("    result = quick_url_check(url)")
    print("    return result['is_phishing'], result['risk_score']")
    print()
    print("# For detailed analysis")
    print("def analyze_url(url):")
    print("    features = extract_all_url_features(url)")
    print("    # Your custom logic here")
    print("    return features")
    print()
    print("# For ML-based detection (after training)")
    print("def ml_check_url(url, trained_detector):")
    print("    result = trained_detector.predict_url(url)")
    print("    return result['is_phishing'], result['confidence']")
    print("```")
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print("The ML system provides multiple ways to analyze URLs:")
    print("   1. Quick heuristic detection (immediate use)")
    print("   2. Feature extraction (for custom analysis)")
    print("   3. ML-based detection (high accuracy, requires training)")
    print("   4. Batch analysis (multiple URLs)")
    print("   5. Custom integration (into your application)")
    print()
    print("Ready for implementation in any application!")

if __name__ == "__main__":
    main()