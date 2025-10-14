#!/usr/bin/env python3
"""
Simple test script for URL ML module
Tests the core functionality without complex imports
"""

import sys
import os

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

def test_url_features():
    """Test URL feature extraction"""
    print("=== Testing URL Feature Extraction ===")
    
    try:
        from ML.URL.url_features import extract_all_url_features
        
        test_url = "https://goog1e-security-alert.com/verify-account"
        print(f"Testing URL: {test_url}")
        
        features = extract_all_url_features(test_url)
        print(f"✅ Successfully extracted {len(features)} features")
        
        # Show some key features
        key_features = ['url_length', 'domain_length', 'has_suspicious_keywords', 'is_shortened']
        for feature in key_features:
            if feature in features:
                print(f"   {feature}: {features[feature]}")
        
        return True
    except Exception as e:
        print(f"❌ Error in feature extraction: {e}")
        return False

def test_quick_check():
    """Test quick URL check"""
    print("\n=== Testing Quick URL Check ===")
    
    try:
        from ML.URL.url_analyzer import quick_url_check
        
        test_urls = [
            "https://www.google.com",
            "https://goog1e-security-alert.com/verify",
            "https://bit.ly/suspicious-link"
        ]
        
        for url in test_urls:
            print(f"\nTesting: {url}")
            result = quick_url_check(url)
            
            print(f"   Phishing: {result['is_phishing']}")
            print(f"   Risk Score: {result['risk_score']}/100")
            print(f"   Risk Level: {result['risk_level']}")
            print(f"   Confidence: {result['confidence']:.2f}")
        
        return True
    except Exception as e:
        print(f"❌ Error in quick check: {e}")
        return False

def test_csv_export():
    """Test CSV export functionality"""
    print("\n=== Testing CSV Export ===")
    
    try:
        from ML.URL.url_csv_exporter import quick_export_url
        
        test_url = "https://suspicious-site.tk/login"
        print(f"Exporting features for: {test_url}")
        
        # Create exports directory
        os.makedirs("test_exports", exist_ok=True)
        
        csv_file = quick_export_url(test_url, "test_exports")
        print(f"✅ CSV exported to: {csv_file}")
        
        # Check if file was created
        if os.path.exists(csv_file):
            file_size = os.path.getsize(csv_file)
            print(f"   File size: {file_size} bytes")
            return True
        else:
            print("❌ CSV file was not created")
            return False
            
    except Exception as e:
        print(f"❌ Error in CSV export: {e}")
        return False

def test_url_detector():
    """Test URL phishing detector"""
    print("\n=== Testing URL Phishing Detector ===")
    
    try:
        from ML.URL.url_phishing_detector import URLPhishingDetector
        
        detector = URLPhishingDetector()
        
        test_url = "https://paypa1-confirm.ml/secure-login"
        print(f"Testing detector with: {test_url}")
        
        features = detector.extract_url_features(test_url)
        print(f"✅ Extracted {len(features)} features")
        
        # Show some suspicious features
        suspicious_features = ['has_suspicious_keywords', 'suspicious_brand_usage', 'has_suspicious_tld']
        for feature in suspicious_features:
            if feature in features:
                print(f"   {feature}: {features[feature]}")
        
        return True
    except Exception as e:
        print(f"❌ Error in URL detector: {e}")
        return False

def main():
    """Run all tests"""
    print("🛡️  URL ML Module Test Suite")
    print("=" * 50)
    
    tests = [
        test_url_features,
        test_quick_check,
        test_csv_export,
        test_url_detector
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! URL ML module is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
