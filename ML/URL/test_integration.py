#!/usr/bin/env python3
"""
Test URL ML module integration with existing project
"""

import sys
import os

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

def test_with_existing_detector():
    """Test integration with existing phishing detector"""
    print("=== Testing Integration with Existing Detector ===")
    
    try:
        # Test that we can import both the old and new detectors
        from ML.phishing_detector import PhishingDetector as OriginalDetector
        from ML.URL.url_phishing_detector import URLPhishingDetector as URLDetector
        
        print("✅ Successfully imported both detectors")
        
        # Test URL detector
        url_detector = URLDetector()
        test_url = "https://goog1e-security-alert.com/verify"
        
        print(f"🔍 Testing URL detector with: {test_url}")
        features = url_detector.extract_url_features(test_url)
        print(f"✅ URL detector extracted {len(features)} features")
        
        # Test original detector (should work the same for URLs)
        original_detector = OriginalDetector()
        print(f"🔍 Testing original detector with: {test_url}")
        original_features = original_detector.extract_features(test_url)
        print(f"✅ Original detector extracted {len(original_features)} features")
        
        # Compare some key features
        print(f"\n📊 Feature Comparison:")
        key_features = ['url_length', 'domain_length', 'has_suspicious_keywords', 'uses_https']
        for feature in key_features:
            if feature in features and feature in original_features:
                url_val = features[feature]
                orig_val = original_features[feature]
                match = "✅" if url_val == orig_val else "⚠️"
                print(f"   {match} {feature}: URL={url_val}, Original={orig_val}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in integration test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_extension_backend_integration():
    """Test integration with extension backend"""
    print("\n=== Testing Extension Backend Integration ===")
    
    try:
        from ML.URL.url_analyzer import quick_url_check
        
        # Simulate what the extension backend would do
        def simulate_extension_analysis(url, html="", css=""):
            """Simulate the extension's analysis function"""
            # Use URL analysis
            url_result = quick_url_check(url)
            
            # Simple design analysis (basic HTML/CSS features)
            design_features = {
                'suspicious_design': False,
                'form_count': html.count('<form') if html else 0,
                'input_count': html.count('<input') if html else 0,
                'has_suspicious_keywords': any(keyword in html.lower() for keyword in 
                    ['password', 'login', 'verify', 'secure', 'account']) if html else False
            }
            
            # Combine results
            final_confidence = url_result['confidence']
            if design_features['suspicious_design']:
                final_confidence = min(1.0, final_confidence + 0.2)
            
            is_phishing = final_confidence > 0.7
            
            return {
                'is_phishing': is_phishing,
                'confidence': final_confidence,
                'url_analysis': url_result,
                'design_features': design_features
            }
        
        # Test with sample data
        test_cases = [
            {
                'url': 'https://goog1e-security-alert.com/verify',
                'html': '<form><input type="password" name="password"><input type="text" name="login"></form>',
                'css': 'body { background: red; }'
            },
            {
                'url': 'https://www.google.com/search',
                'html': '<div>Search results</div>',
                'css': 'body { font-family: Arial; }'
            }
        ]
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n🧪 Test Case {i}:")
            print(f"   URL: {test_case['url']}")
            
            result = simulate_extension_analysis(
                test_case['url'], 
                test_case['html'], 
                test_case['css']
            )
            
            status = "🚨 PHISHING" if result['is_phishing'] else "✅ SAFE"
            print(f"   Result: {status} (Confidence: {result['confidence']:.2f})")
            print(f"   URL Risk: {result['url_analysis']['risk_score']}/100")
            print(f"   Forms Found: {result['design_features']['form_count']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in extension integration test: {e}")
        return False

def test_csv_export_integration():
    """Test CSV export with extension workflow"""
    print("\n=== Testing CSV Export Integration ===")
    
    try:
        from ML.URL.url_csv_exporter import quick_export_url
        
        # Simulate extension workflow
        test_urls = [
            "https://www.google.com",
            "https://goog1e-security-alert.com/verify-account",
            "https://paypa1-confirm.ml/secure-login"
        ]
        
        os.makedirs("integration_exports", exist_ok=True)
        
        for i, url in enumerate(test_urls, 1):
            print(f"📊 Exporting features for URL {i}: {url[:40]}...")
            csv_file = quick_export_url(url, "integration_exports")
            print(f"   ✅ Exported to: {os.path.basename(csv_file)}")
        
        # List exported files
        export_files = os.listdir("integration_exports")
        print(f"\n📁 Total files exported: {len(export_files)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in CSV export integration: {e}")
        return False

def main():
    """Run all integration tests"""
    print("🔗 URL ML Module - Integration Tests")
    print("=" * 50)
    
    tests = [
        test_with_existing_detector,
        test_extension_backend_integration,
        test_csv_export_integration
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
    print(f"Integration Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All integration tests passed! URL ML module works well with your existing code.")
        print("\n✅ Ready for:")
        print("   - Chrome extension integration")
        print("   - CSV feature export")
        print("   - Research and analysis")
    else:
        print("⚠️  Some integration tests failed. Check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
