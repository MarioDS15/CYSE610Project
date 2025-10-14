#!/usr/bin/env python3
"""
Test URL ML module with existing dataset
"""

import sys
import os
import pandas as pd

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

def test_with_existing_dataset():
    """Test URL module with existing dataset"""
    print("=== Testing with Existing Dataset ===")
    
    try:
        from ML.URL.url_csv_exporter import URLFeatureExporter
        
        # Check for existing datasets
        dataset_paths = [
            "../../data/enhanced_phishing_dataset.csv",
            "../../data/phishing_dataset.csv"
        ]
        
        dataset_found = None
        for dataset_path in dataset_paths:
            if os.path.exists(dataset_path):
                dataset_found = dataset_path
                break
        
        if not dataset_found:
            print("❌ No existing datasets found")
            return False
        
        print(f"📂 Using dataset: {dataset_found}")
        
        # Load a small sample for testing
        df = pd.read_csv(dataset_found)
        print(f"📊 Dataset size: {len(df)} URLs")
        
        # Take a small sample for testing
        sample_size = min(10, len(df))
        sample_df = df.sample(n=sample_size, random_state=42)
        
        urls = sample_df['url'].tolist()
        labels = sample_df['label'].tolist()
        
        print(f"🧪 Testing with {sample_size} sample URLs")
        
        # Test feature extraction
        from ML.URL.url_features import extract_all_url_features
        
        features_list = []
        for i, url in enumerate(urls):
            print(f"   Processing {i+1}/{sample_size}: {url[:50]}...")
            features = extract_all_url_features(url)
            features['url'] = url
            features['label'] = labels[i]
            features_list.append(features)
        
        # Create DataFrame
        features_df = pd.DataFrame(features_list)
        print(f"✅ Extracted {len(features_df.columns)-2} features per URL")
        
        # Export to CSV
        os.makedirs("test_exports", exist_ok=True)
        output_file = "test_exports/sample_dataset_features.csv"
        features_df.to_csv(output_file, index=False)
        
        print(f"📁 Features exported to: {output_file}")
        print(f"📊 File size: {os.path.getsize(output_file)} bytes")
        
        # Show some statistics
        if 'label' in features_df.columns:
            phishing_count = features_df['label'].sum()
            print(f"📈 Sample contains: {phishing_count} phishing, {len(features_df)-phishing_count} legitimate URLs")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing with dataset: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_quick_analysis():
    """Test quick analysis on sample URLs"""
    print("\n=== Quick Analysis Test ===")
    
    try:
        from ML.URL.url_analyzer import quick_url_check
        
        # Sample URLs from different categories
        test_urls = [
            # Legitimate
            "https://www.google.com/search?q=python",
            "https://github.com/microsoft/vscode",
            "https://stackoverflow.com/questions/123456",
            
            # Suspicious/Phishing
            "https://goog1e-security-alert.com/verify-account",
            "https://paypa1-confirm-account.ml/secure-login",
            "https://amaz0n-login-verification.tk/update-info",
            "https://faceb00k-security-check.ga/verify-identity"
        ]
        
        print("🔍 Analyzing sample URLs:")
        print("-" * 60)
        
        for url in test_urls:
            result = quick_url_check(url)
            
            status = "🚨 PHISHING" if result['is_phishing'] else "✅ SAFE"
            print(f"{status} | Risk: {result['risk_score']:2d}/100 | {result['risk_level']:7s} | {url}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in quick analysis: {e}")
        return False

def test_feature_analysis():
    """Test detailed feature analysis"""
    print("\n=== Feature Analysis Test ===")
    
    try:
        from ML.URL.url_analyzer import quick_url_check
        
        # Test a clearly suspicious URL
        suspicious_url = "https://goog1e-security-alert.tk/verify-account/login"
        print(f"🔍 Analyzing: {suspicious_url}")
        
        result = quick_url_check(suspicious_url)
        
        print(f"📊 Analysis Results:")
        print(f"   Phishing: {result['is_phishing']}")
        print(f"   Risk Score: {result['risk_score']}/100")
        print(f"   Risk Level: {result['risk_level']}")
        print(f"   Confidence: {result['confidence']:.2f}")
        
        print(f"\n🚨 Suspicious Factors:")
        suspicious = result['suspicious_factors']
        for key, value in suspicious.items():
            if value > 0:
                print(f"   {key}: {value}")
        
        print(f"\n🌐 Domain Factors:")
        domain = result['domain_factors']
        for key, value in domain.items():
            if value != 0:
                print(f"   {key}: {value}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in feature analysis: {e}")
        return False

def main():
    """Run all dataset tests"""
    print("🧪 URL ML Module - Dataset Integration Tests")
    print("=" * 60)
    
    tests = [
        test_with_existing_dataset,
        test_quick_analysis,
        test_feature_analysis
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"Dataset Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All dataset tests passed! URL ML module integrates well with your data.")
    else:
        print("⚠️  Some dataset tests failed. Check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
