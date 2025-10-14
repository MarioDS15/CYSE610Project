#!/usr/bin/env python3
"""
Show live results of URL ML analysis
"""

import sys
import os
import pandas as pd

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from ML.URL import quick_url_check, quick_export_url

def show_live_analysis():
    """Show live URL analysis results"""
    print("🔍 LIVE URL ANALYSIS RESULTS")
    print("=" * 60)
    
    # Test URLs
    test_urls = [
        ("https://www.google.com/search?q=python", "Legitimate - Google Search"),
        ("https://github.com/microsoft/vscode", "Legitimate - GitHub Repository"),
        ("https://goog1e-security-alert.com/verify-account", "Phishing - Google Impersonation"),
        ("https://paypa1-confirm-account.ml/secure-login", "Phishing - PayPal Impersonation"),
        ("https://amaz0n-login-verification.tk/update-info", "Phishing - Amazon Impersonation"),
        ("https://bit.ly/suspicious-redirect", "Suspicious - URL Shortener")
    ]
    
    results = []
    
    for i, (url, description) in enumerate(test_urls, 1):
        print(f"\n{i}. {description}")
        print(f"   URL: {url}")
        
        # Analyze URL
        result = quick_url_check(url)
        
        # Determine status
        status = "🚨 PHISHING" if result['is_phishing'] else "✅ SAFE"
        
        print(f"   Result: {status}")
        print(f"   Risk Score: {result['risk_score']}/100")
        print(f"   Risk Level: {result['risk_level']}")
        print(f"   Confidence: {result['confidence']:.2f}")
        
        # Show key suspicious factors
        suspicious = result['suspicious_factors']
        suspicious_reasons = []
        
        if suspicious['has_suspicious_keywords']:
            suspicious_reasons.append(f"Suspicious keywords ({suspicious['suspicious_keyword_count']})")
        if suspicious['is_shortened']:
            suspicious_reasons.append("URL shortener")
        if suspicious['has_suspicious_tld']:
            suspicious_reasons.append("Suspicious TLD")
        if suspicious['has_brand_names']:
            suspicious_reasons.append(f"Brand names ({suspicious['brand_count']})")
        
        if suspicious_reasons:
            print(f"   🚨 Reasons: {', '.join(suspicious_reasons)}")
        else:
            print(f"   ✅ No major red flags detected")
        
        results.append({
            'url': url,
            'description': description,
            'is_phishing': result['is_phishing'],
            'risk_score': result['risk_score'],
            'risk_level': result['risk_level'],
            'confidence': result['confidence']
        })
    
    return results

def show_csv_export_demo():
    """Show CSV export functionality"""
    print("\n\n📊 CSV EXPORT DEMONSTRATION")
    print("=" * 60)
    
    # Create exports directory
    os.makedirs("demo_results", exist_ok=True)
    
    # Test URLs for export
    export_urls = [
        "https://suspicious-bank-login.tk/verify-account",
        "https://www.facebook.com/login",
        "https://paypa1-security-check.ml/update-password"
    ]
    
    print("Exporting features for sample URLs...")
    
    csv_files = []
    for i, url in enumerate(export_urls, 1):
        print(f"\n{i}. Exporting: {url}")
        csv_file = quick_export_url(url, "demo_results")
        csv_files.append(csv_file)
        
        # Show file info
        file_size = os.path.getsize(csv_file)
        print(f"   📁 File: {os.path.basename(csv_file)}")
        print(f"   📏 Size: {file_size} bytes")
    
    return csv_files

def show_csv_content(csv_file):
    """Show detailed CSV content"""
    print(f"\n📋 CSV CONTENT PREVIEW: {os.path.basename(csv_file)}")
    print("-" * 60)
    
    try:
        df = pd.read_csv(csv_file)
        
        print(f"📊 Shape: {df.shape[0]} rows × {df.shape[1]} columns")
        
        # Show URL and key results
        print(f"\n🔍 Analysis Results:")
        for col in ['url', 'is_phishing', 'confidence', 'risk_score', 'risk_level']:
            if col in df.columns:
                print(f"   {col}: {df[col].iloc[0]}")
        
        # Show feature categories
        print(f"\n📈 Feature Categories:")
        feature_categories = {
            'Domain': [col for col in df.columns if 'domain' in col.lower()],
            'Path': [col for col in df.columns if 'path' in col.lower()],
            'Query': [col for col in df.columns if 'query' in col.lower() or 'param' in col.lower()],
            'Suspicious': [col for col in df.columns if 'suspicious' in col.lower()],
            'Statistical': [col for col in df.columns if any(x in col.lower() for x in ['length', 'ratio', 'entropy'])]
        }
        
        for category, features in feature_categories.items():
            if features:
                print(f"   {category}: {len(features)} features")
                # Show a few example features
                for feature in features[:3]:
                    value = df[feature].iloc[0]
                    print(f"     - {feature}: {value}")
                if len(features) > 3:
                    print(f"     ... and {len(features)-3} more")
        
    except Exception as e:
        print(f"❌ Error reading CSV: {e}")

def main():
    """Main demonstration"""
    print("🛡️  URL ML MODULE - LIVE RESULTS DEMONSTRATION")
    print("=" * 70)
    
    # Show live analysis
    results = show_live_analysis()
    
    # Show CSV export
    csv_files = show_csv_export_demo()
    
    # Show CSV content for first file
    if csv_files:
        show_csv_content(csv_files[0])
    
    # Summary
    print(f"\n\n📊 SUMMARY")
    print("=" * 60)
    print(f"✅ Analyzed {len(results)} URLs")
    print(f"📁 Generated {len(csv_files)} CSV files")
    
    phishing_count = sum(1 for r in results if r['is_phishing'])
    print(f"🚨 Detected {phishing_count} phishing URLs")
    print(f"✅ Identified {len(results) - phishing_count} legitimate URLs")
    
    print(f"\n🎯 Key Features:")
    print(f"   - 35+ features extracted per URL")
    print(f"   - Risk scoring (0-100)")
    print(f"   - CSV export capability")
    print(f"   - Real-time analysis")
    print(f"   - Chrome extension ready")

if __name__ == "__main__":
    main()
