#!/usr/bin/env python3
"""
Demo script for URL feature CSV export functionality
Shows how to export URL features to CSV files
"""

import os
import sys

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ML.URL import URLFeatureExporter, quick_export_url, quick_export_urls

def demo_single_url_export():
    """Demo exporting features for a single URL"""
    print("=== Single URL Feature Export Demo ===")
    
    url = "https://goog1e-security-alert.com/verify-account"
    
    # Method 1: Using quick function
    print(f"📊 Analyzing URL: {url}")
    csv_file = quick_export_url(url, "demo_exports")
    print(f"✅ Exported to: {csv_file}")
    
    # Method 2: Using exporter class
    exporter = URLFeatureExporter()
    csv_file2 = exporter.export_single_url_features(
        url, 
        "demo_exports/manual_export.csv",
        include_analysis=True
    )
    print(f"✅ Manual export to: {csv_file2}")

def demo_batch_url_export():
    """Demo exporting features for multiple URLs"""
    print("\n=== Batch URL Feature Export Demo ===")
    
    # Test URLs
    urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/microsoft/vscode", 
        "https://goog1e-security-alert.com/verify-account",
        "https://paypa1-confirm-account.ml/secure-login",
        "https://amaz0n-login-verification.tk/update-info",
        "https://stackoverflow.com/questions/123456",
        "https://faceb00k-security-check.ga/verify-identity"
    ]
    
    labels = [0, 0, 1, 1, 1, 0, 1]  # 0=legitimate, 1=phishing
    
    # Method 1: Using quick function
    print(f"📊 Analyzing {len(urls)} URLs...")
    csv_file = quick_export_urls(urls, labels, "demo_exports")
    print(f"✅ Batch export to: {csv_file}")
    
    # Method 2: Using exporter class
    exporter = URLFeatureExporter()
    csv_file2 = exporter.export_url_list_features(
        urls, 
        labels,
        "demo_exports/manual_batch.csv",
        include_analysis=True
    )
    print(f"✅ Manual batch export to: {csv_file2}")
    
    return csv_file

def demo_feature_summary(csv_file):
    """Demo generating feature summary"""
    print("\n=== Feature Summary Demo ===")
    
    exporter = URLFeatureExporter()
    summary_file = exporter.export_feature_summary(csv_file, "demo_exports/feature_summary.csv")
    print(f"✅ Feature summary to: {summary_file}")

def demo_dataset_export():
    """Demo exporting features from existing dataset"""
    print("\n=== Dataset Export Demo ===")
    
    # Check if we have an existing dataset
    dataset_paths = [
        "../../data/enhanced_phishing_dataset.csv",
        "../../data/phishing_dataset.csv"
    ]
    
    for dataset_path in dataset_paths:
        if os.path.exists(dataset_path):
            print(f"📂 Found dataset: {dataset_path}")
            
            exporter = URLFeatureExporter()
            csv_file = exporter.export_dataset_features(
                dataset_path,
                "demo_exports/dataset_with_features.csv",
                include_analysis=True
            )
            print(f"✅ Dataset export to: {csv_file}")
            break
    else:
        print("⚠️  No existing datasets found. Skipping dataset export demo.")

def show_csv_content(csv_file):
    """Show a preview of the generated CSV content"""
    print(f"\n=== CSV Content Preview: {csv_file} ===")
    
    import pandas as pd
    
    try:
        df = pd.read_csv(csv_file)
        print(f"📊 Shape: {df.shape[0]} rows × {df.shape[1]} columns")
        print(f"📋 Columns: {list(df.columns)}")
        
        # Show first few rows
        print("\n📄 First 3 rows:")
        print(df.head(3).to_string())
        
        # Show key statistics if analysis columns exist
        if 'risk_score' in df.columns:
            print(f"\n📈 Risk Score Statistics:")
            print(f"   Average: {df['risk_score'].mean():.2f}")
            print(f"   Min: {df['risk_score'].min():.2f}")
            print(f"   Max: {df['risk_score'].max():.2f}")
        
        if 'is_phishing' in df.columns:
            phishing_count = df['is_phishing'].sum()
            print(f"\n🎯 Phishing Detection:")
            print(f"   Phishing URLs: {phishing_count}")
            print(f"   Legitimate URLs: {len(df) - phishing_count}")
            
    except Exception as e:
        print(f"❌ Error reading CSV: {e}")

def main():
    """Main demo function"""
    print("🛡️  URL Feature CSV Export Demo")
    print("=" * 50)
    
    # Create demo exports directory
    os.makedirs("demo_exports", exist_ok=True)
    
    # Run demos
    demo_single_url_export()
    batch_file = demo_batch_url_export()
    demo_feature_summary(batch_file)
    demo_dataset_export()
    
    # Show content preview
    show_csv_content(batch_file)
    
    print("\n" + "=" * 50)
    print("✅ Demo completed! Check the 'demo_exports' folder for generated CSV files.")
    print("📁 Generated files:")
    for file in os.listdir("demo_exports"):
        if file.endswith('.csv'):
            file_path = os.path.join("demo_exports", file)
            size = os.path.getsize(file_path)
            print(f"   - {file} ({size} bytes)")

if __name__ == "__main__":
    main()
