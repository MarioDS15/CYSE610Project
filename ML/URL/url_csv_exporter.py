#!/usr/bin/env python3
"""
URL Feature CSV Exporter
Utility to export extracted URL features to CSV files
"""

import pandas as pd
import numpy as np
import os
from datetime import datetime
from .url_phishing_detector import URLPhishingDetector
from .url_features import extract_all_url_features
from .url_analyzer import quick_url_check

class URLFeatureExporter:
    """Export URL features to CSV files"""
    
    def __init__(self):
        self.detector = URLPhishingDetector()
    
    def export_single_url_features(self, url, output_file=None, include_analysis=True):
        """
        Export features for a single URL to CSV
        
        Args:
            url: URL string to analyze
            output_file: Output CSV file path (optional)
            include_analysis: Whether to include quick analysis results
            
        Returns:
            str: Path to the generated CSV file
        """
        # Extract features
        features = extract_all_url_features(url)
        
        # Add URL and timestamp
        features['url'] = url
        features['timestamp'] = datetime.now().isoformat()
        
        if include_analysis:
            # Add quick analysis
            analysis = quick_url_check(url)
            features['is_phishing'] = analysis['is_phishing']
            features['confidence'] = analysis['confidence']
            features['risk_score'] = analysis['risk_score']
            features['risk_level'] = analysis['risk_level']
        
        # Create DataFrame
        df = pd.DataFrame([features])
        
        # Generate filename if not provided
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = url.replace('://', '_').replace('/', '_').replace('?', '_').replace('&', '_')
            safe_url = safe_url[:50]  # Limit length
            output_file = f"url_features_{safe_url}_{timestamp}.csv"
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else "."
        os.makedirs(output_dir, exist_ok=True)
        
        # Save to CSV
        df.to_csv(output_file, index=False)
        
        print(f"Features exported to: {output_file}")
        print(f"Total features: {len(features)}")
        
        return output_file
    
    def export_url_list_features(self, urls, labels=None, output_file=None, include_analysis=True):
        """
        Export features for multiple URLs to CSV
        
        Args:
            urls: List of URLs to analyze
            labels: Optional list of labels (0=legitimate, 1=phishing)
            output_file: Output CSV file path (optional)
            include_analysis: Whether to include quick analysis results
            
        Returns:
            str: Path to the generated CSV file
        """
        print(f"🔄 Processing {len(urls)} URLs...")
        
        features_list = []
        
        for i, url in enumerate(urls):
            if i % 100 == 0:
                print(f"   Processed {i}/{len(urls)} URLs")
            
            try:
                # Extract features
                features = extract_all_url_features(url)
                
                # Add URL and timestamp
                features['url'] = url
                features['timestamp'] = datetime.now().isoformat()
                
                # Add label if provided
                if labels is not None:
                    features['label'] = labels[i]
                
                if include_analysis:
                    # Add quick analysis
                    analysis = quick_url_check(url)
                    features['is_phishing'] = analysis['is_phishing']
                    features['confidence'] = analysis['confidence']
                    features['risk_score'] = analysis['risk_score']
                    features['risk_level'] = analysis['risk_level']
                
                features_list.append(features)
                
            except Exception as e:
                print(f"⚠️  Error processing URL {url}: {e}")
                # Add error entry
                error_features = {
                    'url': url,
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e)
                }
                if labels is not None:
                    error_features['label'] = labels[i]
                features_list.append(error_features)
        
        # Create DataFrame
        df = pd.DataFrame(features_list)
        
        # Generate filename if not provided
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"url_features_batch_{len(urls)}_urls_{timestamp}.csv"
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else "."
        os.makedirs(output_dir, exist_ok=True)
        
        # Save to CSV
        df.to_csv(output_file, index=False)
        
        print(f"✅ Features exported to: {output_file}")
        print(f"📊 Total URLs processed: {len(features_list)}")
        print(f"📊 Total features per URL: {len(df.columns) - 3}")  # Exclude url, timestamp, label/analysis
        
        return output_file
    
    def export_dataset_features(self, dataset_path, output_file=None, include_analysis=True):
        """
        Export features from an existing dataset
        
        Args:
            dataset_path: Path to existing CSV dataset
            output_file: Output CSV file path (optional)
            include_analysis: Whether to include quick analysis results
            
        Returns:
            str: Path to the generated CSV file
        """
        print(f"📂 Loading dataset from: {dataset_path}")
        
        # Load dataset
        df = pd.read_csv(dataset_path)
        
        # Check required columns
        if 'url' not in df.columns:
            raise ValueError("Dataset must contain 'url' column")
        
        urls = df['url'].tolist()
        labels = df['label'].tolist() if 'label' in df.columns else None
        
        # Generate output filename if not provided
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = os.path.splitext(os.path.basename(dataset_path))[0]
            output_file = f"{base_name}_with_features_{timestamp}.csv"
        
        return self.export_url_list_features(urls, labels, output_file, include_analysis)
    
    def export_feature_summary(self, csv_file, summary_file=None):
        """
        Generate a summary of features from a CSV file
        
        Args:
            csv_file: Path to CSV file with features
            summary_file: Output summary file path (optional)
            
        Returns:
            str: Path to the generated summary file
        """
        print(f"Generating feature summary for: {csv_file}")
        
        # Load CSV
        df = pd.read_csv(csv_file)
        
        # Generate summary
        summary = {
            'total_urls': len(df),
            'total_features': len(df.columns),
            'feature_names': list(df.columns),
            'missing_values': df.isnull().sum().to_dict(),
            'feature_types': df.dtypes.to_dict()
        }
        
        # Add analysis results if available
        if 'is_phishing' in df.columns:
            phishing_count = df['is_phishing'].sum()
            summary['phishing_detected'] = int(phishing_count)
            summary['legitimate_detected'] = int(len(df) - phishing_count)
        
        if 'risk_score' in df.columns:
            summary['avg_risk_score'] = float(df['risk_score'].mean())
            summary['max_risk_score'] = float(df['risk_score'].max())
            summary['min_risk_score'] = float(df['risk_score'].min())
        
        # Generate summary filename if not provided
        if summary_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            summary_file = f"feature_summary_{timestamp}.csv"
        
        # Save summary
        summary_df = pd.DataFrame([summary])
        summary_df.to_csv(summary_file, index=False)
        
        print(f"Summary exported to: {summary_file}")
        
        return summary_file

def quick_export_url(url, output_dir="exports"):
    """
    Quick function to export a single URL's features
    
    Args:
        url: URL to analyze
        output_dir: Directory to save CSV file
        
    Returns:
        str: Path to generated CSV file
    """
    exporter = URLFeatureExporter()
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace('://', '_').replace('/', '_').replace('?', '_').replace('&', '_')
    safe_url = safe_url[:30]  # Limit length
    output_file = os.path.join(output_dir, f"url_{safe_url}_{timestamp}.csv")
    
    return exporter.export_single_url_features(url, output_file)

def quick_export_urls(urls, labels=None, output_dir="exports"):
    """
    Quick function to export multiple URLs' features
    
    Args:
        urls: List of URLs to analyze
        labels: Optional list of labels
        output_dir: Directory to save CSV file
        
    Returns:
        str: Path to generated CSV file
    """
    exporter = URLFeatureExporter()
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"urls_batch_{len(urls)}_{timestamp}.csv")
    
    return exporter.export_url_list_features(urls, labels, output_file)

if __name__ == "__main__":
    # Demo the CSV exporter
    print("=== URL Feature CSV Exporter Demo ===")
    
    # Test URLs
    test_urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/microsoft/vscode",
        "https://goog1e-security-alert.com/verify-account",
        "https://paypa1-confirm-account.ml/secure-login"
    ]
    
    test_labels = [0, 0, 1, 1]  # 0=legitimate, 1=phishing
    
    # Create exporter
    exporter = URLFeatureExporter()
    
    # Export single URL
    print("\n1. Exporting single URL features...")
    single_file = exporter.export_single_url_features(test_urls[0])
    
    # Export multiple URLs
    print("\n2. Exporting multiple URL features...")
    batch_file = exporter.export_url_list_features(test_urls, test_labels)
    
    # Generate summary
    print("\n3. Generating feature summary...")
    summary_file = exporter.export_feature_summary(batch_file)
    
    print(f"\n Demo completed!")
    print(f"   Single URL: {single_file}")
    print(f"   Batch URLs: {batch_file}")
    print(f"   Summary: {summary_file}")
