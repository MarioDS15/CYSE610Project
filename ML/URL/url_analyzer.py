#!/usr/bin/env python3
"""
URL Analyzer - High-level interface for URL analysis
Provides easy-to-use functions for URL phishing detection
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from .url_phishing_detector import URLPhishingDetector
from .url_features import URLFeatureExtractor
import warnings
warnings.filterwarnings('ignore')

class URLAnalyzer:
    """High-level URL analysis interface"""
    
    def __init__(self):
        self.detector = URLPhishingDetector()
        self.feature_extractor = URLFeatureExtractor()
        self.is_trained = False
    
    def train_with_dataset(self, urls, labels, test_size=0.2):
        """
        Train the URL analyzer with a dataset
        
        Args:
            urls: List of URLs
            labels: List of labels (0=legitimate, 1=phishing)
            test_size: Fraction of data to use for testing
        """
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
        """
        Analyze a single URL for phishing
        
        Args:
            url: URL string to analyze
            
        Returns:
            dict: Analysis results with prediction and confidence
        """
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
    
    def batch_analyze_urls(self, urls):
        """
        Analyze multiple URLs
        
        Args:
            urls: List of URLs to analyze
            
        Returns:
            list: List of analysis results
        """
        if not self.is_trained:
            raise ValueError("Analyzer not trained yet! Call train_with_dataset() first.")
        
        results = []
        for url in urls:
            try:
                result = self.analyze_url(url)
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'is_phishing': False,
                    'confidence': 0.0,
                    'error': str(e)
                })
        
        return results
    
    def get_url_risk_score(self, url):
        """
        Get a risk score for a URL (0-100)
        
        Args:
            url: URL string
            
        Returns:
            float: Risk score from 0 (safe) to 100 (very risky)
        """
        result = self.analyze_url(url)
        
        # Base score from ML prediction
        base_score = result['confidence'] * 100
        
        # Adjust based on suspicious features
        suspicious_features = result['suspicious_analysis']
        
        # Add points for various suspicious indicators
        risk_adjustments = 0
        
        if suspicious_features['has_suspicious_keywords']:
            risk_adjustments += 15
        
        if suspicious_features['is_shortened']:
            risk_adjustments += 10
        
        if suspicious_features['has_suspicious_tld']:
            risk_adjustments += 20
        
        if suspicious_features['has_ip_address']:
            risk_adjustments += 25
        
        if suspicious_features['has_brand_names']:
            risk_adjustments += 15
        
        final_score = min(100, base_score + risk_adjustments)
        
        return {
            'risk_score': final_score,
            'risk_level': self._get_risk_level(final_score),
            'analysis': result
        }
    
    def _get_risk_level(self, score):
        """Convert numeric score to risk level"""
        if score >= 80:
            return "HIGH"
        elif score >= 60:
            return "MEDIUM"
        elif score >= 40:
            return "LOW"
        else:
            return "MINIMAL"
    
    def explain_analysis(self, url):
        """
        Provide human-readable explanation of URL analysis
        
        Args:
            url: URL string
            
        Returns:
            dict: Detailed explanation of analysis
        """
        result = self.analyze_url(url)
        
        explanation = {
            'url': url,
            'overall_result': 'PHISHING' if result['is_phishing'] else 'LEGITIMATE',
            'confidence': result['confidence'],
            'risk_factors': [],
            'safe_factors': []
        }
        
        # Analyze suspicious features
        suspicious = result['suspicious_analysis']
        
        if suspicious['has_suspicious_keywords']:
            explanation['risk_factors'].append(
                f"Contains suspicious keywords ({suspicious['suspicious_keyword_count']} found)"
            )
        
        if suspicious['is_shortened']:
            explanation['risk_factors'].append("Uses URL shortener service")
        
        if suspicious['has_suspicious_tld']:
            explanation['risk_factors'].append("Uses suspicious top-level domain")
        
        if suspicious['has_ip_address']:
            explanation['risk_factors'].append("Uses IP address instead of domain name")
        
        if suspicious['has_brand_names']:
            explanation['risk_factors'].append(
                f"Contains brand names ({suspicious['brand_count']} found) - potential impersonation"
            )
        
        # Analyze domain features
        domain = result['domain_analysis']
        
        if domain['domain_length'] > 50:
            explanation['risk_factors'].append("Very long domain name")
        
        if domain['has_numbers']:
            explanation['risk_factors'].append("Domain contains numbers")
        
        # Safe factors
        if result['features']['uses_https']:
            explanation['safe_factors'].append("Uses HTTPS encryption")
        
        if domain['has_www']:
            explanation['safe_factors'].append("Uses standard www subdomain")
        
        if not suspicious['has_suspicious_keywords']:
            explanation['safe_factors'].append("No suspicious keywords detected")
        
        return explanation

def quick_url_check(url):
    """
    Quick URL check without training - uses basic heuristics
    
    Args:
        url: URL string
        
    Returns:
        dict: Basic analysis result
    """
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

if __name__ == "__main__":
    # Demo the URL analyzer
    analyzer = URLAnalyzer()
    
    # Test URLs
    test_urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/microsoft/vscode",
        "https://goog1e-security-alert.com/verify-account",
        "https://paypa1-confirm-account.ml/secure-login"
    ]
    
    print("=== Quick URL Check Demo ===")
    for url in test_urls:
        result = quick_url_check(url)
        print(f"\nURL: {url}")
        print(f"Result: {'PHISHING' if result['is_phishing'] else 'SAFE'}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Confidence: {result['confidence']:.2f}")
