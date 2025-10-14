#!/usr/bin/env python3
"""
Phishing URL Detection using Machine Learning
Advanced Feature Engineering for URL Analysis
"""

import pandas as pd
import numpy as np
import re
import urllib.parse
import tldextract
import requests
from urllib.parse import urlparse, parse_qs
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

class PhishingDetector:
    def __init__(self):
        self.feature_names = []
        self.scaler = StandardScaler()
        self.model = None
        
    def extract_features(self, url):
        """
        Extract comprehensive features from a URL for phishing detection
        """
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_ampersands'] = url.count('&')
        features['num_percentages'] = url.count('%')
        
        # Parse URL components
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Domain analysis
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        
        # TLD analysis
        extracted = tldextract.extract(url)
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['has_subdomain'] = 1 if extracted.subdomain else 0
        features['domain_name_length'] = len(extracted.domain)
        features['tld_length'] = len(extracted.suffix)
        
        # Special character analysis
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_port'] = 1 if ':' in domain and domain.split(':')[-1].isdigit() else 0
        features['has_ip'] = self._has_ip_address(url)
        features['has_suspicious_tld'] = self._has_suspicious_tld(extracted.suffix)
        
        # Suspicious patterns
        features['has_shortener'] = self._is_shortened_url(url)
        features['has_suspicious_keywords'] = self._has_suspicious_keywords(url)
        features['has_numbers_in_domain'] = self._has_numbers_in_domain(domain)
        features['has_mixed_case'] = self._has_mixed_case(domain)
        
        # Statistical features
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0
        features['letter_ratio'] = sum(c.isalpha() for c in url) / len(url) if url else 0
        features['special_char_ratio'] = sum(not c.isalnum() for c in url) / len(url) if url else 0
        
        # Entropy calculation
        features['url_entropy'] = self._calculate_entropy(url)
        features['domain_entropy'] = self._calculate_entropy(domain)
        
        # Path analysis
        features['path_depth'] = path.count('/') if path else 0
        features['has_file_extension'] = 1 if '.' in path.split('/')[-1] and len(path.split('/')[-1]) > 0 else 0
        features['suspicious_file_ext'] = self._has_suspicious_file_extension(path)
        
        # Query parameter analysis
        features['num_params'] = len(parse_qs(query)) if query else 0
        features['has_suspicious_params'] = self._has_suspicious_params(query)
        
        # Brand impersonation detection
        features['suspicious_brand_usage'] = self._has_suspicious_brand_usage(url)
        
        # URL structure anomalies
        features['double_slash'] = 1 if '//' in url[url.find('://')+3:] else 0
        features['trailing_slash'] = 1 if url.endswith('/') else 0
        
        # HTTPS analysis
        features['uses_https'] = 1 if url.startswith('https://') else 0
        features['uses_http'] = 1 if url.startswith('http://') else 0
        
        return features
    
    def _has_ip_address(self, url):
        """Check if URL contains an IP address"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return 1 if re.search(ip_pattern, url) else 0
    
    def _has_suspicious_tld(self, tld):
        """Check for suspicious top-level domains"""
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'stream']
        return 1 if tld.lower() in suspicious_tlds else 0
    
    def _is_shortened_url(self, url):
        """Check if URL is from a known URL shortener"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
        return 1 if any(shortener in url for shortener in shorteners) else 0
    
    def _has_suspicious_keywords(self, url):
        """Check for suspicious keywords in URL"""
        suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'validate', 'authenticate', 'bank', 'paypal', 'amazon',
            'facebook', 'google', 'apple', 'microsoft', 'support'
        ]
        url_lower = url.lower()
        return 1 if any(keyword in url_lower for keyword in suspicious_keywords) else 0
    
    def _has_numbers_in_domain(self, domain):
        """Check if domain contains numbers"""
        return 1 if re.search(r'\d', domain) else 0
    
    def _has_mixed_case(self, domain):
        """Check for mixed case in domain (suspicious)"""
        return 1 if domain != domain.lower() and domain != domain.upper() else 0
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        entropy = 0
        for i in range(256):
            freq = float(text.count(chr(i)))
            if freq > 0:
                freq = freq / len(text)
                entropy = entropy - freq * np.log2(freq)
        return entropy
    
    def _has_suspicious_file_extension(self, path):
        """Check for suspicious file extensions"""
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif']
        return 1 if any(ext in path.lower() for ext in suspicious_extensions) else 0
    
    def _has_suspicious_params(self, query):
        """Check for suspicious query parameters"""
        suspicious_params = ['redirect', 'url', 'link', 'goto', 'target']
        params = parse_qs(query)
        return 1 if any(param.lower() in suspicious_params for param in params.keys()) else 0
    
    def _has_suspicious_brand_usage(self, url):
        """Check for potential brand impersonation"""
        brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'ebay']
        url_lower = url.lower()
        brand_count = sum(1 for brand in brands if brand in url_lower)
        return 1 if brand_count > 0 else 0
    
    def create_dataset(self, urls, labels):
        """
        Create feature matrix from URLs
        """
        print("Extracting features from URLs...")
        features_list = []
        
        for i, url in enumerate(urls):
            if i % 1000 == 0:
                print(f"Processed {i}/{len(urls)} URLs")
            
            try:
                features = self.extract_features(url)
                features_list.append(features)
            except Exception as e:
                print(f"Error processing URL {url}: {e}")
                # Fill with zeros if extraction fails
                features_list.append({key: 0 for key in self.feature_names} if self.feature_names else {})
        
        # Convert to DataFrame
        df = pd.DataFrame(features_list)
        self.feature_names = df.columns.tolist()
        
        print(f"Extracted {len(self.feature_names)} features")
        return df
    
    def train_model(self, X_train, y_train):
        """
        Train the phishing detection model
        """
        print("Training Random Forest model...")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train_scaled, y_train)
        print("Model training completed!")
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important Features:")
        print(feature_importance.head(10))
        
        return feature_importance
    
    def evaluate_model(self, X_test, y_test):
        """
        Evaluate the trained model
        """
        print("\nEvaluating model performance...")
        
        # Scale test features
        X_test_scaled = self.scaler.transform(X_test)
        
        # Make predictions
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nModel Performance:")
        print(f"Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(cm)
        
        return {
            'accuracy': accuracy,
            'predictions': y_pred,
            'probabilities': y_pred_proba,
            'confusion_matrix': cm
        }
    
    def plot_results(self, feature_importance, results):
        """
        Create visualizations of results
        """
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # Feature Importance
        top_features = feature_importance.head(15)
        axes[0, 0].barh(range(len(top_features)), top_features['importance'])
        axes[0, 0].set_yticks(range(len(top_features)))
        axes[0, 0].set_yticklabels(top_features['feature'])
        axes[0, 0].set_xlabel('Feature Importance')
        axes[0, 0].set_title('Top 15 Feature Importances')
        axes[0, 0].invert_yaxis()
        
        # Confusion Matrix Heatmap
        sns.heatmap(results['confusion_matrix'], annot=True, fmt='d', 
                   cmap='Blues', ax=axes[0, 1])
        axes[0, 1].set_title('Confusion Matrix')
        axes[0, 1].set_xlabel('Predicted')
        axes[0, 1].set_ylabel('Actual')
        
        # Prediction Probabilities Distribution
        phishing_probs = results['probabilities'][:, 1]
        axes[1, 0].hist(phishing_probs, bins=50, alpha=0.7, color='red')
        axes[1, 0].set_xlabel('Predicted Probability of Phishing')
        axes[1, 0].set_ylabel('Frequency')
        axes[1, 0].set_title('Distribution of Phishing Probabilities')
        
        # Accuracy by Class
        from sklearn.metrics import precision_recall_fscore_support
        precision, recall, fscore, _ = precision_recall_fscore_support(
            results['predictions'], results['predictions'], average=None
        )
        
        metrics = ['Precision', 'Recall', 'F1-Score']
        legitimate_scores = [precision[0], recall[0], fscore[0]]
        phishing_scores = [precision[1], recall[1], fscore[1]]
        
        x = np.arange(len(metrics))
        width = 0.35
        
        axes[1, 1].bar(x - width/2, legitimate_scores, width, label='Legitimate', alpha=0.8)
        axes[1, 1].bar(x + width/2, phishing_scores, width, label='Phishing', alpha=0.8)
        axes[1, 1].set_xlabel('Metrics')
        axes[1, 1].set_ylabel('Score')
        axes[1, 1].set_title('Performance by Class')
        axes[1, 1].set_xticks(x)
        axes[1, 1].set_xticklabels(metrics)
        axes[1, 1].legend()
        
        plt.tight_layout()
        plt.savefig('phishing_detection_results.png', dpi=300, bbox_inches='tight')
        plt.show()

def main():
    """
    Main function to run the phishing detection system
    """
    print("=== Phishing URL Detection System ===")
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Create synthetic dataset for demonstration
    # In a real scenario, you would load actual phishing and legitimate URLs
    print("\nCreating synthetic dataset for demonstration...")
    
    # Generate sample URLs (legitimate and phishing patterns)
    legitimate_urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/user/repository",
        "https://stackoverflow.com/questions/123456",
        "https://www.amazon.com/product/12345",
        "https://www.wikipedia.org/wiki/Machine_learning",
        "https://www.linkedin.com/in/username",
        "https://www.youtube.com/watch?v=abc123",
        "https://www.reddit.com/r/programming",
        "https://www.medium.com/@author/article",
        "https://www.coursera.org/course/ml"
    ] * 500  # Multiply to create more samples
    
    phishing_urls = [
        "https://goog1e-security-alert.com/verify-account",
        "https://amaz0n-login-verification.tk/update-info",
        "https://paypa1-confirm-account.ml/secure-login",
        "https://faceb00k-security-check.ga/verify-identity",
        "https://app1e-id-verification.cf/confirm-details",
        "https://micros0ft-security-alert.tk/update-security",
        "https://ebay-account-verification.ml/secure-update",
        "https://netflix-security-alert.ga/verify-subscription",
        "https://twitt3r-account-security.tk/confirm-account",
        "https://instagr4m-security-check.ml/verify-login"
    ] * 500  # Multiply to create more samples
    
    # Combine URLs and labels
    all_urls = legitimate_urls + phishing_urls
    all_labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)
    
    print(f"Total URLs: {len(all_urls)}")
    print(f"Legitimate: {len(legitimate_urls)}")
    print(f"Phishing: {len(phishing_urls)}")
    
    # Extract features
    X = detector.create_dataset(all_urls, all_labels)
    y = np.array(all_labels)
    
    # Split data (85% train, 15% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    
    print(f"\nData split:")
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Testing set: {X_test.shape[0]} samples")
    
    # Train model
    feature_importance = detector.train_model(X_train, y_train)
    
    # Evaluate model
    results = detector.evaluate_model(X_test, y_test)
    
    # Plot results
    detector.plot_results(feature_importance, results)
    
    # Test on some example URLs
    print("\n=== Testing on Example URLs ===")
    test_urls = [
        "https://www.google.com",
        "https://goog1e-security-alert.com/verify",
        "https://github.com/microsoft/vscode",
        "https://paypa1-confirm.tk/login"
    ]
    
    for url in test_urls:
        features = detector.extract_features(url)
        X_test_sample = pd.DataFrame([features])
        X_test_scaled = detector.scaler.transform(X_test_sample)
        prediction = detector.model.predict(X_test_scaled)[0]
        probability = detector.model.predict_proba(X_test_scaled)[0]
        
        result = "PHISHING" if prediction == 1 else "LEGITIMATE"
        confidence = probability[1] if prediction == 1 else probability[0]
        
        print(f"URL: {url}")
        print(f"Prediction: {result} (Confidence: {confidence:.3f})")
        print("-" * 50)

if __name__ == "__main__":
    main()
