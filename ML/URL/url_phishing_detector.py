#!/usr/bin/env python3
"""
URL-Specific Phishing Detection using Machine Learning
Focused on URL analysis and domain features
"""

import pandas as pd
import numpy as np
import re
import urllib.parse
import tldextract
from urllib.parse import urlparse, parse_qs
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class URLPhishingDetector:
    def __init__(self):
        self.feature_names = []
        self.scaler = StandardScaler()
        self.model = None
        
    def extract_url_features(self, url):
        """
        Extract comprehensive URL-specific features for phishing detection
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
    
    def create_url_dataset(self, urls, labels):
        """
        Create feature matrix from URLs
        """
        print("Extracting URL features...")
        features_list = []
        
        for i, url in enumerate(urls):
            if i % 1000 == 0:
                print(f"Processed {i}/{len(urls)} URLs")
            
            try:
                features = self.extract_url_features(url)
                features_list.append(features)
            except Exception as e:
                print(f"Error processing URL {url}: {e}")
                # Fill with zeros if extraction fails
                features_list.append({key: 0 for key in self.feature_names} if self.feature_names else {})
        
        # Convert to DataFrame
        df = pd.DataFrame(features_list)
        self.feature_names = df.columns.tolist()
        
        print(f"Extracted {len(self.feature_names)} URL features")
        return df
    
    def train_url_model(self, X_train, y_train):
        """
        Train the URL-based phishing detection model
        """
        print("Training URL-based Random Forest model...")
        
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
        print("URL model training completed!")
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important URL Features:")
        print(feature_importance.head(10))
        
        return feature_importance
    
    def predict_url(self, url):
        """
        Predict if a single URL is phishing
        """
        if not self.model:
            raise ValueError("Model not trained yet!")
        
        features = self.extract_url_features(url)
        X_sample = pd.DataFrame([features])
        X_scaled = self.scaler.transform(X_sample)
        
        prediction = self.model.predict(X_scaled)[0]
        probability = self.model.predict_proba(X_scaled)[0]
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(probability[1] if prediction == 1 else probability[0]),
            'features': features
        }
    
    def evaluate_url_model(self, X_test, y_test):
        """
        Evaluate the URL-based model
        """
        print("\nEvaluating URL model performance...")
        
        # Scale test features
        X_test_scaled = self.scaler.transform(X_test)
        
        # Make predictions
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nURL Model Performance:")
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

def main():
    """
    Demo function for URL-specific phishing detection
    """
    print("=== URL-Specific Phishing Detection Demo ===")
    
    # Initialize detector
    detector = URLPhishingDetector()
    
    # Sample URLs for testing
    test_urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/microsoft/vscode",
        "https://goog1e-security-alert.com/verify-account",
        "https://paypa1-confirm-account.ml/secure-login",
        "https://amaz0n-login-verification.tk/update-info",
        "https://faceb00k-security-check.ga/verify-identity"
    ]
    
    print("\nTesting URL feature extraction:")
    for url in test_urls:
        features = detector.extract_url_features(url)
        print(f"\nURL: {url}")
        print(f"Features extracted: {len(features)}")
        print(f"Key features: url_length={features['url_length']}, "
              f"suspicious_tld={features['has_suspicious_tld']}, "
              f"brand_usage={features['suspicious_brand_usage']}")

if __name__ == "__main__":
    main()
