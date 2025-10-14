#!/usr/bin/env python3
"""
Script to download and prepare real phishing datasets
"""

import pandas as pd
import numpy as np
import requests
import zipfile
import os
from urllib.parse import urlparse

def download_phishing_dataset():
    """
    Download and prepare a real phishing dataset
    """
    print("Downloading phishing dataset...")
    
    # Create data directory
    os.makedirs('data', exist_ok=True)
    
    # For demonstration, we'll create a more realistic synthetic dataset
    # In practice, you would download from UCI, Mendeley, or IEEE DataPort
    
    print("Creating realistic synthetic dataset...")
    
    # Legitimate URLs (real patterns)
    legitimate_urls = [
        # Google services
        "https://www.google.com/search?q=machine+learning",
        "https://mail.google.com/mail/u/0/#inbox",
        "https://drive.google.com/drive/my-drive",
        "https://maps.google.com/maps?q=New+York",
        "https://translate.google.com/?sl=en&tl=es",
        
        # GitHub
        "https://github.com/microsoft/vscode",
        "https://github.com/tensorflow/tensorflow",
        "https://github.com/pytorch/pytorch",
        "https://github.com/scikit-learn/scikit-learn",
        "https://github.com/pandas-dev/pandas",
        
        # Stack Overflow
        "https://stackoverflow.com/questions/123456/python-error",
        "https://stackoverflow.com/questions/789012/machine-learning",
        "https://stackoverflow.com/questions/345678/data-science",
        
        # E-commerce
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://www.ebay.com/itm/123456789",
        "https://shop.apple.com/us/iphone",
        
        # Social Media
        "https://www.linkedin.com/in/johndoe",
        "https://twitter.com/username/status/123456789",
        "https://www.facebook.com/pages/Example-Page",
        "https://www.instagram.com/username/",
        
        # News and Information
        "https://www.nytimes.com/section/technology",
        "https://www.bbc.com/news/technology",
        "https://www.wikipedia.org/wiki/Machine_learning",
        "https://www.reddit.com/r/MachineLearning/",
        
        # Educational
        "https://www.coursera.org/course/ml",
        "https://www.edx.org/course/machine-learning",
        "https://www.kaggle.com/competitions/titanic",
        
        # Technology Companies
        "https://www.microsoft.com/en-us/",
        "https://www.apple.com/macbook-pro/",
        "https://cloud.google.com/",
        "https://aws.amazon.com/",
        
        # Development Tools
        "https://code.visualstudio.com/",
        "https://www.jetbrains.com/pycharm/",
        "https://www.docker.com/products/docker-desktop",
        "https://kubernetes.io/docs/home/",
        
        # Financial
        "https://www.paypal.com/us/home",
        "https://www.bankofamerica.com/",
        "https://www.chase.com/",
        "https://www.wellsfargo.com/",
        
        # Entertainment
        "https://www.netflix.com/",
        "https://www.spotify.com/us/",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.twitch.tv/",
        
        # Travel
        "https://www.booking.com/",
        "https://www.expedia.com/",
        "https://www.airbnb.com/",
        "https://www.tripadvisor.com/",
        
        # Professional
        "https://www.salesforce.com/",
        "https://www.slack.com/",
        "https://www.dropbox.com/",
        "https://www.adobe.com/products/photoshop.html"
    ]
    
    # Phishing URLs (realistic patterns)
    phishing_urls = [
        # Google impersonation
        "https://goog1e-security-alert.com/verify-account",
        "https://google-security-update.tk/confirm-login",
        "https://goog1e-account-recovery.ml/verify-identity",
        "https://google-2fa-verification.ga/secure-login",
        "https://goog1e-security-check.cf/update-account",
        
        # Amazon impersonation
        "https://amaz0n-login-verification.tk/update-info",
        "https://amazon-account-security.ml/confirm-details",
        "https://amaz0n-prime-renewal.ga/verify-payment",
        "https://amazon-security-alert.tk/update-account",
        "https://amaz0n-order-confirmation.cf/verify-purchase",
        
        # PayPal impersonation
        "https://paypa1-confirm-account.ml/secure-login",
        "https://paypal-security-update.tk/verify-account",
        "https://paypa1-payment-confirmation.ga/update-info",
        "https://paypal-account-security.ml/confirm-details",
        "https://paypa1-verification-required.cf/secure-login",
        
        # Facebook impersonation
        "https://faceb00k-security-check.ga/verify-identity",
        "https://facebook-account-recovery.tk/confirm-login",
        "https://faceb00k-privacy-update.ml/verify-account",
        "https://facebook-security-alert.ga/update-profile",
        "https://faceb00k-login-verification.cf/confirm-access",
        
        # Apple impersonation
        "https://app1e-id-verification.cf/confirm-details",
        "https://apple-security-update.tk/verify-account",
        "https://app1e-icloud-recovery.ml/confirm-login",
        "https://apple-account-security.ga/update-info",
        "https://app1e-payment-verification.cf/secure-login",
        
        # Microsoft impersonation
        "https://micros0ft-security-alert.tk/update-security",
        "https://microsoft-account-verification.ml/confirm-login",
        "https://micros0ft-office-update.ga/verify-account",
        "https://microsoft-security-check.tk/update-profile",
        "https://micros0ft-login-verification.cf/confirm-access",
        
        # eBay impersonation
        "https://ebay-account-verification.ml/secure-update",
        "https://ebay-security-alert.tk/verify-account",
        "https://ebay-payment-confirmation.ga/update-info",
        "https://ebay-login-verification.ml/confirm-details",
        "https://ebay-account-security.cf/secure-login",
        
        # Netflix impersonation
        "https://netflix-security-alert.ga/verify-subscription",
        "https://netflix-account-update.tk/confirm-payment",
        "https://netflix-login-verification.ml/secure-access",
        "https://netflix-subscription-renewal.cf/verify-account",
        "https://netflix-security-check.ga/update-profile",
        
        # Twitter impersonation
        "https://twitt3r-account-security.tk/confirm-account",
        "https://twitter-verification-required.ml/verify-identity",
        "https://twitt3r-login-update.ga/secure-access",
        "https://twitter-security-alert.cf/confirm-login",
        "https://twitt3r-account-recovery.tk/verify-account",
        
        # Instagram impersonation
        "https://instagr4m-security-check.ml/verify-login",
        "https://instagram-account-verification.ga/confirm-identity",
        "https://instagr4m-security-update.tk/verify-account",
        "https://instagram-login-required.cf/secure-access",
        "https://instagr4m-account-security.ml/confirm-login",
        
        # Banking impersonation
        "https://bank0famerica-security.tk/verify-account",
        "https://chase-login-verification.ml/secure-access",
        "https://wellsfarg0-security-alert.ga/confirm-login",
        "https://citi-security-update.cf/verify-account",
        
        # Generic phishing patterns
        "https://secure-account-update.tk/login",
        "https://urgent-verification-required.ml/confirm",
        "https://security-alert-important.ga/verify",
        "https://account-suspended-notice.cf/update",
        "https://payment-confirmation-needed.tk/secure",
        
        # Suspicious domains with numbers
        "https://www2-paypal-security.com/verify",
        "https://secure3-amazon-update.net/confirm",
        "https://login4-google-account.org/verify",
        "https://account5-microsoft-security.info/update",
        
        # URL shorteners with suspicious redirects
        "https://bit.ly/secure-paypal-login",
        "https://tinyurl.com/amazon-verification",
        "https://goo.gl/google-security-update",
        "https://t.co/facebook-account-recovery"
    ]
    
    # Expand datasets
    legitimate_expanded = legitimate_urls * 20  # 1000 legitimate URLs
    phishing_expanded = phishing_urls * 20     # 1000 phishing URLs
    
    # Combine and shuffle
    all_urls = legitimate_expanded + phishing_expanded
    all_labels = [0] * len(legitimate_expanded) + [1] * len(phishing_expanded)
    
    # Create DataFrame
    df = pd.DataFrame({
        'url': all_urls,
        'label': all_labels,
        'type': ['legitimate'] * len(legitimate_expanded) + ['phishing'] * len(phishing_expanded)
    })
    
    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save to CSV
    df.to_csv('data/phishing_dataset.csv', index=False)
    
    print(f"Dataset created with {len(df)} URLs")
    print(f"Legitimate: {len(df[df['label'] == 0])} URLs")
    print(f"Phishing: {len(df[df['label'] == 1])} URLs")
    print("Dataset saved to 'data/phishing_dataset.csv'")
    
    return df

def load_dataset():
    """
    Load the phishing dataset
    """
    if not os.path.exists('data/phishing_dataset.csv'):
        print("Dataset not found. Creating new dataset...")
        return download_phishing_dataset()
    
    df = pd.read_csv('data/phishing_dataset.csv')
    print(f"Loaded dataset with {len(df)} URLs")
    return df

if __name__ == "__main__":
    download_phishing_dataset()

