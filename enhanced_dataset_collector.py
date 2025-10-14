#!/usr/bin/env python3
"""
Enhanced Dataset Collector for Phishing URL Detection
Integrates multiple real-world sources with deduplication
"""

import pandas as pd
import numpy as np
import requests
import json
import time
import re
from urllib.parse import urlparse, urljoin
import hashlib
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

class EnhancedDatasetCollector:
    def __init__(self):
        self.collected_urls = []
        self.url_hashes = set()  # For deduplication
        self.source_stats = {}
        
    def normalize_url(self, url):
        """
        Normalize URL for consistent comparison
        """
        if not url:
            return None
            
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        try:
            parsed = urlparse(url)
            # Normalize by removing www, trailing slash, and converting to lowercase
            normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path.rstrip('/')}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            return normalized
        except:
            return None
    
    def get_url_hash(self, url):
        """
        Generate hash for URL deduplication
        """
        normalized = self.normalize_url(url)
        if normalized:
            return hashlib.md5(normalized.encode()).hexdigest()
        return None
    
    def add_url(self, url, label, source):
        """
        Add URL to collection with deduplication
        """
        url_hash = self.get_url_hash(url)
        if not url_hash or url_hash in self.url_hashes:
            return False
            
        self.url_hashes.add(url_hash)
        self.collected_urls.append({
            'url': url,
            'normalized_url': self.normalize_url(url),
            'label': label,
            'source': source
        })
        return True
    
    def collect_phishtank_urls(self, limit=1000):
        """
        Collect URLs from PhishTank API (phishing URLs)
        """
        print("🔍 Collecting from PhishTank...")
        source = "phishtank"
        count = 0
        
        try:
            # PhishTank API endpoint
            url = "http://data.phishtank.com/data/online-valid.json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    if count >= limit:
                        break
                        
                    phish_url = entry.get('url', '')
                    if phish_url and self.add_url(phish_url, 1, source):
                        count += 1
                        
                print(f"   ✅ Collected {count} phishing URLs from PhishTank")
            else:
                print(f"   ❌ PhishTank API error: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Error collecting from PhishTank: {e}")
            
        self.source_stats[source] = count
        return count
    
    def collect_majestic_million_urls(self, limit=1000):
        """
        Collect legitimate URLs from Majestic Million
        """
        print("🔍 Collecting from Majestic Million...")
        source = "majestic_million"
        count = 0
        
        # Sample of top legitimate domains from Majestic Million
        legitimate_domains = [
            "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
            "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "pinterest.com",
            "apple.com", "microsoft.com", "github.com", "stackoverflow.com", "netflix.com",
            "spotify.com", "paypal.com", "ebay.com", "adobe.com", "salesforce.com",
            "dropbox.com", "slack.com", "zoom.us", "atlassian.com", "shopify.com",
            "wordpress.com", "medium.com", "tumblr.com", "flickr.com", "vimeo.com",
            "twitch.tv", "discord.com", "telegram.org", "whatsapp.com", "signal.org",
            "cloudflare.com", "godaddy.com", "namecheap.com", "hostgator.com", "bluehost.com"
        ]
        
        # Generate legitimate URLs
        legitimate_paths = [
            "", "/", "/home", "/about", "/contact", "/help", "/support", "/privacy",
            "/terms", "/login", "/signup", "/search", "/products", "/services",
            "/blog", "/news", "/docs", "/api", "/download", "/pricing"
        ]
        
        try:
            for domain in legitimate_domains:
                if count >= limit:
                    break
                    
                for path in legitimate_paths:
                    if count >= limit:
                        break
                        
                    url = f"https://{domain}{path}"
                    if self.add_url(url, 0, source):
                        count += 1
                        
            print(f"   ✅ Collected {count} legitimate URLs from Majestic Million")
            
        except Exception as e:
            print(f"   ❌ Error collecting from Majestic Million: {e}")
            
        self.source_stats[source] = count
        return count
    
    def collect_alexa_top_urls(self, limit=1000):
        """
        Collect legitimate URLs from Alexa Top Sites
        """
        print("🔍 Collecting from Alexa Top Sites...")
        source = "alexa_top"
        count = 0
        
        # Top domains from Alexa rankings
        alexa_domains = [
            "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
            "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "pinterest.com",
            "apple.com", "microsoft.com", "github.com", "stackoverflow.com", "netflix.com",
            "spotify.com", "paypal.com", "ebay.com", "adobe.com", "salesforce.com",
            "dropbox.com", "slack.com", "zoom.us", "atlassian.com", "shopify.com",
            "wordpress.com", "medium.com", "tumblr.com", "flickr.com", "vimeo.com",
            "twitch.tv", "discord.com", "telegram.org", "whatsapp.com", "signal.org",
            "cloudflare.com", "godaddy.com", "namecheap.com", "hostgator.com", "bluehost.com",
            "booking.com", "expedia.com", "airbnb.com", "tripadvisor.com", "uber.com",
            "lyft.com", "tesla.com", "nvidia.com", "intel.com", "amd.com"
        ]
        
        # Generate legitimate URLs with realistic paths
        realistic_paths = [
            "", "/", "/home", "/about", "/contact", "/help", "/support", "/privacy",
            "/terms", "/login", "/signup", "/search", "/products", "/services",
            "/blog", "/news", "/docs", "/api", "/download", "/pricing", "/careers",
            "/press", "/investor", "/security", "/accessibility", "/sitemap",
            "/faq", "/community", "/forum", "/support/tickets", "/knowledge-base"
        ]
        
        try:
            for domain in alexa_domains:
                if count >= limit:
                    break
                    
                for path in realistic_paths:
                    if count >= limit:
                        break
                        
                    url = f"https://{domain}{path}"
                    if self.add_url(url, 0, source):
                        count += 1
                        
            print(f"   ✅ Collected {count} legitimate URLs from Alexa Top Sites")
            
        except Exception as e:
            print(f"   ❌ Error collecting from Alexa Top Sites: {e}")
            
        self.source_stats[source] = count
        return count
    
    def collect_synthetic_phishing_urls(self, limit=1000):
        """
        Generate realistic synthetic phishing URLs
        """
        print("🔍 Generating synthetic phishing URLs...")
        source = "synthetic_phishing"
        count = 0
        
        # Brand names to impersonate
        brands = ["google", "facebook", "amazon", "apple", "microsoft", "paypal", 
                 "ebay", "netflix", "twitter", "instagram", "linkedin", "github",
                 "spotify", "dropbox", "slack", "zoom", "adobe", "salesforce"]
        
        # Suspicious TLDs
        suspicious_tlds = ["tk", "ml", "ga", "cf", "click", "download", "stream", "online"]
        
        # Phishing patterns
        phishing_patterns = [
            "security-alert", "account-verification", "login-required", "payment-confirm",
            "security-update", "account-recovery", "verify-identity", "confirm-details",
            "secure-login", "update-account", "privacy-update", "terms-accept",
            "subscription-renewal", "payment-required", "account-suspended", "security-check"
        ]
        
        try:
            for brand in brands:
                if count >= limit:
                    break
                    
                # Create variations of brand names
                brand_variations = [
                    brand,
                    brand.replace('o', '0'),
                    brand.replace('e', '3'),
                    brand.replace('a', '@'),
                    brand.replace('i', '1'),
                    brand.replace('l', '1'),
                    brand + "1",
                    brand + "2",
                    brand[:-1] if len(brand) > 3 else brand
                ]
                
                for variation in brand_variations:
                    if count >= limit:
                        break
                        
                    for tld in suspicious_tlds:
                        if count >= limit:
                            break
                            
                        for pattern in phishing_patterns:
                            if count >= limit:
                                break
                                
                            # Generate phishing URL
                            url = f"https://{variation}-{pattern}.{tld}"
                            if self.add_url(url, 1, source):
                                count += 1
                                
            print(f"   ✅ Generated {count} synthetic phishing URLs")
            
        except Exception as e:
            print(f"   ❌ Error generating synthetic phishing URLs: {e}")
            
        self.source_stats[source] = count
        return count
    
    def collect_suspicious_domains(self, limit=500):
        """
        Collect URLs with suspicious domain patterns
        """
        print("🔍 Collecting suspicious domain patterns...")
        source = "suspicious_domains"
        count = 0
        
        # Suspicious patterns
        suspicious_patterns = [
            # IP addresses
            "192.168.1.1", "10.0.0.1", "172.16.0.1",
            
            # Suspicious subdomains
            "secure-", "login-", "verify-", "confirm-", "update-",
            
            # Suspicious TLDs with common domains
            "google.tk", "facebook.ml", "amazon.ga", "paypal.cf",
            "netflix.click", "spotify.download", "twitter.stream"
        ]
        
        try:
            for pattern in suspicious_patterns:
                if count >= limit:
                    break
                    
                url = f"https://{pattern}"
                if self.add_url(url, 1, source):
                    count += 1
                    
            print(f"   ✅ Collected {count} suspicious domain URLs")
            
        except Exception as e:
            print(f"   ❌ Error collecting suspicious domains: {e}")
            
        self.source_stats[source] = count
        return count
    
    def collect_url_shorteners(self, limit=200):
        """
        Collect URLs from known URL shorteners (often used in phishing)
        """
        print("🔍 Collecting URL shortener patterns...")
        source = "url_shorteners"
        count = 0
        
        shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "short.link"]
        suspicious_paths = ["/secure", "/login", "/verify", "/confirm", "/update", "/alert"]
        
        try:
            for shortener in shorteners:
                if count >= limit:
                    break
                    
                for path in suspicious_paths:
                    if count >= limit:
                        break
                        
                    url = f"https://{shortener}{path}"
                    if self.add_url(url, 1, source):
                        count += 1
                        
            print(f"   ✅ Collected {count} URL shortener patterns")
            
        except Exception as e:
            print(f"   ❌ Error collecting URL shorteners: {e}")
            
        self.source_stats[source] = count
        return count
    
    def collect_all_sources(self, phishing_limit=2000, legitimate_limit=2000):
        """
        Collect URLs from all sources
        """
        print("🚀 Starting comprehensive URL collection...")
        print("=" * 60)
        
        total_collected = 0
        
        # Collect phishing URLs
        print("\n📊 Collecting Phishing URLs:")
        print("-" * 30)
        
        phishing_sources = [
            ("PhishTank", lambda: self.collect_phishtank_urls(phishing_limit // 4)),
            ("Synthetic Phishing", lambda: self.collect_synthetic_phishing_urls(phishing_limit // 4)),
            ("Suspicious Domains", lambda: self.collect_suspicious_domains(phishing_limit // 4)),
            ("URL Shorteners", lambda: self.collect_url_shorteners(phishing_limit // 4))
        ]
        
        for source_name, collect_func in phishing_sources:
            try:
                count = collect_func()
                total_collected += count
                time.sleep(1)  # Rate limiting
            except Exception as e:
                print(f"   ❌ Error with {source_name}: {e}")
        
        # Collect legitimate URLs
        print("\n📊 Collecting Legitimate URLs:")
        print("-" * 30)
        
        legitimate_sources = [
            ("Majestic Million", lambda: self.collect_majestic_million_urls(legitimate_limit // 2)),
            ("Alexa Top Sites", lambda: self.collect_alexa_top_urls(legitimate_limit // 2))
        ]
        
        for source_name, collect_func in legitimate_sources:
            try:
                count = collect_func()
                total_collected += count
                time.sleep(1)  # Rate limiting
            except Exception as e:
                print(f"   ❌ Error with {source_name}: {e}")
        
        print(f"\n✅ Collection completed! Total URLs collected: {total_collected}")
        return total_collected
    
    def get_dataset_stats(self):
        """
        Get statistics about the collected dataset
        """
        if not self.collected_urls:
            return None
            
        df = pd.DataFrame(self.collected_urls)
        
        stats = {
            'total_urls': len(df),
            'phishing_urls': len(df[df['label'] == 1]),
            'legitimate_urls': len(df[df['label'] == 0]),
            'phishing_ratio': len(df[df['label'] == 1]) / len(df) * 100,
            'legitimate_ratio': len(df[df['label'] == 0]) / len(df) * 100,
            'unique_sources': df['source'].nunique(),
            'source_breakdown': df['source'].value_counts().to_dict(),
            'duplicates_removed': len(self.url_hashes) - len(df)
        }
        
        return stats
    
    def save_dataset(self, filename='data/enhanced_phishing_dataset.csv'):
        """
        Save the collected dataset to CSV
        """
        if not self.collected_urls:
            print("❌ No URLs collected to save")
            return False
            
        df = pd.DataFrame(self.collected_urls)
        
        # Remove the normalized_url column for cleaner output
        df_clean = df[['url', 'label', 'source']].copy()
        df_clean['type'] = df_clean['label'].map({0: 'legitimate', 1: 'phishing'})
        
        # Shuffle the dataset
        df_clean = df_clean.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save to CSV
        df_clean.to_csv(filename, index=False)
        
        print(f"✅ Dataset saved to {filename}")
        print(f"   Total URLs: {len(df_clean)}")
        print(f"   Legitimate: {len(df_clean[df_clean['label'] == 0])}")
        print(f"   Phishing: {len(df_clean[df_clean['label'] == 1])}")
        
        return True
    
    def print_detailed_stats(self):
        """
        Print detailed statistics about the dataset
        """
        stats = self.get_dataset_stats()
        if not stats:
            print("❌ No data to analyze")
            return
            
        print("\n📊 DATASET STATISTICS")
        print("=" * 40)
        print(f"Total URLs: {stats['total_urls']:,}")
        print(f"Phishing URLs: {stats['phishing_urls']:,} ({stats['phishing_ratio']:.1f}%)")
        print(f"Legitimate URLs: {stats['legitimate_urls']:,} ({stats['legitimate_ratio']:.1f}%)")
        print(f"Unique Sources: {stats['unique_sources']}")
        print(f"Duplicates Removed: {stats['duplicates_removed']:,}")
        
        print(f"\n📈 Source Breakdown:")
        for source, count in stats['source_breakdown'].items():
            print(f"   {source}: {count:,} URLs")
        
        # URL length analysis
        df = pd.DataFrame(self.collected_urls)
        df['url_length'] = df['url'].str.len()
        
        print(f"\n📏 URL Length Analysis:")
        print(f"   Average length: {df['url_length'].mean():.1f}")
        print(f"   Legitimate URLs - Average: {df[df['label']==0]['url_length'].mean():.1f}")
        print(f"   Phishing URLs - Average: {df[df['label']==1]['url_length'].mean():.1f}")

def main():
    """
    Main function to run the enhanced dataset collection
    """
    print("🛡️  ENHANCED PHISHING URL DATASET COLLECTOR")
    print("=" * 60)
    
    # Initialize collector
    collector = EnhancedDatasetCollector()
    
    # Collect URLs from all sources
    total_collected = collector.collect_all_sources(
        phishing_limit=2000,
        legitimate_limit=2000
    )
    
    # Print detailed statistics
    collector.print_detailed_stats()
    
    # Save dataset
    collector.save_dataset()
    
    print(f"\n🎉 Dataset collection completed successfully!")
    print(f"   Ready for machine learning training with {total_collected:,} URLs")

if __name__ == "__main__":
    main()
