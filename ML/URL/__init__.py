"""
URL-based Phishing Detection Module

This module provides URL-specific phishing detection functionality,
including feature extraction, model training, and analysis.
"""

from .url_phishing_detector import URLPhishingDetector
from .url_features import URLFeatureExtractor, extract_all_url_features
from .url_analyzer import URLAnalyzer, quick_url_check
from .url_csv_exporter import URLFeatureExporter, quick_export_url, quick_export_urls

__version__ = "1.0.0"
__author__ = "CYSE 610 Project"

__all__ = [
    'URLPhishingDetector',
    'URLFeatureExtractor', 
    'extract_all_url_features',
    'URLAnalyzer',
    'quick_url_check',
    'URLFeatureExporter',
    'quick_export_url',
    'quick_export_urls'
]
