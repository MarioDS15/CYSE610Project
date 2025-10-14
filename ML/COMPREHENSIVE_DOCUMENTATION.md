# Phishing URL Detection System - Comprehensive Documentation

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [File Structure](#file-structure)
3. [Core Files Documentation](#core-files-documentation)
4. [Supporting Files](#supporting-files)
5. [Data Files](#data-files)
6. [Documentation Files](#documentation-files)
7. [Function Reference](#function-reference)
8. [Usage Examples](#usage-examples)

---

## 🎯 Project Overview

This project implements a comprehensive machine learning system for detecting phishing URLs using advanced feature engineering and Random Forest classification. The system extracts 39 features from URLs and achieves high accuracy in distinguishing between legitimate and phishing websites.

**Key Features:**
- 39 engineered features from URL analysis
- Multi-source dataset collection with deduplication
- Random Forest classification with 99%+ accuracy
- Comprehensive evaluation and visualization
- Interactive demo and testing capabilities

---

## 📁 File Structure

```
CYSE610Project/
├── Core System Files
│   ├── phishing_detector.py           # Main ML detection system
│   ├── enhanced_dataset_collector.py  # Multi-source data collection
│   └── main.py                       # Enhanced evaluation system (consolidated)
├── Dataset Management
│   ├── download_dataset.py           # Original dataset creation
│   └── run_experiment.py             # Quick experiment runner
├── Interactive Tools
│   └── demo.py                       # Interactive demo system
├── Data Files
│   ├── data/phishing_dataset.csv     # Original dataset (2,360 URLs)
│   └── data/enhanced_phishing_dataset.csv # Enhanced dataset (2,557 URLs)
├── Configuration
│   └── requirements.txt              # Python dependencies
└── Documentation
    ├── README.md                     # Basic project documentation
    ├── PROJECT_SUMMARY.md            # Project completion summary
    ├── DATASET_EXPANSION_SUMMARY.md  # Dataset expansion details
    └── COMPREHENSIVE_DOCUMENTATION.md # This file
```

---

## 🔧 Core Files Documentation

### 1. `phishing_detector.py` - Main ML Detection System

**Purpose:** Core machine learning system for phishing URL detection with comprehensive feature engineering.

**Class: `PhishingDetector`**

#### Key Methods:

##### `__init__(self)`
- **Purpose:** Initialize the phishing detector with empty feature names, scaler, and model
- **Parameters:** None
- **Returns:** None
- **Usage:** `detector = PhishingDetector()`

##### `extract_features(self, url)`
- **Purpose:** Extract 39 comprehensive features from a single URL
- **Parameters:** 
  - `url` (str): URL to analyze
- **Returns:** Dictionary of features
- **Features Extracted:**
  - **URL Structure (9 features):** Length, dots, hyphens, underscores, slashes, question marks, equals, ampersands, percentages
  - **Domain Analysis (8 features):** Domain length, path length, query length, subdomain count, TLD length, IP detection, suspicious TLD detection
  - **Security Indicators (6 features):** HTTPS/HTTP usage, suspicious keywords, brand impersonation, URL shortener detection
  - **Statistical Features (4 features):** Character ratios, Shannon entropy
  - **Pattern Recognition (12 features):** Mixed case, numbers in domain, path depth, file extensions, query parameters, URL anomalies

##### Helper Methods:

##### `_has_ip_address(self, url)`
- **Purpose:** Detect IP addresses in URLs using regex
- **Parameters:** `url` (str)
- **Returns:** 1 if IP found, 0 otherwise
- **Pattern:** `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`

##### `_has_suspicious_tld(self, tld)`
- **Purpose:** Check for suspicious top-level domains
- **Parameters:** `tld` (str): Top-level domain
- **Returns:** 1 if suspicious, 0 otherwise
- **Suspicious TLDs:** ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'stream']

##### `_is_shortened_url(self, url)`
- **Purpose:** Detect known URL shorteners
- **Parameters:** `url` (str)
- **Returns:** 1 if shortener found, 0 otherwise
- **Shorteners:** ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']

##### `_has_suspicious_keywords(self, url)`
- **Purpose:** Detect suspicious keywords in URLs
- **Parameters:** `url` (str)
- **Returns:** 1 if suspicious keywords found, 0 otherwise
- **Keywords:** ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'validate', 'authenticate', 'bank', 'paypal', 'amazon', 'facebook', 'google', 'apple', 'microsoft', 'support']

##### `_has_numbers_in_domain(self, domain)`
- **Purpose:** Check if domain contains numbers
- **Parameters:** `domain` (str)
- **Returns:** 1 if numbers found, 0 otherwise

##### `_has_mixed_case(self, domain)`
- **Purpose:** Detect mixed case in domain names (suspicious)
- **Parameters:** `domain` (str)
- **Returns:** 1 if mixed case, 0 otherwise

##### `_calculate_entropy(self, text)`
- **Purpose:** Calculate Shannon entropy of text
- **Parameters:** `text` (str)
- **Returns:** Entropy value (float)
- **Formula:** H(X) = -Σ P(xi) * log2(P(xi))

##### `_has_suspicious_file_extension(self, path)`
- **Purpose:** Detect suspicious file extensions
- **Parameters:** `path` (str): URL path
- **Returns:** 1 if suspicious extension found, 0 otherwise
- **Suspicious Extensions:** ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif']

##### `_has_suspicious_params(self, query)`
- **Purpose:** Detect suspicious query parameters
- **Parameters:** `query` (str): URL query string
- **Returns:** 1 if suspicious parameters found, 0 otherwise
- **Suspicious Parameters:** ['redirect', 'url', 'link', 'goto', 'target']

##### `_has_suspicious_brand_usage(self, url)`
- **Purpose:** Detect potential brand impersonation
- **Parameters:** `url` (str)
- **Returns:** 1 if brand names found, 0 otherwise
- **Brands:** ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'ebay']

##### `create_dataset(self, urls, labels)`
- **Purpose:** Create feature matrix from list of URLs
- **Parameters:** 
  - `urls` (list): List of URLs
  - `labels` (list): List of labels (0=legitimate, 1=phishing)
- **Returns:** DataFrame with extracted features
- **Features:** Progress tracking, error handling, feature extraction

##### `train_model(self, X_train, y_train)`
- **Purpose:** Train Random Forest model on training data
- **Parameters:** 
  - `X_train` (DataFrame): Training features
  - `y_train` (array): Training labels
- **Returns:** Feature importance DataFrame
- **Model Configuration:**
  - Algorithm: RandomForestClassifier
  - Estimators: 100
  - Max depth: 10
  - Min samples split: 5
  - Min samples leaf: 2
  - Random state: 42

##### `evaluate_model(self, X_test, y_test)`
- **Purpose:** Evaluate trained model performance
- **Parameters:** 
  - `X_test` (DataFrame): Test features
  - `y_test` (array): Test labels
- **Returns:** Dictionary with metrics and predictions
- **Metrics:** Accuracy, classification report, confusion matrix

##### `plot_results(self, feature_importance, results)`
- **Purpose:** Create visualization plots of results
- **Parameters:** 
  - `feature_importance` (DataFrame): Feature importance data
  - `results` (dict): Evaluation results
- **Returns:** None
- **Plots:** Feature importance, confusion matrix, probability distribution, performance by class

##### `main()`
- **Purpose:** Main function demonstrating the system
- **Parameters:** None
- **Returns:** None
- **Process:** Creates synthetic dataset, trains model, evaluates performance, tests examples

---

### 2. `enhanced_dataset_collector.py` - Multi-Source Data Collection

**Purpose:** Advanced dataset collection system that integrates multiple real-world sources with deduplication.

**Class: `EnhancedDatasetCollector`**

#### Key Methods:

##### `__init__(self)`
- **Purpose:** Initialize collector with empty collections and hash set for deduplication
- **Parameters:** None
- **Returns:** None
- **Attributes:** collected_urls, url_hashes, source_stats

##### `normalize_url(self, url)`
- **Purpose:** Normalize URL for consistent comparison and deduplication
- **Parameters:** `url` (str): URL to normalize
- **Returns:** Normalized URL string
- **Normalization:** Protocol addition, lowercase conversion, www removal, trailing slash removal

##### `get_url_hash(self, url)`
- **Purpose:** Generate MD5 hash for URL deduplication
- **Parameters:** `url` (str)
- **Returns:** MD5 hash string
- **Process:** Normalize URL → Generate MD5 hash

##### `add_url(self, url, label, source)`
- **Purpose:** Add URL to collection with deduplication
- **Parameters:** 
  - `url` (str): URL to add
  - `label` (int): 0=legitimate, 1=phishing
  - `source` (str): Data source name
- **Returns:** Boolean indicating if URL was added
- **Process:** Check hash → Add if unique → Track statistics

##### Data Collection Methods:

##### `collect_phishtank_urls(self, limit=1000)`
- **Purpose:** Collect real phishing URLs from PhishTank API
- **Parameters:** `limit` (int): Maximum URLs to collect
- **Returns:** Number of URLs collected
- **API Endpoint:** http://data.phishtank.com/data/online-valid.json
- **Features:** Real-time phishing data, community verified

##### `collect_majestic_million_urls(self, limit=1000)`
- **Purpose:** Collect legitimate URLs from Majestic Million domains
- **Parameters:** `limit` (int): Maximum URLs to collect
- **Returns:** Number of URLs collected
- **Domains:** Top 40 legitimate domains (Google, YouTube, Facebook, etc.)
- **Paths:** Common legitimate paths (/home, /about, /contact, etc.)

##### `collect_alexa_top_urls(self, limit=1000)`
- **Purpose:** Collect legitimate URLs from Alexa Top Sites
- **Parameters:** `limit` (int): Maximum URLs to collect
- **Returns:** Number of URLs collected
- **Domains:** Top 50 Alexa-ranked domains
- **Paths:** Extended legitimate paths (/careers, /press, /investor, etc.)

##### `collect_synthetic_phishing_urls(self, limit=1000)`
- **Purpose:** Generate realistic synthetic phishing URLs
- **Parameters:** `limit` (int): Maximum URLs to generate
- **Returns:** Number of URLs generated
- **Process:** 
  - Brand variations (goog1e, amaz0n, paypa1)
  - Suspicious TLDs (.tk, .ml, .ga, .cf)
  - Phishing patterns (security-alert, account-verification)

##### `collect_suspicious_domains(self, limit=500)`
- **Purpose:** Collect URLs with suspicious domain patterns
- **Parameters:** `limit` (int): Maximum URLs to collect
- **Returns:** Number of URLs collected
- **Patterns:** IP addresses, suspicious subdomains, suspicious TLD combinations

##### `collect_url_shorteners(self, limit=200)`
- **Purpose:** Collect URLs from known URL shorteners
- **Parameters:** `limit` (int): Maximum URLs to collect
- **Returns:** Number of URLs collected
- **Shorteners:** bit.ly, tinyurl.com, goo.gl, t.co, ow.ly, is.gd
- **Paths:** Suspicious paths (/secure, /login, /verify, /confirm)

##### `collect_all_sources(self, phishing_limit=2000, legitimate_limit=2000)`
- **Purpose:** Collect URLs from all sources with rate limiting
- **Parameters:** 
  - `phishing_limit` (int): Total phishing URLs to collect
  - `legitimate_limit` (int): Total legitimate URLs to collect
- **Returns:** Total URLs collected
- **Process:** Collect from all sources → Rate limiting → Error handling

##### Analysis Methods:

##### `get_dataset_stats(self)`
- **Purpose:** Get comprehensive statistics about collected dataset
- **Parameters:** None
- **Returns:** Dictionary with statistics
- **Statistics:** Total URLs, class distribution, source breakdown, duplicates removed

##### `save_dataset(self, filename='data/enhanced_phishing_dataset.csv')`
- **Purpose:** Save collected dataset to CSV file
- **Parameters:** `filename` (str): Output file path
- **Returns:** Boolean indicating success
- **Process:** Clean data → Shuffle → Add type column → Save CSV

##### `print_detailed_stats(self)`
- **Purpose:** Print detailed dataset statistics
- **Parameters:** None
- **Returns:** None
- **Output:** Dataset statistics, source breakdown, URL length analysis

##### `main()`
- **Purpose:** Main function to run dataset collection
- **Parameters:** None
- **Returns:** None
- **Process:** Initialize collector → Collect from all sources → Print stats → Save dataset

---

### 3. `main.py` - Enhanced Evaluation System (Consolidated)

**Purpose:** Advanced evaluation system using multi-source dataset with comprehensive analysis.

#### Key Functions:

##### `load_or_create_enhanced_dataset()`
- **Purpose:** Load existing enhanced dataset or create new one
- **Parameters:** None
- **Returns:** DataFrame with enhanced dataset
- **Process:** Check file existence → Load or create → Return dataset

##### `analyze_enhanced_dataset(df)`
- **Purpose:** Comprehensive analysis of enhanced dataset characteristics
- **Parameters:** `df` (DataFrame): Enhanced dataset
- **Returns:** Enhanced DataFrame with additional columns
- **Analysis:** Class distribution, source analysis, URL length, domain statistics, TLD analysis

##### `enhanced_feature_analysis(detector, X, y)`
- **Purpose:** Enhanced feature analysis with source breakdown
- **Parameters:** 
  - `detector` (PhishingDetector): Trained detector
  - `X` (DataFrame): Features
  - `y` (array): Labels
- **Returns:** Feature importance DataFrame
- **Analysis:** Feature importance by category, total features extracted

##### `cross_validate_by_source(detector, df, X, y)`
- **Purpose:** Cross-validation analysis by data source
- **Parameters:** 
  - `detector` (PhishingDetector): Trained detector
  - `df` (DataFrame): Dataset with source information
  - `X` (DataFrame): Features
  - `y` (array): Labels
- **Returns:** None
- **Process:** 5-fold cross-validation → Source-specific analysis → Performance reporting

##### `enhanced_evaluation(detector, X_test, y_test, df_test)`
- **Purpose:** Enhanced evaluation with source-aware analysis
- **Parameters:** 
  - `detector` (PhishingDetector): Trained detector
  - `X_test` (DataFrame): Test features
  - `y_test` (array): Test labels
  - `df_test` (DataFrame): Test dataset with source information
- **Returns:** Dictionary with comprehensive metrics
- **Metrics:** Accuracy, precision, recall, F1-score, ROC AUC, source-specific performance

##### `plot_enhanced_results(feature_importance, results, df)`
- **Purpose:** Create enhanced visualizations with source analysis
- **Parameters:** 
  - `feature_importance` (DataFrame): Feature importance data
  - `results` (dict): Evaluation results
  - `df` (DataFrame): Dataset for source analysis
- **Returns:** None
- **Plots:** 6 subplots including feature importance, confusion matrix, ROC curve, source distribution, URL length distribution, performance metrics

##### `test_enhanced_system(detector, df)`
- **Purpose:** Test enhanced system on diverse URL samples from all sources
- **Parameters:** 
  - `detector` (PhishingDetector): Trained detector
  - `df` (DataFrame): Dataset for sampling
- **Returns:** None
- **Process:** Sample URLs from each source → Test predictions → Calculate source-specific performance

##### `main()`
- **Purpose:** Main function for enhanced phishing detection system
- **Parameters:** None
- **Returns:** None
- **Process:** Load dataset → Analyze → Extract features → Train → Cross-validate → Evaluate → Plot → Test → Summary

---

### 4. `main.py` - Original Evaluation System

**Purpose:** Original evaluation system with comprehensive metrics and real-world testing.

#### Key Functions:

##### `analyze_dataset(df)`
- **Purpose:** Analyze basic dataset characteristics
- **Parameters:** `df` (DataFrame): Dataset to analyze
- **Returns:** Enhanced DataFrame with analysis columns
- **Analysis:** Class distribution, URL length statistics, domain statistics

##### `enhanced_evaluation(detector, X_test, y_test)`
- **Purpose:** Enhanced model evaluation with additional metrics
- **Parameters:** 
  - `detector` (PhishingDetector): Trained detector
  - `X_test` (DataFrame): Test features
  - `y_test` (array): Test labels
- **Returns:** Dictionary with comprehensive metrics
- **Metrics:** Accuracy, precision, recall, F1-score, ROC AUC, specificity, sensitivity

##### `plot_enhanced_results(feature_importance, results)`
- **Purpose:** Create enhanced visualizations
- **Parameters:** 
  - `feature_importance` (DataFrame): Feature importance data
  - `results` (dict): Evaluation results
- **Returns:** None
- **Plots:** 6 subplots with comprehensive analysis

##### `test_real_world_examples(detector)`
- **Purpose:** Test model on real-world example URLs
- **Parameters:** `detector` (PhishingDetector): Trained detector
- **Returns:** None
- **Test Cases:** 15 diverse URLs including legitimate, phishing, and edge cases

##### `main()`
- **Purpose:** Main function to run complete phishing detection system
- **Parameters:** None
- **Returns:** None
- **Process:** Load dataset → Analyze → Extract features → Train → Evaluate → Plot → Test → Summary

---

## 🛠️ Supporting Files

### 5. `download_dataset.py` - Original Dataset Creation

**Purpose:** Script to create the original synthetic dataset for demonstration.

#### Key Functions:

##### `download_phishing_dataset()`
- **Purpose:** Create realistic synthetic dataset with legitimate and phishing URLs
- **Parameters:** None
- **Returns:** DataFrame with synthetic dataset
- **Process:** 
  - Generate legitimate URLs from real patterns
  - Generate phishing URLs with brand impersonation
  - Combine and shuffle dataset
  - Save to CSV

##### `load_dataset()`
- **Purpose:** Load existing dataset or create new one
- **Parameters:** None
- **Returns:** DataFrame with dataset
- **Process:** Check file existence → Load or create → Return dataset

---

### 6. `demo.py` - Interactive Demo System

**Purpose:** Interactive demonstration system for testing URLs in real-time.

#### Key Functions:

##### `interactive_demo()`
- **Purpose:** Interactive demonstration allowing users to input URLs for analysis
- **Parameters:** None
- **Returns:** None
- **Process:** 
  - Initialize and train detector
  - Interactive loop for URL input
  - Real-time analysis and feature explanation
  - Top contributing features display

##### `quick_test()`
- **Purpose:** Quick test with predefined URLs
- **Parameters:** None
- **Returns:** None
- **Process:** 
  - Initialize and train detector
  - Test on 6 predefined URLs
  - Display results with accuracy indicators

##### `main()`
- **Purpose:** Main function with command-line argument handling
- **Parameters:** None
- **Returns:** None
- **Usage:** `python demo.py` (interactive) or `python demo.py test` (quick test)

---

### 7. `run_experiment.py` - Quick Experiment Runner

**Purpose:** Automated script to run the complete experiment pipeline.

#### Key Functions:

##### `run_experiment()`
- **Purpose:** Run the complete phishing detection experiment
- **Parameters:** None
- **Returns:** None
- **Process:** 
  - Check dataset existence
  - Create dataset if needed
  - Run main phishing detection system
  - Display results summary

---

## 📊 Data Files

### 8. `data/phishing_dataset.csv` - Original Dataset
- **Size:** 2,360 URLs
- **Distribution:** 1,020 legitimate (43.2%), 1,340 phishing (56.8%)
- **Sources:** Synthetic generation
- **Features:** URL, label, type columns
- **Usage:** Original system training and testing

### 9. `data/enhanced_phishing_dataset.csv` - Enhanced Dataset
- **Size:** 2,557 URLs
- **Distribution:** 1,500 legitimate (58.7%), 1,057 phishing (41.3%)
- **Sources:** 6 real-world sources
- **Features:** URL, label, source, type columns
- **Usage:** Enhanced system training and testing

---

## 📋 Configuration Files

### 10. `requirements.txt` - Python Dependencies
```
pandas==2.1.4
numpy==1.24.3
scikit-learn==1.3.2
requests==2.31.0
tldextract==5.1.1
urllib3==2.1.0
matplotlib==3.7.2
seaborn==0.12.2
plotly==5.17.0
joblib==1.3.2
```

---

## 📚 Documentation Files

### 11. `README.md` - Basic Project Documentation
- Project overview and features
- Installation instructions
- Usage examples
- File structure overview

### 12. `PROJECT_SUMMARY.md` - Project Completion Summary
- Detailed project overview
- Key achievements and metrics
- Technical implementation details
- Results interpretation

### 13. `DATASET_EXPANSION_SUMMARY.md` - Dataset Expansion Details
- Dataset comparison (before/after)
- Multi-source integration details
- Performance improvements
- Technical enhancements

---

## 🔧 Function Reference

### Core Detection Functions

| Function | File | Purpose | Parameters | Returns |
|----------|------|---------|------------|---------|
| `extract_features()` | phishing_detector.py | Extract 39 features from URL | url (str) | dict |
| `train_model()` | phishing_detector.py | Train Random Forest model | X_train, y_train | DataFrame |
| `evaluate_model()` | phishing_detector.py | Evaluate model performance | X_test, y_test | dict |
| `normalize_url()` | enhanced_dataset_collector.py | Normalize URL for deduplication | url (str) | str |
| `collect_all_sources()` | enhanced_dataset_collector.py | Collect from all data sources | limits | int |

### Analysis Functions

| Function | File | Purpose | Parameters | Returns |
|----------|------|---------|------------|---------|
| `analyze_dataset()` | main.py | Analyze dataset characteristics | df | DataFrame |
| `enhanced_evaluation()` | main.py | Enhanced model evaluation | detector, X_test, y_test | dict |
| `cross_validate_by_source()` | main.py | Cross-validation by source | detector, df, X, y | None |
| `test_real_world_examples()` | main.py | Test on real URLs | detector | None |

### Utility Functions

| Function | File | Purpose | Parameters | Returns |
|----------|------|---------|------------|---------|
| `load_dataset()` | download_dataset.py | Load or create dataset | None | DataFrame |
| `save_dataset()` | enhanced_dataset_collector.py | Save dataset to CSV | filename | bool |
| `plot_results()` | phishing_detector.py | Create visualizations | feature_importance, results | None |
| `interactive_demo()` | demo.py | Interactive URL testing | None | None |

---

## 💡 Usage Examples

### Basic Usage

```python
from phishing_detector import PhishingDetector

# Initialize detector
detector = PhishingDetector()

# Extract features from a URL
features = detector.extract_features("https://suspicious-site.tk/login")

# Train on dataset
X = detector.create_dataset(urls, labels)
detector.train_model(X_train, y_train)

# Evaluate performance
results = detector.evaluate_model(X_test, y_test)
```

### Enhanced Dataset Collection

```python
from enhanced_dataset_collector import EnhancedDatasetCollector

# Initialize collector
collector = EnhancedDatasetCollector()

# Collect from all sources
total_collected = collector.collect_all_sources(
    phishing_limit=2000,
    legitimate_limit=2000
)

# Save dataset
collector.save_dataset('data/my_dataset.csv')
```

### Interactive Demo

```bash
# Run interactive demo
python demo.py

# Run quick test
python demo.py test
```

### Complete Experiment

```bash
# Run enhanced system (now the default)
python main.py

# Run complete experiment
python run_experiment.py
```

---

## 🎯 Key Features Summary

### Feature Engineering (39 Features)
- **URL Structure:** Length, character counts, special characters
- **Domain Analysis:** Domain characteristics, TLD analysis, subdomain detection
- **Security Indicators:** HTTPS usage, suspicious keywords, brand impersonation
- **Statistical Measures:** Character ratios, entropy calculations
- **Pattern Recognition:** Mixed case, numbers, file extensions, parameters

### Data Sources (Enhanced System)
- **PhishTank:** Real verified phishing URLs (500 URLs)
- **Majestic Million:** Top legitimate domains (760 URLs)
- **Alexa Top Sites:** Alexa-ranked domains (740 URLs)
- **Synthetic Phishing:** Generated phishing patterns (500 URLs)
- **URL Shorteners:** Known shortener services (42 URLs)
- **Suspicious Domains:** Domain anomalies (15 URLs)

### Model Performance
- **Algorithm:** Random Forest Classifier
- **Accuracy:** 99.48% (Enhanced), 100% (Original)
- **Cross-Validation:** 99.73% (±0.19%)
- **Features:** 39 engineered features
- **Train/Test Split:** 85%/15%

### Output Files
- **Datasets:** CSV files with URLs and labels
- **Visualizations:** PNG files with comprehensive plots
- **Documentation:** Multiple markdown files with detailed explanations

---

## 🔍 Troubleshooting

### Common Issues

1. **Missing Dependencies:** Install requirements with `pip install -r requirements.txt`
2. **Dataset Not Found:** Run `python download_dataset.py` or `python enhanced_dataset_collector.py`
3. **Memory Issues:** Reduce dataset size or use smaller feature sets
4. **API Errors:** Check internet connection for PhishTank API access

### Performance Optimization

1. **Feature Selection:** Use top features only for faster processing
2. **Dataset Size:** Reduce dataset size for quicker experiments
3. **Model Parameters:** Adjust Random Forest parameters for speed vs. accuracy trade-off

---

This comprehensive documentation provides complete coverage of all files, functions, and usage patterns in the phishing URL detection system. Each component is designed to work independently or as part of the complete system, providing flexibility for different use cases and research needs.
