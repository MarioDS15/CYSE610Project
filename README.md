# Phishing URL Detection System

A machine learning system that uses advanced feature engineering to detect phishing URLs with high accuracy.

## Features

### Comprehensive Feature Design
The system extracts **40+ features** from URLs including:

**URL Structure Features:**
- URL length, number of dots, hyphens, underscores
- Number of slashes, question marks, equals, ampersands
- Path depth, file extensions, query parameters

**Domain Analysis:**
- Domain length, subdomain count
- TLD analysis and suspicious TLD detection
- IP address detection in URLs
- Mixed case detection in domains

**Security Indicators:**
- HTTPS/HTTP usage
- Suspicious keywords detection
- Brand impersonation detection
- URL shortener identification

**Statistical Features:**
- Character ratios (digits, letters, special characters)
- Shannon entropy calculation
- Suspicious parameter detection

**Pattern Recognition:**
- Double slash detection
- Trailing slash analysis
- Suspicious file extension detection

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the phishing detector:
```bash
python phishing_detector.py
```

## Dataset

The system is designed to work with real phishing datasets. For demonstration purposes, it includes synthetic data generation, but you can easily integrate real datasets like:

- **PhiUSIIL Phishing URL Dataset** (UCI ML Repository)
- **Phishing Websites Dataset** (Mendeley)
- **Phishing Attack Dataset** (IEEE DataPort)

## Model Performance

The system uses a **Random Forest Classifier** with:
- 85% training data / 15% testing data split
- Feature scaling and normalization
- Cross-validation for robust evaluation

### Evaluation Metrics
- Accuracy
- Precision, Recall, F1-Score
- Confusion Matrix
- Feature Importance Analysis

## Usage Example

```python
from phishing_detector import PhishingDetector

detector = PhishingDetector()

# Extract features from a URL
features = detector.extract_features("https://suspicious-site.com/login")

# Train on your dataset
X = detector.create_dataset(urls, labels)
detector.train_model(X_train, y_train)

# Evaluate performance
results = detector.evaluate_model(X_test, y_test)
```

## Output

The system generates:
- Detailed classification reports
- Feature importance rankings
- Confusion matrix visualizations
- Performance metrics by class
- Probability distributions

## File Structure

```
CYSE610Project/
├── phishing_detector.py    # Main detection system
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── phishing_detection_results.png  # Generated visualizations
```

## Contributing

Feel free to extend the feature set or improve the model architecture. The modular design makes it easy to add new features or try different algorithms.

