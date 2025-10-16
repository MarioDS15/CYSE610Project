# Setup Guide for Phishing Detection ML System

## Quick Setup

### Option 1: Quick Check (Recommended)
```bash
python3 quick_setup.py
```
This will check what's installed and provide specific instructions for what's missing.

### Option 2: Complete Setup
```bash
python3 setup_everything.py
```
This will automatically install everything needed (requires pip3).

## 📋 Manual Setup

### 1. Install Python Dependencies
```bash
pip3 install -r Setup/requirements.txt
```

### 2. Download Datasets
```bash
python3 Setup/enhanced_dataset_collector.py
```

### 3. Create Directories (if needed)
```bash
mkdir -p ML/URL/URL\ Data
mkdir -p ML/URL/URL\ Results
mkdir -p data
mkdir -p logs
```

## Verify Installation

Run the quick check to verify everything is working:
```bash
python3 quick_setup.py
```

## 🚀 Quick Start

Once setup is complete, you can run:

```bash
# Run ML tests
python3 ml_test.py

# Run full application
python3 main.py

# See usage examples
python3 example_usage.py
```

## Project Structure

```
CYSE610Project/
├── setup_everything.py          # Complete setup script
├── quick_setup.py               # Quick setup check
├── ml_test.py                   # ML testing script
├── main.py                      # Full application
├── example_usage.py             # Usage examples
├── ML/                          # Core ML components
│   ├── __init__.py
│   ├── phishing_detector.py
│   └── URL/
│       ├── __init__.py
│       ├── url_phishing_detector.py
│       ├── url_features.py
│       ├── URL Data/            # Datasets
│       └── URL Results/         # Test results and graphs
├── Setup/                       # Setup utilities
│   ├── requirements.txt
│   ├── download_dataset.py
│   └── enhanced_dataset_collector.py
└── requirements.txt             # Main requirements file
```

## 🔧 Troubleshooting

### Import Errors
- Make sure `ML/__init__.py` exists
- Check that Python path includes ML directories
- Verify all dependencies are installed

### Dataset Issues
- Run `python3 Setup/enhanced_dataset_collector.py`
- Check that `ML/URL/URL Data/enhanced_phishing_dataset.csv` exists

### Permission Errors
- Use `pip3` instead of `pip`
- Check file permissions in the project directory

## What Gets Installed

- **Python Packages**: pandas, numpy, scikit-learn, matplotlib, seaborn, requests, tldextract, joblib
- **Datasets**: Enhanced phishing dataset (2,557 URLs from multiple sources)
- **Directories**: All necessary folders for data and results
- **ML Modules**: All core ML components for phishing detection

## 🎯 Ready to Use!

Once setup is complete, your phishing detection ML system will be ready for:
- Testing ML models
- Running full applications
- Generating results and graphs
- Integration into other projects
