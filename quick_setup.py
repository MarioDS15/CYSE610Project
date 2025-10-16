#!/usr/bin/env python3
"""
Quick Setup Check for Phishing Detection ML System
Checks what's needed and provides setup instructions
"""

import os
import sys
import subprocess

def check_python_packages():
    """Check if required Python packages are installed"""
    print("Checking Python packages...")
    
    required_packages = [
        'pandas', 'numpy', 'sklearn', 'matplotlib', 
        'seaborn', 'requests', 'tldextract', 'joblib'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'sklearn':
                import sklearn
            else:
                __import__(package)
            print(f"  OK {package}")
        except ImportError:
            print(f"  MISSING {package}")
            missing_packages.append(package)
    
    return missing_packages

def check_datasets():
    """Check if datasets exist"""
    print("\nChecking datasets...")
    
    datasets = [
        "ML/URL/URL Data/enhanced_phishing_dataset.csv",
        "ML/URL/URL Data/phishing_dataset.csv"
    ]
    
    found_datasets = []
    
    for dataset in datasets:
        if os.path.exists(dataset):
            print(f"  OK {dataset}")
            found_datasets.append(dataset)
        else:
            print(f"  MISSING {dataset}")
    
    return found_datasets

def check_directories():
    """Check if required directories exist"""
    print("\nChecking directories...")
    
    directories = [
        "ML",
        "ML/URL",
        "ML/URL/URL Data",
        "ML/URL/URL Results",
        "Setup"
    ]
    
    missing_dirs = []
    
    for directory in directories:
        if os.path.exists(directory):
            print(f"  OK {directory}")
        else:
            print(f"  MISSING {directory}")
            missing_dirs.append(directory)
    
    return missing_dirs

def check_ml_modules():
    """Check if ML modules can be imported"""
    print("\nChecking ML modules...")
    
    try:
        sys.path.append('ML')
        sys.path.append('ML/URL')
        
        from phishing_detector import PhishingDetector
        print("  OK phishing_detector")
        
        from url_phishing_detector import URLPhishingDetector
        print("  OK url_phishing_detector")
        
        from url_features import URLFeatureExtractor
        print("  OK url_features")
        
        return True
    except ImportError as e:
        print(f"  ERROR ML modules: {e}")
        return False

def provide_setup_instructions(missing_packages, found_datasets, missing_dirs, ml_modules_ok):
    """Provide setup instructions based on what's missing"""
    print("\n" + "="*60)
    print(" SETUP INSTRUCTIONS")
    print("="*60)
    
    if missing_packages:
        print(f"\nInstall missing Python packages:")
        print(f"   pip3 install {' '.join(missing_packages)}")
        print(f"   OR")
        print(f"   pip3 install -r Setup/requirements.txt")
    
    if not found_datasets:
        print(f"\nDownload datasets:")
        print(f"   python3 Setup/enhanced_dataset_collector.py")
    
    if missing_dirs:
        print(f"\nCreate missing directories:")
        for directory in missing_dirs:
            print(f"   mkdir -p {directory}")
    
    if not ml_modules_ok:
        print(f"\nFix ML module imports:")
        print(f"   Check that ML/__init__.py exists")
        print(f"   Verify import paths in your scripts")
    
    if not missing_packages and found_datasets and not missing_dirs and ml_modules_ok:
        print("\nEverything looks good! Your system is ready to use.")
        print("\nQuick start commands:")
        print("   python3 ml_test.py          # Run ML tests")
        print("   python3 main.py             # Run full application")
        print("   python3 example_usage.py    # See usage examples")

def main():
    """Main function"""
    print("PHISHING DETECTION ML SYSTEM - QUICK SETUP CHECK")
    print("="*60)
    
    # Run all checks
    missing_packages = check_python_packages()
    found_datasets = check_datasets()
    missing_dirs = check_directories()
    ml_modules_ok = check_ml_modules()
    
    # Provide instructions
    provide_setup_instructions(missing_packages, found_datasets, missing_dirs, ml_modules_ok)

if __name__ == "__main__":
    main()
