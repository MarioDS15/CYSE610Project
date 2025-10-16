#!/usr/bin/env python3
"""
Complete Setup Script for Phishing Detection ML System
Downloads datasets, installs dependencies, and sets up the environment
"""

import os
import sys
import subprocess
import urllib.request
import zipfile
import shutil
from pathlib import Path

def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n{description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"SUCCESS: {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR during {description}:")
        print(f"   Command: {command}")
        print(f"   Error: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    print_header("CHECKING PYTHON VERSION")
    
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("ERROR: Python 3.8 or higher is required")
        return False
    
    print("SUCCESS: Python version is compatible")
    return True

def install_dependencies():
    """Install Python dependencies"""
    print_header("INSTALLING PYTHON DEPENDENCIES")
    
    # Check if requirements.txt exists
    requirements_file = "Setup/requirements.txt"
    if not os.path.exists(requirements_file):
        print(f"❌ Requirements file not found: {requirements_file}")
        return False
    
    # Install dependencies
    command = f"pip3 install -r {requirements_file}"
    if not run_command(command, "Installing Python packages"):
        return False
    
    print("SUCCESS: All dependencies installed successfully")
    return True

def create_directories():
    """Create necessary directories"""
    print_header("CREATING DIRECTORIES")
    
    directories = [
        "ML/URL/URL Data",
        "ML/URL/URL Results", 
        "data",
        "logs"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"SUCCESS: Created directory: {directory}")
    
    return True

def download_datasets():
    """Download and set up datasets"""
    print_header("SETTING UP DATASETS")
    
    # Check if enhanced dataset already exists
    enhanced_dataset = "ML/URL/URL Data/enhanced_phishing_dataset.csv"
    if os.path.exists(enhanced_dataset):
        print(f"SUCCESS: Enhanced dataset already exists: {enhanced_dataset}")
        return True
    
    print("Enhanced dataset not found. Running dataset collector...")
    
    # Run the enhanced dataset collector
    if os.path.exists("Setup/enhanced_dataset_collector.py"):
        command = "python3 Setup/enhanced_dataset_collector.py"
        if run_command(command, "Collecting enhanced dataset"):
            print("SUCCESS: Enhanced dataset created successfully")
            return True
        else:
            print("ERROR: Failed to create enhanced dataset")
            return False
    else:
        print("ERROR: Enhanced dataset collector not found")
        return False

def verify_installation():
    """Verify that everything is working"""
    print_header("VERIFYING INSTALLATION")
    
    # Test imports
    try:
        import pandas as pd
        import numpy as np
        import sklearn
        import matplotlib.pyplot as plt
        import seaborn as sns
        print("SUCCESS: All required packages imported successfully")
    except ImportError as e:
        print(f"ERROR: Import error: {e}")
        return False
    
    # Test ML modules
    try:
        sys.path.append('ML')
        sys.path.append('ML/URL')
        from phishing_detector import PhishingDetector
        from url_phishing_detector import URLPhishingDetector
        from url_features import URLFeatureExtractor
        print("SUCCESS: ML modules imported successfully")
    except ImportError as e:
        print(f"ERROR: ML module import error: {e}")
        return False
    
    # Test dataset
    enhanced_dataset = "ML/URL/URL Data/enhanced_phishing_dataset.csv"
    if os.path.exists(enhanced_dataset):
        df = pd.read_csv(enhanced_dataset)
        print(f"SUCCESS: Dataset loaded: {len(df)} URLs")
    else:
        print("ERROR: Enhanced dataset not found")
        return False
    
    print("SUCCESS: Installation verification completed successfully")
    return True

def run_quick_test():
    """Run a quick test to ensure everything works"""
    print_header("RUNNING QUICK TEST")
    
    try:
        # Run the ML test
        command = "python3 ml_test.py"
        if run_command(command, "Running ML test"):
            print("SUCCESS: Quick test completed successfully")
            return True
        else:
            print("ERROR: Quick test failed")
            return False
    except Exception as e:
        print(f"ERROR: Test error: {e}")
        return False

def create_requirements_file():
    """Create a main requirements.txt file in the root"""
    print_header("CREATING MAIN REQUIREMENTS FILE")
    
    # Copy requirements from Setup folder
    setup_requirements = "Setup/requirements.txt"
    main_requirements = "requirements.txt"
    
    if os.path.exists(setup_requirements):
        shutil.copy2(setup_requirements, main_requirements)
        print(f"SUCCESS: Created {main_requirements}")
        return True
    else:
        print(f"ERROR: Source requirements file not found: {setup_requirements}")
        return False

def main():
    """Main setup function"""
    print("PHISHING DETECTION ML SYSTEM - COMPLETE SETUP")
    print("="*60)
    print("This script will set up everything needed for the ML system")
    print("="*60)
    
    # Track success of each step
    steps = [
        ("Python Version Check", check_python_version),
        ("Create Directories", create_directories),
        ("Install Dependencies", install_dependencies),
        ("Download Datasets", download_datasets),
        ("Create Requirements File", create_requirements_file),
        ("Verify Installation", verify_installation),
        ("Run Quick Test", run_quick_test)
    ]
    
    success_count = 0
    total_steps = len(steps)
    
    for step_name, step_function in steps:
        if step_function():
            success_count += 1
        else:
            print(f"\nERROR: Setup failed at step: {step_name}")
            print("Please check the error messages above and try again.")
            return False
    
    # Final summary
    print_header("SETUP COMPLETE")
    print(f"SUCCESS: Successfully completed {success_count}/{total_steps} steps")
    print("\nYour Phishing Detection ML System is ready!")
    print("\nProject Structure:")
    print("   - ML/ - Core ML components")
    print("   - ML/URL/URL Data/ - Datasets")
    print("   - ML/URL/URL Results/ - Test results and graphs")
    print("   - Setup/ - Setup utilities")
    print("\nQuick Start:")
    print("   python3 ml_test.py          # Run ML tests")
    print("   python3 main.py             # Run full application")
    print("   python3 example_usage.py    # See usage examples")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nERROR: Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Unexpected error: {e}")
        sys.exit(1)
