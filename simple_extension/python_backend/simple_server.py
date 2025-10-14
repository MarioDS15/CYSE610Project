#!/usr/bin/env python3
"""
Simple Flask server to receive data from Chrome extension
and use existing phishing detection code
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Add the parent directory to path to import our existing ML code
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from ML.phishing_detector import PhishingDetector
import pandas as pd
import numpy as np

app = Flask(__name__)
CORS(app)  # Allow requests from extension

# Initialize the detector (this will use your existing code)
detector = None

def initialize_detector():
    """Initialize the phishing detector with training data"""
    global detector
    try:
        print("Initializing phishing detector...")
        detector = PhishingDetector()
        
        # Load your existing dataset
        from Setup.enhanced_dataset_collector import EnhancedDatasetCollector
        import pandas as pd
        
        # Try to load existing dataset or create a small one
        dataset_path = '../../data/enhanced_phishing_dataset.csv'
        if os.path.exists(dataset_path):
            print("Loading existing dataset...")
            df = pd.read_csv(dataset_path)
        else:
            print("Creating small dataset for demo...")
            # Create a small demo dataset
            collector = EnhancedDatasetCollector()
            collector.collect_all_sources(phishing_limit=100, legitimate_limit=100)
            collector.save_dataset(dataset_path)
            df = pd.read_csv(dataset_path)
        
        # Train the model
        print("Training model...")
        X = detector.create_dataset(df['url'].tolist(), df['label'].tolist())
        y = np.array(df['label'].tolist())
        detector.train_model(X, y)
        
        print("Detector ready!")
        return True
    except Exception as e:
        print(f"Error initializing detector: {e}")
        return False

@app.route('/check', methods=['POST'])
def check_url():
    """Check if URL is phishing"""
    try:
        data = request.json
        url = data.get('url', '')
        html = data.get('html', '')
        css = data.get('css', '')
        
        if not detector:
            return jsonify({
                'is_phishing': False,
                'confidence': 0.0,
                'error': 'Detector not initialized'
            })
        
        # Use your existing URL analysis
        features = detector.extract_features(url)
        X_sample = pd.DataFrame([features])
        X_scaled = detector.scaler.transform(X_sample)
        
        # Get prediction
        prediction = detector.model.predict(X_scaled)[0]
        probability = detector.model.predict_proba(X_scaled)[0]
        
        # Simple design analysis (basic HTML/CSS features)
        design_features = analyze_design_features(html, css)
        
        # Combine results (simple approach)
        final_confidence = probability[1] if prediction == 1 else probability[0]
        
        # Adjust based on design features
        if design_features['suspicious_design']:
            final_confidence = min(1.0, final_confidence + 0.2)
        
        is_phishing = final_confidence > 0.7
        
        return jsonify({
            'is_phishing': bool(is_phishing),
            'confidence': float(final_confidence),
            'url_features': features,
            'design_features': design_features
        })
        
    except Exception as e:
        print(f"Error checking URL: {e}")
        return jsonify({
            'is_phishing': False,
            'confidence': 0.0,
            'error': str(e)
        })

def analyze_design_features(html, css):
    """Simple design feature analysis"""
    features = {
        'suspicious_design': False,
        'form_count': 0,
        'input_count': 0,
        'has_suspicious_keywords': False
    }
    
    try:
        # Count forms and inputs
        features['form_count'] = html.lower().count('<form')
        features['input_count'] = html.lower().count('<input')
        
        # Check for suspicious keywords in HTML
        suspicious_keywords = ['password', 'login', 'verify', 'secure', 'account', 'bank']
        html_lower = html.lower()
        for keyword in suspicious_keywords:
            if keyword in html_lower:
                features['has_suspicious_keywords'] = True
                break
        
        # Simple heuristic: lots of forms + suspicious keywords = suspicious
        if features['form_count'] > 2 and features['has_suspicious_keywords']:
            features['suspicious_design'] = True
            
    except Exception as e:
        print(f"Error analyzing design: {e}")
    
    return features

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'detector_ready': detector is not None})

if __name__ == '__main__':
    print("Starting Simple Phish Detection Server...")
    
    if initialize_detector():
        print("Server ready at http://localhost:5000")
        print("Extension can now send data to this server")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("Failed to initialize detector. Server not started.")
