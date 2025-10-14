#!/usr/bin/env python3
"""
Main script to run the complete phishing detection system
with real dataset loading and comprehensive evaluation
"""

from phishing_detector import PhishingDetector
from download_dataset import load_dataset
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_auc_score, roc_curve
import warnings
warnings.filterwarnings('ignore')

def analyze_dataset(df):
    """
    Analyze the dataset characteristics
    """
    print("=== Dataset Analysis ===")
    print(f"Total URLs: {len(df)}")
    print(f"Legitimate URLs: {len(df[df['label'] == 0])} ({len(df[df['label'] == 0])/len(df)*100:.1f}%)")
    print(f"Phishing URLs: {len(df[df['label'] == 1])} ({len(df[df['label'] == 1])/len(df)*100:.1f}%)")
    
    # URL length analysis
    df['url_length'] = df['url'].str.len()
    print(f"\nURL Length Statistics:")
    print(f"Average URL length: {df['url_length'].mean():.1f}")
    print(f"Legitimate URLs - Average length: {df[df['label']==0]['url_length'].mean():.1f}")
    print(f"Phishing URLs - Average length: {df[df['label']==1]['url_length'].mean():.1f}")
    
    # Domain analysis
    df['domain'] = df['url'].apply(lambda x: x.split('/')[2] if '://' in x else x.split('/')[0])
    print(f"\nDomain Statistics:")
    print(f"Unique domains: {df['domain'].nunique()}")
    
    return df

def enhanced_evaluation(detector, X_test, y_test):
    """
    Enhanced model evaluation with additional metrics
    """
    print("\n=== Enhanced Model Evaluation ===")
    
    # Scale test features
    X_test_scaled = detector.scaler.transform(X_test)
    
    # Make predictions
    y_pred = detector.model.predict(X_test_scaled)
    y_pred_proba = detector.model.predict_proba(X_test_scaled)
    
    # Basic metrics
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    # ROC AUC
    roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
    
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-Score: {f1:.4f}")
    print(f"ROC AUC: {roc_auc:.4f}")
    
    # Confusion Matrix
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"True Negatives (Legitimate): {cm[0,0]}")
    print(f"False Positives: {cm[0,1]}")
    print(f"False Negatives: {cm[1,0]}")
    print(f"True Positives (Phishing): {cm[1,1]}")
    
    # Calculate additional metrics
    tn, fp, fn, tp = cm.ravel()
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0
    
    print(f"\nAdditional Metrics:")
    print(f"Specificity (True Negative Rate): {specificity:.4f}")
    print(f"Sensitivity (True Positive Rate): {sensitivity:.4f}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc,
        'specificity': specificity,
        'sensitivity': sensitivity,
        'predictions': y_pred,
        'probabilities': y_pred_proba,
        'confusion_matrix': cm
    }

def plot_enhanced_results(feature_importance, results):
    """
    Create enhanced visualizations
    """
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    
    # Feature Importance
    top_features = feature_importance.head(15)
    axes[0, 0].barh(range(len(top_features)), top_features['importance'])
    axes[0, 0].set_yticks(range(len(top_features)))
    axes[0, 0].set_yticklabels(top_features['feature'])
    axes[0, 0].set_xlabel('Feature Importance')
    axes[0, 0].set_title('Top 15 Feature Importances')
    axes[0, 0].invert_yaxis()
    
    # Confusion Matrix Heatmap
    sns.heatmap(results['confusion_matrix'], annot=True, fmt='d', 
               cmap='Blues', ax=axes[0, 1],
               xticklabels=['Legitimate', 'Phishing'],
               yticklabels=['Legitimate', 'Phishing'])
    axes[0, 1].set_title('Confusion Matrix')
    axes[0, 1].set_xlabel('Predicted')
    axes[0, 1].set_ylabel('Actual')
    
    # ROC Curve
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(results['predictions'], results['probabilities'][:, 1])
    axes[0, 2].plot(fpr, tpr, color='darkorange', lw=2, 
                   label=f'ROC curve (AUC = {results["roc_auc"]:.3f})')
    axes[0, 2].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    axes[0, 2].set_xlim([0.0, 1.0])
    axes[0, 2].set_ylim([0.0, 1.05])
    axes[0, 2].set_xlabel('False Positive Rate')
    axes[0, 2].set_ylabel('True Positive Rate')
    axes[0, 2].set_title('ROC Curve')
    axes[0, 2].legend(loc="lower right")
    
    # Prediction Probabilities Distribution
    phishing_probs = results['probabilities'][:, 1]
    axes[1, 0].hist(phishing_probs, bins=50, alpha=0.7, color='red', edgecolor='black')
    axes[1, 0].set_xlabel('Predicted Probability of Phishing')
    axes[1, 0].set_ylabel('Frequency')
    axes[1, 0].set_title('Distribution of Phishing Probabilities')
    axes[1, 0].axvline(x=0.5, color='blue', linestyle='--', label='Decision Threshold')
    axes[1, 0].legend()
    
    # Performance Metrics Bar Chart
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC AUC']
    values = [results['accuracy'], results['precision'], results['recall'], 
              results['f1'], results['roc_auc']]
    
    bars = axes[1, 1].bar(metrics, values, color=['skyblue', 'lightgreen', 'lightcoral', 
                                                 'lightsalmon', 'plum'])
    axes[1, 1].set_ylabel('Score')
    axes[1, 1].set_title('Model Performance Metrics')
    axes[1, 1].set_ylim([0, 1])
    
    # Add value labels on bars
    for bar, value in zip(bars, values):
        height = bar.get_height()
        axes[1, 1].text(bar.get_x() + bar.get_width()/2., height + 0.01,
                       f'{value:.3f}', ha='center', va='bottom')
    
    # Feature Importance Distribution
    all_features = feature_importance['importance']
    axes[1, 2].hist(all_features, bins=30, alpha=0.7, color='lightblue', edgecolor='black')
    axes[1, 2].set_xlabel('Feature Importance')
    axes[1, 2].set_ylabel('Number of Features')
    axes[1, 2].set_title('Distribution of Feature Importances')
    
    plt.tight_layout()
    plt.savefig('phishing_detection_enhanced_results.png', dpi=300, bbox_inches='tight')
    plt.show()

def test_real_world_examples(detector):
    """
    Test the model on real-world example URLs
    """
    print("\n=== Real-World URL Testing ===")
    
    test_cases = [
        # Legitimate URLs
        ("https://www.google.com/search?q=machine+learning", "Legitimate"),
        ("https://github.com/microsoft/vscode", "Legitimate"),
        ("https://stackoverflow.com/questions/123456", "Legitimate"),
        ("https://www.amazon.com/dp/B08N5WRWNW", "Legitimate"),
        ("https://www.paypal.com/us/home", "Legitimate"),
        
        # Phishing URLs
        ("https://goog1e-security-alert.com/verify-account", "Phishing"),
        ("https://paypa1-confirm-account.ml/secure-login", "Phishing"),
        ("https://amaz0n-login-verification.tk/update-info", "Phishing"),
        ("https://faceb00k-security-check.ga/verify-identity", "Phishing"),
        ("https://secure-account-update.tk/login", "Phishing"),
        
        # Edge cases
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "Legitimate"),
        ("https://bit.ly/suspicious-redirect", "Phishing"),
        ("https://192.168.1.1/admin", "Suspicious (IP)"),
        ("https://www.example.com", "Legitimate"),
        ("https://suspicious-site.tk/verify-now", "Phishing")
    ]
    
    print("Testing on various URL types:")
    print("-" * 80)
    
    for url, expected in test_cases:
        try:
            features = detector.extract_features(url)
            X_test_sample = pd.DataFrame([features])
            X_test_scaled = detector.scaler.transform(X_test_sample)
            prediction = detector.model.predict(X_test_scaled)[0]
            probability = detector.model.predict_proba(X_test_scaled)[0]
            
            result = "PHISHING" if prediction == 1 else "LEGITIMATE"
            confidence = probability[1] if prediction == 1 else probability[0]
            
            # Check if prediction matches expectation
            status = "✓" if (result == "PHISHING" and "Phishing" in expected) or \
                           (result == "LEGITIMATE" and "Legitimate" in expected) else "✗"
            
            print(f"URL: {url}")
            print(f"Expected: {expected}")
            print(f"Predicted: {result} (Confidence: {confidence:.3f}) {status}")
            print("-" * 80)
            
        except Exception as e:
            print(f"Error testing URL {url}: {e}")
            print("-" * 80)

def main():
    """
    Main function to run the complete phishing detection system
    """
    print("=== Advanced Phishing URL Detection System ===")
    print("Using Real Dataset with Comprehensive Feature Engineering\n")
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Load dataset
    print("Loading dataset...")
    df = load_dataset()
    
    # Analyze dataset
    df = analyze_dataset(df)
    
    # Extract features
    print("\nExtracting features from URLs...")
    X = detector.create_dataset(df['url'].tolist(), df['label'].tolist())
    y = np.array(df['label'].tolist())
    
    # Split data (85% train, 15% test)
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    
    print(f"\nData split:")
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Testing set: {X_test.shape[0]} samples")
    
    # Train model
    feature_importance = detector.train_model(X_train, y_train)
    
    # Enhanced evaluation
    results = enhanced_evaluation(detector, X_test, y_test)
    
    # Plot enhanced results
    plot_enhanced_results(feature_importance, results)
    
    # Test on real-world examples
    test_real_world_examples(detector)
    
    # Summary
    print("\n=== FINAL SUMMARY ===")
    print(f"Model trained successfully with {len(feature_importance)} features")
    print(f"Final Accuracy: {results['accuracy']:.4f}")
    print(f"Final F1-Score: {results['f1']:.4f}")
    print(f"ROC AUC Score: {results['roc_auc']:.4f}")
    print(f"Successfully detected {results['confusion_matrix'][1,1]} phishing URLs")
    print(f"Correctly identified {results['confusion_matrix'][0,0]} legitimate URLs")
    
    print("\nTop 5 Most Important Features:")
    for i, (_, row) in enumerate(feature_importance.head(5).iterrows()):
        print(f"{i+1}. {row['feature']}: {row['importance']:.4f}")

if __name__ == "__main__":
    main()

