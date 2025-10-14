#!/usr/bin/env python3
"""
Enhanced Main Script for Phishing URL Detection
Uses expanded multi-source dataset with deduplication
"""

from phishing_detector import PhishingDetector
from enhanced_dataset_collector import EnhancedDatasetCollector
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_auc_score, roc_curve
import os
import warnings
warnings.filterwarnings('ignore')

def load_or_create_enhanced_dataset():
    """
    Load existing enhanced dataset or create new one
    """
    dataset_path = 'data/enhanced_phishing_dataset.csv'
    
    if os.path.exists(dataset_path):
        print("📊 Loading existing enhanced dataset...")
        df = pd.read_csv(dataset_path)
        print(f"   Loaded {len(df):,} URLs from existing dataset")
        return df
    else:
        print("📊 Creating new enhanced dataset...")
        collector = EnhancedDatasetCollector()
        collector.collect_all_sources(phishing_limit=2000, legitimate_limit=2000)
        collector.save_dataset(dataset_path)
        
        df = pd.read_csv(dataset_path)
        print(f"   Created new dataset with {len(df):,} URLs")
        return df

def analyze_enhanced_dataset(df):
    """
    Comprehensive analysis of the enhanced dataset
    """
    print("\n=== ENHANCED DATASET ANALYSIS ===")
    print(f"Total URLs: {len(df):,}")
    print(f"Legitimate URLs: {len(df[df['label'] == 0]):,} ({len(df[df['label'] == 0])/len(df)*100:.1f}%)")
    print(f"Phishing URLs: {len(df[df['label'] == 1]):,} ({len(df[df['label'] == 1])/len(df)*100:.1f}%)")
    
    # Source analysis
    print(f"\n📈 Source Distribution:")
    source_counts = df['source'].value_counts()
    for source, count in source_counts.items():
        phishing_count = len(df[(df['source'] == source) & (df['label'] == 1)])
        legitimate_count = len(df[(df['source'] == source) & (df['label'] == 0)])
        print(f"   {source}: {count:,} URLs (P: {phishing_count:,}, L: {legitimate_count:,})")
    
    # URL length analysis
    df['url_length'] = df['url'].str.len()
    print(f"\n📏 URL Length Statistics:")
    print(f"   Average URL length: {df['url_length'].mean():.1f}")
    print(f"   Legitimate URLs - Average: {df[df['label']==0]['url_length'].mean():.1f}")
    print(f"   Phishing URLs - Average: {df[df['label']==1]['url_length'].mean():.1f}")
    print(f"   Min length: {df['url_length'].min()}")
    print(f"   Max length: {df['url_length'].max()}")
    
    # Domain analysis
    df['domain'] = df['url'].apply(lambda x: x.split('/')[2] if '://' in x else x.split('/')[0])
    print(f"\n🌐 Domain Statistics:")
    print(f"   Unique domains: {df['domain'].nunique():,}")
    print(f"   Most common domains:")
    top_domains = df['domain'].value_counts().head(10)
    for domain, count in top_domains.items():
        print(f"     {domain}: {count}")
    
    # TLD analysis
    df['tld'] = df['domain'].apply(lambda x: x.split('.')[-1] if '.' in x else '')
    print(f"\n🏷️  Top-Level Domain Analysis:")
    tld_counts = df['tld'].value_counts().head(10)
    for tld, count in tld_counts.items():
        phishing_count = len(df[(df['tld'] == tld) & (df['label'] == 1)])
        print(f"     .{tld}: {count:,} ({phishing_count:,} phishing)")
    
    return df

def enhanced_feature_analysis(detector, X, y):
    """
    Enhanced feature analysis with source breakdown
    """
    print("\n=== ENHANCED FEATURE ANALYSIS ===")
    
    # Train model for feature analysis
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    
    feature_importance = detector.train_model(X_train, y_train)
    
    print(f"\n🔧 Feature Engineering Results:")
    print(f"   Total features extracted: {len(detector.feature_names)}")
    
    # Analyze feature importance by category
    feature_categories = {
        'URL Structure': ['url_length', 'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes'],
        'Domain Analysis': ['domain_length', 'domain_name_length', 'tld_length', 'subdomain_count'],
        'Security Indicators': ['has_suspicious_tld', 'has_ip', 'has_suspicious_keywords', 'uses_https'],
        'Statistical': ['digit_ratio', 'letter_ratio', 'special_char_ratio', 'url_entropy'],
        'Pattern Recognition': ['has_mixed_case', 'has_numbers_in_domain', 'path_depth', 'num_params']
    }
    
    print(f"\n📊 Feature Importance by Category:")
    for category, features in feature_categories.items():
        category_features = [f for f in features if f in detector.feature_names]
        if category_features:
            category_importance = feature_importance[
                feature_importance['feature'].isin(category_features)
            ]['importance'].sum()
            print(f"   {category}: {category_importance:.3f}")
    
    return feature_importance

def cross_validate_by_source(detector, df, X, y):
    """
    Cross-validation analysis by data source
    """
    print("\n=== CROSS-VALIDATION BY SOURCE ===")
    
    from sklearn.model_selection import cross_val_score
    from sklearn.ensemble import RandomForestClassifier
    
    # Prepare data
    X_scaled = detector.scaler.fit_transform(X)
    
    # Overall cross-validation
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    cv_scores = cross_val_score(rf, X_scaled, y, cv=5, scoring='accuracy')
    
    print(f"📊 Overall 5-Fold Cross-Validation:")
    print(f"   Mean Accuracy: {cv_scores.mean():.4f} (±{cv_scores.std()*2:.4f})")
    print(f"   Individual scores: {[f'{score:.4f}' for score in cv_scores]}")
    
    # Source-specific analysis
    print(f"\n🔍 Source-Specific Analysis:")
    for source in df['source'].unique():
        source_mask = df['source'] == source
        source_X = X[source_mask]
        source_y = y[source_mask]
        
        if len(source_y) > 50:  # Only analyze sources with sufficient data
            source_X_scaled = detector.scaler.transform(source_X)
            source_cv_scores = cross_val_score(rf, source_X_scaled, source_y, cv=3, scoring='accuracy')
            
            phishing_ratio = len(source_y[source_y == 1]) / len(source_y) * 100
            print(f"   {source}: {len(source_y):,} URLs ({phishing_ratio:.1f}% phishing)")
            print(f"     CV Accuracy: {source_cv_scores.mean():.4f} (±{source_cv_scores.std()*2:.4f})")

def enhanced_evaluation(detector, X_test, y_test, df_test):
    """
    Enhanced evaluation with source-aware analysis
    """
    print("\n=== ENHANCED MODEL EVALUATION ===")
    
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
    
    print(f"📊 Overall Performance:")
    print(f"   Accuracy: {accuracy:.4f}")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall: {recall:.4f}")
    print(f"   F1-Score: {f1:.4f}")
    print(f"   ROC AUC: {roc_auc:.4f}")
    
    # Source-specific performance
    print(f"\n🎯 Performance by Source:")
    for source in df_test['source'].unique():
        source_mask = df_test['source'] == source
        if source_mask.sum() > 10:  # Only analyze sources with sufficient test data
            source_y_test = y_test[source_mask]
            source_y_pred = y_pred[source_mask]
            
            source_accuracy = accuracy_score(source_y_test, source_y_pred)
            source_samples = source_mask.sum()
            
            print(f"   {source}: {source_accuracy:.4f} ({source_samples} samples)")
    
    # Confusion Matrix
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"\n📋 Confusion Matrix:")
    print(f"   True Negatives (Legitimate): {cm[0,0]}")
    print(f"   False Positives: {cm[0,1]}")
    print(f"   False Negatives: {cm[1,0]}")
    print(f"   True Positives (Phishing): {cm[1,1]}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc,
        'predictions': y_pred,
        'probabilities': y_pred_proba,
        'confusion_matrix': cm
    }

def plot_enhanced_results(feature_importance, results, df):
    """
    Create enhanced visualizations with source analysis
    """
    fig, axes = plt.subplots(3, 2, figsize=(15, 18))
    
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
    fpr, tpr, _ = roc_curve(results['predictions'], results['probabilities'][:, 1])
    axes[1, 0].plot(fpr, tpr, color='darkorange', lw=2, 
                   label=f'ROC curve (AUC = {results["roc_auc"]:.3f})')
    axes[1, 0].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    axes[1, 0].set_xlim([0.0, 1.0])
    axes[1, 0].set_ylim([0.0, 1.05])
    axes[1, 0].set_xlabel('False Positive Rate')
    axes[1, 0].set_ylabel('True Positive Rate')
    axes[1, 0].set_title('ROC Curve')
    axes[1, 0].legend(loc="lower right")
    
    # Source Distribution
    source_counts = df['source'].value_counts()
    axes[1, 1].pie(source_counts.values, labels=source_counts.index, autopct='%1.1f%%')
    axes[1, 1].set_title('Dataset Sources Distribution')
    
    # URL Length Distribution
    df['url_length'] = df['url'].str.len()
    legitimate_lengths = df[df['label'] == 0]['url_length']
    phishing_lengths = df[df['label'] == 1]['url_length']
    
    axes[2, 0].hist(legitimate_lengths, bins=30, alpha=0.7, label='Legitimate', color='blue')
    axes[2, 0].hist(phishing_lengths, bins=30, alpha=0.7, label='Phishing', color='red')
    axes[2, 0].set_xlabel('URL Length')
    axes[2, 0].set_ylabel('Frequency')
    axes[2, 0].set_title('URL Length Distribution by Class')
    axes[2, 0].legend()
    
    # Performance Metrics
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC AUC']
    values = [results['accuracy'], results['precision'], results['recall'], 
              results['f1'], results['roc_auc']]
    
    bars = axes[2, 1].bar(metrics, values, color=['skyblue', 'lightgreen', 'lightcoral', 
                                                 'lightsalmon', 'plum'])
    axes[2, 1].set_ylabel('Score')
    axes[2, 1].set_title('Model Performance Metrics')
    axes[2, 1].set_ylim([0, 1])
    
    # Add value labels on bars
    for bar, value in zip(bars, values):
        height = bar.get_height()
        axes[2, 1].text(bar.get_x() + bar.get_width()/2., height + 0.01,
                       f'{value:.3f}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig('enhanced_phishing_detection_results.png', dpi=300, bbox_inches='tight')
    plt.show()

def test_enhanced_system(detector, df):
    """
    Test the enhanced system on diverse URL samples
    """
    print("\n=== ENHANCED SYSTEM TESTING ===")
    
    # Sample URLs from different sources for testing
    test_cases = []
    
    # Add some URLs from each source
    for source in df['source'].unique():
        source_df = df[df['source'] == source]
        if len(source_df) > 0:
            sample = source_df.sample(min(3, len(source_df)), random_state=42)
            for _, row in sample.iterrows():
                test_cases.append((row['url'], row['label'], source))
    
    print(f"Testing on {len(test_cases)} diverse URLs from all sources:")
    print("-" * 80)
    
    correct_predictions = 0
    source_performance = {}
    
    for url, expected_label, source in test_cases:
        try:
            features = detector.extract_features(url)
            X_test_sample = pd.DataFrame([features])
            X_test_scaled = detector.scaler.transform(X_test_sample)
            prediction = detector.model.predict(X_test_scaled)[0]
            probability = detector.model.predict_proba(X_test_scaled)[0]
            
            result = "PHISHING" if prediction == 1 else "LEGITIMATE"
            expected = "PHISHING" if expected_label == 1 else "LEGITIMATE"
            confidence = probability[1] if prediction == 1 else probability[0]
            
            # Check if prediction matches expectation
            is_correct = prediction == expected_label
            if is_correct:
                correct_predictions += 1
            
            # Track source performance
            if source not in source_performance:
                source_performance[source] = {'correct': 0, 'total': 0}
            source_performance[source]['total'] += 1
            if is_correct:
                source_performance[source]['correct'] += 1
            
            status = "✓" if is_correct else "✗"
            
            print(f"URL: {url[:60]}{'...' if len(url) > 60 else ''}")
            print(f"Source: {source} | Expected: {expected} | Got: {result} ({confidence:.3f}) {status}")
            print("-" * 80)
            
        except Exception as e:
            print(f"Error testing URL from {source}: {e}")
            print("-" * 80)
    
    # Print performance summary
    overall_accuracy = correct_predictions / len(test_cases) * 100
    print(f"\n🎯 Test Performance Summary:")
    print(f"   Overall Accuracy: {overall_accuracy:.1f}% ({correct_predictions}/{len(test_cases)})")
    
    print(f"\n📊 Performance by Source:")
    for source, perf in source_performance.items():
        source_accuracy = perf['correct'] / perf['total'] * 100
        print(f"   {source}: {source_accuracy:.1f}% ({perf['correct']}/{perf['total']})")

def main():
    """
    Main function for enhanced phishing detection system
    """
    print("🛡️  ENHANCED PHISHING URL DETECTION SYSTEM")
    print("=" * 60)
    print("Using Multi-Source Dataset with Advanced Deduplication\n")
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Load or create enhanced dataset
    df = load_or_create_enhanced_dataset()
    
    # Analyze enhanced dataset
    df = analyze_enhanced_dataset(df)
    
    # Extract features
    print("\n🔧 Extracting features from enhanced dataset...")
    X = detector.create_dataset(df['url'].tolist(), df['label'].tolist())
    y = np.array(df['label'].tolist())
    
    # Split data (85% train, 15% test)
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    
    # Also split the dataframe for source analysis
    df_train, df_test = train_test_split(
        df, test_size=0.15, random_state=42, stratify=df['label']
    )
    
    print(f"\n📊 Data split:")
    print(f"   Training set: {X_train.shape[0]:,} samples")
    print(f"   Testing set: {X_test.shape[0]:,} samples")
    
    # Enhanced feature analysis
    feature_importance = enhanced_feature_analysis(detector, X, y)
    
    # Cross-validation analysis
    cross_validate_by_source(detector, df, X, y)
    
    # Enhanced evaluation
    results = enhanced_evaluation(detector, X_test, y_test, df_test)
    
    # Plot enhanced results
    plot_enhanced_results(feature_importance, results, df)
    
    # Test enhanced system
    test_enhanced_system(detector, df)
    
    # Final summary
    print("\n=== FINAL ENHANCED SUMMARY ===")
    print(f"🚀 Enhanced system with {len(df):,} URLs from {df['source'].nunique()} sources")
    print(f"📊 Model trained with {len(feature_importance)} advanced features")
    print(f"🎯 Final Accuracy: {results['accuracy']:.4f}")
    print(f"🏆 Final F1-Score: {results['f1']:.4f}")
    print(f"📈 ROC AUC Score: {results['roc_auc']:.4f}")
    print(f"✅ Successfully detected {results['confusion_matrix'][1,1]} phishing URLs")
    print(f"✅ Correctly identified {results['confusion_matrix'][0,0]} legitimate URLs")
    
    print(f"\n🔧 Top 5 Most Important Features:")
    for i, (_, row) in enumerate(feature_importance.head(5).iterrows()):
        print(f"   {i+1}. {row['feature']}: {row['importance']:.4f}")
    
    print(f"\n📈 Dataset Sources:")
    for source, count in df['source'].value_counts().items():
        print(f"   {source}: {count:,} URLs")

if __name__ == "__main__":
    main()
