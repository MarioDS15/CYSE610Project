# PhishGuard Pro API Reference

## Core Classes

### URLAnalyzer
- `analyzeUrl(url)`: Extract URL features
- `getDomainFeatures(domain)`: Analyze domain characteristics
- `detectBrandImpersonation(url, brand)`: Check for brand spoofing

### DesignAnalyzer
- `analyzeLayout(document)`: Extract layout features
- `analyzeVisuals(document)`: Extract visual design features
- `detectFormPatterns(document)`: Identify suspicious form patterns

### PhishingModel
- `predict(features)`: Make phishing prediction
- `getConfidence(features)`: Get confidence score
- `explainFeatures(features)`: Explain contributing features

## Extension APIs

### Background Service Worker
- `handleTabUpdate(tab)`: Process new page loads
- `processAnalysisRequest(data)`: Handle analysis requests
- `updateModel(data)`: Update ML model

### Content Script
- `extractPageFeatures(document)`: Extract all page features
- `showWarning(level)`: Display security warnings
- `collectUserFeedback(action)`: Collect user interactions

### Popup Interface
- `displayResults(results)`: Show analysis results
- `updateSettings(settings)`: Update user preferences
- `showStatistics(stats)`: Display usage statistics

## Data Structures

### Feature Vector
```javascript
{
  url: {
    length: number,
    entropy: number,
    suspiciousTLD: boolean,
    brandImpersonation: boolean
  },
  design: {
    layoutComplexity: number,
    colorConsistency: number,
    formSuspiciousness: number,
    visualQuality: number
  }
}
```

### Analysis Result
```javascript
{
  isPhishing: boolean,
  confidence: number,
  features: FeatureVector,
  explanation: string[],
  recommendations: string[]
}
```
