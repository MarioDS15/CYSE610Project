# PhishGuard Pro Chrome Extension

## Overview
Advanced phishing detection Chrome extension that combines URL analysis with website design feature extraction using machine learning.

## Features
- **URL-based Detection**: Analyzes URL patterns, domains, and structures
- **Design Analysis**: Extracts visual and layout features from websites
- **Real-time Protection**: Instant phishing detection as you browse
- **User-friendly Interface**: Clean popup with detailed analysis
- **Customizable Settings**: Adjustable confidence thresholds and preferences

## Project Structure
```
chrome_extension/
├── manifest.json                 # Extension configuration
├── src/
│   ├── popup/                   # Extension popup interface
│   ├── background/              # Service worker
│   ├── content/                 # Content scripts
│   ├── options/                 # Settings page
│   ├── ml/                      # Machine learning components
│   │   ├── url_features/        # URL analysis features
│   │   ├── design_features/     # Website design analysis
│   │   ├── models/              # ML models and prediction
│   │   └── utils/               # ML utilities
│   └── shared/                  # Shared utilities
├── assets/                      # Icons, images, styles
├── docs/                        # Documentation
└── tests/                       # Test files
```

## Development Status
- [ ] Core extension structure
- [ ] URL feature extraction
- [ ] Design feature extraction
- [ ] ML model integration
- [ ] User interface
- [ ] Testing and validation
