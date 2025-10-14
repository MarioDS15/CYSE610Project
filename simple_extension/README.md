# Simple Phish Detector Extension

A simple Chrome extension that sends URLs and page content to your existing Python phishing detection code.

## How it works:
1. User clicks the extension button
2. Extension sends current page URL + HTML/CSS to Python server
3. Python server uses your existing ML code to analyze
4. Extension shows result (Safe/Phishing)

## Setup Instructions:

### 1. Install Python Dependencies
```bash
cd python_backend
pip install -r requirements.txt
```

### 2. Start the Python Server
```bash
python simple_server.py
```
The server will run at http://localhost:5000

### 3. Load the Extension in Chrome
1. Open Chrome and go to `chrome://extensions/`
2. Turn on "Developer mode"
3. Click "Load unpacked"
4. Select the `extension` folder
5. The extension icon should appear in your toolbar

### 4. Test the Extension
1. Go to any website
2. Click the extension icon
3. Click "Check Current Page"
4. See the result!

## Files:
- `extension/manifest.json` - Extension configuration
- `extension/popup.html` - Simple UI
- `extension/popup.js` - Minimal JavaScript (sends data to Python)
- `extension/content.js` - Gets page data
- `python_backend/simple_server.py` - Python server that uses your existing code
- `python_backend/requirements.txt` - Python dependencies

## What the Extension Does:
- Gets current page URL and HTML/CSS
- Sends it to your Python server
- Your Python code does the ML analysis
- Extension shows the result

## Minimal JavaScript:
The JavaScript is very basic - just gets page data and sends it to Python. No complex ML code in the extension!
