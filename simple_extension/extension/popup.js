// Very simple popup script - minimal JavaScript
document.getElementById('checkButton').addEventListener('click', function() {
    // Get current tab
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        var currentTab = tabs[0];
        
        // Show loading
        document.getElementById('loading').style.display = 'block';
        document.getElementById('result').innerHTML = '';
        
        // Get page content from content script
        chrome.tabs.sendMessage(currentTab.id, {action: 'getPageData'}, function(response) {
            if (response) {
                // Send data to Python backend
                sendToBackend(response.url, response.html, response.css);
            }
        });
    });
});

function sendToBackend(url, html, css) {
    // Send data to Python server
    fetch('http://localhost:5000/check', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url: url,
            html: html,
            css: css
        })
    })
    .then(response => response.json())
    .then(data => {
        // Show result
        document.getElementById('loading').style.display = 'none';
        showResult(data);
    })
    .catch(error => {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('result').innerHTML = '<div class="danger">Error: Could not connect to Python server</div>';
    });
}

function showResult(data) {
    var resultDiv = document.getElementById('result');
    var className = data.is_phishing ? 'danger' : 'safe';
    var message = data.is_phishing ? '⚠️ PHISHING DETECTED!' : '✅ Site appears safe';
    
    resultDiv.innerHTML = '<div class="' + className + '">' + message + 
                         '<br>Confidence: ' + Math.round(data.confidence * 100) + '%</div>';
}
