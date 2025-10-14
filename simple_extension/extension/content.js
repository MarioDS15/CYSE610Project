// Simple content script - minimal JavaScript
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'getPageData') {
        // Get basic page data
        var pageData = {
            url: window.location.href,
            html: document.documentElement.outerHTML.substring(0, 10000), // Limit size
            css: getPageCSS()
        };
        
        sendResponse(pageData);
    }
});

function getPageCSS() {
    // Get basic CSS info - very simple
    var styles = '';
    var styleSheets = document.styleSheets;
    
    for (var i = 0; i < Math.min(styleSheets.length, 5); i++) { // Limit to 5 stylesheets
        try {
            var rules = styleSheets[i].cssRules || styleSheets[i].rules;
            if (rules) {
                for (var j = 0; j < Math.min(rules.length, 20); j++) { // Limit rules
                    styles += rules[j].cssText + '\n';
                }
            }
        } catch (e) {
            // Skip if can't access
        }
    }
    
    return styles.substring(0, 5000); // Limit CSS size
}
