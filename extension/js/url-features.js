/**
 * URL Feature Extraction for Phishing Detection
 * Port of Python URLFeatureExtractor to JavaScript
 */

class URLFeatureExtractor {
    constructor() {
        // Suspicious keywords and patterns
        this.suspiciousKeywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'validate', 'authenticate', 'bank', 'paypal', 'amazon',
            'facebook', 'google', 'apple', 'microsoft', 'support',
            'password', 'signin', 'signup', 'register'
        ];

        this.brands = [
            'google', 'facebook', 'amazon', 'apple', 'microsoft',
            'paypal', 'ebay', 'netflix', 'twitter', 'instagram'
        ];

        this.suspiciousTLDs = [
            'tk', 'ml', 'ga', 'cf', 'click', 'download', 'stream',
            'gq', 'top', 'zip', 'review'
        ];

        this.urlShorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'short.link', 'buff.ly'
        ];

        this.suspiciousExtensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs'
        ];
    }

    /**
     * Extract all features from a URL
     */
    extractAllFeatures(url) {
        const features = {};

        // Parse URL
        let parsedUrl;
        try {
            parsedUrl = new URL(url);
        } catch (e) {
            console.error('Invalid URL:', url);
            return this.getDefaultFeatures();
        }

        // Basic URL features
        features['url_length'] = url.length;
        features['num_dots'] = (url.match(/\./g) || []).length;
        features['num_hyphens'] = (url.match(/-/g) || []).length;
        features['num_underscores'] = (url.match(/_/g) || []).length;
        features['num_slashes'] = (url.match(/\//g) || []).length;
        features['num_question_marks'] = (url.match(/\?/g) || []).length;
        features['num_equals'] = (url.match(/=/g) || []).length;
        features['num_ampersands'] = (url.match(/&/g) || []).length;
        features['num_percentages'] = (url.match(/%/g) || []).length;

        // Domain analysis
        const domain = parsedUrl.hostname;
        const path = parsedUrl.pathname;
        const query = parsedUrl.search.substring(1);

        features['domain_length'] = domain.length;
        features['path_length'] = path.length;
        features['query_length'] = query.length;

        // TLD analysis
        const tldInfo = this.extractTLD(domain);
        features['subdomain_count'] = tldInfo.subdomainCount;
        features['has_subdomain'] = tldInfo.hasSubdomain ? 1 : 0;
        features['domain_name_length'] = tldInfo.domainLength;
        features['tld_length'] = tldInfo.tldLength;

        // Special character analysis
        features['has_at_symbol'] = url.includes('@') ? 1 : 0;
        features['has_port'] = parsedUrl.port !== '' ? 1 : 0;
        features['has_ip'] = this.hasIPAddress(url);
        features['has_suspicious_tld'] = this.hasSuspiciousTLD(tldInfo.tld);

        // Suspicious patterns
        features['has_shortener'] = this.isShortenerURL(url);
        features['has_suspicious_keywords'] = this.hasSuspiciousKeywords(url);
        features['has_numbers_in_domain'] = /\d/.test(domain) ? 1 : 0;
        features['has_mixed_case'] = this.hasMixedCase(domain);

        // Statistical features
        features['digit_ratio'] = this.calculateDigitRatio(url);
        features['letter_ratio'] = this.calculateLetterRatio(url);
        features['special_char_ratio'] = this.calculateSpecialCharRatio(url);

        // Entropy calculation
        features['url_entropy'] = this.calculateEntropy(url);
        features['domain_entropy'] = this.calculateEntropy(domain);

        // Path analysis
        features['path_depth'] = (path.match(/\//g) || []).length;
        features['has_file_extension'] = this.hasFileExtension(path);
        features['suspicious_file_ext'] = this.hasSuspiciousFileExtension(path);

        // Query parameter analysis
        const params = new URLSearchParams(query);
        features['num_params'] = params.size;
        features['has_suspicious_params'] = this.hasSuspiciousParams(query);

        // Brand impersonation detection
        features['suspicious_brand_usage'] = this.hasSuspiciousBrandUsage(url);

        // URL structure anomalies
        features['double_slash'] = (url.indexOf('//') !== url.lastIndexOf('//')) ? 1 : 0;
        features['trailing_slash'] = url.endsWith('/') ? 1 : 0;

        // HTTPS analysis
        features['uses_https'] = url.startsWith('https://') ? 1 : 0;
        features['uses_http'] = url.startsWith('http://') ? 1 : 0;

        return features;
    }

    /**
     * Extract TLD information from domain
     */
    extractTLD(domain) {
        const parts = domain.split('.');
        const tld = parts.length > 1 ? parts[parts.length - 1] : '';
        const domainName = parts.length > 1 ? parts[parts.length - 2] : parts[0];
        const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : '';

        return {
            tld: tld,
            domain: domainName,
            subdomain: subdomain,
            tldLength: tld.length,
            domainLength: domainName.length,
            subdomainCount: subdomain ? subdomain.split('.').length : 0,
            hasSubdomain: subdomain !== ''
        };
    }

    /**
     * Check if URL contains an IP address
     */
    hasIPAddress(url) {
        const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
        return ipPattern.test(url) ? 1 : 0;
    }

    /**
     * Check for suspicious TLD
     */
    hasSuspiciousTLD(tld) {
        return this.suspiciousTLDs.includes(tld.toLowerCase()) ? 1 : 0;
    }

    /**
     * Check if URL is from a shortener service
     */
    isShortenerURL(url) {
        const urlLower = url.toLowerCase();
        return this.urlShorteners.some(shortener => urlLower.includes(shortener)) ? 1 : 0;
    }

    /**
     * Check for suspicious keywords
     */
    hasSuspiciousKeywords(url) {
        const urlLower = url.toLowerCase();
        return this.suspiciousKeywords.some(keyword => urlLower.includes(keyword)) ? 1 : 0;
    }

    /**
     * Check for mixed case in domain
     */
    hasMixedCase(domain) {
        const hasUpper = /[A-Z]/.test(domain);
        const hasLower = /[a-z]/.test(domain);
        return (hasUpper && hasLower) ? 1 : 0;
    }

    /**
     * Calculate digit ratio
     */
    calculateDigitRatio(text) {
        const digitCount = (text.match(/\d/g) || []).length;
        return text.length > 0 ? digitCount / text.length : 0;
    }

    /**
     * Calculate letter ratio
     */
    calculateLetterRatio(text) {
        const letterCount = (text.match(/[a-zA-Z]/g) || []).length;
        return text.length > 0 ? letterCount / text.length : 0;
    }

    /**
     * Calculate special character ratio
     */
    calculateSpecialCharRatio(text) {
        const specialCount = (text.match(/[^a-zA-Z0-9]/g) || []).length;
        return text.length > 0 ? specialCount / text.length : 0;
    }

    /**
     * Calculate Shannon entropy
     */
    calculateEntropy(text) {
        if (!text || text.length === 0) return 0;

        const charCounts = {};
        for (let char of text) {
            charCounts[char] = (charCounts[char] || 0) + 1;
        }

        let entropy = 0;
        const textLength = text.length;

        for (let count of Object.values(charCounts)) {
            const probability = count / textLength;
            entropy -= probability * Math.log2(probability);
        }

        return entropy;
    }

    /**
     * Check if path has file extension
     */
    hasFileExtension(path) {
        const pathParts = path.split('/');
        const lastPart = pathParts[pathParts.length - 1];
        return (lastPart.includes('.') && lastPart.length > 0) ? 1 : 0;
    }

    /**
     * Check for suspicious file extensions
     */
    hasSuspiciousFileExtension(path) {
        const pathLower = path.toLowerCase();
        return this.suspiciousExtensions.some(ext => pathLower.includes(ext)) ? 1 : 0;
    }

    /**
     * Check for suspicious query parameters
     */
    hasSuspiciousParams(query) {
        const suspiciousParams = ['redirect', 'url', 'link', 'goto', 'target', 'ref'];
        const queryLower = query.toLowerCase();
        return suspiciousParams.some(param => queryLower.includes(param)) ? 1 : 0;
    }

    /**
     * Check for suspicious brand usage (potential impersonation)
     */
    hasSuspiciousBrandUsage(url) {
        const urlLower = url.toLowerCase();
        return this.brands.some(brand => urlLower.includes(brand)) ? 1 : 0;
    }

    /**
     * Get default features for invalid URLs
     */
    getDefaultFeatures() {
        const defaultFeatures = {};
        const featureNames = [
            'url_length', 'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_question_marks', 'num_equals', 'num_ampersands', 'num_percentages',
            'domain_length', 'path_length', 'query_length', 'subdomain_count',
            'has_subdomain', 'domain_name_length', 'tld_length', 'has_at_symbol',
            'has_port', 'has_ip', 'has_suspicious_tld', 'has_shortener',
            'has_suspicious_keywords', 'has_numbers_in_domain', 'has_mixed_case',
            'digit_ratio', 'letter_ratio', 'special_char_ratio', 'url_entropy',
            'domain_entropy', 'path_depth', 'has_file_extension', 'suspicious_file_ext',
            'num_params', 'has_suspicious_params', 'suspicious_brand_usage',
            'double_slash', 'trailing_slash', 'uses_https', 'uses_http'
        ];

        featureNames.forEach(name => {
            defaultFeatures[name] = 0;
        });

        return defaultFeatures;
    }

    /**
     * Get feature explanations for detected phishing indicators
     */
    getFeatureExplanations(features) {
        const explanations = [];

        if (features['has_ip']) {
            explanations.push('URL contains an IP address instead of a domain name');
        }

        if (features['has_suspicious_tld']) {
            explanations.push('Uses a suspicious top-level domain (TLD) commonly used in phishing');
        }

        if (features['has_suspicious_keywords']) {
            explanations.push('Contains suspicious keywords like "login", "verify", "secure", etc.');
        }

        if (features['suspicious_brand_usage']) {
            explanations.push('Mentions well-known brands (potential impersonation)');
        }

        if (features['has_shortener']) {
            explanations.push('Uses a URL shortening service (hides actual destination)');
        }

        if (features['url_length'] > 75) {
            explanations.push(`Unusually long URL (${features['url_length']} characters)`);
        }

        if (features['has_numbers_in_domain']) {
            explanations.push('Domain contains numbers (e.g., "goog1e" instead of "google")');
        }

        if (features['subdomain_count'] > 2) {
            explanations.push(`Multiple subdomains detected (${features['subdomain_count']})`);
        }

        if (features['has_at_symbol']) {
            explanations.push('Contains @ symbol (can be used to obscure real domain)');
        }

        if (features['suspicious_file_ext']) {
            explanations.push('Contains suspicious file extension (.exe, .bat, etc.)');
        }

        if (features['has_suspicious_params']) {
            explanations.push('Has suspicious query parameters (redirect, url, etc.)');
        }

        if (!features['uses_https']) {
            explanations.push('Does not use HTTPS encryption');
        }

        if (features['url_entropy'] > 4.5) {
            explanations.push('High URL randomness/entropy (characteristic of generated phishing URLs)');
        }

        return explanations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = URLFeatureExtractor;
}
