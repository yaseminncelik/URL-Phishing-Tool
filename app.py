from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
import warnings
import re
import math
from urllib.parse import urlparse
from collections import Counter

warnings.filterwarnings('ignore')

app = Flask(__name__, template_folder="templates")

# Whitelist trusted domains
WHITELIST = {
    'google.com', 'www.google.com', 'github.com', 'www.github.com',
    'facebook.com', 'www.facebook.com', 'twitter.com', 'www.twitter.com',
    'linkedin.com', 'www.linkedin.com', 'amazon.com', 'www.amazon.com',
    'microsoft.com', 'www.microsoft.com', 'apple.com', 'www.apple.com',
    'youtube.com', 'www.youtube.com', 'stackoverflow.com', 'www.stackoverflow.com',
    'reddit.com', 'www.reddit.com', 'wikipedia.org', 'www.wikipedia.org',
    'gmail.com', 'outlook.com', 'yahoo.com', 'portswigger.net', 'www.portswigger.net',
    'kaggle.com', 'www.kaggle.com', 'colab.research.google.com', 'medium.com', 'www.medium.com',
    'github.io', 'gitlab.com', 'netflix.com', 'www.netflix.com', 'spotify.com', 'www.spotify.com'
}

# Load models
try:
    print("[*] Loading models...")
    model = joblib.load("xgboost_model.pkl")
    scaler = joblib.load("scaler.pkl")
    tfidf_vectorizer = joblib.load("tfidf_vectorizer.pkl")
    feature_columns = joblib.load("feature_columns.pkl")
    print("[*] Models loaded successfully!")
except Exception as e:
    print(f"[!] Error loading models: {e}")

def is_whitelisted(url):
    """Check if URL is in whitelist"""
    url_lower = url.lower().strip('/')
    if '://' in url_lower:
        url_lower = url_lower.split('://', 1)[1]
    if '/' in url_lower:
        url_lower = url_lower.split('/', 1)[0]
    return url_lower in WHITELIST or any(url_lower.endswith('.' + domain) for domain in WHITELIST)

def calculate_entropy(text):
    if not text:
        return 0
    counter = Counter(text)
    probabilities = [count / len(text) for count in counter.values()]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return entropy

def is_ip(url):
    match = re.search(
        '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(/|:|$)',
        url)
    return 1 if match else 0

def extract_features(url):
    """Extract improved features from URL (Must match training logic)"""
    features = {}
    
    # Basic structural features
    features['length'] = len(url)
    features['dots_count'] = url.count('.')
    features['slash_count'] = url.count('/')
    features['dash_count'] = url.count('-')
    features['underscore_count'] = url.count('_')
    features['at_count'] = url.count('@')
    features['query_count'] = url.count('?')
    features['ampersand_count'] = url.count('&')
    features['equal_count'] = url.count('=')
    features['colon_count'] = url.count(':')
    features['percent_count'] = url.count('%')
    
    # Character type counts
    digit_count = sum(c.isdigit() for c in url)
    features['digit_count'] = digit_count
    features['uppercase_count'] = sum(c.isupper() for c in url)
    features['lowercase_count'] = sum(c.islower() for c in url)
    features['digit_ratio'] = digit_count / len(url) if len(url) > 0 else 0
    
    # Advanced features
    features['entropy'] = calculate_entropy(url)
    features['is_ip'] = is_ip(url)
    
    # Parsing features
    try:
        parsed = urlparse(url)
        features['hostname_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['subdomain_count'] = parsed.netloc.count('.')
    except:
        features['hostname_length'] = 0
        features['path_length'] = 0
        features['subdomain_count'] = 0

    # Keyword flags
    keywords = ['login', 'signin', 'verify', 'confirm', 'update', 'account', 'secure', 'free', 'click', 'bank', 'paypal', 'ebay', 'amazon']
    for kw in keywords:
        features[f'has_{kw}'] = 1 if kw in url.lower() else 0
        
    features['has_https'] = 1 if url.startswith('https://') else 0
    features['has_http'] = 1 if url.startswith('http://') else 0
    
    return features

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan_url():
    """Scan URL and return risk assessment"""
    data = request.get_json()
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Check whitelist
    if is_whitelisted(url):
        return jsonify({
            "url": url,
            "prediction": 0,
            "risk_score": 0.0,
            "risk_level": "✅ WHITELISTED - SAFE",
            "risk_type": "low",
            "whitelisted": True
        })
    
    try:
        features_dict = extract_features(url)
        tfidf_features = tfidf_vectorizer.transform([url]).toarray()[0]
        
        # Build feature vector
        feature_vector = []
        for col in feature_columns:
            if col.startswith('tfidf_'):
                idx = int(col.split('_')[1])
                feature_vector.append(tfidf_features[idx])
            else:
                feature_vector.append(features_dict.get(col, 0))
        
        feature_vector = np.array([feature_vector])
        feature_vector_scaled = scaler.transform(feature_vector)
        
        prediction = model.predict(feature_vector_scaled)[0]
        probability = model.predict_proba(feature_vector_scaled)[0][1]
        
        # Determine risk level
        if probability > 0.75:
            risk_level = "🚨 HIGH RISK - PHISHING"
            risk_type = "high"
        elif probability > 0.50:
            risk_level = "⚠️ MEDIUM RISK"
            risk_type = "medium"
        else:
            risk_level = "✅ LOW RISK - SAFE"
            risk_type = "low"
        
        return jsonify({
            "url": url,
            "prediction": int(prediction),
            "risk_score": float(probability),
            "risk_level": risk_level,
            "risk_type": risk_type,
            "whitelisted": False
        })
    
    except Exception as e:
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5000)
