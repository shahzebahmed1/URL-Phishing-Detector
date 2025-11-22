from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re

app = Flask(__name__)

def extract_features(url):
    """Extract features from URL for phishing detection"""
    features = {}
    
    # Basic URL features
    features['url_length'] = len(url)
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_eq'] = url.count('=')
    features['nb_slash'] = url.count('/')
    features['nb_percent'] = url.count('%')
    
    # Parse URL
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    features['hostname_length'] = len(hostname)
    features['https_token'] = 1 if 'https' in url.lower() else 0
    
    # IP address detection
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    features['ip_in_url'] = 1 if ip_pattern.search(url) else 0
    
    # Suspicious TLDs
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq']
    features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
    
    # URL shorteners
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly']
    features['url_shortened'] = 1 if any(short in url.lower() for short in shorteners) else 0
    
    return features

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
