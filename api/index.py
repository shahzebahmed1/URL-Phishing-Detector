from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
import numpy as np
import joblib
import os
import warnings
warnings.filterwarnings('ignore', category=UserWarning)

app = Flask(__name__, template_folder='../templates', static_folder='../static')

# Load the trained model
model_path = os.path.join(os.path.dirname(__file__), '..', 'phishing_detection_model.pkl')
try:
    model = joblib.load(model_path)
    print("Model loaded successfully!")
except Exception as e:
    model = None
    print(f"Warning: Model not found: {e}")

def extract_features(url):
    """Extract features from URL for phishing detection"""
    features = {}
    features['url_length'] = len(url)
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolon'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = 1 if 'www' in url else 0
    features['https_token'] = 1 if 'https' in url.lower() else 0
    
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.review', '.date', '.gdn']
    features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
    
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
    features['url_shortened'] = 1 if any(short in url.lower() for short in shorteners) else 0
    
    features['nb_redirection'] = url.count('//')
    features['nb_external_redirection'] = url.count('http')
    features['length_words_raw'] = len(url.split('/'))
    features['char_repeat'] = max([0] + [len(list(g)) for _, g in re.findall(r'((\w)\2{2,})', url)])
    
    return features

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        if model is None:
            return jsonify({
                'status': 'error',
                'message': 'Model not loaded. Please train the model first.'
            })
        
        url = request.form.get('url', '').strip()
        
        if not url:
            return jsonify({
                'status': 'error',
                'message': 'Please provide a URL'
            })
        
        # Extract features
        features = extract_features(url)
        
        # Convert features dict to numpy array in the correct order
        # Feature order must match training data (order from extract_features function)
        feature_order = [
            'url_length', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 
            'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash',
            'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolon', 'nb_dollar', 'nb_space',
            'nb_www', 'https_token', 'suspicious_tld', 'url_shortened', 'nb_redirection',
            'nb_external_redirection', 'length_words_raw', 'char_repeat'
        ]
        features_array = np.array([[features[key] for key in feature_order]])
        
        # Make prediction
        prediction = model.predict(features_array)[0]
        probabilities = model.predict_proba(features_array)[0]
        
        result = 'Phishing' if prediction == 1 else 'Legitimate'
        confidence = f"{max(probabilities) * 100:.2f}%"
        
        return jsonify({
            'status': 'success',
            'url': url,
            'result': result,
            'confidence': confidence,
            'features': features
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

# Vercel automatically detects Flask apps named 'app'
