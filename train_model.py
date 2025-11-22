import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re
from urllib.parse import urlparse

def extract_url_features(url):
    """Extract features from URL"""
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

def create_comprehensive_dataset():
    """Create a comprehensive dataset with real phishing patterns"""
    
    # Legitimate URLs
    legitimate_urls = [
        'https://www.google.com', 'https://www.facebook.com', 'https://www.amazon.com',
        'https://www.youtube.com', 'https://www.wikipedia.org', 'https://www.github.com',
        'https://www.stackoverflow.com', 'https://www.microsoft.com', 'https://www.apple.com',
        'https://www.twitter.com', 'https://www.linkedin.com', 'https://www.reddit.com',
        'https://www.netflix.com', 'https://www.instagram.com', 'https://www.paypal.com',
        'https://mail.google.com', 'https://drive.google.com', 'https://docs.google.com',
        'https://www.ebay.com', 'https://www.cnn.com', 'https://www.bbc.com',
        'https://www.nytimes.com', 'https://www.adobe.com', 'https://www.salesforce.com',
        'https://www.oracle.com', 'https://www.ibm.com', 'https://www.cisco.com',
        'https://www.intel.com', 'https://www.nvidia.com', 'https://www.dell.com',
        'https://www.hp.com', 'https://www.walmart.com', 'https://www.target.com',
        'https://www.bestbuy.com', 'https://www.spotify.com', 'https://www.dropbox.com',
        'https://www.zoom.us', 'https://www.slack.com', 'https://www.trello.com',
        'https://www.atlassian.com', 'https://www.shopify.com', 'https://www.wordpress.com',
        'https://www.medium.com', 'https://www.quora.com', 'https://www.pinterest.com',
        'https://www.tumblr.com', 'https://www.twitch.tv', 'https://www.vimeo.com',
        'https://www.soundcloud.com', 'https://www.imdb.com',
    ]
    
    # Phishing URLs
    phishing_urls = [
        'https://toolssocial.in/get-follower/KAXKXb3K77',
        'https://getfollowers.xyz/instagram/free',
        'https://insta-followers.tk/get/12345',
        'https://free-likes.ml/facebook/boost',
        'https://social-boost.ga/twitter/followers',
        'https://follow4follow.cf/insta/premium',
        'https://likesmania.gq/get-likes/abc123',
        'https://paypal-verify.xyz/account/login',
        'https://secure-paypal.tk/update/billing',
        'https://bankofamerica-secure.ml/signin',
        'https://chase-verify.ga/account/suspended',
        'https://wellsfargo-alert.cf/security/update',
        'https://paypal.com-secure.xyz/verify',
        'https://amazon-payment.tk/update',
        'https://microsoft-support.xyz/windows/update',
        'https://apple-id.tk/verify/account',
        'https://google-security.ml/alert/suspicious',
        'https://facebook-security.ga/verify/identity',
        'https://netflix-billing.cf/update/payment',
        'https://amazon-prize.gq/winner/claim',
        'http://secure-login.xyz/verify',
        'https://account-verify.tk/update',
        'http://click-here-now.ml/offer',
        'https://limited-time-offer.ga/claim',
        'http://urgent-action-required.cf/verify',
        'https://confirm-your-account.gq/now',
        'http://prize-winner.xyz/claim/12345',
        'http://192.168.1.1/login/secure',
        'https://123.456.789.012/verify/account',
        'https://bit.ly/3xYz9Ab?redirect=http://malicious.xyz',
        'http://tinyurl.com/abc123?next=http://phishing.tk',
        'https://secure-site.com/aB3dEf9GhI2jKlM',
        'https://verify-account.net/XyZ123AbC456DeF',
        'https://login-portal.org/qWeRtYuIoP',
        'http://redirect.com//http://phishing.xyz',
        'https://link.com//https://malicious.tk',
        'https://secure@login.com/verify?id=123&token=abc&redirect=xyz',
        'http://account-update.com/verify?user=test&pass=123&confirm=yes&submit=true',
        'https://free-money.xyz/claim/now',
        'https://win-iphone.tk/enter/contest',
        'https://urgent-update.ml/security/alert',
        'https://account-suspended.ga/restore/access',
        'https://verify-identity.cf/confirm/now',
        'https://claim-reward.gq/winner/prize',
        'https://PayPaI.com/login',
        'https://g00gle.com/verify',
        'https://micros0ft.com/update',
    ]
    
    data_list = []
    
    print(f"Processing {len(legitimate_urls)} legitimate URLs...")
    for url in legitimate_urls:
        features = extract_url_features(url)
        features['label'] = 0
        data_list.append(features)
    
    print(f"Processing {len(phishing_urls)} phishing URLs...")
    for url in phishing_urls:
        features = extract_url_features(url)
        features['label'] = 1
        data_list.append(features)
    
    df = pd.DataFrame(data_list)
    print(f"\nDataset created with {len(df)} total URLs")
    print(f"Legitimate: {len(df[df['label']==0])}, Phishing: {len(df[df['label']==1])}")
    
    return df

def train_model():
    print("Creating comprehensive dataset...")
    df = create_comprehensive_dataset()
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    print(f"\nDataset shape: {X.shape}")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    print("\nTraining Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nModel Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    joblib.dump(model, 'phishing_detection_model.pkl')
    print("\nModel saved to phishing_detection_model.pkl")
    
    return model

if __name__ == "__main__":
    train_model()
