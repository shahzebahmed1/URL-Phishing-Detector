import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

def create_sample_dataset():
    """Create a simple dataset for initial training"""
    legitimate_urls = [
        'https://www.google.com',
        'https://www.facebook.com',
        'https://www.amazon.com',
        'https://www.youtube.com',
        'https://www.wikipedia.org',
    ]
    
    phishing_urls = [
        'https://paypal-verify.xyz/account/login',
        'https://secure-paypal.tk/update/billing',
        'http://192.168.1.1/login/secure',
        'https://bit.ly/3xYz9Ab?redirect=http://malicious.xyz',
        'https://free-money.xyz/claim/now',
    ]
    
    # For now, simple dataset - will add feature extraction later
    data = {
        'url_length': [len(url) for url in legitimate_urls + phishing_urls],
        'label': [0]*len(legitimate_urls) + [1]*len(phishing_urls)
    }
    
    return pd.DataFrame(data)

def train_model():
    print("Creating dataset...")
    df = create_sample_dataset()
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"Model accuracy: {accuracy:.2f}")
    
    joblib.dump(model, 'phishing_detection_model.pkl')
    print("Model saved!")

if __name__ == "__main__":
    train_model()
