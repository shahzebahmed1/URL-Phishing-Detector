# URL Shield - Phishing Detector

A machine learning-based cybersecurity project that detects phishing websites by analyzing URL features.

## Features

- **Real-time URL Analysis**: Instantly analyze any URL for phishing indicators
- **Machine Learning Detection**: Uses Random Forest classifier trained on URL features
- **Interactive Web Interface**: Clean, dark-themed UI with Matrix-style background
- **Detailed Analysis**: Shows confidence scores and feature breakdowns
- **Feature Extraction**: Analyzes 26+ URL characteristics

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/shahzebahmed1/URL-Phishing-Detector.git
   cd URL-Phishing-Detector
   ```

2. **Install required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the machine learning model**:
   ```bash
   python train_model.py
   ```

4. **Run the Flask application**:
   ```bash
   python app.py
   ```

5. **Open your browser** and navigate to:
   ```
   http://127.0.0.1:5000
   ```

## How It Works

1. **Feature Extraction**: The system extracts 26+ features from the input URL
2. **ML Classification**: A Random Forest classifier analyzes these features
3. **Prediction**: Returns whether the URL is "Phishing" or "Legitimate"
4. **Confidence Score**: Shows the model's confidence in its prediction

## Technologies Used

- **Backend**: Flask (Python web framework)
- **Machine Learning**: Scikit-learn (Random Forest Classifier)
- **Frontend**: HTML5, CSS3, Bootstrap 5, jQuery
- **Data Processing**: Pandas, NumPy
- **Model Persistence**: Joblib

## Model Performance

The model is trained on a comprehensive dataset with 97 URLs (50 legitimate, 47 phishing):
- **Accuracy**: High accuracy in detecting phishing patterns
- **Training Data**: Includes real-world phishing patterns
- **Detection**: Successfully identifies suspicious TLDs, URL shorteners, and malicious patterns

## Disclaimer

This tool is for educational and research purposes only. It should not be used as the sole method for determining website legitimacy. Always exercise caution when visiting unfamiliar websites.

## Author

Created as a cybersecurity educational project demonstrating machine learning applications in threat detection.
