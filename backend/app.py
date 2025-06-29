from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# === Feature extraction for phishing URL detection ===

URL_FEATURES = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
    'DomainInSubdomains', 'DomainInPaths'
]

def extract_url_features(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
        parts = hostname.split('.') if hostname else []
        root_domain = parts[-2] if len(parts) >= 2 else ''

        return {
            'NumDots': url.count('.'),
            'SubdomainLevel': hostname.count('.') - 1 if hostname else 0,
            'PathLevel': path.count('/'),
            'UrlLength': len(url),
            'NumDash': url.count('-'),
            'NumDashInHostname': hostname.count('-'),
            'AtSymbol': int('@' in url),
            'TildeSymbol': int('~' in url),
            'NumUnderscore': url.count('_'),
            'NumPercent': url.count('%'),
            'NumQueryComponents': query.count('='),
            'NumAmpersand': url.count('&'),
            'NumHash': url.count('#'),
            'NumNumericChars': sum(map(str.isdigit, url)),
            'NoHttps': int(not url.startswith('https')),
            'RandomString': int(len(path.replace('/', '')) > 15 and not re.search(r'[aeiou]{2,}', path)),
            'IpAddress': int(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', hostname) is not None),
            'DomainInSubdomains': int(root_domain in parts[:-2]) if root_domain else 0,
            'DomainInPaths': int(root_domain in path) if root_domain else 0
        }
    except Exception as e:
        print(f"[ERROR] Feature extraction failed: {e}")
        return {feat: 0 for feat in URL_FEATURES}

# === Load model safely ===

try:
    url_model = joblib.load('phishing_model.pkl')
    print("✅ Model loaded successfully.")
except Exception as e:
    url_model = None
    print(f"❌ Error loading model: {e}")

# === Routes ===

@app.route('/')
def home():
    return jsonify({"message": "✅ Phishing Detection API is Live!"})

@app.route('/predict/url', methods=['POST'])
def predict_url():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        features = extract_url_features(url)
        input_df = pd.DataFrame([features], columns=URL_FEATURES)

        if url_model is None:
            return jsonify({'error': 'Model not loaded'}), 500

        prediction = url_model.predict(input_df)[0]
        result = 'Phishing' if prediction == 1 else 'Legitimate'

        return jsonify({'result': result, 'features': features})
    except Exception as e:
        return jsonify({'error': f"Prediction failed: {e}"}), 500

# === Entry point for local run ===
if __name__ == '__main__':
    app.run(debug=True)
