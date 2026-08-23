from flask import Flask, request, jsonify
import joblib
import pandas as pd
from urllib.parse import urlparse
import re

app = Flask(__name__)


model = joblib.load("phishing_model.pkl")


columns = list(model.feature_names_in_)


def extract_features(url):
    features = {}
    
    parsed = urlparse(url)
    hostname = parsed.hostname if parsed.hostname else ""
    path = parsed.path if parsed.path else ""

    
    for col in columns:
        features[col] = 0

    
    for col in columns:
        if col in ['n_dots', 'n_dot', 'count_dot']:
            features[col] = url.count('.')
        elif col in ['n_hyphen', 'n_hyphens', 'count_hyphen']:
            features[col] = url.count('-')
        elif col in ['n_at', 'count_at']:
            features[col] = url.count('@')
        elif col in ['n_slash', 'count_slash']:
            features[col] = url.count('/')
        elif col in ['n_questionmark', 'count_question']:
            features[col] = url.count('?')
        elif col in ['n_equal', 'count_equal']:
            features[col] = url.count('=')
        elif col in ['n_digit', 'count_digit']:
            features[col] = sum(c.isdigit() for c in url)
        elif col in ['n_hostname_length', 'hostname_length']:
            features[col] = len(hostname)
        elif col in ['n_url_length', 'url_length']:
            features[col] = len(url)
        elif col in ['contains_suspicious_word']:
            suspicious_words = ["secure", "account", "update", "free", "verify", "login", "bank"]
            features[col] = int(any(word in url.lower() for word in suspicious_words))
        elif col in ['contains_ip']:
            features[col] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))


    return [features[col] for col in columns]


@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "Please send JSON with 'url' key"}), 400

    url = data['url']

    try:
        feature_values = extract_features(url)
        features_df = pd.DataFrame([feature_values], columns=columns)

        prediction = model.predict(features_df)[0]
        confidence = float(model.predict_proba(features_df).max())

        result = "Legitimate" if prediction == 0 else "Phishing"

        return jsonify({
            "url": url,
            "prediction": result,
            "confidence_score": int(confidence*100)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/')
def home():
    return app.send_static_file("index.html")

if __name__ == '__main__':
    app.run(debug=True)



