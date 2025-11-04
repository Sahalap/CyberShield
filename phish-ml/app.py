from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import os
import pandas as pd
import joblib
from feature_extraction import extract_features

app = Flask(__name__)
CORS(app)  # Enable CORS for extension
logging.basicConfig(level=logging.INFO)

# Load model with error handling
model = None
try:
    if os.path.exists("models/catboost_model.pkl"):
        model = joblib.load("models/catboost_model.pkl")
        logging.info("✅ Model loaded successfully")
    else:
        logging.error("❌ Model file not found: models/catboost_model.pkl")
except Exception as e:
    logging.error(f"❌ Failed to load model: {e}")
    model = None

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        if not data or 'url' not in data:
            logging.warning("⚠️ No URL provided in request")
            return jsonify({"error": "No URL provided"}), 400
        
        url = data.get("url")
        if not isinstance(url, str) or not url.strip():
            logging.warning(f"⚠️ Invalid URL format: {url}")
            return jsonify({"error": "Invalid URL format"}), 400
        
        logging.info(f"🔍 Processing URL: {url}")
        
        # Extract features
        try:
            features_df = extract_features([url])
            logging.info(f"✅ Features extracted: {features_df.shape}")
        except Exception as e:
            logging.error(f"❌ Feature extraction failed: {e}")
            return jsonify({"error": f"Feature extraction failed: {str(e)}"}), 500
        
        if model is None:
            logging.error("❌ Model not available")
            return jsonify({"error": "Model not available"}), 503
        
        # Predict
        try:
            prediction = model.predict(features_df)[0]
            
            # Get probability/confidence
            if hasattr(model, 'predict_proba'):
                probability = model.predict_proba(features_df)[0][1]
            else:
                probability = 0.5
            
            # Ensure prediction is 0 or 1
            prediction = int(prediction)
            if prediction not in [0, 1]:
                logging.warning(f"⚠️ Unexpected prediction value: {prediction}, defaulting to 1")
                prediction = 1
            
            result = {
                "url": url,
                "prediction": prediction,  # 0 = safe, 1 = phishing
                "confidence": float(probability),  # Changed from 'probability' to 'confidence'
                "probability": float(probability),  # Keep both for compatibility
                "features": {}  # Optional: add feature values if needed
            }
            
            logging.info(f"✅ Prediction: {prediction} (confidence: {probability:.2f})")
            return jsonify(result)
            
        except Exception as e:
            logging.error(f"❌ Prediction failed: {e}")
            return jsonify({"error": f"Prediction failed: {str(e)}"}), 500
            
    except Exception as e:
        logging.error(f"❌ Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/health", methods=["GET"])
def health():
    status = {
        "status": "healthy",
        "model_loaded": model is not None,
        "version": "1.0.0"
    }
    logging.info(f"🏥 Health check: {status}")
    return jsonify(status)

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "PhishGuard ML Backend",
        "version": "1.0.0",
        "endpoints": {
            "/health": "GET - Check service health",
            "/predict": "POST - Predict phishing URLs"
        }
    })

if __name__ == "__main__":
    logging.info("🚀 Starting PhishGuard ML Backend on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)
