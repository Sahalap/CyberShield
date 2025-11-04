# -*- coding: utf-8 -*-
"""
Quick test of the ML model
"""

import joblib
from feature_extraction import extract_features

def test_model():
    """Test the ML model on various URLs"""
    
    print("Testing ML model...")
    
    # Load the model
    try:
        model = joblib.load('models/catboost_model.pkl')
        print("✅ Model loaded successfully")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return
    
    # Test URLs
    test_urls = [
        # Suspicious URLs
        'https://bit.ly/suspicious-link',
        'https://tinyurl.com/fake-deal',
        'https://p4ypal-security.ml',
        'https://amaz0n-update.ga',
        'https://whatsapp-verify.tk',
        
        # Legitimate URLs
        'https://google.com',
        'https://youtube.com',
        'https://facebook.com',
        'https://wikipedia.org',
        'https://github.com'
    ]
    
    print("\nTesting URLs:")
    for url in test_urls:
        try:
            features = extract_features([url])
            prediction = model.predict(features)[0]
            probability = model.predict_proba(features)[0][1]
            
            result = "PHISHING" if prediction == 1 else "LEGITIMATE"
            confidence = probability if prediction == 1 else (1 - probability)
            
            print(f"  {url}")
            print(f"    -> {result} (confidence: {confidence:.3f})")
            
        except Exception as e:
            print(f"  {url} -> ERROR: {e}")
    
    print("\nModel test completed!")

if __name__ == "__main__":
    test_model()
