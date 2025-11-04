# 🛡️ CyberShield – Phishing Detection System

**CyberShield** is an intelligent phishing detection and prevention system that combines **Machine Learning** and a **browser extension** to safeguard users from malicious websites and links.
It analyzes URLs in real time and detects phishing attempts using a trained CatBoost model integrated with a Flask backend.

---

## 🚀 Features

### 🔍 Machine Learning Backend (`phish-ml/`)

* Built using **Flask** and **CatBoost**.
* Extracts over 30+ features from URLs for phishing prediction.
* Provides REST API endpoints for:

  * `/predict` – Classifies URLs as *safe* or *phishing*.
  * `/health` – Checks service status.
* Logs predictions and handles errors gracefully.

### 🌐 Browser Extension (`Phising-extension/`)

* Detects phishing attempts directly while browsing.
* Real-time scanning of email links, social media links, and websites.
* Highlights unsafe links and warns users before visiting.
* Clean and responsive UI with dashboard integration.

---

## 🧠 Tech Stack

| Component     | Technology                               |
| ------------- | ---------------------------------------- |
| Backend       | Python (Flask), CatBoost, Pandas, Joblib |
| Frontend      | JavaScript, HTML, CSS (Chrome Extension) |
| Communication | REST API + CORS                          |
| Tools         | VS Code, Git, Node.js, npm               |

---

## 📂 Project Structure

```
CyberShield/
├── phish-ml/                     # Machine Learning backend
│   ├── app.py                    # Flask app for predictions
│   ├── feature_extraction.py     # Extracts URL-based features
│   ├── train_model.py            # Model training script
│   ├── models/                   # Saved ML models
│   ├── data/                     # Datasets (OpenPhish, Tranco, etc.)
│   ├── requirements.txt          # Python dependencies
│   └── .gitignore
│
└── Phising-extension/            # Browser extension frontend
    ├── manifest.json             # Chrome extension manifest
    ├── background.js             # Background event handler
    ├── popup.html / popup.js     # User interface popup
    ├── icons/                    # Extension icons
    ├── ml-detector.js            # Communicates with Flask backend
    ├── phishing-detector.js      # Core detection logic
    ├── package.json              # Node dependencies
    └── .gitignore
```

---

## ⚙️ Installation

### Backend Setup (Flask)

1. Navigate to the `phish-ml` folder:

   ```bash
   cd phish-ml
   ```
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
3. Run the backend:

   ```bash
   python app.py
   ```
4. The API will start at:
   **[http://localhost:5000](http://localhost:5000)**

---

### Frontend Setup (Chrome Extension)

1. Open **Chrome → Extensions → Manage Extensions**
2. Enable **Developer Mode** (top right).
3. Click **Load unpacked** → select the `Phising-extension` folder.
4. The extension will appear in the toolbar — ready to detect phishing sites!

---

## 🧪 Example API Usage

**POST Request to /predict**

```bash
curl -X POST http://localhost:5000/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "http://example.com"}'
```

**Response**

```json
{
  "url": "http://example.com",
  "prediction": 0,
  "confidence": 0.85
}
```

---

## 📊 Model Details

* **Algorithm:** CatBoost Classifier
* **Accuracy:** ~97%
* **Features Used:** URL length, domain age, special character counts, HTTPS presence, etc.

---

## 🔒 Security Note

No sensitive credentials or private keys are stored in this repository.
If deploying online, secure the API using authentication (e.g., API keys or tokens).

---

## 📄 License

This project is licensed under the **MIT License** — you’re free to use, modify, and distribute it.

---

## 👩‍💻 Author

**Sahala P**
A passionate developer exploring cybersecurity and intelligent web safety systems.

---
