# Accurate Phishing URL Detector - ML & Rule-Based Web Application

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-black?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.x-orange?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)

## **Overview**

This project implements a web application and browser extension designed to detect phishing URLs using a combination of a machine learning model (Random Forest(Future - Logistic Regression)) and a rule-based scoring system. The application provides a user-friendly interface to analyze URLs, view historical scans, and offers an API endpoint for real-time checks, utilized by the accompanying Chrome extension.

The ML model is trained on the PhiUSIIL dataset using 7 carefully selected, lightweight lexical features, allowing for fast and efficient prediction suitable for live deployment.

**Live Application:** `https://ml-phish-detector.onrender.com/`

---

## **Features**

* **Web Interface:** A Flask-based web UI for manually entering and analyzing URLs.
* **Machine Learning Prediction:** Utilizes a trained Logistic Regression model (served via Flask API) to classify URLs as "Legitimate" or "Phishing" with a confidence score.
* **Rule-Based Scoring:** Implements a secondary scoring system based on common phishing URL patterns (IP address usage, long URLs, suspicious characters, etc.).
* **Analysis History:** Keeps track of recent URL scans in the web interface.
* **CSV Download:** Allows users to download their scan history.
* **API Endpoint:** Provides a `/predict` endpoint for programmatic URL analysis.
* **Browser Extension:** A simple Chrome extension that calls the live API to check the current tab's URL in real-time. 

---

## **Technology Stack**

* **Backend:** Python 3, Flask
* **Machine Learning:** Scikit-learn, Pandas, NumPy
* **Web Frontend:** HTML, CSS, JavaScript (basic, via Flask Templates)
* **Browser Extension:** JavaScript (Manifest V3), HTML, CSS
* **Deployment:** Render (or similar cloud platform), Git/GitHub

---

## **Setup and Installation (Local Development)**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Aiman-D/ml-phish-detector
    cd ml-phish-detector
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **(Optional) Train the Model:** If you don't have the `data/model.pkl` file or want to retrain:
    ```bash
    # Ensure your training data CSV is in the correct location (e.g., data/)
    python3 train_model.py --train_csv data/PhiUSIIL_Phishing_URL_Dataset.csv --out_model data/model.pkl
    ```

5.  **Run the Flask application:**
    ```bash
    python3 app.py
    ```
    The application will be available at `http://127.0.0.1:8000`.

---

## **Training the Model**

The machine learning model (`model.pkl`) is generated using the `train_model.py` script. It performs the following steps:

1.  Loads the URL and label data from the specified CSV file (expects PhiUSIIL format).
2.  Applies the custom `extract_features` function (7 lexical features with host/path normalization) to each URL.
3.  Splits the data into training and testing sets.
4.  Creates a Scikit-learn Pipeline that includes `StandardScaler` for feature normalization and `LogisticRegression` for classification.
5.  Trains the pipeline on the training data.
6.  Evaluates the model on the test set and prints the accuracy.
7.  Saves the trained pipeline (including the scaler and model) to the specified output path (`data/model.pkl`).

To retrain the model:
```bash
python3 train_model.py--train_csv data/PhiUSIIL_Phishing_URL_Dataset.csv --out_model data/model.pkl
```
---

## **Sample Data Generation**

The `sample_data_generator.py` script (if included) can be used to create smaller subsets of the main dataset (e.g., `train_small.csv`, `real_dataset.csv`). This is useful for faster local testing, debugging feature extraction, or quick model training iterations without processing the full large dataset.

Example Usage (Modify script as needed):
```bash
python3 sample_data_generator.py --input_csv data/PhiUSIIL_Phishing_URL_Dataset.csv --output_csv data/train_small.csv --num_rows 1000
```

---

## **Browser Extension**

The `extension/` folder contains the source code for a simple Chrome browser extension that interacts with the deployed API.

**Features:**
* Automatically fetches the URL of the currently active tab.
* Sends the URL to the live API endpoint (`/predict`).
* Displays the ML prediction ("Legitimate" or "Phishing") and confidence score.
* Shows the 7 feature values used by the ML model for the prediction.

**Installation Steps:**

1.  **Configure API Endpoint:** Ensure the `API_ENDPOINT` variable in `extension/popup.js` points to your live deployment URL (e.g., `https://ml-phish-detector.onrender.com/predict`).
2.  **Navigate to Extensions:** Open Chrome (or a Chromium-based browser) and go to `chrome://extensions`.
3.  **Enable Developer Mode:** Find the **Developer mode** toggle switch (usually in the top-right corner) and turn it **ON**. \
4.  **Load the Extension:** Click the **Load unpacked** button. A file dialog will open.
5.  **Select Folder:** Navigate to your project directory and select the **`extension/`** folder. Click "Select Folder".
6.  **Verify and Pin:** The extension icon should appear. Click the puzzle piece icon in your toolbar and click the pin icon next to "Accurate Phishing Detector" to keep it visible.

---

## **Project Journey & Key Learnings**

Developing this project involved overcoming several common challenges in deploying ML web applications:

* **Feature Alignment:** Ensuring the features extracted during live prediction exactly matched those used during training was critical. This required standardizing URL inputs (handling `https://`, `www.`, trailing slashes).
* **Deployment Path Issues:** Loading the `model.pkl` file reliably on the deployment server (Render) required using robust absolute path logic (`os.path.abspath`) instead of simple relative paths.
* **CORS Configuration:** Enabling the browser extension (running on `chrome-extension://`) to communicate with the API (running on `https://*.onrender.com`) required specific CORS configuration in the Flask app (`Flask-CORS`), particularly handling preflight `OPTIONS` requests.
* **Serialization Errors:** Returning NumPy arrays directly from the Flask API caused JSON serialization errors, necessitating conversion to standard Python lists before sending the response.
* **Model Selection & Confidence:** While initially using RandomForest (which sometimes gave 100% confidence for clear phishing due to unanimous tree votes), switching to Logistic Regression provided more interpretable probability scores suitable for user feedback. Extremely strong phishing signals (like using an IP address directly) can still result in very high (~100%) confidence scores even with Logistic Regression, as the model becomes highly certain based on that single powerful feature.
