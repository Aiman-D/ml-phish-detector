import os, pickle
from flask import Flask, render_template, request, make_response, jsonify
from flask_cors import CORS # Ensure this is imported
import phish_detect
import io, csv, datetime, re, json
from urllib.parse import urlparse
import sys
import traceback # Import for detailed error logging

# --- Model Loading Configuration ---
_pipeline = None
MODEL_PATH = None
MAX_HISTORY = 200

# --- Load ML pipeline ---
# (Using the robust path finding logic - NO CHANGE HERE)
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    path_check = current_dir
    for _ in range(5): 
        potential_path = os.path.join(path_check, "data", "model.pkl")
        if os.path.exists(potential_path):
            MODEL_PATH = potential_path
            break
        path_check = os.path.dirname(path_check)
        if path_check == "/": break
    if MODEL_PATH and os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f: _pipeline = pickle.load(f)
            print(f"✅ ML pipeline loaded successfully from: {MODEL_PATH}")
        except Exception as e: print(f"⚠️ Failed to load ML pipeline: {e}")
    else: print(f"⚠️ No ML pipeline found. Tried path relative to: {current_dir}")
except Exception as e_path: print(f"⚠️ Error during path finding: {e_path}")

# --- Flask App Initialization ---
app = Flask(__name__, static_folder="static")

# --- SIMPLIFIED CORS INITIALIZATION ---
# Let Flask-CORS handle the defaults, which are often more robust.
CORS(app) 
# ------------------------------------

HISTORY = []

def is_valid_url(url: str) -> bool:
    # ... (Your existing is_valid_url function - NO CHANGE) ...
    if not isinstance(url, str) or not url.strip(): return False
    has_scheme = url.lower().startswith(("http://", "https://"))
    s = url if has_scheme else "http://" + url
    parsed = urlparse(s); host = parsed.hostname or ""
    ip_match = re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host)
    if '.' in host or ip_match: return True
    if has_scheme and host and parsed.path: return True
    return False

# --- API Endpoint for Extension (with Error Logging) ---
@app.route("/predict", methods=["POST"]) # No OPTIONS needed explicitly with simple CORS(app)
def predict():
    try: # --- ADDED TRY BLOCK ---
        data = request.get_json()
        if not data:
             print("⚠️ API /predict: Received empty JSON data")
             return jsonify({"error": "No JSON data received"}), 400
             
        url_input = data.get("url", "").strip()

        if not url_input or not is_valid_url(url_input):
            print(f"⚠️ API /predict: Invalid URL received: {url_input}")
            return jsonify({"error": "Invalid URL provided"}), 400

        # --- Log the URL being processed ---
        print(f"✅ API /predict: Processing URL: {url_input}")

        # Rule-based detection (keep this simple for now)
        rule_data = phish_detect.rule_score(url_input) 
        
        # ML prediction
        ml_label, ml_conf, ml_features = phish_detect.ml_predict(url_input, _pipeline)
        
        # --- Log the prediction result ---
        print(f"✅ API /predict: Prediction result: {ml_label} ({ml_conf}%)")
        
        return jsonify({
            "url": url_input,
            "rule_label": rule_data.get('label', 'N/A'), # Use .get for safety
            "rule_score": rule_data.get('score', 0),
            "ml_label": ml_label,
            "ml_conf": ml_conf,
            "features_ml": ml_features
        })
        
    except Exception as e: # --- ADDED EXCEPT BLOCK ---
        # Log the exact error causing the 500 crash
        print(f"💥 API /predict CRASHED: {e}")
        traceback.print_exc() # Print detailed traceback to Render logs
        return jsonify({"error": "Internal Server Error during prediction"}), 500


@app.route("/", methods=["GET", "POST"])
def index():
    # ... (Your existing index route - NO CHANGES NEEDED) ...
    result = None; ml_label = None; ml_conf = None; highlights = None
    use_ml = False; error_msg = None; ml_features = []
    if request.method == "POST":
        url_input = request.form.get("url_input", "").strip()
        use_ml = "use_ml" in request.form
        if not url_input: error_msg = "⚠️ Please enter a URL."
        elif not is_valid_url(url_input): error_msg = "⚠️ Invalid URL."
        else:
            result = phish_detect.rule_score(url_input)
            highlights = phish_detect.highlight_suspicious_parts(url_input)
            if use_ml:
                ml_label, ml_conf, ml_features = phish_detect.ml_predict(url_input, _pipeline)
            entry = {"time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "url": url_input, "rule_label": result['label'],
                     "ml_label": ml_label if ml_label is not None else "n/a", "ml_conf": ml_conf if ml_conf is not None else 0}
            HISTORY.insert(0, entry); 
            if len(HISTORY) > MAX_HISTORY: HISTORY.pop()
            if request.form.get("download") == "1":
                si = io.StringIO(); w = csv.writer(si); w.writerow(["time","url","rule_label","ml_label","ml_conf"])
                for h in HISTORY: w.writerow([h["time"], h["url"], h["rule_label"], h["ml_label"], h["ml_conf"]])
                mem = io.BytesIO(); mem.write(si.getvalue().encode("utf-8")); mem.seek(0)
                resp = make_response(mem.read())
                resp.headers.set("Content-Type", "text/csv; charset=utf-8")
                resp.headers.set("Content-Disposition", "attachment", filename="phish_history.csv")
                return resp
    total = len(HISTORY); phish_count = sum(1 for h in HISTORY if h['rule_label']=='Phishing')
    ml_phish = sum(1 for h in HISTORY if h.get('ml_label') == 'Phishing')
    history_times = [h["time"] for h in HISTORY]; history_rule_labels = [1 if h["rule_label"]=="Phishing" else 0 for h in HISTORY]
    history_ml_labels = [1 if h.get("ml_label")=="Phishing" else 0 for h in HISTORY]
    history_times_json = json.dumps(history_times); history_rule_labels_json = json.dumps(history_rule_labels)
    history_ml_labels_json = json.dumps(history_ml_labels)
    return render_template(
        "index.html", result=result, ml_label=ml_label, ml_conf=ml_conf, highlights=highlights, history=HISTORY, total=total,
        phish_count=phish_count, ml_phish=ml_phish, use_ml=use_ml, history_times_json=history_times_json,
        history_rule_labels_json=history_rule_labels_json, history_ml_labels_json=history_ml_labels_json,
        error_msg=error_msg, ml_features=ml_features
    )

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    # Remove debug=True for production
    app.run(host="0.0.0.0", port=port)