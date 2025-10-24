import os, pickle
from flask import Flask, render_template, request, make_response, jsonify
from flask_cors import CORS
import phish_detect
import io, csv, datetime, re, json
from urllib.parse import urlparse
import sys

# --- Model Loading Configuration ---
_pipeline = None
MODEL_PATH = None
MAX_HISTORY = 200

# -----------------------------------------------------------------
# ---------- Load ML pipeline (Robust Absolute Path Fix) ----------
# -----------------------------------------------------------------
# This logic loads the model from the 'data' folder relative to this script.
try:
    # Start from the current file's directory (app.py)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Walk up the tree until the project root is likely found
    # (We assume the project root is the directory containing the 'data' folder)
    path_check = current_dir
    for _ in range(5): # Check up to 5 parent directories
        potential_path = os.path.join(path_check, "data", "model.pkl")
        if os.path.exists(potential_path):
            MODEL_PATH = potential_path
            break
        # Move up one directory level
        path_check = os.path.dirname(path_check)
        if path_check == "/": # Stop at the system root
            break

    if MODEL_PATH and os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                _pipeline = pickle.load(f)
            print(f"✅ ML pipeline loaded successfully from: {MODEL_PATH}")
        except Exception as e:
            print(f"⚠️ Failed to load ML pipeline: {e}")
    else:
        print(f"⚠️ No ML pipeline found. Tried path relative to: {current_dir}")
except Exception as e_path:
     print(f"⚠️ Error during path finding: {e_path}")


# --- Flask App Initialization ---
app = Flask(__name__, static_folder="static")
CORS(app) # Enable CORS for all routes

HISTORY = []


def is_valid_url(url: str) -> bool:
    """
    Stricter-but-flexible validation:
    - Accept if hostname contains a dot (example.com) or is an IPv4 address.
    """
    if not isinstance(url, str) or not url.strip():
        return False

    has_scheme = url.lower().startswith(("http://", "https://"))
    s = url if has_scheme else "http://" + url
    parsed = urlparse(s)
    host = parsed.hostname or ""

    # IP address check
    ip_match = re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host)

    # If host contains a dot or is IP -> accept
    if '.' in host or ip_match:
        return True

    # If host has no dot: accept only when user explicitly provided scheme and there is a path
    if has_scheme and host and parsed.path:
        return True

    return False

# --- API Endpoint for Extension ---
@app.route("/predict", methods=["POST"])
def predict():
    """API endpoint for the browser extension or external tools."""
    data = request.get_json()
    url_input = data.get("url", "").strip()

    if not url_input or not is_valid_url(url_input):
        return jsonify({"error": "Invalid URL provided"}), 400

    # 1. Rule-based detection
    rule_data = phish_detect.rule_score(url_input)

    # 2. ML prediction (PASS THE LOADED MODEL)
    ml_label, ml_conf = phish_detect.ml_predict(url_input, _pipeline)
    
    # Assemble and return the results
    return jsonify({
        "url": url_input,
        "rule_label": rule_data['label'],
        "rule_score": rule_data['score'],
        "reasons": rule_data['reasons'],
        "ml_label": ml_label,
        "ml_conf": ml_conf,
    })


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    ml_label = None
    ml_conf = None
    highlights = None
    use_ml = False
    error_msg = None

    if request.method == "POST":
        url_input = request.form.get("url_input", "").strip()
        use_ml = "use_ml" in request.form

        if not url_input:
            error_msg = "⚠️ Please enter a URL."
        elif not is_valid_url(url_input):
            error_msg = "⚠️ Invalid URL. Please enter a proper URL (e.g., http://example.com)."
        else:
            # Rule-based detection
            result = phish_detect.rule_score(url_input)
            highlights = phish_detect.highlight_suspicious_parts(url_input)

            # ML prediction (PASS THE LOADED MODEL)
            if use_ml:
                ml_label, ml_conf = phish_detect.ml_predict(url_input, _pipeline)

            # Add entry to history
            entry = {
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "url": url_input,
                "rule_label": result['label'],
                "ml_label": ml_label if ml_label is not None else "n/a",
                "ml_conf": ml_conf if ml_conf is not None else 0
            }
            HISTORY.insert(0, entry)
            if len(HISTORY) > MAX_HISTORY:
                HISTORY.pop()

            # CSV download
            if request.form.get("download") == "1":
                si = io.StringIO()
                w = csv.writer(si)
                w.writerow(["time","url","rule_label","ml_label","ml_conf"])
                for h in HISTORY:
                    w.writerow([h["time"], h["url"], h["rule_label"], h["ml_label"], h["ml_conf"]])
                mem = io.BytesIO()
                mem.write(si.getvalue().encode("utf-8"))
                mem.seek(0)
                resp = make_response(mem.read())
                resp.headers.set("Content-Type", "text/csv; charset=utf-8")
                resp.headers.set("Content-Disposition", "attachment", filename="phish_history.csv")
                return resp

    # Analytics
    total = len(HISTORY)
    phish_count = sum(1 for h in HISTORY if h['rule_label']=='Phishing')
    ml_phish = sum(1 for h in HISTORY if h.get('ml_label') == 'Phishing')

    # Chart data
    history_times = [h["time"] for h in HISTORY]
    history_rule_labels = [1 if h["rule_label"]=="Phishing" else 0 for h in HISTORY]
    history_ml_labels = [1 if h.get("ml_label")=="Phishing" else 0 for h in HISTORY]

    # JSON-safe versions for embedding in template
    history_times_json = json.dumps(history_times)
    history_rule_labels_json = json.dumps(history_rule_labels)
    history_ml_labels_json = json.dumps(history_ml_labels)

    return render_template(
        "index.html",
        result=result, ml_label=ml_label, ml_conf=ml_conf,
        highlights=highlights, history=HISTORY, total=total,
        phish_count=phish_count, ml_phish=ml_phish, use_ml=use_ml,
        history_times_json=history_times_json,
        history_rule_labels_json=history_rule_labels_json,
        history_ml_labels_json=history_ml_labels_json,
        error_msg=error_msg
    )

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    # Note: On Render, the host must be 0.0.0.0 for external access
    app.run(host="0.0.0.0", port=port, debug=True) # Added debug=True for better local testing