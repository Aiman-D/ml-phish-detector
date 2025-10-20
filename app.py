from flask import Flask, render_template, request, make_response
import phish_detect
import io, csv, datetime, re, json
from urllib.parse import urlparse

app = Flask(__name__, static_folder="static")

HISTORY = []
MAX_HISTORY = 200

def is_valid_url(url: str) -> bool:
    """
    Stricter-but-flexible validation:
    - Accept if hostname contains a dot (example.com) or is an IPv4 address.
    - If hostname has no dot, accept only when the user included an explicit scheme
      (http:// or https://) and there is a path (e.g. http://paypal/free/...)
    - Reject plain inputs like "abcd" (no scheme, no dot).
    """
    if not isinstance(url, str) or not url.strip():
        return False

    original = url
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

    # If there's no host but path starts with '/', allow (cases like http://127.0.0.1/ handled above)
    if not host and parsed.path and parsed.path.startswith('/'):
        return True

    return False

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

            # ML prediction
            if use_ml:
                ml_label, ml_conf = phish_detect.ml_predict(url_input)

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
    phish_count = sum(1 for h in HISTORY if h['rule_label']=='phishing')
    ml_phish = sum(1 for h in HISTORY if h.get('ml_label') == 'Phishing')

    # Chart data
    history_times = [h["time"] for h in HISTORY]
    history_rule_labels = [1 if h["rule_label"]=="phishing" else 0 for h in HISTORY]
    history_ml_labels = [1 if h.get("ml_label")=="Phishing" else 0 for h in HISTORY]

    # JSON-safe versions for embedding in template (use | safe in template)
    history_times_json = json.dumps(history_times)
    history_rule_labels_json = json.dumps(history_rule_labels)
    history_ml_labels_json = json.dumps(history_ml_labels)

    return render_template(
        "index.html",
        result=result, ml_label=ml_label, ml_conf=ml_conf,
        highlights=highlights, history=HISTORY, total=total,
        phish_count=phish_count, ml_phish=ml_phish, use_ml=use_ml,
        history_times=history_times, history_rule_labels=history_rule_labels,
        history_ml_labels=history_ml_labels, error_msg=error_msg,
        history_times_json=history_times_json,
        history_rule_labels_json=history_rule_labels_json,
        history_ml_labels_json=history_ml_labels_json
    )

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
