# phish_detect.py
import re
from urllib.parse import urlparse
import os, pickle, math
from collections import Counter

MODEL_PATH = "data/model.pkl"
_pipeline = None  # lazy-loaded pipeline

# ---------- Feature extraction (per single URL) ----------
def extract_features(url: str):
    """Return dict of handcrafted features for a single URL."""
    s = url if url.startswith(("http://","https://")) else "http://" + url
    parsed = urlparse(s)
    host = parsed.hostname or ""
    path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    len_url = len(url)
    len_host = len(host)
    count_digits = sum(c.isdigit() for c in url)
    subdomains = max(0, host.count('.') - 1)
    cnt = Counter(path)
    L = len(path) if len(path) else 1
    ent = -sum((c/L) * (math.log2(c/L)) for c in cnt.values()) if L > 0 else 0.0
    non_alnum = sum(1 for c in url if not c.isalnum()) / max(1, len(url))
    has_ip = bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host))
    return {
        'len_url': len_url,
        'len_host': len_host,
        'count_digits': count_digits,
        'subdomains': subdomains,
        'has_ip': int(has_ip),
        'non_alnum_ratio': non_alnum,
        'path_entropy': ent
    }

# ---------- FunctionTransformer-compatible function ----------
def handcrafted_features(urls):
    """
    Accepts an iterable of URLs and returns a list of dicts (one dict per URL).
    This function must be importable by name (so pipelines referencing it can be unpickled).
    """
    return [extract_features(u) for u in urls]

# ---------- Lazy pipeline loader ----------
def load_pipeline():
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as fh:
                _pipeline = pickle.load(fh)
            print("✅ ML pipeline loaded from", MODEL_PATH)
        except Exception as e:
            _pipeline = None
            print("⚠️ Failed to load ML pipeline:", e)
    else:
        print("⚠️ No ML pipeline found at", MODEL_PATH)
    return _pipeline

# ---------- Rule-based classifier ----------
def rule_score(url: str):
    f = extract_features(url)
    score = 0
    reasons = []

    if f['has_ip']:
        score += 3; reasons.append("IP address used in domain")
    if f['len_url'] > 75:
        score += 2; reasons.append(f"URL length {f['len_url']} > 75")
    if f['subdomains'] > 1:
        score += 2; reasons.append(f"{f['subdomains']} subdomains")
    if '@' in url:
        score += 3; reasons.append("Contains '@' character")
    if '-' in url:
        reasons.append("Contains dash '-'")
    if f['count_digits'] > 4:
        reasons.append(f"{f['count_digits']} digits in URL")
    if f['non_alnum_ratio'] > 0.25:
        reasons.append("High non-alphanumeric character ratio")
    if f['path_entropy'] > 3.5:
        reasons.append("High path entropy")
    if f['len_host'] < 20 and not f['has_ip'] and f['subdomains'] == 0:
        reasons.append("Short host, likely legitimate")

    label = "phishing" if score >= 2 else "legitimate"
    return {'url': url, 'score': score, 'label': label, 'reasons': reasons, 'features': f}

# ---------- ML predict using saved pipeline ----------
def ml_predict(url: str):
    """
    Returns (label_str, confidence_float) or (None, None) if ML pipeline not available.
    Label strings: 'Phishing' or 'Legitimate'
    """
    pipe = load_pipeline()
    if pipe is None:
        return None, None

    try:
        # Our pipeline expects raw URLs (FunctionTransformer -> DictVectorizer -> clf)
        probs = pipe.predict_proba([url])[0]
        pred = pipe.predict([url])[0]
    except Exception:
        # fallback: transform manually using handcrafted_features
        feats = handcrafted_features([url])
        probs = pipe.predict_proba(feats)[0]
        pred = pipe.predict(feats)[0]

    if pred == 1:
        return "Phishing", round(float(probs[1]) * 100, 1)
    else:
        return "Legitimate", round(float(probs[0]) * 100, 1)

# ---------- helper to highlight suspicious segments ----------
def highlight_suspicious_parts(url: str):
    tokens = []
    suspicious_words = ['login','secure','verify','account','update','confirm']
    parts = re.split(r'([/:@?&=._-])', url)
    for p in parts:
        lp = p.lower()
        if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', p):
            tokens.append((p, True))
        elif p == '@':
            tokens.append((p, True))
        elif any(w in lp for w in suspicious_words):
            tokens.append((p, True))
        else:
            tokens.append((p, False))
    return tokens
