import re
from urllib.parse import urlparse
import os, pickle, math
from collections import Counter
import numpy as np

MODEL_PATH = "data/model.pkl"

# ---------- Load ML pipeline ----------
_pipeline = None
if os.path.exists(MODEL_PATH):
    try:
        with open(MODEL_PATH, "rb") as f:
            _pipeline = pickle.load(f)
        # Store expected features for validation
        _expected_features = _pipeline.n_features_in_
        print(f"✅ ML pipeline loaded from {MODEL_PATH}. Expects {_expected_features} features.")
    except Exception as e:
        print("⚠️ Failed to load ML pipeline:", e)
        _expected_features = 0
else:
    print("⚠️ No ML pipeline found at", MODEL_PATH)
    _expected_features = 0

# -------------------------------------------------------------
# ---------- FEATURE EXTRACTION (7 Features)
# -------------------------------------------------------------
def extract_features(url: str):
    # 1. Standardize the URL for parsing
    s = url if url.startswith(("http://","https://")) else "http://" + url
    parsed = urlparse(s)
    
    host = parsed.hostname or ""
    path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    
    # --- HOST NORMALIZATION FIX ---
    # Strip common prefixes for standardized feature calculation
    normalized_host = host.lower()
    if normalized_host.startswith('www.'):
        normalized_host = normalized_host[4:] # Remove 'www.' for better comparison
    
    # 2. Derive the base string for calculating overall URL features
    base_url_string = normalized_host + path 

    # --- Feature Calculations (using normalized host) ---
    len_url = len(base_url_string) 
    len_host = len(normalized_host) # Use normalized length
    count_digits = sum(c.isdigit() for c in base_url_string) 
    # Recalculate subdomains using the original host (or normalized host)
    subdomains = max(0, normalized_host.count('.') - 1)
    
    # Path Entropy
    cnt = Counter(path)
    L = len(path) if len(path) else 1
    ent = -sum((c/L) * (math.log2(c/L)) for c in cnt.values()) if L > 0 else 0.0
    
    # Non-Alphanumeric Ratio
    non_alnum = sum(1 for c in base_url_string if not c.isalnum()) / max(1, len(base_url_string))
    
    # Has IP Address
    has_ip = bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host))

    return [
        len_url, len_host, count_digits, subdomains, int(has_ip), non_alnum, ent
    ]

# -------------------------------------------------------------
# ---------- ML Prediction (Uses the 7 features above)
# -------------------------------------------------------------
def ml_predict(url: str):
    if _pipeline is None:
        return None, 0 # Changed "n/a" to None for template check
    try:
        # Extract the 7 features
        features = np.array([extract_features(url)]) 
        
        # Validate feature count
        if _expected_features != features.shape[1]:
            print(f"⚠️ Feature count mismatch: Model expects {_expected_features} features, but input has {features.shape[1]}.")
            return "n/a", 0
            
        pred = _pipeline.predict(features)[0]
        probs = _pipeline.predict_proba(features)[0]
        
        # PhiUSIIL labels: 1 is legitimate, 0 is phishing
        if pred == 1:
            return "Legitimate", round(float(probs[1]) * 100, 1)
        else:
            return "Phishing", round(float(probs[0]) * 100, 1)
            
    except Exception as e:
        print("⚠️ ML prediction error:", e)
        return "n/a", 0

# -------------------------------------------------------------
# ---------- Rule-based detection 
# -------------------------------------------------------------
def rule_score(url: str):
    """
    Calculates a phishing score based on lexical rules.
    This logic MUST mirror the feature extraction logic for feature calculation.
    """
    s = url if url.startswith(("http://","https://")) else "http://" + url
    parsed = urlparse(s)
    host = parsed.hostname or ""
    path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")

    # Recalculate features
    len_url = len(url)
    len_host = len(host)
    count_digits = sum(c.isdigit() for c in url)
    subdomains = max(0, host.count('.') - 1)
    cnt = Counter(path)
    L = len(path) if len(path) else 1
    ent = -sum((c/L) * (math.log2(c/L)) for c in cnt.values()) if L > 0 else 0.0
    non_alnum = sum(1 for c in url if not c.isalnum()) / max(1, len(url))
    has_ip = bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host))

    score = 0
    reasons = []

    if has_ip:
        score += 3; reasons.append("IP address used in domain")
    if len_url > 75:
        score += 2; reasons.append(f"URL length {len_url} > 75")
    if subdomains > 1:
        score += 2; reasons.append(f"{subdomains} subdomains")
    if '@' in url:
        score += 3; reasons.append("Contains '@' character")
    if '-' in url:
        reasons.append("Contains dash '-'")
    if count_digits > 4:
        reasons.append(f"{count_digits} digits in URL")
    if non_alnum > 0.25:
        reasons.append("High non-alphanumeric character ratio")
    if ent > 3.5:
        reasons.append("High path entropy")
    if len_host < 20 and not has_ip and subdomains == 0:
        reasons.append("Short host, likely legitimate")

    label = "Phishing" if score >= 2 else "Legitimate"
    return {
        'url': url,
        'score': score,
        'label': label,
        'reasons': reasons,
        'features': {
            'len_url': len_url,
            'len_host': len_host,
            'count_digits': count_digits,
            'subdomains': subdomains,
            'has_ip': int(has_ip),
            'non_alnum_ratio': non_alnum,
            'path_entropy': ent
        }
    }

# -------------------------------------------------------------
# ---------- Highlight suspicious parts 
# -------------------------------------------------------------
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
