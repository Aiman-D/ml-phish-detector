import re
from urllib.parse import urlparse
import math
from collections import Counter
import numpy as np
import os

# -------------------------------------------------------------
# ---------- FEATURE EXTRACTION (Matches training script)
# -------------------------------------------------------------
def extract_features(url: str):
    s = url if url.startswith(("http://","https://")) else "http://" + url
    parsed = urlparse(s)
    host = parsed.hostname or ""
    path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    
    # --- FINAL PATH NORMALIZATION FIX ---
    if path == "/":
        path = ""
    
    # --- HOST NORMALIZATION FIX ---
    normalized_host = host.lower()
    if normalized_host.startswith('www.'):
        normalized_host = normalized_host[4:] 
    
    base_url_string = normalized_host + path 

    # --- Feature Calculations ---
    len_url = len(base_url_string) 
    len_host = len(normalized_host) 
    count_digits = sum(c.isdigit() for c in base_url_string) 
    subdomains = max(0, normalized_host.count('.') - 1)
    
    cnt = Counter(path)
    L = len(path) if len(path) else 1
    ent = -sum((c/L) * (math.log2(c/L)) for c in cnt.values()) if L > 0 else 0.0
    
    non_alnum = sum(1 for c in base_url_string if not c.isalnum()) / max(1, len(base_url_string))
    
    has_ip = bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host))

    # This is the 7-feature vector
    features = [len_url, len_host, count_digits, subdomains, int(has_ip), non_alnum, ent]
    return features

# -------------------------------------------------------------
# ---------- ML Prediction (Returns 3 values)
# -------------------------------------------------------------
def ml_predict(url: str, pipeline):
    """
    Predicts if a URL is phishing or legitimate using the provided pipeline.
    'pipeline' is the loaded scikit-learn model object.
    """
    if pipeline is None:
        return "n/a", 0, [] # Return empty features list
    try:
        features = np.array([extract_features(url)]) 
            
        pred = pipeline.predict(features)[0]
        probs = pipeline.predict_proba(features)[0]
        
        # PhiUSIIL labels: 1 is legitimate, 0 is phishing
        if pred == 1:
            # Return 'Legitimate', probability of Legitimate, and the features
            return "Legitimate", round(float(probs[1]) * 100, 1), features[0]
        else:
            # Return 'Phishing', probability of Phishing, and the features
            return "Phishing", round(float(probs[0]) * 100, 1), features[0]
            
    except Exception as e:
        print(f"⚠️ ML prediction error: {e}")
        return "n/a", 0, []

# -------------------------------------------------------------
# ---------- Rule-based detection (No Change)
# -------------------------------------------------------------
def rule_score(url: str):
    s = url if url.startswith(("http://","https://")) else "http://" + url
    parsed = urlparse(s)
    host = parsed.hostname or ""
    path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    len_url = len(url); len_host = len(host); count_digits = sum(c.isdigit() for c in url)
    subdomains = max(0, host.count('.') - 1); cnt = Counter(path); L = len(path) if len(path) else 1
    ent = -sum((c/L) * (math.log2(c/L)) for c in cnt.values()) if L > 0 else 0.0
    non_alnum = sum(1 for c in url if not c.isalnum()) / max(1, len(url))
    has_ip = bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host)); score = 0; reasons = []
    if has_ip: score += 3; reasons.append("IP address used in domain")
    if len_url > 75: score += 2; reasons.append(f"URL length {len_url} > 75")
    if subdomains > 1: score += 2; reasons.append(f"{subdomains} subdomains")
    if '@' in url: score += 3; reasons.append("Contains '@' character")
    if '-' in url: reasons.append("Contains dash '-'")
    if count_digits > 4: reasons.append(f"{count_digits} digits in URL")
    if non_alnum > 0.25: reasons.append("High non-alphanumeric character ratio")
    if ent > 3.5: reasons.append("High path entropy")
    if len_host < 20 and not has_ip and subdomains == 0: reasons.append("Short host, likely legitimate")
    label = "Phishing" if score >= 2 else "Legitimate"
    return { 'url': url, 'score': score, 'label': label, 'reasons': reasons,
        'features': { 'len_url': len_url, 'len_host': len_host, 'count_digits': count_digits, 
                      'subdomains': subdomains, 'has_ip': int(has_ip), 'non_alnum_ratio': non_alnum, 'path_entropy': ent }}

# -------------------------------------------------------------
# ---------- Highlight suspicious parts (No Change)
# -------------------------------------------------------------
def highlight_suspicious_parts(url: str):
    tokens = []; suspicious_words = ['login','secure','verify','account','update','confirm']
    parts = re.split(r'([/:@?&=._-])', url)
    for p in parts:
        lp = p.lower()
        if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', p): tokens.append((p, True))
        elif p == '@': tokens.append((p, True))
        elif any(w in lp for w in suspicious_words): tokens.append((p, True))
        else: tokens.append((p, False))
    return tokens