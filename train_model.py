import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle
import argparse
import sys
from urllib.parse import urlparse
from collections import Counter
import math
import re

# ---------- Argument parser ----------
parser = argparse.ArgumentParser()
parser.add_argument('--train_csv', type=str, required=True, help='Path to CSV file with URLs and labels')
parser.add_argument('--out_model', type=str, required=True, help='Path to save trained model')
args = parser.parse_args()

# -------------------------------------------------------------
# ---------- FEATURE EXTRACTION (The 7 features used for training)
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

# ---------- Load dataset and extract features ----------
print("[*] Attempting to load dataset and extract 7 features...")

try:
    # Load only the 'URL' and 'label' columns, using the header.
    df = pd.read_csv(
        args.train_csv,
        usecols=['URL', 'label'],
        header=0,
        low_memory=False
    )
    print("[*] Dataset loaded successfully.")

except Exception as e:
    print(f"\n--- FATAL ERROR ---")
    print(f"Could not load CSV. Error: {e}")
    sys.exit(1)

# ---------- Data Processing and Feature Engineering ----------
try:
    # Apply the 7-feature extraction to every URL in the training set
    print("[*] Extracting 7 features from all URLs...")
    X = df['URL'].apply(extract_features).tolist()
    
    # Ensure labels are integers
    y = df['label'].astype(int).tolist()
    
except Exception as e_proc:
    print(f"\n--- FATAL ERROR DURING DATA PROCESSING ---")
    print(f"Error: {e_proc}")
    sys.exit(1)

# ---------- Train/test split ----------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ---------- Train Random Forest (7 calculated features) ----------
print("[*] Fitting Random Forest model (this may take a bit)...")
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# ---------- Save model ----------
with open(args.out_model, "wb") as f:
    pickle.dump(clf, f)

print("[*] Model saved to", args.out_model)

# ---------- Evaluate ----------
acc = clf.score(X_test, y_test)
print(f"[*] Test Accuracy: {acc:.4f}")
