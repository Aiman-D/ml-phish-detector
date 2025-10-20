# train_model.py
import pandas as pd
import argparse
import pickle
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier

# import the canonical handcrafted_features from phish_detect so pickle references phish_detect.handcrafted_features
import phish_detect

parser = argparse.ArgumentParser()
parser.add_argument("--train_csv", required=True, help="CSV path with url,label")
parser.add_argument("--out_model", required=True, help="Output pickle path")
args = parser.parse_args()

# Load CSV
df = pd.read_csv(args.train_csv)
X_raw = df['url'].astype(str).tolist()
y = df['label'].astype(int).tolist()

# Build pipeline: handcrafted_features (list of dicts) -> DictVectorizer -> RandomForest
pipe = Pipeline([
    ("features", FunctionTransformer(phish_detect.handcrafted_features, validate=False)),
    ("vect", DictVectorizer(sparse=False)),
    ("clf", RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42))
])

print("[*] Fitting pipeline (this may take a bit)...")
pipe.fit(X_raw, y)

# Evaluate quickly on training set (for demo)
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
preds = pipe.predict(X_raw)
print("Accuracy:", accuracy_score(y, preds))
print(classification_report(y, preds))
print("Confusion matrix:\n", confusion_matrix(y, preds))

# Save pipeline
with open(args.out_model, "wb") as fh:
    pickle.dump(pipe, fh)
print("Saved pipeline model to", args.out_model)
