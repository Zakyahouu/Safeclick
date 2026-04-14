# SafeClick — model_trainer.py
# Trains a Random Forest on phishing data.
#
# Supports two dataset formats automatically:
#
#   A) UCI pre-extracted features (phishing.csv from the repo)
#      Columns: Index, UsingIP, LongURL, ShortURL, … class
#      Labels:  -1 = legitimate, 0 = suspicious, 1 = phishing
#      Source:  https://archive.ics.uci.edu/dataset/327/phishing+websites
#
#   B) Raw-URL format (phishing_dataset.csv)
#      Columns: url, label
#      Labels:  0 = safe, 1 = phishing

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix
import joblib

from feature_extractor import extract, to_vector


# ─── UCI column → our feature index mapping ───────────────────────────────────
# The UCI dataset has 30 pre-computed binary/ternary features.
# We map the ones that overlap with our extract() output.
# Remaining slots are filled with a neutral value so the vector stays valid.

UCI_FEATURE_MAP = {
    # UCI column name  : (our_feature_name, mapping_fn)
    "UsingIP":          ("has_ip",         lambda v: 1 if v == 1 else 0),
    "LongURL":          ("url_length",     lambda v: 150 if v == 1 else (80 if v == 0 else 40)),
    "ShortURL":         ("is_shortened",   lambda v: 1 if v == 1 else 0),
    "Symbol@":          ("has_at",         lambda v: 1 if v == 1 else 0),
    "Redirecting//":    ("double_slash",   lambda v: 1 if v == 1 else 0),
    "SubDomains":       ("subdomain_count",lambda v: 3 if v == 1 else (1 if v == 0 else 0)),
    "HTTPS":            ("has_https",      lambda v: 0 if v == 1 else 1),  # UCI: 1=no HTTPS
    "NonStdPort":       ("has_port",       lambda v: 1 if v == 1 else 0),
    "IframeRedirection":("domain_entropy", lambda v: 4.0 if v == 1 else 2.5),  # proxy feature
    "PrefixSuffix-":    ("hyphen_count",   lambda v: 3 if v == 1 else 0),
}


def detect_format(df: pd.DataFrame) -> str:
    """Returns 'uci' or 'url' based on column names."""
    if "url" in df.columns and "label" in df.columns:
        return "url"
    if "class" in df.columns:
        return "uci"
    raise ValueError(
        "Unrecognised CSV format. Need either (url, label) or UCI phishing columns."
    )


def load_uci(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """
    Converts UCI pre-extracted feature rows to our fixed-length vector.
    UCI labels: -1=legitimate → 0, 0=suspicious → 0, 1=phishing → 1
    """
    ORDERED_KEYS = [
        "url_length", "domain_length", "path_length",
        "has_ip", "has_at", "double_slash", "has_port",
        "is_shortened",
        "phishing_words", "digit_count_domain", "hyphen_count",
        "dot_count", "special_chars", "subdomain_count",
        "path_depth", "query_params", "suspicious_tld",
        "has_https", "has_encoded", "domain_entropy",
    ]

    DEFAULTS = {k: 0 for k in ORDERED_KEYS}
    DEFAULTS.update({"url_length": 60, "domain_entropy": 2.5})

    X, y = [], []
    for _, row in df.iterrows():
        feats = dict(DEFAULTS)
        for uci_col, (our_key, fn) in UCI_FEATURE_MAP.items():
            if uci_col in df.columns:
                feats[our_key] = fn(row[uci_col])

        X.append([feats[k] for k in ORDERED_KEYS])
        # -1 and 0 both map to "safe" (0); 1 maps to "phishing" (1)
        y.append(1 if row["class"] == 1 else 0)

    return np.array(X, dtype=float), np.array(y)


def load_url_csv(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Extracts features from raw URLs using feature_extractor.extract()."""
    X, y   = [], []
    errors = 0
    for _, row in df.iterrows():
        try:
            feats = extract(str(row["url"]))
            X.append(to_vector(feats))
            y.append(int(row["label"]))
        except Exception:
            errors += 1
    if errors:
        print(f"⚠️  Skipped {errors} malformed rows")
    return np.array(X, dtype=float), np.array(y)


def train(csv_path: str = "phishing.csv", output_path: str = "phishing_model.pkl"):
    df     = pd.read_csv(csv_path)
    fmt    = detect_format(df)
    print(f"📂 Loaded {len(df)} rows  |  format: {fmt.upper()}")

    if fmt == "uci":
        X, y = load_uci(df)
    else:
        X, y = load_url_csv(df)

    print(f"   Phishing: {y.sum()}  /  Legitimate: {(y == 0).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Pipeline: scaler + Random Forest
    # StandardScaler helps even though RF doesn't strictly need it —
    # it prevents future GBM/SVM experiments from breaking.
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=300,
            max_depth=14,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print("🔄 Training …")
    pipeline.fit(X_train, y_train)

    # ── Evaluation ────────────────────────────────────────────────────────────
    y_pred = pipeline.predict(X_test)
    print("\n📊 Test-set results:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_f1 = cross_val_score(pipeline, X, y, cv=cv, scoring="f1")
    print(f"\nCross-val F1: {cv_f1.mean():.3f} ± {cv_f1.std():.3f}")

    # Overfit check — warn if train score >> test score
    train_f1 = cross_val_score(pipeline, X_train, y_train, cv=3, scoring="f1").mean()
    test_f1  = cv_f1.mean()
    if train_f1 - test_f1 > 0.10:
        print(f"⚠️  Possible overfit: train F1={train_f1:.3f} vs test F1={test_f1:.3f}")

    # ── Feature importance ────────────────────────────────────────────────────
    feature_names = [
        "url_length", "domain_length", "path_length",
        "has_ip", "has_at", "double_slash", "has_port",
        "is_shortened",
        "phishing_words", "digit_count_domain", "hyphen_count",
        "dot_count", "special_chars", "subdomain_count",
        "path_depth", "query_params", "suspicious_tld",
        "has_https", "has_encoded", "domain_entropy",
    ]
    importances = pipeline.named_steps["clf"].feature_importances_
    top = sorted(zip(feature_names, importances), key=lambda x: -x[1])[:5]
    print("\nTop-5 features:")
    for name, imp in top:
        print(f"  {name:<26} {imp:.3f}")

    joblib.dump(pipeline, output_path)
    print(f"\n✅ Model saved to {output_path}")


if __name__ == "__main__":
    import sys
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "phishing.csv"
    train(csv_path)
