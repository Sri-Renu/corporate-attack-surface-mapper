"""
ML Training Pipeline for Corporate Attack Surface Risk Scorer
─────────────────────────────────────────────────────────────
This script:
1. Builds a training dataset from public breach databases
2. Engineers 15 OSINT features per company
3. Trains an XGBoost classifier
4. Evaluates with AUC-ROC, precision, recall
5. Saves the model for production use

Run: python train_model.py
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (classification_report, roc_auc_score,
                              confusion_matrix, average_precision_score)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import pickle
import json
import warnings
warnings.filterwarnings('ignore')

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    from sklearn.ensemble import GradientBoostingClassifier
    XGB_AVAILABLE = False


# ────────────────────────────────────────────────────────────
# 1. DATA COLLECTION GUIDE
# ────────────────────────────────────────────────────────────
"""
Collect ground truth labels from these public breach databases:

BREACHED COMPANIES (label = 1):
  - https://haveibeenpwned.com/PwnedWebsites  (list of breached sites)
  - Verizon DBIR (Data Breach Investigations Report) — lists breached organizations
  - https://www.privacyrights.org/data-breaches — US data breach list
  - https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf — HIPAA breach portal
  - Wikipedia: List of data breaches

UN-BREACHED COMPANIES (label = 0):
  - Fortune 500 companies not on breach lists
  - Randomly sampled Alexa Top 10K sites

For each company, run OSINTEngine to collect features,
then store in the dataset with their breach label.
"""

# ────────────────────────────────────────────────────────────
# 2. SYNTHETIC DATASET BUILDER (for demonstration/testing)
#    Replace with real data from the collection above.
# ────────────────────────────────────────────────────────────

def generate_synthetic_dataset(n_samples=5000, breach_rate=0.25, random_state=42):
    """
    Generate synthetic OSINT feature dataset that mimics real-world distributions.
    
    In production: replace this with real scan results from OSINTEngine
    labeled against known breach databases.
    """
    rng = np.random.RandomState(random_state)
    n_breach = int(n_samples * breach_rate)
    n_safe = n_samples - n_breach

    def sample_safe(n):
        return {
            'f_subdomain_count':     rng.randint(2, 20, n),
            'f_zone_transfer_enabled': rng.choice([0, 1], n, p=[0.97, 0.03]),
            'f_wildcard_dns':        rng.choice([0, 1], n, p=[0.85, 0.15]),
            'f_open_ports':          rng.randint(1, 6, n),
            'f_critical_cves':       rng.choice([0, 1, 2], n, p=[0.75, 0.20, 0.05]),
            'f_high_cves':           rng.randint(0, 4, n),
            'f_github_leaks':        rng.choice([0, 1], n, p=[0.90, 0.10]),
            'f_public_repos':        rng.randint(0, 5, n),
            'f_email_score':         rng.randint(55, 100, n),
            'f_spf_present':         rng.choice([0, 1], n, p=[0.20, 0.80]),
            'f_dmarc_present':       rng.choice([0, 1], n, p=[0.35, 0.65]),
            'f_dkim_present':        rng.choice([0, 1], n, p=[0.25, 0.75]),
            'f_missing_headers':     rng.randint(0, 4, n),
            'f_version_disclosed':   rng.choice([0, 1], n, p=[0.60, 0.40]),
            'f_cert_issues':         rng.randint(0, 2, n),
        }

    def sample_breach(n):
        # Breached companies have worse security posture on average
        return {
            'f_subdomain_count':     rng.randint(10, 80, n),
            'f_zone_transfer_enabled': rng.choice([0, 1], n, p=[0.85, 0.15]),
            'f_wildcard_dns':        rng.choice([0, 1], n, p=[0.60, 0.40]),
            'f_open_ports':          rng.randint(3, 25, n),
            'f_critical_cves':       rng.randint(1, 8, n),
            'f_high_cves':           rng.randint(2, 15, n),
            'f_github_leaks':        rng.choice([0, 1, 2, 3], n, p=[0.40, 0.35, 0.15, 0.10]),
            'f_public_repos':        rng.randint(1, 15, n),
            'f_email_score':         rng.randint(10, 60, n),
            'f_spf_present':         rng.choice([0, 1], n, p=[0.55, 0.45]),
            'f_dmarc_present':       rng.choice([0, 1], n, p=[0.70, 0.30]),
            'f_dkim_present':        rng.choice([0, 1], n, p=[0.50, 0.50]),
            'f_missing_headers':     rng.randint(3, 7, n),
            'f_version_disclosed':   rng.choice([0, 1], n, p=[0.30, 0.70]),
            'f_cert_issues':         rng.randint(1, 5, n),
        }

    safe_data = sample_safe(n_safe)
    breach_data = sample_breach(n_breach)

    df_safe = pd.DataFrame(safe_data)
    df_safe['breach'] = 0

    df_breach = pd.DataFrame(breach_data)
    df_breach['breach'] = 1

    df = pd.concat([df_safe, df_breach], ignore_index=True)
    df = df.sample(frac=1, random_state=random_state).reset_index(drop=True)

    print(f"Dataset: {len(df)} samples, {n_breach} breached ({breach_rate*100:.0f}%)")
    return df


# ────────────────────────────────────────────────────────────
# 3. FEATURE ENGINEERING
# ────────────────────────────────────────────────────────────

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add derived features for better model performance."""
    df = df.copy()

    # Composite: unprotected email (no SPF + no DMARC)
    df['f_email_exposed'] = ((df['f_spf_present'] == 0) & (df['f_dmarc_present'] == 0)).astype(int)

    # CVE density score
    df['f_cve_density'] = df['f_critical_cves'] * 3 + df['f_high_cves']

    # Subdomain sprawl (log scale)
    df['f_subdomain_log'] = np.log1p(df['f_subdomain_count'])

    # Combined leak signal
    df['f_leak_signal'] = df['f_github_leaks'] * 2 + df['f_public_repos']

    # Security posture score (higher = worse)
    df['f_security_debt'] = (
        df['f_missing_headers'] * 0.5 +
        df['f_version_disclosed'] * 0.3 +
        (1 - df['f_spf_present']) * 1.0 +
        (1 - df['f_dmarc_present']) * 1.0 +
        df['f_zone_transfer_enabled'] * 2.0
    )

    return df


# ────────────────────────────────────────────────────────────
# 4. MODEL TRAINING
# ────────────────────────────────────────────────────────────

class AttackSurfaceRiskModel:
    def __init__(self):
        self.model = None
        self.feature_cols = None
        self.metrics = {}

    def train(self, df: pd.DataFrame):
        df = engineer_features(df)
        self.feature_cols = [c for c in df.columns if c.startswith('f_')]

        X = df[self.feature_cols]
        y = df['breach']

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )

        print(f"\nTraining on {len(X_train)} samples, testing on {len(X_test)}")
        print(f"Positive rate — train: {y_train.mean():.2%}, test: {y_test.mean():.2%}")

        if XGB_AVAILABLE:
            self.model = xgb.XGBClassifier(
                n_estimators=300,
                max_depth=5,
                learning_rate=0.08,
                subsample=0.8,
                colsample_bytree=0.8,
                min_child_weight=3,
                gamma=0.1,
                reg_alpha=0.1,
                reg_lambda=1.0,
                scale_pos_weight=int((y_train == 0).sum() / (y_train == 1).sum()),
                eval_metric='auc',
                random_state=42,
                use_label_encoder=False,
            )
        else:
            print("XGBoost not available, using GradientBoosting")
            from sklearn.ensemble import GradientBoostingClassifier
            self.model = GradientBoostingClassifier(n_estimators=300, random_state=42)

        if XGB_AVAILABLE:
            self.model.fit(
                X_train, y_train,
                eval_set=[(X_test, y_test)],
                verbose=100,
            )
        else:
            self.model.fit(X_train, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]

        auc = roc_auc_score(y_test, y_prob)
        ap = average_precision_score(y_test, y_prob)

        self.metrics = {
            'auc_roc': round(auc, 4),
            'avg_precision': round(ap, 4),
            'n_train': len(X_train),
            'n_test': len(X_test),
            'n_features': len(self.feature_cols),
        }

        print(f"\n{'='*50}")
        print(f"AUC-ROC Score: {auc:.4f}")
        print(f"Avg Precision: {ap:.4f}")
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Safe', 'Breached']))

        # Cross-validation
        cv_scores = cross_val_score(self.model, X, y, cv=StratifiedKFold(5),
                                    scoring='roc_auc', n_jobs=-1)
        print(f"\n5-Fold CV AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        self.metrics['cv_auc_mean'] = round(cv_scores.mean(), 4)
        self.metrics['cv_auc_std'] = round(cv_scores.std(), 4)

        return self

    def feature_importance(self) -> dict:
        if self.model is None:
            return {}
        importances = self.model.feature_importances_
        fi = dict(sorted(zip(self.feature_cols, importances),
                         key=lambda x: x[1], reverse=True))
        print("\nTop Feature Importances:")
        for feat, imp in list(fi.items())[:10]:
            bar = '█' * int(imp * 100)
            print(f"  {feat:<35} {bar} {imp:.4f}")
        return fi

    def save(self, path='models/risk_model.pkl'):
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'feature_cols': self.feature_cols,
                'metrics': self.metrics,
            }, f)
        # Save metrics as JSON too
        with open(path.replace('.pkl', '_metrics.json'), 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"\nModel saved to {path}")
        print(f"Metrics: {json.dumps(self.metrics, indent=2)}")

    @classmethod
    def load(cls, path='models/risk_model.pkl'):
        with open(path, 'rb') as f:
            data = pickle.load(f)
        model = cls()
        model.model = data['model']
        model.feature_cols = data['feature_cols']
        model.metrics = data['metrics']
        return model

    def predict_proba(self, features: dict) -> float:
        """Predict breach probability for a single company."""
        df = pd.DataFrame([features])
        df = engineer_features(df)
        X = df[[c for c in self.feature_cols if c in df.columns]].fillna(0)
        return float(self.model.predict_proba(X)[0][1])


# ────────────────────────────────────────────────────────────
# 5. MAIN
# ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("╔══════════════════════════════════════════╗")
    print("║  Attack Surface ML Model Training        ║")
    print("╚══════════════════════════════════════════╝\n")

    # Generate / load dataset
    print("Building dataset...")
    df = generate_synthetic_dataset(n_samples=10000, breach_rate=0.25)

    # Train
    print("\nTraining XGBoost model...")
    model = AttackSurfaceRiskModel()
    model.train(df)
    model.feature_importance()

    # Save
    model.save('models/risk_model.pkl')

    # Example inference
    print("\n" + "="*50)
    print("Example Prediction:")
    example = {
        'f_subdomain_count': 25,
        'f_zone_transfer_enabled': 1,
        'f_wildcard_dns': 1,
        'f_open_ports': 8,
        'f_critical_cves': 3,
        'f_high_cves': 7,
        'f_github_leaks': 2,
        'f_public_repos': 5,
        'f_email_score': 20,
        'f_spf_present': 0,
        'f_dmarc_present': 0,
        'f_dkim_present': 0,
        'f_missing_headers': 6,
        'f_version_disclosed': 1,
        'f_cert_issues': 3,
    }
    prob = model.predict_proba(example)
    print(f"Input features: {example}")
    print(f"\nPredicted breach probability: {prob:.2%}")
    print(f"Risk Level: {'CRITICAL' if prob > 0.75 else 'HIGH' if prob > 0.5 else 'MEDIUM'}")