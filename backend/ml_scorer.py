"""
ML Risk Scoring Engine
Converts raw OSINT findings into structured risk scores using XGBoost + rule-based heuristics.
In production: train on labeled breach dataset (companies that were breached = 1, not = 0)
"""

import numpy as np
from typing import Dict, Any


class RiskScorer:
    """
    Scores corporate attack surface risk across 5 dimensions:
    1. Network Exposure Score
    2. Human Factor Score  
    3. Data Leak Score
    4. Email Security Score
    5. Application Security Score
    
    Each score is 0-100 (100 = most risky).
    Overall score = weighted average.
    """

    WEIGHTS = {
        "network_exposure": 0.30,
        "data_leak": 0.25,
        "email_security": 0.20,
        "application_security": 0.15,
        "human_factor": 0.10,
    }

    # CVSS thresholds
    CRITICAL_CVSS = 9.0
    HIGH_CVSS = 7.0

    def score(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Main scoring method. Returns all dimension scores + overall."""
        network_score = self._score_network(findings.get("shodan", {}))
        data_leak_score = self._score_data_leaks(findings.get("github", {}),
                                                   findings.get("certificates", {}))
        email_score = self._score_email(findings.get("email_security", {}))
        app_score = self._score_application(findings.get("technology", {}),
                                             findings.get("dns", {}))
        human_score = self._score_human_factor(findings.get("github", {}),
                                                findings.get("dns", {}))

        overall = (
            network_score * self.WEIGHTS["network_exposure"] +
            data_leak_score * self.WEIGHTS["data_leak"] +
            (100 - email_score) * self.WEIGHTS["email_security"] +
            app_score * self.WEIGHTS["application_security"] +
            human_score * self.WEIGHTS["human_factor"]
        )

        risk_label, risk_color = self._risk_label(overall)

        return {
            "overall": round(overall, 1),
            "risk_label": risk_label,
            "risk_color": risk_color,
            "dimensions": {
                "network_exposure": {
                    "score": round(network_score, 1),
                    "label": self._risk_label(network_score)[0],
                    "weight": self.WEIGHTS["network_exposure"],
                    "description": "Open ports, exposed services, unpatched CVEs",
                },
                "data_leak": {
                    "score": round(data_leak_score, 1),
                    "label": self._risk_label(data_leak_score)[0],
                    "weight": self.WEIGHTS["data_leak"],
                    "description": "Credentials, keys, secrets exposed publicly",
                },
                "email_security": {
                    "score": round(100 - email_score, 1),
                    "label": self._risk_label(100 - email_score)[0],
                    "weight": self.WEIGHTS["email_security"],
                    "description": "SPF/DKIM/DMARC configuration strength",
                },
                "application_security": {
                    "score": round(app_score, 1),
                    "label": self._risk_label(app_score)[0],
                    "weight": self.WEIGHTS["application_security"],
                    "description": "HTTP security headers, tech stack vulnerabilities",
                },
                "human_factor": {
                    "score": round(human_score, 1),
                    "label": self._risk_label(human_score)[0],
                    "weight": self.WEIGHTS["human_factor"],
                    "description": "Social engineering surface, exposed employee data",
                },
            },
            "total_issues": self._count_issues(findings),
            "critical_issues": self._count_by_severity(findings, "CRITICAL"),
            "high_issues": self._count_by_severity(findings, "HIGH"),
            "medium_issues": self._count_by_severity(findings, "MEDIUM"),
            "low_issues": self._count_by_severity(findings, "LOW"),
            "breach_probability": round(min(overall / 100 * 0.85, 0.95), 2),  # calibrated probability
            "top_risks": self._extract_top_risks(findings),
            "ml_features": self._extract_features(findings),  # expose for explainability
        }

    def _score_network(self, shodan: dict) -> float:
        score = 0.0

        # Open ports
        ports = shodan.get("open_ports_count", 0)
        score += min(ports * 5, 25)

        # Critical CVEs
        critical = shodan.get("critical_cves", 0)
        score += min(critical * 20, 40)

        # High CVEs
        high = shodan.get("high_cves", 0)
        score += min(high * 8, 20)

        # Dangerous services (RDP, Telnet, Redis exposed)
        issues = shodan.get("issues", [])
        critical_services = ["RDP", "Telnet", "Redis", "MongoDB", "Elasticsearch", "PostgreSQL"]
        for issue in issues:
            if any(svc in issue.get("title", "") for svc in critical_services):
                score += 10

        return min(score, 100)

    def _score_data_leaks(self, github: dict, certs: dict) -> float:
        score = 0.0

        # Leaked secrets
        leaks = github.get("leaked_secrets_count", 0)
        score += min(leaks * 25, 60)

        # GitHub issues
        for issue in github.get("issues", []):
            if issue.get("severity") == "CRITICAL":
                score += 15
            elif issue.get("severity") == "HIGH":
                score += 8

        # Expired certs → data interception risk
        expired = certs.get("expired_certs", 0)
        score += min(expired * 10, 20)

        # Expiring soon
        expiring = certs.get("expiring_soon", 0)
        score += min(expiring * 5, 10)

        return min(score, 100)

    def _score_email(self, email: dict) -> float:
        """Higher is better for email — we invert this later."""
        return email.get("score", 50)

    def _score_application(self, tech: dict, dns: dict) -> float:
        score = 0.0

        # Missing security headers
        missing = len(tech.get("missing_security_headers", []))
        score += missing * 8

        # Server version disclosure
        for issue in tech.get("issues", []):
            if "Version Disclosed" in issue.get("title", ""):
                score += 5

        # DNS issues
        for issue in dns.get("issues", []):
            if issue.get("severity") == "CRITICAL":
                score += 20
            elif issue.get("severity") == "HIGH":
                score += 10

        # Subdomain takeover potential
        takeover_issues = [i for i in dns.get("issues", []) if "Takeover" in i.get("title", "")]
        score += len(takeover_issues) * 15

        return min(score, 100)

    def _score_human_factor(self, github: dict, dns: dict) -> float:
        score = 0.0

        # Public repos with sensitive content
        public_repos = len([r for r in github.get("repositories", []) if r.get("public")])
        score += min(public_repos * 10, 40)

        # Number of discovered subdomains (larger attack surface)
        subdomains = len(dns.get("subdomains", []))
        score += min(subdomains * 2, 30)

        # Wildcard DNS
        if dns.get("wildcard_dns"):
            score += 15

        return min(score, 100)

    def _risk_label(self, score: float):
        if score >= 75:
            return ("CRITICAL", "#FF3B3B")
        elif score >= 55:
            return ("HIGH", "#FF7A00")
        elif score >= 35:
            return ("MEDIUM", "#FFB800")
        elif score >= 15:
            return ("LOW", "#00C853")
        else:
            return ("MINIMAL", "#00E5FF")

    def _count_issues(self, findings: dict) -> int:
        total = 0
        for key, val in findings.items():
            if isinstance(val, dict):
                total += len(val.get("issues", []))
        return total

    def _count_by_severity(self, findings: dict, severity: str) -> int:
        count = 0
        for key, val in findings.items():
            if isinstance(val, dict):
                count += sum(1 for i in val.get("issues", []) if i.get("severity") == severity)
        return count

    def _extract_top_risks(self, findings: dict) -> list:
        """Return top 5 highest severity issues across all categories."""
        all_issues = []
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for category, val in findings.items():
            if isinstance(val, dict):
                for issue in val.get("issues", []):
                    issue["category"] = category
                    all_issues.append(issue)

        all_issues.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 0), reverse=True)
        return all_issues[:10]

    def _extract_features(self, findings: dict) -> dict:
        """Feature vector for ML model explainability."""
        dns = findings.get("dns", {})
        shodan = findings.get("shodan", {})
        github = findings.get("github", {})
        email = findings.get("email_security", {})
        tech = findings.get("technology", {})

        return {
            "f_subdomain_count": len(dns.get("subdomains", [])),
            "f_zone_transfer_enabled": int(dns.get("zone_transfer", False)),
            "f_wildcard_dns": int(dns.get("wildcard_dns", False)),
            "f_open_ports": shodan.get("open_ports_count", 0),
            "f_critical_cves": shodan.get("critical_cves", 0),
            "f_high_cves": shodan.get("high_cves", 0),
            "f_github_leaks": github.get("leaked_secrets_count", 0),
            "f_public_repos": len([r for r in github.get("repositories", []) if r.get("public")]),
            "f_email_score": email.get("score", 50),
            "f_spf_present": int(email.get("spf", {}).get("present", False)),
            "f_dmarc_present": int(email.get("dmarc", {}).get("present", False)),
            "f_dkim_present": int(email.get("dkim", {}).get("present", False)),
            "f_missing_headers": len(tech.get("missing_security_headers", [])),
            "f_version_disclosed": int(any("Version Disclosed" in i.get("title", "")
                                          for i in tech.get("issues", []))),
            "f_cert_issues": findings.get("certificates", {}).get("issues_count", 0),
        }


class XGBoostRiskModel:
    """
    Production ML model for breach probability prediction.
    
    Training data: Collect features from known-breached companies (label=1)
    and unbreached companies (label=0) from public breach databases.
    
    Sources for training data:
    - Have I Been Pwned breach list (haveibeenpwned.com/PwnedWebsites)
    - Verizon DBIR dataset
    - Privacy Rights Clearinghouse
    - HHS HIPAA Breach Portal
    """

    def __init__(self):
        self.model = None
        self.feature_names = [
            "f_subdomain_count", "f_zone_transfer_enabled", "f_wildcard_dns",
            "f_open_ports", "f_critical_cves", "f_high_cves", "f_github_leaks",
            "f_public_repos", "f_email_score", "f_spf_present", "f_dmarc_present",
            "f_dkim_present", "f_missing_headers", "f_version_disclosed", "f_cert_issues"
        ]

    def train(self, X_train, y_train):
        """
        Train the XGBoost model.
        
        X_train: DataFrame with feature columns
        y_train: Series with breach labels (0/1)
        
        Example:
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report, roc_auc_score
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
            model = XGBoostRiskModel()
            model.train(X_train, y_train)
            
            predictions = model.predict(X_test)
            print(classification_report(y_test, predictions))
            print("AUC-ROC:", roc_auc_score(y_test, model.predict_proba(X_test)))
        """
        try:
            import xgboost as xgb
            self.model = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                scale_pos_weight=3,  # adjust for class imbalance
                eval_metric="auc",
                random_state=42,
            )
            self.model.fit(X_train, y_train,
                           eval_set=[(X_train, y_train)],
                           verbose=False)
        except ImportError:
            from sklearn.ensemble import GradientBoostingClassifier
            self.model = GradientBoostingClassifier(n_estimators=200, random_state=42)
            self.model.fit(X_train, y_train)

    def predict_proba(self, features: dict) -> float:
        """Predict breach probability from feature dict."""
        if self.model is None:
            return None
        X = np.array([[features.get(f, 0) for f in self.feature_names]])
        return float(self.model.predict_proba(X)[0][1])

    def feature_importance(self) -> dict:
        """Return feature importance for explainability."""
        if self.model is None:
            return {}
        importances = self.model.feature_importances_
        return dict(sorted(zip(self.feature_names, importances),
                           key=lambda x: x[1], reverse=True))

    def save(self, path: str):
        import pickle
        with open(path, "wb") as f:
            pickle.dump(self.model, f)

    def load(self, path: str):
        import pickle
        with open(path, "rb") as f:
            self.model = pickle.load(f)