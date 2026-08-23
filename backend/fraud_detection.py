import re
from typing import Dict, List, Tuple


class FraudDetector:
    """
    NLP and heuristic rule-based engine to detect phishing, social engineering,
    credential harvesting, BEC fraud, and impersonation indicators in email content.
    """

    URGENCY_KEYWORDS = [
        r"\burgent\b",
        r"\bimmediate(ly)?\b",
        r"\baction required\b",
        r"\baccount (suspended|locked|frozen|disabled|blocked|restricted)\b",
        r"\bsuspension\b",
        r"\bunauthorized (access|activity|sign-in|login|attempt)\b",
        r"\bsecurity (alert|warning|notice|update)\b",
        r"\bverify your (account|identity|details|email|identity|profile|card)\b",
        r"\bpassword (expired|reset|compromised)\b",
        r"\bwithin (24|12|48) hours\b",
        r"\bdeactivation\b",
        r"\bwire transfer\b",
        r"\bconfidential\b",
        r"\bdeadline\b",
        r"\bfailure to (comply|verify|respond)\b",
    ]

    CREDENTIAL_LURES = [
        r"\bclick (here|below|this link|on the link)\b",
        r"\bupdate (payment|billing|credentials|profile|security|kyc|info)\b",
        r"\bconfirm your (login|password|pin|ssn|identity|credentials|code)\b",
        r"\benter your (card|bank|account|password|pin|otp)\b",
        r"\bverify your identity\b",
        r"\blogin to (your account|view|verify|proceed)\b",
        r"\bre-authenticate\b",
        r"\bsign in to\b",
        r"\bdownload (attachment|invoice|statement)\b",
        r"\botp\b",
        r"\bone-time (password|pin|passcode)\b",
    ]

    FINANCIAL_LURES = [
        r"\bbitcoin\b",
        r"\bcrypto(currency)?\b",
        r"\binheritance\b",
        r"\bmillion (dollars|usd|inr|euros|pounds)\b",
        r"\blottery\b",
        r"\binvoice (attached|due|overdue|payment)\b",
        r"\brefund\b",
        r"\bdirect deposit\b",
        r"\bbank transfer\b",
        r"\bpayroll\b",
        r"\bremittance\b",
        r"\bescrow\b",
        r"\bpayment received\b",
        r"\btransaction (id|failed|pending)\b",
        r"\bclaim your (prize|reward|funds|gift)\b",
    ]

    SUSPICIOUS_DOMAIN_PATTERNS = [
        r"paypal-verify",
        r"account-update",
        r"bank-secure",
        r"login-verification",
        r"apple-support-verify",
        r"service-portal-auth",
        r"secure-login",
        r"microsoft-auth",
        r"chase-verify",
        r"\.ru/",
        r"\.xyz/",
        r"\.top/",
        r"\.tk/",
        r"\.click/",
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Direct IP in URL
    ]

    def __init__(self):
        self.urgency_regex = [re.compile(p, re.IGNORECASE) for p in self.URGENCY_KEYWORDS]
        self.credential_regex = [re.compile(p, re.IGNORECASE) for p in self.CREDENTIAL_LURES]
        self.financial_regex = [re.compile(p, re.IGNORECASE) for p in self.FINANCIAL_LURES]
        self.suspicious_domain_regex = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_DOMAIN_PATTERNS]

    def analyze(self, subject: str, body_text: str) -> Tuple[float, List[str]]:
        """
        Analyze subject and body for fraud indicators.
        Returns:
            (fraud_score: float [0.0 - 1.0], indicators: List[str])
        """
        text = f"{subject} {body_text}"
        score = 0.0
        indicators = []

        # 1. Check Subject Capitalization & Exclamation marks
        if subject.isupper() and len(subject) > 8:
            score += 0.15
            indicators.append("Subject is written entirely in uppercase")
        if "!" in subject:
            score += 0.08
            indicators.append("Subject contains aggressive exclamation marks")

        # 2. Check Urgency keywords
        urgency_matches = [p.pattern for p in self.urgency_regex if p.search(text)]
        if urgency_matches:
            weight = min(0.40, len(urgency_matches) * 0.15)
            score += weight
            indicators.append(f"Urgency / panic triggers detected ({len(urgency_matches)} match{'es' if len(urgency_matches) > 1 else ''})")

        # 3. Check Credential harvesting lures
        cred_matches = [p.pattern for p in self.credential_regex if p.search(text)]
        if cred_matches:
            weight = min(0.40, len(cred_matches) * 0.15)
            score += weight
            indicators.append(f"Credential harvesting language detected ({len(cred_matches)} match{'es' if len(cred_matches) > 1 else ''})")

        # 4. Check Financial keywords
        fin_matches = [p.pattern for p in self.financial_regex if p.search(text)]
        if fin_matches:
            weight = min(0.30, len(fin_matches) * 0.12)
            score += weight
            indicators.append(f"Financial / payment lure phrases detected ({len(fin_matches)} matches)")

        # 5. Check Suspicious Link patterns & Lookalike URLs
        url_matches = [p.pattern for p in self.suspicious_domain_regex if p.search(text)]
        if url_matches:
            score += 0.35
            indicators.append(f"Suspicious / typosquat URL pattern found: {url_matches[0]}")

        # 6. Check for Obfuscated / Direct IP hyperlinks
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text):
            score += 0.35
            indicators.append("Message contains direct bare IP address hyperlink")

        # 7. Check for Generic Greetings (Classic Phishing Trait)
        if re.search(r"\b(dear customer|dear user|dear valued client|dear member|valued user)\b", text, re.IGNORECASE):
            score += 0.12
            indicators.append("Impersonal generic greeting detected (e.g. 'Dear Customer')")

        # Normalize score between 0.0 and 1.0
        final_score = min(1.0, max(0.0, round(score, 2)))
        return final_score, indicators


# Singleton scanner function
def scan_email_content(subject: str, body_text: str) -> Dict:
    detector = FraudDetector()
    fraud_score, indicators = detector.analyze(subject, body_text)
    return {
        "fraud_score": fraud_score,
        "is_suspicious": fraud_score >= 0.30,
        "indicators": indicators,
    }
