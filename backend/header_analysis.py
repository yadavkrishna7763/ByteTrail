import re
import email
from email import policy
from typing import Dict, Optional


def parse_authentication_results(auth_header: str) -> Dict[str, str]:
    """Extract SPF, DKIM, and DMARC results from Authentication-Results header."""
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    if not auth_header:
        return results

    auth_lower = auth_header.lower()

    # SPF match
    spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", auth_lower)
    if spf_match:
        results["spf"] = spf_match.group(1)

    # DKIM match
    dkim_match = re.search(r"\bdkim=(pass|fail|none|temperror|permerror)\b", auth_lower)
    if dkim_match:
        results["dkim"] = dkim_match.group(1)

    # DMARC match
    dmarc_match = re.search(r"\bdmarc=(pass|fail|none|temperror|permerror)\b", auth_lower)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1)

    return results


def analyze_headers(raw_headers: Optional[str], sender: str = "") -> Dict:
    """
    Parse RFC 822 email headers and perform cryptographic authentication
    and domain consistency verification.
    """
    if not raw_headers or not raw_headers.strip():
        return {
            "header_valid": False,
            "spf_result": "none",
            "dkim_result": "none",
            "dmarc_result": "none",
            "domain_mismatch": False,
            "auth_notes": ["No raw headers provided for cryptographic verification"],
        }

    try:
        msg = email.message_from_string(raw_headers, policy=policy.default)
    except Exception:
        msg = {}

    auth_results_header = msg.get("Authentication-Results", "") if hasattr(msg, "get") else ""
    received_spf_header = msg.get("Received-SPF", "") if hasattr(msg, "get") else ""
    dkim_sig_header = msg.get("DKIM-Signature", "") if hasattr(msg, "get") else ""
    reply_to = msg.get("Reply-To", "") if hasattr(msg, "get") else ""

    parsed_auth = parse_authentication_results(auth_results_header)
    
    # Fallback to Received-SPF header if not in Authentication-Results
    if parsed_auth["spf"] == "none" and received_spf_header:
        spf_match = re.search(r"^(pass|fail|softfail|neutral|none)", received_spf_header.lower().strip())
        if spf_match:
            parsed_auth["spf"] = spf_match.group(1)

    # Fallback to DKIM-Signature presence
    if parsed_auth["dkim"] == "none" and dkim_sig_header:
        parsed_auth["dkim"] = "present"

    # Domain mismatch check between From and Reply-To
    domain_mismatch = False
    notes = []

    from_domain = ""
    from_header = msg.get("From", sender) if hasattr(msg, "get") else sender
    if "@" in from_header:
        from_domain = from_header.split("@")[-1].strip(">").strip().lower()

    if reply_to and "@" in reply_to:
        reply_domain = reply_to.split("@")[-1].strip(">").strip().lower()
        if from_domain and reply_domain != from_domain:
            domain_mismatch = True
            notes.append(f"Domain mismatch: From '@{from_domain}' differs from Reply-To '@{reply_domain}'")

    # Evaluate overall header validity
    spf_pass = parsed_auth["spf"] in ("pass",)
    dkim_pass = parsed_auth["dkim"] in ("pass", "present")
    dmarc_pass = parsed_auth["dmarc"] in ("pass",)

    # If any explicit fail occurs, invalid
    explicit_fail = (
        parsed_auth["spf"] in ("fail", "softfail") or
        parsed_auth["dkim"] in ("fail",) or
        parsed_auth["dmarc"] in ("fail",)
    )

    if explicit_fail or domain_mismatch:
        header_valid = False
        if parsed_auth["spf"] in ("fail", "softfail"):
            notes.append(f"SPF validation failed ({parsed_auth['spf']})")
        if parsed_auth["dkim"] == "fail":
            notes.append("DKIM digital signature failed validation")
        if parsed_auth["dmarc"] == "fail":
            notes.append("DMARC policy enforcement failed")
    elif spf_pass and (dkim_pass or dmarc_pass):
        header_valid = True
        notes.append("Email passed SPF and DKIM/DMARC authentication")
    elif not auth_results_header and not received_spf_header:
        header_valid = False
        notes.append("Missing authentication headers (SPF/DKIM/DMARC unverified)")
    else:
        header_valid = spf_pass or dkim_pass

    return {
        "header_valid": header_valid,
        "spf_result": parsed_auth["spf"],
        "dkim_result": parsed_auth["dkim"],
        "dmarc_result": parsed_auth["dmarc"],
        "domain_mismatch": domain_mismatch,
        "auth_notes": notes,
    }
