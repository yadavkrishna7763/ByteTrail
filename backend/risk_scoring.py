from typing import Dict, Tuple


def calculate_risk_score(
    fraud_score: float,
    header_valid: bool,
    spf_result: str = "none",
    dkim_result: str = "none",
    dmarc_result: str = "none",
    domain_mismatch: bool = False,
    country: str = "Unknown",
) -> Tuple[float, str, str]:
    """
    Calculate composite multi-vector risk score (0.0 to 100.0)
    and categorize threat level as 'low', 'medium', or 'high'.

    Returns:
        (final_score: float, risk_level: str, threat_summary: str)
    """
    # 1. Content Fraud Score Contribution (0 - 60 points)
    content_points = fraud_score * 60.0

    # 2. Authentication & Header Security Points (0 - 40 points)
    auth_points = 0.0

    if spf_result in ("fail", "softfail"):
        auth_points += 15.0
    elif spf_result == "pass":
        auth_points -= 5.0

    if dkim_result == "fail":
        auth_points += 15.0
    elif dkim_result in ("pass", "present"):
        auth_points -= 5.0

    if dmarc_result == "fail":
        auth_points += 15.0
    elif dmarc_result == "pass":
        auth_points -= 5.0

    if domain_mismatch:
        auth_points += 20.0

    if not header_valid and (spf_result != "pass" and dkim_result != "pass"):
        auth_points += 10.0

    # 3. GeoIP Threat Intelligence Indicator
    geo_points = 0.0
    if country in ("Russia", "China", "Nigeria", "North Korea", "Iran"):
        # Elevated scrutiny for known high-volume phishing relay hubs
        geo_points += 10.0

    total_score = content_points + auth_points + geo_points
    final_score = round(min(100.0, max(0.0, total_score)), 1)

    # Risk level thresholding
    if final_score >= 60.0:
        risk_level = "high"
        threat_summary = "CRITICAL THREAT: Strong indicators of credential harvesting, spoofing, or fraud."
    elif final_score >= 30.0:
        risk_level = "medium"
        threat_summary = "SUSPICIOUS: Moderate threat indicators or unverified sender credentials detected."
    else:
        risk_level = "low"
        threat_summary = "BENIGN / LOW RISK: Verified sender credentials and normal linguistic patterns."

    return final_score, risk_level, threat_summary
