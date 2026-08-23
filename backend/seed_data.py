import os
import sys
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import (
    init_db,
    insert_email,
    save_analysis_results,
    get_email_details,
    log_forensic_report,
)
from schemas import EmailCreate
from fraud_detection import scan_email_content
from header_analysis import analyze_headers
from geo_lookup import resolve_geo_for_headers
from risk_scoring import calculate_risk_score
from report_generator import generate_forensic_report


DEMO_EMAILS = [
    {
        "sender": "security-dept@paypal-verify-user-account.com",
        "subject": "URGENT ACTION REQUIRED: Account Access Suspended Immediately",
        "raw_headers": (
            "From: PayPal Support <security-dept@paypal-verify-user-account.com>\n"
            "To: victim@company.com\n"
            "Subject: URGENT ACTION REQUIRED: Account Access Suspended Immediately\n"
            "Date: Sun, 23 Aug 2026 14:30:00 +0000\n"
            "Received: from unknown (185.220.101.5) by mx.relay-gateway.net\n"
            "Authentication-Results: mx.relay-gateway.net; spf=fail smtp.mailfrom=paypal-verify-user-account.com; dkim=fail; dmarc=fail\n"
            "Message-ID: <992837198237@paypal-verify-user-account.com>"
        ),
        "body_text": (
            "Dear Customer,\n\nWe detected suspicious unauthorized login attempts on your account from IP 185.220.101.5.\n"
            "To prevent permanent account termination, please verify your identity and credit card details within 24 hours:\n"
            "http://paypal-verify-user-account.com/secure-login/login.php\n\n"
            "Failure to comply will lead to permanent account deactivation.\n\nPayPal Security Team"
        ),
    },
    {
        "sender": "ceo-update@corp-secure-finance.net",
        "subject": "URGENT CONFIDENTIAL: Wire Transfer Required Before 4 PM",
        "raw_headers": (
            "From: Executive Office <ceo-update@corp-secure-finance.net>\n"
            "Reply-To: executive-wire-escrow@gmail.com\n"
            "To: finance-lead@company.com\n"
            "Received: from mail.cloud-relays.com (198.51.100.23) by mx.company.com\n"
            "Authentication-Results: mx.company.com; spf=softfail; dkim=fail; dmarc=fail\n"
        ),
        "body_text": (
            "Hi team,\n\nI am currently in an all-day acquisition board meeting. "
            "We need to execute an urgent confidential wire transfer of $84,500 to the vendor escrow account attached.\n"
            "Please process immediately and confirm once transmitted.\n\nRegards,\nChief Executive Officer"
        ),
    },
    {
        "sender": "admin@m365-security-reauth-portal.com",
        "subject": "CRITICAL: Microsoft 365 Password Expired — Re-authenticate Now",
        "raw_headers": (
            "From: Microsoft Online Security <admin@m365-security-reauth-portal.com>\n"
            "To: employee@company.com\n"
            "Received: from relay-node.nigeria-net.ng (197.210.45.12) by mx.microsoft.com\n"
            "Authentication-Results: mx.microsoft.com; spf=fail; dkim=none; dmarc=fail\n"
        ),
        "body_text": (
            "Your Microsoft 365 enterprise session has expired. All inbound corporate emails are placed on hold.\n"
            "Please click below to keep your current password and restore email routing:\n"
            "https://m365-security-reauth-portal.com/login/auth-session.php\n\nMicrosoft IT Operations"
        ),
    },
    {
        "sender": "tracking-update@amazon-shipment-reroute.com",
        "subject": "Delivery Alert: Package #982-10293 Delivery Address Incomplete",
        "raw_headers": (
            "From: Amazon Logistics <tracking-update@amazon-shipment-reroute.com>\n"
            "To: customer@example.com\n"
            "Received: from vps-node.amsterdam-relay.nl (188.166.50.21) by mx.mail.net\n"
            "Authentication-Results: mx.mail.net; spf=neutral; dkim=fail; dmarc=fail\n"
        ),
        "body_text": (
            "We were unable to deliver your package due to an invalid street number. "
            "Please update payment and address information to reschedule delivery within 48 hours:\n"
            "http://amazon-shipment-reroute.com/update-address\n\nAmazon Shipping Services"
        ),
    },
    {
        "sender": "security-audit@blackmail-btc-ledger.com",
        "subject": "Your Computer was Compromised — Bitcoin Payment Required",
        "raw_headers": (
            "From: Anonymous Security Team <security-audit@blackmail-btc-ledger.com>\n"
            "To: user@domain.com\n"
            "Received: from tor-exit.ru (95.173.136.1) by mx.relay.net\n"
            "Authentication-Results: mx.relay.net; spf=fail; dkim=fail; dmarc=fail\n"
        ),
        "body_text": (
            "We installed trojan malware on your device. To prevent leaking your data and video recordings, "
            "transfer 0.25 Bitcoin ($15,000 USDT) to our wallet address within 24 hours:\n"
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n\nNo negotiation."
        ),
    },
    {
        "sender": "hr-feedback@company-internal-surveys.co",
        "subject": "Annual Employee Benefit Bonus Survey Form",
        "raw_headers": (
            "From: HR Department <hr-feedback@company-internal-surveys.co>\n"
            "To: staff@company.com\n"
            "Received: from mail-relay.delhi-telecom.in (115.112.89.4) by mx.company.com\n"
            "Authentication-Results: mx.company.com; spf=pass; dkim=none; dmarc=none\n"
        ),
        "body_text": (
            "Dear Employees,\n\nPlease fill out this short compensation and bonus feedback form "
            "to ensure proper HR benefits enrollment for Q4.\n\nAccess form: http://company-internal-surveys.co/form\n\nHR Team"
        ),
    },
    {
        "sender": "notifications@github.com",
        "subject": "[GitHub] Security advisory alert: Update dependencies in ByteTrail",
        "raw_headers": (
            "From: GitHub <notifications@github.com>\n"
            "To: dev-team@company.com\n"
            "Subject: [GitHub] Security advisory alert: Update dependencies in ByteTrail\n"
            "Received: from out-21.mail.github.com (192.30.252.204) by mx.google.com\n"
            "Authentication-Results: mx.google.com; spf=pass header.i=@github.com; dkim=pass header.i=@github.com; dmarc=pass\n"
            "Message-ID: <github/security-advisory/1029384@github.com>"
        ),
        "body_text": (
            "Hello,\n\nA new security advisory was published for a library used in your repository. "
            "We recommend reviewing the vulnerability severity and upgrading to the latest patched version.\n\n"
            "View advisory: https://github.com/ByteTrail/ByteTrail/security/advisories\n\nBest regards,\nThe GitHub Security Team"
        ),
    },
    {
        "sender": "google-billing@google.com",
        "subject": "Google Cloud Monthly Billing Invoice Summary",
        "raw_headers": (
            "From: Google Cloud Billing <google-billing@google.com>\n"
            "To: devops@company.com\n"
            "Received: from mail-relay.google.com (142.250.190.46) by mx.corp.net\n"
            "Authentication-Results: mx.corp.net; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <gcp/billing/2026/08@google.com>"
        ),
        "body_text": (
            "Hello Google Cloud Administrator,\n\nYour monthly billing statement for the billing account 'Production Infrastructure' "
            "has been generated. Total charges: $142.50.\n\nYou can review your invoice breakdown in the Google Cloud Console.\n\n"
            "Thank you,\nGoogle Cloud Platform"
        ),
    },
    {
        "sender": "no-reply-aws@amazon.com",
        "subject": "AWS CloudWatch Alarm Notification: Auto-Scaling Triggered",
        "raw_headers": (
            "From: AWS Notifications <no-reply-aws@amazon.com>\n"
            "To: sysadmin@company.com\n"
            "Received: from relay.us-west-2.amazonses.com (52.96.166.12) by mx.corp.net\n"
            "Authentication-Results: mx.corp.net; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <aws/cloudwatch/alarm-9872@amazonses.com>"
        ),
        "body_text": (
            "You are receiving this email because your Amazon CloudWatch Alarm 'High-CPU-Utilization' in region us-west-2 "
            "has entered the ALARM state. Automatic scale-out policy has been successfully executed.\n\nAmazon Web Services"
        ),
    },
    {
        "sender": "internal-it@company.in",
        "subject": "Scheduled Corporate VPN Maintenance Notice for Weekend",
        "raw_headers": (
            "From: Corporate IT Desk <internal-it@company.in>\n"
            "To: all-employees@company.in\n"
            "Received: from vpn-gw.bengaluru-dc.in (49.207.200.15) by mx.company.in\n"
            "Authentication-Results: mx.company.in; spf=pass; dkim=pass; dmarc=pass\n"
        ),
        "body_text": (
            "Dear Team,\n\nPlease be advised that our internal VPN gateways will undergo scheduled infrastructure maintenance "
            "this Saturday between 02:00 AM and 04:00 AM IST. No action is required from your side.\n\nIT Support Helpdesk"
        ),
    },
]


def seed_database():
    """Ingest, analyze, and generate forensic reports for sample emails."""
    print("🚀 Initializing ByteTrail Database and Intelligence Pipeline...")
    init_db()

    print(f"📦 Seeding {len(DEMO_EMAILS)} realistic threat & forensic scenarios...\n")
    print(f"{'ID':<4} | {'Threat Level':<12} | {'Score':<6} | {'Sender':<35} | {'Origin Location':<25}")
    print("-" * 90)

    for item in DEMO_EMAILS:
        # 1. Insert Email
        email_id = insert_email(
            sender=item["sender"],
            subject=item["subject"],
            raw_headers=item["raw_headers"],
            body_text=item["body_text"],
        )

        # 2. Intelligence Pipeline
        fraud_analysis = scan_email_content(item["subject"], item["body_text"])
        fraud_score = fraud_analysis["fraud_score"]

        header_forensics = analyze_headers(item["raw_headers"], item["sender"])
        header_valid = header_forensics["header_valid"]
        spf_result = header_forensics["spf_result"]
        dkim_result = header_forensics["dkim_result"]
        dmarc_result = header_forensics["dmarc_result"]
        domain_mismatch = header_forensics["domain_mismatch"]

        geo_intel = resolve_geo_for_headers(item["raw_headers"])
        ip_address = geo_intel["ip_address"]
        country = geo_intel["country"]
        city = geo_intel["city"]
        latitude = geo_intel["latitude"]
        longitude = geo_intel["longitude"]

        final_score, risk_level, threat_summary = calculate_risk_score(
            fraud_score=fraud_score,
            header_valid=header_valid,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            domain_mismatch=domain_mismatch,
            country=country,
        )

        # 3. Save Analysis
        save_analysis_results(
            email_id=email_id,
            fraud_score=fraud_score,
            header_valid=header_valid,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            ip_address=ip_address,
            country=country,
            city=city,
            latitude=latitude,
            longitude=longitude,
            final_score=final_score,
            risk_level=risk_level,
        )

        # 4. Generate PDF Report
        record = get_email_details(email_id)
        if record:
            try:
                pdf_path = generate_forensic_report(record)
                log_forensic_report(email_id, pdf_path)
            except Exception as e:
                print(f"Warning: PDF gen error for #{email_id}: {e}")

        loc_str = f"{country}, {city}"
        print(f"#{email_id:<3} | {risk_level.upper():<12} | {final_score:<6} | {item['sender'][:33]:<35} | {loc_str[:24]:<25}")

    print("\n✅ Seed dataset generated and forensic reports compiled in reports/!")


if __name__ == "__main__":
    seed_database()
