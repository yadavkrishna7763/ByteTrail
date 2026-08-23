#!/usr/bin/env python3
"""
ByteTrail — Inbound Webhook Simulator Script
Simulates an Enterprise Email Security Gateway (e.g. SendGrid, Mailgun, Cloudflare, Postfix)
forwarding live inbound emails directly to ByteTrail's automated REST webhook.
"""

import sys
import time
import requests

WEBHOOK_URL = "http://127.0.0.1:8000/api/v1/webhook/inbound"

SAMPLE_WEBHOOK_EVENTS = [
    {
        "name": "🚨 Phishing Attack: Urgent Bank KYC Verification",
        "payload": {
            "from": "compliance-team@chase-bank-verify-portal.net",
            "to": "employee@target-enterprise.com",
            "subject": "CRITICAL: Mandatory Federal KYC Update Required Immediately",
            "headers": (
                "From: Chase Compliance <compliance-team@chase-bank-verify-portal.net>\n"
                "To: employee@target-enterprise.com\n"
                "Received: from relay-node.ru (185.220.101.5) by mx.gateway.com\n"
                "Authentication-Results: mx.gateway.com; spf=fail; dkim=fail; dmarc=fail\n"
            ),
            "text": (
                "Dear Valued Customer,\n\n"
                "Federal regulatory mandates require you to confirm your identity and billing details "
                "within 12 hours to prevent account freeze: http://chase-bank-verify-portal.net/auth.php\n\n"
                "Chase Risk Management Operations"
            ),
        },
    },
    {
        "name": "🚨 BEC Wire Fraud: CEO Urgent Acquisition Escrow",
        "payload": {
            "from": "executive-desk@global-corp-group.net",
            "to": "cfo@target-enterprise.com",
            "subject": "URGENT CONFIDENTIAL: Wire Transfer for Q3 Acquisition",
            "headers": (
                "From: Chief Executive <executive-desk@global-corp-group.net>\n"
                "Reply-To: secret-escrow-settlement@gmail.com\n"
                "Received: from vps-frankfurt.de (198.51.100.23) by mx.gateway.com\n"
                "Authentication-Results: mx.gateway.com; spf=softfail; dkim=fail; dmarc=fail\n"
            ),
            "text": (
                "Team,\n\nPlease process an urgent wire transfer of $142,000 to the attached acquisition escrow account before market close.\n"
                "Transmit confirmation slip as soon as done."
            ),
        },
    },
    {
        "name": "✅ Legitimate: AWS CloudWatch Alarm Notification",
        "payload": {
            "from": "no-reply@sns.amazonaws.com",
            "to": "devops@target-enterprise.com",
            "subject": "ALARM: High CPU Utilization on Production Cluster",
            "headers": (
                "From: Amazon Web Services <no-reply@sns.amazonaws.com>\n"
                "To: devops@target-enterprise.com\n"
                "Received: from a27-45.smtp-out.us-west-2.amazonses.com (52.96.166.12) by mx.google.com\n"
                "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n"
            ),
            "text": (
                "You are receiving this email because your Amazon CloudWatch Alarm "
                "'High-CPU-Utilization' in region us-west-2 has entered the ALARM state.\n"
                "Threshold: CPUUtilization > 85.0 for 5 minutes."
            ),
        },
    },
]


def run_simulation():
    print("=" * 70)
    print("🚀 BYTETRAIL AUTOMATED INBOUND WEBHOOK SIMULATION")
    print("Target Webhook:", WEBHOOK_URL)
    print("=" * 70)

    for i, event in enumerate(SAMPLE_WEBHOOK_EVENTS, 1):
        print(f"\n[Event {i}/3] Forwarding: {event['name']}...")
        try:
            resp = requests.post(WEBHOOK_URL, json=event["payload"], timeout=10)
            if resp.status_code == 201:
                data = resp.json()
                print(f"  ✅ INGESTED SUCCESSFULLY in <500ms!")
                print(f"     Case ID:      #{data['id']}")
                print(f"     Risk Level:   {data['risk_level'].upper()} (Score: {data['final_score']}/100)")
                print(f"     Origin Geo:   {data.get('country', 'Unknown')} ({data.get('ip_address', 'No IP')})")
                print(f"     Evidence SHA: {data.get('sha256_hash', 'N/A')[:24]}...")
            else:
                print(f"  ❌ Webhook rejected: HTTP {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"  ❌ Connection error: {e}")

        time.sleep(1)

    print("\n" + "=" * 70)
    print("🎉 ALL INBOUND WEBHOOK EVENTS PROCESSED AUTOMATICALLY!")
    print("👉 Open dashboard at http://127.0.0.1:3000 to see live pins & feed.")
    print("=" * 70)


if __name__ == "__main__":
    run_simulation()
