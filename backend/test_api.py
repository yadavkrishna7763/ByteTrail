from fastapi.testclient import TestClient
from main import app
from db import add_connected_mailbox, get_all_connected_mailboxes, delete_connected_mailbox

client = TestClient(app)


def test_ping():
    with TestClient(app) as c:
        response = c.get("/ping")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


def test_phishing_email_pipeline():
    with TestClient(app) as c:
        phishing_payload = {
            "sender": "security-dept@paypal-verify-user-account.com",
            "subject": "URGENT ACTION REQUIRED: Account Access Suspended Immediately",
            "raw_headers": (
                "From: PayPal Support <security-dept@paypal-verify-user-account.com>\n"
                "To: victim@company.com\n"
                "Received: from unknown (185.220.101.5) by mx.relay.net\n"
                "Authentication-Results: mx.relay.net; spf=fail; dkim=fail; dmarc=fail\n"
            ),
            "body_text": (
                "Dear Customer, We detected unauthorized access to your account. "
                "Please click here to verify your login credentials immediately: "
                "http://paypal-verify-user-account.com/secure-login/login.php within 24 hours."
            ),
        }

        resp = c.post("/emails", json=phishing_payload)
        assert resp.status_code == 201
        data = resp.json()

        assert data["id"] is not None
        # Fraud score should be high
        assert data["fraud_score"] >= 0.5
        # Authentication should be invalid
        assert data["header_valid"] is False
        assert data["spf_result"] == "fail"
        assert data["dkim_result"] == "fail"
        assert data["dmarc_result"] == "fail"
        # GeoIP should resolve to Russia
        assert data["country"] == "Russia"
        assert data["city"] == "Moscow"
        # Composite risk level should be high
        assert data["risk_level"] == "high"
        assert data["final_score"] >= 60.0


def test_safe_email_pipeline():
    with TestClient(app) as c:
        safe_payload = {
            "sender": "notifications@github.com",
            "subject": "Weekly team sprint summary and release notes",
            "raw_headers": (
                "From: GitHub <notifications@github.com>\n"
                "To: dev@company.com\n"
                "Received: from out-21.mail.github.com (192.30.252.204) by mx.google.com\n"
                "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n"
            ),
            "body_text": "Hello, Here is the weekly project status report. All builds passed smoothly.",
        }

        resp = c.post("/emails", json=safe_payload)
        assert resp.status_code == 201
        data = resp.json()

        assert data["id"] is not None
        assert data["fraud_score"] < 0.2
        assert data["header_valid"] is True
        assert data["spf_result"] == "pass"
        assert data["country"] == "United States"
        assert data["risk_level"] == "low"

        # Test GET /emails/{id}/report
        email_id = data["id"]
        report_resp = c.get(f"/emails/{email_id}/report")
        assert report_resp.status_code == 200
        assert report_resp.headers["content-type"] == "application/pdf"
        assert len(report_resp.content) > 1000


def test_upload_eml_file():
    with TestClient(app) as c:
        raw_eml = (
            "From: alerts@apple-security-recovery.com\n"
            "To: target@company.com\n"
            "Subject: CRITICAL: Apple ID Locked\n"
            "Received: from unknown (185.220.101.5)\n"
            "Authentication-Results: mx.apple.com; spf=fail; dkim=fail\n\n"
            "Your Apple account has been suspended. Click here to verify your identity immediately."
        ).encode("utf-8")

        files = {"file": ("test_phish.eml", raw_eml, "message/rfc822")}
        resp = c.post("/emails/upload-eml", files=files)
        assert resp.status_code == 201
        data = resp.json()
        assert data["sender"] == "alerts@apple-security-recovery.com"
        assert data["country"] == "Russia"
        assert data["risk_level"] == "high"


def test_inbound_webhook():
    with TestClient(app) as c:
        webhook_data = {
            "from": "payroll@spoofed-domain.net",
            "subject": "CRITICAL: Urgent Wire Transfer and Account Access Suspended",
            "headers": "From: payroll@spoofed-domain.net\nReceived: from 185.220.101.5\nAuthentication-Results: spf=fail; dkim=fail",
            "text": "Dear user, please click here to verify login credentials and wire transfer immediately: http://spoofed-domain.net/login.php"
        }
        resp = c.post("/api/v1/webhook/inbound", json=webhook_data)
        assert resp.status_code == 201
        data = resp.json()
        assert data["id"] is not None
        assert data["risk_level"] == "high"


def test_campaign_graph_attribution():
    with TestClient(app) as c:
        resp = c.get("/campaigns/graph")
        assert resp.status_code == 200
        graph = resp.json()
        assert "nodes" in graph
        assert "edges" in graph
        assert "total_nodes" in graph
        assert "total_edges" in graph


def test_integrations_status():
    with TestClient(app) as c:
        resp = c.get("/integrations/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "webhook_url" in data
        assert "connected_mailboxes_count" in data


def test_connected_mailboxes_api():
    with TestClient(app) as c:
        # 1. Register test mailbox directly into DB
        mb_id = add_connected_mailbox(
            email_address="soc-honeypot@enterprise.org",
            host="imap.enterprise.org",
            port=993,
            username="soc-honeypot@enterprise.org",
            password="test-secret-password",
            provider="custom",
        )
        assert mb_id is not None

        # 2. Query list endpoint
        resp = c.get("/api/v1/mailboxes")
        assert resp.status_code == 200
        items = resp.json()
        found = any(m["id"] == mb_id for m in items)
        assert found is True

        # 3. Clean up
        delete_connected_mailbox(mb_id)
