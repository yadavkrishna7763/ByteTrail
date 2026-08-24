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

        # 2. Query list endpoint as the administrator (the endpoint is protected)
        login = c.post("/api/auth/demo-login").json()
        resp = c.get("/api/v1/mailboxes", headers={"Authorization": f"Bearer {login['access_token']}"})
        assert resp.status_code == 200
        items = resp.json()
        found = any(m["id"] == mb_id for m in items)
        assert found is True

        # 3. Clean up
        delete_connected_mailbox(mb_id)


def test_user_registration_and_login():
    import uuid
    with TestClient(app) as c:
        unique_id = uuid.uuid4().hex[:8]
        test_email = f"test.analyst.{unique_id}@bytetrail.io"
        test_password = "SecureAnalystPassword123!"

        # 1. Register new user
        reg_payload = {
            "email": test_email,
            "password": test_password,
            "full_name": "Test Security Analyst",
            "role": "analyst",
        }
        reg_resp = c.post("/api/auth/register", json=reg_payload)
        assert reg_resp.status_code == 201
        reg_data = reg_resp.json()
        assert "access_token" in reg_data
        assert reg_data["user"]["email"] == test_email
        token = reg_data["access_token"]

        # 2. Duplicate registration rejection
        dup_resp = c.post("/api/auth/register", json=reg_payload)
        assert dup_resp.status_code == 400

        # 3. Login with correct password
        login_resp = c.post("/api/auth/login", json={"email": test_email, "password": test_password})
        assert login_resp.status_code == 200
        login_data = login_resp.json()
        assert "access_token" in login_data
        assert login_data["user"]["email"] == test_email

        # 4. Login with invalid password rejection
        bad_login = c.post("/api/auth/login", json={"email": test_email, "password": "WrongPassword123"})
        assert bad_login.status_code == 401

        # 5. Access /api/auth/me with Bearer token
        headers = {"Authorization": f"Bearer {token}"}
        me_resp = c.get("/api/auth/me", headers=headers)
        assert me_resp.status_code == 200
        assert me_resp.json()["email"] == test_email


def test_demo_login_and_auth_me():
    with TestClient(app) as c:
        # 1. 1-Click Administrator Login
        demo_resp = c.post("/api/auth/demo-login")
        assert demo_resp.status_code == 200
        data = demo_resp.json()
        assert "access_token" in data
        assert data["user"]["email"] == "krishnayadav770694@gmail.com"
        assert data["user"]["role"] == "admin"

        # 2. Access /api/auth/me with demo token
        headers = {"Authorization": f"Bearer {data['access_token']}"}
        me_resp = c.get("/api/auth/me", headers=headers)
        assert me_resp.status_code == 200
        assert me_resp.json()["email"] == "krishnayadav770694@gmail.com"


def test_google_signin_flow():
    with TestClient(app) as c:
        resp = c.post("/api/auth/google/signin", json={"email": "google.test.user@gmail.com", "full_name": "Google Test User"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["email"] == "google.test.user@gmail.com"
        assert data["user"]["role"] == "analyst"


def test_user_data_isolation():
    import uuid
    with TestClient(app) as c:
        u1_email = f"user1.{uuid.uuid4().hex[:6]}@domain.com"
        u2_email = f"user2.{uuid.uuid4().hex[:6]}@domain.com"

        # Register User 1 & 2
        r1 = c.post("/api/auth/register", json={"email": u1_email, "password": "Password123!", "full_name": "User One", "role": "analyst"}).json()
        r2 = c.post("/api/auth/register", json={"email": u2_email, "password": "Password123!", "full_name": "User Two", "role": "analyst"}).json()

        h1 = {"Authorization": f"Bearer {r1['access_token']}"}
        h2 = {"Authorization": f"Bearer {r2['access_token']}"}

        # User 1 ingests Email 1
        e1_resp = c.post("/emails", json={"sender": "attacker1@phish.com", "subject": "User 1 Confidential Alert", "body_text": "Please verify user 1 account"}, headers=h1)
        assert e1_resp.status_code == 201

        # User 2 ingests Email 2
        e2_resp = c.post("/emails", json={"sender": "attacker2@phish.com", "subject": "User 2 Confidential Alert", "body_text": "Please verify user 2 account"}, headers=h2)
        assert e2_resp.status_code == 201

        # Query User 1 emails
        u1_emails = c.get("/emails", headers=h1).json()
        u1_subjects = [e["subject"] for e in u1_emails]
        assert "User 1 Confidential Alert" in u1_subjects
        assert "User 2 Confidential Alert" not in u1_subjects

        # Query User 2 emails
        u2_emails = c.get("/emails", headers=h2).json()
        u2_subjects = [e["subject"] for e in u2_emails]
        assert "User 2 Confidential Alert" in u2_subjects
        assert "User 1 Confidential Alert" not in u2_subjects


