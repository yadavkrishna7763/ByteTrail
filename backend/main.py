import os
from contextlib import asynccontextmanager
from typing import List, Optional, Dict
from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from db import (
    init_db,
    insert_email,
    save_analysis_results,
    get_all_emails_enriched,
    get_email_details,
    log_forensic_report,
    get_forensic_report_log,
    add_connected_mailbox,
    get_all_connected_mailboxes,
    delete_connected_mailbox,
    update_mailbox_stats,
    upsert_oauth_mailbox,
)
from schemas import EmailCreate, EmailDetailResponse, MailboxConnectRequest, MailboxResponse
from fraud_detection import scan_email_content
from header_analysis import analyze_headers
from geo_lookup import resolve_geo_for_headers
from risk_scoring import calculate_risk_score
from report_generator import generate_forensic_report
from compliance import calculate_evidence_hash
from threat_intel import lookup_threat_intelligence
from eml_parser import parse_raw_eml, parse_eml_bytes
from campaign_correlation import build_campaign_attribution_graph
from imap_listener import mailbox_manager, test_imap_credentials, PROVIDER_PRESETS
from directory_watcher import scan_and_ingest_directory, init_watch_directories
from google_oauth import (
    get_google_auth_url,
    exchange_code_for_tokens,
    fetch_user_email,
    fetch_gmail_raw_messages,
    is_google_oauth_configured,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize database tables & inbound directories on startup
    init_db()
    init_watch_directories()

    # 2. Register pipeline runner and start automated background mailbox polling daemon
    mailbox_manager.register_pipeline_runner(run_intelligence_pipeline)
    mailbox_manager.start_background_poller(interval_seconds=10)

    yield


app = FastAPI(
    title="ByteTrail Threat Intelligence API",
    description="AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform (SIH PS-26106)",
    version="2.6.0",
    lifespan=lifespan,
)

# Enable CORS for frontend and external callers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def run_intelligence_pipeline(sender: str, subject: str, raw_headers: Optional[str], body_text: str) -> dict:
    """Internal helper to execute the 4-vector intelligence pipeline and persist results."""
    # 1. Chain of Custody SHA-256 Hash
    sha256_hash = calculate_evidence_hash(sender, subject, raw_headers or "", body_text)

    # 2. Insert Base Email
    email_id = insert_email(
        sender=sender,
        subject=subject,
        raw_headers=raw_headers,
        body_text=body_text,
        sha256_hash=sha256_hash,
    )

    # 3. Vector 1: Phishing & Fraud NLP Heuristics
    fraud_analysis = scan_email_content(subject, body_text)
    fraud_score = fraud_analysis["fraud_score"]

    # 4. Vector 2: Header & Authentication Forensics (SPF/DKIM/DMARC)
    header_forensics = analyze_headers(raw_headers, sender)
    header_valid = header_forensics["header_valid"]
    spf_result = header_forensics["spf_result"]
    dkim_result = header_forensics["dkim_result"]
    dmarc_result = header_forensics["dmarc_result"]
    domain_mismatch = header_forensics["domain_mismatch"]

    # 5. Vector 3: Origin GeoIP & Threat Intel (ISP/ASN)
    geo_intel = resolve_geo_for_headers(raw_headers, sender=sender)
    ip_address = geo_intel["ip_address"]
    country = geo_intel["country"]
    city = geo_intel["city"]
    latitude = geo_intel["latitude"]
    longitude = geo_intel["longitude"]

    threat_intel = lookup_threat_intelligence(ip_address)
    isp_asn = threat_intel["isp_asn"]
    is_vpn_tor = threat_intel["is_vpn_tor"]
    threat_actor = threat_intel["threat_actor_group"]

    # 6. Vector 4: Multi-Factor Composite Risk Scoring
    final_score, risk_level, threat_summary = calculate_risk_score(
        fraud_score=fraud_score,
        header_valid=header_valid,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        domain_mismatch=domain_mismatch,
        country=country,
    )

    # 7. Persist Pipeline Results into MySQL Tables
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
        isp_asn=isp_asn,
        is_vpn_tor=is_vpn_tor,
        threat_actor=threat_actor,
    )

    # 8. Fetch complete enriched record
    record = get_email_details(email_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve newly created enriched email record.",
        )

    # 9. Generate forensic PDF report
    try:
        pdf_path = generate_forensic_report(record)
        log_forensic_report(email_id, pdf_path)
    except Exception:
        pass

    return record


@app.get("/ping", tags=["Health"])
def ping():
    """Health check endpoint confirming API and system status."""
    return {"status": "ok"}


@app.post(
    "/emails",
    response_model=EmailDetailResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Emails & Forensics"],
)
def create_and_analyze_email(email_data: EmailCreate):
    """
    Ingest a new email payload, trigger the 4-step intelligence pipeline,
    and persist results with SHA-256 chain of custody to MySQL.
    """
    try:
        return run_intelligence_pipeline(
            sender=email_data.sender,
            subject=email_data.subject,
            raw_headers=email_data.raw_headers,
            body_text=email_data.body_text,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Intelligence pipeline error: {str(exc)}",
        )


@app.post(
    "/emails/upload-eml",
    response_model=EmailDetailResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Emails & Forensics"],
)
async def upload_raw_eml_file(file: UploadFile = File(...)):
    """
    Upload and parse a raw RFC 822 .eml file directly through the forensic engine.
    """
    try:
        eml_content = await file.read()
        parsed = parse_raw_eml(eml_content)

        return run_intelligence_pipeline(
            sender=parsed["sender"],
            subject=parsed["subject"],
            raw_headers=parsed["raw_headers"],
            body_text=parsed["body_text"],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse .eml file: {str(exc)}",
        )


# ==============================================================================
# CONNECTED MAILBOXES (LIVE GMAIL / OUTLOOK / CUSTOM IMAP MONITORING)
# ==============================================================================

@app.post(
    "/api/v1/mailboxes/connect",
    response_model=MailboxResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Connected Mailboxes"],
)
def connect_mailbox(req: MailboxConnectRequest):
    """
    Connect any live email account (Gmail, Outlook, Yahoo, or Custom IMAP)
    to automatically monitor and run all incoming emails through ByteTrail.
    """
    provider = req.provider.lower() if req.provider else "custom"
    
    # Resolve host/port from presets
    if provider in PROVIDER_PRESETS and not req.host:
        host = PROVIDER_PRESETS[provider]["host"]
        port = PROVIDER_PRESETS[provider]["port"]
        use_ssl = PROVIDER_PRESETS[provider]["use_ssl"]
    else:
        host = req.host or "imap.gmail.com"
        port = req.port or 993
        use_ssl = req.use_ssl if req.use_ssl is not None else True

    # Test authentication before saving (unless user requested sandbox / skip verification)
    if not req.skip_verification:
        auth_test = test_imap_credentials(
            host=host,
            port=port,
            username=req.email_address,
            password=req.password,
            use_ssl=use_ssl,
            folder=req.folder or "INBOX",
        )

        if not auth_test["success"]:
            msg = auth_test["message"]
            if "AUTHENTICATIONFAILED" in msg.upper() or "LOGIN" in msg.upper():
                hint = " (Note: For Gmail, you must use a 16-character Google App Password from myaccount.google.com/apppasswords with 2-Step Verification ON, not your regular password)"
            else:
                hint = ""
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not authenticate with {host}: {msg}{hint}",
            )

    # Save to database
    mb_id = add_connected_mailbox(
        email_address=req.email_address,
        host=host,
        port=port,
        username=req.email_address,
        password=req.password,
        provider=provider,
        folder=req.folder or "INBOX",
        use_ssl=use_ssl,
        is_active=True,
    )

    mailboxes = get_all_connected_mailboxes()
    match = next((m for m in mailboxes if m["id"] == mb_id), None)
    if not match:
        raise HTTPException(status_code=500, detail="Mailbox registration failed.")

    # If user requested immediate historical scan of existing read + unread emails
    if req.scan_history and not req.skip_verification:
        try:
            ingested = mailbox_manager._poll_single_mailbox(match, include_read=True, limit=50)
            if ingested:
                update_mailbox_stats(mb_id, count_increment=len(ingested))
                mailboxes = get_all_connected_mailboxes()
                match = next((m for m in mailboxes if m["id"] == mb_id), match)
        except Exception:
            pass

    return match


@app.get(
    "/api/v1/mailboxes",
    response_model=List[MailboxResponse],
    tags=["Connected Mailboxes"],
)
def list_connected_mailboxes():
    """
    List all connected live email accounts and their automated monitoring status.
    """
    return get_all_connected_mailboxes()


@app.post(
    "/api/v1/mailboxes/{mailbox_id}/sync",
    tags=["Connected Mailboxes"],
)
def sync_mailbox(mailbox_id: int):
    """
    Trigger an instant scan/poll for a specific connected mailbox (new unread emails only).
    """
    mailboxes = get_all_connected_mailboxes()
    match = next((m for m in mailboxes if m["id"] == mailbox_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Connected mailbox not found.")

    try:
        ingested = mailbox_manager._poll_single_mailbox(match, include_read=False)
        if ingested:
            update_mailbox_stats(mailbox_id, count_increment=len(ingested))

        return {
            "status": "success",
            "mailbox": match["email_address"],
            "new_emails_detected": len(ingested),
            "cases": [r["id"] for r in ingested],
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Mailbox sync error: {str(exc)}. If using Gmail, make sure you use a 16-character Google App Password with 2FA enabled.",
        )


@app.post(
    "/api/v1/mailboxes/{mailbox_id}/deep-scan",
    tags=["Connected Mailboxes"],
)
def deep_scan_mailbox(mailbox_id: int, limit: int = 50):
    """
    Deep scan all historical emails (both read and unread) in the connected inbox.
    """
    mailboxes = get_all_connected_mailboxes()
    match = next((m for m in mailboxes if m["id"] == mailbox_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Connected mailbox not found.")

    try:
        ingested = mailbox_manager._poll_single_mailbox(match, include_read=True, limit=limit)
        if ingested:
            update_mailbox_stats(mailbox_id, count_increment=len(ingested))

        return {
            "status": "success",
            "mailbox": match["email_address"],
            "historical_emails_analyzed": len(ingested),
            "cases": [r["id"] for r in ingested],
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Deep scan error: {str(exc)}. If using Gmail, make sure you use a 16-character Google App Password with 2FA enabled.",
        )


@app.delete(
    "/api/v1/mailboxes/{mailbox_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Connected Mailboxes"],
)
def disconnect_mailbox(mailbox_id: int):
    """
    Disconnect and remove an automated email monitoring account.
    """
    delete_connected_mailbox(mailbox_id)
    return None


# ==============================================================================
# Google OAuth 2.0 & Gmail REST API Ingestion Endpoints
# ==============================================================================

def resolve_redirect_uri(request: Request, override_uri: Optional[str] = None) -> str:
    if override_uri:
        return override_uri
    env_redirect = os.getenv("GOOGLE_REDIRECT_URI", "").strip()
    if env_redirect:
        return env_redirect
    host_header = request.headers.get("host", "127.0.0.1:8000")
    scheme = "https" if ("https" in str(request.url.scheme) or "onrender.com" in host_header or "vercel.app" in host_header) else "http"
    return f"{scheme}://{host_header}/api/v1/auth/google/callback"


@app.get(
    "/api/v1/auth/google/url",
    tags=["Google OAuth 2.0"],
)
def get_google_oauth_url(request: Request, redirect_uri: Optional[str] = None):
    """
    Generate the official Google OAuth 2.0 Authorization URL for 1-click login.
    """
    final_redirect = resolve_redirect_uri(request, redirect_uri)
    auth_url = get_google_auth_url(final_redirect)
    return {
        "url": auth_url,
        "is_configured": is_google_oauth_configured(),
        "redirect_uri": final_redirect,
    }


@app.get(
    "/api/v1/auth/google/callback",
    tags=["Google OAuth 2.0"],
)
def google_oauth_callback(code: str, request: Request, state: Optional[str] = None):
    """
    Google OAuth 2.0 redirect callback handler.
    Exchanges code for tokens, fetches user info & emails, and registers mailbox.
    """
    from fastapi.responses import HTMLResponse

    redirect_uri = resolve_redirect_uri(request)

    try:
        tokens = exchange_code_for_tokens(code, redirect_uri)
        access_token = tokens.get("access_token", "")
        refresh_token = tokens.get("refresh_token", "")

        user_email = fetch_user_email(access_token)
        mb_id = upsert_oauth_mailbox(user_email, provider="google", access_token=access_token, refresh_token=refresh_token)

        # Ingest initial batch of emails from Gmail REST API
        raw_emls = fetch_gmail_raw_messages(access_token, max_results=10)
        ingested_count = 0
        for eml_bytes in raw_emls:
            try:
                parsed = parse_eml_bytes(eml_bytes)
                run_intelligence_pipeline(
                    sender=parsed["sender"],
                    subject=parsed["subject"],
                    raw_headers=parsed["raw_headers"],
                    body_text=parsed["body_text"],
                )
                ingested_count += 1
            except Exception:
                pass

        if ingested_count > 0:
            update_mailbox_stats(mb_id, count_increment=ingested_count)

        # Return auto-closing redirect script to communicate with parent window
        frontend_url = os.getenv("FRONTEND_URL", "https://byte-trail.vercel.app").rstrip("/")
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>ByteTrail Google Authentication</title></head>
        <body style="background: #09090b; color: #f4f4f5; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
            <div style="text-align: center; background: #18181b; padding: 2rem; border-radius: 0.75rem; border: 1px solid #27272a;">
                <h2 style="color: #a78bfa; margin-bottom: 0.5rem;">✅ Google Account Connected!</h2>
                <p style="color: #a1a1aa; font-size: 0.9rem;">Connected: <strong>{user_email}</strong></p>
                <p style="color: #71717a; font-size: 0.8rem;">Syncing emails into threat intelligence pipeline...</p>
                <script>
                    if (window.opener) {{
                        window.opener.postMessage({{ type: 'GOOGLE_AUTH_SUCCESS', email: '{user_email}', ingested: {ingested_count} }}, '*');
                        setTimeout(() => window.close(), 1200);
                    }} else {{
                        window.location.href = '{frontend_url}?google_auth=success';
                    }}
                </script>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html)
    except Exception as exc:
        err_html = f"""
        <!DOCTYPE html>
        <html>
        <body style="background: #09090b; color: #f87171; font-family: sans-serif; padding: 2rem;">
            <h2>❌ Google OAuth Connection Failed</h2>
            <p>{str(exc)}</p>
        </body>
        </html>
        """
        return HTMLResponse(content=err_html, status_code=400)


@app.post(
    "/api/v1/auth/google/demo-connect",
    tags=["Google OAuth 2.0"],
)
async def demo_google_connect(request: Request, email: Optional[str] = None):
    """
    1-Click Google OAuth Direct Simulation for instant presentations & live testing.
    """
    if not email:
        try:
            body = await request.json()
            email = body.get("email")
        except Exception:
            pass
    chosen_email = email or "krishnayadav7763@gmail.com"

    mb_id = upsert_oauth_mailbox(chosen_email, provider="google", access_token="mock_google_access_token_demo")
    raw_emls = fetch_gmail_raw_messages("mock_google_access_token_demo", max_results=5)
    ingested_count = 0
    for eml_bytes in raw_emls:
        try:
            parsed = parse_eml_bytes(eml_bytes)
            run_intelligence_pipeline(
                sender=parsed["sender"],
                subject=parsed["subject"],
                raw_headers=parsed["raw_headers"],
                body_text=parsed["body_text"],
            )
            ingested_count += 1
        except Exception:
            pass

    if ingested_count > 0:
        update_mailbox_stats(mb_id, count_increment=ingested_count)

    return {
        "status": "success",
        "email_address": chosen_email,
        "provider": "google_oauth2",
        "ingested_cases": ingested_count,
    }


@app.post(
    "/api/v1/webhook/inbound",
    response_model=EmailDetailResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Automated Ingestion"],
)
async def inbound_email_webhook(request: Request):
    """
    Automated Webhook Endpoint for Email Security Gateways, SendGrid Inbound Parse,
    Mailgun, Cloudflare Email Routing, or Postfix milters.
    """
    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            payload = await request.json()
            sender = payload.get("from") or payload.get("sender") or "gateway-relay@unknown.com"
            subject = payload.get("subject", "Automated Gateway Event")
            raw_headers = payload.get("headers") or payload.get("raw_headers") or ""
            body_text = payload.get("text") or payload.get("body") or payload.get("html") or ""
        else:
            form_data = await request.form()
            sender = form_data.get("from") or form_data.get("sender") or "gateway-relay@unknown.com"
            subject = form_data.get("subject", "Automated Gateway Event")
            raw_headers = form_data.get("headers") or ""
            body_text = form_data.get("text") or form_data.get("body") or form_data.get("html") or ""

        return run_intelligence_pipeline(
            sender=str(sender),
            subject=str(subject),
            raw_headers=str(raw_headers),
            body_text=str(body_text),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Inbound webhook processing error: {str(exc)}",
        )


@app.post(
    "/integrations/watcher/scan",
    tags=["Automated Ingestion"],
)
def trigger_directory_scan():
    """
    Scan the inbound_emails directory for dropped .eml files and auto-process them.
    """
    try:
        results = scan_and_ingest_directory(run_intelligence_pipeline)
        return {
            "status": "success",
            "auto_ingested_count": len(results),
            "cases": [r["id"] for r in results],
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Directory watcher error: {str(exc)}",
        )


@app.get(
    "/integrations/status",
    tags=["Automated Ingestion"],
)
def get_integrations_status():
    """
    Get live status of automated ingestion pipelines (Connected Mailboxes, Webhook, Directory Watcher).
    """
    mailboxes = get_all_connected_mailboxes()
    return {
        "webhook_url": "http://127.0.0.1:8000/api/v1/webhook/inbound",
        "supported_gateways": ["SendGrid Inbound Parse", "Mailgun", "Cloudflare Email Routing", "Postfix", "Exchange Journaling"],
        "directory_watcher": {
            "status": "active",
            "watch_path": "backend/inbound_emails/",
            "processed_path": "backend/inbound_emails/processed/",
        },
        "connected_mailboxes_count": len(mailboxes),
        "connected_mailboxes": mailboxes,
    }


@app.get(
    "/emails",
    response_model=List[EmailDetailResponse],
    tags=["Emails & Forensics"],
)
def list_emails():
    """
    Retrieve all analyzed emails with complete threat intelligence metadata.
    """
    try:
        return get_all_emails_enriched()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        )


@app.get(
    "/emails/{email_id}",
    response_model=EmailDetailResponse,
    tags=["Emails & Forensics"],
)
def get_email(email_id: int):
    """
    Retrieve forensic threat intelligence for a specific email by ID.
    """
    record = get_email_details(email_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with ID {email_id} not found.",
        )
    return record


@app.get(
    "/emails/{email_id}/report",
    tags=["Emails & Forensics"],
)
def download_forensic_report(email_id: int):
    """
    Generate and stream downloadable PDF Forensic Incident Report for the given email ID.
    """
    record = get_email_details(email_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with ID {email_id} not found.",
        )

    try:
        report_path = generate_forensic_report(record)
        log_forensic_report(email_id, report_path)

        if not os.path.exists(report_path):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Forensic PDF report generation failed.",
            )

        return FileResponse(
            path=report_path,
            filename=f"bytetrail_forensic_report_case_{email_id}.pdf",
            media_type="application/pdf",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation error: {str(exc)}",
        )


@app.get(
    "/campaigns/graph",
    tags=["Campaigns & Graph Attribution"],
)
def get_campaign_graph():
    """
    Generate node-and-edge correlation network graph data linking emails,
    domains, and originating IP infrastructures into campaign clusters.
    """
    try:
        emails = get_all_emails_enriched()
        return build_campaign_attribution_graph(emails)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Graph generation error: {str(exc)}",
        )
