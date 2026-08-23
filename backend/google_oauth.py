import os
import base64
import logging
import urllib.parse
from typing import Dict, List, Optional
import httpx

logger = logging.getLogger("bytetrail.google_oauth")

# Environment variables for Google Cloud OAuth 2.0 Client
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo"
GMAIL_MESSAGES_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/messages"

SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]


def is_google_oauth_configured() -> bool:
    """Check if Google OAuth Client credentials are set in environment."""
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def get_google_auth_url(redirect_uri: str, state: str = "bytetrail_oauth") -> str:
    """
    Generate the official Google OAuth 2.0 authorization consent screen URL.
    """
    params = {
        "client_id": GOOGLE_CLIENT_ID or "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


def exchange_code_for_tokens(code: str, redirect_uri: str) -> Dict:
    """
    Exchange authorization code for access and refresh tokens.
    """
    if not is_google_oauth_configured():
        # Demo / Test fallback if developer has not yet added Google Cloud secrets
        return {
            "access_token": f"mock_google_access_token_{code[:12]}",
            "refresh_token": "mock_google_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    with httpx.Client(timeout=15.0) as client:
        resp = client.post(GOOGLE_TOKEN_ENDPOINT, data=data)
        if resp.status_code != 200:
            logger.error("Google token exchange failed: %s", resp.text)
            raise ValueError(f"Google OAuth token exchange failed: {resp.text}")
        return resp.json()


def fetch_user_email(access_token: str) -> str:
    """
    Fetch authenticated user's email address from Google UserInfo API.
    """
    if access_token.startswith("mock_google_access_token_"):
        return "analyst.google.account@gmail.com"

    headers = {"Authorization": f"Bearer {access_token}"}
    with httpx.Client(timeout=15.0) as client:
        resp = client.get(GOOGLE_USERINFO_ENDPOINT, headers=headers)
        if resp.status_code != 200:
            logger.error("Google userinfo fetch failed: %s", resp.text)
            raise ValueError(f"Could not retrieve user info: {resp.text}")
        data = resp.json()
        return data.get("email", "unknown@gmail.com")


def fetch_gmail_raw_messages(access_token: str, max_results: int = 25) -> List[bytes]:
    """
    Fetch raw RFC 822 email bytes from Gmail REST API for the authenticated user.
    """
    if access_token.startswith("mock_google_access_token_"):
        # Return realistic simulated phishing and safe RFC 822 emails for demonstration
        sample_eml = (
            b"From: security-alert@paypal-verification.ru\r\n"
            b"To: me@gmail.com\r\n"
            b"Subject: Action Required: Account Suspended within 24 hours\r\n"
            b"Received: from mail.paypal-verification.ru (185.220.101.5) by mx.google.com\r\n"
            b"Content-Type: text/plain; charset=UTF-8\r\n\r\n"
            b"Dear user, your account has been temporarily restricted. Please verify your login credentials immediately: http://paypal-verification.ru/login"
        )
        return [sample_eml]

    headers = {"Authorization": f"Bearer {access_token}"}
    raw_emails = []

    with httpx.Client(timeout=20.0) as client:
        # 1. List message IDs
        list_resp = client.get(f"{GMAIL_MESSAGES_ENDPOINT}?maxResults={max_results}", headers=headers)
        if list_resp.status_code != 200:
            logger.error("Failed to list Gmail messages: %s", list_resp.text)
            return []

        messages_list = list_resp.json().get("messages", [])
        
        # 2. Fetch raw email bytes for each message
        for item in messages_list:
            msg_id = item["id"]
            msg_resp = client.get(f"{GMAIL_MESSAGES_ENDPOINT}/{msg_id}?format=raw", headers=headers)
            if msg_resp.status_code == 200:
                raw_base64 = msg_resp.json().get("raw", "")
                if raw_base64:
                    # Google uses URL-safe base64 encoding with '-' and '_'
                    try:
                        raw_bytes = base64.urlsafe_b64decode(raw_base64.encode("ASCII"))
                        raw_emails.append(raw_bytes)
                    except Exception as e:
                        logger.error("Error decoding Gmail raw message %s: %s", msg_id, e)

    return raw_emails
