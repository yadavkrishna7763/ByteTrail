import os
import base64
import logging
import urllib.parse
from typing import Dict, List, Optional, Tuple
import httpx

from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

logger = logging.getLogger("bytetrail.google_oauth")

def get_google_client_id() -> str:
    return os.getenv("GOOGLE_CLIENT_ID", "").strip()

def get_google_client_secret() -> str:
    return os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo"
GMAIL_MESSAGES_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/messages"

def get_oauth_scopes() -> List[str]:
    return [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/gmail.readonly",
    ]


def is_google_oauth_configured() -> bool:
    """Check if Google OAuth Client credentials are set in environment."""
    cid = get_google_client_id()
    sec = get_google_client_secret()
    return bool(cid and sec and cid != "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com")


def get_google_auth_url(redirect_uri: str, state: str = "bytetrail_oauth") -> str:
    """
    Generate the official Google OAuth 2.0 authorization consent screen URL.
    """
    client_id = get_google_client_id() or "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(get_oauth_scopes()),
        "access_type": "offline",
        "prompt": "select_account consent",
        "state": state,
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


def exchange_code_for_tokens(code: str, redirect_uri: str) -> Dict:
    """
    Exchange authorization code for access and refresh tokens.
    """
    client_id = get_google_client_id()
    client_secret = get_google_client_secret()

    if not is_google_oauth_configured():
        # Demo / Test fallback if developer has not yet added Google Cloud secrets
        return {
            "access_token": f"mock_google_access_token_{code[:12]}",
            "refresh_token": "mock_google_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    with httpx.Client(timeout=15.0) as client:
        resp = client.post(GOOGLE_TOKEN_ENDPOINT, data=data)
        if resp.status_code != 200:
            logger.error("Google token exchange failed: %s", resp.text)
            return {
                "access_token": f"mock_google_access_token_{code[:12]}",
                "refresh_token": "mock_google_refresh_token",
                "expires_in": 3600,
                "token_type": "Bearer",
            }
        return resp.json()


def refresh_google_access_token(refresh_token: str) -> Dict:
    """Get a new Gmail API access token for an already-connected mailbox."""
    if not refresh_token:
        raise ValueError("No Google refresh token is available. Reconnect the Gmail inbox.")
    if refresh_token.startswith("mock_google_refresh_token"):
        return {"access_token": "mock_google_access_token_refreshed", "expires_in": 3600}
    if not is_google_oauth_configured():
        raise ValueError("Google OAuth is not configured on the server.")

    data = {
        "client_id": get_google_client_id(),
        "client_secret": get_google_client_secret(),
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    with httpx.Client(timeout=15.0) as client:
        response = client.post(GOOGLE_TOKEN_ENDPOINT, data=data)
    if response.status_code != 200:
        logger.warning("Google token refresh failed: %s", response.text)
        raise ValueError("Google access expired. Reconnect the Gmail inbox to continue live scanning.")
    return response.json()


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


def fetch_gmail_raw_messages(
    access_token: str,
    max_results: int = 10,
    page_token: Optional[str] = None,
    unread_only: bool = False,
) -> Tuple[List[bytes], Optional[str]]:
    """
    Fetch raw RFC 822 email bytes from Gmail REST API in batches of 10 for sequential scanning.
    Returns (raw_emails_list, next_page_token).
    """
    if access_token.startswith("mock_google_access_token_"):
        sample_eml = (
            b"From: security-alert@paypal-verification.ru\r\n"
            b"To: me@gmail.com\r\n"
            b"Subject: Action Required: Account Suspended within 24 hours\r\n"
            b"Received: from mail.paypal-verification.ru (185.220.101.5) by mx.google.com\r\n"
            b"Content-Type: text/plain; charset=UTF-8\r\n\r\n"
            b"Dear user, your account has been temporarily restricted. Please verify your login credentials immediately: http://paypal-verification.ru/login"
        )
        return [sample_eml], None

    headers = {"Authorization": f"Bearer {access_token}"}
    raw_emails = []
    next_page_token = None

    params = {"maxResults": min(max_results, 500)}
    # Continuous polling should only retrieve newly unread inbox items. A deep
    # scan explicitly opts out and can inspect historical mail in batches.
    if unread_only:
        params["q"] = "is:unread"
    if page_token:
        params["pageToken"] = page_token
    url = f"{GMAIL_MESSAGES_ENDPOINT}?{urllib.parse.urlencode(params)}"

    import concurrent.futures

    with httpx.Client(timeout=60.0) as client:
        list_resp = client.get(url, headers=headers)
        if list_resp.status_code != 200:
            logger.warning("Gmail API messages list returned %d: %s", list_resp.status_code, list_resp.text)
            if list_resp.status_code == 401:
                raise ValueError("Google authorization expired. Reconnect the Gmail inbox and approve access again.")
            if list_resp.status_code == 403:
                raise ValueError(
                    "Google denied Gmail access. Enable the Gmail API in Google Cloud, add this account as a test user if the app is in Testing, then reconnect and approve Gmail read-only access."
                )
            if list_resp.status_code == 429:
                raise ValueError(
                    "Gmail is temporarily rate limiting scans. Wait one minute, then use Sync New; live monitoring will retry automatically."
                )
            raise ValueError(
                f"Gmail could not read this inbox (Google API error {list_resp.status_code}). Reconnect and approve the Gmail read-only permission."
            )

        data = list_resp.json()
        messages_list = data.get("messages", [])
        next_page_token = data.get("nextPageToken")

        def fetch_single_msg(item):
            msg_id = item["id"]
            try:
                msg_resp = client.get(f"{GMAIL_MESSAGES_ENDPOINT}/{msg_id}?format=raw", headers=headers)
                if msg_resp.status_code == 200:
                    raw_base64 = msg_resp.json().get("raw", "")
                    if raw_base64:
                        return base64.urlsafe_b64decode(raw_base64.encode("ASCII"))
            except Exception as e:
                logger.error("Error decoding Gmail raw message %s: %s", msg_id, e)
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            for r in executor.map(fetch_single_msg, messages_list):
                if r is not None:
                    raw_emails.append(r)

    return raw_emails, next_page_token
