import imaplib
import email
import logging
import threading
import time
from typing import Optional, Dict, List
from datetime import datetime

logger = logging.getLogger("bytetrail.imap")

# Provider presets for instant auto-discovery
PROVIDER_PRESETS = {
    "gmail": {
        "host": "imap.gmail.com",
        "port": 993,
        "use_ssl": True,
        "name": "Google Gmail / Google Workspace",
        "instructions": "Use a 16-character Google App Password (myaccount.google.com/apppasswords)",
    },
    "outlook": {
        "host": "outlook.office365.com",
        "port": 993,
        "use_ssl": True,
        "name": "Microsoft Outlook / Office 365 / Hotmail",
        "instructions": "Use your Microsoft Account Password or App Password",
    },
    "yahoo": {
        "host": "imap.mail.yahoo.com",
        "port": 993,
        "use_ssl": True,
        "name": "Yahoo Mail",
        "instructions": "Generate a Yahoo App Password in Account Security Settings",
    },
    "icloud": {
        "host": "imap.mail.me.com",
        "port": 993,
        "use_ssl": True,
        "name": "Apple iCloud Mail",
        "instructions": "Generate an app-specific password at appleid.apple.com",
    },
}


def test_imap_credentials(host: str, port: int, username: str, password: str, use_ssl: bool = True, folder: str = "INBOX") -> Dict:
    """Test connection and login to an IMAP mailbox."""
    clean_user = username.strip()
    clean_pwd = password.replace(" ", "").strip() if ("gmail" in host or "google" in host) else password.strip()
    try:
        if use_ssl:
            client = imaplib.IMAP4_SSL(host, port, timeout=12)
        else:
            client = imaplib.IMAP4(host, port, timeout=12)

        client.login(clean_user, clean_pwd)
        status, _ = client.select(folder)
        client.close()
        client.logout()

        return {"success": True, "message": "Successfully connected and authenticated."}
    except Exception as exc:
        return {"success": False, "message": f"Connection failed: {str(exc)}"}


class MultiMailboxManager:
    """
    Manages continuous automated monitoring for multiple user-connected email accounts.
    """

    def __init__(self):
        self._poller_thread = None
        self._is_running = False
        self._pipeline_runner = None
        self._active_accounts = {}
        self._stats = {"total_ingested": 0, "last_poll_utc": None}

    def register_pipeline_runner(self, runner_func):
        self._pipeline_runner = runner_func

    def start_background_poller(self, interval_seconds: int = 60):
        """Start background daemon thread that polls all active accounts."""
        if self._is_running:
            return

        self._is_running = True

        def _poll_loop():
            logger.info("Starting ByteTrail Mailbox Poller Daemon (Interval: %ds)", interval_seconds)
            while self._is_running:
                try:
                    self.poll_all_accounts()
                except Exception as exc:
                    logger.error("Error in mailbox poll loop: %s", exc)
                time.sleep(interval_seconds)

        self._poller_thread = threading.Thread(target=_poll_loop, daemon=True)
        self._poller_thread.start()

    def poll_all_accounts(self) -> List[Dict]:
        """Poll each registered active email account for unread messages."""
        if not self._pipeline_runner:
            return []

        from db import get_all_connected_mailboxes, update_mailbox_stats

        mailboxes = get_all_connected_mailboxes(active_only=True)
        all_ingested = []

        for mb in mailboxes:
            try:
                # Batch processing: fetch and scan 10 emails (both read and unread) per polling cycle.
                res = self._poll_single_mailbox(mb, include_read=True, limit=10)
                ingested = res.get("records", []) if isinstance(res, dict) else res
                if ingested:
                    all_ingested.extend(ingested)
                    update_mailbox_stats(mb["id"], count_increment=len(ingested))
            except Exception as exc:
                logger.error("Error polling mailbox %s: %s", mb.get("email_address"), exc)

        self._stats["last_poll_utc"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        return all_ingested

    def _poll_single_mailbox(
        self,
        mb: dict,
        include_read: bool = False,
        limit: int = 10,
        offset: int = 0,
        page_token: Optional[str] = None
    ) -> Dict:
        """Connect to single mailbox and extract new or historical emails in batches of 10."""
        from compliance import calculate_evidence_hash
        from db import check_email_exists_by_hash, get_email_details, get_user_by_email

        target_user_id = mb.get("user_id")
        if target_user_id is None and mb.get("email_address"):
            u = get_user_by_email(mb["email_address"])
            if u:
                target_user_id = u["id"]

        host = mb.get("host", "")
        port = int(mb.get("port", 993))
        username = mb.get("username", "").strip()
        password = mb.get("password", "").replace(" ", "").strip() if ("gmail" in host or "google" in host) else mb.get("password", "").strip()
        folder = mb.get("folder", "INBOX")
        use_ssl = bool(mb.get("use_ssl", 1))

        # If account authenticated via OAuth 2.0 (e.g. Google Gmail API)
        auth_type = mb.get("auth_type", "password")
        access_token = mb.get("access_token", "")
        if auth_type == "oauth" or (access_token and "gmail" in host.lower()):
            if not access_token:
                return {"records": [], "has_more": False, "next_offset": offset, "next_page_token": None, "total_scanned_in_batch": 0}
            try:
                from google_oauth import fetch_gmail_raw_messages, refresh_google_access_token
                from eml_parser import parse_eml_bytes
                try:
                    raw_emls, next_token = fetch_gmail_raw_messages(
                        access_token,
                        max_results=limit or 500,
                        page_token=page_token,
                        unread_only=not include_read,
                    )
                except ValueError as exc:
                    if "rate limiting" in str(exc).lower():
                        raise
                    # Google access tokens are short-lived. Retry once with the
                    # stored refresh token so background live polling keeps working.
                    refreshed = refresh_google_access_token(mb.get("refresh_token", ""))
                    access_token = refreshed["access_token"]
                    from db import update_mailbox_tokens
                    update_mailbox_tokens(mb["id"], access_token, refreshed.get("refresh_token"))
                    raw_emls, next_token = fetch_gmail_raw_messages(
                        access_token,
                        max_results=limit or 500,
                        page_token=page_token,
                        unread_only=not include_read,
                    )
                ingested_records = []
                for eml_bytes in raw_emls:
                    try:
                        parsed = parse_eml_bytes(eml_bytes)
                        evidence_hash = calculate_evidence_hash(
                            parsed["sender"], parsed["subject"], parsed["raw_headers"], parsed["body_text"]
                        )
                        existing_id = check_email_exists_by_hash(evidence_hash, user_id=target_user_id)
                        if existing_id:
                            continue
                        record = self._pipeline_runner(
                            sender=parsed["sender"],
                            subject=parsed["subject"],
                            raw_headers=parsed["raw_headers"],
                            body_text=parsed["body_text"],
                            user_id=target_user_id,
                        )
                        ingested_records.append(record)
                        self._stats["total_ingested"] += 1
                    except Exception as e:
                        logger.error("Error processing OAuth email part: %s", e)
                return {
                    "records": ingested_records,
                    "has_more": bool(next_token and len(raw_emls) > 0),
                    "next_offset": offset + len(raw_emls),
                    "next_page_token": next_token,
                    "total_scanned_in_batch": len(raw_emls),
                }
            except Exception as exc:
                logger.error("OAuth poll error for %s: %s", username, exc)
                return {"records": [], "has_more": False, "next_offset": offset, "next_page_token": None, "total_scanned_in_batch": 0}

        if use_ssl:
            client = imaplib.IMAP4_SSL(host, port, timeout=15)
        else:
            client = imaplib.IMAP4(host, port, timeout=15)

        client.login(username, password)
        client.select(folder)

        # If include_read is True, search ALL messages; otherwise search UNSEEN only
        search_filter = "ALL" if include_read else "UNSEEN"
        status, messages = client.search(None, search_filter)
        if status != "OK" or not messages or not messages[0]:
            client.close()
            client.logout()
            return {"records": [], "has_more": False, "next_offset": offset, "next_page_token": None, "total_scanned_in_batch": 0, "total_inbox_count": 0}

        all_ids = messages[0].split()
        total_inbox_count = len(all_ids)
        all_ids_reversed = list(reversed(all_ids))

        batch_ids = all_ids_reversed[offset : offset + limit] if limit else all_ids_reversed[offset:]
        has_more = (offset + len(batch_ids)) < total_inbox_count

        ingested_records = []
        for e_id in batch_ids:
            try:
                status, msg_data = client.fetch(e_id, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                sender = str(msg.get("From", "unknown@domain.com"))
                subject = str(msg.get("Subject", "No Subject"))

                # Extract raw RFC 822 headers
                headers_list = [f"{k}: {v}" for k, v in msg.items()]
                raw_headers = "\n".join(headers_list)

                # Extract plaintext body
                body_text = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type == "text/plain":
                            body_text += part.get_payload(decode=True).decode("utf-8", errors="ignore") + "\n"
                        elif content_type == "text/html" and not body_text:
                            body_text += part.get_payload(decode=True).decode("utf-8", errors="ignore") + "\n"
                else:
                    body_text = msg.get_payload(decode=True).decode("utf-8", errors="ignore")

                # Evidence hash check for deduplication
                clean_body = body_text.strip() or "(No readable text body)"
                evidence_hash = calculate_evidence_hash(sender, subject, raw_headers, clean_body)
                existing_id = check_email_exists_by_hash(evidence_hash, user_id=target_user_id)
                if existing_id:
                    continue

                # Trigger ByteTrail 4-vector intelligence pipeline
                record = self._pipeline_runner(
                    sender=sender,
                    subject=subject,
                    raw_headers=raw_headers,
                    body_text=clean_body,
                    user_id=target_user_id,
                )
                ingested_records.append(record)
                self._stats["total_ingested"] += 1

                # Mark as seen if it was unread
                if not include_read:
                    client.store(e_id, "+FLAGS", "\\Seen")
            except Exception as e:
                logger.error("Error processing email msg in %s: %s", username, e)

        client.close()
        client.logout()
        return {
            "records": ingested_records,
            "has_more": has_more,
            "next_offset": offset + len(batch_ids),
            "next_page_token": None,
            "total_inbox_count": total_inbox_count,
            "total_scanned_in_batch": len(batch_ids),
        }


# Global singleton instance
mailbox_manager = MultiMailboxManager()
