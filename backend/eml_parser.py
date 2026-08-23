import email
from email import policy
from typing import Dict, Tuple


def parse_raw_eml(eml_bytes: bytes) -> Dict[str, str]:
    """
    Parse a raw RFC 822 .eml file content into sender, subject,
    raw headers, and extracted plain text body.
    """
    try:
        msg = email.message_from_bytes(eml_bytes, policy=policy.default)
    except Exception:
        text = eml_bytes.decode("utf-8", errors="ignore")
        msg = email.message_from_string(text, policy=policy.default)

    sender = msg.get("From", "unknown@domain.com")
    subject = msg.get("Subject", "No Subject")

    # Extract all raw headers
    headers_list = []
    for k, v in msg.items():
        headers_list.append(f"{k}: {v}")
    raw_headers = "\n".join(headers_list)

    # Extract body
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text += payload.decode("utf-8", errors="ignore") + "\n"
            elif content_type == "text/html" and not body_text and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text += payload.decode("utf-8", errors="ignore") + "\n"
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_text = payload.decode("utf-8", errors="ignore")
        else:
            body_text = str(msg.get_payload() or "")

    return {
        "sender": str(sender),
        "subject": str(subject),
        "raw_headers": raw_headers,
        "body_text": body_text.strip() or "(No readable text body found in EML)",
    }


# Alias
parse_eml_bytes = parse_raw_eml
