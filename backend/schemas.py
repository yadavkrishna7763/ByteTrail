from typing import Optional
from pydantic import BaseModel, Field


class EmailCreate(BaseModel):
    sender: str = Field(
        ...,
        description="Email sender address",
        json_schema_extra={"example": "security@bank-alert-update.com"},
    )
    subject: str = Field(
        ...,
        description="Email subject line",
        json_schema_extra={"example": "URGENT: Verify your account immediately"},
    )
    body_text: str = Field(
        ...,
        description="Email body content",
        json_schema_extra={"example": "Your account has been suspended. Click here to verify."},
    )
    raw_headers: Optional[str] = Field(
        None,
        description="Optional raw RFC 822 email headers",
    )


class EmailResponse(BaseModel):
    id: int
    sender: str
    subject: str
    raw_headers: Optional[str] = None
    body_text: Optional[str] = None
    sha256_hash: Optional[str] = None
    received_at: Optional[str] = None


class EmailDetailResponse(EmailResponse):
    fraud_score: Optional[float] = None
    header_valid: Optional[bool] = None
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp_asn: Optional[str] = None
    is_vpn_tor: Optional[bool] = None
    final_score: Optional[float] = None
    risk_level: Optional[str] = None
    threat_actor: Optional[str] = None


class MailboxConnectRequest(BaseModel):
    email_address: str = Field(..., description="Email address to monitor (e.g. alerts@gmail.com)")
    password: str = Field(..., description="App Password or account password")
    provider: Optional[str] = Field("gmail", description="gmail, outlook, yahoo, icloud, or custom")
    host: Optional[str] = Field(None, description="Custom IMAP Host if provider is custom")
    port: Optional[int] = Field(993, description="IMAP Port (default 993)")
    folder: Optional[str] = Field("INBOX", description="Folder to monitor (default INBOX)")
    use_ssl: Optional[bool] = Field(True, description="Enable SSL/TLS")
    skip_verification: Optional[bool] = Field(False, description="Allow connection without live IMAP auth check for sandbox/demo mode")
    scan_history: Optional[bool] = Field(False, description="Whether to perform an immediate deep historical scan of read + unread emails")


class MailboxResponse(BaseModel):
    id: int
    email_address: str
    provider: str
    host: str
    port: int
    folder: str
    is_active: bool
    total_ingested: int
    created_at: Optional[str] = None
    last_polled: Optional[str] = None
