import os
from pathlib import Path
from datetime import datetime
from typing import Dict

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable


def get_reports_dir() -> Path:
    """Ensure and return the reports directory."""
    project_root = Path(__file__).resolve().parent.parent
    reports_dir = project_root / "reports"
    reports_dir.mkdir(exist_ok=True)
    return reports_dir


def generate_forensic_report(email_data: Dict) -> str:
    """
    Generate a formal PDF Cyber Threat & Forensic Intelligence Incident Report
    using ReportLab.

    Returns:
        Absolute filepath to the generated PDF report.
    """
    email_id = email_data.get("id", 0)
    reports_dir = get_reports_dir()
    report_filename = f"forensic_report_email_{email_id}.pdf"
    report_path = reports_dir / report_filename

    doc = SimpleDocTemplate(
        str(report_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    
    # Custom Palette
    primary_color = colors.HexColor("#0f172a")     # Dark Slate
    accent_blue = colors.HexColor("#0284c7")       # Cyan Blue
    dark_gray = colors.HexColor("#334155")
    light_bg = colors.HexColor("#f8fafc")
    border_color = colors.HexColor("#cbd5e1")
    
    risk_level = (email_data.get("risk_level") or "low").upper()
    if risk_level == "HIGH":
        risk_color = colors.HexColor("#e11d48")     # Rose Red
        risk_bg = colors.HexColor("#ffe4e6")
    elif risk_level == "MEDIUM":
        risk_color = colors.HexColor("#d97706")   # Amber
        risk_bg = colors.HexColor("#fef3c7")
    else:
        risk_color = colors.HexColor("#16a34a")    # Emerald Green
        risk_bg = colors.HexColor("#dcfce7")

    # Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=primary_color,
        fontName="Helvetica-Bold",
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        fontName="Helvetica",
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=11,
        leading=14,
        textColor=accent_blue,
        fontName="Helvetica-Bold",
        spaceBefore=10,
        spaceAfter=4,
    )

    body_style = ParagraphStyle(
        "TableBody",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
        fontName="Helvetica",
    )

    body_bold = ParagraphStyle(
        "TableBodyBold",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
        fontName="Helvetica-Bold",
    )

    code_style = ParagraphStyle(
        "CodeText",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#334155"),
        fontName="Courier",
    )

    story = []

    # 1. Header Banner
    header_data = [
        [
            Paragraph("<b>BYTETRAIL FORENSIC INTELLIGENCE REPORT</b>", title_style),
            Paragraph(f"<b>CASE ID:</b> #{email_id}<br/><b>DATE:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style)
        ],
        [
            Paragraph("AI-Powered Threat Detection & Forensic Intelligence | SIH Problem Statement 26106", subtitle_style),
            Paragraph("<b>CLASSIFICATION:</b> TLP:AMBER", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[380, 160])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_blue, spaceBefore=2, spaceAfter=8))

    # 2. Executive Threat Summary Box
    final_score = email_data.get("final_score", 0.0)
    fraud_score = email_data.get("fraud_score", 0.0)
    
    summary_data = [
        [
            Paragraph("<b>COMPOSITE RISK ASSESSMENT</b>", body_bold),
            Paragraph(f"<font color='{risk_color.hexval()}'><b>{risk_level} THREAT LEVEL ({final_score} / 100)</b></font>", body_bold),
            Paragraph(f"<b>FRAUD PROBABILITY:</b> {round(fraud_score * 100)}%", body_bold),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[180, 200, 160])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_bg),
        ('BOX', (0, 0), (-1, -1), 1, risk_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    # 3. Incident Metadata & GeoLocation Forensics
    story.append(Paragraph("1. Incident Metadata & Origin Geolocation", section_heading))
    
    sender = email_data.get("sender", "N/A")
    subject = email_data.get("subject", "N/A")
    received_at = email_data.get("received_at", "N/A")
    ip_address = email_data.get("ip_address", "Unknown")
    country = email_data.get("country", "Unknown")
    city = email_data.get("city", "Unknown")
    lat = email_data.get("latitude", 0.0)
    lon = email_data.get("longitude", 0.0)
    sha256_hash = email_data.get("sha256_hash") or "N/A"
    isp_asn = email_data.get("isp_asn") or "Standard Autonomous System"
    threat_actor = email_data.get("threat_actor") or "Unattributed"

    meta_geo_data = [
        [Paragraph("<b>Sender:</b>", body_bold), Paragraph(sender, body_style), Paragraph("<b>Origin IP:</b>", body_bold), Paragraph(ip_address, code_style)],
        [Paragraph("<b>Subject:</b>", body_bold), Paragraph(subject, body_style), Paragraph("<b>Country/City:</b>", body_bold), Paragraph(f"{country}, {city}", body_style)],
        [Paragraph("<b>ISP / ASN:</b>", body_bold), Paragraph(isp_asn, body_style), Paragraph("<b>Threat Actor:</b>", body_bold), Paragraph(threat_actor, body_bold)],
        [Paragraph("<b>Evidence SHA-256:</b>", body_bold), Paragraph(sha256_hash[:32] + "...", code_style), Paragraph("<b>Coordinates:</b>", body_bold), Paragraph(f"Lat: {lat}, Lon: {lon}", code_style)],
    ]
    meta_table = Table(meta_geo_data, colWidths=[90, 180, 85, 185])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), light_bg),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 4. Authentication & Header Forensics Table
    story.append(Paragraph("2. Cryptographic Email Authentication Forensics", section_heading))
    
    spf = (email_data.get("spf_result") or "none").upper()
    dkim = (email_data.get("dkim_result") or "none").upper()
    dmarc = (email_data.get("dmarc_result") or "none").upper()
    header_valid = "VALID / AUTHENTICATED" if email_data.get("header_valid") else "UNVERIFIED / FAILED"

    auth_data = [
        [
            Paragraph("<b>Protocol</b>", body_bold),
            Paragraph("<b>Validation Status</b>", body_bold),
            Paragraph("<b>Security Evaluation</b>", body_bold)
        ],
        [
            Paragraph("<b>SPF (Sender Policy Framework)</b>", body_style),
            Paragraph(f"<b>{spf}</b>", body_bold),
            Paragraph("Validates relay IP against DNS authorization record" if spf == "PASS" else "Unauthorized sending relay IP detected", body_style)
        ],
        [
            Paragraph("<b>DKIM (DomainKeys Identified Mail)</b>", body_style),
            Paragraph(f"<b>{dkim}</b>", body_bold),
            Paragraph("Cryptographic RSA public key signature matches message body" if dkim in ("PASS", "PRESENT") else "Digital signature missing or signature tamper detected", body_style)
        ],
        [
            Paragraph("<b>DMARC Alignment</b>", body_style),
            Paragraph(f"<b>{dmarc}</b>", body_bold),
            Paragraph("Domain alignment conforms to strict organizational policy" if dmarc == "PASS" else "Failed domain alignment or spoofing protection policy", body_style)
        ],
        [
            Paragraph("<b>Overall Header Integrity</b>", body_bold),
            Paragraph(f"<b>{header_valid}</b>", body_bold),
            Paragraph("Headers show no domain mismatch" if email_data.get("header_valid") else "Anomalous or spoofed headers identified", body_style)
        ],
    ]
    auth_table = Table(auth_data, colWidths=[170, 120, 250])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 10))

    # 5. Raw Evidence & Excerpt
    story.append(Paragraph("3. Forensic Evidence Excerpt", section_heading))
    body_snippet = (email_data.get("body_text") or "No body content provided.")[:400]
    if len(email_data.get("body_text") or "") > 400:
        body_snippet += " ... [truncated]"
    
    evidence_data = [
        [Paragraph("<b>Message Body Content Excerpt:</b>", body_bold)],
        [Paragraph(body_snippet.replace("\n", "<br/>"), code_style)]
    ]
    evidence_table = Table(evidence_data, colWidths=[540])
    evidence_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), light_bg),
        ('BOX', (0, 0), (-1, -1), 0.5, border_color),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(evidence_table)
    story.append(Spacer(1, 12))

    # 6. Auditor Certification Footer
    story.append(HRFlowable(width="100%", thickness=0.5, color=border_color, spaceBefore=2, spaceAfter=4))
    footer_text = Paragraph(
        "<b>ByteTrail Automated Forensic Engine</b> | Problem Statement 26106 | "
        "Generated strictly for security incident analysis and law enforcement auditing.",
        subtitle_style
    )
    story.append(footer_text)

    # Build Document
    doc.build(story)
    return str(report_path)
