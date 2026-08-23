# 🛡️ ByteTrail — Enterprise AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

**AICTE Cyber Security Cell | Smart India Hackathon Problem Statement 26106**
*Theme: Blockchain & Cybersecurity | Category: Software*

---

## 🌟 Executive Overview: What ByteTrail Does

ByteTrail addresses the complete 3-layered email threat lifecycle:
1. **🔍 DETECT (Classification & Phishing NLP Engine)**: Classifies incoming email as legitimate, suspicious, impersonated, or malicious phishing/BEC using linguistic heuristics, urgency detectors, and typosquatting pattern matching.
2. **📍 TRACE (Forensics, GeoIP & Relay Reconstruction)**: Parses raw RFC 822 `Received:` header hops from bottom to top to identify the earliest trustworthy public relay IP, resolving Country, City, Lat/Lon GPS coordinates, and Autonomous System (ISP/ASN).
3. **🕸️ CORRELATE (Graph-Based Threat Attribution)**: Clustered graph correlation linking disparate email incidents sharing the same attacker infrastructure, lookalike domains, or bulletproof hosters.
4. **⚖️ COMPLY (Chain-of-Custody & Evidence Integrity)**: Computes tamper-proof cryptographic **SHA-256 digital evidence fingerprints** compliant with digital forensic handling guidelines (ISO/IEC 27037:2012).
5. **📄 REPORT (Case Management & Incident Export)**: Dynamic generation of official **1-page Cyber Incident Investigation PDF Reports** via ReportLab.

---

## 🧩 Architectural Mapping to SIH PS-26106 Requirements

| SIH Requirement | ByteTrail Implementation Module | Status |
| :--- | :--- | :---: |
| **Fraudulent Email Detection** | [`backend/fraud_detection.py`](backend/fraud_detection.py) (NLP, Urgency Lures, Financial BEC keywords, Typosquatting) | ✅ 100% |
| **Header & Protocol Forensics** | [`backend/header_analysis.py`](backend/header_analysis.py) (SPF, DKIM RSA signatures, DMARC alignment, From/Reply-To spoofing) | ✅ 100% |
| **Origin Traceability & GeoIP** | [`backend/geo_lookup.py`](backend/geo_lookup.py) & [`backend/threat_intel.py`](backend/threat_intel.py) (Relay-chain extraction, MaxMind/Threat feeds, ISP/ASN) | ✅ 100% |
| **Identity & Campaign Correlation** | [`backend/campaign_correlation.py`](backend/campaign_correlation.py) (Graph analysis linking nodes: Cases, Domains, Origin IPs) | ✅ 100% |
| **Raw `.EML` File Support** | [`backend/eml_parser.py`](backend/eml_parser.py) (RFC 822 MIME parser supporting drag-and-drop `.eml` uploads) | ✅ 100% |
| **Privacy & Legal Chain-of-Custody** | [`backend/compliance.py`](backend/compliance.py) (SHA-256 digital fingerprinting & evidence audit trail) | ✅ 100% |
| **Web SOC Dashboard & Threat Map** | [`frontend/index.html`](frontend/index.html), [`frontend/styles.css`](frontend/styles.css), [`frontend/app.js`](frontend/app.js) (Leaflet.js Threat Radar, Ticker, Graph View) | ✅ 100% |
| **Forensic PDF Incident Reports** | [`backend/report_generator.py`](backend/report_generator.py) (ReportLab automated 1-page PDF exports) | ✅ 100% |
| **Multi-Platform Dockerization** | [`docker-compose.yml`](docker-compose.yml) (One-command boot for Mac, Windows, Linux) | ✅ 100% |

---

## 🚀 Quick Start with Docker (Recommended for Teammates)

No need to install Python or MySQL manually. Run the entire stack with a single command:

```bash
docker compose up --build
```

- **Web SOC Dashboard**: 👉 [http://localhost:3000](http://localhost:3000)
- **FastAPI Backend & Interactive Swagger Docs**: 👉 [http://localhost:8000/docs](http://localhost:8000/docs)
- **MySQL Database**: Running on port `3306` (`root` / `rootpassword`).

---

## 💻 Manual Setup (Without Docker)

### 1. Database Configuration
Create the MySQL database `bytetrail_db` and configure `backend/.env`:
```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=bytetrail_db
```

### 2. Backend Setup
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python seed_data.py
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### 3. Frontend Dashboard
```bash
cd frontend
python3 -m http.server 3000
```
Open **[http://127.0.0.1:3000](http://127.0.0.1:3000)**.

---

## 🧪 Automated Testing

```bash
cd backend
venv/bin/pytest -v test_api.py
```
*(All 5 unit and integration tests passing)*
