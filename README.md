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

Teammates can clone and boot the entire stack (Database + Backend + Frontend) in one command without installing Python or MySQL manually.

### 1. Prerequisites
- Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Mac, Windows, or Linux) and ensure it is running.
- Install [Git](https://git-scm.com/).

### 2. Clone and Setup Environment
```bash
git clone https://github.com/yadavkrishna7763/ByteTrail.git
cd ByteTrail

# Copy the sample environment file
cp backend/.env.example backend/.env
```

*(Optional: Add your Google Cloud OAuth credentials to `backend/.env` if testing real Google Login, or use standard IMAP/App Passwords).*

### 3. Build and Launch Containers(Make sure that Docker is running/open on your system)
```bash
docker compose build --no-cache
docker compose up -d
```

### 4. Access the Application
- 🖥️ **Web SOC Dashboard**: 👉 [http://localhost:3000](http://localhost:3000)
- ⚙️ **Interactive API Docs (Swagger UI)**: 👉 [http://localhost:8000/docs](http://localhost:8000/docs)
- 🗄️ **MySQL Database**: `localhost:3306` (`root` / `password` / `bytetrail_db`)

### 5. Useful Docker Commands
```bash
# View live backend & frontend logs
docker compose logs -f

# Check container status
docker compose ps

# Stop all containers
docker compose down

# Restart containers
docker compose restart
```

---

## 💻 Local Setup (Without Docker)

If you prefer running without Docker:

### 1. Backend Setup
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start FastAPI server (auto-uses local MySQL or built-in SQLite)
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Frontend Setup
Open a new terminal window:
```bash
cd frontend
python3 -m http.server 3000
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser.

---

## 🧪 Automated Testing

```bash
cd backend
./venv/bin/pytest -v
```
*(All 8 API and pipeline unit tests verified)*
