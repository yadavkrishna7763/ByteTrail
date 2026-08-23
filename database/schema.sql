-- ByteTrail Relational Database Schema
-- Problem Statement ID: 26106 (Smart India Hackathon)

CREATE DATABASE IF NOT EXISTS bytetrail_db;
USE bytetrail_db;

-- 1. Stored emails with Chain of Custody SHA-256 Hash
CREATE TABLE IF NOT EXISTS emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    raw_headers TEXT,
    body_text LONGTEXT,
    sha256_hash VARCHAR(64),
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Analysis results (Fraud score and email authentication)
CREATE TABLE IF NOT EXISTS analysis_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT NOT NULL,
    fraud_score FLOAT DEFAULT 0.0,
    header_valid BOOLEAN DEFAULT FALSE,
    spf_result VARCHAR(50),
    dkim_result VARCHAR(50),
    dmarc_result VARCHAR(50),
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. GeoLocation & Threat Intelligence data
CREATE TABLE IF NOT EXISTS geo_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT NOT NULL,
    ip_address VARCHAR(45),
    country VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    isp_asn VARCHAR(255),
    is_vpn_tor BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Aggregate threat risk scores & Campaign attribution
CREATE TABLE IF NOT EXISTS risk_scores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT NOT NULL,
    final_score FLOAT DEFAULT 0.0,
    risk_level VARCHAR(20) DEFAULT 'low',
    threat_actor VARCHAR(255) DEFAULT 'Unattributed',
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Forensic report logs
CREATE TABLE IF NOT EXISTS forensic_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT NOT NULL,
    report_path VARCHAR(500),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. Live Connected Email Accounts (Automated continuous monitoring)
CREATE TABLE IF NOT EXISTS connected_mailboxes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_address VARCHAR(255) NOT NULL,
    provider VARCHAR(50) DEFAULT 'custom',
    host VARCHAR(255) NOT NULL,
    port INT DEFAULT 993,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    folder VARCHAR(100) DEFAULT 'INBOX',
    use_ssl BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    total_ingested INT DEFAULT 0,
    auth_type VARCHAR(20) DEFAULT 'password',
    access_token TEXT,
    refresh_token TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_polled TIMESTAMP NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
