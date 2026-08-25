import os
import sqlite3
import logging
from typing import Optional, List, Dict, Any
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "bytetrail_db")
ENABLE_SQLITE_FALLBACK = os.getenv("ENABLE_SQLITE_FALLBACK", "True").lower() in ("true", "1", "yes")

SQLITE_DB_PATH = Path(__file__).resolve().parent / "bytetrail_dev.db"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bytetrail.db")

ACTIVE_ENGINE = "mysql"
_DB_INITIALIZED = False


def try_mysql_connection():
    """Attempt connection to MySQL or TiDB Cloud server."""
    import mysql.connector

    connect_kwargs = {
        "host": DB_HOST,
        "port": DB_PORT,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "autocommit": True,
    }

    # Enable SSL for TiDB Cloud or remote cloud MySQL (port 4000, tidbcloud domain, or DB_USE_SSL)
    use_ssl = (
        os.getenv("DB_USE_SSL", "").lower() in ("true", "1", "yes")
        or DB_PORT == 4000
        or "tidbcloud" in str(DB_HOST).lower()
        or os.getenv("MYSQL_SSL", "").lower() in ("true", "1", "yes")
    )
    if use_ssl:
        connect_kwargs["ssl_disabled"] = False
        connect_kwargs["ssl_verify_cert"] = False
        connect_kwargs["ssl_verify_identity"] = False

    # Try connecting directly to database
    try:
        return mysql.connector.connect(database=DB_NAME, **connect_kwargs)
    except Exception:
        try:
            root_conn = mysql.connector.connect(**connect_kwargs)
            cursor = root_conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}`;")
            cursor.close()
            root_conn.close()
        except Exception:
            pass
        return mysql.connector.connect(database=DB_NAME, **connect_kwargs)


def get_connection(ensure_init: bool = True):
    """Get active database connection (MySQL or fallback SQLite)."""
    global ACTIVE_ENGINE, _DB_INITIALIZED
    try:
        conn = try_mysql_connection()
        ACTIVE_ENGINE = "mysql"
    except Exception as exc:
        if ENABLE_SQLITE_FALLBACK:
            logger.warning(
                "Could not connect to MySQL (%s). Falling back to SQLite (%s).",
                exc,
                SQLITE_DB_PATH,
            )
            ACTIVE_ENGINE = "sqlite"
            conn = sqlite3.connect(str(SQLITE_DB_PATH))
            conn.row_factory = sqlite3.Row
        else:
            logger.error("MySQL connection failed and SQLite fallback disabled: %s", exc)
            raise

    if ensure_init and not _DB_INITIALIZED:
        _DB_INITIALIZED = True
        init_db(conn=conn)

    return conn


def init_db(conn=None):
    """Initialize database tables and run automatic migrations."""
    close_after = False
    if conn is None:
        conn = get_connection(ensure_init=False)
        close_after = True
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                sender VARCHAR(255) NOT NULL,
                subject VARCHAR(255) NOT NULL,
                raw_headers TEXT,
                body_text LONGTEXT,
                sha256_hash VARCHAR(64),
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        cursor.execute("""
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
        """)

        cursor.execute("""
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
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_scores (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email_id INT NOT NULL,
                final_score FLOAT DEFAULT 0.0,
                risk_level VARCHAR(20) DEFAULT 'low',
                threat_actor VARCHAR(255) DEFAULT 'Unattributed',
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS forensic_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email_id INT NOT NULL,
                report_path VARCHAR(500),
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS connected_mailboxes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_polled TIMESTAMP NULL DEFAULT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'analyst',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL DEFAULT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        # Run non-destructive column additions if upgrading existing database
        migrations = [
            "ALTER TABLE emails ADD COLUMN sha256_hash VARCHAR(64);",
            "ALTER TABLE emails ADD COLUMN user_id INT;",
            "ALTER TABLE geo_data ADD COLUMN isp_asn VARCHAR(255);",
            "ALTER TABLE geo_data ADD COLUMN is_vpn_tor BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE risk_scores ADD COLUMN threat_actor VARCHAR(255) DEFAULT 'Unattributed';",
            "ALTER TABLE connected_mailboxes ADD COLUMN auth_type VARCHAR(20) DEFAULT 'password';",
            "ALTER TABLE connected_mailboxes ADD COLUMN access_token TEXT;",
            "ALTER TABLE connected_mailboxes ADD COLUMN refresh_token TEXT;",
            "ALTER TABLE connected_mailboxes ADD COLUMN user_id INT;",
        ]
        for m in migrations:
            try:
                cursor.execute(m)
            except Exception:
                pass

    else:
        # SQLite schema
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NULL,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                raw_headers TEXT,
                body_text TEXT,
                sha256_hash TEXT,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER NOT NULL,
                fraud_score REAL DEFAULT 0.0,
                header_valid INTEGER DEFAULT 0,
                spf_result TEXT,
                dkim_result TEXT,
                dmarc_result TEXT,
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS geo_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER NOT NULL,
                ip_address TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                isp_asn TEXT,
                is_vpn_tor INTEGER DEFAULT 0,
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS risk_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER NOT NULL,
                final_score REAL DEFAULT 0.0,
                risk_level TEXT DEFAULT 'low',
                threat_actor TEXT DEFAULT 'Unattributed',
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS forensic_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER NOT NULL,
                report_path TEXT,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS connected_mailboxes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NULL,
                email_address TEXT NOT NULL,
                provider TEXT DEFAULT 'custom',
                host TEXT NOT NULL,
                port INTEGER DEFAULT 993,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                folder TEXT DEFAULT 'INBOX',
                use_ssl INTEGER DEFAULT 1,
                is_active INTEGER DEFAULT 1,
                total_ingested INTEGER DEFAULT 0,
                auth_type TEXT DEFAULT 'password',
                access_token TEXT,
                refresh_token TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_polled TIMESTAMP NULL DEFAULT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'analyst',
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL DEFAULT NULL
            );
        """)

        sqlite_migrations = [
            "ALTER TABLE emails ADD COLUMN sha256_hash TEXT;",
            "ALTER TABLE emails ADD COLUMN user_id INTEGER;",
            "ALTER TABLE geo_data ADD COLUMN isp_asn TEXT;",
            "ALTER TABLE geo_data ADD COLUMN is_vpn_tor INTEGER DEFAULT 0;",
            "ALTER TABLE risk_scores ADD COLUMN threat_actor TEXT DEFAULT 'Unattributed';",
            "ALTER TABLE connected_mailboxes ADD COLUMN auth_type TEXT DEFAULT 'password';",
            "ALTER TABLE connected_mailboxes ADD COLUMN access_token TEXT;",
            "ALTER TABLE connected_mailboxes ADD COLUMN refresh_token TEXT;",
            "ALTER TABLE connected_mailboxes ADD COLUMN user_id INTEGER;",
        ]
        for m in sqlite_migrations:
            try:
                cursor.execute(m)
            except Exception:
                pass

    cursor.close()
    conn.commit()
    if close_after:
        conn.close()
    logger.info("Database initialized successfully using engine: %s", ACTIVE_ENGINE)


def check_email_exists_by_hash(sha256_hash: str, user_id: Optional[int] = None) -> Optional[int]:
    """Check for an existing evidence hash within one user's case feed."""
    if not sha256_hash:
        return None
    conn = get_connection()
    cursor = conn.cursor()
    if user_id is None:
        if ACTIVE_ENGINE == "mysql":
            cursor.execute("SELECT id FROM emails WHERE sha256_hash = %s AND user_id IS NULL LIMIT 1", (sha256_hash,))
        else:
            cursor.execute("SELECT id FROM emails WHERE sha256_hash = ? AND user_id IS NULL LIMIT 1", (sha256_hash,))
    elif ACTIVE_ENGINE == "mysql":
        cursor.execute("SELECT id FROM emails WHERE sha256_hash = %s AND user_id = %s LIMIT 1", (sha256_hash, user_id))
    else:
        cursor.execute("SELECT id FROM emails WHERE sha256_hash = ? AND user_id = ? LIMIT 1", (sha256_hash, user_id))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if row:
        if hasattr(row, "keys"):
            return row["id"]
        elif isinstance(row, dict):
            return row.get("id")
        else:
            return row[0]
    return None


def insert_email(sender: str, subject: str, raw_headers: str = None, body_text: str = None, sha256_hash: str = None, user_id: Optional[int] = None) -> int:
    """Insert a new email record and return its generated ID."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        query = "INSERT INTO emails (sender, subject, raw_headers, body_text, sha256_hash, user_id) VALUES (%s, %s, %s, %s, %s, %s)"
        cursor.execute(query, (sender, subject, raw_headers, body_text, sha256_hash, user_id))
        email_id = cursor.lastrowid
    else:
        query = "INSERT INTO emails (sender, subject, raw_headers, body_text, sha256_hash, user_id) VALUES (?, ?, ?, ?, ?, ?)"
        cursor.execute(query, (sender, subject, raw_headers, body_text, sha256_hash, user_id))
        email_id = cursor.lastrowid

    cursor.close()
    conn.commit()
    conn.close()
    return email_id


def save_analysis_results(
    email_id: int,
    fraud_score: float,
    header_valid: bool,
    spf_result: str,
    dkim_result: str,
    dmarc_result: str,
    ip_address: str,
    country: str,
    city: str,
    latitude: float,
    longitude: float,
    final_score: float,
    risk_level: str,
    isp_asn: str = "Unknown ASN",
    is_vpn_tor: bool = False,
    threat_actor: str = "Unattributed",
):
    """Save analysis, geo, threat intelligence, and risk results for an email record."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        cursor.execute(
            """
            INSERT INTO analysis_results (email_id, fraud_score, header_valid, spf_result, dkim_result, dmarc_result)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (email_id, fraud_score, header_valid, spf_result, dkim_result, dmarc_result),
        )
        cursor.execute(
            """
            INSERT INTO geo_data (email_id, ip_address, country, city, latitude, longitude, isp_asn, is_vpn_tor)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (email_id, ip_address, country, city, latitude, longitude, isp_asn, is_vpn_tor),
        )
        cursor.execute(
            """
            INSERT INTO risk_scores (email_id, final_score, risk_level, threat_actor)
            VALUES (%s, %s, %s, %s)
            """,
            (email_id, final_score, risk_level, threat_actor),
        )
    else:
        cursor.execute(
            """
            INSERT INTO analysis_results (email_id, fraud_score, header_valid, spf_result, dkim_result, dmarc_result)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (email_id, fraud_score, 1 if header_valid else 0, spf_result, dkim_result, dmarc_result),
        )
        cursor.execute(
            """
            INSERT INTO geo_data (email_id, ip_address, country, city, latitude, longitude, isp_asn, is_vpn_tor)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (email_id, ip_address, country, city, latitude, longitude, isp_asn, 1 if is_vpn_tor else 0),
        )
        cursor.execute(
            """
            INSERT INTO risk_scores (email_id, final_score, risk_level, threat_actor)
            VALUES (?, ?, ?, ?)
            """,
            (email_id, final_score, risk_level, threat_actor),
        )

    cursor.close()
    conn.commit()
    conn.close()


def get_all_emails_enriched(user_id: Optional[int] = None, is_admin: bool = False) -> list:
    """Retrieve all emails with their associated intelligence analysis data (strictly scoped to user if not admin)."""
    conn = get_connection()
    cursor = conn.cursor()

    where_clause = ""
    params = ()

    if not is_admin:
        if user_id is None:
            cursor.close()
            conn.close()
            return []
        if ACTIVE_ENGINE == "mysql":
            where_clause = "WHERE e.user_id = %s"
            params = (user_id,)
        else:
            where_clause = "WHERE e.user_id = ?"
            params = (user_id,)

    query = f"""
        SELECT 
            e.id, e.sender, e.subject, e.raw_headers, e.body_text, e.sha256_hash, e.received_at, e.user_id,
            a.fraud_score, a.header_valid, a.spf_result, a.dkim_result, a.dmarc_result,
            g.ip_address, g.country, g.city, g.latitude, g.longitude, g.isp_asn, g.is_vpn_tor,
            r.final_score, r.risk_level, r.threat_actor
        FROM emails e
        LEFT JOIN analysis_results a ON e.id = a.email_id
        LEFT JOIN geo_data g ON e.id = g.email_id
        LEFT JOIN risk_scores r ON e.id = r.email_id
        {where_clause}
        ORDER BY e.id DESC
    """
    cursor.execute(query, params)
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()

    results = []
    for row in rows:
        if hasattr(row, "keys"):
            rec = {k: row[k] for k in row.keys()}
        elif isinstance(row, dict):
            rec = dict(row)
        else:
            rec = dict(zip(columns, row))

        if rec.get("received_at") is not None:
            rec["received_at"] = str(rec["received_at"])
        if rec.get("header_valid") is not None:
            rec["header_valid"] = bool(rec["header_valid"])
        if rec.get("is_vpn_tor") is not None:
            rec["is_vpn_tor"] = bool(rec["is_vpn_tor"])
        if rec.get("latitude") is not None:
            rec["latitude"] = float(rec["latitude"])
        if rec.get("longitude") is not None:
            rec["longitude"] = float(rec["longitude"])
        results.append(rec)

    cursor.close()
    conn.close()
    return results


def get_email_details(email_id: int):
    """Retrieve full intelligence details for a single email by ID."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        query = """
            SELECT 
                e.id, e.sender, e.subject, e.raw_headers, e.body_text, e.sha256_hash, e.received_at, e.user_id,
                a.fraud_score, a.header_valid, a.spf_result, a.dkim_result, a.dmarc_result,
                g.ip_address, g.country, g.city, g.latitude, g.longitude, g.isp_asn, g.is_vpn_tor,
                r.final_score, r.risk_level, r.threat_actor
            FROM emails e
            LEFT JOIN analysis_results a ON e.id = a.email_id
            LEFT JOIN geo_data g ON e.id = g.email_id
            LEFT JOIN risk_scores r ON e.id = r.email_id
            WHERE e.id = %s
        """
        cursor.execute(query, (email_id,))
    else:
        query = """
            SELECT 
                e.id, e.sender, e.subject, e.raw_headers, e.body_text, e.sha256_hash, e.received_at, e.user_id,
                a.fraud_score, a.header_valid, a.spf_result, a.dkim_result, a.dmarc_result,
                g.ip_address, g.country, g.city, g.latitude, g.longitude, g.isp_asn, g.is_vpn_tor,
                r.final_score, r.risk_level, r.threat_actor
            FROM emails e
            LEFT JOIN analysis_results a ON e.id = a.email_id
            LEFT JOIN geo_data g ON e.id = g.email_id
            LEFT JOIN risk_scores r ON e.id = r.email_id
            WHERE e.id = ?
        """
        cursor.execute(query, (email_id,))

    row = cursor.fetchone()
    if not row:
        cursor.close()
        conn.close()
        return None

    columns = [desc[0] for desc in cursor.description]
    cursor.close()
    conn.close()

    if hasattr(row, "keys"):
        rec = {k: row[k] for k in row.keys()}
    elif isinstance(row, dict):
        rec = dict(row)
    else:
        rec = dict(zip(columns, row))

    if rec.get("received_at") is not None:
        rec["received_at"] = str(rec["received_at"])
    if rec.get("header_valid") is not None:
        rec["header_valid"] = bool(rec["header_valid"])
    if rec.get("is_vpn_tor") is not None:
        rec["is_vpn_tor"] = bool(rec["is_vpn_tor"])
    if rec.get("latitude") is not None:
        rec["latitude"] = float(rec["latitude"])
    if rec.get("longitude") is not None:
        rec["longitude"] = float(rec["longitude"])
    return rec


def log_forensic_report(email_id: int, report_path: str):
    """Log or update the generated forensic report path in forensic_reports table."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        query = "INSERT INTO forensic_reports (email_id, report_path) VALUES (%s, %s)"
        cursor.execute(query, (email_id, report_path))
    else:
        query = "INSERT INTO forensic_reports (email_id, report_path) VALUES (?, ?)"
        cursor.execute(query, (email_id, report_path))

    cursor.close()
    conn.commit()
    conn.close()


def get_forensic_report_log(email_id: int) -> str:
    """Retrieve the stored report path for an email ID if exists."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        query = "SELECT report_path FROM forensic_reports WHERE email_id = %s ORDER BY id DESC LIMIT 1"
        cursor.execute(query, (email_id,))
    else:
        query = "SELECT report_path FROM forensic_reports WHERE email_id = ? ORDER BY id DESC LIMIT 1"
        cursor.execute(query, (email_id,))

    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        return None

    if hasattr(row, "keys"):
        return row["report_path"]
    elif isinstance(row, dict):
        return row.get("report_path")
    else:
        return row[0]


# ==============================================================================
# CONNECTED MAILBOX MANAGEMENT (Continuous Live Monitoring)
# ==============================================================================

def add_connected_mailbox(
    email_address: str,
    host: str,
    port: int,
    username: str,
    password: str,
    provider: str = "custom",
    folder: str = "INBOX",
    use_ssl: bool = True,
    is_active: bool = True,
    user_id: Optional[int] = None,
) -> int:
    """Register a new live email account for continuous automated polling."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        query = """
            INSERT INTO connected_mailboxes (email_address, provider, host, port, username, password, folder, use_ssl, is_active, user_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (email_address, provider, host, port, username, password, folder, use_ssl, is_active, user_id))
        mb_id = cursor.lastrowid
    else:
        query = """
            INSERT INTO connected_mailboxes (email_address, provider, host, port, username, password, folder, use_ssl, is_active, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(query, (email_address, provider, host, port, username, password, folder, 1 if use_ssl else 0, 1 if is_active else 0, user_id))
        mb_id = cursor.lastrowid

    cursor.close()
    conn.commit()
    conn.close()
    return mb_id


def get_all_connected_mailboxes(active_only: bool = False, user_id: Optional[int] = None, is_admin: bool = False, user_email: Optional[str] = None) -> list:
    """Retrieve list of connected mailboxes (strictly scoped to user if not admin)."""
    conn = get_connection()
    cursor = conn.cursor()

    conditions = []
    params = []

    if active_only:
        conditions.append("is_active = 1")

    if not is_admin:
        if user_id is None:
            cursor.close()
            conn.close()
            return []
        if ACTIVE_ENGINE == "mysql":
            conditions.append("user_id = %s")
        else:
            conditions.append("user_id = ?")
        params.append(user_id)

    clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    query = f"SELECT id, email_address, provider, host, port, username, password, folder, use_ssl, is_active, total_ingested, created_at, last_polled, auth_type, access_token, refresh_token, user_id FROM connected_mailboxes {clause} ORDER BY id DESC"
    cursor.execute(query, tuple(params))
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()

    results = []
    for row in rows:
        if hasattr(row, "keys"):
            rec = {k: row[k] for k in row.keys()}
        elif isinstance(row, dict):
            rec = dict(row)
        else:
            rec = dict(zip(columns, row))

        if rec.get("created_at") is not None:
            rec["created_at"] = str(rec["created_at"])
        if rec.get("last_polled") is not None:
            rec["last_polled"] = str(rec["last_polled"])
        if rec.get("use_ssl") is not None:
            rec["use_ssl"] = bool(rec["use_ssl"])
        if rec.get("is_active") is not None:
            rec["is_active"] = bool(rec["is_active"])

        # Non-admin safety check: do not return mailboxes belonging to a different email address
        if not is_admin and user_email:
            if rec.get("email_address") and rec["email_address"].strip().lower() != user_email.strip().lower():
                continue

        # Dynamically compute exact real ingested email count for this user from the emails table
        mb_user_id = rec.get("user_id")
        if mb_user_id is not None:
            cursor2 = conn.cursor()
            if ACTIVE_ENGINE == "mysql":
                cursor2.execute("SELECT COUNT(*) FROM emails WHERE user_id = %s", (mb_user_id,))
            else:
                cursor2.execute("SELECT COUNT(*) FROM emails WHERE user_id = ?", (mb_user_id,))
            cnt_row = cursor2.fetchone()
            real_count = cnt_row[0] if (cnt_row and cnt_row[0] is not None) else 0
            cursor2.close()
            rec["total_ingested"] = real_count
        elif not is_admin:
            rec["total_ingested"] = 0

        results.append(rec)

    cursor.close()
    conn.close()
    return results


def delete_connected_mailbox(mailbox_id: int):
    """Disconnect and remove a connected email mailbox."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        cursor.execute("DELETE FROM connected_mailboxes WHERE id = %s", (mailbox_id,))
    else:
        cursor.execute("DELETE FROM connected_mailboxes WHERE id = ?", (mailbox_id,))

    cursor.close()
    conn.commit()
    conn.close()


def update_mailbox_stats(mailbox_id: int, count_increment: int = 1):
    """Update total ingested count and last polled timestamp."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        cursor.execute(
            """
            UPDATE connected_mailboxes 
            SET total_ingested = total_ingested + %s, last_polled = CURRENT_TIMESTAMP 
            WHERE id = %s
            """,
            (count_increment, mailbox_id),
        )
    else:
        cursor.execute(
            """
            UPDATE connected_mailboxes 
            SET total_ingested = total_ingested + ?, last_polled = CURRENT_TIMESTAMP 
            WHERE id = ?
            """,
            (count_increment, mailbox_id),
        )

    cursor.close()
    conn.commit()
    conn.close()


def upsert_oauth_mailbox(email_address: str, provider: str = "google", access_token: str = "", refresh_token: str = "", user_id: Optional[int] = None) -> int:
    """Register or update an OAuth-authenticated mailbox (e.g. Google OAuth 2.0)."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        cursor.execute("SELECT id FROM connected_mailboxes WHERE email_address = %s LIMIT 1", (email_address,))
        row = cursor.fetchone()
        if row:
            mb_id = row[0] if isinstance(row, (list, tuple)) else row["id"]
            if user_id is not None:
                cursor.execute(
                    """
                    UPDATE connected_mailboxes 
                    SET auth_type = 'oauth', access_token = %s, refresh_token = COALESCE(%s, refresh_token), is_active = 1, user_id = %s
                    WHERE id = %s
                    """,
                    (access_token, refresh_token or None, user_id, mb_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE connected_mailboxes 
                    SET auth_type = 'oauth', access_token = %s, refresh_token = COALESCE(%s, refresh_token), is_active = 1
                    WHERE id = %s
                    """,
                    (access_token, refresh_token or None, mb_id),
                )
        else:
            cursor.execute(
                """
                INSERT INTO connected_mailboxes (email_address, provider, host, port, username, password, folder, auth_type, access_token, refresh_token, is_active, user_id)
                VALUES (%s, %s, 'gmail.googleapis.com', 443, %s, '', 'INBOX', 'oauth', %s, %s, 1, %s)
                """,
                (email_address, provider, email_address, access_token, refresh_token, user_id),
            )
            mb_id = cursor.lastrowid
    else:
        cursor.execute("SELECT id FROM connected_mailboxes WHERE email_address = ? LIMIT 1", (email_address,))
        row = cursor.fetchone()
        if row:
            mb_id = row[0] if isinstance(row, (list, tuple)) else row["id"]
            if user_id is not None:
                cursor.execute(
                    """
                    UPDATE connected_mailboxes 
                    SET auth_type = 'oauth', access_token = ?, refresh_token = COALESCE(?, refresh_token), is_active = 1, user_id = ?
                    WHERE id = ?
                    """,
                    (access_token, refresh_token or None, user_id, mb_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE connected_mailboxes 
                    SET auth_type = 'oauth', access_token = ?, refresh_token = COALESCE(?, refresh_token), is_active = 1
                    WHERE id = ?
                    """,
                    (access_token, refresh_token or None, mb_id),
                )
        else:
            cursor.execute(
                """
                INSERT INTO connected_mailboxes (email_address, provider, host, port, username, password, folder, auth_type, access_token, refresh_token, is_active, user_id)
                VALUES (?, ?, 'gmail.googleapis.com', 443, ?, '', 'INBOX', 'oauth', ?, ?, 1, ?)
                """,
                (email_address, provider, email_address, access_token, refresh_token, user_id),
            )
            mb_id = cursor.lastrowid

    cursor.close()
    conn.commit()
    conn.close()
    return mb_id


def update_mailbox_tokens(mailbox_id: int, access_token: str, refresh_token: str = None):
    """Update OAuth tokens after token refresh."""
    conn = get_connection()
    cursor = conn.cursor()
    if ACTIVE_ENGINE == "mysql":
        cursor.execute(
            "UPDATE connected_mailboxes SET access_token = %s, refresh_token = COALESCE(%s, refresh_token) WHERE id = %s",
            (access_token, refresh_token, mailbox_id),
        )
    else:
        cursor.execute(
            "UPDATE connected_mailboxes SET access_token = ?, refresh_token = COALESCE(?, refresh_token) WHERE id = ?",
            (access_token, refresh_token, mailbox_id),
        )
    cursor.close()
    conn.commit()
    conn.close()


# ==============================================================================
# User Management & Authentication Helpers
# ==============================================================================
def create_user(email: str, full_name: str, password_hash: str, role: str = "analyst") -> int:
    """Create a new registered user in the database."""
    conn = get_connection()
    cursor = conn.cursor()
    clean_email = email.strip().lower()
    
    if ACTIVE_ENGINE == "mysql":
        cursor.execute(
            """
            INSERT INTO users (email, full_name, password_hash, role, is_active)
            VALUES (%s, %s, %s, %s, 1)
            """,
            (clean_email, full_name.strip(), password_hash, role),
        )
        user_id = cursor.lastrowid
    else:
        cursor.execute(
            """
            INSERT INTO users (email, full_name, password_hash, role, is_active)
            VALUES (?, ?, ?, ?, 1)
            """,
            (clean_email, full_name.strip(), password_hash, role),
        )
        user_id = cursor.lastrowid

    cursor.close()
    conn.commit()
    conn.close()
    return user_id


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieve user record by email address."""
    conn = get_connection()
    cursor = conn.cursor()
    clean_email = email.strip().lower()

    if ACTIVE_ENGINE == "mysql":
        cursor.execute(
            "SELECT id, email, full_name, password_hash, role, is_active, created_at, last_login FROM users WHERE email = %s LIMIT 1",
            (clean_email,),
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if not row:
            return None
        return {
            "id": row[0],
            "email": row[1],
            "full_name": row[2],
            "password_hash": row[3],
            "role": row[4],
            "is_active": bool(row[5]),
            "created_at": str(row[6]) if row[6] else None,
            "last_login": str(row[7]) if row[7] else None,
        }
    else:
        cursor.execute(
            "SELECT id, email, full_name, password_hash, role, is_active, created_at, last_login FROM users WHERE email = ? LIMIT 1",
            (clean_email,),
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"] if isinstance(row, sqlite3.Row) else row[0],
            "email": row["email"] if isinstance(row, sqlite3.Row) else row[1],
            "full_name": row["full_name"] if isinstance(row, sqlite3.Row) else row[2],
            "password_hash": row["password_hash"] if isinstance(row, sqlite3.Row) else row[3],
            "role": row["role"] if isinstance(row, sqlite3.Row) else row[4],
            "is_active": bool(row["is_active"] if isinstance(row, sqlite3.Row) else row[5]),
            "created_at": str(row["created_at"]) if (isinstance(row, sqlite3.Row) and row["created_at"]) or (not isinstance(row, sqlite3.Row) and row[6]) else None,
            "last_login": str(row["last_login"]) if (isinstance(row, sqlite3.Row) and row["last_login"]) or (not isinstance(row, sqlite3.Row) and row[7]) else None,
        }


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve user record by user ID."""
    conn = get_connection()
    cursor = conn.cursor()

    if ACTIVE_ENGINE == "mysql":
        cursor.execute(
            "SELECT id, email, full_name, password_hash, role, is_active, created_at, last_login FROM users WHERE id = %s LIMIT 1",
            (user_id,),
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if not row:
            return None
        return {
            "id": row[0],
            "email": row[1],
            "full_name": row[2],
            "password_hash": row[3],
            "role": row[4],
            "is_active": bool(row[5]),
            "created_at": str(row[6]) if row[6] else None,
            "last_login": str(row[7]) if row[7] else None,
        }
    else:
        cursor.execute(
            "SELECT id, email, full_name, password_hash, role, is_active, created_at, last_login FROM users WHERE id = ? LIMIT 1",
            (user_id,),
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if not row:
            return None
        return {
            "id": row["id"] if isinstance(row, sqlite3.Row) else row[0],
            "email": row["email"] if isinstance(row, sqlite3.Row) else row[1],
            "full_name": row["full_name"] if isinstance(row, sqlite3.Row) else row[2],
            "password_hash": row["password_hash"] if isinstance(row, sqlite3.Row) else row[3],
            "role": row["role"] if isinstance(row, sqlite3.Row) else row[4],
            "is_active": bool(row["is_active"] if isinstance(row, sqlite3.Row) else row[5]),
            "created_at": str(row["created_at"]) if (isinstance(row, sqlite3.Row) and row["created_at"]) or (not isinstance(row, sqlite3.Row) and row[6]) else None,
            "last_login": str(row["last_login"]) if (isinstance(row, sqlite3.Row) and row["last_login"]) or (not isinstance(row, sqlite3.Row) and row[7]) else None,
        }


def update_user_last_login(user_id: int):
    """Record current timestamp as user's last login."""
    from datetime import datetime
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    if ACTIVE_ENGINE == "mysql":
        cursor.execute("UPDATE users SET last_login = %s WHERE id = %s", (now_str, user_id))
    else:
        cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_str, user_id))

    cursor.close()
    conn.commit()
    conn.close()


def count_users() -> int:
    """Return total number of registered users."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    row = cursor.fetchone()
    count = row[0] if row else 0
    cursor.close()
    conn.close()
    return count
