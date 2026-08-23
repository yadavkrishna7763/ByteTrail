import os
import shutil
import logging
from pathlib import Path
from typing import List, Dict
from eml_parser import parse_raw_eml

logger = logging.getLogger("bytetrail.watcher")

WATCH_DIR = Path(__file__).resolve().parent / "inbound_emails"
PROCESSED_DIR = WATCH_DIR / "processed"


def init_watch_directories():
    """Ensure the inbound watch directory structure exists."""
    WATCH_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def scan_and_ingest_directory(pipeline_runner_func) -> List[Dict]:
    """
    Scan the inbound_emails directory for any dropped .eml or .msg files,
    automatically process them through the intelligence pipeline,
    and archive them to prevent duplicate ingestion.
    """
    init_watch_directories()
    ingested_records = []

    for file_path in WATCH_DIR.glob("*.*"):
        if file_path.is_file() and file_path.suffix.lower() in (".eml", ".msg", ".txt"):
            try:
                with open(file_path, "rb") as f:
                    content = f.read()

                parsed = parse_raw_eml(content)
                record = pipeline_runner_func(
                    sender=parsed["sender"],
                    subject=parsed["subject"],
                    raw_headers=parsed["raw_headers"],
                    body_text=parsed["body_text"],
                )
                ingested_records.append(record)

                # Move to processed archive
                target_dest = PROCESSED_DIR / file_path.name
                shutil.move(str(file_path), str(target_dest))
                logger.info("Auto-ingested and archived file: %s -> %s", file_path.name, target_dest)
            except Exception as exc:
                logger.error("Failed to auto-ingest file %s: %s", file_path.name, exc)

    return ingested_records
