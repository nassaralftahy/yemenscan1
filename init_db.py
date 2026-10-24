"""
Database Initialization & Enterprise Schema Migration for YemenScan.

Connects to the database, executes schema upgrades (PostgreSQL / SQLite),
seeds default system settings, and optionally ingests historical scan
sessions from the disk storage into PostgreSQL.

Usage:
    python init_db.py                     # Initialize schema & seed settings
    python init_db.py --migrate-scans     # Ingest all historical disk scans
    python init_db.py --all               # Initialize, migrate schema & ingest scans
"""

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine
from models import (
    Targets,
    ScanSessions,
    Assets,
    VulnerabilityCatalog,
    VulnerabilityFindings,
    AIReports,
    SystemSettings,
)
from core.db_service import (
    ingest_scan_from_directory,
    get_or_set_system_setting,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("yemenscan.init_db")


def migrate_schema() -> bool:
    """
    Executes non-destructive schema migrations for PostgreSQL and SQLite,
    ensuring newly added columns and indexes exist without dropping data.
    """
    dialect = engine.dialect.name
    logger.info("Running schema migration for dialect: %s", dialect)

    if dialect == "postgresql":
        pg_migrations = [
            # Targets
            "ALTER TABLE targets ADD COLUMN IF NOT EXISTS organization VARCHAR(255);",
            "ALTER TABLE targets ADD COLUMN IF NOT EXISTS description TEXT;",
            "ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMP WITH TIME ZONE;",
            # ScanSessions
            "ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS current_stage VARCHAR(50);",
            "ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0;",
            "ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS stats_summary JSONB;",
            "ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS execution_logs JSONB;",
            # Assets
            "ALTER TABLE assets ADD COLUMN IF NOT EXISTS asset_type VARCHAR(50) DEFAULT 'web_service';",
            "ALTER TABLE assets ADD COLUMN IF NOT EXISTS status_code INTEGER;",
            # VulnerabilityCatalog
            "ALTER TABLE vulnerability_catalog ADD COLUMN IF NOT EXISTS severity VARCHAR(20);",
            "ALTER TABLE vulnerability_catalog ADD COLUMN IF NOT EXISTS reference_links JSONB;",
            # VulnerabilityFindings
            "ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS source VARCHAR(100) DEFAULT 'Vulnerability Engine';",
            "ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'open';",
            # AIReports
            "ALTER TABLE ai_reports ADD COLUMN IF NOT EXISTS model_used VARCHAR(100);",
            "ALTER TABLE ai_reports ADD COLUMN IF NOT EXISTS report_metadata JSONB;",
            # Performance Indexes
            "CREATE INDEX IF NOT EXISTS ix_vulnerability_findings_source ON vulnerability_findings (source);",
            "CREATE INDEX IF NOT EXISTS ix_assets_asset_type ON assets (asset_type);",
            "CREATE INDEX IF NOT EXISTS ix_system_settings_key ON system_settings (key);",
        ]

        with engine.begin() as conn:
            for stmt in pg_migrations:
                try:
                    conn.execute(text(stmt))
                except Exception as ex:
                    logger.warning("Migration statement note: %s (%s)", stmt.strip(), ex)

        logger.info("PostgreSQL schema migration completed successfully.")
        return True

    elif dialect == "sqlite":
        # SQLite inspection and safe column additions
        sqlite_columns = [
            ("targets", "organization", "VARCHAR(255)"),
            ("targets", "description", "TEXT"),
            ("targets", "last_scanned_at", "DATETIME"),
            ("scan_sessions", "current_stage", "VARCHAR(50)"),
            ("scan_sessions", "progress", "INTEGER DEFAULT 0"),
            ("scan_sessions", "stats_summary", "JSON"),
            ("scan_sessions", "execution_logs", "JSON"),
            ("assets", "asset_type", "VARCHAR(50) DEFAULT 'web_service'"),
            ("assets", "status_code", "INTEGER"),
            ("vulnerability_catalog", "severity", "VARCHAR(20)"),
            ("vulnerability_catalog", "reference_links", "JSON"),
            ("vulnerability_findings", "source", "VARCHAR(100) DEFAULT 'Vulnerability Engine'"),
            ("vulnerability_findings", "status", "VARCHAR(50) DEFAULT 'open'"),
            ("ai_reports", "model_used", "VARCHAR(100)"),
            ("ai_reports", "report_metadata", "JSON"),
        ]

        with engine.begin() as conn:
            for table, col_name, col_type in sqlite_columns:
                try:
                    # Check if table exists
                    tbl_check = conn.execute(
                        text(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}';")
                    ).scalar()
                    if not tbl_check:
                        continue
                    # Check if column exists
                    cols = [
                        row[1]
                        for row in conn.execute(text(f"PRAGMA table_info({table});")).fetchall()
                    ]
                    if col_name not in cols:
                        logger.info("Adding column %s.%s (%s)", table, col_name, col_type)
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type};"))
                except Exception as ex:
                    logger.warning("SQLite migration note for %s.%s: %s", table, col_name, ex)

        logger.info("SQLite schema migration completed successfully.")
        return True

    return True


def seed_system_settings(db: Session) -> None:
    """
    Ensures core system settings are initialized in the database.
    """
    defaults = [
        ("app_name", "YemenScan Cyber Security Platform", "Name of the security platform"),
        ("version", "2.0.0", "Current system version"),
        ("gemini_model", "gemini-1.5-flash", "Primary Gemini AI model for assessment analysis"),
        ("max_concurrent_scans", "3", "Maximum number of parallel scan pipelines"),
        ("subdomain_concurrency", "100", "Default concurrency rate for subfinder/amass"),
        ("default_scan_mode", "full", "Default scan mode: surface, fast, full, or nuclei_only"),
    ]

    for key, val, desc in defaults:
        get_or_set_system_setting(db, key, default_value=val, description=desc)

    logger.info("System settings seeded and verified (%d entries).", len(defaults))


def init_database() -> bool:
    """
    Initializes database schema, creates tables, executes migrations,
    and seeds default configuration records.
    """
    try:
        logger.info("Connecting to database: %s", engine.url)
        logger.info("Creating base database tables if they do not exist...")

        # Base.metadata.create_all creates tables in topological order respecting foreign keys
        Base.metadata.create_all(bind=engine)

        # Non-destructive column additions
        migrate_schema()

        # Seed system settings
        with SessionLocal() as session:
            seed_system_settings(session)

        logger.info("Verified all YemenScan database tables:")
        for table_name in Base.metadata.tables.keys():
            logger.info("  - Table: %s", table_name)

        logger.info("Database initialization completed successfully.")
        return True

    except Exception as exc:
        logger.error("Failed to initialize database: %s", exc, exc_info=True)
        return False


def migrate_scans_from_disk(force: bool = False) -> Dict[str, int]:
    """
    Scans the local 'scans/' directory and ingests all historical scan sessions
    into the database.

    :param force: If True, re-ingests scans even if they already exist in ScanSessions
    :return: Summary dictionary with counts of processed records
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    scans_dir = os.path.join(base_dir, "scans")

    if not os.path.exists(scans_dir):
        logger.warning("Scans directory not found: %s", scans_dir)
        return {"scans_processed": 0, "errors": 0}

    logger.info("Scanning historical scans directory: %s", scans_dir)
    scan_entries = [
        d for d in os.listdir(scans_dir)
        if os.path.isdir(os.path.join(scans_dir, d)) and d.startswith("scan_")
    ]
    scan_entries.sort()

    logger.info("Found %d historical scan directories on disk.", len(scan_entries))

    stats = {
        "total_scans_on_disk": len(scan_entries),
        "newly_ingested": 0,
        "already_existing": 0,
        "errors": 0,
    }

    with SessionLocal() as db:
        for idx, scan_id in enumerate(scan_entries, start=1):
            session_dir = os.path.join(scans_dir, scan_id)
            try:
                # Check if session already exists
                existing = db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
                if existing and not force:
                    stats["already_existing"] += 1
                    continue

                logger.info("[%d/%d] Ingesting scan: %s", idx, len(scan_entries), scan_id)
                ingest_scan_from_directory(db, scan_id=scan_id, session_dir=session_dir)
                stats["newly_ingested"] += 1

            except Exception as exc:
                stats["errors"] += 1
                logger.error("Error ingesting scan %s: %s", scan_id, exc)

        # Print final database summary
        total_targets = db.query(Targets).count()
        total_sessions = db.query(ScanSessions).count()
        total_assets = db.query(Assets).count()
        total_catalog = db.query(VulnerabilityCatalog).count()
        total_findings = db.query(VulnerabilityFindings).count()
        total_reports = db.query(AIReports).count()

        logger.info("=" * 60)
        logger.info(" Historical Scan Ingestion Summary:")
        logger.info("  - Total on Disk:     %d", stats["total_scans_on_disk"])
        logger.info("  - Newly Ingested:    %d", stats["newly_ingested"])
        logger.info("  - Already in DB:     %d", stats["already_existing"])
        logger.info("  - Ingestion Errors:  %d", stats["errors"])
        logger.info(" Current PostgreSQL Database Totals:")
        logger.info("  - Targets:           %d", total_targets)
        logger.info("  - Scan Sessions:     %d", total_sessions)
        logger.info("  - Discovered Assets: %d", total_assets)
        logger.info("  - Vuln Catalog:      %d", total_catalog)
        logger.info("  - Findings:          %d", total_findings)
        logger.info("  - AI Reports:        %d", total_reports)
        logger.info("=" * 60)

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="YemenScan PostgreSQL Database Initializer & Migration Manager"
    )
    parser.add_argument(
        "--migrate-scans",
        action="store_true",
        help="Scan and ingest all historical scan sessions from disk into the database",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-ingestion of scan sessions even if already present",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Initialize database, apply schema migrations, and ingest all scans",
    )

    args = parser.parse_args()

    # Step 1: Initialize database & schema migrations
    success = init_database()
    if not success:
        sys.exit(1)

    # Step 2: Historical scan ingestion if requested
    if args.migrate_scans or args.all:
        migrate_scans_from_disk(force=args.force)


if __name__ == "__main__":
    main()
