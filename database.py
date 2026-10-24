"""
Database Configuration Module for YemenScan.

Configures SQLAlchemy engine, session factory, declarative base,
and provides a FastAPI dependency for database session management.
"""

import os
from typing import Generator
from dotenv import load_dotenv
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Load environment variables from .env file
load_dotenv()

# Retrieve database connection string from environment
# If DATABASE_URL is configured, use it (with automatic fallback to SQLite on failure).
# If not configured, immediately use local SQLite to avoid network latency.
RAW_DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

def _resolve_database_engine():
    global DATABASE_URL
    if RAW_DATABASE_URL:
        db_url = RAW_DATABASE_URL
    else:
        db_url = "sqlite:///yemenscan.db"

    DATABASE_URL = db_url

    c_args = {}
    engine_kwargs = {
        "echo": False,
        "pool_pre_ping": True,
    }

    if db_url.startswith("sqlite"):
        c_args["check_same_thread"] = False
        engine_kwargs["connect_args"] = c_args
    else:
        # PostgreSQL Connection Pool and Timeout configuration
        c_args["connect_timeout"] = 10
        engine_kwargs["pool_size"] = 10
        engine_kwargs["max_overflow"] = 20
        engine_kwargs["pool_recycle"] = 1800
        engine_kwargs["connect_args"] = c_args

    try:
        eng = create_engine(db_url, **engine_kwargs)
        # Test connection if PostgreSQL
        if not db_url.startswith("sqlite"):
            with eng.connect() as conn:
                pass
        return eng
    except Exception as err:
        # Fallback to SQLite if PostgreSQL engine initialization fails
        print(f"[!] Database Warning: Failed to connect to {db_url}: {err}. Falling back to SQLite.", flush=True)
        DATABASE_URL = "sqlite:///yemenscan.db"
        return create_engine(
            "sqlite:///yemenscan.db",
            echo=False,
            pool_pre_ping=True,
            connect_args={"check_same_thread": False}
        )

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable SQLite foreign key constraints for cascade deletions."""
    if dbapi_connection.__class__.__module__.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

DATABASE_URL = ""
engine = _resolve_database_engine()

# SessionLocal class factory for generating scoped sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for all ORM models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a SQLAlchemy database session.
    Ensures that the session is properly closed after each request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
