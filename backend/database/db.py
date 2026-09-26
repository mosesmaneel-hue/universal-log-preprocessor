import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Database configuration:
# Production uses logs_production.db by default.
# Development can use logs.db via APP_ENV="development" / ENV="dev" or LOGS_DB_PATH.
PROD_DB_PATH = os.path.join(BASE_DIR, "logs_production.db")
DEV_DB_PATH = os.path.join(BASE_DIR, "logs.db")

APP_ENV = (
    os.getenv("APP_ENV") or os.getenv("ENV") or os.getenv("ENVIRONMENT") or "production"
).lower()
DEFAULT_DB_PATH = DEV_DB_PATH if APP_ENV in ("dev", "development") else PROD_DB_PATH
DATABASE_NAME = os.getenv("LOGS_DB_PATH", DEFAULT_DB_PATH)


def get_connection():
    db_path = os.getenv("LOGS_DB_PATH", DATABASE_NAME)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS quarantine_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quarantine_id TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            detection TEXT,
            validation TEXT,
            normalized TEXT,
            raw_log TEXT NOT NULL,
            review_status TEXT DEFAULT 'PENDING',
            reviewed_at TIMESTAMP DEFAULT NULL,
            resolution_notes TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processed_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            source_format TEXT,
            parser TEXT,
            parsed_data TEXT,
            normalized_data TEXT,
            raw_log TEXT NOT NULL,
            severity_level TEXT DEFAULT 'CLEAN',
            severity_score INTEGER DEFAULT 0,
            severity_reason TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_severity ON processed_logs(severity_level)")

    connection.commit()
    connection.close()
