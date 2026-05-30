import sqlite3

conn = sqlite3.connect(
    "credentials.db",
    check_same_thread=False
)

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    credential_type TEXT,
    name TEXT,
    surname TEXT,
    date_of_birth TEXT,
    document_id TEXT,
    expiry TEXT,
    issued_at TEXT,
    signature TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS revoked (
    credential_id TEXT PRIMARY KEY
)
""")

conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS presentations (
    presentation_id TEXT PRIMARY KEY,
    credential_id TEXT,
    shared_claims TEXT,
    created_at TEXT,
    signature TEXT
)
""")

conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS verification_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id TEXT,
    verification_time TEXT,
    result TEXT
)
""")

conn.commit()