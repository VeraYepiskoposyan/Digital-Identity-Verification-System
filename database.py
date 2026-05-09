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