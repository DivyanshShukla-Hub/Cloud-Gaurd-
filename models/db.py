import os
import sqlite3
from flask import g, current_app

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    schema_path = os.path.join(current_app.root_path, "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        db.executescript(f.read())

def log_audit(user_id, action, target):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (user_id, action, target) VALUES (?, ?, ?)",
            (user_id, action, target),
        )
        db.commit()
    except Exception as e:
        print(f"Audit log error: {e}")
