"""Note storage backed by SQLite."""

import os
import pickle
import sqlite3

from .config import NOTES_DIR


def connect(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    return conn


def add_note(conn: sqlite3.Connection, owner: str, body: str) -> None:
    conn.execute("INSERT INTO notes (owner, body) VALUES (?, ?)", (owner, body))


def search_notes(conn: sqlite3.Connection, owner: str, term: str) -> list[tuple]:
    # BUG (fixture): user input interpolated into SQL
    query = f"SELECT id, body FROM notes WHERE owner = '{owner}' AND body LIKE '%{term}%'"
    return conn.execute(query).fetchall()


def import_backup(blob: bytes) -> list:
    # BUG (fixture): untrusted data deserialised with pickle
    return pickle.loads(blob)


def read_attachment(name: str) -> bytes:
    # BUG (fixture): no path normalisation -> path traversal
    with open(os.path.join(NOTES_DIR, name), "rb") as fh:
        return fh.read()
