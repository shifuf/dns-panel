"""Database transactions release connections on every exit path."""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


class DatabaseConnectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / "transactions.db"
        self.db_patch = patch.object(app, "DB", self.db)
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        with sqlite3.connect(self.db) as connection:
            connection.execute("CREATE TABLE entries (value TEXT)")
        connection.close()

    def values(self):
        connection = sqlite3.connect(self.db)
        try:
            return connection.execute("SELECT value FROM entries").fetchall()
        finally:
            connection.close()

    def test_success_commits_and_closes_connection(self):
        with app.conn() as connection:
            connection.execute("INSERT INTO entries VALUES ('saved')")
        self.addCleanup(connection.close)
        self.assertEqual(self.values(), [("saved",)])
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

    def test_exception_rolls_back_and_closes_connection(self):
        with self.assertRaisesRegex(ValueError, "aborted"):
            with app.conn() as connection:
                connection.execute("INSERT INTO entries VALUES ('discarded')")
                raise ValueError("aborted")
        self.addCleanup(connection.close)
        self.assertEqual(self.values(), [])
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

    def test_failed_commit_also_closes_connection(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with app.conn() as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
                connection.execute("CREATE TABLE child (id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)")
                connection.execute("INSERT INTO child VALUES (42)")
        self.addCleanup(connection.close)
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
