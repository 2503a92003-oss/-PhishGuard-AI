import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as phishguard_app


class EmailUploadTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.db_patch = patch.object(phishguard_app, "DB_PATH", self.db_path)
        self.db_patch.start()
        phishguard_app.init_db()
        phishguard_app.app.config["TESTING"] = True
        self.client = phishguard_app.app.test_client()
        self.client.get("/")
        with self.client.session_transaction() as session:
            self.csrf = session["_csrf"]

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def upload(self, name, content):
        return self.client.post(
            "/scan",
            data={
                "_csrf": self.csrf,
                "kind": "message",
                "email_file": (io.BytesIO(content), name),
            },
            follow_redirects=True,
        )

    def test_scans_uploaded_eml_and_stores_email_kind(self):
        eml = (
            b"From: Security <security@paypa1-login.xyz>\r\n"
            b"Reply-To: attacker@example.net\r\n"
            b"Subject: URGENT: verify your account\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Your account will be suspended. Verify your password at "
            b"http://paypa1-login.xyz/login now!"
        )

        response = self.upload("sample.eml", eml)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"The email, marked up", response.data)
        self.assertIn(b"Reply-To: attacker@example.net", response.data)
        conn = sqlite3.connect(self.db_path)
        try:
            kind, content = conn.execute("SELECT kind, content FROM scans").fetchone()
        finally:
            conn.close()
        self.assertEqual(kind, "email")
        self.assertIn("paypa1-login.xyz", content)

    def test_scans_html_only_email_links(self):
        eml = (
            b"Subject: Review this notice\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body><p>Review this notice</p>"
            b"<a href='https://paypa1-login.xyz/verify'>Open</a></body></html>"
        )

        response = self.upload("sample.eml", eml)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"paypa1-login", response.data)
        self.assertIn(b"Links in this email", response.data)

    def test_rejects_non_eml_upload(self):
        response = self.upload("message.txt", b"Suspicious message")

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Choose an email file with the .eml extension.", response.data)
        conn = sqlite3.connect(self.db_path)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)
        finally:
            conn.close()

    def test_clear_history_deletes_all_scans(self):
        self.upload("sample.eml", b"Subject: Test\r\n\r\nSuspicious message")
        conn = sqlite3.connect(self.db_path)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)
        finally:
            conn.close()

        response = self.client.post(
            "/history/clear",
            data={"_csrf": self.csrf},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan history cleared.", response.data)
        conn = sqlite3.connect(self.db_path)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
