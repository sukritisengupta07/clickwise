"""Tests for the CSV report and the Flask routes (using Flask's built-in test client, no real network)."""

import csv
import io
import unittest

from app import app
from detector import analyze_url
from report import build_csv, csv_safe


class TestCsvSafety(unittest.TestCase):
    def test_formula_characters_are_neutralised(self):
        for text in ("=1+1", "+cmd", "-2+3", "@SUM(A1)"):
            self.assertTrue(csv_safe(text).startswith("'"), text)

    def test_normal_text_unchanged(self):
        self.assertEqual(csv_safe("https://example.com"), "https://example.com")

    def test_report_has_header_and_one_row(self):
        text = build_csv(analyze_url("http://203.0.113.5/login"))
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(len(rows), 2)
        self.assertIn("Risk score (0-100)", rows[0])

    def test_no_indicators_message_does_not_claim_safe(self):
        text = build_csv(analyze_url("https://www.example.com/"))
        self.assertIn("No configured warning indicators detected", text)
        self.assertNotIn("is safe", text.replace("Not a verdict on whether the site is safe", ""))


class TestRoutes(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_page_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan URL", response.data)

    def test_scan_shows_score_and_category(self):
        response = self.client.post("/scan", data={"url": "http://203.0.113.5/secure/login"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Medium Risk", response.data)

    def test_submitted_url_is_escaped(self):
        # a script tag inside the URL must be shown as text, never run
        response = self.client.post("/scan", data={"url": "https://www.example.com/<script>alert(1)</script>"})
        self.assertNotIn(b"<script>alert(1)</script>", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)

    def test_invalid_input_shows_error_not_crash(self):
        response = self.client.post("/scan", data={"url": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Please enter a URL", response.data)

    def test_download_returns_csv(self):
        response = self.client.post("/download", data={"url": "http://203.0.113.5/login"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_debug_mode_is_off(self):
        self.assertFalse(app.debug)


if __name__ == "__main__":
    unittest.main()
