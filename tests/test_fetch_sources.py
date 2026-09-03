"""
Unit tests for pipeline/fetch_sources.py - one class per source, covering both
the happy path (well-formed data parses correctly) and the unhappy path
(malformed rows / missing keys / API errors should be skipped or raise
clearly, never crash the whole run silently).

All network calls are mocked - this file never makes a real HTTP request and
is safe to run anytime.

Run with: pytest tests/test_fetch_sources.py
"""

import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("ABUSECH_AUTH_KEY", "test-key")
os.environ.setdefault("OTX_API_KEY", "test-otx-key")

from pipeline import fetch_sources as fs  # noqa: E402


def make_response(json_data=None, text_data=None, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status.side_effect = Exception(f"HTTP {status_code} Error") if status_code >= 400 else None
    if json_data is not None:
        resp.json.return_value = json_data
    if text_data is not None:
        resp.text = text_data
    return resp


class TestFeodoTracker(unittest.TestCase):

    def test_normal_parsing(self):
        sample = "################\n# header #\n################\n# DstIP\n1.2.3.4\n5.6.7.8\n# END 2 entries"
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.return_value = make_response(text_data=sample)
            results = fs.fetch_feodo_tracker()
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["indicator"], "1.2.3.4")
        self.assertEqual(results[0]["confidence_tier"], "confirmed")

    def test_malformed_line_skipped(self):
        sample = "1.2.3.4\nnot-an-ip-address\n5.6.7.8"
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.return_value = make_response(text_data=sample)
            results = fs.fetch_feodo_tracker()
        self.assertEqual(len(results), 2, "only the 2 valid IPs should survive, garbage skipped")

    def test_http_error_raises(self):
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.return_value = make_response(text_data="", status_code=500)
            with self.assertRaises(Exception):
                fs.fetch_feodo_tracker()


class TestSpamhausDrop(unittest.TestCase):

    def test_normal_parsing(self):
        sample = "; Spamhaus DROP List\n; copyright notice\n1.10.16.0/20 ; SBL256894\n2.26.75.0/24 ; SBL698389"
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.return_value = make_response(text_data=sample)
            results = fs.fetch_spamhaus_drop()
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["indicator"], "1.10.16.0/20")
        self.assertEqual(results[0]["confidence_tier"], "confirmed")

    def test_malformed_cidr_skipped(self):
        sample = "1.10.16.0/20 ; SBL256894\nnot-a-valid-cidr ; SBLxxx\n2.26.75.0/24 ; SBL698389"
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.return_value = make_response(text_data=sample)
            results = fs.fetch_spamhaus_drop()
        self.assertEqual(len(results), 2, "malformed CIDR should be skipped, not crash")


class TestThreatFox(unittest.TestCase):

    def test_confidence_tiering(self):
        data = {"query_status": "ok", "data": [
            {"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": "TestMalware", "first_seen": "2026-01-01", "confidence_level": 90},
            {"ioc": "5.6.7.8:80", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": "TestMalware", "first_seen": "2026-01-01", "confidence_level": 40},
        ]}
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.post.return_value = make_response(json_data=data)
            results = fs.fetch_threatfox()
        self.assertEqual(results[0]["confidence_tier"], "confirmed")
        self.assertEqual(results[1]["confidence_tier"], "observation")

    def test_non_ip_type_filtered(self):
        data = {"query_status": "ok", "data": [
            {"ioc": "evil.example.com", "ioc_type": "domain", "threat_type": "x",
             "malware_printable": "x", "first_seen": None, "confidence_level": 90},
            {"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "threat_type": "x",
             "malware_printable": "x", "first_seen": None, "confidence_level": 90},
        ]}
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.post.return_value = make_response(json_data=data)
            results = fs.fetch_threatfox()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["indicator"], "1.2.3.4")

    def test_query_status_not_ok_raises(self):
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.post.return_value = make_response(json_data={"query_status": "auth_failed"})
            with self.assertRaises(RuntimeError):
                fs.fetch_threatfox()

    def test_missing_auth_key_raises(self):
        original = fs.ABUSECH_AUTH_KEY
        fs.ABUSECH_AUTH_KEY = None
        try:
            with self.assertRaises(RuntimeError):
                fs.fetch_threatfox()
        finally:
            fs.ABUSECH_AUTH_KEY = original


class TestURLhaus(unittest.TestCase):

    def test_ip_domain_classification(self):
        data = {"query_status": "ok", "urls": [
            {"host": "1.2.3.4", "threat": "malware_download", "url_status": "online", "date_added": None},
            {"host": "evil.example.com", "threat": "malware_download", "url_status": "online", "date_added": None},
        ]}
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.return_value = make_response(json_data=data)
            results = fs.fetch_urlhaus()
        types = {r["indicator"]: r["type"] for r in results}
        self.assertEqual(types["1.2.3.4"], "ip")
        self.assertEqual(types["evil.example.com"], "domain")

    def test_confidence_tier_by_status(self):
        data = {"query_status": "ok", "urls": [
            {"host": "1.2.3.4", "threat": "x", "url_status": "online", "date_added": None},
            {"host": "5.6.7.8", "threat": "x", "url_status": "offline", "date_added": None},
        ]}
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.return_value = make_response(json_data=data)
            results = fs.fetch_urlhaus()
        tiers = {r["indicator"]: r["confidence_tier"] for r in results}
        self.assertEqual(tiers["1.2.3.4"], "confirmed")
        self.assertEqual(tiers["5.6.7.8"], "observation")

    def test_empty_host_skipped(self):
        data = {"query_status": "ok", "urls": [{"host": "", "threat": "x", "url_status": "online", "date_added": None}]}
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.return_value = make_response(json_data=data)
            results = fs.fetch_urlhaus()
        self.assertEqual(len(results), 0)


class TestOTX(unittest.TestCase):

    def test_ip_type_filtering_and_pagination(self):
        page1 = {"results": [{"name": "Pulse A", "indicators": [
            {"type": "IPv4", "indicator": "1.2.3.4", "created": None},
            {"type": "domain", "indicator": "evil.com", "created": None},
        ]}], "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2"}
        page2 = {"results": [{"name": "Pulse B", "indicators": [
            {"type": "IPv4", "indicator": "5.6.7.8", "created": None},
        ]}], "next": None}
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.side_effect = [make_response(json_data=page1), make_response(json_data=page2)]
            results = fs.fetch_otx()
        indicators = [r["indicator"] for r in results]
        self.assertEqual(len(results), 2, "should collect across both pages and drop the domain entry")
        self.assertIn("1.2.3.4", indicators)
        self.assertIn("5.6.7.8", indicators)
        self.assertNotIn("evil.com", indicators)

    def test_missing_api_key_raises(self):
        original = fs.OTX_API_KEY
        fs.OTX_API_KEY = None
        try:
            with self.assertRaises(RuntimeError):
                fs.fetch_otx()
        finally:
            fs.OTX_API_KEY = original

    def test_max_pages_limit(self):
        def infinite_page(*args, **kwargs):
            return make_response(json_data={
                "results": [], "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?page=999",
            })
        with patch.object(fs, "requests") as mock_requests:
            mock_requests.get.side_effect = infinite_page
            results = fs.fetch_otx()  # must not hang forever
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
