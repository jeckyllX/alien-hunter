"""
Unit tests for SignatureSyncEngine.
Tests privacy guarantees, conditional HTTP caching (ETag / 304), schema validation, and atomic writes.
"""

import json
import os
import shutil
import tempfile
import unittest
import urllib.error
from unittest.mock import patch, MagicMock

from alien_hunter.identifiers.sync import SignatureSyncEngine


class TestSignatureSyncEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_sig_sync_")
        self.target_file = os.path.join(self.test_dir, "signatures.json")
        self.engine = SignatureSyncEngine(
            feed_url="https://example.com/signatures.json",
            target_path=self.target_file,
        )

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_schema_validation(self):
        """Verifies signature payload validation logic."""
        # Valid payload
        valid = {
            "version": "1.0.1",
            "dhcp_signatures": [{"vendor": "Test", "category": "Phone", "param_list": [1, 2, 3]}] * 5,
            "mdns_signatures": {"_test._tcp": {"vendor": "Test", "category": "IoT"}},
        }
        ok, _ = SignatureSyncEngine.validate_signatures_data(valid)
        self.assertTrue(ok)

        # Missing dhcp_signatures
        ok, reason = SignatureSyncEngine.validate_signatures_data({"mdns_signatures": {}})
        self.assertFalse(ok)

        # Fewer than 5 signatures
        few = {
            "dhcp_signatures": [{"vendor": "Test", "param_list": [1]}],
            "mdns_signatures": {},
        }
        ok, reason = SignatureSyncEngine.validate_signatures_data(few)
        self.assertFalse(ok)

    @patch("urllib.request.urlopen")
    def test_sync_success_http_200(self, mock_urlopen):
        """Tests successful signature download, atomic write, and metadata update."""
        valid_payload = {
            "version": "1.1.0",
            "dhcp_signatures": [{"vendor": f"Vendor {i}", "category": "Smartphone", "param_list": [1, 3, 6, i]} for i in range(10)],
            "mdns_signatures": {"_cast._tcp": {"vendor": "Google", "category": "Smart TV"}},
        }
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"ETag": '"etag-12345"', "Last-Modified": "Mon, 28 Sep 2026 23:00:00 GMT"}
        mock_resp.read.return_value = json.dumps(valid_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        success, msg = self.engine.sync(force=True)

        self.assertTrue(success)
        self.assertIn("Successfully synchronized", msg)
        self.assertTrue(os.path.exists(self.target_file))

        # Verify saved data on disk
        with open(self.target_file, "r") as f:
            saved = json.load(f)
        self.assertEqual(saved["version"], "1.1.0")

        # Verify metadata
        meta = self.engine.load_metadata()
        self.assertEqual(meta.get("etag"), '"etag-12345"')

    @patch("urllib.request.urlopen")
    def test_sync_http_304_not_modified(self, mock_urlopen):
        """Tests HTTP 304 handling with zero payload transfer."""
        err = urllib.error.HTTPError(
            url="https://example.com/signatures.json",
            code=304,
            msg="Not Modified",
            hdrs={},
            fp=None,
        )
        mock_urlopen.side_effect = err

        success, msg = self.engine.sync(force=True)
        self.assertTrue(success)
        self.assertIn("304 Not Modified", msg)

    @patch("urllib.request.urlopen")
    def test_sync_network_error(self, mock_urlopen):
        """Tests graceful handling when remote server is unreachable."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        success, msg = self.engine.sync(force=True)
        self.assertFalse(success)
        self.assertIn("Network error", msg)

    def test_privacy_headers(self):
        """Verifies no identifying local information is sent in request headers."""
        meta = {"etag": '"abc"', "last_modified": "Mon, 28 Sep 2026"}
        self.engine.save_metadata(meta)

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = {}
            mock_resp.read.return_value = json.dumps({
                "dhcp_signatures": [{"vendor": "X", "param_list": [1]}] * 5,
                "mdns_signatures": {},
            }).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp

            self.engine.sync(force=True)

            req = mock_urlopen.call_args[0][0]
            # Ensure standard headers only
            self.assertIn("AlienHunterSentinel", req.headers["User-agent"])
            self.assertEqual(req.headers["If-none-match"], '"abc"')
            # Verify no query string or local parameters exist
            self.assertNotIn("ip=", req.full_url)
            self.assertNotIn("mac=", req.full_url)


if __name__ == "__main__":
    unittest.main()
