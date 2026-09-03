"""
End-to-end integration tests: fetch -> dedupe/normalize -> diff -> approve ->
publish -> baseline update, wired all the way through. Unit correctness of
each module is covered elsewhere; this file is about "does the handoff
between modules actually work".

Runs entirely in a temp directory with the demo (mock) publisher; no real
network calls.

Scenarios:
1. First run: brand-new environment, full approve+publish flow.
2. Second run: baseline correctly reflects the previous run, diff only shows
   genuine changes.
3. Publish failure recovery: a simulated adapter failure must not corrupt
   state, and a retry must succeed cleanly afterwards.

Run with: pytest tests/test_integration.py
"""

import importlib
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch


class IntegrationTestBase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="threatgate_test_")

        os.environ["THREATGATE_DATA_DIR"] = self.temp_dir
        os.environ["ABUSECH_AUTH_KEY"] = "test-key"
        os.environ["OTX_API_KEY"] = "test-otx-key"
        os.environ["APPROVAL_SECRET_KEY"] = "test-secret"
        os.environ["APPROVAL_API_BASE_URL"] = "http://127.0.0.1:5000"
        os.environ["THREATGATE_DEMO_MODE"] = "true"
        os.environ["THREATGATE_ENABLE_SCHEDULER"] = "false"
        os.environ.pop("GOOGLE_CHAT_WEBHOOK_URL", None)

        import pipeline.fetch_sources as fetch_sources
        import pipeline.dedupe_normalize as dedupe_normalize
        import pipeline.diff_summary as diff_summary
        import adapters.mock_scm as mock_scm
        import app.publisher as publisher
        import app.notify as notify
        import app.approval as approval
        for mod in (fetch_sources, dedupe_normalize, diff_summary, mock_scm, publisher, notify, approval):
            importlib.reload(mod)

        self.fetch_sources = fetch_sources
        self.dedupe_normalize = dedupe_normalize
        self.diff_summary = diff_summary
        self.approval = approval

        self.sent_messages = []
        approval.send_chat_message = lambda text, to_supervisor=False: self.sent_messages.append(text)

        from app import create_app
        self.client = create_app().test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_fetch_with_mock_sources(self, feodo=None, spamhaus=None, threatfox=None, urlhaus=None, otx=None):
        """Mocks each source function directly (parsing correctness is covered by
        test_fetch_sources.py); here we only need main() to merge + write correctly."""
        with patch.object(self.fetch_sources, "fetch_feodo_tracker", return_value=feodo or []), \
             patch.object(self.fetch_sources, "fetch_spamhaus_drop", return_value=spamhaus or []), \
             patch.object(self.fetch_sources, "fetch_threatfox", return_value=threatfox or []), \
             patch.object(self.fetch_sources, "fetch_urlhaus", return_value=urlhaus or []), \
             patch.object(self.fetch_sources, "fetch_otx", return_value=otx or []):
            self.fetch_sources.run()

    def _path(self, name):
        return os.path.join(self.temp_dir, name)


def entry(indicator, type_="ip", source="ThreatFox", tier="confirmed", category="botnet_cc"):
    return {"indicator": indicator, "type": type_, "source": source,
            "category": category, "confidence_tier": tier, "first_seen": None}


class TestFirstRunFullFlow(IntegrationTestBase):

    def test_end_to_end_first_run(self):
        self.run_fetch_with_mock_sources(
            feodo=[entry("1.1.1.1", source="Feodo Tracker")],
            spamhaus=[entry("2.2.0.0/16", type_="cidr", source="Spamhaus DROP")],
            threatfox=[entry("3.3.3.3", source="ThreatFox")],
            urlhaus=[entry("4.4.4.4", source="URLhaus")],
            otx=[entry("5.5.5.5", source="AlienVault OTX")],
        )
        self.assertTrue(os.path.exists(self._path("threat_intel_raw.json")))
        with open(self._path("threat_intel_raw.json"), encoding="utf-8") as f:
            raw = json.load(f)
        self.assertEqual(raw["total"], 5)

        self.dedupe_normalize.run()
        with open(self._path("threat_intel_normalized.json"), encoding="utf-8") as f:
            normalized = json.load(f)
        self.assertEqual(len(normalized["entries"]), 5, "no duplicates, so dedupe should keep all 5")

        diff = self.diff_summary.run()
        self.assertTrue(diff["is_first_run"])
        self.assertEqual(diff["added_count"], 5)

        run_id = diff["run_id"]
        tokens = self.approval.generate_tokens_for_run(run_id, diff["added_count"])
        resp = self.client.get(f"/approve/{tokens['approve']}")
        self.assertIn("approved", resp.data.decode())
        self.assertTrue(self.sent_messages, "an approval notification should have been sent")

        state = self.approval.load_state()
        publish_token = state[run_id]["publish_token"]
        resp2 = self.client.get(f"/confirm-publish/{publish_token}")
        self.assertEqual(resp2.get_json()["published_count"], 5)

        with open(self._path("edl_blocklist.txt"), encoding="utf-8") as f:
            published = f.read().splitlines()
        self.assertEqual(len(published), 5)
        self.assertIn("1.1.1.1", published)
        self.assertIn("2.2.0.0/16", published)

        self.assertTrue(os.path.exists(self._path("baseline_active_list.json")))
        with open(self._path("baseline_active_list.json"), encoding="utf-8") as f:
            baseline = json.load(f)
        self.assertEqual(len(baseline["entries"]), 5)


class TestSecondRunDiffAccuracy(IntegrationTestBase):

    def test_diff_reflects_actual_changes(self):
        self.run_fetch_with_mock_sources(threatfox=[entry("1.1.1.1"), entry("2.2.2.2"), entry("3.3.3.3")])
        self.dedupe_normalize.run()
        diff1 = self.diff_summary.run()

        tokens1 = self.approval.generate_tokens_for_run(diff1["run_id"], diff1["added_count"])
        self.client.get(f"/approve/{tokens1['approve']}")
        state = self.approval.load_state()
        self.client.get(f"/confirm-publish/{state[diff1['run_id']]['publish_token']}")

        # round 2: 2.2.2.2 drops off, 4.4.4.4 is new, the rest is unchanged
        self.run_fetch_with_mock_sources(threatfox=[entry("1.1.1.1"), entry("3.3.3.3"), entry("4.4.4.4")])
        self.dedupe_normalize.run()
        diff2 = self.diff_summary.run()

        self.assertFalse(diff2["is_first_run"])
        self.assertEqual(diff2["added_count"], 1)
        self.assertEqual(diff2["removed_count"], 1)
        self.assertEqual(diff2["unchanged_count"], 2)

        self.assertEqual([e["indicator"] for e in diff2["added_entries"]], ["4.4.4.4"])
        self.assertEqual([e["indicator"] for e in diff2["removed_entries"]], ["2.2.2.2"])


class FakeFailingPublisher:
    """Simulates a real firewall adapter whose content write succeeds but
    whose object-confirmation call fails - e.g. an expired credential."""

    def publish_content(self):
        return 1

    def ensure_edl_object(self):
        raise RuntimeError("simulated 403 Forbidden")


class TestPublishFailureRecovery(IntegrationTestBase):

    def test_failure_does_not_corrupt_state_and_retry_succeeds(self):
        self.run_fetch_with_mock_sources(threatfox=[entry("9.9.9.9")])
        self.dedupe_normalize.run()
        diff = self.diff_summary.run()

        run_id = diff["run_id"]
        tokens = self.approval.generate_tokens_for_run(run_id, diff["added_count"])
        self.client.get(f"/approve/{tokens['approve']}")
        publish_token = self.approval.load_state()[run_id]["publish_token"]

        with patch.object(self.approval, "get_publisher", return_value=FakeFailingPublisher()):
            resp_fail = self.client.get(f"/confirm-publish/{publish_token}")
        self.assertEqual(resp_fail.status_code, 500)

        state_after_fail = self.approval.load_state()
        self.assertNotEqual(state_after_fail[run_id]["status"], "published", "a failure must not look like success")
        self.assertEqual(state_after_fail[run_id]["failure_count"], 1)
        self.assertFalse(os.path.exists(self._path("baseline_active_list.json")),
                          "baseline must not move on a failed publish")

        # retry with the real (mock) publisher restored by setUp
        resp_retry = self.client.get(f"/confirm-publish/{publish_token}")
        self.assertEqual(resp_retry.get_json()["current_status"], "published")
        self.assertTrue(os.path.exists(self._path("baseline_active_list.json")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
