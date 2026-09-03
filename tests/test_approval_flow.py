"""
Tests for app/approval.py: approve, reject, timeout (expired token), and the
state-transition guards that stop a stale link from overwriting a decision
that's already final.

Runs entirely against a temp directory and the demo (mock) publisher - no
real network calls, safe to run anytime.

Run with: pytest tests/test_approval_flow.py
"""

import base64
import importlib
import json
import os
import shutil
import tempfile
import time
import unittest


class ApprovalTestBase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="threatgate_test_")

        os.environ["THREATGATE_DATA_DIR"] = self.temp_dir
        os.environ["APPROVAL_SECRET_KEY"] = "test-secret"
        os.environ["APPROVAL_API_BASE_URL"] = "http://127.0.0.1:5000"
        os.environ["THREATGATE_DEMO_MODE"] = "true"
        os.environ["THREATGATE_ENABLE_SCHEDULER"] = "false"
        os.environ.pop("GOOGLE_CHAT_WEBHOOK_URL", None)

        with open(os.path.join(self.temp_dir, "threat_intel_normalized.json"), "w", encoding="utf-8") as f:
            json.dump({"entries": [{"indicator": "1.2.3.4", "type": "ip", "sources": ["A"], "categories": []}]}, f)

        import pipeline.diff_summary as diff_summary
        import adapters.mock_scm as mock_scm
        import app.publisher as publisher
        import app.approval as approval
        for mod in (diff_summary, mock_scm, publisher, approval):
            importlib.reload(mod)

        self.sent_messages = []
        approval.send_chat_message = lambda text, to_supervisor=False: self.sent_messages.append(text)

        from app import create_app
        flask_app = create_app()
        self.client = flask_app.test_client()
        self.approval = approval

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)


class TestRejectFlow(ApprovalTestBase):

    def test_reject_form_is_shown_first(self):
        tokens = self.approval.generate_tokens_for_run("run-reject-000", added_count=10)
        resp = self.client.get(f"/reject/{tokens['reject']}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"reason", resp.data)

        state = self.approval.load_state()
        self.assertNotIn("run-reject-000", state, "viewing the form must not itself record a rejection")

    def test_reject_requires_reason(self):
        tokens = self.approval.generate_tokens_for_run("run-reject-noreason", added_count=10)
        resp = self.client.post(f"/reject/{tokens['reject']}", data={"reason": ""})
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn("run-reject-noreason", self.approval.load_state())

    def test_requester_reject_with_reason(self):
        tokens = self.approval.generate_tokens_for_run("run-reject-001", added_count=10)
        resp = self.client.post(f"/reject/{tokens['reject']}", data={"reason": "source reliability in question"})
        self.assertEqual(resp.status_code, 200)

        entry = self.approval.load_state()["run-reject-001"]
        self.assertEqual(entry["status"], "rejected")
        self.assertEqual(entry["reject_reason"], "source reliability in question")
        self.assertNotIn("publish_token", entry, "a rejected run must never get a publish token")

    def test_requester_reject_does_not_notify(self):
        tokens = self.approval.generate_tokens_for_run("run-reject-002", added_count=10)
        self.client.post(f"/reject/{tokens['reject']}", data={"reason": "test reason"})
        self.assertFalse(
            any("Supervisor rejected" in m for m in self.sent_messages),
            "a requester rejecting their own run should not trigger the supervisor-rejection notice",
        )


class TestEscalationFlow(ApprovalTestBase):
    """Runs with a large added_count all the way through supervisor review to publish-readiness."""

    def test_full_escalation_to_publish(self):
        tokens = self.approval.generate_tokens_for_run("run-esc-001", added_count=600)
        resp = self.client.get(f"/approve/{tokens['approve']}")
        self.assertIn("pending supervisor review", resp.data.decode())

        entry = self.approval.load_state()["run-esc-001"]
        self.assertIn("escalation_tokens", entry)
        self.assertNotIn("publish_token", entry, "no publish token until the supervisor has acted")

        supervisor_approve_token = entry["escalation_tokens"]["approve"]
        resp2 = self.client.get(f"/approve/{supervisor_approve_token}")
        self.assertIn("approved (supervisor-reviewed)", resp2.data.decode())

        entry2 = self.approval.load_state()["run-esc-001"]
        self.assertIn("publish_token", entry2, "supervisor approval should mint a publish token")
        self.assertTrue(any("approved" in m for m in self.sent_messages))

    def test_supervisor_reject_notifies_requester_with_reason(self):
        tokens = self.approval.generate_tokens_for_run("run-esc-002", added_count=600)
        self.client.get(f"/approve/{tokens['approve']}")
        entry = self.approval.load_state()["run-esc-002"]
        supervisor_reject_token = entry["escalation_tokens"]["reject"]

        resp = self.client.post(f"/reject/{supervisor_reject_token}", data={"reason": "spike is too large, holding off"})
        self.assertEqual(resp.status_code, 200)

        entry2 = self.approval.load_state()["run-esc-002"]
        self.assertEqual(entry2["status"], "rejected")
        self.assertEqual(entry2["reject_reason"], "spike is too large, holding off")
        self.assertEqual(entry2["rejected_by"], "supervisor")

        notified = [m for m in self.sent_messages if "Supervisor rejected" in m]
        self.assertEqual(len(notified), 1, "a supervisor rejection should actively notify the requester")
        self.assertIn("spike is too large, holding off", notified[0])


class TestTokenExpiry(ApprovalTestBase):

    def _make_expired_token(self, run_id, role, action, added_count):
        token = self.approval.generate_token(run_id, role, action, added_count)
        payload_b64, _ = token.split(".", 1)
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        payload["exp"] = int(time.time()) - 100
        new_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        new_b64 = base64.urlsafe_b64encode(new_json.encode()).decode().rstrip("=")
        new_sig = self.approval._sign(new_b64.encode())
        return f"{new_b64}.{new_sig}"

    def test_expired_approve_token_rejected(self):
        expired = self._make_expired_token("run-exp-001", "requester", "approve", 10)
        resp = self.client.get(f"/approve/{expired}")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("expired", resp.data.decode())

    def test_expired_publish_token_rejected(self):
        expired = self._make_expired_token("run-exp-002", "requester", "publish", 10)
        resp = self.client.get(f"/confirm-publish/{expired}")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("expired", resp.get_json()["message"])


class TestStateTransitionGuards(ApprovalTestBase):
    """
    Guards against a stale link overwriting a decision that's already final -
    the reason record_decision() checks current state before acting at all.
    """

    def test_cannot_re_approve_after_rejected(self):
        tokens = self.approval.generate_tokens_for_run("run-guard-001", added_count=10)
        self.client.post(f"/reject/{tokens['reject']}", data={"reason": "test rejection"})

        resp = self.client.get(f"/approve/{tokens['approve']}")
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(self.approval.load_state()["run-guard-001"]["status"], "rejected")

    def test_cannot_re_trigger_escalation_with_new_tokens(self):
        tokens = self.approval.generate_tokens_for_run("run-guard-002", added_count=600)
        self.client.get(f"/approve/{tokens['approve']}")
        original_supervisor_token = self.approval.load_state()["run-guard-002"]["escalation_tokens"]["approve"]

        resp = self.client.get(f"/approve/{tokens['approve']}")
        self.assertEqual(resp.status_code, 409)

        self.assertEqual(
            self.approval.load_state()["run-guard-002"]["escalation_tokens"]["approve"],
            original_supervisor_token,
            "the supervisor's link must not be silently invalidated by a re-click",
        )

    def test_cannot_publish_twice_via_confirm_publish(self):
        tokens = self.approval.generate_tokens_for_run("run-guard-003", added_count=10)
        self.client.get(f"/approve/{tokens['approve']}")
        publish_token = self.approval.load_state()["run-guard-003"]["publish_token"]
        self.client.get(f"/confirm-publish/{publish_token}")

        resp = self.client.get(f"/reject/{tokens['reject']}")
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(self.approval.load_state()["run-guard-003"]["status"], "published")


if __name__ == "__main__":
    unittest.main(verbosity=2)
