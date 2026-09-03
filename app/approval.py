"""
ThreatGate - Approval Engine
核准／拒絕核心邏輯 + 發布確認關卡

This is the heart of the project: a stateless, signed-link approval flow
that turns "review a diff and click approve" into something that needs no
login system of its own.

Flow:
1. After a pipeline run produces a diff, generate_tokens_for_run() creates a
   signed approve/reject link pair for the "requester" (the person who owns
   this pipeline).
2. On approve:
   - added_count <= ESCALATION_THRESHOLD -> straight to "approved".
   - added_count >  ESCALATION_THRESHOLD -> "pending supervisor review", and
     a fresh approve/reject link pair is minted for a "supervisor" role.
3. Supervisor approval finalizes the run as "approved (supervisor-reviewed)".
4. Either role rejecting shows a short reason form first; only submitting it
   actually finalizes the rejection. A supervisor rejection notifies the
   requester (with the reason); a requester's own rejection doesn't notify
   itself.
5. The moment a run reaches any "approved" state, a separate one-time
   "confirm publish" link is minted. Approval and publish are intentionally
   two different actions - a burst of noisy new indicators shouldn't reach
   the firewall automatically just because someone clicked approve.
6. Clicking "confirm publish" is the only thing that actually calls the
   publisher adapter (mock or real SCM) and advances the baseline.

Security:
- Tokens are HMAC-signed (tamper-evident: can't swap run_id or forge a role).
- Tokens expire (default 24h).
- The signing key (APPROVAL_SECRET_KEY) is read from the environment only.
- confirm-publish re-checks server-side state even if the token itself is
  valid, so a leaked publish link alone can never skip the approval step.
"""

import base64
import hashlib
import hmac
import json
import os
import time

from flask import Blueprint, jsonify, request

from app.notify import send_chat_message
from app.publisher import get_publisher
from pipeline.diff_summary import promote_baseline

bp = Blueprint("approval", __name__)

SECRET_KEY = os.environ.get("APPROVAL_SECRET_KEY", "").encode()
TOKEN_VALID_HOURS = 24
ESCALATION_THRESHOLD = int(os.environ.get("ESCALATION_THRESHOLD", "500"))

DATA_DIR = os.environ.get("THREATGATE_DATA_DIR", "data")
STATE_FILE = os.path.join(DATA_DIR, "approval_state.json")
EDL_CONTENT_FILE = os.path.join(DATA_DIR, "edl_blocklist.txt")
NORMALIZED_FILE = os.path.join(DATA_DIR, "threat_intel_normalized.json")

FULLY_APPROVED_STATUSES = {"approved", "approved (supervisor-reviewed)"}

APPROVAL_API_BASE_URL = os.environ.get("APPROVAL_API_BASE_URL", "http://127.0.0.1:5000")


# ---------- token generation & verification ----------

def _sign(payload_bytes: bytes) -> str:
    if not SECRET_KEY:
        raise RuntimeError("APPROVAL_SECRET_KEY is not set")
    sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def generate_token(run_id: str, role: str, action: str, added_count: int) -> str:
    """role: 'requester' or 'supervisor'. action: 'approve' / 'reject' / 'publish'."""
    payload = {
        "run_id": run_id,
        "role": role,
        "action": action,
        "added_count": added_count,
        "exp": int(time.time()) + TOKEN_VALID_HOURS * 3600,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
    sig = _sign(payload_b64.encode())
    return f"{payload_b64}.{sig}"


def verify_token(token: str) -> dict:
    try:
        payload_b64, sig = token.split(".", 1)
    except ValueError:
        raise ValueError("Malformed token")

    expected_sig = _sign(payload_b64.encode())
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("Signature mismatch - token may have been tampered with")

    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))

    if payload["exp"] < int(time.time()):
        raise ValueError("Token has expired")

    return payload


def generate_tokens_for_run(run_id: str, added_count: int) -> dict:
    return {
        "approve": generate_token(run_id, "requester", "approve", added_count),
        "reject": generate_token(run_id, "requester", "reject", added_count),
    }


def record_new_run(run_id: str, diff: dict, tokens: dict):
    """Called right after a pipeline run produces a diff, before anyone has
    clicked anything. Makes the run show up on the dashboard immediately as
    'awaiting review' with clickable links, instead of only appearing once a
    decision has been recorded."""
    state = load_state()
    if run_id in state:
        return state[run_id]

    entry = {
        "run_id": run_id,
        "status": "awaiting review",
        "created_at": int(time.time()),
        "history": [],
        "diff": {
            "generated_at": diff.get("generated_at"),
            "is_first_run": diff.get("is_first_run"),
            "baseline_count": diff.get("baseline_count"),
            "today_count": diff.get("today_count"),
            "added_count": diff.get("added_count"),
            "removed_count": diff.get("removed_count"),
            "unchanged_count": diff.get("unchanged_count"),
            "is_anomaly": diff.get("is_anomaly"),
            "anomaly_reason": diff.get("anomaly_reason"),
            "added_preview": diff.get("added_entries", [])[:10],
        },
        "requester_tokens": tokens,
    }
    state[run_id] = entry
    save_state(state)
    return entry


# ---------- state persistence ----------

def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def record_decision(run_id, role, action, added_count, reason=None):
    state = load_state()
    entry = state.get(run_id, {"run_id": run_id, "status": "pending", "history": []})

    entry["history"].append({"role": role, "action": action, "reason": reason, "at": int(time.time())})

    if action == "reject":
        entry["status"] = "rejected"
        entry["reject_reason"] = reason
        entry["rejected_by"] = role
        if role == "supervisor":
            send_chat_message(
                f"❌ Supervisor rejected run {run_id}\nReason: {reason}\n"
                f"This run is stopped and will not be published."
            )
    elif role == "requester" and action == "approve":
        if added_count > ESCALATION_THRESHOLD:
            entry["status"] = "pending supervisor review"
            entry["escalation_tokens"] = {
                "approve": generate_token(run_id, "supervisor", "approve", added_count),
                "reject": generate_token(run_id, "supervisor", "reject", added_count),
            }
        else:
            entry["status"] = "approved"
    elif role == "supervisor" and action == "approve":
        entry["status"] = "approved (supervisor-reviewed)"

    if entry["status"] in FULLY_APPROVED_STATUSES and "publish_token" not in entry:
        publish_token = generate_token(run_id, "requester", "publish", added_count)
        entry["publish_token"] = publish_token
        entry["approved_at"] = int(time.time())
        publish_url = f"{APPROVAL_API_BASE_URL}/confirm-publish/{publish_token}"
        send_chat_message(
            f"✅ Run {run_id} approved ({added_count} added), not yet published.\n"
            f"<{publish_url}|👉 Confirm publish>"
        )

    state[run_id] = entry
    save_state(state)
    return entry


# ---------- helpers ----------

def _check_state_guard(payload):
    """Returns None if OK to proceed, or an error string if this link is now stale."""
    state = load_state()
    existing = state.get(payload["run_id"])
    if not existing:
        return None

    current_status = existing["status"]
    role = payload["role"]

    if current_status in ("rejected", "published"):
        return f"This run is already finalized ({current_status})"

    if current_status == "pending supervisor review" and role == "requester":
        return "Escalated to supervisor review - the requester can no longer act on this link"

    if current_status in FULLY_APPROVED_STATUSES and role == "requester" and payload["action"] == "reject":
        return "This run is already approved - it can't be rejected from this link anymore"

    return None


def _simple_page(title, message, is_error=False):
    color = "#C00000" if is_error else "#1F4E5A"
    return f"""
    <html><head><meta charset="utf-8"><title>{title}</title></head>
    <body style="font-family:system-ui,sans-serif;max-width:480px;margin:60px auto;text-align:center;">
    <h2 style="color:{color};">{title}</h2>
    <p style="font-size:16px;color:#333;white-space:pre-line;">{message}</p>
    <p><a href="{APPROVAL_API_BASE_URL}/">&larr; Back to dashboard</a></p>
    </body></html>
    """


# ---------- routes ----------

@bp.route("/approve/<token>")
def approve(token):
    return _handle(token, "approve")


def _handle(token, expected_action):
    try:
        payload = verify_token(token)
    except ValueError as e:
        return _simple_page("Invalid link", str(e), is_error=True), 400

    if payload["action"] != expected_action:
        return _simple_page("Wrong link", "Token doesn't match this action", is_error=True), 400

    guard_error = _check_state_guard(payload)
    if guard_error:
        return _simple_page("Can't proceed", guard_error, is_error=True), 409

    entry = record_decision(
        run_id=payload["run_id"], role=payload["role"], action=payload["action"],
        added_count=payload["added_count"],
    )

    return _simple_page(
        "Recorded",
        f"run_id: {payload['run_id']}\nrole: {payload['role']}\ncurrent status: {entry['status']}",
    )


@bp.route("/reject/<token>", methods=["GET"])
def reject_form(token):
    try:
        payload = verify_token(token)
    except ValueError as e:
        return _simple_page("Invalid link", str(e), is_error=True), 400

    if payload["action"] != "reject":
        return _simple_page("Wrong link", "Token doesn't match this action", is_error=True), 400

    guard_error = _check_state_guard(payload)
    if guard_error:
        return _simple_page("Can't reject", guard_error, is_error=True), 409

    return f"""
    <html><head><meta charset="utf-8"><title>Reject run {payload['run_id']}</title></head>
    <body style="font-family:system-ui,sans-serif;max-width:480px;margin:60px auto;">
    <h2 style="color:#C00000;">Reject run {payload['run_id']}</h2>
    <p>Please give a reason - it will be shared with the requester/reviewer:</p>
    <form method="POST" action="/reject/{token}">
        <textarea name="reason" rows="4" style="width:100%;font-size:14px;padding:8px;"
            placeholder="e.g. source reliability in question, needs verification..." required></textarea>
        <br><br>
        <button type="submit" style="background:#C00000;color:white;border:none;
            padding:10px 24px;font-size:15px;border-radius:4px;cursor:pointer;">Confirm rejection</button>
    </form>
    </body></html>
    """


@bp.route("/reject/<token>", methods=["POST"])
def reject_submit(token):
    try:
        payload = verify_token(token)
    except ValueError as e:
        return _simple_page("Invalid link", str(e), is_error=True), 400

    if payload["action"] != "reject":
        return _simple_page("Wrong link", "Token doesn't match this action", is_error=True), 400

    guard_error = _check_state_guard(payload)
    if guard_error:
        return _simple_page("Can't reject", guard_error, is_error=True), 409

    reason = request.form.get("reason", "").strip()
    if not reason:
        return _simple_page("Reason required", "Please go back and fill in a reason", is_error=True), 400

    entry = record_decision(
        run_id=payload["run_id"], role=payload["role"], action="reject",
        added_count=payload["added_count"], reason=reason,
    )

    return _simple_page("Rejection recorded", f"Status: {entry['status']}")


@bp.route("/confirm-publish/<token>")
def confirm_publish(token):
    try:
        payload = verify_token(token)
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400

    if payload["action"] != "publish":
        return jsonify({"status": "error", "message": "Token doesn't match this action"}), 400

    run_id = payload["run_id"]
    state = load_state()
    entry = state.get(run_id)

    if entry and entry["status"] == "published":
        return jsonify({"status": "ok", "message": "Already published previously - not repeating", "run_id": run_id})

    # Re-check server-side state even though the token itself is valid, so a
    # leaked publish link alone can never bypass the approval step.
    if not entry or entry["status"] not in FULLY_APPROVED_STATUSES:
        return jsonify({
            "status": "error",
            "message": f"run_id not fully approved yet (current: {entry['status'] if entry else 'not found'})"
        }), 400

    publisher = get_publisher()
    try:
        published_count = publisher.publish_content()
        publisher.ensure_edl_object()
    except Exception as e:
        entry["failure_count"] = entry.get("failure_count", 0) + 1
        entry["last_failure_at"] = int(time.time())
        entry["last_failure_reason"] = str(e)
        state[run_id] = entry
        save_state(state)

        send_chat_message(
            f"❌ Publish failed for run {run_id}\nReason: {e}\n"
            f"This is failure #{entry['failure_count']}, status is still '{entry['status']}'."
        )
        return jsonify({"status": "error", "message": f"Publish failed: {e}"}), 500

    entry["status"] = "published"
    entry["published_count"] = published_count
    entry["published_at"] = int(time.time())
    state[run_id] = entry
    save_state(state)

    try:
        with open(NORMALIZED_FILE, "r", encoding="utf-8") as f:
            normalized_entries = json.load(f).get("entries", [])
        promote_baseline(normalized_entries)
    except Exception as e:
        send_chat_message(f"⚠️ Published, but baseline update failed: {e}\nPlease check data/baseline_active_list.json")

    send_chat_message(f"✅ Run {run_id} published - {published_count} entries now live.")

    return jsonify({
        "status": "ok", "run_id": run_id, "current_status": entry["status"],
        "published_count": published_count,
    })


@bp.route("/edl/blocklist.txt")
def edl_blocklist():
    """What the firewall/SCM EDL object polls. No app-layer auth here on purpose -
    matches standard EDL hosting practice; access control is a network-layer concern."""
    try:
        with open(EDL_CONTENT_FILE, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        content = ""

    from flask import current_app
    return current_app.response_class(content, mimetype="text/plain")
