"""
Production launcher for a REAL internal deployment (not the public demo).

This preserves the original design decision: the approval API should only
be reachable from inside your own network (e.g. bound to a VPN-segment IP),
never exposed directly to the internet - unlike wsgi.py, which is used for
the public portfolio demo and binds openly on purpose.

Usage:
  set APPROVAL_API_HOST to your host's internal-only interface IP, then:
    python scripts/run_internal.py
"""

import os
import sys

from waitress import serve

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app  # noqa: E402

HOST = os.environ.get("APPROVAL_API_HOST")
PORT = int(os.environ.get("APPROVAL_API_PORT", "5000"))

if not HOST:
    print("ERROR: set APPROVAL_API_HOST to your host's internal-only interface IP")
    sys.exit(1)

if HOST in ("0.0.0.0", "*"):
    print("ERROR: APPROVAL_API_HOST must not be 0.0.0.0 - that would expose this "
          "publicly, which defeats the internal-only design of this script.")
    sys.exit(1)

app = create_app()
print(f"Starting on {HOST}:{PORT} (internal interface only)")
serve(app, host=HOST, port=PORT)
