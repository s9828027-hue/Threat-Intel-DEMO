"""
WSGI entry point for the public demo deployment (gunicorn/Render, etc).
This intentionally binds publicly - the whole point of this build is a
visitor being able to open the dashboard and click through the flow.

For a real internal deployment where the approval API should NOT be public,
use scripts/run_internal.py instead - see its docstring.
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(__import__("os").environ.get("PORT", "5000")))
