import os

from flask import Flask


def create_app():
    app = Flask(__name__)

    from app.approval import bp as approval_bp
    from app.dashboard import bp as dashboard_bp

    app.register_blueprint(approval_bp)
    app.register_blueprint(dashboard_bp)

    if os.environ.get("THREATGATE_ENABLE_SCHEDULER", "true").lower() == "true":
        from app.scheduler import start_scheduler
        start_scheduler(app)

    return app
