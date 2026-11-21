import os
from pathlib import Path
from flask import Flask, render_template
from sqlalchemy import event
from sqlalchemy.engine import Engine

from config import config_by_name
from app.extensions import db, login_manager, csrf
from app.models.user import User


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable SQLite WAL mode and busy timeout for concurrent safety."""
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:
        pass


def create_app(config_name: str | None = None) -> Flask:
    """Application factory for AutoShield Pakistan."""
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name["development"]))

    # Ensure required directories exist
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config.get("EXPORTS_DIR", Path(app.instance_path) / "exports"), exist_ok=True)
    os.makedirs(app.config.get("RULES_DIR", Path(app.root_path).parent / "rules"), exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        return db.session.get(User, int(user_id))

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template("errors/403.html"), 403

    # Context processors
    @app.context_processor
    def inject_app_metadata():
        return {
            "app_name": "AutoShield Pakistan",
            "app_tagline": "Accessible Cyber Hygiene. Stronger Digital Pakistan.",
            "app_version": "1.0.0-beta",
        }

    return app
