import os
from app import create_app
from app.extensions import db

app = create_app(os.getenv("FLASK_ENV", "development"))

if __name__ == "__main__":
    with app.app_context():
        # Ensure database tables are created
        db.create_all()

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "True").lower() in ("true", "1")

    # Defensive binding: default to localhost
    print(f"[*] AutoShield Pakistan starting on http://{host}:{port}")
    print("[*] Accessible Cyber Hygiene. Stronger Digital Pakistan.")
    app.run(host=host, port=port, debug=debug)
