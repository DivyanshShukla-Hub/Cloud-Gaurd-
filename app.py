import os
import socket
from flask import Flask, render_template, flash, redirect, url_for
from config import Config
from models.db import init_db, close_db
from routes.auth import auth_bp
from routes.scans import scans_bp
from routes.analytics import analytics_bp
from routes.admin import admin_bp
from seed_rules import seed_database
from werkzeug.serving import BaseWSGIServer, WSGIRequestHandler

class DualStackServer(BaseWSGIServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        super().server_bind()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    app.teardown_appcontext(close_db)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(admin_bp)

    @app.errorhandler(413)
    def request_entity_too_large(e):
        flash("The uploaded file exceeds the 1MB limit. Please upload a smaller file.", "danger")
        return redirect(url_for("scans.upload"))

    with app.app_context():
        init_db()
        db_path = app.config["DATABASE"]
        seed_database(db_path)

    return app

app = create_app()

def run_server(port=5000):
    print("==================================================")
    print(" CloudGuard — Azure Cloud Misconfiguration Checker")
    print(f" Local URL:       http://localhost:{port}/")
    print(f" Loopback IP:     http://127.0.0.1:{port}/")
    print(" Default Admin:   admin@cloudguard.com / Admin@123")
    print("==================================================")
    try:
        server = DualStackServer("::", port, app, handler=WSGIRequestHandler)
        server.serve_forever()
    except Exception as e:
        print(f"Notice: Dual-stack unavailable ({e}). Falling back to 127.0.0.1...")
        app.run(host="127.0.0.1", port=port, debug=False)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    run_server(port)