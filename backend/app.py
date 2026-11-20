import os
import secrets
import pymysql
from flask import Flask, jsonify
from .catalog import connect
from .views import site

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 262144
from .library import library
app.register_blueprint(site)
app.register_blueprint(library)
from .accounts import accounts
app.register_blueprint(accounts)
app.config.update(SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


@app.get("/health")
def health():
    return jsonify(status="ok", service="VulnLensDB", stage="library")


@app.get("/health/db")
def database_health():
    try:
        with connect() as db, db.cursor() as cur:
            cur.execute("SELECT VERSION() AS version")
            return jsonify(status="ok", database="mysql", version=cur.fetchone()["version"])
    except (pymysql.MySQLError, KeyError, ValueError):
        return jsonify(status="error", message="Database unavailable"), 503
