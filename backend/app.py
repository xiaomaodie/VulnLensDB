import pymysql
from flask import Flask, jsonify
from .catalog import connect
from .views import site

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16384
app.register_blueprint(site)


@app.get("/health")
def health():
    return jsonify(status="ok", service="VulnLensDB", stage="catalog")


@app.get("/health/db")
def database_health():
    try:
        with connect() as db, db.cursor() as cur:
            cur.execute("SELECT VERSION() AS version")
            return jsonify(status="ok", database="mysql", version=cur.fetchone()["version"])
    except (pymysql.MySQLError, KeyError, ValueError):
        return jsonify(status="error", message="Database unavailable"), 503
