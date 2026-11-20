"""Cloud environment checks. Business APIs will be implemented next."""

import os

import pymysql
from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok", service="VulnLensDB", stage="environment-only")


@app.get("/health/db")
def database_health():
    try:
        with pymysql.connect(
            host=os.environ.get("DB_HOST", "127.0.0.1"),
            port=int(os.environ.get("DB_PORT", "3306")),
            user=os.environ.get("DB_USER", "vulnlens"),
            password=os.environ["DB_PASSWORD"],
            database=os.environ.get("DB_NAME", "vulnlens"),
            charset="utf8mb4",
            connect_timeout=5,
            read_timeout=5,
            write_timeout=5,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT VERSION()")
                version = cursor.fetchone()[0]
        return jsonify(status="ok", database="mysql", version=version)
    except (pymysql.MySQLError, KeyError, ValueError):
        app.logger.warning("Database health check failed")
        return jsonify(status="error", message="Database unavailable; check environment configuration."), 503
