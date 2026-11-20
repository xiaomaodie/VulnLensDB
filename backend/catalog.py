"""Rebuild the course snapshot with transactional, repeatable imports."""
import json
import os
from datetime import datetime
from pathlib import Path

import pymysql
from pymysql.cursors import DictCursor

ROOT = Path(__file__).resolve().parents[1]


def connect():
    return pymysql.connect(host=os.getenv("DB_HOST", "127.0.0.1"),
                           port=int(os.getenv("DB_PORT", "3306")),
                           user=os.getenv("DB_USER", "vulnlens"),
                           password=os.environ["DB_PASSWORD"],
                           database=os.getenv("DB_NAME", "vulnlens"),
                           charset="utf8mb4", cursorclass=DictCursor,
                           connect_timeout=5, read_timeout=15)


def stamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None, microsecond=0)


def initialize():
    data = json.loads((ROOT / "data/snapshot.json").read_text(encoding="utf-8"))
    with connect() as db, db.cursor() as c:
        for statement in (ROOT / "sql/schema.sql").read_text().split(";"):
            if statement.strip():
                c.execute(statement)
        # The catalog tables belong exclusively to this frozen teaching snapshot.
        # A single transaction replaces all rows, including removed aliases/ranges.
        for table in ("evidence", "affected_range", "package_release", "advisory_alias",
                      "nvd_rating", "advisory", "package"):
            c.execute(f"DELETE FROM {table}")
        seen_packages, seen_releases = set(), set()
        for a in data["records"]:
            aid, name = a["id"], a["name"]
            if name not in seen_packages:
                c.execute("INSERT INTO package VALUES (%s,'PyPI')", (name,))
                seen_packages.add(name)
            c.execute("INSERT INTO advisory VALUES (%s,%s,%s,%s,%s)",
                      (aid, a["title"], a["osv_level"], stamp(a["published"]), stamp(a["modified"])))
            c.executemany("INSERT INTO advisory_alias VALUES (%s,%s)", [(x, aid) for x in a["aliases"]])
            c.execute("INSERT INTO nvd_rating VALUES (%s,%s,%s,%s)",
                      (a["cve"], a["nvd_score"], a["nvd_author"], stamp(a["nvd_modified"])))
            links = {("OSV", "https://osv.dev/vulnerability/" + aid),
                     ("NVD", "https://nvd.nist.gov/vuln/detail/" + a["cve"])}
            for r in a["ranges"]:
                release = (name, r["fixed"])
                if release not in seen_releases:
                    c.execute("INSERT INTO package_release VALUES (%s,%s,%s)", (*release, stamp(r["published"])))
                    seen_releases.add(release)
                c.execute("INSERT INTO affected_range VALUES (%s,%s,%s,%s)",
                          (aid, name, r["introduced"], r["fixed"]))
                links.add(("deps.dev", r["source"]))
            c.executemany("INSERT INTO evidence VALUES (%s,%s,%s,%s)",
                          [(aid, src, url, stamp(data["retrieved"])) for src, url in sorted(links)])
        db.commit()


if __name__ == "__main__":
    initialize()
