"""Measure a full snapshot and an isolated synthetic index workload on MySQL 8."""
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns
from backend.catalog import connect
from backend.views import BASE

TABLES = ("package", "advisory", "advisory_alias", "affected_range",
          "package_release", "nvd_rating", "evidence")


def measure(cur, sql, params):
    cur.execute("EXPLAIN ANALYZE " + sql, params)
    plan = next(iter(cur.fetchone().values()))
    times = []
    for _ in range(7):
        start = perf_counter_ns()
        cur.execute(sql, params)
        result = cur.fetchall()
        times.append(round((perf_counter_ns() - start) / 1e6, 3))
    return {"plan": plan, "runs_ms": times, "median_ms": statistics.median(times)}, result


def main():
    with connect() as db, db.cursor() as cur:
        cur.execute("SELECT VERSION() AS v")
        version = cur.fetchone()["v"]
        counts = {}
        for table in TABLES:
            cur.execute(f"SELECT COUNT(*) AS n FROM {table}")
            counts[table] = cur.fetchone()["n"]
        live, rows = measure(cur, BASE + " WHERE r.package_name=%s ORDER BY n.score DESC,a.id", ("django",))
        cur.execute("CREATE TEMPORARY TABLE course_index_trial (seq INT PRIMARY KEY, "
                    "package_id INT NOT NULL, advisory_id INT NOT NULL) ENGINE=InnoDB")
        cur.execute("""INSERT INTO course_index_trial
            WITH RECURSIVE nums(n) AS (SELECT 0 UNION ALL SELECT n+1 FROM nums WHERE n<999)
            SELECT a.n*1000+b.n, MOD(a.n*1000+b.n,10000), MOD(a.n*1000+b.n,7919)
            FROM nums a CROSS JOIN nums b""")
        cur.execute("SELECT COUNT(*) AS n FROM course_index_trial")
        total = cur.fetchone()["n"]
        sql = "SELECT seq,advisory_id FROM course_index_trial WHERE package_id=%s ORDER BY advisory_id,seq"
        before, first = measure(cur, sql, (42,))
        cur.execute("ALTER TABLE course_index_trial ADD INDEX by_package_advisory(package_id,advisory_id)")
        after, second = measure(cur, sql, (42,))
        assert total == 1000000 and len(first) == 100 and first == second
    result = dict(utc=datetime.now(timezone.utc).isoformat(), mysql=version, python=platform.python_version(),
                  counts=counts, snapshot_lookup=dict(rows=len(rows), **live), synthetic_rows=total,
                  matched=len(first), query=sql, parameter=42, before=before, after=after)
    path = Path(sys.argv[1]) if len(sys.argv)>1 else Path("benchmark.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(f"{total:,} rows; median {before['median_ms']} -> {after['median_ms']} ms")


if __name__ == "__main__":
    main()
