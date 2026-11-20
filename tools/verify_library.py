import json
from pathlib import Path
from backend.catalog import connect
from backend.library_db import TABLES,load
from tools.benchmark import measure


def main():
    load()
    with connect() as db,db.cursor() as c:
        counts={}
        for table in TABLES:
            c.execute("SELECT COUNT(*) n FROM "+table)
            counts[table]=c.fetchone()["n"]
        c.execute("SELECT id FROM lib_package WHERE ecosystem='PyPI' AND name='django'")
        pid=c.fetchone()["id"]
        c.execute("CREATE TEMPORARY TABLE full_lookup_trial (package_id INT,advisory_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin) ENGINE=InnoDB")
        c.execute("INSERT INTO full_lookup_trial SELECT package_id,advisory_id FROM lib_affected")
        q="SELECT advisory_id FROM full_lookup_trial WHERE package_id=%s ORDER BY advisory_id"
        before,baseline=measure(c,q,(pid,))
        c.execute("ALTER TABLE full_lookup_trial ADD INDEX pkg_advisory(package_id,advisory_id)")
        after,indexed=measure(c,q,(pid,))
        assert indexed==baseline and indexed and counts["lib_advisory"]>1000
        c.execute("SELECT e.ecosystem,COUNT(DISTINCT a.advisory_id) advisories FROM lib_affected a JOIN lib_package e ON e.id=a.package_id GROUP BY e.ecosystem")
        eco=c.fetchall()
        c.execute("SELECT COUNT(*) n FROM lib_project WHERE score IS NOT NULL")
        scored=c.fetchone()["n"]
        assert scored>=4 and counts["lib_edge"]>10 and counts["lib_cpe"]>0
        result=dict(counts=counts,ecosystems=eco,scored_projects=scored,full_rows=counts["lib_affected"],
                    query=q,package_id=pid,matched=len(indexed),before=before,after=after)
        out=Path("build/library-evidence.json");out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(result,indent=2,default=str))
        print(json.dumps(result,default=str),flush=True)


if __name__=="__main__":main()
