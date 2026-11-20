"""Load the reviewed compressed snapshot in one transaction."""
import gzip
import hashlib
import json
from pathlib import Path
from .catalog import ROOT, connect, stamp

DATA=ROOT/"data/library"
TABLES=("lib_stats","lib_edge","lib_profile","lib_check","lib_project","lib_release",
        "lib_cpe","lib_nvd","lib_span","lib_affected","lib_alias","lib_advisory","lib_package","lib_batch")


def bulk(cur,table,items,columns=None):
    if not items:
        return
    fields="("+",".join(columns)+")" if columns else ""
    query=f"INSERT INTO {table}{fields} VALUES ("+",".join(["%s"]*len(items[0]))+")"
    for i in range(0,len(items),400):
        cur.executemany(query,items[i:i+400])


def refresh_stats(cur):
    cur.execute("DELETE FROM lib_stats")
    cur.execute("""INSERT INTO lib_stats
        SELECT p.id,COALESCE(a.n,0),a.score,COALESCE(d.n,0),COALESCE(v.n,0) FROM lib_package p
        LEFT JOIN (SELECT x.package_id,COUNT(*) n,MAX(a.score) score FROM lib_affected x
                   JOIN lib_advisory a ON a.id=x.advisory_id GROUP BY x.package_id) a ON a.package_id=p.id
        LEFT JOIN (SELECT child_id,COUNT(DISTINCT parent_id) n FROM lib_edge GROUP BY child_id) d ON d.child_id=p.id
        LEFT JOIN (SELECT package_id,COUNT(*) n FROM lib_release GROUP BY package_id) v ON v.package_id=p.id""")


def load():
    manifest=json.loads((DATA/"manifest.json").read_text(encoding="utf-8"))
    h=hashlib.sha256()
    for name in ("manifest.json","advisories.jsonl.gz","enrichment.json.gz"):
        with (DATA/name).open("rb") as stream:
            for chunk in iter(lambda:stream.read(1<<20),b""): h.update(chunk)
    digest=h.hexdigest()
    with connect() as db,db.cursor() as cur:
        cur.execute("SET SESSION innodb_lock_wait_timeout=180")
        cur.execute("SELECT GET_LOCK('vulnlens_library_import',120) AS locked")
        if cur.fetchone()["locked"]!=1: raise RuntimeError("Another snapshot import is active")
        for stmt in (ROOT/"sql/library.sql").read_text().split(";"):
            if stmt.strip(): cur.execute(stmt)
        cur.execute("SELECT fingerprint FROM lib_batch WHERE id=1")
        old=cur.fetchone()
        if old and old["fingerprint"]==digest: return
        for table in TABLES: cur.execute("DELETE FROM "+table)
        with gzip.open(DATA/"enrichment.json.gz","rt",encoding="utf-8") as stream: extra=json.load(stream)
        packages={}
        def pkg(eco,name):
            key=(eco,name)
            if key not in packages: packages[key]=len(packages)+1
            return packages[key]
        with gzip.open(DATA/"advisories.jsonl.gz","rt",encoding="utf-8") as stream:
            for line in stream:
                for eco,name,_,_ in json.loads(line)["affected"]: pkg(eco,name)
        for row in extra["roots"]:
            eco=row["eco"]
            pkg(eco,row["name"])
            for parent,_,child,_,_ in row["edges"]: pkg(eco,parent);pkg(eco,child)
        bulk(cur,"lib_package",[(i,e,n) for (e,n),i in packages.items()])
        def flush(batch):
            advisories,aliases,affected,spans=[],[],[],[]
            for a in batch:
                aid=a["id"]
                advisories.append((aid,a["title"],stamp(a["published"]),stamp(a["modified"]),a["score"],a["level"]))
                sources=set(a["sources"])
                aliases.extend((x,aid,x in sources) for x in a["aliases"])
                for eco,name,ranges,versions in a["affected"]:
                    pid=pkg(eco,name)
                    affected.append((pid,aid,json.dumps(versions)))
                    spans.extend((pid,aid,start,endtype,end) for start,endtype,end in ranges)
            bulk(cur,"lib_advisory",advisories);bulk(cur,"lib_alias",aliases)
            bulk(cur,"lib_affected",affected)
            bulk(cur,"lib_span",spans,("package_id","advisory_id","introduced","end_type","endpoint"))
        with gzip.open(DATA/"advisories.jsonl.gz","rt",encoding="utf-8") as stream:
            batch=[]
            for line in stream:
                batch.append(json.loads(line))
                if len(batch)>=250: flush(batch);batch=[]
            if batch: flush(batch)
        projects={}
        for root in extra["roots"]:
            project=root.get("project")
            if project: projects[project["id"]]=project
        for p in projects.values():
            cur.execute("INSERT INTO lib_project VALUES (%s,%s,%s,%s)",(p["id"],p["url"],p["score"],stamp(p["date"]) if p["date"] else None))
            bulk(cur,"lib_check",[(p["id"],n,s) for n,s in p["checks"]])
        for p in extra["roots"]:
            eco=p["eco"]; root=pkg(eco,p["name"])
            cur.execute("INSERT INTO lib_profile VALUES (%s,%s,%s,%s)",(root,p["version"],p["url"],(p.get("project") or {}).get("id")))
            versions={v:d for v,d in p["releases"]}
            bulk(cur,"lib_release",[(root,v,stamp(d) if d else None) for v,d in versions.items()])
            edges={(root,pkg(eco,n1),pkg(eco,n2),v1,v2):req for n1,v1,n2,v2,req in p["edges"]}
            bulk(cur,"lib_edge",[(*k,r) for k,r in edges.items()])
        for n in extra["nvd"]:
            cur.execute("INSERT INTO lib_nvd VALUES (%s,%s,%s,%s,%s)",(n["id"],n["description"],n["score"],n["source"],stamp(n["published"])))
            bulk(cur,"lib_cpe",[(n["id"],json.dumps(x)) for x in n["rules"]],("cve","rule_json"))
        refresh_stats(cur)
        cur.execute("INSERT INTO lib_batch VALUES (1,%s,%s,%s)",(digest,stamp(manifest["collected"]),json.dumps(manifest)))
        db.commit()
        print("Imported",manifest["advisories"],"advisories and",len(packages),"packages",flush=True)


if __name__=="__main__": load()
