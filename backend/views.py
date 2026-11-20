"""Read-only views for the public advisory snapshot."""
import re
from flask import Blueprint, abort, render_template, request
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from .catalog import connect

site = Blueprint("site", __name__)
BASE = """
SELECT r.package_name, a.id, a.title, a.osv_level, n.cve, n.score, r.introduced, r.fixed,
       v.published AS released
FROM affected_range r JOIN advisory a ON a.id=r.advisory_id
JOIN package_release v ON (v.package_name,v.version)=(r.package_name,r.fixed)
LEFT JOIN advisory_alias x ON x.advisory_id=a.id AND x.alias_id LIKE 'CVE-%%'
LEFT JOIN nvd_rating n ON n.cve=x.alias_id
"""
REPORTS = {
    "levels": ("公告等级分布", """SELECT osv_level AS level, COUNT(*) AS advisories FROM advisory
        GROUP BY osv_level HAVING COUNT(*) > 0 ORDER BY advisories DESC, level"""),
    "coverage": ("CVE 对齐检查", """SELECT x.alias_id AS cve, '仅 OSV' AS coverage FROM advisory_alias x
        WHERE x.alias_id LIKE 'CVE-%' AND NOT EXISTS (SELECT 1 FROM nvd_rating n WHERE n.cve=x.alias_id)
        UNION ALL SELECT n.cve,'仅 NVD' FROM nvd_rating n LEFT JOIN advisory_alias x ON x.alias_id=n.cve
        WHERE x.alias_id IS NULL UNION ALL SELECT n.cve,'两源均有' FROM nvd_rating n
        JOIN advisory_alias x ON n.cve=x.alias_id ORDER BY cve"""),
    "ranking": ("包的最高评分排名", """SELECT r.package_name, MAX(n.score) AS max_cvss,
        DENSE_RANK() OVER (ORDER BY MAX(n.score) DESC) AS risk_rank FROM affected_range r
        JOIN advisory_alias x ON x.advisory_id=r.advisory_id JOIN nvd_rating n ON n.cve=x.alias_id
        GROUP BY r.package_name ORDER BY risk_rank,r.package_name"""),
    "timeline": ("修复版本发布历史", """SELECT package_name,version,published,
        LAG(published) OVER(PARTITION BY package_name ORDER BY published,version) AS previous_release
        FROM package_release ORDER BY package_name,published,version"""),
    "sources": ("三源证据覆盖", """SELECT provider,COUNT(*) AS links,COUNT(DISTINCT advisory_id) AS advisories,
        MAX(retrieved) AS collected_utc FROM evidence GROUP BY provider ORDER BY provider""")
}


def rows(sql, params=None):
    with connect() as db, db.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def affected(version, start, stop):
    target = Version(version)
    return (start == "0" or Version(start) <= target) and target < Version(stop)


@site.get("/sample")
def home():
    term = request.args.get("q", "").strip()[:160]
    entries = rows("""SELECT DISTINCT a.id,a.title,a.osv_level,r.package_name,n.score,n.cve
        FROM advisory a JOIN affected_range r ON r.advisory_id=a.id
        JOIN advisory_alias x ON x.advisory_id=a.id JOIN nvd_rating n ON n.cve=x.alias_id
        WHERE %s='' OR a.id=%s OR r.package_name=%s
        OR EXISTS(SELECT 1 FROM advisory_alias z WHERE z.advisory_id=a.id AND z.alias_id=%s)
        OR MATCH(a.title) AGAINST (%s IN NATURAL LANGUAGE MODE)
        ORDER BY n.score DESC,a.id""", (term,term,canonicalize_name(term),term,term))
    counts = rows("""SELECT (SELECT COUNT(*) FROM advisory) AS advisories,
        (SELECT COUNT(*) FROM package) AS packages,(SELECT COUNT(*) FROM affected_range) AS spans,
        (SELECT MAX(retrieved) FROM evidence) AS collected""")[0]
    return render_template("index.html", entries=entries, counts=counts, term=term)


@site.get("/advisories/<aid>")
def detail(aid):
    spans = rows(BASE + " WHERE a.id=%s ORDER BY v.published,r.introduced", (aid,))
    if not spans:
        abort(404)
    return render_template("detail.html", item=spans[0], spans=spans,
        aliases=rows("SELECT alias_id FROM advisory_alias WHERE advisory_id=%s ORDER BY alias_id", (aid,)),
        links=rows("SELECT provider,url,retrieved FROM evidence WHERE advisory_id=%s ORDER BY provider,url",(aid,)))


@site.route("/check", methods=["GET","POST"])
def check():
    raw = request.form.get("pins", "") if request.method=="POST" else "django==3.2.1\ndjango==3.2.13"
    results, error = [], None
    if request.method=="POST":
        pins = [line.strip() for line in raw.splitlines() if line.strip()]
        try:
            if not 1 <= len(pins) <= 20:
                raise ValueError("请输入 1 至 20 条依赖。")
            parsed = []
            for i, line in enumerate(pins, 1):
                match = re.fullmatch(r"([A-Za-z0-9]+(?:[-._]+[A-Za-z0-9]+)*)==([^\s=;]+)", line)
                if not match:
                    raise ValueError(f"第 {i} 行请使用 包名==版本。")
                try:
                    ver = str(Version(match[2]))
                except InvalidVersion:
                    raise ValueError(f"第 {i} 行的版本不符合 PEP 440。") from None
                parsed.append((line, canonicalize_name(match[1]), ver))
            names = sorted({p[1] for p in parsed})
            markers = ",".join(["%s"]*len(names))
            spans = rows(BASE + f" WHERE r.package_name IN ({markers}) ORDER BY n.score DESC,a.id", names)
            for line,name,ver in parsed:
                records = [r for r in spans if r["package_name"]==name]
                hits = [r for r in records if affected(ver,r["introduced"],r["fixed"])]
                results.append((line, hits, "本快照未命中" if records else "包未收录"))
        except ValueError as exc:
            error = str(exc)
    return render_template("check.html", raw=raw, results=results, error=error), 400 if error else 200


@site.get("/reports")
def reports():
    key = request.args.get("view","levels")
    if key not in REPORTS:
        abort(404)
    title, sql = REPORTS[key]
    return render_template("reports.html", reports=REPORTS, selected=key, title=title, records=rows(sql))
