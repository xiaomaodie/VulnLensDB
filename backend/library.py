"""Views for the multi-ecosystem dataset. All filters are bound SQL parameters."""
import csv
from functools import lru_cache
import io
import json
import re
from collections import defaultdict
from datetime import timedelta
from flask import Blueprint, Response, abort, render_template, request
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion
from semver import Version as SemVer
from .views import rows
from .library_db import DATA

library=Blueprint("library",__name__)
ECOS=("PyPI","Maven","Go")
LEVELS=("CRITICAL","HIGH","MODERATE","LOW","UNKNOWN")


@lru_cache(maxsize=8192)
def key_version(eco,value):
    if eco=="PyPI": return Version(value)
    if eco=="Go":
        value=value.removeprefix("v").split("+")[0]
        return SemVer.parse(value,optional_minor_and_patch=True)
    if not re.fullmatch(r"\d+(?:\.\d+)*",value):
        raise ValueError("Maven qualifier requires explicit OSV membership")
    seq=[int(v) for v in value.split(".")]
    while len(seq)>1 and seq[-1]==0: seq.pop()
    return tuple(seq)


def classify(eco,version,listed,spans):
    explicit=version in listed or (eco=="Go" and version.removeprefix("v") in listed)
    matches=[];unknown=False
    for r in spans:
        try:
            target=key_version(eco,version)
            if r["introduced"]!="0" and target<key_version(eco,r["introduced"]): continue
            kind=r["end_type"]
            if kind!="open":
                end=key_version(eco,r["endpoint"])
                if target>end or (target==end and kind!="last_affected"): continue
            matches.append(r)
        except (InvalidVersion,ValueError,TypeError): unknown=True
    if explicit or matches:
        return "命中",sorted({r["endpoint"] for r in matches if r["end_type"]=="fixed"})
    if unknown or (not spans and not listed): return "待核对",[]
    return "未命中",[]


def normalize(eco,name):
    return canonicalize_name(name) if eco=="PyPI" else name


def contains_pattern(term):
    """Treat SQL wildcard characters as literal search text."""
    escaped = term.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    return "%" + escaped + "%"


def keyword_clause(term):
    if not term:
        return "", []
    fragment = contains_pattern(term)
    identifier = contains_pattern(term.lower())
    package = contains_pattern(canonicalize_name(term))
    clause = """(
        LOWER(a.id) LIKE %s ESCAPE '!'
        OR a.title LIKE %s ESCAPE '!'
        OR MATCH(a.title) AGAINST (%s IN NATURAL LANGUAGE MODE)
        OR a.id IN (
            SELECT l.advisory_id FROM lib_alias l
            WHERE LOWER(l.alias) LIKE %s ESCAPE '!'
            UNION
            SELECT x.advisory_id FROM lib_package p
            JOIN lib_affected x ON x.package_id=p.id
            WHERE LOWER(p.name) LIKE %s ESCAPE '!' OR LOWER(p.name) LIKE %s ESCAPE '!'
            UNION
            SELECT z.advisory_id FROM lib_nvd n JOIN lib_alias z ON n.cve=z.alias
            WHERE n.description LIKE %s ESCAPE '!'
               OR MATCH(n.description) AGAINST (%s IN NATURAL LANGUAGE MODE)
        )
    )"""
    return clause, [
        identifier, fragment, term, identifier,
        identifier, package, fragment, term,
    ]


PACKAGE_PAGE_SIZE = 20
PACKAGE_INTROS = {
    ("PyPI", "pillow"): "Python 图片处理库",
    ("PyPI", "django"): "Python 网站开发框架",
    ("PyPI", "requests"): "Python HTTP 请求库",
    ("PyPI", "flask"): "Python 轻量级网站开发框架",
    ("Maven", "org.apache.logging.log4j:log4j-core"): "Java 日志组件",
}
PACKAGE_LABELS = {"PyPI": "PyPI · Python", "Maven": "Maven · Java", "Go": "Go"}


@library.get("/")
def package_search():
    if not (DATA / "manifest.json").exists():
        return catalog()
    term = request.args.get("q", "").strip()[:150]
    eco = request.args.get("eco", "")
    if eco and eco not in ECOS:
        abort(400)
    search = term.lower()
    normalized = canonicalize_name(term)
    predicates, params = [], []
    if eco:
        predicates.append("p.ecosystem=%s")
        params.append(eco)
    if term:
        predicates.append("(LOWER(p.name) LIKE %s ESCAPE '!' OR "
                          "(p.ecosystem='PyPI' AND p.name LIKE %s ESCAPE '!'))")
        params += [contains_pattern(search), contains_pattern(normalized)]
    condition = " WHERE " + " AND ".join(predicates) if predicates else ""
    total = rows("SELECT COUNT(*) n FROM lib_package p" + condition, params)[0]["n"]
    pages = max(1, (total + PACKAGE_PAGE_SIZE - 1) // PACKAGE_PAGE_SIZE)
    page = max(1, min(request.args.get("page", 1, type=int), pages))
    order = ""
    order_params = []
    if term:
        order = """CASE
            WHEN LOWER(p.name)=%s OR (p.ecosystem='PyPI' AND p.name=%s) THEN 0
            WHEN LEFT(LOWER(p.name),CHAR_LENGTH(%s))=%s THEN 1
            ELSE 2 END, """
        order_params = [search, normalized, search, search]
    packages = rows("""SELECT p.ecosystem,p.name,s.advisories
        FROM lib_package p JOIN lib_stats s ON s.package_id=p.id""" + condition +
        " ORDER BY " + order + "s.advisories DESC,p.ecosystem,p.name LIMIT %s OFFSET %s",
        params + order_params + [PACKAGE_PAGE_SIZE, (page - 1) * PACKAGE_PAGE_SIZE])
    return render_template("package_search.html", packages=packages, q=term, eco=eco,
                           total=total, page=page, pages=pages, labels=PACKAGE_LABELS,
                           intros=PACKAGE_INTROS)


VERSION_PAGE_SIZE = 15
VERSION_SEVERITIES = ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")


def package_advisories(package_id):
    advisories = rows("""SELECT a.id,a.title,a.severity,a.score,x.listed_versions
        FROM lib_affected x JOIN lib_advisory a ON a.id=x.advisory_id
        WHERE x.package_id=%s ORDER BY a.score DESC,a.id""", (package_id,))
    spans = defaultdict(list)
    for span in rows("""SELECT advisory_id,introduced,end_type,endpoint FROM lib_span
                        WHERE package_id=%s""", (package_id,)):
        spans[span["advisory_id"]].append(span)
    return [(item, set(json.loads(item["listed_versions"])), spans[item["id"]])
            for item in advisories]


def release_findings(eco, version, advisories):
    counts = dict.fromkeys(VERSION_SEVERITIES, 0)
    hits, uncertain = [], []
    for item, listed, spans in advisories:
        status, fixes = classify(eco, version, listed, spans)
        if status == "命中":
            severity = item["severity"] if item["severity"] in counts else "UNKNOWN"
            counts[severity] += 1
            hits.append(dict(item, fixed=", ".join(fixes)))
        elif status == "待核对":
            uncertain.append(item)
    return dict(hits=hits, uncertain=uncertain, counts=counts)


def version_results(eco, releases, advisories):
    return [dict(release, **release_findings(eco, release["version"], advisories))
            for release in releases]


@library.get("/packages/<eco>/<path:name>")
def package_detail(eco, name):
    if eco not in ECOS or len(name) > 730:
        abort(404)
    record = rows("""SELECT p.id,p.name,s.advisories FROM lib_package p
        JOIN lib_stats s ON s.package_id=p.id WHERE p.ecosystem=%s AND p.name=%s""",
        (eco, normalize(eco, name)))
    if not record:
        abort(404)
    package = record[0]
    releases = rows("""SELECT version,published FROM lib_release WHERE package_id=%s
        ORDER BY published IS NULL,published DESC,version DESC""", (package["id"],))
    advisories = package_advisories(package["id"])
    listed_only = not releases
    if listed_only:
        # Some packages have OSV coverage but no deps.dev release listing in this snapshot.
        candidates = set()
        for _, listed, spans in advisories:
            candidates.update(listed)
            candidates.update(span["endpoint"] for span in spans if span["endpoint"])
            candidates.update(span["introduced"] for span in spans if span["introduced"] != "0")
        sortable, other = [], []
        for value in candidates:
            try:
                sortable.append((key_version(eco, value), value))
            except ValueError:
                other.append(value)
        versions = [value for _, value in sorted(sortable, reverse=True)] + sorted(other)
        releases = [dict(version=value, published=None) for value in versions]
    show = request.args.get("show", "")
    version = request.args.get("version", "").strip()
    all_results = version_results(eco, releases, advisories) if show == "affected" else None
    visible = [r for r in all_results if r["hits"]] if all_results is not None else releases
    pages = max(1, (len(visible) + VERSION_PAGE_SIZE - 1) // VERSION_PAGE_SIZE)
    page = max(1, min(request.args.get("page", 1, type=int), pages))
    start = (page - 1) * VERSION_PAGE_SIZE
    shown = visible[start:start + VERSION_PAGE_SIZE]
    if all_results is None:
        shown = version_results(eco, shown, advisories)

    error = None
    selected = None
    if version:
        try:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!_+\-]{0,199}", version):
                raise ValueError("Expected a fixed version")
            parse_pins(f"{package['name']}=={version}", eco)
            selected = release_findings(eco, version, advisories)
        except ValueError:
            error = "请输入一个有效的固定版本号，例如 10.3.0。"
    return render_template("package_detail.html", package=package, eco=eco,
                           ecosystem_label=PACKAGE_LABELS[eco],
                           intro=PACKAGE_INTROS.get((eco, package["name"])),
                           releases=releases, shown=shown, listed_only=listed_only,
                           version=version, error=error, selected=selected,
                           show=show, page=page, pages=pages), 400 if error else 200


@library.get("/library")
def catalog():
    if not (DATA/"manifest.json").exists():
        from .views import home
        return home()
    term=request.args.get("q","").strip()[:150]
    eco=request.args.get("eco",""); level=request.args.get("level",""); year=request.args.get("year","")
    order=request.args.get("sort","new")
    if eco and eco not in ECOS or level and level not in LEVELS: abort(400)
    criteria=[];params=[]
    clause,values=keyword_clause(term)
    if clause: criteria.append(clause);params+=values
    if eco:
        criteria.append("""EXISTS(SELECT 1 FROM lib_affected x JOIN lib_package p ON p.id=x.package_id
            WHERE x.advisory_id=a.id AND p.ecosystem=%s)""");params.append(eco)
    if level: criteria.append("a.severity=%s");params.append(level)
    if year:
        if not re.fullmatch(r"(19|20)\d\d",year):abort(400)
        criteria.append("a.published >= %s AND a.published < %s");params += [year+"-01-01",str(int(year)+1)+"-01-01"]
    cond=" WHERE "+" AND ".join(criteria) if criteria else ""
    total=rows("SELECT COUNT(*) n FROM lib_advisory a"+cond,params)[0]["n"]
    page=max(1,min(request.args.get("page",1,type=int),(total+24)//25))
    ordering="a.score DESC,a.published DESC,a.id" if order=="score" else "a.published DESC,a.id"
    entries=rows("SELECT a.id,a.title,a.published,a.score,a.severity FROM lib_advisory a"+cond+
                 " ORDER BY "+ordering+" LIMIT 25 OFFSET %s",params+[(page-1)*25])
    metrics=rows("""SELECT (SELECT COUNT(*) FROM lib_advisory) advisories,
        (SELECT COUNT(*) FROM lib_package) packages,(SELECT COUNT(*) FROM lib_span) spans,
        (SELECT COUNT(*) FROM lib_advisory a WHERE a.severity IN ('CRITICAL','HIGH') AND
         a.published BETWEEN b.collected-INTERVAL 30 DAY AND b.collected) recent,b.collected
        FROM lib_batch b WHERE b.id=1""")[0]
    filters=dict(q=term,eco=eco,level=level,year=year,sort=order)
    return render_template("library.html",entries=entries,m=metrics,n=total,page=page,filters=filters,ecos=ECOS,levels=LEVELS)


# Reviewed plain-language summaries for selected demonstration advisories.
ADVISORY_SUMMARIES = {
    "GHSA-5x8w-8jj5-q52h": (
        "Pillow 处理 FlashPix 图片时可能执行恶意代码",
        "应用用受影响的 Pillow 处理特制 FlashPix（FPX）图片时，可能崩溃或执行恶意代码。"
        "如果你的应用允许上传或自动处理图片，优先检查正在用的版本。",
    ),
}


@library.get("/library/advisory/<aid>")
def advisory(aid):
    records = rows("""SELECT a.* FROM lib_alias l JOIN lib_advisory a ON a.id=l.advisory_id
        WHERE l.alias=%s""", (aid,))
    if not records:
        abort(404)
    record = records[0]
    aid = record["id"]
    links = rows("SELECT alias,osv_record FROM lib_alias WHERE advisory_id=%s ORDER BY alias", (aid,))
    packages = rows("""SELECT p.id,p.ecosystem,p.name,x.listed_versions
        FROM lib_affected x JOIN lib_package p ON p.id=x.package_id
        WHERE x.advisory_id=%s ORDER BY p.ecosystem,p.name""", (aid,))
    ranges = defaultdict(list)
    for span in rows("""SELECT package_id,introduced,end_type,endpoint FROM lib_span
                       WHERE advisory_id=%s ORDER BY id""", (aid,)):
        ranges[span["package_id"]].append(span)
    for package in packages:
        package["spans"] = ranges[package["id"]]
        package["listed"] = json.loads(package["listed_versions"])
    selected = request.args.get("package", type=int)
    package = next((p for p in packages if p["id"] == selected), packages[0] if packages else None)
    version = request.args.get("version", "").strip()
    error, status, fixes = None, None, []
    if version and package:
        try:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!_+\-]{0,199}", version):
                raise ValueError("Expected one version")
            parse_pins(f"{package['name']}=={version}", package["ecosystem"])
            status, fixes = classify(package["ecosystem"], version, set(package["listed"]), package["spans"])
        except ValueError:
            error = "请输入一个有效的固定版本号，例如 12.3.0。"
    nvd = rows("""SELECT n.* FROM lib_nvd n JOIN lib_alias l ON l.alias=n.cve
                    WHERE l.advisory_id=%s""", (aid,))
    cp = rows("""SELECT c.cve,c.rule_json FROM lib_cpe c JOIN lib_alias l ON l.alias=c.cve
                 WHERE l.advisory_id=%s ORDER BY c.id""", (aid,))
    cve = next((l["alias"] for l in links if l["alias"].startswith("CVE-")), None)
    summary = next((ADVISORY_SUMMARIES[l["alias"]] for l in links if l["alias"] in ADVISORY_SUMMARIES), None)
    return render_template("library_detail.html", a=record, links=links, packages=packages,
                           package=package, version=version, error=error, status=status, fixes=fixes,
                           cve=cve, summary=summary, nvd=nvd,
                           cpes=[(r["cve"], json.loads(r["rule_json"])) for r in cp])


def parse_pins(text,eco):
    from defusedxml import ElementTree
    if text.lstrip().startswith("<"):
        root=ElementTree.fromstring(text)
        if root.tag.rsplit("}",1)[-1]!="project": raise ValueError("请输入 Maven project XML。")
        pins=[]
        for dep in root.findall("./{*}dependencies/{*}dependency"):
            parts=[(dep.findtext("{*}"+k) or "").strip() for k in ("groupId","artifactId","version")]
            if not all(parts) or any(x in parts[2] for x in ("$","[","(",",")): raise ValueError("POM 只支持直接依赖的固定版本。")
            pins.append(("Maven",parts[0]+":"+parts[1],parts[2]))
    else:
        pins=[]
        for i,line in enumerate(text.splitlines(),1):
            line=line.split("#",1)[0].strip()
            if not line: continue
            match=re.fullmatch(r"([^\s=]+)==([^\s=;]+)",line)
            if not match: raise ValueError(f"第 {i} 行需要 包名==固定版本。")
            name,v=match.groups()
            if eco=="PyPI": Version(v)
            elif eco=="Go": key_version(eco,v)
            pins.append((eco,normalize(eco,name),v))
    if not 1<=len(pins)<=100: raise ValueError("每次可检查 1 至 100 项。")
    if any(len(n)>700 or len(v)>200 for _,n,v in pins): raise ValueError("包名或版本过长。")
    return pins


def scan(pins):
    keys=sorted({(e,n) for e,n,_ in pins})
    marks=",".join(["(%s,%s)"]*len(keys));params=[x for pair in keys for x in pair]
    scope=" WHERE (p.ecosystem,p.name) IN ("+marks+")"
    entries=rows("""SELECT p.ecosystem,p.name,x.advisory_id,x.listed_versions,a.score,a.severity
        FROM lib_package p LEFT JOIN lib_affected x ON x.package_id=p.id
        LEFT JOIN lib_advisory a ON a.id=x.advisory_id"""+scope+" ORDER BY a.score DESC,a.id",params)
    spans=rows("""SELECT p.ecosystem,p.name,s.advisory_id,s.introduced,s.end_type,s.endpoint
        FROM lib_package p JOIN lib_span s ON s.package_id=p.id"""+scope,params)
    ranges=defaultdict(list); packages=defaultdict(list)
    for r in spans:ranges[(r["ecosystem"],r["name"],r["advisory_id"])].append(r)
    for r in entries:
        r["listed"]=set(json.loads(r["listed_versions"] or "[]"))
        packages[(r["ecosystem"],r["name"])].append(r)
    result=[]
    for e,n,v in pins:
        candidates=packages.get((e,n),[])
        found=False
        for r in candidates:
            aid=r["advisory_id"]
            if not aid:continue
            status,fixed=classify(e,v,r["listed"],ranges[(e,n,aid)])
            if status in ("命中","待核对"):
                result.append((e,n,v,status,aid,r["score"],", ".join(fixed)))
                found=True
        if not found: result.append((e,n,v,"本快照未命中" if candidates else "包未收录","",None,""))
    return result


@library.route("/library/check",methods=["GET","POST"])
def check():
    from defusedxml.common import DefusedXmlException
    from xml.etree.ElementTree import ParseError
    eco=request.form.get("eco","PyPI")
    raw=request.form.get("pins","django==3.2.9\ndjango==3.2.13");result=[];error=None
    if request.method=="POST":
        try:
            if eco not in ECOS:raise ValueError("未知生态。")
            f=request.files.get("upload")
            if f and f.filename:raw=f.read().decode("utf-8-sig")
            pins=parse_pins(raw,eco)
            result=scan(pins)
            if request.form.get("save")=="yes":
                from .accounts import save_summary
                save_summary(pins,result)
            if request.form.get("format")=="csv":
                out=io.StringIO();w=csv.writer(out);w.writerow(("生态","包","版本","状态","公告","CVSS","修复端点"))
                for row in result:
                    w.writerow(["'"+x if isinstance(x,str) and x.startswith(("=","+","-","@")) else x for x in row])
                return Response("\ufeff"+out.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=dependency-report.csv"})
        except (ValueError,ParseError,DefusedXmlException,UnicodeError):
            error="请检查文件与版本格式。支持 UTF-8、固定版本、1 至 100 项。"
    return render_template("library_check.html",eco=eco,ecos=ECOS,raw=raw,result=result,error=error),400 if error else 200


QUERIES={
 "severity":("Q3　近十二个月高危公告", "时间窗口以快照采集日为准。默认仅显示超过 500 条的生态，可调整阈值。",
 """SELECT p.ecosystem AS ecosystem,COUNT(DISTINCT a.id) AS high_advisories
    FROM lib_affected x JOIN lib_package p ON p.id=x.package_id JOIN lib_advisory a ON a.id=x.advisory_id
    JOIN lib_batch b ON b.id=1 WHERE a.severity IN ('HIGH','CRITICAL')
    AND a.published BETWEEN DATE_SUB(b.collected,INTERVAL 12 MONTH) AND b.collected
    GROUP BY p.ecosystem HAVING COUNT(DISTINCT a.id)>%s ORDER BY high_advisories DESC"""),
 "coverage":("Q4　两源 CVE 覆盖","NVD 含演示案例与独立时间窗口样本。单边收录仅表示本批次的覆盖差异。",
 """WITH coverage AS (
    SELECT l.alias cve,IF(n.cve IS NULL,'仅 OSV','两源均有') coverage
    FROM lib_alias l LEFT JOIN lib_nvd n ON n.cve=l.alias WHERE l.alias LIKE 'CVE-%'
    UNION ALL SELECT n.cve,'仅 NVD' FROM lib_nvd n WHERE NOT EXISTS(SELECT 1 FROM lib_alias l WHERE l.alias=n.cve))
    SELECT coverage,COUNT(*) AS cves,MIN(cve) AS example FROM coverage GROUP BY coverage ORDER BY coverage"""),
 "downstream":("Q6　下游依赖影响面","只统计样本依赖图中出现的直接边。按不同下游包去重，同一条边在多个根版本中出现只计一次。只列存在高危公告的包。",
 """WITH risk AS (SELECT DISTINCT x.package_id FROM lib_affected x JOIN lib_advisory a ON a.id=x.advisory_id
    WHERE a.severity IN ('HIGH','CRITICAL'))
    SELECT DENSE_RANK() OVER(ORDER BY s.dependents DESC) AS position,p.ecosystem,p.name,s.dependents,
    s.advisories,s.max_score FROM lib_stats s JOIN risk r ON r.package_id=s.package_id JOIN lib_package p ON p.id=s.package_id
    WHERE s.dependents>0 ORDER BY position,p.name LIMIT 50"""),
 "timeline":("Q8　公告修复时间线","选择包后，按可查到的修复版发布时间为每条公告排序。发布日期缺失的端点另行标记。",
 """WITH points AS (SELECT DISTINCT s.advisory_id,s.endpoint,v.published
    FROM lib_span s JOIN lib_package p ON p.id=s.package_id
    LEFT JOIN lib_release v ON v.package_id=s.package_id AND v.version=s.endpoint
    WHERE p.ecosystem=%s AND p.name=%s AND s.end_type='fixed'),
    ranked AS (SELECT *,ROW_NUMBER() OVER(PARTITION BY advisory_id ORDER BY published IS NULL,published,endpoint) rn
    FROM points) SELECT advisory_id,endpoint,published FROM ranked WHERE rn=1
    ORDER BY published IS NULL,published DESC,advisory_id LIMIT 150"""),
 "scorecard":("Q9　健康度与公告密度","每百个已列出发行版本对应的公告数 = 100 × 公告数 / 发行版本数。按 Scorecard 得分等频分四组，同分时按包编号分配。样本关联不代表因果。",
 """WITH measured AS (SELECT p.package_id,j.score,s.advisories,s.releases,
    NTILE(4) OVER(ORDER BY j.score,p.package_id) AS bucket FROM lib_profile p JOIN lib_project j ON j.project_key=p.project_key
    JOIN lib_stats s ON s.package_id=p.package_id WHERE j.score IS NOT NULL AND s.releases>0)
    SELECT bucket,COUNT(*) AS packages,MIN(score) min_score,MAX(score) max_score,SUM(advisories) advisories,
    SUM(releases) releases,ROUND(100*SUM(advisories)/SUM(releases),2) AS density FROM measured GROUP BY bucket ORDER BY bucket""")
}


@library.get("/library/reports")
def reports():
    view=request.args.get("view","downstream")
    if view not in QUERIES: abort(404)
    eco=request.args.get("eco","PyPI");name=request.args.get("name","django")[:500]
    minimum=max(0,min(request.args.get("minimum",500,type=int),1000000))
    params=(minimum,) if view=="severity" else (eco,normalize(eco,name)) if view=="timeline" else None
    title,note,query=QUERIES[view]
    result=rows(query,params)
    return render_template("lib_reports.html",queries=QUERIES,view=view,title=title,note=note,result=result,
                           sql=query,eco=eco,name=name,minimum=minimum,ecos=ECOS)


@library.get("/library/sources")
def sources():
    m=rows("SELECT manifest,collected FROM lib_batch WHERE id=1")[0]
    profiles=rows("""SELECT p.ecosystem,p.name,f.version,f.evidence_url,f.project_key,j.url,j.score,j.assessed,
          s.releases,s.dependents FROM lib_profile f JOIN lib_package p ON p.id=f.package_id
          JOIN lib_stats s ON s.package_id=p.id LEFT JOIN lib_project j ON j.project_key=f.project_key ORDER BY p.ecosystem,p.name""")
    return render_template("lib_sources.html",manifest=json.loads(m["manifest"]),profiles=profiles)


@library.get("/library/nvd/<cve>")
def official(cve):
    a=rows("SELECT * FROM lib_nvd WHERE cve=%s",(cve,))
    if not a:abort(404)
    return render_template("lib_nvd.html",a=a[0],cpes=[json.loads(r["rule_json"]) for r in
        rows("SELECT rule_json FROM lib_cpe WHERE cve=%s ORDER BY id",(cve,))])
