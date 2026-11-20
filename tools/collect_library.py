"""Collect public advisory metadata and a bounded, attributable enrichment sample."""
import gzip
import io
import json
import time
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import requests
from cvss import CVSS3
from packaging.utils import canonicalize_name
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

OUT = Path("data/library")
ECOS = ("PyPI", "Maven", "Go")
PINS = {
    "PyPI": {"django":"3.2.13","requests":"2.31.0","urllib3":"1.26.19","flask":"3.0.0",
             "werkzeug":"3.0.1","jinja2":"3.1.3","pillow":"10.3.0","pyyaml":"6.0.1",
             "cryptography":"42.0.5","pip":"24.0","sqlalchemy":"2.0.30","setuptools":"70.0.0",
             "boto3":"1.34.0","httpx":"0.27.0","fastapi":"0.110.0","starlette":"0.36.3"},
    "Maven":{"org.apache.logging.log4j:log4j-core":"2.15.0","org.apache.logging.log4j:log4j-api":"2.15.0",
             "org.springframework:spring-core":"5.3.20","com.google.guava:guava":"31.1-jre"}}
CVE_SAMPLE = ["CVE-2021-44228","CVE-2022-28346","CVE-2024-37891","CVE-2023-32681",
              "CVE-2021-45046","CVE-2022-22965"]
S = requests.Session()
S.mount("https://", HTTPAdapter(max_retries=Retry(total=3,backoff_factor=1,
        status_forcelist=(429,500,502,503,504))))
def fetch(url, **params):
    r=S.get(url,params=params,timeout=(10,90))
    r.raise_for_status()
    return r.json()


def normal(eco,name):
    return canonicalize_name(name) if eco=="PyPI" else name


def osv():
    parent={}
    def root(x):
        parent.setdefault(x,x)
        while parent[x]!=x:
            parent[x]=parent[parent[x]]
            x=parent[x]
        return x
    records={}
    skips=defaultdict(int)
    for eco in ECOS:
        url=f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
        r=S.get(url, timeout=(15,180))
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as archive:
            for file in archive.namelist():
                if not file.endswith(".json"): continue
                a=json.loads(archive.read(file))
                aid=a["id"]
                if a.get("withdrawn") or aid.startswith("MAL-"):
                    skips[eco]+=1
                    continue
                if aid in records: continue
                aliases=set(a.get("aliases",[]))|{aid}
                for alias in aliases:
                    parent[root(alias)]=root(aid)
                scores=[]
                for s in a.get("severity",[]):
                    if s.get("type")=="CVSS_V3":
                        try: scores.append(CVSS3(s["score"]).scores()[0])
                        except ValueError: pass
                affects=[]
                for entry in a.get("affected",[]):
                    pkg=entry.get("package",{})
                    if pkg.get("ecosystem") not in ECOS or not pkg.get("name"): continue
                    name=normal(pkg["ecosystem"],pkg["name"])
                    spans=[]
                    for group in entry.get("ranges",[]):
                        if group["type"] not in ("SEMVER","ECOSYSTEM"): continue
                        lo=None
                        for event in group.get("events",[]):
                            if "introduced" in event: lo=str(event["introduced"])
                            elif lo is not None:
                                for kind in ("fixed","last_affected","limit"):
                                    if kind in event:
                                        spans.append((lo,kind,str(event[kind])))
                                        lo=None
                                        break
                        if lo is not None: spans.append((lo,"open",""))
                    affects.append((pkg["ecosystem"],name,spans,entry.get("versions",[])))
                records[aid]=(a.get("summary","")[:700],a.get("published") or a["modified"],
                    a["modified"],max(scores,default=None),a.get("database_specific",{}).get("severity"),
                    aliases, affects)
    groups=defaultdict(list)
    for aid in records: groups[root(aid)].append(aid)
    result=[]
    for members in groups.values():
        members.sort(key=lambda x:(not x.startswith("GHSA-"),x))
        title=next((records[i][0] for i in members if records[i][0]),members[0])
        aliases=set()
        package_map={}
        scores=[]
        levels=[]
        for i in members:
            _,_,_,score,level,ids,affects=records[i]
            aliases.update(ids)
            if score is not None: scores.append(score)
            if level: levels.append(str(level).upper())
            for eco,name,spans,versions in affects:
                ran,ver=package_map.setdefault((eco,name),(set(),set()))
                ran.update(spans)
                ver.update(versions)
        if not package_map: continue
        score=max(scores,default=None)
        level=("CRITICAL" if score>=9 else "HIGH" if score>=7 else "MODERATE" if score>=4 else "LOW") if score is not None else next((v for v in ("CRITICAL","HIGH","MODERATE","MEDIUM","LOW") if v in levels),"UNKNOWN")
        result.append(dict(id=members[0],title=title,aliases=sorted(aliases),sources=members,
            published=min(records[i][1] for i in members),modified=max(records[i][2] for i in members),
            score=score,level=level,affected=[[e,n,sorted(r),sorted(v)] for (e,n),(r,v) in sorted(package_map.items())]))
    return sorted(result,key=lambda a:a["id"]),dict(skips)


def deps():
    roots=[]; missing=[]
    for eco,pins in PINS.items():
        for name,version in pins.items():
            pkg=f"https://api.deps.dev/v3/systems/{eco.upper()}/packages/{quote(name,safe='')}"
            url=pkg+"/versions/"+quote(version,safe="")
            try:
                meta=fetch(url)
                versions=fetch(pkg).get("versions",[])
                graph=fetch(url+":dependencies")
                edges=[]
                for edge in graph.get("edges",[]):
                    u,v=[graph["nodes"][edge[k]]["versionKey"] for k in ("fromNode","toNode")]
                    if u["system"]!=eco.upper() or v["system"]!=eco.upper(): continue
                    edges.append([normal(eco,u["name"]),u["version"],normal(eco,v["name"]),v["version"],edge.get("requirement","")])
                projects=[p["projectKey"]["id"] for p in meta.get("relatedProjects",[]) if p.get("relationType")=="SOURCE_REPO"]
                project=None
                if projects:
                    project_url="https://api.deps.dev/v3/projects/"+quote(projects[0],safe="")
                    try:
                        info=fetch(project_url)
                        sc=info.get("scorecard") or {}
                        project=dict(id=projects[0],url=project_url,date=sc.get("date"),score=sc.get("overallScore"),
                            checks=[[c["name"],c["score"]] for c in sc.get("checks",[]) if c.get("score",-1)>=0])
                    except requests.RequestException as ex: missing.append([project_url,str(ex)])
                roots.append(dict(eco=eco,name=name,version=version,url=url,edges=edges,project=project,
                    releases=[[x["versionKey"]["version"],x.get("publishedAt")] for x in versions]))
            except requests.RequestException as ex: missing.append([url,str(ex)])
    return roots,missing


def nvd():
    base="https://services.nvd.nist.gov/rest/json/cves/2.0"
    end=datetime.now(timezone.utc)-timedelta(days=1)
    iso=lambda d:d.strftime("%Y-%m-%dT%H:%M:%S.000")
    queries=[{"cveId":x} for x in CVE_SAMPLE]+[{"pubStartDate":iso(end-timedelta(days=7)),
             "pubEndDate":iso(end),"resultsPerPage":60}]
    result={}
    for i,params in enumerate(queries):
        if i: time.sleep(7)
        for hit in fetch(base,**params).get("vulnerabilities",[]):
            c=hit["cve"]
            if c.get("vulnStatus")=="Rejected": continue
            desc=next((x["value"] for x in c.get("descriptions",[]) if x["lang"]=="en"),"")
            ratings=c.get("metrics",{})
            metrics=next((ratings[k] for k in ("cvssMetricV31","cvssMetricV30","cvssMetricV40","cvssMetricV2") if ratings.get(k)),[])
            metric=min(metrics,key=lambda m:m.get("source")!="nvd@nist.gov") if metrics else {}
            rules=[]
            for group in c.get("configurations",[]):
                for node in group.get("nodes",[]):
                    for x in node.get("cpeMatch",[]):
                        rules.append({k:v for k,v in x.items() if k not in ("matchCriteriaId",)})
            result[c["id"]]=dict(id=c["id"],description=desc,score=metric.get("cvssData",{}).get("baseScore"),
                source=metric.get("source"),published=c["published"],rules=rules)
    return list(result.values())


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    advisories,skips=osv()
    roots,missing=deps()
    official=nvd()
    assert len(advisories)>1000 and len(roots)>=10 and len(official)>=6
    assert any(p.get("project") and p["project"]["score"] is not None for p in roots)
    assert any(p["edges"] for p in roots)
    with gzip.open(OUT/"advisories.jsonl.gz","wt",encoding="utf-8") as dest:
        for row in advisories: dest.write(json.dumps(row,ensure_ascii=False,separators=(",",":"))+"\n")
    with gzip.open(OUT/"enrichment.json.gz","wt",encoding="utf-8") as dest:
        json.dump(dict(roots=roots,nvd=official),dest,ensure_ascii=False,separators=(",",":"))
    manifest=dict(collected=datetime.now(timezone.utc).isoformat(),ecosystems=ECOS,advisories=len(advisories),
        excluded=skips,dependency_roots=len(roots),nvd_records=len(official),collection_errors=missing)
    (OUT/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
    print(manifest,flush=True)


if __name__=="__main__": main()
