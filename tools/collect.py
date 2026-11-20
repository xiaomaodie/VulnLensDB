"""Refresh the three reviewed PyPI advisories. Run from the repository root."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from packaging.utils import canonicalize_name
from packaging.version import Version
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

IDS = ["GHSA-2gwj-7jmv-h26r", "GHSA-j8r2-6x86-q33q", "GHSA-34jh-p97f-mpxf"]
ROOT = Path(__file__).resolve().parents[1]


def fetch(session, url):
    result = session.get(url, timeout=(8, 35))
    result.raise_for_status()
    return result.json()


def collect(session, aid):
    a = fetch(session, f"https://api.osv.dev/v1/vulns/{aid}")
    if a.get("withdrawn"):
        raise ValueError(f"Review withdrawn advisory: {aid}")
    cve, = [x for x in a["aliases"] if x.startswith("CVE-")]
    n = fetch(session, f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}")["vulnerabilities"][0]["cve"]
    metric = min(n["metrics"]["cvssMetricV31"], key=lambda m: m["source"] != "nvd@nist.gov")
    ranges, names = [], set()
    for entry in a["affected"]:
        if entry["package"]["ecosystem"] != "PyPI":
            continue
        name = canonicalize_name(entry["package"]["name"])
        names.add(name)
        for group in entry["ranges"]:
            if group["type"] != "ECOSYSTEM":
                raise ValueError(f"Review range type for {aid}")
            start = None
            for event in group["events"]:
                if set(event) == {"introduced"} and start is None:
                    start = event["introduced"]
                elif set(event) == {"fixed"} and start is not None:
                    fixed = event["fixed"]
                    if start != "0" and Version(start) >= Version(fixed):
                        raise ValueError(f"Invalid interval for {aid}")
                    url = f"https://api.deps.dev/v3/systems/PYPI/packages/{name}/versions/{fixed}"
                    release = fetch(session, url)
                    ranges.append(dict(introduced=start, fixed=fixed, source=url, published=release["publishedAt"]))
                    start = None
                else:
                    raise ValueError(f"Review range event for {aid}: {event}")
            if start is not None:
                raise ValueError(f"Review open interval for {aid}")
    if len(names) != 1 or not ranges:
        raise ValueError(f"Review package mapping for {aid}")
    return dict(id=aid, name=names.pop(), title=a["summary"], aliases=a["aliases"],
                osv_level=a["database_specific"]["severity"], published=a["published"],
                modified=a["modified"], cve=cve, nvd_score=metric["cvssData"]["baseScore"],
                nvd_author=metric["source"], nvd_modified=n["lastModified"], ranges=ranges)


def main():
    records = []
    with requests.Session() as session:
        session.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1,
                      status_forcelist=(429, 500, 502, 503, 504))))
        for aid in IDS:
            if records:
                time.sleep(7)
            records.append(collect(session, aid))
    snapshot = dict(retrieved=datetime.now(timezone.utc).isoformat(), records=records)
    destination = ROOT / "data/snapshot.json"
    temp = destination.with_suffix(".tmp")
    temp.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    temp.replace(destination)


if __name__ == "__main__":
    main()
