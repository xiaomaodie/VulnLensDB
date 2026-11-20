import os
import pytest
from backend.app import app
from backend.catalog import initialize
from backend.views import affected, REPORTS


def test_pep440_and_exclusive_upper_bound():
    assert affected("3.2.9", "3.2", "3.2.13")
    assert not affected("3.2.13", "3.2", "3.2.13")
    assert not affected("3.1", "3.2", "3.2.13")
    assert affected("1.0rc1", "0", "1.0")


@pytest.mark.skipif(not os.getenv("DB_PASSWORD"), reason="integration requires course MySQL")
def test_snapshot_pages_and_pins():
    initialize()
    initialize()
    client = app.test_client()
    assert b"SQL Injection in Django" in client.get("/?q=PYSEC-2022-190").data
    assert b"2.2.28" in client.get("/advisories/GHSA-2gwj-7jmv-h26r").data
    assert client.get("/advisories/missing").status_code == 404
    for view in REPORTS:
        assert client.get("/reports", query_string={"view": view}).status_code == 200
    page = client.post("/check", data={"pins":"django==3.2.9\ndjango==3.2.13\nunknown==1"})
    assert page.status_code == 200
    result = page.get_data(as_text=True)
    assert result.count("CVE-2022-28346") == 1
    assert "本快照未命中" in result and "包未收录" in result
    assert client.post("/check", data={"pins":"django>=3"}).status_code == 400
