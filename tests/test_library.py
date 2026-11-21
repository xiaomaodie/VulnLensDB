import io
import os
import re
import uuid
import pytest
from backend.app import app
from backend.library import classify,parse_pins,QUERIES


def test_version_boundaries():
    span=[dict(introduced="3.2",end_type="fixed",endpoint="3.2.13")]
    assert classify("PyPI","3.2.9",set(),span)[0]=="命中"
    assert classify("PyPI","3.2.13",set(),span)[0]=="未命中"
    span=[dict(introduced="0",end_type="last_affected",endpoint="1.2.0")]
    assert classify("Go","v1.2.0",set(),span)[0]=="命中"
    assert classify("Maven","2.0-RC1",set(),span)[0]=="待核对"
    assert classify("Maven","2.0-RC1",{"2.0-RC1"},span)[0]=="命中"


@pytest.mark.skipif(not os.getenv("DB_PASSWORD"),reason="requires MySQL snapshot")
def test_library_end_to_end():
    c=app.test_client()
    assert "去重公告" in c.get("/library").get_data(as_text=True)
    page=c.get("/library/advisory/CVE-2021-44228").get_data(as_text=True)
    assert "log4j-core" in page and "CPE" in page and "versionEndExcluding" in page
    for key in QUERIES:assert c.get("/library/reports",query_string={"view":key}).status_code==200
    assert c.get("/library/sources").status_code==200
    assert c.get("/library?eco=Go&sort=score&page=2").status_code==200
    xml=b"<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>"
    response=c.post("/library/check",data={"upload":(io.BytesIO(xml),"pom.xml"),"format":"csv"})
    assert response.status_code==200 and "text/csv" in response.content_type and "命中" in response.get_data(as_text=True)
    assert c.post("/library/check",data={"pins":"foo>=3"}).status_code==400
    page=c.get("/account").get_data(as_text=True)
    token=re.search(r'name="_token" value="([^"]+)',page)[1]
    response=c.post("/account",data={"op":"register","username":"test_"+uuid.uuid4().hex[:12],
        "password":"test-long-password","_token":token},follow_redirects=True)
    assert response.status_code==200 and "注册用户" in response.get_data(as_text=True)
    token=re.search(r'name="_token" value="([^"]+)',response.get_data(as_text=True))[1]
    assert c.post("/account/refresh-stats",data={"_token":token}).status_code==403
    assert c.post("/library/check",data={"eco":"PyPI","pins":"django==3.2.9","save":"yes","_token":token}).status_code==200
    assert "暂无保存记录" not in c.get("/account").get_data(as_text=True)


@pytest.mark.skipif(not os.getenv("DB_PASSWORD"), reason="requires MySQL snapshot")
@pytest.mark.parametrize("query,ecosystem", [
    ("jang", "PyPI"),            # Inside the package name django.
    ("cve-2021-4422", "Maven"),  # Incomplete, mixed-case advisory identifier.
    ("njectio", "PyPI"),         # Inside a title word, not a FULLTEXT token.
])
def test_search_matches_partial_terms(query, ecosystem):
    with app.test_client() as client:
        page = client.get("/library", query_string={"q": query, "eco": ecosystem})
    assert page.status_code == 200
    assert re.search(r"共 [1-9][0-9]* 条", page.get_data(as_text=True))


@pytest.mark.skipif(not os.getenv("DB_PASSWORD"), reason="requires MySQL snapshot")
def test_search_treats_sql_wildcards_as_literals():
    with app.test_client() as client:
        page = client.get("/library", query_string={"q": "%_%_!"})
    assert page.status_code == 200
    assert "共 0 条" in page.get_data(as_text=True)


@pytest.mark.skipif(not os.getenv("DB_PASSWORD"), reason="requires MySQL snapshot")
def test_package_home_and_version_check():
    from html.parser import HTMLParser

    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.packages = []

        def handle_starttag(self, tag, attrs):
            href = dict(attrs).get("href", "")
            if tag == "a" and href.startswith("/packages/"):
                self.packages.append(href)

    with app.test_client() as client:
        listing = client.get("/", query_string={"q": "pillow"}).get_data(as_text=True)
        links = Links()
        links.feed(listing)
        assert links.packages[0] == "/packages/PyPI/pillow"
        assert links.packages.count("/packages/PyPI/pillow") == 1
        assert "Python 图片处理库" in listing
        detail = client.get(links.packages[0]).get_data(as_text=True)
        assert 'id="releases"' in detail and "全部历史公告" in detail
        check_page = client.get(links.packages[0], query_string={"version": "10.3.0"})
        assert check_page.status_code == 200
        assert re.search(r"10\.3\.0 命中 [0-9]+ 条公告", check_page.get_data(as_text=True))
        assert client.get(links.packages[0], query_string={"version": ">>"}).status_code == 400
        assert client.get("/library", query_string={"q": "44228"}).status_code == 200
