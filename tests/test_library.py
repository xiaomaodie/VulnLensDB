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
    assert "去重公告" in c.get("/").get_data(as_text=True)
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
