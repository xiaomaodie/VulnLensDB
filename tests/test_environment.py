"""Integration check against the real MySQL service in CI or Codespaces."""

import os

import pytest

from backend.app import app


@pytest.mark.skipif(not os.environ.get("DB_PASSWORD"), reason="MySQL credentials are not configured")
def test_api_connects_to_mysql_8():
    with app.test_client() as client:
        response = client.get("/health/db")
    assert response.status_code == 200, response.get_json()
    assert response.get_json()["version"].startswith("8."), response.get_json()
