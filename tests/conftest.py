import os
import pytest
from backend.library_db import DATA,load


@pytest.fixture(scope="session",autouse=True)
def library_snapshot():
    if os.getenv("DB_PASSWORD") and (DATA/"manifest.json").is_file():
        load()
