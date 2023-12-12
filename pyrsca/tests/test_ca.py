import os
import pyrsca
import pytest

@pytest.fixture
def pfx_path():
    return os.environ.get("PFX_PATH", "Sinopac.pfx")

@pytest.fixture
def password():
    return os.environ.get("PFX_PASSWORD", "")

def test_get_person_id(pfx_path: str, password: str):
    ca = pyrsca.PyTWCA(pfx_path, password)
    person_id = ca.get_person_id()
    assert person_id == password