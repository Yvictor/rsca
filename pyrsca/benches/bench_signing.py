import os
import pytest
from pyrsca import PyTWCA

@pytest.fixture(scope="module")
def twca():
    pfx_path = os.environ.get("PFX_PATH")
    password = os.environ.get("PFX_PASSWORD")
    if not pfx_path or not password:
        pytest.skip("PFX_PATH or PFX_PASSWORD not set in environment")
    return PyTWCA(pfx_path, password, "192.168.1.1")

def test_sign_pkcs7_benchmark(benchmark, twca):
    """Benchmark for PKCS7 signing (the `sign` method)."""
    result = benchmark(twca.sign, "benchmark test data for pkcs7")
    assert result is not None

def test_sign_pkcs1_benchmark(benchmark, twca):
    """Benchmark for PKCS1 signing."""
    result = benchmark(twca.sign_pkcs1, "benchmark test data for pkcs1")
    assert result is not None 