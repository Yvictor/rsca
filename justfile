bench-sign-rust:
    cd rsca && cargo bench --bench signing_benchmark

bench-sign-py:
    cd pyrsca && uv run maturin develop --release && uv run pytest --benchmark-only benches/bench_signing.py

test-rust:
    cd rsca && cargo test

test-py:
    cd pyrsca && uv run maturin develop --release && uv run pytest -v