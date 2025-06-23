#!/bin/bash

# Development script for pyrsca with uv
# This script handles environment variable conflicts and provides common development commands

set -e

# Clear conda environment to avoid conflicts with uv
unset CONDA_PREFIX

# Activate uv virtual environment
source .venv/bin/activate

# Function to show help
show_help() {
    echo "PyRSCA Development Script"
    echo ""
    echo "Usage: ./dev.sh [command]"
    echo ""
    echo "Commands:"
    echo "  sync       - Install/update dependencies"
    echo "  dev        - Build in development mode"
    echo "  build      - Build release mode"
    echo "  test       - Run tests"
    echo "  clean      - Clean build artifacts"
    echo "  install    - Install package in editable mode"
    echo "  bench      - Run benchmarks"
    echo "  help       - Show this help"
    echo ""
}

# Parse command
case "${1:-help}" in
    "sync")
        echo "🔄 Syncing dependencies..."
        uv sync --dev
        ;;
    "dev")
        echo "🛠 Building in development mode..."
        uv run maturin develop
        ;;
    "build")
        echo "📦 Building release..."
        uv run maturin build --release
        ;;
    "test")
        echo "🧪 Running tests..."
        uv run pytest -v
        ;;
    "clean")
        echo "🧹 Cleaning build artifacts..."
        cargo clean
        rm -rf dist/
        rm -rf .pytest_cache/
        ;;
    "install")
        echo "📥 Installing in editable mode..."
        uv run maturin develop --release
        ;;
    "bench")
        echo "⏱️ Running benchmarks..."
        uv run pytest --benchmark-only benches/bench_signing.py
        ;;
    "help"|"--help"|"-h")
        show_help
        ;;
    *)
        echo "❌ Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac

echo "✅ Done!" 