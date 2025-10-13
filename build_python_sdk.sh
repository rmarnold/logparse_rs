#!/usr/bin/env bash
set -e

# Build script for logparse_rs Python SDK
# Based on README.md instructions for local development

echo "🔧 Building logparse_rs Python SDK locally..."
echo ""

# Check prerequisites
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: Rust toolchain not found. Please install rustup/cargo first."
    echo "   Visit: https://rustup.rs/"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 not found. Please install Python 3.9+ first."
    exit 1
fi

echo "✅ Prerequisites check passed"
echo "   Rust: $(cargo --version)"
echo "   Python: $(python3 --version)"
echo ""

# Navigate to Python bindings directory
cd "$(dirname "$0")/bindings/python"

# Handle Conda environment if present
if [ -n "$CONDA_PREFIX" ]; then
    echo "⚠️  Conda environment detected. Unsetting CONDA_PREFIX for this build..."
    unset CONDA_PREFIX
fi

# Check if uv is available
if command -v uv &> /dev/null; then
    echo "📦 Using uv (fast Python package manager)..."

    # Create venv if it doesn't exist
    if [ ! -d ".venv" ]; then
        echo "   Creating virtual environment..."
        uv venv .venv
    fi

    # Activate venv and unset any remaining VIRTUAL_ENV to avoid conflicts
    echo "   Activating virtual environment..."
    unset VIRTUAL_ENV
    source .venv/bin/activate

    # Check if maturin is installed in the venv
    if ! python -c "import maturin" &> /dev/null; then
        echo "   Installing maturin..."
        uv pip install maturin
    fi

    # Build with maturin
    echo "🔨 Building extension module (release mode)..."
    maturin develop --release

else
    echo "📦 Using standard Python venv (uv not found)..."

    # Create venv if it doesn't exist
    if [ ! -d ".venv" ]; then
        echo "   Creating virtual environment..."
        python3 -m venv .venv
    fi

    # Activate venv and unset any remaining VIRTUAL_ENV to avoid conflicts
    echo "   Activating virtual environment..."
    unset VIRTUAL_ENV
    source .venv/bin/activate

    # Install maturin if not present
    if ! python -c "import maturin" &> /dev/null; then
        echo "   Installing maturin..."
        pip install maturin
    fi

    # Build with maturin
    echo "🔨 Building extension module (release mode)..."
    maturin develop --release
fi

echo ""
echo "✅ Build complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Activate the virtual environment:"
echo "      source bindings/python/.venv/bin/activate"
echo "   2. Test the installation:"
echo "      python -c 'import logparse_rs; print(logparse_rs.__doc__)'"
echo "   3. Run your Python scripts using the logparse_rs module"
echo ""
echo "💡 Tip: Install uv for faster builds:"
echo "   curl -LsSf https://astral.sh/uv/install.sh | sh"
