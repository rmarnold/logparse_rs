# Installation

## Python (logparse-rs)

Install the prebuilt wheel from PyPI (recommended):

```
pip install logparse-rs
```

Notes:
- Requires Python 3.9–3.12 on Linux, macOS, or Windows.
- Wheels are compiled with Rust/PyO3.
- If a wheel is not available for your platform, `pip` may try to build from source; in that case you need a Rust toolchain (rustup) and maturin. Prefer a wheel if possible.

Alternatively, install from a GitHub Release artifact (wheel or sdist):
1. Download a suitable wheel for your OS/Python version from the repository Releases.
2. Install with `pip install path/to/wheel.whl`.

## Rust (logparse_core)

Add the crate to your `Cargo.toml`:

```
cargo add logparse_core
```

Or manually:

```
[dependencies]
logparse_core = "*"
```

## Local development

- Rust: Install the Rust toolchain via https://rustup.rs/
- Python: For building wheels locally use `maturin`:

```
pip install maturin
maturin develop -m bindings/python/Cargo.toml
```

This will build and install the Python extension into your current virtual environment for iterative development.
