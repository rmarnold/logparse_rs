# logparse-rs

High-performance, schema-driven log parsing and optional anonymization — Rust core with first-class Python bindings.

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-blue?logo=github)](./.github/workflows)
[![Crates.io](https://img.shields.io/crates/v/logparse_core.svg)](https://crates.io/crates/logparse_core)
[![PyPI](https://img.shields.io/pypi/v/logparse-rs.svg)](https://pypi.org/project/logparse-rs/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

This repository is a small monorepo:
- crates/logparse_core — pure Rust engine for CSV tokenization, schema-driven KV parsing, hashing, and anonymization primitives.
- bindings/python — Python SDK (PyO3 + maturin) exposing the core to Python with a friendly API.

Features:
- Quote-aware CSV tokenizer (Rust, memchr-accelerated)
- Schema-driven KV parsing (load at runtime from JSON)
- Enriched results with raw excerpts and stable 64-bit hash
- Optional anonymization with deterministic replacements and integrity table
- Environment-based preloading for hot paths

This SDK is source-agnostic: you can provide your own schema describing log fields and types. A Palo Alto Networks schema can be used as an example, but the library is not tied to PAN-OS.

## Table of contents
- Overview
- Features
- Installation
  - Python (wheels)
  - Rust (crate)
  - Local development
- Quickstart
  - Python
  - Rust
- API Overview
- Environment Variables
- Schema Expectations
- Anonymizer Config
- Troubleshooting
- Contributing
- Versioning & Releases
- Roadmap
- Security
- License
- Changelog

## Repository layout
```
repo/
  Cargo.toml                 # workspace
  crates/
    logparse_core/           # pure Rust core, publish to crates.io
  bindings/
    python/                  # PyO3 bindings, publish wheels to PyPI
```

## Packages
- Rust crate: logparse_core (library)
- Python package: logparse-rs (binary extension built with PyO3)

## Status
- Rust core: stable API surface for CSV split/extract, schema-driven parsing, FNV-1a hash, anonymizer primitives.
- Python bindings: stable for core flows; APIs may evolve prior to 1.0.

## Links
- Crate: https://crates.io/crates/logparse_core
- PyPI: https://pypi.org/project/logparse-rs/
- Issues: https://github.com/<your-org>/logparse_rs/issues

## Install (local dev)

Recommended: use uv (fast Python package manager and venv)

- Prerequisites: Rust toolchain (rustup/cargo) and Python (3.9–3.13).
- Install uv
  - macOS/Linux:
    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```
  - Windows (PowerShell):
    ```powershell
    irm https://astral.sh/uv/install.ps1 | iex
    ```
- Create and activate a virtual environment for this project:
  ```bash
  cd bindings/python
  uv venv .venv
  source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
  ```
- Optional: pin a specific Python version (e.g., 3.12) and recreate the venv:
  macOS/Linux:
  ```bash
  uv python pin 3.12
  rm -rf .venv && uv venv .venv
  source .venv/bin/activate 
  ```
  Windows (PowerShell):
  ```powershell
  uv python pin 3.12
  Remove-Item -Recurse -Force .venv; uv venv .venv
  ```
- Build and install the Rust extension into this env:
  - Option A (no install): use uvx to run maturin ad-hoc
    ```bash
    uvx maturin develop --release
    ```
  - Option B: install maturin into the env and run it
    ```bash
    uv pip install maturin
    maturin develop --release
    ```

This builds and installs the `logparse_rs` extension module into your active environment.

Alternative: pip + venv (if you prefer not to use uv)

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
pip install maturin
maturin develop --release
```

Notes:
- Avoid mixing multiple Python environments (e.g., Conda base + a venv). Prefer activating only the uv-created .venv when building native extensions.
- If you see linker or Python version errors, ensure your active interpreter matches the environment where maturin runs (print with `python -V` and `which python`).

## Quickstart

```python
import json
import logparse_rs as lp

# Load a schema file
lp.load_schema("path/to/your_schema.json")

# Parse a CSV line (enriched)
res = lp.parse_kv_enriched("1,2025/10/12 05:07:29,...")
print(res["parsed"]["source_address"])  # if defined in your schema

# Anonymization (optional)
lp.set_anonymizer_json(json.dumps({
  "version": 1,
  "defaults": {"mode": "tokenize", "tokenize": {"prefix": "T_", "salt": "demo-salt"}},
  "fields": {"source_address": {"mode": "tokenize", "tokenize": {"prefix": "SRC_"}}}
}))
res2 = lp.parse_kv_enriched_anon("1,2025/10/12 05:07:29,...")
print(res2["parsed"]["source_address"])  # anonymized
```

## API Overview

- CSV helpers: `split_csv`, `extract_field`, `extract_type_subtype`
- Schema: `load_schema`, `parse_kv`, `parse_kv_with_schema`, `parse_kv_enriched`, `parse_kv_enriched_with_schema`, `get_schema_status`
- Anonymizer: `load_anonymizer`, `set_anonymizer_json`, `get_anonymizer_status`, `export_integrity_table`, `parse_kv_enriched_anon`, `parse_kv_enriched_with_schema_anon`

## Environment Variables (preload)

- `LOGPARSE_PRELOAD_SCHEMA` or `SCHEMA_JSON_PATH` (and legacy `PAN_RUST_PRELOAD_SCHEMA`): path to a schema JSON to load at import-time
- `LOGPARSE_ANON_CONFIG` (and legacy `PAN_RUST_ANON_CONFIG`): path to an anonymizer JSON to load at import-time

## Schema Expectations

The current parser expects a JSON structure that defines log `log_types`, each with a `type_value` and a `fields` array of either strings or objects with a `name`. For example (simplified):

```json
{
  "palo_alto_syslog_fields": {
    "log_types": {
      "traffic": {
        "type_value": "TRAFFIC",
        "fields": [ {"name": "Source Address"}, {"name": "Destination Address"} ]
      }
    }
  }
}
```

Keys are sanitized (lowercased, spaces and slashes replaced with underscores), and positional order is preserved to maintain alignment with the CSV.

## Anonymizer Config

See the project root `datasets/anonymizer.sample.json` in the main repository as a reference; the SDK uses the same format:
- Modes: `fixed`, `map`, `tokenize`
- Deterministic tokens using a salt and a prefix
- Integrity table export for audits

## License

This project is licensed under the MIT License. See the LICENSE file for details.


## Included schemas

For convenience during local development, this SDK repository includes a reference Palo Alto Networks schema:
- Path: `schemas/palo_alto_schema.json`

You can load it directly:

```python
import logparse_rs as lp
lp.load_schema("schemas/palo_alto_schema.json")
```

Note: when installed as a wheel, only the compiled extension is shipped by default. Treat the included schema as a local example; in production, point `load_schema()` to your own schema file or manage schemas in your application repository. You can also set `LOGPARSE_PRELOAD_SCHEMA` to that path to auto-load on import.


## Troubleshooting

### Error: "Both VIRTUAL_ENV and CONDA_PREFIX are set. Please unset one of them"

Cause: this happens when a Conda environment (CONDA_PREFIX) is active at the same time as a virtualenv/uv venv (VIRTUAL_ENV). maturin refuses to proceed to avoid mixing ABIs.

Pick one environment strategy and ensure only one of these variables is set before running maturin.

Recommended: use the uv-created .venv (no Conda active)
- macOS/Linux:
  ```bash
  # If your shell auto-activates Conda base, deactivate it first
  conda deactivate || true
  # Verify CONDA_PREFIX is now unset
  echo ${CONDA_PREFIX:-<unset>}

  cd bindings/python
  uv venv .venv
  source .venv/bin/activate
  # Build (either approach works)
  uvx maturin develop --release
  # or, if you installed maturin into the venv:
  uv pip install maturin
  maturin develop --release
  ```
- Windows (PowerShell):
  ```powershell
  conda deactivate
  $env:CONDA_PREFIX  # should be blank

  cd bindings/python
  uv venv .venv
  .venv\Scripts\Activate.ps1
  uvx maturin develop --release
  # or
  uv pip install maturin
  maturin develop --release
  ```

Alternative: build entirely inside Conda (no .venv)
- macOS/Linux:
  ```bash
  conda create -n logparse-rs python=3.12 -y
  conda activate logparse-rs
  python -m pip install maturin
  cd bindings/python
  maturin develop --release
  ```
- Windows (PowerShell):
  ```powershell
  conda create -n logparse-rs python=3.12 -y
  conda activate logparse-rs
  python -m pip install maturin
  cd bindings/python
  maturin develop --release
  ```

Quick one-off fix (not recommended long-term): temporarily unset the conflicting variable just for the build command.
- If using a venv/.venv (keep VIRTUAL_ENV; drop Conda):
  - macOS/Linux:
    ```bash
    env -u CONDA_PREFIX maturin develop --release
    ```
  - Windows PowerShell:
    ```powershell
    Remove-Item Env:CONDA_PREFIX; maturin develop --release
    ```
- If using Conda (keep CONDA_PREFIX; drop venv):
  - macOS/Linux:
    ```bash
    env -u VIRTUAL_ENV maturin develop --release
    ```
  - Windows PowerShell:
    ```powershell
    Remove-Item Env:VIRTUAL_ENV; maturin develop --release
    ```

Verify your environment before building
```bash
python -V
which python        # (Get-Command python on PowerShell)
python -c "import os; print('VIRTUAL_ENV=', os.getenv('VIRTUAL_ENV')); print('CONDA_PREFIX=', os.getenv('CONDA_PREFIX'))"
```
You should see exactly one of VIRTUAL_ENV or CONDA_PREFIX set.


## Contributing
We welcome issues and pull requests! To get started locally:
- Install Rust (rustup) and Python 3.9+.
- For Python bindings development, see the Install (local dev) section above and use maturin via uv or pip.
- Run tests:
  - Rust core: `cargo test -p logparse_core`
  - Python (once wheels are built in develop mode): write usage examples or add tests under your project.
- Lint:
  - Rust: `cargo clippy -D warnings`

Please keep PRs focused, add tests where possible, and update docs if behavior changes.

## Versioning & Releases
- Rust crate (logparse_core): semantic versioning on crates.io.
- Python package (logparse-rs): mirrors core versions where possible; may have minor wrappers-only releases.
- Tags: consider `core-vX.Y.Z` and `py-vX.Y.Z` for clarity in CI.

## Roadmap
- Streaming parsers for very long lines
- Schema validation improvements and richer typing
- Additional bindings (Node via napi-rs)
- More anonymization modes and metrics

## Security
This project does not handle secrets directly, but anonymization makes deterministic replacements. Do not treat FNV-1a tokens as cryptographic hashes. Report security concerns privately via issues with minimal repro or your org’s preferred channel.

## Changelog
See Git history and release notes on GitHub Releases once publishing starts.
