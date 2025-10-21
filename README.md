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
- Unified intermediate representation (IR) bridging a JSON abstract schema and the Rust encoding algorithm at runtime
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
- Batch/streaming: `parse_many(...)`, `parse_file(...)`, `parse_many_parallel(...)`, `parse_file_parallel(...)`, `parse_file_to_ndjson(input_path, output_path, schema_path=None)`
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


## Benchmarking Rust acceleration

A simple benchmark script is included to compare Rust-accelerated parsing to the pure-Python fallback. It measures wall-clock time over multiple iterations and saves a plot.

Example:

```bash
python examples/benchmark.py \
  --file examples/sample_logs/pan_inc.log \
  --schema examples/schema/schema.json \
  --iterations 5 \
  --plot-out examples/benchmark.png
```

Notes:
- The script runs two modes: Rust (accel) and Python (no accel). It toggles an env var internally.
- You can also manually control the toggle in your own code using:
  - `LOGPARSE_RS_DISABLE_RUST=1` to force pure-Python path
  - unset or `LOGPARSE_RS_DISABLE_RUST=0` to use Rust if available
- Anonymized parsing requires the Rust anonymizer. In Python mode, anonymized runs are skipped.

### Advanced benchmarking and bottleneck analysis

For deeper insight (throughput, per-iteration timelines, internal parser time vs overhead, and a richer 4-panel plot), use:

```bash
python examples/benchmark_advanced.py \
  --file examples/sample_logs/pan_inc.log \
  --schema examples/schema/schema.json \
  --iterations 50 \
  --plot-out examples/benchmark_advanced.png
```

This script also prints JSON including:
- wall_ms statistics (mean/median/p90/p99/min/max)
- internal_ms_from_records (sum of per-record runtime_ns where available)
- cpu_time_ms (user+sys from the OS, when available)
- throughput_lines_per_sec_mean and a bottleneck_hint per mode

#### Parallel parsing (experimental)

#### Eliminating Python overhead with NDJSON streaming (new)

When your benchmarks show that Rust internal parser time is small and overall wall time is dominated by Python iteration or file I/O, you can offload the whole loop to Rust and write directly to disk as newline-delimited JSON (NDJSON):

```python
from logparse_rs import rust_accel

rust_accel.load_schema("examples/schema/schema.json")
# Parse and write NDJSON entirely in Rust (one FFI call per file)
out_lines = rust_accel.parse_file_to_ndjson(
    "examples/sample_logs/pan_inc.log",
    "reports/pan_inc.ndjson",
)
print("wrote", out_lines, "records")
```

The output records mirror `parse_kv_enriched()` shape (keys: `parsed`, `raw_excerpt`, `hash64`, `runtime_ns`). This path minimizes Python overhead and is ideal for large batch conversions or piping into downstream tools.

The Rust bindings include a parallel batch parser powered by Rayon. The advanced benchmark can use it for Rust mode:

```bash
python examples/benchmark_advanced.py \
  --file examples/sample_logs/pan_inc.log \
  --schema examples/schema/schema.json \
  --iterations 50 \
  --rust-parallel \
  --rayon-threads 8 \
  --batch-size 2048 \
  --plot-out examples/benchmark_advanced.png
```

- Set `--rayon-threads N` to override the thread count (defaults to number of CPU cores or `RAYON_NUM_THREADS`).
- `--batch-size` controls how many lines are processed per Rust call; increase for fewer crossings between Python and Rust.
- Programmatic API: `rust_accel.parse_file_parallel(path, batch_size=1024, rayon_threads=None, schema_path=...)` and `rust_accel.parse_many_parallel(iterable, ...)`.
- Limitations: current parallel fast path does not yet support anonymized parsing; it falls back to the sequential path for anonymized runs. Streaming output is chunked; memory usage scales with batch size.

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


## Exporting the anonymizer integrity table

If you enable anonymization, the library tracks a per-field integrity table mapping original values to their anonymized replacements. You can retrieve it (and optionally write it to JSON) from Python via the rust_accel helper:

```python
from logparse_rs import rust_accel

# After loading schema and anonymizer and processing some lines...
status = rust_accel.get_anonymizer_status()
print(status)  # {'enabled': True, 'fields': N, 'pairs': M}

# Get the integrity table as a nested dict
table = rust_accel.export_integrity_table()

# Or write it directly to a file (and also get the dict back)
path = 'integrity_table.json'
table = rust_accel.export_integrity_table(path)
print(f"Wrote {sum(len(v) for v in table.values())} pairs to {path}")
```

The integrity table has this shape:
- keys: field names (e.g., "src_ip", "user")
- values: dicts mapping original values to their replacement tokens or mapped values

Note: the table only contains entries for values that were actually anonymized during this run (it grows as more unique values are seen).


## Streaming and FastAPI HTTP syslog (example)

The SDK already supports streaming and batching in multiple ways:
- Stream any iterable: rust_accel.parse_many(iterable, ...)
- Stream a file: rust_accel.parse_file(path, ...)
- Batch/parallel in-memory: rust_accel.parse_many_parallel(iterable, batch_size=..., rayon_threads=...)
- End-to-end Rust NDJSON fast path: rust_accel.parse_file_to_ndjson(input_path, output_path, schema_path=None)

For ingesting syslog over HTTP, an example FastAPI app is included that runs a background loop ("hop loop") to batch lines and parse them efficiently:

Run the example server

1. Install FastAPI and uvicorn into the same environment where logparse_rs is installed:
   pip install fastapi uvicorn

2. Set optional environment variables:
   export SCHEMA_JSON_PATH=examples/schema/schema.json
   export OUT_NDJSON=examples/reports/syslog_ingest.ndjson
   export BATCH_SIZE=1024
   export RAYON_THREADS=8

3. Start the server:
   uvicorn examples.fastapi_http_syslog:app --reload --port 8000

4. Send messages:
   - Text (one or more lines):
     curl -X POST http://127.0.0.1:8000/syslog -H 'Content-Type: text/plain' --data-binary $'1,2025/10/12 05:07:29,TRAFFIC,...\n1,2025/10/12 05:07:31,THREAT,...'
   - JSON: {"message": "..."} or {"messages": ["..."]}
     curl -X POST http://127.0.0.1:8000/syslog -H 'Content-Type: application/json' -d '{"message":"1,2025/10/12 05:07:29,TRAFFIC,..."}'
   - Stream (chunked):
     curl -X POST http://127.0.0.1:8000/syslog/stream -H 'Content-Type: text/plain' --data-binary @examples/sample_logs/pan_inc.log

Endpoints provided by the example
- POST /syslog          : Ingests text/plain or application/json payloads; splits on newlines
- POST /syslog/stream   : Reads a streaming/chunked body and enqueues lines as they arrive
- GET  /healthz         : Basic health and queue stats
- GET  /metrics         : Simple text metrics

Implementation notes
- The background task batches lines from an asyncio.Queue and, when Rust is available, uses parse_kv_enriched_batch (Rayon-backed, no GIL) for speed; otherwise it falls back to sequential parsing.
- Enriched results are appended to OUT_NDJSON as NDJSON, mirroring parse_kv_enriched() output.
- This example is intentionally minimal and does not include durable queues or error logging. Adapt it for production.
