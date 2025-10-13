# Python SDK Overview

The `logparse-rs` Python package provides a fast, schema-driven log parser implemented in Rust and exposed via PyO3.

Key capabilities:
- Load a JSON schema and map CSV log lines into named fields
- Robust CSV handling (quotes, embedded commas)
- Enriched parse results with raw excerpt, 64-bit hash, and timing
- Optional field anonymization with deterministic tokens or fixed replacements
- Simple helpers for CSV-level operations (split a line, extract fields)

Typical workflow:
1. `load_schema(path)` — load a schema once
2. `parse_kv(...)` or `parse_kv_enriched(...)` — parse lines at high throughput
3. Optional: `load_anonymizer(...)` — anonymize selected fields
4. Export `export_integrity_table()` for audit/compliance if needed

Environment-based preload:
- `LOGPARSE_PRELOAD_SCHEMA` or `SCHEMA_JSON_PATH` — preload schema on import
- `LOGPARSE_ANON_CONFIG` — preload anonymizer config on import

See the API Reference for the full list of functions.
