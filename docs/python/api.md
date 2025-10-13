# Python API Reference

The `logparse_rs` module exposes the following functions. Import it as:

```python
import logparse_rs as lp
```

## Schema-driven parsing

- load_schema(schema_path: str) -> bool
  - Load a JSON schema from disk into a process-wide cache. Returns True on success; raises ValueError on error.

- parse_kv(line: str) -> dict[str, Optional[str]]
  - Parse one CSV log line into a dict of field_name -> value (or None if missing). Requires a previously loaded schema.

- parse_kv_with_schema(line: str, schema_path: str) -> dict[str, Optional[str]]
  - Convenience method that ensures the given schema is loaded (reloads if changed) and parses the line in one call.

- parse_kv_enriched(line: str) -> dict
  - Like parse_kv, but returns a dict with:
    - parsed: dict[str, Optional[str]] — the parsed fields
    - raw_excerpt: str — up to the first 256 chars of the raw line
    - hash64: int — 64-bit FNV-1a hash of the raw line (as Python int)
    - parse_ns: int — time spent parsing in nanoseconds
    - runtime_ns_total: int — total runtime in nanoseconds

- parse_kv_enriched_with_schema(line: str, schema_path: str) -> dict
  - As above, but ensures the given schema is loaded.

- get_schema_status() -> dict
  - Returns schema loader state, e.g., { "loaded": True/False, "path": str, "types": int }

## CSV helpers

- extract_field(line: str, index: int) -> Optional[str]
  - Return the N-th field (0-based) from a CSV line, respecting quotes; None if out of bounds.

- extract_type_subtype(line: str) -> tuple[Optional[str], Optional[str]]
  - Convenience: returns the "type" and "subtype" fields commonly present in vendor logs. Both may be None.

- split_csv(line: str) -> list[str]
  - Quote-aware fast splitter. All fields are returned as strings (may be empty strings).

## Anonymizer

- load_anonymizer(config_path: str) -> bool
  - Load anonymizer configuration from a JSON file. Returns True on success.

- set_anonymizer_json(config_json: str) -> bool
  - Load anonymizer configuration directly from a JSON string.

- get_anonymizer_status() -> dict
  - If enabled, returns { "enabled": True, "fields": N, "pairs": M } where pairs is the total integrity table size.

- export_integrity_table() -> dict[str, dict[str, str]]
  - Export the integrity table mapping: field -> { original_value: replacement }. Useful for audits.

- parse_kv_enriched_anon(line: str) -> dict
  - Enriched parse with anonymization enabled (if config loaded). Adds `_anonymized: True` and `anonymize_ns` to timings.

- parse_kv_enriched_with_schema_anon(line: str, schema_path: str) -> dict
  - Same as above, ensuring the given schema is loaded.

## Exceptions

Most functions return simple booleans or dicts. Errors such as a missing schema surface as `ValueError` from Rust via PyO3.

## Example

```python
import logparse_rs as lp
lp.load_schema("schema.json")
res = lp.parse_kv_enriched("ts,serial,TRAFFIC,allow,src,dst,...")
print(res["parsed"]["src_ip"])  # may be None if not present/defined by schema
```
