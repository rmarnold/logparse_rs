# Troubleshooting

## ValueError: No schema loaded

Call `load_schema(path)` once before parsing, or use the `*_with_schema(...)` variants which will ensure the schema is loaded.

## Unknown log type in schema: X

Your CSV line contains a `type` field (commonly at index 3) whose value is not defined in your schema’s `log_types`. Add an entry with matching `type_value` and corresponding field list.

## Could not extract log type at index 3

The parser expects the log type at a fixed index (3) for schema selection. Ensure your schema and input lines follow the same convention. You can still use `split_csv` and `extract_field` to inspect inputs.

## Anonymizer not enabled

Load it with `load_anonymizer(path)` or `set_anonymizer_json(json_str)`. Use `get_anonymizer_status()` to verify.

## Performance considerations

- Preload schema and anonymizer via environment variables to avoid per-process cold starts.
- Use `parse_kv_enriched` to get detailed timing (`parse_ns`, `anonymize_ns`) for profiling.
- Keep the anonymizer config lean; per-field maps are cached but very large maps can grow memory usage.
