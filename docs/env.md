# Environment variables

The Python module attempts to preload schema/anonymizer based on environment variables at import time. This is useful for short-lived processes or serverless environments.

Supported variables:

- LOGPARSE_PRELOAD_SCHEMA
- SCHEMA_JSON_PATH
- PAN_RUST_PRELOAD_SCHEMA

If any of the above is set to a readable path, the schema is loaded into the process-wide cache on module import.

- LOGPARSE_ANON_CONFIG
- PAN_RUST_ANON_CONFIG

If set to a readable path, an anonymizer configuration is loaded on module import.

Example:

```bash
export LOGPARSE_PRELOAD_SCHEMA=/etc/logparse/schema.json
export LOGPARSE_ANON_CONFIG=/etc/logparse/anon.json
python -c "import logparse_rs, json; print(json.dumps(logparse_rs.get_schema_status()))"
```
