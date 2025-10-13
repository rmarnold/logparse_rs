# Anonymization

The anonymizer lets you replace sensitive field values deterministically while keeping analytical value.

Supported modes per field:
- tokenize (default): produce a stable token like `T_<hash>`
- map: replace known values from a map, and control fallback behavior
- fixed: always use a fixed replacement string

Global defaults can be overridden per-field.

## Config format

JSON schema for the anonymizer configuration (version 1):

```json
{
  "version": 1,
  "defaults": {
    "mode": "tokenize",            
    "fixed": null,                  
    "tokenize": { "prefix": "T_", "salt": "pepper" }
  },
  "fields": {
    "username": {
      "mode": "map",
      "map": { "alice": "A" },
      "fallback": "tokenize",     
      "tokenize": { "prefix": "U_" }
    },
    "ip": {
      "mode": "tokenize",
      "tokenize": { "prefix": "IP_" }
    },
    "fixed_field": {
      "mode": "fixed",
      "fixed": "REDACTED"
    },
    "reject_field": {
      "mode": "map",
      "map": {},
      "fallback": "reject"
    }
  }
}
```

Notes:
- `tokenize.prefix` sets the token prefix; `salt` allows project-specific deterministic tokens.
- `fallback` when `mode=map` decides behavior for unknown values: `tokenize` (default), `fixed`, or `reject`.
- The anonymizer maintains an in-memory integrity table you can export.

## Python usage

```python
import logparse_rs as lp
lp.load_schema("schema.json")
lp.load_anonymizer("anon.json")

res = lp.parse_kv_enriched_anon("ts,serial,TRAFFIC,allow,10.0.0.1,10.0.0.2,...")
print(res["_anonymized"])     # True
print(res["parsed"]["src_ip"]) # e.g., "IP_..." if configured

status = lp.get_anonymizer_status()  # {"enabled": True, "fields": N, "pairs": M}
itable = lp.export_integrity_table()  # {"field": {"original": "replacement", ...}}
```

Performance tips:
- Load the anonymizer once and reuse. The integrity table grows lazily and ensures identical inputs map to identical outputs.
