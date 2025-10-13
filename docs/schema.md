# Schema format

The parser maps CSV fields into named keys using a JSON schema. The built-in example follows a Palo Alto Networks style, but the library is generic.

Top-level shape:

```json
{
  "palo_alto_syslog_fields": {
    "log_types": {
      "TRAFFIC": {
        "type_value": "TRAFFIC",
        "description": "Traffic logs",
        "field_count": 72,
        "fields": [
          "time_generated", "serial", "type", "subtype", "src_ip", "dst_ip"
        ]
      },
      "THREAT": {
        "type_value": "THREAT",
        "fields": ["time_generated", "serial", "type", "subtype", "misc"]
      }
    }
  }
}
```

Rules:
- `log_types` is a map of logical record types by name; each entry has:
  - `type_value`: the literal string found in your CSV line that identifies the type (e.g., at index 3 in many PAN-OS logs)
  - `fields`: list of field names in order (strings or objects `{ "name": "..." }`)
  - optional `description` and `field_count`
- Field names are sanitized:
  - trimmed, lowercased, spaces and punctuation replaced with `_`
  - must start with a letter or `_` — otherwise an `_` is prefixed

Loader behavior:
- On first load `load_schema(path)` parses the file and builds an in-memory mapping: `type_value -> [field_names...]`.
- `parse_kv*` extracts the type (at index 3 by convention), selects the field list for that type, splits the CSV line, and builds a dict.
- Missing trailing fields are returned as `None`.

Hot-reload semantics:
- `parse_kv_with_schema(..., schema_path)` and `parse_kv_enriched_with_schema(..., schema_path)` call `ensure_schema_loaded`, which reloads when the file’s mtime changes.

Example minimal schema:

```json
{
  "palo_alto_syslog_fields": {
    "log_types": {
      "TRAFFIC": { "type_value": "TRAFFIC", "fields": ["f0", "f1", "f2", "f3"] }
    }
  }
}
```
