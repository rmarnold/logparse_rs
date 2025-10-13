# Quickstart

This page shows minimal, end-to-end examples for both Python and Rust.

## Python

```python
import json
import logparse_rs as lp

# 1) Load a schema (see the Schema page for format)
assert lp.load_schema("schema.json")

# 2) Parse a CSV log line into a dict of fields
line = "2025/10/12 05:07:29,serial,THREAT,subtype,..."
parsed = lp.parse_kv(line)
print(parsed["type"])  # e.g., "THREAT"

# 3) Enriched parsing with metadata
res = lp.parse_kv_enriched(line)
print(res["parsed"]["src_ip"])  # if defined in your schema
print(res["hash64"])             # 64-bit hash of the raw line

# 4) Optional anonymization
ok = lp.load_anonymizer("anon.json")
res_anon = lp.parse_kv_enriched_anon(line)
print(res_anon["_anonymized"])   # True

# 5) Inspect current status
print(lp.get_schema_status())      # { "loaded": True, "path": ..., "types": N, ... }
print(lp.get_anonymizer_status())  # { "enabled": True, "fields": N, "pairs": M }
```

## Rust

```rust
use logparse_core::{load_schema_internal, parse_line_to_map};

fn main() -> Result<(), String> {
    let schema = load_schema_internal("schema.json")?;
    let line = "2025/10/12 05:07:29,serial,TRAFFIC,allow,...";
    let map = parse_line_to_map(line, &schema)?;
    println!("src={}, dst={}",
        map.get("src_ip").and_then(|v| v.as_ref()).unwrap_or("-"),
        map.get("dst_ip").and_then(|v| v.as_ref()).unwrap_or("-"),
    );
    Ok(())
}
```

Tips:
- See Environment for preloading schema/anonymizer via env vars.
- See Anonymization for config examples.
