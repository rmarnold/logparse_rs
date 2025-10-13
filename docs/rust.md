# Rust core (`logparse_core`)

The Rust crate powers the parsing and anonymization. It’s designed to be lightweight and easily embedded.

- Crate: https://crates.io/crates/logparse_core
- API docs: https://docs.rs/logparse_core/latest/logparse_core/

## Public API highlights

- schema
  - `load_schema_internal(path: &str) -> Result<LoadedSchema, String>`
  - `ensure_schema_loaded(path: &str) -> Result<(), String>` and a global `SCHEMA_CACHE`
- tokenizer
  - `split_csv_internal(line: &str) -> Vec<String>`
  - `extract_field_internal(line: &str, idx: usize) -> Option<String>`
- parser
  - `parse_line_to_map(line: &str, schema: &LoadedSchema) -> Result<HashMap<String, Option<String>>, String>`
- anonymizer
  - `anonymizer_from_json(json: &str) -> Result<AnonymizerCore, String>`
  - `AnonymizerCore::anonymize_one(field, original) -> Option<String>`

Utility:
- `hash64_fnv1a(bytes: &[u8]) -> u64`

## Example

```rust
use logparse_core::{load_schema_internal, parse_line_to_map};

fn example() -> Result<(), String> {
    let schema = load_schema_internal("schema.json")?;
    let map = parse_line_to_map("x,y,z,TRAFFIC,sub,foo,bar,baz", &schema)?;
    assert_eq!(map.get("f0").and_then(|v| v.as_ref()), Some(&"x".to_string()));
    Ok(())
}
```

For more details, see the docs.rs link above.
