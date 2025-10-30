// parser.rs: map a CSV log line to a key->value map using a loaded schema
use std::collections::HashMap;

use crate::schema::LoadedSchema;
use crate::tokenizer::{extract_field_internal, split_csv_internal};

pub fn parse_line_to_map(
    line: &str,
    schema: &LoadedSchema,
) -> Result<HashMap<String, Option<String>>, String> {
    let t = extract_field_internal(line, 3)
        .ok_or_else(|| "Could not extract log type at index 3".to_string())?;
    let field_names = schema
        .type_to_fields
        .get(&t)
        .ok_or_else(|| format!("Unknown log type in schema: {}", t))?;
    let fields = split_csv_internal(line);
    let mut map_out: HashMap<String, Option<String>> = HashMap::new();
    for (i, name) in field_names.iter().enumerate() {
        let v = if i < fields.len() { Some(fields[i].clone()) } else { None };
        map_out.insert(name.clone(), v);
    }
    Ok(map_out)
}

#[cfg(test)]
mod tests {
    use super::parse_line_to_map;
    use crate::schema::LoadedSchema;
    use std::collections::HashMap;

    #[test]
    fn test_parse_line_to_map_with_schema() {
        // build a minimal LoadedSchema with a type -> fields mapping
        let mut type_to_fields: HashMap<String, Vec<String>> = HashMap::new();
        type_to_fields.insert(
            "TRAFFIC".to_string(),
            vec!["f0".to_string(), "f1".to_string(), "f2".to_string(), "f3".to_string()],
        );
        let loaded = LoadedSchema { path: "mem".to_string(), mtime: None, type_to_fields };
        let line = "x,y,z,TRAFFIC,sub,foo,bar,baz";
        let map = parse_line_to_map(line, &loaded).expect("parse map");
        assert_eq!(map.get("f0").unwrap().as_deref(), Some("x"));
        assert_eq!(map.get("f1").unwrap().as_deref(), Some("y"));
        assert_eq!(map.get("f2").unwrap().as_deref(), Some("z"));
        assert_eq!(map.get("f3").unwrap().as_deref(), Some("TRAFFIC"));
    }
}
