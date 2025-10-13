// schema.rs: schema types and cache/loader
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::RwLock;
use std::time::SystemTime;

#[derive(Deserialize)]
pub struct SchemaRoot {
    #[serde(rename = "palo_alto_syslog_fields", default)]
    pub palo_alto_syslog_fields: PaloAltoSyslogFields,
}

#[derive(Deserialize, Default)]
pub struct PaloAltoSyslogFields {
    #[serde(default)]
    pub log_types: HashMap<String, LogTypeDef>,
}

#[derive(Deserialize)]
pub struct LogTypeDef {
    pub type_value: String,
    #[allow(dead_code)]
    pub description: Option<String>,
    #[allow(dead_code)]
    pub field_count: Option<usize>,
    pub fields: Vec<FieldDef>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum FieldDef { Str(String), Obj { name: String } }

pub(crate) fn sanitize_identifier(name: &str) -> String {
    let mut s = name.trim().to_lowercase();
    s = s.replace(' ', "_").replace('/', "_").replace('-', "_");
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' { out.push(ch); } else { out.push('_'); }
    }
    if out.is_empty() || !(out.chars().next().unwrap().is_ascii_alphabetic() || out.starts_with('_')) {
        out.insert(0, '_');
    }
    out
}

pub struct LoadedSchema {
    pub path: String,
    pub mtime: Option<SystemTime>,
    pub type_to_fields: HashMap<String, Vec<String>>, // key: type_value
}

pub static SCHEMA_CACHE: Lazy<RwLock<Option<LoadedSchema>>> = Lazy::new(|| RwLock::new(None));

fn build_type_to_fields(root: SchemaRoot) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for (_name, def) in root.palo_alto_syslog_fields.log_types.into_iter() {
        let mut fields: Vec<String> = Vec::new();
        for f in def.fields.into_iter() {
            let raw = match f { FieldDef::Str(s) => s, FieldDef::Obj { name } => name };
            let key = sanitize_identifier(&raw);
            fields.push(key);
        }
        map.insert(def.type_value, fields);
    }
    map
}

fn read_mtime(path: &Path) -> Option<SystemTime> { fs::metadata(path).ok().and_then(|m| m.modified().ok()) }

pub fn load_schema_internal(schema_path: &str) -> Result<LoadedSchema, String> {
    let data = fs::read_to_string(schema_path).map_err(|e| format!("Failed to read schema {}: {}", schema_path, e))?;
    let root: SchemaRoot = serde_json::from_str(&data).map_err(|e| format!("Failed to parse schema JSON: {}", e))?;
    let type_to_fields = build_type_to_fields(root);
    let mtime = read_mtime(Path::new(schema_path));
    Ok(LoadedSchema { path: schema_path.to_string(), mtime, type_to_fields })
}

pub fn ensure_schema_loaded(schema_path: &str) -> Result<(), String> {
    let mut guard = SCHEMA_CACHE.write().unwrap();
    let need_reload = match guard.as_ref() {
        None => true,
        Some(ls) => {
            if ls.path != schema_path { true } else {
                let current = read_mtime(Path::new(schema_path));
                current != ls.mtime
            }
        }
    };
    if need_reload {
        let loaded = load_schema_internal(schema_path)?;
        *guard = Some(loaded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sanitize_identifier;

    #[test]
    fn test_sanitize_identifier() {
        assert_eq!(sanitize_identifier("Src IP"), "src_ip");
        assert_eq!(sanitize_identifier("src-ip"), "src_ip");
        assert_eq!(sanitize_identifier("9bad"), "_9bad");
        assert_eq!(sanitize_identifier(""), "_");
    }
}
