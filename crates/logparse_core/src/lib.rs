// logparse_core: pure Rust library for CSV tokenization and schema-driven parsing + anonymization primitives.
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::RwLock;
use std::time::SystemTime;
use memchr::memchr;

// ---------------- Schema types and cache ----------------
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

fn sanitize_identifier(name: &str) -> String {
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

pub fn extract_field_internal(line: &str, target_idx: usize) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();
    let mut idx = 0usize;

    while idx <= target_idx && i <= n {
        if i >= n {
            if idx == target_idx { return Some(String::new()); } else { return None; }
        }
        let mut field = String::new();
        if bytes[i] == b'"' {
            i += 1;
            while i < n {
                let b = bytes[i];
                if b == b'"' {
                    if i + 1 < n && bytes[i + 1] == b'"' {
                        field.push('"');
                        i += 2;
                        continue;
                    } else {
                        i += 1;
                        break;
                    }
                } else {
                    field.push(b as char);
                    i += 1;
                }
            }
            while i < n && bytes[i] != b',' { i += 1; }
        } else {
            if let Some(pos) = memchr(b',', &bytes[i..]) {
                let end = i + pos;
                match std::str::from_utf8(&bytes[i..end]) {
                    Ok(s) => field.push_str(s),
                    Err(_) => field.extend((&bytes[i..end]).iter().map(|&b| b as char)),
                }
                i = end;
            } else {
                match std::str::from_utf8(&bytes[i..]) {
                    Ok(s) => field.push_str(s),
                    Err(_) => field.extend((&bytes[i..]).iter().map(|&b| b as char)),
                }
                i = n;
            }
        }
        if i < n && bytes[i] == b',' { i += 1; }
        if idx == target_idx { return Some(field); }
        idx += 1;
    }
    None
}

pub fn split_csv_internal(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();
    let mut out: Vec<String> = Vec::new();

    while i <= n {
        if i >= n {
            if n > 0 && bytes.get(n.wrapping_sub(1)) == Some(&b',') {
                out.push(String::new());
            }
            break;
        }
        let mut field = String::new();
        if bytes[i] == b'"' {
            i += 1;
            while i < n {
                let b = bytes[i];
                if b == b'"' {
                    if i + 1 < n && bytes[i + 1] == b'"' {
                        field.push('"');
                        i += 2;
                    } else {
                        i += 1;
                        break;
                    }
                } else {
                    field.push(b as char);
                    i += 1;
                }
            }
            while i < n && bytes[i] != b',' { i += 1; }
        } else {
            if let Some(pos) = memchr(b',', &bytes[i..]) {
                let end = i + pos;
                match std::str::from_utf8(&bytes[i..end]) {
                    Ok(s) => field.push_str(s),
                    Err(_) => field.extend((&bytes[i..end]).iter().map(|&b| b as char)),
                }
                i = end;
            } else {
                match std::str::from_utf8(&bytes[i..]) {
                    Ok(s) => field.push_str(s),
                    Err(_) => field.extend((&bytes[i..]).iter().map(|&b| b as char)),
                }
                i = n;
            }
        }
        if i < n && bytes[i] == b',' { i += 1; }
        out.push(field);
    }

    out
}

pub fn parse_line_to_map(line: &str, schema: &LoadedSchema) -> Result<HashMap<String, Option<String>>, String> {
    let t = extract_field_internal(line, 3).ok_or_else(|| "Could not extract log type at index 3".to_string())?;
    let field_names = schema.type_to_fields.get(&t).ok_or_else(|| format!("Unknown log type in schema: {}", t))?;
    let fields = split_csv_internal(line);
    let mut map_out: HashMap<String, Option<String>> = HashMap::new();
    for (i, name) in field_names.iter().enumerate() {
        let v = if i < fields.len() { Some(fields[i].clone()) } else { None };
        map_out.insert(name.clone(), v);
    }
    Ok(map_out)
}

pub fn hash64_fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for &b in bytes { hash ^= b as u64; hash = hash.wrapping_mul(0x100000001b3); }
    hash
}

// --------------- Anonymizer core types (no PyO3) ---------------
#[derive(Deserialize, Clone, Default)]
pub struct TokenizeCfg { pub prefix: Option<String>, pub salt: Option<String> }

#[derive(Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum FallbackMode { Tokenize, Fixed, Reject }

#[derive(Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Mode { Fixed, Map, Tokenize }

#[derive(Deserialize, Clone, Default)]
pub struct FieldRule {
    pub mode: Option<Mode>,
    pub fixed: Option<String>,
    #[serde(default)]
    pub map: HashMap<String, String>,
    pub fallback: Option<FallbackMode>,
    #[serde(default)]
    pub tokenize: TokenizeCfg,
}

#[derive(Deserialize, Clone, Default)]
pub struct Defaults {
    pub mode: Option<Mode>,
    pub fixed: Option<String>,
    #[serde(default)]
    pub tokenize: TokenizeCfg,
}

#[derive(Deserialize, Clone, Default)]
pub struct AnonConfig {
    pub version: Option<u32>,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub fields: HashMap<String, FieldRule>,
}

pub struct AnonymizerCore {
    cfg: AnonConfig,
    pub table: HashMap<String, HashMap<String, String>>, // field -> (orig -> repl)
    salt: Vec<u8>,
}

impl AnonymizerCore {
    pub fn from_config(cfg: AnonConfig) -> Self {
        let salt = cfg.defaults.tokenize.salt.clone().unwrap_or_default().into_bytes();
        Self { cfg, table: HashMap::new(), salt }
    }
    fn resolve_rule<'a>(&'a self, field: &str) -> (&'a Mode, Option<&'a str>, &'a TokenizeCfg) {
        let fr = self.cfg.fields.get(field);
        let mode = fr.and_then(|r| r.mode.as_ref()).or(self.cfg.defaults.mode.as_ref()).unwrap_or(&Mode::Tokenize);
        let fixed = fr.and_then(|r| r.fixed.as_deref()).or(self.cfg.defaults.fixed.as_deref());
        let tk = fr.map(|r| &r.tokenize).unwrap_or(&self.cfg.defaults.tokenize);
        (mode, fixed, tk)
    }
    fn tokenize_value(&self, prefix: &str, salt_override: Option<&str>, value: &str) -> String {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in salt_override.unwrap_or("").as_bytes().iter().chain(self.salt.iter()).chain(value.as_bytes()) {
            let bb = *b as u64; let mut x = h ^ bb; x = x.wrapping_mul(0x100000001b3); h = x;
        }
        format!("{}{:016x}", prefix, h)
    }
    pub fn anonymize_one(&mut self, field: &str, orig: &str) -> Option<String> {
        use Mode::*;
        if let Some(existing) = self.table.get(field).and_then(|m| m.get(orig)) { return Some(existing.clone()); }
        let (mode_ref, fixed_ref, tk_ref) = self.resolve_rule(field);
        let mode = mode_ref.clone();
        let fixed_owned: Option<String> = fixed_ref.map(|s| s.to_string());
        let tk_prefix: String = tk_ref.prefix.clone().unwrap_or_else(|| "T_".to_string());
        let tk_salt_override: Option<String> = tk_ref.salt.clone();
        let fr = self.cfg.fields.get(field).cloned().unwrap_or_default();
        let field_map = fr.map; let fallback = fr.fallback;
        let repl: String = match mode {
            Fixed => fixed_owned.as_deref().unwrap_or("REDACTED").to_string(),
            Map => {
                if let Some(r) = field_map.get(orig) { r.clone() } else {
                    match fallback {
                        Some(FallbackMode::Fixed) => fixed_owned.as_deref().unwrap_or("REDACTED").to_string(),
                        Some(FallbackMode::Reject) => return None,
                        _ => { self.tokenize_value(&tk_prefix, tk_salt_override.as_deref(), orig) }
                    }
                }
            }
            Tokenize => { self.tokenize_value(&tk_prefix, tk_salt_override.as_deref(), orig) }
        };
        let table_for_field = self.table.entry(field.to_string()).or_default();
        table_for_field.insert(orig.to_string(), repl.clone());
        Some(repl)
    }
}

pub fn anonymizer_from_json(json: &str) -> Result<AnonymizerCore, String> {
    let cfg: AnonConfig = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if let Some(v) = cfg.version { if v != 1 { return Err(format!("Unsupported anonymizer config version: {}", v)); } }
    Ok(AnonymizerCore::from_config(cfg))
}

// --------------- Backwards-compat module re-export ---------------
// Some users import `logparse_core::anonymizer::*`. Provide a thin compatibility module.
pub mod anonymizer {
    pub use super::{AnonConfig, AnonymizerCore, Defaults, FallbackMode, FieldRule, Mode, TokenizeCfg};
    /// Construct an AnonymizerCore from JSON config (compat wrapper)
    pub fn from_json(config_json: &str) -> Result<AnonymizerCore, String> {
        super::anonymizer_from_json(config_json)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    #[test]
    fn test_sanitize_identifier() {
        assert_eq!(super::sanitize_identifier("Source Address"), "source_address");
        assert_eq!(super::sanitize_identifier("Type/Sub-Type"), "type_sub_type");
        assert_eq!(super::sanitize_identifier("9starts-with-digit"), "_9starts_with_digit");
        assert_eq!(super::sanitize_identifier("weird🚀chars"), "weird_chars");
        assert_eq!(super::sanitize_identifier(" already_ok "), "already_ok");
    }

    #[test]
    fn test_split_csv_internal_basic_and_quotes() {
        // Basic
        let v = split_csv_internal("a,b,c");
        assert_eq!(v, vec!["a", "b", "c"]);

        // Quoted with comma and escaped quote
        let v = split_csv_internal("\"a,b\",\"c\"\"d\"\"e\",f");
        assert_eq!(v, vec!["a,b", "c\"d\"e", "f"]);

        // Trailing empty field
        let v = split_csv_internal("x,y,z,");
        assert_eq!(v, vec!["x", "y", "z", ""]);

        // Empty string
        let v: Vec<String> = split_csv_internal("");
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn test_extract_field_internal() {
        // Validate consistency with split_csv_internal for a variety of inputs
        let cases = vec![
            "a,b,c",
            "a,\"b,c\",d,,e",
            ",leading,comma",
            "trailing,comma,",
            "quoted,\"\"\"q\"\"\"", // field with embedded quotes => "q"
        ];
        for line in cases {
            let split = split_csv_internal(line);
            // In-range indices should match split_csv_internal exactly
            for idx in 0..split.len() {
                let got = extract_field_internal(line, idx);
                let want = split.get(idx).cloned();
                assert_eq!(got, want, "mismatch at idx={} for line={}", idx, line);
            }
            // Edge: idx == len
            let edge = extract_field_internal(line, split.len());
            let expected_edge = if line.ends_with(',') { None } else { Some(String::new()) };
            assert_eq!(edge, expected_edge, "edge mismatch at len={} for line={}", split.len(), line);
            // Out of range beyond len
            assert_eq!(extract_field_internal(line, split.len() + 1), None);
        }
    }

    #[test]
    fn test_hash64_fnv1a_deterministic() {
        let h1 = hash64_fnv1a(b"hello world");
        let h2 = hash64_fnv1a(b"hello world");
        assert_eq!(h1, h2);
        // Check against known value for our implementation
        assert_eq!(h1, 0x779a65e7023cd2e7);
    }

    #[test]
    fn test_parse_line_to_map_with_schema() {
        // Build a minimal schema file on disk
        let schema_json = r#"{
          "palo_alto_syslog_fields": {
            "log_types": {
              "traffic": { 
                "type_value": "TRAFFIC", 
                "fields": ["Field A", "Field B", "Field C"] 
              }
            }
          }
        }"#;
        let tmp = std::env::temp_dir().join("logparse_core_test_schema.json");
        fs::write(&tmp, schema_json).unwrap();

        // Ensure the file mtime differs if re-used in fast succession on some filesystems
        std::thread::sleep(Duration::from_millis(5));

        let loaded = load_schema_internal(tmp.to_str().unwrap()).expect("schema load");
        assert_eq!(loaded.type_to_fields.get("TRAFFIC").unwrap(), &vec![
            "field_a".to_string(), "field_b".to_string(), "field_c".to_string()
        ]);

        // CSV where index 3 is type value (TRAFFIC)
        let line = "0,2025/10/12 05:07:29,foo,TRAFFIC,subtype,va,vb,vc";
        let map = parse_line_to_map(line, &loaded).expect("parse map");
        assert_eq!(map.get("field_a").unwrap().as_deref(), Some("0"));
        assert_eq!(map.get("field_b").unwrap().as_deref(), Some("2025/10/12 05:07:29"));
        assert_eq!(map.get("field_c").unwrap().as_deref(), Some("foo"));
    }

    #[test]
    fn test_anonymizer_tokenize_and_map() {
        // Tokenize defaults with salt/prefix
        let cfg_json = r#"{
          "version": 1,
          "defaults": { "mode": "tokenize", "tokenize": { "prefix": "T_", "salt": "pepper" } },
          "fields": {
            "username": { "mode": "map", "map": { "alice": "A" }, "fallback": "tokenize" },
            "fixed_field": { "mode": "fixed", "fixed": "CONST" },
            "reject_field": { "mode": "map", "map": {}, "fallback": "reject" },
            "fixed_fallback": { "mode": "map", "map": {}, "fallback": "fixed", "fixed": "REDACTED" }
          }
        }"#;
        let mut anon = anonymizer_from_json(cfg_json).expect("anon json");

        // Deterministic tokenization
        let t1 = anon.anonymize_one("ip", "10.0.0.1").unwrap();
        let t2 = anon.anonymize_one("ip", "10.0.0.1").unwrap();
        assert_eq!(t1, t2);
        assert!(t1.starts_with("T_"));

        // Map with known value
        let u = anon.anonymize_one("username", "alice").unwrap();
        assert_eq!(u, "A");
        // Map fallback to tokenize
        let u2 = anon.anonymize_one("username", "bob").unwrap();
        assert!(u2.starts_with("T_"));

        // Fixed mode
        let f = anon.anonymize_one("fixed_field", "anything").unwrap();
        assert_eq!(f, "CONST");

        // Reject fallback returns None
        assert_eq!(anon.anonymize_one("reject_field", "x"), None);

        // Fixed fallback
        let ff = anon.anonymize_one("fixed_fallback", "y").unwrap();
        assert_eq!(ff, "REDACTED");

        // Integrity table growth
        let status: usize = anon.table.values().map(|m| m.len()).sum();
        assert!(status >= 4);
    }
}
