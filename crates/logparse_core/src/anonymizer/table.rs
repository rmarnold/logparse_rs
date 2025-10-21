// anonymizer/table.rs: anonymization engine and integrity table
use std::collections::HashMap;

use super::rules::{AnonConfig, FallbackMode, Mode};

pub struct AnonymizerCore {
    pub(crate) cfg: AnonConfig,
    pub table: HashMap<String, HashMap<String, String>>, // field -> (orig -> repl)
    salt: Vec<u8>,
}

impl AnonymizerCore {
    pub fn from_config(cfg: AnonConfig) -> Self {
        let salt = cfg.defaults.tokenize.salt.clone().unwrap_or_default().into_bytes();
        Self { cfg, table: HashMap::new(), salt }
    }
    fn resolve_rule<'a>(&'a self, field: &str) -> (Option<&'a Mode>, Option<&'a str>, &'a super::rules::TokenizeCfg) {
        let fr = self.cfg.fields.get(field);
        // Determine mode: field rule wins; else defaults.mode; else None (passthrough)
        let mode_opt = fr.and_then(|r| r.mode.as_ref()).or(self.cfg.defaults.mode.as_ref());
        let fixed = fr.and_then(|r| r.fixed.as_deref()).or(self.cfg.defaults.fixed.as_deref());
        let tk = fr.map(|r| &r.tokenize).unwrap_or(&self.cfg.defaults.tokenize);
        (mode_opt, fixed, tk)
    }
    fn tokenize_value(&self, prefix: &str, salt_override: Option<&str>, value: &str) -> String {
        // simple salted fnv-like rolling hash
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
        let fixed_owned: Option<String> = fixed_ref.map(|s| s.to_string());
        let tk_prefix: String = tk_ref.prefix.clone().unwrap_or_else(|| "T_".to_string());
        let tk_salt_override: Option<String> = tk_ref.salt.clone();
        let fr = self.cfg.fields.get(field).cloned().unwrap_or_default();
        let field_map = fr.map; let fallback = fr.fallback;
        let repl: String = match mode_ref {
            Some(Fixed) => fixed_owned.as_deref().unwrap_or("REDACTED").to_string(),
            Some(Map) => {
                if let Some(r) = field_map.get(orig) { r.clone() } else {
                    match fallback {
                        Some(FallbackMode::Fixed) => fixed_owned.as_deref().unwrap_or("REDACTED").to_string(),
                        Some(FallbackMode::Reject) => return None,
                        _ => { self.tokenize_value(&tk_prefix, tk_salt_override.as_deref(), orig) }
                    }
                }
            }
            Some(Tokenize) => { self.tokenize_value(&tk_prefix, tk_salt_override.as_deref(), orig) }
            None => { return None }
        };
        let table_for_field = self.table.entry(field.to_string()).or_default();
        table_for_field.insert(orig.to_string(), repl.clone());
        Some(repl)
    }
}

pub fn anonymizer_from_json(json: &str) -> Result<AnonymizerCore, String> {
    let cfg: super::rules::AnonConfig = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if let Some(v) = cfg.version { if v != 1 { return Err(format!("Unsupported anonymizer config version: {}", v)); } }
    Ok(AnonymizerCore::from_config(cfg))
}

#[cfg(test)]
mod tests {
    use super::anonymizer_from_json;

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
