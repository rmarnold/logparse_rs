// anonymizer/rules.rs: configuration types for anonymization
use serde::Deserialize;
use std::collections::HashMap;

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
