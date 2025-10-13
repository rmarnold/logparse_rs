pub mod rules;
pub mod table;

pub use rules::*;
pub use table::*;

/// Construct an AnonymizerCore from JSON config
pub fn from_json(config_json: &str) -> Result<table::AnonymizerCore, String> {
    table::anonymizer_from_json(config_json)
}
