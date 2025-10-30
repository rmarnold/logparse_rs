// logparse_core: pure Rust library for CSV tokenization and schema-driven parsing + anonymization primitives.

pub mod anonymizer;
pub mod parser;
pub mod schema;
pub mod tokenizer;

// Re-export commonly used items at the crate root to preserve the public API
pub use anonymizer::table::anonymizer_from_json;
pub use anonymizer::{
    AnonConfig, AnonymizerCore, Defaults, FallbackMode, FieldRule, Mode, TokenizeCfg,
};
pub use parser::parse_line_to_map;
pub use schema::{ensure_schema_loaded, load_schema_internal, LoadedSchema, SCHEMA_CACHE};
pub use tokenizer::{extract_field_internal, split_csv_internal};

// Utility hashing function used by bindings
pub fn hash64_fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
