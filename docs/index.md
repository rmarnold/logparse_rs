# logparse-rs SDK

High-performance, schema-driven log parsing and optional anonymization — Rust core with first-class Python bindings.

This site provides comprehensive documentation for both:
- Rust core crate: `logparse_core`
- Python SDK package: `logparse-rs`

What you can do with logparse-rs:
- Parse quote-aware CSV log lines reliably and fast (Rust memchr-accelerated)
- Map CSV fields into named keys driven by a JSON schema (e.g., PAN-OS syslog)
- Compute a stable 64-bit hash of the raw log line for correlation
- Optionally anonymize selected fields with deterministic tokens or fixed values
- Export an integrity table with original→replacement mappings for audits

If you’re in a hurry, jump straight to Quickstart.

## Repository layout
```
repo/
  Cargo.toml                 # workspace
  crates/
    logparse_core/           # pure Rust core, publish to crates.io
  bindings/
    python/                  # PyO3 bindings, publish wheels to PyPI
```

## Packages
- Rust crate: `logparse_core` (library)
- Python package: `logparse-rs` (binary extension built with PyO3)

## Status
- Rust core: stable API surface for CSV split/extract, schema-driven parsing, FNV-1a hash, anonymizer primitives.
- Python bindings: stable for core flows; APIs may evolve prior to 1.0.

