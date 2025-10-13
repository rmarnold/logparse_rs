// PyO3 bindings for logparse_core
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};
use once_cell::sync::Lazy;
use std::sync::RwLock;
use std::time::Instant;

use logparse_core as core;

// Re-export a local schema cache that uses the core types
use core::{LoadedSchema, SCHEMA_CACHE};

fn parse_line_to_dict<'py>(py: Python<'py>, line: &str, schema: &LoadedSchema) -> PyResult<Bound<'py, PyDict>> {
    let map = core::parse_line_to_map(line, schema).map_err(PyValueError::new_err)?;
    let d = PyDict::new(py);
    for (k, v) in map.into_iter() {
        let key = pyo3::types::PyString::intern(py, &k);
        match v {
            Some(s) => { d.set_item(key, s)?; }
            None => { d.set_item(key, py.None())?; }
        }
    }
    Ok(d)
}

#[pyfunction]
fn load_schema(schema_path: &str) -> PyResult<bool> {
    match core::load_schema_internal(schema_path) {
        Ok(loaded) => { let mut guard = SCHEMA_CACHE.write().unwrap(); *guard = Some(loaded); Ok(true) }
        Err(e) => Err(PyValueError::new_err(e)),
    }
}

#[pyfunction]
fn parse_kv(py: Python, line: &str) -> PyResult<Py<PyDict>> {
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard.as_ref().ok_or_else(|| PyValueError::new_err("No schema loaded. Call load_schema() or use parse_kv_with_schema()."))?;
    let dict = parse_line_to_dict(py, line, schema)?;
    Ok(dict.unbind())
}

#[pyfunction]
fn parse_kv_with_schema(py: Python, line: &str, schema_path: &str) -> PyResult<Py<PyDict>> {
    core::ensure_schema_loaded(schema_path).map_err(PyValueError::new_err)?;
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard.as_ref().unwrap();
    let dict = parse_line_to_dict(py, line, schema)?;
    Ok(dict.unbind())
}

#[pyfunction]
fn get_schema_status(py: Python) -> PyResult<Py<PyDict>> {
    use std::time::SystemTime;
    let guard = SCHEMA_CACHE.read().unwrap();
    let d = PyDict::new(py);
    match guard.as_ref() {
        Some(ls) => {
            d.set_item("loaded", true)?;
            d.set_item("path", ls.path.clone())?;
            d.set_item("source", "file")?;
            if let Some(mt) = ls.mtime {
                match mt.duration_since(SystemTime::UNIX_EPOCH) {
                    Ok(dur) => { let ms: i64 = (dur.as_secs() as i64) * 1000 + (dur.subsec_millis() as i64); d.set_item("mtime_epoch_ms", ms)?; }
                    Err(_) => { d.set_item("mtime_epoch_ms", py.None())?; }
                }
            } else {
                d.set_item("mtime_epoch_ms", py.None())?;
            }
        }
        None => { d.set_item("loaded", false)?; d.set_item("path", py.None())?; d.set_item("source", py.None())?; d.set_item("mtime_epoch_ms", py.None())?; }
    }
    Ok(d.unbind())
}

#[pyfunction]
fn extract_field(line: &str, index: usize) -> PyResult<Option<String>> { Ok(core::extract_field_internal(line, index)) }

#[pyfunction]
fn extract_type_subtype(line: &str) -> PyResult<(Option<String>, Option<String>)> {
    let t = core::extract_field_internal(line, 3);
    let st = core::extract_field_internal(line, 4);
    Ok((t, st))
}

#[pyfunction]
fn split_csv(line: &str) -> PyResult<Vec<String>> { Ok(core::split_csv_internal(line)) }

#[pyfunction]
fn parse_kv_enriched(py: Python, line: &str) -> PyResult<Py<PyDict>> {
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard.as_ref().ok_or_else(|| PyValueError::new_err("No schema loaded. Call load_schema() or use parse_kv_enriched_with_schema()."))?;
    let t0 = Instant::now();
    let parsed = parse_line_to_dict(py, line, schema)?;
    let runtime_ns = t0.elapsed().as_nanos() as u128;
    let d = PyDict::new(py);
    d.set_item("parsed", parsed)?;
    let max_len = std::cmp::min(256, line.len());
    d.set_item("raw_excerpt", &line[..max_len])?;
    let h = core::hash64_fnv1a(line.as_bytes());
    d.set_item("hash64", h as u128)?;
    d.set_item("runtime_ns", runtime_ns)?;
    Ok(d.unbind())
}

#[pyfunction]
fn parse_kv_enriched_with_schema(py: Python, line: &str, schema_path: &str) -> PyResult<Py<PyDict>> {
    core::ensure_schema_loaded(schema_path).map_err(PyValueError::new_err)?;
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard.as_ref().unwrap();
    let t0 = Instant::now();
    let parsed = parse_line_to_dict(py, line, schema)?;
    let runtime_ns = t0.elapsed().as_nanos() as u128;
    let d = PyDict::new(py);
    d.set_item("parsed", parsed)?;
    let max_len = std::cmp::min(256, line.len());
    d.set_item("raw_excerpt", &line[..max_len])?;
    let h = core::hash64_fnv1a(line.as_bytes());
    d.set_item("hash64", h as u128)?;
    d.set_item("runtime_ns", runtime_ns)?;
    Ok(d.unbind())
}

// -------- Anonymizer state (bindings) --------
static ANONYMIZER: Lazy<RwLock<Option<core::AnonymizerCore>>> = Lazy::new(|| RwLock::new(None));

#[pyfunction]
fn load_anonymizer(config_path: &str) -> PyResult<bool> {
    let json = std::fs::read_to_string(config_path).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let anon = core::anonymizer_from_json(&json).map_err(PyValueError::new_err)?;
    let mut g = ANONYMIZER.write().unwrap();
    *g = Some(anon);
    Ok(true)
}

#[pyfunction]
fn set_anonymizer_json(config_json: &str) -> PyResult<bool> {
    let anon = core::anonymizer_from_json(config_json).map_err(PyValueError::new_err)?;
    let mut g = ANONYMIZER.write().unwrap();
    *g = Some(anon);
    Ok(true)
}

#[pyfunction]
fn get_anonymizer_status(py: Python) -> PyResult<Py<PyDict>> {
    let d = PyDict::new(py);
    let g = ANONYMIZER.read().unwrap();
    if let Some(a) = g.as_ref() {
        let total_pairs: usize = a.table.values().map(|m| m.len()).sum();
        d.set_item("enabled", true)?;
        d.set_item("fields", a.table.len())?;
        d.set_item("pairs", total_pairs)?;
    } else {
        d.set_item("enabled", false)?;
    }
    Ok(d.unbind())
}

#[pyfunction]
fn export_integrity_table(py: Python) -> PyResult<Py<PyDict>> {
    let g = ANONYMIZER.read().unwrap();
    let d = PyDict::new(py);
    if let Some(a) = g.as_ref() {
        for (field, map) in &a.table {
            let sub = PyDict::new(py);
            for (orig, repl) in map { sub.set_item(orig, repl)?; }
            d.set_item(field, sub)?;
        }
    }
    Ok(d.unbind())
}

#[pyfunction]
fn parse_kv_enriched_anon(py: Python, line: &str) -> PyResult<Py<PyDict>> {
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard.as_ref().ok_or_else(|| PyValueError::new_err("No schema loaded"))?;
    let t_parse = Instant::now();
    let parsed0 = parse_line_to_dict(py, line, schema)?;
    let parse_ns = t_parse.elapsed().as_nanos() as u128;
    let t_anon = Instant::now();
    let parsed = {
        let mut anon_guard = ANONYMIZER.write().unwrap();
        if let Some(a) = anon_guard.as_mut() {
            let out = PyDict::new(py);
            for (k, v) in parsed0.iter() {
                let key: String = k.extract()?;
                if let Some(value_str) = v.extract::<Option<String>>().ok().flatten() {
                    if let Some(repl) = a.anonymize_one(&key, &value_str) {
                        out.set_item(k, repl)?;
                        continue;
                    }
                }
                out.set_item(k, v)?;
            }
            out
        } else { parsed0 }
    };
    let anonymize_ns = t_anon.elapsed().as_nanos() as u128;
    let total_ns = parse_ns + anonymize_ns;
    let out = PyDict::new(py);
    out.set_item("parsed", parsed)?;
    let max_len = std::cmp::min(256, line.len());
    out.set_item("raw_excerpt", &line[..max_len])?;
    out.set_item("hash64", core::hash64_fnv1a(line.as_bytes()) as u128)?;
    out.set_item("_anonymized", true)?;
    out.set_item("parse_ns", parse_ns)?;
    out.set_item("anonymize_ns", anonymize_ns)?;
    out.set_item("runtime_ns_total", total_ns)?;
    Ok(out.unbind())
}

#[pyfunction]
fn parse_kv_enriched_with_schema_anon(py: Python, line: &str, schema_path: &str) -> PyResult<Py<PyDict>> {
    core::ensure_schema_loaded(schema_path).map_err(PyValueError::new_err)?;
    parse_kv_enriched_anon(py, line)
}

#[pymodule]
#[pyo3(module = "logparse_rs")]
fn logparse_rs(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add("__doc__", "High-performance log parsing and anonymization library.\n\n\
        Features:\n\
        - Schema-driven CSV/KV parsing\n\
        - Optional field anonymization with deterministic tokens\n\
        - Fast Rust core with Python bindings\n\n\
        Quick start:\n\
        >>> import logparse_rs as lp\n\
        >>> lp.load_schema('path/to/schema.json')\n\
        >>> result = lp.parse_kv_enriched('1,2025/10/12 05:07:29,...')\n\
        >>> print(result['parsed'])")?;

    // Schema-driven parsing APIs
    m.add_function(wrap_pyfunction!(load_schema, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv_with_schema, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv_enriched, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv_enriched_with_schema, m)?)?;
    m.add_function(wrap_pyfunction!(get_schema_status, m)?)?;

    // CSV helpers
    m.add_function(wrap_pyfunction!(extract_field, m)?)?;
    m.add_function(wrap_pyfunction!(extract_type_subtype, m)?)?;
    m.add_function(wrap_pyfunction!(split_csv, m)?)?;

    // Anonymizer APIs
    m.add_function(wrap_pyfunction!(load_anonymizer, m)?)?;
    m.add_function(wrap_pyfunction!(set_anonymizer_json, m)?)?;
    m.add_function(wrap_pyfunction!(get_anonymizer_status, m)?)?;
    m.add_function(wrap_pyfunction!(export_integrity_table, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv_enriched_anon, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv_enriched_with_schema_anon, m)?)?;

    // Optional: preload schema from env var for a faster startup in hot paths.
    if let Ok(path) = std::env::var("LOGPARSE_PRELOAD_SCHEMA")
        .or_else(|_| std::env::var("SCHEMA_JSON_PATH"))
        .or_else(|_| std::env::var("PAN_RUST_PRELOAD_SCHEMA"))
    {
        if let Ok(loaded) = core::load_schema_internal(&path) {
            let mut guard = SCHEMA_CACHE.write().unwrap();
            *guard = Some(loaded);
        }
    }

    // Optional: preload anonymizer from env var (generic + legacy)
    if let Ok(anon_path) = std::env::var("LOGPARSE_ANON_CONFIG").or_else(|_| std::env::var("PAN_RUST_ANON_CONFIG")) {
        if let Ok(json) = std::fs::read_to_string(&anon_path) {
            if let Ok(anon) = core::anonymizer_from_json(&json) {
                let mut g = ANONYMIZER.write().unwrap();
                *g = Some(anon);
            }
        }
    }

    Ok(())
}
