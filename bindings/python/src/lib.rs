// PyO3 bindings for logparse_core
use once_cell::sync::Lazy;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};
use std::sync::RwLock;
use std::time::Instant;

use logparse_core as core;

// Re-export a local schema cache that uses the core types
use core::{LoadedSchema, SCHEMA_CACHE};

// Parallel iterators for batch parsing
use rayon::prelude::*;

fn parse_line_to_dict<'py>(
    py: Python<'py>,
    line: &str,
    schema: &LoadedSchema,
) -> PyResult<Bound<'py, PyDict>> {
    // Fast path: avoid building an intermediate HashMap. Instead, split the CSV
    // once and populate the Python dict directly using the schema's field names.
    // This eliminates per-line hashing and key String cloning.
    let t = core::extract_field_internal(line, 3)
        .ok_or_else(|| PyValueError::new_err("Could not extract log type at index 3"))?;
    let names = schema
        .type_to_fields
        .get(&t)
        .ok_or_else(|| PyValueError::new_err(format!("Unknown log type in schema: {}", t)))?;

    let fields = core::split_csv_internal(line);
    let d = PyDict::new(py);
    for (i, name) in names.iter().enumerate() {
        let key = pyo3::types::PyString::intern(py, name);
        if i < fields.len() {
            d.set_item(key, &fields[i])?;
        } else {
            d.set_item(key, py.None())?;
        }
    }
    Ok(d)
}

/// Load a schema from a JSON file path. Returns True on success.
/// Raises ValueError if the file cannot be read or parsed.
#[pyfunction]
#[pyo3(text_signature = "(schema_path)")]
fn load_schema(schema_path: &str) -> PyResult<bool> {
    match core::load_schema_internal(schema_path) {
        Ok(loaded) => {
            let mut guard = SCHEMA_CACHE.write().unwrap();
            *guard = Some(loaded);
            Ok(true)
        }
        Err(e) => Err(PyValueError::new_err(e)),
    }
}

/// Parse a single CSV/KV log line using the previously loaded schema.
/// Returns a dict mapping field names to values.
#[pyfunction]
#[pyo3(text_signature = "(line)")]
fn parse_kv(py: Python, line: &str) -> PyResult<Py<PyDict>> {
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard.as_ref().ok_or_else(|| {
        PyValueError::new_err("No schema loaded. Call load_schema() or use parse_kv_with_schema().")
    })?;
    let dict = parse_line_to_dict(py, line, schema)?;
    Ok(dict.unbind())
}

/// Parse a single log line using the schema at the given path (temporary load).
#[pyfunction]
#[pyo3(text_signature = "(line, schema_path)")]
fn parse_kv_with_schema(py: Python, line: &str, schema_path: &str) -> PyResult<Py<PyDict>> {
    core::ensure_schema_loaded(schema_path).map_err(PyValueError::new_err)?;
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard.as_ref().unwrap();
    let dict = parse_line_to_dict(py, line, schema)?;
    Ok(dict.unbind())
}

/// Return current schema loader status and metadata.
#[pyfunction]
#[pyo3(text_signature = "()")]
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
                    Ok(dur) => {
                        let ms: i64 = (dur.as_secs() as i64) * 1000 + (dur.subsec_millis() as i64);
                        d.set_item("mtime_epoch_ms", ms)?;
                    }
                    Err(_) => {
                        d.set_item("mtime_epoch_ms", py.None())?;
                    }
                }
            } else {
                d.set_item("mtime_epoch_ms", py.None())?;
            }
        }
        None => {
            d.set_item("loaded", false)?;
            d.set_item("path", py.None())?;
            d.set_item("source", py.None())?;
            d.set_item("mtime_epoch_ms", py.None())?;
        }
    }
    Ok(d.unbind())
}

/// Extract the raw CSV field at the given 0-based index. Returns the field string or None if out of bounds.
#[pyfunction]
#[pyo3(text_signature = "(line, index)")]
fn extract_field(line: &str, index: usize) -> PyResult<Option<String>> {
    Ok(core::extract_field_internal(line, index))
}

/// Extract the event type and subtype fields (indexes 3 and 4) from the CSV line.
#[pyfunction]
#[pyo3(text_signature = "(line)")]
fn extract_type_subtype(line: &str) -> PyResult<(Option<String>, Option<String>)> {
    let t = core::extract_field_internal(line, 3);
    let st = core::extract_field_internal(line, 4);
    Ok((t, st))
}

/// Split a CSV line (quote-aware) into a list of fields.
#[pyfunction]
#[pyo3(text_signature = "(line)")]
fn split_csv(line: &str) -> PyResult<Vec<String>> {
    Ok(core::split_csv_internal(line))
}

/// Parse a line and return an enriched result with parsed fields, raw excerpt, hash64, and runtime.
#[pyfunction]
#[pyo3(text_signature = "(line)")]
fn parse_kv_enriched(py: Python, line: &str) -> PyResult<Py<PyDict>> {
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard.as_ref().ok_or_else(|| {
        PyValueError::new_err(
            "No schema loaded. Call load_schema() or use parse_kv_enriched_with_schema().",
        )
    })?;
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

/// Parse using the schema at the given path and return an enriched result.
#[pyfunction]
#[pyo3(text_signature = "(line, schema_path)")]
fn parse_kv_enriched_with_schema(
    py: Python,
    line: &str,
    schema_path: &str,
) -> PyResult<Py<PyDict>> {
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

/// Parse a batch of lines in parallel and return enriched dicts per line.
/// Heavy parsing happens without the Python GIL using Rayon; Python dicts are
/// constructed after parsing, minimizing GIL contention.
#[pyfunction]
#[pyo3(text_signature = "(lines)")]
fn parse_kv_enriched_batch(py: Python, lines: Vec<String>) -> PyResult<Vec<Py<PyDict>>> {
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard
        .as_ref()
        .ok_or_else(|| PyValueError::new_err("No schema loaded. Call load_schema()"))?;

    // Perform the heavy parsing in parallel without holding the GIL
    // Avoid cloning schema key names per record by carrying only the log type and
    // the parsed field values; we look up the names again when building Python
    // objects. This reduces per-record allocations and hashing.
    struct Mid {
        t: String,
        fields: Vec<String>,
        hash64: u64,
        excerpt: String,
        runtime_ns: u128,
    }

    // Perform heavy compute without interacting with Python; no need to hold the GIL here.
    let mids: Vec<Result<Mid, String>> = {
        lines
            .par_iter()
            .map(|line| {
                let t0 = Instant::now();
                let t = core::extract_field_internal(line, 3)
                    .ok_or_else(|| "Could not extract log type at index 3".to_string())?;
                // Validate type exists early to surface errors promptly
                let _ = schema
                    .type_to_fields
                    .get(&t)
                    .ok_or_else(|| format!("Unknown log type in schema: {}", t))?;
                let fields = core::split_csv_internal(line);
                let runtime_ns = t0.elapsed().as_nanos() as u128;
                let excerpt_len = std::cmp::min(256, line.len());
                Ok(Mid {
                    t,
                    fields,
                    hash64: core::hash64_fnv1a(line.as_bytes()),
                    excerpt: line[..excerpt_len].to_string(),
                    runtime_ns,
                })
            })
            .collect()
    };

    // If any error occurred, return the first one as a Python ValueError
    for r in &mids {
        if let Err(e) = r {
            return Err(PyValueError::new_err(e.clone()));
        }
    }

    // Build Python objects
    let mut out: Vec<Py<PyDict>> = Vec::with_capacity(mids.len());
    for r in mids.into_iter().map(|x| x.unwrap()) {
        let d = PyDict::new(py);
        let parsed = PyDict::new(py);
        // Lookup field names by type without cloning them
        let names = match schema.type_to_fields.get(&r.t) {
            Some(n) => n,
            None => {
                return Err(PyValueError::new_err(format!("Unknown log type in schema: {}", r.t)))
            }
        };
        for (i, name) in names.iter().enumerate() {
            let key = pyo3::types::PyString::intern(py, name);
            if i < r.fields.len() {
                parsed.set_item(key, &r.fields[i])?;
            } else {
                parsed.set_item(key, py.None())?;
            }
        }
        d.set_item("parsed", parsed)?;
        d.set_item("raw_excerpt", r.excerpt)?;
        d.set_item("hash64", r.hash64 as u128)?;
        d.set_item("runtime_ns", r.runtime_ns)?;
        out.push(d.unbind());
    }

    Ok(out)
}

// -------- Anonymizer state (bindings) --------
static ANONYMIZER: Lazy<RwLock<Option<core::AnonymizerCore>>> = Lazy::new(|| RwLock::new(None));

/// Load anonymizer rules from a JSON file path. Returns True on success.
#[pyfunction]
#[pyo3(text_signature = "(config_path)")]
fn load_anonymizer(config_path: &str) -> PyResult<bool> {
    let json =
        std::fs::read_to_string(config_path).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let anon = core::anonymizer_from_json(&json).map_err(PyValueError::new_err)?;
    let mut g = ANONYMIZER.write().unwrap();
    *g = Some(anon);
    Ok(true)
}

/// Set anonymizer rules from a JSON string. Returns True on success.
#[pyfunction]
#[pyo3(text_signature = "(config_json)")]
fn set_anonymizer_json(config_json: &str) -> PyResult<bool> {
    let anon = core::anonymizer_from_json(config_json).map_err(PyValueError::new_err)?;
    let mut g = ANONYMIZER.write().unwrap();
    *g = Some(anon);
    Ok(true)
}

/// Return anonymizer status and basic statistics.
#[pyfunction]
#[pyo3(text_signature = "()")]
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

/// Export the anonymizer integrity table as a nested dict: field -> {original: replacement}.
#[pyfunction]
#[pyo3(text_signature = "()")]
fn export_integrity_table(py: Python) -> PyResult<Py<PyDict>> {
    let g = ANONYMIZER.read().unwrap();
    let d = PyDict::new(py);
    if let Some(a) = g.as_ref() {
        for (field, map) in &a.table {
            let sub = PyDict::new(py);
            for (orig, repl) in map {
                sub.set_item(orig, repl)?;
            }
            d.set_item(field, sub)?;
        }
    }
    Ok(d.unbind())
}

/// Parse a line and return enriched results with anonymization applied when enabled.
#[pyfunction]
#[pyo3(text_signature = "(line)")]
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
        } else {
            parsed0
        }
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

/// Parse a line using the given schema path and return enriched results with anonymization when enabled.
#[pyfunction]
#[pyo3(text_signature = "(line, schema_path)")]
fn parse_kv_enriched_with_schema_anon(
    py: Python,
    line: &str,
    schema_path: &str,
) -> PyResult<Py<PyDict>> {
    core::ensure_schema_loaded(schema_path).map_err(PyValueError::new_err)?;
    parse_kv_enriched_anon(py, line)
}

#[pyfunction]
#[pyo3(text_signature = "(input_path, output_path)")]
fn parse_file_to_ndjson(input_path: &str, output_path: &str) -> PyResult<usize> {
    use std::io::{BufRead, BufReader, BufWriter, Write};
    // Ensure schema is loaded
    let guard = SCHEMA_CACHE.read().unwrap();
    let schema = guard
        .as_ref()
        .ok_or_else(|| PyValueError::new_err("No schema loaded. Call load_schema() first."))?;

    let infile =
        std::fs::File::open(input_path).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let mut outfile =
        std::fs::File::create(output_path).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let reader = BufReader::new(infile);
    let mut writer = BufWriter::new(&mut outfile);

    let mut count: usize = 0;
    for line_res in reader.lines() {
        let line = line_res.map_err(|e| PyValueError::new_err(e.to_string()))?;
        if line.is_empty() {
            continue;
        }
        let t0 = Instant::now();
        let t = match core::extract_field_internal(&line, 3) {
            Some(s) => s,
            None => continue, // skip malformed lines
        };
        let names = match schema.type_to_fields.get(&t) {
            Some(n) => n,
            None => continue, // unknown type; skip
        };
        let fields = core::split_csv_internal(&line);
        let runtime_ns = t0.elapsed().as_nanos() as u128;

        // Build JSON object directly using serde_json::Map to minimize allocations
        let mut parsed = serde_json::Map::with_capacity(names.len());
        for (i, name) in names.iter().enumerate() {
            if i < fields.len() {
                parsed.insert(name.clone(), serde_json::Value::String(fields[i].clone()));
            } else {
                parsed.insert(name.clone(), serde_json::Value::Null);
            }
        }
        // Enriched payload aligns to parse_kv_enriched()
        let max_len = std::cmp::min(256, line.len());
        let mut root = serde_json::Map::with_capacity(4);
        root.insert("parsed".to_string(), serde_json::Value::Object(parsed));
        root.insert(
            "raw_excerpt".to_string(),
            serde_json::Value::String(line[..max_len].to_string()),
        );
        root.insert(
            "hash64".to_string(),
            serde_json::Value::Number(serde_json::Number::from(
                core::hash64_fnv1a(line.as_bytes()) as u64,
            )),
        );
        root.insert(
            "runtime_ns".to_string(),
            serde_json::Value::Number(serde_json::Number::from(runtime_ns as u64)),
        );

        let value = serde_json::Value::Object(root);
        serde_json::to_writer(&mut writer, &value)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        writer.write_all(b"\n").map_err(|e| PyValueError::new_err(e.to_string()))?;
        count += 1;
    }
    writer.flush().map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(count)
}

#[pymodule]
#[pyo3(module = "logparse_rs")]
fn logparse_rs(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add(
        "__doc__",
        "High-performance log parsing and anonymization library.\n\n\
        Features:\n\
        - Schema-driven CSV/KV parsing\n\
        - Optional field anonymization with deterministic tokens\n\
        - Fast Rust core with Python bindings\n\n\
        Quick start:\n\
        >>> import logparse_rs as lp\n\
        >>> lp.load_schema('path/to/schema.json')\n\
        >>> result = lp.parse_kv_enriched('1,2025/10/12 05:07:29,...')\n\
        >>> print(result['parsed'])",
    )?;

    // Schema-driven parsing APIs
    m.add_function(wrap_pyfunction!(load_schema, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv_with_schema, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv_enriched, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv_enriched_with_schema, m)?)?;
    m.add_function(wrap_pyfunction!(get_schema_status, m)?)?;
    m.add_function(wrap_pyfunction!(parse_kv_enriched_batch, m)?)?;
    m.add_function(wrap_pyfunction!(parse_file_to_ndjson, m)?)?;

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
    if let Ok(anon_path) =
        std::env::var("LOGPARSE_ANON_CONFIG").or_else(|_| std::env::var("PAN_RUST_ANON_CONFIG"))
    {
        if let Ok(json) = std::fs::read_to_string(&anon_path) {
            if let Ok(anon) = core::anonymizer_from_json(&json) {
                let mut g = ANONYMIZER.write().unwrap();
                *g = Some(anon);
            }
        }
    }

    Ok(())
}
