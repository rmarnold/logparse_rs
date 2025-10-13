"""
Python controller for Rust-accelerated CSV parsing and schema-driven KV parsing.

This module uses the generic `logparse_rs` PyO3 extension when available and
falls back to pure-Python implementations otherwise.

Build instructions (one-time):
- Install Rust toolchain and maturin: `pip install maturin`
- Build and develop locally from bindings/python: `maturin develop`

Functions:
- get_field(line: str, index: int) -> str | None
- get_type_subtype(line: str) -> tuple[str | None, str | None]
- get_fields(line: str) -> list[str]
- load_schema(schema_path: str) -> bool
- load_embedded_schema() -> bool  # when built with --features embed_schema
- parse_kv(line: str, include_all: bool = False) -> dict  # uses previously loaded schema
- parse_kv_with_schema(line: str, schema_path: str, include_all: bool = False) -> dict
"""
from __future__ import annotations

from typing import Optional, Tuple, List, Dict
import json
import os

# Import the generic Rust-backed SDK; fall back to pure Python if unavailable
try:
    from logparse_rs import (
        extract_field as _rs_extract_field,
        extract_type_subtype as _rs_extract_type_subtype,
        split_csv as _rs_split_csv,
        load_schema as _rs_load_schema,
        parse_kv as _rs_parse_kv,
        parse_kv_with_schema as _rs_parse_kv_with_schema,
        get_schema_status as _rs_get_schema_status,
        parse_kv_enriched as _rs_parse_kv_enriched,
        parse_kv_enriched_with_schema as _rs_parse_kv_enriched_with_schema,
        load_anonymizer as _rs_load_anonymizer,
        set_anonymizer_json as _rs_set_anonymizer_json,
        get_anonymizer_status as _rs_get_anonymizer_status,
        export_integrity_table as _rs_export_integrity_table,
        parse_kv_enriched_anon as _rs_parse_kv_enriched_anon,
        parse_kv_enriched_with_schema_anon as _rs_parse_kv_enriched_with_schema_anon,
        load_embedded_schema as _rs_load_embedded_schema,
    )  # type: ignore
    _HAS_RUST = True
except Exception:
    _HAS_RUST = False
    _rs_extract_field = None
    _rs_extract_type_subtype = None
    _rs_split_csv = None
    _rs_load_schema = None
    _rs_parse_kv = None
    _rs_parse_kv_with_schema = None
    _rs_get_schema_status = None
    _rs_parse_kv_enriched = None
    _rs_parse_kv_enriched_with_schema = None
    _rs_load_anonymizer = None
    _rs_set_anonymizer_json = None
    _rs_get_anonymizer_status = None
    _rs_export_integrity_table = None
    _rs_parse_kv_enriched_anon = None
    _rs_parse_kv_enriched_with_schema_anon = None
    _rs_load_embedded_schema = None

# Optional embedded schema loader (available only when the Rust extension was built
# with `--features embed_schema`). Already handled by the main import above.


def load_embedded_schema() -> bool:
    """Load the compile-time embedded schema if the Rust extension was built with --features embed_schema.
    Returns True on success; raises RuntimeError if unsupported.
    """
    if _rs_load_embedded_schema is None:
        raise RuntimeError("Embedded schema not supported; rebuild with --features embed_schema")
    return _rs_load_embedded_schema()  # type: ignore[misc]

# Optional: preload schema from environment at import time for faster hot paths.
# Prefer embedded schema when LOGPARSE_USE_EMBEDDED=1; otherwise fall back to a file path
# via LOGPARSE_PRELOAD_SCHEMA or SCHEMA_JSON_PATH.
try:
    _SCHEMA_PRELOAD = os.getenv('LOGPARSE_PRELOAD_SCHEMA') or os.getenv('SCHEMA_JSON_PATH')
    if _HAS_RUST:
        if os.getenv('LOGPARSE_USE_EMBEDDED') == '1' and _rs_load_embedded_schema is not None:
            _rs_load_embedded_schema()
        elif _rs_load_schema is not None and _SCHEMA_PRELOAD:
            _rs_load_schema(_SCHEMA_PRELOAD)
except Exception:
    # Ignore any preload errors to keep import robust
    pass


def _py_extract_field(line: str, index: int) -> Optional[str]:
    """Pure-Python CSV field extractor with basic quote handling (0-based index)."""
    idx = 0
    i = 0
    n = len(line)
    while idx <= index and i <= n:
        if i >= n:
            return "" if idx == index else None
        field = []
        if line[i] == '"':
            i += 1
            while i < n:
                ch = line[i]
                if ch == '"':
                    # Escaped quote
                    if i + 1 < n and line[i + 1] == '"':
                        field.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                field.append(ch)
                i += 1
            while i < n and line[i] != ',':
                i += 1
        else:
            while i < n and line[i] != ',':
                field.append(line[i])
                i += 1
        if i < n and line[i] == ',':
            i += 1
        if idx == index:
            return ''.join(field)
        idx += 1
    return None


def _py_split_fields(line: str) -> List[str]:
    # Reuse extractor to split all fields
    fields: List[str] = []
    i = 0
    n = len(line)
    while True:
        if i >= n:
            # Handle potential trailing comma -> empty field
            if n > 0 and line.endswith(','):
                fields.append("")
            break
        # Extract next field by scanning similar to _py_extract_field
        start = i
        if line[i] == '"':
            i += 1
            field_chars = []
            while i < n:
                ch = line[i]
                if ch == '"':
                    if i + 1 < n and line[i + 1] == '"':
                        field_chars.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                field_chars.append(ch)
                i += 1
            while i < n and line[i] != ',':
                i += 1
            fields.append(''.join(field_chars))
        else:
            field_chars = []
            while i < n and line[i] != ',':
                field_chars.append(line[i])
                i += 1
            fields.append(''.join(field_chars))
        if i < n and line[i] == ',':
            i += 1
    return fields


def get_field(line: str, index: int) -> Optional[str]:
    if _HAS_RUST and _rs_extract_field is not None:
        return _rs_extract_field(line, index)
    return _py_extract_field(line, index)


def get_type_subtype(line: str) -> Tuple[Optional[str], Optional[str]]:
    if _HAS_RUST and _rs_extract_type_subtype is not None:
        return _rs_extract_type_subtype(line)
    return _py_extract_field(line, 3), _py_extract_field(line, 4)


def get_fields(line: str) -> List[str]:
    if _HAS_RUST and _rs_split_csv is not None:
        return _rs_split_csv(line)
    return _py_split_fields(line)

# ---------------- Schema-driven KV parsing (Rust-backed with Python fallback) ----------------
_PY_SCHEMA: Optional[Dict[str, List[str]]]= None
_PY_SCHEMA_PATH: Optional[str] = None
_PY_SCHEMA_MTIME: Optional[float] = None


def _sanitize_identifier(name: str) -> str:
    s = name.strip().lower().replace(' ', '_').replace('/', '_').replace('-', '_')
    s = ''.join(ch if (ch.isalnum() or ch == '_') else '_' for ch in s)
    if not s or not (s[0].isalpha() or s[0] == '_'):
        s = '_' + s
    return s


def _py_build_type_to_fields(schema: Dict) -> Dict[str, List[str]]:
    res: Dict[str, List[str]] = {}
    lt = schema.get('palo_alto_syslog_fields', {}).get('log_types', {})
    for _name, defn in lt.items():
        tval = defn.get('type_value')
        fields: List[str] = []
        seen = set()
        for f in defn.get('fields', []):
            if isinstance(f, str):
                raw = f
            else:
                raw = f.get('name')
            if raw is None:
                continue
            key = _sanitize_identifier(raw)
            if key not in seen:
                fields.append(key)
                seen.add(key)
        if isinstance(tval, str):
            res[tval] = fields
    return res


def _py_load_schema(schema_path: str) -> bool:
    global _PY_SCHEMA, _PY_SCHEMA_PATH, _PY_SCHEMA_MTIME
    with open(schema_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    _PY_SCHEMA = _py_build_type_to_fields(data)
    _PY_SCHEMA_PATH = schema_path
    try:
        _PY_SCHEMA_MTIME = os.path.getmtime(schema_path)
    except Exception:
        _PY_SCHEMA_MTIME = None
    return True


def load_schema(schema_path: str) -> bool:
    if _HAS_RUST and _rs_load_schema is not None:
        return _rs_load_schema(schema_path)
    return _py_load_schema(schema_path)


def _py_parse_kv_with_loaded_schema(line: str) -> Dict[str, Optional[str]]:
    if not _PY_SCHEMA:
        raise ValueError("No schema loaded. Call load_schema() or parse_kv_with_schema().")
    # type is at index 3
    t = get_field(line, 3)
    if not t:
        raise ValueError("Could not extract log type at index 3")
    fields = get_fields(line)
    names = _PY_SCHEMA.get(t)
    if not names:
        raise ValueError(f"Unknown log type in schema: {t}")
    out: Dict[str, Optional[str]] = {}
    for i, name in enumerate(names):
        out[name] = fields[i] if i < len(fields) else None
    return out


def parse_kv(line: str, include_all: bool = False):
    """Parse a CSV line into a dict according to the loaded schema.

    If include_all=True, also add index-based keys for every field: field_0, field_1, ...
    This preserves existing schema-mapped keys and only adds additional index keys.
    """
    if _HAS_RUST and _rs_parse_kv is not None:
        base = _rs_parse_kv(line)
    else:
        base = _py_parse_kv_with_loaded_schema(line)
    if include_all:
        try:
            fields = get_fields(line)
            for i, v in enumerate(fields):
                k = f"field_{i}"
                if k not in base:
                    base[k] = v
        except Exception:
            # If field splitting fails, return base as-is
            pass
    return base


def parse_kv_with_schema(line: str, schema_path: str, include_all: bool = False):
    """Parse a CSV line using the given schema path (auto-reload on mtime change).

    If include_all=True, also add index-based keys for every field: field_0, field_1, ...
    """
    if _HAS_RUST and _rs_parse_kv_with_schema is not None:
        base = _rs_parse_kv_with_schema(line, schema_path)
    else:
        need_reload = False
        if _PY_SCHEMA_PATH != schema_path:
            need_reload = True
        else:
            try:
                m = os.path.getmtime(schema_path)
                if _PY_SCHEMA_MTIME != m:
                    need_reload = True
            except Exception:
                pass
        if need_reload:
            _py_load_schema(schema_path)
        base = _py_parse_kv_with_loaded_schema(line)
    if include_all:
        try:
            fields = get_fields(line)
            for i, v in enumerate(fields):
                k = f"field_{i}"
                if k not in base:
                    base[k] = v
        except Exception:
            pass
    return base


def _py_hash64_fnv1a(s: str) -> int:
    h = 0xcbf29ce484222325
    for ch in s.encode('utf-8', errors='ignore'):
        h ^= ch
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def parse_kv_enriched(line: str, include_all: bool = False) -> Dict:
    """Return a dict with keys: parsed (dict), raw_excerpt (str), hash64 (int).
    Uses Rust if available; otherwise Python fallback.
    """
    if _HAS_RUST and _rs_parse_kv_enriched is not None:
        try:
            d = _rs_parse_kv_enriched(line)
            if include_all and isinstance(d.get('parsed'), dict):
                fields = get_fields(line)
                for i, v in enumerate(fields):
                    k = f"field_{i}"
                    if k not in d['parsed']:
                        d['parsed'][k] = v
            return d
        except Exception:
            pass
    base = parse_kv(line, include_all=include_all)
    return {
        'parsed': base,
        'raw_excerpt': line[:256],
        'hash64': _py_hash64_fnv1a(line),
    }


def parse_kv_enriched_with_schema(line: str, schema_path: str, include_all: bool = False) -> Dict:
    if _HAS_RUST and _rs_parse_kv_enriched_with_schema is not None:
        try:
            d = _rs_parse_kv_enriched_with_schema(line, schema_path)
            if include_all and isinstance(d.get('parsed'), dict):
                fields = get_fields(line)
                for i, v in enumerate(fields):
                    k = f"field_{i}"
                    if k not in d['parsed']:
                        d['parsed'][k] = v
            return d
        except Exception:
            pass
    base = parse_kv_with_schema(line, schema_path, include_all=include_all)
    return {
        'parsed': base,
        'raw_excerpt': line[:256],
        'hash64': _py_hash64_fnv1a(line),
    }


# -------------- Anonymizer wrappers --------------

def load_anonymizer(config_path: str) -> bool:
    if _HAS_RUST and _rs_load_anonymizer is not None:
        return _rs_load_anonymizer(config_path)  # type: ignore
    raise RuntimeError("Rust anonymizer not available in this build")


def set_anonymizer_json(config_json: str) -> bool:
    if _HAS_RUST and _rs_set_anonymizer_json is not None:
        return _rs_set_anonymizer_json(config_json)  # type: ignore
    raise RuntimeError("Rust anonymizer not available in this build")


def get_anonymizer_status() -> Dict[str, object]:
    if _HAS_RUST and _rs_get_anonymizer_status is not None:
        return _rs_get_anonymizer_status()  # type: ignore
    return {"enabled": False}


def export_integrity_table() -> Dict[str, Dict[str, str]]:
    if _HAS_RUST and _rs_export_integrity_table is not None:
        return _rs_export_integrity_table()  # type: ignore
    return {}


def parse_kv_enriched_anon(line: str, include_all: bool = False) -> Dict:
    if _HAS_RUST and _rs_parse_kv_enriched_anon is not None:
        d = _rs_parse_kv_enriched_anon(line)  # type: ignore
        if include_all and isinstance(d.get('parsed'), dict):
            fields = get_fields(line)
            for i, v in enumerate(fields):
                d['parsed'].setdefault(f"field_{i}", v)
        return d
    raise RuntimeError("Anonymized parse requires Rust extension")


def parse_kv_enriched_with_schema_anon(line: str, schema_path: str, include_all: bool = False) -> Dict:
    if _HAS_RUST and _rs_parse_kv_enriched_with_schema_anon is not None:
        d = _rs_parse_kv_enriched_with_schema_anon(line, schema_path)  # type: ignore
        if include_all and isinstance(d.get('parsed'), dict):
            fields = get_fields(line)
            for i, v in enumerate(fields):
                d['parsed'].setdefault(f"field_{i}", v)
        return d
    raise RuntimeError("Anonymized parse requires Rust extension")


# Optional: preload anonymizer from env at import time
try:
    _ANON_PRELOAD = os.getenv('LOGPARSE_ANON_CONFIG')
    if _HAS_RUST and _ANON_PRELOAD and _rs_load_anonymizer is not None:
        _rs_load_anonymizer(_ANON_PRELOAD)  # type: ignore
except Exception:
    pass


def get_schema_status() -> Dict[str, object]:
    """Return runtime schema status from Rust if available, else Python fallback.
    Keys: loaded (bool), source ("embedded"|"file"|None), path (str|None), mtime_epoch_ms (int|None)
    """
    if _HAS_RUST and _rs_get_schema_status is not None:
        try:
            return _rs_get_schema_status()
        except Exception:
            pass
    loaded = _PY_SCHEMA is not None
    source = "file" if loaded and _PY_SCHEMA_PATH else None
    try:
        mtime_ms = int(_PY_SCHEMA_MTIME * 1000) if _PY_SCHEMA_MTIME else None
    except Exception:
        mtime_ms = None
    return {
        "loaded": loaded,
        "source": source,
        "path": _PY_SCHEMA_PATH,
        "mtime_epoch_ms": mtime_ms,
    }
