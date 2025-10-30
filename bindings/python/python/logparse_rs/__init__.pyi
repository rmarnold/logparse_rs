from __future__ import annotations
from typing import Any, Dict, Optional, Tuple, List
from . import rust_accel as rust_accel

# Public functions exposed by the native extension

def load_schema(path: str) -> bool: ...

# Parse using a previously loaded schema
# Returns a dict mapping field names to values (str or None)
def parse_kv(line: str) -> Dict[str, Any]: ...

# Parse using a schema path provided for this call (does not persist)
def parse_kv_with_schema(line: str, schema_path: str) -> Dict[str, Any]: ...

# Introspection of the schema loader state
# Example keys: {"loaded": bool, "path": Optional[str], "source": Optional[str], "mtime_epoch_ms": Optional[int]}

def get_schema_status() -> Dict[str, Any]: ...

# CSV helpers

def extract_field(line: str, index: int) -> Optional[str]: ...

def extract_type_subtype(line: str) -> Tuple[Optional[str], Optional[str]]: ...

def split_csv(line: str) -> List[str]: ...

# Enriched parsing results
# Returns a dict with keys like: {"parsed": Dict[str, Any], "raw_excerpt": str, "hash64": int, "runtime_ns": int}

def parse_kv_enriched(line: str) -> Dict[str, Any]: ...

def parse_kv_enriched_with_schema(line: str, schema_path: str) -> Dict[str, Any]: ...

# Anonymizer APIs

def load_anonymizer(config_path: str) -> bool: ...

def set_anonymizer_json(config_json: str) -> bool: ...

# Example keys: {"enabled": bool, "fields": int, "pairs": int}

def get_anonymizer_status() -> Dict[str, Any]: ...

# Mapping of field -> {original_value -> replacement}

def export_integrity_table() -> Dict[str, Dict[str, str]]: ...

# Enriched parsing with anonymization; includes additional timing and flags
# Example keys include: _anonymized, parse_ns, anonymize_ns, runtime_ns_total

def parse_kv_enriched_anon(line: str) -> Dict[str, Any]: ...

def parse_kv_enriched_with_schema_anon(line: str, schema_path: str) -> Dict[str, Any]: ...
