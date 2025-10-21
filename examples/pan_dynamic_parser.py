#!/usr/bin/env python3
"""
Dynamic Palo Alto Networks Syslog Parser Generator
Reads JSON field definitions and compiles parser at runtime
"""

import json
import os
from typing import Dict, List, Any, Callable
from dataclasses import dataclass, field, asdict
import keyword
from datetime import datetime
from collections import Counter
import time
import hashlib
import importlib.util
import sys
from pathlib import Path


def _import_rust_accel():
    """Return the rust_accel module if available, preferring installed package path.
    Order: logparse_rs.rust_accel -> logparse_rs (attribute) -> bare rust_accel -> None.
    """
    try:
        from logparse_rs import rust_accel as _ra  # type: ignore
        return _ra
    except Exception:
        try:
            import logparse_rs as _pkg  # type: ignore
            try:
                return _pkg.rust_accel  # type: ignore[attr-defined]
            except Exception:
                pass
        except Exception:
            pass
        try:
            import rust_accel as _ra  # type: ignore
            return _ra
        except Exception:
            return None


def _get_fields(csv_line: str) -> List[str]:
    """Get CSV fields for a Palo Alto syslog line.
    Tries Rust-accelerated splitter if available, else falls back to Python split with basic quotes.
    """
    rust_accel = _import_rust_accel()
    if rust_accel is not None:
        try:
            return rust_accel.get_fields(csv_line)
        except Exception:
            pass
    # Fallback: naive but quote-aware splitter similar to rust_accel._py_split_fields
    fields: List[str] = []
    i = 0
    n = len(csv_line)
    while True:
        if i >= n:
            if n > 0 and csv_line.endswith(','):
                fields.append("")
            break
        if csv_line[i] == '"':
            i += 1
            buf = []
            while i < n:
                ch = csv_line[i]
                if ch == '"':
                    if i + 1 < n and csv_line[i + 1] == '"':
                        buf.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                buf.append(ch)
                i += 1
            while i < n and csv_line[i] != ',':
                i += 1
            fields.append(''.join(buf))
        else:
            buf = []
            while i < n and csv_line[i] != ',':
                buf.append(csv_line[i])
                i += 1
            fields.append(''.join(buf))
        if i < n and csv_line[i] == ',':
            i += 1
    return fields


def _to_identifier(name: str) -> str:
    """Sanitize a schema field name into a valid, non-keyword Python identifier.
    - Lowercase
    - Replace spaces, slashes, hyphens and other non-alnum with underscores
    - Prefix underscore if starts with a digit or is a Python keyword
    """
    s = name.strip().replace(' ', '_').replace('/', '_').replace('-', '_')
    s = ''.join(ch if (ch.isalnum() or ch == '_') else '_' for ch in s)
    s = s.lower()
    if not s or not (s[0].isalpha() or s[0] == '_'):
        s = '_' + s
    if keyword.iskeyword(s):
        s = '_' + s
    return s

# ============================================================================
# CONFIGURATION PARAMETERS - Modify these for your environment
# ============================================================================

# Path to the JSON schema file containing field definitions
# You can override this with env var SCHEMA_JSON_PATH
SCHEMA_JSON_PATH = os.getenv('SCHEMA_JSON_PATH', 'schema/schema.json')

# Path to the sample Palo Alto log file used in demos; override with env var PAN_SAMPLE_LOG_PATH
SAMPLE_LOG_PATH = os.getenv('PAN_SAMPLE_LOG_PATH', 'sample_logs/pan_inc.log')

# Directory to write generated reports; override with env var REPORT_DIR
REPORT_DIR = os.getenv('REPORT_DIR', 'reports')

# ----------------------------------------------------------------------------
# Schema-based code generation cache
# ----------------------------------------------------------------------------
# We avoid regenerating/compiling dynamic parsers on every run by caching
# generated source files keyed by a stable hash of the schema contents and a
# small generator version salt. When the schema changes (or the salt changes),
# we regenerate.
CACHE_DIR = os.getenv('PAN_CACHE_DIR', '.pan_cache')


def _compute_schema_hash(schema_path: str, salt: str = '') -> str:
    hasher = hashlib.sha256()
    # Include generator salt to invalidate cache when codegen logic changes
    if salt:
        hasher.update(salt.encode('utf-8'))
    with open(schema_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hasher.update(chunk)
    # Keep it short but unique enough for file names
    return hasher.hexdigest()[:16]


def _cache_subdir(kind: str) -> Path:
    p = Path(CACHE_DIR) / kind
    p.mkdir(parents=True, exist_ok=True)
    return p


def _import_module_from_path(mod_name: str, file_path: str):
    spec = importlib.util.spec_from_file_location(mod_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f'Cannot load spec for {mod_name} from {file_path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


# ============================================================================
# APPROACH 1: Dynamic Function Generation with compile()
# ============================================================================

class DynamicParserGenerator:
    """Generates and compiles parser functions from JSON field definitions"""
    
    def __init__(self, json_file_path: str):
        """Load JSON field definitions and set up cached compiled parsers"""
        with open(json_file_path, 'r') as f:
            self.schema = json.load(f)
        
        self.compiled_parsers = {}

        # Cache lookup
        force_rebuild = os.getenv('PAN_REBUILD_CACHE', '0') == '1'
        salt = 'dynfunc_v1'
        schema_hash = _compute_schema_hash(json_file_path, salt)
        subdir = _cache_subdir('dynamic')
        module_filename = f'dynamic_{schema_hash}.py'
        module_path = subdir / module_filename
        module_name = f'pan_cache.dynamic_{schema_hash}'

        if (not force_rebuild) and module_path.exists():
            try:
                mod = _import_module_from_path(module_name, str(module_path))
                if hasattr(mod, 'PARSERS'):
                    self.compiled_parsers = dict(mod.PARSERS)
                    return
            except Exception:
                # Fall through to rebuild
                pass

        # Regenerate and cache
        log_types = self.schema['palo_alto_syslog_fields']['log_types']
        parts = [
            "# Auto-generated. Do not edit by hand.",
            "# Cached dynamic function parsers",
            "from datetime import datetime",
            "from pan_dynamic_parser import _get_fields",
            "PARSERS = {}",
            "",
        ]
        for log_type_name, log_type_def in log_types.items():
            field_mappings = []
            for idx, field_info in enumerate(log_type_def['fields']):
                if isinstance(field_info, str):
                    field_name = field_info.replace(' ', '_').replace('/', '_').lower()
                else:
                    field_name = field_info['name'].replace(' ', '_').replace('/', '_').lower()
                field_mappings.append(
                    f"    result['{field_name}'] = fields[{idx}] if len(fields) > {idx} else None"
                )
            func_code = f"""
def parse_{log_type_name}(csv_line: str) -> dict:
    \"\"\"Auto-generated parser for {log_type_def['type_value']} logs\"\"\"
    fields = _get_fields(csv_line)
    result = {{
        '_log_type': '{log_type_def['type_value']}',
        '_log_description': '{log_type_def['description']}',
        '_field_count': {log_type_def['field_count']},
        '_parsed_at': datetime.now().isoformat()
    }}
{chr(10).join(field_mappings)}
    return result
PARSERS['{log_type_def['type_value']}'] = parse_{log_type_name}
"""
            parts.append(func_code)
        module_source = "\n".join(parts)
        _write_text(module_path, module_source)
        mod = _import_module_from_path(module_name, str(module_path))
        self.compiled_parsers = dict(mod.PARSERS)
    
    def _generate_all_parsers(self):
        """Generate parser functions for all log types"""
        log_types = self.schema['palo_alto_syslog_fields']['log_types']
        
        for log_type_name, log_type_def in log_types.items():
            parser_func = self._compile_parser(log_type_name, log_type_def)
            self.compiled_parsers[log_type_def['type_value']] = parser_func
    
    def _compile_parser(self, log_type_name: str, log_type_def: Dict) -> Callable:
        """Compile a parser function for a specific log type"""

        # Generate field mapping code
        field_mappings = []
        for idx, field_info in enumerate(log_type_def['fields']):
            # Handle both string and dict field formats
            if isinstance(field_info, str):
                field_name = field_info.replace(' ', '_').replace('/', '_').lower()
            else:
                field_name = field_info['name'].replace(' ', '_').replace('/', '_').lower()
            field_mappings.append(
                f"    result['{field_name}'] = fields[{idx}] if len(fields) > {idx} else None"
            )
        
        # Generate the complete function code
        func_code = f'''
def parse_{log_type_name}(csv_line: str) -> dict:
    """
    Auto-generated parser for {log_type_def['type_value']} logs
    Description: {log_type_def['description']}
    Field count: {log_type_def['field_count']}
    """
    fields = _get_fields(csv_line)
    result = {{
        '_log_type': '{log_type_def['type_value']}',
        '_log_description': '{log_type_def['description']}',
        '_field_count': {log_type_def['field_count']},
        '_parsed_at': datetime.now().isoformat()
    }}
    
{chr(10).join(field_mappings)}
    
    return result
'''
        
        # Compile the function
        namespace = {'datetime': datetime, '_get_fields': _get_fields}
        exec(compile(func_code, f'<dynamic_{log_type_name}>', 'exec'), namespace)
        
        return namespace[f'parse_{log_type_name}']
    
    def parse(self, csv_line: str) -> Dict:
        """Parse a CSV log line using the appropriate compiled parser"""
        # Use Rust-accelerated extraction for log type when available (fallback to Python)
        rust_accel = _import_rust_accel()
        log_type = rust_accel.get_field(csv_line, 3) if rust_accel is not None else None

        if not log_type:
            raise ValueError("Invalid log format: insufficient fields")

        if log_type not in self.compiled_parsers:
            raise ValueError(f"Unknown log type: {log_type}")

        return self.compiled_parsers[log_type](csv_line)
    
    def get_parser_source(self, log_type: str) -> str:
        """Get the generated source code for a parser (for debugging)"""
        if log_type in self.compiled_parsers:
            import inspect
            return inspect.getsource(self.compiled_parsers[log_type])
        return None


# ============================================================================
# APPROACH 2: Dynamic Class Generation with type()
# ============================================================================

class LogEntryFactory:
    """Dynamically creates dataclass types for each log type"""
    
    def __init__(self, json_file_path: str):
        with open(json_file_path, 'r') as f:
            self.schema = json.load(f)
        
        self.log_classes = {}
        self._generate_all_classes()
    
    def _generate_all_classes(self):
        """Generate dataclass types for all log types"""
        log_types = self.schema['palo_alto_syslog_fields']['log_types']
        
        for log_type_name, log_type_def in log_types.items():
            log_class = self._create_log_class(log_type_name, log_type_def)
            self.log_classes[log_type_def['type_value']] = log_class
    
    def _create_log_class(self, log_type_name: str, log_type_def: Dict):
        """Dynamically create a dataclass for a log type"""

        # Prepare fields for dataclass
        class_fields = {}
        annotations = {}

        for field_info in log_type_def['fields']:
            # Handle both string and dict field formats
            original_name = field_info if isinstance(field_info, str) else field_info['name']
            field_name = _to_identifier(original_name)
            # Skip duplicate field names (like multiple FUTURE_USE)
            if field_name not in class_fields:
                class_fields[field_name] = None
                annotations[field_name] = str
        
        # Create the class dynamically
        class_name = f"{log_type_name.title().replace('_', '')}Log"
        
        # Create namespace with annotations
        namespace = {
            '__annotations__': annotations,
            '__module__': __name__,
            '__doc__': f"{log_type_def['description']}\n\nLog Type: {log_type_def['type_value']}"
        }
        
        # Add default values
        namespace.update(class_fields)
        
        # Create the class
        log_class = type(class_name, (), namespace)
        
        # Make it a dataclass
        log_class = dataclass(log_class)
        
        return log_class
    
    def parse_to_object(self, csv_line: str):
        """Parse CSV line into a typed object"""
        # Use Rust-accelerated extraction for log type when available (fallback to Python)
        rust_accel = _import_rust_accel()
        log_type = rust_accel.get_field(csv_line, 3) if rust_accel is not None else None
        
        if not log_type:
            raise ValueError("Invalid log format")
        
        if log_type not in self.log_classes:
            raise ValueError(f"Unknown log type: {log_type}")
        
        log_class = self.log_classes[log_type]
        
        # Get field names from the schema
        log_type_name = None
        for name, definition in self.schema['palo_alto_syslog_fields']['log_types'].items():
            if definition['type_value'] == log_type:
                log_type_name = name
                break
        
        if not log_type_name:
            raise ValueError(f"Schema not found for log type: {log_type}")
        
        field_defs = self.schema['palo_alto_syslog_fields']['log_types'][log_type_name]['fields']

        # Create kwargs for object instantiation
        kwargs = {}
        seen_fields = set()

        # Split once to populate fields for object creation
        fields = _get_fields(csv_line)
        for idx, field_info in enumerate(field_defs):
            # Handle both string and dict field formats
            original_name = field_info if isinstance(field_info, str) else field_info['name']
            field_name = _to_identifier(original_name)
            if field_name not in seen_fields:
                kwargs[field_name] = fields[idx] if idx < len(fields) else None
                seen_fields.add(field_name)
        
        return log_class(**kwargs)


# ============================================================================
# APPROACH 3: Template-Based Code Generation
# ============================================================================

class TemplateBasedParser:
    """Uses string templates to generate optimized parsers"""
    
    PARSER_TEMPLATE = '''
class {class_name}:
    """
    {description}
    Type: {type_value}
    """
    
    @staticmethod
    def parse(csv_line: str) -> dict:
        fields = _get_fields(csv_line)
        return {{
{field_mappings}
        }}
    
    @staticmethod
    def get_field_info(field_name: str) -> dict:
        field_info = {{
{field_info_map}
        }}
        return field_info.get(field_name, {{}})
'''
    
    def __init__(self, json_file_path: str):
        with open(json_file_path, 'r') as f:
            self.schema = json.load(f)
        
        self.parser_classes = {}

        # Cache lookup
        force_rebuild = os.getenv('PAN_REBUILD_CACHE', '0') == '1'
        salt = 'template_v1'
        schema_hash = _compute_schema_hash(json_file_path, salt)
        subdir = _cache_subdir('template')
        module_filename = f'template_{schema_hash}.py'
        module_path = subdir / module_filename
        module_name = f'pan_cache.template_{schema_hash}'

        if (not force_rebuild) and module_path.exists():
            try:
                mod = _import_module_from_path(module_name, str(module_path))
                if hasattr(mod, 'CLASSES'):
                    self.parser_classes = dict(mod.CLASSES)
                    return
            except Exception:
                # Fall through to rebuild
                pass

        # Regenerate and cache
        log_types = self.schema['palo_alto_syslog_fields']['log_types']
        parts = [
            "# Auto-generated. Do not edit by hand.",
            "# Cached template-based parsers",
            "from pan_dynamic_parser import _get_fields",
            "CLASSES = {}",
            "",
        ]
        for log_type_name, log_type_def in log_types.items():
            # Build class code using the same generator
            class_code = self._generate_parser_code(log_type_name, log_type_def)
            parts.append(class_code)
            class_name = f"{log_type_name.title().replace('_', '')}Parser"
            parts.append(f"CLASSES['{log_type_def['type_value']}'] = {class_name}")
        module_source = "\n".join(parts)
        _write_text(module_path, module_source)
        mod = _import_module_from_path(module_name, str(module_path))
        self.parser_classes = dict(mod.CLASSES)
    
    def _generate_all_parsers(self):
        """Generate parser classes from templates"""
        log_types = self.schema['palo_alto_syslog_fields']['log_types']
        
        for log_type_name, log_type_def in log_types.items():
            parser_code = self._generate_parser_code(log_type_name, log_type_def)
            
            # Compile and execute
            namespace = {'_get_fields': _get_fields}
            exec(parser_code, namespace)
            
            class_name = f"{log_type_name.title().replace('_', '')}Parser"
            self.parser_classes[log_type_def['type_value']] = namespace[class_name]
    
    def _generate_parser_code(self, log_type_name: str, log_type_def: Dict) -> str:
        """Generate parser code from template"""
        
        # Generate field mappings
        field_mappings = []
        field_info_map = []
        
        for idx, field_info in enumerate(log_type_def['fields']):
            field_name = field_info['name'].replace(' ', '_').replace('/', '_').lower()
            safe_name = field_name.replace("'", "\\'")
            safe_desc = field_info['description'].replace("'", "\\'").replace('\n', ' ')
            
            field_mappings.append(
                f"            '{safe_name}': fields[{idx}] if len(fields) > {idx} else None,"
            )
            
            field_info_map.append(
                f"            '{safe_name}': {{'name': '{field_info['name']}', 'description': '{safe_desc}', 'position': {idx}}},"
            )
        
        class_name = f"{log_type_name.title().replace('_', '')}Parser"
        
        return self.PARSER_TEMPLATE.format(
            class_name=class_name,
            description=log_type_def['description'].replace("'", "\\'"),
            type_value=log_type_def['type_value'],
            field_mappings='\n'.join(field_mappings),
            field_info_map='\n'.join(field_info_map)
        )
    
    def parse(self, csv_line: str) -> Dict:
        """Parse using the appropriate generated parser"""
        fields = _get_fields(csv_line)
        
        if len(fields) < 4:
            raise ValueError("Invalid log format")
        
        log_type = fields[3]
        
        if log_type not in self.parser_classes:
            raise ValueError(f"Unknown log type: {log_type}")
        
        return self.parser_classes[log_type].parse(csv_line)


# ============================================================================
# APPROACH 4: AST-Based Dynamic Parser (Most Advanced)
# ============================================================================

import ast

class ASTParserGenerator:
    """Uses AST manipulation for type-safe parser generation"""
    
    def __init__(self, json_file_path: str):
        with open(json_file_path, 'r') as f:
            self.schema = json.load(f)
        
        self.compiled_parsers = {}

        # Cache lookup
        force_rebuild = os.getenv('PAN_REBUILD_CACHE', '0') == '1'
        salt = 'astgen_v1'
        schema_hash = _compute_schema_hash(json_file_path, salt)
        subdir = _cache_subdir('ast')
        module_filename = f'ast_{schema_hash}.py'
        module_path = subdir / module_filename
        module_name = f'pan_cache.ast_{schema_hash}'

        if (not force_rebuild) and module_path.exists():
            try:
                mod = _import_module_from_path(module_name, str(module_path))
                if hasattr(mod, 'PARSERS'):
                    self.compiled_parsers = dict(mod.PARSERS)
                    return
            except Exception:
                # Fall through to rebuild
                pass

        # Regenerate (via AST) then optionally emit equivalent source for cache
        # We'll generate equivalent source functions to make the cache importable
        log_types = self.schema['palo_alto_syslog_fields']['log_types']
        parts = [
            "# Auto-generated. Do not edit by hand.",
            "# Cached AST-based parsers (emitted as source)",
            "from datetime import datetime",
            "from pan_dynamic_parser import _get_fields",
            "PARSERS = {}",
            "",
        ]
        for log_type_name, log_type_def in log_types.items():
            field_mappings = []
            for idx, field_info in enumerate(log_type_def['fields']):
                if isinstance(field_info, str):
                    field_name = field_info.replace(' ', '_').replace('/', '_').lower()
                else:
                    field_name = field_info['name'].replace(' ', '_').replace('/', '_').lower()
                field_mappings.append(
                    f"    result['{field_name}'] = fields[{idx}] if len(fields) > {idx} else None"
                )
            func_code = f"""
def parse_{log_type_name}(csv_line: str) -> dict:
    \"\"\"Auto-generated (AST) parser for {log_type_def['type_value']} logs\"\"\"
    fields = _get_fields(csv_line)
    result = {{
        '_log_type': '{log_type_def['type_value']}',
        '_log_description': '{log_type_def['description']}',
        '_field_count': {log_type_def['field_count']},
        '_parsed_at': datetime.now().isoformat()
    }}
{chr(10).join(field_mappings)}
    return result
PARSERS['{log_type_def['type_value']}'] = parse_{log_type_name}
"""
            parts.append(func_code)
        module_source = "\n".join(parts)
        _write_text(module_path, module_source)
        mod = _import_module_from_path(module_name, str(module_path))
        self.compiled_parsers = dict(mod.PARSERS)
    
    def _generate_all_parsers(self):
        """Generate parsers using AST"""
        log_types = self.schema['palo_alto_syslog_fields']['log_types']
        
        for log_type_name, log_type_def in log_types.items():
            parser_func = self._compile_parser_ast(log_type_name, log_type_def)
            self.compiled_parsers[log_type_def['type_value']] = parser_func
    
    def _compile_parser_ast(self, log_type_name: str, log_type_def: Dict) -> Callable:
        """Compile parser using AST"""
        
        # Build AST for the function
        func_name = f"parse_{log_type_name}"
        
        # Create function arguments
        args = ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg='csv_line', annotation=ast.Name(id='str'))],
            kwonlyargs=[],
            kw_defaults=[],
            defaults=[]
        )
        
        # Create function body
        body = [
            # fields = _get_fields(csv_line)
            ast.Assign(
                targets=[ast.Name(id='fields', ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id='_get_fields', ctx=ast.Load()),
                    args=[ast.Name(id='csv_line', ctx=ast.Load())],
                    keywords=[]
                )
            ),
            # result = {}
            ast.Assign(
                targets=[ast.Name(id='result', ctx=ast.Store())],
                value=ast.Dict(keys=[], values=[])
            )
        ]
        
        # Add field assignments
        for idx, field_info in enumerate(log_type_def['fields']):
            field_name = field_info['name'].replace(' ', '_').replace('/', '_').lower()
            
            # result[field_name] = fields[idx] if len(fields) > idx else None
            body.append(
                ast.Assign(
                    targets=[
                        ast.Subscript(
                            value=ast.Name(id='result', ctx=ast.Load()),
                            slice=ast.Constant(value=field_name),
                            ctx=ast.Store()
                        )
                    ],
                    value=ast.IfExp(
                        test=ast.Compare(
                            left=ast.Call(
                                func=ast.Name(id='len', ctx=ast.Load()),
                                args=[ast.Name(id='fields', ctx=ast.Load())],
                                keywords=[]
                            ),
                            ops=[ast.Gt()],
                            comparators=[ast.Constant(value=idx)]
                        ),
                        body=ast.Subscript(
                            value=ast.Name(id='fields', ctx=ast.Load()),
                            slice=ast.Constant(value=idx),
                            ctx=ast.Load()
                        ),
                        orelse=ast.Constant(value=None)
                    )
                )
            )
        
        # return result
        body.append(ast.Return(value=ast.Name(id='result', ctx=ast.Load())))
        
        # Create function definition
        func_def = ast.FunctionDef(
            name=func_name,
            args=args,
            body=body,
            decorator_list=[],
            returns=ast.Name(id='dict')
        )
        
        # Create module and compile
        module = ast.Module(body=[func_def], type_ignores=[])
        ast.fix_missing_locations(module)
        
        # Compile to code object
        code = compile(module, f'<ast_{log_type_name}>', 'exec')
        
        # Execute to create function
        namespace = {'_get_fields': _get_fields}
        exec(code, namespace)
        
        return namespace[func_name]
    
    def parse(self, csv_line: str) -> Dict:
        """Parse using AST-compiled parser"""
        fields = csv_line.split(',')
        
        if len(fields) < 4:
            raise ValueError("Invalid log format")
        
        log_type = fields[3]
        
        if log_type not in self.compiled_parsers:
            raise ValueError(f"Unknown log type: {log_type}")
        
        return self.compiled_parsers[log_type](csv_line)


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

def _detect_rust_features() -> dict:
    """Detect which Rust acceleration features/backends are available/used.
    Returns a dictionary suitable for printing and inclusion in reports.
    """
    import os as _os
    _ra = _import_rust_accel()
    feats = {}
    has_rust = bool(getattr(_ra, "_HAS_RUST", False)) if _ra else False
    feats["has_rust_extension"] = has_rust

    # Backends used by shim
    feats["csv_tokenizer_backend"] = "Rust" if has_rust else "Python"
    feats["type_subtype_backend"] = "Rust" if has_rust else "Python"

    # KV parsing backend availability
    kv_backend = "Rust" if has_rust else "Python"
    try:
        # Presence of Rust KV functions inside shim internals
        if not has_rust or getattr(_ra, "_rs_parse_kv", None) is None:
            kv_backend = "Python"
    except Exception:
        kv_backend = "Unknown"
    feats["kv_parsing_backend"] = kv_backend

    # Embedded schema support (compile-time feature)
    embedded_supported = bool(getattr(_ra, "_rs_load_embedded_schema", None)) if _ra else False
    feats["embedded_schema_supported"] = embedded_supported

    # Read environment request flags
    use_embedded_env = _os.getenv("PAN_RUST_USE_EMBEDDED") == "1"
    feats["embedded_schema_requested"] = use_embedded_env

    # Query actual runtime schema status from rust_accel if available
    status = None
    try:
        if _ra and hasattr(_ra, "get_schema_status"):
            status = _ra.get_schema_status()  # type: ignore[attr-defined]
    except Exception:
        status = None

    # Determine whether embedded schema is actually loaded
    embedded_loaded = False
    if isinstance(status, dict):
        try:
            embedded_loaded = bool(status.get("loaded") and status.get("source") == "embedded")
        except Exception:
            embedded_loaded = False
    else:
        # Fallback heuristic if no status available
        embedded_loaded = bool(embedded_supported and use_embedded_env and has_rust)
    feats["embedded_schema_loaded"] = embedded_loaded

    # Schema preload mode and path should reflect actual loaded source when possible
    preload_mode = "none"
    preload_path = None
    if isinstance(status, dict) and status.get("loaded"):
        src = status.get("source")
        if src == "embedded":
            preload_mode = "embedded"
            preload_path = None
        elif src == "file":
            preload_mode = "file"
            try:
                preload_path = status.get("path")
            except Exception:
                preload_path = None
    else:
        # Fall back to environment-based expectation
        env_path = _os.getenv("PAN_RUST_PRELOAD_SCHEMA") or _os.getenv("SCHEMA_JSON_PATH")
        if use_embedded_env and embedded_supported:
            preload_mode = "embedded"
            preload_path = None
        elif env_path:
            preload_mode = "file"
            preload_path = env_path
        else:
            preload_mode = "none"
            preload_path = None

    feats["schema_preload_mode"] = preload_mode
    feats["schema_preload_path"] = preload_path

    return feats


def main():
    """Demonstrate all approaches"""
    
    # Load sample Palo Alto syslog entries from file and strip syslog prefix (uses global SAMPLE_LOG_PATH)
    # You can override SAMPLE_LOG_PATH via env var PAN_SAMPLE_LOG_PATH

    def extract_csv(line: str) -> str:
        """Extract the CSV portion from a syslog line. Looks for the first occurrence of ' 1,' and returns the substring starting at '1,'. If not found, returns the trimmed line."""
        idx = line.find(' 1,')
        return line[idx + 1:].strip() if idx != -1 else line.strip()

    try:
        with open(SAMPLE_LOG_PATH, 'r') as f:
            sample_logs = [extract_csv(l) for l in f if l.strip()]
    except FileNotFoundError:
        print("Note: Sample log file not found. Using empty sample list.")
        sample_logs = []
    
    print("=" * 80)
    print("PALO ALTO NETWORKS DYNAMIC PARSER DEMONSTRATION")
    print("=" * 80)

    # If requested, proactively load the embedded schema for this demo
    try:
        if os.getenv("PAN_RUST_USE_EMBEDDED") == "1":
            _ra = _import_rust_accel()
            if _ra and getattr(_ra, "load_embedded_schema", None):
                _ra.load_embedded_schema()
    except Exception:
        # Keep the demo resilient; feature detection below will still reflect availability
        pass

    # Show which Rust acceleration features/backends are active
    feats = _detect_rust_features()
    print("\n[Rust acceleration features]")
    print("-" * 80)
    for _k, _v in feats.items():
        print(f"{_k}: {_v}")

    # Compiled (Rust) Acceleration Test
    print("\n[0] Compiled (Rust) Acceleration Test")
    print("-" * 80)
    t0 = time.perf_counter()
    try:
        rust_accel = _import_rust_accel()
        accel = bool(getattr(rust_accel, "_HAS_RUST", False)) if rust_accel else False
        line = sample_logs[0] if sample_logs else ""
        if line:
            fields0 = rust_accel.get_fields(line) if rust_accel else _get_fields(line)
            t1 = time.perf_counter()
            print(f"Accelerated backend: {'Rust' if accel else 'Python'}")
            print(f"Fields parsed: {len(fields0)}")
            print(f"Runtime: {(t1 - t0)*1000:.2f} ms")
        else:
            t1 = time.perf_counter()
            print("No sample logs available")
            print(f"Accelerated backend: {'Rust' if accel else 'Python'}")
            print(f"Runtime: {(t1 - t0)*1000:.2f} ms")
    except Exception as e:
        t1 = time.perf_counter()
        print(f"Compiled test failed: {e}")
        print(f"Runtime: {(t1 - t0)*1000:.2f} ms")
    
    # Approach 1: Dynamic Function Generation
    print("\n[1] Dynamic Function Generation (compile/exec)")
    print("-" * 80)
    t0 = time.perf_counter()
    try:
        parser1 = DynamicParserGenerator(SCHEMA_JSON_PATH)
        for log in sample_logs[:1]:  # Parse first log only
            result = parser1.parse(log)
            print(f"Log Type: {result['_log_type']}")
            print(f"Source: {result.get('source_address', 'N/A')}")
            print(f"Destination: {result.get('destination_address', 'N/A')}")
            print(f"Application: {result.get('application', 'N/A')}")
    except FileNotFoundError:
        print("Note: JSON schema file not found. This would work with actual file.")
    except Exception as e:
        print(f"Note: {e}")
    finally:
        t1 = time.perf_counter()
        print(f"Runtime: {(t1 - t0)*1000:.2f} ms")
    
    # Approach 2: Dynamic Class Generation
    print("\n[2] Dynamic Class Generation (dataclasses)")
    print("-" * 80)
    t0 = time.perf_counter()
    try:
        factory = LogEntryFactory(SCHEMA_JSON_PATH)
        for log in sample_logs[:1]:
            log_obj = factory.parse_to_object(log)
            print(f"Object Type: {type(log_obj).__name__}")
            print(f"Source: {log_obj.source_address}")
    except FileNotFoundError:
        print("Note: JSON schema file not found. This would work with actual file.")
    except Exception as e:
        print(f"Note: {e}")
    finally:
        t1 = time.perf_counter()
        print(f"Runtime: {(t1 - t0)*1000:.2f} ms")
    
    # Approach 3: Template-Based
    print("\n[3] Template-Based Parser Generation")
    print("-" * 80)
    t0 = time.perf_counter()
    try:
        parser3 = TemplateBasedParser(SCHEMA_JSON_PATH)
        for log in sample_logs[:1]:
            result = parser3.parse(log)
            print(f"Parsed {len(result)} fields")
    except FileNotFoundError:
        print("Note: JSON schema file not found. This would work with actual file.")
    except Exception as e:
        print(f"Note: {e}")
    finally:
        t1 = time.perf_counter()
        print(f"Runtime: {(t1 - t0)*1000:.2f} ms")
    
    # Approach 4: AST-Based
    print("\n[4] AST-Based Parser Generation")
    print("-" * 80)
    t0 = time.perf_counter()
    try:
        parser4 = ASTParserGenerator(SCHEMA_JSON_PATH)
        for log in sample_logs[:1]:
            result = parser4.parse(log)
            print(f"AST-parsed {len(result)} fields")
    except FileNotFoundError:
        print("Note: JSON schema file not found. This would work with actual file.")
    except Exception as e:
        print(f"Note: {e}")
    finally:
        t1 = time.perf_counter()
        print(f"Runtime: {(t1 - t0)*1000:.2f} ms")

    # Report Generation
    print("\n[5] Report Generation")
    print("-" * 80)
    t0 = time.perf_counter()
    try:
        # Initialize all parsers
        parsers = {}
        per_parser_stats = {}
        # Build parser instances with timing
        build_times = {}
        # Rust-backed generic parser that maps fields using the schema and uses the Rust splitter directly
        try:
            bt0 = time.perf_counter()
            # Load schema once to build mapping from type_value to field original names
            with open(SCHEMA_JSON_PATH, 'r') as _sf:
                _schema_obj = json.load(_sf)
            _lt_defs = _schema_obj['palo_alto_syslog_fields']['log_types']
            _type_to_names = {}
            for _name, _def in _lt_defs.items():
                _names = []
                for _fi in _def['fields']:
                    _orig = _fi if isinstance(_fi, str) else _fi.get('name', '')
                    _names.append(_orig)
                _type_to_names[_def['type_value']] = _names
            # Precompute sanitized keys per log type to avoid per-line cost
            _type_to_keys = { _tv: [_to_identifier(_orig) for _orig in _names] for _tv, _names in _type_to_names.items() }
            _rust_accel = _import_rust_accel()
            _accel = bool(getattr(_rust_accel, '_HAS_RUST', False)) if _rust_accel else False
            def rust_backend_parse(line: str) -> Dict[str, Any]:
                fields_local = (_rust_accel.get_fields(line) if _rust_accel is not None else _get_fields(line))
                res: Dict[str, Any] = {}
                lt_local = fields_local[3] if len(fields_local) > 3 else None
                if lt_local and lt_local in _type_to_keys:
                    _keys = _type_to_keys[lt_local]
                    # Assign using precomputed keys
                    for _idx, _key in enumerate(_keys):
                        res[_key] = fields_local[_idx] if _idx < len(fields_local) else None
                if lt_local:
                    res['_log_type'] = lt_local
                return res
            # Attach metadata to indicate whether Rust extension is active
            setattr(rust_backend_parse, 'accelerated', _accel)
            setattr(rust_backend_parse, 'backend', 'Rust' if _accel else 'Python')
            setattr(rust_backend_parse, 'hint', 'Install Rust toolchain and run: maturin develop -m rust_ext/pan_rust/Cargo.toml' if not _accel else '')
            parsers['rust_backend'] = rust_backend_parse
            build_times['rust_backend_build_ms'] = (time.perf_counter() - bt0) * 1000.0
        except Exception as e:
            per_parser_stats['rust_backend'] = {'error': f'build failed: {e}'}
        try:
            bt0 = time.perf_counter()
            parsers['dynamic_function'] = DynamicParserGenerator(SCHEMA_JSON_PATH).parse
            build_times['dynamic_function_build_ms'] = (time.perf_counter() - bt0) * 1000.0
        except Exception as e:
            per_parser_stats['dynamic_function'] = {'error': f'build failed: {e}'}
        try:
            bt0 = time.perf_counter()
            factory_inst = LogEntryFactory(SCHEMA_JSON_PATH)
            def _class_parse(line: str):
                obj = factory_inst.parse_to_object(line)
                # Convert dataclass instance to dict
                try:
                    return asdict(obj)
                except Exception:
                    return obj.__dict__
            parsers['dynamic_class'] = _class_parse
            build_times['dynamic_class_build_ms'] = (time.perf_counter() - bt0) * 1000.0
        except Exception as e:
            per_parser_stats['dynamic_class'] = {'error': f'build failed: {e}'}
        try:
            bt0 = time.perf_counter()
            parsers['template_based'] = TemplateBasedParser(SCHEMA_JSON_PATH).parse
            build_times['template_based_build_ms'] = (time.perf_counter() - bt0) * 1000.0
        except Exception as e:
            per_parser_stats['template_based'] = {'error': f'build failed: {e}'}
        try:
            bt0 = time.perf_counter()
            parsers['ast_based'] = ASTParserGenerator(SCHEMA_JSON_PATH).parse
            build_times['ast_based_build_ms'] = (time.perf_counter() - bt0) * 1000.0
        except Exception as e:
            per_parser_stats['ast_based'] = {'error': f'build failed: {e}'}

        # Helper to collect stats for a given parser
        def collect_stats(parse_fn: Callable[[str], Dict[str, Any]], logs: List[str]) -> Dict[str, Any]:
            total = 0
            errs = 0
            by_type = Counter()
            by_action = Counter()
            srcs = Counter()
            dsts = Counter()
            apps = Counter()
            sample_traffic = None
            sample_threat = None
            tstart = time.perf_counter()
            for line in logs:
                if not line:
                    continue
                try:
                    res = parse_fn(line)
                except Exception:
                    errs += 1
                    continue
                total += 1
                lt = res.get('_log_type') or res.get('type') or res.get('log_type')
                if not lt:
                    # attempt to derive via field position 4
                    fields_local = _get_fields(line)
                    if len(fields_local) > 3:
                        lt = fields_local[3]
                by_type.update([lt or 'unknown'])
                if lt == 'TRAFFIC' and sample_traffic is None:
                    sample_traffic = res
                elif lt == 'THREAT' and sample_threat is None:
                    sample_threat = res
                action = res.get('action')
                if action:
                    by_action.update([action])
                sa = res.get('source_address') or res.get('source')
                if sa:
                    srcs.update([sa])
                da = res.get('destination_address') or res.get('destination')
                if da:
                    dsts.update([da])
                app = res.get('application')
                if app:
                    apps.update([app])
            telapsed = (time.perf_counter() - tstart) * 1000.0
            return {
                'runtime_ms': telapsed,
                'total_logs': total,
                'errors': errs,
                'by_log_type': dict(by_type.most_common()),
                'by_action': dict(by_action.most_common()),
                'top_sources': [{'value': k, 'count': v} for k, v in srcs.most_common(10)],
                'top_destinations': [{'value': k, 'count': v} for k, v in dsts.most_common(10)],
                'top_applications': [{'value': k, 'count': v} for k, v in apps.most_common(10)],
                'example_kv_pairs': {
                    'traffic': sample_traffic,
                    'threat': sample_threat,
                }
            }

        # Build per-parser stats over all logs
        for pname, pfn in parsers.items():
            if pname in per_parser_stats and 'error' in per_parser_stats[pname]:
                continue
            per_parser_stats[pname] = collect_stats(pfn, sample_logs)
            # If parser exposes an 'accelerated' attribute, include it in the stats for visibility
            if hasattr(pfn, 'accelerated'):
                try:
                    per_parser_stats[pname]['accelerated'] = bool(getattr(pfn, 'accelerated'))
                except Exception:
                    per_parser_stats[pname]['accelerated'] = None
            # Also include optional backend and hint metadata if present
            if hasattr(pfn, 'backend'):
                try:
                    per_parser_stats[pname]['backend'] = str(getattr(pfn, 'backend'))
                except Exception:
                    per_parser_stats[pname]['backend'] = None
            if hasattr(pfn, 'hint'):
                try:
                    per_parser_stats[pname]['hint'] = str(getattr(pfn, 'hint'))
                except Exception:
                    per_parser_stats[pname]['hint'] = None
            # Record which CSV tokenizer backend was used globally
            try:
                per_parser_stats[pname]['csv_backend'] = feats.get('csv_tokenizer_backend')
            except Exception:
                pass

        # Build a combined summary from dynamic_function if available, else first successful parser
        combined_key = 'dynamic_function' if 'dynamic_function' in per_parser_stats and 'error' not in per_parser_stats['dynamic_function'] else None
        if not combined_key:
            for k, v in per_parser_stats.items():
                if isinstance(v, dict) and 'error' not in v:
                    combined_key = k
                    break

        combined = per_parser_stats.get(combined_key, {}) if combined_key else {}

        # Advanced benchmark (leveraging benchmark_advanced.py)
        adv_result = None
        try:
            # Import the advanced benchmark module from this examples directory
            try:
                import benchmark_advanced as ba  # type: ignore
            except Exception:
                ba = None  # type: ignore
            if ba is not None:
                iterations = int(os.getenv('PAN_BENCH_ITER', '20'))
                warmup = int(os.getenv('PAN_BENCH_WARMUP', '2'))
                rust_parallel = os.getenv('PAN_BENCH_RUST_PARALLEL', '1').strip().lower() in ('1','true','yes')
                batch_size = int(os.getenv('PAN_BENCH_BATCH_SIZE', '1024'))
                _rt = os.getenv('PAN_BENCH_RAYON_THREADS')
                rayon_threads = int(_rt) if _rt else None

                # Run both modes (Rust and Python). Anonymized is False here for comparability.
                rust_iters, rust_lines = ba.run_mode(
                    SAMPLE_LOG_PATH,
                    mode="rust",
                    iterations=iterations,
                    warmup=warmup,
                    anonymized=False,
                    schema_path=SCHEMA_JSON_PATH,
                    include_all=False,
                    encoding="utf-8",
                    errors="ignore",
                    use_parallel=rust_parallel,
                    batch_size=batch_size,
                    rayon_threads=rayon_threads,
                )
                py_iters, py_lines = ba.run_mode(
                    SAMPLE_LOG_PATH,
                    mode="python",
                    iterations=iterations,
                    warmup=warmup,
                    anonymized=False,
                    schema_path=SCHEMA_JSON_PATH,
                    include_all=False,
                    encoding="utf-8",
                    errors="ignore",
                    use_parallel=False,
                    batch_size=batch_size,
                    rayon_threads=rayon_threads,
                )

                # Summaries (reuse helper from advanced benchmark)
                r_wall = [it.wall_ms for it in rust_iters]
                p_wall = [it.wall_ms for it in py_iters]
                r_int = [it.internal_ms for it in rust_iters if it.internal_ms == it.internal_ms]
                p_int = [it.internal_ms for it in py_iters if it.internal_ms == it.internal_ms]
                r_cpu = [it.cpu_ms for it in rust_iters if it.cpu_ms == it.cpu_ms]
                p_cpu = [it.cpu_ms for it in py_iters if it.cpu_ms == it.cpu_ms]

                rust_summary = {
                    "wall_ms": ba._summary(r_wall),  # type: ignore[attr-defined]
                    "internal_ms": ba._summary(r_int),  # type: ignore[attr-defined]
                    "cpu_ms": ba._summary(r_cpu),  # type: ignore[attr-defined]
                }
                py_summary = {
                    "wall_ms": ba._summary(p_wall),  # type: ignore[attr-defined]
                    "internal_ms": ba._summary(p_int),  # type: ignore[attr-defined]
                    "cpu_ms": ba._summary(p_cpu),  # type: ignore[attr-defined]
                }

                def _thr(mean_wall_ms: float, lines: int) -> float:
                    if lines <= 0 or not mean_wall_ms or mean_wall_ms != mean_wall_ms:
                        return float("nan")
                    return float(lines) / (mean_wall_ms / 1000.0)

                r_thr = _thr(rust_summary["wall_ms"]["mean"], rust_lines)
                p_thr = _thr(py_summary["wall_ms"]["mean"], py_lines)

                # Bottleneck hints
                r_hint = ba._bottleneck_hint(
                    rust_summary["wall_ms"]["mean"],
                    rust_summary["internal_ms"]["mean"],
                    rust_summary["cpu_ms"]["mean"],
                )  # type: ignore[attr-defined]
                p_hint = ba._bottleneck_hint(
                    py_summary["wall_ms"]["mean"],
                    py_summary["internal_ms"]["mean"],
                    py_summary["cpu_ms"]["mean"],
                )  # type: ignore[attr-defined]

                # Plot
                ts_plot = datetime.now().strftime('%Y%m%d_%H%M%S')
                bench_plot_path = os.path.join(REPORT_DIR, f'benchmark_advanced_{ts_plot}.png')
                try:
                    ba.plot_results(  # type: ignore[attr-defined]
                        bench_plot_path,
                        rust_iters,
                        py_iters,
                        f"Parsing benchmark (advanced): {os.path.basename(SAMPLE_LOG_PATH)}",
                        rust_lines or py_lines,
                    )
                except Exception:
                    pass

                adv_result = {
                    "file": SAMPLE_LOG_PATH,
                    "schema": SCHEMA_JSON_PATH,
                    "iterations": iterations,
                    "warmup": warmup,
                    "rust_mode": ("parallel" if rust_parallel else "sequential"),
                    "lines_per_file": rust_lines or py_lines,
                    "results": {
                        "rust": {
                            "lines": rust_lines,
                            "throughput_lines_per_sec_mean": r_thr,
                            "wall_ms": rust_summary["wall_ms"],
                            "internal_ms_from_records": rust_summary["internal_ms"],
                            "cpu_time_ms": rust_summary["cpu_ms"],
                            "bottleneck_hint": r_hint,
                        },
                        "python": {
                            "lines": py_lines,
                            "throughput_lines_per_sec_mean": p_thr,
                            "wall_ms": py_summary["wall_ms"],
                            "internal_ms_from_records": py_summary["internal_ms"],
                            "cpu_time_ms": py_summary["cpu_ms"],
                            "bottleneck_hint": p_hint,
                        },
                    },
                    "speedup_python_over_rust": (
                        (py_summary["wall_ms"]["mean"] / rust_summary["wall_ms"]["mean"]) if rust_summary["wall_ms"]["mean"] == rust_summary["wall_ms"]["mean"] else float("nan")
                    ),
                    "plot": bench_plot_path,
                }

                # Brief console summary
                try:
                    print("\n[Advanced Benchmark]")
                    print("-" * 80)
                    print(
                        f"Rust mean wall: {rust_summary['wall_ms']['mean']:.2f} ms | "
                        f"Python mean wall: {py_summary['wall_ms']['mean']:.2f} ms | "
                        f"Speedup: {adv_result['speedup_python_over_rust']:.2f}x | "
                        f"Rust throughput: {r_thr:.1f} lines/s"
                    )
                    print(f"Bottleneck (Rust): {r_hint} | Bottleneck (Python): {p_hint}")
                    if os.path.exists(bench_plot_path):
                        print(f"Advanced benchmark plot: {bench_plot_path}")
                except Exception:
                    pass
        except Exception as _adv_e:
            adv_result = {"error": str(_adv_e)}

        report = {
            'generated_at': datetime.now().isoformat(),
            'summary_from': combined_key,
            'total_logs': combined.get('total_logs', 0),
            'errors': combined.get('errors', 0),
            'by_log_type': combined.get('by_log_type', {}),
            'by_action': combined.get('by_action', {}),
            'top_sources': combined.get('top_sources', []),
            'top_destinations': combined.get('top_destinations', []),
            'top_applications': combined.get('top_applications', []),
            'example_kv_pairs': combined.get('example_kv_pairs', {}),
            'parsers': per_parser_stats,
            'build_times_ms': build_times,
            'rust_acceleration': feats,
            'advanced_benchmark': adv_result,
        }

        # Ensure directory and write JSON
        try:
            os.makedirs(REPORT_DIR, exist_ok=True)
        except Exception:
            pass
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(REPORT_DIR, f'pan_report_{ts}.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report written to: {report_path}")
        # Print brief console summary
        if combined:
            print(f"Total logs (from {combined_key}): {combined.get('total_logs', 0)} | Errors: {combined.get('errors', 0)}")
            by_type = combined.get('by_log_type', {})
            if by_type:
                items = list(by_type.items())[:5]
                print("Top log types:", ", ".join(f"{k}={v}" for k, v in items))
            by_action = combined.get('by_action', {})
            if by_action:
                items = list(by_action.items())[:5]
                print("Top actions:", ", ".join(f"{k}={v}" for k, v in items))
            kv = combined.get('example_kv_pairs', {})
            if kv.get('traffic'):
                print(f"Included KV sample for TRAFFIC with {len(kv['traffic'])} keys")
            else:
                print("No TRAFFIC sample found for KV demo")
            if kv.get('threat'):
                print(f"Included KV sample for THREAT with {len(kv['threat'])} keys")
            else:
                print("No THREAT sample found for KV demo")
        else:
            print("No successful parser results to summarize.")
    except Exception as e:
        print(f"Note: failed to generate report: {e}")
    finally:
        t1 = time.perf_counter()
        print(f"Runtime: {(t1 - t0)*1000:.2f} ms")
    
    print("\n" + "=" * 80)
    print("All approaches successfully demonstrated!")
    print("=" * 80)


if __name__ == "__main__":
    main()
