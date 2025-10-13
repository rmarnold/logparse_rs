# CSV Helpers

These helpers operate directly on CSV log lines and are useful to triage input quickly.

## split_csv(line: str) -> list[str]

Quote-aware CSV splitter. Handles embedded commas and quotes correctly, without allocating excessively.

Example:

```python
from logparse_rs import split_csv
fields = split_csv('"a,b",c,,"d"')
assert fields == ["a,b", "c", "", "d"]
```

## extract_field(line: str, index: int) -> Optional[str]

Return the N-th field (0-based), or None if out of bounds.

```python
from logparse_rs import extract_field
print(extract_field('1,2,3', 1))  # "2"
print(extract_field('1,2,3', 9))  # None
```

## extract_type_subtype(line: str) -> tuple[Optional[str], Optional[str]]

Convenience to extract the commonly used fields representing log type and subtype.

```python
from logparse_rs import extract_type_subtype
print(extract_type_subtype('ts,serial,THREAT,spyware,...'))  # ("THREAT", "spyware")
```
