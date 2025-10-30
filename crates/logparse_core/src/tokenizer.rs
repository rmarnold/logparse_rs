// tokenizer.rs: CSV extraction and splitting utilities
use memchr::{memchr, memchr_iter};

pub fn extract_field_internal(line: &str, target_idx: usize) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();
    let mut idx = 0usize;

    while idx <= target_idx && i <= n {
        if i >= n {
            if idx == target_idx {
                return Some(String::new());
            } else {
                return None;
            }
        }
        let mut field = String::new();
        if bytes[i] == b'"' {
            i += 1;
            while i < n {
                let b = bytes[i];
                if b == b'"' {
                    if i + 1 < n && bytes[i + 1] == b'"' {
                        field.push('"');
                        i += 2;
                        continue;
                    } else {
                        i += 1;
                        break;
                    }
                } else {
                    field.push(b as char);
                    i += 1;
                }
            }
            while i < n && bytes[i] != b',' {
                i += 1;
            }
        } else {
            if let Some(pos) = memchr(b',', &bytes[i..]) {
                let end = i + pos;
                match std::str::from_utf8(&bytes[i..end]) {
                    Ok(s) => field.push_str(s),
                    Err(_) => field.extend((&bytes[i..end]).iter().map(|&b| b as char)),
                }
                i = end;
            } else {
                match std::str::from_utf8(&bytes[i..]) {
                    Ok(s) => field.push_str(s),
                    Err(_) => field.extend((&bytes[i..]).iter().map(|&b| b as char)),
                }
                i = n;
            }
        }
        if i < n && bytes[i] == b',' {
            i += 1;
        }
        if idx == target_idx {
            return Some(field);
        }
        idx += 1;
    }
    None
}

pub fn split_csv_internal(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();
    // Pre-reserve capacity based on comma count to reduce reallocations
    let approx_fields = memchr_iter(b',', bytes).count() + 1;
    let mut out: Vec<String> = Vec::with_capacity(approx_fields.max(8));

    while i <= n {
        if i >= n {
            if n > 0 && bytes.get(n.wrapping_sub(1)) == Some(&b',') {
                out.push(String::new());
            }
            break;
        }
        // Small initial capacity helps for short fields and avoids many growth steps
        let mut field = String::with_capacity(16);
        if bytes[i] == b'"' {
            i += 1;
            while i < n {
                let b = bytes[i];
                if b == b'"' {
                    if i + 1 < n && bytes[i + 1] == b'"' {
                        field.push('"');
                        i += 2;
                    } else {
                        i += 1;
                        break;
                    }
                } else {
                    field.push(b as char);
                    i += 1;
                }
            }
            while i < n && bytes[i] != b',' {
                i += 1;
            }
        } else {
            if let Some(pos) = memchr(b',', &bytes[i..]) {
                let end = i + pos;
                match std::str::from_utf8(&bytes[i..end]) {
                    Ok(s) => field.push_str(s),
                    Err(_) => field.extend((&bytes[i..end]).iter().map(|&b| b as char)),
                }
                i = end;
            } else {
                match std::str::from_utf8(&bytes[i..]) {
                    Ok(s) => field.push_str(s),
                    Err(_) => field.extend((&bytes[i..]).iter().map(|&b| b as char)),
                }
                i = n;
            }
        }
        if i < n && bytes[i] == b',' {
            i += 1;
        }
        out.push(field);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::{extract_field_internal, split_csv_internal};

    #[test]
    fn test_split_csv_internal_basic_and_quotes() {
        // Basic
        assert_eq!(split_csv_internal("a,b,c"), vec!["a", "b", "c"]);
        // Quoted with comma and escaped quotes
        assert_eq!(split_csv_internal("\"a,b\",\"c\"\"d\"\"e\",f"), vec!["a,b", "c\"d\"e", "f"]);
        // Trailing empty field
        assert_eq!(split_csv_internal("a,b,"), vec!["a", "b", ""]);
        // Empty string
        let v: Vec<String> = split_csv_internal("");
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn test_extract_field_internal() {
        // Validate consistency with split_csv_internal for a variety of inputs
        let cases = vec![
            "a,b,c",
            "a,\"b,c\",d,,e",
            ",leading,comma",
            "trailing,comma,",
            "quoted,\"\"\"q\"\"\"", // field with embedded quotes => "q"
        ];
        for line in cases {
            let split = split_csv_internal(line);
            // In-range indices should match split_csv_internal exactly
            for idx in 0..split.len() {
                let got = extract_field_internal(line, idx);
                let want = split.get(idx).cloned();
                assert_eq!(got, want, "mismatch at idx={} for line={}", idx, line);
            }
            // Edge: idx == len
            let edge = extract_field_internal(line, split.len());
            let expected_edge = if line.ends_with(',') { None } else { Some(String::new()) };
            assert_eq!(
                edge,
                expected_edge,
                "edge mismatch at len={} for line={}",
                split.len(),
                line
            );
            // Out of range beyond len
            assert_eq!(extract_field_internal(line, split.len() + 1), None);
        }
    }
}
