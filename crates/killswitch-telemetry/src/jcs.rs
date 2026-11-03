//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Provides deterministic UTF-8 byte serialization of arbitrary JSON values:
//! - Strict lexicographic key ordering by UTF-16 code unit values.
//! - Whitespace elimination (no extraneous spaces, tabs, or newlines).
//! - Deterministic ECMAScript number formatting (-0 normalized to 0, no trailing .0).
//! - Standard JSON string escaping (\b, \f, \n, \r, \t, and \u00XX for control characters).

use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum JcsError {
    #[error("Non-finite number (NaN or Infinity) is not supported in RFC 8785 JCS")]
    NonFiniteNumber,
    #[error("UTF-8 encoding error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

/// Canonicalizes a JSON Value per RFC 8785, returning the canonical UTF-8 bytes.
pub fn canonicalize_jcs(val: &Value) -> Result<Vec<u8>, JcsError> {
    let mut buf = Vec::new();
    serialize_val(val, &mut buf)?;
    Ok(buf)
}

/// Canonicalizes a JSON Value per RFC 8785, returning a UTF-8 string.
pub fn canonicalize_jcs_string(val: &Value) -> Result<String, JcsError> {
    let bytes = canonicalize_jcs(val)?;
    Ok(String::from_utf8(bytes)?)
}

fn serialize_val(val: &Value, buf: &mut Vec<u8>) -> Result<(), JcsError> {
    match val {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(true) => buf.extend_from_slice(b"true"),
        Value::Bool(false) => buf.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                buf.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                buf.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(JcsError::NonFiniteNumber);
                }
                let formatted = format_ecma_float(f);
                buf.extend_from_slice(formatted.as_bytes());
            }
        }
        Value::String(s) => {
            buf.push(b'"');
            for c in s.chars() {
                match c {
                    '"' => buf.extend_from_slice(b"\\\""),
                    '\\' => buf.extend_from_slice(b"\\\\"),
                    '\x08' => buf.extend_from_slice(b"\\b"),
                    '\x0C' => buf.extend_from_slice(b"\\f"),
                    '\n' => buf.extend_from_slice(b"\\n"),
                    '\r' => buf.extend_from_slice(b"\\r"),
                    '\t' => buf.extend_from_slice(b"\\t"),
                    ch if (ch as u32) < 0x20 => {
                        let esc = format!("\\u{:04x}", ch as u32);
                        buf.extend_from_slice(esc.as_bytes());
                    }
                    ch => {
                        let mut b = [0u8; 4];
                        buf.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                    }
                }
            }
            buf.push(b'"');
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                serialize_val(elem, buf)?;
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            buf.push(b'{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // RFC 8785: Keys must be ordered lexicographically by UTF-16 code units
            entries.sort_by(|(k1, _), (k2, _)| k1.encode_utf16().cmp(k2.encode_utf16()));
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                serialize_val(&Value::String(key.clone()), buf)?;
                buf.push(b':');
                serialize_val(value, buf)?;
            }
            buf.push(b'}');
        }
    }
    Ok(())
}

fn format_ecma_float(f: f64) -> String {
    if f == 0.0 {
        return "0".to_string();
    }
    let abs_f = f.abs();

    if abs_f >= 1e21 {
        // Scientific notation with 'e+' per ECMAScript / RFC 8785
        let s = format!("{:e}", f);
        if let Some(pos) = s.find('e') {
            let (mantissa, exp) = s.split_at(pos);
            let exp_val: i32 = exp[1..].parse().unwrap_or(0);
            if exp_val >= 0 {
                format!("{}e+{}", mantissa, exp_val)
            } else {
                format!("{}e{}", mantissa, exp_val)
            }
        } else {
            s
        }
    } else if abs_f < 1e-6 {
        // Scientific notation with 'e-' per ECMAScript / RFC 8785
        format!("{:e}", f)
    } else if f.fract() == 0.0 {
        if abs_f <= i64::MAX as f64 {
            (f as i64).to_string()
        } else {
            (f as i128).to_string()
        }
    } else {
        f.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_rfc8785_key_sorting() {
        let val = json!({
            "b": 2,
            "a": 1,
            "aa": 3,
            "1": 0
        });
        let canonical = canonicalize_jcs_string(&val).unwrap();
        assert_eq!(canonical, r#"{"1":0,"a":1,"aa":3,"b":2}"#);
    }

    #[test]
    fn test_rfc8785_whitespace_elimination() {
        let raw = r#"{ "x" :   [ 1 ,  2 , 3 ] , "y" : null }"#;
        let val: Value = serde_json::from_str(raw).unwrap();
        let canonical = canonicalize_jcs_string(&val).unwrap();
        assert_eq!(canonical, r#"{"x":[1,2,3],"y":null}"#);
    }

    #[test]
    fn test_rfc8785_utf16_code_unit_sorting() {
        // In UTF-16: "\u0080" (code unit 0x0080) precedes "\uFFFF" (0xFFFF)
        // Surrogate pair: U+10000 encodes to [0xD800, 0xDC00] in UTF-16.
        // It should be sorted by the lead surrogate 0xD800, which is < 0xE000.
        let val = json!({
            "\u{E000}": 1,
            "\u{10000}": 2
        });
        let canonical = canonicalize_jcs_string(&val).unwrap();
        // Lead surrogate 0xD800 < 0xE000, so "\u{10000}" comes first
        let expected = format!(r#"{{"{}":2,"{}":1}}"#, "\u{10000}", "\u{E000}");
        assert_eq!(canonical, expected);
    }

    #[test]
    fn test_rfc8785_escaping() {
        let val = json!({
            "msg": "hello\nworld\t\"quoted\"\\backslash\x08backspace\x0Cformfeed\rreturn"
        });
        let canonical = canonicalize_jcs_string(&val).unwrap();
        assert_eq!(
            canonical,
            r#"{"msg":"hello\nworld\t\"quoted\"\\backslash\bbackspace\fformfeed\rreturn"}"#
        );
    }

    #[test]
    fn test_rfc8785_float_ecmascript_formatting() {
        assert_eq!(canonicalize_jcs_string(&json!(0.0)).unwrap(), "0");
        assert_eq!(canonicalize_jcs_string(&json!(-0.0)).unwrap(), "0");
        assert_eq!(canonicalize_jcs_string(&json!(100.0)).unwrap(), "100");
        assert_eq!(canonicalize_jcs_string(&json!(1e19)).unwrap(), "10000000000000000000");
        assert_eq!(canonicalize_jcs_string(&json!(-1e19)).unwrap(), "-10000000000000000000");
        assert_eq!(canonicalize_jcs_string(&json!(1e20)).unwrap(), "100000000000000000000");
        assert_eq!(canonicalize_jcs_string(&json!(1e21)).unwrap(), "1e+21");
        assert_eq!(canonicalize_jcs_string(&json!(1e-7)).unwrap(), "1e-7");
    }
}
