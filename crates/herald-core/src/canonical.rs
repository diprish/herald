//! Canonical JSON serialization (JCS, RFC 8785 profile).
//!
//! Every signature in HERALD is computed over the canonical form of an object,
//! so this module is the single most correctness-critical piece of the core:
//! two implementations that disagree by one byte cannot verify each other's
//! events. The rules:
//!
//! * object keys are sorted by **UTF-16 code unit** order (RFC 8785 §3.2.3),
//!   which is not the same as Rust's default `str` ordering for astral-plane
//!   characters;
//! * no insignificant whitespace;
//! * strings use the shortest JSON escapes, with remaining C0 controls as
//!   lowercase `\u00xx`;
//! * **floating-point numbers are rejected.** HERALD inherits this restriction
//!   from Matrix canonical JSON: permitting them would require ES6 number
//!   serialization in every implementation, for no protocol benefit. Integers
//!   within the `i64`/`u64` range are the only numbers a signed HERALD object
//!   may contain.

use core::fmt::Write as _;

use serde_json::{Map, Value};

/// Errors produced while canonicalizing a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// A non-integer number was encountered. See the module note.
    #[error("floating-point numbers are not permitted in canonical JSON: {0}")]
    FloatNotPermitted(String),
    /// A value could not be represented as JSON at all.
    #[error("value is not serializable as JSON: {0}")]
    NotSerializable(String),
}

/// Serializes `value` into its canonical JSON form.
pub fn canonicalize(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Serializes any [`serde::Serialize`] type into canonical JSON.
pub fn canonicalize_to_string<T: serde::Serialize>(value: &T) -> Result<String, CanonicalError> {
    let json =
        serde_json::to_value(value).map_err(|e| CanonicalError::NotSerializable(e.to_string()))?;
    canonicalize(&json)
}

/// SHA-512 of the canonical form of `value`.
///
/// Specification §9 selects SHA-512 for certificates and canonical events.
pub fn canonical_hash(value: &Value) -> Result<[u8; 64], CanonicalError> {
    use sha2::{Digest, Sha512};
    let canonical = canonicalize(value)?;
    let digest = Sha512::digest(canonical.as_bytes());
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(map, out)?,
    }
    Ok(())
}

fn write_number(number: &serde_json::Number, out: &mut String) -> Result<(), CanonicalError> {
    if let Some(i) = number.as_i64() {
        out.push_str(i.to_string().as_str());
        Ok(())
    } else if let Some(u) = number.as_u64() {
        out.push_str(u.to_string().as_str());
        Ok(())
    } else {
        Err(CanonicalError::FloatNotPermitted(number.to_string()))
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                // Writing into a String cannot fail.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_object(map: &Map<String, Value>, out: &mut String) -> Result<(), CanonicalError> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));

    out.push('{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(key, out);
        out.push(':');
        write_value(&map[*key], out)?;
    }
    out.push('}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let value: Value = serde_json::from_str(r#"{ "b": 1, "a": 2 }"#).unwrap();
        assert_eq!(canonicalize(&value).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn sorts_nested_objects_too() {
        let value = json!({ "z": { "y": 1, "x": 2 }, "a": [ { "d": 1, "c": 2 } ] });
        assert_eq!(
            canonicalize(&value).unwrap(),
            r#"{"a":[{"c":2,"d":1}],"z":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn sorts_by_utf16_code_units_not_code_points() {
        // U+FF3A (fullwidth Z, BMP) must sort *before* U+10000 (astral), because
        // the astral character's leading surrogate is 0xD800 < 0xFF3A. Ordering by
        // Unicode scalar value would place them the other way round.
        let value = json!({ "\u{10000}": 1, "\u{ff3a}": 2 });
        let canonical = canonicalize(&value).unwrap();
        let astral = canonical.find('\u{10000}').unwrap();
        let fullwidth = canonical.find('\u{ff3a}').unwrap();
        assert!(
            astral < fullwidth,
            "expected astral key first, got {canonical}"
        );
    }

    #[test]
    fn escapes_control_characters_minimally() {
        let value = json!({ "k": "a\"b\\c\nd\u{0001}e" });
        assert_eq!(
            canonicalize(&value).unwrap(),
            r#"{"k":"a\"b\\c\nd\u0001e"}"#
        );
    }

    #[test]
    fn preserves_array_order() {
        let value = json!([3, 1, 2]);
        assert_eq!(canonicalize(&value).unwrap(), "[3,1,2]");
    }

    #[test]
    fn rejects_floats() {
        let value = json!({ "k": 1.5 });
        assert!(matches!(
            canonicalize(&value),
            Err(CanonicalError::FloatNotPermitted(_))
        ));
    }

    #[test]
    fn accepts_integer_bounds() {
        let value = json!({ "min": i64::MIN, "max": u64::MAX });
        assert_eq!(
            canonicalize(&value).unwrap(),
            format!(r#"{{"max":{},"min":{}}}"#, u64::MAX, i64::MIN)
        );
    }

    #[test]
    fn hash_is_stable_across_key_order() {
        let a: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(canonical_hash(&a).unwrap(), canonical_hash(&b).unwrap());
    }
}
