//! Minimal JSON Schema validation, integer normalization, and flat filter schema derivation.

use serde_json::{Map, Value, json};

/// Normalize a JSON number to `i64` if it represents an exact integer (rejecting fractional floats).
pub fn as_exact_i64(val: &Value) -> Option<i64> {
    let n = val.as_number()?;
    if let Some(i) = n.as_i64() {
        return Some(i);
    }
    if let Some(u) = n.as_u64() {
        return i64::try_from(u).ok();
    }
    let f = n.as_f64()?;
    if f.is_finite() && f.fract() == 0.0 && f >= (i64::MIN as f64) && f < (i64::MAX as f64) {
        Some(f as i64)
    } else {
        None
    }
}

/// Compare two JSON scalar values, treating exact integer representations as equal.
pub fn scalar_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(_), Value::Number(_)) => match (as_exact_i64(a), as_exact_i64(b)) {
            (Some(ia), Some(ib)) => ia == ib,
            _ => a == b,
        },
        _ => a == b,
    }
}

/// Derive a flat `inputSchema` from `payload_schema` and `filter_fields` per spec §3.
pub fn build_filter_input_schema(
    payload_schema: &Value,
    filter_fields: &[String],
) -> Result<Value, String> {
    let Some(schema_obj) = payload_schema.as_object() else {
        return Err("payload_schema must be a JSON object".into());
    };
    if filter_fields.is_empty() {
        return Ok(json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }));
    }
    let props = schema_obj
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            "payload_schema must declare 'properties' when filter_fields is non-empty".to_string()
        })?;

    let mut out_props = Map::new();
    for field in filter_fields {
        let prop_schema = props.get(field).ok_or_else(|| {
            format!("filter_fields entry '{field}' is missing from payload_schema.properties")
        })?;
        let prop_type = prop_schema
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "filter_fields entry '{field}' must declare a string 'type' in payload_schema"
                )
            })?;
        if !matches!(prop_type, "string" | "integer" | "boolean") {
            return Err(format!(
                "filter_fields entry '{field}' has unsupported type '{prop_type}' (allowed: string, integer, boolean)"
            ));
        }
        let mut entry = Map::new();
        entry.insert("type".into(), Value::String(prop_type.to_owned()));
        if let Some(desc) = prop_schema.get("description").and_then(Value::as_str) {
            entry.insert("description".into(), Value::String(desc.to_owned()));
        }
        if let Some(enm) = prop_schema.get("enum") {
            entry.insert("enum".into(), enm.clone());
        }
        out_props.insert(field.clone(), Value::Object(entry));
    }

    Ok(json!({
        "type": "object",
        "properties": Value::Object(out_props),
        "additionalProperties": false
    }))
}

/// Validate `value` against a JSON Schema object (Draft 2020-12 core subset).
pub fn validate_against_schema(schema: &Value, value: &Value) -> Result<(), String> {
    validate_node(schema, value, "$", 0)
}

const MAX_SCHEMA_DEPTH: usize = 32;

fn validate_node(schema: &Value, value: &Value, path: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!("{path}: schema validation depth limit exceeded"));
    }
    match schema {
        Value::Bool(true) => return Ok(()),
        Value::Bool(false) => return Err(format!("{path}: value disallowed by false schema")),
        Value::Object(_) => {}
        _ => return Err(format!("{path}: schema must be an object or boolean")),
    }
    let obj = schema.as_object().unwrap();

    if let Some(expected_const) = obj.get("const")
        && !scalar_eq(value, expected_const)
    {
        return Err(format!("{path}: value does not match const"));
    }

    if let Some(Value::Array(allowed)) = obj.get("enum")
        && !allowed.iter().any(|item| scalar_eq(value, item))
    {
        return Err(format!("{path}: value is not in enum"));
    }

    if let Some(type_val) = obj.get("type") {
        let matches = match type_val {
            Value::String(t) => matches_type(t, value),
            Value::Array(arr) => arr
                .iter()
                .filter_map(Value::as_str)
                .any(|t| matches_type(t, value)),
            _ => false,
        };
        if !matches {
            return Err(format!("{path}: type mismatch"));
        }
    }

    if let Some(Value::Array(all_of)) = obj.get("allOf") {
        for sub in all_of {
            validate_node(sub, value, path, depth + 1)?;
        }
    }
    if let Some(Value::Array(any_of)) = obj.get("anyOf")
        && !any_of
            .iter()
            .any(|sub| validate_node(sub, value, path, depth + 1).is_ok())
    {
        return Err(format!("{path}: value did not match anyOf"));
    }
    if let Some(Value::Array(one_of)) = obj.get("oneOf") {
        let count = one_of
            .iter()
            .filter(|sub| validate_node(sub, value, path, depth + 1).is_ok())
            .count();
        if count != 1 {
            return Err(format!("{path}: value matched {count} schemas in oneOf"));
        }
    }
    if let Some(not_schema) = obj.get("not")
        && validate_node(not_schema, value, path, depth + 1).is_ok()
    {
        return Err(format!("{path}: value matched negated schema"));
    }

    match value {
        Value::String(s) => {
            let char_len = s.chars().count();
            if let Some(min_len) = obj.get("minLength").and_then(Value::as_u64)
                && (char_len as u64) < min_len
            {
                return Err(format!("{path}: string shorter than minLength {min_len}"));
            }
            if let Some(max_len) = obj.get("maxLength").and_then(Value::as_u64)
                && (char_len as u64) > max_len
            {
                return Err(format!("{path}: string longer than maxLength {max_len}"));
            }
        }
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if let Some(min) = obj.get("minimum").and_then(Value::as_f64)
                    && f < min
                {
                    return Err(format!("{path}: number below minimum {min}"));
                }
                if let Some(max) = obj.get("maximum").and_then(Value::as_f64)
                    && f > max
                {
                    return Err(format!("{path}: number above maximum {max}"));
                }
                if let Some(ex_min) = obj.get("exclusiveMinimum").and_then(Value::as_f64)
                    && f <= ex_min
                {
                    return Err(format!("{path}: number not greater than {ex_min}"));
                }
                if let Some(ex_max) = obj.get("exclusiveMaximum").and_then(Value::as_f64)
                    && f >= ex_max
                {
                    return Err(format!("{path}: number not less than {ex_max}"));
                }
            }
        }
        Value::Array(items) => {
            if let Some(min_items) = obj.get("minItems").and_then(Value::as_u64)
                && (items.len() as u64) < min_items
            {
                return Err(format!("{path}: array has fewer than {min_items} items"));
            }
            if let Some(max_items) = obj.get("maxItems").and_then(Value::as_u64)
                && (items.len() as u64) > max_items
            {
                return Err(format!("{path}: array has more than {max_items} items"));
            }
            if let Some(item_schema) = obj.get("items") {
                for (i, item) in items.iter().enumerate() {
                    let sub_path = format!("{path}[{i}]");
                    validate_node(item_schema, item, &sub_path, depth + 1)?;
                }
            }
        }
        Value::Object(map) => {
            if let Some(Value::Array(required)) = obj.get("required") {
                for req in required.iter().filter_map(Value::as_str) {
                    if !map.contains_key(req) {
                        return Err(format!("{path}: missing required property '{req}'"));
                    }
                }
            }
            let props = obj.get("properties").and_then(Value::as_object);
            let addl = obj.get("additionalProperties");
            for (k, v) in map {
                let sub_path = format!("{path}.{k}");
                if let Some(prop_schema) = props.and_then(|p| p.get(k)) {
                    validate_node(prop_schema, v, &sub_path, depth + 1)?;
                } else if let Some(addl_schema) = addl {
                    match addl_schema {
                        Value::Bool(false) => {
                            return Err(format!("{sub_path}: additional property not allowed"));
                        }
                        Value::Bool(true) => {}
                        other => validate_node(other, v, &sub_path, depth + 1)?,
                    }
                }
            }
        }
        Value::Null | Value::Bool(_) => {}
    }

    Ok(())
}

fn matches_type(ty: &str, value: &Value) -> bool {
    match ty {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "string" => value.is_string(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "number" => value.is_number(),
        "integer" => as_exact_i64(value).is_some(),
        _ => false,
    }
}

/// Normalize integer filter arguments in-place so `1.0` becomes `1`, while rejecting non-integer floats.
pub fn normalize_filter_arguments(
    input_schema: &Value,
    args: &Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    validate_against_schema(input_schema, &Value::Object(args.clone()))?;
    let props = input_schema.get("properties").and_then(Value::as_object);
    let mut normalized = Map::with_capacity(args.len());
    for (k, v) in args {
        let is_integer_prop = props
            .and_then(|p| p.get(k))
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str)
            == Some("integer");
        if is_integer_prop && !v.is_null() {
            let int_val =
                as_exact_i64(v).ok_or_else(|| format!("argument '{k}' must be an integer"))?;
            normalized.insert(k.clone(), Value::Number(int_val.into()));
        } else {
            normalized.insert(k.clone(), v.clone());
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_filter_input_schema_derives_flat_optional_properties() {
        let payload = json!({
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "pr": {"type": "integer"},
                "draft": {"type": "boolean"},
                "nested": {"type": "object"}
            },
            "required": ["repo"],
            "additionalProperties": false
        });
        let schema = build_filter_input_schema(&payload, &["repo".into(), "pr".into()]).unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["repo"]["type"], "string");
        assert_eq!(schema["properties"]["pr"]["type"], "integer");
        assert!(schema.get("required").is_none());

        assert!(build_filter_input_schema(&payload, &["nested".into()]).is_err());
        assert!(build_filter_input_schema(&payload, &["missing".into()]).is_err());
    }

    #[test]
    fn integer_normalization_accepts_whole_float_and_rejects_fractional() {
        let schema = json!({
            "type": "object",
            "properties": {"pr": {"type": "integer"}},
            "additionalProperties": false
        });
        let ok_args = json!({"pr": 42.0}).as_object().unwrap().clone();
        let norm = normalize_filter_arguments(&schema, &ok_args).unwrap();
        assert_eq!(norm["pr"], json!(42));

        let bad_args = json!({"pr": 42.5}).as_object().unwrap().clone();
        assert!(normalize_filter_arguments(&schema, &bad_args).is_err());
    }
}
