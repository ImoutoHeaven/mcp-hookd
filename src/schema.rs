//! JSON Schema validation, integer normalization, and flat filter schema derivation.

use serde_json::{Map, Number, Value, json};

fn as_exact_integer(value: &Value) -> Option<i128> {
    let number = value.as_number()?;
    if let Some(value) = number.as_i64() {
        return Some(i128::from(value));
    }
    if let Some(value) = number.as_u64() {
        return Some(i128::from(value));
    }
    let value = number.as_f64()?;
    if value.fract() == 0.0 && value >= i128::MIN as f64 && value < i128::MAX as f64 {
        Some(value as i128)
    } else {
        None
    }
}

/// Compare two JSON scalar values, treating exact integer representations as equal.
pub fn scalar_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(_), Value::Number(_)) => match (as_exact_integer(a), as_exact_integer(b)) {
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

/// Check a configured schema against its bundled draft meta-schema without external retrieval.
pub fn validate_schema(schema: &Value) -> Result<(), String> {
    let result = match schema.get("$schema").and_then(Value::as_str) {
        None => jsonschema::draft202012::meta::validate(schema),
        Some(uri) => match uri.trim_end_matches('#') {
            "http://json-schema.org/draft-04/schema"
            | "https://json-schema.org/draft-04/schema" => {
                jsonschema::draft4::meta::validate(schema)
            }
            "http://json-schema.org/draft-06/schema"
            | "https://json-schema.org/draft-06/schema" => {
                jsonschema::draft6::meta::validate(schema)
            }
            "http://json-schema.org/draft-07/schema"
            | "https://json-schema.org/draft-07/schema" => {
                jsonschema::draft7::meta::validate(schema)
            }
            "https://json-schema.org/draft/2019-09/schema"
            | "http://json-schema.org/draft/2019-09/schema" => {
                jsonschema::draft201909::meta::validate(schema)
            }
            "https://json-schema.org/draft/2020-12/schema"
            | "http://json-schema.org/draft/2020-12/schema" => {
                jsonschema::draft202012::meta::validate(schema)
            }
            // Custom dialects are resolved asynchronously when the schema is compiled.
            _ => return Ok(()),
        },
    };
    result.map_err(|error| format!("invalid JSON Schema: {error}"))
}

/// Validate with the declared draft, resolving external references asynchronously.
pub async fn validate_against_schema(schema: &Value, value: &Value) -> Result<(), String> {
    let validator = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        jsonschema::async_validator_for(schema),
    )
    .await
    .map_err(|_| "JSON Schema resolution timed out after 30 seconds".to_owned())?
    .map_err(|error| format!("invalid JSON Schema: {error}"))?;
    validator.validate(value).map_err(|error| error.to_string())
}

/// Normalize whole integer arguments without narrowing their supported range.
pub async fn normalize_filter_arguments(
    input_schema: &Value,
    args: &Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    validate_against_schema(input_schema, &Value::Object(args.clone())).await?;
    let props = input_schema.get("properties").and_then(Value::as_object);
    let mut normalized = Map::with_capacity(args.len());
    for (k, v) in args {
        let is_integer_prop = props
            .and_then(|p| p.get(k))
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str)
            == Some("integer");
        if is_integer_prop && !v.is_null() {
            let integer = as_exact_integer(v).and_then(|integer| {
                i64::try_from(integer)
                    .map(Number::from)
                    .or_else(|_| u64::try_from(integer).map(Number::from))
                    .ok()
            });
            normalized.insert(k.clone(), integer.map_or_else(|| v.clone(), Value::Number));
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

    #[tokio::test]
    async fn integer_normalization_accepts_whole_float_and_rejects_fractional() {
        let schema = json!({
            "type": "object",
            "properties": {"pr": {"type": "integer"}},
            "additionalProperties": false
        });
        let ok_args = json!({"pr": 42.0}).as_object().unwrap().clone();
        let norm = normalize_filter_arguments(&schema, &ok_args).await.unwrap();
        assert_eq!(norm["pr"], json!(42));

        let bad_args = json!({"pr": 42.5}).as_object().unwrap().clone();
        assert!(
            normalize_filter_arguments(&schema, &bad_args)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn validates_standard_keywords_and_declared_drafts() {
        for (schema, valid, invalid) in [
            (
                json!({"type": "object", "properties": {"repo": {"$ref": "#/$defs/repo"}},
                       "required": ["repo"], "$defs": {"repo": {"type": "string", "pattern": "^[A-Z]+$"}}}),
                json!({"repo": "ABC"}),
                json!({"repo": "abc"}),
            ),
            (
                json!({"type": "number", "multipleOf": 0.25}),
                json!(1.5),
                json!(1.6),
            ),
            (
                json!({"type": "array", "prefixItems": [{"type": "string"}, {"type": "integer"}],
                       "items": false}),
                json!(["repo", 2]),
                json!([2, "repo"]),
            ),
            (
                json!({"type": "object", "properties": {"n": {"type": "integer"}},
                       "if": {"required": ["n"]}, "then": {"required": ["label"]},
                       "unevaluatedProperties": false}),
                json!({}),
                json!({"n": 2}),
            ),
            (
                json!({"$schema": "http://json-schema.org/draft-04/schema#",
                       "minimum": 3, "exclusiveMinimum": true}),
                json!(4),
                json!(3),
            ),
            (
                json!({"$schema": "http://json-schema.org/draft-07/schema#",
                       "items": [{"type": "integer"}, {"type": "string"}],
                       "additionalItems": false}),
                json!([2, "repo"]),
                json!([2, 3]),
            ),
        ] {
            assert!(validate_schema(&schema).is_ok(), "{schema}");
            assert!(
                validate_against_schema(&schema, &valid).await.is_ok(),
                "{schema}"
            );
            assert!(
                validate_against_schema(&schema, &invalid).await.is_err(),
                "{schema}"
            );
        }
        assert!(validate_schema(&json!({"type": "unknown"})).is_err());
        assert!(validate_schema(&json!({"minimum": "3"})).is_err());
        assert!(validate_schema(&json!({"$ref": "https://example.com/schema.json"})).is_ok());
    }

    #[tokio::test]
    async fn integer_validation_and_equality_preserve_u64_precision() {
        let schema = json!({
            "type": "object",
            "properties": {"n": {"type": "integer", "minimum": 9_007_199_254_740_993u64}}
        });
        let args = json!({"n": u64::MAX}).as_object().unwrap().clone();
        assert_eq!(
            normalize_filter_arguments(&schema, &args).await.unwrap()["n"],
            json!(u64::MAX)
        );
        assert!(
            validate_against_schema(&schema, &json!({"n": 9_007_199_254_740_992u64}))
                .await
                .is_err()
        );
        assert!(scalar_eq(
            &json!(9_223_372_036_854_775_808u64),
            &json!(9_223_372_036_854_775_808.0)
        ));
        assert!(!scalar_eq(
            &json!(9_007_199_254_740_993u64),
            &json!(9_007_199_254_740_992.0)
        ));
        assert!(!scalar_eq(&json!(u64::MAX), &json!(u64::MAX as f64)));
    }

    #[tokio::test]
    async fn resolves_external_references_without_blocking_the_runtime() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                assert!(socket.read(&mut request).await.unwrap() > 0);
                let body = r#"{"type":"string","pattern":"^[A-Z]+$"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let schema = json!({"$ref": format!("http://{address}/schema.json")});
        assert!(
            validate_against_schema(&schema, &json!("ABC"))
                .await
                .is_ok()
        );
        assert!(
            validate_against_schema(&schema, &json!("abc"))
                .await
                .is_err()
        );
        server.await.unwrap();
    }
}
