use serde_json::{json, Value};

pub(super) fn response(value: &Value) -> Value {
    json!({
        "rpc_error": value.get("error").is_some(),
        "tool_error": value.get("result").and_then(|r| r.get("isError")).and_then(Value::as_bool),
        "rpc_code": value.get("error").and_then(|e| e.get("code")).and_then(Value::as_i64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_server_error_text_is_not_diagnostic_data() {
        let value = json!({"id":"private-id","error":{"code":-32603,
            "message":"private-token-and-path","data":{"credential":"private-secret"}}});
        let observed = response(&value);
        assert_eq!(
            observed,
            json!({"rpc_error":true,"tool_error":null,"rpc_code":-32603})
        );
        assert!(!observed.to_string().contains("private"));
    }

    #[test]
    fn original_tool_error_is_distinct_from_a_protocol_error() {
        let observed = response(&json!({"result":{"isError":true,
            "content":[{"type":"text","text":"private-server-exception"}]}}));
        assert_eq!(
            observed,
            json!({"rpc_error":false,"tool_error":true,"rpc_code":null})
        );
        assert_eq!(
            response(&json!({"result":{"content":[]}}))["tool_error"],
            Value::Null
        );
    }
}
