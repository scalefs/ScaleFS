
use crate::json::{Value, object};

pub const PROTOCOL_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BadRequest,
    Unsupported,
    NotFound,
    Forbidden,
    Busy,
    Conflict,
    Io,
    Corrupt,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::Busy => "busy",
            ErrorCode::Conflict => "conflict",
            ErrorCode::Io => "io",
            ErrorCode::Corrupt => "corrupt",
            ErrorCode::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: u64,
    pub op: String,
    pub params: Value,
}

impl Request {
    pub fn encode(&self) -> Value {
        let mut entries = vec![
            ("id".to_string(), Value::Int(i128::from(self.id))),
            ("op".to_string(), Value::Str(self.op.clone())),
        ];
        if self.params != Value::Null {
            entries.push(("params".to_string(), self.params.clone()));
        }
        Value::Object(entries)
    }

    pub fn decode(value: &Value) -> Result<Request, &'static str> {
        let id = value
            .get("id")
            .and_then(Value::as_u64)
            .ok_or("request needs a non-negative integer id")?;
        let op = value
            .get("op")
            .and_then(Value::as_str)
            .ok_or("request needs a string op")?;
        Ok(Request {
            id,
            op: op.to_string(),
            params: value.get("params").cloned().unwrap_or(Value::Null),
        })
    }
}

pub fn ok_response(id: u64, result: Value) -> Value {
    let mut entries = vec![
        ("id".to_string(), Value::Int(i128::from(id))),
        ("ok".to_string(), Value::Bool(true)),
    ];
    if result != Value::Null {
        entries.push(("result".to_string(), result));
    }
    Value::Object(entries)
}

pub fn error_response(id: Option<u64>, code: ErrorCode, message: &str) -> Value {
    object(vec![
        (
            "id",
            id.map_or(Value::Null, |id| Value::Int(i128::from(id))),
        ),
        ("ok", Value::Bool(false)),
        (
            "error",
            object(vec![
                ("code", Value::Str(code.as_str().to_string())),
                ("message", Value::Str(message.to_string())),
            ]),
        ),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok {
        id: u64,
        result: Value,
    },
    Err {
        id: Option<u64>,
        code: String,
        message: String,
    },
}

impl Response {
    pub fn decode(value: &Value) -> Result<Response, &'static str> {
        match value.get("ok").and_then(Value::as_bool) {
            Some(true) => Ok(Response::Ok {
                id: value
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or("response needs an id")?,
                result: value.get("result").cloned().unwrap_or(Value::Null),
            }),
            Some(false) => {
                let error = value.get("error").ok_or("error response needs an error")?;
                Ok(Response::Err {
                    id: value.get("id").and_then(Value::as_u64),
                    code: error
                        .get("code")
                        .and_then(Value::as_str)
                        .ok_or("error needs a code")?
                        .to_string(),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                })
            }
            None => Err("response needs a boolean ok"),
        }
    }
}

pub fn client_hello() -> Value {
    object(vec![
        ("type", Value::Str("hello".to_string())),
        ("protocol", Value::Int(i128::from(PROTOCOL_VERSION))),
    ])
}

pub fn daemon_hello(protocol: u64, capabilities: &[&str], daemon_version: &str) -> Value {
    object(vec![
        ("type", Value::Str("hello".to_string())),
        ("protocol", Value::Int(i128::from(protocol))),
        (
            "capabilities",
            Value::Array(
                capabilities
                    .iter()
                    .map(|capability| Value::Str(capability.to_string()))
                    .collect(),
            ),
        ),
        ("daemon", Value::Str(daemon_version.to_string())),
    ])
}

pub const MIN_PROTOCOL_VERSION: u64 = 1;

pub fn check_client_hello(value: &Value) -> Result<u64, &'static str> {
    let protocol = hello_protocol(value)?;
    if protocol < MIN_PROTOCOL_VERSION {
        return Err("peer speaks an older protocol version than this build supports");
    }
    Ok(protocol.min(PROTOCOL_VERSION))
}

pub fn check_daemon_hello(value: &Value) -> Result<u64, &'static str> {
    let protocol = hello_protocol(value)?;
    if protocol < MIN_PROTOCOL_VERSION {
        return Err("the daemon negotiated a protocol version older than this build supports");
    }
    if protocol > PROTOCOL_VERSION {
        return Err("the daemon negotiated a protocol version newer than this build speaks");
    }
    Ok(protocol)
}

fn hello_protocol(value: &Value) -> Result<u64, &'static str> {
    if value.get("type").and_then(Value::as_str) != Some("hello") {
        return Err("expected a hello frame");
    }
    value
        .get("protocol")
        .and_then(Value::as_u64)
        .ok_or("hello needs an integer protocol version")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        for request in [
            Request {
                id: 0,
                op: "ping".into(),
                params: Value::Null,
            },
            Request {
                id: u64::MAX,
                op: "pool.status".into(),
                params: object(vec![("name", Value::Str("tank".into()))]),
            },
        ] {
            assert_eq!(Request::decode(&request.encode()).unwrap(), request);
        }
        assert_eq!(
            Request {
                id: 1,
                op: "ping".into(),
                params: Value::Null
            }
            .encode()
            .encode(),
            "{\"id\":1,\"op\":\"ping\"}"
        );
    }

    #[test]
    fn bad_requests_are_rejected() {
        for text in [
            "{\"op\":\"ping\"}",
            "{\"id\":-1,\"op\":\"ping\"}",
            "{\"id\":\"1\",\"op\":\"ping\"}",
            "{\"id\":1}",
            "{\"id\":1,\"op\":7}",
        ] {
            let value = crate::json::parse(text).unwrap();
            assert!(Request::decode(&value).is_err(), "{text}");
        }
    }

    #[test]
    fn responses_round_trip() {
        let ok = ok_response(9, object(vec![("pong", Value::Bool(true))]));
        assert_eq!(
            Response::decode(&ok).unwrap(),
            Response::Ok {
                id: 9,
                result: object(vec![("pong", Value::Bool(true))]),
            }
        );
        let err = error_response(None, ErrorCode::BadRequest, "unreadable");
        assert_eq!(
            Response::decode(&err).unwrap(),
            Response::Err {
                id: None,
                code: "bad_request".into(),
                message: "unreadable".into(),
            }
        );
        assert_eq!(
            err.encode(),
            "{\"id\":null,\"ok\":false,\"error\":{\"code\":\"bad_request\",\
             \"message\":\"unreadable\"}}"
        );
    }

    #[test]
    fn hello_negotiates() {
        assert_eq!(
            check_client_hello(&client_hello()).unwrap(),
            PROTOCOL_VERSION
        );
        assert_eq!(
            check_daemon_hello(&daemon_hello(PROTOCOL_VERSION, &["pools"], "0.1.0")).unwrap(),
            PROTOCOL_VERSION
        );
        let versioned = |protocol: i128| {
            object(vec![
                ("type", Value::Str("hello".into())),
                ("protocol", Value::Int(protocol)),
            ])
        };
        assert_eq!(check_client_hello(&versioned(2)).unwrap(), PROTOCOL_VERSION);
        assert_eq!(check_daemon_hello(&versioned(1)).unwrap(), 1);
        assert!(check_daemon_hello(&versioned(2)).is_err());
        assert!(check_client_hello(&versioned(0)).is_err());
        assert!(check_daemon_hello(&versioned(0)).is_err());
        assert!(check_client_hello(&Value::Null).is_err());
    }
}
