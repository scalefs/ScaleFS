use crate::endpoint::{Endpoint, Stream, connect, connect_limited};
use crate::frame::{read_frame, write_frame};
use crate::json::Value;
use crate::proto::{Request, Response, check_daemon_hello, client_hello};
use std::io::BufReader;
use std::time::Duration;

#[derive(Debug)]
pub enum CallError {
    Session(String),
    Daemon { code: String, message: String },
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Session(message) => write!(f, "{message}"),
            CallError::Daemon { code, message } => write!(f, "{message} ({code})"),
        }
    }
}

pub struct Client {
    reader: BufReader<Stream>,
    hello: Value,
    next_id: u64,
}

impl Client {
    pub fn connect(endpoint: &Endpoint, timeout: Duration) -> Result<Client, String> {
        Client::over(endpoint, connect(endpoint, timeout))
    }

    pub fn connect_limited(endpoint: &Endpoint, timeout: Duration) -> Result<Client, String> {
        Client::over(endpoint, connect_limited(endpoint, timeout))
    }

    fn over(endpoint: &Endpoint, stream: std::io::Result<Stream>) -> Result<Client, String> {
        let stream = stream.map_err(|error| {
            format!("cannot reach the daemon at {}: {error}", endpoint.as_str())
        })?;
        match stream.server_is_trusted() {
            Ok(true) => {}
            Ok(false) => {
                return Err(format!(
                    "refusing {}: its server is not running as an identity this \
                     client trusts (expected the daemon: a service, an \
                     administrator, or this same account)",
                    endpoint.as_str()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "cannot verify the identity of the server at {}: {error}",
                    endpoint.as_str()
                ));
            }
        }
        let mut reader = BufReader::new(stream);
        write_frame(reader.get_mut(), &client_hello())
            .map_err(|error| format!("hello failed: {error}"))?;
        let hello = read_frame(&mut reader)
            .map_err(|error| format!("hello failed: {error}"))?
            .ok_or("the daemon closed the connection during hello")?;
        check_daemon_hello(&hello).map_err(|error| error.to_string())?;
        Ok(Client {
            reader,
            hello,
            next_id: 1,
        })
    }

    pub fn daemon_version(&self) -> &str {
        self.hello
            .get("daemon")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    }

    pub fn call(&mut self, op: &str, params: Value) -> Result<Value, CallError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = Request {
            id,
            op: op.to_string(),
            params,
        };
        write_frame(self.reader.get_mut(), &request.encode())
            .map_err(|error| CallError::Session(format!("send failed: {error}")))?;
        let frame = read_frame(&mut self.reader)
            .map_err(|error| CallError::Session(format!("receive failed: {error}")))?
            .ok_or(CallError::Session(
                "the daemon closed the connection".to_string(),
            ))?;
        match Response::decode(&frame).map_err(|error| CallError::Session(error.to_string()))? {
            Response::Ok {
                id: response_id,
                result,
            } if response_id == id => Ok(result),
            Response::Err {
                id: response_id,
                code,
                message,
            } if response_id == Some(id) => Err(CallError::Daemon { code, message }),
            Response::Ok { .. } | Response::Err { .. } => Err(CallError::Session(
                "the daemon answered a different request".to_string(),
            )),
        }
    }
}
