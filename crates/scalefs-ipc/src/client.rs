use crate::endpoint::{Endpoint, Stream, connect, connect_limited};
use crate::frame::{read_frame, write_frame};
use crate::json::Value;
use crate::proto::{Request, Response, check_daemon_hello, client_hello};
use crate::trust::ServerIdentity;
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
        Client::over(
            endpoint,
            connect(endpoint, timeout),
            &ServerIdentity::Daemon,
        )
    }

    pub fn connect_limited(
        endpoint: &Endpoint,
        timeout: Duration,
        server: &ServerIdentity,
    ) -> Result<Client, String> {
        Client::over(endpoint, connect_limited(endpoint, timeout), server)
    }

    fn over(
        endpoint: &Endpoint,
        stream: std::io::Result<Stream>,
        server: &ServerIdentity,
    ) -> Result<Client, String> {
        let stream = stream.map_err(|error| {
            format!("cannot reach the daemon at {}: {error}", endpoint.as_str())
        })?;
        match stream.server_is(server) {
            Ok(true) => {}
            Ok(false) => {
                return Err(match server {
                    ServerIdentity::Daemon => format!(
                        "refusing {}: its server is not running as an identity this \
                         client trusts (expected the daemon: a service, an \
                         administrator, or this same account)",
                        endpoint.as_str()
                    ),
                    ServerIdentity::Account(account) => format!(
                        "refusing {}: its server is not running as the account this \
                         client was set up to trust ({account})",
                        endpoint.as_str()
                    ),
                });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::Listener;
    use crate::proto::daemon_hello;
    use crate::trust::own_account;
    use std::io::Read;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn private_endpoint(tag: &str) -> Endpoint {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("scalefs-client-{}-{tag}-{n}", std::process::id());
        #[cfg(windows)]
        {
            Endpoint::new(&name)
        }
        #[cfg(unix)]
        {
            Endpoint::new(
                &std::env::temp_dir()
                    .join(format!("{name}.sock"))
                    .to_string_lossy(),
            )
        }
    }

    fn bind_as_this_account(endpoint: &Endpoint) -> Listener {
        #[cfg(windows)]
        {
            Listener::bind_for_interactive_users(endpoint).unwrap()
        }
        #[cfg(unix)]
        {
            Listener::bind(endpoint).unwrap()
        }
    }

    fn another_account() -> String {
        #[cfg(windows)]
        {
            crate::trust::LOCAL_SYSTEM_SID.to_string()
        }
        #[cfg(unix)]
        {
            let own: u32 = own_account().unwrap().parse().unwrap();
            own.wrapping_add(1).to_string()
        }
    }

    #[test]
    fn a_server_of_this_account_is_refused_when_another_is_required() {
        if own_account().unwrap() == another_account() {
            return;
        }
        let endpoint = private_endpoint("squat");
        let mut listener = bind_as_this_account(&endpoint);
        let client_endpoint = endpoint.clone();
        let required = another_account();
        let client = std::thread::spawn(move || {
            Client::connect_limited(
                &client_endpoint,
                Duration::from_secs(5),
                &ServerIdentity::Account(required),
            )
            .err()
        });
        let mut server_side = listener.accept().unwrap();
        let refusal = client.join().unwrap().expect("the client must refuse");
        assert!(refusal.contains(&another_account()), "{refusal}");
        let mut received = Vec::new();
        server_side.read_to_end(&mut received).unwrap();
        assert!(
            received.is_empty(),
            "the impostor received {} bytes",
            received.len()
        );
    }

    #[test]
    fn the_required_account_is_accepted() {
        let endpoint = private_endpoint("owned");
        let mut listener = bind_as_this_account(&endpoint);
        let client_endpoint = endpoint.clone();
        let client = std::thread::spawn(move || {
            Client::connect_limited(
                &client_endpoint,
                Duration::from_secs(5),
                &ServerIdentity::Account(own_account().unwrap()),
            )
            .map(|client| client.daemon_version().to_string())
        });
        let stream = listener.accept().unwrap();
        let mut reader = std::io::BufReader::new(stream);
        let hello = read_frame(&mut reader)
            .unwrap()
            .expect("the client's hello");
        assert_eq!(hello.get("type").and_then(Value::as_str), Some("hello"));
        write_frame(reader.get_mut(), &daemon_hello(1, &[], "test")).unwrap();
        assert_eq!(client.join().unwrap().as_deref(), Ok("test"));
    }

    #[test]
    fn a_malformed_account_is_refused() {
        let endpoint = private_endpoint("malformed");
        let mut listener = bind_as_this_account(&endpoint);
        let client_endpoint = endpoint.clone();
        let client = std::thread::spawn(move || {
            Client::connect_limited(
                &client_endpoint,
                Duration::from_secs(5),
                &ServerIdentity::Account("not an account".to_string()),
            )
            .err()
        });
        let _server_side = listener.accept().unwrap();
        let refusal = client.join().unwrap().expect("the client must refuse");
        assert!(refusal.contains("cannot verify"), "{refusal}");
    }
}
