use super::crypto::kdf::smb3_signing_key;
use super::crypto::sha512::Sha512;
use super::sign;
use super::wire::{self, Header, command, flags, status};
use scalefs_core::wire::Cursor;

const MESSAGE_ID_WINDOW: u64 = 512;

struct SequenceWindow {
    highest: u64,
    seen: [u64; (2 * MESSAGE_ID_WINDOW / 64) as usize],
}

impl SequenceWindow {
    fn new() -> SequenceWindow {
        SequenceWindow {
            highest: 0,
            seen: [0; (2 * MESSAGE_ID_WINDOW / 64) as usize],
        }
    }

    fn floor(highest: u64) -> u64 {
        highest.saturating_add(1).saturating_sub(MESSAGE_ID_WINDOW)
    }

    fn bit(id: u64) -> (usize, u64) {
        let index = (id % (2 * MESSAGE_ID_WINDOW)) as usize;
        (index / 64, 1u64 << (index % 64))
    }

    fn is_seen(&self, id: u64) -> bool {
        let (word, mask) = Self::bit(id);
        self.seen[word] & mask != 0
    }

    fn set(&mut self, id: u64) {
        let (word, mask) = Self::bit(id);
        self.seen[word] |= mask;
    }

    fn clear(&mut self, id: u64) {
        let (word, mask) = Self::bit(id);
        self.seen[word] &= !mask;
    }

    fn accepts(&self, id: u64, charge: u16) -> bool {
        let Some(last) = id.checked_add(u64::from(charge.max(1)) - 1) else {
            return false;
        };
        id >= Self::floor(self.highest)
            && last <= self.highest.saturating_add(MESSAGE_ID_WINDOW)
            && (id..=last).all(|n| !self.is_seen(n))
    }

    fn claim(&mut self, id: u64, charge: u16) -> bool {
        if !self.accepts(id, charge) {
            return false;
        }
        let last = id + (u64::from(charge.max(1)) - 1);
        for n in id..=last {
            self.set(n);
        }
        if last > self.highest {
            for n in Self::floor(self.highest)..Self::floor(last) {
                self.clear(n);
            }
            self.highest = last;
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Negotiated,
    Ready,
    LoggedOff,
}

pub trait Handler {
    fn dispatch(&self, header: &Header, body: &[u8]) -> Response;

    fn negotiate_smb2_wildcard(&self) -> Response {
        Response::error(status::NOT_SUPPORTED)
    }
}

pub struct Response {
    pub status: u32,
    pub body: Vec<u8>,
    pub session_id: Option<u64>,
    pub tree_id: Option<u32>,
    pub session_key: Option<[u8; 16]>,
}

impl Response {
    pub fn ok(body: Vec<u8>) -> Response {
        Response {
            status: status::SUCCESS,
            body,
            session_id: None,
            tree_id: None,
            session_key: None,
        }
    }

    pub fn error(status: u32) -> Response {
        Response {
            status,
            body: error_body(),
            session_id: None,
            tree_id: None,
            session_key: None,
        }
    }
}

pub fn error_body() -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    scalefs_core::wire::put_u16(&mut out, 9);
    out.push(0);
    out.push(0);
    scalefs_core::wire::put_u32(&mut out, 0);
    out.push(0);
    out
}

pub struct Connection {
    phase: Phase,
    window: SequenceWindow,
    session_id: u64,
    preauth: [u8; 64],
    signing_key: Option<[u8; 16]>,
}

impl Default for Connection {
    fn default() -> Self {
        Connection::new()
    }
}

pub(crate) fn fold(preauth: &mut [u8; 64], message: &[u8]) {
    let mut hasher = Sha512::new();
    hasher.update(preauth);
    hasher.update(message);
    *preauth = hasher.finish();
}

impl Connection {
    pub fn new() -> Connection {
        Connection {
            phase: Phase::New,
            window: SequenceWindow::new(),
            session_id: 0,
            preauth: [0u8; 64],
            signing_key: None,
        }
    }

    pub fn signing_key(&self) -> Option<[u8; 16]> {
        self.signing_key
    }

    pub fn handle(&mut self, message: &[u8], handler: &dyn Handler) -> Option<Vec<u8>> {
        if self.phase == Phase::New
            && message.len() >= 5
            && message[..4] == [0xFF, b'S', b'M', b'B']
            && message[4] == 0x72
        {
            let response = handler.negotiate_smb2_wildcard();
            return Some(self.frame_single(command::NEGOTIATE, 0, response));
        }

        let mut responses: Vec<(Header, Response)> = Vec::new();
        let mut offset = 0usize;
        let mut chain_failure: Option<u32> = None;

        loop {
            let remaining = message.get(offset..)?;
            if remaining.len() < wire::HEADER_LEN {
                return None;
            }
            let header = Header::decode(&mut Cursor::new(remaining)).ok()?;
            let next = header.next_command as usize;
            let body_end = if next != 0 {
                if next < wire::HEADER_LEN || offset + next > message.len() {
                    return None;
                }
                offset + next
            } else {
                message.len()
            };
            let segment = &message[offset..body_end];
            let body = &message[offset + wire::HEADER_LEN..body_end];

            if let Some(key) = self.signing_key {
                let signed = header.flags & flags::SIGNED != 0;
                if !signed || !sign::verify(segment, &key) {
                    return None;
                }
            }

            let handshake_request = header.command == command::NEGOTIATE
                || (header.command == command::SESSION_SETUP && self.signing_key.is_none());
            if handshake_request {
                fold(&mut self.preauth, segment);
            }

            if header.flags & flags::RELATED_OPERATIONS == 0 {
                chain_failure = None;
            }
            let response = match chain_failure {
                Some(failed) => {
                    if header.message_id != u64::MAX {
                        self.window.claim(header.message_id, header.credit_charge);
                    }
                    Response::error(failed)
                }
                None => self.handle_one(&header, body, handler),
            };
            if !matches!(
                response.status,
                status::SUCCESS | status::MORE_PROCESSING_REQUIRED | status::PENDING
            ) {
                chain_failure = Some(response.status);
            }

            if header.command == command::SESSION_SETUP && response.status == status::SUCCESS {
                let session_key = response.session_key?;
                if self.signing_key.is_none() {
                    self.signing_key = Some(smb3_signing_key(&session_key, &self.preauth));
                }
            }
            responses.push((header, response));

            if next == 0 {
                break;
            }
            offset += next;
        }

        Some(self.frame_responses(responses))
    }

    fn handle_one(&mut self, header: &Header, body: &[u8], handler: &dyn Handler) -> Response {
        if header.message_id != u64::MAX
            && !self.window.claim(header.message_id, header.credit_charge)
        {
            return Response::error(status::INVALID_PARAMETER);
        }

        match header.command {
            command::NEGOTIATE => {
                if self.phase != Phase::New {
                    return Response::error(status::INVALID_PARAMETER);
                }
                let response = handler.dispatch(header, body);
                if response.status == status::SUCCESS {
                    self.phase = Phase::Negotiated;
                }
                response
            }
            command::SESSION_SETUP => {
                if matches!(self.phase, Phase::New | Phase::LoggedOff) {
                    return Response::error(status::INVALID_PARAMETER);
                }
                let response = handler.dispatch(header, body);
                if let Some(id) = response.session_id {
                    self.session_id = id;
                }
                if response.status == status::SUCCESS {
                    self.phase = Phase::Ready;
                }
                response
            }
            _ => match self.phase {
                Phase::LoggedOff => Response::error(status::USER_SESSION_DELETED),
                Phase::New | Phase::Negotiated => Response::error(status::ACCESS_DENIED),
                Phase::Ready if header.session_id != self.session_id => {
                    Response::error(status::USER_SESSION_DELETED)
                }
                Phase::Ready => {
                    let response = handler.dispatch(header, body);
                    if header.command == command::LOGOFF && response.status == status::SUCCESS {
                        self.phase = Phase::LoggedOff;
                    }
                    response
                }
            },
        }
    }

    fn frame_responses(&mut self, responses: Vec<(Header, Response)>) -> Vec<u8> {
        let count = responses.len();
        let mut message = Vec::new();
        for (index, (request, response)) in responses.into_iter().enumerate() {
            let last = index + 1 == count;

            let will_sign = match request.command {
                command::NEGOTIATE => false,
                command::SESSION_SETUP => {
                    response.status == status::SUCCESS && response.session_key.is_some()
                }
                _ => self.signing_key.is_some(),
            };
            let will_fold = match request.command {
                command::NEGOTIATE => true,
                command::SESSION_SETUP => response.status == status::MORE_PROCESSING_REQUIRED,
                _ => false,
            };

            let body_len = response.body.len();
            let padded_len = if last {
                0
            } else {
                (wire::HEADER_LEN + body_len).div_ceil(8) * 8
            };
            let mut header_flags =
                flags::SERVER_TO_REDIR | (request.flags & flags::RELATED_OPERATIONS);
            if will_sign {
                header_flags |= flags::SIGNED;
            }
            let header = Header {
                credit_charge: request.credit_charge,
                status: response.status,
                command: request.command,
                credits: request.credits.max(1),
                flags: header_flags,
                next_command: padded_len as u32,
                message_id: request.message_id,
                tree_id: response.tree_id.unwrap_or(request.tree_id),
                session_id: response.session_id.unwrap_or(self.session_id),
                signature: [0u8; 16],
            };

            let start = message.len();
            header.encode(&mut message);
            message.extend_from_slice(&response.body);

            if !last {
                while message.len() - start < padded_len {
                    message.push(0);
                }
            }
            let seg_end = message.len();

            if will_sign && let Some(key) = self.signing_key {
                sign::sign(&mut message[start..seg_end], &key);
            }

            if will_fold {
                let segment = message[start..seg_end].to_vec();
                fold(&mut self.preauth, &segment);
            }
        }

        let mut framed = Vec::with_capacity(4 + message.len());
        framed.extend_from_slice(&wire::transport_header(message.len()));
        framed.extend_from_slice(&message);
        framed
    }

    fn frame_single(&self, command: u16, message_id: u64, response: Response) -> Vec<u8> {
        let header = Header {
            status: response.status,
            command,
            credits: 1,
            flags: flags::SERVER_TO_REDIR,
            message_id,
            session_id: response.session_id.unwrap_or(0),
            ..Header::default()
        };
        let mut message = Vec::new();
        header.encode(&mut message);
        message.extend_from_slice(&response.body);
        let mut framed = Vec::with_capacity(4 + message.len());
        framed.extend_from_slice(&wire::transport_header(message.len()));
        framed.extend_from_slice(&message);
        framed
    }

    pub fn route(&mut self, message: &[u8]) -> Route {
        let Some(key) = self.signing_key else {
            return Route::Inline;
        };
        if self.phase != Phase::Ready {
            return Route::Inline;
        }
        let Ok(header) = Header::decode(&mut Cursor::new(message)) else {
            return Route::Inline;
        };
        if header.next_command != 0 || header.flags & flags::RELATED_OPERATIONS != 0 {
            return Route::Inline;
        }
        if !matches!(
            header.command,
            command::READ | command::WRITE | command::QUERY_INFO
        ) {
            return Route::Inline;
        }
        if header.message_id == u64::MAX
            || header.session_id != self.session_id
            || !self.window.accepts(header.message_id, header.credit_charge)
        {
            return Route::Inline;
        }
        let file_id_offset = match header.command {
            command::READ | command::WRITE => Some(16),
            command::QUERY_INFO => Some(24),
            _ => None,
        };
        if let Some(at) = file_id_offset {
            match super::fileops::file_id_at(&message[wire::HEADER_LEN..], at) {
                Ok(id) if id == [0xFF; 16] => return Route::Inline,
                Ok(_) => {}
                Err(_) => return Route::Inline,
            }
        }
        self.window.claim(header.message_id, header.credit_charge);
        Route::Parallel(ParallelRequest {
            header,
            key,
            session_id: self.session_id,
        })
    }
}

pub enum Route {
    Inline,
    Parallel(ParallelRequest),
}

pub struct ParallelRequest {
    pub header: Header,
    pub key: [u8; 16],
    pub session_id: u64,
}

pub fn verify_parallel(message: &[u8], key: &[u8; 16]) -> bool {
    let Ok(header) = Header::decode(&mut Cursor::new(message)) else {
        return false;
    };
    header.flags & flags::SIGNED != 0 && sign::verify(message, key)
}

pub fn frame_parallel_reply(
    request: &Header,
    response: Response,
    key: &[u8; 16],
    session_id: u64,
) -> Vec<u8> {
    let header = Header {
        credit_charge: request.credit_charge,
        status: response.status,
        command: request.command,
        credits: request.credits.max(1),
        flags: flags::SERVER_TO_REDIR | flags::SIGNED,
        next_command: 0,
        message_id: request.message_id,
        tree_id: response.tree_id.unwrap_or(request.tree_id),
        session_id: response.session_id.unwrap_or(session_id),
        signature: [0u8; 16],
    };
    let mut message = Vec::with_capacity(wire::HEADER_LEN + response.body.len());
    header.encode(&mut message);
    message.extend_from_slice(&response.body);
    sign::sign(&mut message, key);
    let mut framed = Vec::with_capacity(4 + message.len());
    framed.extend_from_slice(&wire::transport_header(message.len()));
    framed.extend_from_slice(&message);
    framed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        seen: std::cell::RefCell<Vec<u16>>,
        setups: std::cell::Cell<u32>,
    }

    impl Recorder {
        fn seen(&self) -> Vec<u16> {
            self.seen.borrow().clone()
        }
    }

    impl Handler for Recorder {
        fn dispatch(&self, header: &Header, _body: &[u8]) -> Response {
            self.seen.borrow_mut().push(header.command);
            match header.command {
                command::NEGOTIATE => Response::ok(vec![0u8; 8]),
                command::SESSION_SETUP => {
                    self.setups.set(self.setups.get() + 1);
                    if self.setups.get() == 1 {
                        Response {
                            status: status::MORE_PROCESSING_REQUIRED,
                            body: vec![9, 0, 0, 0],
                            session_id: Some(0x1234),
                            tree_id: None,
                            session_key: None,
                        }
                    } else {
                        Response {
                            status: status::SUCCESS,
                            body: vec![9, 0, 0, 0],
                            session_id: Some(0x1234),
                            tree_id: None,
                            session_key: Some([0x5A; 16]),
                        }
                    }
                }
                command::QUERY_DIRECTORY => Response::error(status::NO_SUCH_FILE),
                _ => Response::ok(vec![command::ECHO as u8, 0]),
            }
        }
    }

    fn request(cmd: u16, message_id: u64, next_command: u32, body: &[u8]) -> Vec<u8> {
        request_flagged(cmd, message_id, next_command, 0, body)
    }

    fn request_flagged(
        cmd: u16,
        message_id: u64,
        next_command: u32,
        flags: u32,
        body: &[u8],
    ) -> Vec<u8> {
        request_for_session(cmd, message_id, next_command, flags, 0x1234, body)
    }

    fn request_for_session(
        cmd: u16,
        message_id: u64,
        next_command: u32,
        flags: u32,
        session_id: u64,
        body: &[u8],
    ) -> Vec<u8> {
        let header = Header {
            command: cmd,
            message_id,
            credits: 1,
            next_command,
            flags,
            session_id,
            ..Header::default()
        };
        let mut out = Vec::new();
        header.encode(&mut out);
        out.extend_from_slice(body);
        out
    }

    fn sign_request(message: &mut [u8], key: &[u8; 16]) {
        let mut offset = 0;
        loop {
            let next = u32::from_le_bytes([
                message[offset + 20],
                message[offset + 21],
                message[offset + 22],
                message[offset + 23],
            ]) as usize;
            let end = if next != 0 {
                offset + next
            } else {
                message.len()
            };
            let mut header_flags = u32::from_le_bytes([
                message[offset + 16],
                message[offset + 17],
                message[offset + 18],
                message[offset + 19],
            ]);
            header_flags |= flags::SIGNED;
            message[offset + 16..offset + 20].copy_from_slice(&header_flags.to_le_bytes());
            sign::sign(&mut message[offset..end], key);
            if next == 0 {
                break;
            }
            offset += next;
        }
    }

    fn message_of(framed: &[u8]) -> &[u8] {
        &framed[4..]
    }

    fn reply_status(framed: &[u8]) -> u32 {
        u32::from_le_bytes([framed[12], framed[13], framed[14], framed[15]])
    }

    fn reply_flags(framed: &[u8]) -> u32 {
        u32::from_le_bytes([
            framed[4 + 16],
            framed[4 + 17],
            framed[4 + 18],
            framed[4 + 19],
        ])
    }

    fn handshake(conn: &mut Connection, handler: &Recorder) -> [u8; 16] {
        conn.handle(&request(command::NEGOTIATE, 0, 0, &[]), handler)
            .unwrap();
        conn.handle(&request(command::SESSION_SETUP, 1, 0, &[]), handler)
            .unwrap();
        let final_reply = conn
            .handle(&request(command::SESSION_SETUP, 2, 0, &[]), handler)
            .unwrap();
        assert_eq!(reply_status(&final_reply), status::SUCCESS);
        assert_ne!(reply_flags(&final_reply) & flags::SIGNED, 0);
        assert!(sign::verify(
            message_of(&final_reply),
            &conn.signing_key().unwrap()
        ));
        conn.signing_key().unwrap()
    }

    #[test]
    fn sequence_window_refuses_replays_and_tolerates_gaps() {
        let mut window = SequenceWindow::new();
        assert!(window.claim(0, 1));
        assert!(!window.claim(0, 1), "a consumed id is a replay");
        assert!(window.claim(10, 4));
        assert!(!window.claim(11, 1));
        assert!(!window.claim(13, 1));
        assert!(window.claim(14, 1));
        assert!(window.claim(20, 1));
        assert!(window.claim(15, 1));
        assert!(!window.claim(20 + MESSAGE_ID_WINDOW + 1, 1));
        assert!(window.claim(20 + MESSAGE_ID_WINDOW, 1));
        assert!(!window.claim(20, 1));
        assert!(window.claim(21, 1));

        let mut window = SequenceWindow::new();
        for id in 0..5_000u64 {
            assert!(window.claim(id, 1), "{id}");
        }
        assert!(!window.claim(4_999, 1));
        assert!(!window.claim(4_600, 1));
        assert!(
            !window.claim(4_000, 1),
            "too old to be anything but a replay"
        );
        assert!(window.claim(5_000, 1));
    }

    #[test]
    fn replayed_frames_are_refused_without_dispatch() {
        let mut conn = Connection::new();
        let handler = Recorder::default();
        let key = handshake(&mut conn, &handler);
        let mut echo = request(command::ECHO, 3, 0, &[]);
        sign_request(&mut echo, &key);
        assert_eq!(
            reply_status(&conn.handle(&echo, &handler).unwrap()),
            status::SUCCESS
        );
        let dispatched = handler.seen().len();
        let replay = conn.handle(&echo, &handler).unwrap();
        assert_eq!(reply_status(&replay), status::INVALID_PARAMETER);
        assert_eq!(
            handler.seen().len(),
            dispatched,
            "a replay must not dispatch"
        );
    }

    #[test]
    fn foreign_session_ids_and_logged_off_sessions_are_refused() {
        let mut conn = Connection::new();
        let handler = Recorder::default();
        let key = handshake(&mut conn, &handler);
        let dispatched = handler.seen().len();

        let mut foreign = request_for_session(command::ECHO, 3, 0, 0, 0x9999, &[]);
        sign_request(&mut foreign, &key);
        assert_eq!(
            reply_status(&conn.handle(&foreign, &handler).unwrap()),
            status::USER_SESSION_DELETED
        );
        assert_eq!(handler.seen().len(), dispatched);

        let mut logoff = request(command::LOGOFF, 4, 0, &[]);
        sign_request(&mut logoff, &key);
        assert_eq!(
            reply_status(&conn.handle(&logoff, &handler).unwrap()),
            status::SUCCESS
        );
        let mut after = request(command::ECHO, 5, 0, &[]);
        sign_request(&mut after, &key);
        assert_eq!(
            reply_status(&conn.handle(&after, &handler).unwrap()),
            status::USER_SESSION_DELETED
        );
        let mut again = request(command::SESSION_SETUP, 6, 0, &[]);
        sign_request(&mut again, &key);
        assert_eq!(
            reply_status(&conn.handle(&again, &handler).unwrap()),
            status::INVALID_PARAMETER
        );
    }

    #[test]
    fn a_failed_element_poisons_the_related_chain() {
        let mut conn = Connection::new();
        let handler = Recorder::default();
        let key = handshake(&mut conn, &handler);

        let mut compound = Vec::new();
        compound.extend_from_slice(&request(command::CREATE, 3, 64, &[]));
        compound.extend_from_slice(&request_flagged(
            command::QUERY_DIRECTORY,
            4,
            64,
            flags::RELATED_OPERATIONS,
            &[],
        ));
        compound.extend_from_slice(&request_flagged(
            command::CLOSE,
            5,
            64,
            flags::RELATED_OPERATIONS,
            &[],
        ));
        compound.extend_from_slice(&request(command::ECHO, 6, 0, &[]));
        sign_request(&mut compound, &key);

        let dispatched_before = handler.seen().len();
        let reply = conn.handle(&compound, &handler).unwrap();
        let message = message_of(&reply);
        let mut statuses = Vec::new();
        let mut offset = 0usize;
        loop {
            statuses.push(u32::from_le_bytes([
                message[offset + 8],
                message[offset + 9],
                message[offset + 10],
                message[offset + 11],
            ]));
            let next = u32::from_le_bytes([
                message[offset + 20],
                message[offset + 21],
                message[offset + 22],
                message[offset + 23],
            ]) as usize;
            if next == 0 {
                break;
            }
            offset += next;
        }
        assert_eq!(
            statuses,
            vec![
                status::SUCCESS,
                status::NO_SUCH_FILE,
                status::NO_SUCH_FILE,
                status::SUCCESS,
            ],
        );
        assert_eq!(
            &handler.seen()[dispatched_before..],
            &[command::CREATE, command::QUERY_DIRECTORY, command::ECHO],
            "the poisoned CLOSE must never reach the handler"
        );
    }

    #[test]
    fn compound_reply_signatures_cover_padding() {
        let mut conn = Connection::new();
        let handler = Recorder::default();
        let key = handshake(&mut conn, &handler);

        let mut compound = Vec::new();
        compound.extend_from_slice(&request(command::CREATE, 3, 64, &[]));
        compound.extend_from_slice(&request_flagged(
            command::QUERY_DIRECTORY,
            4,
            64,
            flags::RELATED_OPERATIONS,
            &[],
        ));
        compound.extend_from_slice(&request_flagged(
            command::CLOSE,
            5,
            0,
            flags::RELATED_OPERATIONS,
            &[],
        ));
        sign_request(&mut compound, &key);
        let reply = conn.handle(&compound, &handler).unwrap();
        let message = message_of(&reply);

        let mut offset = 0usize;
        let mut elements = 0;
        loop {
            let next = u32::from_le_bytes([
                message[offset + 20],
                message[offset + 21],
                message[offset + 22],
                message[offset + 23],
            ]) as usize;
            let end = if next != 0 {
                offset + next
            } else {
                message.len()
            };
            if next != 0 {
                assert_eq!(next % 8, 0, "element {elements} next_command not 8-aligned");
            }
            assert!(
                sign::verify(&message[offset..end], &key),
                "element {elements} (next={next}) failed signature verification",
            );
            elements += 1;
            if next == 0 {
                break;
            }
            offset += next;
        }
        assert_eq!(elements, 3, "three compound reply elements");
    }

    #[test]
    fn lifecycle_is_enforced() {
        let mut conn = Connection::new();
        let handler = Recorder::default();

        let framed = conn
            .handle(&request(command::TREE_CONNECT, 0, 0, &[]), &handler)
            .unwrap();
        assert_eq!(reply_status(&framed), status::ACCESS_DENIED);
        assert!(handler.seen().is_empty());

        let framed = conn
            .handle(&request(command::SESSION_SETUP, 1, 0, &[]), &handler)
            .unwrap();
        assert_eq!(reply_status(&framed), status::INVALID_PARAMETER);

        conn.handle(&request(command::NEGOTIATE, 2, 0, &[]), &handler)
            .unwrap();
        let framed = conn
            .handle(&request(command::NEGOTIATE, 3, 0, &[]), &handler)
            .unwrap();
        assert_eq!(reply_status(&framed), status::INVALID_PARAMETER);
    }

    #[test]
    fn handshake_derives_signing_and_signs_traffic() {
        let mut conn = Connection::new();
        let handler = Recorder::default();
        let key = handshake(&mut conn, &handler);

        let mut echo = request(command::ECHO, 3, 0, &[]);
        sign_request(&mut echo, &key);
        let framed = conn.handle(&echo, &handler).unwrap();
        assert_ne!(reply_flags(&framed) & flags::SIGNED, 0);
        assert!(sign::verify(message_of(&framed), &key));

        assert!(
            conn.handle(&request(command::ECHO, 4, 0, &[]), &handler)
                .is_none()
        );

        let forged = request_flagged(command::ECHO, 5, 0, flags::SIGNED, &[0u8; 8]);
        assert!(conn.handle(&forged, &handler).is_none());
    }

    #[test]
    fn a_correctly_signed_request_is_accepted() {
        let mut conn = Connection::new();
        let handler = Recorder::default();
        let key = handshake(&mut conn, &handler);

        let mut signed = request_flagged(command::ECHO, 5, 0, flags::SIGNED, &[0u8; 8]);
        sign::sign(&mut signed, &key);
        let framed = conn.handle(&signed, &handler).unwrap();
        assert_eq!(reply_status(&framed), status::SUCCESS);
    }

    #[test]
    fn ops_compounded_onto_the_completing_setup_do_not_ride_unsigned() {
        let mut conn = Connection::new();
        let handler = Recorder::default();
        conn.handle(&request(command::NEGOTIATE, 0, 0, &[]), &handler)
            .unwrap();
        conn.handle(&request(command::SESSION_SETUP, 1, 0, &[]), &handler)
            .unwrap();
        handler.seen.borrow_mut().clear();

        let setup = request(command::SESSION_SETUP, 2, 0, &[]);
        let setup_padded = setup.len().div_ceil(8) * 8;
        let mut compound = request(command::SESSION_SETUP, 2, setup_padded as u32, &[]);
        while compound.len() < setup_padded {
            compound.push(0);
        }
        compound.extend_from_slice(&request(command::ECHO, 3, 0, &[]));

        assert!(conn.handle(&compound, &handler).is_none());
        assert!(!handler.seen().contains(&command::ECHO));
    }

    #[test]
    fn compounds_split_and_chain() {
        let mut conn = Connection::new();
        let handler = Recorder::default();
        let key = handshake(&mut conn, &handler);
        handler.seen.borrow_mut().clear();

        let first = request(command::TREE_CONNECT, 6, 0, &[0xAA, 0xBB]);
        let first_padded = first.len().div_ceil(8) * 8;
        let mut compound = request(command::TREE_CONNECT, 6, first_padded as u32, &[0xAA, 0xBB]);
        while compound.len() < first_padded {
            compound.push(0);
        }
        compound.extend_from_slice(&request(command::ECHO, 7, 0, &[0xCC]));
        sign_request(&mut compound, &key);

        let framed = conn.handle(&compound, &handler).unwrap();
        assert_eq!(handler.seen(), vec![command::TREE_CONNECT, command::ECHO]);
        let next = u32::from_le_bytes([
            framed[4 + 20],
            framed[4 + 21],
            framed[4 + 22],
            framed[4 + 23],
        ]);
        assert_ne!(next, 0);
        assert_eq!(next % 8, 0);
    }

    #[test]
    fn hostile_frames_are_refused() {
        let mut conn = Connection::new();
        let handler = Recorder::default();
        let key = handshake(&mut conn, &handler);

        let mut leap = request(command::ECHO, 1_000_000, 0, &[]);
        sign_request(&mut leap, &key);
        let framed = conn.handle(&leap, &handler).unwrap();
        assert_eq!(reply_status(&framed), status::INVALID_PARAMETER);

        assert!(
            conn.handle(&request(command::ECHO, 3, 8, &[]), &handler)
                .is_none()
        );
        assert!(
            conn.handle(&request(command::ECHO, 3, 4096, &[]), &handler)
                .is_none()
        );
        assert!(conn.handle(&[0u8; 20], &handler).is_none());
    }

    fn read_body(file_id: [u8; 16]) -> Vec<u8> {
        let mut body = Vec::new();
        scalefs_core::wire::put_u16(&mut body, 49);
        body.push(0);
        body.push(0);
        scalefs_core::wire::put_u32(&mut body, 512);
        scalefs_core::wire::put_u64(&mut body, 0);
        body.extend_from_slice(&file_id);
        body.extend_from_slice(&[0u8; 17]);
        body
    }

    #[test]
    fn routing_classifies_and_the_worker_helpers_agree() {
        let mut conn = Connection::new();
        let handler = Recorder::default();

        assert!(matches!(
            conn.route(&request(command::READ, 0, 0, &read_body([0x11; 16]))),
            Route::Inline
        ));
        let key = handshake(&mut conn, &handler);

        let mut read = request(command::READ, 7, 0, &read_body([0x11; 16]));
        sign_request(&mut read, &key);
        let Route::Parallel(parallel) = conn.route(&read) else {
            panic!("a lone post-auth READ must route to a worker");
        };
        assert_eq!(parallel.header.message_id, 7);
        assert_eq!(parallel.header.command, command::READ);
        assert_eq!(parallel.key, key);

        assert!(verify_parallel(&read, &key));
        let mut tampered = read.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(!verify_parallel(&tampered, &key));
        let unsigned = request(command::READ, 8, 0, &read_body([0x11; 16]));
        assert!(!verify_parallel(&unsigned, &key));

        let reply = frame_parallel_reply(
            &parallel.header,
            Response::ok(vec![9, 0, 0, 0, 0, 0, 0, 0, 0]),
            &key,
            parallel.session_id,
        );
        assert_eq!(reply_status(&reply), status::SUCCESS);
        let echoed_mid = u64::from_le_bytes(reply[4 + 24..4 + 32].try_into().unwrap());
        assert_eq!(echoed_mid, 7);
        assert_ne!(reply_flags(&reply) & flags::SIGNED, 0);
        assert!(sign::verify(message_of(&reply), &key));

        let mut echo = request(command::ECHO, 8, 0, &[]);
        sign_request(&mut echo, &key);
        let framed = conn.handle(&echo, &handler).unwrap();
        assert_eq!(reply_status(&framed), status::SUCCESS);

        let mut compound = Vec::new();
        compound.extend_from_slice(&request(command::READ, 9, 96, &read_body([0x11; 16])));
        compound.extend_from_slice(&request(command::READ, 10, 0, &read_body([0x11; 16])));
        assert!(matches!(conn.route(&compound), Route::Inline));
        assert!(matches!(
            conn.route(&request_flagged(
                command::READ,
                9,
                0,
                flags::RELATED_OPERATIONS,
                &read_body([0x11; 16]),
            )),
            Route::Inline
        ));
        assert!(matches!(
            conn.route(&request(command::READ, 9, 0, &read_body([0xFF; 16]))),
            Route::Inline
        ));
        assert!(matches!(
            conn.route(&request(command::CREATE, 9, 0, &[])),
            Route::Inline
        ));
        let mut flush = request(command::FLUSH, 9, 0, &[0u8; 24]);
        sign_request(&mut flush, &key);
        assert!(matches!(conn.route(&flush), Route::Inline));
        assert!(matches!(
            conn.route(&request(
                command::READ,
                1_000_000,
                0,
                &read_body([0x11; 16])
            )),
            Route::Inline
        ));
        assert!(matches!(
            conn.route(&request(command::READ, u64::MAX, 0, &read_body([0x11; 16]))),
            Route::Inline
        ));
    }
}
