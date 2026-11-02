use super::crypto::md5::hmac_md5;
use super::crypto::rc4::rc4;
use super::crypto::{ct_eq, md4::nt_hash};

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

pub mod flags {
    pub const UNICODE: u32 = 0x0000_0001;
    pub const SIGN: u32 = 0x0000_0010;
    pub const SEAL: u32 = 0x0000_0020;
    pub const NTLM: u32 = 0x0000_0200;
    pub const TARGET_INFO: u32 = 0x0080_0000;
    pub const KEY_EXCH: u32 = 0x4000_0000;
    pub const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub const NEGOTIATE_128: u32 = 0x2000_0000;
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub user: String,
    pub nt_hash: [u8; 16],
}

impl Credential {
    pub fn new(user: &str, password: &str) -> Credential {
        Credential {
            user: user.to_string(),
            nt_hash: nt_hash(password),
        }
    }

    pub fn from_nt_hash(user: &str, nt_hash: [u8; 16]) -> Credential {
        Credential {
            user: user.to_string(),
            nt_hash,
        }
    }
}

pub struct Server {
    challenge: [u8; 8],
    target_name: Vec<u8>,
    target_info: Vec<u8>,
}

#[derive(Debug)]
pub struct Authenticated {
    pub session_key: [u8; 16],
    pub user: String,
}

impl Server {
    pub fn new(challenge: [u8; 8], target: &str) -> Server {
        let target_name = utf16le(target);
        let mut target_info = Vec::new();
        av_pair(&mut target_info, 0x0002, &utf16le(target));
        av_pair(&mut target_info, 0x0001, &utf16le(target));
        av_pair(&mut target_info, 0x0000, &[]);
        Server {
            challenge,
            target_name,
            target_info,
        }
    }

    pub fn challenge_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP_SIGNATURE);
        put_u32(&mut msg, 2);
        let target_off = 56u32;
        put_u16(&mut msg, self.target_name.len() as u16);
        put_u16(&mut msg, self.target_name.len() as u16);
        put_u32(&mut msg, target_off);
        let negotiate = flags::UNICODE
            | flags::NTLM
            | flags::TARGET_INFO
            | flags::KEY_EXCH
            | flags::EXTENDED_SESSIONSECURITY
            | flags::NEGOTIATE_128
            | flags::SIGN;
        put_u32(&mut msg, negotiate);
        msg.extend_from_slice(&self.challenge);
        msg.extend_from_slice(&[0u8; 8]);
        let info_off = target_off + self.target_name.len() as u32;
        put_u16(&mut msg, self.target_info.len() as u16);
        put_u16(&mut msg, self.target_info.len() as u16);
        put_u32(&mut msg, info_off);
        put_u64(&mut msg, 0);
        debug_assert_eq!(msg.len(), 56);
        msg.extend_from_slice(&self.target_name);
        msg.extend_from_slice(&self.target_info);
        msg
    }

    pub fn verify(&self, auth: &[u8], credential: &Credential) -> Result<Authenticated, AuthError> {
        let msg = AuthenticateMessage::parse(auth)?;
        if msg.nt_response.len() < 16 {
            return Err(AuthError::NotNtlmV2);
        }
        let (proof, blob) = msg.nt_response.split_at(16);

        let mut identity = utf16le(&msg.user.to_uppercase());
        identity.extend_from_slice(&utf16le(&msg.domain));
        let ntowfv2 = hmac_md5(&credential.nt_hash, &identity);

        let mut proof_input = Vec::with_capacity(8 + blob.len());
        proof_input.extend_from_slice(&self.challenge);
        proof_input.extend_from_slice(blob);
        let expected = hmac_md5(&ntowfv2, &proof_input);
        if !ct_eq(proof, &expected) {
            return Err(AuthError::BadProof);
        }

        if !msg.user.eq_ignore_ascii_case(&credential.user) {
            return Err(AuthError::WrongUser);
        }

        let session_base_key = hmac_md5(&ntowfv2, proof);

        let session_key =
            if msg.flags & flags::KEY_EXCH != 0 && msg.encrypted_session_key.len() == 16 {
                let decrypted = rc4(&session_base_key, &msg.encrypted_session_key);
                let mut key = [0u8; 16];
                key.copy_from_slice(&decrypted);
                key
            } else {
                session_base_key
            };

        Ok(Authenticated {
            session_key,
            user: msg.user,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Malformed,
    NotNtlmV2,
    BadProof,
    WrongUser,
}

struct AuthenticateMessage {
    flags: u32,
    domain: String,
    user: String,
    nt_response: Vec<u8>,
    encrypted_session_key: Vec<u8>,
}

impl AuthenticateMessage {
    fn parse(msg: &[u8]) -> Result<AuthenticateMessage, AuthError> {
        if msg.len() < 64 || &msg[0..8] != NTLMSSP_SIGNATURE {
            return Err(AuthError::Malformed);
        }
        if read_u32(msg, 8) != 3 {
            return Err(AuthError::Malformed);
        }
        let field = |pos: usize| -> Result<&[u8], AuthError> {
            let len = read_u16(msg, pos) as usize;
            let off = read_u32(msg, pos + 4) as usize;
            msg.get(off..off + len).ok_or(AuthError::Malformed)
        };
        let _lm = field(12)?;
        let nt_response = field(20)?.to_vec();
        let domain = utf16le_to_string(field(28)?);
        let user = utf16le_to_string(field(36)?);
        let _workstation = field(44)?;
        let encrypted_session_key = field(52)?.to_vec();
        let flags = read_u32(msg, 60);
        Ok(AuthenticateMessage {
            flags,
            domain,
            user,
            nt_response,
            encrypted_session_key,
        })
    }
}

fn av_pair(out: &mut Vec<u8>, id: u16, value: &[u8]) {
    put_u16(out, id);
    put_u16(out, value.len() as u16);
    out.extend_from_slice(value);
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn utf16le_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
#[derive(Debug)]
pub struct AuthThrottle {
    free_failures: u32,
    base_delay: std::time::Duration,
    max_delay: std::time::Duration,
    state: std::sync::Mutex<ThrottleState>,
}

#[derive(Debug, Default)]
struct ThrottleState {
    consecutive: u32,
    cooldown_until: Option<std::time::Instant>,
}

impl Default for AuthThrottle {
    fn default() -> AuthThrottle {
        AuthThrottle::with_tuning(
            3,
            std::time::Duration::from_millis(500),
            std::time::Duration::from_secs(30),
        )
    }
}

impl AuthThrottle {
    pub fn share_wide() -> AuthThrottle {
        AuthThrottle::with_tuning(
            20,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(5),
        )
    }

    pub fn with_tuning(
        free_failures: u32,
        base_delay: std::time::Duration,
        max_delay: std::time::Duration,
    ) -> AuthThrottle {
        AuthThrottle {
            free_failures,
            base_delay,
            max_delay,
            state: std::sync::Mutex::new(ThrottleState::default()),
        }
    }

    pub fn gate(&self) -> bool {
        self.gate_at(std::time::Instant::now())
    }

    pub fn record_failure(&self) {
        self.record_failure_at(std::time::Instant::now());
    }

    pub fn record_success(&self) {
        let mut state = self.state.lock().expect("throttle state");
        state.consecutive = 0;
        state.cooldown_until = None;
    }

    fn gate_at(&self, now: std::time::Instant) -> bool {
        let state = self.state.lock().expect("throttle state");
        match state.cooldown_until {
            Some(until) => now >= until,
            None => true,
        }
    }

    fn record_failure_at(&self, now: std::time::Instant) {
        let mut state = self.state.lock().expect("throttle state");
        state.consecutive = state.consecutive.saturating_add(1);
        if state.consecutive <= self.free_failures {
            return;
        }
        let over = state.consecutive - self.free_failures;
        let doubling = 1u32 << (over - 1).min(16);
        let delay = self.base_delay.saturating_mul(doubling).min(self.max_delay);
        state.cooldown_until = Some(now + delay);
    }
}

#[cfg(test)]
mod throttle_tests {
    use super::AuthThrottle;
    use std::time::{Duration, Instant};

    fn throttle() -> AuthThrottle {
        AuthThrottle::with_tuning(3, Duration::from_millis(100), Duration::from_secs(2))
    }

    #[test]
    fn free_failures_never_cool_down() {
        let throttle = throttle();
        let now = Instant::now();
        for _ in 0..3 {
            assert!(throttle.gate_at(now));
            throttle.record_failure_at(now);
        }
        assert!(throttle.gate_at(now), "the free budget must not throttle");
    }

    #[test]
    fn failures_past_the_budget_cool_down_exponentially_to_the_cap() {
        let throttle = throttle();
        let now = Instant::now();
        for _ in 0..3 {
            throttle.record_failure_at(now);
        }
        throttle.record_failure_at(now);
        assert!(!throttle.gate_at(now + Duration::from_millis(99)));
        assert!(throttle.gate_at(now + Duration::from_millis(100)));
        throttle.record_failure_at(now);
        assert!(!throttle.gate_at(now + Duration::from_millis(199)));
        assert!(throttle.gate_at(now + Duration::from_millis(200)));
        throttle.record_failure_at(now);
        assert!(!throttle.gate_at(now + Duration::from_millis(399)));
        assert!(throttle.gate_at(now + Duration::from_millis(400)));
        for _ in 0..64 {
            throttle.record_failure_at(now);
        }
        assert!(!throttle.gate_at(now + Duration::from_millis(1_999)));
        assert!(throttle.gate_at(now + Duration::from_secs(2)));
    }

    #[test]
    fn success_resets_the_count() {
        let throttle = throttle();
        let now = Instant::now();
        for _ in 0..8 {
            throttle.record_failure_at(now);
        }
        assert!(!throttle.gate_at(now));
        throttle.record_success();
        assert!(throttle.gate_at(now), "success must clear the cooldown");
        for _ in 0..3 {
            throttle.record_failure_at(now);
        }
        assert!(throttle.gate_at(now));
    }
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_authenticate(
        server: &Server,
        user: &str,
        domain: &str,
        password: &str,
        client_challenge: [u8; 8],
        want_key_exch: bool,
    ) -> (Vec<u8>, [u8; 16]) {
        let nt_hash = nt_hash(password);
        let mut identity = utf16le(&user.to_uppercase());
        identity.extend_from_slice(&utf16le(domain));
        let ntowfv2 = hmac_md5(&nt_hash, &identity);

        let mut blob = Vec::new();
        blob.extend_from_slice(&[0x01, 0x01, 0, 0]);
        put_u32(&mut blob, 0);
        put_u64(&mut blob, 0x01D9_0000_0000_0000);
        blob.extend_from_slice(&client_challenge);
        put_u32(&mut blob, 0);
        blob.extend_from_slice(&server.target_info);
        put_u32(&mut blob, 0);

        let mut proof_input = Vec::new();
        proof_input.extend_from_slice(&server.challenge);
        proof_input.extend_from_slice(&blob);
        let proof = hmac_md5(&ntowfv2, &proof_input);
        let session_base_key = hmac_md5(&ntowfv2, &proof);

        let mut nt_response = proof.to_vec();
        nt_response.extend_from_slice(&blob);

        let exported = [0x5Au8; 16];
        let (encrypted_key, expect_key) = if want_key_exch {
            (rc4(&session_base_key, &exported).to_vec(), exported)
        } else {
            (Vec::new(), session_base_key)
        };

        let mut fixed = vec![0u8; 64];
        fixed[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        fixed[8..12].copy_from_slice(&3u32.to_le_bytes());
        let mut payload = Vec::new();
        let place = |fixed: &mut [u8], pos: usize, data: &[u8], payload: &mut Vec<u8>| {
            let off = 64 + payload.len();
            fixed[pos..pos + 2].copy_from_slice(&(data.len() as u16).to_le_bytes());
            fixed[pos + 2..pos + 4].copy_from_slice(&(data.len() as u16).to_le_bytes());
            fixed[pos + 4..pos + 8].copy_from_slice(&(off as u32).to_le_bytes());
            payload.extend_from_slice(data);
        };
        place(&mut fixed, 12, &[], &mut payload);
        place(&mut fixed, 20, &nt_response, &mut payload);
        place(&mut fixed, 28, &utf16le(domain), &mut payload);
        place(&mut fixed, 36, &utf16le(user), &mut payload);
        place(&mut fixed, 44, &utf16le("WS"), &mut payload);
        place(&mut fixed, 52, &encrypted_key, &mut payload);
        let mut negotiate = flags::UNICODE | flags::NTLM | flags::EXTENDED_SESSIONSECURITY;
        if want_key_exch {
            negotiate |= flags::KEY_EXCH;
        }
        fixed[60..64].copy_from_slice(&negotiate.to_le_bytes());

        let mut msg = fixed;
        msg.extend_from_slice(&payload);
        (msg, expect_key)
    }

    #[test]
    fn challenge_message_is_well_formed() {
        let server = Server::new([0xAB; 8], "SCALEFS");
        let msg = server.challenge_message();
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(read_u32(&msg, 8), 2, "type 2");
        assert_eq!(&msg[24..32], &[0xAB; 8]);
        let f = read_u32(&msg, 20);
        assert_ne!(f & flags::UNICODE, 0);
        assert_ne!(f & flags::KEY_EXCH, 0);
    }

    #[test]
    fn correct_password_authenticates_with_key_exchange() {
        let server = Server::new([0x11; 8], "SCALEFS");
        let credential = Credential::new("backup", "s3cret-pass");
        let (auth, expect_key) =
            client_authenticate(&server, "backup", "SCALEFS", "s3cret-pass", [0x22; 8], true);
        let result = server.verify(&auth, &credential).unwrap();
        assert_eq!(result.user, "backup");
        assert_eq!(
            result.session_key, expect_key,
            "the exchanged key is recovered"
        );
    }

    #[test]
    fn correct_password_without_key_exchange_uses_base_key() {
        let server = Server::new([0x11; 8], "SCALEFS");
        let credential = Credential::new("backup", "hunter2");
        let (auth, expect_key) =
            client_authenticate(&server, "backup", "SCALEFS", "hunter2", [0x33; 8], false);
        let result = server.verify(&auth, &credential).unwrap();
        assert_eq!(result.session_key, expect_key);
    }

    #[test]
    fn a_credential_from_the_stored_hash_authenticates() {
        let from_password = Credential::new("backup", "s3cret-pass");
        let restored = Credential::from_nt_hash("backup", from_password.nt_hash);
        let server = Server::new([0x11; 8], "SCALEFS");
        let (auth, expect_key) =
            client_authenticate(&server, "backup", "SCALEFS", "s3cret-pass", [0x22; 8], true);
        let result = server.verify(&auth, &restored).unwrap();
        assert_eq!(result.user, "backup");
        assert_eq!(result.session_key, expect_key);
    }

    #[test]
    fn wrong_password_is_refused() {
        let server = Server::new([0x11; 8], "SCALEFS");
        let credential = Credential::new("backup", "the-real-password");
        let (auth, _) = client_authenticate(
            &server,
            "backup",
            "SCALEFS",
            "a-different-password",
            [0x44; 8],
            true,
        );
        assert_eq!(
            server.verify(&auth, &credential).unwrap_err(),
            AuthError::BadProof
        );
    }

    #[test]
    fn wrong_user_is_refused() {
        let server = Server::new([0x11; 8], "SCALEFS");
        let credential = Credential {
            user: "admin".to_string(),
            nt_hash: nt_hash("shared"),
        };
        let (auth, _) = client_authenticate(&server, "guest", "SCALEFS", "shared", [0x55; 8], true);
        assert_eq!(
            server.verify(&auth, &credential).unwrap_err(),
            AuthError::WrongUser
        );
    }

    #[test]
    fn ntlmv1_and_garbage_are_refused() {
        let server = Server::new([0x11; 8], "SCALEFS");
        let credential = Credential::new("backup", "pw");
        assert_eq!(
            server.verify(&[0u8; 10], &credential).unwrap_err(),
            AuthError::Malformed
        );
        let (mut auth, _) =
            client_authenticate(&server, "backup", "SCALEFS", "pw", [0x66; 8], true);
        auth[20..22].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(
            server.verify(&auth, &credential).unwrap_err(),
            AuthError::NotNtlmV2
        );
    }
}
