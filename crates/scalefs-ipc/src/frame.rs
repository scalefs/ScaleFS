
use crate::json::{JsonError, Value, parse};
use std::io::{BufRead, Write};

pub const MAX_FRAME_LEN: usize = 8 << 20;

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    TooLong,
    NotUtf8,
    Json(JsonError),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(error) => write!(f, "transport error: {error}"),
            FrameError::TooLong => write!(f, "frame exceeds {} bytes", MAX_FRAME_LEN),
            FrameError::NotUtf8 => write!(f, "frame is not UTF-8"),
            FrameError::Json(error) => write!(f, "malformed frame: {error}"),
        }
    }
}

impl From<std::io::Error> for FrameError {
    fn from(error: std::io::Error) -> Self {
        FrameError::Io(error)
    }
}

pub fn write_frame(writer: &mut impl Write, value: &Value) -> std::io::Result<()> {
    let mut line = value.encode();
    line.push('\n');
    if line.len() > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds the 8 MiB limit",
        ));
    }
    writer.write_all(line.as_bytes())?;
    writer.flush()
}

pub fn read_frame(reader: &mut impl BufRead) -> Result<Option<Value>, FrameError> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(FrameError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream ended inside a frame",
                )))
            };
        }
        let (chunk, terminated) = match buffer.iter().position(|byte| *byte == b'\n') {
            Some(newline) => (&buffer[..newline], true),
            None => (buffer, false),
        };
        if line.len() + chunk.len() + usize::from(terminated) > MAX_FRAME_LEN {
            return Err(FrameError::TooLong);
        }
        line.extend_from_slice(chunk);
        let consumed = chunk.len() + usize::from(terminated);
        reader.consume(consumed);
        if terminated {
            let text = std::str::from_utf8(&line).map_err(|_| FrameError::NotUtf8)?;
            return parse(text).map(Some).map_err(FrameError::Json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::object;
    use std::io::BufReader;

    #[test]
    fn frames_round_trip() {
        let first = object(vec![("id", Value::Int(1))]);
        let second = object(vec![("id", Value::Int(2))]);
        let mut wire = Vec::new();
        write_frame(&mut wire, &first).unwrap();
        write_frame(&mut wire, &second).unwrap();

        let mut reader = BufReader::new(wire.as_slice());
        assert_eq!(read_frame(&mut reader).unwrap(), Some(first));
        assert_eq!(read_frame(&mut reader).unwrap(), Some(second));
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn tiny_buffers_reassemble_frames() {
        let value = object(vec![("text", Value::Str("x".repeat(1000)))]);
        let mut wire = Vec::new();
        write_frame(&mut wire, &value).unwrap();
        let mut reader = BufReader::with_capacity(7, wire.as_slice());
        assert_eq!(read_frame(&mut reader).unwrap(), Some(value));
    }

    #[test]
    fn oversized_frames_are_refused_while_reading() {
        let wire = vec![b'['; MAX_FRAME_LEN + 10];
        let mut reader = BufReader::new(wire.as_slice());
        assert!(matches!(read_frame(&mut reader), Err(FrameError::TooLong)));
    }

    #[test]
    fn truncated_and_malformed_frames_are_errors() {
        let mut reader = BufReader::new(&b"{\"id\":1}"[..]);
        assert!(matches!(read_frame(&mut reader), Err(FrameError::Io(_))));

        let mut reader = BufReader::new(&b"not json\n"[..]);
        assert!(matches!(read_frame(&mut reader), Err(FrameError::Json(_))));

        let mut reader = BufReader::new(&b"\xFF\xFE\n"[..]);
        assert!(matches!(read_frame(&mut reader), Err(FrameError::NotUtf8)));
    }

    #[test]
    fn exact_cap_is_accepted() {
        let padding = MAX_FRAME_LEN - "{\"p\":\"\"}\n".len();
        let value = object(vec![("p", Value::Str("y".repeat(padding)))]);
        let mut wire = Vec::new();
        write_frame(&mut wire, &value).unwrap();
        assert_eq!(wire.len(), MAX_FRAME_LEN);
        let mut reader = BufReader::new(wire.as_slice());
        assert_eq!(read_frame(&mut reader).unwrap(), Some(value));
    }
}
