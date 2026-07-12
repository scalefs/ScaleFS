
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

pub const MAX_DEPTH: usize = 64;

pub const INT_MIN: i128 = i64::MIN as i128;
pub const INT_MAX: i128 = u64::MAX as i128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    pub offset: usize,
    pub message: &'static str,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(int) => u64::try_from(*int).ok(),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(int) => i64::try_from(*int).ok(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn encode(&self) -> String {
        let mut out = String::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Int(int) => out.push_str(&int.to_string()),
            Value::Str(text) => encode_string(text, out),
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.encode_into(out);
                }
                out.push(']');
            }
            Value::Object(entries) => {
                out.push('{');
                for (index, (key, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    encode_string(key, out);
                    out.push(':');
                    value.encode_into(out);
                }
                out.push('}');
            }
        }
    }
}

pub fn object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn encode_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

pub fn parse(text: &str) -> Result<Value, JsonError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        offset: 0,
    };
    parser.skip_whitespace();
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.offset != parser.bytes.len() {
        return Err(parser.error("trailing bytes after the document"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Parser<'a> {
    fn error(&self, message: &'static str) -> JsonError {
        JsonError {
            offset: self.offset,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            match byte {
                b' ' | b'\t' | b'\n' | b'\r' => self.offset += 1,
                _ => break,
            }
        }
    }

    fn expect(&mut self, literal: &str, message: &'static str) -> Result<(), JsonError> {
        if self.bytes[self.offset..].starts_with(literal.as_bytes()) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(self.error(message))
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, JsonError> {
        match self.peek() {
            None => Err(self.error("unexpected end of document")),
            Some(b'n') => {
                self.expect("null", "expected null")?;
                Ok(Value::Null)
            }
            Some(b't') => {
                self.expect("true", "expected true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.expect("false", "expected false")?;
                Ok(Value::Bool(false))
            }
            Some(b'"') => Ok(Value::Str(self.parse_string()?)),
            Some(b'[') => {
                if depth >= MAX_DEPTH {
                    return Err(self.error("document nests too deeply"));
                }
                self.parse_array(depth)
            }
            Some(b'{') => {
                if depth >= MAX_DEPTH {
                    return Err(self.error("document nests too deeply"));
                }
                self.parse_object(depth)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_int(),
            Some(_) => Err(self.error("unexpected character")),
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.offset += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.offset += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.parse_value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.offset += 1,
                Some(b']') => {
                    self.offset += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error("expected ',' or ']' in array")),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.offset += 1;
        let mut entries: Vec<(String, Value)> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.offset += 1;
            return Ok(Value::Object(entries));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected a string key"));
            }
            let key = self.parse_string()?;
            if !seen.insert(key.clone()) {
                return Err(self.error("duplicate object key"));
            }
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(self.error("expected ':' after object key"));
            }
            self.offset += 1;
            self.skip_whitespace();
            let value = self.parse_value(depth + 1)?;
            entries.push((key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.offset += 1,
                Some(b'}') => {
                    self.offset += 1;
                    return Ok(Value::Object(entries));
                }
                _ => return Err(self.error("expected ',' or '}' in object")),
            }
        }
    }

    fn parse_int(&mut self) -> Result<Value, JsonError> {
        let start = self.offset;
        if self.peek() == Some(b'-') {
            self.offset += 1;
        }
        let digits_start = self.offset;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        if self.offset == digits_start {
            return Err(self.error("expected digits"));
        }
        if self.bytes[digits_start] == b'0' && self.offset - digits_start > 1 {
            self.offset = digits_start;
            return Err(self.error("leading zeros are not permitted"));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(self.error("non-integer numbers are not part of this protocol"));
        }
        let text = std::str::from_utf8(&self.bytes[start..self.offset])
            .expect("digits and minus are ASCII");
        let int: i128 = text.parse().map_err(|_| JsonError {
            offset: start,
            message: "integer overflows the protocol range",
        })?;
        if !(INT_MIN..=INT_MAX).contains(&int) {
            return Err(JsonError {
                offset: start,
                message: "integer outside the protocol range",
            });
        }
        Ok(Value::Int(int))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.offset += 1;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.error("unterminated string"));
            };
            match byte {
                b'"' => {
                    self.offset += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.offset += 1;
                    out.push(self.parse_escape()?);
                }
                0x00..=0x1F => return Err(self.error("unescaped control character in string")),
                _ => {
                    let text = &self.bytes[self.offset..];
                    let ch_len = utf8_len(byte);
                    let slice = std::str::from_utf8(&text[..ch_len.min(text.len())])
                        .map_err(|_| self.error("invalid UTF-8 in string"))?;
                    let ch = slice.chars().next().ok_or(self.error("truncated string"))?;
                    out.push(ch);
                    self.offset += ch.len_utf8();
                }
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, JsonError> {
        let Some(byte) = self.peek() else {
            return Err(self.error("unterminated escape"));
        };
        self.offset += 1;
        Ok(match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{08}',
            b'f' => '\u{0C}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.parse_unicode_escape(),
            _ => {
                self.offset -= 1;
                return Err(self.error("unknown escape"));
            }
        })
    }

    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.parse_hex4()?;
        if (0xD800..=0xDBFF).contains(&first) {
            self.expect("\\u", "high surrogate must pair with a low surrogate")?;
            let second = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(self.error("invalid low surrogate"));
            }
            let combined = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
            return char::from_u32(combined).ok_or(self.error("invalid surrogate pair"));
        }
        if (0xDC00..=0xDFFF).contains(&first) {
            return Err(self.error("lone low surrogate"));
        }
        char::from_u32(first).ok_or(self.error("invalid unicode escape"))
    }

    fn parse_hex4(&mut self) -> Result<u32, JsonError> {
        let mut out: u32 = 0;
        for _ in 0..4 {
            let Some(byte) = self.peek() else {
                return Err(self.error("truncated unicode escape"));
            };
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err(self.error("invalid hex digit in unicode escape")),
            };
            out = out * 16 + digit;
            self.offset += 1;
        }
        Ok(out)
    }
}

fn utf8_len(first_byte: u8) -> usize {
    match first_byte {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(value: &Value) {
        assert_eq!(&parse(&value.encode()).unwrap(), value);
    }

    #[test]
    fn scalars_round_trip() {
        round_trip(&Value::Null);
        round_trip(&Value::Bool(true));
        round_trip(&Value::Bool(false));
        round_trip(&Value::Int(0));
        round_trip(&Value::Int(-1));
        round_trip(&Value::Int(INT_MIN));
        round_trip(&Value::Int(INT_MAX));
        round_trip(&Value::Str(String::new()));
        round_trip(&Value::Str("plain text".into()));
    }

    #[test]
    fn strings_with_escapes_round_trip() {
        round_trip(&Value::Str("quote \" slash \\ newline \n tab \t".into()));
        round_trip(&Value::Str("control \u{01} \u{1F} bell \u{07}".into()));
        round_trip(&Value::Str("unicode: żółć 日本語 🦀".into()));
    }

    #[test]
    fn containers_round_trip() {
        round_trip(&Value::Array(vec![]));
        round_trip(&Value::Object(vec![]));
        round_trip(&object(vec![
            ("id", Value::Int(7)),
            ("op", Value::Str("ping".into())),
            (
                "params",
                object(vec![(
                    "members",
                    Value::Array(vec![Value::Str("a.img".into()), Value::Null]),
                )]),
            ),
        ]));
    }

    #[test]
    fn golden_encoding_is_stable() {
        let value = object(vec![
            ("id", Value::Int(1)),
            ("op", Value::Str("pool.status".into())),
            ("ok", Value::Bool(true)),
            ("size", Value::Int(18_446_744_073_709_551_615)),
            ("note", Value::Str("tab\there".into())),
        ]);
        assert_eq!(
            value.encode(),
            "{\"id\":1,\"op\":\"pool.status\",\"ok\":true,\
             \"size\":18446744073709551615,\"note\":\"tab\\there\"}"
        );
    }

    #[test]
    fn standard_json_parses() {
        let value = parse(" { \"a\" : [ 1 , 2 ] , \"b\" : null } ").unwrap();
        assert_eq!(value.get("a").unwrap().as_array().unwrap().len(), 2);
        assert_eq!(value.get("b"), Some(&Value::Null));
        assert_eq!(parse("\"\\u0041\\u00e9\\ud83e\\udd80\"").unwrap(), {
            Value::Str("Aé🦀".into())
        });
    }

    #[test]
    fn accessors_narrow_types() {
        let value = object(vec![
            ("small", Value::Int(-5)),
            ("big", Value::Int(INT_MAX)),
        ]);
        assert_eq!(value.get("small").unwrap().as_i64(), Some(-5));
        assert_eq!(value.get("small").unwrap().as_u64(), None);
        assert_eq!(value.get("big").unwrap().as_u64(), Some(u64::MAX));
        assert_eq!(value.get("big").unwrap().as_i64(), None);
        assert_eq!(value.get("missing"), None);
        assert_eq!(Value::Null.get("anything"), None);
    }

    #[test]
    fn malformed_documents_are_rejected() {
        for (text, why) in [
            ("", "empty"),
            ("  ", "whitespace only"),
            ("nul", "truncated literal"),
            ("truee", "trailing garbage"),
            ("1 2", "two documents"),
            ("[1,]", "trailing comma"),
            ("[1 2]", "missing comma"),
            ("{\"a\":1,}", "trailing comma in object"),
            ("{a:1}", "unquoted key"),
            ("{\"a\"}", "missing value"),
            ("{\"a\":1 \"b\":2}", "missing comma in object"),
            ("\"unterminated", "unterminated string"),
            ("\"bad \\q escape\"", "unknown escape"),
            ("\"tab\ttab\"", "raw control character"),
            ("\"\\ud800\"", "lone high surrogate"),
            ("\"\\udc00\"", "lone low surrogate"),
            ("\"\\ud800\\u0041\"", "bad low surrogate"),
            ("\"\\u12g4\"", "bad hex digit"),
            ("01", "leading zero"),
            ("-", "bare minus"),
            ("+1", "leading plus"),
            ("1.5", "fraction"),
            ("1e3", "exponent"),
            ("18446744073709551616", "past u64::MAX"),
            ("-9223372036854775809", "past i64::MIN"),
        ] {
            assert!(parse(text).is_err(), "{why}: {text}");
        }
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        assert_eq!(
            parse("{\"a\":1,\"a\":2}").unwrap_err().message,
            "duplicate object key"
        );
    }

    #[test]
    fn depth_is_capped() {
        let over = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert_eq!(
            parse(&over).unwrap_err().message,
            "document nests too deeply"
        );
        let ok = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(parse(&ok).is_ok());
        let mixed = "{\"k\":".repeat(MAX_DEPTH / 2)
            + &"[".repeat(MAX_DEPTH / 2 + 1)
            + &"]".repeat(MAX_DEPTH / 2 + 1)
            + &"}".repeat(MAX_DEPTH / 2);
        assert_eq!(
            parse(&mixed).unwrap_err().message,
            "document nests too deeply"
        );
    }

    #[test]
    fn errors_carry_offsets() {
        let error = parse("{\"a\": bad}").unwrap_err();
        assert_eq!(error.offset, 6);
        assert_eq!(format!("{error}"), "unexpected character at byte 6");
    }
}
