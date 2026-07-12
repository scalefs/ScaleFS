
use crate::error::{Result, ScaleFsError};

pub fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ScaleFsError::Corrupt("length overflows cursor"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(ScaleFsError::Corrupt("payload ended unexpectedly"))?;
        self.offset = end;
        Ok(bytes)
    }

    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.take(N)?;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    pub fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn take_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take_array()?))
    }

    pub fn take_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take_array()?))
    }

    pub fn take_u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take_array()?))
    }

    pub fn take_i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.take_array()?))
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub fn expect_end(&self, what: &'static str) -> Result<()> {
        if self.remaining() != 0 {
            return Err(ScaleFsError::Corrupt(what));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_integers() {
        let mut out = Vec::new();
        put_u16(&mut out, 0x1234);
        put_u32(&mut out, 0x5678_9ABC);
        put_u64(&mut out, 0xDEF0_1234_5678_9ABC);
        put_i64(&mut out, -42);

        let mut cursor = Cursor::new(&out);
        assert_eq!(cursor.take_u16().unwrap(), 0x1234);
        assert_eq!(cursor.take_u32().unwrap(), 0x5678_9ABC);
        assert_eq!(cursor.take_u64().unwrap(), 0xDEF0_1234_5678_9ABC);
        assert_eq!(cursor.take_i64().unwrap(), -42);
        cursor.expect_end("trailing").unwrap();
    }

    #[test]
    fn reading_past_the_end_is_corruption() {
        let mut cursor = Cursor::new(&[1, 2, 3]);
        assert_eq!(cursor.take_u16().unwrap(), 0x0201);
        assert!(cursor.take_u16().is_err());
        assert_eq!(cursor.remaining(), 1);
        assert_eq!(cursor.take_u8().unwrap(), 3);
    }

    #[test]
    fn expect_end_reports_trailing_bytes() {
        let cursor = Cursor::new(&[0xFF]);
        assert!(matches!(
            cursor.expect_end("record has trailing bytes"),
            Err(ScaleFsError::Corrupt("record has trailing bytes"))
        ));
    }
}
