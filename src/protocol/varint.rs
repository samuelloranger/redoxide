use std::io::Read;

use tokio::io::{AsyncRead, AsyncReadExt};

pub async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<i32> {
    let mut result = 0i32;
    let mut shift = 0u32;

    loop {
        let byte = reader.read_u8().await?;
        result |= ((byte & 0x7f) as i32) << shift;

        if byte & 0x80 == 0 {
            return Ok(result);
        }

        shift += 7;
        anyhow::ensure!(shift < 35, "VarInt too long");
    }
}

pub fn read_varint_sync<R: Read>(reader: &mut R) -> anyhow::Result<i32> {
    let mut result = 0i32;
    let mut shift = 0u32;

    loop {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        result |= ((buf[0] & 0x7f) as i32) << shift;

        if buf[0] & 0x80 == 0 {
            return Ok(result);
        }

        shift += 7;
        anyhow::ensure!(shift < 35, "VarInt too long");
    }
}

pub fn encode_varint(value: i32) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut value = value as u32;

    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;

        if value != 0 {
            byte |= 0x80;
        }

        buf.push(byte);

        if value == 0 {
            break;
        }
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_varint_known_values() {
        assert_eq!(encode_varint(0), vec![0x00]);
        assert_eq!(encode_varint(1), vec![0x01]);
        assert_eq!(encode_varint(127), vec![0x7f]);
        assert_eq!(encode_varint(128), vec![0x80, 0x01]);
        assert_eq!(encode_varint(255), vec![0xff, 0x01]);
        assert_eq!(encode_varint(2097151), vec![0xff, 0xff, 0x7f]);
        assert_eq!(encode_varint(-1), vec![0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    #[tokio::test]
    async fn test_round_trip_async() {
        for val in [0, 1, 127, 128, 255, 769, 2097151, -1, i32::MAX] {
            let encoded = encode_varint(val);
            let mut cursor = std::io::Cursor::new(encoded);
            let decoded = read_varint(&mut cursor).await.unwrap();
            assert_eq!(decoded, val, "round trip failed for {val}");
        }
    }

    #[test]
    fn test_round_trip_sync() {
        for val in [0, 1, 128, 769, -1] {
            let encoded = encode_varint(val);
            let mut cursor = std::io::Cursor::new(encoded);
            let decoded = read_varint_sync(&mut cursor).unwrap();
            assert_eq!(decoded, val);
        }
    }
}
