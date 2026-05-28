use tokio::io::{AsyncRead, AsyncReadExt};

use super::varint::{encode_varint, read_varint, read_varint_sync};

pub struct RawPacket {
    pub id: i32,
    pub data: Vec<u8>,
}

pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<(RawPacket, Vec<u8>)> {
    let length = read_varint(reader).await? as usize;
    let mut buf = vec![0u8; length];
    reader.read_exact(&mut buf).await?;

    let len_bytes = encode_varint(length as i32);
    let mut raw = Vec::with_capacity(len_bytes.len() + length);
    raw.extend_from_slice(&len_bytes);
    raw.extend_from_slice(&buf);

    let mut cursor = std::io::Cursor::new(buf.as_slice());
    let id = read_varint_sync(&mut cursor)?;
    let data = buf[cursor.position() as usize..].to_vec();

    Ok((RawPacket { id, data }, raw))
}

pub fn encode_packet(id: i32, data: &[u8]) -> Vec<u8> {
    let id_bytes = encode_varint(id);
    let total = id_bytes.len() + data.len();
    let len_bytes = encode_varint(total as i32);
    let mut buf = Vec::with_capacity(len_bytes.len() + total);
    buf.extend_from_slice(&len_bytes);
    buf.extend_from_slice(&id_bytes);
    buf.extend_from_slice(data);
    buf
}

pub fn encode_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut buf = encode_varint(bytes.len() as i32);
    buf.extend_from_slice(bytes);
    buf
}

pub fn read_string_sync(cursor: &mut std::io::Cursor<&[u8]>) -> anyhow::Result<String> {
    let len = read_varint_sync(cursor)? as usize;
    let mut bytes = vec![0u8; len];
    std::io::Read::read_exact(cursor, &mut bytes)?;
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_packet_round_trip() {
        let data = vec![0xaa, 0xbb, 0xcc];
        let encoded = encode_packet(0x00, &data);
        let mut cursor = std::io::Cursor::new(encoded.clone());
        let (packet, raw) = read_packet(&mut cursor).await.unwrap();
        assert_eq!(packet.id, 0x00);
        assert_eq!(packet.data, data);
        assert_eq!(raw, encoded);
    }

    #[test]
    fn test_encode_string() {
        let encoded = encode_string("hello");
        assert_eq!(encoded[0], 5);
        assert_eq!(&encoded[1..], b"hello");
    }

    #[test]
    fn test_string_round_trip() {
        let original = "forbidden.samlo.cloud";
        let encoded = encode_string(original);
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let decoded = read_string_sync(&mut cursor).unwrap();
        assert_eq!(decoded, original);
    }
}
