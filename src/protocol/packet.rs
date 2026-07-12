use tokio::io::{AsyncRead, AsyncReadExt};

use super::varint::{encode_varint, read_varint, read_varint_sync};

/// Max uncompressed packet size per wiki.vg "Protocol#Packet_format": 2^21 - 1.
pub const MAX_PACKET_LEN: usize = 2_097_151;
/// Generous cap for length-prefixed strings — well above any vanilla protocol
/// string field (chat messages, the largest, cap at 262144 chars/~1MB utf8;
/// this proxy only ever reads addresses/usernames, so this is already loose).
pub const MAX_STRING_LEN: usize = 131_072;

pub struct RawPacket {
    pub id: i32,
    pub data: Vec<u8>,
}

pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<(RawPacket, Vec<u8>)> {
    let raw_length = read_varint(reader).await?;
    anyhow::ensure!(raw_length >= 0, "negative packet length: {raw_length}");
    let length = raw_length as usize;
    anyhow::ensure!(
        length <= MAX_PACKET_LEN,
        "packet length {length} exceeds max {MAX_PACKET_LEN}"
    );
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
    let raw_len = read_varint_sync(cursor)?;
    anyhow::ensure!(raw_len >= 0, "negative string length: {raw_len}");
    let len = raw_len as usize;
    anyhow::ensure!(
        len <= MAX_STRING_LEN,
        "string length {len} exceeds max {MAX_STRING_LEN}"
    );
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

    #[tokio::test]
    async fn test_read_packet_rejects_negative_length() {
        // encode_varint(-1) == 0xff 0xff 0xff 0xff 0x0f — a valid 5-byte VarInt
        // whose decoded value is negative.
        let encoded = crate::protocol::varint::encode_varint(-1);
        let mut cursor = std::io::Cursor::new(encoded);
        let result = read_packet(&mut cursor).await;
        assert!(result.is_err(), "negative packet length must be rejected");
    }

    #[tokio::test]
    async fn test_read_packet_rejects_oversized_length() {
        // MAX_PACKET_LEN + 1, framed as a VarInt with no payload behind it —
        // must be rejected before any allocation/read is attempted.
        let encoded = crate::protocol::varint::encode_varint((MAX_PACKET_LEN + 1) as i32);
        let mut cursor = std::io::Cursor::new(encoded);
        let result = read_packet(&mut cursor).await;
        assert!(result.is_err(), "oversized packet length must be rejected");
    }

    #[test]
    fn test_read_string_rejects_oversized_length() {
        let encoded = crate::protocol::varint::encode_varint((MAX_STRING_LEN + 1) as i32);
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let result = read_string_sync(&mut cursor);
        assert!(result.is_err(), "oversized string length must be rejected");
    }
}
