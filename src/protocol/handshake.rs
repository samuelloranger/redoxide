use super::packet::read_string_sync;
use super::varint::read_varint_sync;

#[derive(Debug)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: i32,
}

pub fn parse_handshake(data: &[u8]) -> anyhow::Result<Handshake> {
    use std::io::Read;

    let mut cursor = std::io::Cursor::new(data);
    let protocol_version = read_varint_sync(&mut cursor)?;
    let raw_address = read_string_sync(&mut cursor)?;
    let server_address = raw_address.split('\0').next().unwrap_or("").to_string();

    let mut port_bytes = [0u8; 2];
    cursor.read_exact(&mut port_bytes)?;
    let server_port = u16::from_be_bytes(port_bytes);
    let next_state = read_varint_sync(&mut cursor)?;

    Ok(Handshake {
        protocol_version,
        server_address,
        server_port,
        next_state,
    })
}

/// Extracts just the username from a Login Start packet. Deliberately does
/// not parse whatever follows the username: that tail differs by protocol
/// version (nothing on 1.13-1.18.2, an optional signature + optional UUID on
/// 1.19.x, a mandatory 16-byte UUID on 1.20.2+) and this proxy forwards the
/// client's raw packet bytes rather than reconstructing them, so it never
/// needs to interpret the tail.
pub fn parse_login_start(data: &[u8]) -> anyhow::Result<String> {
    let mut cursor = std::io::Cursor::new(data);
    read_string_sync(&mut cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::packet::encode_string;
    use super::super::varint::encode_varint;

    fn make_handshake_bytes(protocol: i32, addr: &str, port: u16, state: i32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&encode_varint(protocol));
        data.extend_from_slice(&encode_string(addr));
        data.extend_from_slice(&port.to_be_bytes());
        data.extend_from_slice(&encode_varint(state));
        data
    }

    #[test]
    fn test_parse_handshake_login() {
        let data = make_handshake_bytes(769, "forbidden.samlo.cloud", 25565, 2);
        let hs = parse_handshake(&data).unwrap();
        assert_eq!(hs.protocol_version, 769);
        assert_eq!(hs.server_address, "forbidden.samlo.cloud");
        assert_eq!(hs.server_port, 25565);
        assert_eq!(hs.next_state, 2);
    }

    #[test]
    fn test_parse_handshake_strips_forge_marker_for_validation_only() {
        let data = make_handshake_bytes(769, "forbidden.samlo.cloud\0FML2\0", 25565, 1);
        let hs = parse_handshake(&data).unwrap();
        assert_eq!(hs.server_address, "forbidden.samlo.cloud");
    }

    #[test]
    fn test_parse_login_start_1_13_style_no_tail() {
        // 1.13-1.18.2: Login Start is just the username, nothing else.
        let data = encode_string("Notch");
        let username = parse_login_start(&data).unwrap();
        assert_eq!(username, "Notch");
    }

    #[test]
    fn test_parse_login_start_1_20_2_style_with_uuid_tail() {
        // 1.20.2+: username followed by a mandatory 16-byte UUID.
        let uuid = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut data = encode_string("Notch");
        data.extend_from_slice(&uuid);
        let username = parse_login_start(&data).unwrap();
        assert_eq!(username, "Notch");
    }

    #[test]
    fn test_parse_login_start_arbitrary_tail_length() {
        // 1.19.x: optional signature data of variable length. This proxy
        // never needs to interpret the tail — it forwards the raw packet —
        // so parsing must tolerate any trailing length, including odd ones.
        let mut data = encode_string("Notch");
        data.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        let username = parse_login_start(&data).unwrap();
        assert_eq!(username, "Notch");
    }
}
