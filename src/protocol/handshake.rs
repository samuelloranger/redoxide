use super::packet::{encode_string, read_string_sync};
use super::varint::{encode_varint, read_varint_sync};

#[derive(Debug)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: i32,
}

#[derive(Debug)]
pub struct LoginStart {
    pub username: String,
    pub uuid_bytes: [u8; 16],
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

pub fn parse_login_start(data: &[u8]) -> anyhow::Result<LoginStart> {
    use std::io::Read;
    let mut cursor = std::io::Cursor::new(data);
    let username = read_string_sync(&mut cursor)?;
    let mut uuid_bytes = [0u8; 16];
    cursor.read_exact(&mut uuid_bytes)?;
    Ok(LoginStart { username, uuid_bytes })
}

pub fn encode_handshake(handshake: &Handshake) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&encode_varint(handshake.protocol_version));
    data.extend_from_slice(&encode_string(&handshake.server_address));
    data.extend_from_slice(&handshake.server_port.to_be_bytes());
    data.extend_from_slice(&encode_varint(handshake.next_state));
    data
}

pub fn encode_login_start(login_start: &LoginStart) -> Vec<u8> {
    let mut data = encode_string(&login_start.username);
    data.extend_from_slice(&login_start.uuid_bytes);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_parse_handshake_strips_forge_marker() {
        let data = make_handshake_bytes(769, "forbidden.samlo.cloud\0FML2\0", 25565, 1);
        let hs = parse_handshake(&data).unwrap();
        assert_eq!(hs.server_address, "forbidden.samlo.cloud");
    }

    #[test]
    fn test_parse_login_start() {
        let uuid = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut data = Vec::new();
        data.extend_from_slice(&encode_string("Notch"));
        data.extend_from_slice(&uuid);
        let ls = parse_login_start(&data).unwrap();
        assert_eq!(ls.username, "Notch");
        assert_eq!(ls.uuid_bytes, uuid);
    }

    #[test]
    fn test_login_start_encode_round_trip() {
        let uuid = [0xABu8; 16];
        let original = LoginStart { username: "Steve".to_string(), uuid_bytes: uuid };
        let encoded = encode_login_start(&original);
        let decoded = parse_login_start(&encoded).unwrap();
        assert_eq!(decoded.username, original.username);
        assert_eq!(decoded.uuid_bytes, original.uuid_bytes);
    }

    #[test]
    fn test_handshake_encode_round_trip() {
        let original = Handshake {
            protocol_version: 769,
            server_address: "forbidden.samlo.cloud".to_string(),
            server_port: 25565,
            next_state: 2,
        };
        let encoded = encode_handshake(&original);
        let decoded = parse_handshake(&encoded).unwrap();
        assert_eq!(decoded.protocol_version, original.protocol_version);
        assert_eq!(decoded.server_address, original.server_address);
        assert_eq!(decoded.server_port, original.server_port);
        assert_eq!(decoded.next_state, original.next_state);
    }
}
