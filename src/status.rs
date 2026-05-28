use crate::config::StatusConfig;
use crate::protocol::packet::{encode_packet, encode_string};
use crate::protocol::varint::encode_varint;

pub fn build_status_json(motd: &str, cfg: &StatusConfig, online_players: i32) -> String {
    serde_json::json!({
        "version": {
            "name": cfg.version_name,
            "protocol": cfg.protocol_version,
        },
        "players": {
            "max": cfg.max_players,
            "online": online_players,
            "sample": [],
        },
        "description": {
            "text": motd,
        },
    })
    .to_string()
}

pub fn encode_status_response(motd: &str, cfg: &StatusConfig, online: i32) -> Vec<u8> {
    let json = build_status_json(motd, cfg, online);
    encode_packet(0x00, &encode_string(&json))
}

pub fn encode_login_disconnect(reason: &str) -> Vec<u8> {
    let json = serde_json::json!({ "text": reason }).to_string();
    encode_packet(0x00, &encode_string(&json))
}

pub fn encode_login_plugin_request(message_id: i32, channel: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_varint(message_id));
    payload.extend_from_slice(&encode_string(channel));
    encode_packet(0x04, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> StatusConfig {
        StatusConfig {
            protocol_version: 769,
            max_players: 20,
            offline_motd: "Offline".to_string(),
            online_motd: "Online".to_string(),
            version_name: "1.21.4".to_string(),
        }
    }

    #[test]
    fn test_status_json_is_valid() {
        let json = build_status_json("Hello world", &test_cfg(), 0);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"]["protocol"], 769);
        assert_eq!(parsed["players"]["max"], 20);
        assert_eq!(parsed["description"]["text"], "Hello world");
    }

    #[test]
    fn test_login_disconnect_json() {
        let encoded = encode_login_disconnect("Server offline");
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_login_plugin_request_packet_id() {
        let encoded = encode_login_plugin_request(1, "redoxide:keepalive");
        assert!(encoded.len() > 2);
    }
}
