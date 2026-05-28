use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub target: TargetConfig,
    pub docker: DockerConfig,
    pub status: StatusConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub bind: String,
    pub server_address: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TargetConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DockerConfig {
    pub container_name: String,
    pub startup_timeout_secs: u64,
    pub idle_shutdown_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StatusConfig {
    pub protocol_version: i32,
    pub max_players: i32,
    pub online_motd: String,
    pub version_name: String,
    /// Optional path to server.properties — if set, overrides max_players and version_name
    #[serde(default)]
    pub server_properties: Option<String>,
}

pub fn load(path: &str) -> anyhow::Result<Config> {
    let contents = std::fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&contents)?;
    if let Some(ref props_path) = config.status.server_properties.clone() {
        apply_server_properties(&mut config, props_path);
    }
    Ok(config)
}

fn apply_server_properties(config: &mut Config, path: &str) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        tracing::warn!("Could not read server.properties at {path}");
        return;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "max-players" => {
                    if let Ok(n) = value.trim().parse::<i32>() {
                        tracing::info!("server.properties: max-players={n}");
                        config.status.max_players = n;
                    }
                }
                "motd" => {
                    let motd = value.trim().to_string();
                    tracing::info!("server.properties: motd={motd}");
                    config.status.online_motd = motd;
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_example_config() {
        let config = load("config.example.toml").unwrap();
        assert_eq!(config.proxy.server_address, "forbidden.samlo.cloud");
        assert_eq!(config.target.port, 25565);
        assert_eq!(config.docker.startup_timeout_secs, 120);
        assert_eq!(config.docker.idle_shutdown_secs, 600);
        assert_eq!(config.status.protocol_version, 769);
    }
}
