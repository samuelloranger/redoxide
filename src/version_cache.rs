use serde::{Deserialize, Serialize};

const CACHE_DIR: &str = "/var/cache/redoxide";
const CACHE_PATH: &str = "/var/cache/redoxide/version.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionCache {
    pub protocol: i32,
    pub version: String,
}

pub fn load() -> Option<VersionCache> {
    let data = std::fs::read_to_string(CACHE_PATH).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn save(protocol: i32, version: &str) {
    if let Err(e) = std::fs::create_dir_all(CACHE_DIR) {
        tracing::warn!("Could not create cache directory: {e}");
        return;
    }
    let cache = VersionCache { protocol, version: version.to_string() };
    match serde_json::to_string_pretty(&cache) {
        Ok(json) => {
            if let Err(e) = std::fs::write(CACHE_PATH, json) {
                tracing::warn!("Could not save version cache: {e}");
            }
        }
        Err(e) => tracing::warn!("Could not serialize version cache: {e}"),
    }
}
