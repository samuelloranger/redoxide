use serde::{Deserialize, Serialize};

const CACHE_PATH: &str = ".redoxide-version-cache.json";

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
