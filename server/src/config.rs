use crate::logger::{warn, log};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) mount: Option<String>,
    pub(crate) can_unauthenticated_cache: Option<bool>,
    pub(crate) max_cache_entry_size: Option<u64>,
    pub(crate) total_max_cache: Option<u64>,
    pub(crate) default_use_cache: Option<bool>,
    pub(crate) remove_not_found_files: Option<bool>,
    pub(crate) allow_query_override_default: Option<bool>,
    pub(crate) allow_query_override_db: Option<bool>,
    pub(crate) remote_allow_local: Option<bool>,
}

impl Config {
    pub fn host(&self) -> &str {
        self.host.as_deref().unwrap_or("127.0.0.1")
    }

    pub fn port(&self) -> u16 {
        self.port.unwrap_or(8080)
    }

    pub fn mount(&self) -> &str {
        self.mount.as_deref().unwrap_or("./data/")
    }

    pub fn can_unauthenticated_cache(&self) -> bool {
        self.can_unauthenticated_cache.unwrap_or(true)
    }

    pub fn max_cache_entry_size(&self) -> u64 {
        self.max_cache_entry_size.unwrap_or(104_857_600)
    }

    pub fn total_max_cache(&self) -> u64 {
        self.total_max_cache.unwrap_or(1_073_741_824)
    }

    pub fn default_use_cache(&self) -> bool {
        self.default_use_cache.unwrap_or(true)
    }

    pub fn remove_not_found_files(&self) -> bool {
        self.remove_not_found_files.unwrap_or(false)
    }

    pub fn allow_query_override_default(&self) -> bool {
        self.allow_query_override_default.unwrap_or(true)
    }

    pub fn allow_query_override_db(&self) -> bool {
        self.allow_query_override_db.unwrap_or(true)
    }

    pub fn remote_allow_local(&self) -> bool {
        self.remote_allow_local.unwrap_or(false)
    }

    pub fn defaulted() -> Self {
        Config {
            host: Some("127.0.0.1".to_string()),
            port: Some(8080),
            mount: Some("./data/".to_string()),
            can_unauthenticated_cache: Some(true),
            max_cache_entry_size: Some(104_857_600),
            total_max_cache: Some(1_073_741_824),
            default_use_cache: Some(true),
            remove_not_found_files: Some(false),
            allow_query_override_default: Some(true),
            allow_query_override_db: Some(true),
            remote_allow_local: Some(false),
        }
    }
}

async fn internal_read_config() -> Result<Config, Box<dyn std::error::Error>> {
    let config_path = Path::new("config.toml");
    if !config_path.exists() {
        log("Config file not found, creating default config.toml...");
        let default_config = Config::defaulted();
        let toml_string = toml::to_string_pretty(&default_config)?;
        tokio::fs::write(config_path, toml_string).await?;
    }
    let config_data = tokio::fs::read_to_string(config_path).await?;
    let config: Config = toml::from_str(&config_data)?;
    Ok(config)
}

pub async fn config() -> Config {
    internal_read_config().await.unwrap_or_else(|e| {
        warn(format!("Failed to load config, using defaults: {}", e).as_str());
        Config::defaulted()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_cover_all_optional_fields() {
        let config = Config {
            host: None,
            port: None,
            mount: None,
            can_unauthenticated_cache: None,
            max_cache_entry_size: None,
            total_max_cache: None,
            default_use_cache: None,
            remove_not_found_files: None,
            allow_query_override_default: None,
            allow_query_override_db: None,
            remote_allow_local: None,
        };

        assert_eq!(config.host(), "127.0.0.1");
        assert_eq!(config.port(), 8080);
        assert_eq!(config.mount(), "./data/");
        assert!(config.can_unauthenticated_cache());
        assert_eq!(config.max_cache_entry_size(), 104_857_600);
        assert_eq!(config.total_max_cache(), 1_073_741_824);
        assert!(config.default_use_cache());
        assert!(!config.remove_not_found_files());
        assert!(config.allow_query_override_default());
        assert!(config.allow_query_override_db());
        assert!(!config.remote_allow_local());
    }
}
