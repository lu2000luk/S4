use std::path::Path;
use serde::{Serialize, Deserialize};
use crate::logger::{warn};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) mount: Option<String>,
}

async fn internal_read_config() -> Result<Config, Box<dyn std::error::Error>> {
    let config_data = tokio::fs::read_to_string(Path::new("config.toml")).await?;
    let config: Config = toml::from_str(&config_data)?;
    Ok(config)
}

pub async fn config() -> Config {
    internal_read_config().await.unwrap_or_else(|e| {
        warn(format!("Failed to read config.toml: {}", e).as_str());
        Config {
            host: Some("127.0.0.1".to_string()),
            port: Some(8080),
            mount: Some("./data/".to_string()),
        }
    })
}


