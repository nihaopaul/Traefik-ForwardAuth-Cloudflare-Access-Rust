use reqwest::{self, header};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::time::{interval, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certs {
    pub keys: <Vec<Keys>>,
    pub public_cert: PublicCert,
    pub public_certs: <Vec<PublicCert>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keys {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    pub use_: String,
    pub e: String,
    pub n: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCert {
    pub kid: String,
    pub cert: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub api: String,
    pub domain: String,
    pub duration: u64,
}

#[derive(Debug, Clone)]
pub struct DynamicConfigManager {
    config: Config,
    apps: Arc<Mutex<Vec<Certs>>>, // Use Arc and Mutex for shared access
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Serde URL encoding error: {0}")]
    SerdeUrlencodedError(#[from] serde_urlencoded::ser::Error),
    #[error("Serde JSON error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Error parsing JSON response: {0}")]
    JsonParseError(String),
    #[error("Missing 'result' field in API response")]
    MissingResultError,
}
