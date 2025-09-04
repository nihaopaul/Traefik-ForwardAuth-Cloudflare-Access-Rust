use reqwest::{self, header};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::time::{interval, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub aud: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub api: String,
    pub token: String,
    pub duration: u64,
}

#[derive(Debug, Clone)]
pub struct DynamicConfigManager {
    config: Config,
    apps: Arc<Mutex<Vec<App>>>, // Use Arc and Mutex for shared access
    client: reqwest::Client,
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

impl DynamicConfigManager {
    pub async fn new(config: Config) -> Result<Self, ConfigError> {
        let manager = Self {
            config,
            apps: Arc::new(Mutex::new(Vec::new())),
            client: reqwest::Client::new(),
        };

        // Start the background task to update apps periodically
        manager.clone().start_update_task();

        Ok(manager)
    }

    pub async fn get_aud(&self) -> Vec<String> {
        let apps = self.apps.lock().unwrap();
        apps.iter().map(|app| app.aud.clone()).collect()
    }

    fn update_apps(&self, new_apps: Vec<App>) {
        println!("Updating apps: {:?}", new_apps);
        let mut apps = self.apps.lock().unwrap();
        *apps = new_apps;
    }

    async fn fetch_apps(&self) -> Result<(), ConfigError> {
        let query_params = [("match", "any"), ("ui_apps", "true")];

        let response = self
            .client
            .get(&format!(
                "{}?{}",
                self.config.api.clone(),
                serde_urlencoded::to_string(&query_params)?
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .bearer_auth(&self.config.token.clone())
            .send()
            .await?;

        let response_body: serde_json::Value = response.json().await?;

        if let Some(result) = response_body.get("result") {
            if let Ok(apps) = serde_json::from_value::<Vec<App>>(result.clone()) {
                self.update_apps(apps);
                Ok(())
            } else {
                Err(ConfigError::JsonParseError(
                    "Error parsing JSON response".into(),
                ))
            }
        } else {
            Err(ConfigError::MissingResultError)
        }
    }

    // Background task to periodically update apps
    fn start_update_task(self) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(self.config.duration));
            loop {
                interval.tick().await;
                if let Err(e) = self.fetch_apps().await {
                    eprintln!("Error updating apps: {}", e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito;
    use serde_json::json;

    #[tokio::test] // Use tokio for async testing
    async fn test_fetch_apps_success() {
        let mut server = mockito::Server::new_async().await;
        let mock_url = format!(
            "{}/client/v4/accounts/test-account/access/apps",
            server.url()
        );

        let mock = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(mockito::Matcher::UrlEncoded("match".into(), "any".into()))
            .match_query(mockito::Matcher::UrlEncoded(
                "ui_apps".into(),
                "true".into(),
            ))
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                  "success": true,
                  "result": [
                    {"aud": "test-app-1"},
                    {"aud": "test-app-2"}
                  ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let config = Config {
            api: mock_url.clone(),
            token: "test-token".into(),
            duration: 60 * 60,
        };

        // Create and initialize the manager using new()
        let manager = match DynamicConfigManager::new(config).await {
            Ok(manager) => manager,
            Err(e) => panic!("Failed to create DynamicConfigManager: {}", e),
        };

        // wait for the background task to fetch and update the apps
        tokio::time::sleep(Duration::from_secs(1)).await;

        let apps = manager.get_aud().await;

        assert_eq!(apps, vec!["test-app-1", "test-app-2"]);
        mock.assert();
    }
}
