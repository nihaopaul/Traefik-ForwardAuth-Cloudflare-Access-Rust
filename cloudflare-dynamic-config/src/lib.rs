use reqwest::{self, header};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::time::{interval, Duration};

const APPS_PER_PAGE: usize = 50;
const MAX_APP_PAGES: usize = 1_000;
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CATALOG_REFRESH_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub aud: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub api: String,
    pub token: String,
    pub duration: u64,
}

#[derive(Debug, Clone, Default)]
struct Catalog {
    auds: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DynamicConfigManager {
    config: Config,
    catalog: Arc<Mutex<Catalog>>,
    client: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct AppsQuery {
    #[serde(rename = "match")]
    match_: &'static str,
    ui_apps: bool,
    page: usize,
    per_page: usize,
}

#[derive(Debug, Deserialize)]
struct AppsResponse {
    #[serde(default)]
    success: bool,
    result: Option<Vec<App>>,
    result_info: Option<ResultInfo>,
}

#[derive(Debug, Deserialize)]
struct ResultInfo {
    total_pages: Option<usize>,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Serde JSON error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Cloudflare returned an unsuccessful applications response")]
    UnsuccessfulResponse,
    #[error("Missing 'result' field in API response")]
    MissingResultError,
    #[error("Cloudflare applications catalog contains no usable audiences")]
    EmptyCatalog,
    #[error("Cloudflare applications response exceeds the {MAX_APP_PAGES}-page safety limit")]
    PaginationLimitExceeded,
    #[error("Cloudflare applications catalog fetch exceeded the 60-second deadline")]
    CatalogFetchTimedOut,
}

impl DynamicConfigManager {
    fn http_client() -> Result<reqwest::Client, ConfigError> {
        Ok(reqwest::Client::builder()
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()?)
    }

    pub async fn new(config: Config) -> Result<Self, ConfigError> {
        let manager = Self {
            config,
            catalog: Arc::new(Mutex::new(Catalog::default())),
            client: Self::http_client()?,
        };

        // Do not open the listener with an empty catalog. A failed initial
        // fetch aborts startup; later failures retain this known-good state.
        manager.refresh_apps().await?;
        manager.clone().start_update_task();

        Ok(manager)
    }

    pub async fn get_aud(&self) -> Vec<String> {
        self.catalog.lock().unwrap().auds.clone()
    }

    fn update_catalog(&self, apps: Vec<App>, pages: usize) -> Result<(), ConfigError> {
        let app_count = apps.len();
        let mut seen = HashSet::new();
        let auds = apps
            .into_iter()
            .filter_map(|app| app.aud)
            .filter(|aud| !aud.is_empty())
            .filter(|aud| seen.insert(aud.clone()))
            .collect::<Vec<_>>();

        if auds.is_empty() {
            return Err(ConfigError::EmptyCatalog);
        }

        eprintln!(
            "event=access_catalog_updated pages={pages} applications={app_count} audiences={}",
            auds.len()
        );
        self.catalog.lock().unwrap().auds = auds;
        Ok(())
    }

    async fn fetch_page(&self, page: usize) -> Result<AppsResponse, ConfigError> {
        // Keep the historical filters until their effect on the accepted AUD
        // set has been measured against a real account.
        let query = AppsQuery {
            match_: "any",
            ui_apps: true,
            page,
            per_page: APPS_PER_PAGE,
        };

        let response = self
            .client
            .get(&self.config.api)
            .query(&query)
            .header(header::CONTENT_TYPE, "application/json")
            .bearer_auth(self.config.token.as_str())
            .send()
            .await?
            .error_for_status()?;

        Ok(response.json().await?)
    }

    async fn fetch_apps(&self) -> Result<(Vec<App>, usize), ConfigError> {
        let mut apps = Vec::new();
        let mut page = 1;

        loop {
            if page > MAX_APP_PAGES {
                return Err(ConfigError::PaginationLimitExceeded);
            }

            let response = self.fetch_page(page).await?;
            if !response.success {
                return Err(ConfigError::UnsuccessfulResponse);
            }

            let page_apps = response.result.ok_or(ConfigError::MissingResultError)?;
            let page_was_full = page_apps.len() == APPS_PER_PAGE;
            apps.extend(page_apps);

            let total_pages = response.result_info.and_then(|info| info.total_pages);
            if total_pages.is_some_and(|total_pages| total_pages > MAX_APP_PAGES) {
                return Err(ConfigError::PaginationLimitExceeded);
            }

            let has_another_page = match total_pages {
                Some(total_pages) => page < total_pages,
                None => page_was_full,
            };
            if !has_another_page {
                return Ok((apps, page));
            }
            page += 1;
        }
    }

    async fn refresh_apps(&self) -> Result<(), ConfigError> {
        let (apps, pages) = tokio::time::timeout(CATALOG_REFRESH_TIMEOUT, self.fetch_apps())
            .await
            .map_err(|_| ConfigError::CatalogFetchTimedOut)??;
        // Publish only after every page succeeds, so a partial refresh can
        // never replace a previously complete catalog.
        self.update_catalog(apps, pages)
    }

    fn start_update_task(self) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(self.config.duration));
            // The initial refresh was synchronous. Consume interval's immediate
            // first tick so the next request happens after the configured delay.
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(error) = self.refresh_apps().await {
                    eprintln!("event=catalog_refresh_failed error={error}");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(server: &mockito::ServerGuard) -> Config {
        Config {
            api: format!(
                "{}/client/v4/accounts/test-account/access/apps",
                server.url()
            ),
            token: "test-token".into(),
            duration: 60 * 60,
        }
    }

    fn page_query(page: usize) -> mockito::Matcher {
        mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("match".into(), "any".into()),
            mockito::Matcher::UrlEncoded("ui_apps".into(), "true".into()),
            mockito::Matcher::UrlEncoded("page".into(), page.to_string()),
            mockito::Matcher::UrlEncoded("per_page".into(), APPS_PER_PAGE.to_string()),
        ])
    }

    fn response(apps: serde_json::Value, total_pages: usize) -> String {
        json!({
            "success": true,
            "result": apps,
            "result_info": { "total_pages": total_pages }
        })
        .to_string()
    }

    #[tokio::test]
    async fn initial_fetch_is_complete_before_new_returns() {
        let mut server = mockito::Server::new_async().await;
        let request = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(page_query(1))
            .with_header("content-type", "application/json")
            .with_body(response(
                json!([{ "aud": "test-app-1" }, { "aud": "test-app-2" }]),
                1,
            ))
            .expect(1)
            .create_async()
            .await;

        let manager = DynamicConfigManager::new(config(&server))
            .await
            .expect("create manager");

        assert_eq!(manager.get_aud().await, vec!["test-app-1", "test-app-2"]);
        request.assert_async().await;
    }

    #[tokio::test]
    async fn fetches_every_page_and_deduplicates_audiences() {
        let mut server = mockito::Server::new_async().await;
        let first = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(page_query(1))
            .with_body(response(
                json!([{ "aud": "app-a" }, { "aud": null }, { "aud": "" }]),
                2,
            ))
            .create_async()
            .await;
        let second = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(page_query(2))
            .with_body(response(json!([{ "aud": "app-b" }, { "aud": "app-a" }]), 2))
            .create_async()
            .await;

        let manager = DynamicConfigManager::new(config(&server))
            .await
            .expect("create manager");

        assert_eq!(manager.get_aud().await, vec!["app-a", "app-b"]);
        first.assert_async().await;
        second.assert_async().await;
    }

    #[tokio::test]
    async fn a_partial_refresh_keeps_the_last_complete_catalog() {
        let mut server = mockito::Server::new_async().await;
        let manager = DynamicConfigManager {
            config: config(&server),
            catalog: Arc::new(Mutex::new(Catalog {
                auds: vec!["known-good".into()],
            })),
            client: DynamicConfigManager::http_client().expect("build test HTTP client"),
        };

        let first = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(page_query(1))
            .with_body(response(json!([{ "aud": "partial" }]), 2))
            .create_async()
            .await;
        let second = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(page_query(2))
            .with_status(503)
            .create_async()
            .await;

        manager
            .refresh_apps()
            .await
            .expect_err("a failed later page must fail the refresh");

        assert_eq!(manager.get_aud().await, vec!["known-good"]);
        first.assert_async().await;
        second.assert_async().await;
    }

    #[tokio::test]
    async fn initial_fetch_failure_prevents_startup() {
        let mut server = mockito::Server::new_async().await;
        let request = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(page_query(1))
            .with_status(503)
            .create_async()
            .await;

        DynamicConfigManager::new(config(&server))
            .await
            .expect_err("startup must fail without an initial catalog");
        request.assert_async().await;
    }

    #[tokio::test]
    async fn an_empty_catalog_prevents_startup() {
        let mut server = mockito::Server::new_async().await;
        let request = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(page_query(1))
            .with_body(response(json!([]), 1))
            .create_async()
            .await;

        let error = DynamicConfigManager::new(config(&server))
            .await
            .expect_err("startup must fail without any application audiences");

        assert!(matches!(error, ConfigError::EmptyCatalog));
        request.assert_async().await;
    }

    #[tokio::test]
    async fn an_empty_refresh_keeps_the_last_complete_catalog() {
        let mut server = mockito::Server::new_async().await;
        let manager = DynamicConfigManager {
            config: config(&server),
            catalog: Arc::new(Mutex::new(Catalog {
                auds: vec!["known-good".into()],
            })),
            client: DynamicConfigManager::http_client().expect("build test HTTP client"),
        };
        let request = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(page_query(1))
            .with_body(response(json!([]), 1))
            .create_async()
            .await;

        let error = manager
            .refresh_apps()
            .await
            .expect_err("an empty refresh must not replace known-good state");

        assert!(matches!(error, ConfigError::EmptyCatalog));
        assert_eq!(manager.get_aud().await, vec!["known-good"]);
        request.assert_async().await;
    }

    #[tokio::test]
    async fn rejects_an_unbounded_reported_page_count() {
        let mut server = mockito::Server::new_async().await;
        let request = server
            .mock("GET", "/client/v4/accounts/test-account/access/apps")
            .match_query(page_query(1))
            .with_body(response(json!([{ "aud": "app-a" }]), MAX_APP_PAGES + 1))
            .expect(1)
            .create_async()
            .await;

        let error = DynamicConfigManager::new(config(&server))
            .await
            .expect_err("an unreasonable page count must fail fast");

        assert!(matches!(error, ConfigError::PaginationLimitExceeded));
        request.assert_async().await;
    }
}
