use cloudflare_authenticator as cfa;
use cloudflare_dynamic_config as cdc;
use local_ip_address::local_ip;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use tower_cookies::{CookieManagerLayer, Cookies};

#[derive(Clone)]
struct AppState<A = cfa::Authenticator, C = cdc::DynamicConfigManager> {
    authenticator: A,
    configurator: C,
    denial_logger: DenialLogger,
}

trait TokenAuthenticator: Clone + Send + Sync + 'static {
    async fn validate(&self, token: &str, auds: Vec<String>) -> Result<(), &'static str>;
}

impl TokenAuthenticator for cfa::Authenticator {
    async fn validate(&self, token: &str, auds: Vec<String>) -> Result<(), &'static str> {
        self.test(token, auds)
            .await
            .map_err(|error| error.reason_code())
    }
}

trait AudienceCatalog: Clone + Send + Sync + 'static {
    async fn audiences(&self) -> Vec<String>;
}

impl AudienceCatalog for cdc::DynamicConfigManager {
    async fn audiences(&self) -> Vec<String> {
        self.get_aud().await
    }
}

const MISSING_TOKEN: &str = "missing_token";
const MALFORMED_TOKEN: &str = "malformed_token";
const CATALOG_EMPTY: &str = "catalog_empty";
const DENIAL_LOG_LIMIT: u32 = 10;
const DENIAL_LOG_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenSource {
    AssertionHeader,
    Cookie,
}

impl TokenSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::AssertionHeader => "assertion_header",
            Self::Cookie => "cookie",
        }
    }
}

#[derive(Debug)]
struct LogWindow {
    started_at: Instant,
    emitted: u32,
    suppressed: u64,
}

#[derive(Clone, Debug, Default)]
struct DenialLogger {
    windows: Arc<Mutex<HashMap<&'static str, LogWindow>>>,
}

#[derive(Debug, Eq, PartialEq)]
enum LogDecision {
    Detailed,
    Suppressed,
    SummaryAndDetailed { suppressed: u64 },
}

impl DenialLogger {
    fn decision_at(&self, reason: &'static str, now: Instant) -> LogDecision {
        use std::collections::hash_map::Entry;

        let mut windows = self.windows.lock().unwrap();
        match windows.entry(reason) {
            Entry::Vacant(entry) => {
                entry.insert(LogWindow {
                    started_at: now,
                    emitted: 1,
                    suppressed: 0,
                });
                LogDecision::Detailed
            }
            Entry::Occupied(mut entry) => {
                let window = entry.get_mut();
                if now.duration_since(window.started_at) >= DENIAL_LOG_WINDOW {
                    let suppressed = window.suppressed;
                    *window = LogWindow {
                        started_at: now,
                        emitted: 1,
                        suppressed: 0,
                    };
                    if suppressed == 0 {
                        LogDecision::Detailed
                    } else {
                        LogDecision::SummaryAndDetailed { suppressed }
                    }
                } else if window.emitted < DENIAL_LOG_LIMIT {
                    window.emitted += 1;
                    LogDecision::Detailed
                } else {
                    window.suppressed += 1;
                    LogDecision::Suppressed
                }
            }
        }
    }

    fn record(&self, reason: &'static str, token_source: Option<TokenSource>) {
        let source = token_source.map_or("none", TokenSource::as_str);
        match self.decision_at(reason, Instant::now()) {
            LogDecision::Detailed => {
                eprintln!("event=auth_denied reason={reason} token_source={source}");
            }
            LogDecision::Suppressed => {}
            LogDecision::SummaryAndDetailed { suppressed } => {
                eprintln!("event=auth_denied_suppressed reason={reason} count={suppressed}");
                eprintln!("event=auth_denied reason={reason} token_source={source}");
            }
        }
    }

    fn flush_expired_at(&self, now: Instant) -> Vec<(&'static str, u64)> {
        let mut windows = self.windows.lock().unwrap();
        let mut summaries = Vec::new();

        windows.retain(|reason, window| {
            if now.duration_since(window.started_at) < DENIAL_LOG_WINDOW {
                return true;
            }

            if window.suppressed > 0 {
                summaries.push((*reason, window.suppressed));
            }
            false
        });

        summaries
    }

    fn flush_expired(&self) {
        for (reason, suppressed) in self.flush_expired_at(Instant::now()) {
            eprintln!("event=auth_denied_suppressed reason={reason} count={suppressed}");
        }
    }

    fn start_flush_task(self) {
        tokio::spawn(async move {
            let mut flush_interval = tokio::time::interval(DENIAL_LOG_WINDOW);
            // Tokio intervals tick immediately. The first useful flush is one
            // complete rate-limit window after startup.
            flush_interval.tick().await;
            loop {
                flush_interval.tick().await;
                self.flush_expired();
            }
        });
    }
}

fn select_token(
    headers: &HeaderMap,
    cookie: Option<&str>,
) -> Result<(String, TokenSource), (&'static str, Option<TokenSource>)> {
    let mut assertion_headers = headers.get_all("Cf-Access-Jwt-Assertion").iter();
    if let Some(value) = assertion_headers.next() {
        if assertion_headers.next().is_some() {
            return Err((MALFORMED_TOKEN, Some(TokenSource::AssertionHeader)));
        }
        let value = value
            .to_str()
            .map_err(|_| (MALFORMED_TOKEN, Some(TokenSource::AssertionHeader)))?;
        if value.trim().is_empty() {
            return Err((MALFORMED_TOKEN, Some(TokenSource::AssertionHeader)));
        }
        return Ok((value.to_string(), TokenSource::AssertionHeader));
    }

    match cookie {
        Some(value) if !value.trim().is_empty() => Ok((value.to_string(), TokenSource::Cookie)),
        Some(_) => Err((MALFORMED_TOKEN, Some(TokenSource::Cookie))),
        None => Err((MISSING_TOKEN, None)),
    }
}

async fn handler<A, C>(
    State(state): State<AppState<A, C>>,
    cookies: Cookies,
    req: Request,
) -> impl IntoResponse
where
    A: TokenAuthenticator,
    C: AudienceCatalog,
{
    let cookie = cookies
        .get("CF_Authorization")
        .map(|cookie| cookie.value().to_string());
    let (token, token_source) = match select_token(req.headers(), cookie.as_deref()) {
        Ok(token) => token,
        Err((reason, source)) => {
            state.denial_logger.record(reason, source);
            return StatusCode::FORBIDDEN;
        }
    };

    let auds = state.configurator.audiences().await;
    if auds.is_empty() {
        state
            .denial_logger
            .record(CATALOG_EMPTY, Some(token_source));
        return StatusCode::FORBIDDEN;
    }

    match state.authenticator.validate(&token, auds).await {
        Ok(_) => StatusCode::OK,
        Err(reason) => {
            state.denial_logger.record(reason, Some(token_source));
            StatusCode::FORBIDDEN
        }
    }
}

#[tokio::main]
async fn main() {
    let local_ip = local_ip().unwrap();
    eprintln!("event=server_starting ip={local_ip}");

    let port = env::var("PORT").unwrap_or("3000".to_string());
    let authenticator = start_authenticator_service().await;
    let configurator = start_dynamic_config_manager().await;
    let denial_logger = DenialLogger::default();
    denial_logger.clone().start_flush_task();
    let app_state = AppState {
        authenticator,
        configurator,
        denial_logger,
    };

    let app = Router::new()
        .route(
            "/auth",
            get(handler::<cfa::Authenticator, cdc::DynamicConfigManager>),
        )
        .layer(CookieManagerLayer::new())
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn start_dynamic_config_manager() -> cdc::DynamicConfigManager {
    let account_id = env::var("CF_ORG").expect("CF_ORG must be set");
    let token = env::var("CF_TOKEN").expect("CF_TOKEN must be set");

    let api = format!(
        "{}/client/v4/accounts/{}/access/apps",
        "https://api.cloudflare.com", account_id
    );
    let config = cdc::Config {
        api,
        token,
        duration: 60 * 60,
    };

    match cdc::DynamicConfigManager::new(config).await {
        Ok(manager) => manager,
        Err(error) => {
            eprintln!("event=catalog_initialization_failed error={error}");
            std::process::exit(1);
        }
    }
}

async fn start_authenticator_service() -> cfa::Authenticator {
    let api = env::var("CF_DOMAIN").expect("CF_DOMAIN must be set");
    let config = cfa::Config {
        api,
        duration: 60 * 60 * 24,
    };

    match cfa::Authenticator::new(config).await {
        Ok(manager) => manager,
        Err(error) => {
            eprintln!("event=jwks_initialization_failed error={error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderValue, Request as HttpRequest};
    use tower::ServiceExt;

    #[derive(Clone)]
    struct FakeAuthenticator {
        denial_reason: Option<&'static str>,
    }

    impl TokenAuthenticator for FakeAuthenticator {
        async fn validate(&self, _token: &str, _auds: Vec<String>) -> Result<(), &'static str> {
            match self.denial_reason {
                Some(reason) => Err(reason),
                None => Ok(()),
            }
        }
    }

    #[derive(Clone)]
    struct FakeCatalog(Vec<String>);

    impl AudienceCatalog for FakeCatalog {
        async fn audiences(&self) -> Vec<String> {
            self.0.clone()
        }
    }

    fn test_app(
        audiences: Vec<String>,
        denial_reason: Option<&'static str>,
    ) -> (Router, DenialLogger) {
        let denial_logger = DenialLogger::default();
        let state = AppState {
            authenticator: FakeAuthenticator { denial_reason },
            configurator: FakeCatalog(audiences),
            denial_logger: denial_logger.clone(),
        };
        let app = Router::new()
            .route("/auth", get(handler::<FakeAuthenticator, FakeCatalog>))
            .layer(CookieManagerLayer::new())
            .with_state(state);

        (app, denial_logger)
    }

    fn assertion_request() -> HttpRequest<Body> {
        HttpRequest::builder()
            .uri("/auth")
            .header("Cf-Access-Jwt-Assertion", "signed-token")
            .body(Body::empty())
            .expect("build request")
    }

    #[test]
    fn assertion_header_is_preferred_over_the_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Cf-Access-Jwt-Assertion",
            HeaderValue::from_static("header-token"),
        );

        assert_eq!(
            select_token(&headers, Some("cookie-token")),
            Ok(("header-token".into(), TokenSource::AssertionHeader))
        );
    }

    #[test]
    fn cookie_is_used_only_when_the_assertion_header_is_absent() {
        assert_eq!(
            select_token(&HeaderMap::new(), Some("cookie-token")),
            Ok(("cookie-token".into(), TokenSource::Cookie))
        );
    }

    #[test]
    fn malformed_assertion_header_does_not_fall_back_to_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Cf-Access-Jwt-Assertion",
            HeaderValue::from_bytes(&[0xff]).expect("header bytes are accepted"),
        );

        assert_eq!(
            select_token(&headers, Some("valid-cookie")),
            Err((MALFORMED_TOKEN, Some(TokenSource::AssertionHeader)))
        );
    }

    #[test]
    fn duplicate_assertion_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            "Cf-Access-Jwt-Assertion",
            HeaderValue::from_static("first-token"),
        );
        headers.append(
            "Cf-Access-Jwt-Assertion",
            HeaderValue::from_static("second-token"),
        );

        assert_eq!(
            select_token(&headers, Some("valid-cookie")),
            Err((MALFORMED_TOKEN, Some(TokenSource::AssertionHeader)))
        );
    }

    #[test]
    fn missing_credentials_are_distinguishable() {
        assert_eq!(
            select_token(&HeaderMap::new(), None),
            Err((MISSING_TOKEN, None))
        );
    }

    #[test]
    fn denial_logs_are_limited_and_report_suppression() {
        let logger = DenialLogger::default();
        let start = Instant::now();

        for _ in 0..DENIAL_LOG_LIMIT {
            assert_eq!(
                logger.decision_at(MALFORMED_TOKEN, start),
                LogDecision::Detailed
            );
        }
        assert_eq!(
            logger.decision_at(MALFORMED_TOKEN, start),
            LogDecision::Suppressed
        );
        assert_eq!(
            logger.decision_at(MALFORMED_TOKEN, start + DENIAL_LOG_WINDOW),
            LogDecision::SummaryAndDetailed { suppressed: 1 }
        );
    }

    #[test]
    fn expired_log_windows_flush_suppression_without_another_denial() {
        let logger = DenialLogger::default();
        let start = Instant::now();

        for _ in 0..DENIAL_LOG_LIMIT {
            assert_eq!(
                logger.decision_at(MALFORMED_TOKEN, start),
                LogDecision::Detailed
            );
        }
        for _ in 0..9_990 {
            assert_eq!(
                logger.decision_at(MALFORMED_TOKEN, start),
                LogDecision::Suppressed
            );
        }

        assert!(logger
            .flush_expired_at(start + DENIAL_LOG_WINDOW - Duration::from_millis(1))
            .is_empty());
        assert_eq!(
            logger.flush_expired_at(start + DENIAL_LOG_WINDOW),
            vec![(MALFORMED_TOKEN, 9_990)]
        );
        assert!(logger
            .flush_expired_at(start + DENIAL_LOG_WINDOW)
            .is_empty());
    }

    #[tokio::test]
    async fn handler_rejects_an_empty_catalog_with_a_generic_forbidden_response() {
        let (app, logger) = test_app(vec![], None);

        let response = app
            .oneshot(assertion_request())
            .await
            .expect("handler responds");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body")
            .is_empty());

        let windows = logger.windows.lock().unwrap();
        assert_eq!(
            windows.get(CATALOG_EMPTY).map(|window| window.emitted),
            Some(1)
        );
    }

    #[tokio::test]
    async fn handler_does_not_expose_internal_denial_reasons_to_clients() {
        let (app, logger) = test_app(vec!["app-a".into()], Some("invalid_issuer"));

        let response = app
            .oneshot(assertion_request())
            .await
            .expect("handler responds");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body")
            .is_empty());

        let windows = logger.windows.lock().unwrap();
        assert_eq!(
            windows.get("invalid_issuer").map(|window| window.emitted),
            Some(1)
        );
    }
}
