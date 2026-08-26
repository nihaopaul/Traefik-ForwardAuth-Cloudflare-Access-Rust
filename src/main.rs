use cloudflare_authenticator as cfa;
use cloudflare_dynamic_config as cdc;
use local_ip_address::local_ip;
use std::collections::HashMap;
use std::collections::HashSet;
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
    configurator: Option<C>,
    authorization_mode: AuthorizationMode,
    denial_logger: DenialLogger,
}

trait TokenAuthenticator: Clone + Send + Sync + 'static {
    fn validate(
        &self,
        token: &str,
        auds: Arc<HashSet<String>>,
    ) -> impl std::future::Future<Output = Result<(), &'static str>> + Send;
}

impl TokenAuthenticator for cfa::Authenticator {
    async fn validate(&self, token: &str, auds: Arc<HashSet<String>>) -> Result<(), &'static str> {
        self.test(token, &auds)
            .await
            .map_err(|error| error.reason_code())
    }
}

trait AudienceCatalog: Clone + Send + Sync + 'static {
    fn audiences(&self) -> impl std::future::Future<Output = Arc<HashSet<String>>> + Send;
}

impl AudienceCatalog for cdc::DynamicConfigManager {
    async fn audiences(&self) -> Arc<HashSet<String>> {
        self.get_aud().await
    }
}

const MISSING_TOKEN: &str = "missing_token";
const MALFORMED_TOKEN: &str = "malformed_token";
const CATALOG_EMPTY: &str = "catalog_empty";
const MISSING_AUDIENCE_OVERRIDE: &str = "missing_audience_override";
const INVALID_AUDIENCE_OVERRIDE: &str = "invalid_audience_override";
const AUTH_AUDIENCE_HEADER: &str = "X-Auth-Audience";
const MAX_AUDIENCE_OVERRIDE_LENGTH: usize = 256;
const DENIAL_LOG_LIMIT: u32 = 10;
const DENIAL_LOG_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum AuthorizationMode {
    #[default]
    AnyApp,
    PerApp,
}

impl AuthorizationMode {
    fn parse(value: Option<&str>) -> Result<Self, StartupConfigError> {
        match value {
            None | Some("any_app") => Ok(Self::AnyApp),
            Some("per_app") => Ok(Self::PerApp),
            Some(_) => Err(StartupConfigError::InvalidAuthorizationMode),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::AnyApp => "any_app",
            Self::PerApp => "per_app",
        }
    }
}

#[derive(Debug)]
struct CatalogCredentials {
    account_id: String,
    token: String,
}

#[derive(Debug)]
struct StartupConfig {
    port: String,
    domain: String,
    authorization_mode: AuthorizationMode,
    catalog_credentials: Option<CatalogCredentials>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
enum StartupConfigError {
    #[error("{0} must be set")]
    MissingVariable(&'static str),
    #[error("{0} must contain valid Unicode")]
    NonUnicodeVariable(&'static str),
    #[error("CF_AUTHORIZATION_MODE must be any_app or per_app")]
    InvalidAuthorizationMode,
}

impl StartupConfig {
    fn from_env() -> Result<Self, StartupConfigError> {
        Self::from_reader(|name| env::var(name))
    }

    fn from_reader<F>(mut read: F) -> Result<Self, StartupConfigError>
    where
        F: FnMut(&str) -> Result<String, env::VarError>,
    {
        fn required<F>(read: &mut F, name: &'static str) -> Result<String, StartupConfigError>
        where
            F: FnMut(&str) -> Result<String, env::VarError>,
        {
            match read(name) {
                Ok(value) => Ok(value),
                Err(env::VarError::NotPresent) => Err(StartupConfigError::MissingVariable(name)),
                Err(env::VarError::NotUnicode(_)) => {
                    Err(StartupConfigError::NonUnicodeVariable(name))
                }
            }
        }

        let mode_value = match read("CF_AUTHORIZATION_MODE") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(StartupConfigError::NonUnicodeVariable(
                    "CF_AUTHORIZATION_MODE",
                ));
            }
        };
        let authorization_mode = AuthorizationMode::parse(mode_value.as_deref())?;
        let domain = required(&mut read, "CF_DOMAIN")?;
        let port = match read("PORT") {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => "3000".to_string(),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(StartupConfigError::NonUnicodeVariable("PORT"));
            }
        };
        let catalog_credentials = match authorization_mode {
            AuthorizationMode::AnyApp => Some(CatalogCredentials {
                account_id: required(&mut read, "CF_ORG")?,
                token: required(&mut read, "CF_TOKEN")?,
            }),
            AuthorizationMode::PerApp => None,
        };

        Ok(Self {
            port,
            domain,
            authorization_mode,
            catalog_credentials,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
enum AudienceSelection {
    Catalog,
    Bound(String),
}

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

fn select_audience(
    headers: &HeaderMap,
    mode: AuthorizationMode,
) -> Result<AudienceSelection, &'static str> {
    let mut values = headers.get_all(AUTH_AUDIENCE_HEADER).iter();
    let Some(value) = values.next() else {
        return match mode {
            AuthorizationMode::AnyApp => Ok(AudienceSelection::Catalog),
            AuthorizationMode::PerApp => Err(MISSING_AUDIENCE_OVERRIDE),
        };
    };

    if values.next().is_some() {
        return Err(INVALID_AUDIENCE_OVERRIDE);
    }

    let value = value.to_str().map_err(|_| INVALID_AUDIENCE_OVERRIDE)?;
    if value.is_empty()
        || value.len() > MAX_AUDIENCE_OVERRIDE_LENGTH
        || value.contains(',')
        || value.chars().any(char::is_whitespace)
    {
        return Err(INVALID_AUDIENCE_OVERRIDE);
    }

    Ok(AudienceSelection::Bound(value.to_string()))
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

    let auds = match select_audience(req.headers(), state.authorization_mode) {
        Ok(AudienceSelection::Bound(audience)) => Arc::new(HashSet::from([audience])),
        Ok(AudienceSelection::Catalog) => {
            let Some(configurator) = state.configurator.as_ref() else {
                state
                    .denial_logger
                    .record(CATALOG_EMPTY, Some(token_source));
                return StatusCode::FORBIDDEN;
            };
            let audiences = configurator.audiences().await;
            if audiences.is_empty() {
                state
                    .denial_logger
                    .record(CATALOG_EMPTY, Some(token_source));
                return StatusCode::FORBIDDEN;
            }
            audiences
        }
        Err(reason) => {
            state.denial_logger.record(reason, Some(token_source));
            return StatusCode::FORBIDDEN;
        }
    };

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

    let startup = match StartupConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("event=configuration_invalid error={error}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "event=authorization_mode_configured mode={} catalog_enabled={}",
        startup.authorization_mode.as_str(),
        startup.catalog_credentials.is_some()
    );

    let authenticator = start_authenticator_service(startup.domain).await;
    let configurator = match startup.catalog_credentials {
        Some(credentials) => Some(start_dynamic_config_manager(credentials).await),
        None => None,
    };
    let denial_logger = DenialLogger::default();
    denial_logger.clone().start_flush_task();
    let app_state = AppState {
        authenticator,
        configurator,
        authorization_mode: startup.authorization_mode,
        denial_logger,
    };

    let app = Router::new()
        .route(
            "/auth",
            get(handler::<cfa::Authenticator, cdc::DynamicConfigManager>),
        )
        .layer(CookieManagerLayer::new())
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", startup.port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn start_dynamic_config_manager(
    credentials: CatalogCredentials,
) -> cdc::DynamicConfigManager {
    let api = format!(
        "{}/client/v4/accounts/{}/access/apps",
        "https://api.cloudflare.com", credentials.account_id
    );
    let config = cdc::Config {
        api,
        token: credentials.token,
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

async fn start_authenticator_service(api: String) -> cfa::Authenticator {
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
        async fn validate(
            &self,
            _token: &str,
            _auds: Arc<HashSet<String>>,
        ) -> Result<(), &'static str> {
            match self.denial_reason {
                Some(reason) => Err(reason),
                None => Ok(()),
            }
        }
    }

    #[derive(Clone)]
    struct FakeCatalog(Vec<String>);

    impl AudienceCatalog for FakeCatalog {
        async fn audiences(&self) -> Arc<HashSet<String>> {
            Arc::new(self.0.iter().cloned().collect())
        }
    }

    #[derive(Clone)]
    struct PanicCatalog;

    impl AudienceCatalog for PanicCatalog {
        async fn audiences(&self) -> Arc<HashSet<String>> {
            panic!("an explicitly bound request must not read the catalog")
        }
    }

    #[derive(Clone)]
    struct AppBoundAuthenticator;

    impl TokenAuthenticator for AppBoundAuthenticator {
        async fn validate(
            &self,
            token: &str,
            auds: Arc<HashSet<String>>,
        ) -> Result<(), &'static str> {
            let expected_audience = match token {
                "token-a" => "app-a",
                "token-b" => "app-b",
                _ => return Err(MALFORMED_TOKEN),
            };
            if auds.contains(expected_audience) {
                Ok(())
            } else {
                Err("audience_mismatch")
            }
        }
    }

    fn app_bound_router<C>(
        mode: AuthorizationMode,
        configurator: Option<C>,
    ) -> (Router, DenialLogger)
    where
        C: AudienceCatalog,
    {
        let denial_logger = DenialLogger::default();
        let state = AppState {
            authenticator: AppBoundAuthenticator,
            configurator,
            authorization_mode: mode,
            denial_logger: denial_logger.clone(),
        };
        let app = Router::new()
            .route("/auth", get(handler::<AppBoundAuthenticator, C>))
            .layer(CookieManagerLayer::new())
            .with_state(state);

        (app, denial_logger)
    }

    fn test_app(
        audiences: Vec<String>,
        denial_reason: Option<&'static str>,
    ) -> (Router, DenialLogger) {
        test_app_with_mode(audiences, denial_reason, AuthorizationMode::AnyApp)
    }

    fn test_app_with_mode(
        audiences: Vec<String>,
        denial_reason: Option<&'static str>,
        authorization_mode: AuthorizationMode,
    ) -> (Router, DenialLogger) {
        let denial_logger = DenialLogger::default();
        let state = AppState {
            authenticator: FakeAuthenticator { denial_reason },
            configurator: Some(FakeCatalog(audiences)),
            authorization_mode,
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

    fn app_token_request(uri: &str, token: &str, audience: Option<&str>) -> HttpRequest<Body> {
        let mut request = HttpRequest::builder()
            .uri(uri)
            .header("Cf-Access-Jwt-Assertion", token);
        if let Some(audience) = audience {
            request = request.header(AUTH_AUDIENCE_HEADER, audience);
        }
        request.body(Body::empty()).expect("build request")
    }

    fn environment<'a>(
        values: &'a [(&'a str, &'a str)],
    ) -> impl FnMut(&str) -> Result<String, env::VarError> + 'a {
        move |name| {
            values
                .iter()
                .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
                .ok_or(env::VarError::NotPresent)
        }
    }

    #[test]
    fn authorization_mode_defaults_to_any_app_and_rejects_unknown_values() {
        assert_eq!(
            AuthorizationMode::parse(None),
            Ok(AuthorizationMode::AnyApp)
        );
        assert_eq!(
            AuthorizationMode::parse(Some("any_app")),
            Ok(AuthorizationMode::AnyApp)
        );
        assert_eq!(
            AuthorizationMode::parse(Some("per_app")),
            Ok(AuthorizationMode::PerApp)
        );
        assert_eq!(
            AuthorizationMode::parse(Some("per-route")),
            Err(StartupConfigError::InvalidAuthorizationMode)
        );
    }

    #[test]
    fn per_app_configuration_does_not_read_cloudflare_api_credentials() {
        let mut reads = Vec::new();
        let config = StartupConfig::from_reader(|name| {
            reads.push(name.to_string());
            match name {
                "CF_AUTHORIZATION_MODE" => Ok("per_app".to_string()),
                "CF_DOMAIN" => Ok("https://team.cloudflareaccess.com".to_string()),
                "PORT" => Err(env::VarError::NotPresent),
                "CF_ORG" | "CF_TOKEN" => panic!("strict mode must not read {name}"),
                _ => Err(env::VarError::NotPresent),
            }
        })
        .expect("strict mode requires no Applications API credentials");

        assert_eq!(config.authorization_mode, AuthorizationMode::PerApp);
        assert!(config.catalog_credentials.is_none());
        assert!(!reads
            .iter()
            .any(|name| name == "CF_ORG" || name == "CF_TOKEN"));
    }

    #[test]
    fn any_app_configuration_requires_cloudflare_api_credentials() {
        let missing_org = StartupConfig::from_reader(environment(&[(
            "CF_DOMAIN",
            "https://team.cloudflareaccess.com",
        )]))
        .expect_err("unbound routes cannot start without an account ID");
        assert_eq!(missing_org, StartupConfigError::MissingVariable("CF_ORG"));

        let missing_token = StartupConfig::from_reader(environment(&[
            ("CF_DOMAIN", "https://team.cloudflareaccess.com"),
            ("CF_ORG", "account-id"),
        ]))
        .expect_err("unbound routes cannot start without an API token");
        assert_eq!(
            missing_token,
            StartupConfigError::MissingVariable("CF_TOKEN")
        );
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
    fn any_app_uses_the_catalog_only_when_the_audience_header_is_absent() {
        assert_eq!(
            select_audience(&HeaderMap::new(), AuthorizationMode::AnyApp),
            Ok(AudienceSelection::Catalog)
        );

        let mut headers = HeaderMap::new();
        headers.insert(AUTH_AUDIENCE_HEADER, HeaderValue::from_static("app-a"));
        assert_eq!(
            select_audience(&headers, AuthorizationMode::AnyApp),
            Ok(AudienceSelection::Bound("app-a".into()))
        );
    }

    #[test]
    fn per_app_requires_exactly_one_valid_audience_header() {
        assert_eq!(
            select_audience(&HeaderMap::new(), AuthorizationMode::PerApp),
            Err(MISSING_AUDIENCE_OVERRIDE)
        );

        for invalid in ["", " app-a", "app-a ", "app a", "app-a,app-b"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTH_AUDIENCE_HEADER,
                HeaderValue::from_str(invalid).expect("test header is syntactically valid"),
            );
            assert_eq!(
                select_audience(&headers, AuthorizationMode::PerApp),
                Err(INVALID_AUDIENCE_OVERRIDE),
                "{invalid:?} must fail closed"
            );
        }

        let mut duplicate = HeaderMap::new();
        duplicate.append(AUTH_AUDIENCE_HEADER, HeaderValue::from_static("app-a"));
        duplicate.append(AUTH_AUDIENCE_HEADER, HeaderValue::from_static("app-b"));
        assert_eq!(
            select_audience(&duplicate, AuthorizationMode::PerApp),
            Err(INVALID_AUDIENCE_OVERRIDE)
        );

        let mut oversized = HeaderMap::new();
        oversized.insert(
            AUTH_AUDIENCE_HEADER,
            HeaderValue::from_str(&"a".repeat(MAX_AUDIENCE_OVERRIDE_LENGTH + 1))
                .expect("ASCII test header is valid"),
        );
        assert_eq!(
            select_audience(&oversized, AuthorizationMode::PerApp),
            Err(INVALID_AUDIENCE_OVERRIDE)
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

    #[tokio::test]
    async fn per_app_accepts_a_token_only_through_its_bound_application() {
        let (app, _) = app_bound_router(AuthorizationMode::PerApp, None::<FakeCatalog>);

        let accepted = app
            .clone()
            .oneshot(app_token_request("/auth", "token-a", Some("app-a")))
            .await
            .expect("handler responds");
        assert_eq!(accepted.status(), StatusCode::OK);

        let rejected = app
            .oneshot(app_token_request("/auth", "token-a", Some("app-b")))
            .await
            .expect("handler responds");
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn client_query_parameters_cannot_change_the_trusted_header_binding() {
        let (app, _) = app_bound_router(AuthorizationMode::PerApp, None::<FakeCatalog>);

        let response = app
            .oneshot(app_token_request(
                "/auth?aud=app-a",
                "token-b",
                Some("app-b"),
            ))
            .await
            .expect("handler responds");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn any_app_explicit_binding_does_not_read_the_catalog() {
        let (app, _) = app_bound_router(AuthorizationMode::AnyApp, Some(PanicCatalog));

        let response = app
            .oneshot(app_token_request("/auth", "token-a", Some("app-a")))
            .await
            .expect("handler responds");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn per_app_missing_binding_fails_closed_with_a_generic_response() {
        let (app, logger) = app_bound_router(AuthorizationMode::PerApp, None::<FakeCatalog>);

        let response = app
            .oneshot(app_token_request("/auth", "token-a", None))
            .await
            .expect("handler responds");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body")
            .is_empty());
        let windows = logger.windows.lock().unwrap();
        assert_eq!(
            windows
                .get(MISSING_AUDIENCE_OVERRIDE)
                .map(|window| window.emitted),
            Some(1)
        );
    }
}
