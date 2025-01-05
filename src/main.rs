use cloudflare_authenticator as cfa;
use cloudflare_dynamic_config as cdc;
use std::env;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use tower_cookies::{CookieManagerLayer, Cookies};

#[derive(Clone)]
struct AppState {
    authenticator: cfa::Authenticator,
    configurator: cdc::DynamicConfigManager, // Use Arc for shared ownership
}

async fn handler(
    State(state): State<AppState>,
    cookies: Cookies,
    _req: Request,
) -> impl IntoResponse {
    let auth_cookie = match cookies.get("CF_Authorization") {
        Some(cookie) => cookie.value().to_string(),
        None => return StatusCode::FORBIDDEN,
    };

    let auds = state.configurator.get_aud().await;

    match state.authenticator.test(&auth_cookie, auds).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::FORBIDDEN,
    }
}

#[tokio::main]
async fn main() {
    let port = env::var("PORT").unwrap_or("3000".to_string());
    let app_state = AppState {
        authenticator: start_authenticator_service().await,
        configurator: start_dynamic_config_manager().await,
    };

    let app = Router::new()
        .route("/", get(handler))
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

    // Create and initialize the manager using new()
    let manager = match cdc::DynamicConfigManager::new(config).await {
        Ok(manager) => manager,
        Err(e) => panic!("Failed to create DynamicConfigManager: {}", e),
    };

    return manager;
}

async fn start_authenticator_service() -> cfa::Authenticator {
    let api = env::var("CF_DOMAIN").expect("CF_DOMAIN must be set");
    let config = cfa::Config {
        api,
        duration: 60 * 60 * 24,
    };

    // Create and initialize the manager using new()
    let manager = match cfa::Authenticator::new(config).await {
        Ok(manager) => manager,
        Err(e) => panic!("Failed to create DynamicConfigManager: {}", e),
    };
    return manager;
}
