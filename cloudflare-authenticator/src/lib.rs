use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use reqwest::{self, header};
use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::time::{interval, Duration};

const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ACCESS_APPLICATION_TOKEN_TYPE: &str = "app";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certs {
    pub keys: Vec<Key>,
    pub public_cert: PublicCert,
    pub public_certs: Vec<PublicCert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    pub kid: String,
    pub kty: String,
    pub alg: Algorithm,
    #[serde(rename = "use")] // use is a reserved keyword in Rust, so we will rename it
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
    pub duration: u64,
}

#[derive(Debug, Clone)]
pub struct Authenticator {
    config: Config,
    certs: Arc<Mutex<Certs>>,
    observed_token_types: Arc<Mutex<HashSet<String>>>,
    client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    aud: Vec<String>,
    email: String,
    exp: usize,
    iat: usize,
    nbf: usize,
    iss: String,
    #[serde(rename = "type")] // use is a reserved keyword in Rust, so we will rename it
    type_: String,
    identity_nonce: String,
    sub: String,
    country: String,
}

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Environment variable error: {0}")]
    EnvVarError(#[from] std::env::VarError),
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Serde JSON error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token is not a Cloudflare Access application token")]
    InvalidTokenType,
    #[error("No matching AUD found")]
    NoAudMatch,
    #[error("Certificate not found")]
    CertificateNotFound,
    #[error("JWKS contains no signing keys")]
    NoSigningKeys,
    #[error("JWKS contains invalid signing key material")]
    InvalidSigningKey,
    #[error("Failed to fetch certificates")]
    FetchCertificatesFailed,
    #[error("JWT decoding error: {0}")]
    JwtDecodingError(#[from] jsonwebtoken::errors::Error),
    #[error("Error parsing JSON response: {0}")]
    JsonParseError(String),
    #[error("Missing 'result' field in API response")]
    MissingResultError,
    #[error("Missing 'public_certs' field in API response")]
    MissingPublicCertsError,
    #[error("Serde URL encoding error: {0}")]
    SerdeUrlencodedError(#[from] serde_urlencoded::ser::Error),
}

impl ValidationError {
    pub fn reason_code(&self) -> &'static str {
        use jsonwebtoken::errors::ErrorKind;

        match self {
            Self::CertificateNotFound
            | Self::NoSigningKeys
            | Self::InvalidSigningKey
            | Self::FetchCertificatesFailed => "signing_key_unavailable",
            Self::NoAudMatch => "audience_mismatch",
            Self::InvalidToken => "malformed_token",
            Self::InvalidTokenType => "invalid_token_type",
            Self::JwtDecodingError(error) => match error.kind() {
                ErrorKind::ExpiredSignature => "expired_token",
                ErrorKind::InvalidIssuer => "invalid_issuer",
                ErrorKind::InvalidAudience => "audience_mismatch",
                ErrorKind::InvalidSignature | ErrorKind::InvalidAlgorithm => "invalid_signature",
                _ => "malformed_token",
            },
            _ => "malformed_token",
        }
    }
}

impl Authenticator {
    pub async fn new(config: Config) -> Result<Self, ValidationError> {
        let config = Config {
            api: config.api.trim_end_matches('/').to_string(),
            duration: config.duration,
        };
        let certs_manager = Self {
            config,
            certs: Arc::new(Mutex::new(Certs {
                keys: vec![],
                public_cert: PublicCert {
                    kid: "".to_string(),
                    cert: "".to_string(),
                },
                public_certs: vec![],
            })),
            observed_token_types: Arc::new(Mutex::new(HashSet::new())),
            client: reqwest::Client::builder()
                .timeout(HTTP_REQUEST_TIMEOUT)
                .build()?,
        };

        // Refuse to serve until signature validation can actually succeed.
        certs_manager.fetch_certs().await?;
        certs_manager.clone().start_update_task();

        Ok(certs_manager)
    }

    fn update_certs(&self, new_certs: Certs) {
        eprintln!("event=jwks_updated keys={}", new_certs.keys.len());
        let mut certs = self.certs.lock().unwrap();
        *certs = new_certs;
    }

    pub async fn decode(
        &self,
        jwt: &str,
        auds: Vec<String>,
    ) -> Result<TokenData<Claims>, ValidationError> {
        let header = decode_header(jwt)?;

        let kid = header.kid.as_ref().ok_or(ValidationError::InvalidToken)?;
        let key = self.get_certificate(kid).await?;

        let decode_key = DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str())
            .map_err(|_| ValidationError::InvalidSigningKey)?;

        let validation = self.validation_for(key.alg, &auds);

        let token_data = decode::<Claims>(&jwt, &decode_key, &validation)?;
        self.observe_token_type(&token_data.claims.type_);
        if token_data.claims.type_ != ACCESS_APPLICATION_TOKEN_TYPE {
            return Err(ValidationError::InvalidTokenType);
        }

        Ok(token_data)
    }

    fn validation_for(&self, algorithm: Algorithm, auds: &[String]) -> Validation {
        // Trust the algorithm advertised by the JWKS, not the one in the token
        // header: the header is attacker-controlled, so using it lets a caller
        // pick which algorithm their own token is checked against.
        let mut validation = Validation::new(algorithm);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_audience(auds);
        validation.set_issuer(&[self.config.api.as_str()]);
        validation.validate_nbf = true;
        validation
    }

    fn observe_token_type(&self, token_type: &str) {
        let mut observed = self.observed_token_types.lock().unwrap();
        if observed.insert(token_type.to_string()) {
            eprintln!("event=access_token_type_observed token_type={token_type:?}");
        }
    }

    async fn get_certificate(&self, certificate_id: &str) -> Result<Key, ValidationError> {
        let certs = self.certs.lock().unwrap();
        let keys = certs.keys.iter().find(|key| key.kid == certificate_id);

        match keys {
            Some(key) => Ok(key.clone()),
            None => Err(ValidationError::CertificateNotFound),
        }
    }

    pub async fn test(&self, jwt: &str, auds: Vec<String>) -> Result<(), ValidationError> {
        self.decode(jwt, auds).await?;
        Ok(())
    }

    async fn fetch_certs(&self) -> Result<(), ValidationError> {
        let response = self
            .client
            .get(format!("{}/cdn-cgi/access/certs", self.config.api))
            .header(header::CONTENT_TYPE, "application/json")
            .send()
            .await?
            .error_for_status()?;

        // Proceed with parsing the result
        match serde_json::from_value::<Certs>(response.json().await?) {
            Ok(certs) if certs.keys.is_empty() => Err(ValidationError::NoSigningKeys),
            Ok(certs) => {
                self.update_certs(certs);
                Ok(())
            }
            Err(e) => Err(ValidationError::JsonParseError(format!(
                "Error parsing JSON response: {}",
                e
            ))),
        }
    }

    fn start_update_task(self) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(self.config.duration));
            // The initial fetch was synchronous, so skip interval's immediate tick.
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(e) = self.fetch_certs().await {
                    eprintln!("event=jwks_refresh_failed error={e}");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use jsonwebtoken::errors::ErrorKind;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde_json::json;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    const KID: &str = "test-key-1";
    const AUD: &str = "aud-under-test";

    fn now() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
    }

    /// RSA keygen is expensive in a debug build, so every test shares one
    /// throwaway keypair. Generating it at run time keeps a private key out of
    /// the repository and stops tokens from ageing into permanent failure.
    fn test_key() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let mut rng = rand::thread_rng();
            RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA test key")
        })
    }

    /// The public half of the test key, shaped like a Cloudflare Access JWKS entry.
    fn jwk(kid: &str, alg: &str) -> serde_json::Value {
        let public = test_key().to_public_key();
        json!({
            "kid": kid,
            "kty": "RSA",
            "alg": alg,
            "use": "sig",
            "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
            "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        })
    }

    fn jwks_body(jwk: serde_json::Value) -> String {
        json!({
            "keys": [jwk],
            "public_cert": { "kid": KID, "cert": "" },
            "public_certs": [{ "kid": KID, "cert": "" }],
        })
        .to_string()
    }

    fn sign_payload<T: Serialize>(claims: &T, alg: Algorithm, kid: Option<&str>) -> String {
        let der = test_key().to_pkcs1_der().expect("encode test key");
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_string);
        encode(&header, claims, &EncodingKey::from_rsa_der(der.as_bytes())).expect("sign token")
    }

    fn sign(claims: &Claims, alg: Algorithm, kid: Option<&str>) -> String {
        sign_payload(claims, alg, kid)
    }

    fn claims(aud: &str, exp: usize, issuer: &str) -> Claims {
        // Issued an hour before it expires, so expired tokens stay coherent.
        let issued = exp.saturating_sub(3600);
        Claims {
            aud: vec![aud.to_string()],
            email: "user@example.com".to_string(),
            exp,
            iat: issued,
            nbf: issued,
            iss: issuer.to_string(),
            type_: ACCESS_APPLICATION_TOKEN_TYPE.to_string(),
            identity_nonce: "test-nonce".to_string(),
            sub: "00000000-0000-0000-0000-000000000000".to_string(),
            country: "SG".to_string(),
        }
    }

    /// Serves `jwk` from a mock JWKS endpoint and returns an Authenticator whose
    /// certs have already been loaded synchronously.
    async fn authenticator(
        server: &mut mockito::ServerGuard,
        jwk: serde_json::Value,
    ) -> Authenticator {
        server
            .mock("GET", "/cdn-cgi/access/certs")
            .with_header("content-type", "application/json")
            .with_body(jwks_body(jwk))
            .create_async()
            .await;

        Authenticator::new(Config {
            api: server.url(),
            duration: 60 * 60 * 24,
        })
        .await
        .expect("create authenticator")
    }

    #[tokio::test]
    async fn accepts_a_validly_signed_token() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        let token = sign(
            &claims(AUD, now() + 3600, &server.url()),
            Algorithm::RS256,
            Some(KID),
        );
        let decoded = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect("a correctly signed, unexpired, correctly-audienced token must verify");

        assert_eq!(decoded.claims.email, "user@example.com");
        assert_eq!(decoded.claims.aud, vec![AUD.to_string()]);
    }

    #[tokio::test]
    async fn accepts_one_matching_audience_from_the_catalog() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;
        let token = sign(
            &claims(AUD, now() + 3600, &server.url()),
            Algorithm::RS256,
            Some(KID),
        );

        auth.decode(&token, vec!["another-app".into(), AUD.into()])
            .await
            .expect("one matching catalog audience is sufficient");
    }

    #[tokio::test]
    async fn initial_jwks_failure_prevents_startup() {
        let mut server = mockito::Server::new_async().await;
        let request = server
            .mock("GET", "/cdn-cgi/access/certs")
            .with_status(503)
            .create_async()
            .await;

        Authenticator::new(Config {
            api: server.url(),
            duration: 60 * 60 * 24,
        })
        .await
        .expect_err("startup must fail without signing keys");

        request.assert_async().await;
    }

    #[tokio::test]
    async fn an_empty_jwks_prevents_startup() {
        let mut server = mockito::Server::new_async().await;
        let request = server
            .mock("GET", "/cdn-cgi/access/certs")
            .with_body(
                json!({
                    "keys": [],
                    "public_cert": { "kid": KID, "cert": "" },
                    "public_certs": []
                })
                .to_string(),
            )
            .create_async()
            .await;

        let error = Authenticator::new(Config {
            api: server.url(),
            duration: 60 * 60 * 24,
        })
        .await
        .expect_err("startup must fail when the JWKS has no signing keys");

        assert!(matches!(error, ValidationError::NoSigningKeys));
        assert_eq!(error.reason_code(), "signing_key_unavailable");
        request.assert_async().await;
    }

    #[tokio::test]
    async fn normalizes_a_trailing_slash_and_validates_the_issuer() {
        let mut server = mockito::Server::new_async().await;
        let request = server
            .mock("GET", "/cdn-cgi/access/certs")
            .with_body(jwks_body(jwk(KID, "RS256")))
            .create_async()
            .await;
        let auth = Authenticator::new(Config {
            api: format!("{}/", server.url()),
            duration: 60 * 60 * 24,
        })
        .await
        .expect("create authenticator");
        let token = sign(
            &claims(AUD, now() + 3600, &server.url()),
            Algorithm::RS256,
            Some(KID),
        );

        auth.decode(&token, vec![AUD.to_string()])
            .await
            .expect("the normalized issuer must match");
        request.assert_async().await;
    }

    #[tokio::test]
    async fn rejects_and_classifies_a_wrong_issuer() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;
        let token = sign(
            &claims(AUD, now() + 3600, "https://other.cloudflareaccess.com"),
            Algorithm::RS256,
            Some(KID),
        );

        let error = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("a token from another issuer must fail");

        assert_eq!(error.reason_code(), "invalid_issuer");
        assert!(
            matches!(&error, ValidationError::JwtDecodingError(error) if matches!(error.kind(), ErrorKind::InvalidIssuer))
        );
    }

    #[tokio::test]
    async fn rejects_tokens_missing_required_issuer_or_audience_claims() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;
        let key = auth
            .get_certificate(KID)
            .await
            .expect("test signing key is loaded");
        let decoding_key =
            DecodingKey::from_rsa_components(&key.n, &key.e).expect("test signing key is valid");
        let audiences = vec![AUD.to_string()];
        let validation = auth.validation_for(key.alg, &audiences);

        for missing_claim in ["iss", "aud"] {
            let mut payload = serde_json::to_value(claims(AUD, now() + 3600, &server.url()))
                .expect("serialize claims");
            payload
                .as_object_mut()
                .expect("claims serialize as an object")
                .remove(missing_claim);
            let token = sign_payload(&payload, Algorithm::RS256, Some(KID));

            // Value accepts either missing claim, so this reaches Validation
            // instead of failing early while deserializing the strict Claims
            // type used by production decoding.
            let error =
                jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation)
                    .expect_err(
                        "required issuer and audience claims must be enforced by Validation",
                    );

            assert!(
                matches!(error.kind(), ErrorKind::MissingRequiredClaim(_)),
                "missing {missing_claim} should reach required-claim validation, got {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_and_observes_non_application_token_types() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;
        let mut token_claims = claims(AUD, now() + 3600, &server.url());
        token_claims.type_ = "unexpected-signed-type".into();
        let token = sign(&token_claims, Algorithm::RS256, Some(KID));

        let error = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("Piece 1b requires a Cloudflare Access application token");

        assert!(matches!(error, ValidationError::InvalidTokenType));
        assert_eq!(error.reason_code(), "invalid_token_type");
        let observed = auth.observed_token_types.lock().unwrap();
        assert_eq!(observed.len(), 1);
        assert!(observed.contains("unexpected-signed-type"));
    }

    #[tokio::test]
    async fn rejects_an_expired_token() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        // Comfortably past jsonwebtoken's default 60s clock-skew leeway, which
        // would otherwise still accept a token that expired seconds ago.
        let token = sign(
            &claims(AUD, now() - 3600, &server.url()),
            Algorithm::RS256,
            Some(KID),
        );
        let err = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("an expired token must be rejected");

        assert!(
            matches!(&err, ValidationError::JwtDecodingError(e) if matches!(e.kind(), ErrorKind::ExpiredSignature)),
            "expected ExpiredSignature, got {err:?}"
        );
    }

    #[tokio::test]
    async fn applies_jsonwebtokens_sixty_second_expiration_leeway() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;
        let issuer = server.url();
        let within_leeway = sign(
            &claims(AUD, now() - 59, &issuer),
            Algorithm::RS256,
            Some(KID),
        );
        let beyond_leeway = sign(
            &claims(AUD, now() - 61, &issuer),
            Algorithm::RS256,
            Some(KID),
        );

        auth.decode(&within_leeway, vec![AUD.to_string()])
            .await
            .expect("a token 59 seconds past exp is inside the configured leeway");
        let error = auth
            .decode(&beyond_leeway, vec![AUD.to_string()])
            .await
            .expect_err("a token 61 seconds past exp is outside the configured leeway");

        assert_eq!(error.reason_code(), "expired_token");
    }

    #[tokio::test]
    async fn rejects_a_token_that_is_not_valid_yet() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;
        let mut token_claims = claims(AUD, now() + 3600, &server.url());
        token_claims.nbf = now() + 120;
        let token = sign(&token_claims, Algorithm::RS256, Some(KID));

        let error = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("a token beyond the 60-second nbf leeway must be rejected");

        assert!(
            matches!(&error, ValidationError::JwtDecodingError(error) if matches!(error.kind(), ErrorKind::ImmatureSignature))
        );
    }

    #[tokio::test]
    async fn rejects_a_token_for_a_different_audience() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        let token = sign(
            &claims("someone-elses-aud", now() + 3600, &server.url()),
            Algorithm::RS256,
            Some(KID),
        );
        let err = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("a token issued for another audience must be rejected");

        assert!(
            matches!(&err, ValidationError::JwtDecodingError(e) if matches!(e.kind(), ErrorKind::InvalidAudience)),
            "expected InvalidAudience, got {err:?}"
        );
        assert_eq!(err.reason_code(), "audience_mismatch");
    }

    #[tokio::test]
    async fn rejects_a_token_signed_by_an_unknown_key() {
        let mut server = mockito::Server::new_async().await;
        // The JWKS only knows "rotated-key"; the token claims "test-key-1".
        let auth = authenticator(&mut server, jwk("rotated-key", "RS256")).await;

        let token = sign(
            &claims(AUD, now() + 3600, &server.url()),
            Algorithm::RS256,
            Some(KID),
        );
        let err = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("a token whose kid is absent from the JWKS must be rejected");

        assert!(
            matches!(err, ValidationError::CertificateNotFound),
            "expected CertificateNotFound, got {err:?}"
        );
        assert_eq!(err.reason_code(), "signing_key_unavailable");
    }

    #[tokio::test]
    async fn invalid_jwks_key_material_is_a_server_side_failure() {
        let mut server = mockito::Server::new_async().await;
        let mut invalid_jwk = jwk(KID, "RS256");
        invalid_jwk["n"] = json!("not-valid-base64!");
        let auth = authenticator(&mut server, invalid_jwk).await;
        let token = sign(
            &claims(AUD, now() + 3600, &server.url()),
            Algorithm::RS256,
            Some(KID),
        );

        let error = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("invalid JWKS key material must fail validation");

        assert!(matches!(error, ValidationError::InvalidSigningKey));
        assert_eq!(error.reason_code(), "signing_key_unavailable");
    }

    #[tokio::test]
    async fn rejects_a_token_with_no_kid() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        let token = sign(
            &claims(AUD, now() + 3600, &server.url()),
            Algorithm::RS256,
            None,
        );
        let err = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("a token without a kid must be rejected");

        assert!(
            matches!(err, ValidationError::InvalidToken),
            "expected InvalidToken, got {err:?}"
        );
        assert_eq!(err.reason_code(), "malformed_token");
    }

    /// Regression test: the algorithm must come from the JWKS, not the token
    /// header. Validating with `Validation::new(header.alg)` accepts this token,
    /// because it lets the caller nominate the algorithm their own signature is
    /// checked against.
    #[tokio::test]
    async fn token_header_cannot_choose_the_signing_algorithm() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        let token = sign(
            &claims(AUD, now() + 3600, &server.url()),
            Algorithm::RS384,
            Some(KID),
        );
        let err = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("RS384 must be refused when the JWKS advertises RS256");

        assert!(
            matches!(&err, ValidationError::JwtDecodingError(e) if matches!(e.kind(), ErrorKind::InvalidAlgorithm)),
            "expected InvalidAlgorithm, got {err:?}"
        );
        assert_eq!(err.reason_code(), "invalid_signature");
    }
}
