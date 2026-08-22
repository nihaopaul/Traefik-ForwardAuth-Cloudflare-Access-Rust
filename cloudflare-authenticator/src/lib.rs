use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use reqwest::{self, header};
use serde::{Deserialize, Serialize};

use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::time::{interval, Duration};

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
    #[error("No matching AUD found")]
    NoAudMatch,
    #[error("Certificate not found")]
    CertificateNotFound,
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

impl Authenticator {
    pub async fn new(config: Config) -> Result<Self, ValidationError> {
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
            client: reqwest::Client::new(),
        };

        // Start the background task to update certs periodically
        certs_manager.clone().start_update_task();

        Ok(certs_manager)
    }

    fn update_certs(&self, new_certs: Certs) {
        println!("Updating certs: {:?}", new_certs);
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

        let decode_key = DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str())?;

        // Trust the algorithm advertised by the JWKS, not the one in the token
        // header: the header is attacker-controlled, so using it lets a caller
        // pick which algorithm their own token is checked against.
        let mut validation = Validation::new(key.alg);
        validation.set_audience(&auds);

        let token_data = decode::<Claims>(&jwt, &decode_key, &validation)?;

        Ok(token_data)
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
            .await?;

        // Proceed with parsing the result
        match serde_json::from_value::<Certs>(response.json().await?) {
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
            loop {
                interval.tick().await;
                if let Err(e) = self.fetch_certs().await {
                    eprintln!("Error updating certs: {}", e);
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

    fn sign(claims: &Claims, alg: Algorithm, kid: Option<&str>) -> String {
        let der = test_key().to_pkcs1_der().expect("encode test key");
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_string);
        encode(&header, claims, &EncodingKey::from_rsa_der(der.as_bytes())).expect("sign token")
    }

    fn claims(aud: &str, exp: usize) -> Claims {
        // Issued an hour before it expires, so expired tokens stay coherent.
        let issued = exp.saturating_sub(3600);
        Claims {
            aud: vec![aud.to_string()],
            email: "user@example.com".to_string(),
            exp,
            iat: issued,
            nbf: issued,
            iss: "https://example.cloudflareaccess.com".to_string(),
            type_: "app".to_string(),
            identity_nonce: "test-nonce".to_string(),
            sub: "00000000-0000-0000-0000-000000000000".to_string(),
            country: "SG".to_string(),
        }
    }

    /// Serves `jwk` from a mock JWKS endpoint and returns an Authenticator whose
    /// certs have actually been loaded.
    async fn authenticator(server: &mut mockito::ServerGuard, jwk: serde_json::Value) -> Authenticator {
        let body = json!({
            "keys": [jwk],
            "public_cert": { "kid": KID, "cert": "" },
            "public_certs": [{ "kid": KID, "cert": "" }],
        });

        server
            .mock("GET", "/cdn-cgi/access/certs")
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create_async()
            .await;

        let auth = Authenticator::new(Config {
            api: server.url(),
            duration: 60 * 60 * 24,
        })
        .await
        .expect("create authenticator");

        // The initial fetch happens on the background task's first tick.
        for _ in 0..100 {
            let loaded = !auth.certs.lock().unwrap().keys.is_empty();
            if loaded {
                return auth;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("certs were never fetched from the mock JWKS endpoint");
    }

    #[tokio::test]
    async fn accepts_a_validly_signed_token() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        let token = sign(&claims(AUD, now() + 3600), Algorithm::RS256, Some(KID));
        let decoded = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect("a correctly signed, unexpired, correctly-audienced token must verify");

        assert_eq!(decoded.claims.email, "user@example.com");
        assert_eq!(decoded.claims.aud, vec![AUD.to_string()]);
    }

    #[tokio::test]
    async fn rejects_an_expired_token() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        // Comfortably past jsonwebtoken's default 60s clock-skew leeway, which
        // would otherwise still accept a token that expired seconds ago.
        let token = sign(&claims(AUD, now() - 3600), Algorithm::RS256, Some(KID));
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
    async fn rejects_a_token_for_a_different_audience() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        let token = sign(
            &claims("someone-elses-aud", now() + 3600),
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
    }

    #[tokio::test]
    async fn rejects_a_token_signed_by_an_unknown_key() {
        let mut server = mockito::Server::new_async().await;
        // The JWKS only knows "rotated-key"; the token claims "test-key-1".
        let auth = authenticator(&mut server, jwk("rotated-key", "RS256")).await;

        let token = sign(&claims(AUD, now() + 3600), Algorithm::RS256, Some(KID));
        let err = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("a token whose kid is absent from the JWKS must be rejected");

        assert!(
            matches!(err, ValidationError::CertificateNotFound),
            "expected CertificateNotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_a_token_with_no_kid() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        let token = sign(&claims(AUD, now() + 3600), Algorithm::RS256, None);
        let err = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("a token without a kid must be rejected");

        assert!(
            matches!(err, ValidationError::InvalidToken),
            "expected InvalidToken, got {err:?}"
        );
    }

    /// Regression test: the algorithm must come from the JWKS, not the token
    /// header. Validating with `Validation::new(header.alg)` accepts this token,
    /// because it lets the caller nominate the algorithm their own signature is
    /// checked against.
    #[tokio::test]
    async fn token_header_cannot_choose_the_signing_algorithm() {
        let mut server = mockito::Server::new_async().await;
        let auth = authenticator(&mut server, jwk(KID, "RS256")).await;

        let token = sign(&claims(AUD, now() + 3600), Algorithm::RS384, Some(KID));
        let err = auth
            .decode(&token, vec![AUD.to_string()])
            .await
            .expect_err("RS384 must be refused when the JWKS advertises RS256");

        assert!(
            matches!(&err, ValidationError::JwtDecodingError(e) if matches!(e.kind(), ErrorKind::InvalidAlgorithm)),
            "expected InvalidAlgorithm, got {err:?}"
        );
    }
}
