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
        let header = decode_header(&jwt)?;

        let kid = header.kid.as_ref().ok_or(ValidationError::InvalidToken)?;
        let key = self.get_certificate(kid).await?;

        let decode_key = DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str()).unwrap();
        let mut validation = Validation::new(header.alg);
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
        self.decode(&jwt, auds).await?;
        Ok(())
    }

    async fn fetch_certs(&self) -> Result<(), ValidationError> {
        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/cdn-cgi/access/certs", &self.config.api))
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
    use mockito;
    use serde_json::json;

    #[tokio::test]
    async fn test_fetch_certs_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/cdn-cgi/access/certs")
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                  "keys": [
                    {
                      "kid": "179225fc257d581d1acefc31d5f6eeac9c1454f34ac5fc78311a125bc2bc183c",
                      "kty": "RSA",
                      "alg": "RS256",
                      "use": "sig",
                      "e": "AQAB",
                      "n": "mPb0s4zQJuyjlk9GNSGFVq2dNMrAXk_E-WYnv-0uBUkoxKQCjDpFnglxMeGW14GCo7KxnS2Lk8FTpKeFqFCF6Z_Nte-VmakMsW7QtPBk1WWiCwdRUbNdaBHDWAzrKzXUGPcnLtNpfJYFoawZsLZRPiY-rvVCEhfOX8ycb_NSdHDXNU5w3Y0aVSgLUzFVyVKkvmYzLgo62VbvWscTJ-19AaQV_dKE3cZpd13FvZEST1NsSRRZJ_75_YXeroxBw-YOamBipIRQwpdJHjlcISSv83svSctIwl8C60K32fZ5D5Pl9hiTQIx11zo6LU4Al7Tgd7I_h1aUzjPR7FSeVmZzhQ"
                    },
                    {
                      "kid": "6110ccf8fdddee78b239ceb42abe87c8712dc3041f34ed0876c246cbd7065cfd",
                      "kty": "RSA",
                      "alg": "RS256",
                      "use": "sig",
                      "e": "AQAB",
                      "n": "yyOHO7mOl4FIXhMuU59kR71xfWBpvfRJeavhjTJr_YWL8-Oi5U2yB1g8KDa9X1gxm2Mua2VRSCon3L2uzdhi7GCLO6gd5BewpRSJkZoCVznQhVktra18L-sxPKjApm7auwpLBCm68VMV_1U0rQB8K4frNeavnsU4OMP91lYla16qtMYCDDwe0Hl1Wn4rwGEVeqv6G3k4z_YkeGgGnuWOKAZpPz9NdLj3C7qb6LVhbrBB-_sFKhG9cKaJA06eXULi0qaxtgYdVf5OGfq2PK-JcSSSJEWCMEZj84-potLcSHWXWh5zOEsH8dfYZ8StH1ePZO7pHY6qUB4OeVXm5hzLaw"
                    }
                  ],
                  "public_cert": {
                    "kid": "179225fc257d581d1acefc31d5f6eeac9c1454f34ac5fc78311a125bc2bc183c",
                    "cert": "-----BEGIN CERTIFICATE-----\nMIIDTTCCAjWgAwIBAgIRAP8+7f1+s/N7hI7rj9VTeLQwDQYJKoZIhvcNAQELBQAw\nYjELMAkGA1UEBhMCVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4x\nEzARBgNVBAoTCkNsb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3Mu\nY29tMB4XDTI0MTEyMjE1MzAzNloXDTI1MTIwNjE1MzAzNlowYjELMAkGA1UEBhMC\nVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4xEzARBgNVBAoTCkNs\nb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3MuY29tMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmPb0s4zQJuyjlk9GNSGFVq2dNMrAXk/E\n+WYnv+0uBUkoxKQCjDpFnglxMeGW14GCo7KxnS2Lk8FTpKeFqFCF6Z/Nte+VmakM\nsW7QtPBk1WWiCwdRUbNdaBHDWAzrKzXUGPcnLtNpfJYFoawZsLZRPiY+rvVCEhfO\nX8ycb/NSdHDXNU5w3Y0aVSgLUzFVyVKkvmYzLgo62VbvWscTJ+19AaQV/dKE3cZp\nd13FvZEST1NsSRRZJ/75/YXeroxBw+YOamBipIRQwpdJHjlcISSv83svSctIwl8C\n60K32fZ5D5Pl9hiTQIx11zo6LU4Al7Tgd7I/h1aUzjPR7FSeVmZzhQIDAQABMA0G\nCSqGSIb3DQEBCwUAA4IBAQAaNa5bBdf9LBy0AtEU6OHQZdTiOLGFYVbzxaeEIE9f\nnoR8cNK6yTLHRKJ4brN0yfrTPLMPmg3/SZuI4O2D/jqJsUMiJWd9m10U3WuCe8Pu\nUmXQcAoqhy77P0JA6xmslw3V+7kDJEomy9vEeZ5TpjBSyI2/0scJb64V/mhvOfF7\njXeXIiA4Qpm5V4hy0qPGpabENVtmvGZSDZHZoADvl3hGcN2G5n7cyGg1t+kUdPnK\n38dGvvGvwoN5oosnpfi1iJvxsbAZdgVBpz2Q5vUvStb4cHYg5NSxzVMqckH3BKjP\neN1AoZMHOKfInSIdf9j6xN1kP4Q4EvScX+TXC9D2JUIx\n-----END CERTIFICATE-----\n"
                  },
                  "public_certs": [
                    {
                      "kid": "179225fc257d581d1acefc31d5f6eeac9c1454f34ac5fc78311a125bc2bc183c",
                      "cert": "-----BEGIN CERTIFICATE-----\nMIIDTTCCAjWgAwIBAgIRAP8+7f1+s/N7hI7rj9VTeLQwDQYJKoZIhvcNAQELBQAw\nYjELMAkGA1UEBhMCVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4x\nEzARBgNVBAoTCkNsb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3Mu\nY29tMB4XDTI0MTEyMjE1MzAzNloXDTI1MTIwNjE1MzAzNlowYjELMAkGA1UEBhMC\nVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4xEzARBgNVBAoTCkNs\nb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3MuY29tMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmPb0s4zQJuyjlk9GNSGFVq2dNMrAXk/E\n+WYnv+0uBUkoxKQCjDpFnglxMeGW14GCo7KxnS2Lk8FTpKeFqFCF6Z/Nte+VmakM\nsW7QtPBk1WWiCwdRUbNdaBHDWAzrKzXUGPcnLtNpfJYFoawZsLZRPiY+rvVCEhfO\nX8ycb/NSdHDXNU5w3Y0aVSgLUzFVyVKkvmYzLgo62VbvWscTJ+19AaQV/dKE3cZp\nd13FvZEST1NsSRRZJ/75/YXeroxBw+YOamBipIRQwpdJHjlcISSv83svSctIwl8C\n60K32fZ5D5Pl9hiTQIx11zo6LU4Al7Tgd7I/h1aUzjPR7FSeVmZzhQIDAQABMA0G\nCSqGSIb3DQEBCwUAA4IBAQAaNa5bBdf9LBy0AtEU6OHQZdTiOLGFYVbzxaeEIE9f\nnoR8cNK6yTLHRKJ4brN0yfrTPLMPmg3/SZuI4O2D/jqJsUMiJWd9m10U3WuCe8Pu\nUmXQcAoqhy77P0JA6xmslw3V+7kDJEomy9vEeZ5TpjBSyI2/0scJb64V/mhvOfF7\njXeXIiA4Qpm5V4hy0qPGpabENVtmvGZSDZHZoADvl3hGcN2G5n7cyGg1t+kUdPnK\n38dGvvGvwoN5oosnpfi1iJvxsbAZdgVBpz2Q5vUvStb4cHYg5NSxzVMqckH3BKjP\neN1AoZMHOKfInSIdf9j6xN1kP4Q4EvScX+TXC9D2JUIx\n-----END CERTIFICATE-----\n"
                    },
                    {
                      "kid": "6110ccf8fdddee78b239ceb42abe87c8712dc3041f34ed0876c246cbd7065cfd",
                      "cert": "-----BEGIN CERTIFICATE-----\nMIIDTDCCAjSgAwIBAgIQKxBEDYxED80GP0LK9Pt61zANBgkqhkiG9w0BAQsFADBi\nMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxDzANBgNVBAcTBkF1c3RpbjET\nMBEGA1UEChMKQ2xvdWRmbGFyZTEdMBsGA1UEAxMUY2xvdWRmbGFyZWFjY2Vzcy5j\nb20wHhcNMjQxMTIyMTUzMDM2WhcNMjUxMjA2MTUzMDM2WjBiMQswCQYDVQQGEwJV\nUzEOMAwGA1UECBMFVGV4YXMxDzANBgNVBAcTBkF1c3RpbjETMBEGA1UEChMKQ2xv\ndWRmbGFyZTEdMBsGA1UEAxMUY2xvdWRmbGFyZWFjY2Vzcy5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLI4c7uY6XgUheEy5Tn2RHvXF9YGm99El5\nq+GNMmv9hYvz46LlTbIHWDwoNr1fWDGbYy5rZVFIKifcva7N2GLsYIs7qB3kF7Cl\nFImRmgJXOdCFWS2trXwv6zE8qMCmbtq7CksEKbrxUxX/VTStAHwrh+s15q+exTg4\nw/3WViVrXqq0xgIMPB7QeXVafivAYRV6q/obeTjP9iR4aAae5Y4oBmk/P010uPcL\nupvotWFusEH7+wUqEb1wpokDTp5dQuLSprG2Bh1V/k4Z+rY8r4lxJJIkRYIwRmPz\nj6mi0txIdZdaHnM4Swfx19hnxK0fV49k7ukdjqpQHg55VebmHMtrAgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAHjPzx7HpdcxwTIADqWAy1Ms/LO/aE7WW3v4PgI6remU\nP5IQhcpZt9j7GkNPkG8ZP6r23crbPJ5aj4q0GCeFX/X8iMdJpQwuB/QwBcbKwKU3\n+X/+sPQyZfDwaFvqTcDSpCj1FqQ70uI66i6btbq/mkRWohihSuojIC/ylENwFOhq\netK8wblL08ddLlHYXI4g06gVshn9pa25NZSgA3okJu1mZHzAkxX+wuyTPn49ublP\nrkWqJDmenztHnXrZeVUufGx03YRQQNrYMRgtFdGOQRwM0GPEvzchMj7vDyxMyuw9\nOZ55B0Pd/Cg+IKvuwCldmh3iNaDW+vQ9Of5Ga7w74Ok=\n-----END CERTIFICATE-----\n"
                    }
                  ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let config = Config {
            api: server.url(),
            duration: 60 * 60 * 24,
        };

        // Create and initialize the manager using new()
        let manager = match Authenticator::new(config).await {
            Ok(manager) => manager,
            Err(e) => panic!("Failed to create DynamicConfigManager: {}", e),
        };

        // wait for the background task to fetch and update the apps
        tokio::time::sleep(Duration::from_secs(1)).await;

        let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3OTIyNWZjMjU3ZDU4MWQxYWNlZmMzMWQ1ZjZlZWFjOWMxNDU0ZjM0YWM1ZmM3ODMxMWExMjViYzJiYzE4M2MifQ.eyJhdWQiOlsiYTRiZWY3NzU2NDFjODRhMjFkYTUyMTM0MTY4OWM2MmYzODRhYTZmYjhlNGExZGNjMmZmZmZkMzQzOWRhYTgzZCJdLCJlbWFpbCI6Im5paGFvcGF1bEBnbWFpbC5jb20iLCJleHAiOjE3MzgxNzUwMTEsImlhdCI6MTczNTU0NzAxMSwibmJmIjoxNzM1NTQ3MDExLCJpc3MiOiJodHRwczovL25paGFvcGF1bC5jbG91ZGZsYXJlYWNjZXNzLmNvbSIsInR5cGUiOiJhcHAiLCJpZGVudGl0eV9ub25jZSI6IlBDOTdWZmRJZ0RzelFzODciLCJzdWIiOiIwODQ1ZDk2Ny04MGM1LTQzMTYtOGFlMy00YTY3NDQ4NWM1YTQiLCJjb3VudHJ5IjoiU0cifQ.aC3UTLE-Yd5_7qzWSQ8KEfiN1m6fvC_UyUq3Smk262jWKQxVtYCa-K_fMZ1GYOW__0mzc3j7xbAPEEx8FICFFmD9NK8xF5waxYAGHQKLXM18uYnV-d35G8WS3DFrHU59rXiMjxXzLVlj2bPKKPjdLSsHn8p4NwHweE29mswb_GLI0OmrJn_o_mM14WpsM0ZVy_Zjqws1QChm2_g8oDz81pGqiKOrgElgz_hd-A-d2qSbK05wJtWQOwd8j8sz3WbF9CJNQLCEj1UFcHFz6L7j6W2tfXaV_9zWTvQLKvfDB1TZVpuJ-iImX3SCoLLu_dikldAo0whDTD16BiDjBFgWiQ";
        let auds: Vec<String> = vec![
            "0e576496044ad490d0794329efc41931d3658e76e07fdab2a166085f34220f4".to_string(),
            "f097ff34ef52cf135a8cc1863c94776644c20e13c3e6df463f64618306f8262".to_string(),
            "4bef775641c84a21da521341689c62f384aa6fb8e4a1dcc2ffffd3439daa83d".to_string(),
            "06fb25724bb43a85ba83fa0b6c0c5958e640b626be78d87dd0b8787a07d2f00".to_string(),
            "eaf6f30860dea0276d63fbe3c1c8648da53a0354cf651643921a4f1fbeb2da2".to_string(),
        ];

        let test = manager.test(jwt, auds).await;

        assert_eq!(test.is_ok(), !test.is_err());
        mock.assert();
    }

    #[tokio::test]
    async fn test_fetch_certs_failure() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/cdn-cgi/access/certs")
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                  "keys": [
                    {
                      "kid": "179225fc257d581d1acefc31d5f6eeac9c1454f34ac5fc78311a125bc2bc183c",
                      "kty": "RSA",
                      "alg": "RS256",
                      "use": "sig",
                      "e": "AQAB",
                      "n": "mPb0s4zQJuyjlk9GNSGFVq2dNMrAXk_E-WYnv-0uBUkoxKQCjDpFnglxMeGW14GCo7KxnS2Lk8FTpKeFqFCF6Z_Nte-VmakMsW7QtPBk1WWiCwdRUbNdaBHDWAzrKzXUGPcnLtNpfJYFoawZsLZRPiY-rvVCEhfOX8ycb_NSdHDXNU5w3Y0aVSgLUzFVyVKkvmYzLgo62VbvWscTJ-19AaQV_dKE3cZpd13FvZEST1NsSRRZJ_75_YXeroxBw-YOamBipIRQwpdJHjlcISSv83svSctIwl8C60K32fZ5D5Pl9hiTQIx11zo6LU4Al7Tgd7I_h1aUzjPR7FSeVmZzhQ"
                    },
                    {
                      "kid": "6110ccf8fdddee78b239ceb42abe87c8712dc3041f34ed0876c246cbd7065cfd",
                      "kty": "RSA",
                      "alg": "RS256",
                      "use": "sig",
                      "e": "AQAB",
                      "n": "yyOHO7mOl4FIXhMuU59kR71xfWBpvfRJeavhjTJr_YWL8-Oi5U2yB1g8KDa9X1gxm2Mua2VRSCon3L2uzdhi7GCLO6gd5BewpRSJkZoCVznQhVktra18L-sxPKjApm7auwpLBCm68VMV_1U0rQB8K4frNeavnsU4OMP91lYla16qtMYCDDwe0Hl1Wn4rwGEVeqv6G3k4z_YkeGgGnuWOKAZpPz9NdLj3C7qb6LVhbrBB-_sFKhG9cKaJA06eXULi0qaxtgYdVf5OGfq2PK-JcSSSJEWCMEZj84-potLcSHWXWh5zOEsH8dfYZ8StH1ePZO7pHY6qUB4OeVXm5hzLaw"
                    }
                  ],
                  "public_cert": {
                    "kid": "179225fc257d581d1acefc31d5f6eeac9c1454f34ac5fc78311a125bc2bc183c",
                    "cert": "-----BEGIN CERTIFICATE-----\nMIIDTTCCAjWgAwIBAgIRAP8+7f1+s/N7hI7rj9VTeLQwDQYJKoZIhvcNAQELBQAw\nYjELMAkGA1UEBhMCVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4x\nEzARBgNVBAoTCkNsb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3Mu\nY29tMB4XDTI0MTEyMjE1MzAzNloXDTI1MTIwNjE1MzAzNlowYjELMAkGA1UEBhMC\nVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4xEzARBgNVBAoTCkNs\nb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3MuY29tMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmPb0s4zQJuyjlk9GNSGFVq2dNMrAXk/E\n+WYnv+0uBUkoxKQCjDpFnglxMeGW14GCo7KxnS2Lk8FTpKeFqFCF6Z/Nte+VmakM\nsW7QtPBk1WWiCwdRUbNdaBHDWAzrKzXUGPcnLtNpfJYFoawZsLZRPiY+rvVCEhfO\nX8ycb/NSdHDXNU5w3Y0aVSgLUzFVyVKkvmYzLgo62VbvWscTJ+19AaQV/dKE3cZp\nd13FvZEST1NsSRRZJ/75/YXeroxBw+YOamBipIRQwpdJHjlcISSv83svSctIwl8C\n60K32fZ5D5Pl9hiTQIx11zo6LU4Al7Tgd7I/h1aUzjPR7FSeVmZzhQIDAQABMA0G\nCSqGSIb3DQEBCwUAA4IBAQAaNa5bBdf9LBy0AtEU6OHQZdTiOLGFYVbzxaeEIE9f\nnoR8cNK6yTLHRKJ4brN0yfrTPLMPmg3/SZuI4O2D/jqJsUMiJWd9m10U3WuCe8Pu\nUmXQcAoqhy77P0JA6xmslw3V+7kDJEomy9vEeZ5TpjBSyI2/0scJb64V/mhvOfF7\njXeXIiA4Qpm5V4hy0qPGpabENVtmvGZSDZHZoADvl3hGcN2G5n7cyGg1t+kUdPnK\n38dGvvGvwoN5oosnpfi1iJvxsbAZdgVBpz2Q5vUvStb4cHYg5NSxzVMqckH3BKjP\neN1AoZMHOKfInSIdf9j6xN1kP4Q4EvScX+TXC9D2JUIx\n-----END CERTIFICATE-----\n"
                  },
                  "public_certs": [
                    {
                      "kid": "179225fc257d581d1acefc31d5f6eeac9c1454f34ac5fc78311a125bc2bc183c",
                      "cert": "-----BEGIN CERTIFICATE-----\nMIIDTTCCAjWgAwIBAgIRAP8+7f1+s/N7hI7rj9VTeLQwDQYJKoZIhvcNAQELBQAw\nYjELMAkGA1UEBhMCVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4x\nEzARBgNVBAoTCkNsb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3Mu\nY29tMB4XDTI0MTEyMjE1MzAzNloXDTI1MTIwNjE1MzAzNlowYjELMAkGA1UEBhMC\nVVMxDjAMBgNVBAgTBVRleGFzMQ8wDQYDVQQHEwZBdXN0aW4xEzARBgNVBAoTCkNs\nb3VkZmxhcmUxHTAbBgNVBAMTFGNsb3VkZmxhcmVhY2Nlc3MuY29tMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmPb0s4zQJuyjlk9GNSGFVq2dNMrAXk/E\n+WYnv+0uBUkoxKQCjDpFnglxMeGW14GCo7KxnS2Lk8FTpKeFqFCF6Z/Nte+VmakM\nsW7QtPBk1WWiCwdRUbNdaBHDWAzrKzXUGPcnLtNpfJYFoawZsLZRPiY+rvVCEhfO\nX8ycb/NSdHDXNU5w3Y0aVSgLUzFVyVKkvmYzLgo62VbvWscTJ+19AaQV/dKE3cZp\nd13FvZEST1NsSRRZJ/75/YXeroxBw+YOamBipIRQwpdJHjlcISSv83svSctIwl8C\n60K32fZ5D5Pl9hiTQIx11zo6LU4Al7Tgd7I/h1aUzjPR7FSeVmZzhQIDAQABMA0G\nCSqGSIb3DQEBCwUAA4IBAQAaNa5bBdf9LBy0AtEU6OHQZdTiOLGFYVbzxaeEIE9f\nnoR8cNK6yTLHRKJ4brN0yfrTPLMPmg3/SZuI4O2D/jqJsUMiJWd9m10U3WuCe8Pu\nUmXQcAoqhy77P0JA6xmslw3V+7kDJEomy9vEeZ5TpjBSyI2/0scJb64V/mhvOfF7\njXeXIiA4Qpm5V4hy0qPGpabENVtmvGZSDZHZoADvl3hGcN2G5n7cyGg1t+kUdPnK\n38dGvvGvwoN5oosnpfi1iJvxsbAZdgVBpz2Q5vUvStb4cHYg5NSxzVMqckH3BKjP\neN1AoZMHOKfInSIdf9j6xN1kP4Q4EvScX+TXC9D2JUIx\n-----END CERTIFICATE-----\n"
                    },
                    {
                      "kid": "6110ccf8fdddee78b239ceb42abe87c8712dc3041f34ed0876c246cbd7065cfd",
                      "cert": "-----BEGIN CERTIFICATE-----\nMIIDTDCCAjSgAwIBAgIQKxBEDYxED80GP0LK9Pt61zANBgkqhkiG9w0BAQsFADBi\nMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxDzANBgNVBAcTBkF1c3RpbjET\nMBEGA1UEChMKQ2xvdWRmbGFyZTEdMBsGA1UEAxMUY2xvdWRmbGFyZWFjY2Vzcy5j\nb20wHhcNMjQxMTIyMTUzMDM2WhcNMjUxMjA2MTUzMDM2WjBiMQswCQYDVQQGEwJV\nUzEOMAwGA1UECBMFVGV4YXMxDzANBgNVBAcTBkF1c3RpbjETMBEGA1UEChMKQ2xv\ndWRmbGFyZTEdMBsGA1UEAxMUY2xvdWRmbGFyZWFjY2Vzcy5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLI4c7uY6XgUheEy5Tn2RHvXF9YGm99El5\nq+GNMmv9hYvz46LlTbIHWDwoNr1fWDGbYy5rZVFIKifcva7N2GLsYIs7qB3kF7Cl\nFImRmgJXOdCFWS2trXwv6zE8qMCmbtq7CksEKbrxUxX/VTStAHwrh+s15q+exTg4\nw/3WViVrXqq0xgIMPB7QeXVafivAYRV6q/obeTjP9iR4aAae5Y4oBmk/P010uPcL\nupvotWFusEH7+wUqEb1wpokDTp5dQuLSprG2Bh1V/k4Z+rY8r4lxJJIkRYIwRmPz\nj6mi0txIdZdaHnM4Swfx19hnxK0fV49k7ukdjqpQHg55VebmHMtrAgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAHjPzx7HpdcxwTIADqWAy1Ms/LO/aE7WW3v4PgI6remU\nP5IQhcpZt9j7GkNPkG8ZP6r23crbPJ5aj4q0GCeFX/X8iMdJpQwuB/QwBcbKwKU3\n+X/+sPQyZfDwaFvqTcDSpCj1FqQ70uI66i6btbq/mkRWohihSuojIC/ylENwFOhq\netK8wblL08ddLlHYXI4g06gVshn9pa25NZSgA3okJu1mZHzAkxX+wuyTPn49ublP\nrkWqJDmenztHnXrZeVUufGx03YRQQNrYMRgtFdGOQRwM0GPEvzchMj7vDyxMyuw9\nOZ55B0Pd/Cg+IKvuwCldmh3iNaDW+vQ9Of5Ga7w74Ok=\n-----END CERTIFICATE-----\n"
                    }
                  ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let config = Config {
            api: server.url(),
            duration: 60 * 60 * 24,
        };

        // Create and initialize the manager using new()
        let manager = match Authenticator::new(config).await {
            Ok(manager) => manager,
            Err(e) => panic!("Failed to create DynamicConfigManager: {}", e),
        };

        // wait for the background task to fetch and update the apps
        tokio::time::sleep(Duration::from_secs(1)).await;

        let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3OTIyNWZjMjU3ZDU4MWQxYWNlZmMzMWQ1ZjZlZWFjOWMxNDU0ZjM0YWM1ZmM3ODMxMWExMjViYzJiYzE4M2MifQ.eyJhdWQiOlsiYTRiZWY3NzU2NDFjODRhMjFkYTUyMTM0MTY4OWM2MmYzODRhYTZmYjhlNGExZGNjMmZmZmZkMzQzOWRhYTgzZCJdLCJlbWFpbCI6Im5paGFvcGF1bEBnbWFpbC5jb20iLCJleHAiOjE3MzgxNzUwMTEsImlhdCI6MTczNTU0NzAxMSwibmJmIjoxNzM1NTQ3MDExLCJpc3MiOiJodHRwczovL25paGFvcGF1bC5jbG91ZGZsYXJlYWNjZXNzLmNvbSIsInR5cGUiOiJhcHAiLCJpZGVudGl0eV9ub25jZSI6IlBDOTdWZmRJZ0RzelFzODciLCJzdWIiOiIwODQ1ZDk2Ny04MGM1LTQzMTYtOGFlMy00YTY3NDQ4NWM1YTQiLCJjb3VudHJ5IjoiU0cifQ.aC3UTLE-Yd5_7qzWSQ8KEfiN1m6fvC_UyUq3Smk262jWKQxVtYCa-K_fMZ1GYOW__0mzc3j7xbAPEEx8FICFFmD9NK8xF5waxYAGHQKLXM18uYnV-d35G8WS3DFrHU59rXiMjxXzLVlj2bPKKPjdLSsHn8p4NwHweE29mswb_GLI0OmrJn_o_mM14WpsM0ZVy_Zjqws1QChm2_g8oDz81pGqiKOrgElgz_hd-A-d2qSbK05wJtWQOwd8j8sz3WbF9CJNQLCEj1UFcHFz6L7j6W2tfXaV_9zWTvQLKvfDB1TZVpuJ-iImX3SCoLLu_dikldAo0whDTD16BiDjBFgWiQ";
        let auds = vec![];

        let test = manager.test(jwt, auds).await;

        assert_eq!(test.is_err(), !test.is_ok());
        mock.assert();
    }
}
