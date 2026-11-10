// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded HTTPS client (ADR-0004: reqwest with rustls and the `ring` provider).
//!
//! Only the URL and validator headers leave the host: no cookies, no referrer,
//! and a fixed `User-Agent`. Redirects are limited and never leave HTTPS.

use std::io::Write;
use std::time::Duration;

use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RETRY_AFTER};
use reqwest::{Client, StatusCode, redirect};

/// Validators sent to make a request conditional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    /// Value for `If-None-Match`.
    pub etag: Option<String>,
    /// Value for `If-Modified-Since`.
    pub last_modified: Option<String>,
}

/// A response the caller can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// 200 with a body.
    Fresh {
        /// Response body (at most the configured limit).
        body: Vec<u8>,
        /// `ETag` header.
        etag: Option<String>,
        /// `Last-Modified` header.
        last_modified: Option<String>,
    },
    /// 304: the cached copy is still current.
    NotModified,
}

/// Why a request failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpError {
    /// The server asked us to slow down.
    #[error("rate limited by the server{}", .0.map(|s| format!(" (retry after {s} s)")).unwrap_or_default())]
    RateLimited(Option<u64>),
    /// 5xx response.
    #[error("server error: HTTP {0}")]
    Server(u16),
    /// Any other unexpected status.
    #[error("unexpected HTTP status {0}")]
    Status(u16),
    /// The body is larger than the limit.
    #[error("response is larger than the {0} byte limit")]
    TooLarge(usize),
    /// The request timed out.
    #[error("request timed out")]
    Timeout,
    /// Connection, TLS or protocol failure.
    #[error("network error: {0}")]
    Network(String),
    /// Refused before sending (for example a non-HTTPS URL).
    #[error("refused: {0}")]
    Refused(String),
}

/// Client configuration.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Per-request timeout.
    pub timeout: Duration,
    /// Maximum accepted body size in bytes.
    pub max_body: usize,
    /// Accept plain `http://` URLs. Only for tests against a local mock server.
    pub allow_insecure: bool,
    /// Explicit proxy URL (`http://` or `https://`), used for every request.
    /// Without it the usual `HTTPS_PROXY`/`NO_PROXY` variables apply.
    pub proxy: Option<String>,
    /// Extra trusted root certificates, PEM encoded (a corporate CA).
    pub ca_pem: Option<Vec<u8>>,
    /// Text appended to the `User-Agent`, for example a team tag.
    pub user_agent_suffix: Option<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_body: 32 * 1024 * 1024,
            allow_insecure: false,
            proxy: None,
            ca_pem: None,
            user_agent_suffix: None,
        }
    }
}

/// The HTTP client.
#[derive(Debug, Clone)]
pub struct HttpClient {
    inner: Client,
    config: HttpConfig,
}

/// Installs the `ring` crypto provider once; later calls are no-ops.
fn ensure_crypto_provider() {
    // Err means a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl HttpClient {
    /// Builds a client.
    ///
    /// # Errors
    ///
    /// Fails when the TLS backend cannot be initialised.
    pub fn new(config: HttpConfig) -> Result<Self, HttpError> {
        ensure_crypto_provider();
        let agent = match config.user_agent_suffix.as_deref() {
            Some(suffix) => format!("amivuln/{} {suffix}", env!("CARGO_PKG_VERSION")),
            None => concat!("amivuln/", env!("CARGO_PKG_VERSION")).to_owned(),
        };
        let mut builder = Client::builder()
            .user_agent(agent)
            .timeout(config.timeout)
            .redirect(redirect::Policy::limited(3))
            .referer(false);
        if let Some(url) = &config.proxy {
            // The URL may carry credentials, so the error never repeats it.
            let proxy = reqwest::Proxy::all(url.as_str())
                .map_err(|_| HttpError::Refused("the proxy URL is not valid".to_owned()))?;
            builder = builder.proxy(proxy);
        }
        if let Some(pem) = &config.ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|e| HttpError::Refused(format!("the CA file is not valid PEM: {e}")))?;
            if certs.is_empty() {
                return Err(HttpError::Refused(
                    "the CA file holds no certificate".to_owned(),
                ));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        let inner = builder
            .build()
            .map_err(|e| HttpError::Network(e.to_string()))?;
        Ok(Self { inner, config })
    }

    /// POST `body` as `application/json` to `url`.
    ///
    /// # Errors
    ///
    /// See [`HttpError`].
    pub async fn post(&self, url: &str, body: &str) -> Result<Response, HttpError> {
        self.post_bearer(url, body, None).await
    }

    /// POST `body` as `application/json`, optionally with a bearer token.
    ///
    /// # Errors
    ///
    /// See [`HttpError`].
    pub async fn post_bearer(
        &self,
        url: &str,
        body: &str,
        bearer: Option<&str>,
    ) -> Result<Response, HttpError> {
        if !self.config.allow_insecure && !url.starts_with("https://") {
            return Err(HttpError::Refused(format!("{url} is not an https URL")));
        }
        let mut req = self
            .inner
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_owned());
        if let Some(token) = bearer {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let resp = req.send().await.map_err(map_error)?;
        Self::finish(resp, self.config.max_body).await
    }

    /// GET `url`, optionally conditional on `validators`.
    ///
    /// # Errors
    ///
    /// See [`HttpError`]. 429 and 5xx are reported as such so callers can fall
    /// back to cached data.
    pub async fn get(&self, url: &str, validators: &Validators) -> Result<Response, HttpError> {
        if !self.config.allow_insecure && !url.starts_with("https://") {
            return Err(HttpError::Refused(format!("{url} is not an https URL")));
        }
        let mut req = self.inner.get(url);
        if let Some(etag) = &validators.etag {
            req = req.header(IF_NONE_MATCH, etag);
        }
        if let Some(lm) = &validators.last_modified {
            req = req.header(IF_MODIFIED_SINCE, lm);
        }
        let resp = req.send().await.map_err(map_error)?;
        Self::finish(resp, self.config.max_body).await
    }

    /// Streams `url` into `out`, with the usual checks. Returns the byte count.
    ///
    /// # Errors
    ///
    /// See [`HttpError`]. Bodies above 4 GiB are refused.
    pub async fn download(&self, url: &str, out: &mut dyn Write) -> Result<u64, HttpError> {
        if !self.config.allow_insecure && !url.starts_with("https://") {
            return Err(HttpError::Refused(format!("{url} is not an https URL")));
        }
        let mut resp = self.inner.get(url).send().await.map_err(map_error)?;
        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let secs = resp
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok());
            return Err(HttpError::RateLimited(secs));
        }
        if status.is_client_error() || status.is_server_error() {
            return Err(HttpError::Status(status.as_u16()));
        }
        if !status.is_success() {
            return Err(HttpError::Status(status.as_u16()));
        }
        let limit: u64 = 4 * 1024 * 1024 * 1024;
        let mut copied: u64 = 0;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| HttpError::Network(e.to_string()))?
        {
            copied += chunk.len() as u64;
            if copied > limit {
                let small = usize::try_from(limit).unwrap_or(usize::MAX);
                return Err(HttpError::TooLarge(small));
            }
            out.write_all(chunk.as_ref())
                .map_err(|e| HttpError::Network(e.to_string()))?;
        }
        Ok(copied)
    }

    /// Shared response handling: status mapping and the body cap.
    async fn finish(mut resp: reqwest::Response, max_body: usize) -> Result<Response, HttpError> {
        let status = resp.status();
        match status {
            StatusCode::NOT_MODIFIED => return Ok(Response::NotModified),
            StatusCode::TOO_MANY_REQUESTS => {
                let secs = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse().ok());
                return Err(HttpError::RateLimited(secs));
            }
            s if s.is_server_error() => return Err(HttpError::Server(s.as_u16())),
            StatusCode::OK => {}
            s => return Err(HttpError::Status(s.as_u16())),
        }

        let header = |name| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let etag = header(ETAG);
        let last_modified = header(LAST_MODIFIED);

        // Reject early when the server announces an oversized body, then
        // enforce the limit while streaming for servers that do not.
        if resp
            .content_length()
            .is_some_and(|n| usize::try_from(n).map_or(true, |n| n > max_body))
        {
            return Err(HttpError::TooLarge(max_body));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(map_error)? {
            if body.len() + chunk.len() > max_body {
                return Err(HttpError::TooLarge(max_body));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response::Fresh {
            body,
            etag,
            last_modified,
        })
    }
}
fn map_error(e: reqwest::Error) -> HttpError {
    if e.is_timeout() {
        HttpError::Timeout
    } else {
        // Without the URL: error text may be shown to users and logs.
        HttpError::Network(e.without_url().to_string())
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn plain() -> HttpConfig {
        HttpConfig {
            allow_insecure: true,
            ..HttpConfig::default()
        }
    }

    #[tokio::test]
    async fn the_user_agent_suffix_is_appended() {
        let server = MockServer::start().await;
        let ua = format!("amivuln/{} team-sre", env!("CARGO_PKG_VERSION"));
        Mock::given(method("GET"))
            .and(path("/x"))
            .and(header("user-agent", ua.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .expect(1)
            .mount(&server)
            .await;
        let client = HttpClient::new(HttpConfig {
            user_agent_suffix: Some("team-sre".to_owned()),
            ..plain()
        })
        .unwrap();
        let r = client
            .get(&format!("{}/x", server.uri()), &Validators::default())
            .await;
        assert!(matches!(r, Ok(Response::Fresh { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn an_explicit_proxy_carries_the_request() {
        // The target host does not exist: only the proxy can answer.
        let proxy = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_string("via proxy"))
            .expect(1)
            .mount(&proxy)
            .await;
        let client = HttpClient::new(HttpConfig {
            proxy: Some(proxy.uri()),
            ..plain()
        })
        .unwrap();
        let r = client
            .get("http://source.invalid/x", &Validators::default())
            .await;
        assert!(
            matches!(&r, Ok(Response::Fresh { body, .. }) if body == b"via proxy"),
            "{r:?}"
        );
    }

    #[test]
    fn a_valid_ca_bundle_is_accepted() {
        // Throwaway self-signed certificate, generated for this test only.
        let pem = include_str!("../../../tests/fixtures/ca/test-ca.pem");
        assert!(
            HttpClient::new(HttpConfig {
                ca_pem: Some(pem.as_bytes().to_vec()),
                ..HttpConfig::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn a_bad_proxy_or_ca_is_refused_without_echoing_secrets() {
        let e = HttpClient::new(HttpConfig {
            proxy: Some("not a url with user:secret@".to_owned()),
            ..HttpConfig::default()
        })
        .unwrap_err();
        assert!(!e.to_string().contains("secret"), "{e}");
        let e = HttpClient::new(HttpConfig {
            ca_pem: Some(b"definitely not pem".to_vec()),
            ..HttpConfig::default()
        })
        .unwrap_err();
        assert!(matches!(e, HttpError::Refused(_)), "{e:?}");
    }
}
