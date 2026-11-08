// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded HTTPS client (ADR-0004: reqwest with rustls and the `ring` provider).
//!
//! Only the URL and validator headers leave the host: no cookies, no referrer,
//! and a fixed `User-Agent`. Redirects are limited and never leave HTTPS.

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
#[derive(Debug, Clone, Copy)]
pub struct HttpConfig {
    /// Per-request timeout.
    pub timeout: Duration,
    /// Maximum accepted body size in bytes.
    pub max_body: usize,
    /// Accept plain `http://` URLs. Only for tests against a local mock server.
    pub allow_insecure: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_body: 32 * 1024 * 1024,
            allow_insecure: false,
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
        let inner = Client::builder()
            .user_agent(concat!("amivuln/", env!("CARGO_PKG_VERSION")))
            .timeout(config.timeout)
            .redirect(redirect::Policy::limited(3))
            .referer(false)
            .build()
            .map_err(|e| HttpError::Network(e.to_string()))?;
        Ok(Self { inner, config })
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
        let mut resp = req.send().await.map_err(map_error)?;
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
            .is_some_and(|n| usize::try_from(n).map_or(true, |n| n > self.config.max_body))
        {
            return Err(HttpError::TooLarge(self.config.max_body));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(map_error)? {
            if body.len() + chunk.len() > self.config.max_body {
                return Err(HttpError::TooLarge(self.config.max_body));
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
