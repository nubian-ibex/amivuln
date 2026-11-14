// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded HTTPS client (ADR-0004: reqwest with rustls and the `ring` provider).
//!
//! Only the URL and validator headers leave the host: no cookies, no referrer,
//! and a fixed `User-Agent`. Redirects are limited and never leave HTTPS.

use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RETRY_AFTER};
use reqwest::{Client, StatusCode, redirect};

use crate::resilience::{BreakerPolicy, Breakers, Limiter, Next, RetryPolicy};

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
    /// The endpoint is down for longer than the retry budget.
    #[error("{0} is down; the circuit breaker is open")]
    CircuitOpen(String),
}

/// A secret sent with every request of one client (an API key). It never shows
/// in `Debug` output.
#[derive(Clone)]
pub struct ApiKey {
    /// The header name, for example `apiKey`.
    pub header: String,
    /// The key.
    pub value: String,
}

impl core::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApiKey")
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
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
    /// Retry attempts on retriable failures (timeouts, 5xx, 429).
    pub retry: RetryPolicy,
    /// Circuit breaker thresholds per endpoint (host).
    pub breaker: BreakerPolicy,
    /// Minimum spacing between requests to one host, when set.
    pub min_interval: Option<Duration>,
    /// A key sent in a header with every request. Use a client of its own for
    /// the one service the key belongs to: it goes to every URL this client
    /// requests.
    pub api_key: Option<ApiKey>,
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
            retry: RetryPolicy::default(),
            breaker: BreakerPolicy::default(),
            min_interval: None,
            api_key: None,
        }
    }
}

/// The HTTP client.
#[derive(Debug, Clone)]
pub struct HttpClient {
    inner: Client,
    config: HttpConfig,
    breakers: std::sync::Arc<Mutex<Breakers>>,
    limiter: std::sync::Arc<Mutex<Limiter>>,
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
            // The first URL is checked in `execute`; this also stops a redirect
            // from an https URL to plain http, which `Policy::limited` follows.
            .https_only(!config.allow_insecure)
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
        if let Some(key) = &config.api_key {
            let invalid =
                || HttpError::Refused("the API key is not a valid header value".to_owned());
            let name = reqwest::header::HeaderName::from_bytes(key.header.as_bytes())
                .map_err(|_| invalid())?;
            let mut value =
                reqwest::header::HeaderValue::from_str(&key.value).map_err(|_| invalid())?;
            value.set_sensitive(true);
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(name, value);
            builder = builder.default_headers(headers);
        }
        let inner = builder
            .build()
            .map_err(|e| HttpError::Network(e.to_string()))?;
        let breakers = std::sync::Arc::new(Mutex::new(Breakers::new(config.breaker)));
        let limiter = std::sync::Arc::new(Mutex::new(Limiter::new(config.min_interval)));
        Ok(Self {
            inner,
            config,
            breakers,
            limiter,
        })
    }

    /// The endpoint a URL belongs to: scheme plus authority, so the circuit
    /// breaker and rate limiter treat each mirror as independent.
    fn endpoint(url: &str) -> String {
        url.split_once('/')
            .filter(|(scheme, _)| scheme.ends_with(':'))
            .map_or_else(
                || url.to_owned(),
                |(scheme, rest)| {
                    format!("{scheme}//{}", rest.split('/').next().unwrap_or_default())
                },
            )
    }

    /// Locks the breakers; a poisoned lock still hands out its contents.
    fn breakers(&self) -> std::sync::MutexGuard<'_, Breakers> {
        self.breakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn limiter(&self) -> std::sync::MutexGuard<'_, Limiter> {
        self.limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn record(&self, endpoint: &str, ok: bool) {
        if ok {
            self.breakers().success(endpoint);
        } else {
            self.breakers().failure(endpoint, Instant::now());
        }
    }

    /// Sends one request for `url`, with the circuit breaker, the retry
    /// policy (honoring `Retry-After`) and the per-host spacing. 5xx and 429
    /// are retried; a 4xx is handed to the caller untouched, since the
    /// endpoint answered and the same call would fail the same way.
    async fn execute(
        &self,
        url: &str,
        build: impl Fn(&Client) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, HttpError> {
        if !self.config.allow_insecure && !url.starts_with("https://") {
            return Err(HttpError::Refused(format!("{url} is not an https URL")));
        }
        let endpoint = Self::endpoint(url);
        let policy = self.config.retry;
        let mut attempt: u32 = 0;
        loop {
            if !self.breakers().allow(&endpoint, Instant::now()) {
                return Err(HttpError::CircuitOpen(endpoint.clone()));
            }
            let wait_for_slot = self.limiter().reserve(&endpoint, Instant::now());
            if wait_for_slot > Duration::ZERO {
                tokio::time::sleep(wait_for_slot).await;
            }

            match build(&self.inner).send().await {
                Ok(response) => {
                    let status = response.status();
                    let retry_after = if status == StatusCode::TOO_MANY_REQUESTS {
                        Some(
                            response
                                .headers()
                                .get(RETRY_AFTER)
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.trim().parse::<u64>().ok()),
                        )
                    } else if status.is_server_error() {
                        Some(None)
                    } else {
                        // Answered correctly: the circuit stays closed and
                        // the caller maps the status (200, 304, an error).
                        self.record(&endpoint, true);
                        return Ok(response);
                    };
                    match policy.next(attempt, retry_after.flatten(), jitter(url, attempt + 1)) {
                        Next::Wait(wait) => {
                            tokio::time::sleep(wait).await;
                            attempt += 1;
                        }
                        Next::GiveUp => {
                            // One failing call is one breaker failure, no
                            // matter how many attempts it took.
                            self.record(&endpoint, false);
                            return Err(if status == StatusCode::TOO_MANY_REQUESTS {
                                HttpError::RateLimited(retry_after.unwrap_or_default())
                            } else {
                                HttpError::Server(status.as_u16())
                            });
                        }
                    }
                }
                Err(e) => match policy.next(attempt, None, jitter(url, attempt + 1)) {
                    Next::Wait(wait) => {
                        tokio::time::sleep(wait).await;
                        attempt += 1;
                    }
                    Next::GiveUp => {
                        self.record(&endpoint, false);
                        return Err(map_error(e));
                    }
                },
            }
        }
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
        let response = self
            .execute(url, |client| {
                let req = client
                    .post(url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.to_owned());
                if let Some(token) = bearer {
                    req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                } else {
                    req
                }
            })
            .await?;
        Self::finish(response, self.config.max_body).await
    }

    /// GET `url`, optionally conditional on `validators`.
    ///
    /// # Errors
    ///
    /// See [`HttpError`]. 429 and 5xx are reported as such so callers can fall
    /// back to cached data.
    pub async fn get(&self, url: &str, validators: &Validators) -> Result<Response, HttpError> {
        let response = self
            .execute(url, |client| {
                let mut req = client.get(url);
                if let Some(etag) = &validators.etag {
                    req = req.header(IF_NONE_MATCH, etag);
                }
                if let Some(lm) = &validators.last_modified {
                    req = req.header(IF_MODIFIED_SINCE, lm);
                }
                req
            })
            .await?;
        Self::finish(response, self.config.max_body).await
    }

    /// Streams `url` into `out`, with the usual checks. Returns the byte count.
    ///
    /// # Errors
    ///
    /// See [`HttpError`]. Bodies above 4 GiB are refused.
    pub async fn download(&self, url: &str, out: &mut dyn Write) -> Result<u64, HttpError> {
        let response = self.execute(url, |client| client.get(url)).await?;
        if !response.status().is_success() {
            return Err(HttpError::Status(response.status().as_u16()));
        }
        let limit: u64 = 4 * 1024 * 1024 * 1024;
        let mut copied: u64 = 0;
        let mut response = response;
        while let Some(chunk) = response
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
/// A deterministic per-URL jitter (per mille of the delay to subtract), so
/// clients that failed together spread out without another dependency.
fn jitter(url: &str, salt: u32) -> u64 {
    use std::hash::{DefaultHasher, Hasher};
    let mut hasher = DefaultHasher::new();
    hasher.write(url.as_bytes());
    hasher.write(&salt.to_le_bytes());
    hasher.finish() % 1001
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
    async fn redirects_are_still_followed_when_plain_http_is_allowed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/old"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/new"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/new"))
            .respond_with(ResponseTemplate::new(200).set_body_string("moved"))
            .mount(&server)
            .await;
        let client = HttpClient::new(plain()).unwrap();
        let r = client
            .get(&format!("{}/old", server.uri()), &Validators::default())
            .await
            .unwrap();
        assert!(matches!(r, Response::Fresh { ref body, .. } if body == b"moved"));
    }

    #[tokio::test]
    async fn a_plain_http_url_is_refused_by_default() {
        let client = HttpClient::new(HttpConfig::default()).unwrap();
        let err = client
            .get("http://127.0.0.1:9/x", &Validators::default())
            .await
            .unwrap_err();
        assert!(matches!(err, HttpError::Refused(_)), "{err:?}");
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

#[cfg(test)]
mod resilience_tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::resilience::RetryPolicy;

    fn base() -> HttpConfig {
        HttpConfig {
            allow_insecure: true,
            ..HttpConfig::default()
        }
    }

    fn fast() -> HttpConfig {
        HttpConfig {
            allow_insecure: true,
            retry: RetryPolicy {
                retries: 2,
                base: Duration::from_millis(1),
                max_wait: Duration::from_millis(20),
            },
            ..base()
        }
    }

    #[tokio::test]
    async fn retries_5xx_until_it_works() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_string("finally"))
            .mount(&server)
            .await;
        let client = HttpClient::new(fast()).unwrap();
        let r = client
            .get(&format!("{}/x", server.uri()), &Validators::default())
            .await;
        assert!(
            matches!(&r, Ok(Response::Fresh { body, .. }) if body == b"finally"),
            "{r:?}"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn retry_after_zero_is_honored_without_a_long_stop() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(
                ResponseTemplate::new(429)
                    .append_header("retry-after", "0")
                    .set_body_string("later"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        let client = HttpClient::new(fast()).unwrap();
        let r = client
            .get(&format!("{}/x", server.uri()), &Validators::default())
            .await;
        assert!(
            matches!(&r, Ok(Response::Fresh { body, .. }) if body == b"ok"),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn a_4xx_is_never_retried() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        let client = HttpClient::new(fast()).unwrap();
        let r = client
            .get(&format!("{}/x", server.uri()), &Validators::default())
            .await;
        assert!(matches!(r, Err(HttpError::Status(404))), "{r:?}");
    }

    #[tokio::test]
    async fn the_breaker_skips_calls_shortly_after_the_budget_is_spent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(503))
            .expect(2)
            .mount(&server)
            .await;
        // Two calls reach the server and burn the retry budget; the third is
        // refused by the breaker without touching it (one failed call = one
        // breaker failure, and the threshold here is 2).
        let client = HttpClient::new(HttpConfig {
            retry: RetryPolicy {
                retries: 0,
                ..RetryPolicy::default()
            },
            breaker: crate::resilience::BreakerPolicy {
                threshold: 2,
                cooldown: Duration::from_secs(30),
            },
            ..fast()
        })
        .unwrap();
        let url = format!("{}/x", server.uri());
        for _ in 0..2 {
            let r = client.get(&url, &Validators::default()).await;
            assert!(matches!(r, Err(HttpError::Server(503))), "{r:?}");
        }
        let r = client.get(&url, &Validators::default()).await;
        assert!(matches!(r, Err(HttpError::CircuitOpen(_))), "{r:?}");
    }
}
