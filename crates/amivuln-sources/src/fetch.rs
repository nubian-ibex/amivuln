// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cache-aware fetching with an honest source status.
//!
//! Order of preference: fresh cache, then the network (conditional when a
//! cached copy exists), then a stale cached copy within `stale_max_age`. The
//! caller always learns which of these produced the data.

use core::time::Duration;

use amivuln_cache::{Cache, CacheError, Lookup, Policy};
use amivuln_core::SourceStatus;

use crate::http::{HttpClient, HttpError, Response, Validators};

/// Data plus where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// Response body.
    pub body: Vec<u8>,
    /// [`SourceStatus::Ok`] for fresh data, [`SourceStatus::Stale`] for a
    /// stale cache fallback.
    pub status: SourceStatus,
    /// Age of the data.
    pub age: Duration,
}

/// No usable data could be produced.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// Offline mode and nothing usable in the cache.
    #[error("offline and no cached copy within the allowed age")]
    Offline,
    /// The network failed and there is no usable cached copy.
    #[error("source unavailable and no usable cache: {0}")]
    Unavailable(#[from] HttpError),
    /// The cache itself failed.
    #[error(transparent)]
    Cache(#[from] CacheError),
}

fn age(now: i64, fetched_at: i64) -> Duration {
    Duration::from_secs(u64::try_from(now.saturating_sub(fetched_at)).unwrap_or(0))
}

/// Fetches `url` with `GET`, using `cache` under `key`.
///
/// `now` is Unix seconds from the caller's clock. With `offline` the network
/// is never touched.
///
/// # Errors
///
/// [`FetchError::Offline`] when offline without a usable copy,
/// [`FetchError::Unavailable`] when the request fails and no cached copy is
/// within `stale_max_age`.
/// Everything [`fetch_cached`] needs.
#[derive(Debug, Clone, Copy)]
pub struct FetchCtx<'a> {
    /// HTTP client.
    pub http: &'a HttpClient,
    /// Cache.
    pub cache: &'a Cache,
    /// Current Unix time.
    pub now: i64,
    /// Freshness limits.
    pub policy: Policy,
    /// Never touch the network.
    pub offline: bool,
}

/// Fetches `url` with `GET`, using `cache` under `key`.
///
/// # Errors
///
/// [`FetchError::Offline`] when offline without a usable copy,
/// [`FetchError::Unavailable`] when the request fails and no cached copy is
/// within `stale_max_age`.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_cached(
    http: &HttpClient,
    cache: &Cache,
    key: &str,
    url: &str,
    now: i64,
    policy: Policy,
    offline: bool,
) -> Result<Fetched, FetchError> {
    let ctx = FetchCtx {
        http,
        cache,
        now,
        policy,
        offline,
    };
    fetch_cached_body(&ctx, key, url, None).await
}

/// Fetches `url`, `POST`ing `body` when given (an API that takes a request
/// document). The cache key must already encode the body; responses to POST
/// are cached only because the key is deterministic.
///
/// # Errors
///
/// [`FetchError::Offline`] when offline without a usable copy,
/// [`FetchError::Unavailable`] when the request fails and no cached copy is
/// within `stale_max_age`.
pub async fn fetch_cached_body(
    ctx: &FetchCtx<'_>,
    key: &str,
    url: &str,
    body: Option<&str>,
) -> Result<Fetched, FetchError> {
    let FetchCtx {
        http,
        cache,
        now,
        policy,
        offline,
    } = *ctx;
    let lookup = cache.get(key, now, policy)?;
    if let Lookup::Fresh(e) = &lookup {
        return Ok(Fetched {
            body: e.body.clone(),
            status: SourceStatus::Ok,
            age: age(now, e.fetched_at),
        });
    }
    if offline {
        return match lookup {
            Lookup::Stale(e) => Ok(Fetched {
                age: age(now, e.fetched_at),
                body: e.body,
                status: SourceStatus::Stale,
            }),
            _ => Err(FetchError::Offline),
        };
    }

    let validators = match &lookup {
        Lookup::Stale(e) | Lookup::Expired(e) => Validators {
            etag: e.etag.clone(),
            last_modified: e.last_modified.clone(),
        },
        _ => Validators::default(),
    };

    let response = match body {
        Some(body) => http.post(url, body).await,
        None => http.get(url, &validators).await,
    };
    match response {
        Ok(Response::Fresh {
            body,
            etag,
            last_modified,
        }) => {
            cache.put(key, &body, etag.as_deref(), last_modified.as_deref(), now)?;
            Ok(Fetched {
                body,
                status: SourceStatus::Ok,
                age: Duration::ZERO,
            })
        }
        Ok(Response::NotModified) => match lookup {
            Lookup::Stale(e) | Lookup::Expired(e) => {
                cache.touch(key, now)?;
                Ok(Fetched {
                    body: e.body,
                    status: SourceStatus::Ok,
                    age: Duration::ZERO,
                })
            }
            // A 304 we never asked for: treat as a protocol failure.
            _ => Err(HttpError::Status(304).into()),
        },
        Err(err) => match lookup {
            Lookup::Stale(e) => Ok(Fetched {
                age: age(now, e.fetched_at),
                body: e.body,
                status: SourceStatus::Stale,
            }),
            _ => Err(err.into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpConfig;
    use std::fmt::Write as _;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const POLICY: Policy = Policy {
        ttl: 100,
        stale_max_age: 1000,
    };

    fn client(timeout_ms: u64, max_body: usize) -> HttpClient {
        HttpClient::new(HttpConfig {
            timeout: Duration::from_millis(timeout_ms),
            max_body,
            allow_insecure: true,
            ..HttpConfig::default()
        })
        .unwrap()
    }

    fn default_client() -> HttpClient {
        client(2000, 1024 * 1024)
    }

    #[tokio::test]
    async fn miss_fetches_then_fresh_cache_skips_the_network() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/data"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("hello")
                    .insert_header("etag", "\"v1\""),
            )
            .expect(1)
            .mount(&server)
            .await;
        let cache = Cache::in_memory().unwrap();
        let url = format!("{}/data", server.uri());
        let http = default_client();

        let a = fetch_cached(&http, &cache, "k", &url, 1000, POLICY, false)
            .await
            .unwrap();
        assert_eq!(
            (a.body.as_slice(), a.status.clone()),
            (&b"hello"[..], SourceStatus::Ok)
        );
        let b = fetch_cached(&http, &cache, "k", &url, 1050, POLICY, false)
            .await
            .unwrap();
        assert_eq!(b.body, b"hello");
        assert_eq!(b.age, Duration::from_secs(50));
        // `expect(1)` verifies on drop that the second call did not hit the server.
    }

    #[tokio::test]
    async fn stale_entry_is_revalidated_with_etag_and_304_refreshes_it() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("if-none-match", "\"v1\""))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;
        let cache = Cache::in_memory().unwrap();
        cache.put("k", b"cached", Some("\"v1\""), None, 0).unwrap();
        let url = format!("{}/x", server.uri());

        let r = fetch_cached(&default_client(), &cache, "k", &url, 500, POLICY, false)
            .await
            .unwrap();
        assert_eq!(r.body, b"cached");
        assert_eq!(r.status, SourceStatus::Ok);
        assert!(matches!(
            cache.get("k", 500, POLICY).unwrap(),
            Lookup::Fresh(_)
        ));
    }

    #[tokio::test]
    async fn server_error_falls_back_to_stale_but_never_to_expired() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let cache = Cache::in_memory().unwrap();
        cache.put("k", b"old", None, None, 0).unwrap();
        let url = format!("{}/x", server.uri());
        let http = default_client();

        let stale = fetch_cached(&http, &cache, "k", &url, 500, POLICY, false)
            .await
            .unwrap();
        assert_eq!(stale.status, SourceStatus::Stale);
        assert_eq!(stale.body, b"old");

        let expired = fetch_cached(&http, &cache, "k", &url, 5000, POLICY, false).await;
        assert!(matches!(
            expired,
            Err(FetchError::Unavailable(HttpError::Server(503)))
        ));
        let miss = fetch_cached(&http, &cache, "other", &url, 5000, POLICY, false).await;
        assert!(matches!(
            miss,
            Err(FetchError::Unavailable(HttpError::Server(503)))
        ));
    }

    #[tokio::test]
    async fn offline_never_touches_the_network() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let cache = Cache::in_memory().unwrap();
        cache.put("k", b"old", None, None, 0).unwrap();
        let url = format!("{}/x", server.uri());
        let http = default_client();

        let r = fetch_cached(&http, &cache, "k", &url, 500, POLICY, true)
            .await
            .unwrap();
        assert_eq!(r.status, SourceStatus::Stale);
        assert!(matches!(
            fetch_cached(&http, &cache, "missing", &url, 500, POLICY, true).await,
            Err(FetchError::Offline)
        ));
        assert!(matches!(
            fetch_cached(&http, &cache, "k", &url, 5000, POLICY, true).await,
            Err(FetchError::Offline)
        ));
    }

    #[tokio::test]
    async fn rate_limit_reports_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
            .mount(&server)
            .await;
        let r = default_client()
            .get(&format!("{}/x", server.uri()), &Validators::default())
            .await;
        assert_eq!(r, Err(HttpError::RateLimited(Some(7))));
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 5000]))
            .mount(&server)
            .await;
        let r = client(2000, 1000)
            .get(&format!("{}/x", server.uri()), &Validators::default())
            .await;
        assert_eq!(r, Err(HttpError::TooLarge(1000)));
    }

    #[tokio::test]
    async fn slow_server_times_out() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(500)))
            .mount(&server)
            .await;
        let r = client(50, 1024)
            .get(&format!("{}/x", server.uri()), &Validators::default())
            .await;
        assert_eq!(r, Err(HttpError::Timeout));
    }

    #[tokio::test]
    async fn plain_http_is_refused_by_default() {
        let strict = HttpClient::new(HttpConfig::default()).unwrap();
        let r = strict
            .get("http://example.invalid/x", &Validators::default())
            .await;
        assert!(matches!(r, Err(HttpError::Refused(_))));
    }

    #[tokio::test]
    async fn other_statuses_are_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let r = default_client()
            .get(&format!("{}/x", server.uri()), &Validators::default())
            .await;
        assert_eq!(r, Err(HttpError::Status(404)));
    }

    /// Privacy: a request carries the URL, a fixed user agent and validators,
    /// and nothing that identifies the host or the user.
    #[tokio::test]
    async fn requests_do_not_leak_host_identity() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        let _ = default_client()
            .get(
                &format!("{}/issues/all.json", server.uri()),
                &Validators::default(),
            )
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap_or_default();
        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        let mut wire = format!("{} {}\n", req.method, req.url.path());
        for (name, value) in &req.headers {
            let _ = writeln!(wire, "{name}: {}", value.to_str().unwrap_or(""));
        }
        wire.push_str(&String::from_utf8_lossy(&req.body));

        assert_eq!(req.url.path(), "/issues/all.json");
        let ua = req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ua.starts_with("amivuln/"), "{ua}");
        for forbidden in identity_strings() {
            assert!(
                !wire.contains(&forbidden),
                "request leaks {forbidden:?}: {wire}"
            );
        }
        assert!(req.headers.get("cookie").is_none());
        assert!(req.headers.get("referer").is_none());
        assert!(req.headers.get("authorization").is_none());
    }

    /// Host name, user name and working directory of this process.
    fn identity_strings() -> Vec<String> {
        let mut v = Vec::new();
        if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
            v.push(h.trim().to_owned());
        }
        for var in ["USER", "LOGNAME", "HOME"] {
            if let Ok(x) = std::env::var(var) {
                v.push(x);
            }
        }
        if let Ok(d) = std::env::current_dir() {
            v.push(d.display().to_string());
        }
        v.retain(|s| s.len() >= 3 && s != "localhost" && s != "/");
        v
    }
}
