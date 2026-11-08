// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SQLite-backed HTTP cache (ADR-0005).
//!
//! Entries carry the validators (`ETag`, `Last-Modified`) so callers can
//! revalidate, and the cache classifies each lookup against two ages: the TTL
//! (fresh) and `stale_max_age` (still usable when the network fails). Time is
//! always passed in as Unix seconds so tests control the clock.

#![forbid(unsafe_code)]

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

/// Largest body the cache accepts for one entry.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Schema version stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 1;

/// Cache failures.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// SQLite reported an error.
    #[error("cache database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The database was written by a newer amivuln.
    #[error(
        "cache schema version {0} is newer than this amivuln supports ({SCHEMA_VERSION}); run `amivuln cache clear`"
    )]
    NewerSchema(i64),
    /// The body exceeds [`MAX_BODY_BYTES`].
    #[error("refusing to cache a {0} byte body (limit {MAX_BODY_BYTES})")]
    BodyTooLarge(usize),
    /// Creating the cache directory or setting permissions failed.
    #[error("cache directory error: {0}")]
    Io(#[from] std::io::Error),
}

/// A cached response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Response body.
    pub body: Vec<u8>,
    /// `ETag` validator, when the server sent one.
    pub etag: Option<String>,
    /// `Last-Modified` validator, when the server sent one.
    pub last_modified: Option<String>,
    /// Unix seconds when the body was last confirmed current.
    pub fetched_at: i64,
}

/// Freshness limits, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Entries younger than this are fresh.
    pub ttl: i64,
    /// Entries up to this age may still be served when the source is down.
    pub stale_max_age: i64,
}

/// Result of a lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// Nothing cached.
    Miss,
    /// Within the TTL: use without asking the network.
    Fresh(Entry),
    /// Past the TTL but within `stale_max_age`: revalidate, fall back to this.
    Stale(Entry),
    /// Older than `stale_max_age`: only the validators are useful.
    Expired(Entry),
}

/// Counts for `amivuln cache info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    /// Number of entries.
    pub entries: u64,
    /// Total body bytes.
    pub bytes: u64,
}

/// The cache handle.
#[derive(Debug)]
pub struct Cache {
    conn: Connection,
}

impl Cache {
    /// Opens (creating if needed) the database at `path`.
    ///
    /// On Unix the parent directory is created with mode 0700 and the file is
    /// restricted to 0600.
    ///
    /// # Errors
    ///
    /// Fails on I/O errors, SQLite errors or a newer schema.
    pub fn open(path: &Path) -> Result<Self, CacheError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            create_private_dir(dir)?;
        }
        let conn = Connection::open(path)?;
        restrict_file(path)?;
        Self::init(conn)
    }

    /// Opens an in-memory cache (tests).
    ///
    /// # Errors
    ///
    /// Fails on SQLite errors.
    pub fn in_memory() -> Result<Self, CacheError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, CacheError> {
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(CacheError::NewerSchema(version));
        }
        if version < 1 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS http_cache (
                     key           TEXT PRIMARY KEY NOT NULL,
                     body          BLOB NOT NULL,
                     etag          TEXT,
                     last_modified TEXT,
                     fetched_at    INTEGER NOT NULL
                 ) WITHOUT ROWID;
                 PRAGMA user_version = 1;",
            )?;
        }
        Ok(Self { conn })
    }

    /// Classifies the cached entry for `key` at time `now`.
    ///
    /// # Errors
    ///
    /// Fails on SQLite errors.
    pub fn get(&self, key: &str, now: i64, policy: Policy) -> Result<Lookup, CacheError> {
        let entry = self
            .conn
            .query_row(
                "SELECT body, etag, last_modified, fetched_at FROM http_cache WHERE key = ?1",
                [key],
                |r| {
                    Ok(Entry {
                        body: r.get(0)?,
                        etag: r.get(1)?,
                        last_modified: r.get(2)?,
                        fetched_at: r.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(match entry {
            None => Lookup::Miss,
            Some(e) => {
                // A clock that went backwards counts as age zero, not negative.
                let age = now.saturating_sub(e.fetched_at).max(0);
                if age < policy.ttl {
                    Lookup::Fresh(e)
                } else if age <= policy.stale_max_age {
                    Lookup::Stale(e)
                } else {
                    Lookup::Expired(e)
                }
            }
        })
    }

    /// Stores a response, replacing any previous entry for `key`.
    ///
    /// # Errors
    ///
    /// Fails when the body is above [`MAX_BODY_BYTES`] or on SQLite errors.
    pub fn put(
        &self,
        key: &str,
        body: &[u8],
        etag: Option<&str>,
        last_modified: Option<&str>,
        now: i64,
    ) -> Result<(), CacheError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(CacheError::BodyTooLarge(body.len()));
        }
        self.conn.execute(
            "INSERT INTO http_cache (key, body, etag, last_modified, fetched_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(key) DO UPDATE SET body = excluded.body, etag = excluded.etag,
                 last_modified = excluded.last_modified, fetched_at = excluded.fetched_at",
            params![key, body, etag, last_modified, now],
        )?;
        Ok(())
    }

    /// Marks an entry as confirmed current (after a `304 Not Modified`).
    /// Returns false when the key does not exist.
    ///
    /// # Errors
    ///
    /// Fails on SQLite errors.
    pub fn touch(&self, key: &str, now: i64) -> Result<bool, CacheError> {
        let n = self.conn.execute(
            "UPDATE http_cache SET fetched_at = ?2 WHERE key = ?1",
            params![key, now],
        )?;
        Ok(n > 0)
    }

    /// Removes every entry.
    ///
    /// # Errors
    ///
    /// Fails on SQLite errors.
    pub fn clear(&self) -> Result<(), CacheError> {
        self.conn.execute("DELETE FROM http_cache", [])?;
        Ok(())
    }

    /// Entry count and total body size.
    ///
    /// # Errors
    ///
    /// Fails on SQLite errors.
    pub fn info(&self) -> Result<Info, CacheError> {
        let (entries, bytes): (i64, i64) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(body)), 0) FROM http_cache",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(Info {
            entries: u64::try_from(entries).unwrap_or(0),
            bytes: u64::try_from(bytes).unwrap_or(0),
        })
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_file(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: Policy = Policy {
        ttl: 100,
        stale_max_age: 1000,
    };

    fn cache() -> Cache {
        Cache::in_memory().unwrap()
    }

    #[test]
    fn miss_then_fresh_stale_expired() {
        let c = cache();
        assert_eq!(c.get("k", 0, POLICY).unwrap(), Lookup::Miss);
        c.put("k", b"body", Some("\"e1\""), Some("Mon"), 1000)
            .unwrap();
        assert!(matches!(
            c.get("k", 1000, POLICY).unwrap(),
            Lookup::Fresh(_)
        ));
        assert!(matches!(
            c.get("k", 1099, POLICY).unwrap(),
            Lookup::Fresh(_)
        ));
        assert!(matches!(
            c.get("k", 1100, POLICY).unwrap(),
            Lookup::Stale(_)
        ));
        assert!(matches!(
            c.get("k", 2000, POLICY).unwrap(),
            Lookup::Stale(_)
        ));
        let expired = c.get("k", 2001, POLICY).unwrap();
        assert!(matches!(&expired, Lookup::Expired(e) if e.etag.as_deref() == Some("\"e1\"")));
    }

    #[test]
    fn put_replaces_and_keeps_validators() {
        let c = cache();
        c.put("k", b"one", Some("a"), None, 10).unwrap();
        c.put("k", b"two", None, Some("lm"), 20).unwrap();
        let want = Entry {
            body: b"two".to_vec(),
            etag: None,
            last_modified: Some("lm".into()),
            fetched_at: 20,
        };
        assert_eq!(c.get("k", 20, POLICY).unwrap(), Lookup::Fresh(want));
    }

    #[test]
    fn touch_refreshes_age() {
        let c = cache();
        c.put("k", b"b", None, None, 0).unwrap();
        assert!(matches!(c.get("k", 500, POLICY).unwrap(), Lookup::Stale(_)));
        assert!(c.touch("k", 500).unwrap());
        assert!(matches!(c.get("k", 500, POLICY).unwrap(), Lookup::Fresh(_)));
        assert!(!c.touch("missing", 1).unwrap());
    }

    #[test]
    fn clock_going_backwards_is_fresh_not_a_panic() {
        let c = cache();
        c.put("k", b"b", None, None, 5000).unwrap();
        assert!(matches!(c.get("k", 10, POLICY).unwrap(), Lookup::Fresh(_)));
    }

    #[test]
    fn info_and_clear() {
        let c = cache();
        assert_eq!(
            c.info().unwrap(),
            Info {
                entries: 0,
                bytes: 0
            }
        );
        c.put("a", b"123", None, None, 0).unwrap();
        c.put("b", b"45", None, None, 0).unwrap();
        assert_eq!(
            c.info().unwrap(),
            Info {
                entries: 2,
                bytes: 5
            }
        );
        c.clear().unwrap();
        assert_eq!(c.info().unwrap().entries, 0);
    }

    #[test]
    fn oversized_body_is_rejected() {
        let c = cache();
        let big = vec![0_u8; MAX_BODY_BYTES + 1];
        assert!(matches!(
            c.put("k", &big, None, None, 0),
            Err(CacheError::BodyTooLarge(_))
        ));
        assert_eq!(c.info().unwrap().entries, 0);
    }

    #[test]
    fn keys_with_sql_metacharacters_are_data() {
        let c = cache();
        let key = "x'; DROP TABLE http_cache;--";
        c.put(key, b"b", None, None, 0).unwrap();
        assert!(matches!(c.get(key, 0, POLICY).unwrap(), Lookup::Fresh(_)));
        assert_eq!(c.info().unwrap().entries, 1);
    }

    #[test]
    fn file_cache_persists_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/cache.sqlite");
        {
            let c = Cache::open(&path).unwrap();
            c.put("k", b"persisted", None, None, 0).unwrap();
        }
        let c = Cache::open(&path).unwrap();
        assert!(matches!(c.get("k", 0, POLICY).unwrap(), Lookup::Fresh(_)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
    }

    #[test]
    fn newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA user_version = 99;").unwrap();
        }
        assert!(matches!(
            Cache::open(&path),
            Err(CacheError::NewerSchema(99))
        ));
    }
}
