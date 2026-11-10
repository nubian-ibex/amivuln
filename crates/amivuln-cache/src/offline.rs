// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The offline database (ADR-0010): a signed `tar.zst` snapshot of a cache.
//!
//! `pack` turns a cache into `db.sqlite` plus `manifest.json` inside a
//! `tar.zst` archive. `verify` checks the manifest, the SHA-256 of the
//! database and, when a minisign public key and signature are given, the
//! signature over the manifest bytes. `install` puts a verified archive into
//! the offline directory and refuses a database older than the installed one
//! (anti-rollback), so a compromised mirror cannot serve stale advisories
//! that hide fresh CVEs.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use minisign_verify::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Cache, CacheError};

/// Schema version of `manifest.json`.
pub const SCHEMA_VERSION: u64 = 1;

/// Names of the two files inside the archive.
pub const DB_MEMBER: &str = "db.sqlite";
/// Name of the manifest file inside the archive and in the offline directory.
pub const MANIFEST_MEMBER: &str = "manifest.json";

/// Largest database accepted inside an archive.
const MAX_DB_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Largest manifest accepted.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Failures of the offline database handling.
#[derive(Debug, thiserror::Error)]
pub enum OfflineError {
    /// SQLite reported an error.
    #[error("cache database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// I/O failed.
    #[error("{0}")]
    Io(String),
    /// The archive or key file does not exist.
    #[error("{0}")]
    NotFound(String),
    /// The archive does not hold the expected members.
    #[error("the archive is missing {0}")]
    MissingMember(&'static str),
    /// The manifest is malformed or from a newer amivuln.
    #[error("{0}")]
    Manifest(String),
    /// The database does not match the manifest checksum.
    #[error("the database does not match the manifest checksum")]
    Checksum,
    /// The minisign signature does not verify.
    #[error("the signature does not verify")]
    Signature,
    /// The database is older than the installed one.
    #[error(
        "the database is older than the installed one ({0} < {1}); pass --force to install it anyway"
    )]
    Rollback(String, String),
}

/// The `manifest.json` inside an archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest schema version.
    pub schema_version: u64,
    /// When the snapshot was taken, `YYYY-MM-DDTHH:MM:SSZ` in UTC.
    pub created_at: String,
    /// amivuln version that produced it.
    pub tool_version: String,
    /// Number of cached entries.
    pub entries: u64,
    /// Total body bytes.
    pub bytes: u64,
    /// SHA-256 of `db.sqlite`, hex.
    pub db_sha256: String,
    /// Size of `db.sqlite` in bytes.
    pub db_bytes: u64,
}

impl Manifest {
    /// Builds the manifest for the cache at `db_path`.
    ///
    /// # Errors
    ///
    /// Fails on SQLite or I/O errors.
    pub fn for_db(
        db_path: &Path,
        tool_version: &str,
        created_at: String,
    ) -> Result<Self, OfflineError> {
        let conn = rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let check: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if check != "ok" {
            return Err(OfflineError::Manifest(format!(
                "the cache database fails its integrity check: {check}"
            )));
        }
        let (entries, bytes) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(body)), 0) FROM http_cache",
            [],
            |r| {
                let to_u64 = |v: rusqlite::types::Value| match v {
                    rusqlite::types::Value::Integer(n) => n.max(0).cast_unsigned(),
                    _ => 0,
                };
                Ok((to_u64(r.get(0)?), to_u64(r.get(1)?)))
            },
        )?;
        let db_bytes = std::fs::metadata(db_path)
            .map_err(|e| OfflineError::Io(format!("{}: {e}", db_path.display())))?
            .len();
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            created_at,
            tool_version: tool_version.to_owned(),
            entries,
            bytes,
            db_sha256: sha256_file(db_path)?,
            db_bytes,
        })
    }

    /// Validates the shape of a parsed manifest.
    ///
    /// # Errors
    ///
    /// Fails on an unsupported version or a malformed timestamp.
    pub fn validate(&self) -> Result<(), OfflineError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(OfflineError::Manifest(format!(
                "manifest schema_version {} is not supported (this amivuln reads {SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        if !is_rfc3339_utc(&self.created_at) {
            return Err(OfflineError::Manifest(format!(
                "created_at {:?} is not a UTC timestamp",
                self.created_at
            )));
        }
        if self.db_sha256.len() != 64 || self.db_sha256.bytes().any(|b| !b.is_ascii_hexdigit()) {
            return Err(OfflineError::Manifest(
                "db_sha256 is not a SHA-256 hex digest".to_owned(),
            ));
        }
        Ok(())
    }

    /// True when this manifest is strictly older than `installed`.
    #[must_use]
    pub fn older_than(&self, installed: &Manifest) -> bool {
        self.created_at < installed.created_at
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix timestamp.
#[must_use]
pub fn rfc3339_utc(now: i64) -> String {
    let days = now.div_euclid(86_400);
    let secs = now.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Days since the Unix epoch to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u64, u64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    // Both quantities are provably in range for a valid date.
    #[allow(clippy::cast_sign_loss)]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u64;
    #[allow(clippy::cast_sign_loss)]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u64;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Checks the exact timestamp shape this crate produces.
fn is_rfc3339_utc(text: &str) -> bool {
    let bytes = text.as_bytes();
    let at = |i: usize| bytes.get(i).copied();
    if bytes.len() != 20
        || at(4) != Some(b'-')
        || at(7) != Some(b'-')
        || at(10) != Some(b'T')
        || at(13) != Some(b':')
        || at(16) != Some(b':')
        || at(19) != Some(b'Z')
    {
        return false;
    }
    let digit_run = |range: std::ops::Range<usize>| {
        text.get(range)
            .is_some_and(|part| part.bytes().all(|c| c.is_ascii_digit()))
    };
    if !(digit_run(0..4)
        && digit_run(5..7)
        && digit_run(8..10)
        && digit_run(11..13)
        && digit_run(14..16)
        && digit_run(17..19))
    {
        return false;
    }
    let int = |range: std::ops::Range<usize>| text.get(range).and_then(|v| v.parse::<u32>().ok());
    let (y, mo, da) = (
        int(0..4).unwrap_or_default(),
        int(5..7).unwrap_or_default(),
        int(8..10).unwrap_or_default(),
    );
    let (hh, mi, ss) = (
        int(11..13).unwrap_or_default(),
        int(14..16).unwrap_or_default(),
        int(17..19).unwrap_or_default(),
    );
    (1..=12).contains(&mo) && (1..=31).contains(&da) && hh < 24 && mi < 60 && ss < 60 && y > 1969
}

/// Maps a missing file to [`OfflineError::NotFound`].
fn not_found(path: &Path) -> impl Fn(std::io::Error) -> OfflineError + '_ {
    move |e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            OfflineError::NotFound(format!("{} does not exist", path.display()))
        } else {
            OfflineError::Io(format!("{}: {e}", path.display()))
        }
    }
}

/// Lowercase hex for a digest.
fn hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn sha256_file(path: &Path) -> Result<String, OfflineError> {
    let file = std::fs::File::open(path)
        .map_err(|e| OfflineError::Io(format!("{}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut reader = std::io::BufReader::new(file);
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| OfflineError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n).unwrap_or_default());
    }
    Ok(hex(&hasher.finalize()))
}

/// Writes the cache database and its manifest into a `tar.zst` archive.
///
/// # Errors
///
/// Fails on SQLite or I/O errors.
pub fn pack(
    db_path: &Path,
    output: &Path,
    tool_version: &str,
    now: i64,
) -> Result<Manifest, OfflineError> {
    let manifest = Manifest::for_db(db_path, tool_version, rfc3339_utc(now))?;
    if let Some(dir) = output.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .map_err(|e| OfflineError::Io(format!("{}: {e}", dir.display())))?;
    }
    let db = std::fs::read(db_path)
        .map_err(|e| OfflineError::Io(format!("{}: {e}", db_path.display())))?;
    let file = std::fs::File::create(output)
        .map_err(|e| OfflineError::Io(format!("{}: {e}", output.display())))?;
    let mut zstd = zstd::Encoder::new(std::io::BufWriter::new(file), 6)
        .map_err(|e| OfflineError::Io(e.to_string()))?;
    {
        let mut tar = tar::Builder::new(&mut zstd);
        let mut header = tar::Header::new_gnu();
        header.set_size(db.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append_data(&mut header, DB_MEMBER, db.as_slice())
            .map_err(|e| OfflineError::Io(e.to_string()))?;
        let json = serde_json::to_vec(&manifest).map_err(|e| OfflineError::Io(e.to_string()))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(json.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append_data(&mut header, MANIFEST_MEMBER, json.as_slice())
            .map_err(|e| OfflineError::Io(e.to_string()))?;
        tar.finish().map_err(|e| OfflineError::Io(e.to_string()))?;
    }
    zstd.finish().map_err(|e| OfflineError::Io(e.to_string()))?;
    Ok(manifest)
}

/// The two members of an archive, with the manifest already validated.
#[derive(Debug)]
pub struct Verified {
    /// The manifest.
    pub manifest: Manifest,
    /// The database bytes.
    pub db: Vec<u8>,
}

fn signature_bytes(
    key: Option<&Path>,
    sig: Option<&Path>,
    manifest: &[u8],
) -> Result<(), OfflineError> {
    let (Some(key), Some(sig)) = (key, sig) else {
        return Ok(());
    };
    let pubkey = PublicKey::from_file(key).map_err(|_| OfflineError::Signature)?;
    let signature = Signature::from_file(sig).map_err(|_| OfflineError::Signature)?;
    // `true` accepts pre-hashed signatures, which current minisign produces.
    if pubkey.verify(manifest, &signature, true).is_err() {
        return Err(OfflineError::Signature);
    }
    Ok(())
}

/// Reads an archive, validates the manifest and the database checksum and,
/// when `key` and `sig` are given, the minisign signature over the manifest.
///
/// # Errors
///
/// Fails on I/O errors and on any integrity or signature problem.
pub fn verify_archive(
    archive: &Path,
    key: Option<&Path>,
    sig: Option<&Path>,
) -> Result<Verified, OfflineError> {
    let file = std::fs::File::open(archive).map_err(not_found(archive))?;
    let zstd = zstd::Decoder::new(std::io::BufReader::new(file))
        .map_err(|e| OfflineError::Io(e.to_string()))?;
    let mut tar = tar::Archive::new(zstd);
    let mut db: Option<Vec<u8>> = None;
    let mut manifest: Option<Vec<u8>> = None;
    let entries = tar.entries().map_err(|e| OfflineError::Io(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| OfflineError::Io(e.to_string()))?;
        let name = entry
            .path()
            .map_err(|e| OfflineError::Io(e.to_string()))?
            .to_path_buf();
        match name.file_name().and_then(|n| n.to_str()) {
            Some(DB_MEMBER) => {
                let mut buf = Vec::new();
                entry
                    .by_ref()
                    .take(MAX_DB_BYTES + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| OfflineError::Io(e.to_string()))?;
                if buf.len() as u64 > MAX_DB_BYTES {
                    return Err(OfflineError::Manifest(format!(
                        "the database is larger than {MAX_DB_BYTES} bytes"
                    )));
                }
                db = Some(buf);
            }
            Some(MANIFEST_MEMBER) => {
                let mut buf = Vec::new();
                entry
                    .by_ref()
                    .take(MAX_MANIFEST_BYTES + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| OfflineError::Io(e.to_string()))?;
                if buf.len() as u64 > MAX_MANIFEST_BYTES {
                    return Err(OfflineError::Manifest(format!(
                        "the manifest is larger than {MAX_MANIFEST_BYTES} bytes"
                    )));
                }
                manifest = Some(buf);
            }
            _ => {}
        }
    }
    let manifest = manifest.ok_or(OfflineError::MissingMember(MANIFEST_MEMBER))?;
    signature_bytes(key, sig, &manifest)?;
    let manifest: Manifest = serde_json::from_slice(&manifest)
        .map_err(|e| OfflineError::Manifest(format!("manifest.json: {e}")))?;
    manifest.validate()?;
    let db = db.ok_or(OfflineError::MissingMember(DB_MEMBER))?;
    if db.len() as u64 != manifest.db_bytes {
        return Err(OfflineError::Checksum);
    }
    let mut hasher = Sha256::new();
    hasher.update(&db);
    if hex(&hasher.finalize()) != manifest.db_sha256 {
        return Err(OfflineError::Checksum);
    }
    Ok(Verified { manifest, db })
}

/// Installs a verified archive into `dir`, refusing a database older than the
/// one already installed unless `force`.
///
/// # Errors
///
/// Fails on I/O errors, on a rollback and when the archive is invalid.
pub fn install(dir: &Path, verified: &Verified, force: bool) -> Result<(), OfflineError> {
    let manifest_path = dir.join(MANIFEST_MEMBER);
    let installed = if force || !manifest_path.is_file() {
        None
    } else {
        read_manifest(&manifest_path).ok()
    };
    if let Some(installed) = installed
        && verified.manifest.older_than(&installed)
    {
        return Err(OfflineError::Rollback(
            verified.manifest.created_at.clone(),
            installed.created_at,
        ));
    }
    create_offline_dir(dir)?;
    let db_path = dir.join(DB_MEMBER);
    let tmp_db = dir.join(".db.sqlite.tmp");
    let tmp_manifest = dir.join(".manifest.json.tmp");
    write_private(&tmp_db, &verified.db)?;
    let json = serde_json::to_vec_pretty(&verified.manifest)
        .map_err(|e| OfflineError::Io(e.to_string()))?;
    write_private(&tmp_manifest, &json)?;
    std::fs::rename(&tmp_db, &db_path).map_err(|e| OfflineError::Io(e.to_string()))?;
    // The manifest is installed last: its presence says the database is whole.
    std::fs::rename(&tmp_manifest, &manifest_path).map_err(|e| OfflineError::Io(e.to_string()))?;
    Ok(())
}

/// The manifest of the installed database, when there is one.
///
/// # Errors
///
/// Fails when a manifest exists but cannot be read or parsed.
pub fn read_manifest(path: &Path) -> Result<Manifest, OfflineError> {
    let bytes =
        std::fs::read(path).map_err(|e| OfflineError::Io(format!("{}: {e}", path.display())))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|e| OfflineError::Manifest(format!("{}: {e}", path.display())))?;
    manifest.validate()?;
    Ok(manifest)
}

/// Opens the installed database read-only, for offline lookups.
///
/// Returns `None` when there is no installed database.
///
/// # Errors
///
/// Fails when a database exists but cannot be opened.
pub fn open_installed(dir: &Path) -> Result<Option<Cache>, CacheError> {
    let db_path = dir.join(DB_MEMBER);
    if !db_path.is_file() || !dir.join(MANIFEST_MEMBER).is_file() {
        return Ok(None);
    }
    Cache::open_read_only(&db_path).map(Some)
}

fn create_offline_dir(dir: &Path) -> Result<(), OfflineError> {
    crate::create_private_dir(dir).map_err(|e| OfflineError::Io(format!("{}: {e}", dir.display())))
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), OfflineError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| OfflineError::Io(format!("{}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| OfflineError::Io(e.to_string()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), OfflineError> {
    std::fs::write(path, bytes).map_err(|e| OfflineError::Io(e.to_string()))
}

/// Where `amivuln db pull` installs, and the offline lookups read from.
#[must_use]
pub fn default_dir(xdg_data_home: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
    let base = xdg_data_home
        .map(PathBuf::from)
        .or_else(|| home.map(|h| h.join(".local").join("share")))?;
    Some(base.join("amivuln").join("offline"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Policy;

    fn warm_cache(dir: &Path, now: i64) -> PathBuf {
        let path = dir.join("cache.sqlite");
        let cache = Cache::open(&path).unwrap();
        cache.put("osv:a", b"body-a", None, None, now).unwrap();
        cache
            .put("osv:b", b"body-b", Some("\"e\""), None, now)
            .unwrap();
        path
    }

    #[test]
    fn timestamps_round_trip() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_794_181_461), "2026-11-08T23:44:21Z");
        assert_eq!(rfc3339_utc(951_868_800), "2000-03-01T00:00:00Z");
    }

    #[test]
    fn pack_verify_install_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = warm_cache(dir.path(), 1_700_000_000);
        let archive = dir.path().join("db.tar.zst");
        let manifest = pack(&db_path, &archive, "0.0.0", 1_794_000_000).unwrap();
        assert_eq!(manifest.entries, 2);
        assert_eq!(manifest.bytes, 12);

        let verified = verify_archive(&archive, None, None).unwrap();
        assert_eq!(verified.manifest, manifest);
        assert_eq!(verified.db.len() as u64, manifest.db_bytes);

        let out = dir.path().join("installed");
        install(&out, &verified, false).unwrap();
        let installed = read_manifest(&out.join(MANIFEST_MEMBER)).unwrap();
        assert_eq!(installed, manifest);
        let cache = open_installed(&out).unwrap().unwrap();
        let lookup = cache
            .get(
                "osv:a",
                1_794_000_100,
                Policy {
                    ttl: 100,
                    stale_max_age: 200,
                },
            )
            .unwrap();
        assert!(matches!(
            lookup,
            crate::Lookup::Expired(crate::Entry { ref body, .. }) if body == b"body-a"
        ));
    }

    #[test]
    fn a_tampered_database_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = warm_cache(dir.path(), 1);
        let archive = dir.path().join("db.tar.zst");
        let manifest = pack(&db_path, &archive, "0.0.0", 100).unwrap();

        // Repack with a manifest that lies about the checksum.
        let mut lying = manifest.clone();
        lying.db_sha256 = "0".repeat(64);
        lying.db_bytes = 16;
        let file = std::fs::File::create(&archive).unwrap();
        let mut zstd = zstd::Encoder::new(std::io::BufWriter::new(file), 1).unwrap();
        {
            let mut tar = tar::Builder::new(&mut zstd);
            let mut header = tar::Header::new_gnu();
            header.set_size(16);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, DB_MEMBER, [0u8; 16].as_slice())
                .unwrap();
            let mut header = tar::Header::new_gnu();
            let json = serde_json::to_vec(&lying).unwrap();
            header.set_size(json.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, MANIFEST_MEMBER, json.as_slice())
                .unwrap();
            tar.finish().unwrap();
        }
        zstd.finish().unwrap();
        let err = verify_archive(&archive, None, None).unwrap_err();
        assert!(
            matches!(err, OfflineError::Checksum | OfflineError::Manifest(_)),
            "{err}"
        );
    }

    #[test]
    fn a_wrong_schema_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = warm_cache(dir.path(), 1);
        let archive = dir.path().join("db.tar.zst");
        let mut manifest = pack(&db_path, &archive, "0.0.0", 100).unwrap();
        let verified = verify_archive(&archive, None, None).unwrap();
        manifest.schema_version = 2;
        let out = dir.path().join("installed");
        let tampered = Verified {
            manifest,
            db: verified.db,
        };
        install(&out, &tampered, false).unwrap();
        assert!(read_manifest(&out.join(MANIFEST_MEMBER)).is_err());
    }

    #[test]
    fn signatures_verify_and_reject_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = warm_cache(dir.path(), 1);
        let archive = dir.path().join("db.tar.zst");
        let manifest = pack(&db_path, &archive, "0.0.0", 100).unwrap();
        let json = serde_json::to_vec(&manifest).unwrap();

        // Sign the manifest bytes with the reference minisign implementation.
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let sig = minisign::sign(Some(&kp.pk), &kp.sk, &json[..], None, None).unwrap();

        let pubkey_file = dir.path().join("key.pub");
        std::fs::write(&pubkey_file, kp.pk.to_box().unwrap().to_string()).unwrap();
        let sig_file = dir.path().join("manifest.minisig");
        std::fs::write(&sig_file, sig.to_string()).unwrap();
        signature_bytes(Some(&pubkey_file), Some(&sig_file), &json).unwrap();

        // One flipped byte in the manifest must fail the signature.
        let mut tampered = json.clone();
        tampered[0] ^= 0x20;
        assert!(matches!(
            signature_bytes(Some(&pubkey_file), Some(&sig_file), &tampered),
            Err(OfflineError::Signature)
        ));
    }

    #[test]
    fn a_rollback_is_refused_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = warm_cache(dir.path(), 1);
        let new = dir.path().join("new.tar.zst");
        let old = dir.path().join("old.tar.zst");
        let new_manifest = pack(&db_path, &new, "0.0.0", 2_000_000_000).unwrap();
        let old_manifest = pack(&db_path, &old, "0.0.0", 1_000_000_000).unwrap();
        let out = dir.path().join("installed");
        install(
            &out,
            &Verified {
                manifest: new_manifest,
                db: Vec::new(),
            },
            false,
        )
        .unwrap();
        let old_verified = verify_archive(&old, None, None).unwrap();
        assert_eq!(old_verified.manifest, old_manifest);
        let err = install(&out, &old_verified, false).unwrap_err();
        assert!(matches!(err, OfflineError::Rollback(_, _)), "{err}");
        install(&out, &old_verified, true).unwrap();
        assert_eq!(
            read_manifest(&out.join(MANIFEST_MEMBER))
                .unwrap()
                .created_at,
            "2001-09-09T01:46:40Z"
        );
    }

    #[test]
    fn an_empty_offline_dir_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            open_installed(&dir.path().join("missing"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn the_default_dir_prefers_xdg() {
        let from_xdg = default_dir(Some(Path::new("/xdg")), Some(Path::new("/home")));
        assert_eq!(from_xdg.unwrap(), PathBuf::from("/xdg/amivuln/offline"));
        let from_home = default_dir(None, Some(Path::new("/home")));
        assert_eq!(
            from_home.unwrap(),
            PathBuf::from("/home/.local/share/amivuln/offline")
        );
        assert!(default_dir(None, None).is_none());
    }
}
