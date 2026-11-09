// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests of the real binary against a mock server. No test touches
//! the network: every source URL points at wiremock through a config file.

// Test helpers sit outside `#[test]` functions, where the workspace's
// allow-unwrap-in-tests setting does not reach; unwrapping is the intended
// failure mode of a test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use assert_cmd::Command;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UPDATEINFO_ZST: &[u8] =
    include_bytes!("../../../tests/fixtures/http/fedora-updateinfo/2026-11-07/updateinfo.xml.zst");
const ARCH_JSON: &[u8] =
    include_bytes!("../../../tests/fixtures/http/arch-tracker/2026-11-07/all.json");
const KEV_JSON: &[u8] = include_bytes!(
    "../../../tests/fixtures/http/kev/2026-11-08/known_exploited_vulnerabilities.json"
);
const EPSS_JSON: &[u8] = include_bytes!("../../../tests/fixtures/http/epss/2026-11-08/epss.json");

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    Sha256::digest(data)
        .iter()
        .fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

fn repomd_with(sum: &str, name: &str) -> String {
    format!(
        r#"<repomd><data type="updateinfo"><checksum type="sha256">{sum}</checksum><location href="repodata/{name}"/></data></repomd>"#
    )
}

fn fixture_sum() -> String {
    sha256_hex(UPDATEINFO_ZST)
}

fn fixture_name() -> String {
    format!("{}-updateinfo.xml.zst", sha256_hex(UPDATEINFO_ZST))
}

fn repomd() -> String {
    repomd_with(&fixture_sum(), &fixture_name())
}

async fn mount_fedora(server: &MockServer) {
    let name = fixture_name();
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/updates/43/Everything/[^/]+/repodata/repomd\.xml$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(repomd()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            r"^/updates/43/Everything/[^/]+/repodata/{name}$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(UPDATEINFO_ZST))
        .mount(server)
        .await;
}

async fn mount_fedora_with_wrong_checksum(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/updates/43/Everything/[^/]+/repodata/repomd\.xml$",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(repomd_with(&"0".repeat(64), "x-updateinfo.xml.zst")),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/updates/43/Everything/[^/]+/repodata/[^/]+-updateinfo\.xml\.zst$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(UPDATEINFO_ZST))
        .mount(server)
        .await;
}

async fn mount_enrichment(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(KEV_JSON))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/epss"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(EPSS_JSON))
        .mount(server)
        .await;
}

struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new(server_uri: &str, distro_url: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cfg = format!(
            "[network]\nallow_insecure_http = true\n\
             [sources.distro]\nurl = \"{server_uri}{distro_url}\"\n\
             [sources.kev]\nurl = \"{server_uri}/kev.json\"\n\
             [sources.epss]\nurl = \"{server_uri}/epss\"\n"
        );
        std::fs::write(dir.path().join("config.toml"), cfg).unwrap();
        Self { dir }
    }

    fn cmd(&self) -> Command {
        self.cmd_opts(true)
    }

    /// `with_config = false` drops the built-in config so a test can pass its own.
    fn cmd_opts(&self, with_config: bool) -> Command {
        let mut c = Command::cargo_bin("amivuln").unwrap();
        c.env_clear()
            .env("HOME", self.dir.path())
            .env("XDG_CACHE_HOME", self.dir.path().join("cache"))
            .env("PATH", "/nonexistent");
        if with_config {
            c.args(["--config"])
                .arg(self.dir.path().join("config.toml"));
        }
        c
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

/// Runs the blocking binary without stalling the mock server.
async fn run(mut cmd: Command, args: Vec<&'static str>) -> std::process::Output {
    cmd.args(args);
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn json(o: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", stdout(o)))
}

#[tokio::test(flavor = "multi_thread")]
async fn fedora_pending_update_is_reported_as_json_with_exit_zero_by_default() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let out = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "-f",
            "json",
        ],
    )
    .await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["complete"], true);
    assert_eq!(v["host"]["os_id"], "fedora");
    let t = &v["targets"][0];
    assert_eq!(t["findings"][0]["id"], "CVE-2026-28356");
    assert_eq!(t["findings"][0]["distro_status"]["state"], "affected");
    assert_eq!(
        t["findings"][0]["distro_status"]["fixed_in"],
        "1.3.1-1.fc43"
    );
    assert_eq!(t["package"]["provenance"], "user_input");
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fail_on_turns_findings_into_exit_one_and_a_fixed_version_is_clean() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let bad = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "--fail-on",
            "high",
            "--color",
            "never",
        ],
    )
    .await;
    assert_eq!(bad.status.code(), Some(1));
    let text = stdout(&bad);
    assert!(text.contains("HIGH 1"), "{text}");
    assert!(
        text.contains("Fixed in: 1.3.1-1.fc43  (dnf upgrade python3-multipart)"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'));

    let good = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.1-1.fc43",
            "--distro",
            "fedora:43",
            "--fail-on",
            "low",
        ],
    )
    .await;
    assert_eq!(good.status.code(), Some(0), "{}", stdout(&good));
}

#[tokio::test(flavor = "multi_thread")]
async fn arch_tracker_flow() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/arch.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ARCH_JSON))
        .mount(&server)
        .await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/arch.json");
    let out = run(
        sb.cmd(),
        vec![
            "djvulibre@3.5.28-6",
            "--distro",
            "arch",
            "-f",
            "json",
            "--fail-on",
            "high",
        ],
    )
    .await;
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    assert_eq!(v["targets"][0]["findings"][0]["id"], "CVE-2025-53367");
    assert_eq!(
        v["targets"][0]["findings"][0]["distro_status"]["fixed_in"],
        "3.5.30-1"
    );
    assert_eq!(v["sources"][0]["id"], "arch-tracker");

    let fixed = run(
        sb.cmd(),
        vec!["djvulibre@3.5.30-1", "--distro", "arch", "--fail-on", "low"],
    )
    .await;
    assert_eq!(fixed.status.code(), Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_required_source_is_incomplete_exit_two_never_a_clean_scan() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let out = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "-f",
            "json",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(2));
    let v = json(&out);
    assert_eq!(v["complete"], false);
    assert_eq!(v["sources"][0]["status"], "failed");

    let text = run(
        sb.cmd(),
        vec!["python3-multipart@0:1.3.0-1.fc43", "--distro", "fedora:43"],
    )
    .await;
    assert_eq!(text.status.code(), Some(2));
    assert!(stdout(&text).contains("INCOMPLETE"), "{}", stdout(&text));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mirror_serving_bytes_that_do_not_match_repomd_is_rejected() {
    let server = MockServer::start().await;
    mount_fedora_with_wrong_checksum(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let out = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "-f",
            "json",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(2));
    let v = json(&out);
    assert_eq!(v["complete"], false);
    assert!(
        v["sources"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("checksum")
    );
    assert!(v["targets"][0]["findings"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_uses_the_cache_and_fails_closed_without_one() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");

    let cold = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "--offline",
        ],
    )
    .await;
    assert_eq!(
        cold.status.code(),
        Some(2),
        "offline without a cache must be incomplete"
    );

    let warm = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "-f",
            "json",
        ],
    )
    .await;
    assert_eq!(warm.status.code(), Some(0));
    server.reset().await;

    let offline = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "--offline",
            "-f",
            "json",
        ],
    )
    .await;
    assert_eq!(
        offline.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&offline.stderr)
    );
    assert_eq!(
        json(&offline)["targets"][0]["findings"][0]["id"],
        "CVE-2026-28356"
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_package_data_leaves_the_host() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let out = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "-f",
            "json",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(0));
    let mut forbidden = vec![sb.path().display().to_string()];
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        forbidden.push(h.trim().to_owned());
    }
    if let Ok(u) = std::env::var("USER") {
        forbidden.push(u);
    }
    forbidden.retain(|s| s.len() >= 3 && s != "localhost");
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(requests.len() >= 3);
    for r in requests {
        let wire = format!("{} {:?}", r.url, r.headers);
        for f in &forbidden {
            assert!(!wire.contains(f), "request leaks {f:?}: {wire}");
        }
        assert!(r.headers.get("cookie").is_none() && r.headers.get("authorization").is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_input_is_a_usage_or_resolution_error_with_a_clear_message() {
    let sb = Sandbox::new("http://127.0.0.1:9", "/updates");
    let cases: Vec<(Vec<&'static str>, i32, &str)> = vec![
        (vec!["--distro", "fedora:43"], 64, "no target given"),
        (
            vec!["x", "--distro", "fedora:43", "--format", "xml"],
            64,
            "invalid --format",
        ),
        (
            vec!["x", "--distro", "fedora:43", "--fail-on", "urgent"],
            64,
            "invalid --fail-on",
        ),
        (
            vec!["x", "--distro", "fedora:43", "--fail-on-epss", "2"],
            64,
            "between 0.0 and 1.0",
        ),
        (vec!["x", "--distro", "debian"], 64, "unsupported --distro"),
        (vec!["--bogus"], 64, "unexpected argument"),
        (
            vec!["nginx.service", "--distro", "fedora:43", "--offline"],
            3,
            "unresolved nginx.service",
        ),
        (
            vec!["pkg:deb/debian/x@1", "--offline", "--distro", "fedora:43"],
            3,
            "does not match --distro fedora:43",
        ),
        (
            vec!["a b@1", "--distro", "fedora:43", "--offline"],
            3,
            "invalid package name",
        ),
    ];
    for (args, code, needle) in cases {
        let out = run(sb.cmd(), args.clone()).await;
        let all = format!("{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.status.code(), Some(code), "{args:?}: {all}");
        assert!(
            all.contains(needle),
            "{args:?} should mention {needle:?}: {all}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ignore_file_suppresses_and_an_expired_one_fails_the_run() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let inv = sb.path().join("inv.txt");
    std::fs::write(&inv, "python3-multipart@0:1.3.0-1.fc43\n").unwrap();

    // A valid entry suppresses the finding: exit 0 with the reason shown.
    let inv_leak: &'static str = Box::leak(inv.display().to_string().into_boxed_str());
    let good = sb.path().join("good.toml");
    std::fs::write(&good, "ignore_file = \"ignore.toml\"\n").unwrap();
    std::fs::write(
        sb.path().join("ignore.toml"),
        "[[ignore]]\nid = \"CVE-2026-28356\"\nreason = \"accepted (INFRA-42)\"\nowner = \"sre@example.com\"\nexpires = \"2099-12-31\"\n",
    )
    .unwrap();
    let cfg_leak: &'static str = Box::leak(good.display().to_string().into_boxed_str());
    let out = run(
        sb.cmd_opts(false),
        vec![
            "--config",
            cfg_leak,
            "--fail-on",
            "high",
            "--color",
            "never",
            "--format",
            "detail",
            "--distro",
            "fedora:43",
            "--packages-from",
            inv_leak,
        ],
    )
    .await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout(&out).contains("accepted (INFRA-42)") || stdout(&out).contains("1 accepted"),
        "suppression must be visible: {}",
        stdout(&out)
    );

    // Without the ignore file the same run fails at HIGH severity.
    let bare = run(
        sb.cmd(),
        vec![
            "--fail-on",
            "high",
            "--color",
            "never",
            "--distro",
            "fedora:43",
            "--packages-from",
            inv_leak,
        ],
    )
    .await;
    assert_eq!(bare.status.code(), Some(1));

    // An expired entry is a configuration error (usage), not a silent pass.
    let bad = sb.path().join("bad.toml");
    std::fs::write(&bad, "ignore_file = \"ignore.toml\"\n").unwrap();
    std::fs::write(
        sb.path().join("ignore.toml"),
        "[[ignore]]\nid = \"CVE-2026-28356\"\nreason = \"x\"\nowner = \"a@b\"\nexpires = \"2020-01-01\"\n",
    )
    .unwrap();
    let cfg_bad: &'static str = Box::leak(bad.display().to_string().into_boxed_str());
    let out = run(sb.cmd_opts(false), vec!["--config", cfg_bad, "nginx@1.0-1"]).await;
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("expired on"));
}

#[tokio::test(flavor = "multi_thread")]
async fn sarif_markdown_and_csv_output() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");

    let sarif = run(
        sb.cmd(),
        vec![
            "-f",
            "sarif",
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
        ],
    )
    .await;
    assert_eq!(sarif.status.code(), Some(0));
    let v = json(&sarif);
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["results"][0]["ruleId"], "CVE-2026-28356");
    assert_eq!(v["runs"][0]["results"][0]["level"], "error");

    let md = run(
        sb.cmd(),
        vec![
            "-f",
            "markdown",
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
        ],
    )
    .await;
    assert_eq!(md.status.code(), Some(0));
    let text = stdout(&md);
    assert!(
        text.contains("## python3-multipart 1.3.0-1.fc43 (fedora)"),
        "{text}"
    );
    assert!(text.contains("| CVE-2026-28356 | high | affected | 1.3.1-1.fc43 |"));

    let csv = run(
        sb.cmd(),
        vec![
            "-f",
            "csv",
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
        ],
    )
    .await;
    assert_eq!(csv.status.code(), Some(0));
    let text = stdout(&csv);
    assert!(text.starts_with("package,version,ecosystem,id,severity,state,fixed_in,kev,epss"));
    assert!(
        text.contains(
            "\"python3-multipart\",\"1.3.0-1.fc43\",\"fedora\",\"CVE-2026-28356\",high,affected,\"1.3.1-1.fc43\",",
        ),
        "{text}"
    );

    let prom = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "-f",
            "prometheus",
        ],
    )
    .await;
    assert_eq!(prom.status.code(), Some(0));
    let text = stdout(&prom);
    assert!(
        text.contains("amivuln_findings{severity=\"high\",kev=\"false\"} 1"),
        "{text}"
    );
    assert!(text.contains("amivuln_run_complete 1"), "{text}");
    assert!(!text.contains("python3-multipart"), "{text}");

    let bad = run(sb.cmd(), vec!["-f", "xml", "nginx@1.0-1"]).await;
    assert_eq!(bad.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("markdown, csv or prometheus"));
}

#[tokio::test(flavor = "multi_thread")]
async fn vex_not_affected_statement_overrides_the_verdict() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let vex = sb.path().join("vex.json");
    std::fs::write(
        &vex,
        r#"{"author":"Vendor Security Team","statements":[{"status":"not_affected","vulnerability_id":"CVE-2026-28356","justification":"vulnerable code not in this build","products":[{"@id":"pkg:rpm/fedora/python3-multipart@1.3.0-1.fc43"}]}]}"#,
    )
    .unwrap();
    let vex_leak: &'static str = Box::leak(vex.display().to_string().into_boxed_str());

    let out = run(
        sb.cmd(),
        vec![
            "--vex",
            vex_leak,
            "--fail-on",
            "high",
            "-f",
            "json",
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let v = json(&out);
    let f = &v["targets"][0]["findings"][0];
    assert_eq!(f["distro_status"]["state"], "not_affected");
    assert!(
        f["distro_status"]["fixed_in"]
            .as_str()
            .unwrap_or("")
            .contains("VEX by Vendor Security Team"),
        "{f}"
    );

    // Without the VEX file the same run fails at HIGH.
    let bare = run(
        sb.cmd(),
        vec![
            "--fail-on",
            "high",
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
        ],
    )
    .await;
    assert_eq!(bare.status.code(), Some(1));

    // A malformed VEX file is a usage error.
    let bad = sb.path().join("bad.json");
    std::fs::write(&bad, "[").unwrap();
    let bad_leak: &'static str = Box::leak(bad.display().to_string().into_boxed_str());
    let out = run(sb.cmd(), vec!["--vex", bad_leak, "nginx@1.0-1"]).await;
    assert_eq!(out.status.code(), Some(64));
}

#[tokio::test(flavor = "multi_thread")]
async fn baseline_only_new_findings_violate_the_policy() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let inv = sb.path().join("inv.txt");
    std::fs::write(&inv, "python3-multipart@0:1.3.0-1.fc43\n").unwrap();
    let inv_leak: &'static str = Box::leak(inv.display().to_string().into_boxed_str());

    // Produce the first report: exit 1 at HIGH.
    let first = run(
        sb.cmd(),
        vec![
            "-f",
            "json",
            "--fail-on",
            "high",
            "--distro",
            "fedora:43",
            "--packages-from",
            inv_leak,
        ],
    )
    .await;
    assert_eq!(
        first.status.code(),
        Some(1),
        "first: {} | stderr: {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let _ = serde_json::from_slice::<serde_json::Value>(&first.stdout)
        .unwrap()["targets"][0]["findings"].as_array().unwrap().len();
    let baseline = sb.path().join("baseline.json");
    std::fs::write(&baseline, &first.stdout).unwrap();
    let bl_leak: &'static str = Box::leak(baseline.display().to_string().into_boxed_str());

    // The same scan against the baseline: no new findings, exit 0.
    let same = run(
        sb.cmd(),
        vec![
            "--baseline",
            bl_leak,
            "--fail-on",
            "high",
            "--color",
            "never",
            "--distro",
            "fedora:43",
            "--packages-from",
            inv_leak,
        ],
    )
    .await;
    assert_eq!(
        same.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&same.stderr)
    );

    // A broken or foreign baseline is a usage error.
    let junk = sb.path().join("junk.json");
    std::fs::write(&junk, "not json").unwrap();
    let junk_leak: &'static str = Box::leak(junk.display().to_string().into_boxed_str());
    let out = run(sb.cmd(), vec!["--baseline", junk_leak, "nginx@1.0-1"]).await;
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("baseline is not valid"));
}

#[test]
fn help_version_completions_and_config_commands() {
    let dir = tempfile::tempdir().unwrap();
    let base = |args: &[&str]| {
        let mut c = Command::cargo_bin("amivuln").unwrap();
        c.env_clear()
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("cfg"))
            .args(args);
        c
    };
    let help = base(&["--help"]).output().unwrap();
    let text = String::from_utf8_lossy(&help.stdout).into_owned();
    assert_eq!(help.status.code(), Some(0));
    for needle in [
        "EXAMPLES",
        "EXIT CODES",
        "--fail-on",
        "--all",
        "completions",
    ] {
        assert!(text.contains(needle), "help lacks {needle}");
    }
    let v = base(&["version", "--json"]).output().unwrap();
    assert!(String::from_utf8_lossy(&v.stdout).contains("\"schema_version\":1"));
    let c = base(&["completions", "bash"]).output().unwrap();
    assert!(String::from_utf8_lossy(&c.stdout).contains("amivuln"));

    let init = base(&["config", "init"]).output().unwrap();
    assert_eq!(init.status.code(), Some(0));
    let file = dir.path().join("cfg/amivuln/config.toml");
    assert!(file.is_file());
    assert_eq!(
        base(&["config", "init"]).output().unwrap().status.code(),
        Some(64),
        "must not overwrite"
    );
    let show = base(&["config", "show"]).output().unwrap();
    assert!(String::from_utf8_lossy(&show.stdout).contains("fail_on = \"none\""));
    assert_eq!(
        base(&["config", "validate"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );

    std::fs::write(&file, "[policy]\nfail_on = \"urgent\"\n").unwrap();
    let bad = base(&["config", "validate"]).output().unwrap();
    assert_eq!(bad.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("config.toml"));
}

#[test]
fn cache_commands_work_on_an_empty_cache() {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::cargo_bin("amivuln")
            .unwrap()
            .env_clear()
            .env("HOME", dir.path())
            .env("XDG_CACHE_HOME", dir.path().join("c"))
            .args(args)
            .output()
            .unwrap()
    };
    let info = run(&["cache", "info"]);
    assert_eq!(info.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&info.stdout).contains("entries: 0"));
    assert_eq!(run(&["cache", "clear"]).status.code(), Some(0));
}

/// A sandbox plus an inventory file, as the leaked path the helpers need.
async fn inventory_sandbox() -> (MockServer, Sandbox, &'static str) {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let inventory = sb.path().join("inventory.txt");
    std::fs::write(
        &inventory,
        "# exported from another host\n\
         python3-multipart@(none):1.3.0-1.fc43\n\
         python3-wheel@0.45.1-20.fc43\n\
         bash@5.3.9-3.fc43\n\n",
    )
    .unwrap();
    let inv: &'static str = Box::leak(inventory.display().to_string().into_boxed_str());
    (server, sb, inv)
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_ranks_updates_from_an_inventory() {
    let (_server, sb, inv) = inventory_sandbox().await;
    let out = run(
        sb.cmd(),
        vec![
            "--format",
            "json",
            "pending",
            "--distro",
            "fedora:43",
            "--packages-from",
            inv,
        ],
    )
    .await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    assert_eq!(v["kind"], "pending");
    assert_eq!(v["summary"]["updates"], 2);
    let names: Vec<&str> = v["updates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["package"]["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"python3-multipart") && names.contains(&"python3-wheel"),
        "{names:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cve_reports_affected_known_and_unknown() {
    let (_server, sb, inv) = inventory_sandbox().await;
    let hit = run(
        sb.cmd(),
        vec![
            "-f",
            "json",
            "cve",
            "CVE-2026-28356",
            "--distro",
            "fedora:43",
            "--packages-from",
            inv,
        ],
    )
    .await;
    assert_eq!(hit.status.code(), Some(1));
    let v = json(&hit);
    assert_eq!(v["answers"][0]["state"], "affected");
    assert_eq!(
        v["answers"][0]["packages"][0]["package"]["name"],
        "python3-multipart"
    );

    let unknown = run(
        sb.cmd(),
        vec![
            "--color",
            "never",
            "cve",
            "CVE-2026-99999",
            "--distro",
            "fedora:43",
            "--packages-from",
            inv,
        ],
    )
    .await;
    assert_eq!(unknown.status.code(), Some(0));
    assert!(
        stdout(&unknown).contains("not a statement that this host is safe"),
        "{}",
        stdout(&unknown)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn check_accepts_an_inventory_and_scores_it_and_bad_input_is_rejected() {
    let (_server, sb, inv) = inventory_sandbox().await;
    let chk = run(
        sb.cmd(),
        vec![
            "--distro",
            "fedora:43",
            "--packages-from",
            inv,
            "-f",
            "json",
        ],
    )
    .await;
    assert_eq!(chk.status.code(), Some(0));
    let v = json(&chk);
    assert_eq!(v["targets"].as_array().unwrap().len(), 3);
    assert!(v["score"]["grade"].is_string());

    let bad = run(sb.cmd(), vec!["cve", "CVE-12", "--distro", "fedora:43"]).await;
    assert_eq!(bad.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("not a CVE id"));
    let none = run(sb.cmd(), vec!["cve", "--distro", "fedora:43"]).await;
    assert_eq!(none.status.code(), Some(64));
    let missing = run(
        sb.cmd(),
        vec![
            "pending",
            "--distro",
            "fedora:43",
            "--packages-from",
            "/nonexistent/inv.txt",
        ],
    )
    .await;
    assert_eq!(missing.status.code(), Some(64));
}

#[test]
fn restart_reads_proc_without_a_package_manager_and_emits_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("amivuln")
        .unwrap()
        .env_clear()
        .env("HOME", dir.path())
        .args(["restart", "-f", "json"])
        .output()
        .unwrap();
    // 0 when nothing runs a replaced file, 1 when something does (a CI runner
    // may have just been updated); never an error.
    assert!(
        matches!(out.status.code(), Some(0 | 1)),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    assert_eq!(v["kind"], "restart");
    assert!(v["inspected"].as_u64().unwrap() >= 1);
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/book/src/schema/restart-v1.json"
    ))
    .unwrap();
    let _ = schema;
}

#[tokio::test(flavor = "multi_thread")]
async fn exit_code_precedence_is_unresolved_over_violation_over_success() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let common = ["--distro", "fedora:43", "-f", "json"];
    let affected = "python3-multipart@0:1.3.0-1.fc43";

    // 0: findings below the (absent) threshold, 1: a violation.
    let ok = run(sb.cmd(), [vec![affected], common.to_vec()].concat()).await;
    assert_eq!(ok.status.code(), Some(0));
    let hit = run(
        sb.cmd(),
        [vec![affected, "--fail-on", "high"], common.to_vec()].concat(),
    )
    .await;
    assert_eq!(hit.status.code(), Some(1));

    // 3 beats 1: the same violation plus a target that cannot be resolved.
    let both = run(
        sb.cmd(),
        [
            vec![affected, "a b@1", "--fail-on", "high"],
            common.to_vec(),
        ]
        .concat(),
    )
    .await;
    assert_eq!(
        both.status.code(),
        Some(3),
        "{}{}",
        stdout(&both),
        String::from_utf8_lossy(&both.stderr)
    );

    // 64 beats everything: a bad --fail-on value is a usage error.
    let usage = run(
        sb.cmd(),
        [vec![affected, "--fail-on", "bogus"], common.to_vec()].concat(),
    )
    .await;
    assert_eq!(usage.status.code(), Some(64));
}

#[tokio::test(flavor = "multi_thread")]
async fn output_writes_atomically_and_keeps_the_old_file_on_a_usage_error() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let file = sb.path().join("amivuln.prom");
    let file_arg: &'static str = Box::leak(file.display().to_string().into_boxed_str());

    let out = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "-f",
            "prometheus",
            "--output",
            file_arg,
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stdout.is_empty(),
        "stdout must stay empty with --output"
    );
    let written = std::fs::read_to_string(&file).unwrap();
    assert!(written.contains("amivuln_run_complete 1"), "{written}");
    assert!(!sb.path().join(".amivuln.prom.tmp").exists());

    // A usage error produces no output and must not clobber the good file.
    let bad = run(
        sb.cmd(),
        vec![
            "x@1",
            "-f",
            "bogus",
            "--distro",
            "fedora:43",
            "--output",
            file_arg,
        ],
    )
    .await;
    assert_eq!(bad.status.code(), Some(64));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), written);
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_serves_a_check_over_stdio() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let input = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_target","arguments":{"targets":["python3-multipart@0:1.3.0-1.fc43"],"distro":"fedora:43"}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_target","arguments":{"targets":["--output=/tmp/x"]}}}"#,
    ]
    .join("\n");
    let mut cmd = sb.cmd();
    cmd.arg("mcp").write_stdin(input);
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let replies: Vec<serde_json::Value> = stdout(&out)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(replies.len(), 3, "{replies:?}");
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "amivuln");
    assert_eq!(replies[1]["result"]["isError"], false, "{}", replies[1]);
    let report: serde_json::Value =
        serde_json::from_str(replies[1]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(report["complete"], true);
    assert_eq!(report["targets"][0]["summary"]["high"], 1);
    assert_eq!(
        replies[2]["error"]["code"], -32602,
        "option injection must be refused"
    );
}
