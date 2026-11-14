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
use wiremock::matchers::{body_string_contains, header, method, path, path_regex};
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
    assert!(String::from_utf8_lossy(&bad.stderr).contains("prometheus, cyclonedx or openvex"));
}

/// The messages follow the locale; the formats other programs read do not.
#[tokio::test(flavor = "multi_thread")]
async fn messages_follow_the_locale_and_machine_formats_do_not() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let target = "python3-multipart@0:1.3.0-1.fc43";
    let ask = |format: &'static str| vec!["-f", format, target, "--distro", "fedora:43"];

    let mut portuguese = sb.cmd();
    portuguese.env("LC_ALL", "pt_BR.UTF-8");
    let pt = run(portuguese, ask("detail")).await;
    let text = stdout(&pt);
    assert!(text.contains("Corrigido em:"), "{text}");
    assert!(text.contains("resultado: completo"), "{text}");
    assert!(text.contains("Afetados:"), "{text}");
    assert!(!text.contains("result: complete"), "{text}");

    // LANG is used when LC_ALL is not set; C and unknown languages are English.
    let mut lang = sb.cmd();
    lang.env("LANG", "pt_BR.UTF-8");
    assert!(stdout(&run(lang, ask("summary")).await).contains("resultado: completo"));
    let mut posix = sb.cmd();
    posix.env("LC_ALL", "C").env("LANG", "pt_BR.UTF-8");
    assert!(stdout(&run(posix, ask("summary")).await).contains("result: complete"));

    // JSON, SARIF and the other machine formats are identical in every locale.
    for format in ["json", "sarif", "csv", "prometheus", "cyclonedx", "openvex"] {
        let mut a = sb.cmd();
        a.env("LC_ALL", "pt_BR.UTF-8");
        let mut b = sb.cmd();
        b.env("LC_ALL", "C");
        let (in_pt, in_en) = (run(a, ask(format)).await, run(b, ask(format)).await);
        let strip = |o: &std::process::Output| {
            // The generation time differs between two runs; nothing else may.
            stdout(o)
                .lines()
                .filter(|l| {
                    [
                        "generated_at",
                        "timestamp",
                        "last_run",
                        "age_s",
                        "age_seconds",
                    ]
                    .iter()
                    .all(|word| !l.contains(word))
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(
            strip(&in_pt),
            strip(&in_en),
            "{format} depends on the locale"
        );
    }

    // A usage error is translated too; the exit code is not.
    let mut bad = sb.cmd();
    bad.env("LC_ALL", "pt_BR.UTF-8");
    let failed = run(
        bad,
        vec![
            "--packages-from",
            "/nonexistent/list.txt",
            "--distro",
            "fedora:43",
        ],
    )
    .await;
    assert_eq!(failed.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&failed.stderr).starts_with("erro:"));
}

#[tokio::test(flavor = "multi_thread")]
async fn cyclonedx_and_openvex_state_what_the_distribution_says() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let args =
        |format: &'static str, pkg: &'static str| vec!["-f", format, pkg, "--distro", "fedora:43"];

    // 1.3.0 is below the fix: affected, with the update to move to.
    let bom = run(
        sb.cmd(),
        args("cyclonedx", "python3-multipart@0:1.3.0-1.fc43"),
    )
    .await;
    assert_eq!(
        bom.status.code(),
        Some(0),
        "formats do not set the exit code"
    );
    let b = json(&bom);
    assert_eq!(b["bomFormat"], "CycloneDX");
    assert_eq!(b["specVersion"], "1.6");
    assert_eq!(b["components"][0]["name"], "python3-multipart");
    assert_eq!(b["metadata"]["properties"][0]["value"], "true");
    let v = &b["vulnerabilities"][0];
    assert_eq!(v["id"], "CVE-2026-28356");
    assert_eq!(v["analysis"]["state"], "exploitable");
    assert_eq!(v["analysis"]["response"][0], "update");
    assert_eq!(v["affects"][0]["ref"], b["components"][0]["bom-ref"]);

    // 1.3.1 carries the fix. It is not a finding (JSON stays empty), but the
    // VEX states it: that statement is what lets a scanner drop the match.
    let fixed = "python3-multipart@0:1.3.1-1.fc43";
    let plain = run(sb.cmd(), args("json", fixed)).await;
    assert_eq!(
        json(&plain)["targets"][0]["findings"],
        serde_json::json!([])
    );
    let vex = run(sb.cmd(), args("openvex", fixed)).await;
    let x = json(&vex);
    assert_eq!(x["@context"], "https://openvex.dev/ns/v0.2.0");
    let st = &x["statements"][0];
    assert_eq!(st["vulnerability"]["name"], "CVE-2026-28356");
    assert_eq!(st["status"], "fixed");
    assert!(
        st["products"][0]["@id"]
            .as_str()
            .unwrap()
            .starts_with("pkg:rpm/fedora/python3-multipart@1.3.1-1.fc43")
    );
    let bom_fixed = run(sb.cmd(), args("cyclonedx", fixed)).await;
    assert_eq!(
        json(&bom_fixed)["vulnerabilities"][0]["analysis"]["state"],
        "resolved"
    );

    // The same run renders the same bytes, down to the document id.
    let again = run(sb.cmd(), args("openvex", fixed)).await;
    assert_eq!(x["@id"], json(&again)["@id"]);
    assert_eq!(x["statements"], json(&again)["statements"]);
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
async fn a_missing_ca_file_is_a_usage_error() {
    let server = MockServer::start().await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let cfg = sb.path().join("ca.toml");
    std::fs::write(&cfg, "[network]\nca_file = \"/nonexistent/corp.pem\"\n").unwrap();
    let cfg_arg: &'static str = Box::leak(cfg.display().to_string().into_boxed_str());
    let out = run(
        sb.cmd_opts(false),
        vec![
            "--config",
            cfg_arg,
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("network.ca_file"));
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

#[tokio::test(flavor = "multi_thread")]
async fn sbom_input_checks_os_packages_and_lists_the_rest() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let sbom = sb.path().join("bom.cdx.json");
    std::fs::write(
        &sbom,
        r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"type":"library","name":"python3-multipart","purl":"pkg:rpm/fedora/python3-multipart@0:1.3.0-1.fc43"},
            {"type":"library","name":"left-pad","purl":"pkg:npm/left-pad@1.3.0",
             "components":[{"type":"library","name":"inner","purl":"pkg:npm/inner@1.0.0"}]},
            {"type":"file","name":"no purl here"}
        ]}"#,
    )
    .unwrap();
    let sbom_arg: &'static str = Box::leak(sbom.display().to_string().into_boxed_str());
    let out = run(
        sb.cmd(),
        vec![
            "--sbom",
            sbom_arg,
            "--distro",
            "fedora:43",
            "-f",
            "json",
            "--fail-on",
            "high",
        ],
    )
    .await;
    // 3 (unresolved) outranks 1 (policy violation).
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    assert_eq!(v["targets"][0]["summary"]["high"], 1);
    let unresolved: Vec<&str> = v["unresolved"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["input"].as_str().unwrap())
        .collect();
    assert_eq!(unresolved, ["sbom:pkg:npm", "sbom:no-purl"], "{v}");
    assert!(
        v["unresolved"][0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("2 component")
    );

    let junk = sb.path().join("junk.json");
    std::fs::write(&junk, r#"{"bomFormat":"SPDX"}"#).unwrap();
    let junk_arg: &'static str = Box::leak(junk.display().to_string().into_boxed_str());
    let bad = run(sb.cmd(), vec!["--sbom", junk_arg, "--distro", "fedora:43"]).await;
    assert_eq!(bad.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("not a CycloneDX"));
}

/// Regression: the webhook client ignored the `[network]` settings, so behind
/// a proxy or with a company CA the scan worked and the alert never left.
#[tokio::test(flavor = "multi_thread")]
async fn the_webhook_uses_the_network_settings_of_the_scan() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let hook = MockServer::start().await;
    let ua = format!("amivuln/{} team-sre", env!("CARGO_PKG_VERSION"));
    Mock::given(method("POST"))
        .and(header("user-agent", ua.as_str()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&hook)
        .await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let cfg = sb.path().join("notify-ua.toml");
    std::fs::write(
        &cfg,
        format!(
            "[network]\nallow_insecure_http = true\nuser_agent_suffix = \"team-sre\"\n\
             [sources.distro]\nurl = \"{}/updates\"\n\
             [sources.kev]\nurl = \"{}/kev.json\"\n\
             [sources.epss]\nurl = \"{}/epss\"\n\
             [notify]\nwebhook = \"{}\"\non = \"violation\"\n",
            server.uri(),
            server.uri(),
            server.uri(),
            hook.uri(),
        ),
    )
    .unwrap();
    let cfg_arg: &'static str = Box::leak(cfg.display().to_string().into_boxed_str());
    let out = run(
        sb.cmd_opts(false),
        vec![
            "--config",
            cfg_arg,
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "--fail-on",
            "high",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_violation_posts_a_webhook_summary() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let hook = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer secret-token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&hook)
        .await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let token = sb.path().join("token");
    std::fs::write(&token, "secret-token\n").unwrap();
    let cfg = sb.path().join("notify.toml");
    std::fs::write(
        &cfg,
        format!(
            "[network]\nallow_insecure_http = true\n\
             [sources.distro]\nurl = \"{}/updates\"\n\
             [sources.kev]\nurl = \"{}/kev.json\"\n\
             [sources.epss]\nurl = \"{}/epss\"\n\
             [notify]\nwebhook = \"{}\"\nbearer_file = \"{}\"\non = \"violation\"\n",
            server.uri(),
            server.uri(),
            server.uri(),
            hook.uri(),
            token.display()
        ),
    )
    .unwrap();
    let cfg_arg: &'static str = Box::leak(cfg.display().to_string().into_boxed_str());
    let out = run(
        sb.cmd_opts(false),
        vec![
            "--config",
            cfg_arg,
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "--fail-on",
            "high",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // A clean run on the same hook with on = violation sends nothing.
    let other_cfg = sb.path().join("notify2.toml");
    std::fs::write(
        &other_cfg,
        std::fs::read_to_string(&cfg)
            .unwrap()
            .replace("on = \"violation\"", "on = \"incomplete\""),
    )
    .unwrap();
    let other_arg: &'static str = Box::leak(other_cfg.display().to_string().into_boxed_str());
    let ok = run(
        sb.cmd_opts(false),
        vec![
            "--config",
            other_arg,
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "--fail-on",
            "high",
        ],
    )
    .await;
    assert_eq!(ok.status.code(), Some(1), "no notification is sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broken_webhook_warns_and_keeps_the_exit_code() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let cfg = sb.path().join("notify3.toml");
    std::fs::write(
        &cfg,
        format!(
            "[network]\nallow_insecure_http = true\n\
             [sources.distro]\nurl = \"{}/updates\"\n\
             [sources.kev]\nurl = \"{}/kev.json\"\n\
             [sources.epss]\nurl = \"{}/epss\"\n\
             [notify]\nwebhook = \"http://127.0.0.1:1/dead\"\n",
            server.uri(),
            server.uri(),
            server.uri()
        ),
    )
    .unwrap();
    let cfg_arg: &'static str = Box::leak(cfg.display().to_string().into_boxed_str());
    let out = run(
        sb.cmd_opts(false),
        vec![
            "--config",
            cfg_arg,
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "--fail-on",
            "high",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(1));
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(e.contains("warning: notify failed"), "{e}");
}

#[tokio::test(flavor = "multi_thread")]
async fn osv_advisories_stay_with_the_package_they_were_found_for() {
    // Regression: advisories of one package were judged against every other
    // package of the run, so curl 1.0 inherited openssl's fix version.
    let server = MockServer::start().await;
    // Both packages go to OSV in ONE request, and the answer holds one result
    // per query in the order they were asked.
    Mock::given(method("POST"))
        .and(path("/osv/v1/querybatch"))
        .respond_with(|req: &wiremock::Request| {
            let asked: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            let results: Vec<_> = asked["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| {
                    if q["package"]["name"] == "openssl" {
                        serde_json::json!({"vulns": [{"id": "DEBIAN-CVE-2023-5678"}]})
                    } else {
                        serde_json::json!({})
                    }
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
        })
        .expect(1)
        .mount(&server)
        .await;
    let advisory =
        include_str!("../../../tests/fixtures/http/osv/2026-11-08/DEBIAN-CVE-2023-5678.json");
    Mock::given(method("GET"))
        .and(path("/osv/v1/vulns/DEBIAN-CVE-2023-5678"))
        .respond_with(ResponseTemplate::new(200).set_body_string(advisory))
        .mount(&server)
        .await;
    let home = tempfile::tempdir().unwrap();
    let cfg = home.path().join("cfg.toml");
    std::fs::write(
        &cfg,
        format!(
            "[network]\nallow_insecure_http = true\n[sources.distro]\nurl = \"{}/osv\"\n",
            server.uri()
        ),
    )
    .unwrap();
    let inv = home.path().join("inv.txt");
    std::fs::write(&inv, "openssl@3.0.10-1\ncurl@1.0-1\n").unwrap();
    let cfg_arg: &'static str = Box::leak(cfg.display().to_string().into_boxed_str());
    let inv_arg: &'static str = Box::leak(inv.display().to_string().into_boxed_str());
    let out = Command::cargo_bin("amivuln")
        .unwrap()
        .env("LC_ALL", "C")
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("PATH", "/nonexistent")
        .args([
            "--config",
            cfg_arg,
            "--packages-from",
            inv_arg,
            "--distro",
            "debian:12",
            "-f",
            "json",
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids = |name: &str| -> Vec<String> {
        v["targets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["package"]["name"] == name)
            .flat_map(|t| t["findings"].as_array().unwrap().iter())
            .map(|f| f["id"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(ids("openssl"), ["CVE-2023-5678"], "{v}");
    assert!(ids("curl").is_empty(), "curl inherited {:?}", ids("curl"));
}

/// openSUSE advisories are filed under the source package, so a package that
/// the host knows by its source name is found and a fixed one is not.
#[tokio::test(flavor = "multi_thread")]
async fn opensuse_packages_are_judged_by_the_advisories_of_their_source() {
    let server = MockServer::start().await;
    // OSV answers a query only when the version is in the affected range.
    Mock::given(method("POST"))
        .and(path("/osv/v1/querybatch"))
        .respond_with(|req: &wiremock::Request| {
            let asked: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            let results: Vec<_> = asked["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| {
                    let hit = q["package"]["ecosystem"] == "openSUSE:Leap 15.6"
                        && q["package"]["name"] == "examplelib"
                        && q["version"] == "1.0-150600.1.1";
                    if hit {
                        serde_json::json!({"vulns": [{"id": "SUSE-SU-2099:0001-1"}, {"id": "SUSE-RU-2099:0002-1"}]})
                    } else {
                        serde_json::json!({})
                    }
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/osv/v1/vulns/SUSE-SU-2099:0001-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "SUSE-SU-2099:0001-1",
            "upstream": ["CVE-2099-0001"],
            "affected": [{
                "package": {"ecosystem": "openSUSE:Leap 15.6", "name": "examplelib"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-150600.2.1"}]}]
            }]
        })))
        .mount(&server)
        .await;
    let home = tempfile::tempdir().unwrap();
    let cfg = home.path().join("cfg.toml");
    std::fs::write(
        &cfg,
        format!(
            "[network]\nallow_insecure_http = true\n[sources.distro]\nurl = \"{}/osv\"\n[sources.kev]\nenabled = false\n[sources.epss]\nenabled = false\n",
            server.uri()
        ),
    )
    .unwrap();
    let inv = home.path().join("inv.txt");
    std::fs::write(&inv, "examplelib@1.0-150600.1.1\n").unwrap();
    let ask = |inventory: &std::path::Path| {
        Command::cargo_bin("amivuln")
            .unwrap()
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_CACHE_HOME", home.path().join("cache"))
            .env("PATH", "/nonexistent")
            .args(["--config"])
            .arg(&cfg)
            .args(["--packages-from"])
            .arg(inventory)
            .args(["--distro", "opensuse:15.6", "-f", "json"])
            .output()
            .unwrap()
    };
    let out = ask(&inv);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let t = &v["targets"][0];
    assert_eq!(t["package"]["ecosystem"], "opensuse", "{v}");
    assert!(
        t["package"]["purl"]
            .as_str()
            .unwrap()
            .starts_with("pkg:rpm/opensuse/examplelib@")
    );
    assert_eq!(t["findings"][0]["id"], "CVE-2099-0001", "{v}");
    assert_eq!(
        t["findings"][0]["distro_status"]["fixed_in"],
        "1.0-150600.2.1"
    );
    // The recommended update (SUSE-RU) is not a security advisory: never fetched.
    assert_eq!(t["findings"].as_array().unwrap().len(), 1);

    // The fixed build is clean.
    std::fs::write(&inv, "examplelib@1.0-150600.2.1\n").unwrap();
    let fixed = ask(&inv);
    let v: serde_json::Value = serde_json::from_slice(&fixed.stdout).unwrap();
    assert_eq!(v["targets"][0]["findings"], serde_json::json!([]), "{v}");
}

/// A Gentoo list is judged by the GLSAs of a directory, offline, per slot; and
/// without the advisories the result is incomplete, never clean.
#[test]
fn gentoo_packages_are_judged_by_the_advisories_of_a_directory() {
    let home = tempfile::tempdir().unwrap();
    let glsa = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/glsa");
    let cfg = home.path().join("cfg.toml");
    let write_config = |path: &std::path::Path| {
        std::fs::write(
            &cfg,
            format!(
                "[network]\nallow_insecure_http = true\n[sources.distro]\npath = \"{}\"\n[sources.kev]\nenabled = false\n[sources.epss]\nenabled = false\n",
                path.display()
            ),
        )
        .unwrap();
    };
    write_config(&glsa);
    let inv = home.path().join("inv.txt");
    std::fs::write(
        &inv,
        "dev-python/joblib@1.1.0\ndev-lang/php:8.2@8.2.20\ndev-lang/php:8.3@8.3.12\nx11-libs/gtk+@3.24.41\n",
    )
    .unwrap();
    let ask = || {
        Command::cargo_bin("amivuln")
            .unwrap()
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_CACHE_HOME", home.path().join("cache"))
            .env("PATH", "/nonexistent")
            .args(["--config"])
            .arg(&cfg)
            .args(["--packages-from"])
            .arg(&inv)
            .args(["--distro", "gentoo", "-f", "json"])
            .output()
            .unwrap()
    };
    let out = ask();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(0), "{v}");
    assert_eq!(v["complete"], true);
    assert_eq!(v["sources"][0]["id"], "glsa");
    let by_name = |name: &str, slot: &str| {
        v["targets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| {
                t["package"]["name"] == name
                    && (slot.is_empty()
                        || t["package"]["purl"]
                            .as_str()
                            .unwrap()
                            .contains(&format!("slot={slot}")))
            })
            .unwrap()
            .clone()
    };
    let joblib = by_name("dev-python/joblib", "");
    assert_eq!(joblib["findings"][0]["id"], "CVE-2022-21797");
    assert_eq!(joblib["findings"][0]["distro_status"]["fixed_in"], "1.2.0");
    assert_eq!(joblib["package"]["ecosystem"], "gentoo");
    assert!(
        joblib["package"]["purl"]
            .as_str()
            .unwrap()
            .starts_with("pkg:generic/gentoo/dev-python/joblib@1.1.0")
    );
    // php 8.2.20 is below its slot's fix; 8.3.12 is at its own.
    let php82 = by_name("dev-lang/php", "8.2");
    assert_eq!(php82["findings"][0]["distro_status"]["fixed_in"], "8.2.24");
    let php83 = by_name("dev-lang/php", "8.3");
    assert_eq!(php83["findings"], serde_json::json!([]));
    assert_eq!(
        by_name("x11-libs/gtk+", "")["findings"],
        serde_json::json!([])
    );

    // No advisories: incomplete (2), and the source says why.
    write_config(&home.path().join("no-such-dir"));
    let missing = ask();
    let m: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(missing.status.code(), Some(2), "{m}");
    assert_eq!(m["complete"], false);
    assert_eq!(m["sources"][0]["status"], "failed");
    assert!(
        m["sources"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("no-such-dir")
    );
    // An empty directory is no answer either.
    let empty = home.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    write_config(&empty);
    let none = ask();
    assert_eq!(none.status.code(), Some(2));
}

/// `--mitigations` shows what Red Hat publishes for an affected CVE, leaves out
/// its "nothing to do" text, and is off unless asked for.
#[tokio::test(flavor = "multi_thread")]
async fn mitigations_come_from_red_hat_only_when_asked_for() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let redhat = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hydra/rest/securitydata/cve/CVE-2026-28356.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "CVE-2026-28356",
            "mitigation": {"value": "Do not\n accept uploads from\n anyone you do not trust.", "lang": "en:US"}
        })))
        .expect(1)
        .mount(&redhat)
        .await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let cfg = sb.path().join("mit.toml");
    std::fs::write(
        &cfg,
        format!(
            "[network]\nallow_insecure_http = true\n[sources.distro]\nurl = \"{}/updates\"\n[sources.kev]\nurl = \"{}/kev.json\"\n[sources.epss]\nurl = \"{}/epss\"\n[sources.mitigations]\nurl = \"{}\"\n",
            server.uri(), server.uri(), server.uri(), redhat.uri()
        ),
    )
    .unwrap();
    let cfg_arg: &'static str = Box::leak(cfg.display().to_string().into_boxed_str());
    let ask = |extra: Vec<&'static str>, format: &'static str| {
        let mut args = vec![
            "--config",
            cfg_arg,
            "-f",
            format,
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
        ];
        args.extend(extra);
        run(sb.cmd_opts(false), args)
    };
    // Off by default: nothing is sent to Red Hat and no field appears.
    let off = ask(vec![], "json").await;
    let o = json(&off);
    assert!(
        o["targets"][0]["findings"][0].get("mitigation").is_none(),
        "{o}"
    );
    assert!(
        !o["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == "redhat-cve")
    );
    assert!(redhat.received_requests().await.unwrap().is_empty());

    let on = ask(vec!["--mitigations"], "json").await;
    let v = json(&on);
    let m = &v["targets"][0]["findings"][0]["mitigation"];
    assert_eq!(m["source"], "redhat");
    assert_eq!(
        m["text"],
        "Do not accept uploads from anyone you do not trust."
    );
    assert_eq!(
        m["url"],
        "https://access.redhat.com/security/cve/CVE-2026-28356"
    );
    assert!(
        v["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == "redhat-cve" && s["status"] == "ok")
    );

    let text = stdout(&ask(vec!["--mitigations"], "detail").await);
    assert!(
        text.contains("mitigation (Red Hat, not checked on this host): Do not accept uploads"),
        "{text}"
    );
    let bom = json(&ask(vec!["--mitigations"], "cyclonedx").await);
    assert!(
        bom["vulnerabilities"][0]["workaround"]
            .as_str()
            .unwrap()
            .contains("Do not accept uploads")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_mitigation_lookup_is_reported_not_read_as_none() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let redhat = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&redhat)
        .await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let cfg = sb.path().join("mit2.toml");
    std::fs::write(
        &cfg,
        format!(
            "[network]\nallow_insecure_http = true\nretries = 0\n[sources.distro]\nurl = \"{}/updates\"\n[sources.kev]\nurl = \"{}/kev.json\"\n[sources.epss]\nurl = \"{}/epss\"\n[sources.mitigations]\nurl = \"{}\"\nrequired = true\n",
            server.uri(), server.uri(), server.uri(), redhat.uri()
        ),
    )
    .unwrap();
    let cfg_arg: &'static str = Box::leak(cfg.display().to_string().into_boxed_str());
    let out = run(
        sb.cmd_opts(false),
        vec![
            "--config",
            cfg_arg,
            "--mitigations",
            "-f",
            "json",
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
        ],
    )
    .await;
    let v = json(&out);
    let source = v["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "redhat-cve")
        .unwrap();
    assert_eq!(source["status"], "failed");
    assert!(
        source["detail"]
            .as_str()
            .unwrap()
            .contains("CVE-2026-28356"),
        "{source}"
    );
    assert_eq!(v["complete"], false);
    assert_eq!(out.status.code(), Some(2));
}

/// Runs the binary with a per-test HOME and returns its output.
fn run_home(
    home: &std::path::Path,
    cache: Option<&std::path::Path>,
    args: Vec<&'static str>,
) -> std::process::Output {
    let mut cmd = Command::cargo_bin("amivuln").unwrap();
    cmd.env("HOME", home)
        .env("LC_ALL", "C")
        .env("PATH", "/nonexistent");
    if let Some(cache) = cache {
        cmd.env("XDG_CACHE_HOME", cache);
    }
    cmd.args(args).output().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn the_offline_database_answers_when_the_network_is_gone() {
    // Sandbox A warms a cache against the OSV mock; the archive built from it
    // is installed into sandbox B, whose sources are unreachable.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/osv/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"vulns": [{"id": "DEBIAN-CVE-2023-5678"}]}]
        })))
        .mount(&server)
        .await;
    let advisory =
        include_str!("../../../tests/fixtures/http/osv/2026-11-08/DEBIAN-CVE-2023-5678.json");
    Mock::given(method("GET"))
        .and(path("/osv/v1/vulns/DEBIAN-CVE-2023-5678"))
        .respond_with(ResponseTemplate::new(200).set_body_string(advisory))
        .mount(&server)
        .await;

    let home_a = tempfile::tempdir().unwrap();
    let cache_a = tempfile::tempdir().unwrap();
    let cfg_a = home_a.path().join("cfg.toml");
    std::fs::write(
        &cfg_a,
        format!(
            "[network]\nallow_insecure_http = true\n[sources.distro]\nurl = \"{}/osv\"\n",
            server.uri()
        ),
    )
    .unwrap();
    let inv = home_a.path().join("inv.txt");
    std::fs::write(&inv, "openssl@3.0.10-1\n").unwrap();
    let inv_arg: &'static str = Box::leak(inv.display().to_string().into_boxed_str());
    let cfg_a_arg: &'static str = Box::leak(cfg_a.display().to_string().into_boxed_str());

    let online = Command::cargo_bin("amivuln")
        .unwrap()
        .env("LC_ALL", "C")
        .env("HOME", home_a.path())
        .env("XDG_CACHE_HOME", cache_a.path())
        .env("PATH", "/nonexistent")
        .args([
            "--config",
            cfg_a_arg,
            "--packages-from",
            inv_arg,
            "--distro",
            "debian:12",
            "-f",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        online.status.success(),
        "{}",
        String::from_utf8_lossy(&online.stderr)
    );

    let archive = home_a.path().join("db.tar.zst");
    let archive_arg: &'static str = Box::leak(archive.display().to_string().into_boxed_str());
    let build = run_home(
        home_a.path(),
        Some(cache_a.path()),
        vec!["db", "build", "--archive", archive_arg],
    );
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let verified = run_home(home_a.path(), None, vec!["db", "verify", archive_arg]);
    assert_eq!(verified.status.code(), Some(0));

    // Sandbox B installs the archive and goes offline.
    let home_b = tempfile::tempdir().unwrap();
    let pull = run_home(home_b.path(), None, vec!["db", "pull", archive_arg]);
    assert!(
        pull.status.success(),
        "{}",
        String::from_utf8_lossy(&pull.stderr)
    );
    assert!(
        home_b
            .path()
            .join(".local/share/amivuln/offline/db.sqlite")
            .is_file()
    );

    let dead = home_b.path().join("dead.toml");
    std::fs::write(
        &dead,
        "[network]\nallow_insecure_http = true\n[sources.distro]\nurl = \"http://127.0.0.1:1/osv\"\n",
    )
    .unwrap();
    let dead_arg: &'static str = Box::leak(dead.display().to_string().into_boxed_str());
    let offline = run_home(
        home_b.path(),
        None,
        vec![
            "--config",
            dead_arg,
            "--packages-from",
            inv_arg,
            "--distro",
            "debian:12",
            "--offline",
            "-f",
            "json",
        ],
    );
    let v: serde_json::Value = serde_json::from_slice(&offline.stdout).unwrap_or_default();
    assert_eq!(
        offline.status.code(),
        Some(0),
        "{} | {}",
        String::from_utf8_lossy(&offline.stdout),
        String::from_utf8_lossy(&offline.stderr)
    );
    assert_eq!(v["complete"], true, "{}", offline.stdout.len());
    assert_eq!(v["sources"][0]["id"], "osv");
    assert_eq!(v["sources"][0]["status"], "stale");
    let ids: Vec<&str> = v["targets"][0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"CVE-2023-5678"), "{ids:?}");

    // A tampered archive is rejected with the data error code.
    let bad = home_b.path().join("bad.tar.zst");
    std::fs::copy(&archive, &bad).unwrap();
    {
        let mut bytes = std::fs::read(&bad).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        std::fs::write(&bad, &bytes).unwrap();
    }
    let bad_arg: &'static str = Box::leak(bad.display().to_string().into_boxed_str());
    let rejected = run_home(home_b.path(), None, vec!["db", "verify", bad_arg]);
    assert_eq!(rejected.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("error:"));
}

#[tokio::test(flavor = "multi_thread")]
async fn optional_sources_failing_alone_stay_complete() {
    // Chaos: only kev and epss are down. The distro source answers, so the
    // result is complete and the exit code comes from the findings alone.
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let out = run(
        sb.cmd(),
        vec![
            "python3-multipart@0:1.3.0-1.fc43",
            "--distro",
            "fedora:43",
            "-f",
            "json",
            "--fail-on",
            "high",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(1));
    let v = json(&out);
    assert_eq!(v["complete"], true);
    let statuses: Vec<(&str, &str)> = v["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["id"].as_str().unwrap(), s["status"].as_str().unwrap()))
        .collect();
    assert!(
        statuses.contains(&("fedora-updateinfo", "ok")),
        "{statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .any(|(id, st)| *id == "kev" && *st == "failed")
    );
    assert!(
        statuses
            .iter()
            .any(|(id, st)| *id == "epss" && *st == "failed")
    );
}

/// Writes the ELF sample `name` to `dest`. The samples are stored as hex text
/// under `tests/fixtures/elf` so the repository holds no binary blobs.
fn write_elf_fixture(name: &str, dest: &std::path::Path) {
    let path = format!(
        "{}/../../tests/fixtures/elf/{name}.hex",
        env!("CARGO_MANIFEST_DIR")
    );
    let hex = std::fs::read_to_string(path).unwrap();
    let digits: Vec<u8> = hex.bytes().filter(u8::is_ascii_hexdigit).collect();
    let bytes: Vec<u8> = digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(&String::from_utf8_lossy(pair), 16).unwrap())
        .collect();
    std::fs::write(dest, bytes).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_no_package_owns_is_identified_by_its_package_note() {
    let server = MockServer::start().await;
    mount_fedora(&server).await;
    mount_enrichment(&server).await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    let elf = sb.path().join("multipart-tool");
    write_elf_fixture("with-package-note.elf", &elf);
    let elf_arg: &'static str = Box::leak(elf.display().to_string().into_boxed_str());
    let out = run(
        sb.cmd(),
        vec![elf_arg, "--distro", "fedora:43", "-f", "json"],
    )
    .await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    let pkg = &v["targets"][0]["package"];
    assert_eq!(pkg["name"], "python3-multipart");
    assert_eq!(pkg["provenance"], "embedded_note");
    assert_eq!(v["targets"][0]["summary"]["high"], 1, "{v}");

    // A note for another packaging system is refused, not guessed.
    let wrong = run(
        sb.cmd(),
        vec![elf_arg, "--distro", "debian:12", "-f", "json"],
    )
    .await;
    assert_eq!(wrong.status.code(), Some(3));
    assert!(
        json(&wrong)["unresolved"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("for rpm packages but this host uses deb")
    );
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn unowned_binaries_are_judged_by_their_embedded_go_and_rust_dependencies() {
    let server = MockServer::start().await;
    mount_enrichment(&server).await;
    let osv_batch = |needle: &'static str, id: Option<&'static str>| {
        let vulns = id.map_or_else(
            || serde_json::json!({}),
            |id| serde_json::json!({"vulns": [{"id": id}]}),
        );
        (needle, serde_json::json!({ "results": [vulns] }))
    };
    for (needle, body) in [
        osv_batch("golang.org/x/net", Some("GHSA-4374-p667-p6c8")),
        osv_batch("github.com/pkg/errors", None),
        osv_batch("\"time\"", Some("RUSTSEC-2020-0071")),
        osv_batch("\"serde\"", None),
    ] {
        Mock::given(method("POST"))
            .and(path("/osv/v1/querybatch"))
            .and(body_string_contains(needle))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
    }
    for (id, doc) in [
        (
            "GHSA-4374-p667-p6c8",
            include_str!(
                "../../../tests/fixtures/http/osv/2026-11-10-lang/GHSA-4374-p667-p6c8.json"
            ),
        ),
        (
            "RUSTSEC-2020-0071",
            include_str!("../../../tests/fixtures/http/osv/2026-11-10-lang/RUSTSEC-2020-0071.json"),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/osv/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(doc))
            .mount(&server)
            .await;
    }
    let sb = Sandbox::new(&server.uri(), "/updates");
    let cfg = sb.path().join("lang.toml");
    std::fs::write(
        &cfg,
        format!(
            "[network]\nallow_insecure_http = true\n\
             [sources.osv]\nurl = \"{u}/osv\"\n\
             [sources.kev]\nurl = \"{u}/kev.json\"\n\
             [sources.epss]\nurl = \"{u}/epss\"\n",
            u = server.uri()
        ),
    )
    .unwrap();
    let cfg_arg: &'static str = Box::leak(cfg.display().to_string().into_boxed_str());
    for (file, package, cve, fixed, severity) in [
        (
            "go-app.bin",
            "golang.org/x/net",
            "CVE-2023-39325",
            "0.17.0",
            "high",
        ),
        ("rust-app.bin", "time", "CVE-2020-26235", "0.2.0", "unknown"),
    ] {
        let bin = sb.path().join(file);
        write_elf_fixture(file, &bin);
        let bin_arg: &'static str = Box::leak(bin.display().to_string().into_boxed_str());
        let out = run(
            sb.cmd_opts(false),
            vec![
                "--config",
                cfg_arg,
                bin_arg,
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
            "{file}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v = json(&out);
        let sources: Vec<(&str, &str)> = v["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| (s["id"].as_str().unwrap(), s["status"].as_str().unwrap()))
            .collect();
        assert!(sources.contains(&("osv", "ok")), "{sources:?}");
        assert!(
            !sources.iter().any(|(id, _)| *id == "fedora-updateinfo"),
            "no distro package is involved: {sources:?}"
        );
        let target = v["targets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["package"]["name"] == package)
            .unwrap_or_else(|| panic!("{package} missing: {v}"));
        assert_eq!(target["package"]["provenance"], "embedded_buildinfo");
        let finding = &target["findings"][0];
        assert_eq!(finding["id"], cve);
        assert_eq!(finding["distro_status"]["fixed_in"], fixed);
        assert_eq!(finding["severity"], severity);
        // The other module in the file has no advisory and no finding.
        assert!(
            v["targets"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|t| t["package"]["name"] != package)
                .all(|t| t["findings"].as_array().unwrap().is_empty())
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pid_checks_a_running_executable_and_names_a_missing_process() {
    let server = MockServer::start().await;
    let sb = Sandbox::new(&server.uri(), "/updates");
    // A process that cannot exist: the failure names it instead of guessing.
    let gone = run(
        sb.cmd(),
        vec!["--pid", "4294967295", "--distro", "fedora:43", "-f", "json"],
    )
    .await;
    assert_eq!(gone.status.code(), Some(3));
    let reason = json(&gone)["unresolved"][0]["reason"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(reason.contains("the process is gone"), "{reason}");

    // The test process itself is a real executable that no package owns and
    // that carries no metadata: unresolved, with the file named.
    let me: &'static str = Box::leak(std::process::id().to_string().into_boxed_str());
    let own = run(
        sb.cmd(),
        vec!["--pid", me, "--distro", "fedora:43", "-f", "json"],
    )
    .await;
    // The test binary carries version banners (SQLite, etc), so the string
    // heuristic resolves it. The sandbox has no mock for the resulting
    // packages, so the run is incomplete (exit 2), not clean.
    assert_eq!(
        own.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&own.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failover_tries_the_mirrors_after_a_failed_primary() {
    // The primary port is closed; the mirror serves the same data.
    let mirror = MockServer::start().await;
    mount_fedora(&mirror).await;
    mount_enrichment(&mirror).await;
    let sb = Sandbox::new(&mirror.uri(), "/updates");
    let cfg = sb.path().join("mirror.toml");
    std::fs::write(
        &cfg,
        format!(
            "[network]\nallow_insecure_http = true\n\
             [sources.distro]\nurl = \"http://127.0.0.1:1/updates\"\n\
             fallback = [\"{}/updates\"]\n\
             [sources.kev]\nurl = \"http://127.0.0.1:1/kev.json\"\n\
             [sources.epss]\nurl = \"http://127.0.0.1:1/epss\"\n",
            mirror.uri()
        ),
    )
    .unwrap();
    let cfg_arg: &'static str = Box::leak(cfg.display().to_string().into_boxed_str());
    let out = run(
        sb.cmd_opts(false),
        vec![
            "--config",
            cfg_arg,
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
    assert_eq!(v["complete"], true);
    assert_eq!(v["sources"][0]["status"], "ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn retries_run_out_before_the_mirror_is_abandoned() {
    // Every source dies: the run is incomplete with exit 2, never clean.
    let sb = Sandbox::new("http://127.0.0.1:1", "/updates");
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
    assert_eq!(json(&out)["complete"], false);
}
