// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `amivuln mcp`: a read-only Model Context Protocol server on stdio.
//!
//! Messages are newline-delimited JSON-RPC 2.0. Every tool is a fixed
//! `amivuln` invocation built from validated arguments and run in process:
//! there is no shell, no file path input and no write option. Tool output is
//! the same versioned JSON the command line prints with `-f json`.

use std::io::{BufRead, Read, Write};

use serde_json::{Value, json};

use amivuln_core::ExitCode;

/// Longest accepted request line.
const MAX_LINE: u64 = 1024 * 1024;
/// Largest tool result returned to the client.
const MAX_RESULT: usize = 4 * 1024 * 1024;
/// Most targets in one `check_target` call.
const MAX_TARGETS: usize = 20;
/// Protocol revisions this server speaks, newest first.
const PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// What a tool run produced: exit code, stdout and stderr.
pub(crate) type ToolOutput = (i32, Vec<u8>, Vec<u8>);

fn tools() -> Value {
    let no_args = json!({"type": "object", "properties": {}, "additionalProperties": false});
    json!([
        {
            "name": "check_target",
            "description": "Which CVEs apply to installed packages or package versions on this host, taking distro backports into account. Targets are package names, name@version or package URLs (pkg:...).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array", "minItems": 1, "maxItems": MAX_TARGETS,
                        "items": {"type": "string", "maxLength": 256},
                        "description": "For example [\"openssl\", \"nginx@1:1.26.2-1.fc41\", \"pkg:rpm/fedora/curl@8.9.1-1.fc41\"]."
                    },
                    "distro": {
                        "type": "string", "maxLength": 32,
                        "description": "Treat the host as another distro, for example fedora:44, arch, debian:12, ubuntu:24.04, rocky:9."
                    }
                },
                "required": ["targets"],
                "additionalProperties": false
            }
        },
        {
            "name": "check_cve",
            "description": "Is this host affected by a CVE? Scans every installed package.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"}},
                "required": ["id"],
                "additionalProperties": false
            }
        },
        {
            "name": "pending_updates",
            "description": "Which pending updates close the most risk, ranked by the findings they fix.",
            "inputSchema": no_args.clone()
        },
        {
            "name": "needs_restart",
            "description": "Running processes that still use files an update replaced, mapped to their systemd units.",
            "inputSchema": no_args.clone()
        },
        {
            "name": "list_services",
            "description": "Every running systemd service checked for CVEs, with a score per service.",
            "inputSchema": no_args
        }
    ])
}

fn valid_cve(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, seq)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && seq.len() >= 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && seq.bytes().all(|b| b.is_ascii_digit())
}

fn valid_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.starts_with('-') && s.chars().all(|c| !c.is_control())
}

/// The command line for a tool call, or why the arguments are invalid.
fn tool_args(name: &str, args: &Value) -> Result<Vec<String>, String> {
    let known: &[&str] = match name {
        "check_target" => &["targets", "distro"],
        "check_cve" => &["id"],
        "pending_updates" | "needs_restart" | "list_services" => &[],
        _ => return Err(format!("unknown tool {name:?}")),
    };
    if let Some(obj) = args.as_object()
        && let Some(extra) = obj.keys().find(|k| !known.contains(&k.as_str()))
    {
        return Err(format!("unexpected argument {extra:?}"));
    }
    let mut cmd: Vec<String> = Vec::new();
    match name {
        "check_target" => {
            let targets = args
                .get("targets")
                .and_then(Value::as_array)
                .filter(|t| !t.is_empty() && t.len() <= MAX_TARGETS)
                .ok_or_else(|| format!("targets must hold 1 to {MAX_TARGETS} strings"))?;
            cmd.push("check".to_owned());
            for t in targets {
                let t = t.as_str().ok_or("every target must be a string")?;
                if !valid_text(t, 256) {
                    return Err(format!("invalid target {t:?}"));
                }
                // Bound to a flag so a value can never be read as an option.
                cmd.push(
                    if t.starts_with("pkg:") {
                        "--purl"
                    } else {
                        "--package"
                    }
                    .to_owned(),
                );
                cmd.push(t.to_owned());
            }
            if let Some(d) = args.get("distro") {
                let d = d.as_str().ok_or("distro must be a string")?;
                if !valid_text(d, 32)
                    || !d
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'.')
                {
                    return Err(format!("invalid distro {d:?}"));
                }
                cmd.push("--distro".to_owned());
                cmd.push(d.to_owned());
            }
        }
        "check_cve" => {
            let id = args
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| valid_cve(id))
                .ok_or("id must look like CVE-2024-6387")?;
            cmd.extend(["cve".to_owned(), id.to_owned()]);
        }
        "pending_updates" => cmd.push("pending".to_owned()),
        "needs_restart" => cmd.push("restart".to_owned()),
        _ => cmd.push("services".to_owned()),
    }
    Ok(cmd)
}

fn reply(id: &Value, result: Value) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("jsonrpc".to_owned(), Value::from("2.0"));
    m.insert("id".to_owned(), id.clone());
    m.insert("result".to_owned(), result);
    Value::Object(m)
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Handles one request. `None` means no response (a notification).
fn handle(request: &Value, run_tool: &mut dyn FnMut(&[String]) -> ToolOutput) -> Option<Value> {
    let Some(obj) = request.as_object() else {
        return Some(error(
            &Value::Null,
            -32600,
            "a request must be a JSON object",
        ));
    };
    let id = obj.get("id");
    let method = obj.get("method").and_then(Value::as_str);
    let (Some(id), Some(method)) = (id, method) else {
        // A notification, or a response to us (we send no requests).
        return match (id, method) {
            (None, Some(_)) => None,
            _ => Some(error(
                id.unwrap_or(&Value::Null),
                -32600,
                "a request needs an id and a method",
            )),
        };
    };
    let params = obj.get("params").unwrap_or(&Value::Null);
    Some(match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str);
            let version = PROTOCOLS
                .iter()
                .find(|v| Some(**v) == asked)
                .unwrap_or(&PROTOCOLS[0]);
            reply(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "amivuln", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Read-only CVE checks for this host. Results are amivuln JSON reports; check `complete` and `sources` before treating an empty result as clean."
                }),
            )
        }
        "ping" => reply(id, json!({})),
        "tools/list" => reply(id, json!({"tools": tools()})),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(error(id, -32602, "tools/call needs a tool name"));
            };
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let command_line = match tool_args(name, &args) {
                Ok(a) => a,
                Err(e) => return Some(error(id, -32602, &e)),
            };
            let (code, out, err) = run_tool(&command_line);
            // 0..=3 all carry a report; usage and internal errors do not.
            let failed = code >= 64 || out.is_empty();
            let bytes = if failed { err } else { out };
            if bytes.len() > MAX_RESULT {
                return Some(reply(
                    id,
                    json!({"isError": true, "content": [{"type": "text", "text": "result too large"}]}),
                ));
            }
            reply(
                id,
                json!({
                    "isError": failed,
                    "content": [{"type": "text", "text": String::from_utf8_lossy(&bytes)}]
                }),
            )
        }
        _ => error(id, -32601, "method not found"),
    })
}

/// Serves requests from `input` until it closes.
pub(crate) fn serve(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    run_tool: &mut dyn FnMut(&[String]) -> ToolOutput,
) -> ExitCode {
    loop {
        let mut line = Vec::new();
        match input.take(MAX_LINE + 1).read_until(b'\n', &mut line) {
            Ok(0) => return ExitCode::Success,
            Ok(_) => {}
            Err(_) => return ExitCode::Internal,
        }
        let response = if line.len() as u64 > MAX_LINE {
            // The rest of the line cannot be trusted to be framed; stop here.
            let r = error(&Value::Null, -32600, "request line too long");
            let _ = writeln!(output, "{r}");
            let _ = output.flush();
            return ExitCode::Usage;
        } else if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        } else {
            match serde_json::from_slice::<Value>(&line) {
                Ok(v) => handle(&v, run_tool),
                Err(_) => Some(error(&Value::Null, -32700, "parse error")),
            }
        };
        if let Some(r) = response
            && (writeln!(output, "{r}").is_err() || output.flush().is_err())
        {
            return ExitCode::Internal;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(input: &str) -> Vec<Value> {
        let mut seen: Vec<Vec<String>> = Vec::new();
        let mut runner = |argv: &[String]| -> ToolOutput {
            seen.push(argv.to_vec());
            (0, b"{\"schema_version\":1}".to_vec(), Vec::new())
        };
        let mut out = Vec::new();
        let code = serve(&mut input.as_bytes(), &mut out, &mut runner);
        assert_eq!(code, ExitCode::Success);
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn initialize_list_and_ping() {
        let r = call(concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
            "\n",
        ));
        assert_eq!(r.len(), 3, "a notification gets no response");
        assert_eq!(r[0]["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(r[0]["result"]["serverInfo"]["name"], "amivuln");
        let names: Vec<&str> = r[1]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "check_target",
                "check_cve",
                "pending_updates",
                "needs_restart",
                "list_services"
            ]
        );
        assert_eq!(r[2]["result"], json!({}));
    }

    #[test]
    fn an_unknown_protocol_gets_the_newest_one() {
        let r = call(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}\n",
        );
        assert_eq!(r[0]["result"]["protocolVersion"], PROTOCOLS[0]);
    }

    #[test]
    fn tools_map_to_fixed_command_lines() {
        let ok = |name: &str, a: Value| tool_args(name, &a).unwrap();
        assert_eq!(
            ok(
                "check_target",
                json!({"targets": ["openssl", "pkg:rpm/fedora/curl@8-1.fc41"], "distro": "fedora:44"})
            ),
            [
                "check",
                "--package",
                "openssl",
                "--purl",
                "pkg:rpm/fedora/curl@8-1.fc41",
                "--distro",
                "fedora:44"
            ]
        );
        assert_eq!(
            ok("check_cve", json!({"id": "CVE-2024-6387"})),
            ["cve", "CVE-2024-6387"]
        );
        assert_eq!(ok("pending_updates", json!({})), ["pending"]);
        assert_eq!(ok("needs_restart", json!({})), ["restart"]);
        assert_eq!(ok("list_services", json!({})), ["services"]);
    }

    #[test]
    fn hostile_arguments_are_rejected() {
        let bad = |name: &str, a: Value| assert!(tool_args(name, &a).is_err(), "{name} {a}");
        bad("check_target", json!({"targets": ["--output=/etc/passwd"]}));
        bad("check_target", json!({"targets": ["-f"]}));
        bad("check_target", json!({"targets": ["a\nb"]}));
        bad("check_target", json!({"targets": []}));
        bad(
            "check_target",
            json!({"targets": ["ok"], "distro": "fedora:44 --offline"}),
        );
        bad(
            "check_target",
            json!({"targets": ["ok"], "output": "/tmp/x"}),
        );
        bad(
            "check_target",
            json!({"targets": vec!["a"; MAX_TARGETS + 1]}),
        );
        bad("check_cve", json!({"id": "CVE-2024-6387; rm -rf /"}));
        bad("check_cve", json!({"id": "cve-2024-6387"}));
        bad("pending_updates", json!({"extra": 1}));
        bad("shell", json!({}));
    }

    #[test]
    fn errors_and_failed_tools() {
        let r = call(concat!(
            "not json\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"nope"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_cve","arguments":{"id":"x"}}}"#,
            "\n",
            r#"[1,2]"#,
            "\n",
        ));
        assert_eq!(r[0]["error"]["code"], -32700);
        assert_eq!(r[1]["error"]["code"], -32601);
        assert_eq!(r[2]["error"]["code"], -32602);
        assert_eq!(r[3]["error"]["code"], -32600);
    }

    #[test]
    fn a_tool_result_is_the_json_report_and_usage_errors_are_flagged() {
        let mut runner = |argv: &[String]| -> ToolOutput {
            if argv.first().map(String::as_str) == Some("pending") {
                (64, Vec::new(), b"bad flag".to_vec())
            } else {
                (1, b"{\"complete\":true}".to_vec(), Vec::new())
            }
        };
        let ok = handle(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"needs_restart"}}),
            &mut runner,
        )
        .unwrap();
        assert_eq!(
            ok["result"]["isError"], false,
            "exit 1 still carries a report"
        );
        assert_eq!(ok["result"]["content"][0]["text"], "{\"complete\":true}");
        let bad = handle(
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pending_updates"}}),
            &mut runner,
        )
        .unwrap();
        assert_eq!(bad["result"]["isError"], true);
        assert_eq!(bad["result"]["content"][0]["text"], "bad flag");
    }

    #[test]
    fn an_oversized_line_stops_the_server() {
        let big = format!("{}\n", "x".repeat(usize::try_from(MAX_LINE).unwrap() + 10));
        let mut runner = |_: &[String]| -> ToolOutput { (0, Vec::new(), Vec::new()) };
        let mut out = Vec::new();
        let code = serve(&mut big.as_bytes(), &mut out, &mut runner);
        assert_eq!(code, ExitCode::Usage);
        assert!(String::from_utf8(out).unwrap().contains("too long"));
    }
}
