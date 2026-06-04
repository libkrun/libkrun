#[cfg(target_os = "freebsd")]
use crate::freebsd::ISO_CONFIG_PATH;
use std::env;
use std::fs;
#[cfg(target_os = "freebsd")]
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

const CONFIG_FILE_PATH: &str = "/.krun_config.json";

// The krun OCI runtime passes a full OCI runtime-spec config.json as the
// config file.  The fields we care about live inside "process".
#[derive(Deserialize, Default)]
struct ProcessConfig {
    args: Option<Vec<String>>,
    env: Option<Vec<String>>,
    cwd: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Default)]
struct Mount {
    #[serde(rename = "destination")]
    destination: Option<String>,
    #[serde(rename = "type")]
    mount_type: Option<String>,
    #[serde(rename = "source")]
    source: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawConfig {
    process: Option<ProcessConfig>,
    // OCI runtime-spec flat format ("args"/"env"/"cwd") and Docker image config
    // aliases ("Cmd"/"Env"/"WorkingDir"/"Cwd") are all accepted.  Only
    // consulted when "process" is absent.
    #[serde(alias = "Cmd")]
    args: Option<Vec<String>>,
    #[serde(alias = "Env")]
    env: Option<Vec<String>>,
    #[serde(alias = "WorkingDir", alias = "Cwd")]
    cwd: Option<String>,
    // Docker image config: Entrypoint is prepended to args/Cmd to form argv.
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[cfg(target_os = "linux")]
    mounts: Option<Vec<Mount>>,
}

#[derive(Default)]
pub struct Config {
    pub argv: Option<Vec<String>>,
    pub workdir: Option<String>,
    #[cfg(target_os = "linux")]
    pub tmpfs: Option<String>,
}

pub fn load(#[cfg(target_os = "linux")] is_mount_point: impl Fn(&str) -> bool) -> Config {
    let path = env::var("KRUN_CONFIG").unwrap_or_else(|_| {
        #[cfg(target_os = "freebsd")]
        if Path::new(ISO_CONFIG_PATH).exists() {
            return ISO_CONFIG_PATH.to_string();
        }
        CONFIG_FILE_PATH.to_string()
    });

    let Ok(raw) = parse_file(&path) else {
        return Config::default();
    };

    // Extract Entrypoint before partially moving raw into process below.
    let entrypoint = raw.entrypoint.filter(|v| !v.is_empty());

    let process = raw.process.unwrap_or(ProcessConfig {
        args: raw.args,
        env: raw.env,
        cwd: raw.cwd,
    });

    // Apply environment variables from the process config.
    for entry in process.env.unwrap_or_default() {
        let Some((key, val)) = entry.split_once('=') else {
            continue;
        };
        let overwrite = matches!(key, "HOME" | "TERM");
        if env::var(key).is_err() || overwrite {
            // SAFETY: single-threaded at this point.
            unsafe { env::set_var(key, val) };
        }
    }

    // Prepend Entrypoint (Docker image config) to args when both are present.
    let base_args = process.args.filter(|v| !v.is_empty());
    let argv = match entrypoint {
        Some(mut ep) => {
            if let Some(args) = base_args {
                ep.extend(args);
            }
            Some(ep)
        }
        None => base_args,
    };
    let workdir = process.cwd;

    // Find the first tmpfs mount whose destination is not already mounted.
    #[cfg(target_os = "linux")]
    let tmpfs = raw.mounts.unwrap_or_default().into_iter().find_map(|m| {
        let dest = m.destination?;
        let ty = m.mount_type.as_deref().unwrap_or("");
        let src = m.source.as_deref().unwrap_or("");
        if ty == "tmpfs" && src == "tmpfs" && !is_mount_point(&dest) {
            Some(dest)
        } else {
            None
        }
    });

    Config {
        argv,
        workdir,
        #[cfg(target_os = "linux")]
        tmpfs,
    }
}

fn parse_file(path: &str) -> Result<RawConfig> {
    let data = fs::read(path).with_context(|| format!("read {path}"))?;
    serde_json::from_slice(&data).with_context(|| format!("parse {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(json: &str) -> RawConfig {
        serde_json::from_str(json).expect("parse")
    }

    #[test]
    fn cmd_alias_maps_to_args() {
        let r = raw(r#"{"Cmd": ["bash", "-c", "echo hi"]}"#);
        assert_eq!(
            r.args,
            Some(vec!["bash".into(), "-c".into(), "echo hi".into()])
        );
    }

    #[test]
    fn env_alias_maps_to_env() {
        let r = raw(r#"{"Env": ["FOO=bar", "BAZ=qux"]}"#);
        assert_eq!(r.env, Some(vec!["FOO=bar".into(), "BAZ=qux".into()]));
    }

    #[test]
    fn working_dir_alias_maps_to_cwd() {
        let r = raw(r#"{"WorkingDir": "/app"}"#);
        assert_eq!(r.cwd, Some("/app".into()));
    }

    #[test]
    fn cwd_alias_maps_to_cwd() {
        let r = raw(r#"{"Cwd": "/work"}"#);
        assert_eq!(r.cwd, Some("/work".into()));
    }

    #[test]
    fn entrypoint_is_parsed() {
        let r = raw(r#"{"Entrypoint": ["/ep.sh", "--flag"]}"#);
        assert_eq!(r.entrypoint, Some(vec!["/ep.sh".into(), "--flag".into()]));
    }

    #[test]
    fn entrypoint_prepended_to_args() {
        // Simulate what load() does to merge entrypoint + base_args.
        let ep = Some(vec!["/ep.sh".to_string()]);
        let base = Some(vec!["nginx".to_string()]);
        let argv = match ep.filter(|v| !v.is_empty()) {
            Some(mut e) => {
                if let Some(a) = base {
                    e.extend(a);
                }
                Some(e)
            }
            None => base,
        };
        assert_eq!(argv, Some(vec!["/ep.sh".into(), "nginx".into()]));
    }

    #[test]
    fn entrypoint_alone_when_no_args() {
        let ep = Some(vec!["/ep.sh".to_string()]);
        let base: Option<Vec<String>> = None;
        let argv = match ep.filter(|v| !v.is_empty()) {
            Some(mut e) => {
                if let Some(a) = base {
                    e.extend(a);
                }
                Some(e)
            }
            None => base,
        };
        assert_eq!(argv, Some(vec!["/ep.sh".into()]));
    }

    #[test]
    fn args_used_when_no_entrypoint() {
        let ep: Option<Vec<String>> = None;
        let base = Some(vec!["myapp".to_string()]);
        let argv = match ep.filter(|v| !v.is_empty()) {
            Some(mut e) => {
                if let Some(a) = base {
                    e.extend(a);
                }
                Some(e)
            }
            None => base,
        };
        assert_eq!(argv, Some(vec!["myapp".into()]));
    }
}
