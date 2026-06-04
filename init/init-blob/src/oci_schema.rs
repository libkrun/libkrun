// SPDX-License-Identifier: Apache-2.0
//
//! OCI runtime-spec config.json parsing types.
//!
//! These are used by [`Builder::from_oci_json`](super::Builder::from_oci_json)
//! to accept external OCI configs. Unknown fields are silently ignored.
//! krun-specific extensions will go here rather than polluting
//! [`ConfigSchema`](super::init_schema::ConfigSchema).

use serde::Deserialize;

use crate::init_schema::{ConfigSchema, Mount, ProcessConfig};

/// OCI runtime-spec "process" object.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct OciProcess {
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: Option<String>,
}

/// OCI runtime-spec "mount" object.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct OciMount {
    pub destination: String,
    #[serde(rename = "type", default)]
    pub fs_type: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

/// Subset of OCI runtime-spec config.json that we parse.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct OciSchema {
    pub process: OciProcess,
    pub mounts: Vec<OciMount>,
}

impl From<OciSchema> for ConfigSchema {
    fn from(oci: OciSchema) -> Self {
        Self {
            process: ProcessConfig {
                args: oci.process.args,
                env: oci.process.env,
                cwd: oci.process.cwd,
            },
            mounts: oci
                .mounts
                .into_iter()
                .filter_map(|m| {
                    Some(Mount {
                        destination: m.destination,
                        fs_type: m.fs_type?,
                        source: m.source.unwrap_or_default(),
                    })
                })
                .collect(),
        }
    }
}
