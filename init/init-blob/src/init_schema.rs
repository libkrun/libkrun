// SPDX-License-Identifier: Apache-2.0
//
//! Internal serialization types for `/.krun_config.json` (consumed by the
//! in-guest init binary).

use serde::{Deserialize, Serialize};

/// Process configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct ProcessConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

impl ProcessConfig {
    pub fn is_empty(&self) -> bool {
        self.args.is_empty() && self.env.is_empty() && self.cwd.is_none()
    }
}

/// A mount specification.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub fs_type: String,
    pub source: String,
}

/// Config envelope (matches what the init binary parses).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct ConfigSchema {
    #[serde(skip_serializing_if = "ProcessConfig::is_empty")]
    pub process: ProcessConfig,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
}
