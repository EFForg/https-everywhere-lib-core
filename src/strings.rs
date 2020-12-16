#[cfg(any(feature="add_rulesets",feature="settings"))]
pub const ERROR_SERDE_PARSE: &str = "Could not convert json string to serde_json::Value struct";
