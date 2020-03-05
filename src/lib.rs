pub mod rulesets;
pub use rulesets::RuleSets;

#[cfg(feature="settings")]
pub mod settings;
#[cfg(feature="settings")]
pub use settings::Settings;

#[cfg(feature="updater")]
pub mod updater;
#[cfg(feature="updater")]
pub use updater::Updater;

#[cfg(feature="rewriter")]
pub mod rewriter;
#[cfg(feature="rewriter")]
pub use rewriter::Rewriter;

#[cfg(feature="get_simple_rules_ending_with")]
pub mod regex;
#[cfg(feature="get_simple_rules_ending_with")]
pub use crate::regex::RegEx;

#[cfg(any(feature="settings",feature="updater",feature="rewriter"))]
mod storage;
#[cfg(any(feature="settings",feature="rewriter",feature="updater"))]
pub use storage::Storage;

#[cfg(any(feature="rewriter",feature="updater"))]
#[macro_use]
extern crate log;

mod strings;

#[cfg(any(all(test,feature="add_rulesets"),feature="updater",feature="rewriter"))]
#[macro_use]
extern crate lazy_static;
