mod rulesets;
pub use rulesets::{Rule, CookieRule, RuleSet, RuleSets};
#[cfg(feature="updates")]
mod update_channels;
#[cfg(feature="updates")]
pub use update_channels::{UpdateChannel, UpdateChannels};
#[cfg(feature="updates")]
mod updater;
#[cfg(feature="updates")]
pub use updater::Updater;
#[cfg(feature="updates")]
mod storage;
#[cfg(feature="updates")]
pub use storage::Storage;
#[cfg(feature="updates")]
#[macro_use]
extern crate log;

mod strings;

#[cfg(any(test,feature="updates"))]
#[macro_use]
extern crate lazy_static;
