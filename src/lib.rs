pub mod rulesets;
pub use rulesets::RuleSets;

mod strings;

cfg_if::cfg_if! {
    if #[cfg(feature="settings")] {
        pub mod settings;
        pub use settings::Settings;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature="updater")] {
        pub mod updater;
        pub use updater::Updater;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature="rewriter")] {
        pub mod rewriter;
        pub use rewriter::Rewriter;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature="get_simple_rules_ending_with")] {
        pub mod regex;
        pub use crate::regex::RegEx;
    }
}

#[cfg(any(feature="settings",feature="updater",feature="rewriter"))]
mod storage;
#[cfg(any(feature="settings",feature="updater",feature="rewriter"))]
pub use storage::Storage;

#[cfg(any(feature="rewriter",feature="updater"))]
#[macro_use]
extern crate log;

#[cfg(any(all(test,feature="add_rulesets"),feature="updater"))]
#[macro_use]
extern crate lazy_static;
