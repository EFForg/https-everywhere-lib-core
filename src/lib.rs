pub mod rulesets;
pub use rulesets::RuleSets;

#[cfg(feature="updater")]
pub mod updater;
#[cfg(feature="updater")]
pub use updater::Updater;

#[cfg(feature="rewriter")]
pub mod rewriter;
#[cfg(feature="rewriter")]
pub use rewriter::Rewriter;

#[cfg(any(feature="updater",feature="rewriter"))]
mod storage;
#[cfg(any(feature="rewriter",feature="updater"))]
pub use storage::Storage;

#[cfg(any(feature="rewriter",feature="updater"))]
#[macro_use]
extern crate log;

mod strings;

#[cfg(any(all(test,feature="add_rulesets"),feature="updater",feature="rewriter"))]
#[macro_use]
extern crate lazy_static;
