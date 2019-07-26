use crate::{RuleSets, Storage, UpdateChannel, UpdateChannels};
use http_req::request;
use std::time::{SystemTime, UNIX_EPOCH};

type Timestamp = usize;

pub struct Updater<'a> {
    rulesets: &'a mut RuleSets,
    update_channels: &'a UpdateChannels,
    storage: &'a Storage,
    interval: usize,
}

impl<'a> Updater<'a> {
    /// Returns an updater with the rulesets, update channels, and interval to check for new
    /// rulesets
    ///
    /// # Arguments
    ///
    /// * `rulesets` - A ruleset struct to update
    /// * `update_channels` - The update channels where to look for new rulesets
    /// * `storage` - The storage engine for key-value pairs
    /// * `interval` - The interval to check for new rulesets
    pub fn new(rulesets: &'a mut RuleSets, update_channels: &'a UpdateChannels, storage: &'a Storage, interval: usize, ) -> Updater<'a> {
        Updater {
            rulesets,
            update_channels,
            storage,
            interval,
        }
    }

    /// Returns an `Option<i32>` optional timestamp if there are new rulesets.  If no new rulesets
    /// are available, or if there is a failure for any reason, return `None`
    ///
    /// # Arguments
    ///
    /// * `uc` - The update channel to check for new rulesets on
    pub fn check_for_new_rulesets(&self, uc: &UpdateChannel) -> Option<Timestamp> {
        let mut writer = Vec::new();

        let res = match request::get(uc.update_path_prefix.clone() + "/latest-rulesets-timestamp", &mut writer) {
            Ok(result) => result,
            Err(_) => return None
        };

        if res.status_code().is_success() {
            let ts_string = match String::from_utf8(writer) {
                Ok(timestamp) => timestamp,
                Err(_) => return None
            };
            
            let timestamp: Timestamp = match ts_string.trim().parse() {
                Ok(num) => num,
                Err(_) => return None
            };

            let stored_timestamp: Timestamp = self.storage.get_int(String::from("rulesets-timestamp: ") + &uc.name);

            if stored_timestamp < timestamp {
                Some(timestamp)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn perform_check(&self) {
        info!("Checking for new rulesets.");

	let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
	let current_timestamp = since_the_epoch.as_secs();
	self.storage.set_int(String::from("last-checked"), current_timestamp as usize);

	let extension_timestamp = self.storage.get_int(String::from("extension-timestamp"));

        for uc in self.update_channels.get_all() {
            if let Some(new_rulesets_timestamp) = self.check_for_new_rulesets(uc) {
                if uc.replaces_default_rulesets && extension_timestamp > new_rulesets_timestamp {
                    info!("{}: A new ruleset bundle has been released, but it is older than the extension-bundled rulesets it replaces.  Skipping.", uc.name);
                    continue;
                }
                info!("{}: A new ruleset bundle has been released.  Downloading now.", uc.name);
            }
        }
    }
}
