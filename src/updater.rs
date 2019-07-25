use crate::update_channels::UpdateChannels;
use crate::update_channels::UpdateChannel;
use crate::RuleSets;

use http_req::request;

type Timestamp = i32;

pub struct Updater<'a> {
    rulesets: &'a mut RuleSets,
    update_channels: &'a UpdateChannels,
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
    /// * `interval` - The interval to check for new rulesets
    pub fn new(rulesets: &'a mut RuleSets, update_channels: &'a UpdateChannels, interval: usize) -> Updater<'a> {
        Updater {
            rulesets,
            update_channels,
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

            Some(timestamp)
        } else {
            None
        }
    }

    pub fn perform_check(&self) {
        for uc in self.update_channels.get_all() {
            if let Some(timestamp) = self.check_for_new_rulesets(uc) {
                println!("New rulesets are available for {:?} with timestamp {:?}", uc, timestamp);
            }
        }
    }
}
