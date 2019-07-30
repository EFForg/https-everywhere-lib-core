use crate::{RuleSets, Storage, UpdateChannel, UpdateChannels};
use flate2::read::GzDecoder;
use http_req::request;
use openssl::hash::MessageDigest;
use openssl::rsa::Padding;
use openssl::sign::Verifier;
use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

type Timestamp = usize;

#[derive(Debug, Clone)]
struct UpdaterError {
    error_string: String,
}

impl UpdaterError {
    pub fn new(error_string: String) -> UpdaterError {
        UpdaterError {
            error_string
        }
    }
}

impl fmt::Display for UpdaterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_string)
    }
}

impl Error for UpdaterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}


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

    pub fn get_new_rulesets(&self, rulesets_timestamp: Timestamp, update_channel: &UpdateChannel) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        self.storage.set_int(String::from("rulesets-timestamp: ") + &update_channel.name, rulesets_timestamp);

        // TODO: Use futures to asynchronously fetch signature and rulesets

        let mut signature_writer = Vec::new();
        let signature_res = request::get(update_channel.update_path_prefix.clone() + "/rulesets-signature." + &rulesets_timestamp.to_string() + ".sha256", &mut signature_writer)?;

        if !signature_res.status_code().is_success() {
            return Err(Box::new(UpdaterError::new(format!("{}: A non-2XX response was returned from the ruleset signature URL", &update_channel.name))));
        }


        let mut rulesets_writer = Vec::new();
        let rulesets_res = request::get(update_channel.update_path_prefix.clone() + "/default.rulesets." + &rulesets_timestamp.to_string() + ".gz", &mut rulesets_writer)?;

        if !rulesets_res.status_code().is_success() {
            return Err(Box::new(UpdaterError::new(format!("{}: A non-2XX response was returned from the ruleset URL", &update_channel.name))));
        }

        Ok((signature_writer, rulesets_writer))
    }

    pub fn verify_and_store_new_rulesets(&mut self, signature: Vec<u8>, rulesets: Vec<u8>, rulesets_timestamp: Timestamp, update_channel: &UpdateChannel) -> Result<(), Box<dyn Error>> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &update_channel.key)?;
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;

        verifier.update(&rulesets)?;

        if verifier.verify(&signature)? {
            info!("{}: Downloaded ruleset signature checks out.  Storing rulesets.", update_channel.name);

            let mut rulesets_json_string = String::new();
            let mut decoder = GzDecoder::new(&rulesets[..]);
            decoder.read_to_string(&mut rulesets_json_string)?;

            let rulesets_json_value: Value = serde_json::from_str(&rulesets_json_string)?;
            match rulesets_json_value.get("timestamp") {
                Some(Value::Number(json_timestamp)) if json_timestamp.is_i64() => {
                    if json_timestamp.as_i64().unwrap() != rulesets_timestamp as i64 {
                        return Err(Box::new(UpdaterError::new(format!("{}: JSON timestamp does not match with latest timestamp file", &update_channel.name))));
                    }
                },
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: Could not parse JSON timestamp", &update_channel.name))));
                }
            }

            self.storage.set_string(format!("rulesets: {}", update_channel.name), rulesets_json_string);
        } else {
            return Err(Box::new(UpdaterError::new(format!("{}: Downloaded ruleset signature is invalid.  Aborting.", &update_channel.name))));
        }

        Ok(())
    }

    pub fn perform_check(&mut self) {
        info!("Checking for new rulesets.");

	let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
	let current_timestamp = since_the_epoch.as_secs();
	self.storage.set_int(String::from("last-checked"), current_timestamp as usize);

	let extension_timestamp = self.storage.get_int(String::from("extension-timestamp"));

        let mut some_updated = false;
        for uc in self.update_channels.get_all() {
            if let Some(new_rulesets_timestamp) = self.check_for_new_rulesets(uc) {
                if uc.replaces_default_rulesets && extension_timestamp > new_rulesets_timestamp {
                    info!("{}: A new ruleset bundle has been released, but it is older than the extension-bundled rulesets it replaces.  Skipping.", uc.name);
                    continue;
                }
                info!("{}: A new ruleset bundle has been released.  Downloading now.", uc.name);

                let (signature, rulesets) = match self.get_new_rulesets(new_rulesets_timestamp, uc) {
                    Ok(rs_tuple) => rs_tuple,
                    Err(err) => {
                        error!("{:?}", err);
                        continue;
                    }
                };

                if let Err(err) = self.verify_and_store_new_rulesets(signature, rulesets, new_rulesets_timestamp, uc) {
                    error!("{:?}", err);
                    continue;
                }

                self.storage.set_int(format!("rulesets-stored-timestamp: {}", uc.name), new_rulesets_timestamp);
                some_updated = true;
            } else {
                info!("{}: No new ruleset bundle discovered.", uc.name);
            }
        }

        if some_updated {
            info!("Some have been updated!");
        }
    }
}
