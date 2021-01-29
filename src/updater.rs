mod update_channels;
pub use update_channels::{UpdateChannel, UpdateChannels, UpdateChannelFormat};

use bloomfilter::Bloom;
use crate::{rulesets::ENABLE_MIXED_RULESETS, rulesets::RULE_ACTIVE_STATES, storage::ThreadSafeStorage, rulesets::ThreadSafeRuleSets};
use flate2::read::GzDecoder;
use http_req::request;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::Verifier;
use ring::{digest, test};
use serde_json::Value;
use std::collections::HashMap;
use std::cmp;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

type Timestamp = usize;
pub type ThreadSafeBloomVec = Arc<Mutex<Vec<bloomfilter::Bloom<str>>>>;

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


pub struct Updater {
    rulesets: ThreadSafeRuleSets,
    blooms: ThreadSafeBloomVec,
    pub update_channels: UpdateChannels,
    storage: ThreadSafeStorage,
    default_rulesets: Option<String>,
    periodicity: usize,
}

impl Updater {
    /// Returns an updater with the rulesets, update channels, storage, and interval to check for
    /// new rulesets
    ///
    /// # Arguments
    ///
    /// * `rulesets` - A ruleset struct to update, wrapped in an Arc<Mutex>
    /// * `update_channels` - The update channels where to look for new rulesets
    /// * `storage` - The storage engine for key-value pairs, wrapped in an Arc<Mutex>
    /// * `default_rulesets` - An optional string representing the default rulesets, which may or
    /// may not be replaced by updates
    /// * `periodicity` - The interval to check for new rulesets
    pub fn new(rulesets: ThreadSafeRuleSets, update_channels: UpdateChannels, storage: ThreadSafeStorage, default_rulesets: Option<String>, periodicity: usize) -> Updater {
        Updater {
            rulesets,
            blooms: Arc::new(Mutex::new(vec![])),
            update_channels,
            storage,
            default_rulesets,
            periodicity,
        }
    }

    /// Get the current timestamp in seconds
    fn current_timestamp() -> Timestamp {
	let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
	let current_timestamp = since_the_epoch.as_secs();
        current_timestamp as Timestamp
    }

    /// Returns an `Option<i32>` optional timestamp if there are new updates.  If no new updates
    /// are available, or if there is a failure for any reason, return `None`
    ///
    /// # Arguments
    ///
    /// * `uc` - The update channel to check for new updates on
    fn check_for_new_updates(&self, uc: &UpdateChannel) -> Option<Timestamp> {
        let mut writer = Vec::new();

        let timestamp_str = match uc.format {
            UpdateChannelFormat::RuleSets => "/latest-rulesets-timestamp",
            UpdateChannelFormat::Bloom => "/latest-bloom-timestamp",
        };
        let res = match request::get(uc.update_path_prefix.clone() + timestamp_str, &mut writer) { Ok(result) => result,
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

            let stored_timestamp: Timestamp = self.storage.lock().unwrap().get_int(format!("uc-timestamp: {}", &uc.name)).unwrap_or(0);

            if stored_timestamp < timestamp {
                Some(timestamp)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns a `HashMap` of optional timestamps for all update channels, keyed by the update
    /// channel name
    pub fn get_update_channel_timestamps(&self) -> HashMap<String, Option<Timestamp>> {
        let mut timestamps = HashMap::new();

        for uc in self.update_channels.get_all() {
            timestamps.insert(String::from(&uc.name), self.storage.lock().unwrap().get_int(format!("uc-timestamp: {}", &uc.name)));
        }
        timestamps
    }

    /// Given an update channel and timestamp, this returns a result-wrapped tuple, the first value the first value is
    /// a `Vec<u8>` of the signature file, the second is a `Vec<u8>` of the rulesets file.
    ///
    /// # Arguments
    ///
    /// * `rulesets_timestamp` - The timestamp for the rulesets
    /// * `update_channel` - The update channel to download rulesets for
    fn get_new_rulesets(&self, rulesets_timestamp: Timestamp, update_channel: &UpdateChannel) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        self.storage.lock().unwrap().set_int(format!("uc-timestamp: {}", &update_channel.name), rulesets_timestamp);

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

    /// Given an update channel and timestamp, this returns a result-wrapped tuple, the first value the first value is
    /// a `Vec<u8>` of the signature file, the second is a `Vec<u8>` of the bloom filter metadata file, and the third
    /// is a `Vec<u8>` of the bloom filter file.
    ///
    /// # Arguments
    ///
    /// * `bloom_timestamp` - The timestamp for the bloom filter
    /// * `update_channel` - The update channel to download the bloom filter for
    fn get_new_bloom(&self, bloom_timestamp: Timestamp, update_channel: &UpdateChannel) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn Error>> {
        self.storage.lock().unwrap().set_int(format!("uc-timestamp: {}", &update_channel.name), bloom_timestamp);

        // TODO: Use futures to asynchronously fetch signature and rulesets

        let mut signature_writer = Vec::new();
        let signature_res = request::get(update_channel.update_path_prefix.clone() + "/bloom-signature." + &bloom_timestamp.to_string() + ".sha256", &mut signature_writer)?;

        if !signature_res.status_code().is_success() {
            return Err(Box::new(UpdaterError::new(format!("{}: A non-2XX response was returned from the bloom signature URL", &update_channel.name))));
        }


        let mut bloom_metadata_writer = Vec::new();
        let bloom_metadata_res = request::get(update_channel.update_path_prefix.clone() + "/bloom-metadata." + &bloom_timestamp.to_string() + ".json", &mut bloom_metadata_writer)?;

        if !bloom_metadata_res.status_code().is_success() {
            return Err(Box::new(UpdaterError::new(format!("{}: A non-2XX response was returned from the bloom metadata URL", &update_channel.name))));
        }


        let mut bloom_writer = Vec::new();
        let bloom_res = request::get(update_channel.update_path_prefix.clone() + "/bloom." + &bloom_timestamp.to_string() + ".bin", &mut bloom_writer)?;

        if !bloom_res.status_code().is_success() {
            return Err(Box::new(UpdaterError::new(format!("{}: A non-2XX response was returned from the bloom URL", &update_channel.name))));
        }

        Ok((signature_writer, bloom_metadata_writer, bloom_writer))
    }

    /// If the given signature for the given rulesets verifies with the key stored in the given
    /// update channel, store this update channel in the struct storage layer.  Returns a
    /// result-wrapped unit
    ///
    /// # Arguments
    ///
    /// * `signature` - A SHA256 RSA PSS signature
    /// * `rulesets` - Rulesets to check the signature for
    /// * `rulesets_timestamp` - The timestamp for the rulesets, which we use to verify that it
    /// matches the timestamp in the signed rulesets JSON
    /// * `update_channel` - Contains the key which we verify the signatures with
    fn verify_and_store_new_rulesets(&self, signature: Vec<u8>, rulesets: Vec<u8>, rulesets_timestamp: Timestamp, update_channel: &UpdateChannel) -> Result<(), Box<dyn Error>> {
        let update_channel_key = PKey::from_rsa(update_channel.key.clone())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &update_channel_key)?;
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
                    return Err(Box::new(UpdaterError::new(format!("{}: Could not parse JSON `timestamp`", &update_channel.name))));
                }
            }

            self.storage.lock().unwrap().set_string(format!("rulesets: {}", update_channel.name), rulesets_json_string);
        } else {
            return Err(Box::new(UpdaterError::new(format!("{}: Downloaded ruleset signature is invalid.  Aborting.", &update_channel.name))));
        }

        Ok(())
    }

    fn verify_and_store_new_bloom(&self, signature: Vec<u8>, bloom_metadata: Vec<u8>, bloom: Vec<u8>, bloom_timestamp: Timestamp, update_channel: &UpdateChannel) -> Result<(), Box<dyn Error>> {
        let update_channel_key = PKey::from_rsa(update_channel.key.clone())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &update_channel_key)?;
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;

        verifier.update(&bloom_metadata)?;

        if verifier.verify(&signature)? {
            info!("{}: Bloom metadata signature checks out.", update_channel.name);

            let metadata_json_value: Value = serde_json::from_slice(&bloom_metadata)?;
            match metadata_json_value.get("timestamp") {
                Some(Value::Number(json_timestamp)) if json_timestamp.is_i64() => {
                    if json_timestamp.as_i64().unwrap() != bloom_timestamp as i64 {
                        return Err(Box::new(UpdaterError::new(format!("{}: JSON timestamp does not match with latest timestamp file", &update_channel.name))));
                    }
                },
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: Could not parse JSON `timestamp`", &update_channel.name))));
                }

            }

            let sha256sum: Vec<u8> = match metadata_json_value.get("sha256sum") {
                Some(Value::String(sha256sum)) => {
                    match test::from_hex(sha256sum) {
                        Ok(sha256sum) => sha256sum,
                        Err(_) => {
                            return Err(Box::new(UpdaterError::new(format!("{}: `sha256sum` is not formatted correctly", &update_channel.name))));
                        },
                    }
                },
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: Could not parse JSON `sha256sum`", &update_channel.name))));
                },
            };
            if sha256sum != digest::digest(&digest::SHA256, &bloom).as_ref() {
                return Err(Box::new(UpdaterError::new(format!("{}: sha256sum of the bloom filter is invalid.  Aborting.", &update_channel.name))));
            }

            let bitmap_bits: u64 = match metadata_json_value.get("bitmap_bits") {
                Some(Value::Number(bitmap_bits)) if bitmap_bits.is_u64() => bitmap_bits.as_u64().unwrap(),
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: Could not parse JSON `bitmap_bits`", &update_channel.name))));
                },
            };

            let k_num: u32 = match metadata_json_value.get("k_num") {
                Some(Value::Number(k_num)) if k_num.is_u64() => k_num.as_u64().unwrap() as u32,
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: Could not parse JSON `k_num`", &update_channel.name))));
                },
            };

            let sip_keys = match metadata_json_value.get("sip_keys") {
                Some(Value::Array(sip_keys)) => sip_keys,
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: Could not parse JSON `sip_keys`", &update_channel.name))));
                },
            };
            let sip_keys_0 = match &sip_keys[0] {
                Value::Array(sip_keys_0) => sip_keys_0,
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: `sip_keys[0]` is not a JSON array", &update_channel.name))));
                },
            };
            let (sip_keys_0_0, sip_keys_0_1) = match sip_keys_0.as_slice() {
                [Value::String(sip_keys_0_0), Value::String(sip_keys_0_1)] if sip_keys_0_0.parse::<u64>().is_ok() && sip_keys_0_1.parse::<u64>().is_ok() => {
                    (sip_keys_0_0.parse::<u64>().unwrap(), sip_keys_0_1.parse::<u64>().unwrap())
                }
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: `sip_keys[0]` is not in the format [String(Number), String(Number)]", &update_channel.name))));
                },
            };
            let sip_keys_1 = match &sip_keys[1] {
                Value::Array(sip_keys_1) => sip_keys_1,
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: `sip_keys[0]` is not a JSON array", &update_channel.name))));
                },
            };
            let (sip_keys_1_0, sip_keys_1_1) = match sip_keys_1.as_slice() {
                [Value::String(sip_keys_1_0), Value::String(sip_keys_1_1)] if sip_keys_1_0.parse::<u64>().is_ok() && sip_keys_1_1.parse::<u64>().is_ok() => {
                    (sip_keys_1_0.parse::<u64>().unwrap(), sip_keys_1_1.parse::<u64>().unwrap())
                }
                _ => {
                    return Err(Box::new(UpdaterError::new(format!("{}: `sip_keys[0]` is not in the format [String(Number), String(Number)]", &update_channel.name))));
                },
            };

            let mut storage = self.storage.lock().unwrap();
            storage.set_bytes(format!("bloom: {}", update_channel.name), bloom);
            storage.set_int(format!("bloom_bitmap_bits: {}", update_channel.name), bitmap_bits as usize);
            storage.set_int(format!("bloom_k_num: {}", update_channel.name), k_num as usize);
            storage.set_int(format!("bloom_sip_keys_0_0: {}", update_channel.name), sip_keys_0_0 as usize);
            storage.set_int(format!("bloom_sip_keys_0_1: {}", update_channel.name), sip_keys_0_1 as usize);
            storage.set_int(format!("bloom_sip_keys_1_0: {}", update_channel.name), sip_keys_1_0 as usize);
            storage.set_int(format!("bloom_sip_keys_1_1: {}", update_channel.name), sip_keys_1_1 as usize);
        }
        Ok(())

    }

    /// Perform a check for updates.  For all ruleset update channels:
    ///
    /// 1. Check if new rulesets exist by requesting a defined endpoint for a timestamp, which is
    ///    compared to a stored timestamp
    /// 2. If new rulesets exist, download them along with a signature
    /// 3. Verify if the signature is valid, and if so...
    /// 4. Store the rulesets
    pub fn perform_check(&mut self) {
        info!("Checking for new updates.");

	self.storage.lock().unwrap().set_int(String::from("last-checked"), Self::current_timestamp());

	let extension_timestamp = self.storage.lock().unwrap().get_int(String::from("extension-timestamp")).unwrap_or(0);

        let mut some_updated = false;
        for uc in self.update_channels.get_all().iter().filter(|uc| uc.format == UpdateChannelFormat::RuleSets) {
            if let Some(new_rulesets_timestamp) = self.check_for_new_updates(uc) {
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

                self.storage.lock().unwrap().set_int(format!("uc-stored-timestamp: {}", uc.name), new_rulesets_timestamp);
                some_updated = true;
            } else {
                info!("{}: No new ruleset bundle discovered.", uc.name);
            }
        }

        for uc in self.update_channels.get_all().iter().filter(|uc| uc.format == UpdateChannelFormat::Bloom) {
            if let Some(new_bloom_timestamp) = self.check_for_new_updates(uc) {
                info!("{}: A new bloom filter has been released.  Downloading now.", uc.name);

                let (signature, bloom_metadata, bloom) = match self.get_new_bloom(new_bloom_timestamp, uc) {
                    Ok(rs_tuple) => rs_tuple,
                    Err(err) => {
                        error!("{:?}", err);
                        continue;
                    }
                };

                if let Err(err) = self.verify_and_store_new_bloom(signature, bloom_metadata, bloom, new_bloom_timestamp, uc) {
                    error!("{:?}", err);
                    continue;
                }

                self.storage.lock().unwrap().set_int(format!("uc-stored-timestamp: {}", uc.name), new_bloom_timestamp);
                some_updated = true;
             }
        }

        if some_updated {
            self.apply_stored_rulesets();
        }
    }

    /// Modify rulesets struct to apply the stored rulesets
    pub fn apply_stored_rulesets(&mut self) {
        type OkRuleSetsResult = (Value, Option<String>, bool);
        type OkBloomResult = bloomfilter::Bloom<str>;

        // TODO: Use futures to asynchronously apply stored rulesets
        let rulesets_closure = |uc: &UpdateChannel| -> Result<OkRuleSetsResult, Box<dyn Error>> {
            match self.storage.lock().unwrap().get_string(format!("rulesets: {}", &uc.name)) {
                Some(rulesets_json_string) => {
                    info!("{}: Applying stored rulesets.", &uc.name);

                    let rulesets_json_value: Value = serde_json::from_str(&rulesets_json_string)?;
                    let inner_rulesets: Value = rulesets_json_value.get("rulesets").unwrap().clone();
                    Ok((inner_rulesets, uc.scope.clone(), uc.replaces_default_rulesets))
                }
                None => Err(Box::new(UpdaterError::new(format!("{} Could not retrieve stored rulesets", &uc.name))))
            }
        };

        let mut rulesets_tuple_results = vec![];
        for uc in self.update_channels.get_all().iter().filter(|uc| uc.format == UpdateChannelFormat::RuleSets) {
            rulesets_tuple_results.push(rulesets_closure(uc));
        }
        let rulesets_tuples: Vec<OkRuleSetsResult> = rulesets_tuple_results.into_iter().filter(|rt| rt.is_ok()).map(|rt| rt.unwrap()).collect();
        let replaces = rulesets_tuples.iter().fold(false, |acc, rt| {
            if rt.2 {
                true
            } else {
                acc
            }
        });

        let mut rs = self.rulesets.lock().unwrap();
        rs.clear();

        for rt in rulesets_tuples {
            rs.add_all_from_serde_value(rt.0, ENABLE_MIXED_RULESETS, &RULE_ACTIVE_STATES, &rt.1);
        }

        if !replaces && self.default_rulesets.is_some() {
            rs.add_all_from_json_string(&self.default_rulesets.clone().unwrap(), ENABLE_MIXED_RULESETS, &RULE_ACTIVE_STATES, &None);
        }


        let bloom_closure = |uc: &UpdateChannel| -> Result<OkBloomResult, Box<dyn Error>> {
            let storage = self.storage.lock().unwrap();
            match storage.get_bytes(format!("bloom: {}", &uc.name)) {
                Some(bloom) => {
                    info!("{}: Applying stored bloom filter.", &uc.name);

                    let bitmap_bits = storage.get_int(format!("bloom_bitmap_bits: {}", &uc.name)).unwrap() as u64;
                    let k_num = storage.get_int(format!("bloom_k_num: {}", &uc.name)).unwrap() as u32;
                    let sip_keys_0_0 = storage.get_int(format!("bloom_sip_keys_0_0: {}", &uc.name)).unwrap() as u64;
                    let sip_keys_0_1 = storage.get_int(format!("bloom_sip_keys_0_1: {}", &uc.name)).unwrap() as u64;
                    let sip_keys_1_0 = storage.get_int(format!("bloom_sip_keys_1_0: {}", &uc.name)).unwrap() as u64;
                    let sip_keys_1_1 = storage.get_int(format!("bloom_sip_keys_1_1: {}", &uc.name)).unwrap() as u64;

                    Ok(Bloom::from_existing(&bloom, bitmap_bits, k_num, [(sip_keys_0_0, sip_keys_0_1), (sip_keys_1_0, sip_keys_1_1)]))
                },
                None => Err(Box::new(UpdaterError::new(format!("{} Could not retrieve stored bloom filter", &uc.name))))
            }
        };

        let mut blooms = self.blooms.lock().unwrap();
        blooms.clear();
        for uc in self.update_channels.get_all().iter().filter(|uc| uc.format == UpdateChannelFormat::Bloom) {
            if let Ok(bloom) = bloom_closure(uc) {
                blooms.push(bloom);
            }
        }
    }

    /// Return the time until we should check for new rulesets, in seconds
    pub fn time_to_next_check(&self) -> usize {
        let last_checked = self.storage.lock().unwrap().get_int(String::from("last-checked")).unwrap_or(0);
        let current_timestamp = Self::current_timestamp();
        let secs_since_last_checked = current_timestamp - last_checked;
        cmp::max(0, self.periodicity as isize - secs_since_last_checked as isize) as usize
    }

    /// Clear the stored rulesets for any update channels which replace the default rulesets.  This
    /// should be run when a new version of the extension is released, so the bundled rulesets are
    /// not overwritten by old stored rulesets.
    pub fn clear_replacement_update_channels(&self) {
        for uc in self.update_channels.get_all() {
            if uc.replaces_default_rulesets {
                self.storage.lock().unwrap().set_int(format!("rulesets-timestamp: {}", &uc.name), 0);
                self.storage.lock().unwrap().set_int(format!("rulesets-stored-timestamp: {}", &uc.name), 0);
                self.storage.lock().unwrap().set_string(format!("rulesets: {}", &uc.name), String::from(""));
            }
        }
    }
}

pub trait NewUpdaterWithBloom {
    fn new(rulesets: ThreadSafeRuleSets, blooms: ThreadSafeBloomVec, update_channels: UpdateChannels, storage: ThreadSafeStorage, default_rulesets: Option<String>, periodicity: usize) -> Updater;
}

impl NewUpdaterWithBloom for Updater {
    /// Returns an updater with the rulesets, blooms, update channels, storage, and interval to
    /// check for new rulesets
    ///
    /// # Arguments
    ///
    /// * `rulesets` - A ruleset struct to update, wrapped in an Arc<Mutex>
    /// * `blooms` - A bloom vec to update, wrapped in an Arc<Mutex>
    /// * `update_channels` - The update channels where to look for new rulesets
    /// * `storage` - The storage engine for key-value pairs, wrapped in an Arc<Mutex>
    /// * `default_rulesets` - An optional string representing the default rulesets, which may or
    /// may not be replaced by updates
    /// * `periodicity` - The interval to check for new rulesets
    fn new(rulesets: ThreadSafeRuleSets, blooms: ThreadSafeBloomVec, update_channels: UpdateChannels, storage: ThreadSafeStorage, default_rulesets: Option<String>, periodicity: usize) -> Updater {
        Updater {
            rulesets,
            blooms,
            update_channels,
            storage,
            default_rulesets,
            periodicity,
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, thread};
    use std::sync::{Arc, Mutex};
    use crate::RuleSets;
    use crate::rulesets::tests as rulesets_tests;
    use crate::storage::tests::{mock_storage::TestStorage, working_storage::WorkingTempStorage};

    #[test]
    fn updates_correctly() {
        let s: ThreadSafeStorage = Arc::new(Mutex::new(WorkingTempStorage::new()));
        let rs = Arc::new(Mutex::new(RuleSets::new()));
        let rs2 = Arc::clone(&rs);
        let b: ThreadSafeBloomVec = Arc::new(Mutex::new(Vec::new()));
        let b2 = Arc::clone(&b);
        assert_eq!(rs2.lock().unwrap().count_targets(), 0);

        let update_channels_string = fs::read_to_string("tests/update_channels.json").unwrap();
        let ucs = UpdateChannels::from(&update_channels_string[..]);

        let mut updater = <Updater as NewUpdaterWithBloom>::new(rs, b, ucs, s, None, 15);
        updater.perform_check();

        assert!(rs2.lock().unwrap().count_targets() > 0);
        assert!(b2.lock().unwrap()[0].check("news.example.com"), true);
    }

    #[test]
    fn is_threadsafe() {
        let s: ThreadSafeStorage = Arc::new(Mutex::new(TestStorage));

        let mut rs = RuleSets::new();
        rulesets_tests::add_mock_rulesets(&mut rs);
        let rs = Arc::new(Mutex::new(rs));

        let update_channels_string = fs::read_to_string("tests/update_channels.json").unwrap();
        let ucs = UpdateChannels::from(&update_channels_string[..]);

        let t = thread::spawn(move || {
            let updater = Updater::new(rs, ucs, s, None, 15);
            updater.time_to_next_check();
        });

        assert!(t.join().is_ok());
    }
}
