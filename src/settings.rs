use crate::storage::{ThreadSafeStorage};
use serde_json::Value;
use crate::strings::ERROR_SERDE_PARSE;
use std::collections::HashSet;
use std::iter::FromIterator;
use url::Host;

/// A high-level abstracton over the storage object which sets and gets global settings
pub struct Settings {
    pub storage: ThreadSafeStorage,
    sites_disabled: HashSet<Host>
}

use std::sync::{Arc, Mutex};
pub type ThreadSafeSettings = Arc<Mutex<Settings>>;

impl Settings {
    /// Returns a struct for retrieving and storing global settings
    ///
    /// # Arguments
    ///
    /// * `storage` - The storage engine for key-value pairs, wrapped in an Arc<Mutex>
    pub fn new(storage: ThreadSafeStorage) -> Settings {
        let mut settings = Settings { storage, sites_disabled: HashSet::new() };
        settings.load_sites_disabled();
        settings
    }

    /// Retrieve whether HTTPS Everywhere is enabled
    pub fn get_https_everywhere_enabled(&self) -> Option<bool> {
        self.storage.lock().unwrap().get_bool(String::from("global_enabled"))
    }

    /// Retrieve whether HTTPS Everywhere is enabled. If no value is able to be retrieved, return
    /// the default value provided
    pub fn get_https_everywhere_enabled_or(&self, default: bool) -> bool {
        match self.storage.lock().unwrap().get_bool(String::from("global_enabled")) {
            Some(value) => value,
            None => default,
        }
    }

    /// Set HTTPS Everywhere to enabled or disabled
    pub fn set_https_everywhere_enabled(&mut self, value: bool) {
        self.storage.lock().unwrap().set_bool(String::from("global_enabled"), value);
    }

    /// Retrieve whether EASE (Encrypt All Sites Eligible) mode is enabled
    pub fn get_ease_mode_enabled(&self) -> Option<bool> {
        self.storage.lock().unwrap().get_bool(String::from("http_nowhere_on"))
    }

    /// Retrieve whether EASE (Encrypt All Sites Eligible) mode is enabled. If no value is able to
    /// be retrieved, return the default value provided
    pub fn get_ease_mode_enabled_or(&self, default: bool) -> bool {
        match self.storage.lock().unwrap().get_bool(String::from("http_nowhere_on")) {
            Some(value) => value,
            None => default,
        }
    }

    /// Set EASE (Encrypt All Sites Eligible) mode to enabled or disabled
    pub fn set_ease_mode_enabled(&mut self, value: bool) {
        self.storage.lock().unwrap().set_bool(String::from("http_nowhere_on"), value);
    }

    /// Load the sites that are disabled from the storage engine
    fn load_sites_disabled(&mut self) {
        self.sites_disabled = match self.storage.lock().unwrap().get_string(String::from("sites_disabled")) {
            Some(sites_disabled_string) => {
                if let Value::Array(sites_disabled) = serde_json::from_str(&sites_disabled_string).expect(ERROR_SERDE_PARSE) {
                    HashSet::from_iter(sites_disabled.iter().filter_map(|site_disabled_json| {
                        match site_disabled_json {
                            Value::String(site_disabled) => Some(Host::parse(site_disabled).unwrap()),
                            _ => None
                        }
                    }))
                } else {
                    panic!("Unexpected: disabled sites is not an array");
                }
            },
            None => HashSet::new()
        }
    }

    /// Store the sites that are disabled to the storage engine
    fn store_sites_disabled(&mut self) {
        let sites_disabled_json: Value = self.sites_disabled.iter().map(|site_disabled| Value::String(site_disabled.to_string())).collect();
        self.storage.lock().unwrap().set_string(String::from("sites_disabled"), sites_disabled_json.to_string());
    }


    /// Provide a Url::Host object to disable or enable a site
    pub fn set_site_disabled(&mut self, site: Host, set_disabled: bool) {
        let currently_disabled = self.get_site_disabled(&site);
        if currently_disabled && !set_disabled {
            self.sites_disabled.remove(&site);
            self.store_sites_disabled();
        } else if !currently_disabled && set_disabled {
            self.sites_disabled.insert(site);
            self.store_sites_disabled();
        }
    }

    pub fn get_site_disabled(&self, site: &Host) -> bool {
       self.sites_disabled.contains(site)
    }

    pub fn get_sites_disabled(&self) -> &HashSet<Host> {
        &self.sites_disabled
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::storage::tests::working_storage::WorkingTempStorage;
    use std::sync::{Arc, Mutex};
    use std::thread;
    
    #[test]
    fn sets() {
        let mut settings = Settings::new(Arc::new(Mutex::new(WorkingTempStorage::new())));
        settings.set_https_everywhere_enabled(true);
        assert_eq!(settings.get_https_everywhere_enabled(), Some(true));
    }

    #[test]
    fn gets_with_default() {
        let settings = Settings::new(Arc::new(Mutex::new(WorkingTempStorage::new())));
        assert_eq!(settings.get_ease_mode_enabled_or(false), false);
    }

    #[test]
    fn is_threadsafe() {
        let mut settings = Settings::new(Arc::new(Mutex::new(WorkingTempStorage::new())));

        let t = thread::spawn(move || {
            settings.set_https_everywhere_enabled(true);
            assert_eq!(settings.get_https_everywhere_enabled(), Some(true));
        });

        assert!(t.join().is_ok());
    }

}
