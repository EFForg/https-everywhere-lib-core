use crate::storage::{ThreadSafeStorage};

/// A high-level abstracton over the storage object which sets and gets global settings
pub struct Settings {
    pub storage: ThreadSafeStorage,
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
        Settings { storage }
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
