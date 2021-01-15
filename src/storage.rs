pub trait Storage {
    /// Get an integer from whatever key-value storage engine implements trait
    fn get_int(&self, key: String) -> Option<usize>;
    /// Set an integer for whatever key-value storage engine implements trait
    fn set_int(&mut self, key: String, value: usize);
    /// Get a string from whatever key-value storage engine implements trait
    fn get_string(&self, key: String) -> Option<String>;
    /// Set a string for whatever key-value storage engine implements trait
    fn set_string(&mut self, key: String, value: String);
    /// Get a boolean from whatever key-value storage engine implements trait
    fn get_bool(&self, key: String) -> Option<bool>;
    /// Set a bool for whatever key-value storage engine implements trait
    fn set_bool(&mut self, key: String, value: bool);
    /// Get bytes from whatever key-value storage engine implements trait
    fn get_bytes(&self, key: String) -> Option<Vec<u8>>;
    /// Set bytes for whatever key-value storage engine implements trait
    fn set_bytes(&mut self, key: String, value: Vec<u8>);
}

use std::sync::{Arc, Mutex};
pub type ThreadSafeStorage = Arc<Mutex<dyn Storage + Sync + Send>>;

#[cfg(test)]
pub mod tests {

    #[cfg(all(feature="add_rulesets",any(feature="updater",feature="rewriter")))]
    pub mod mock_storage {
        use super::super::*;
        use multi_default_trait_impl::{default_trait_impl, trait_impl};

        #[default_trait_impl]
        impl Storage for DefaultStorage {
            fn get_int(&self, _key: String) -> Option<usize> { Some(5) }
            fn set_int(&mut self, _key: String, _value: usize) {}
            fn get_string(&self, key: String) -> Option<String> {
                if key == String::from("sites_disabled") {
                    None
                } else {
                    Some(String::from("test"))
                }
            }
            fn set_string(&mut self, _key: String, _value: String) {}
            fn get_bool(&self, key: String) -> Option<bool> {
                if key == String::from("http_nowhere_on") {
                    Some(false)
                } else {
                    Some(true)
                }
            }
            fn set_bool(&mut self, _key: String, _value: bool) {}
            fn get_bytes(&self, _key: String) -> Option<Vec<u8>> { Vec::new(12) }
            fn set_bytes(&mut self, _key: String, _value: Vec<u8>) {}
        }

        pub struct TestStorage;
        #[trait_impl]
        impl DefaultStorage for TestStorage {
        }

        #[cfg(feature="rewriter")]
        pub struct HttpNowhereOnStorage;
        #[cfg(feature="rewriter")]
        #[trait_impl]
        impl DefaultStorage for HttpNowhereOnStorage {
            fn get_bool(&self, _key: String) -> Option<bool> { Some(true) }
        }
    }

    #[cfg(any(feature="updater",feature="settings"))]
    pub mod working_storage {
        use super::super::*;
        use std::collections::HashMap;

        pub struct WorkingTempStorage {
            ints: HashMap<String, usize>,
            bools: HashMap<String, bool>,
            strings: HashMap<String, String>,
        }

        impl WorkingTempStorage {
            pub fn new() -> WorkingTempStorage {
                WorkingTempStorage {
                    ints: HashMap::new(),
                    bools: HashMap::new(),
                    strings: HashMap::new(),
                }
            }
        }

        impl Storage for WorkingTempStorage {
            fn get_int(&self, key: String) -> Option<usize> {
                match self.ints.get(&key) {
                    Some(value) => Some(value.clone()),
                    None => None
                }
            }

            fn get_bool(&self, key: String) -> Option<bool> {
                match self.bools.get(&key) {
                    Some(value) => Some(value.clone()),
                    None => None
                }
            }

            fn get_string(&self, key: String) -> Option<String> {
                match self.strings.get(&key) {
                    Some(value) => Some(value.clone()),
                    None => None
                }
            }

            fn set_int(&mut self, key: String, value: usize) {
                self.ints.insert(key, value);
            }

            fn set_bool(&mut self, key: String, value: bool) {
                self.bools.insert(key, value);
            }

            fn set_string(&mut self, key: String, value: String) {
                self.strings.insert(key, value);
            }
        }
    }
}
