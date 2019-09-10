pub trait Storage {
    /// Get an integer from whatever key-value storage engine implements trait
    fn get_int(&self, key: String) -> Option<usize>;
    /// Set an integer for whatever key-value storage engine implements trait
    fn set_int(&self, key: String, value: usize);
    /// Get a string from whatever key-value storage engine implements trait
    fn get_string(&self, key: String) -> Option<String>;
    /// Set a string for whatever key-value storage engine implements trait
    fn set_string(&self, key: String, value: String);
    /// Get a boolean from whatever key-value storage engine implements trait
    fn get_bool(&self, key: String) -> Option<bool>;
    /// Set a bool for whatever key-value storage engine implements trait
    fn set_bool(&self, key: String, value: bool);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use multi_default_trait_impl::{default_trait_impl, trait_impl};

    #[default_trait_impl]
    impl Storage for DefaultStorage {
        fn get_int(&self, _key: String) -> Option<usize> { Some(5) }
        fn set_int(&self, _key: String, _value: usize) {}
        fn get_string(&self, _key: String) -> Option<String> { Some(String::from("test")) }
        fn set_string(&self, _key: String, _value: String) {}
        fn get_bool(&self, key: String) -> Option<bool> {
            if key == String::from("http_nowhere_on") {
                Some(false)
            } else {
                Some(true)
            }
        }
        fn set_bool(&self, _key: String, _value: bool) {}
    }

    pub struct TestStorage;
    #[trait_impl]
    impl DefaultStorage for TestStorage {
    }

    pub struct HttpNowhereOnStorage;
    #[trait_impl]
    impl DefaultStorage for HttpNowhereOnStorage {
        fn get_bool(&self, _key: String) -> Option<bool> { Some(true) }
    }
}
