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
