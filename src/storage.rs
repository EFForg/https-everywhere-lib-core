pub trait Storage {
    /// Get an integer from whatever key-value storage engine implements trait
    fn get_int(&self, key: String) -> usize;
    /// Set an integer for whatever key-value storage engine implements trait
    fn set_int(&self, key: String, value: usize);
    /// Get a string from whatever key-value storage engine implements trait
    fn get_string(&self, key: String) -> String;
    /// Set a string for whatever key-value storage engine implements trait
    fn set_string(&self, key: String, value: String);
}
