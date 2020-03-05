pub trait RegEx {
    fn new(re: &str) -> Self;
    fn is_match(&self, text: &str) -> bool;
}

#[cfg(all(test,feature="get_simple_rules_ending_with"))]
use regex::Regex;
#[cfg(all(test,feature="get_simple_rules_ending_with"))]
impl RegEx for Regex {
    fn new(re: &str) -> Self {
        Regex::new(re).unwrap()
    }

    fn is_match(&self, text: &str) -> bool {
        self.is_match(text)
    }
}
