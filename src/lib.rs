use std::rc::Rc;
use std::collections::BTreeMap;

/// A Rule is used to rewrite URLs from some regular expression to some string
#[derive(Debug)]
pub enum Rule {
    Trivial,
    NonTrivial(String, String)
}

impl Rule {

    /// Returns a rule with the from regex and replacement string specified
    ///
    /// # Arguments
    ///
    /// * `from_regex` - A string that will be compiled to regex indicating the URL to replace
    /// * `to` - A string indicating the replacement value
    pub fn new(from_regex: String, to: String) -> Rule {
        if &from_regex == "^http:" && &to == "https:" {
            Rule::Trivial
        } else {
            Rule::NonTrivial(from_regex, to)
        }
    }

}


/// A CookieRule is used to secure cookies which conform to some name and host constraints
#[derive(Debug)]
pub struct CookieRule {
    pub host_regex: String, // RegExp
    pub name_regex: String // RegExp
}

impl CookieRule {

    /// Returns a cookierule with the host and scope regex specified
    ///
    /// # Arguments
    ///
    /// * `host_regex` - A string that will be compiled to regex indicating the host of the cookie
    /// * `name_regex` - A string that will be compiled to regex indicating the name of the cookie
    pub fn new(host_regex: String, name_regex: String) -> CookieRule {
        CookieRule {
            host_regex,
            name_regex
        }
    }
}


/// A RuleSet is a grouping of rules which act on some target
#[derive(Debug)]
pub struct RuleSet {
    pub name: String,
    pub rules: Vec<Rule>,
    pub exclusions: Option<String>, // RegExp
    pub cookierules: Option<Vec<CookieRule>>,
    pub active: bool,
    pub default_state: bool,
    pub scope: Rc<Option<String>>, // RegExp
    pub note: Option<String>
}

impl RuleSet {

    /// Returns a ruleset with the name and scope specified
    ///
    /// # Arguments
    ///
    /// * `name` - A string that holds the name of the ruleset
    /// * `scope` - An optional string slice specifying the scope of the ruleset
    pub fn new(name: String, scope: Rc<Option<String>>) -> RuleSet {
        RuleSet {
            name,
            rules: vec![],
            exclusions: None,
            cookierules: None,
            active: true,
            default_state: true,
            scope,
            note: None
        }
    }
}


/// RuleSets consists of a tuple btreemap of rulesets, keyed by some target FQDN
#[derive(Debug)]
pub struct RuleSets(pub BTreeMap<String, Vec<Rc<RuleSet>>>);

impl RuleSets {

    /// Returns a new rulesets struct
    pub fn new() -> RuleSets {
        RuleSets(BTreeMap::new())
    }

    /// Returns the number of targets in the current RuleSets struct as a `usize`
    pub fn count_targets(&self) -> usize {
        self.0.len()
    }
}
