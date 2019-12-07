use std::sync::Arc;
use std::collections::BTreeMap;

#[cfg(feature="add_rulesets")]
use serde_json::Value;
#[cfg(feature="add_rulesets")]
use crate::strings::ERROR_SERDE_PARSE;
#[cfg(feature="add_rulesets")]
use std::collections::HashMap;
#[cfg(feature="rewriter")]
use regex::Regex;

#[cfg(any(feature="rewriter",feature="updater"))]
use std::sync::Mutex;
#[cfg(any(feature="rewriter",feature="updater"))]
pub type ThreadSafeRuleSets = Arc<Mutex<RuleSets>>;

#[cfg(any(all(test,feature="add_rulesets"),feature="updater"))]
pub(crate) const ENABLE_MIXED_RULESETS: bool = true;

#[cfg(any(all(test,feature="add_rulesets"),feature="updater"))]
lazy_static!{
    pub(crate) static ref RULE_ACTIVE_STATES: HashMap<String, bool> = HashMap::new();
}

#[cfg(feature="rewriter")]
lazy_static!{
    pub(crate) static ref TRIVIAL_REGEX: Regex = Regex::new(r"^http:").unwrap();
}


#[cfg(feature="add_rulesets")]
struct StaticJsonStrings {
    default_off: &'static str,
    exclusion: &'static str,
    from: &'static str,
    host: &'static str,
    mixed_content: &'static str,
    name: &'static str,
    platform: &'static str,
    rule: &'static str,
    securecookie: &'static str,
    target: &'static str,
    to: &'static str,
    user_rule: &'static str,
}

#[cfg(feature="add_rulesets")]
const JSON_STRINGS: StaticJsonStrings = StaticJsonStrings {
    default_off: "default_off",
    exclusion: "exclusion",
    from: "from",
    host: "host",
    mixed_content: "mixedcontent",
    name: "name",
    platform: "platform",
    rule: "rule",
    securecookie: "securecookie",
    target: "target",
    to: "to",
    user_rule: "user rule",
};

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
    pub scope: Arc<Option<String>>, // RegExp
    pub note: Option<String>
}

impl RuleSet {

    /// Returns a ruleset with the name and scope specified
    ///
    /// # Arguments
    ///
    /// * `name` - A string that holds the name of the ruleset
    /// * `scope` - An optional string slice specifying the scope of the ruleset
    pub fn new(name: String, scope: Arc<Option<String>>) -> RuleSet {
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

    #[cfg(feature="add_rulesets")]
    pub(crate) fn add_rules(&mut self, rules: &[Value]) {
        for rule in rules {
            if let Value::Object(rule) = rule {
                let from = match rule.get(JSON_STRINGS.from) {
                    Some(Value::String(from)) => from.to_string(),
                    _ => String::new(),
                };
                let to = match rule.get(JSON_STRINGS.to) {
                    Some(Value::String(to)) => to.to_string(),
                    _ => String::new(),
                };
                self.rules.push(Rule::new(from, to));
            }
        }
    }

    #[cfg(feature="add_rulesets")]
    pub(crate) fn add_exclusions(&mut self, exclusions: &[Value]) {
        let mut exclusions_vec = vec![];
        for exclusion in exclusions {
            if let Value::String(exclusion) = exclusion {
                exclusions_vec.push(exclusion.to_string());
            }
        }

        self.exclusions = Some(exclusions_vec.join("|"));
    }

    #[cfg(feature="add_rulesets")]
    pub(crate) fn add_cookierules(&mut self, cookierules: &[Value]) {
        let mut cookierules_vec = vec![];

        for cookierule in cookierules {
            if let Value::Object(cookierule) = cookierule {
                let host = match cookierule.get(JSON_STRINGS.host) {
                    Some(Value::String(host)) => host.to_string(),
                    _ => String::new(),
                };
                let name = match cookierule.get(JSON_STRINGS.name) {
                    Some(Value::String(name)) => name.to_string(),
                    _ => String::new(),
                };

                cookierules_vec.push(
                    CookieRule::new(
                        host,
                        name));
            }
        }

        self.cookierules = Some(cookierules_vec);
    }

    #[cfg(feature="rewriter")]
    pub(crate) fn apply(&self, url: &str) -> Option<String> {
        // If we're covered by an exclusion, return
        if !self.exclusions.is_none() {
            let exclusions_regex = Regex::new(&self.exclusions.clone().unwrap()).unwrap();
            if exclusions_regex.is_match(&url) {
               debug!("Excluded url: {}", url);
               return None;
            }
        }

        for rule in self.rules.iter() {
            match rule {
                Rule::Trivial => {
                    return Some(TRIVIAL_REGEX.replace_all(url, "https:").to_string());
                }
                Rule::NonTrivial(from_regex, to) => {
                    let from_regex = Regex::new(from_regex).unwrap();
                    let returl = from_regex.replace_all(url, &to[..]).to_string();
                    if returl != url {
                        return Some(returl);
                    }
                }
            }
        }
        None
    }
}


/// RuleSets consists of a tuple btreemap of rulesets, keyed by some target FQDN
#[derive(Debug)]
pub struct RuleSets(pub BTreeMap<String, Vec<Arc<RuleSet>>>);

impl RuleSets {

    /// Returns a new rulesets struct
    pub fn new() -> RuleSets {
        RuleSets(BTreeMap::new())
    }

    /// Returns the number of targets in the current RuleSets struct as a `usize`
    pub fn count_targets(&self) -> usize {
        self.0.len()
    }

    /// Clears the ruleset btreemap of all values
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Construct and add new rulesets given a json string of values
    ///
    /// # Arguments
    ///
    /// * `json_string` - A json string representing the rulesets to add
    /// * `enable_mixed_rulesets` - A bool indicating whether rulesets which trigger mixed
    /// content blocking should be enabled
    /// * `rule_active_states` - A HashMap which lets us know whether rulesets have been disabled
    /// or enabled
    /// * `scope` - An optional string which indicates the scope of the current batch of rulesets
    /// being added (see the [ruleset update channels](https://github.com/EFForg/https-everywhere/blob/master/docs/en_US/ruleset-update-channels.md) documentation)
    #[cfg(feature="add_rulesets")]
    pub fn add_all_from_json_string(&mut self, json_string: &str, enable_mixed_rulesets: &bool, ruleset_active_states: &HashMap<String, bool>, scope: &Option<String>) {
        let rulesets: Value = serde_json::from_str(&json_string).expect(ERROR_SERDE_PARSE);
        self.add_all_from_serde_value(rulesets, enable_mixed_rulesets, ruleset_active_states, scope);
    }

    #[cfg(feature="add_rulesets")]
    pub fn add_all_from_serde_value(&mut self, rulesets: Value, enable_mixed_rulesets: &bool, ruleset_active_states: &HashMap<String, bool>, scope: &Option<String>) {
        let scope: Arc<Option<String>> = Arc::new(scope.clone());

        let mut add_one_from_json = |ruleset: Value| {
            if let Value::Object(ruleset) = ruleset {
                let ruleset_name: String;
                let mut default_state = true;
                let mut note = String::new();

                if let Some(Value::String(default_off)) = ruleset.get(JSON_STRINGS.default_off) {
                    if default_off != &JSON_STRINGS.user_rule {
                        default_state = false;
                    }
                    note.push_str(default_off);
                    note.push_str("\n");
                }

                if let Some(Value::String(platform)) = ruleset.get(JSON_STRINGS.platform) {
                    if platform == &JSON_STRINGS.mixed_content {
                        if !enable_mixed_rulesets {
                            default_state = false;
                        }
                    } else {
                        default_state = false;
                    }

                    note.push_str("Platform(s): ");
                    note.push_str(platform);
                    note.push_str("\n");
                }

                let mut active = default_state;
                if let Some(Value::String(name)) = ruleset.get(JSON_STRINGS.name) {
                    ruleset_name = name.to_string();

                    match ruleset_active_states.get(&ruleset_name) {
                        Some(false) => { active = false; }
                        Some(true) => { active = true; }
                        _ => {}
                    }

                    let mut rs = RuleSet::new(ruleset_name, Arc::clone(&scope));
                    rs.default_state = default_state;
                    rs.note = match note.len() {
                        0 => None,
                        _ => Some(note.trim().to_string())
                    };

                    rs.active = active;

                    if let Some(Value::Array(rules)) = ruleset.get(JSON_STRINGS.rule) {
                        rs.add_rules(rules);
                    }

                    if let Some(Value::Array(exclusions)) = ruleset.get(JSON_STRINGS.exclusion) {
                        rs.add_exclusions(exclusions);
                    }

                    if let Some(Value::Array(securecookies)) = ruleset.get(JSON_STRINGS.securecookie) {
                        rs.add_cookierules(securecookies);
                    }

                    let rs_rc = Arc::new(rs);
                    if let Some(Value::Array(targets)) = ruleset.get(JSON_STRINGS.target) {
                        for target in targets {
                            if let Value::String(target) = target {
                                match self.0.get_mut(target) {
                                    Some(rs_vec) => {
                                        rs_vec.push(Arc::clone(&rs_rc));
                                    },
                                    None => {
                                        self.0.insert(target.to_string(), vec![Arc::clone(&rs_rc)]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        if let Value::Array(rulesets) = rulesets {
            for ruleset in rulesets {
                add_one_from_json(ruleset);
            }
        }
    }

    /// Return a vector of rulesets that apply to the given host
    ///
    /// # Arguments
    ///
    /// * `host` - A string which indicates the host to search for potentially applicable rulesets
    #[cfg(feature="potentially_applicable")]
    pub fn potentially_applicable(&self, host: &str) -> Vec<Arc<RuleSet>> {
        let mut results = vec![];

        self.try_add(&mut results, host);

        // Ensure host is well-formed (RFC 1035)
        if host.len() <= 0 || host.len() > 255 || host.find("..").is_some() {
            return results;
        }

        // Replace www.example.com with www.example.*
        // eat away from the right for once and only once
        let mut segmented: Vec<&str> = host.split('.').collect();
        let last_index = segmented.len() - 1;
        let tld = segmented[last_index];

        segmented[last_index] = "*";
        let tmp_host = segmented.join(".");
        self.try_add(&mut results, &tmp_host);
        segmented[last_index] = tld;

        // now eat away from the left, with *, so that for x.y.z.google.com we
        // check *.y.z.google.com, *.z.google.com and *.google.com
        for index in 0..(segmented.len() - 1) {
            let mut segmented_tmp = segmented.clone();
            segmented_tmp[index] = "*";
            if let Some(slice) = segmented_tmp.get(index..segmented.len()) {
                let tmp_host = slice.join(".");
                self.try_add(&mut results, &tmp_host);
            }
        }

        results
    }

    #[cfg(feature="potentially_applicable")]
    fn try_add(&self, results: &mut Vec<Arc<RuleSet>>, host: &str) {
        if self.0.contains_key(host) {
            if let Some(rulesets) = self.0.get(host) {
                for ruleset in rulesets {
                    results.push(Arc::clone(ruleset));
                }
            }
        }
    }
}

#[cfg(all(test,feature="add_rulesets"))]
pub mod tests {
    use super::*;
    use std::{fs, thread};

    fn mock_rulesets_json() -> String {
        fs::read_to_string("tests/mock_rulesets.json").unwrap()
    }

    pub fn add_mock_rulesets(rs: &mut RuleSets) {
        rs.add_all_from_json_string(&mock_rulesets_json(), &ENABLE_MIXED_RULESETS, &RULE_ACTIVE_STATES, &None);
    }

    #[test]
    fn adds_targets_correctly() {
        let mut rs = RuleSets::new();
        add_mock_rulesets(&mut rs);
        assert_eq!(rs.count_targets(), 28);
    }

    #[test]
    fn rulesets_represented_correctly() {
        let mut rs = RuleSets::new();
        add_mock_rulesets(&mut rs);

        let rulesets_representation = fs::read_to_string("tests/rulesets_representation.txt").unwrap();
        assert_eq!(format!("{:?}", rs), rulesets_representation);
    }

    #[test]
    #[cfg(feature="potentially_applicable")]
    fn potentially_applicable() {
        let mut rs = RuleSets::new();
        add_mock_rulesets(&mut rs);

        assert_eq!(rs.potentially_applicable("1fichier.com").len(), 1);
    }

    #[test]
    #[cfg(feature="potentially_applicable")]
    fn potentially_applicable_left_widlcard() {
        let mut rs = RuleSets::new();
        add_mock_rulesets(&mut rs);

        assert_eq!(rs.potentially_applicable("foo.1fichier.com").len(), 1);
        assert_eq!(rs.potentially_applicable("bar.foo.1fichier.com").len(), 1);
        assert_eq!(rs.potentially_applicable("foo.storage.googleapis.com").len(), 1);
        assert_eq!(rs.potentially_applicable("bar.foo.storage.googleapis.com").len(), 1);
    }

    #[test]
    #[cfg(feature="potentially_applicable")]
    fn potentially_applicable_no_matches() {
        let mut rs = RuleSets::new();
        add_mock_rulesets(&mut rs);

        assert_eq!(rs.potentially_applicable("nonmatch.example.com").len(), 0);
    }

    #[test]
    fn is_threadsafe() {
        let mut rs = RuleSets::new();

        let t = thread::spawn(move || {
            add_mock_rulesets(&mut rs);
        });

        assert!(t.join().is_ok());
    }
}
