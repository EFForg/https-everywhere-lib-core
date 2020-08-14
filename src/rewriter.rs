use lru::LruCache;
use regex::Regex;
use std::error::Error;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::collections::VecDeque;

use url::Url;

use crate::{settings::ThreadSafeSettings, rulesets::{ThreadSafeRuleSets, RuleSet}};

/// A RewriteAction is used to indicate an action to take, returned by the rewrite_url method on
/// the Rewriter struct
#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Clone)]
pub enum RewriteAction {
    CancelRequest,
    NoOp,
    RewriteUrl(String),
    RedirectLoopWarning,
}


/// A Rewriter provides an abstraction layer over RuleSets and Settings, providing the logic for
/// rewriting URLs
pub struct Rewriter {
    rulesets: ThreadSafeRuleSets,
    settings: ThreadSafeSettings,
    rewrite_count: AtomicUsize,
    cookie_host_safety_cache: LruCache<String, bool>,
    rewrite_history: VecDeque<(String, RewriteAction)>,
}

impl Rewriter {
    /// Returns a rewriter with the rulesets and settings specified
    ///
    /// # Arguments
    ///
    /// * `rulesets` - An instance of RuleSets for rewriting URLs, wrapped in an Arc<Mutex>
    /// * `settings` - A settings object to query current state, wrapped in an Arc<Mutex>
    pub fn new(rulesets: ThreadSafeRuleSets, settings: ThreadSafeSettings) -> Rewriter {
        Rewriter {
            rulesets,
            settings,
            rewrite_count: AtomicUsize::new(0),
            cookie_host_safety_cache: LruCache::new(250), // 250 is somewhat arbitrary
            rewrite_history: VecDeque::with_capacity(15),
        }
    }

    /// Return a RewriteAction wrapped in a Result when given a URL.  This action should be
    /// ingested by the implementation using the library
    ///
    /// # Arguments
    ///
    /// * `url` - A URL to determine the action for
    pub fn rewrite_url(&mut self, url: &str) -> Result<RewriteAction, Box<dyn Error>> {
        if !self.settings.lock().unwrap().get_https_everywhere_enabled_or(true) {
            return Ok(RewriteAction::NoOp);
        }

        let mut url = Url::parse(url)?;
        if let Some(hostname) = url.host_str() {
            let mut hostname = hostname.trim_end_matches('.');
            if hostname.is_empty() {
                hostname = ".";
            }
            let hostname = hostname.to_string();

            let mut should_cancel = false;
            let http_nowhere_on = self.settings.lock().unwrap().get_ease_mode_enabled_or(false);
            if http_nowhere_on {
                if url.scheme() == "http" || url.scheme() == "ftp" {
                    let num_localhost = Regex::new(r"^127(\.[0-9]{1,3}){3}$").unwrap();
                    if !hostname.ends_with(".onion") &&
                        hostname != "localhost" &&
                        !hostname.ends_with(".localhost") &&
                        !num_localhost.is_match(&hostname) &&
                        hostname != "0.0.0.0" &&
                        hostname != "[::1]" {
                        should_cancel = true;
                    }
                }
            }
            let mut using_credentials_in_url = false;
            let tmp_url = url.clone();
            if url.username() != "" || url.password() != None {
                using_credentials_in_url = true;
                url.set_username("").unwrap();
                url.set_password(None).unwrap();
            }

            let mut new_url: Option<Url> = None;

            let mut apply_if_active = |ruleset: &RuleSet| {
                if ruleset.active && new_url.is_none() {
                    new_url = match ruleset.apply(url.as_str()) {
                        None => None,
                        Some(url_str) => Some(Url::parse(&url_str).unwrap())
                    };
                }
            };


            for ruleset in self.rulesets.lock().unwrap().potentially_applicable(&hostname) {
                if let Some(scope) = (*ruleset.scope).clone() {
                    let scope_regex = Regex::new(&scope).unwrap();
                    if scope_regex.is_match(url.as_str()) {
                        apply_if_active(&ruleset);
                    }
                } else {
                    apply_if_active(&ruleset);
                }
            }

            if using_credentials_in_url {
                match &mut new_url {
                    None => {
                        url.set_username(tmp_url.username()).unwrap();
                        url.set_password(tmp_url.password()).unwrap();
                    },
                    Some(url) => {
                        url.set_username(tmp_url.username()).unwrap();
                        url.set_password(tmp_url.password()).unwrap();
                    }
                }
            }

            if http_nowhere_on {
                if should_cancel && new_url.is_none() {
                    return Ok(self.record_history(url, RewriteAction::CancelRequest));
                }

                // Cancel if we're about to redirect to HTTP or FTP in EASE mode
                if let Some(rewritten_url) = &new_url {
                    if rewritten_url.as_str().starts_with("http:") ||
                       rewritten_url.as_str().starts_with("ftp:") {
                        return Ok(self.record_history(url, RewriteAction::CancelRequest));
                    }
                }
            }

            if let Some(rewritten_url) = new_url {
                info!("rewrite_url returning redirect url: {}", rewritten_url.as_str());
                self.rewrite_count.fetch_add(1, Ordering::Relaxed);
                Ok(self.record_history(url, RewriteAction::RewriteUrl(rewritten_url.as_str().to_string())))
            } else {
                Ok(self.record_history(url, RewriteAction::NoOp))
            }
        } else {
            Ok(self.record_history(url, RewriteAction::NoOp))
        }
    }

    /// Helper function which assumes that if we've seen the same rewrite 8 times out of the last
    /// 15 rewrites, we're probably in a redirect loop and should warn the consumer
    fn record_history(&mut self, url: Url, action: RewriteAction) -> RewriteAction {
        self.rewrite_history.truncate(14);
        self.rewrite_history.push_front((url.as_str().to_string(), action.clone()));
        if self.rewrite_history.iter().filter(|(history_url, history_action)| {
            history_url == url.as_str() && history_action == &action
        }).count() >= 8 {
            RewriteAction::RedirectLoopWarning
        } else {
            action
        }
    }

    /// Get the number of times a URL has been rewritten with this rewriter
    pub fn get_rewrite_count(&self) -> usize {
        self.rewrite_count.load(Ordering::Relaxed)
    }

    /// Return whether a cookie should be secured based on our cookierule criteria.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain for this cookie
    /// * `name` - The name of the cookie
    pub fn should_secure_cookie(&mut self, domain: &str, name: &str) -> bool {
        let domain = String::from(domain.trim_start_matches('.'));

        // We need a cookie pass two tests before patching it
        //   (1) it is safe to secure the cookie, as per safe_to_secure_cookie()
        //   (2) it matches the CookieRule
        //
        // We keep a cache of the results for (1). If we have a cached result which
        //   (a) is false, we should not secure the cookie and return false immediately
        //   (b) is true, we need to perform test (2)
        //
        // If we have no cached result,
        //   (c) We need to perform (1) and (2) in place

        let safe = match self.cookie_host_safety_cache.get(&domain) {
            Some(safe) => {
                debug!("Cookie host safety cache hit for {:?}", domain);
                if !safe {
                    return false;
                }
                true
            },
            None => {
                debug!("Cookie host safety cache miss for {:?}", domain);
                false
            },
        };

        let potentially_applicable = self.rulesets.lock().unwrap().potentially_applicable(&domain);
        for ruleset in &potentially_applicable {
            if ruleset.cookierules.is_some() && ruleset.active {
                for cookierule in ruleset.cookierules.as_ref().unwrap() {
                    let cookierule_host = Regex::new(&cookierule.host_regex).unwrap();
                    let cookierule_name = Regex::new(&cookierule.name_regex).unwrap();
                    if cookierule_host.is_match(&domain) && cookierule_name.is_match(name) {
                        return safe || self.safe_to_secure_cookie(domain, &potentially_applicable);
                    }
                }
            }
        }
        false
    }

    /// Return whether it is safe to secure the cookie
    fn safe_to_secure_cookie(&mut self, domain: String, potentially_applicable: &[Arc<RuleSet>]) -> bool {
        // Make up a random URL on the domain, and see if we would HTTPSify that.
        let test_url = String::from("http://") + &domain + "/is_it_safe/to_secure_this_cookie";

        for ruleset in potentially_applicable {
            if ruleset.active && ruleset.apply(&test_url).is_some() {
                info!("Cookie domain could be secured: {:?}", domain);
                self.cookie_host_safety_cache.put(domain, true);
                return true;
            }
        }
        info!("Cookie domain could not be secured: {:?}", domain);
        self.cookie_host_safety_cache.put(domain, false);
        false
    }
}

#[cfg(all(test,feature="add_rulesets"))]
mod tests {
    use super::*;
    use std::{panic, thread};
    use std::sync::Mutex;
    use crate::RuleSets;
    use crate::Settings;
    use crate::storage::tests::mock_storage::{TestStorage, HttpNowhereOnStorage};
    use crate::rulesets::tests as rulesets_tests;

    #[test]
    fn rewrite_url() {
        let mut rs = RuleSets::new();
        rulesets_tests::add_mock_rulesets(&mut rs);
        let rs = Arc::new(Mutex::new(rs));

        let s: ThreadSafeSettings = Arc::new(Mutex::new(Settings::new(Arc::new(Mutex::new(TestStorage)))));
        let mut rw = Rewriter::new(rs, s);

        assert_eq!(
            rw.rewrite_url("http://freerangekitten.com/").unwrap(),
            RewriteAction::RewriteUrl(String::from("https://freerangekitten.com/")));

        assert_eq!(
            rw.rewrite_url("http://fake-example.com/").unwrap(),
            RewriteAction::NoOp);
    }

    #[test]
    fn rewrite_url_http_nowhere_on() {
        let mut rs = RuleSets::new();
        rulesets_tests::add_mock_rulesets(&mut rs);
        let rs = Arc::new(Mutex::new(rs));

        let s: ThreadSafeSettings = Arc::new(Mutex::new(Settings::new(Arc::new(Mutex::new(HttpNowhereOnStorage)))));
        let mut rw = Rewriter::new(rs, s);

        assert_eq!(rw.get_rewrite_count(), 0);

        assert_eq!(
            rw.rewrite_url("http://freerangekitten.com/").unwrap(),
            RewriteAction::RewriteUrl(String::from("https://freerangekitten.com/")));

        assert_eq!(rw.get_rewrite_count(), 1);

        assert_eq!(
            rw.rewrite_url("http://fake-example.com/").unwrap(),
            RewriteAction::CancelRequest);

        assert_eq!(rw.get_rewrite_count(), 1);

        assert_eq!(
            rw.rewrite_url("http://fake-example.onion/").unwrap(),
            RewriteAction::NoOp);

        assert_eq!(rw.get_rewrite_count(), 1);

        assert_eq!(
            rw.rewrite_url("http://fake-example.onion..../").unwrap(),
            RewriteAction::NoOp);
    }

    #[test]
    fn rewrite_exclusions() {
        let mut rs = RuleSets::new();
        rulesets_tests::add_mock_rulesets(&mut rs);
        let rs = Arc::new(Mutex::new(rs));

        let s: ThreadSafeSettings = Arc::new(Mutex::new(Settings::new(Arc::new(Mutex::new(TestStorage)))));
        let mut rw = Rewriter::new(rs, s);

        assert_eq!(
            rw.rewrite_url("http://chart.googleapis.com/").unwrap(),
            RewriteAction::NoOp);

        assert_eq!(
            rw.rewrite_url("http://chart.googleapis.com/123").unwrap(),
            RewriteAction::RewriteUrl(String::from("https://chart.googleapis.com/123")));
    }

    #[test]
    fn rewrite_with_credentials() {
        let mut rs = RuleSets::new();
        rulesets_tests::add_mock_rulesets(&mut rs);
        let rs = Arc::new(Mutex::new(rs));

        let s: ThreadSafeSettings = Arc::new(Mutex::new(Settings::new(Arc::new(Mutex::new(TestStorage)))));
        let mut rw = Rewriter::new(rs, s);

        assert_eq!(
            rw.rewrite_url("http://eff:techprojects@chart.googleapis.com/123").unwrap(),
            RewriteAction::RewriteUrl(String::from("https://eff:techprojects@chart.googleapis.com/123")));
    }

    #[test]
    fn gives_redirect_loop_warning() {
        let mut rs = RuleSets::new();
        rulesets_tests::add_mock_rulesets(&mut rs);
        let rs = Arc::new(Mutex::new(rs));

        let s: ThreadSafeSettings = Arc::new(Mutex::new(Settings::new(Arc::new(Mutex::new(TestStorage)))));
        let mut rw = Rewriter::new(rs, s);

        rw.rewrite_url("http://freerangekitten.com/").unwrap();
        rw.rewrite_url("http://freerangekitten.com/").unwrap();
        rw.rewrite_url("http://freerangekitten.com/").unwrap();
        rw.rewrite_url("http://freerangekitten.com/").unwrap();
        rw.rewrite_url("http://freerangekitten.com/").unwrap();
        rw.rewrite_url("http://freerangekitten.com/").unwrap();
        rw.rewrite_url("http://freerangekitten.com/").unwrap();

        assert_eq!(
            rw.rewrite_url("http://freerangekitten.com/").unwrap(),
            RewriteAction::RedirectLoopWarning);
    }

    #[test]
    fn secures_cookies() {
        let mut rs = RuleSets::new();
        rulesets_tests::add_mock_rulesets(&mut rs);
        let rs = Arc::new(Mutex::new(rs));

        let s: ThreadSafeSettings = Arc::new(Mutex::new(Settings::new(Arc::new(Mutex::new(TestStorage)))));
        let mut rw = Rewriter::new(rs, s);

        assert_eq!(rw.should_secure_cookie("maps.gstatic.com", "some_google_cookie"), true);
    }

    #[test]
    fn does_not_secure_unspecified_cookies() {
        let mut rs = RuleSets::new();
        rulesets_tests::add_mock_rulesets(&mut rs);
        let rs = Arc::new(Mutex::new(rs));

        let s: ThreadSafeSettings = Arc::new(Mutex::new(Settings::new(Arc::new(Mutex::new(TestStorage)))));
        let mut rw = Rewriter::new(rs, s);

        assert_eq!(rw.should_secure_cookie("example.com", "some_example_cookie"), false);
    }

    #[test]
    fn is_threadsafe() {
        let mut rs = RuleSets::new();
        rulesets_tests::add_mock_rulesets(&mut rs);
        let rs = Arc::new(Mutex::new(rs));

        let s: ThreadSafeSettings = Arc::new(Mutex::new(Settings::new(Arc::new(Mutex::new(TestStorage)))));

        let t = thread::spawn(move || {
            let rw = Rewriter::new(rs, s);
            let _ = Box::new(rw);
        });

        assert!(t.join().is_ok());
    }
}
