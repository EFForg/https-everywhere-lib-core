use openssl::pkey::{PKey, Public};
use serde_json::Value;
use crate::strings::ERROR_SERDE_PARSE;

struct StaticJsonStrings {
    pub name: &'static str,
    pub update_path_prefix: &'static str,
    pub scope: &'static str,
    pub replaces_default_rulesets: &'static str,
    pub pem: &'static str,
}

const JSON_STRINGS: StaticJsonStrings = StaticJsonStrings {
    name: "name",
    update_path_prefix: "update_path_prefix",
    scope: "scope",
    replaces_default_rulesets: "replaces_default_rulesets",
    pem: "pem",
};


/// An UpdateChannel defines where to find ruleset updates, the key to verify them, the scope they
/// are applied to (which should be a regular expression), and whether they replace the default
/// rulesets included with the application.
pub struct UpdateChannel {
    pub name: String,
    pub key: PKey<Public>,
    pub update_path_prefix: String,
    pub scope: Option<String>,
    pub replaces_default_rulesets: bool,
}

impl From<&String> for UpdateChannel {
    /// Returns an update channel given a JSON string
    ///
    /// # Arguments
    ///
    /// * `json_string` - A json string specifying the update channel.  See
    /// [`tests/update_channels.json`](https://github.com/EFForg/https-everywhere-lib-core/blob/master/tests/update_channels.json) for the correct format
    ///
    /// # Panics
    ///
    /// Panics if a name, update path prefix, or pem is not specified, if the pem file does not
    /// parse correctly into an RSA key, or it is not an object
    fn from(json_string: &String) -> UpdateChannel {
        let update_channel: Value = serde_json::from_str(&json_string).expect(ERROR_SERDE_PARSE);
        UpdateChannel::from(&update_channel)
    }
}

impl From<&Value> for UpdateChannel {
    /// Returns an update channel given a serde_json::Value
    ///
    /// See the implementation of `From<&String>` for more detail
    fn from(json_value: &Value) -> UpdateChannel {
        if let Value::Object(update_channel) = json_value {
            let name = match update_channel.get(JSON_STRINGS.name) {
                Some(Value::String(name)) => name.to_string(),
                _ => panic!("Name can not be blank")
            };
            let update_path_prefix = match update_channel.get(JSON_STRINGS.update_path_prefix) {
                Some(Value::String(update_path_prefix)) => update_path_prefix.to_string(),
                _ => panic!("Update path prefix can not be blank")
            };
            let scope = match update_channel.get(JSON_STRINGS.scope) {
                Some(Value::String(scope)) if scope == "" => None,
                Some(Value::String(scope)) => Some(scope.to_string()),
                _ => None
            };
            let replaces_default_rulesets = match update_channel.get(JSON_STRINGS.replaces_default_rulesets) {
                Some(Value::Bool(replaces_default_rulesets)) => replaces_default_rulesets.clone(),
                _ => false
            };
            let key = match update_channel.get(JSON_STRINGS.pem) {
                Some(Value::String(pem)) => {
                    match PKey::public_key_from_pem(&pem.clone().into_bytes()) {
                        Ok(key) => key,
                        _ => panic!("Could not parse public key")
                    }
                },
                _ => panic!("Pem can not be blank")
            };
            UpdateChannel {
                name,
                key,
                update_path_prefix,
                scope,
                replaces_default_rulesets,
            }
        } else {
            panic!("Unexpected: update channel is not an object");
        }
    }
}


/// RuleSets consists of a tuple vec of update channels
pub struct UpdateChannels(Vec<UpdateChannel>);

impl UpdateChannels {
    /// Get an immutable reference to all update channels
    pub fn get_all(&self) -> &Vec<UpdateChannel>{
       &self.0
    }

    /// Get a mutable reference to all update channels
    pub fn get_all_mut(&mut self) -> &mut Vec<UpdateChannel>{
       &mut self.0
    }
}

/// Returns update channels given a JSON string
///
/// See the implementation of `From<&String> for UpdateChannel` for more detail
///
/// # Panics
///
/// Panics if the update channels JSON is not an array
impl From<&String> for UpdateChannels {
    fn from(json_string: &String) -> UpdateChannels {
        if let Value::Array(update_channels) = serde_json::from_str(&json_string).expect(ERROR_SERDE_PARSE) {
            UpdateChannels(update_channels.into_iter().map(|uc| {
                UpdateChannel::from(&uc)
            }).collect())
        } else {
            panic!("Unexpected: update channels is not an array")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn mock_update_channels_json() -> String {
        fs::read_to_string("tests/update_channels.json").unwrap()
    }

    fn create_mock_update_channels() -> UpdateChannels {
        UpdateChannels::from(&mock_update_channels_json())
    }

    #[test]
    fn creates_update_channels_correctly() {
        let ucs = create_mock_update_channels();

        let update_channels_representation = fs::read_to_string("tests/update_channels_representation.txt").unwrap();
        assert_eq!(format!("{:?}", ucs), update_channels_representation);
    }

    #[test]
    #[should_panic]
    fn panics_if_no_name_specified() {
        let mut update_channels: Value = serde_json::from_str(&mock_update_channels_json()).expect(ERROR_SERDE_PARSE);
        update_channels.get_mut(0).unwrap().get_mut(JSON_STRINGS.name).unwrap().take();
        UpdateChannel::from(update_channels.get(0).unwrap());
    }

    #[test]
    #[should_panic]
    fn panics_if_no_update_path_prefix_specified() {
        let mut update_channels: Value = serde_json::from_str(&mock_update_channels_json()).expect(ERROR_SERDE_PARSE);
        update_channels.get_mut(0).unwrap().get_mut(JSON_STRINGS.update_path_prefix).unwrap().take();
        UpdateChannel::from(update_channels.get(0).unwrap());
    }

    #[test]
    #[should_panic]
    fn panics_if_no_pem_specified() {
        let mut update_channels: Value = serde_json::from_str(&mock_update_channels_json()).expect(ERROR_SERDE_PARSE);
        update_channels.get_mut(0).unwrap().get_mut(JSON_STRINGS.pem).unwrap().take();
        UpdateChannel::from(update_channels.get(0).unwrap());
    }

    #[test]
    #[should_panic]
    fn panics_if_pem_specified_incorrectly() {
        let mut update_channels: Value = serde_json::from_str(&mock_update_channels_json()).expect(ERROR_SERDE_PARSE);
        let pem = update_channels.get_mut(0).unwrap().get_mut(JSON_STRINGS.pem).unwrap();
        *pem = Value::String(String::from("Not a pem value"));
        UpdateChannel::from(update_channels.get(0).unwrap());
    }
}
