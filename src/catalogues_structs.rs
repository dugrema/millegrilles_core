use std::collections::HashMap;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::jwt_simple::prelude::Deserialize;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesOwned;
use millegrilles_common_rust::serde_json::Value;
use serde::Serialize;

#[derive(Clone, Deserialize)]
pub struct MessageCatalogue {
    pub catalogue: MessageMilleGrillesOwned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Catalogue {
    pub nom: String,
    pub securite: String,
    pub version: String,
    pub description: Option<HashMap<String, String>>,
    pub dependances: Option<Vec<Value>>,
    pub nginx: Option<HashMap<String, Value>>,
    pub web: Option<HashMap<String, Value>>,
    #[serde(rename="securityLevels")]
    pub security_levels: Option<Vec<String>>,
}

pub struct PackageVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
}

impl PartialEq for PackageVersion {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major && self.minor == other.minor && self.build == other.build
    }
}

impl PartialOrd for PackageVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.major != other.major {
            if self.major < other.major { return Some(std::cmp::Ordering::Less) }
            return Some(std::cmp::Ordering::Greater)
        } else if self.minor != other.minor {
            if self.minor < other.minor { return Some(std::cmp::Ordering::Less) }
            return Some(std::cmp::Ordering::Greater)
        } else if self.build != other.build {
            if self.build < other.build { return Some(std::cmp::Ordering::Less) }
            return Some(std::cmp::Ordering::Greater)
        }
        Some(std::cmp::Ordering::Equal)
    }
}

impl TryFrom<String> for PackageVersion {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        let parts = s.split(".").collect::<Vec<&str>>();
        // let major = parts[0].parse::<u16>().unwrap_or_else(|_| Err(Error::Str("A")))?;
        let major = parts[0].parse::<u16>().map_err(|_| Error::Str("Unsupported major version"))?;
        let minor = parts[1].parse::<u16>().map_err(|_| Error::Str("Unsupported minor version"))?;
        let build = parts[2].parse::<u16>().map_err(|_| Error::Str("Unsupported build version"))?;
        Ok(Self {major, minor, build})
    }
}
