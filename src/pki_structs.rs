use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorePkiCertificat {
    pub fingerprint: String,
    pub certificat: Vec<String>,
    pub ca: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorePkiCollectionRow {
    pub fingerprint: String,
    pub certificat: Vec<String>,
    pub ca: Option<String>,
    pub chaine: Option<Vec<String>>,
    pub dirty: Option<bool>,
    pub est_ca: Option<bool>,
    pub exchanges: Option<Vec<String>>,
    pub fingerprint_pk: Option<String>,
    pub idmg: Option<String>,
    #[serde(default, with = "opt_chrono_datetime_as_bson_datetime")]
    pub not_valid_after: Option<DateTime<Utc>>,
    #[serde(default, with = "opt_chrono_datetime_as_bson_datetime")]
    pub not_valid_before: Option<DateTime<Utc>>,
    pub roles: Option<Vec<String>>,
    pub suject: Option<HashMap<String, String>>,
}
