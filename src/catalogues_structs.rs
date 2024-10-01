use std::collections::HashMap;
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
}
