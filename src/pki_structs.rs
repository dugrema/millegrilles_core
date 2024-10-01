use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorePkiCertificat {
    pub fingerprint: String,
    pub certificat: Vec<String>,
    pub ca: Option<String>,
}
