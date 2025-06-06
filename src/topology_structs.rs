use std::collections::HashMap;
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::reqwest::Url;
use millegrilles_common_rust::serde_json::Value;
use serde::{Deserialize, Serialize};
use millegrilles_common_rust::bson;
use millegrilles_common_rust::common_messages::{FileUsage, RequeteFilehostItem};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::mongo_dao::{opt_chrono_datetime_as_bson_datetime, map_opt_chrono_datetime_as_bson_datetime};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSetFilehostInstance {
    pub instance_id: String,
    pub filehost_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionConfigurerConsignation {
    pub instance_id: String,
    pub type_store: Option<String>,
    pub url_download: Option<String>,
    pub url_archives: Option<String>,
    pub consignation_url: Option<String>,
    pub sync_intervalle: Option<i64>,
    pub sync_actif: Option<bool>,
    pub supporte_archives: Option<bool>,
    pub data_chiffre: Option<DataChiffre>,
    // SFTP
    pub hostname_sftp: Option<String>,
    pub username_sftp: Option<String>,
    pub port_sftp: Option<u16>,
    pub remote_path_sftp: Option<String>,
    pub key_type_sftp: Option<String>,
    // AWS S3
    pub s3_access_key_id: Option<String>,
    pub s3_region: Option<String>,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    // Backup
    pub type_backup: Option<String>,
    pub hostname_sftp_backup: Option<String>,
    pub port_sftp_backup: Option<u16>,
    pub username_sftp_backup: Option<String>,
    pub remote_path_sftp_backup: Option<String>,
    pub key_type_sftp_backup: Option<String>,
    pub backup_intervalle_secs: Option<i64>,
    pub backup_limit_bytes: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSetFichiersPrimaire {
    pub instance_id: String
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationPublique {
    pub application: String,
    pub version: Option<String>,
    pub url: String,
    pub preference: u8,
    pub nature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationApplicationInstance {
    pub pathname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationsV2 {
    pub instances: HashMap<String, InformationApplicationInstance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<HashMap<String, String>>,
    pub securite: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supporte_usager: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationInstance {
    pub domaines: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onion: Option<Vec<String>>,
    pub ports: HashMap<String, u16>,
    pub securite: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FichePublique {
    #[serde(rename = "applicationsV2")]
    pub applications_v2: HashMap<String, ApplicationsV2>,
    pub chiffrage: Option<Vec<Vec<String>>>,
    pub ca: Option<String>,
    pub idmg: String,
    pub instances: HashMap<String, InformationInstance>,
}

pub struct ReponseUrlEtag {
    pub url: Url,
    pub etag: String,
}

#[derive(Deserialize)]
pub struct JwtHebergement {
    pub jwt_readonly: String,
    pub jwt_readwrite: String,
}

#[derive(Serialize)]
pub struct RequeteRelaiWeb {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub json: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseRelaiWeb {
    pub code: Option<u16>,
    pub verify_ok: Option<bool>,
    pub headers: Option<HashMap<String, String>>,
    pub json: Option<Value>,
    pub text: Option<String>,
}

#[derive(Deserialize)]
pub struct TransactionSetCleidBackupDomaine {
    pub domaine: String,
    pub cle_id: Option<String>,
    pub reset: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InfoService {
    pub etat: Option<String>,
    pub labels: Option<HashMap<String, String>>,
    pub replicas: Option<usize>,
    pub image: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationConfiguree {
    pub nom: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebAppLink {
    pub name: String,
    pub labels: Option<HashMap<String, Value>>,
    pub securite: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceMonitor {
    #[serde(serialize_with = "optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    pub date_presence: Option<chrono::DateTime<Utc>>,
    pub domaine: Option<String>,
    pub domaines: Option<Vec<String>>,
    pub instance_id: String,
    pub services: Option<HashMap<String, InfoService>>,
    pub applications_configurees: Option<Vec<ApplicationConfiguree>>,
    pub containers: Option<HashMap<String, Value>>,
    pub disk: Option<Vec<Value>>,
    pub fqdn_detecte: Option<String>,
    pub hostname: Option<String>,
    pub info: Option<HashMap<String, Value>>,
    pub ip_detectee: Option<String>,
    pub load_average: Option<Vec<Value>>,
    pub securite: Option<String>,
    pub system_battery: Option<Value>,
    pub system_fans: Option<Value>,
    pub system_temperature: Option<HashMap<String, Value>>,
    pub webapps: Option<Vec<WebAppLink>>,
    pub consignation_id: Option<String>,
    pub filehost_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerInstanceStatus {
    pub instance_id: String,
    pub disk: Option<Vec<Value>>,
    pub hostname: Option<String>,
    pub hostnames: Option<Vec<String>>,
    pub ip: Option<String>,
    pub load_average: Option<Vec<f32>>,
    pub security: Option<String>,
    pub system_battery: Option<Value>,
    pub system_fans: Option<Value>,
    pub system_temperature: Option<HashMap<String, Value>>,
    #[serde(default, serialize_with = "optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    pub timestamp: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationApplication {
    pub application: String,
    pub securite: Option<String>,
    pub url: Option<String>,
    pub millegrille: Option<String>,
    pub name_property: Option<String>,
    pub supporte_usagers: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationMonitor {
    pub domaines: Option<Vec<String>>,
    pub instance_id: String,
    pub securite: Option<String>,
    pub onion: Option<String>,
    pub applications: Option<Vec<InformationApplication>>,
    pub applications_configurees: Option<Vec<ApplicationConfiguree>>,
    #[serde(serialize_with = "optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    pub date_presence: Option<chrono::DateTime<Utc>>,
    pub webapps: Option<Vec<WebAppLink>>,
    pub consignation_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceDomaine {
    pub domaine: Option<String>,
    pub instance_id: Option<String>,
    pub reclame_fuuids: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerConsignationInstance {
    pub instance_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FilehostServerRow {
    pub filehost_id: String,
    pub instance_id: Option<String>,
    pub url_internal: Option<String>,
    pub url_external: Option<String>,
    pub tls_external: Option<String>,
    pub deleted: bool,
    pub sync_active: bool,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created: DateTime<Utc>,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub modified: DateTime<Utc>,
    pub fuuid: Option<FileUsageMongo>,  // Workaround in f64 to handle mapping issue, NOT SERIALIZABLE
}

impl Into<RequeteFilehostItem> for FilehostServerRow {
    fn into(self) -> RequeteFilehostItem {
        RequeteFilehostItem {
            filehost_id: self.filehost_id,
            instance_id: self.instance_id,
            url_internal: self.url_internal,
            url_external: self.url_external,
            tls_external: self.tls_external,
            deleted: self.deleted,
            sync_active: self.sync_active,
            created: self.created,
            modified: self.modified,
            fuuid: match self.fuuid {Some (inner) => Some(inner.into()), None => None},
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FilehostingCongurationRow {
    pub name: String,
    pub value: String,
}

// #[derive(Serialize, Deserialize)]
// pub struct FilehostingFileVisit {
//     pub fuuid: String,
//     pub filehost_id: String,
//     #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
//     pub visit_time: DateTime<Utc>,
// }

#[derive(Serialize, Deserialize)]
pub struct FileStorageInfo {
    pub count: i64,
    pub size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct EventFilehostUsage {
    pub filehost_id: String,
    #[serde(with="epochseconds")]
    pub date: DateTime<Utc>,
    pub fuuid: Option<FileStorageInfo>,
}

#[derive(Serialize, Deserialize)]
pub struct EventNewFuuid {
    pub filehost_id: String,
    pub fuuid: String,
}

// #[derive(Serialize, Deserialize)]
// pub struct FuuidReclameRow {
//     pub fuuid: String,
//     #[serde(with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
//     pub last_claim: DateTime<Utc>,
// }

#[derive(Deserialize)]
pub struct RowFuuid { pub fuuid: String }

#[derive(Serialize, Deserialize)]
pub struct FilehostTransfer {
    pub destination_filehost_id: String,
    pub fuuid: String,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created: DateTime<Utc>,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub modified: DateTime<Utc>,
    #[serde(default, with="opt_chrono_datetime_as_bson_datetime")]
    pub job_picked_up: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RowFilehostFuuid {
    pub fuuid: String,
    #[serde(default, with="opt_chrono_datetime_as_bson_datetime")]
    pub last_claim_date: Option<DateTime<Utc>>,
    #[serde(default, with="map_opt_chrono_datetime_as_bson_datetime")]
    pub filehost: Option<HashMap<String, Option<DateTime<Utc>>>>,
}

#[derive(Deserialize)]
pub struct RowFilehostId { pub filehost_id: String }

#[derive(Serialize, Deserialize)]
pub struct ServerInstanceConfigurationRow {
    pub instance_id: String,
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileUsageMongo {
    // Note: using f64 rather than usize/u64 because of random bug loading large values with mongo client 2.8.1
    pub count: Option<f64>,
    pub size: Option<f64>,
}

impl Into<FileUsage> for FileUsageMongo {
    fn into(self) -> FileUsage {
        FileUsage {
            count: Some(self.count.unwrap_or(0f64) as usize),
            size: Some(self.size.unwrap_or(0f64) as usize),
        }
    }
}
