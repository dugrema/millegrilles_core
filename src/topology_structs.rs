use std::collections::HashMap;
use millegrilles_common_rust::chrono::{DateTime, Utc};
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

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct ServerInstanceStatus {
//     pub instance_id: String,
//     pub disk: Option<Vec<Value>>,
//     pub hostname: Option<String>,
//     pub hostnames: Option<Vec<String>>,
//     pub ip: Option<String>,
//     pub load_average: Option<Vec<f32>>,
//     pub security: Option<String>,
//     pub system_battery: Option<Value>,
//     pub system_fans: Option<Value>,
//     pub system_temperature: Option<HashMap<String, Value>>,
//     #[serde(default, serialize_with = "optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
//     pub timestamp: Option<chrono::DateTime<Utc>>,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceDomaine {
    pub domaine: Option<String>,
    pub instance_id: Option<String>,
    pub reclame_fuuids: Option<bool>,
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

// New system layout

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub ports: HashMap<String, u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionUsageItem {
    pub mountpoint: String,
    pub free: u64,
    pub used: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total: u64,
    pub available: u64,
    pub percent: f64,
    pub used: u64,
    pub free: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapInfo {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub errin: u64,
    pub errout: u64,
    pub dropin: u64,
    pub dropout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIOInfo {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_count: u64,
    pub write_count: u64,
    pub read_time: f64,
    pub write_time: f64,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertissuerState {
    #[serde(default, with="optionepochseconds")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, with="optionepochseconds")]
    pub not_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub host: Option<HostInfo>,
    pub disk: Vec<PartitionUsageItem>,
    pub load_average: Vec<f64>,
    pub memory: MemoryInfo,
    pub swap: SwapInfo,
    pub cpu_count: i32,
    pub cpu_usage_percent: f64,
    pub network: NetworkInfo,
    pub disk_io: Option<DiskIOInfo>,
    pub uptime_seconds: f64,
    pub system_temperature: Option<serde_json::Value>,
    pub system_fans: Option<serde_json::Value>,
    pub system_battery: Option<serde_json::Value>,
    pub apc: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerStatusV2 {
    pub instance_id: String,
    pub system_state: SystemState,
    pub securite: String,
    pub supprime: bool,
    pub timestamp: DateTime<Utc>,
    pub certissuer: Option<CertissuerState>,
}

type ApplicationLabels = HashMap<String, String>;

#[derive(Debug, Serialize, Deserialize)]
pub struct WebItem {
    pub admin: Option<bool>,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub labels: Option<ApplicationLabels>,
    pub api: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationInfo {
    pub name: String,
    pub alias: Option<String>,
    pub version: String,
    pub securite: Option<String>,
    pub labels: ApplicationLabels,
    pub path: Option<String>,
    pub web: Option<Vec<WebItem>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationStatusV2 {
    pub instance_id: String,
    pub applications: HashMap<String, ApplicationInfo>,
    pub securite: String,
    pub supprime: bool,
    pub timestamp: DateTime<Utc>,
}
