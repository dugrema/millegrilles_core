use log::debug;
use webauthn_rs::prelude::{Base64UrlSafeData, CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration, RegisterPublicKeyCredential, RequestChallengeResponse};

use millegrilles_common_rust::bson::DateTime as DateTimeBson;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::jwt_simple::prelude::{Deserialize, Serialize};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesOwned;
use millegrilles_common_rust::{base64_url, chrono, openssl, serde_json};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeRegistrationWebauthn {
    pub user_uuid: String,
    pub registration_challenge: CreationChallengeResponse,
    pub resistration_state: PasskeyRegistration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeAuthenticationWebauthn {
    pub authentication_challenge: RequestChallengeResponse,
    pub passkey_authentication: PasskeyAuthentication,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocChallenge {
    #[serde(rename="userId")]
    pub user_id: String,
    pub type_challenge: String,
    pub hostname: String,
    pub challenge: String,

    #[serde(rename="_mg-creation")]
    pub date_creation: DateTimeBson,

    // Les elements suivants sont exlusifs (max 1 a la fois)

    /// Pour une registration webauthn
    pub webauthn_registration: Option<ChallengeRegistrationWebauthn>,

    /// Pour une authentification webauthn
    pub webauthn_authentication: Option<ChallengeAuthenticationWebauthn>,
}

impl DocChallenge {
    pub fn new_challenge_resgistration<T,U,V>(
        user_id: U, user_uuid: T, hostname: V, challenge: CreationChallengeResponse, registration: PasskeyRegistration
    ) -> Self
    where T: Into<String>, U: Into<String>, V: Into<String>
    {
        let webauthn_registration = ChallengeRegistrationWebauthn {
            user_uuid: user_uuid.into(),
            registration_challenge: challenge,
            resistration_state: registration,
        };

        let challenge = webauthn_registration.registration_challenge.public_key.challenge.to_string();

        Self {
            user_id: user_id.into(),
            type_challenge: "registration".to_string(),
            hostname: hostname.into(),
            challenge,
            date_creation: DateTimeBson::now(),
            webauthn_registration: Some(webauthn_registration),
            webauthn_authentication: None,
        }
    }

    pub fn new_challenge_authentication<U,V>(
        user_id: U, hostname: V, authentication_challenge: RequestChallengeResponse, passkey_authentication: PasskeyAuthentication
    ) -> Self
    where U: Into<String>, V: Into<String>
    {
        let challenge = authentication_challenge.public_key.challenge.to_string();

        let webauthn_authentication = ChallengeAuthenticationWebauthn {
            authentication_challenge, passkey_authentication };

        Self {
            user_id: user_id.into(),
            type_challenge: "authentication".to_string(),
            hostname: hostname.into(),
            challenge,
            date_creation: DateTimeBson::now(),
            webauthn_registration: None,
            webauthn_authentication: Some(webauthn_authentication),
        }
    }

    pub fn new_challenge_generique<U,V,S>(
        user_id: U, hostname: V, challenge: Base64UrlSafeData, type_challenge: S
    ) -> Self
    where U: Into<String>, V: Into<String>, S: Into<String>
    {
        let type_challenge = type_challenge.into();
        let challenge = challenge.to_string();

        Self {
            user_id: user_id.into(),
            type_challenge,
            hostname: hostname.into(),
            challenge,
            date_creation: DateTimeBson::now(),
            webauthn_registration: None,
            webauthn_authentication: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AjouterCleResponseClient {
    #[serde(rename="attestationObject")]
    pub attestation_object: String,
    #[serde(rename="clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AjouterClePublickKeyCredential {
    pub id: String,
    pub response: AjouterCleResponseClient,
    #[serde(rename="type")]
    pub type_: String,
}

impl TryInto<RegisterPublicKeyCredential> for AjouterClePublickKeyCredential {
    type Error = millegrilles_common_rust::error::Error;

    fn try_into(self) -> Result<RegisterPublicKeyCredential, Self::Error> {
        let id = self.id;

        let json_attest = json!({
            "id": &id,
            "rawId": id,
            "response": self.response,
            "type": self.type_,
            "extensions": {},
        });

        debug!("TryInto<RegisterPublicKeyCredential> json_attest: {:?}", json_attest);
        let cred: RegisterPublicKeyCredential = serde_json::from_value(json_attest)?;
        debug!("TryInto<RegisterPublicKeyCredential> cred: {:?}", cred);

        Ok(cred)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAjouterCle {
    #[serde(rename="fingerprintPk")]
    pub fingerprint_pk: Option<String>,
    pub hostname: Option<String>,
    #[serde(rename="reponseChallenge")]
    pub reponse_client: AjouterClePublickKeyCredential,
    pub reset_cles: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInscrireUsager {
    pub fingerprint_pk: String,
    #[serde(rename="nomUsager")]
    pub nom_usager: String,
    #[serde(rename="userId")]
    pub user_id: String,
    pub securite: String,
    pub csr: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CommandeAjouterDelegationSignee<'a> {
    // #[serde(borrow="'a")]
    // confirmation: MessageMilleGrillesRefDefault<'a>,
    pub confirmation: MessageMilleGrillesOwned,
    #[serde(rename="userId")]
    pub user_id: Option<&'a str>,
    pub hostname: &'a str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationSigneeDelegationGlobale {
    #[serde(rename="activerDelegation")]
    pub activer_delegation: Option<bool>,
    pub challenge: String,
    #[serde(rename="nomUsager")]
    pub nom_usager: String,
    #[serde(rename="userId")]
    pub user_id: String,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CookieSession {
    pub user_id: String,
    pub hostname: String,
    pub challenge: String,
    #[serde(with = "epochseconds")]
    pub expiration: DateTime<Utc>,
}

impl Into<Value> for CookieSession {
    fn into(self) -> Value {
        serde_json::to_value(self).expect("value")
    }
}

impl CookieSession {
    pub fn new<U,H>(user_id: U, hostname: H, duree_session: i64) -> Self
    where U: Into<String>, H: Into<String>
    {
        let date_expiration = Utc::now() + chrono::Duration::seconds(duree_session);

        let mut buffer_challenge = [0u8; 32];
        openssl::rand::rand_bytes(&mut buffer_challenge).expect("openssl::random::rand_bytes");
        let challenge = base64_url::encode(&buffer_challenge[..]);

        Self {
            user_id: user_id.into(),
            hostname: hostname.into(),
            challenge,
            expiration: date_expiration,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompteUsager {
    #[serde(rename="nomUsager")]
    pub nom_usager: String,
    #[serde(rename="userId")]
    pub user_id: String,

    pub compte_prive: Option<bool>,

    pub delegation_globale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with="optionepochseconds")]
    pub delegations_date: Option<DateTime<Utc>>,
    pub delegations_version: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteGetCookieUsager {
    pub user_id: String,
    pub hostname: String,
    pub challenge: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionMajUsagerDelegations {
    pub compte_prive: Option<bool>,
    pub delegation_globale: Option<String>,
    #[serde(rename="userId")]
    pub user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerCles {
    #[serde(rename="userId")]
    pub user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvenementMajCompteUsager {
    #[serde(rename="nomUsager")]
    pub nom_usager: String,
    #[serde(rename="userId")]
    pub user_id: String,
    pub compte_prive: Option<bool>,
    pub delegation_globale: Option<String>,
    pub delegations_version: Option<usize>,
    pub delegations_date: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeResetWebauthnUsager {
    #[serde(rename="userId")]
    pub user_id: String,
    #[serde(rename="resetWebauthn")]
    pub reset_webauthn: Option<bool>,
    #[serde(rename="evictAllSessions")]
    pub evict_all_sessions: Option<bool>,
}
