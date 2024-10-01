use log::debug;
use webauthn_rs::prelude::{Base64UrlSafeData, CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration, RegisterPublicKeyCredential, RequestChallengeResponse};

use millegrilles_common_rust::bson::DateTime as DateTimeBson;
use millegrilles_common_rust::jwt_simple::prelude::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::json;

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
