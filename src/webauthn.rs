use std::error::Error;
use std::fmt::{Debug, Formatter};

use log::{debug, error, info, warn};
use millegrilles_common_rust::chiffrage::random_vec;
use millegrilles_common_rust::multibase;
use millegrilles_common_rust::rand;
use millegrilles_common_rust::rand::Rng;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::{json};
use webauthn_rs::{Webauthn, WebauthnConfig, AuthenticationState};
use webauthn_rs::proto::{PublicKeyCredential, AuthenticatorAssertionResponseRaw};
use webauthn_rs::base64_data::Base64UrlSafeData;
use millegrilles_common_rust::openssl;
use std::convert::TryInto;
use millegrilles_common_rust::openssl::bn::{BigNumRef, BigNum};

pub fn generer_challenge_auth(url_site: &str, credentials: Vec<Credential>) -> Result<Challenge, Box<dyn Error>> {

    let rnd_bytes = random_vec(128);
    debug!("Random ... {:?}", rnd_bytes);
    let challenge = multibase::encode(multibase::Base::Base64, &rnd_bytes);

    let creds: Vec<AllowCredential> = credentials.into_iter().map(|c| {
        AllowCredential {id: c.credId, cred_type: c.key_type}
    }).collect();

    let challenge = Challenge {
        challenge,
        timeout: 60_000,
        rpId: url_site.into(),
        userVerification: "preferred".into(),
        allowCredentials: creds,
        hostname: url_site.into(),
    };

    Ok(challenge)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    credId: String,
    counter: Option<usize>,
    publicKeyPem: Option<String>,
    #[serde(rename = "type")]
    key_type: String,
}
impl Credential {
    pub fn new<S>(cred_id: S, key_type: S, counter: Option<usize>, public_key_pem: Option<String>) -> Self
        where S: Into<String>
    {
        Credential {
            credId: cred_id.into(),
            counter,
            publicKeyPem: public_key_pem,
            key_type: key_type.into(),
        }
    }
}
impl TryInto<webauthn_rs::proto::Credential> for Credential {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<webauthn_rs::proto::Credential, Self::Error> {

        // let id_b64 = &self.credId[1..];  // Base64, retirer le premier char multibase (m)

        let counter = match self.counter {
            Some(c) => c as u32,
            None => 0,
        };

        let cle = match self.publicKeyPem {
            Some(pem) => openssl::pkey::PKey::public_key_from_pem(pem.as_bytes())?,
            None => Err("publicKeyPem manquant")?
        };

        let cose_key = match cle.id() {
            openssl::pkey::Id::EC => {
                debug!("Type cle EC");
                let key = cle.ec_key()?;
                key.check_key()?;

                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;

                let pk_ref = key.public_key();
                let mut ctx = openssl::bn::BigNumContext::new()?;
                pk_ref.affine_coordinates(key.group(), &mut x, &mut y, &mut ctx)?;

                debug!("Webauthn extraction x {:?}, y {:?} de cle publique EC", x, y);

                let mut x_array: [u8; 32] = [0u8; 32];
                let mut y_array: [u8; 32] = [0u8; 32];

                let vec_x = x.to_vec();
                let vec_y = y.to_vec();
                for i in 0..32 {
                    x_array[i] = vec_x.get(i).expect("val x").to_owned();
                }
                for i in 0..32 {
                    y_array[i] = vec_y.get(i).expect("val y").to_owned();
                }

                webauthn_rs::crypto::COSEKey {
                    type_: webauthn_rs::crypto::COSEContentType::ECDSA_SHA256,
                    key: webauthn_rs::crypto::COSEKeyType::EC_EC2(webauthn_rs::crypto::COSEEC2Key {
                        curve: webauthn_rs::crypto::ECDSACurve::SECP256R1,
                        x: x_array,
                        y: y_array,
                    }),
                }
            },
            _ => Err(format!("Type cle non supporte : {:?}", cle.id()))?
        };

        debug!("Public key chargee : {:?}", cle);

        let cred = webauthn_rs::proto::Credential {
            cred_id: multibase::decode(self.credId)?.1,
            cred: cose_key,
            counter,
        };

        Ok(cred)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Challenge {
    challenge: String,
    timeout: usize,
    rpId: String,
    userVerification: String,  // 'preferred',
    allowCredentials: Vec<AllowCredential>,
    hostname: String,
}

pub struct ConfigChallenge {
    pub rp_id: String,
    pub hostname: String,
    pub challenge: String,
}
impl WebauthnConfig for ConfigChallenge {
    fn get_relying_party_name(&self) -> String {
        self.rp_id.clone()
    }

    fn get_origin(&self) -> &String {
        &self.hostname
    }

    fn get_relying_party_id(&self) -> String {
        self.rp_id.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowCredential {
    id: String,
    #[serde(rename = "type")]
    cred_type: String,
}

// def authenticate_complete(self, url_site: str, assertions: dict, auth_response: dict, user_webauthn: list):
pub fn authenticate_complete(credentials: Vec<Credential>, challenge: ConfigChallenge, rsp: PublicKeyCredential)  // , challenge: &Challenge, response: AuthenticatorAssertionResponseRaw, credentials: Vec<Credential>) -> Result<bool, Box<dyn Error>> {
    -> Result<bool, Box<dyn Error>>
{
    let mut convert_iter = credentials.into_iter();
    let mut creds = Vec::new();
    while let Some(c) = convert_iter.next() {
        let cred: webauthn_rs::proto::Credential = c.try_into()?;
        creds.push(cred);
    }
    debug!("Creds : {:?}", creds);

    let val_auth_state = json!({
        "credentials": creds,
        "policy": "preferred",
        "challenge": challenge.challenge.clone(),
    });

    let state: AuthenticationState = serde_json::from_value(val_auth_state)?;
    let mut webauthn = Webauthn::new(challenge);

    match webauthn.authenticate_credential(rsp, state)? {
        Some(r) => {
            debug!("Credential OK, info : {:?}", r);
            Ok(true)
        },
        None => Ok(true),
    }

}

#[cfg(test)]
mod webauthn_test {
    use crate::test_setup::setup;

    use super::*;

    #[test]
    fn generer_challenge_1() {
        setup("generer_challenge_1");

        let url_site = "https://monsite.test.com";
        let creds = vec! [
            Credential::new("id_1", "public-key", Some(0), Some("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzsQMBGueMw2v1oy1jMSBDvqZJZ3t\nbp8ENrRaK7QS3+sd77IXGM0MTGF4S9I5ERNp4+9ET5WYZb3tNtOFcQ1nyg==\n-----END PUBLIC KEY-----\n".into()))
        ];

        let challenge = generer_challenge_auth(url_site, creds).expect("challenge");
        debug!("Challenge : {:?}", challenge);
    }

    #[test]
    fn authenticate_complete_1() {
        setup("authenticate_complete_1");

        let url_site = "https://mg-dev4.maple.maceroc.com";
        let creds = vec! [
            Credential::new(
                "mWVjN2yomAi8r5aUfz9nE+SMtBMLnFBFZ7FhSqqSOK03yCS9r43d1Hxs/BGefwkCNPV/zUWGT/BTIe9HkbPnz80/tkD1PvqHOHhsjENeeNtMmDK07rBv5V396ughPy1TK",
                "public-key",
                Some(0),
                Some("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzsQMBGueMw2v1oy1jMSBDvqZJZ3t\nbp8ENrRaK7QS3+sd77IXGM0MTGF4S9I5ERNp4+9ET5WYZb3tNtOFcQ1nyg==\n-----END PUBLIC KEY-----\n".into())
            )
        ];

        let config_challenge = ConfigChallenge {
            rp_id: "mg-dev4.maple.maceroc.com".into(),
            hostname: "https://mg-dev4.maple.maceroc.com".into(),
            challenge: "AhLcH6qPs4lx5wqU1zWvoGclhf38iGYOG05gQs1Mz+p932tUk55Xa+TNeFpFLdmen1KT1EMKMn1bvL4Zmp8bKqhYlqHag7BZwHlgFe7tYFxQ00yfnLowLvIr7k+b36GMEeLukuP3JRANY2AVfZsz/e1BjFEoFk7uxjlZzIy7ac0".into(),
        };

        let pks: PublicKeyCredential = serde_json::from_str(r#"
            {
                "id": "WVjN2yomAi8r5aUfz9nE+SMtBMLnFBFZ7FhSqqSOK03yCS9r43d1Hxs/BGefwkCNPV/zUWGT/BTIe9HkbPnz80/tkD1PvqHOHhsjENeeNtMmDK07rBv5V396ughPy1TK",
                "rawId": "WVjN2yomAi8r5aUfz9nE+SMtBMLnFBFZ7FhSqqSOK03yCS9r43d1Hxs/BGefwkCNPV/zUWGT/BTIe9HkbPnz80/tkD1PvqHOHhsjENeeNtMmDK07rBv5V396ughPy1TK",
                "response": {
                    "authenticatorData": "XlKhqDgMWprKE3rlMr02qmlCJFm/jp1XZO+iT4bTTDYBAAI/LA",
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQWhMY0g2cVBzNGx4NXdxVTF6V3ZvR2NsaGYzOGlHWU9HMDVnUXMxTXotcDkzMnRVazU1WGEtVE5lRnBGTGRtZW4xS1QxRU1LTW4xYnZMNFptcDhiS3FoWWxxSGFnN0Jad0hsZ0ZlN3RZRnhRMDB5Zm5Mb3dMdklyN2stYjM2R01FZUx1a3VQM0pSQU5ZMkFWZlpzel9lMUJqRkVvRms3dXhqbFp6SXk3YWMwIiwib3JpZ2luIjoiaHR0cHM6Ly9tZy1kZXY0Lm1hcGxlLm1hY2Vyb2MuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
                    "signature": "MEUCIQCsr+mDJa5AcorLvwBJB+BIpJH12oOx0K5z70L5uNLBNQIgc9r92MDZ5zpeNia4h6tifSjZI7+P557yj02TK22jdyw",
                    "userHandle": null
                },
                "type": "public-key"
            }
        "#).expect("pks");
        debug!("PublicKeyCredential : {:?}", pks);

        let valide = authenticate_complete(creds, config_challenge, pks).expect("auth");
        assert_eq!(valide, true);
    }

}
