use std::error::Error;
use std::fmt::{Debug, Formatter};

use log::{debug, error, info, warn};
use millegrilles_common_rust::chiffrage::random_vec;
use millegrilles_common_rust::multibase;
use millegrilles_common_rust::rand;
use millegrilles_common_rust::rand::Rng;
use millegrilles_common_rust::serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Challenge {
    challenge: String,
    timeout: usize,
    rpId: String,
    userVerification: String,  // 'preferred',
    allowCredentials: Vec<AllowCredential>,
    hostname: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowCredential {
    id: String,
    #[serde(rename = "type")]
    cred_type: String,
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

}
