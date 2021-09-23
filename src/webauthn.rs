use std::error::Error;
use std::fmt::{Debug, Formatter};

use log::{debug, error, info, warn};
use millegrilles_common_rust::chiffrage::random_vec;
use millegrilles_common_rust::multibase;
use millegrilles_common_rust::rand;
use millegrilles_common_rust::rand::Rng;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::{json, Value, Map};
use millegrilles_common_rust::bson::{doc, Document, Array, Bson};
use webauthn_rs::{Webauthn, WebauthnConfig, AuthenticationState};
use webauthn_rs::proto::{PublicKeyCredential, AuthenticatorAssertionResponseRaw};
use webauthn_rs::base64_data::Base64UrlSafeData;
use millegrilles_common_rust::openssl;
use std::convert::TryInto;
use millegrilles_common_rust::openssl::bn::{BigNumRef, BigNum};
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::formatteur_messages::preparer_btree_recursif;
use millegrilles_common_rust::hachages::verifier_hachage_serializable;

pub fn generer_challenge_auth(url_site: &str, credentials: Vec<Credential>) -> Result<Challenge, Box<dyn Error>> {

    let rnd_bytes = random_vec(128);
    debug!("Random ... {:?}", rnd_bytes);
    let challenge = multibase::encode(multibase::Base::Base64, &rnd_bytes);

    let creds: Vec<AllowCredential> = credentials.into_iter().map(|c| {
        AllowCredential {id: c.cred_id, cred_type: c.key_type}
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
    #[serde(rename="credId")]
    cred_id: String,
    counter: Option<usize>,
    #[serde(rename="publicKeyPem")]
    public_key_pem: Option<String>,
    #[serde(rename = "type")]
    key_type: String,
}
impl Credential {
    pub fn new<S>(cred_id: S, key_type: S, counter: Option<usize>, public_key_pem: Option<String>) -> Self
        where S: Into<String>
    {
        Credential {
            cred_id: cred_id.into(),
            counter,
            public_key_pem: public_key_pem,
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

        let cle = match self.public_key_pem {
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
            cred_id: multibase::decode(self.cred_id)?.1,
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
    pub challenge_b64: String,
    pub challenge_bytes: Vec<u8>,
}
impl ConfigChallenge {
    pub fn try_new<S>(hostname: S, challenge: S) -> Result<Self, Box<dyn Error>>
        where S: Into<String>
    {
        let hostname = hostname.into();
        let rp_id = hostname.replace("https://", "");
        let challenge_string = challenge.into();
        let challenge_bytes: Vec<u8> = multibase::decode(challenge_string.as_str())?.1;
        Ok(ConfigChallenge {
            rp_id,
            hostname,
            challenge_b64: multibase_to_b64(challenge_string.as_str())?,
            challenge_bytes,
        })
    }

    fn get_commande(&self) -> Result<CommandeWebauthn, Box<dyn Error>> {
        let byte_commande = self.challenge_bytes[0];
        match byte_commande {
            0x2 => {
                let buffer = &self.challenge_bytes[1..65];
                Ok(CommandeWebauthn::DemandeCertificat(buffer.to_vec()))
            },
            _ => Err(format!("Commande inconnue, byte {:?}", byte_commande))?
        }
    }
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

#[derive(Clone, Debug)]
enum CommandeWebauthn {
    DemandeCertificat(Vec<u8>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowCredential {
    id: String,
    #[serde(rename = "type")]
    cred_type: String,
}

fn verifier_commande<S>(commande: &CommandeWebauthn, message: &S) -> Result<bool, Box<dyn Error>>
    where S: Serialize
{
    let val = serde_json::to_value(message)?;
    let contenu: Map<String, Value> = match val.as_object() {
        Some(c) => preparer_btree_recursif(c.to_owned())?,
        None => Err("Serializable n'est pas un document")?
    };

    match commande {
        CommandeWebauthn::DemandeCertificat(h) => {
            match contenu.get("demandeCertificat") {
                Some(d) => Ok(verifier_hachage_serializable(h.as_slice(), Code::Sha2_512, d)?),
                None => Err("Element 'demandeCertificat' absent de la commande")?
            }
        }
    }
}

/// Verifier signature avec webauthn
pub fn authenticate_complete(credentials: Vec<webauthn_rs::proto::Credential>, challenge: ConfigChallenge, rsp: PublicKeyCredential)  // , challenge: &Challenge, response: AuthenticatorAssertionResponseRaw, credentials: Vec<Credential>) -> Result<bool, Box<dyn Error>> {
    -> Result<u32, Box<dyn Error>>
{
    let val_auth_state = json!({
        "credentials": credentials,
        "policy": "preferred",
        "challenge": challenge.challenge_b64.clone(),
    });

    let state: AuthenticationState = serde_json::from_value(val_auth_state)?;
    let mut webauthn = Webauthn::new(challenge);

    match webauthn.authenticate_credential(rsp, state)? {
        Some((_, counter)) => {
            debug!("Credential OK, info : {:?}", counter);
            Ok(counter)
        },
        None => Ok(0),
    }

}

fn convertir_creds_compte(doc_compte: Document) -> Result<Vec<webauthn_rs::proto::Credential>, Box<dyn Error>> {
    let element_webauthn = doc_compte.get_array("webauthn")?;

    let mut creds = Vec::new();
    for c in element_webauthn {
        let cred: Credential = serde_json::from_value(serde_json::to_value(c)?)?;
        let cw: webauthn_rs::proto::Credential = cred.try_into()?;
        creds.push(cw);
    }

    Ok(creds)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientAssertionResponse {
    id64: String,
    response: ClientAssertResponseContent
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientAssertResponseContent {
    #[serde(rename="authenticatorData")]
    authenticator_data: String,
    #[serde(rename="clientDataJSON")]
    client_data_json: String,
    #[serde(rename="signature")]
    signature: String,
    #[serde(rename="userHandle")]
    user_handle: Option<String>,
}

impl TryInto<PublicKeyCredential> for ClientAssertionResponse {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<PublicKeyCredential, Self::Error> {
        let id_b64 = multibase_to_b64(self.id64)?;
        let response = &self.response;

        let val = json!({
            "id": id_b64,
            "rawId": id_b64,
            "response": {
                "authenticatorData": multibase_to_b64(&response.authenticator_data)?,
                "clientDataJSON": multibase_to_b64(&response.client_data_json)?,
                "signature": multibase_to_b64(&response.signature)?,
                "userHandle": &response.user_handle
            },
            "type": "public-key"
        });

        Ok(serde_json::from_value(val)?)
    }
}

fn multibase_to_b64<S>(val: S) -> Result<String, Box<dyn Error>>
    where S: AsRef<str>
{
    let val_str = val.as_ref();
    let (format, contenu_bytes) = multibase::decode(val_str)?;
    match format {
        multibase::Base::Base64 => Ok(String::from(&val_str[1..])),
        _ => {
            let format_string = multibase::encode(multibase::Base::Base64, contenu_bytes);
            Ok(format_string[1..].to_string())
        }
    }
}

#[cfg(test)]
mod webauthn_test {
    use crate::test_setup::setup;

    use super::*;
    use millegrilles_common_rust::serde_json::Value;

    const COMMANDE_CERTIFICAT: &str = r#"
        {
            "userId": "zQmZKg39RmHf4qo2pxjYpTk5ARzbyFeGX8va8XDpGBc6sah",
            "demandeCertificat": {
                "nomUsager": "proprietaire",
                "csr": "-----BEGIN CERTIFICATE REQUEST-----\r\nMIICXDCCAUQCAQAwFzEVMBMGA1UEAxMMcHJvcHJpZXRhaXJlMIIBIjANBgkqhkiG\r\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo/wXu4qbu0ineDtdwtXsz5pjfcCnsU3ZT6/8\r\ngX4Ofsv5M7fxQUpzNYuqBOMDbuNfdgc/jX37PxDMCpJCtx505PZCQzSGwyPbi4Wf\r\njtI0IgzyFECgxtXO9wmIVtMIHC3ud36t42R7BVdgTR18tpPQFToEaQc/wTDn9R9d\r\nPpAsuDju4E+ZCimJDrALMiTVlxN4KWsPCdP2Wqx1c/nmHHFYClSLA7toTzjsza9W\r\nSCbBgPopUAMOsltMiI4skpLip8qMrvEqGFsgSVM1Kq+kIHbtq2Aii0Lm5ncuq8nk\r\nfI4rcfGqFzx0RTg0/iB4SNdh4GORnAzXsJkqxJl0+bZRlV4iyQIDAQABoAAwDQYJ\r\nKoZIhvcNAQENBQADggEBAA+FKjiuM+prsU1b3nKwJvGJ2JPTy9Thf7cLM+v7I01I\r\nh/brZkslacAr+m6WA+VGPCsKIv9uyw3aealMGyTw9H704RCsYHQjCWVFRONfd9c7\r\nAtWuMzxo5RMhG4l1+BGVS5zodL1bTmJRbpY+IyxcbSd5piLDUwoF9Se/cS80YtH8\r\nqjBrxKkOyQYmHhmzjH2ql8jcdvpWFVjBDV/lQ/vtQSPveRhjv4Pi+21mbnqTrHWK\r\nYtZ0ztXUhLAvaYvaWCsPoZeoaWptvYwoGOXpXO24njO4qKgqLqHe092HAAaBi8dL\r\nD+u56LdB7GghoCqRPFcsPcGrtYqTncDK9wC6SOYFy3U=\r\n-----END CERTIFICATE REQUEST-----\r\n",
                "date": 1632329666
            },
            "challenge": "mAhLcH6qPs4lx5wqU1zWvoGclhf38iGYOG05gQs1Mz+p932tUk55Xa+TNeFpFLdmen1KT1EMKMn1bvL4Zmp8bKqhYlqHag7BZwHlgFe7tYFxQ00yfnLowLvIr7k+b36GMEeLukuP3JRANY2AVfZsz/e1BjFEoFk7uxjlZzIy7ac0",
            "origin": "https://mg-dev4.maple.maceroc.com",
            "clientAssertionResponse": {
                "id64": "mWVjN2yomAi8r5aUfz9nE+SMtBMLnFBFZ7FhSqqSOK03yCS9r43d1Hxs/BGefwkCNPV/zUWGT/BTIe9HkbPnz80/tkD1PvqHOHhsjENeeNtMmDK07rBv5V396ughPy1TK",
                "response": {
                    "authenticatorData": "mXlKhqDgMWprKE3rlMr02qmlCJFm/jp1XZO+iT4bTTDYBAAI/LA",
                    "clientDataJSON": "meyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQWhMY0g2cVBzNGx4NXdxVTF6V3ZvR2NsaGYzOGlHWU9HMDVnUXMxTXotcDkzMnRVazU1WGEtVE5lRnBGTGRtZW4xS1QxRU1LTW4xYnZMNFptcDhiS3FoWWxxSGFnN0Jad0hsZ0ZlN3RZRnhRMDB5Zm5Mb3dMdklyN2stYjM2R01FZUx1a3VQM0pSQU5ZMkFWZlpzel9lMUJqRkVvRms3dXhqbFp6SXk3YWMwIiwib3JpZ2luIjoiaHR0cHM6Ly9tZy1kZXY0Lm1hcGxlLm1hY2Vyb2MuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
                    "signature": "mMEUCIQCsr+mDJa5AcorLvwBJB+BIpJH12oOx0K5z70L5uNLBNQIgc9r92MDZ5zpeNia4h6tifSjZI7+P557yj02TK22jdyw",
                    "userHandle": null
                }
            },
            "en-tete": {
                "domaine": "MaitreDesComptes.signerCompteUsager",
                "idmg": "z2W2ECnP9eauNXD628aaiURj6tJfSYiygTaffC1bTbCNHCtomhoR7s",
                "uuid_transaction": "957d083d-1145-4be4-b727-d1b3534c8f89",
                "estampille": 1632329669,
                "fingerprint_certificat": "zQmYjXxw7HrnKhpWaXxieSYdKqegv2QSvajafSLA6JNwhC3",
                "hachage_contenu": "mEiDGfDe7wxM2LuLhQ7GdNllYGaOlwvX7U1q9zrFt+njOIw",
                "version": 1
            },
            "_certificat": ["-----BEGIN CERTIFICATE-----\nMIIEkzCCA3ugAwIBAgIUH49DwO0kC5aLuTt6zgA0kUHmqRswDQYJKoZIhvcNAQEL\nBQAwgYgxLTArBgNVBAMTJDM2NjUyMjQ1LTFjMWEtNDY4Ni04Njg2LTIxZGNlYmJk\nZjQzZjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5\nZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMB4X\nDTIxMDkyMDE3MjM0NloXDTIxMTAyMDE3MjU0NlowaTE/MD0GA1UECgw2ejJXMkVD\nblA5ZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdz\nMRQwEgYDVQQLDAt3ZWJfcHJvdGVnZTEQMA4GA1UEAwwHbWctZGV2NDCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBALS18pj8pYieCoAs4wHFBcLuRajhnOBH\nCJHtrGKJ9G0RrrbNeIiwYMKH5RwRK7wD7kkMybGVih551PLEhQG6ikjgx98JKR4h\naLwD5SUnZ21lOiMQEwoOQ5+Sa7OxQrI3KAoo1UadB9kt7eSIJ1Xy1ngP20ZJEI/U\nI6YmWcBtZJuIE9ACHnDS7YcDd3YTxfCrN0wkTGXPZ93iR0fSyV6cnRWmPoTGcIOF\nna8TkxB8tRgSyvjRd+s6g3mFUg8klvApyI0ohWMTsLHgeJ60ANPe5vBiRsbn+y4Z\n19yi+GYU5rnZQLYbV4q61f75jahQyGk1+5g2IkbU28J1dG1n7FWggBcCAwEAAaOC\nAREwggENMB0GA1UdDgQWBBQ0rxIH1phnxKxm58AhaGeEieilPDAfBgNVHSMEGDAW\ngBR4zR8KzqiKgrDCyF8VhieFbzFCiDAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIE\n8DAiBgQqAwQABBozLnByb3RlZ2UsMi5wcml2ZSwxLnB1YmxpYzAkBgQqAwQBBBx3\nZWJfcHJvdGVnZSxNYWl0cmVEZXNDb21wdGVzMGYGA1UdEQRfMF2CC3dlYl9wcm90\nZWdlggdtZy1kZXY0gglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAGC\nB21nLWRldjSCGW1nLWRldjQubWFwbGUubWFjZXJvYy5jb20wDQYJKoZIhvcNAQEL\nBQADggEBAFb4tiatPmk7LmT/3LUPIVLrWcHqD177SC/vNtHr++Hlh+W/6k0CAxB8\nUBTP10NUpnlHtzzmVsD/VOLN8m3zYKY5OF0jeHLMg3qUPOFsFXKgQXunHYc9lX7z\ne4OEy17ejYmvOQiQjdYEWXCHyAANIOTWid0CljBra5V+E/3Z5QqNjCETxy5ZCOmB\nDGVtxOJbAYdzqrMUIwpaGDDoFZYGJZ/eAMKtg5a3QcTDA1J7fUUIX5dhprcl59DM\nj/Cx6/YZzD14zJ5deoWDDbHU+T3LCR5lMqln+95ODZXA0Q7pXX7NsoZCeOEbCqwc\n0bCwN/7Z84U8V9jBG7VG23kScjJSfJg=\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nMIID+TCCAmGgAwIBAgIKBgETY1QkIpJwADANBgkqhkiG9w0BAQ0FADAWMRQwEgYD\nVQQDEwtNaWxsZUdyaWxsZTAeFw0yMTA5MjAxNzI1MDZaFw0yNDA5MjIxNzI1MDZa\nMIGIMS0wKwYDVQQDEyQzNjY1MjI0NS0xYzFhLTQ2ODYtODY4Ni0yMWRjZWJiZGY0\nM2YxFjAUBgNVBAsTDWludGVybWVkaWFpcmUxPzA9BgNVBAoTNnoyVzJFQ25QOWVh\ndU5YRDYyOGFhaVVSajZ0SmZTWWl5Z1RhZmZDMWJUYkNOSEN0b21ob1I3czCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALwed/KGvkzLGcyZnAxwKLIFUydZ\n/kX120yAzRXxM3U20AG0omcbg7aDKyWaGHarYuYywMfM1FylTVQvilbKFeSAO1UJ\nMOatSFLJs7UEVyMMFZrask3/SBsQUw9mIvRixA9iU5wSwU9963VZvIauWvTSkL4u\n0yJddi9IZJbtul2teUI4Vb0ib0VS0KdhP+7iUyErvwbW6ZyvaKYO0Hjd7cnxkEbZ\n9PJgJS6pSNj9mEau4qJs9/s8ygWshnihIIx4snmkrxPiW9EFbHrqPdWtv+UC5iUr\nMPSAJMqQu/bDsnngS+h0i0aFGm8GytsnrLNipG9JdqFBszqYyS3LcOTd9JECAwEA\nAaNWMFQwEgYDVR0TAQH/BAgwBgEB/wIBBDAdBgNVHQ4EFgQUeM0fCs6oioKwwshf\nFYYnhW8xQogwHwYDVR0jBBgwFoAUGrFAg9Cfm8AdmJPKJSRr69Oe5O4wDQYJKoZI\nhvcNAQENBQADggGBAFCIGTE2aKbPG38Eji1tlKyVrdW+PH0BXupZTAsngbJ8SISC\nu+vAe8tA5zAAuMIq6oKdPS7hAVGIY6HfUOJovGaeX80jHGaKL+gjYYUWxXAG3oZj\ndp4PFFW1qt+v7OYz7YFtf89rYupYHoivN33WNja2btKkaMj1gvhG0vzad27ppt6Z\nJEImE/cxFAmLOdl9I/hXq21rrdN++M46saklAMauRDLHGzWwCKZyf8AJH40OVPmx\nQT/4W5yEsfALIIDfB/I1TcAIzNSPS6U5EiV2ajKbO+HK2aDmiUUSXz/6jUQcnwHA\nfnN2lB6mohwK0eBzjAUf6DUYb7jsdR4RYfNOUXghCVX8CllQncomIT8WOj10zL1H\n21hjCHCFF/TqsHmOJRwQqGt9zIh6cbj6BJCP/AunnHy/OIxOl/R8qPiIbLoGbrCs\nwQkNJeGqx4UnhFZ3qMgMhiQpc6vUVlQcHu7XJHhdPTH9/QFrmtzTRs4vxK9zKiY2\nZ0Dd2n3wbZrdoMRNDA==\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nMIIEBjCCAm6gAwIBAgIKCSg3VilRiEQQADANBgkqhkiG9w0BAQ0FADAWMRQwEgYD\nVQQDEwtNaWxsZUdyaWxsZTAeFw0yMTAyMjgyMzM4NDRaFw00MTAyMjgyMzM4NDRa\nMBYxFDASBgNVBAMTC01pbGxlR3JpbGxlMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A\nMIIBigKCAYEAo7LsB6GKr+aKqzmF7jxa3GDzu7PPeOBtUL/5Q6OlZMfMKLdqTGd6\npg12GT2esBh2KWUTt6MwOz3NDgA2Yk+WU9huqmtsz2n7vqIgookhhLaQt/OoPeau\nbJyhm3BSd+Fpf56H1Ya/qZl1Bow/h8r8SjImm8ol1sG9j+bTnaA5xWF4X2Jj7k2q\nTYrJJYLTU+tEnL9jH2quaHyiuEnSOfMmSLeiaC+nyY/MuX2Qdr3LkTTTrF+uOji+\njTBFdZKxK1qGKSJ517jz9/gkDCe7tDnlTOS4qxQlIGPqVP6hcBPaeXjiQ6h1KTl2\n1B5THx0yh0G9ixg90XUuDTHXgIw3vX5876ShxNXZ2ahdxbg38m4QlFMag1RfHh9Z\nXPEPUOjEnAEUp10JgQcd70gXDet27BF5l9rXygxsNz6dqlP7oo2yI8XvdtMcFiYM\neFM1FF+KadV49cXTePqKMpir0mBtGLwtaPNAUZNGCcZCuxF/mt9XOYoBTUEIv1cq\nLsLVaM53fUFFAgMBAAGjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQUwHQYDVR0OBBYE\nFBqxQIPQn5vAHZiTyiUka+vTnuTuMB8GA1UdIwQYMBaAFBqxQIPQn5vAHZiTyiUk\na+vTnuTuMA0GCSqGSIb3DQEBDQUAA4IBgQBLjk2y9nDW2MlP+AYSZlArX9XewMCh\n2xAjU63+nBG/1nFe5u3YdciLsJyiFBlOY2O+ZGliBcQ6EhFx7SoPRDB7v7YKv8+O\nEYZOSyule+SlSk2Dv89eYdmgqess/3YyuJN8XDyEbIbP7UD2KtklxhwkpiWcVSC3\nNK3ALaXwB/5dniuhxhgcoDhztvR7JiCD3fi1Gwi8zUR4BiZOgDQbn2O3NlgFNjDk\n6eRNicWDJ19XjNRxuCKn4/8GlEdLPwlf4CoqKb+O31Bll4aWkWRb9U5lpk/Ia0Kr\no/PtNHZNEcxOrpmmiCIN1n5+Fpk5dIEKqSepWWLGpe1Omg2KPSBjFPGvciluoqfG\nerI92ipS7xJLW1dkpwRGM2H42yD/RLLocPh5ZuW369snbw+axbcvHdST4LGU0Cda\nyGZTCkka1NZqVTise4N+AV//BQjPsxdXyabarqD9ycrd5EFGOQQAFadIdQy+qZvJ\nqn8fGEjvtcCyXhnbCjCO8gykHrRTXO2icrQ=\n-----END CERTIFICATE-----"],
            "_signature": "mAWJW3FKykLQMbYrmpW8X1i4BaPqiMPvZg6kp7ufe75XV+GvrPYcNPY5ZOiVsc4I8a68m3QsB0NEO5c+tBCKwBIVuUKWZeSDDRH4qUGaNNwnJ51HJSSUOiikfJoBGlzBMFGTJ3TBeVb+JfOg6gx2/kuvfS26Xyn4z2vqD6VVUqjKFQjP5GUA8hn40Z4X2FVrnAIcZ4J4yxHnIc4a00iTolEUqokklcLnUR0v208Rw//g06xjLlbOvVb8fZEHLex5AZ2hWjZa1bNMWrgNJREBdbXpjdchhpuNj64y1/DjFtD5N/jLGbP/ZAcICHmEzwPehB5PU86HC4RmnUM2XBYFSsro"
        }
    "#;

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
    fn charger_response() {
        setup("charger_response");

        let response: ClientAssertionResponse = serde_json::from_str(r#"
            {
                "id64": "mWVjN2yomAi8r5aUfz9nE+SMtBMLnFBFZ7FhSqqSOK03yCS9r43d1Hxs/BGefwkCNPV/zUWGT/BTIe9HkbPnz80/tkD1PvqHOHhsjENeeNtMmDK07rBv5V396ughPy1TK",
                "response": {
                    "authenticatorData": "mXlKhqDgMWprKE3rlMr02qmlCJFm/jp1XZO+iT4bTTDYBAAI/LA",
                    "clientDataJSON": "meyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQWhMY0g2cVBzNGx4NXdxVTF6V3ZvR2NsaGYzOGlHWU9HMDVnUXMxTXotcDkzMnRVazU1WGEtVE5lRnBGTGRtZW4xS1QxRU1LTW4xYnZMNFptcDhiS3FoWWxxSGFnN0Jad0hsZ0ZlN3RZRnhRMDB5Zm5Mb3dMdklyN2stYjM2R01FZUx1a3VQM0pSQU5ZMkFWZlpzel9lMUJqRkVvRms3dXhqbFp6SXk3YWMwIiwib3JpZ2luIjoiaHR0cHM6Ly9tZy1kZXY0Lm1hcGxlLm1hY2Vyb2MuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
                    "signature": "mMEUCIQCsr+mDJa5AcorLvwBJB+BIpJH12oOx0K5z70L5uNLBNQIgc9r92MDZ5zpeNia4h6tifSjZI7+P557yj02TK22jdyw",
                    "userHandle": null
                }
            }
        "#).expect("serde response");
        debug!("Response mapped : {:?}", response);

        // Convertir vers le format webauthn interne (PublicKeyCredential)
        let rks: PublicKeyCredential = response.try_into().expect("into pubkey");
        debug!("PublicKeyCredential converti : {:?}", rks);

    }

    #[test]
    fn extraire_commande() {
        setup("extraire_commande");

        let challenge = "mAhLcH6qPs4lx5wqU1zWvoGclhf38iGYOG05gQs1Mz+p932tUk55Xa+TNeFpFLdmen1KT1EMKMn1bvL4Zmp8bKqhYlqHag7BZwHlgFe7tYFxQ00yfnLowLvIr7k+b36GMEeLukuP3JRANY2AVfZsz/e1BjFEoFk7uxjlZzIy7ac0";

        let config_challenge = ConfigChallenge::try_new("localhost", challenge).expect("challenge");

        assert_eq!(config_challenge.challenge_bytes.len(), 128);
        debug!("Challenge bytes : {:?}", config_challenge.challenge_bytes);

        let commande = config_challenge.get_commande().expect("commande");
        let message_demande: Value = serde_json::from_str(COMMANDE_CERTIFICAT).expect("demande");

        let resultat = verifier_commande(&commande, &message_demande).expect("verif");
        assert_eq!(true, resultat);
        debug!("Commande valide");

    }

    #[test]
    fn verifier_commande_test() {
        setup("extraire_commande");

        let challenge = "mAhLcH6qPs4lx5wqU1zWvoGclhf38iGYOG05gQs1Mz+p932tUk55Xa+TNeFpFLdmen1KT1EMKMn1bvL4Zmp8bKqhYlqHag7BZwHlgFe7tYFxQ00yfnLowLvIr7k+b36GMEeLukuP3JRANY2AVfZsz/e1BjFEoFk7uxjlZzIy7ac0";

        let config_challenge = ConfigChallenge::try_new("localhost", challenge).expect("challenge");
        let commande = config_challenge.get_commande().expect("commande");

        debug!("Commande {:?}", commande);
    }

    #[test]
    fn authenticate_complete_1() {
        setup("authenticate_complete_1");

        let url_site = "https://mg-dev4.maple.maceroc.com";
        let creds: Vec<webauthn_rs::proto::Credential> = vec! [
            Credential::new(
                "mWVjN2yomAi8r5aUfz9nE+SMtBMLnFBFZ7FhSqqSOK03yCS9r43d1Hxs/BGefwkCNPV/zUWGT/BTIe9HkbPnz80/tkD1PvqHOHhsjENeeNtMmDK07rBv5V396ughPy1TK",
                "public-key",
                Some(0),
                Some("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzsQMBGueMw2v1oy1jMSBDvqZJZ3t\nbp8ENrRaK7QS3+sd77IXGM0MTGF4S9I5ERNp4+9ET5WYZb3tNtOFcQ1nyg==\n-----END PUBLIC KEY-----\n".into())
            ).try_into().expect("cred")
        ];

        let config_challenge = ConfigChallenge::try_new(
            "https://mg-dev4.maple.maceroc.com",
            "mAhLcH6qPs4lx5wqU1zWvoGclhf38iGYOG05gQs1Mz+p932tUk55Xa+TNeFpFLdmen1KT1EMKMn1bvL4Zmp8bKqhYlqHag7BZwHlgFe7tYFxQ00yfnLowLvIr7k+b36GMEeLukuP3JRANY2AVfZsz/e1BjFEoFk7uxjlZzIy7ac0"
        ).expect("config");

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

        let count = authenticate_complete(creds, config_challenge, pks).expect("auth");
        assert_eq!(count > 0, true);
    }

    #[test]
    fn authenticate_complete_2() {
        setup("authenticate_complete_2");

        let hostname = "https://mg-dev4.maple.maceroc.com";
        let challenge = "mAhLcH6qPs4lx5wqU1zWvoGclhf38iGYOG05gQs1Mz+p932tUk55Xa+TNeFpFLdmen1KT1EMKMn1bvL4Zmp8bKqhYlqHag7BZwHlgFe7tYFxQ00yfnLowLvIr7k+b36GMEeLukuP3JRANY2AVfZsz/e1BjFEoFk7uxjlZzIy7ac0";
        let config_challenge = ConfigChallenge::try_new(hostname, challenge).expect("config");

        let doc_creds = doc! {
            "webauthn": [{
                "credId": "mWVjN2yomAi8r5aUfz9nE+SMtBMLnFBFZ7FhSqqSOK03yCS9r43d1Hxs/BGefwkCNPV/zUWGT/BTIe9HkbPnz80/tkD1PvqHOHhsjENeeNtMmDK07rBv5V396ughPy1TK",
                "type": "public-key",
                "counter": 0,
                "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzsQMBGueMw2v1oy1jMSBDvqZJZ3t\nbp8ENrRaK7QS3+sd77IXGM0MTGF4S9I5ERNp4+9ET5WYZb3tNtOFcQ1nyg==\n-----END PUBLIC KEY-----\n",
            }]
        };
        let vec_creds = convertir_creds_compte(doc_creds).expect("creds");

        let rsp: PublicKeyCredential = serde_json::from_str::<ClientAssertionResponse>(r#"
            {
                "id64": "mWVjN2yomAi8r5aUfz9nE+SMtBMLnFBFZ7FhSqqSOK03yCS9r43d1Hxs/BGefwkCNPV/zUWGT/BTIe9HkbPnz80/tkD1PvqHOHhsjENeeNtMmDK07rBv5V396ughPy1TK",
                "response": {
                    "authenticatorData": "mXlKhqDgMWprKE3rlMr02qmlCJFm/jp1XZO+iT4bTTDYBAAI/LA",
                    "clientDataJSON": "meyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQWhMY0g2cVBzNGx4NXdxVTF6V3ZvR2NsaGYzOGlHWU9HMDVnUXMxTXotcDkzMnRVazU1WGEtVE5lRnBGTGRtZW4xS1QxRU1LTW4xYnZMNFptcDhiS3FoWWxxSGFnN0Jad0hsZ0ZlN3RZRnhRMDB5Zm5Mb3dMdklyN2stYjM2R01FZUx1a3VQM0pSQU5ZMkFWZlpzel9lMUJqRkVvRms3dXhqbFp6SXk3YWMwIiwib3JpZ2luIjoiaHR0cHM6Ly9tZy1kZXY0Lm1hcGxlLm1hY2Vyb2MuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
                    "signature": "mMEUCIQCsr+mDJa5AcorLvwBJB+BIpJH12oOx0K5z70L5uNLBNQIgc9r92MDZ5zpeNia4h6tifSjZI7+P557yj02TK22jdyw",
                    "userHandle": null
                }
            }
        "#).expect("serde response").try_into().expect("rsp");

        debug!("PublicKeyCredential (response client) : {:?}", rsp);

        let valide = authenticate_complete(vec_creds, config_challenge, rsp).expect("auth");
        assert_eq!(valide > 0, true);
    }
}
