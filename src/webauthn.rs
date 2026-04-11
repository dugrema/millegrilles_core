use log::{debug, info};
use millegrilles_common_rust::bson::{doc, DateTime as DateTimeBson};
use millegrilles_common_rust::reqwest::Url;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::uuid;
use std::convert::TryInto;
use webauthn_rs::prelude::{AuthenticationResult, Base64UrlSafeData, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::error::Error as CoreError;
use crate::maitredescomptes_structs::{DocChallenge, TransactionAjouterCle};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialWebauthn {
    #[serde(rename="userId")]
    pub user_id: String,
    pub hostname: String,
    pub passkey: Passkey,
    #[serde(rename="_mg-creation", skip_serializing_if = "Option::is_none")]
    pub date_creation: Option<DateTimeBson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derniere_utilisation: Option<DateTimeBson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_cles: Option<bool>,
}

fn build_webauthn<H,S>(hostname: H, idmg: S) -> Result<Webauthn, CoreError> where H: AsRef<str>, S: AsRef<str> {
    let idmg = idmg.as_ref();
    let rp_id = hostname.as_ref();
    let rp_origin = Url::parse(format!("https://{}/", rp_id).as_str())?;
    debug!("generer_challenge_registration builder webauthn rp_origin parsed: {}", rp_origin);
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?
        .rp_name(idmg);

    let webauthn = builder.build()?;
    Ok(webauthn)
}

/// Genere un nouveau challenge webauthn
pub fn generer_challenge_registration<I,T,U,V,W,X>(
    rp_origin: T, user_name: U, user_uuid: V, idmg: I, existing_credentials: Option<X>
)
    -> Result<(CreationChallengeResponse, PasskeyRegistration), CoreError>
    where I: AsRef<str>, T: AsRef<str>, U: AsRef<str>, V: AsRef<str>, W: AsRef<str>, X: AsRef<Vec<W>>
{
    let rp_origin_str = rp_origin.as_ref();
    let idmg = idmg.as_ref();
    debug!("generer_challenge_registration builder webauthn avec rp_origin: {}", rp_origin_str);
    let rp_origin = Url::parse(rp_origin_str)?;
    let rp_id = match rp_origin.host_str() {
        Some(inner) => inner,
        None => Err(format!("webauthn generer_challenge_registration Format url rp invalide : {}", rp_origin_str))?
    };
    debug!("generer_challenge_registration builder webauthn rp_origin parsed: {}", rp_origin);
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?
        .rp_name(idmg);
    let webauthn = builder.build()?;

    debug!("generer_challenge_registration Challenge genere : {:?}", webauthn);

    let user_uuid = uuid::Uuid::parse_str(user_uuid.as_ref())?;
    let user_name = user_name.as_ref();

    // Convertir existing credentials (si applicable)
    let credentials = match existing_credentials {
        Some(inner) => {
            let creds_str: Vec<&str> = inner.as_ref().into_iter().map(|c| (*c).as_ref()).collect();
            let mut creds = Vec::new();
            for c in creds_str.into_iter() {
                let cred_uuid = match CredentialID::try_from(c) {
                    Ok(inner) => inner,
                    Err(e) => {
                        info!("Erreur parsing credential existing (SKIP) : {:?}", e);
                        continue;
                    }
                };
                creds.push(cred_uuid);
            }
            Some(creds)
        },
        None => None
    };

    let (challenge, passkey_registration) =
        webauthn.start_passkey_registration(
            user_uuid,
            user_name, user_name, credentials)?;

    debug!("challenge : {:?}", challenge);
    debug!("registration : {:?}", passkey_registration);

    // let challenge_json = serde_json::to_string(&challenge).expect("challenge_json");
    // debug!("challenge JSON pour le navigateur :\n{}", challenge_json);

    // Serialiser passkey registration
    // let passkey_json = serde_json::to_string(&passkey_registration).expect("passkey_json");
    // debug!("registration JSON :\n{}", passkey_json);

    Ok((challenge, passkey_registration))
}

pub fn verifier_challenge_registration<S>(idmg: S, doc_registration: &DocChallenge, transaction_ajouter_cle: &TransactionAjouterCle)
    -> Result<Passkey, CoreError>
    where S: AsRef<str>
{
    let public_key_credentials: RegisterPublicKeyCredential = transaction_ajouter_cle.reponse_client.clone().try_into()?;
    let registration = match doc_registration.webauthn_registration.as_ref() {
        Some(inner) => &inner.resistration_state,
        None => Err(format!("webauthn.verifier_challenge_registration Mauvais type de challenge (webauthn_registration:None"))?
    };

    let idmg = idmg.as_ref();
    let rp_id = doc_registration.hostname.as_str();
    let rp_origin = Url::parse(format!("https://{}/", rp_id).as_str())?;
    debug!("generer_challenge_registration builder webauthn rp_origin parsed: {}", rp_origin);
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?
        .rp_name(idmg);
    let webauthn = builder.build()?;

    let passkey_credential = webauthn.finish_passkey_registration(&public_key_credentials, registration)?;

    debug!("Resultat verification registration : {:?}", passkey_credential);
    Ok(passkey_credential)
}

pub fn generer_challenge_authentification<H,S>(hostname: H, idmg: S, creds: Vec<CredentialWebauthn>)
    -> Result<(RequestChallengeResponse, PasskeyAuthentication), CoreError>
    where H: AsRef<str>, S: AsRef<str>
{
    let idmg = idmg.as_ref();
    let hostname = hostname.as_ref();
    let webauthn = build_webauthn(hostname, idmg)?;

    let passkeys: Vec<Passkey> = creds.into_iter().map(|p| p.passkey).collect();

    let resultat = webauthn.start_passkey_authentication(&passkeys[..])?;
    Ok(resultat)
}

pub fn verifier_challenge_authentification<H,S>(hostname: H, idmg: S, reg: PublicKeyCredential, state: PasskeyAuthentication)
    -> Result<AuthenticationResult, CoreError>
    where H: AsRef<str>, S: AsRef<str>
{
    let idmg = idmg.as_ref();
    let hostname = hostname.as_ref();
    let webauthn = build_webauthn(hostname, idmg)?;
    Ok(webauthn.finish_passkey_authentication(&reg, &state)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientAssertionResponse {
    pub id64: Base64UrlSafeData,
    pub response: ClientAssertResponseContent
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientAssertResponseContent {
    #[serde(rename="authenticatorData")]
    pub authenticator_data: Base64UrlSafeData,
    #[serde(rename="clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
    #[serde(rename="signature")]
    pub signature: Base64UrlSafeData,
    #[serde(rename="userHandle")]
    pub user_handle: Option<String>,
}

impl TryInto<PublicKeyCredential> for ClientAssertionResponse {
    type Error = millegrilles_common_rust::error::Error;

    fn try_into(self) -> Result<PublicKeyCredential, Self::Error> {
        // let id_b64 = multibase_to_b64(self.id64)?;
        let id_b64 = &self.id64;
        let response = &self.response;

        // let val = json!({
        //     "id": id_b64,
        //     "rawId": id_b64,
        //     "response": {
        //         "authenticatorData": multibase_to_b64(&response.authenticator_data)?,
        //         "clientDataJSON": multibase_to_b64(&response.client_data_json)?,
        //         "signature": multibase_to_b64(&response.signature)?,
        //         "userHandle": &response.user_handle
        //     },
        //     "type": "public-key"
        // });

        let val = json!({
            "id": id_b64,
            "rawId": id_b64,
            "response": {
                "authenticatorData": &response.authenticator_data,
                "clientDataJSON": response.client_data_json,
                "signature": response.signature,
                "userHandle": &response.user_handle
            },
            "type": "public-key"
        });

        Ok(serde_json::from_value(val)?)
    }
}

#[cfg(test)]
mod webauthn_test {
    use crate::test_setup::setup;
    use millegrilles_common_rust::bson::Uuid;
    use millegrilles_common_rust::multibase::Base;
    use millegrilles_common_rust::reqwest::Url;

    use super::*;
    use millegrilles_common_rust::serde_json::Value;
    use webauthn_rs::prelude::PasskeyRegistration;
    use webauthn_rs::WebauthnBuilder;

    const COMMANDE_SIGNER_CERTIFICAT: &str = r#"
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
    fn generer_challenge_registration_1() {
        // let rp_id = "millegrilles.com";
        let rp_origin = Url::parse("https://www.millegrilles.com")
            .expect("Invalid URL");
        let idmg = "zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf";
        let user_name = "proprietaire";
        let user_id_uuid = uuid::Uuid::new_v4().to_string();
        let (challenge, passkey_registration) = generer_challenge_registration(
            rp_origin, user_name, user_id_uuid, idmg, None::<&Vec<&str>>
        )
            .expect("start_passkey_registration");

        debug!("challenge : {:?}", challenge);
        debug!("registration : {:?}", passkey_registration);

        let challenge_json = serde_json::to_string(&challenge).expect("challenge_json");
        debug!("challenge JSON pour le navigateur :\n{}", challenge_json);

        // Serialiser passkey registration
        let passkey_json = serde_json::to_string(&passkey_registration).expect("passkey_json");
        debug!("registration JSON :\n{}", passkey_json);

        // De-serialiser passkey registration (simuler chargement DB)
        let passkey_deserialized: PasskeyRegistration = serde_json::from_str(passkey_json.as_str()).expect("passkey deserialized");
        debug!("registration de-serialized : {:?}", passkey_deserialized);
    }

}
