use log::{debug, error, info, warn};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{Base64UrlSafeData, CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse};

use millegrilles_common_rust::bson::{Bson, bson, DateTime as DateTimeBson, doc};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, DELEGATION_GLOBALE_PROPRIETAIRE};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_bson_value, convertir_to_bson, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::{base64_url, chrono, openssl, serde_json, uuid};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions};
use millegrilles_common_rust::serde_json::{json, Value};

use crate::maitredescomptes_constants::*;
use crate::error::Error as CoreError;
use crate::maitredescomptes_structs::DocChallenge;
use crate::webauthn::{authenticate_complete, ClientAssertionResponse, CompteCredential, ConfigChallenge, Credential, CredentialWebauthn, generer_challenge_authentification, generer_challenge_registration, multibase_to_safe, valider_commande, verifier_challenge_authentification, verifier_challenge_registration};

pub async fn consommer_requete_maitredescomptes<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("consommer_requete : {:?}", &m.type_message);

    let (action, domaine) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            (r.action.clone(), r.domaine.clone())
        },
        _ => Err("consommer_evenement Mauvais type de message")?
    };

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    let user_id = m.certificat.get_user_id()?;
    match m.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
        true => Ok(()),
        false => match user_id {
            Some(u) => Ok(()),
            None => Err("Commande autorisation invalide (aucun user_id, pas 2.prive, 3.protege ou 4.secure)")
        }
    }?;

    match domaine.as_str() {
        DOMAINE_NOM => {
            match action.as_str() {
                REQUETE_CHARGER_USAGER => {
                    match charger_usager(middleware, m).await {
                        Ok(inner) => Ok(inner),
                        Err(e) => Err(millegrilles_common_rust::error::Error::String(format!("consommer_requete Erreur : {:?}", e)))?
                    }
                },
                REQUETE_LISTE_USAGERS => liste_usagers(middleware, m).await,
                REQUETE_USERID_PAR_NOMUSAGER => get_userid_par_nomusager(middleware, m).await,
                REQUETE_GET_CSR_RECOVERY_PARCODE => get_csr_recovery_parcode(middleware, m).await,
                REQUETE_LISTE_PROPRIETAIRES => get_liste_proprietaires(middleware, m).await,
                REQUETE_COOKIE_USAGER => get_cookie_usager(middleware, m).await,
                REQUETE_PASSKEYS_USAGER => get_passkeys_usager(middleware, m).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
            Ok(None)
        },
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompteUsager {
    #[serde(rename="nomUsager")]
    nom_usager: String,
    #[serde(rename="userId")]
    user_id: String,

    compte_prive: Option<bool>,

    delegation_globale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with="optionepochseconds")]
    delegations_date: Option<DateTime<Utc>>,
    delegations_version: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteUsager {
    /// User_id, utilise de preference.
    #[serde(rename="userId")]
    user_id: Option<String>,

    /// Nom usager, utilise si le user_id est absent.
    #[serde(rename="nomUsager")]
    nom_usager: Option<String>,

    /// Url du serveur qui fait la demande (du point de vue usager).
    /// Requis pour webauthn, agit comme flag pour generer un nouveau challenge d'authentification.
    #[serde(rename="hostUrl")]
    host_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocActivationFingerprintPkUsager {
    #[serde(rename="userId")]
    user_id: String,
    fingerprint_pk: String,
    certificat: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseChargerUsager {
    ok: bool,
    err: Option<String>,
    compte: Option<CompteUsager>,
    activations: Option<HashMap<String, DocActivationFingerprintPkUsager>>,
    generic_challenge: Option<String>,
    registration_challenge: Option<CreationChallengeResponse>,
    authentication_challenge: Option<RequestChallengeResponse>,
    passkey_authentication: Option<PasskeyAuthentication>,
    webauth_credentials_count: Option<usize>,
}

impl From<CompteUsager> for ReponseChargerUsager {
    fn from(value: CompteUsager) -> Self {
        Self {
            ok: true,
            err: None,
            compte: Some(value),
            activations: None,
            generic_challenge: None,
            registration_challenge: None,
            authentication_challenge: None,
            passkey_authentication: None,
            webauth_credentials_count: None,
        }
    }
}

impl ReponseChargerUsager {
    fn erreur<E>(erreur: E) -> Self
    where E: Into<String>
    {
        Self {
            ok: false,
            err: Some(erreur.into()),
            compte: None,
            activations: None,
            generic_challenge: None,
            registration_challenge: None,
            authentication_challenge: None,
            passkey_authentication: None,
            webauth_credentials_count: None,
        }
    }

    fn compte_inconnu<E, F>(nom_usager: Option<E>, user_id: Option<F>) -> Self
    where E: AsRef<str>, F: AsRef<str>
    {
        let nom_usager = match nom_usager.as_ref() {
            Some(inner) => inner.as_ref(),
            None => ""
        };

        let user_id = match user_id.as_ref() {
            Some(inner) => inner.as_ref(),
            None => ""
        };

        Self {
            ok: true,
            err: Some(format!("compte inconnu : nom_usager: {:?}, user_id: {:?}", nom_usager, user_id)),
            compte: None,
            activations: None,
            generic_challenge: None,
            registration_challenge: None,
            authentication_challenge: None,
            passkey_authentication: None,
            webauth_credentials_count: None,
        }
    }
}

async fn charger_usager<M>(middleware: &M, message: MessageValide)
                           -> Result<Option<MessageMilleGrillesBufferDefault>, CoreError>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("charger_usager : {:?}", &message.message);
    let est_delegation_globale = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteUsager = message_contenu.deserialize()?;

    let mut filtre = doc!{};

    // Le filtre utilise le user_id du certificat de preference (et ignore les parametres).
    // Pour un certificat de service (1.public), va utiliser les parametres.
    if message.certificat.verifier_exchanges(vec![Securite::L1Public])? || est_delegation_globale {
        if let Some(nom_usager) = requete.nom_usager.as_ref() {
            filtre.insert(CHAMP_USAGER_NOM, nom_usager);
        }
        if let Some(user_id) = requete.user_id.as_ref() {
            filtre.insert(CHAMP_USER_ID, user_id);
        }
    }

    if filtre.len() == 0 {
        match message.certificat.get_user_id()? {
            Some(u) => {
                filtre.insert(CHAMP_USER_ID, u);
            },
            None => match message.certificat.verifier_exchanges(vec![Securite::L1Public])? {
                true => {
                    if let Some(nom_usager) = requete.nom_usager.as_ref() {
                        filtre.insert(CHAMP_USAGER_NOM, nom_usager);
                    }
                    if let Some(user_id) = requete.user_id.as_ref() {
                        filtre.insert(CHAMP_USER_ID, user_id);
                    }
                },
                false => Err(format!("core_maitredescomptes.charger_usager Requete non autorisee en fonction du certificat"))?
            }
        }
    }

    debug!("charger_usager filtre: {:?}", filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let mut reponse_charger_usager: ReponseChargerUsager = match collection.find_one(filtre, None).await? {
        Some(mut doc_usager) => {
            match convertir_bson_deserializable::<CompteUsager>(doc_usager) {
                Ok(v) => ReponseChargerUsager::from(v),
                Err(e) => {
                    let msg_erreur = format!("Erreur conversion doc vers json : {:?}", e);
                    warn!("{}", msg_erreur);
                    ReponseChargerUsager::erreur(msg_erreur)
                }
            }
        },
        None => {
            ReponseChargerUsager::compte_inconnu(requete.nom_usager.as_ref(), requete.user_id.as_ref())
        }
    };

    if let Some(compte) = reponse_charger_usager.compte.as_ref() {
        let user_id = compte.user_id.as_str();

        debug!("Charger activations pour compte {}", user_id);
        let filtre = doc!{ CHAMP_USER_ID: user_id };
        let collection = middleware.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
        let mut activations = HashMap::new();
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(r) = curseur.next().await {
            let activation: DocActivationFingerprintPkUsager = convertir_bson_deserializable(r?)?;
            activations.insert(activation.fingerprint_pk.clone(), activation);
        }
        reponse_charger_usager.activations = Some(activations);

        if let Some(host_url) = requete.host_url.as_ref() {
            debug!("charger_usager host_url {}", host_url);
            let hostname = host_url;

            let registration_webauthn = preparer_registration_webauthn(middleware, compte, hostname).await?;
            reponse_charger_usager.registration_challenge = match registration_webauthn.webauthn_registration {
                Some(inner) => Some(inner.registration_challenge),
                None => Err(format!("core_maitredescomptes.charger_usager Mauvais format de challenge (registration_challenge=None"))?
            };

            let (generic, challenge, passkey_authentication) =
                match preparer_authentification_webauthn(middleware, compte, hostname).await?
                {
                    Some(doc_challenge) => {
                        match doc_challenge.webauthn_authentication {
                            Some(inner) => {
                                (None, Some(inner.authentication_challenge), Some(inner.passkey_authentication))
                            },
                            None => (Some(doc_challenge.challenge), None, None)
                        }
                    },
                    None => (None, None, None)
                };
            reponse_charger_usager.generic_challenge = generic;
            reponse_charger_usager.authentication_challenge = challenge;
            reponse_charger_usager.passkey_authentication = passkey_authentication;

            let collection_creds = middleware.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
            let filtre = doc!{ CHAMP_USER_ID: &user_id };
            let credentials_count = collection_creds.count_documents(filtre, None).await?;
            reponse_charger_usager.webauth_credentials_count = Some(credentials_count as usize);

            debug!("charger_usager reponse {:?}", reponse_charger_usager);
        } else if ! est_delegation_globale {
            Err(format!("charger_usager host_url n'est pas fourni dans la requete usager"))?;
        }
    }

    match middleware.build_reponse(reponse_charger_usager) {
        Ok(m) => Ok(Some(m.0)),
        Err(e) => Err(format!("Erreur preparation reponse charger_usager : {:?}", e))?
    }
}

async fn preparer_registration_webauthn<M,S>(middleware: &M, compte: &CompteUsager, hostname: S)
                                             -> Result<DocChallenge, CoreError>
where M: MongoDao + ValidateurX509, S: AsRef<str>
{
    let hostname = hostname.as_ref();
    let rp_origin = format!("https://{}/", hostname);
    let user_id = compte.user_id.as_str();
    let nom_usager = compte.nom_usager.as_str();
    let user_uuid = uuid::Uuid::new_v4().to_string();
    let idmg = middleware.idmg();
    let filtre = doc! {
        CHAMP_USER_ID: user_id,
        CHAMP_TYPE_CHALLENGE_WEBAUTHN: "registration",
        "hostname": &hostname,
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let doc_registration: DocChallenge = match collection.find_one(filtre, None).await? {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => {
            let (challenge, registration) = generer_challenge_registration(
                rp_origin.as_str(), nom_usager, &user_uuid, idmg, None::<&Vec<&str>>, // existing_credentials
            )?;
            let doc_registration = DocChallenge::new_challenge_resgistration(
                user_id, user_uuid, hostname, challenge, registration);

            // Sauvegarder dans la base de donnees
            let doc_bson = convertir_to_bson(&doc_registration)?;
            collection.insert_one(doc_bson, None).await?;

            doc_registration
        }
    };

    Ok(doc_registration)
}

async fn preparer_authentification_webauthn<M,S>(middleware: &M, compte: &CompteUsager, hostname: S)
                                                 -> Result<Option<DocChallenge>, millegrilles_common_rust::error::Error>
where M: MongoDao + ValidateurX509, S: AsRef<str>
{
    let hostname = hostname.as_ref();
    let user_id = compte.user_id.as_str();
    let idmg = middleware.idmg();

    // Charger credentials existants
    let collection = middleware.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
    let filtre = doc! { CHAMP_USER_ID: user_id, "hostname": hostname };
    let mut credentials = Vec::new();
    let mut curseur = collection.find(filtre, None).await?;
    while let Some(r) = curseur.next().await {
        let cred: CredentialWebauthn = convertir_bson_deserializable(r?)?;
        credentials.push(cred);
    }

    let doc_challenge = if credentials.len() == 0 {
        debug!("preparer_authentification_webauthn Aucuns credentials webauthn pour {}/{}", user_id, hostname);
        let valeur_challenge =  {
            let mut buffer_random = [0u8; 32];
            openssl::rand::rand_bytes(&mut buffer_random).expect("rand");
            let challenge = buffer_random.to_vec();
            Base64UrlSafeData::from(challenge)
        };
        DocChallenge::new_challenge_generique(user_id, hostname, valeur_challenge, "generique")

    } else {
        let (challenge, passkey_authentication) = match generer_challenge_authentification(
            hostname, idmg, credentials) {
            Ok(inner) => inner,
            Err(e) => Err(millegrilles_common_rust::error::Error::String(format!("preparer_authentification_webauthn Erreur {:?}", e)))?
        };

        DocChallenge::new_challenge_authentication(user_id, hostname, challenge, passkey_authentication)
    };

    // Sauvegarder challenge
    let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let doc_passkey = convertir_to_bson(&doc_challenge)?;
    collection.insert_one(doc_passkey, None).await?;

    Ok(Some(doc_challenge))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteListeUsagers {
    liste_userids: Option<Vec<String>>,
    nom_masque_debut: Option<String>,
}

async fn liste_usagers<M>(middleware: &M, message: MessageValide)
                          -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("liste_usagers : {:?}", &message.message);
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteListeUsagers = message_contenu.deserialize()?;

    let usagers = {
        let mut filtre = doc! {};
        if let Some(userids) = &requete.liste_userids {
            filtre.insert(CHAMP_USER_ID, doc!{"$in": userids});
        }

        let projection = doc! {
            CHAMP_USAGER_NOM: true,
            CHAMP_USER_ID: true,
            CHAMP_COMPTE_PRIVE: true,
            CHAMP_DELEGATION_GLOBALE: true,
        };
        let ops = FindOptions::builder().projection(Some(projection)).build();

        let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
        let mut curseur = collection.find(filtre, ops).await?;

        let mut vec_comptes = Vec::new();
        while let Some(d) = curseur.next().await {
            let mut doc_usager = d?;
            filtrer_doc_id(&mut doc_usager);
            let val_compte = convertir_bson_value(doc_usager)?;
            vec_comptes.push(val_compte);
        }

        vec_comptes
    };

    let val_reponse = json!({
        "complet": true,
        "usagers": usagers,
    });

    match middleware.build_reponse(&val_reponse) {
        Ok(m) => Ok(Some(m.0)),
        Err(e) => Err(format!("Erreur preparation reponse liste_usagers : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteUserIdParNomUsager {
    noms_usagers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseUserIdParNomUsager {
    usagers: HashMap<String, Option<String>>,
}

async fn get_userid_par_nomusager<M>(middleware: &M, message: MessageValide)
                                     -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("get_userid_par_nomusager : {:?}", &message.message);
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteUserIdParNomUsager = message_contenu.deserialize()?;

    // Inserer tous les nom_usagers demandes avec None. Assurer de retourner la reponse complete
    // si certains usagers sont inconnus.
    let mut usagers: HashMap<String, Option<String>> = HashMap::new();
    for nom_usager in &requete.noms_usagers {
        usagers.insert(nom_usager.into(), None);
    }

    {   // Extraire la liste des usagers de la DB
        let filtre = doc! { CHAMP_USAGER_NOM: {"$in": requete.noms_usagers}};
        debug!("get_userid_par_nomusager Requete noms usagers, filtre : {:?}", filtre);
        let projection = doc! {
            CHAMP_USAGER_NOM: true,
            CHAMP_USER_ID: true,
        };
        let ops = FindOptions::builder().projection(Some(projection)).build();
        let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
        let mut curseur = collection.find(filtre, ops).await?;

        while let Some(d) = curseur.next().await {
            let mut doc_usager = d?;
            debug!("get_userid_par_nomusager Usager trouve : {:?}", doc_usager);
            let nom_usager = doc_usager.get_str(CHAMP_USAGER_NOM)?;
            let user_id = doc_usager.get_str(CHAMP_USER_ID)?;
            usagers.insert(nom_usager.into(), Some(user_id.into()));
        }
    };

    let reponse = ReponseUserIdParNomUsager { usagers };

    match middleware.build_reponse(&reponse) {
        Ok(m) => Ok(Some(m.0)),
        Err(e) => Err(format!("Erreur preparation reponse liste_usagers : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteCsrRecoveryParcode {
    nom_usager: Option<String>,
    code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCsrRecovery {
    #[serde(rename="nomUsager")]
    nom_usager: String,
    code: String,
    csr: String,
}

async fn get_csr_recovery_parcode<M>(middleware: &M, message: MessageValide)
                                     -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("get_userid_par_nomusager : {:?}", &message.message);
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteCsrRecoveryParcode = message_contenu.deserialize()?;

    let collection_usagers = middleware.get_collection(NOM_COLLECTION_USAGERS)?;

    // Verifier si on a un usager avec delegation globale (permet d'utiliser le parametre nom_usager)
    let nom_usager_param = match message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        true => requete.nom_usager,
        false => None,
    };

    let nom_usager_option = match nom_usager_param {
        Some(u) => Some(u),
        None => {
            // Trouver nom d'usager qui correspond au user_id du certificat usager
            match message.certificat.get_user_id()? {
                Some(user_id) => {
                    debug!("get_csr_recovery_parcode Get compte usager pour user_id {}", user_id);
                    let filtre = doc!{"userId": &user_id};
                    let doc_usager = collection_usagers.find_one(filtre, None).await?;
                    debug!("get_csr_recovery_parcode Get compte usager pour user_id {}", user_id);
                    match doc_usager {
                        Some(u) => {
                            let info_compte: CompteUsager = convertir_bson_deserializable(u)?;
                            Some(info_compte.nom_usager)
                        },
                        None => None
                    }
                },
                None => None
            }
        }
    };

    let code = requete.code;

    debug!("get_csr_recovery_parcode Verification csr pour usager {:?} avec code {}", nom_usager_option, code);

    let nom_usager = match nom_usager_option {
        Some(u) => u,
        None => {
            let reponse = json!({"ok": false, "err": "Acces refuse", "code": 1});
            return Ok(Some(middleware.build_reponse(reponse)?.0));
        }
    };

    // Charger csr
    let collection = middleware.get_collection(NOM_COLLECTION_RECOVERY)?;
    let filtre = doc! { "nomUsager": nom_usager, "code": code };
    let doc_recovery = collection.find_one(filtre, None).await?;

    match doc_recovery {
        Some(d) => {
            let info_compte: ReponseCsrRecovery = convertir_bson_deserializable(d)?;
            Ok(Some(middleware.build_reponse(info_compte)?.0))
        },
        None => {
            let reponse = json!({"ok": false, "err": "Code de recovery introuvable pour l'usager", "code": 2});
            Ok(Some(middleware.build_reponse(reponse)?.0))
        }
    }
}

async fn get_liste_proprietaires<M>(middleware: &M, message: MessageValide)
                                    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("get_liste_proprietaires : {:?}", &message.message);
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteListeUsagers = message_contenu.deserialize()?;

    let usagers = {
        let filtre = doc! { CHAMP_DELEGATION_GLOBALE: DELEGATION_PROPRIETAIRE };
        let projection = doc! {
            CHAMP_USAGER_NOM: true,
            CHAMP_USER_ID: true,
        };
        let ops = FindOptions::builder().projection(Some(projection)).build();

        let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
        let mut curseur = collection.find(filtre, ops).await?;

        let mut vec_comptes = Vec::new();
        while let Some(d) = curseur.next().await {
            let mut doc_usager = d?;
            filtrer_doc_id(&mut doc_usager);
            let val_compte = convertir_bson_value(doc_usager)?;
            vec_comptes.push(val_compte);
        }

        vec_comptes
    };

    let val_reponse = json!({
        "complet": true,
        "usagers": usagers,
    });

    match middleware.build_reponse(&val_reponse) {
        Ok(m) => Ok(Some(m.0)),
        Err(e) => Err(format!("Erreur preparation reponse liste_usagers : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetCookieUsager {
    user_id: String,
    hostname: String,
    challenge: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CookieSession {
    user_id: String,
    hostname: String,
    challenge: String,
    #[serde(with = "epochseconds")]
    expiration: DateTime<Utc>,
}

impl Into<Value> for CookieSession {
    fn into(self) -> Value {
        serde_json::to_value(self).expect("value")
    }
}

impl CookieSession {
    fn new<U,H>(user_id: U, hostname: H, duree_session: i64) -> Self
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

#[derive(Deserialize)]
struct RowNomUsager {
    #[serde(rename="nomUsager")]
    nom_usager: String,
}

async fn get_cookie_usager<M>(middleware: &M, message: MessageValide)
                              -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("get_cookie_usager Requete : {:?}", &message.message);

    if ! message.certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive])? ||
        ! message.certificat.verifier_roles(vec![RolesCertificats::MaitreComptes, RolesCertificats::WebAuth])? {
        info!("get_cookie_usager Mauvais certificat (doit avoir securite L2Prive, role MaitreComptes");
        let reponse = json!({"ok": false, "err": "Mauvais certificat pour requete"});
        match middleware.build_reponse(&reponse) {
            Ok(m) => return Ok(Some(m.0)),
            Err(e) => Err(format!("Erreur preparation reponse liste_usagers : {:?}", e))?
        }
    }

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteGetCookieUsager = message_contenu.deserialize()?;

    let collection = middleware.get_collection(NOM_COLLECTION_COOKIES)?;
    let filtre = doc! {
        "user_id": requete.user_id,
        "hostname": requete.hostname,
        "challenge": requete.challenge,
    };
    debug!("get_cookie_usager Charger cookie {:?}", filtre);

    match collection.find_one(filtre, None).await? {
        Some(inner) => {
            let cookie: CookieSession = convertir_bson_deserializable(inner)?;

            // Charger username
            let filtre_user = doc! {CHAMP_USER_ID: &cookie.user_id};
            let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
            let projection = doc!{"nomUsager": 1};
            let options = FindOneOptions::builder().projection(projection).build();
            let nom_usager = match collection.find_one(filtre_user, options).await? {
                Some(inner) => {
                    let row_nom_usager: RowNomUsager = convertir_bson_deserializable(inner)?;
                    row_nom_usager.nom_usager
                },
                None => {
                    let reponse = json!({"ok": false, "err": "Usager inconnu"});
                    match middleware.build_reponse(&reponse) {
                        Ok(m) => return Ok(Some(m.0)),
                        Err(e) => Err(format!("get_cookie_usager Erreur preparation reponse match usager : {:?}", e))?
                    }
                }
            };

            let reponse = json!({"ok": true, "nomUsager": nom_usager, "cookie": cookie});
            match middleware.build_reponse(&reponse) {
                Ok(m) => Ok(Some(m.0)),
                Err(e) => Err(format!("get_cookie_usager Erreur preparation reponse ok:true : {:?}", e))?
            }
        },
        None => {
            let reponse = json!({"ok": false, "err": "Cookie inconnu"});
            match middleware.build_reponse(&reponse) {
                Ok(m) => Ok(Some(m.0)),
                Err(e) => Err(format!("get_cookie_usager Erreur preparation reponse cookie inconnu : {:?}", e))?
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RequeteGetPasskeysUsager {
    #[serde(rename="userId")]
    user_id: Option<String>,
}

#[derive(Serialize)]
struct ActivationReponse {
    fingerprint_pk: String,
    #[serde(with="epochseconds")]
    date_creation: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize)]
struct PasskeyAuthenticationCred2 {
    cred_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PasskeyAuthenticationCred {
    cred: PasskeyAuthenticationCred2
}

#[derive(Clone, Debug, Deserialize)]
struct RowWebauthnCredentials {
    #[serde(rename="userId")]
    user_id: String,
    hostname: String,
    #[serde(rename="_mg-creation")]
    date_creation: millegrilles_common_rust::bson::DateTime,
    dernier_auth: Option<millegrilles_common_rust::bson::DateTime>,
    passkey: PasskeyAuthenticationCred,
}

#[derive(Clone, Debug, Deserialize)]
struct RowActivationInfo {
    #[serde(rename="userId")]
    user_id: String,
    fingerprint_pk: String,
    #[serde(rename="_mg-creation")]
    date_creation: millegrilles_common_rust::bson::DateTime,
}

impl From<RowActivationInfo> for ActivationReponse {
    fn from(value: RowActivationInfo) -> Self {
        Self {
            fingerprint_pk: value.fingerprint_pk,
            date_creation: DateTime::from_timestamp(value.date_creation.timestamp_millis()/1000, 0).unwrap()
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RowCookieInfo {
    user_id: String,
    hostname: String,
    expiration: i64,
    #[serde(rename="_mg-creation")]
    date_creation: Option<millegrilles_common_rust::bson::DateTime>,
}

#[derive(Serialize)]
struct CookieReponse {
    hostname: String,
    #[serde(with="epochseconds")]
    expiration: DateTime<Utc>,
    #[serde(with="optionepochseconds")]
    date_creation: Option<DateTime<Utc>>,
}

impl From<RowCookieInfo> for CookieReponse {
    fn from(value: RowCookieInfo) -> Self {
        let date_creation = match value.date_creation {
            Some(inner) => DateTime::from_timestamp(inner.timestamp_millis()/1000, 0),
            None => None
        };
        Self {
            hostname: value.hostname,
            expiration: DateTime::from_timestamp(value.expiration, 0).unwrap(),
            date_creation,
        }
    }
}

#[derive(Serialize)]
struct PasskeyResponse {
    cred_id: String,
    hostname: String,
    #[serde(with="epochseconds")]
    date_creation: DateTime<Utc>,
    #[serde(with="optionepochseconds")]
    dernier_auth: Option<DateTime<Utc>>,
}

impl From<RowWebauthnCredentials> for PasskeyResponse {
    fn from(value: RowWebauthnCredentials) -> Self {
        let dernier_auth = match value.dernier_auth {
            Some(inner) => DateTime::from_timestamp(inner.timestamp_millis()/1000, 0),
            None => None
        };
        Self {
            cred_id: value.passkey.cred.cred_id,
            hostname: value.hostname,
            date_creation: DateTime::from_timestamp(value.date_creation.timestamp_millis()/1000, 0).unwrap(),
            dernier_auth
        }
    }
}

#[derive(Serialize)]
struct GetPasskeysResponse {
    ok: bool,
    user_id: String,
    passkeys: Vec<PasskeyResponse>,
    activations: Vec<ActivationReponse>,
    cookies: Vec<CookieReponse>
}

async fn get_passkeys_usager<M>(middleware: &M, message: MessageValide)
                                -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("get_passkeys_usager Requete : {:?}", &message.message);

    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "User_id absent du certificat"});
            match middleware.build_reponse(&reponse) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("Erreur preparation reponse liste_usagers : {:?}", e))?
            }
        }
    };

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteGetPasskeysUsager = message_contenu.deserialize()?;

    // Si l'usager est un propritaire, permettre de fournir le user_id
    let user_id = match message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        true => match requete.user_id {
            Some(inner) => inner,
            None => user_id.to_owned()
        },
        false => user_id.to_owned()
    };

    let filtre = doc! { CHAMP_USER_ID: &user_id };
    debug!("get_passkeys_usager Charger pour usager {:?}", filtre);

    let passkeys = {
        let mut passkeys = Vec::new();
        let collection = middleware.get_collection_typed::<RowWebauthnCredentials>(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
        let mut curseur = collection.find(filtre.clone(), None).await?;
        while let Some(cred) = curseur.next().await {
            let cred = cred?;
            debug!("get_passkeys_usager Cred : {:?}", cred);
            passkeys.push(cred.into());
        }

        passkeys
    };

    let activations: Vec<ActivationReponse> = {
        let mut activations = Vec::new();
        let collection = middleware.get_collection_typed::<RowActivationInfo>(NOM_COLLECTION_ACTIVATIONS)?;
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(activation) = curseur.next().await {
            let activation = activation?;
            debug!("get_passkeys_usager Activation : {:?}", activation);
            activations.push(activation.into());
        }

        activations
    };

    let cookies: Vec<CookieReponse> = {
        let mut cookies = Vec::new();
        let collection = middleware.get_collection_typed::<RowCookieInfo>(NOM_COLLECTION_COOKIES)?;
        let filtre = doc! { "user_id": &user_id };
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(cookie) = curseur.next().await {
            let cookie = cookie?;
            debug!("get_passkeys_usager Activation : {:?}", cookie);
            cookies.push(cookie.into());
        }

        cookies
    };

    let reponse = GetPasskeysResponse { ok: true, user_id: user_id.to_owned(), passkeys, activations, cookies };

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}
