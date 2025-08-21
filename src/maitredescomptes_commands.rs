use std::time::SystemTime;
use log::{debug, error, warn};
use webauthn_rs::prelude::{Base64UrlSafeData, CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse};
use totp_rs::{Algorithm, TOTP, Secret};

use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions, calculer_fingerprint_pk, csr_calculer_fingerprintpk};
use millegrilles_common_rust::chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::constantes::{Securite, DELEGATION_GLOBALE_PROPRIETAIRE, CHAMP_CREATION, CHAMP_MODIFICATION, DOMAINE_APPLICATION_INSTANCE, DOMAINE_NOM_MAITREDESCOMPTES};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::jwt_simple::prelude::{Base64, Deserialize, Serialize};
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_serializable_v2, sauvegarder_traiter_transaction_v2, Middleware};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, start_transaction_regular, MongoDao};
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::{base64_url, chrono, hex, millegrilles_cryptographie, openssl, reqwest, serde_json, uuid};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::bson::{Bson, bson, DateTime as DateTimeBson, doc};
use millegrilles_common_rust::formatteur_messages::preparer_btree_recursif;
use millegrilles_common_rust::hachages::{hacher_bytes_vu8, Hacheur};
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::transactions::{marquer_transaction, EtatTransaction};
use millegrilles_common_rust::common_messages::{MessageConfirmation, ReponseSignatureCertificat};
use millegrilles_common_rust::certificats::{charger_csr, get_csr_subject};
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::hachages::{hacher_bytes, HachageCode, HacheurBlake2s256};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::mongodb::ClientSession;
use crate::error::Error as CoreError;
use crate::maitredescomptes_common::{charger_compte_user_id, commande_maj_usager_delegations, emettre_maj_compte_usager, sauvegarder_credential};
use crate::maitredescomptes_constants::*;
use crate::maitredescomptes_manager::MaitreDesComptesManager;
use crate::maitredescomptes_structs::{ChallengeAuthenticationWebauthn, CommandeAjouterDelegationSignee, CommandeResetWebauthnUsager, CompteUsager, ConfirmationSigneeDelegationGlobale, CookieSession, DocChallenge, RequeteGetCookieUsager, TotpCredentialsRow, TransactionAjouterCle, TransactionInscrireUsager, TransactionMajUsagerDelegations, TransactionSupprimerCles};
use crate::maitredescomptes_transactions::{transaction_ajouter_delegation_signee, CommandRegisterOtp, TransactionRegisterOtp};
use crate::webauthn::{authenticate_complete, ClientAssertionResponse, CompteCredential, ConfigChallenge, Credential, CredentialWebauthn, generer_challenge_authentification, generer_challenge_registration, multibase_to_safe, valider_commande, verifier_challenge_authentification, verifier_challenge_registration};

pub async fn consommer_commande_maitredescomptes<M>(middleware: &M, gestionnaire: &MaitreDesComptesManager, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: Middleware
{
    debug!("Consommer commande : {:?}", &m.type_message);

    let (action, domaine) = match &m.type_message {
        TypeMessageOut::Commande(r) => {
            (r.action.clone(), r.domaine.clone())
        },
        _ => Err(format!("consommer_evenement Mauvais type de message"))?
    };

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    let result = if m.certificat.verifier_exchanges(vec!(Securite::L2Prive, Securite::L3Protege))? {
        // Actions autorisees pour echanges prives
        match action.as_str() {
            TRANSACTION_INSCRIRE_USAGER => inscrire_usager(middleware, m, gestionnaire, &mut session).await,
            TRANSACTION_AJOUTER_CLE => commande_ajouter_cle(middleware, m, gestionnaire, &mut session).await,
            TRANSACTION_AJOUTER_DELEGATION_SIGNEE => commande_ajouter_delegation_signee(middleware, m, gestionnaire, &mut session).await,
            TRANSACTION_REGISTER_OTP => command_register_otp(middleware, m, gestionnaire, &mut session).await,

            COMMANDE_AUTHENTIFIER_WEBAUTHN => commande_authentifier_webauthn(middleware, m, &mut session).await,
            COMMAND_AUTHENTICATE_TOTP => command_authenticate_otp(middleware, m, &mut session).await,
            COMMANDE_SIGNER_COMPTEUSAGER => commande_signer_compte_par_usager(middleware, m, &mut session).await,
            COMMANDE_AJOUTER_CSR_RECOVERY => commande_ajouter_csr_recovery(middleware, m, &mut session).await,
            COMMANDE_GENERER_CHALLENGE => commande_generer_challenge(middleware, m, &mut session).await,
            COMMAND_GENERATE_OTP => command_generate_otp(middleware, m, &mut session).await,
            COMMANDE_SUPPRIMER_COOKIE => supprimer_cookie(middleware, m, &mut session).await,

            // Commandes inconnues
            _ => Err(format!("Commande {} inconnue (section: exchange L2/L3) : {}, message dropped", DOMAIN_NAME, action))?,
        }
    } else if m.certificat.verifier_exchanges(vec!(Securite::L1Public))? {
        match action.as_str() {
            COMMANDE_AUTHENTIFIER_WEBAUTHN => commande_authentifier_webauthn(middleware, m, &mut session).await,
            COMMAND_AUTHENTICATE_TOTP => command_authenticate_otp(middleware, m, &mut session).await,
            COMMANDE_SUPPRIMER_COOKIE => supprimer_cookie(middleware, m, &mut session).await,
            COMMAND_GENERATE_OTP => command_generate_otp(middleware, m, &mut session).await,
            TRANSACTION_REGISTER_OTP => command_register_otp(middleware, m, gestionnaire, &mut session).await,

            // Commandes inconnues
            _ => Err(format!("Commande {} inconnue (section: exchange L1) : {}, message dropped", DOMAIN_NAME, action))?,
        }
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Commande proprietaire (administrateur)
        match action.as_str() {
            // Commandes delegation globale uniquement
            TRANSACTION_MAJ_USAGER_DELEGATIONS => commande_maj_usager_delegations(middleware, m, gestionnaire, &mut session).await,
            TRANSACTION_SUPPRIMER_CLES => commande_supprimer_cles(middleware, m, gestionnaire, &mut session).await,
            TRANSACTION_RESET_WEBAUTHN_USAGER => commande_reset_webauthn_usager(middleware, gestionnaire, m, &mut session).await,
            TRANSACTION_REGISTER_OTP => command_register_otp(middleware, m, gestionnaire, &mut session).await,

            // Commandes usager standard
            TRANSACTION_AJOUTER_CLE => commande_ajouter_cle(middleware, m, gestionnaire, &mut session).await,
            COMMANDE_SIGNER_COMPTEUSAGER => commande_signer_compte_par_usager(middleware, m, &mut session).await,
            COMMANDE_SIGNER_COMPTE_PAR_PROPRIETAIRE => commande_signer_compte_par_proprietaire(middleware, m, &mut session).await,
            COMMANDE_GENERER_CHALLENGE => commande_generer_challenge(middleware, m, &mut session).await,
            TRANSACTION_AJOUTER_DELEGATION_SIGNEE => commande_ajouter_delegation_signee(middleware, m, gestionnaire, &mut session).await,
            COMMAND_GENERATE_OTP => command_generate_otp(middleware, m, &mut session).await,
            COMMAND_AUTHENTICATE_TOTP => command_authenticate_otp(middleware, m, &mut session).await,

            // Commandes inconnues
            _ => Ok(Some(middleware.reponse_err(252, None, Some("Acces refuse"))?))
        }
    } else if m.certificat.get_user_id()?.is_some() {
        match action.as_str() {
            // TRANSACTION_AJOUTER_CLE => commande_ajouter_cle(middleware, m, gestionnaire).await,
            COMMANDE_SIGNER_COMPTEUSAGER => commande_signer_compte_par_usager(middleware, m, &mut session).await,
            COMMANDE_GENERER_CHALLENGE => commande_generer_challenge(middleware, m, &mut session).await,
            TRANSACTION_AJOUTER_CLE => commande_ajouter_cle(middleware, m, gestionnaire, &mut session).await,
            TRANSACTION_AJOUTER_DELEGATION_SIGNEE => commande_ajouter_delegation_signee(middleware, m, gestionnaire, &mut session).await,
            COMMAND_GENERATE_OTP => command_generate_otp(middleware, m, &mut session).await,
            COMMAND_AUTHENTICATE_TOTP => command_authenticate_otp(middleware, m, &mut session).await,
            TRANSACTION_REGISTER_OTP => command_register_otp(middleware, m, gestionnaire, &mut session).await,

            // Commandes inconnues
            _ => Err(format!("Commande {} inconnue (section: user_id): {}, message dropped", DOMAIN_NAME, action))?,
        }
    } else {
        debug!("Commande {} non autorisee : {}, message dropped", DOMAIN_NAME, action);
        Err(format!("Commande {} non autorisee : {}, message dropped", DOMAIN_NAME, action))?
    };

    match result {
        Ok(result) => {
            session.commit_transaction().await?;
            Ok(result)
        }
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn ajouter_fingerprint_pk_usager<M,S,T>(middleware: &M, user_id: S, fingerprint_pk: T, session: &mut ClientSession)
                                              -> Result<(), millegrilles_common_rust::error::Error>
where M: MongoDao, S: AsRef<str>, T: AsRef<str>
{
    let user_id = user_id.as_ref();
    let fingerprint_pk = fingerprint_pk.as_ref();

    let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FINGERPRINT_PK: fingerprint_pk };
    let ops = doc! {
        "$setOnInsert": {
            CHAMP_USER_ID: user_id,
            CHAMP_CREATION: Utc::now(),
            CHAMP_FINGERPRINT_PK: fingerprint_pk,
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let options = UpdateOptions::builder().upsert(true).build();

    let collection = middleware.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
    collection.update_one_with_session(filtre, ops, options, session).await?;

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSignatureUsager {
    nom_usager: String,
    user_id: String,
    csr: String,
    delegation_globale: Option<String>,
    compte_prive: Option<bool>,
    delegations_version: Option<usize>,
}

impl CommandeSignatureUsager {
    fn new<S,T,U>(nom_usager: S, user_id: T, csr: U, compte: Option<&CompteUsager>) -> Self
    where S: Into<String>, T: Into<String>, U: Into<String>
    {
        let (compte_prive, delegation_globale, delegations_version) = match compte {
            Some(inner) => {
                (inner.compte_prive.to_owned(), inner.delegation_globale.to_owned(), inner.delegations_version.to_owned())
            },
            None => (None, None, None)
        };

        CommandeSignatureUsager {
            nom_usager: nom_usager.into(),
            user_id: user_id.into(),
            csr: csr.into(),
            delegation_globale,
            compte_prive,
            delegations_version,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCertificatSigne {
    ok: bool,
    certificat: Vec<String>,
}

/// Signe un certificat usager sans autre forme de validation. Utilise certissuerInterne/.
async fn signer_certificat_usager<M,S,T,U>(middleware: &M, nom_usager: S, user_id: T, csr: U, compte: Option<&CompteUsager>)
                                           -> Result<MessageMilleGrillesBufferDefault, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud,
      S: AsRef<str>, T: AsRef<str>, U: AsRef<str>
{
    let nom_usager_str = nom_usager.as_ref();
    let user_id_str = user_id.as_ref();
    let csr_str = csr.as_ref();
    debug!("signer_certificat_usager {} (id: {})", nom_usager_str, user_id_str);

    let config = middleware.get_configuration_noeud();
    let certissuer_url = match config.certissuer_url.as_ref() {
        Some(inner) => inner,
        None => Err(format!("core_maitredescomptes.signer_certificat_usager Certissuer URL manquant"))?
    };

    let client = reqwest::Client::builder()
        .timeout(core::time::Duration::new(7, 0))
        .build()?;

    let mut url_post = certissuer_url.clone();
    url_post.set_path("certissuerInterne/signerUsager");

    // let mut commande_signature = json!({
    //     "nom_usager": nom_usager_str,
    //     "user_id": user_id_str,
    //     "csr": csr_str
    // });

    let commande_signature = CommandeSignatureUsager::new(nom_usager_str, user_id_str, csr_str, compte);
    let routage = RoutageMessageAction::builder(DOMAIN_NAME, "signer", vec![])
        .build();
    let commande_signee = middleware.build_message_action(
        millegrilles_cryptographie::messages_structs::MessageKind::Commande, routage, &commande_signature)?.0;
    // let commande_signee = middleware.build_message_action(
    //     MessageKind::Document, &commande_signature,
    //     None::<&str>, None::<&str>, None::<&str>, None::<&str>,
    //     None, false)?;

    // On retransmet le message recu tel quel
    match client.post(url_post).body(commande_signee.buffer).send().await {
        Ok(response) => {
            match response.status().is_success() {
                true => {
                    let reponse_json: ReponseCertificatSigne = response.json().await?;
                    debug!("signer_certificat_usager Reponse certificat : {:?}", reponse_json);
                    // Charger le certificat - le valide et sauvegarde dans PKI
                    let enveloppe = middleware.charger_enveloppe(
                        &reponse_json.certificat, None, None).await?;
                    debug!("signer_certificat_usager Nouveau certificat valide, fingerprint : {}", enveloppe.fingerprint()?);
                    return Ok(middleware.build_reponse(reponse_json)?.0)
                },
                false => {
                    debug!("core_maitredescomptes.signer_certificat_usager Erreur reqwest : status {}", response.status());
                }
            }
        },
        Err(e) => {
            debug!("core_maitredescomptes.signer_certificat_usager Erreur reqwest : {:?}", e);
        }
    };

    // Une erreur est survenue dans le post, fallback vers noeuds 4.secure (si presents)
    debug!("Echec connexion a certissuer local, relai vers instances 4.secure");
    let routage = RoutageMessageAction::builder(
        DOMAINE_APPLICATION_INSTANCE, COMMANDE_SIGNER_COMPTEUSAGER, vec![Securite::L4Secure])
        .build();

    match middleware.transmettre_commande(routage, &commande_signature).await? {
        Some(reponse) => {
            if let TypeMessage::Valide(reponse) = reponse {
                let reponse_ref = reponse.message.parse()?;
                let message_contenu = reponse_ref.contenu()?;
                let reponse_json: ReponseCertificatSigne = message_contenu.deserialize()?;
                Ok(middleware.build_reponse(reponse_json)?.0)
            } else {
                error!("core_pki.commande_signer_csr Erreur signature, echec local et relai 4.secure");
                Ok(middleware.build_reponse(
                    json!({"ok": false, "err": "Erreur signature : aucun signateur disponible"})
                )?.0)
            }
        },
        None => {
            error!("core_pki.commande_signer_csr Erreur signature, aucune reponse");
            Ok(middleware.build_reponse(
                json!({"ok": false, "err": "Erreur signature : aucun signateur disponible"})
            )?.0)
        }
    }
}

async fn inscrire_usager<M>(middleware: &M, message: MessageValide, gestionnaire: &MaitreDesComptesManager, session: &mut ClientSession)
                            -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("inscrire_usager Consommer inscrire_usager : {:?}", &message.type_message);
    let (transaction, message_id) = {
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        let transaction: TransactionInscrireUsager = message_contenu.deserialize()?;
        let message_id = message_ref.id.clone();
        (transaction, message_id)
    };
    let nom_usager = transaction.nom_usager.as_str();

    // Verifier que l'usager n'existe pas deja (collection usagers)
    let filtre = doc!{CHAMP_USAGER_NOM: nom_usager};
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let doc_usager = collection.find_one_with_session(filtre, None, session).await?;
    let reponse = match doc_usager {
        Some(d) => {
            debug!("inscrire_usager Usager {} existe deja : {:?}, on skip", nom_usager, d);
            let val = json!({"ok": false, "err": format!("Usager {} existe deja", nom_usager)});
            match middleware.build_reponse(val) {
                Ok(m) => Ok(Some(m.0)),
                Err(e) => Err(format!("inscrire_usager Erreur preparation reponse liste_usagers : {:?}", e))
            }
        },
        None => {
            debug!("inscrire_usager L'usager '{}' n'existe pas, on genere un certificat", nom_usager);
            let user_id = &transaction.user_id;
            let securite = &transaction.securite;

            // Generer certificat usager si CSR present
            let certificat = match transaction.csr {
                Some(csr) => {
                    let fingerprint_pk = match csr_calculer_fingerprintpk(csr.as_str()) {
                        Ok(fp) => fp,
                        Err(e) => {
                            error!("inscrire_usager Erreur calcul fingerprint_pk du csr : {:?}", e);
                            let val = json!({"ok": false, "err": format!("Erreur calcul fingerprint_pk du csr")});
                            return match middleware.build_reponse(val) {
                                Ok(m) => Ok(Some(m.0)),
                                Err(e) => Err(format!("inscrire_usager Erreur preparation reponse csr manquant : {:?}", e))?
                            }
                        }
                    };
                    debug!("Ajouter activation pour user_id: {}, fingerprint_pk: {}", user_id, fingerprint_pk);
                    ajouter_fingerprint_pk_usager(middleware, user_id, fingerprint_pk, session).await?;
                    signer_certificat_usager(middleware, nom_usager, user_id, csr, None).await?
                },
                None => {
                    error!("inscrire_usager Inscription usager {} sans CSR initial - ABORT", nom_usager);
                    let val = json!({"ok": false, "err": format!("Requete sans CSR")});
                    return match middleware.build_reponse(val) {
                        Ok(m) => Ok(Some(m.0)),
                        Err(e) => Err(format!("inscrire_usager Erreur preparation reponse csr manquant : {:?}", e))?
                    }
                }
            };

            // sauvegarder_transaction(middleware, &message, NOM_COLLECTION_TRANSACTIONS).await?;
            let resultat_inscrire_usager = sauvegarder_traiter_transaction_v2(
                middleware, message, gestionnaire, session).await?;

            if let Err(e) = emettre_maj_compte_usager(middleware, user_id, Some(EVENEMENT_INSCRIRE_COMPTE_USAGER), session).await {
                warn!("Erreur emission evenement inscription usager : {:?}", e);
            }
            // let transaction: TransactionImpl = message.clone().try_into()?;
            // let resultat_inscrire_usager = sauvegarder_inscrire_usager(middleware, transaction).await?;
            // marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, uuid_transaction, EtatTransaction::Complete).await?;

            // let reponse = match certificat {
            //     Some(inner) => Some(inner),
            //     None => resultat_inscrire_usager
            // };

            Ok(Some(certificat))
        }
    }?;

    Ok(reponse)
}


async fn commande_ajouter_cle<M>(middleware: &M, message: MessageValide, gestionnaire: &MaitreDesComptesManager, session: &mut ClientSession)
                                 -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer ajouter_cle : {:?}", &message.type_message);

    let message_ref = message.message.parse()?;
    let uuid_transaction = message_ref.id.to_owned();

    let certificat = message.certificat.as_ref();

    let message_contenu = message_ref.contenu()?;
    let transaction_ajouter_cle_contenu: TransactionAjouterCle = message_contenu.deserialize()?;

    let idmg = middleware.idmg();

    // let transaction_ajouter_cle_contenu: TransactionAjouterCle = reponse_client_serialise.parsed.map_contenu()?;
    let hostname = match transaction_ajouter_cle_contenu.hostname.as_ref() {
        Some(inner) => inner.as_str(),
        None => {
            let err = json!({"ok": false, "code": 15, "err": format!{"Permission refusee, hostname manquant"}});
            debug!("ajouter_cle hostname manquant");
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("ajouter_cle: Erreur preparation reponse commande_ajouter_cle (15) : {:?}", e))?
            }
        }
    };

    // Verifier si on fait une association en utilisant un nouveau certificat active de maniere
    // externe (e.g. par le proprietaire dans Coup D'Oeil ou code QR). Utiliser fingperprint
    // de la cle publique du message signe par l'usager.
    let user_id_certificat = match certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => {
            let err = json!({"ok": false, "code": 8, "err": "Permission refusee, certificat client sans user_id"});
            debug!("ajouter_cle autorisation acces refuse certificat client sans user_id (8): {:?}", err);
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("Erreur preparation reponse commande_ajouter_cle : {:?}", e))?
            }
        }
    };

    let fingerprint_pk = certificat.fingerprint_pk()?;

    // Validation - s'assurer que le compte usager existe
    let collection_webauthn = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let filtre_webauthn = doc! { CHAMP_USER_ID: &user_id_certificat, "hostname": hostname, "type_challenge": "registration" };
    let doc_registration: DocChallenge = match collection_webauthn.find_one_with_session(filtre_webauthn, None, session).await? {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => {
            let err = json!({"ok": false, "code": 14, "err": format!("Permission refusee, registration webauthn absent pour userId : {}", user_id_certificat)});
            debug!("ajouter_cle registration inconnu pour user_id {} (14) : {:?}", user_id_certificat, err);
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("core_maitredescomptes.ajouter_cle Erreur preparation reponse commande_ajouter_cle (14) : {:?}", e))?
            }
        }
    };

    let compte_usager = match charger_compte_user_id(middleware, &user_id_certificat, session).await? {
        Some(inner) => inner,
        None => {
            let err = json!({"ok": false, "code": 2, "err": format!("Usager inconnu pour userId (2) : {}", user_id_certificat)});
            debug!("ajouter_cle usager inconnu : {:?}", err);
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("core_maitredescomptes.ajouter_cle Erreur preparation reponse commande_ajouter_cle : {:?}", e))?
            }
        }
    };

    // Valider la commande de registration webauthn, sauvegarder nouvelle credential, retirer challenge registration
    let webauthn_credential = match verifier_challenge_registration(idmg, &doc_registration, &transaction_ajouter_cle_contenu) {
        Ok(inner) => inner,
        Err(e) => Err(millegrilles_common_rust::error::Error::String(format!("core_maitredescomptes Erreur {:?}", e)))?
    };
    let mut credential_interne = sauvegarder_credential(
        middleware, &user_id_certificat, hostname, webauthn_credential, true, session).await?;

    {
        // Supprimer activation pour le certificat (si present)
        let collection = middleware.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
        let filtre = doc! { CHAMP_USER_ID: &user_id_certificat, "fingerprint_pk": fingerprint_pk };
        collection.delete_one_with_session(filtre, None, session).await?;
    }

    // Transferer le flag reset_cles vers la transaction au besoin
    if let Some(true) = transaction_ajouter_cle_contenu.reset_cles {
        credential_interne.reset_cles = Some(true)
    }

    debug!("Credentials traite - sauvegarder sous forme de nouvelle transaction");

    Ok(sauvegarder_traiter_transaction_serializable_v2(
        middleware, &credential_interne, gestionnaire, session, DOMAIN_NAME, TRANSACTION_AJOUTER_CLE
    ).await?.0)
}

/// Ajoute une delegation globale a partir d'un message signe par la cle de millegrille
async fn commande_ajouter_delegation_signee<M>(middleware: &M, message: MessageValide, gsetionnaire: &MaitreDesComptesManager, session: &mut ClientSession)
                                               -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer ajouter_delegation_signee : {:?}", &message.type_message);
    // Verifier autorisation
    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => {
            let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat sans user_id"});
            debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("commande_ajouter_delegation_signee Erreur preparation reponse (1) ajouter_delegation_signee : {:?}", e))?
            }
        }
    };

    let message_id = {
        // Valider contenu
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        let commande: CommandeAjouterDelegationSignee = message_contenu.deserialize()?;

        // let vec_message = Vec::from(commande.confirmation.as_bytes());
        // let message_confirmation_buf = MessageMilleGrillesBufferDefault::from(vec_message);
        // let mut message_confirmation = message_confirmation_buf.parse()?;
        let mut message_confirmation = commande.confirmation;
        // let user_id = commande.user_id.as_str();
        let hostname = commande.hostname;

        // S'assurer que la signature est recente (moins de 2 minutes, ajustement 10 secondes futur max)
        let date_signature = &message_confirmation.estampille;
        let now = Utc::now();
        if now - chrono::Duration::minutes(2) > *date_signature || now + chrono::Duration::seconds(10) < *date_signature {
            warn!("ajouter_delegation_signee Commande delegation expiree - on rejette (2)");
            let err = json!({"ok": false, "code": 2, "err": "Permission refusee, estampille invalide"});
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("commande_ajouter_delegation_signee Erreur preparation reponse (2) : {:?}", e))?
            }
        }

        // Valider la signature de la cle de millegrille
        if let Err(e) = message_confirmation.verifier_signature() {
            // if signature != true || hachage != true {
            // let err = json!({"ok": false, "code": 3, "err": "Permission refusee, signature/hachage confirmation invalides"});
            debug!("ajouter_delegation_signee autorisation acces refuse");
            match middleware.reponse_err(3, None, Some("Permission refusee, signature/hachage confirmation invalides")) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("Erreur preparation reponse (3) ajouter_delegation_signee : {:?}", e))?
            }
        }
        debug!("ajouter_delegation_signee Signature message delegation (confirmation) OK");

        // Valider la pubkey, elle doit correspondre au certificat de la MilleGrille.
        let public_key_millegrille = middleware.ca_cert().public_key()?.raw_public_key()?;
        if hex::decode(&message_confirmation.pubkey)? != public_key_millegrille {
            let err = json!({"ok": false, "code": 4, "err": "Permission refusee, pubkey n'est pas la cle de la MilleGrille"});
            debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("Erreur preparation reponse (4) ajouter_delegation_signee : {:?}", e))?
            }
        }
        debug!("ajouter_delegation_signee Correspondance cle publique millegrille OK");

        // Valider le format du contenu (parse)
        // let message_confirmation_buffer = message_confirmation.contenu()?;
        // let commande_ajouter_delegation: ConfirmationSigneeDelegationGlobale = message_confirmation_buffer.deserialize()?;
        let commande_ajouter_delegation: ConfirmationSigneeDelegationGlobale = message_confirmation.deserialize()?;
        if commande_ajouter_delegation.user_id.as_str() != user_id.as_str() {
            let err = json!({"ok": false, "code": 5, "err": "Permission refusee, user_id signe et session serveur mismatch"});
            debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("Erreur preparation reponse (5) ajouter_delegation_signee : {:?}", e))?
            }
        }
        let challenge_recu = commande_ajouter_delegation.challenge.as_str();
        debug!("commande_ajouter_delegation_signee Commande ajouter delegation verifiee {:?}", commande_ajouter_delegation);

        // Verifier que le challenge est bien associe a cet usager pour une delegation
        let challenge = {
            let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
            let filtre = doc! { CHAMP_USER_ID: &user_id, "type_challenge": "delegation", "hostname": hostname, "challenge": challenge_recu};
            let doc_challenge: DocChallenge = match collection.find_one_with_session(filtre, None, session).await? {
                Some(inner) => convertir_bson_deserializable(inner)?,
                None => {
                    let err = json!({"ok": false, "code": 6, "err": "Permission refusee, challenge delegation inconnu"});
                    debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
                    match middleware.build_reponse(err) {
                        Ok(m) => return Ok(Some(m.0)),
                        Err(e) => Err(format!("Erreur preparation reponse (6) ajouter_delegation_signee : {:?}", e))?
                    }
                }
            };
            doc_challenge.challenge
        };

        if challenge == commande_ajouter_delegation.challenge {
            // Challenge est OK, supprimer pour eviter replay attacks
            let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
            let filtre = doc! { CHAMP_USER_ID: &user_id, "hostname": hostname, "challenge": challenge_recu};
            collection.delete_one_with_session(filtre, None, session).await?;
        } else {
            let err = json!({"ok": false, "code": 7, "err": "Permission refusee, challenge delegation inconnu"});
            debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("Erreur preparation reponse (7) ajouter_delegation_signee : {:?}", e))?
            }
        }

        message_ref.id.to_string()
    };

    // Signature valide, on sauvegarde et traite la transaction
    sauvegarder_traiter_transaction_v2(middleware, message, gsetionnaire, session).await?;
    // let transaction: TransactionImpl = message.try_into()?;
    // transaction_ajouter_delegation_signee(middleware, message.try_into()?).await?;
    // marquer_transaction(middleware, COLLECTION_NAME_TRANSACTIONS, &message_id, EtatTransaction::Complete).await?;

    // Charger le document de compte et retourner comme reponse
    let reponse = match charger_compte_user_id(middleware, &user_id, session).await? {
        Some(compte) => serde_json::to_value(&compte)?,
        None => json!({"ok": false, "err": "Compte usager introuvable apres maj"})  // Compte
    };

    if let Err(e) = emettre_maj_compte_usager(middleware, user_id, None, session).await {
        warn!("ajouter_delegation_signee Erreur emission evenement inscription usager : {:?}", e);
    }

    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DemandeSignatureCertificatWebauthn {
    #[serde(rename="activationTierce", skip_serializing_if = "Option::is_none")]
    activation_tierce: Option<bool>,
    csr: String,
    #[serde(with = "epochseconds")]
    date: DateTime<Utc>,
    #[serde(rename = "nomUsager")]
    nom_usager: String,
}

impl DemandeSignatureCertificatWebauthn {
    /// Valide le message et retourne un hachage du contenu.
    fn valider(&self) -> Result<Vec<u8>, millegrilles_common_rust::error::Error> {

        // Le message recu est valide pour 5 minutes
        // (aussi 1 minute dans l'autre sens si clock mal ajustee)
        let date_now = Utc::now();
        let date_message = self.date;
        if date_now - chrono::Duration::minutes(5) > date_message ||
            date_now + chrono::Duration::minutes(1) < date_message {
            Err("core_maitredescomptes.DemandeSignatureCertificatWebauthn Date expire/invalide")?
        }

        // Calculer le hachage du message
        self.hacher()
    }

    fn hacher(&self) -> Result<Vec<u8>, millegrilles_common_rust::error::Error> {
        let map = serde_json::to_value(&self)?.as_object().expect("value map").to_owned();
        let value_ordered = preparer_btree_recursif(map)?;
        let value_serialisee = serde_json::to_string(&value_ordered)?;
        let value_bytes = value_serialisee.as_bytes();
        Ok(hacher_bytes_vu8(value_bytes, Some(Code::Blake2s256)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResponseChallengeAuthenticationWebauthn {
    #[serde(rename = "authenticatorData")]
    authenticator_data: Base64UrlSafeData,
    #[serde(rename = "clientDataJSON")]
    client_data_json: Base64UrlSafeData,
    signature: Base64UrlSafeData,
    #[serde(rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientAuthentificationWebauthn {
    id64: Base64UrlSafeData,
    response: ResponseChallengeAuthenticationWebauthn,
    #[serde(rename = "type")]
    type_: Option<String>,
}

impl TryInto<PublicKeyCredential> for ClientAuthentificationWebauthn {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<PublicKeyCredential, Self::Error> {
        let id = self.id64;

        let pk_json = json!({
            "id": &id,
            "rawId": id,
            "response": self.response,
            "extensions": {},
            "type": self.type_,
        });

        Ok(serde_json::from_value(pk_json)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeClientAuthentificationWebauthn {
    #[serde(rename = "demandeCertificat")]
    demande_certificat: Option<DemandeSignatureCertificatWebauthn>,
    #[serde(rename = "dureeSession", skip_serializing_if = "Option::is_none")]
    duree_session: Option<i64>,
    webauthn: ClientAuthentificationWebauthn,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeAuthentificationUsager {
    #[serde(rename="userId")]
    user_id: String,
    hostname: String,
    challenge: String,
    #[serde(rename="reponseWebauthn")]
    commande_webauthn: CommandeClientAuthentificationWebauthn,
}

async fn charger_challenge_authentification<M,U,H,C>(middleware: &M, user_id: U, hostname: H, challenge: C, session: &mut ClientSession)
    -> Result<ChallengeAuthenticationWebauthn, millegrilles_common_rust::error::Error>
    where M: MongoDao, U: AsRef<str>, H: AsRef<str>, C: AsRef<str>
{
    // Charger challenge correspondant
    let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let filtre = doc! {
        CHAMP_USER_ID: user_id.as_ref(),
        "hostname": hostname.as_ref(),
        "type_challenge": "authentication",
        "challenge": challenge.as_ref(),
    };

    debug!("Charger challenge webauthn {:?}", filtre);
    let doc_challenge: DocChallenge = match collection.find_one_with_session(filtre.clone(), None, session).await? {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => Err(format!("core_maitredescomptes.commande_authentifier_webauthn Challenge webauthn inconnu ou expire"))?
    };

    let doc_webauth_state = match doc_challenge.webauthn_authentication {
        Some(inner) => inner,
        None => Err(format!("core_maitredescomptes.commande_authentifier_webauthn Challenge webauthn absent (None)"))?
    };

    Ok(doc_webauth_state)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PasskeyAuthenticationStateAjuste {
    pub credentials: Value,
    pub policy: Value,
    pub challenge: Base64UrlSafeData,
    pub appid: Option<String>,
    pub allow_backup_eligible_upgrade: bool
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PasskeyAuthenticationAjuste {
    ast: PasskeyAuthenticationStateAjuste,
}


impl TryInto<PasskeyAuthentication> for PasskeyAuthenticationAjuste {
    type Error = millegrilles_common_rust::error::Error;

    fn try_into(self) -> Result<PasskeyAuthentication, Self::Error> {
        let value = serde_json::to_value(self)?;
        Ok(serde_json::from_value(value)?)
    }
}

impl TryFrom<PasskeyAuthentication> for PasskeyAuthenticationAjuste {
    type Error = millegrilles_common_rust::error::Error;

    fn try_from(value: PasskeyAuthentication) -> Result<Self, Self::Error> {
        let value_conv = serde_json::to_value(value)?;
        Ok(serde_json::from_value(value_conv)?)
    }
}

async fn creer_session_cookie<M,U,H>(middleware: &M, user_id: U, hostname: H, duree_session: i64, session: &mut ClientSession)
                                     -> Result<CookieSession, millegrilles_common_rust::error::Error>
where M: MongoDao, U: AsRef<str>, H: AsRef<str>
{
    let cookie = CookieSession::new(user_id.as_ref(), hostname.as_ref(), duree_session);
    let collection = middleware.get_collection(NOM_COLLECTION_COOKIES)?;
    let cookie_bson = convertir_to_bson(cookie.clone())?;
    // collection.insert_one(cookie_bson, None).await?;
    let ops = doc!{
        "$set": cookie_bson,
        "$currentDate": { CHAMP_CREATION: true },
    };
    let options = UpdateOptions::builder().upsert(true).build();
    let filtre = doc!{"challenge": &cookie.challenge};
    collection.update_many_with_session(filtre, ops, options, session).await?;
    Ok(cookie)
}

async fn commande_authentifier_webauthn<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
                                           -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("commande_authentifier_webauthn : {:?}", message.type_message);

    let idmg = middleware.idmg();
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: CommandeAuthentificationUsager = message_contenu.deserialize()?;

    let doc_webauth_state = match charger_challenge_authentification(
        middleware, &commande.user_id, &commande.hostname, &commande.challenge, session).await
    {
        Ok(inner) => inner,
        Err(e) => {
            error!("core_maitredescomptes.commande_authentifier_webauthn Challenge webauthn inconnu ou expire : {:?}", e);
            let reponse_ok = json!({"ok": false, "err": "Challenge inconnu ou expire", "code": 1});
            return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
        }
    };

    let mut passkey_authentication: PasskeyAuthenticationAjuste = doc_webauth_state.passkey_authentication.try_into()?;
    let flag_generer_nouveau_certificat = commande.commande_webauthn.demande_certificat.is_some();
    let demande_certificat = match commande.commande_webauthn.demande_certificat {
        Some(demande) => {
            debug!("commande_authentifier_usager Demande certificat recue : {:?}", demande);
            let hachage = demande.valider()?;
            debug!("commande_authentifier_usager Hachage calcule pour demande de certificat : {:?}", hachage);
            let challenge = &passkey_authentication.ast.challenge;
            debug!("commande_authentifier_usager Challenge existant : {:?} / {}", challenge, challenge.to_string());
            let mut vec_challenge_acjuste = Vec::new();
            vec_challenge_acjuste.extend_from_slice(&challenge.0[..]);
            vec_challenge_acjuste.extend(hachage);
            debug!("commande_authentifier_usager Hachage ajuste pour demande de certificat : {:?}", vec_challenge_acjuste);
            passkey_authentication.ast.challenge = Base64UrlSafeData::from(vec_challenge_acjuste);
            Some(demande)
        },
        None => None
    };

    // Verifier authentification
    let reg: PublicKeyCredential = commande.commande_webauthn.webauthn.try_into()?;
    let cred_id = reg.id.clone();
    debug!("commande_authentifier_usager Cred id : {}", cred_id);
    let resultat = match verifier_challenge_authentification(
        &commande.hostname, idmg, reg, passkey_authentication.try_into()?
    ) {
        Ok(inner) => inner,
        Err(e) => {
            error!("core_maitredescomptes.commande_authentifier_webauthn Erreur verification challenge webauthn : {:?}", e);
            let reponse_ok = json!({"ok": false, "err": "Erreur verification challenge webauthn", "code": 2});
            return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
        }
    };
    debug!("commande_authentifier_webauthn Resultat webauth OK : {:?}", resultat);

    // Supprimer challenge pour eviter reutilisation
    {
        let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
        let filtre = doc! {
            CHAMP_USER_ID: &commande.user_id,
            "hostname": &commande.hostname,
            "type_challenge": "authentication",
            "challenge": &commande.challenge,
        };
        collection.delete_one_with_session(filtre, None, session).await?;
    }

    // Conserver dernier acces pour la passkey
    {
        let collection = middleware.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
        let filtre = doc! {
            CHAMP_USER_ID: &commande.user_id,
            "hostname": &commande.hostname,
            "passkey.cred.cred_id": cred_id,
        };
        let ops = doc! { "$set": { CHAMP_DERNIER_AUTH: Utc::now() } };
        collection.update_one_with_session(filtre, ops, None, session).await?;
    }

    let mut reponse_ok = json!({
        "ok": true,
        "counter": resultat.counter(),
        "userVerification": resultat.user_verified(),
    });

    if let Some(demande_certificat) = demande_certificat {
        debug!("Generer le nouveau certificat pour l'usager et le retourner");
        let user_id = &commande.user_id;
        let csr = demande_certificat.csr;
        let compte_usager = match charger_compte_user_id(middleware, &commande.user_id, session).await {
            Ok(inner) => match inner {
                Some(inner) => inner,
                None => {
                    error!("core_maitredescomptes.commande_authentifier_webauthn Compte usager inconnu pour generer certificat");
                    let reponse_ok = json!({"ok": false, "err": "Compte usager inconnu pour generer nouveau certificat", "code": 3});
                    return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
                }
            },
            Err(e) => {
                error!("core_maitredescomptes.commande_authentifier_webauthn Erreur chargement compte usager pour generer certificat : {:?}", e);
                let reponse_ok = json!({"ok": false, "err": "Erreur verification challenge webauthn", "code": 4});
                return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
            }
        };
        let nom_usager = &compte_usager.nom_usager;
        // let securite = SECURITE_1_PUBLIC;
        let reponse_commande = signer_certificat_usager(
            middleware, nom_usager, user_id, csr, Some(&compte_usager)).await?;
        let reponse_ref = reponse_commande.parse()?;
        let message_contenu = reponse_ref.contenu()?;
        let info_certificat: ReponseSignatureCertificat = message_contenu.deserialize()?;
        if let Some(certificat) = info_certificat.certificat {
            // Inserer le certificat dans la reponse
            reponse_ok.as_object_mut().expect("as_object_mut")
                .insert("certificat".to_string(), certificat.into());
        }
    }

    if let Some(duree_session) = commande.commande_webauthn.duree_session {
        debug!("Creer cookie de session");
        match creer_session_cookie(middleware, &commande.user_id, &commande.hostname, duree_session, session).await {
            Ok(inner) => {
                reponse_ok.as_object_mut().expect("as_object_mut")
                    .insert("cookie".to_string(), inner.into());
            },
            Err(e) => {
                error!("Erreur creation cookie session : {:?}", e);
            }
        }
    }

    debug!("Reponse authentification : {:?}", reponse_ok);

    Ok(Some(middleware.build_reponse(reponse_ok)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSignerCertificat {
    // csr: String,

    // Si true, va emettre un evenement pour indiquer a un listener que le certificat est pret.
    // activation_tierce: Option<bool>,

    #[serde(rename="demandeCertificat")]
    demande_certificat: DemandeSignatureCertificatWebauthn,

    // Champs pour demande de signature avec preuve webauthn
    challenge: String,
    hostname: String,

    /// Reponse webauthn
    #[serde(rename="clientAssertionResponse")]
    client_assertion_response: ClientAssertionResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCertificatUsager {
    ok: bool,
    certificat: Vec<String>,
}

async fn signer_demande_certificat_usager<M>(middleware: &M, compte_usager: CompteUsager,
                                             demande_certificat: DemandeSignatureCertificatWebauthn,
                                             session: &mut ClientSession)
                                             -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    let nom_usager = &compte_usager.nom_usager;
    let user_id = &compte_usager.user_id;
    // let securite = Securite::L1Public.get_str();
    let reponse_commande = signer_certificat_usager(
        middleware, nom_usager, user_id, demande_certificat.csr, Some(&compte_usager)).await?;

    // Ajouter flag tiers si active d'un autre appareil que l'origine du CSR
    debug!("commande_signer_compte_usager Activation tierce : {:?}", demande_certificat.activation_tierce);
    if let Some(true) = demande_certificat.activation_tierce {
        // Calculer fingerprint du nouveau certificat
        let reponse_ref = reponse_commande.parse()?;
        let message_contenu = reponse_ref.contenu()?;
        let reponsecert_obj: ReponseCertificatUsager = message_contenu.deserialize()?;
        let pem = reponsecert_obj.certificat;
        let enveloppe_cert = middleware.charger_enveloppe(&pem, None, None).await?;
        let fingerprint_pk = enveloppe_cert.fingerprint_pk()?;

        // Donne le droit a l'usager de faire un login initial et enregistrer son appareil.
        let collection_activations = middleware.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
        let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FINGERPRINT_PK: &fingerprint_pk };
        let commande_set = doc! { "certificat": &pem };
        let commande_set_on_insert = doc! { CHAMP_USER_ID: user_id, CHAMP_FINGERPRINT_PK: &fingerprint_pk, CHAMP_CREATION: Utc::now() };
        let ops = doc! {
            "$set": commande_set,
            "$setOnInsert": commande_set_on_insert,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        let options = UpdateOptions::builder().upsert(true).build();
        let resultat_update_activations = collection_activations.update_one_with_session(filtre, ops, options, session).await?;
        debug!("commande_signer_compte_usager Update activations : {:?}", resultat_update_activations);

        // Emettre evenement de signature de certificat, inclus le nouveau certificat
        let evenement_activation = json!({
            "fingerprint_pk": fingerprint_pk,
            "certificat": &pem,
        });
        // domaine_action = 'evenement.MaitreDesComptes.' + ConstantesMaitreDesComptes.EVENEMENT_ACTIVATION_FINGERPRINTPK
        let routage_evenement = RoutageMessageAction::builder(
            DOMAIN_NAME, "activationFingerprintPk", vec![Securite::L2Prive])
            .partition(fingerprint_pk)
            // .user_id(user_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &evenement_activation).await?;

    } else {
        debug!("commande_signer_compte_usager Activation compte {} via meme appareil (pas tierce)", nom_usager);
    }

    debug!("commande_signer_compte_usager Reponse commande : {:?}", reponse_commande);

    Ok(Some(reponse_commande))    // Le message de reponse va etre emis par le module de signature de certificat
}

/// Verifie une demande de signature de certificat pour un compte usager
/// Emet une commande autorisant la signature lorsque c'est approprie
async fn commande_signer_compte_par_usager<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
                                              -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    // Utiliser user_id du cert.
    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner,
        None => {
            error!("commande_signer_compte_usager Doit etre signe par un certificat usager qui inclus le user_id");
            let reponse_ok = json!({"ok": false, "err": "Certificat invalide, doit inclure user_id", "code": 1});
            return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
        }
    };

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: CommandeSignerCertificat = message_contenu.deserialize()?;
    debug!("commande_signer_compte_usager CommandeSignerCertificat : {:?}", commande);

    // Charger le compte usager
    let compte_usager = match charger_compte_user_id(middleware, &user_id, session).await? {
        Some(inner) => inner,
        None => {
            let err = json!({"ok": false, "code": 3, "err": format!("Usager inconnu : {}", user_id)});
            debug!("signer_compte_usager usager inconnu : {:?}", err);
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("core_maitredescomptes.commande_signer_compte_usager Erreur preparation reponse : {:?}", e))?
            }
        }
    };

    // Charger le challenge d'authentification
    let doc_webauth_state= match charger_challenge_authentification(
        middleware, &user_id, &commande.hostname, &commande.challenge, session).await
    {
        Ok(inner) => inner,
        Err(e) => {
            error!("commande_signer_compte_usager Challenge webauthn inconnu ou expire : {:?}", e);
            let reponse_ok = json!({"ok": false, "err": "Challenge inconnu ou expire", "code": 1});
            return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
        }
    };

    let reg = commande.client_assertion_response.try_into()?;

    let (passkey_authentication, demande_certificat) = {
        let mut passkey_authentication: PasskeyAuthenticationAjuste = doc_webauth_state.passkey_authentication.try_into()?;
        let demande = commande.demande_certificat;

        debug!("commande_authentifier_usager Demande certificat recue : {:?}", demande);
        let hachage = demande.valider()?;
        debug!("commande_authentifier_usager Hachage calcule pour demande de certificat : {:?}", hachage);
        let challenge = &passkey_authentication.ast.challenge;
        debug!("commande_authentifier_usager Challenge existant : {:?} / {}", challenge, challenge.to_string());
        let mut vec_challenge_acjuste = Vec::new();
        vec_challenge_acjuste.extend_from_slice(&challenge.0[..]);
        vec_challenge_acjuste.extend(hachage);
        debug!("commande_authentifier_usager Hachage ajuste pour demande de certificat : {:?}", vec_challenge_acjuste);
        passkey_authentication.ast.challenge = Base64UrlSafeData::from(vec_challenge_acjuste);

        (passkey_authentication, demande)
    };

    let idmg = middleware.idmg();
    let hostname = commande.hostname.as_str();
    let resultat = match verifier_challenge_authentification(
        commande.hostname, idmg, reg, passkey_authentication.try_into()?
    ) {
        Ok(inner) => inner,
        Err(e) => {
            error!("commande_signer_compte_usager Erreur verification challenge webauthn : {:?}", e);
            let reponse_ok = json!({"ok": false, "err": "Erreur verification challenge webauthn", "code": 2});
            return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
        }
    };

    debug!("commande_signer_compte_usager Resultat validation webauthn OK : {:?}", resultat);
    signer_demande_certificat_usager(middleware, compte_usager, demande_certificat, session).await
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeAjouterCsrRecovery {
    csr: String,
    #[serde(rename="nomUsager")]
    nom_usager: String,
}

/// Ajouter un CSR pour recuperer un compte usager
async fn commande_ajouter_csr_recovery<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("commande_ajouter_csr_recovery : {:?}", message);

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: CommandeAjouterCsrRecovery = message_contenu.deserialize()?;
    debug!("commande_ajouter_csr_recovery CommandeAjouterCsrRecovery : {:?}", commande);

    let csr = commande.csr;
    let nom_usager = commande.nom_usager;

    // Charger CSR et calculer fingerprint, code.
    let csr_parsed = charger_csr(csr.as_str())?;
    let csr_subject = get_csr_subject(&csr_parsed.as_ref())?;
    let common_name = match csr_subject.get("commonName") {
        Some(n) => n,
        None => {
            let reponse = json!({"ok": false, "err": "Common Name absent du CSR"});
            return Ok(Some(middleware.build_reponse(reponse)?.0));
        }
    };

    let cle_publique = csr_parsed.public_key()?;
    let fingerprint = calculer_fingerprint_pk(&cle_publique)?;
    let code = {
        let len_fingerprint = fingerprint.len();
        let fingerprint_lc = fingerprint.to_lowercase();
        let code_part1 = &fingerprint_lc[len_fingerprint - 8..len_fingerprint - 4];
        let code_part2 = &fingerprint_lc[len_fingerprint - 4..len_fingerprint];
        let code = format!("{}-{}", code_part1, code_part2);
        debug!("Code : {}", code);
        code
    };

    let date_courante = Utc::now();
    let filtre = doc! {
        "code": &code,
        "nomUsager": &nom_usager,
    };
    let ops = doc! {
        "$set": {
            "csr": &csr,
        },
        "$setOnInsert": {
            "code": &code,
            "nomUsager": &nom_usager,
            CHAMP_CREATION: &date_courante,
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let options = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_RECOVERY)?;
    let resultat = collection.update_one_with_session(filtre, ops, Some(options), session).await?;

    let reponse = json!({"ok": true, "code": &code});
    match middleware.build_reponse(reponse) {
        Ok(m) => return Ok(Some(m.0)),
        Err(e) => Err(format!("Erreur preparation reponse commande_ajouter_csr_recovery : {:?}", e))?
    }
}

#[derive(Deserialize)]
struct CommandeGenererChallenge {
    #[serde(rename="userId")]
    user_id: Option<String>,
    hostname: String,
    delegation: Option<bool>,
    #[serde(rename="webauthnRegistration")]
    webauthn_registration: Option<bool>,
    #[serde(rename="webauthnAuthentication")]
    webauthn_authentication: Option<bool>,
}

#[derive(Serialize)]
struct ReponseCommandeGenererChallenge {
    challenge: Option<String>,
    registration_challenge: Option<CreationChallengeResponse>,
    authentication_challenge: Option<RequestChallengeResponse>,
    passkey_authentication: Option<PasskeyAuthentication>,
}

async fn preparer_challenge_generique<M,S,C>(middleware: &M, compte: &CompteUsager, hostname: S, type_challenge: C, session: &mut ClientSession)
                                             -> Result<DocChallenge, millegrilles_common_rust::error::Error>
where M: MongoDao + ValidateurX509, S: AsRef<str>, C: Into<String>
{
    let hostname = hostname.as_ref();
    let user_id = compte.user_id.as_str();
    let type_challenge = type_challenge.into();

    // Genrer un challenge de 32 bytes
    let valeur_challenge =  {
        let mut buffer_random = [0u8; 32];
        openssl::rand::rand_bytes(&mut buffer_random).expect("rand");
        let challenge = buffer_random.to_vec();
        Base64UrlSafeData::from(challenge)
    };

    // Sauvegarder challenge
    let doc_challenge = DocChallenge::new_challenge_generique(user_id, hostname, valeur_challenge, type_challenge);
    let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let doc_passkey = convertir_to_bson(&doc_challenge)?;
    collection.insert_one_with_session(doc_passkey, None, session).await?;

    Ok(doc_challenge)
}

async fn preparer_registration_webauthn<M,S>(middleware: &M, compte: &CompteUsager, hostname: S, session: &mut ClientSession)
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
    let doc_registration: DocChallenge = match collection.find_one_with_session(filtre, None, session).await? {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => {
            let (challenge, registration) = generer_challenge_registration(
                rp_origin.as_str(), nom_usager, &user_uuid, idmg, None::<&Vec<&str>>, // existing_credentials
            )?;
            let doc_registration = DocChallenge::new_challenge_resgistration(
                user_id, user_uuid, hostname, challenge, registration);

            // Sauvegarder dans la base de donnees
            let doc_bson = convertir_to_bson(&doc_registration)?;
            collection.insert_one_with_session(doc_bson, None, session).await?;

            doc_registration
        }
    };

    Ok(doc_registration)
}

async fn commande_generer_challenge<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
                                       -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("commande_generer_challenge : {:?}", message.type_message);

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: CommandeGenererChallenge = message_contenu.deserialize()?;
    let hostname = commande.hostname.as_str();

    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => {
            if let Some(user_id) = commande.user_id {
                if message.certificat.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege])? {
                    user_id
                } else {
                    Err(format!("core_maitredescomptes.commande_generer_challenge Erreur message non autorise"))?
                }
            } else {
                Err(format!("core_maitredescomptes.commande_generer_challenge Erreur message sans user_id"))?
            }
        }
    };

    let compte = {
        let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
        let filtre = doc! { CHAMP_USER_ID: &user_id };
        let resultat = match collection.find_one_with_session(filtre, None, session).await? {
            Some(inner) => inner,
            None => {
                let reponse = json!({"ok": true, "code": 1, "err": "Usager inconnu"});
                match middleware.build_reponse(reponse) {
                    Ok(m) => return Ok(Some(m.0)),
                    Err(e) => Err(format!("Erreur preparation reponse commande_generer_challenge : {:?}", e))?
                }
            }
        };
        convertir_bson_deserializable(resultat)?
    };

    let mut reponse = ReponseCommandeGenererChallenge {
        challenge: None,
        registration_challenge: None,
        authentication_challenge: None,
        passkey_authentication: None,
    };

    if let Some(true) = commande.delegation {
        let doc_challenge = preparer_challenge_generique(middleware, &compte, hostname, "delegation", session).await?;
        reponse.challenge = Some(doc_challenge.challenge);
    }

    if let Some(true) = commande.webauthn_registration {
        let doc_challenge = match preparer_registration_webauthn(middleware, &compte, hostname, session).await {
            Ok(inner) => inner,
            Err(e) => Err(millegrilles_common_rust::error::Error::String(format!("core_maitredescomptes.commande_generer_challenge Erreur {:?}", e)))?
        };
        reponse.registration_challenge = Some(doc_challenge.webauthn_registration.expect("webauthn_registration").registration_challenge);
    }

    if let Some(true) = commande.webauthn_authentication {
        match preparer_authentification_webauthn(middleware, &compte, hostname, session).await? {
            Some(inner) => {
                let challenge = inner.webauthn_authentication.expect("webauthn_authentication");
                reponse.authentication_challenge = Some(challenge.authentication_challenge);
                reponse.passkey_authentication = Some(challenge.passkey_authentication);
            },
            None => {
                error!("commande_generer_challenge Aucun credential webauthn pour l'usager");
            }
        };
    }

    Ok(Some(middleware.build_reponse(reponse)?.0))
}

async fn preparer_authentification_webauthn<M,S>(middleware: &M, compte: &CompteUsager, hostname: S, session: &mut ClientSession)
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
    let mut curseur = collection.find_with_session(filtre, None, session).await?;
    while let Some(r) = curseur.next(session).await {
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
    collection.insert_one_with_session(doc_passkey, None, session).await?;

    Ok(Some(doc_challenge))
}

async fn supprimer_cookie<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
                             -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("supprimer_cookie : {:?}", message.type_message);

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: RequeteGetCookieUsager = message_contenu.deserialize()?;
    let filtre = doc!{
        "user_id": commande.user_id,
        "hostname": commande.hostname,
        "challenge": commande.challenge,
    };
    let collection = middleware.get_collection(NOM_COLLECTION_COOKIES)?;
    collection.delete_one_with_session(filtre, None, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn commande_supprimer_cles<M>(middleware: &M, message: MessageValide, gestionnaire: &MaitreDesComptesManager, session: &mut ClientSession)
                                        -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer commande_supprimer_cles : {:?}", &message.type_message);

    // Valider contenu
    let _commande: TransactionSupprimerCles = deser_message_buffer!(message.message);
    // let user_id = commande.user_id.as_str();

    // Commande valide, on sauvegarde et traite la transaction
    sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire, session).await
    // let _ = transaction_supprimer_cles(middleware, message.try_into()?).await?;
    // marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &uuid_transaction, EtatTransaction::Complete).await?;
    //
    // Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn commande_reset_webauthn_usager<M>(middleware: &M, gestionnaire: &MaitreDesComptesManager, message: MessageValide, session: &mut ClientSession)
                                           -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("commande_reset_webauthn_usager Consommer commande : {:?}", &message.type_message);
    // Verifier autorisation
    if !message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("commande_reset_webauthn_usager autorisation acces refuse : {:?}", err);
        match middleware.build_reponse(err) {
            Ok(m) => return Ok(Some(m.0)),
            Err(e) => Err(format!("Erreur preparation reponse (1) ajouter_delegation_signee : {:?}", e))?
        }
    }

    // Valider contenu en faisant le mapping
    let commande_resultat: CommandeResetWebauthnUsager = {
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        match message_contenu.deserialize() {
            Ok(c) => c,
            Err(e) => {
                let reponse = json!({"ok": false, "code": 2, "err": format!("Format de la commande invalide : {:?}", e)});
                return Ok(Some(middleware.build_reponse(reponse)?.0))
            }
        }
    };

    let user_id = commande_resultat.user_id.as_str();

    // Executer la transaction. S'occupe des elements persistants (cles webauthn)
    let resultat_transaction = sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire, session).await?;

    // Traiter les elements volatils (activations, cookies)

    if let Some(true) = commande_resultat.reset_webauthn {
        // Supprimer activations
        let filtre = doc! { CHAMP_USER_ID: user_id };
        let collection = middleware.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
        if let Err(e) = collection.delete_many_with_session(filtre, None, session).await {
            Err(format!("commande_reset_webauthn_usager Erreur delete_many activations {:?} : {:?}", commande_resultat, e))?
        }
    }

    if let Some(true) = commande_resultat.evict_all_sessions {
        // Supprimer les cookies de sessions longue duree, emettre evenement evict
        {
            let filtre = doc! { "user_id": user_id };
            let collection = middleware.get_collection(NOM_COLLECTION_COOKIES)?;
            if let Err(e) = collection.delete_many_with_session(filtre, None, session).await {
                Err(format!("commande_reset_webauthn_usager Erreur delete_many cookies {:?} : {:?}", commande_resultat, e))?
            }
        }

        // Emettre message pour fermer toutes les sessions en cours de l'usager
        let routage = RoutageMessageAction::builder(DOMAIN_NAME, EVENEMENT_EVICT_USAGER, vec![Securite::L1Public])
            .build();
        let message = json!({CHAMP_USER_ID: user_id});
        middleware.emettre_evenement(routage, &message).await?;
    }

    Ok(resultat_transaction)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSignerCertificatParProprietaire {
    #[serde(rename="userId")]
    user_id: String,
    #[serde(rename="demandeCertificat")]
    demande_certificat: DemandeSignatureCertificatWebauthn,
}

async fn commande_signer_compte_par_proprietaire<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
                                                    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    // Verifier autorisation, pour certificats systemes (Prive), charger param user_id.
    let est_delegation_proprietaire = message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
    if ! est_delegation_proprietaire {
        error!("commande_signer_compte_par_proprietaire Doit etre signe par un certificat avec delegation globale 'proprietaire'");
        let reponse_ok = json!({"ok": false, "err": "Certificat invalide, doit etre proprietaire", "code": 1});
        return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
    }
    debug!("commande_signer_compte_par_proprietaire Resultat validation delegation proprietaire OK");

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: CommandeSignerCertificatParProprietaire = message_contenu.deserialize()?;
    debug!("commande_signer_compte_par_proprietaire CommandeSignerCertificatParProprietaire : {:?}", commande);

    let user_id = commande.user_id.as_str();

    // Charger le compte usager
    let compte_usager = match charger_compte_user_id(middleware, user_id, session).await? {
        Some(inner) => inner,
        None => {
            let err = json!({"ok": false, "code": 2, "err": format!("Usager inconnu : {}", user_id)});
            debug!("commande_signer_compte_par_proprietaire usager inconnu : {:?}", err);
            match middleware.build_reponse(err) {
                Ok(m) => return Ok(Some(m.0)),
                Err(e) => Err(format!("core_maitredescomptes.commande_signer_compte_par_proprietaire Erreur preparation reponse : {:?}", e))?
            }
        }
    };

    signer_demande_certificat_usager(middleware, compte_usager, commande.demande_certificat, session).await
}

#[derive(Deserialize)]
struct CommandeGenererOtp {
    // #[serde(rename="userId")]
    // user_id: Option<String>,
    username: String,
    hostname: String,
    // delegation: Option<bool>,
}

#[derive(Serialize)]
struct ResponseGenerateOtp {
    correlation: String,
    qr_base64: String,
}

async fn command_generate_otp<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("command_generate_otp : {:?}", message.type_message);

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: CommandeGenererOtp = message_contenu.deserialize()?;
    let username = commande.username.as_str();
    let hostname = commande.hostname.as_str();

    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => Err(format!("core_maitredescomptes.commande_generer_challenge Erreur message sans user_id"))?
    };

    let compte: CompteUsager = {
        let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
        let filtre = doc! { CHAMP_USER_ID: &user_id };
        let resultat = match collection.find_one_with_session(filtre, None, session).await? {
            Some(inner) => inner,
            None => {
                let reponse = json!({"ok": true, "code": 1, "err": "Usager inconnu"});
                match middleware.build_reponse(reponse) {
                    Ok(m) => return Ok(Some(m.0)),
                    Err(e) => Err(format!("Erreur preparation reponse commande_generer_challenge : {:?}", e))?
                }
            }
        };
        convertir_bson_deserializable(resultat)?
    };

    // Generate a new temporary TOTP for user_id
    let secret = Secret::generate_secret();

    // Save the user_id/secret for potential new TOTP credentials.
    let secret_string = secret.to_string();
    debug!("command_generate_otp New secret: {:?}", secret_string);

    let authenticator_id = format!("{}", username);

    let totp = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some(hostname.to_string()),
        authenticator_id
    ).unwrap();

    let totp_url = totp.get_url();
    debug!("TOTP url: {}", totp_url);
    // Hash the url to obfuscate the secret
    let challenge_hashvalue = base64_url::encode(&hacher_bytes(totp_url.as_bytes(), HachageCode::Blake2s256));

    let challenge_row = DocChallenge::new_challenge_totp(&user_id, hostname, &challenge_hashvalue, totp_url);
    let collection = middleware.get_collection_typed::<DocChallenge>(NOM_COLLECTION_CHALLENGES)?;
    collection.insert_one_with_session(challenge_row, None, session).await?;

    // let token = totp.generate_current().unwrap();
    let qr_base64 = totp.get_qr_base64().expect("totp.get_qr_base64");
    debug!("New TOTP base 64 QR: {}", qr_base64);
    let reponse = ResponseGenerateOtp {correlation: challenge_hashvalue, qr_base64};

    Ok(Some(middleware.build_reponse_chiffree(reponse, message.certificat.as_ref())?.0))
}

async fn command_register_otp<M>(middleware: &M, message: MessageValide, gestionnaire: &MaitreDesComptesManager, session: &mut ClientSession)
                                 -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("command_add_otp : {:?}", &message.type_message);
    // Verify authorization
    let user_id = match message.certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => Err(format!("command_add_otp No user_id on certificate"))?
    };

    // Validate content by deserializing
    let command = {
        let message_ref = message.message.parse()?;
        match message_ref.contenu()?.deserialize::<CommandRegisterOtp>() {
            Ok(inner) => inner,
            Err(e) => return Ok(Some(middleware.reponse_err(Some(1), None, Some(format!("Invalid message parameters: {:?}", e).as_str()))?))
        }
    };

    let filter = doc!{"userId": &user_id, "type_challenge": "totp", "hostname": &command.hostname, "challenge": &command.correlation};
    debug!("Loading TOTP challenge with: {:?}", filter);
    let collection = middleware.get_collection_typed::<DocChallenge>(NOM_COLLECTION_CHALLENGES)?;
    let challenge = match collection.find_one_with_session(filter, None, session).await {
        Ok(Some(inner)) => inner,
        Ok(None) => return Ok(Some(middleware.reponse_err(Some(404), None, Some("Challenge not found"))?)),
        Err(e) => return Ok(Some(middleware.reponse_err(Some(500), None, Some(format!("Error loading challenge: {:?}", e).as_str()))?))
    };

    let totp_url = match challenge.totp_url {
        Some(inner) => inner,
        None => return Ok(Some(middleware.reponse_err(Some(500), None, Some("TOTP challeng information lost"))?))
    };

    let totp = match TOTP::from_url(&totp_url) {
        Ok(inner) => inner,
        Err(e) => Err(format!("TOTP URL loading error: {:?}", e))?
    };

    let current_code = match totp.check_current(command.code.as_str()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("TOTP checking error - invalid time: {:?}", e))?
    };

    if ! current_code {
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("TOTP code is invalid"))?))
    }

    // Process new transaction
    let transaction = TransactionRegisterOtp {
        user_id,
        hostname: command.hostname,
        totp_url,
    };

    sauvegarder_traiter_transaction_serializable_v2(middleware, &transaction, gestionnaire, session,
                                                    DOMAINE_NOM_MAITREDESCOMPTES, TRANSACTION_REGISTER_OTP).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandAuthenticateOtp {
    #[serde(rename = "userId")]
    user_id: String,
    hostname: String,
    #[serde(rename = "totpCode")]
    totp_code: String,
    #[serde(rename = "certificateRequest")]
    certificate_request: Option<DemandeSignatureCertificatWebauthn>,
    #[serde(rename = "sessionDuration", skip_serializing_if = "Option::is_none")]
    session_duration: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct TotpAuthenticationResponse {
    ok: bool,
    user_verified: bool,
    cookie: Option<CookieSession>,
    certificat: Option<Vec<String>>,
}

async fn command_authenticate_otp<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("command_authenticate_otp : {:?}", message.type_message);

    let idmg = middleware.idmg();
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let command: CommandAuthenticateOtp = message_contenu.deserialize()?;

    debug!("TOTP authentication command: {:?}", command);

    let totp_code = command.totp_code;

    // Test the code with all registered TOTP codes for this user_id/hostname.
    let collection = middleware.get_collection_typed::<TotpCredentialsRow>(NOM_COLLECTION_TOTP_CREDENTIALS)?;
    let filtre = doc!{"user_id": &command.user_id, "hostname": &command.hostname};
    let mut cursor = collection.find(filtre, None).await?;
    let mut valid = false;
    let mut totp_url_used = None;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let totp = match TOTP::from_url(&row.totp_url) {
            Ok(inner) => inner,
            Err(e) => {
                warn!("command_authenticate_otp Error loading TOTP URL for user_id:{}, hostname:{}: {:?}", row.user_id, row.hostname, e);
                continue;
            }
        };
        match totp.check_current(totp_code.as_str()) {
            Ok(true) => {
                valid = true;  // Code is verified and valid
                totp_url_used = Some(row.totp_url);
                break
            }
            Ok(false) => continue,
            Err(e) => {
                warn!("command_authenticate_otp Error validating TOTP code: {:?}", e);
                continue
            }
        }
    }

    if ! valid {
        // No valid TOTP url, rejecting
        return Ok(Some(middleware.reponse_err(Some(401), None, Some("Invalid TOTP code"))?));
    }

    // Conserver dernier acces pour la passkey
    {
        let collection = middleware.get_collection(NOM_COLLECTION_TOTP_CREDENTIALS)?;
        let filtre = doc! {
            CHAMP_USER_ID: &command.user_id,
            "hostname": &command.hostname,
            "totp_url": &totp_url_used,
        };
        let ops = doc! { "$set": { CHAMP_DERNIER_AUTH: Utc::now() } };
        collection.update_one_with_session(filtre, ops, None, session).await?;
    }

    let mut reponse_ok = TotpAuthenticationResponse {ok: true, user_verified: true, cookie: None, certificat: None};

    if let Some(certificate_request) = command.certificate_request {
        debug!("Generer le nouveau certificat pour l'usager et le retourner");
        let user_id = &command.user_id;
        let csr = certificate_request.csr;
        let compte_usager = match charger_compte_user_id(middleware, &command.user_id, session).await {
            Ok(inner) => match inner {
                Some(inner) => inner,
                None => {
                    error!("core_maitredescomptes.commande_authentifier_webauthn Compte usager inconnu pour generer certificat");
                    let reponse_ok = json!({"ok": false, "err": "Compte usager inconnu pour generer nouveau certificat", "code": 3});
                    return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
                }
            },
            Err(e) => {
                error!("core_maitredescomptes.commande_authentifier_webauthn Erreur chargement compte usager pour generer certificat : {:?}", e);
                let reponse_ok = json!({"ok": false, "err": "Erreur verification challenge webauthn", "code": 4});
                return Ok(Some(middleware.build_reponse(reponse_ok)?.0))
            }
        };
        let nom_usager = &compte_usager.nom_usager;
        // let securite = SECURITE_1_PUBLIC;
        let reponse_commande = signer_certificat_usager(
            middleware, nom_usager, user_id, csr, Some(&compte_usager)).await?;
        let reponse_ref = reponse_commande.parse()?;
        let message_contenu = reponse_ref.contenu()?;
        let info_certificat: ReponseSignatureCertificat = message_contenu.deserialize()?;
        if let Some(certificate) = info_certificat.certificat {
            // Inserer le certificat dans la reponse
            reponse_ok.certificat = Some(certificate);
        }
    }

    if let Some(session_duration) = command.session_duration {
        debug!("Creer cookie de session");
        match creer_session_cookie(middleware, &command.user_id, &command.hostname, session_duration, session).await {
            Ok(inner) => {
                reponse_ok.cookie = Some(inner);
            },
            Err(e) => {
                error!("Erreur creation cookie session : {:?}", e);
            }
        }
    }

    Ok(Some(middleware.build_reponse(reponse_ok)?.0))
}
