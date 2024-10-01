use log::{debug, warn};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageValidable};
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::{hex, serde_json};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, CHAMP_CREATION, CHAMP_MODIFICATION};
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use millegrilles_common_rust::serde_json::json;
use crate::maitredescomptes_common::{emettre_maj_compte_usager, sauvegarder_credential};
use crate::maitredescomptes_constants::*;
use crate::maitredescomptes_structs::{CommandeAjouterDelegationSignee, CommandeResetWebauthnUsager, ConfirmationSigneeDelegationGlobale, TransactionInscrireUsager, TransactionMajUsagerDelegations, TransactionSupprimerCles};
use crate::webauthn::CredentialWebauthn;

pub async fn aiguillage_transaction_maitredescomptes<M, T>(middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: TryInto<TransactionValide>
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(String::from("aiguillage_transaction Erreur try_into"))?
    };

    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.to_owned(),
            None => Err(String::from("aiguillage_transaction Action manquante de la transaction"))?
        },
        None => Err(String::from("aiguillage_transaction Routage manquant de la transaction"))?
    };

    match action.as_str() {
        TRANSACTION_INSCRIRE_USAGER => sauvegarder_inscrire_usager(middleware, transaction).await,
        TRANSACTION_AJOUTER_CLE => transaction_ajouter_cle(middleware, transaction).await,
        TRANSACTION_AJOUTER_DELEGATION_SIGNEE => transaction_ajouter_delegation_signee(middleware, transaction).await,
        TRANSACTION_MAJ_USAGER_DELEGATIONS => transaction_maj_usager_delegations(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_CLES => transaction_supprimer_cles(middleware, transaction).await,
        TRANSACTION_RESET_WEBAUTHN_USAGER => transaction_reset_webauthn_usager(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.transaction.id, action))?,
    }
}

pub async fn transaction_ajouter_delegation_signee<M>(middleware: &M, transaction: TransactionValide)
                                                      -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    // let escaped_transaction: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let commande: CommandeAjouterDelegationSignee = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur conversion en CommandeAjouterCle : {:?}", e))?
    };

    let user_id_option = match transaction.certificat.get_user_id()? {
        Some(inner) => Some(inner.to_owned()),
        None => match commande.user_id { Some(inner) => Some(inner.to_owned()), None => None }
    };

    let user_id = match user_id_option.as_ref() {
        Some(inner) => inner.as_str(),
        None => Err(String::from("transaction_ajouter_delegation_signee User_id None"))?
    };

    // Valider contenu
    // let message_confirmation_buf = MessageMilleGrillesBufferDefault::from(Vec::from(commande.confirmation.as_bytes()));
    // let mut message_confirmation = message_confirmation_buf.parse()?;
    let mut message_confirmation = commande.confirmation;

    // Valider la signature de la cle de millegrille
    // let (signature, hachage) = match message_confirmation.verifier_contenu() {
    //     Ok(inner) => inner,
    //     Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur verifier_contenu : {:?}", e))?
    // };
    // if signature != true || hachage != true {
    //     Err(format!("transaction_ajouter_delegation_signee Permission refusee, signature/hachage confirmation invalides"))?
    // }
    if let Err(e) = message_confirmation.verifier_signature() {
        Err(format!("transaction_ajouter_delegation_signee Permission refusee, signature/hachage confirmation invalides : {}", e))?
    }

    // Valider la pubkey, elle doit correspondre au certificat de la MilleGrille.
    let public_key_millegrille = match middleware.ca_cert().public_key() {
        Ok(inner) => match inner.raw_public_key() {
            Ok(inner) => inner,
            Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur raw_public_key {:?}", e))?
        },
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur raw_public_key {:?}", e))?
    };

    let public_key_recue = match hex::decode(&message_confirmation.pubkey) {
        Ok(inner) => inner,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur hex::decode {:?}", e))?
    } ;
    if public_key_recue != public_key_millegrille {
        Err(format!("transaction_ajouter_delegation_signee Permission refusee, pubkey n'est pas la cle de la MilleGrille"))?
    }

    debug!("transaction_ajouter_delegation_signee {:?}", message_confirmation.routage);
    // let message_confirmation_contenu = match message_confirmation.contenu() {
    //     Ok(inner) => inner,
    //     Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur map contenu() : {:?}", e))?
    // };
    let commande_ajouter_delegation: ConfirmationSigneeDelegationGlobale = match message_confirmation.deserialize() {
        Ok(inner) => inner,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur map_contenu : {:?}", e))?
    };
    debug!("commande_ajouter_delegation_signee Commande ajouter delegation verifiee {:?}", commande_ajouter_delegation);

    // Le filtre agit a la fois sur le nom usager (valide par la cle) et le user_id (valide par serveur)
    let filtre = doc! {
        CHAMP_USER_ID: user_id,
        CHAMP_USAGER_NOM: commande_ajouter_delegation.nom_usager.as_str(),
    };
    let now_epoch = Utc::now().timestamp();
    let ops = doc! {
        "$set": {"delegation_globale": "proprietaire", "delegations_date": now_epoch},
        "$inc": {CHAMP_DELEGATION_VERSION: 1},
        "$currentDate": { CHAMP_MODIFICATION: true }
    };

    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur maj pour usager {:?} : {:?}", message_confirmation.routage, e))?
    };
    debug!("transaction_ajouter_delegation_signee resultat {:?}", resultat);
    if resultat.matched_count == 1 {
        Ok(None)
    } else {
        Err(format!("transaction_ajouter_delegation_signee Aucun match pour usager {:?}", user_id))?
    }
}

async fn sauvegarder_inscrire_usager<M>(middleware: &M, transaction: TransactionValide)
                                        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("sauvegarder_inscrire_usager {:?}", transaction.transaction.id);
    // let escaped_transaction: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let transaction: TransactionInscrireUsager = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion en TransactionInscrireUsager : {:?}", e))?
    };
    let nom_usager = transaction.nom_usager.as_str();
    let user_id = transaction.user_id.as_str();

    // let fingerprint_pk = match transaction.csr.as_ref() {
    //     Some(csr) => match csr_calculer_fingerprintpk(csr.as_str()) {
    //         Ok(fp) => fp,
    //         Err(e) => {
    //             error!("Erreur calcul fingerprint_pk du csr, on utilise fingerprint fourni : {:?}", e);
    //             transaction.fingerprint_pk.clone()
    //         }
    //     },
    //     None => transaction.fingerprint_pk.clone()
    // };

    let filtre = doc! {CHAMP_USAGER_NOM: nom_usager};
    let ops = doc! {
        "$set": {
            CHAMP_USER_ID: user_id,
            // format!("{}.{}", CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk): {
            //     "associe": false,
            //     "date_activation": Utc::now(),
            // },
        },
        "$setOnInsert": {
            CHAMP_USAGER_NOM: nom_usager,
            CHAMP_CREATION: Utc::now(),
            CHAMP_DELEGATION_VERSION: 1,
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let options = UpdateOptions::builder().upsert(true).build();

    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let resultat = match collection.update_one(filtre, ops, options).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur update db sauvegarder_inscrire_usager : {:?}", e))?
    };
    debug!("Resultat sauvegarder_inscrire_usager : {:?}", resultat);

    if let Err(e) = emettre_maj_compte_usager(middleware, user_id, None).await {
        warn!("commande_maj_usager_delegations Erreur emission evenement maj : {:?}", e);
    }

    let reponse = json!({"ok": true, "userId": user_id});
    match middleware.build_reponse(reponse) {
        Ok(m) => return Ok(Some(m.0)),
        Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
    }
}

async fn transaction_ajouter_cle<M>(middleware: &M, transaction: TransactionValide)
                                    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let certificat = transaction.certificat.as_ref();

    if ! certificat.verifier_exchanges(vec![Securite::L4Secure])? ||
        ! certificat.verifier_domaines(vec![DOMAIN_NAME.to_string()])? ||
        ! certificat.verifier_roles(vec![RolesCertificats::Core])? {
        Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur exchanges/domaines/roles non autorise - SKIP"))?
    }

    // let escaped_transaction: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let transaction_contenu: CredentialWebauthn = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur conversion en TransactionAjouterCle : {:?}", e))?
    };

    // Retirer flag reset_cles si preset
    let reset_cles = match transaction_contenu.reset_cles {
        Some(inner) => inner,
        None => false
    };

    let user_id = transaction_contenu.user_id.as_str();
    let hostname = transaction_contenu.hostname.as_str();
    let webauthn_credential = transaction_contenu.passkey;
    let cred_id = webauthn_credential.cred_id().to_string();

    let collection = middleware.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
    if reset_cles {
        // Supprimer toutes les cles pour le user_id dans la collection credentials
        debug!("transaction_ajouter_cle Reset toutes les cles webautn pour user_id {}", user_id);
        let filtre = doc! { CHAMP_USER_ID: user_id };
        if let Err(e) = collection.delete_many(filtre, None).await {
            Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur delete cles webauthn"))?
        }
    }

    let mut inserer = reset_cles;
    if ! inserer {
        // Verifier si la cle existe deja
        let filtre = doc! { CHAMP_USER_ID: user_id, "hostname": hostname, "passkey.cred.cred_id": cred_id};
        let resultat = match collection.count_documents(filtre, None).await {
            Ok(inner) => inner,
            Err(e) => Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur count cles existantes : {:?}", e))?
        };
        if resultat == 0 { inserer = true }
    }
    if inserer {
        if let Err(e) = sauvegarder_credential(
            middleware, user_id, hostname, webauthn_credential, true).await {
            Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur sauvegarder credentials : {:?}", e))?
        }
    } else {
        debug!("transaction_ajouter_cle Credential existe deja - OK");
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn transaction_maj_usager_delegations<M>(middleware: &M, transaction: TransactionValide)
                                                   -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    // let escaped_transaction: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let commande: TransactionMajUsagerDelegations = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion en CommandeAjouterDelegationSignee : {:?}", e))?
    };
    let user_id = commande.user_id.as_str();

    let now_epoch = Utc::now().timestamp();

    let filtre = doc! {CHAMP_USER_ID: user_id};
    let set_ops = doc! {
        CHAMP_COMPTE_PRIVE: commande.compte_prive,
        CHAMP_DELEGATION_GLOBALE: commande.delegation_globale,
        CHAMP_DELEGATION_DATE: now_epoch,
    };
    let ops = doc! {
        "$set": set_ops,
        "$inc": {CHAMP_DELEGATION_VERSION: 1},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur transaction_maj_usager_delegations, echec sauvegarde : {:?}", e))?
    };
    debug!("Resultat commande_maj_usager_delegations : {:?}", resultat);

    if resultat.matched_count != 1 {
        Err(format!("Erreur transaction_maj_usager_delegations usager {} non trouve", user_id))?
    }

    Ok(None)
}

pub async fn transaction_supprimer_cles<M>(middleware: &M, transaction: TransactionValide)
                                           -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let commande: TransactionSupprimerCles = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion en CommandeAjouterDelegationSignee : {:?}", e))?
    };

    let filtre = doc! {CHAMP_USER_ID: &commande.user_id};
    let ops = doc! {
        "$unset": {CHAMP_WEBAUTHN: true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("transaction_supprimer_cles Erreur maj collection usagers {:?}", e))?
    } ;
    debug!("transaction_supprimer_cles resultat : {:?}", resultat);

    Ok(None)
}

async fn transaction_reset_webauthn_usager<M>(middleware: &M, transaction: TransactionValide)
                                              -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    // let escaped_transaction: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let commande: CommandeResetWebauthnUsager = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_reset_webauthn_usager Erreur conversion en CommandeResetWebauthnUsager : {:?}", e))?
    };

    debug!("transaction_reset_webauthn_usager {:?}", commande);

    if let Some(true) = commande.reset_webauthn {
        // Supprimer cles webauthn et activations

        let filtre = doc! { CHAMP_USER_ID: commande.user_id.as_str() };
        let collection = middleware.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
        if let Err(e) = collection.delete_many(filtre.clone(), None).await {
            Err(format!("transaction_reset_webauthn_usager Erreur delete_many webauthn {:?} : {:?}", commande, e))?
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}
