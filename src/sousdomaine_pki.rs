use std::convert::TryFrom;
use std::sync::Arc;

use bson::Document;
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use millegrilles_common_rust::certificats::{charger_enveloppe, ValidateurX509};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{formatter_message_certificat, MiddlewareDbPki, upsert_certificat};
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, Transaction, transmettre_evenement_persistance};
use mongodb::bson::doc;
use tokio::sync::mpsc::Receiver;
use serde::Serialize;
use serde_json::{Value, Map, json};

pub async fn preparer_index_mongodb(middleware: &impl MongoDao) -> Result<(), String> {

    // Index transactions
    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from("uuid_transaction")),
        unique: true
    };
    let champs_index_transactions = vec!(
        ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION), direction: 1}
    );
    middleware.create_index(
        PKI_COLLECTION_TRANSACTIONS_NOM,
        champs_index_transactions,
        Some(options_unique_transactions)
    ).await?;

    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from("transaction_complete")),
        unique: false
    };
    let champs_index_transactions = vec!(
        ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_EVENEMENT_COMPLETE), direction: 1}
    );
    middleware.create_index(
        PKI_COLLECTION_TRANSACTIONS_NOM,
        champs_index_transactions,
        Some(options_unique_transactions)
    ).await?;

    // Index certificats fingerprint
    let options_unique_fingerprint = IndexOptions {
        nom_index: Some(String::from("fingerprint")),
        unique: true
    };
    let champs_index_fingerprint = vec!(
        ChampIndex {nom_champ: String::from(PKI_DOCUMENT_CHAMP_FINGERPRINT), direction: 1},
    );
    middleware.create_index(
        PKI_COLLECTION_CERTIFICAT_NOM,
        champs_index_fingerprint,
        Some(options_unique_fingerprint)
    ).await?;

    // Index certificats fingerprint_pk
    let options_unique_fingerprint_pk = IndexOptions {
        nom_index: Some(String::from("fingerprint_pk")),
        unique: true
    };
    let champs_index_fingerprint_pk = vec!(
        ChampIndex {nom_champ: String::from(PKI_DOCUMENT_CHAMP_FINGERPRINT_PK), direction: 1}
    );
    middleware.create_index(
        PKI_COLLECTION_CERTIFICAT_NOM,
        champs_index_fingerprint_pk,
        Some(options_unique_fingerprint_pk)
    ).await?;


    // Index backup transactions
    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from("backup_transactions")),
        unique: false
    };
    let champs_index_transactions = vec!(
        ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_TRANSACTION_TRAITEE), direction: 1},
        ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_BACKUP_FLAG), direction: 1},
        ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_EVENEMENT_COMPLETE), direction: 1},
    );
    middleware.create_index(
        PKI_COLLECTION_TRANSACTIONS_NOM,
        champs_index_transactions,
        Some(options_unique_transactions)
    ).await?;

    Ok(())
}

pub async fn consommer_messages(middleware: Arc<MiddlewareDbPki>, mut rx: Receiver<TypeMessage>) {
    while let Some(message) = rx.recv().await {
        debug!("Message PKI recu : {:?}", message);

        let resultat = match message {
            TypeMessage::ValideAction(inner) => traiter_message_valide_action(&middleware, inner).await,
            TypeMessage::Valide(_inner) => {warn!("Recu MessageValide sur thread consommation"); todo!()},
            TypeMessage::Certificat(_inner) => {warn!("Recu MessageCertificat sur thread consommation"); todo!()},
        };

        match resultat {
            Ok(()) => (),
            Err(e) => warn!("Erreur traitement, message dropped : {}", e),
        }

    }
}

// pub async fn consommer_triggers(middleware: Arc<MiddlewareDbPki>, mut rx: Receiver<TypeMessage>) {
//     while let Some(message) = rx.recv().await {
//         debug!("Message PKI recu : {:?}", message);
//
//         let resultat: Result<(), String> = match message {
//             TypeMessage::ValideAction(inner) => {warn!("Recu MessageValide sur thread triggers"); todo!()},
//             TypeMessage::Valide(_inner) => {warn!("Recu MessageValide sur thread triggers"); todo!()},
//             TypeMessage::Certificat(_inner) => {warn!("Recu MessageCertificat sur thread triggers"); todo!()},
//         };
//
//         match resultat {
//             Ok(()) => (),
//             Err(e) => warn!("Erreur traitement, message dropped : {}", e),
//         }
//
//     }
// }

async fn traiter_message_valide_action(middleware: &Arc<MiddlewareDbPki>, message: MessageValideAction) -> Result<(), String> {

    let correlation_id = match &message.correlation_id {
        Some(inner) => Some(inner.clone()),
        None => None,
    };
    let reply_q = match &message.reply_q {
        Some(inner) => Some(inner.clone()),
        None => None,
    };

    let resultat = match message.type_message {
        TypeMessageOut::Requete => consommer_requete(middleware.as_ref(), message).await,
        TypeMessageOut::Commande => consommer_commande(middleware.as_ref(), message).await,
        TypeMessageOut::Transaction => consommer_transaction(middleware.as_ref(), message).await,
        TypeMessageOut::Reponse => Err(String::from("Recu reponse sur thread consommation, drop message")),
        TypeMessageOut::Evenement => consommer_evenement(middleware.as_ref(), message).await,
    }?;

    match resultat {
        Some(reponse) => {
            let reply_q = match reply_q {
                Some(reply_q) => Ok(reply_q),
                None => Err("Reply Q manquante pour reponse"),
            }?;
            let correlation_id = match correlation_id {
                Some(correlation_id) => Ok(correlation_id),
                None => Err("Correlation id manquant pour reponse"),
            }?;
            info!("Emettre reponse vers reply_q {} correlation_id {}", reply_q, correlation_id);
            middleware.repondre(&reponse, &reply_q, &correlation_id).await?;
        },
        None => (),  // Aucune reponse
    }

    Ok(())
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction) -> Result<Option<Value>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &message.message);
    match message.domaine.as_str() {
        PKI_DOMAINE_NOM => match message.action.as_str() {
            PKI_REQUETE_CERTIFICAT => requete_certificat(middleware, message).await,
            PKI_REQUETE_CERTIFICAT_PAR_PK => requete_certificat_par_pk(middleware, message).await,
            _ => {
                error!("Message requete action inconnue : {}. Message dropped.", message.action);
                Ok(None)
            },
        },
        PKI_DOMAINE_CERTIFICAT_NOM => requete_certificat(middleware, message).await,
        _ => {
            error!("Message requete domaine inconnu : {}. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction) -> Result<Option<Value>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer commande : {:?}", &m.message);
    match m.action.as_str() {
        PKI_COMMANDE_SAUVEGARDER_CERTIFICAT | PKI_COMMANDE_NOUVEAU_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware, m).await,
        _ => Err(format!("Commande Pki inconnue : {}, message dropped", m.action)),
    }
}

async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<Value>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer transaction : {:?}", &m.message);
    match m.action.as_str() {
        PKI_TRANSACTION_NOUVEAU_CERTIFICAT => {
            sauvegarder_transaction(middleware, m).await?;
            Ok(None)
        },
        _ => Err(format!("Mauvais type d'action pour une transaction : {}", m.action)),
    }
}

async fn consommer_evenement(middleware: &(impl ValidateurX509 + GenerateurMessages + MongoDao), m: MessageValideAction) -> Result<Option<Value>, String> {
    debug!("Consommer evenement : {:?}", &m.message);
    match m.action.as_str() {
        EVENEMENT_TRANSACTION_PERSISTEE => {
            traiter_transaction(PKI_DOMAINE_NOM, middleware, m).await?;
            Ok(None)
        },
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", m.action)),
    }
}

async fn requete_certificat<M>(middleware: &M, m: MessageValideAction) -> Result<Option<Value>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let fingerprint = match m.domaine.as_str() {
        PKI_DOMAINE_NOM => {
            match m.message.get_msg().contenu.get(PKI_DOCUMENT_CHAMP_FINGERPRINT) {
                Some(fp) => match fp.as_str() {
                    Some(fp) => Ok(fp),
                    None =>Err("Fingerprint manquant pour requete de certificat"),
                },
                None => Err("Fingerprint manquant pour requete de certificat"),
            }
        },
        PKI_DOMAINE_CERTIFICAT_NOM => Ok(m.action.as_str()),
        _ => Err("Mauvais type de requete de certificat")
    }?;

    let enveloppe = match middleware.get_certificat(fingerprint).await {
        Some(inner) => Ok(inner),
        None => Err(format!("Certificat inconnu : {}", fingerprint)),
    }?;

    let reponse = formatter_message_certificat(enveloppe.as_ref());
    Ok(Some(reponse))
}

async fn requete_certificat_par_pk<M>(middleware: &M, m: MessageValideAction) -> Result<Option<Value>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let fingerprint_pk = match m.message.get_msg().contenu.get(PKI_DOCUMENT_CHAMP_FINGERPRINT_PK) {
        Some(inner) => match inner.as_str() {
            Some(inner) => Ok(inner),
            None => Err("Erreur fingerprint pk mauvais format"),
        },
        None => Err("Erreur fingerprint pk absent"),
    }?;

    let db = middleware.get_database()?;
    let collection = db.collection(PKI_COLLECTION_CERTIFICAT_NOM);
    let filtre = doc! {
        PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: fingerprint_pk,
    };
    let document_certificat = match collection.find_one(filtre, None).await {
        Ok(inner) => match inner {
            Some(inner) => Ok(inner),
            None => Err(format!("Certificat par pk introuvable fingerprint pk : {}", fingerprint_pk)),
        },
        Err(e) => Err(format!("Erreur chargement certificat par pk pour fingerprint pk : {}, {:?}", fingerprint_pk, e)),
    }?;

    let chaine_pem_doc= document_certificat.get(PKI_DOCUMENT_CHAMP_CERTIFICAT);
    let mut chaine_pem = Vec::new();
    for pem in chaine_pem_doc.expect("certificat").as_array().expect("array") {
        chaine_pem.push(String::from(pem.as_str().expect("str")));
    }
    let fingerprint = match document_certificat.get(PKI_DOCUMENT_CHAMP_FINGERPRINT) {
        Some(fp) => Some(fp.as_str().expect("fingerprint")),
        None => None,
    };

    let enveloppe = middleware.charger_enveloppe(&chaine_pem, fingerprint).await?;

    // Certificat trouve, repondre
    debug!("requete_certificat_par_pk repondre fingerprint {:?} pour fingerprint_pk {}", fingerprint, fingerprint_pk);
    // repondre_enveloppe(middleware, &m, enveloppe.as_ref()).await?;
    let reponse = formatter_message_certificat(enveloppe.as_ref());
    Ok(Some(reponse))
}

pub async fn sauvegarder_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<(), String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Sauvegarder transaction avec document {:?}", &m.message);
    let msg = m.message.get_msg();

    // Serialiser le message en serde::Value - permet de convertir en Document bson
    let val = match serde_json::to_value(msg) {
        Ok(v) => match v.as_object() {
            Some(o) => o.to_owned(),
            None => Err(format!("Erreur sauvegarde transaction, mauvais type objet JSON"))?,
        },
        Err(e) => Err(format!("Erreur sauvegarde transaction, conversion : {:?}", e))?,
    };

    let mut contenu_doc = match Document::try_from(val) {
        Ok(c) => Ok(c),
        Err(e) => {
            error!("Erreur conversion json -> bson\n{:?}", e.to_string());
            Err(format!("Erreur sauvegarde transaction, conversion json -> bson : {:?}", e))
        },
    }?;
    debug!("Transaction en format bson : {:?}", contenu_doc);

    let date_courante = chrono::Utc::now();
    let entete = &msg.entete;
    let uuid_transaction = entete.uuid_transaction.as_str();
    let estampille = &entete.estampille;

    let params_evenements = doc! {
        "document_persiste": date_courante,
        "_estampille": estampille.get_datetime(),
        "transaction_complete": false,
        "backup_flag": false,
        "signature_verifiee": date_courante,
    };

    debug!("evenements tags : {:?}", params_evenements);

    // let mut contenu_doc_mut = contenu_doc.as_document_mut().expect("mut");
    contenu_doc.insert("_evenements", params_evenements);

    contenu_doc.remove("_certificat");

    debug!("Inserer nouvelle transaction\n:{:?}", contenu_doc);

    let db = middleware.get_database()?;
    let collection = db.collection("Pki.rust");
    match collection.insert_one(contenu_doc, None).await {
        Ok(_) => {
            debug!("Transaction sauvegardee dans collection de reception");
            Ok(())
        },
        Err(e) => {
            error!("Erreur sauvegarde transaction dans MongoDb : {:?}", e);
            Err(format!("Erreur sauvegarde transaction dans MongoDb : {:?}", e))
        }
    }?;

    transmettre_evenement_persistance(
        middleware,
        uuid_transaction,
        "Core",
        m.reply_q.clone(),
        m.correlation_id.clone()
    ).await?;

    Ok(())
}

async fn traiter_commande_sauvegarder_certificat<M>(middleware: &M, m: MessageValideAction) -> Result<Option<Value>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let pems = match m.message.get_msg().contenu.get("chaine_pem") {
        Some(c) => match c.as_array() {
            Some(c) => Ok(c),
            None => Err("chaine_pem n'est pas une array"),
        },
        None => Err("chaine_pem manquante d'une commande de sauvegarde de certificat")
    }?;

    let mut pems_str = Vec::new();
    for pem in pems {
        match pem.as_str() {
            Some(p) => Ok(pems_str.push(p.to_owned())),
            None => Err("pem n'est pas une str")
        }?;
    }

    let enveloppe = middleware.charger_enveloppe(&pems_str, None).await?;
    debug!("Commande de sauvegarde de certificat {} traitee", enveloppe.fingerprint);

    Ok(Some(json!({"ok": true})))
}

async fn traiter_transaction(_domaine: &str, middleware: &(impl ValidateurX509 + GenerateurMessages + MongoDao), m: MessageValideAction) -> Result<Option<MessageMilleGrille>, String> {
    let transaction = charger_transaction(middleware, &m).await?;
    debug!("Traitement transaction, chargee : {:?}", transaction);

    let uuid_transaction = transaction.get_uuid_transaction().to_owned();

    let reponse = match transaction.get_action() {
        PKI_TRANSACTION_NOUVEAU_CERTIFICAT => sauvegarder_certificat(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    };

    if reponse.is_ok() {
        // Marquer transaction completee
        debug!("Transaction traitee {}, marquer comme completee", uuid_transaction);
        marquer_transaction(middleware, &uuid_transaction, EtatTransaction::Complete).await?;
    }

    reponse
}

async fn sauvegarder_certificat(middleware: &(impl ValidateurX509 + GenerateurMessages + MongoDao), transaction: impl Transaction) -> Result<Option<MessageMilleGrille>, String> {
    debug!("Sauvegarder certificat recu via transaction");

    let contenu = transaction.get_contenu();
    let certificat = match contenu.get_str("pem") {
        Ok(c) => Ok(c),
        Err(e) => Err(format!("Champ PEM manquant de transaction nouveauCertificat: {:?}", e)),
    }?;

    // Utiliser validateur.charger_enveloppe. Va automatiquement sauvegarder le certificat (si manquant).
    let enveloppe = match charger_enveloppe(certificat, Some(middleware.store())) {
        Ok(e) => Ok(e),
        Err(e) => Err(format!("Erreur preparation enveloppe pour sauvegarder certificat : {:?}", e)),
    }?;
    let collection_doc_pki = middleware.get_collection(PKI_COLLECTION_CERTIFICAT_NOM)?;
    upsert_certificat(&enveloppe, collection_doc_pki, Some(false)).await?;

    Ok(None)
}

fn lire_date_epoch(date_epoch: i64) -> DateTime<Utc> {
    let date_naive = chrono::NaiveDateTime::from_timestamp(date_epoch, 0);
    DateTime::from_utc(date_naive, Utc)
}