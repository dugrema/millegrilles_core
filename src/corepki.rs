use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{Chiffreur, ConfigQueue, ConfigRoutingExchange, FormatteurMessage, QueueType, reset_backup_flag, restaurer, sauvegarder_transaction, TraiterTransaction, TransactionImpl, TriggerTransaction, VerificateurPermissions};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::backup;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{charger_enveloppe, ValidateurX509};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{formatter_message_certificat, MiddlewareDbPki, upsert_certificat};
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::serde_json as serde_json;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, Transaction};

// Constantes
pub const NOM_DOMAINE: &str = PKI_DOMAINE_NOM;  //"CorePki";
const NOM_COLLECTION_TRANSACTIONS: &str = "CorePki";

const PKI_DOMAINE_CERTIFICAT_NOM: &str = "certificat";
// pub const PKI_COLLECTION_TRANSACTIONS_NOM: &str = "Pki.rust";
// pub const PKI_COLLECTION_CERTIFICAT_NOM: &str = "Pki.rust/certificat";

const PKI_REQUETE_CERTIFICAT: &str = "infoCertificat";
const PKI_REQUETE_CERTIFICAT_PAR_PK: &str = "certificatParPk";

const PKI_COMMANDE_SAUVEGARDER_CERTIFICAT: &str = "certificat";
const PKI_COMMANDE_NOUVEAU_CERTIFICAT: &str = "nouveauCertificat";

// pub const PKI_TRANSACTION_NOUVEAU_CERTIFICAT: &str = PKI_COMMANDE_NOUVEAU_CERTIFICAT;

// pub const PKI_DOCUMENT_CHAMP_FINGERPRINT: &str = "fingerprint";
const PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
// pub const PKI_DOCUMENT_CHAMP_CERTIFICAT: &str = "certificat";

const NOM_Q_TRANSACTIONS_PKI: &str = "CorePki/transactions";
const NOM_Q_TRANSACTIONS_VOLATILS: &str = "CorePki/volatils";
const NOM_Q_TRIGGERS_PKI: &str = "CorePki/triggers";

const NOM_DOMAINE_CERTIFICATS: &str = "certificat";


/// Initialise le domaine CorePki.
pub async fn preparer_threads(middleware: Arc<MiddlewareDbPki>) -> Result<(HashMap<String, Sender<TypeMessage>>, FuturesUnordered<JoinHandle<()>>), Box<dyn Error>> {

    // Preparer les index MongoDB
    preparer_index_mongodb(middleware.as_ref()).await?;

    // Channels pour traiter messages Pki
    let (tx_pki_messages, rx_pki_messages) = mpsc::channel::<TypeMessage>(20);
    let (tx_pki_triggers, rx_pki_triggers) = mpsc::channel::<TypeMessage>(5);

    // Routing map pour le domaine CorePki (et legacy Pki). Recoit aussi domaine virtuel "certificat".
    // Fonctionne avec le nom de la Q (e.g. CorPki/transactions) ou le domaine (certificat, Pki, etc. dans routing key)
    let mut routing_pki: HashMap<String, Sender<TypeMessage>> = HashMap::new();

    // Mapping par Q nommee
    routing_pki.insert(String::from(NOM_Q_TRANSACTIONS_PKI), tx_pki_messages.clone());  // Legacy
    routing_pki.insert(String::from(NOM_Q_TRANSACTIONS_VOLATILS), tx_pki_messages.clone());  // Legacy
    routing_pki.insert(String::from(NOM_Q_TRIGGERS_PKI), tx_pki_triggers.clone());

    // Mapping par domaine (routing key)
    routing_pki.insert(String::from("Pki"), tx_pki_messages.clone());  // Legacy
    routing_pki.insert(String::from(NOM_DOMAINE), tx_pki_messages.clone());
    routing_pki.insert(String::from(NOM_DOMAINE_CERTIFICATS), tx_pki_messages.clone());

    // Thread consommation
    let futures = FuturesUnordered::new();
    futures.push(spawn(consommer_messages(middleware.clone(), rx_pki_messages)));
    futures.push(spawn(consommer_messages(middleware.clone(), rx_pki_triggers)));

    Ok((routing_pki, futures))
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    let niveaux_securite_public = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);
    let niveaux_securite_prive = vec!(Securite::L2Prive, Securite::L3Protege);

    // RK 1.public (inclus 2.prive et 3.protege)
    for niveau in niveaux_securite_public {
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Pki.infoCertificat"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.CorePki.infoCertificat"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.certificat.*"), exchange: niveau.clone()});
    }

    // RK 2.prive (inclus 3.protege)
    for niveau in niveaux_securite_prive {
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Pki.certificatParPk"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.CorePki.certificatParPk"), exchange: niveau.clone()});
    }

    // RK 3.protege seulement
    rk_volatils.push(ConfigRoutingExchange {routing_key: "commande.Pki.certificat".into(), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: "commande.CorePki.certificat".into(), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.Pki.{}", PKI_COMMANDE_NOUVEAU_CERTIFICAT), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.CorePki.{}", PKI_COMMANDE_NOUVEAU_CERTIFICAT), exchange: Securite::L3Protege});

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: 300000.into(),
            durable: false,
        }
    ));

    let mut rk_transactions = Vec::new();
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.CorePki.{}", PKI_TRANSACTION_NOUVEAU_CERTIFICAT).into(),
        exchange: Securite::L3Protege}
    );

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS_PKI.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (NOM_DOMAINE.into()));

    queues
}

/// Creer index MongoDB
async fn preparer_index_mongodb<M>(middleware: &M) -> Result<(), String>
where M: MongoDao
{

    // Transactions

    // Index transactions par uuid-transaction
    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from(TRANSACTION_CHAMP_UUID_TRANSACTION)),
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

    // Index transactions completes
    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from(TRANSACTION_CHAMP_COMPLETE)),
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

    // Index backup transactions
    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from(BACKUP_CHAMP_BACKUP_TRANSACTIONS)),
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

    // Documents

    // Index certificats fingerprint
    let options_unique_fingerprint = IndexOptions {
        nom_index: Some(String::from(PKI_DOCUMENT_CHAMP_FINGERPRINT)),
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
        nom_index: Some(String::from(PKI_DOCUMENT_CHAMP_FINGERPRINT_PK)),
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

    Ok(())
}

async fn consommer_messages(middleware: Arc<MiddlewareDbPki>, mut rx: Receiver<TypeMessage>) {
    while let Some(message) = rx.recv().await {
        debug!("Message PKI recu : {:?}", message);

        let resultat = match message {
            TypeMessage::ValideAction(inner) => traiter_message_valide_action(&middleware, inner).await,
            TypeMessage::Valide(_inner) => {warn!("Recu MessageValide sur thread consommation"); todo!()},
            TypeMessage::Certificat(_inner) => {warn!("Recu MessageCertificat sur thread consommation"); todo!()},
            TypeMessage::Regeneration => continue, // Rien a faire, on boucle
        };

        match resultat {
            Ok(()) => (),
            Err(e) => warn!("Erreur traitement, message dropped : {}", e),
        }

    }
}

async fn traiter_message_valide_action(middleware: &Arc<MiddlewareDbPki>, message: MessageValideAction) -> Result<(), Box<dyn Error>> {

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
        TypeMessageOut::Commande => consommer_commande(middleware.clone(), message).await,
        TypeMessageOut::Transaction => consommer_transaction(middleware.as_ref(), message).await,
        TypeMessageOut::Reponse => Err(String::from("Recu reponse sur thread consommation, drop message"))?,
        TypeMessageOut::Evenement => consommer_evenement(middleware.as_ref(), message).await,
    }?;

    match resultat {
        Some(reponse) => {
            let reply_q = match reply_q {
                Some(reply_q) => reply_q,
                None => {
                    debug!("Reply Q manquante pour reponse a {:?}", correlation_id);
                    return Ok(())
                },
            };
            let correlation_id = match correlation_id {
                Some(correlation_id) => Ok(correlation_id),
                None => Err("Correlation id manquant pour reponse"),
            }?;
            info!("Emettre reponse vers reply_q {} correlation_id {}", reply_q, correlation_id);
            middleware.repondre(reponse, &reply_q, &correlation_id).await?;
        },
        None => (),  // Aucune reponse
    }

    Ok(())
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &message.message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.

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

async fn consommer_commande(middleware: Arc<MiddlewareDbPki>, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
{
    debug!("Consommer commande : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges(vec!(String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        // Commandes standard
        COMMANDE_BACKUP_HORAIRE => backup(middleware.as_ref(), PKI_DOMAINE_NOM, PKI_COLLECTION_TRANSACTIONS_NOM, true).await,
        COMMANDE_RESTAURER_TRANSACTIONS => restaurer_transactions(middleware.clone()).await,
        COMMANDE_RESET_BACKUP => reset_backup_flag(middleware.as_ref(), PKI_COLLECTION_TRANSACTIONS_NOM).await,

        // Commandes specifiques au domaine
        PKI_COMMANDE_SAUVEGARDER_CERTIFICAT | PKI_COMMANDE_NOUVEAU_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware.as_ref(), m).await,

        // Commandes inconnues
        _ => Err(format!("Commande Pki inconnue : {}, message dropped", m.action))?,
    }
}

async fn restaurer_transactions(middleware: Arc<MiddlewareDbPki>) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> {
    let noms_collections_docs = vec! [
        String::from(PKI_COLLECTION_CERTIFICAT_NOM)
    ];

    let processor = ProcesseurTransactions::new();

    restaurer(
        middleware.clone(),
        PKI_DOMAINE_NOM,
        PKI_COLLECTION_TRANSACTIONS_NOM,
        &noms_collections_docs,
        &processor
    ).await?;

    Ok(None)
}

async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges(vec!(String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        PKI_TRANSACTION_NOUVEAU_CERTIFICAT => {
            sauvegarder_transaction(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
            Ok(None)
        },
        _ => Err(format!("Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_evenement(middleware: &(impl ValidateurX509 + GenerateurMessages + MongoDao), m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> {
    debug!("Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges(vec!(String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        EVENEMENT_TRANSACTION_PERSISTEE => {
            traiter_transaction(PKI_DOMAINE_NOM, middleware, m).await?;
            Ok(None)
        },
        EVENEMENT_CEDULE => {
            traiter_cedule(middleware, m).await?;
            Ok(None)
        }
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", m.action))?,
    }
}

async fn requete_certificat<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
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

    let reponse_value = formatter_message_certificat(enveloppe.as_ref());
    let reponse = middleware.formatter_reponse(reponse_value, None)?;
    Ok(Some(reponse))
}

async fn requete_certificat_par_pk<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
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
    let collection = db.collection::<Document>(PKI_COLLECTION_CERTIFICAT_NOM);
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
    let reponse_value = formatter_message_certificat(enveloppe.as_ref());
    let reponse = middleware.formatter_reponse(reponse_value, None)?;
    Ok(Some(reponse))
}

async fn traiter_commande_sauvegarder_certificat<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
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

    let reponse = middleware.formatter_reponse(json!({"ok": true}), None)?;
    Ok(Some(reponse))
}

async fn traiter_transaction<M>(_domaine: &str, middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?,
    };

    let transaction = charger_transaction(middleware, &trigger).await?;
    debug!("Traitement transaction, chargee : {:?}", transaction);

    let uuid_transaction = transaction.get_uuid_transaction().to_owned();
    let reponse = aiguillage_transaction(middleware, transaction).await;
    if reponse.is_ok() {
        // Marquer transaction completee
        debug!("Transaction traitee {}, marquer comme completee", uuid_transaction);
        marquer_transaction(middleware, &uuid_transaction, EtatTransaction::Complete).await?;
    }

    reponse
}

struct ProcesseurTransactions {}
impl ProcesseurTransactions {
    pub fn new() -> Self {
        ProcesseurTransactions {}
    }
}
#[async_trait]
impl TraiterTransaction for ProcesseurTransactions {
    async fn traiter_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

async fn aiguillage_transaction<M>(middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
where M: ValidateurX509 + GenerateurMessages + MongoDao {
    match transaction.get_action() {
        PKI_TRANSACTION_NOUVEAU_CERTIFICAT => sauvegarder_certificat(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn sauvegarder_certificat<M>(middleware: &M, transaction: impl Transaction) -> Result<Option<MessageMilleGrille>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
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

async fn traiter_cedule<M>(middleware: &M, trigger: MessageValideAction) -> Result<(), Box<dyn Error>>
where M: ValidateurX509 {
    let message = trigger.message;

    debug!("Certificat ceduleur est valide, on peut executer les taches");

    Ok(())
}

/// Implementer methode pour regenerer transactions
struct TraiterTransactionPki {}
#[async_trait]
impl TraiterTransaction for TraiterTransactionPki {
    async fn traiter_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[cfg(test)]
mod test_integration {
    use millegrilles_common_rust::chrono::Utc;
    // use millegrilles_common_rust::certificats::certificats_tests::{CERT_DOMAINES, CERT_FICHIERS, charger_enveloppe_privee_env, prep_enveloppe};
    use millegrilles_common_rust::middleware::preparer_middleware_pki;
    use millegrilles_common_rust::regenerer;
    use millegrilles_common_rust::tokio_stream::StreamExt;

    use chrono::Utc;

    use crate::test_setup::setup;

    use super::*;

    #[tokio::test]
    async fn regenerer_transactions_integration() {
        setup("regenerer_transactions_integration");
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(spawn(async move {

            let debut_traitement = Utc::now();
            debug!("Debut regeneration : {:?}", debut_traitement);
            let mut colls = Vec::new();
            colls.push(String::from(NOM_COLLECTION_CERTIFICATS));
            let processor = TraiterTransactionPki{};
            regenerer(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS, &colls, &processor)
                .await.expect("regenerer");

            let fin_traitemeent = Utc::now();
            let duree = fin_traitemeent - debut_traitement;
            debug!("Duree regeneration : {:?}", duree);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }
}