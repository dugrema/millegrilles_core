use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use log::{trace, debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::restaurer;
use millegrilles_common_rust::bson::{doc, Bson};
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::formatteur_messages::MessageSerialise;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{sauvegarder_transaction, thread_emettre_presence_domaine};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_value, filtrer_doc_id, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb as mongodb;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::serde_json as serde_json;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, TraiterTransaction, Transaction, TransactionImpl, TriggerTransaction};
use millegrilles_common_rust::verificateur::ValidationOptions;
use mongodb::options::{FindOptions, UpdateOptions};
use serde::{Serialize, Deserialize};
use millegrilles_common_rust::bson::Array;

use crate::validateur_pki_mongo::MiddlewareDbPki;
use millegrilles_common_rust::mongodb::options::FindOneAndUpdateOptions;
use millegrilles_common_rust::constantes::Securite::L3Protege;

// Constantes
pub const DOMAINE_NOM: &str = "CoreTopologie";
pub const NOM_COLLECTION_DOMAINES: &str = "CoreTopologie/domaines";
pub const NOM_COLLECTION_NOEUDS: &str = "CoreTopologie/noeuds";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

pub const DOMAINE_PRESENCE_NOM: &str = "presence";

const NOM_Q_TRANSACTIONS: &str = "CoreTopologie/transactions";
const NOM_Q_VOLATILS: &str = "CoreTopologie/volatils";
const NOM_Q_TRIGGERS: &str = "CoreTopologie/triggers";

const REQUETE_APPLICATIONS_DEPLOYEES: &str = "listeApplicationsDeployees";
const REQUETE_LISTE_DOMAINES: &str = "listeDomaines";
const REQUETE_LISTE_NOEUDS: &str = "listeNoeuds";
const REQUETE_INFO_DOMAINE: &str = "infoDomaine";
const REQUETE_INFO_NOEUD: &str = "infoNoeud";

const TRANSACTION_DOMAINE: &str = "domaine";
const TRANSACTION_MONITOR: &str = "monitor";

const EVENEMENT_PRESENCE_MONITOR: &str = "monitor";
const EVENEMENT_PRESENCE_DOMAINE: &str = "domaine";

const INDEX_DOMAINE: &str = "domaine";
const INDEX_NOEUDS: &str = "noeuds";

const CHAMP_DOMAINE: &str = "domaine";
const CHAMP_NOEUD_ID: &str = "noeud_id";

// permissionDechiffrage
// listerNoeudsAWSS3


/// Initialise le domaine.
pub async fn preparer_threads(middleware: Arc<MiddlewareDbPki>)
    -> Result<(HashMap<String, Sender<TypeMessage>>, FuturesUnordered<JoinHandle<()>>), Box<dyn Error>>
{
    // Preparer les index MongoDB
    preparer_index_mongodb(middleware.as_ref()).await?;

    // Channels pour traiter messages
    let (tx_messages, rx_messages) = mpsc::channel::<TypeMessage>(1);
    let (tx_triggers, rx_triggers) = mpsc::channel::<TypeMessage>(1);

    // Routing map pour le domaine
    let mut routing: HashMap<String, Sender<TypeMessage>> = HashMap::new();

    // Mapping par Q nommee
    routing.insert(String::from(NOM_Q_TRANSACTIONS), tx_messages.clone());  // Legacy
    routing.insert(String::from(NOM_Q_VOLATILS), tx_messages.clone());  // Legacy
    routing.insert(String::from(NOM_Q_TRIGGERS), tx_triggers.clone());

    // Mapping par domaine (routing key)
    routing.insert(String::from(DOMAINE_NOM), tx_messages.clone());

    debug!("Routing : {:?}", routing);

    // Thread consommation
    let futures = FuturesUnordered::new();
    futures.push(spawn(consommer_messages(middleware.clone(), rx_messages)));
    futures.push(spawn(consommer_messages(middleware.clone(), rx_triggers)));

    // Thread entretien
    futures.push(spawn(entretien(middleware.clone())));
    futures.push(spawn(thread_emettre_presence_domaine(middleware.clone(), DOMAINE_NOM)));

    Ok((routing, futures))
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 3.protege seulement
    let requetes_protegees = vec![
        REQUETE_APPLICATIONS_DEPLOYEES,
        REQUETE_LISTE_DOMAINES,
        REQUETE_LISTE_NOEUDS,
        REQUETE_INFO_DOMAINE,
        REQUETE_INFO_NOEUD,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
    }

    // RK 2.prive
    let requetes_protegees = vec![
        REQUETE_APPLICATIONS_DEPLOYEES,
        REQUETE_INFO_NOEUD,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
    }

    let commandes: Vec<&str> = vec![
        //TRANSACTION_APPLICATION,  // Transaction est initialement recue sous forme de commande uploadee par ServiceMonitor ou autre source
    ];
    for commande in commandes {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L3Protege});
    }

    let evenements: Vec<&str> = vec![
        EVENEMENT_PRESENCE_MONITOR,
    ];
    for evenement in &evenements {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_PRESENCE_NOM, evenement), exchange: Securite::L3Protege});
    }
    for evenement in &evenements {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_PRESENCE_NOM, evenement), exchange: Securite::L2Prive});
    }
    for evenement in &evenements {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_PRESENCE_NOM, evenement), exchange: Securite::L1Public});
    }

    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_PRESENCE_NOM, EVENEMENT_PRESENCE_DOMAINE), exchange: Securite::L3Protege});

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: 300000.into(),
            durable: false,
        }
    ));

    let mut rk_transactions = Vec::new();
    // rk_transactions.push(ConfigRoutingExchange {
    //     routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_APPLICATION).into(),
    //     exchange: Securite::L3Protege
    // });

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into()));

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
        NOM_COLLECTION_TRANSACTIONS,
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
        NOM_COLLECTION_TRANSACTIONS,
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
        NOM_COLLECTION_TRANSACTIONS,
        champs_index_transactions,
        Some(options_unique_transactions)
    ).await?;

    // Index noeuds
    let options_unique_noeuds = IndexOptions {
        nom_index: Some(String::from(INDEX_NOEUDS)),
        unique: true
    };
    let champs_index_noeuds = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_NOEUD_ID), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_NOEUDS,
        champs_index_noeuds,
        Some(options_unique_noeuds)
    ).await?;

    // Index domaines
    let options_unique_domaine = IndexOptions {
        nom_index: Some(String::from(INDEX_DOMAINE)),
        unique: true
    };
    let champs_index_domaine = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_DOMAINE), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_DOMAINES,
        champs_index_domaine,
        Some(options_unique_domaine)
    ).await?;

    Ok(())
}

async fn consommer_messages(middleware: Arc<MiddlewareDbPki>, mut rx: Receiver<TypeMessage>) {
    while let Some(message) = rx.recv().await {
        trace!("Message {} recu : {:?}", DOMAINE_NOM, message);

        let resultat = match message {
            TypeMessage::ValideAction(inner) => traiter_message_valide_action(&middleware, inner).await,
            TypeMessage::Valide(inner) => {warn!("Recu MessageValide sur thread consommation, skip : {:?}", inner); Ok(())},
            TypeMessage::Certificat(inner) => {warn!("Recu MessageCertificat sur thread consommation, skip : {:?}", inner); Ok(())},
            TypeMessage::Regeneration => continue, // Rien a faire, on boucle
        };

        if let Err(e) = resultat {
            error!("Erreur traitement message : {:?}\n", e);
        }
    }
}

async fn entretien(_middleware: Arc<MiddlewareDbPki>) {

    let mut catalogues_charges = false;

    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

async fn traiter_cedule<M>(_middleware: &M, _trigger: MessageValideAction) -> Result<(), Box<dyn Error>>
where M: ValidateurX509 {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
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
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &message.message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_APPLICATIONS_DEPLOYEES => liste_applications_deployees(middleware, message).await,
                REQUETE_LISTE_DOMAINES => liste_domaines(middleware, message).await,
                REQUETE_LISTE_NOEUDS => liste_noeuds(middleware, message).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}

async fn consommer_commande(middleware: Arc<MiddlewareDbPki>, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
{
    debug!("Consommer commande : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Commande autorisation invalide (pas 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        // Commandes standard
    //     TRANSACTION_APPLICATION => traiter_commande_application(middleware.as_ref(), m).await,
    //     COMMANDE_RESTAURER_TRANSACTIONS => restaurer_transactions(middleware.clone()).await,
    //     COMMANDE_RESET_BACKUP => reset_backup_flag(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS).await,
    //
    //     // Commandes specifiques au domaine
    //     PKI_COMMANDE_SAUVEGARDER_CERTIFICAT | PKI_COMMANDE_NOUVEAU_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware.as_ref(), m).await,
    //
    //     // Commandes inconnues
        _ => Err(format!("Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
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
        TRANSACTION_DOMAINE | TRANSACTION_MONITOR => {
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
            traiter_transaction(DOMAINE_NOM, middleware, m).await?;
            Ok(None)
        },
        EVENEMENT_CEDULE => {
            traiter_cedule(middleware, m).await?;
            Ok(None)
        },
        EVENEMENT_PRESENCE_DOMAINE => traiter_presence_domaine(middleware, m).await,
        EVENEMENT_PRESENCE_MONITOR => traiter_presence_monitor(middleware, m).await,
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", m.action))?,
    }
}

async fn traiter_transaction<M>(_domaine: &str, middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?,
    };

    let transaction = charger_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &trigger).await?;
    debug!("Traitement transaction, chargee : {:?}", transaction);

    let uuid_transaction = transaction.get_uuid_transaction().to_owned();
    let reponse = aiguillage_transaction(middleware, transaction).await;
    if reponse.is_ok() {
        // Marquer transaction completee
        debug!("Transaction traitee {}, marquer comme completee", uuid_transaction);
        marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &uuid_transaction, EtatTransaction::Complete).await?;
    }

    reponse
}

async fn aiguillage_transaction<M>(middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
where M: ValidateurX509 + GenerateurMessages + MongoDao {
    match transaction.get_action() {
        TRANSACTION_DOMAINE => traiter_transaction_domaine(middleware, transaction).await,
        TRANSACTION_MONITOR => traiter_transaction_monitor(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn traiter_presence_domaine<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let event: PresenceDomaine = m.message.get_msg().map_contenu(None)?;
    debug!("Presence domaine : {:?}", event);

    let mut set_ops = m.message.get_msg().map_to_bson()?;
    filtrer_doc_id(&mut set_ops);

    // Retirer champ cle
    set_ops.remove("domaine");

    let filtre = doc! {"domaine": &event.domaine};
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {"domaine": &event.domaine, CHAMP_CREATION: Utc::now(), "dirty": true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    debug!("Document monitor a sauvegarder : {:?}", ops);

    let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
    let options = FindOneAndUpdateOptions::builder().upsert(true).build();
    let result = match collection.find_one_and_update(filtre,ops, Some(options)).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur find document sur transaction domaine : {:?}", e))?
    };
    let creer_transaction = match result {
        Some(d) => d.get_bool("dirty")?,
        None => true,
    };

    if creer_transaction {
        debug!("Creer transaction topologie pour domaine {}", &event.domaine);

        let tval = json!({
            "domaine": event.domaine,
            "noeud_id": event.noeud_id,
        });

        let transaction = middleware.formatter_message(
            &tval,
            Some(DOMAINE_NOM),
            Some(TRANSACTION_DOMAINE),
            None,
            None
        )?;

        // Sauvegarder la transation
        let msg = MessageSerialise::from_parsed(transaction)?;
        let msg_action = MessageValideAction::new(msg, "", "", DOMAINE_NOM, TRANSACTION_DOMAINE, TypeMessageOut::Transaction);
        sauvegarder_transaction(middleware, msg_action, NOM_COLLECTION_TRANSACTIONS).await?;

        // Reset le flag dirty pour eviter multiple transactions sur le meme domaine
        let filtre = doc! {"domaine": &event.domaine};
        let ops = doc! {"$set": {"dirty": false}};
        let _ = collection.update_one(filtre, ops, None).await?;
    }

    Ok(None)
}

async fn traiter_presence_monitor<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let event: PresenceMonitor = m.message.get_msg().map_contenu(None)?;
    debug!("Presence monitor : {:?}", event);

    // Preparer valeurs applications
    let mut applications = Array::new();
    if let Some(map) = &event.services {
        for (nom_service, info_service) in map.iter() {
            if let Some(labels) = &info_service.labels {

                let nom_application = match labels.get("application") {
                    Some(a) => a.as_str(),
                    None => nom_service.as_str()
                };

                if let Some(url) = labels.get("url") {
                    if let Some(securite) = labels.get("securite") {
                        let mut info_app = doc! {
                            "application": nom_application,
                            "securite": securite,
                            "url": url,
                        };

                        if let Some(millegrille) = labels.get("millegrille") {
                            info_app.insert("millegrille", millegrille);
                        }

                        applications.push(Bson::Document(info_app));
                    }
                }
            }
        }
    }

    debug!("Applications noeud : {:?}", &applications);

    let mut set_ops = m.message.get_msg().map_to_bson()?;
    filtrer_doc_id(&mut set_ops);

    // Retirer champ cle
    set_ops.remove("noeud_id");
    set_ops.insert("applications", applications);

    let filtre = doc! {"noeud_id": &event.noeud_id};
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {"noeud_id": &event.noeud_id, CHAMP_CREATION: Utc::now(), "dirty": true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    debug!("Document monitor a sauvegarder : {:?}", ops);
    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
    let options = FindOneAndUpdateOptions::builder().upsert(true).build();
    let result = collection.find_one_and_update(filtre,ops, Some(options)).await?;
    debug!("Result update monitor : {:?}", result);

    // Verifier si on doit creer une nouvelle transaction
    let creer_transaction = match result {
        Some(d) => d.get_bool("dirty")?,
        None => true,
    };

    if creer_transaction {
        debug!("Creer transaction topologie pour monitor/noeud {}", &event.domaine);

        let tval = json!({
            "domaine": event.domaine,
            "noeud_id": event.noeud_id,
        });

        let transaction = middleware.formatter_message(
            &tval, Some(DOMAINE_NOM), Some(TRANSACTION_MONITOR), None, None)?;

        // Sauvegarder la transation
        let msg = MessageSerialise::from_parsed(transaction)?;
        let msg_action = MessageValideAction::new(
            msg, "", "", DOMAINE_NOM, TRANSACTION_DOMAINE, TypeMessageOut::Transaction);
        sauvegarder_transaction(middleware, msg_action, NOM_COLLECTION_TRANSACTIONS).await?;

        // Reset le flag dirty pour eviter multiple transactions sur le meme domaine
        let filtre = doc! {"noeud_id": &event.noeud_id};
        let ops = doc! {"$set": {"dirty": false}};
        let _ = collection.update_one(filtre, ops, None).await?;
    }

    Ok(None)
}

async fn traiter_transaction_domaine<M>(middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
    where M: GenerateurMessages + MongoDao
{
    let mut doc = transaction.contenu();
    let domaine = match doc.get_str("domaine") {
        Ok(d) => d,
        Err(e) => Err(format!("Erreur traitement transaction domaine {:?}", e))?
    };

    let ops = doc! {
        "$set": {"dirty": false},
        "$setOnInsert": {CHAMP_DOMAINE: domaine, CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc! {CHAMP_DOMAINE: domaine};
    let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
    let options = UpdateOptions::builder().upsert(true).build();
    match collection.update_one(filtre, ops, options).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur maj transaction topologie domaine : {:?}", e))?
    }

    let reponse = match middleware.formatter_reponse(json!({"ok": true}), None) {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur reponse transaction : {:?}", e))?
    };
    Ok(Some(reponse))
}

async fn traiter_transaction_monitor<M>(middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
    where M: GenerateurMessages + MongoDao
{
    let mut doc = transaction.contenu();
    let domaine = match doc.get_str("domaine") {
        Ok(d) => d,
        Err(e) => Err(format!("Erreur traitement transaction domaine {:?}", e))?
    };

    let ops = doc! {
        "$set": {"dirty": false},
        "$setOnInsert": {CHAMP_DOMAINE: domaine, CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc! {CHAMP_DOMAINE: domaine};
    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
    let options = UpdateOptions::builder().upsert(true).build();
    match collection.update_one(filtre, ops, options).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur maj transaction topologie domaine : {:?}", e))?
    }

    let reponse = match middleware.formatter_reponse(json!({"ok": true}), None) {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur reponse transaction : {:?}", e))?
    };
    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PresenceDomaine {
    domaine: String,
    noeud_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PresenceMonitor {
    domaine: String,
    noeud_id: String,
    services: Option<HashMap<String, InfoService>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InfoService {
    etat: Option<String>,
    labels: Option<HashMap<String, String>>,
    replicas: Option<usize>,
}

async fn liste_applications_deployees<M>(middleware: &M, message: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    // Valider le niveau de securite
    let sec_enum_opt = match message.message.get_extensions() {
        Some(extensions) => {
            // Verifier le type de securite
            match extensions.exchange_top() {
                Some(sec) => Some(sec),
                None => None
            }
        },
        None => None,
    };
    let sec_cascade = match sec_enum_opt {
        Some(s) => securite_cascade_public(&s),
        None => {
            // Aucun niveau de securite, abort
            let reponse = match middleware.formatter_reponse(json!({"ok": false}),None) {
                Ok(m) => m,
                Err(e) => Err(format!("Erreur preparation reponse applications : {:?}", e))?
            };
            return Ok(Some(reponse))
        }
    };

    let mut curseur = {
        let filtre = doc! {};
        let projection = doc! {"noeud_id": true, "domaine": true, "securite": true, "applications": true};
        let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
        let ops = FindOptions::builder().projection(Some(projection)).build();
        match collection.find(filtre, Some(ops)).await {
            Ok(c) => c,
            Err(e) => Err(format!("Erreur chargement applications : {:?}", e))?
        }
    };

    // Extraire liste d'applications
    let mut apps = Vec::new();
    while let Some(d) = curseur.next().await {
        match d {
            Ok(mut doc) => {
                let info_monitor: InformationMonitor = serde_json::from_value(serde_json::to_value(doc)?)?;

                for app in info_monitor.applications {

                    let securite = match app.securite {
                        Some(s) => match securite_enum(s.as_str()){
                            Ok(s) => s,
                            Err(e) => continue   // Skip
                        },
                        None => continue  // Skip
                    };

                    // Verifier si le demandeur a le niveau de securite approprie
                    if sec_cascade.contains(&securite) {

                        // Preparer la valeur a exporter pour les applications
                        let info_app = json!({
                            "application": app.application,
                            "securite": securite_str(&securite),
                            "url": app.url,
                        });

                        apps.push(info_app);
                    }
                }
            },
            Err(e) => warn!("Erreur chargement document : {:?}", e)
        }
    }

    debug!("Apps : {:?}", apps);
    let liste = json!({"resultats": apps});
    let reponse = match middleware.formatter_reponse(&liste,None) {
        Ok(m) => m,
        Err(e) => Err(format!("Erreur preparation reponse applications : {:?}", e))?
    };
    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InformationMonitor {
    domaine: String,
    noeud_id: String,
    securite: String,
    applications: Vec<ApplicationConfiguree>,
}
impl InformationMonitor {
    fn exporter_applications(&self) -> Vec<Value> {
        vec!()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ApplicationConfiguree {
    application: String,
    securite: Option<String>,
    url: Option<String>,
    millegrille: Option<String>,
}

async fn liste_noeuds<M>(middleware: &M, message: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("liste_noeuds");
    if ! message.verifier_exchanges(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        let refus = json!({"ok": false, "err": "Acces refuse"});
        let reponse = match middleware.formatter_reponse(&refus,None) {
            Ok(m) => m,
            Err(e) => Err(format!("Erreur preparation reponse applications : {:?}", e))?
        };
        return Ok(Some(reponse))
    }

    let mut curseur = {
        let mut filtre = doc! {};
        let msg = message.message.get_msg();
        if let Some(noeud_id) = msg.contenu.get("noeud_id") {
            if let Some(noeud_id) = noeud_id.as_str() {
                filtre.insert("noeud_id", millegrilles_common_rust::bson::Bson::String(noeud_id.into()));
            }
        }

        // let projection = doc! {"noeud_id": true, "domaine": true, "securite": true};
        let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
        // let ops = FindOptions::builder().projection(Some(projection)).build();
        match collection.find(filtre, None).await {
            Ok(c) => c,
            Err(e) => Err(format!("Erreur chargement applications : {:?}", e))?
        }
    };

    let mut noeuds = Vec::new();
    while let Some(r) = curseur.next().await {
        match r {
            Ok(mut d) => {
                filtrer_doc_id(&mut d);
                noeuds.push(d);
            },
            Err(e) => warn!("Erreur lecture document sous liste_noeuds() : {:?}", e)
        }
    }

    debug!("Noeuds : {:?}", noeuds);
    let liste = json!({"resultats": noeuds});
    let reponse = match middleware.formatter_reponse(&liste,None) {
        Ok(m) => m,
        Err(e) => Err(format!("Erreur preparation reponse noeuds : {:?}", e))?
    };
    Ok(Some(reponse))
}

async fn liste_domaines<M>(middleware: &M, message: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("liste_domaines");
    if ! message.verifier_exchanges(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        let refus = json!({"ok": false, "err": "Acces refuse"});
        let reponse = match middleware.formatter_reponse(&refus,None) {
            Ok(m) => m,
            Err(e) => Err(format!("Erreur preparation reponse applications : {:?}", e))?
        };
        return Ok(Some(reponse))
    }

    let mut curseur = {
        let projection = doc! {"noeud_id": true, "domaine": true, CHAMP_MODIFICATION: true};
        let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
        let ops = FindOptions::builder().projection(Some(projection)).build();
        match collection.find(doc!{}, Some(ops)).await {
            Ok(c) => c,
            Err(e) => Err(format!("Erreur chargement domaines : {:?}", e))?
        }
    };

    let mut domaines = Vec::new();
    while let Some(r) = curseur.next().await {
        match r {
            Ok(mut d) => {
                filtrer_doc_id(&mut d);
                domaines.push(d);
            },
            Err(e) => warn!("Erreur lecture document sous liste_noeuds() : {:?}", e)
        }
    }

    debug!("Domaines : {:?}", domaines);
    let liste = json!({"resultats": domaines});
    let reponse = match middleware.formatter_reponse(&liste,None) {
        Ok(m) => m,
        Err(e) => Err(format!("Erreur preparation reponse domaines : {:?}", e))?
    };
    Ok(Some(reponse))
}

#[cfg(test)]
mod test_integration {
    use crate::test_setup::setup;
    use crate::validateur_pki_mongo::preparer_middleware_pki;

    use super::*;
    use millegrilles_common_rust::tokio;
    use millegrilles_common_rust::formatteur_messages::FormatteurMessage;

    #[tokio::test]
    async fn test_liste_applications() {
        setup("test_liste_applications");
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(spawn(async move {

            let message = {
                let contenu = json!({});
                let mm = middleware.formatter_message(&contenu, None, None, None, None).expect("mm");
                let ms = MessageSerialise::from_parsed(mm).expect("ms");
                let mut mva = MessageValideAction::new(ms, "", "", "", "", TypeMessageOut::Transaction);
                mva.exchange = Some(String::from("3.protege"));
                mva
            };

            debug!("Duree test_liste_applications");
            let reponse = liste_applications_deployees(middleware.as_ref(), message).await.expect("reponse");
            debug!("Reponse test_liste_applications : {:?}", reponse);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }


}