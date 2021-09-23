use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::restaurer;
use millegrilles_common_rust::bson::{Bson, doc};
use millegrilles_common_rust::bson::Array;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::L3Protege;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::formatteur_messages::MessageSerialise;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{sauvegarder_transaction, thread_emettre_presence_domaine};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_value, filtrer_doc_id, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb as mongodb;
use millegrilles_common_rust::mongodb::options::FindOneAndUpdateOptions;
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
use serde::{Deserialize, Serialize};

use crate::validateur_pki_mongo::MiddlewareDbPki;

// Constantes
pub const DOMAINE_NOM: &str = "CoreMaitreDesComptes";
pub const NOM_COLLECTION_USAGERS: &str = "CoreMaitreDesComptes/usagers";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

const NOM_Q_TRANSACTIONS: &str = "CoreMaitreDesComptes/transactions";
const NOM_Q_VOLATILS: &str = "CoreMaitreDesComptes/volatils";
const NOM_Q_TRIGGERS: &str = "CoreMaitreDesComptes/triggers";

const REQUETE_CHARGER_USAGER: &str = "chargerUsager";
const REQUETE_LISTE_USAGERS: &str = "getListeUsagers";

const COMMANDE_CHALLENGE_COMPTEUSAGER: &str = "challengeCompteUsager";
const COMMANDE_SIGNER_COMPTEUSAGER: &str = "signerCompteUsager";
const COMMANDE_ACTIVATION_TIERCE: &str = "activationTierce";

// const TRANSACTION_DOMAINE: &str = "domaine";

const INDEX_ID_USAGER: &str = "idusager_unique";
const INDEX_NOM_USAGER: &str = "nomusager_unique";

const CHAMP_USER_ID: &str = "userId";
const CHAMP_USAGER_NOM: &str = "nomUsager";


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

    // RK 2.prive, 3.protege
    let requetes_protegees: Vec<&str> = vec![
        REQUETE_LISTE_USAGERS,
        REQUETE_CHARGER_USAGER,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
    }

    let commandes: Vec<&str> = vec![
        //TRANSACTION_APPLICATION,  // Transaction est initialement recue sous forme de commande uploadee par ServiceMonitor ou autre source
    ];
    for commande in commandes {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L2Prive});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L3Protege});
    }

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

    // Index userId
    let options_unique_noeuds = IndexOptions {
        nom_index: Some(String::from(INDEX_ID_USAGER)),
        unique: true
    };
    let champs_index_noeuds = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_USAGERS,
        champs_index_noeuds,
        Some(options_unique_noeuds)
    ).await?;

    // Index nomUsager
    let options_unique_noeuds = IndexOptions {
        nom_index: Some(String::from(INDEX_NOM_USAGER)),
        unique: true
    };
    let champs_index_noeuds = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USAGER_NOM), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_USAGERS,
        champs_index_noeuds,
        Some(options_unique_noeuds)
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

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    match message.verifier_exchanges(vec!(String::from(SECURITE_2_PRIVE), String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Commande autorisation invalide (pas 2.prive, 3.protege ou 4.secure)")),
    }?;

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                // liste_applications_deployees(middleware, message).await,
                REQUETE_CHARGER_USAGER => charger_usager(middleware, message).await,
                REQUETE_LISTE_USAGERS => todo!(),
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

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    match m.verifier_exchanges(vec!(String::from(SECURITE_2_PRIVE), String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Commande autorisation invalide (pas 2.prive, 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        // Commandes standard

        //traiter_commande_application(middleware.as_ref(), m).await,
        COMMANDE_CHALLENGE_COMPTEUSAGER => todo!(),
        COMMANDE_SIGNER_COMPTEUSAGER => todo!(),
        COMMANDE_ACTIVATION_TIERCE => todo!(),

        // Commandes inconnues
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
        // TRANSACTION_DOMAINE | TRANSACTION_MONITOR => {
        //     sauvegarder_transaction(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
        //     Ok(None)
        // },
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
        // EVENEMENT_PRESENCE_DOMAINE => traiter_presence_domaine(middleware, m).await,
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
        // TRANSACTION_MONITOR => traiter_transaction_monitor(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn charger_usager<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("charger_usager : {:?}", &message.message);
    let requete: RequeteUsager = message.message.get_msg().map_contenu(None)?;

    let filtre = doc!{"userId": &requete.user_id};
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let val = match collection.find_one(filtre, None).await? {
        Some(mut doc_usager) => {
            filtrer_doc_id(&mut doc_usager);
            match convertir_bson_value(doc_usager) {
                Ok(v) => v,
                Err(e) => {
                    let msg_erreur = format!("Erreur conversion doc vers json : {:?}", e);
                    warn!("{}", msg_erreur.as_str());
                    json!({"ok": false, "err": msg_erreur})
                }
            }
        },
        None => {
            json!({"ok": true, "reponse": false})
        }
    };

    match middleware.formatter_reponse(&val,None) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse applications : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteUsager {
    #[serde(rename="userId")]
    user_id: String,
}


#[cfg(test)]
mod test_integration {
    use crate::test_setup::setup;
    use crate::validateur_pki_mongo::preparer_middleware_pki;

    use super::*;

    #[tokio::test]
    async fn test_() {
        setup("test_liste_applications");
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(spawn(async move {

            todo!("Test!")

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

}