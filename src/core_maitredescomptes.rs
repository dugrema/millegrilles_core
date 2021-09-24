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
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageReponse, RoutageMessageAction};
use millegrilles_common_rust::middleware::{sauvegarder_transaction, sauvegarder_transaction_recue, thread_emettre_presence_domaine};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_value, filtrer_doc_id, IndexOptions, MongoDao, convertir_bson_deserializable, convertir_to_bson};
use millegrilles_common_rust::mongodb as mongodb;
use millegrilles_common_rust::mongodb::options::FindOneAndUpdateOptions;
use millegrilles_common_rust::multibase;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage, valider_message};
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
use std::convert::TryInto;
use crate::webauthn::{ClientAssertionResponse, CompteCredential, multibase_to_safe, valider_commande};
use webauthn_rs::base64_data::Base64UrlSafeData;

// Constantes
pub const DOMAINE_NOM: &str = "CoreMaitreDesComptes";
pub const NOM_COLLECTION_USAGERS: &str = "CoreMaitreDesComptes/usagers";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

const NOM_Q_TRANSACTIONS: &str = "CoreMaitreDesComptes/transactions";
const NOM_Q_VOLATILS: &str = "CoreMaitreDesComptes/volatils";
const NOM_Q_TRIGGERS: &str = "CoreMaitreDesComptes/triggers";

const REQUETE_CHARGER_USAGER: &str = "chargerUsager";
const REQUETE_LISTE_USAGERS: &str = "getListeUsagers";

// const COMMANDE_CHALLENGE_COMPTEUSAGER: &str = "challengeCompteUsager";
const COMMANDE_SIGNER_COMPTEUSAGER: &str = "signerCompteUsager";
const COMMANDE_ACTIVATION_TIERCE: &str = "activationTierce";

const TRANSACTION_INSCRIRE_USAGER: &str = "inscrireUsager";
const TRANSACTION_AJOUTER_CLE: &str = "ajouterCle";
const TRANSACTION_SUPPRIMER_CLES: &str = "supprimerCles";
const TRANSACTION_SUPPRIMER_USAGER: &str = "supprimerUsager";
const TRANSACTION_MAJ_USAGER_DELEGATIONS: &str = "majUsagerDelegations";
const TRANSACTION_AJOUTER_DELEGATION_SIGNEE: &str = "ajouterDelegationSignee";

const INDEX_ID_USAGER: &str = "idusager_unique";
const INDEX_NOM_USAGER: &str = "nomusager_unique";

const CHAMP_USER_ID: &str = "userId";
const CHAMP_USAGER_NOM: &str = "nomUsager";
const CHAMP_COMPTE_PRIVE: &str = "compte_prive";
const CHAMP_DELEGATION_GLOBALE: &str = "delegation_globale";
const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
const CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK: &str = "activations_par_fingerprint_pk";
const CHAMP_WEBAUTHN: &str = "webauthn";


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
        // Transactions recues sous forme de commande pour validation
        TRANSACTION_INSCRIRE_USAGER,
        TRANSACTION_AJOUTER_CLE,

        // Commandes
        COMMANDE_SIGNER_COMPTEUSAGER,
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
    debug!("traiter_message_valide_action {:?}/{:?}", reply_q, correlation_id);

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
            let routage = RoutageMessageReponse::new(reply_q, correlation_id);
            middleware.repondre(routage, reponse).await?;
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
    match message.verifier_exchanges_string(vec!(String::from(SECURITE_2_PRIVE), String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Commande autorisation invalide (pas 2.prive, 3.protege ou 4.secure)")),
    }?;

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                // liste_applications_deployees(middleware, message).await,
                REQUETE_CHARGER_USAGER => charger_usager(middleware, message).await,
                REQUETE_LISTE_USAGERS => liste_usagers(middleware, message).await,
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
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_2_PRIVE), String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Commande autorisation invalide (pas 2.prive, 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        // Commandes standard

        // Transactions recues sous forme de commande
        TRANSACTION_INSCRIRE_USAGER => inscrire_usager(middleware.as_ref(), m).await,
        TRANSACTION_AJOUTER_CLE => ajouter_cle(middleware.as_ref(), m).await,

        //traiter_commande_application(middleware.as_ref(), m).await,
        COMMANDE_SIGNER_COMPTEUSAGER => signer_compte_usager(middleware.as_ref(), m).await,
        COMMANDE_CHALLENGE_COMPTEUSAGER => todo!(),
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
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        TRANSACTION_INSCRIRE_USAGER | TRANSACTION_AJOUTER_CLE => {
            sauvegarder_transaction(middleware, &m, NOM_COLLECTION_TRANSACTIONS).await?;
            Ok(None)
        },
        _ => Err(format!("Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_evenement(middleware: &(impl ValidateurX509 + GenerateurMessages + MongoDao), m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> {
    debug!("Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        EVENEMENT_TRANSACTION_PERSISTEE => Ok(traiter_transaction(DOMAINE_NOM, middleware, m).await?),
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
        TRANSACTION_INSCRIRE_USAGER => sauvegarder_inscrire_usager(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn charger_usager<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("charger_usager : {:?}", &message.message);
    let requete: RequeteUsager = message.message.get_msg().map_contenu(None)?;

    let mut filtre = doc!{};
    if let Some(nom_usager) = requete.nom_usager {
        filtre.insert(CHAMP_USAGER_NOM, nom_usager);
    }
    if let Some(user_id) = requete.user_id {
        filtre.insert(CHAMP_USER_ID, user_id);
    }

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
        Err(e) => Err(format!("Erreur preparation reponse charger_usager : {:?}", e))?
    }
}

async fn liste_usagers<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("liste_usagers : {:?}", &message.message);
    let requete: RequeteListeUsagers = message.message.get_msg().map_contenu(None)?;

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

    match middleware.formatter_reponse(&val_reponse,None) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse liste_usagers : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteUsager {
    #[serde(rename="userId")]
    user_id: Option<String>,
    #[serde(rename="nomUsager")]
    nom_usager: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteListeUsagers {
    liste_userids: Option<Vec<String>>,
}

async fn inscrire_usager<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer inscrire_usager : {:?}", &message.message);
    let transaction: TransactionInscrireUsager = message.message.get_msg().map_contenu(None)?;
    let nom_usager = transaction.nom_usager.as_str();

    // Verifier que l'usager n'existe pas deja (collection usagers)
    let filtre = doc!{CHAMP_USAGER_NOM: nom_usager};
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let doc_usager = collection.find_one(filtre, None).await?;
    let reponse = match doc_usager {
        Some(d) => {
            debug!("Usager {} existe deja : {:?}, on skip", nom_usager, d);
            let val = json!({"ok": false, "err": format!("Usager {} existe deja", nom_usager)});
            match middleware.formatter_reponse(&val,None) {
                Ok(m) => Ok(Some(m)),
                Err(e) => Err(format!("Erreur preparation reponse liste_usagers : {:?}", e))
            }
        },
        None => {
            let uuid_transaction = message.message.get_entete().uuid_transaction.as_str();
            debug!("L'usager '{}' n'existe pas, on le sauvegarde sous forme de transaction", nom_usager);
            sauvegarder_transaction(middleware, &message, NOM_COLLECTION_TRANSACTIONS).await?;
            let transaction: TransactionImpl = message.clone().try_into()?;
            let reponse = sauvegarder_inscrire_usager(middleware, transaction).await?;
            marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, uuid_transaction, EtatTransaction::Complete).await?;

            Ok(reponse)
        }
    }?;

    Ok(reponse)
}

async fn sauvegarder_inscrire_usager<M, T>(middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where T: Transaction,
          M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let transaction: TransactionInscrireUsager = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion en TransactionInscrireUsager : {:?}", e))?
    };
    let nom_usager = transaction.nom_usager.as_str();
    let user_id = transaction.user_id.as_str();

    let filtre = doc! {CHAMP_USAGER_NOM: nom_usager};
    let ops = doc! {
        "$set": {
            CHAMP_USER_ID: user_id,
            format!("{}.{}", CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, transaction.fingerprint_pk): {
                "associe": false,
                "date_activation": Utc::now(),
            }
        },
        "$setOnInsert": {
            CHAMP_USAGER_NOM: nom_usager,
            CHAMP_CREATION: Utc::now(),
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

    let reponse = json!({"ok": true, "userId": user_id});
    match middleware.formatter_reponse(&reponse,None) {
        Ok(m) => return Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionInscrireUsager {
    fingerprint_pk: String,
    #[serde(rename="nomUsager")]
    nom_usager: String,
    #[serde(rename="userId")]
    user_id: String,
}

/// Verifie une demande de signature de certificat pour un compte usager
/// Emet une commande autorisant la signature lorsque c'est approprie
async fn signer_compte_usager<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("signer_compte_usager : {:?}", message);

    // Valider information de reponse
    let (reply_to, correlation_id) = message.get_reply_info()?;

    // Verifier autorisation
    if ! message.verifier(
        Some(vec!(Securite::L4Secure, Securite::L3Protege, Securite::L2Prive)),
        Some(vec!(RolesCertificats::NoeudPrive, RolesCertificats::WebProtege)),
    ) {
        let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("signer_compte_usager autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err,None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        }
    }

    let commande: CommandeSignerCertificat = message.message.get_msg().map_contenu(None)?;
    let user_id = commande.user_id.as_str();

    // Charger le compte usager
    let filtre = doc! {CHAMP_USER_ID: user_id};
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let doc_usager = match collection.find_one(filtre, None).await? {
        Some(d) => d,
        None => {
            let err = json!({"ok": false, "code": 3, "err": format!("Usager inconnu : {}", user_id)});
            debug!("signer_compte_usager usager inconnu : {:?}", err);
            match middleware.formatter_reponse(&err,None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
            }
        }
    };

    // Verifier si l'usager a deja des creds WebAuthn (doit signer sa demande) ou non
    let compte_usager: CompteUsager = convertir_bson_deserializable(doc_usager.clone())?;
    let webauthn_present = match compte_usager.webauthn {
        Some(vc) => {
            ! vc.is_empty()
        },
        None => false
    };

    let (csr, activation_tierce) = if webauthn_present {
        match commande.demande_certificat {
            Some(d) => {
                // Valider signature webauthn
                let origin = match commande.origin {
                    Some(o) => o,
                    None => Err(format!("signer_compte_usager Origin absent"))?
                };
                let challenge = match commande.challenge {
                    Some(c) => c,
                    None => Err(format!("signer_compte_usager Origin absent"))?
                };
                let resultat = valider_commande(origin, challenge, &d)?;
                debug!("Resultat validation commande webauthn : {:?}", resultat);

                if ! resultat {
                    let err = json!({"ok": false, "code": 6, "err": format!("Erreur validation signature webauthn : {}", user_id)});
                    debug!("signer_compte_usager signature webauthn pour commande ajouter cle est invalide : {:?}", err);
                    match middleware.formatter_reponse(&err,None) {
                        Ok(m) => return Ok(Some(m)),
                        Err(e) => Err(format!("Erreur preparation reponse (6) signer_compte_usager : {:?}", e))?
                    }
                }

                (d.csr, d.activation_tierce)
            },
            None => {
                let err = json!({"ok": false, "code": 4, "err": format!("Compte existant, demandeCertificat est vide (erreur) : {}", user_id)});
                debug!("signer_compte_usager demandeCertificat vide : {:?}", err);
                match middleware.formatter_reponse(&err,None) {
                    Ok(m) => return Ok(Some(m)),
                    Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
                }
            }
        }
    } else {
        debug!("Le compte {} est nouveau (aucun token webauthn), on permet l'enregistrement direct", user_id);
        match commande.csr {
            Some(c) => (c, Some(false)),
            None => Err(format!("CSR absent de la commande de signature"))?
        }
    };

    // Signature est autorisee, on genere la commande de signature
    // Emettre le compte usager pour qu'il soit signe et retourne au demandeur (serveur web)
    let mut commande_signature = json!({
        CHAMP_USER_ID: user_id,
        "compte": convertir_bson_value(doc_usager)?,
        "csr": csr
    });

    // Ajouter flag tiers si active d'un autre appareil que l'origine du CSR
    // Donne le droit a l'usager de faire un login initial et enregistrer son appareil.
    if let Some(activation_tierce) = commande.activation_tierce {
        if activation_tierce {
            let commande_signature_obj = commande_signature.as_object_mut().expect("mut");
            commande_signature_obj.insert("activation_tierce".into(), Value::Bool(true));
        }
    }

    debug!("Emettre commande d'autorisation de signature certificat navigateur : {:?}", commande_signature);
    let routage = RoutageMessageAction::builder(DOMAINE_SERVICE_MONITOR, "signerNavigateur")
        .correlation_id(correlation_id)
        .reply_to(reply_to)
        .build();
    middleware.transmettre_commande(routage, &commande_signature, false).await?;

    Ok(None)    // Le message de reponse va etre emis par le module de signature de certificat
}

async fn ajouter_cle<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer ajouter_cle : {:?}", &message.message);

    // Verifier autorisation
    if ! message.verifier(
        Some(vec!(Securite::L4Secure, Securite::L3Protege, Securite::L2Prive)),
        Some(vec!(RolesCertificats::NoeudPrive, RolesCertificats::WebProtege)),
    ) {
        let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_cle autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err,None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        }
    }

    let commande: CommandeAjouterCle = message.message.get_msg().map_contenu(None)?;

    let nom_usager = commande.nom_usager.as_str();
    let fingerprint_pk = commande.fingerprint_pk.as_str();

    // Validation - s'assurer que le compte usager existe
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let compte_usager = match charger_compte_usager(middleware, nom_usager).await? {
        Some(c) => c,
        None => {
            let err = json!({"ok": false, "code": 2, "err": format!("Usager inconnu : {}", nom_usager)});
            debug!("ajouter_cle usager inconnu : {:?}", err);
            match middleware.formatter_reponse(&err,None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
            }
        }
    };

    // Verifier autorisation client - le certificat doit correspondre au user_id du compte
    let reponse_client = &commande.reponse_client;
    let mut reponse_client_serialise = MessageSerialise::from_parsed(reponse_client.to_owned())?;
    match valider_message(middleware, &mut reponse_client_serialise).await {
        Ok(()) => {
            // S'assurer que le contenu du message est coherent - credId == response.id (doit convertir en bytes)
            let rep_challenge: ReponseClientAjouterCle = reponse_client.map_contenu(None)?;
            let id_client = rep_challenge.reponse_challenge.id;
            debug!("id client : {:?}, commande a decoder : {:?}", id_client, commande.cle);
            let (_, cred_id): (_, Vec<u8>) = multibase::decode(commande.cle.cred_id)?;
            if id_client.0 != cred_id {
                debug!("Difference entre id_client et cred_id dans message ajouter cle\n{:?}\n{:?}", id_client, cred_id);
                let err = json!({"ok": false, "code": 5, "err": format!{"Permission refusee, reponseClient mismatch credId"}});
                debug!("ajouter_cle autorisation acces refuse : {:?}", err);
                match middleware.formatter_reponse(&err, None) {
                    Ok(m) => return Ok(Some(m)),
                    Err(e) => Err(format!("ajouter_cle: Erreur verification credId avec reponseClient : {:?}", e))?
                }
            }
        },
        Err(e) => {
            let err = json!({"ok": false, "code": 3, "err": format!{"Permission refusee, reponseClient invalide : {:?}", e}});
            debug!("ajouter_cle autorisation acces refuse : {:?}", err);
            match middleware.formatter_reponse(&err,None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("ajouter_cle: Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
            }
        }
    };

    if ! reponse_client_serialise.verifier_usager(compte_usager.user_id) {
        let err = json!({"ok": false, "code": 4, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_cle autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err,None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("ajouter_cle: Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        }
    }

    // Sauvegarder la transaction, marquer complete et repondre
    let uuid_transaction = message.message.get_entete().uuid_transaction.clone();
    sauvegarder_transaction(middleware, &message, NOM_COLLECTION_TRANSACTIONS).await?;
    let transaction: TransactionImpl = message.try_into()?;
    let reponse = sauvegarder_ajouter_cle(middleware, transaction).await?;
    marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, uuid_transaction.as_ref(), EtatTransaction::Complete).await?;

    Ok(reponse)
}

async fn sauvegarder_ajouter_cle<M, T>(middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where T: Transaction,
          M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let commande: CommandeAjouterCle = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion en CommandeAjouterCle : {:?}", e))?
    };
    let nom_usager = commande.nom_usager.as_str();
    let fingerprint_pk = commande.fingerprint_pk.as_str();
    let filtre = doc! {CHAMP_USAGER_NOM: nom_usager};

    let commande_bson = match convertir_to_bson(commande.cle) {
        Ok(c) => c,
        Err(e) => Err(format!("Erreur sauvegarder_ajouter_cle, echec conversion bson {:?}", e))?
    };

    let ops = doc! {
        "$push": {CHAMP_WEBAUTHN: commande_bson},
        "$set": {
            format!("{}.{}.{}", CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk, "associe"): true,
            format!("{}.{}.{}", CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk, "date_association"): Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur sauvegarde transaction sauvegarder_ajouter_cle : {:?}", e))?
    };
    debug!("Resultat ajout cle : {:?}", resultat);

    let reponse = json!({"ok": true, CHAMP_USAGER_NOM: nom_usager});
    match middleware.formatter_reponse(&reponse,None) {
        Ok(m) => return Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
    }
}

/// Charger un compte usager a partir du nom usager
async fn charger_compte_usager<M, S>(middleware: &M, nom_usager: S)
    -> Result<Option<CompteUsager>, Box<dyn Error>>
    where
        M: MongoDao,
        S: AsRef<str>
{
    let filtre = doc! {CHAMP_USAGER_NOM: nom_usager.as_ref()};
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    match collection.find_one(filtre, None).await? {
        Some(c) => {
            let compte: CompteUsager = convertir_bson_deserializable(c)?;
            Ok(Some(compte))
        },
        None => Ok(None)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSignerCertificat {
    #[serde(rename="userId")]
    user_id: String,
    #[serde(rename="nomUsager")]
    nom_usager: Option<String>,

    // Demande initiale (inscription usager ou nouvel appareil)
    csr: Option<String>,  // Present si demande initiale

    activation_tierce: Option<bool>,

    // Champs pour demande de signature avec preuve webauthn
    challenge: Option<String>,
    origin: Option<String>,
    #[serde(rename="demandeCertificat")]
    demande_certificat: Option<DemandeCertificat>,
    #[serde(rename="clientAssertionResponse")]
    client_assertion_response: Option<ClientAssertionResponse>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DemandeCertificat {
    csr: String,
    #[serde(rename="nomUsager")]
    nom_usager: String,
    date: usize,
    #[serde(rename="activationTierce", skip_serializing_if = "Option::is_none")]
    activation_tierce: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompteUsager {
    #[serde(rename="nomUsager")]
    nom_usager: String,
    #[serde(rename="userId")]
    user_id: String,
    webauthn: Option<Vec<CompteCredential>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeAjouterCle {
    cle: CompteCredential,
    fingerprint_pk: String,
    #[serde(rename="nomUsager")]
    nom_usager: String,
    #[serde(rename="reponseClient")]
    reponse_client: MessageMilleGrille
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseClientAjouterCle {
    #[serde(rename="reponseChallenge")]
    reponse_challenge: ReponseClientAjouteCleReponseChallenge
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseClientAjouteCleReponseChallenge {
    id: Base64UrlSafeData
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