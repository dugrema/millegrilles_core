use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::restaurer;
use millegrilles_common_rust::bson::{Bson, doc};
use millegrilles_common_rust::bson::Array;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::{Chiffreur, Dechiffreur};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{FormatteurMessage, MessageMilleGrille, Entete, DateEpochSeconds};
use millegrilles_common_rust::formatteur_messages::MessageSerialise;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageReponse};
use millegrilles_common_rust::middleware::{IsConfigurationPki, Middleware, sauvegarder_transaction_recue, thread_emettre_presence_domaine};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_value, filtrer_doc_id, IndexOptions, MongoDao, convertir_bson_deserializable};
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
pub const DOMAINE_NOM: &str = "CoreBackup";
pub const NOM_COLLECTION_CATALOGUES_HORAIRES: &str = "CoreBackup/cataloguesHoraires";
pub const NOM_COLLECTION_CATALOGUES_QUOTIDIENS: &str = "CoreBackup/cataloguesQuotidiens";
pub const NOM_COLLECTION_RAPPORTS: &str = "CoreBackup/rapports";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

const NOM_Q_TRANSACTIONS: &str = "CoreBackup/transactions";
const NOM_Q_VOLATILS: &str = "CoreBackup/volatils";
const NOM_Q_TRIGGERS: &str = "CoreBackup/triggers";

const REQUETE_DERNIER_HORAIRE: &str = "backupDernierHoraire";

const CHAMP_DOMAINE: &str = "domaine";
const CHAMP_HEURE: &str = "heure";
const CHAMP_JOUR: &str = "jour";

const INDEX_CATALOGUES_HORAIRE: &str = "catalogues_horaire";
const INDEX_CATALOGUES_QUOTIDIEN: &str = "catalogues_quotidiens";

// const TRANSACTION_DOMAINE: &str = "domaine";

/// Instance statique du gestionnaire de backup
pub const GESTIONNAIRE_BACKUP: GestionnaireDomaineCoreBackup = GestionnaireDomaineCoreBackup {};

#[derive(Clone)]
pub struct GestionnaireDomaineCoreBackup {}

#[async_trait]
impl GestionnaireDomaine for GestionnaireDomaineCoreBackup {
    #[inline]
    fn get_nom_domaine(&self) -> &str {DOMAINE_NOM}
    #[inline]
    fn get_collection_transactions(&self) -> &str {NOM_COLLECTION_TRANSACTIONS}
    #[inline]
    fn get_q_transactions(&self) -> &str {NOM_Q_TRANSACTIONS}
    #[inline]
    fn get_q_volatils(&self) -> &str {NOM_Q_VOLATILS}
    #[inline]
    fn get_q_triggers(&self) -> &str {NOM_Q_TRIGGERS}

    fn preparer_queues(&self) -> Vec<QueueType> { preparer_queues() }

    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao {
        preparer_index_mongodb_custom(middleware).await  // Fonction plus bas
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware
    {
        consommer_requete(middleware, message).await  // Fonction plus bas
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware
    {
        consommer_commande(middleware, message).await  // Fonction plus bas
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware {
        consommer_transaction(middleware, message).await  // Fonction plus bas
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware
    {
        consommer_evenement(middleware, message).await  // Fonction plus bas
    }

    async fn entretien<M>(&self, middleware: Arc<M>) where M: Middleware {
        entretien(middleware).await  // Fonction plus bas
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
        -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction
    {
        aiguillage_transaction(middleware, transaction).await   // Fonction plus bas
    }
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 3.protege seulement
    let requetes_protegees: Vec<&str> = vec![
        REQUETE_DERNIER_HORAIRE,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
    }

    let commandes: Vec<&str> = vec![
        //TRANSACTION_APPLICATION,  // Transaction est initialement recue sous forme de commande uploadee par ServiceMonitor ou autre source
    ];
    for commande in commandes {
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
async fn preparer_index_mongodb_custom<M>(middleware: &M) -> Result<(), String>
    where M: MongoDao
{
    // Index noeuds
    let options_unique_catalogues_horaires = IndexOptions {
        nom_index: Some(String::from(INDEX_CATALOGUES_HORAIRE)),
        unique: true
    };
    let champs_index_catalogues_horaires = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_DOMAINE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_HEURE), direction: -1},
    );
    middleware.create_index(
        NOM_COLLECTION_CATALOGUES_HORAIRES,
        champs_index_catalogues_horaires,
        Some(options_unique_catalogues_horaires)
    ).await?;

    // Index noeuds
    let options_unique_catalogues_quotidiens = IndexOptions {
        nom_index: Some(String::from(INDEX_CATALOGUES_QUOTIDIEN)),
        unique: true
    };
    let champs_index_catalogues_quotidiens = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_DOMAINE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_JOUR), direction: -1},
    );
    middleware.create_index(
        NOM_COLLECTION_CATALOGUES_QUOTIDIENS,
        champs_index_catalogues_quotidiens,
        Some(options_unique_catalogues_quotidiens)
    ).await?;

    Ok(())
}

async fn entretien<M>(_middleware: Arc<M>)
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigurationPki + IsConfigNoeud + FormatteurMessage + Chiffreur + Dechiffreur
{
    let mut catalogues_charges = false;

    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

async fn traiter_cedule<M>(_middleware: &M, _trigger: MessageValideAction) -> Result<(), Box<dyn Error>>
where M: ValidateurX509 + GenerateurMessages + MongoDao {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
}

async fn consommer_evenement<M>(middleware: &M, message: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: Middleware
{
    debug!("Consommer evenement : {:?}", &message.message);

    // Autorisation : doit etre de niveau 4.secure
    match message.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match message.action.as_str() {
        EVENEMENT_TRANSACTION_PERSISTEE => {
            GESTIONNAIRE_BACKUP.traiter_transaction(middleware, message).await?;
            Ok(None)
        },
        EVENEMENT_CEDULE => {
            traiter_cedule(middleware, message).await?;
            Ok(None)
        },
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", message.action))?,
    }
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &message.message);

    // Autorisation : doit etre de niveau 4.secure
    match message.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_DERNIER_HORAIRE => requete_dernier_horaire(middleware, message).await,
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

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigurationPki + IsConfigNoeud + FormatteurMessage + Chiffreur + Dechiffreur
{
    debug!("Consommer commande : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
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
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE))) {
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

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        // TRANSACTION_MONITOR => traiter_transaction_monitor(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn requete_dernier_horaire<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: GenerateurMessages + MongoDao,
{
    debug!("Consommer transaction : {:?}", &m.message);
    let requete: RequeteDernierCatalogueHoraire = m.message.get_msg().map_contenu(None)?;

    let mut filtre = doc! {
        "domaine": requete.domaine,
    };
    if let Some(partition) = requete.partition {
        filtre.insert("partition", partition);
    }
    debug!("Charger dernier backup pour : {:?}", filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_CATALOGUES_HORAIRES)?;
    let val_reponse = match collection.find_one(filtre, None).await? {
        Some(d) => {
            let doc_horaire: DocCatalogueHoraire = convertir_bson_deserializable(d)?;
            json!({
                "ok": true,
                "dernier_backup": {
                    "entete": doc_horaire.entete,
                    "heure": doc_horaire.heure,
                }
            })
        },
        None => {
            json!({"ok": true, "dernier_backup": None::<&str>})
        }
    };

    match middleware.formatter_reponse(&val_reponse,None) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteDernierCatalogueHoraire {
    domaine: String,
    partition: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocCatalogueHoraire {
    entete: Entete,
    heure: DateEpochSeconds,
}

#[cfg(test)]
mod test_integration {
    use crate::test_setup::setup;
    use crate::validateur_pki_mongo::preparer_middleware_pki;
    use millegrilles_common_rust::tokio as tokio;

    use super::*;

    #[tokio::test]
    async fn test_requete_dernier_horaire() {
        setup("test_requete_dernier_horaire");
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(spawn(async move {

            let message = {
                let contenu = json!({"domaine": "DUMMY", "partition": "DUMMY_TOO"});
                let mm = middleware.formatter_message(&contenu, None::<&str>, None, None, None).expect("mm");
                let ms = MessageSerialise::from_parsed(mm).expect("ms");
                let mut mva = MessageValideAction::new(ms, "", "", "", "", TypeMessageOut::Transaction);
                mva.exchange = Some(String::from("3.protege"));
                mva
            };
            let resultat = requete_dernier_horaire(
                middleware.as_ref(), message).await
                .expect("requete").expect("option");
            debug!("Resultat dernier horaire : {:?}", resultat);

            assert_eq!(resultat.contenu.get("ok").expect("ok").as_bool().expect("bool"), true);
            assert_eq!(resultat.contenu.get("dernier_backup").expect("dernier_backup").as_null().expect("null"), ());

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

}