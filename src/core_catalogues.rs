use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageReponse, RoutageMessageAction};
use millegrilles_common_rust::middleware::{thread_emettre_presence_domaine, Middleware, sauvegarder_traiter_transaction};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_value, convertir_to_bson, filtrer_doc_id, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb as mongodb;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::serde_json as serde_json;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, TraiterTransaction, Transaction, TriggerTransaction};
use mongodb::options::{FindOptions, UpdateOptions};
use serde::{Serialize, Deserialize};

use crate::validateur_pki_mongo::MiddlewareDbPki;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageMilleGrillesRefDefault, MessageValidable, RoutageMessageOwned};

use millegrilles_common_rust::error::Error as CommonError;

// Constantes
pub const DOMAINE_NOM: &str = "CoreCatalogues";
pub const NOM_COLLECTION_CATALOGUES: &str = "CoreCatalogues/catalogues";
pub const NOM_COLLECTION_CATALOGUES_VERSIONS: &str = "CoreCatalogues/catalogues_versions";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

const NOM_Q_TRANSACTIONS: &str = "CoreCatalogues/transactions";
const NOM_Q_VOLATILS: &str = "CoreCatalogues/volatils";
const NOM_Q_TRIGGERS: &str = "CoreCatalogues/triggers";

const REQUETE_INFO_APPLICATION: &str = "infoApplication";
const REQUETE_LISTE_APPLICATIONS: &str = "listeApplications";
const REQUETE_VERSIONS_APPLICATION: &str = "listeVersionsApplication";
const TRANSACTION_APPLICATION: &str = "catalogueApplication";

const INDEX_NOMS_CATALOGUES: &str = "noms_catalogues";
const CHAMP_NOM_CATALOGUE: &str = "nom";
const CHAMP_VERSION: &str = "version";

/// Instance statique du gestionnaire de catalogues
pub const GESTIONNAIRE_CATALOGUES: GestionnaireDomaineCatalogues = GestionnaireDomaineCatalogues {};

// static mut REGLES_VALIDATION_CATALOGUE: VerificateurRegles = VerificateurRegles { regles_disjointes: None, regles_conjointes: None };

/// Initialise les regles de validation pour le catalogue
// pub fn init_regles_validation() {
//     let regle_idmg = RegleValidationIdmg { idmg: String::from("zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf") };
//     unsafe {
//         REGLES_VALIDATION_CATALOGUE.ajouter_disjointe(regle_idmg);
//         debug!("init_regles_validation Regles de validation catalogue chargees : {:?}", REGLES_VALIDATION_CATALOGUE);
//     }
// }

#[derive(Clone)]
pub struct GestionnaireDomaineCatalogues {}

#[async_trait]
impl TraiterTransaction for GestionnaireDomaineCatalogues {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireDomaineCatalogues {
    #[inline]
    fn get_nom_domaine(&self) -> String {DOMAINE_NOM.into()}
    #[inline]
    fn get_collection_transactions(&self) -> Option<String> {Some(NOM_COLLECTION_TRANSACTIONS.into())}

    fn get_collections_documents(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![
            String::from(NOM_COLLECTION_CATALOGUES),
        ])
    }

    #[inline]
    fn get_q_transactions(&self) -> Result<Option<String>, CommonError> {Ok(Some(NOM_Q_TRANSACTIONS.into()))}
    #[inline]
    fn get_q_volatils(&self) -> Result<Option<String>, CommonError> {Ok(Some(NOM_Q_VOLATILS.into()))}
    #[inline]
    fn get_q_triggers(&self) -> Result<Option<String>, CommonError> {Ok(Some(NOM_Q_TRIGGERS.into()))}

    fn preparer_queues(&self) -> Result<Vec<QueueType>, CommonError> { Ok(preparer_queues()) }

    async fn preparer_database<M>(&self, middleware: &M)
        -> Result<(), millegrilles_common_rust::error::Error>
        where M: MongoDao + ConfigMessages
    {
        preparer_index_mongodb_custom(middleware).await  // Fonction plus bas
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
        where M: Middleware + 'static
    {
        consommer_requete(middleware, message).await  // Fonction plus bas
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
        where M: Middleware + 'static
    {
        consommer_commande(middleware, message, self).await  // Fonction plus bas
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
        where M: Middleware + 'static
    {
        consommer_transaction(middleware, message).await  // Fonction plus bas
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
        where M: Middleware + 'static
    {
        consommer_evenement(middleware, message, self).await  // Fonction plus bas
    }

    async fn entretien<M>(self: &'static Self, middleware: Arc<M>)
        where M: Middleware + 'static
    {
        entretien(middleware).await  // Fonction plus bas
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), millegrilles_common_rust::error::Error> where M: Middleware + 'static
    {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await   // Fonction plus bas
    }
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 3.protege seulement
    let requetes = vec![REQUETE_INFO_APPLICATION, REQUETE_LISTE_APPLICATIONS, REQUETE_VERSIONS_APPLICATION];
    for req in requetes {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
    }

    let commandes = vec![
        TRANSACTION_APPLICATION,  // Transaction est initialement recue sous forme de commande uploadee par ServiceMonitor ou autre source
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
            autodelete: false,
        }
    ));

    let mut rk_transactions = Vec::new();
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_APPLICATION).into(),
        exchange: Securite::L4Secure
    });

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

    queues
}

/// Creer index MongoDB
async fn preparer_index_mongodb_custom<M>(middleware: &M) -> Result<(), millegrilles_common_rust::error::Error>
where M: MongoDao + ConfigMessages
{

    // Transactions

    // Index transactions par uuid-transaction
    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from("index_champ_id")),
        unique: true
    };
    let champs_index_transactions = vec!(
        ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_ID), direction: 1}
    );
    middleware.create_index(
        middleware,
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
        middleware,
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
        middleware,
        NOM_COLLECTION_TRANSACTIONS,
        champs_index_transactions,
        Some(options_unique_transactions)
    ).await?;

    // Index catalogues
    let options_unique_catalogues = IndexOptions {
        nom_index: Some(String::from(INDEX_NOMS_CATALOGUES)),
        unique: true
    };
    let champs_index_catalogues = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_NOM_CATALOGUE), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_CATALOGUES,
        champs_index_catalogues,
        Some(options_unique_catalogues)
    ).await?;

    // catalogues_versions
    let options_unique_catalogues_versions = IndexOptions {
        nom_index: Some(String::from(INDEX_NOMS_CATALOGUES)),
        unique: true
    };
    let champs_index_catalogues_versions = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_NOM_CATALOGUE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_VERSION), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_CATALOGUES_VERSIONS,
        champs_index_catalogues_versions,
        Some(options_unique_catalogues_versions)
    ).await?;

    Ok(())
}

async fn entretien<M>(middleware: Arc<M>)
    where M: Middleware + 'static
{

    let mut catalogues_charges = false;

    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);

        if middleware.get_mode_regeneration() == true {
            debug!("entretien Mode regeneration, skip entretien");
            continue;
        }

        if ! catalogues_charges {
            debug!("Charger catalogues");

            let commande = json!({});
            let routage = RoutageMessageAction::builder(DOMAINE_APPLICATION_INSTANCE, "transmettreCatalogues", vec![Securite::L3Protege])
                .build();
            match middleware.transmettre_commande(routage, &commande).await {
                Ok(r) => {
                    debug!("Reponse demande catalogues : {:?}", r);
                    catalogues_charges = true;
                },
                Err(e) => {
                    error!("Erreur demande catalogues : {:?}", e);
                }
            }
        }
    }
}

async fn consommer_requete<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &message.message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.
    let (domaine, action) = match &message.type_message {
        TypeMessageOut::Requete(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_requete Mauvais type de message"))?
        }
    };

    match domaine.as_str() {
        DOMAINE_NOM => {
            match action.as_str() {
                REQUETE_LISTE_APPLICATIONS => liste_applications(middleware).await,
                REQUETE_VERSIONS_APPLICATION => liste_versions_application(middleware, message).await,
                REQUETE_INFO_APPLICATION => repondre_application(middleware, message).await,
                _ => {
                    error!("Message action inconnue : '{}'. Message dropped.", action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete domaine inconnu : '{}'. Message dropped.", domaine);
            Ok(None)
        },
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDomaineCatalogues)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: Middleware + 'static
{
    debug!("Consommer commande : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges_string(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE)))? {
        true => Ok(()),
        false => {
            match m.certificat.verifier_delegation_globale(String::from(DELEGATION_GLOBALE_PROPRIETAIRE))? {
                true => Ok(()),
                false => Err(format!("Commande autorisation invalide (pas 3.protege ou 4.secure)"))
            }
        },
    }?;

    let action = match &m.type_message {
        TypeMessageOut::Commande(r) => {
            r.action.clone()
        }
        _ => Err(format!("consommer_commande Mauvais type de de message"))?
    };

    match action.as_str() {
        // Commandes standard
        TRANSACTION_APPLICATION => traiter_commande_application(middleware, m, gestionnaire).await,
    //     COMMANDE_RESTAURER_TRANSACTIONS => restaurer_transactions(middleware.clone()).await,
    //     COMMANDE_RESET_BACKUP => reset_backup_flag(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS).await,
    //
    //     // Commandes specifiques au domaine
    //     PKI_COMMANDE_SAUVEGARDER_CERTIFICAT | PKI_COMMANDE_NOUVEAU_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware.as_ref(), m).await,
    //
    //     // Commandes inconnues
        _ => Err(format!("Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
    }
}

// async fn restaurer_transactions(middleware: Arc<MiddlewareDbPki>) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> {
//     let noms_collections_docs = vec! [
//         String::from(NOM_COLLECTION_CATALOGUES)
//     ];
//
//     let processor = ProcesseurTransactions::new();
//
//     restaurer(
//         middleware.clone(),
//         DOMAINE_NOM,
//         NOM_COLLECTION_TRANSACTIONS,
//         &noms_collections_docs,
//         &processor
//     ).await?;
//
//     Ok(None)
// }

async fn consommer_transaction<M>(_middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer transaction : {:?}", &m.message);

    let action = match &m.type_message {
        TypeMessageOut::Transaction(r) => {
            r.action.clone()
        },
        _ => Err(format!("consommer_transaction Mauvais type de message"))?
    };

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE)))? {
        true => Ok(()),
        false => Err(format!("core.catalogue.consommer_transaction Autorisation invalide (pas 4.secure) : action = {}", action)),
    }?;

    match action.as_str() {
    //     PKI_TRANSACTION_NOUVEAU_CERTIFICAT => {
    //         sauvegarder_transaction(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
    //         Ok(None)
    //     },
        _ => Err(format!("Mauvais type d'action pour une transaction : {}", action))?,
    }

    Ok(None)
}

async fn consommer_evenement<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDomaineCatalogues)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer evenement : {:?}", &m.message);

    let action = match &m.type_message {
        TypeMessageOut::Transaction(r) => {
            r.action.clone()
        },
        _ => Err(format!("consommer_evenement Mauvais type de message"))?
    };

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        true => Ok(()),
        false => Err(format!("core_catalogues.consommer_evenement Autorisation invalide (pas 3.protege/4.secure) : action = {}", action)),
    }?;

    match action.as_str() {
        TRANSACTION_APPLICATION => traiter_commande_application(middleware, m, gestionnaire).await,
        _ => Err(format!("core_catalogues.consommer_evenement Mauvais type d'action pour un evenement : {}", action))?,
    }
}

struct ProcesseurTransactions {}
impl ProcesseurTransactions {
    pub fn new() -> Self {
        ProcesseurTransactions {}
    }
}

#[async_trait]
impl TraiterTransaction for ProcesseurTransactions {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        Ok(aiguillage_transaction(middleware, transaction).await?)
    }
}

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
        T: TryInto<TransactionValide>
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(format!("aiguillage_transaction Erreur try_into"))?
    };
    let message_id = transaction.transaction.id.clone();
    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => {
            match inner.action.as_ref() {
                Some(inner) => inner.clone(),
                None => Err(format!("Transaction {} n'a pas d'action", message_id))?
            }
        },
        None => Err(format!("Transaction {} n'a pas de routage", message_id))?
    };

    match action.as_str() {
        TRANSACTION_APPLICATION => maj_catalogue(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", message_id, action))?,
    }
}

async fn traiter_transaction<M>(_domaine: &str, middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    // let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
    let message_ref = m.message.parse()?;
    let message_contenu = match message_ref.contenu() {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion message contenu() {:?} : {:?}", m, e))?,
    };
    let trigger: TriggerTransaction = match message_contenu.deserialize() {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?,
    };

    let transaction = charger_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &trigger).await?;
    debug!("Traitement transaction, chargee : {:?}", transaction.transaction.id);

    let uuid_transaction = transaction.transaction.id.clone();
    let reponse = aiguillage_transaction(middleware, transaction).await;
    if reponse.is_ok() {
        // Marquer transaction completee
        debug!("Transaction traitee {}, marquer comme completee", uuid_transaction);
        marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &uuid_transaction, EtatTransaction::Complete).await?;
    }

    reponse
}

async fn traiter_cedule<M>(_middleware: &M, _trigger: &MessageCedule)
    -> Result<(), millegrilles_common_rust::error::Error>
where M: ValidateurX509 {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
}

#[derive(Clone, Deserialize)]
struct MessageCatalogue {
    catalogue: MessageMilleGrillesOwned,
}

async fn traiter_commande_application<M>(middleware: &M, commande: MessageValide, gestionnaire: &GestionnaireDomaineCatalogues)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + MongoDao + GenerateurMessages
{
    debug!("traiter_commande_application Traitement catalogue application {:?}", commande.type_message);

    let mut message_catalogue: MessageCatalogue = {
        let message_ref = commande.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        message_contenu.deserialize()?
    };

    let info_catalogue: CatalogueApplication = message_catalogue.catalogue.deserialize()?;
    debug!("traiter_commande_application Information catalogue charge : {:?}", info_catalogue);

    // Verifier la signature du catalogue (ne verifie pas le certificat)
    let catalogue_buffer: MessageMilleGrillesBufferDefault = message_catalogue.catalogue.try_into()?;
    let mut catalogue_ref = catalogue_buffer.parse()?;
    catalogue_ref.verifier_signature()?;

    let collection_catalogues = middleware.get_collection(NOM_COLLECTION_CATALOGUES_VERSIONS)?;
    let version = info_catalogue.version.as_str();
    let filtre = doc! {
        CHAMP_NOM_CATALOGUE: info_catalogue.nom.as_str(),
        CHAMP_VERSION: version,
    };

    let doc_catalogue = collection_catalogues.find_one(filtre, None).await?;
    if doc_catalogue.is_some() {
        debug!("traiter_commande_application Catalogue {} version {} deja dans DB, skip.", info_catalogue.nom, info_catalogue.version);
        return Ok(None)
    }

    match &doc_catalogue {
        Some(d) => {
            let version = d.get_str(CHAMP_VERSION)?;
            // Verifier si la version recue est plus grande que celle sauvegardee
            debug!("Version recue : {}, dans DB : {}", info_catalogue.version, version);

            // Si version moins grande, on skip
            if version == info_catalogue.version {
                debug!("Meme version de catalogue, on skip");
                return Ok(None)
            }
        },
        None => (),
    };

    // Valider le certificat et regles du catalogues.
    match middleware.valider_certificat_idmg(&catalogue_ref, "catalogues").await {
        Ok(inner) => {
            debug!("traiter_commande_application Catalogue accepte - certificat valide : {}/{}",
                &info_catalogue.nom, &info_catalogue.version);
            // Conserver la transaction et la traiter immediatement
            sauvegarder_traiter_transaction(middleware, commande, gestionnaire).await?;
        },
        Err(e) => {
            error!("traiter_commande_application Catalogue rejete - certificat invalide : {}/{} : {:?}", &info_catalogue.nom, &info_catalogue.version, e);
        }
    }

    Ok(None)
}

#[derive(Clone, Debug, Deserialize)]
struct CatalogueApplication {
    nom: String,
    version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Catalogue {
    nom: String,
    securite: String,
    version: String,
    description: Option<HashMap<String, String>>,
    dependances: Option<Vec<Value>>,
    nginx: Option<HashMap<String, Value>>
}

async fn maj_catalogue<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("maj_catalogue Sauvegarder application recu via catalogue (transaction)");

    // let catalogue: Catalogue = match transaction.convertir() {
    //     Ok(inner) => inner,
    //     Err(e) => Err(format!("core_catalogues.maj_catalogue Erreur transaction.convertir {:?}", e))?
    // };

    debug!("maj_catalogue Parse catalogue\n{}", transaction.transaction.contenu);
    // let escaped_catalogue: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;

    let transaction_catalogue: MessageCatalogue = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("core_catalogues.maj_catalogue Erreur transaction.convertir {:?}", e))?
    };

    let catalogue: Catalogue = match transaction_catalogue.catalogue.deserialize() {
        Ok(inner) => inner,
        Err(e) => Err(format!("core_catalogues.maj_catalogue Erreur catalogue map_contenu vers Catalogue {:?}", e))?
    };

    let nom = catalogue.nom.clone();
    let version = catalogue.version.clone();
    // let contenu = transaction.contenu();
    // let nom = match contenu.get_str("nom") {
    //     Ok(c) => Ok(c.to_owned()),
    //     Err(e) => Err(format!("Champ nom manquant de transaction application : {:?}", e)),
    // }?;

    // Filtrer le contenu (retirer champs _)
    let set_ops = match convertir_to_bson(catalogue) {
        Ok(inner) => inner,
        Err(e) => Err(format!("core_catalogues.maj_catalogue Erreur convertir_to_bson {:?}", e))?
    };

    // let iter: millegrilles_common_rust::bson::document::IntoIter = contenu.into_iter();
    // for (k, v) in iter {
    //     //if ! k.starts_with("_") && k != TRANSACTION_CHAMP_ENTETE {
    //         set_ops.insert(k, v);
    //     //}
    // }

    debug!("set-ops : {:?}", set_ops);
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    {
        let collection_catalogues_versions = middleware.get_collection(NOM_COLLECTION_CATALOGUES_VERSIONS)?;
        let filtre = doc! { CHAMP_NOM_CATALOGUE: &nom, CHAMP_VERSION: &version };
        let opts = UpdateOptions::builder().upsert(true).build();
        let resultat = match collection_catalogues_versions.update_one(filtre, ops.clone(), Some(opts)).await {
            Ok(r) => r,
            Err(e) => Err(format!("core_catalogues.maj_catalogue Erreur maj document catalogue avec mongo : {:?}", e))?
        };
        debug!("Resultat maj catalogue_versions : {:?}", resultat);
    }

    {
        let filtre = doc! { "nom": &nom };
        let collection_catalogues = middleware.get_collection(NOM_COLLECTION_CATALOGUES)?;
        let opts = UpdateOptions::builder().upsert(true).build();
        let resultat = match collection_catalogues.update_one(filtre, ops, Some(opts)).await {
            Ok(r) => r,
            Err(e) => Err(format!("Erreur maj document catalogue avec mongo : {:?}", e))?
        };
        debug!("Resultat maj catalogues : {:?}", resultat);
    }

    Ok(None)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogueDependance {
    name: Option<String>,
    image: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogueApplicationDeps {
    nom: String,
    version: String,
    securite: Option<String>,
    dependances: Option<Vec<CatalogueDependance>>,
}

#[derive(Serialize)]
struct ReponseListeApplications {
    ok: bool,
    resultats: Option<Vec<CatalogueApplicationDeps>>
}

async fn liste_applications<M>(middleware: &M)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let filtre = doc! {};
    let projection = doc!{
        "nom": true,
        "version": true,
        "securite": true,
        "dependances.name": true,
        "dependances.image": true,
    };

    let collection = middleware.get_collection_typed::<CatalogueApplicationDeps>(NOM_COLLECTION_CATALOGUES)?;
    let ops = FindOptions::builder()
        .projection(Some(projection))
        .build();
    let mut curseur = match collection.find(filtre, Some(ops)).await {
        Ok(c) => c,
        Err(e) => Err(format!("Erreur chargement applications : {:?}", e))?
    };

    let mut apps = Vec::new();
    while let Some(row) = curseur.next().await {
        let catalogue = row?;
        apps.push(catalogue);
    }

    debug!("Apps : {:?}", apps);
    let reponse = ReponseListeApplications { ok: true, resultats: Some(apps) };

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Deserialize)]
struct RequeteVersionsApplication {
    nom: String,
}

async fn liste_versions_application<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteVersionsApplication = message_contenu.deserialize()?;

    let filtre = doc! { "nom": &requete.nom };
    let projection = doc!{
        "nom": true,
        "version": true,
        "dependances.name": true,
        "dependances.image": true,
        "securite": true,
    };

    let collection = middleware.get_collection_typed::<CatalogueApplicationDeps>(NOM_COLLECTION_CATALOGUES_VERSIONS)?;
    let ops = FindOptions::builder()
        .projection(Some(projection))
        .build();
    let mut curseur = match collection.find(filtre, Some(ops)).await {
        Ok(c) => c,
        Err(e) => Err(format!("Erreur chargement applications : {:?}", e))?
    };

    let mut apps = Vec::new();
    while let Some(row) = curseur.next().await {
        let catalogue = row?;
        apps.push(catalogue);
    }

    debug!("Apps : {:?}", apps);
    let reponse = ReponseListeApplications { ok: true, resultats: Some(apps) };

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Deserialize)]
struct ReponseNom {
    nom: String,
}

async fn repondre_application<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let message_nom: ReponseNom = message_contenu.deserialize()?;
    let nom_application = message_nom.nom;

    let filtre = doc! {"nom": nom_application};
    let collection = middleware.get_collection(NOM_COLLECTION_CATALOGUES)?;

    let val = match collection.find_one(filtre, None).await? {
        Some(mut c) => {
            filtrer_doc_id(&mut c);
            match convertir_bson_value(c) {
                Ok(v) => v,
                Err(e) => {
                    let msg_erreur = format!("Erreur conversion doc vers json : {:?}", e);
                    warn!("{}", msg_erreur.as_str());
                    json!({"ok": false, "err": msg_erreur})
                }
            }
        },
        None => json!({"ok": false, "err": "Application inconnue"})
    };

    match middleware.build_reponse(&val) {
        Ok(m) => Ok(Some(m.0)),
        Err(e) => Err(format!("Erreur preparation reponse applications : {:?}", e))?
    }
}

#[cfg(test)]
mod test_integration {
    use crate::test_setup::setup;
    use crate::validateur_pki_mongo::preparer_middleware_pki;

    use super::*;
    use millegrilles_common_rust::tokio;
    use millegrilles_common_rust::formatteur_messages::FormatteurMessage;

// use millegrilles_common_rust::middleware::preparer_middleware_pki;

    // #[tokio::test]
    // async fn test_liste_applications() {
    //     setup("test_liste_applications");
    //     let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
    //     futures.push(spawn(async move {
    //
    //         debug!("Duree test_liste_applications");
    //         let reponse = liste_applications(middleware.as_ref()).await.expect("reponse");
    //         debug!("Reponse test_liste_applications : {:?}", reponse);
    //
    //     }));
    //     // Execution async du test
    //     futures.next().await.expect("resultat").expect("ok");
    // }
    //
    // #[tokio::test]
    // async fn test_application() {
    //     setup("test_application");
    //     let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
    //     futures.push(spawn(async move {
    //
    //         debug!("Duree test_application");
    //         let param = middleware.formatter_reponse(json!({"nom": "blynk"}), None).expect("param");
    //         let reponse = repondre_application(middleware.as_ref(), &param).await.expect("reponse");
    //         debug!("Reponse test_application : {:?}", reponse);
    //
    //     }));
    //     // Execution async du test
    //     futures.next().await.expect("resultat").expect("ok");
    // }
}