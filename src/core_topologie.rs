use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, bson, DateTime, doc, to_bson};
use millegrilles_common_rust::bson::Array;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{Datelike, Timelike, Utc};
use millegrilles_common_rust::common_messages::{MessageReponse, PresenceFichiersRepertoire, ReponseInformationConsignationFichiers, RequeteConsignationFichiers, RequeteDechiffrage};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L1Public, L2Prive, L3Protege};
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::messages_generiques::{MessageCedule, ReponseCommande};
use millegrilles_common_rust::middleware::{EmetteurNotificationsTrait, Middleware, sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable, thread_emettre_presence_domaine};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_deserializable, convertir_bson_value, convertir_to_bson, filtrer_doc_id, IndexOptions, MongoDao};
use millegrilles_common_rust::{chrono, millegrilles_cryptographie, mongodb as mongodb};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::chiffrage_cle::CommandeSauvegarderCle;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, ReturnDocument};
use millegrilles_common_rust::notifications::NotificationMessageInterne;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::reqwest::Url;
use millegrilles_common_rust::serde_json::{json, Map, Value};
use millegrilles_common_rust::serde_json as serde_json;
use millegrilles_common_rust::serde_helpers as serde_helpers;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, TraiterTransaction, Transaction, TriggerTransaction};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;

use mongodb::options::{FindOptions, UpdateOptions};
use crate::core_maitredescomptes::NOM_COLLECTION_USAGERS;

use crate::validateur_pki_mongo::MiddlewareDbPki;

// Constantes
pub const DOMAINE_NOM: &str = "CoreTopologie";
pub const NOM_COLLECTION_DOMAINES: &str = "CoreTopologie/domaines";
pub const NOM_COLLECTION_INSTANCES: &str = "CoreTopologie/instances";
pub const NOM_COLLECTION_NOEUDS: &str = NOM_COLLECTION_INSTANCES;
pub const NOM_COLLECTION_MILLEGRILLES: &str = "CoreTopologie/millegrilles";
pub const NOM_COLLECTION_MILLEGRILLES_ADRESSES: &str = "CoreTopologie/millegrillesAdresses";
pub const NOM_COLLECTION_FICHIERS: &str = "CoreTopologie/fichiers";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

pub const DOMAINE_PRESENCE_NOM: &str = "CoreTopologie";
pub const DOMAINE_FICHIERS: &str = "fichiers";

const NOM_Q_TRANSACTIONS: &str = "CoreTopologie/transactions";
const NOM_Q_VOLATILS: &str = "CoreTopologie/volatils";
const NOM_Q_TRIGGERS: &str = "CoreTopologie/triggers";

const REQUETE_APPLICATIONS_DEPLOYEES: &str = "listeApplicationsDeployees";
const REQUETE_LISTE_DOMAINES: &str = "listeDomaines";
const REQUETE_LISTE_NOEUDS: &str = "listeNoeuds";
// const REQUETE_INFO_DOMAINE: &str = "infoDomaine";
// const REQUETE_INFO_NOEUD: &str = "infoNoeud";
const REQUETE_RESOLVE_IDMG: &str = "resolveIdmg";
const REQUETE_FICHE_MILLEGRILLE: &str = "ficheMillegrille";
const REQUETE_APPLICATIONS_TIERS: &str = "applicationsTiers";
const REQUETE_CONSIGNATION_FICHIERS: &str = "getConsignationFichiers";
const REQUETE_CONFIGURATION_FICHIERS: &str = "getConfigurationFichiers";
const REQUETE_GET_CLE_CONFIGURATION: &str = "getCleConfiguration";

const TRANSACTION_DOMAINE: &str = "domaine";
const TRANSACTION_INSTANCE: &str = "instance";
const TRANSACTION_MONITOR: &str = TRANSACTION_INSTANCE;
const TRANSACTION_SUPPRIMER_INSTANCE: &str = "supprimerInstance";
const TRANSACTION_SET_FICHIERS_PRIMAIRE: &str = "setFichiersPrimaire";
const TRANSACTION_CONFIGURER_CONSIGNATION: &str = "configurerConsignation";
const TRANSACTION_SET_CONSIGNATION_INSTANCE: &str = "setConsignationInstance";

const EVENEMENT_PRESENCE_MONITOR: &str = "presence";
const EVENEMENT_PRESENCE_FICHIERS: &str = EVENEMENT_PRESENCE_MONITOR;
const EVENEMENT_FICHE_PUBLIQUE: &str = "fichePublique";
const EVENEMENT_INSTANCE_SUPPRIMEE: &str = "instanceSupprimee";
const EVENEMENT_APPLICATION_DEMARREE: &str = "applicationDemarree";
const EVENEMENT_APPLICATION_ARRETEE: &str = "applicationArretee";
const EVENEMENT_MODIFICATION_CONSIGNATION: &str = "modificationConsignation";

const INDEX_DOMAINE: &str = "domaine";
const INDEX_NOEUDS: &str = "noeuds";
const INDEX_IDMG: &str = "idmg";
const INDEX_ADRESSES: &str = "adresses";
const INDEX_ADRESSE: &str = "adresse";

const CHAMP_DOMAINE: &str = "domaine";
const CHAMP_INSTANCE_ID: &str = "instance_id";
const CHAMP_NOEUD_ID: &str = CHAMP_INSTANCE_ID;
const CHAMP_ADRESSE: &str = "adresse";
const CHAMP_ADRESSES: &str = "adresses";
const CHAMP_CONSIGNATION_ID: &str = "consignation_id";

const ADRESSE_PREFERENCE_PRIMAIRE: u8 = 1;
const ADRESSE_PREFERENCE_SECONDAIRE: u8 = 2;

const ADRESSE_NATURE_DNS: &str = "dns";
const ADRESSE_NATURE_IP4: &str = "ip4";
const ADRESSE_NATURE_IP6: &str = "ip6";
const ADRESSE_NATURE_ONION: &str = "onion";

const DEFAULT_CONSIGNATION_URL: &str = "https://fichiers:1443";

// permissionDechiffrage
// listerNoeudsAWSS3

/// Instance statique du gestionnaire de maitredescomptes
pub const GESTIONNAIRE_TOPOLOGIE: GestionnaireDomaineTopologie = GestionnaireDomaineTopologie {};

#[derive(Clone)]
pub struct GestionnaireDomaineTopologie {}

#[async_trait]
impl TraiterTransaction for GestionnaireDomaineTopologie {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireDomaineTopologie {
    #[inline]
    fn get_nom_domaine(&self) -> String { DOMAINE_NOM.into() }
    #[inline]
    fn get_collection_transactions(&self) -> Option<String> { Some(NOM_COLLECTION_TRANSACTIONS.into()) }

    fn get_collections_documents(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![
            String::from(NOM_COLLECTION_DOMAINES),
            String::from(NOM_COLLECTION_NOEUDS),
        ])
    }

    #[inline]
    fn get_q_transactions(&self) -> Result<Option<String>, CommonError> { Ok(Some(NOM_Q_TRANSACTIONS.into())) }
    #[inline]
    fn get_q_volatils(&self) -> Result<Option<String>, CommonError> { Ok(Some(NOM_Q_VOLATILS.into())) }
    #[inline]
    fn get_q_triggers(&self) -> Result<Option<String>, CommonError> { Ok(Some(NOM_Q_TRIGGERS.into())) }

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

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
        where M: Middleware + 'static
    {
        consommer_transaction(self, middleware, message).await  // Fonction plus bas
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

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), millegrilles_common_rust::error::Error> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 3.protege seulement
    let requetes_protegees = vec![
        REQUETE_LISTE_DOMAINES,
        REQUETE_LISTE_NOEUDS,
        REQUETE_CONFIGURATION_FICHIERS,
        // REQUETE_INFO_DOMAINE,
        // REQUETE_INFO_NOEUD,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege });
    }

    // RK 2.prive
    let requetes_privees = vec![
        REQUETE_LISTE_DOMAINES,
        REQUETE_APPLICATIONS_DEPLOYEES,
        // REQUETE_INFO_NOEUD,
        REQUETE_RESOLVE_IDMG,
        REQUETE_FICHE_MILLEGRILLE,
        REQUETE_APPLICATIONS_TIERS,
        REQUETE_CONSIGNATION_FICHIERS,
        REQUETE_GET_CLE_CONFIGURATION,
    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive });
    }

    // RK 1.public
    let requetes_publiques = vec![
        REQUETE_FICHE_MILLEGRILLE,
        REQUETE_APPLICATIONS_TIERS,
        REQUETE_CONSIGNATION_FICHIERS,
    ];
    for req in requetes_publiques {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L1Public });
    }

    let commandes: Vec<&str> = vec![
        //TRANSACTION_APPLICATION,  // Transaction est initialement recue sous forme de commande uploadee par ServiceMonitor ou autre source
        TRANSACTION_MONITOR,
        TRANSACTION_SUPPRIMER_INSTANCE,
        TRANSACTION_CONFIGURER_CONSIGNATION,
        TRANSACTION_SET_FICHIERS_PRIMAIRE,
        TRANSACTION_SET_CONSIGNATION_INSTANCE,
    ];
    for commande in commandes {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L3Protege });
    }

    for sec in vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure] {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.instance.{}", EVENEMENT_PRESENCE_MONITOR), exchange: sec});
    }

    let evenements: Vec<&str> = vec![
        EVENEMENT_APPLICATION_DEMARREE,
        EVENEMENT_APPLICATION_ARRETEE,
    ];
    for evnmt in evenements {
        for sec in vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure] {
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.instance.*.{}", evnmt), exchange: sec });
        }
    }

    // Presence de domaines se fait sur l'evenement du domaine specifique (*)
    rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.*.{}", EVENEMENT_PRESENCE_DOMAINE), exchange: Securite::L3Protege });
    rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS, EVENEMENT_PRESENCE_FICHIERS), exchange: Securite::L2Prive });

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue(
        ConfigQueue {
            nom_queue: NOM_Q_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: 300000.into(),
            durable: false,
            autodelete: false,
        }
    ));

    let transactions_liste = vec![
        TRANSACTION_MONITOR,
        TRANSACTION_SUPPRIMER_INSTANCE,
        TRANSACTION_SET_FICHIERS_PRIMAIRE,
        TRANSACTION_CONFIGURER_CONSIGNATION,
        TRANSACTION_SET_CONSIGNATION_INSTANCE,
    ];
    let mut rk_transactions = Vec::new();
    for t in transactions_liste {
        rk_transactions.push(ConfigRoutingExchange {
            routing_key: format!("transaction.{}.{}", DOMAINE_NOM, t).into(),
            exchange: Securite::L4Secure,
        });
    }

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue(
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers(DOMAINE_NOM.into(), Securite::L3Protege));

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
        unique: true,
    };
    let champs_index_transactions = vec!(
        ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_ID), direction: 1 }
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_TRANSACTIONS,
        champs_index_transactions,
        Some(options_unique_transactions),
    ).await?;

    // Index transactions completes
    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from(TRANSACTION_CHAMP_COMPLETE)),
        unique: false,
    };
    let champs_index_transactions = vec!(
        ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_EVENEMENT_COMPLETE), direction: 1 }
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_TRANSACTIONS,
        champs_index_transactions,
        Some(options_unique_transactions),
    ).await?;

    // Index backup transactions
    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from(BACKUP_CHAMP_BACKUP_TRANSACTIONS)),
        unique: false,
    };
    let champs_index_transactions = vec!(
        ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_TRANSACTION_TRAITEE), direction: 1 },
        ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_BACKUP_FLAG), direction: 1 },
        ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_EVENEMENT_COMPLETE), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_TRANSACTIONS,
        champs_index_transactions,
        Some(options_unique_transactions),
    ).await?;

    // Index noeuds
    let options_unique_noeuds = IndexOptions {
        nom_index: Some(String::from(INDEX_NOEUDS)),
        unique: true,
    };
    let champs_index_noeuds = vec!(
        ChampIndex { nom_champ: String::from(CHAMP_NOEUD_ID), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_NOEUDS,
        champs_index_noeuds,
        Some(options_unique_noeuds),
    ).await?;

    // Index domaines
    let options_unique_domaine = IndexOptions {
        nom_index: Some(String::from(INDEX_DOMAINE)),
        unique: true,
    };
    let champs_index_domaine = vec!(
        ChampIndex { nom_champ: String::from(CHAMP_DOMAINE), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_DOMAINES,
        champs_index_domaine,
        Some(options_unique_domaine),
    ).await?;

    // Index table millegilles (idmg)
    let options_unique_millegrilles = IndexOptions {
        nom_index: Some(String::from(INDEX_IDMG)),
        unique: true,
    };
    let champs_index_millegrilles = vec!(
        ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_IDMG), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_MILLEGRILLES,
        champs_index_millegrilles,
        Some(options_unique_millegrilles),
    ).await?;

    // Index table millegilles (adresses)
    let options_unique_adresses = IndexOptions {
        nom_index: Some(String::from(INDEX_ADRESSES)),
        unique: false,
    };
    let champs_index_adresses = vec!(
        ChampIndex { nom_champ: String::from(CHAMP_ADRESSES), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_MILLEGRILLES,
        champs_index_adresses,
        Some(options_unique_adresses),
    ).await?;

    // Index table millegillesAdresses
    let options_unique_mg_adresses = IndexOptions {
        nom_index: Some(String::from(INDEX_ADRESSE)),
        unique: true,
    };
    let champs_index_mg_adresses = vec!(
        ChampIndex { nom_champ: String::from(CHAMP_ADRESSE), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_MILLEGRILLES_ADRESSES,
        champs_index_mg_adresses,
        Some(options_unique_mg_adresses),
    ).await?;

    Ok(())
}

async fn entretien<M>(middleware: Arc<M>)
    where M: Middleware + 'static
{
    let mut catalogues_charges = false;
    let mut notification_demarrage_emise = false;

    // Production fiche publique initiale
    sleep(Duration::new(5, 0)).await;
    if let Err(e) = produire_fiche_publique(middleware.as_ref()).await {
        error!("core_topoologie.entretien Erreur production fiche publique initiale : {:?}", e);
    }
    if let Err(e) = produire_information_locale(middleware.as_ref()).await {
        error!("core_topoologie.entretien Erreur production information locale : {:?}", e);
    }

    loop {
        sleep(Duration::new(30, 0)).await;
        if middleware.get_mode_regeneration() == true {
            debug!("entretien Mode regeneration, skip entretien");
            continue;
        }

        debug!("Cycle entretien {}", DOMAINE_NOM);
        if notification_demarrage_emise == false {
            notification_demarrage_emise = true;
            if let Err(e) = emettre_notification_demarrage(middleware.as_ref()).await {
                warn!("Erreur emission notification demarrage {:?}", e);
            }
        }

        if let Err(e) = verifier_instances_horsligne(middleware.as_ref()).await {
            warn!("Erreur verification etat instances hors ligne {:?}", e);
        }
    }
}

async fn emettre_notification_demarrage<M>(middleware: &M) -> Result<(), millegrilles_common_rust::error::Error>
    where M: EmetteurNotificationsTrait
{
    let notification = NotificationMessageInterne {
        from: "CoreTopologie".to_string(),
        subject: Some("Demarrage core".to_string()),
        content: "<p>Core demarre</p>".to_string(),
        version: 1,
        format: "html".into()
    };
    let expiration_ts = Utc::now().timestamp() + 7 * 86400;
    Ok(middleware.emettre_notification_proprietaire(
        notification, "info", Some(expiration_ts), None).await?)
}

async fn traiter_cedule<M>(middleware: &M, trigger: &MessageCedule) -> Result<(), millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    let date_epoch = trigger.get_date();
    debug!("Traiter cedule {}\n{:?}", DOMAINE_NOM, date_epoch);

    if middleware.get_mode_regeneration() == true {
        debug!("traiter_cedule Mode regeneration, skip entretien");
        return Ok(());
    }

    let minutes = date_epoch.minute();

    if minutes % 5 == 1 {
        debug!("Produire fiche publique");
        if let Err(e) = produire_fiche_publique(middleware).await {
            error!("core_topoologie.entretien Erreur production fiche publique initiale : {:?}", e);
        }
    }

    // Mettre a jour information locale a toutes les 5 minutes
    if minutes % 5 == 2 {
        if let Err(e) = produire_information_locale(middleware).await {
            error!("core_topoologie.entretien Erreur production information locale : {:?}", e);
        }
    }

    Ok(())
}

async fn consommer_requete<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("Consommer requete : {:?}", &m.message);

    let (domaine, action, mut exchanges) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            (r.domaine.clone(), r.action.clone(), r.exchanges.clone())
        }
        _ => {
            Err(format!("consommer_requete Mauvais type de message"))?
        }
    };

    let exchange = match exchanges.pop() {
        Some(inner) => inner,
        None => Err(String::from("consommer_requete Exchange manquant"))?
    };

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.
    match exchange {
        Securite::L1Public => {
            match domaine.as_str() {
                DOMAINE_NOM => {
                    match action.as_str() {
                        REQUETE_FICHE_MILLEGRILLE => requete_fiche_millegrille(middleware, m).await,
                        REQUETE_APPLICATIONS_TIERS => requete_applications_tiers(middleware, m).await,
                        REQUETE_CONSIGNATION_FICHIERS => requete_consignation_fichiers(middleware, m).await,
                        _ => {
                            error!("Message requete/action non autorisee sur 1.public : '{:?}'. Message dropped.", m.type_message);
                            Ok(None)
                        }
                    }
                },
                _ => {
                    error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
                    Ok(None)
                }
            }
        },
        Securite::L2Prive => {
            match domaine.as_str() {
                DOMAINE_NOM => {
                    match action.as_str() {
                        REQUETE_LISTE_DOMAINES => liste_domaines(middleware, m).await,
                        REQUETE_APPLICATIONS_DEPLOYEES => liste_applications_deployees(middleware, m).await,
                        REQUETE_RESOLVE_IDMG => resolve_idmg(middleware, m).await,
                        REQUETE_FICHE_MILLEGRILLE => requete_fiche_millegrille(middleware, m).await,
                        REQUETE_APPLICATIONS_TIERS => requete_applications_tiers(middleware, m).await,
                        REQUETE_CONSIGNATION_FICHIERS => requete_consignation_fichiers(middleware, m).await,
                        REQUETE_GET_CLE_CONFIGURATION => requete_get_cle_configuration(middleware, m).await,
                        _ => {
                            error!("Message requete/action inconnue : '{}'. Message dropped.", action);
                            Ok(None)
                        }
                    }
                },
                _ => {
                    error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
                    Ok(None)
                }
            }
        },
        Securite::L3Protege | Securite::L4Secure => {
            match domaine.as_str() {
                DOMAINE_NOM => {
                    match action.as_str() {
                        REQUETE_LISTE_DOMAINES => liste_domaines(middleware, m).await,
                        REQUETE_LISTE_NOEUDS => liste_noeuds(middleware, m).await,
                        REQUETE_CONFIGURATION_FICHIERS => requete_configuration_fichiers(middleware, m).await,
                        REQUETE_GET_CLE_CONFIGURATION => requete_get_cle_configuration(middleware, m).await,
                        _ => {
                            error!("Message requete/action inconnue : '{}'. Message dropped.", action);
                            Ok(None)
                        }
                    }
                },
                _ => {
                    error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
                    Ok(None)
                }
            }
        },
        _ => {
            error!("Message requete/action sans exchange autorise : '{}'. Message dropped.", action);
            Ok(None)
        }
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
                               -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: Middleware + 'static
{
    debug!("Consommer commande : {:?}", &m.message);

    let (domaine, action) = match &m.type_message {
        TypeMessageOut::Commande(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_commande Mauvais type de message"))?
        }
    };

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges_string(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE)))? {
        true => Ok(()),
        false => match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
            true => Ok(()),
            false => Err(format!("Commande autorisation invalide (pas 3.protege ou 4.secure)")),
        }
    }?;

    match action.as_str() {
        // Commandes standard
        TRANSACTION_MONITOR => traiter_commande_monitor(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_INSTANCE => traiter_commande_supprimer_instance(middleware, m, gestionnaire).await,
        TRANSACTION_CONFIGURER_CONSIGNATION => traiter_commande_configurer_consignation(middleware, m, gestionnaire).await,
        TRANSACTION_SET_FICHIERS_PRIMAIRE => traiter_commande_set_fichiers_primaire(middleware, m, gestionnaire).await,
        TRANSACTION_SET_CONSIGNATION_INSTANCE => traiter_commande_set_consignation_instance(middleware, m, gestionnaire).await,
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

async fn consommer_transaction<M>(gestionnaire: &GestionnaireDomaineTopologie, middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer transaction : {:?}", &m.message);

    let (domaine, action) = match &m.type_message {
        TypeMessageOut::Transaction(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_transaction Mauvais type de message"))?
        }
    };

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        true => Ok(()),
        false => match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
            true => Ok(()),
            false => Err(format!("core_topologie.consommer_transaction Autorisation invalide (pas 4.secure) : {:?}", m.type_message))
        }
    }?;

    match action.as_str() {
        TRANSACTION_DOMAINE | TRANSACTION_MONITOR | TRANSACTION_SUPPRIMER_INSTANCE |
        TRANSACTION_SET_FICHIERS_PRIMAIRE | TRANSACTION_CONFIGURER_CONSIGNATION |
        TRANSACTION_SET_CONSIGNATION_INSTANCE => {
            // sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
            // Ok(None)
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        }
        _ => Err(format!("core_topologie.consommer_transaction Mauvais type d'action pour une transaction : {}", action))?,
    }
}

async fn consommer_evenement<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("Consommer evenement : {:?}", &m.type_message);

    let (domaine, action) = match &m.type_message {
        TypeMessageOut::Evenement(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_evenement Mauvais type de message"))?
        }
    };

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges(vec![
        Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure,
    ])? {
        true => Ok(()),
        false => Err(format!("Evenement autorisation invalide (pas exchange autorise)")),
    }?;

    match action.as_str() {
        EVENEMENT_PRESENCE_DOMAINE => traiter_presence_domaine(middleware, m, gestionnaire).await,
        EVENEMENT_PRESENCE_MONITOR | EVENEMENT_PRESENCE_FICHIERS => {
            match domaine.as_str() {
                DOMAINE_FICHIERS => traiter_presence_fichiers(middleware, m, gestionnaire).await,
                DOMAINE_APPLICATION_INSTANCE => traiter_presence_monitor(middleware, m, gestionnaire).await,
                _ => Err(format!("Mauvais domaine ({}) pour un evenement de presence", domaine))?,
            }
        },
        EVENEMENT_APPLICATION_DEMARREE => traiter_evenement_application(middleware, m).await,
        EVENEMENT_APPLICATION_ARRETEE => traiter_evenement_application(middleware, m).await,
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", action))?,
    }
}

// async fn traiter_transaction<M>(_domaine: &str, middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
//     where
//         M: ValidateurX509 + GenerateurMessages + MongoDao,
// {
//     //let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
//     let message_ref = m.message.parse()?;
//     let message_contenu = match message_ref.contenu() {
//         Ok(t) => t,
//         Err(e) => Err(format!("Erreur conversion contenu {:?} : {:?}", m, e))?,
//     };
//     let trigger: TriggerTransaction = match message_contenu.deserialize() {
//         Ok(t) => t,
//         Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?,
//     };
//
//     let transaction = charger_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &trigger).await?;
//     let message_id = transaction.transaction.id.clone();
//     debug!("Traitement transaction, chargee : {}", message_id);
//
//     let reponse = aiguillage_transaction(middleware, transaction).await;
//     if reponse.is_ok() {
//         // Marquer transaction completee
//         debug!("Transaction traitee {}, marquer comme completee", message_id);
//         marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &message_id, EtatTransaction::Complete).await?;
//     }
//
//     reponse
// }

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
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
            None => Err(format!("Transaction {} n'a pas d'action", transaction.transaction.id))?
        },
        None => Err(format!("Transaction {} n'a pas de routage", transaction.transaction.id))?
    };

    match action.as_str() {
        TRANSACTION_DOMAINE => traiter_transaction_domaine(middleware, transaction).await,
        TRANSACTION_MONITOR => traiter_transaction_monitor(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_INSTANCE => traiter_transaction_supprimer_instance(middleware, transaction).await,
        TRANSACTION_SET_FICHIERS_PRIMAIRE => transaction_set_fichiers_primaire(middleware, transaction).await,
        TRANSACTION_CONFIGURER_CONSIGNATION => transaction_configurer_consignation(middleware, transaction).await,
        TRANSACTION_SET_CONSIGNATION_INSTANCE => transaction_set_consignation_instance(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.transaction.id, action))?,
    }
}

async fn traiter_presence_domaine<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Evenement presence domaine : {:?}", m.type_message);
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let event: PresenceDomaine = message_contenu.deserialize()?;
    debug!("Presence domaine : {:?}", event);

    // let mut set_ops = m.message.get_msg().map_to_bson()?;
    // filtrer_doc_id(&mut set_ops);
    //
    // // Retirer champ cle
    // set_ops.remove("domaine");

    let domaine = match event.domaine.as_ref() {
        Some(d) => d,
        None => {
            // Rien a faire
            return Ok(None)
        }
    };

    let certificat = m.certificat.as_ref();

    if ! certificat.verifier_domaines(vec![domaine.to_owned()])? {
        Err(format!("core_topologie.traiter_presence_domaine Erreur domaine message ({}) mismatch certificat ", domaine))?
    }

    let instance_id = certificat.get_common_name()?;

    let filtre = doc! {"domaine": domaine, "instance_id": &instance_id};
    let ops = doc! {
        "$set": {
            "reclame_fuuids": match event.reclame_fuuids { Some(inner) => inner, None => false },
        },
        "$setOnInsert": {
            "domaine": domaine,
            "instance_id": instance_id,
            CHAMP_CREATION: Utc::now(),
            "dirty": true
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    debug!("Document monitor a sauvegarder : {:?}", ops);

    let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
    let options = FindOneAndUpdateOptions::builder().upsert(true).build();
    let result = match collection.find_one_and_update(filtre, ops, Some(options)).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur find document sur transaction domaine : {:?}", e))?
    };
    // let creer_transaction = match result {
    //     Some(d) => d.get_bool("dirty")?,
    //     None => true,
    // };

    // if creer_transaction {
    //     debug!("Creer transaction topologie pour domaine {}", domaine);
    //
    //     let tval = json!({
    //         "domaine": event.domaine,
    //         "instance_id": event.instance_id,
    //     });
    //
    //     let transaction = middleware.formatter_message(
    //         MessageKind::Transaction,
    //         &tval,
    //         Some(DOMAINE_NOM),
    //         Some(TRANSACTION_DOMAINE),
    //         None,
    //         None,
    //         false
    //     )?;
    //
    //     // Sauvegarder la transation
    //     let msg = MessageSerialise::from_parsed(transaction)?;
    //     let msg_action = MessageValideAction::new(msg, "", "", DOMAINE_NOM, TRANSACTION_DOMAINE, TypeMessageOut::Transaction);
    //     // sauvegarder_transaction_recue(middleware, msg_action, NOM_COLLECTION_TRANSACTIONS).await?;
    //     sauvegarder_traiter_transaction(middleware, msg_action, gestionnaire).await?;
    //
    //     // Reset le flag dirty pour eviter multiple transactions sur le meme domaine
    //     let filtre = doc! {"domaine": &event.domaine};
    //     let ops = doc! {"$set": {"dirty": false}};
    //     let _ = collection.update_one(filtre, ops, None).await?;
    // }

    Ok(None)
}

async fn traiter_presence_monitor<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = m.message.parse()?;
    let estampille = message_ref.estampille;
    let message_contenu = message_ref.contenu()?;
    let event: PresenceMonitor = message_contenu.deserialize()?;
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

                        if let Some(a) = labels.get("nom_application") {
                            info_app.insert("name_property", a.as_str());
                        };

                        if let Some(s) = labels.get("supporte_usagers") {
                            info_app.insert("supporte_usagers", s.as_str() != "false");
                        };

                        applications.push(Bson::Document(info_app));
                    }
                }
            }
        }
    }

    debug!("Applications noeud : {:?}", &applications);

    // let mut set_ops = m.message.get_msg().map_to_bson()?;
    // filtrer_doc_id(&mut set_ops);

    let mut set_ops = convertir_to_bson(event.clone())?;

    // Retirer champ cle
    set_ops.remove("instance_id");
    set_ops.insert("applications", applications);
    set_ops.insert("date_presence", estampille);

    let filtre = doc! {"instance_id": &event.instance_id};
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {"instance_id": &event.instance_id, CHAMP_CREATION: Utc::now(), "dirty": true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    debug!("Document monitor a sauvegarder : {:?}", ops);
    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
    let options = FindOneAndUpdateOptions::builder().upsert(true).build();
    let result = collection.find_one_and_update(filtre, ops, Some(options)).await?;
    debug!("Result update monitor : {:?}", result);

    // Verifier si on doit creer une nouvelle transaction
    let creer_transaction = match result {
        Some(d) => d.get_bool("dirty")?,
        None => true,
    };

    if creer_transaction {
        debug!("Creer transaction topologie pour monitor/noeud {:?}", &event.domaine);

        let tval = json!({
            "domaine": event.domaine,
            "instance_id": event.instance_id,
        });

        // let transaction = middleware.formatter_message(
        //     MessageKind::Transaction, &tval,
        //     Some(DOMAINE_NOM), Some(TRANSACTION_MONITOR), None::<&str>, None::<&str>,
        //     None, false)?;
        //
        // // Sauvegarder la transation
        // let msg = MessageSerialise::from_parsed(transaction)?;
        // let msg_action = MessageValide::new(
        //     msg, "", "", DOMAINE_NOM, TRANSACTION_DOMAINE, TypeMessageOut::Transaction);
        // // sauvegarder_transaction_recue(middleware, msg_action, NOM_COLLECTION_TRANSACTIONS).await?;
        // sauvegarder_traiter_transaction(middleware, msg_action, gestionnaire).await?;

        sauvegarder_traiter_transaction_serializable(middleware, &tval, gestionnaire, DOMAINE_NOM, TRANSACTION_INSTANCE).await?;

        // Reset le flag dirty pour eviter multiple transactions sur le meme domaine
        let filtre = doc! {"instance_id": &event.instance_id};
        let ops = doc! {"$set": {"dirty": false}};
        let _ = collection.update_one(filtre, ops, None).await?;
    }

    Ok(None)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionSetFichiersPrimaire {
    instance_id: String
}

async fn traiter_presence_fichiers<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let event: PresenceFichiers = message_contenu.deserialize()?;
    debug!("traiter_presence_fichiers Presence fichiers : {:?}", event);

    if ! m.certificat.verifier_roles(vec![RolesCertificats::Fichiers])? {
        Err(format!("core_topologie.traiter_presence_fichiers Certificat n'a pas le role 'fichiers'"))?
    }
    let subject = m.certificat.subject()?;
    debug!("traiter_presence_fichiers Subject enveloppe : {:?}", subject);
    let instance_id = match subject.get("commonName") {
        Some(instance_id) => instance_id.clone(),
        None => Err(format!("core_topologie.traiter_presence_fichiers organizationalUnit absent du message"))?
    };

    debug!("traiter_presence_fichiers Presence fichiers recue pour instance_id {}", instance_id);

    let mut unset_ops = doc! {};
    let mut set_ops = doc! {
        "principal": event.principal,
        "archive": event.archive,
        "orphelin": event.orphelin,
        "manquant": event.manquant,
    };

    let mut ops = doc! {
        "$setOnInsert": {
            "instance_id": &instance_id, CHAMP_CREATION: Utc::now(),
            // Defaut pour nouvelle instance
            "type_store": "millegrille",
            "consignation_url": DEFAULT_CONSIGNATION_URL,
            "sync_actif": true,
        },
        "$set": set_ops,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    if unset_ops.len() > 0 {
        ops.insert("$unset", unset_ops);
    }

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
    let filtre = doc! {"instance_id": &instance_id};
    let options = UpdateOptions::builder()
        .upsert(true)
        .build();
    let resultat = collection.update_one(filtre, ops, options).await?;
    debug!("traiter_presence_fichiers Resultat update : {:?}", resultat);

    // Verifier si on a un primaire - sinon generer transaction pour set primaire par defaut
    let filtre = doc! {"primaire": true};
    let resultat = collection.find_one(filtre, None).await?;
    if resultat.is_none() {
        debug!("traiter_presence_fichiers Assigne le role de fichiers primaire a {}", instance_id);
        let transaction = TransactionSetFichiersPrimaire { instance_id };

        // Sauvegarder la transaction
        sauvegarder_traiter_transaction_serializable(
            middleware, &transaction, gestionnaire, DOMAINE_NOM, TRANSACTION_SET_FICHIERS_PRIMAIRE).await?;
    }

    Ok(None)
}

async fn traiter_evenement_application<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    // let event: PresenceMonitor = m.message.get_msg().map_contenu(None)?;
    debug!("Evenement application monitor : {:?}", m.type_message);

    // Regenerer fiche publique
    produire_fiche_publique(middleware).await?;

    Ok(None)
}


async fn traiter_commande_monitor<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer traiter_commande_monitor : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_cle autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Sauvegarder la transaction, marquer complete et repondre
    let reponse = sauvegarder_traiter_transaction(middleware, message, gestionnaire).await?;
    Ok(reponse)
}

async fn traiter_commande_supprimer_instance<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer traiter_commande_supprimer_instance : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_cle autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        //     Ok(m) => return Ok(Some(m)),
        //     Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        // }
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Sauvegarder la transaction, marquer complete et repondre
    let reponse = sauvegarder_traiter_transaction(middleware, message, gestionnaire).await?;
    Ok(reponse)
}

async fn traiter_commande_configurer_consignation<M>(middleware: &M, mut message: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("traiter_commande_configurer_consignation : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("traiter_commande_configurer_consignation autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        //     Ok(m) => return Ok(Some(m)),
        //     Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        // }
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Valider commande
    {
        let mut message_owned = message.message.parse_to_owned()?;
        // let message_contenu = message_ref.contenu()?;
        let commande: TransactionSetFichiersPrimaire = match message_owned.deserialize() {
            Ok(inner) => inner,
            Err(e) => {
                Err(format!("traiter_commande_configurer_consignation Erreur convertir {:?}", e))?
            }
        };

        // Traiter la cle
        if let Some(mut attachements) = message_owned.attachements.take() {
            if let Some(cle) = attachements.remove("cle") {
                if let Some(reponse) = transmettre_cle_attachee(middleware, cle).await? {
                    error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : {:?}", reponse);
                    return Ok(Some(reponse));
                }
            }
        }
    }

    // Sauvegarder la transaction, marquer complete et repondre
    let reponse = sauvegarder_traiter_transaction(middleware, message, gestionnaire).await?;
    Ok(reponse)
}

async fn transmettre_cle_attachee<M>(middleware: &M, cle: Value) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let mut message_cle: MessageMilleGrillesOwned = serde_json::from_value(cle)?;

    let mut routage_builder = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L3Protege])
        .correlation_id(&message_cle.id)
        .partition("all");

    match message_cle.attachements.take() {
        Some(inner) => {
            if let Some(partition) = inner.get("partition") {
                if let Some(partition) = partition.as_str() {
                    // Override la partition
                    routage_builder = routage_builder.partition(partition);
                }
            }
        },
        None => ()
    }

    let routage = routage_builder.build();
    let type_message = TypeMessageOut::Commande(routage);

    let buffer_message: MessageMilleGrillesBufferDefault = message_cle.try_into()?;
    let reponse = middleware.emettre_message(type_message, buffer_message).await?;

    match reponse {
        Some(inner) => match inner {
            TypeMessage::Valide(reponse) => {
                let message_ref = reponse.message.parse()?;
                let contenu = message_ref.contenu()?;
                let reponse: ReponseCommande = contenu.deserialize()?;
                if let Some(true) = reponse.ok {
                    debug!("Cle sauvegardee ok");
                    Ok(None)
                } else {
                    error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : {:?}", reponse);
                    Ok(Some(middleware.reponse_err(3, reponse.message, reponse.err)?))
                }
            },
            _ => {
                error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Mauvais type de reponse");
                Ok(Some(middleware.reponse_err(2, None, Some("Erreur sauvegarde cle"))?))
            }
        },
        None => {
            error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Timeout sur confirmation de sauvegarde");
            Ok(Some(middleware.reponse_err(1, None, Some("Timeout"))?))
        }
    }
}

async fn traiter_commande_set_fichiers_primaire<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("traiter_commande_set_fichiers_primaire : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("traiter_commande_set_fichiers_primaire autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        //     Ok(m) => return Ok(Some(m)),
        //     Err(e) => Err(format!("core_topologie.traiter_commande_set_fichiers_primaire Erreur preparation reponse  : {:?}", e))?
        // }
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Valider commande
    {
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        if let Err(e) = message_contenu.deserialize::<TransactionSetFichiersPrimaire>() {
            Err(format!("traiter_commande_set_fichiers_primaire Erreur convertir {:?}", e))?;
        };
    }

    // Sauvegarder la transaction, marquer complete et repondre
    let reponse = sauvegarder_traiter_transaction(middleware, message, gestionnaire).await?;
    Ok(reponse)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionSetConsignationInstance {
    instance_id: String,
    consignation_id: Option<String>,
}

async fn traiter_commande_set_consignation_instance<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireDomaineTopologie)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("traiter_commande_set_consignation_instance : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("traiter_commande_set_consignation_instance autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        //     Ok(m) => return Ok(Some(m)),
        //     Err(e) => Err(format!("core_topologie.traiter_commande_set_fichiers_primaire Erreur preparation reponse  : {:?}", e))?
        // }
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Valider commande
    {
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        if let Err(e) = message_contenu.deserialize::<TransactionSetConsignationInstance>() {
            Err(format!("traiter_commande_set_consignation_instance Erreur convertir {:?}", e))?;
        };
    }

    // Sauvegarder la transaction, marquer complete et repondre
    let reponse = sauvegarder_traiter_transaction(middleware, message, gestionnaire).await?;
    Ok(reponse)
}

async fn transaction_set_fichiers_primaire<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let transaction = match serde_json::from_str::<TransactionSetFichiersPrimaire>(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_set_fichiers_primaire Erreur convertir {:?}\n{}", e, transaction.transaction.contenu))?
    };
    debug!("transaction_set_fichiers_primaire Set fichiers primaire : {:?}", transaction);

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;

    // Retirer le flag primaire de toutes les instances
    let filtre = doc! {"instance_id": {"$ne": &transaction.instance_id}};
    let ops = doc!{
        "$set": {"primaire": false},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    if let Err(e) = collection.update_many(filtre, ops, None).await {
        Err(format!("transaction_set_fichiers_primaire Erreur update_many : {:?}", e))?
    }

    // Set flag primaire sur la bonne instance
    let filtre = doc! {"instance_id": &transaction.instance_id};
    let ops = doc!{
        "$set": {"primaire": true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    if let Err(e) = collection.update_one(filtre, ops, None).await {
        Err(format!("transaction_set_fichiers_primaire Erreur update_one : {:?}", e))?
    }

    // Emettre evenement de changement de consignation primaire
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, "changementConsignationPrimaire", vec![Securite::L2Prive])
        .build();
    middleware.emettre_evenement(routage, &transaction).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionConfigurerConsignation {
    instance_id: String,
    type_store: Option<String>,
    url_download: Option<String>,
    url_archives: Option<String>,
    consignation_url: Option<String>,
    sync_intervalle: Option<i64>,
    sync_actif: Option<bool>,
    supporte_archives: Option<bool>,
    data_chiffre: Option<DataChiffre>,
    // SFTP
    hostname_sftp: Option<String>,
    username_sftp: Option<String>,
    port_sftp: Option<u16>,
    remote_path_sftp: Option<String>,
    key_type_sftp: Option<String>,
    // AWS S3
    s3_access_key_id: Option<String>,
    s3_region: Option<String>,
    s3_endpoint: Option<String>,
    s3_bucket: Option<String>,

    // Backup
    type_backup: Option<String>,
    hostname_sftp_backup: Option<String>,
    port_sftp_backup: Option<u16>,
    username_sftp_backup: Option<String>,
    remote_path_sftp_backup: Option<String>,
    key_type_sftp_backup: Option<String>,
    backup_intervalle_secs: Option<i64>,
    backup_limit_bytes: Option<i64>,
}

async fn transaction_configurer_consignation<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    debug!("transaction_configurer_consignation Contenu de la transaction\n{}", transaction.transaction.contenu);
    let transaction = match serde_json::from_str::<TransactionConfigurerConsignation>(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_configurer_consignation Erreur convertir {:?}", e))?
    };
    debug!("transaction_configurer_consignation Transaction : {:?}", transaction);

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;

    let data_chiffre = match transaction.data_chiffre {
        Some(d) => match convertir_to_bson(d) {
            Ok(d) => Some(d),
            Err(e) => Err(format!("transaction_configurer_consignation Erreur conversion data_chiffre {:?}", e))?
        },
        None => None
    };

    // Defaults
    let consignation_url = match transaction.consignation_url.as_ref() {
        Some(inner) => inner.as_str(),
        None => DEFAULT_CONSIGNATION_URL
    };
    let supporte_archives = match transaction.supporte_archives.as_ref() {
        Some(inner) => inner.to_owned(),
        None => true
    };
    let sync_actif = match transaction.sync_actif.as_ref() {
        Some(inner) => inner.to_owned(),
        None => true
    };

    let port_sftp = match transaction.port_sftp {
        Some(inner) => Some(inner as i64),
        None => None,
    };

    let port_sftp_backup = match transaction.port_sftp_backup {
        Some(inner) => Some(inner as i64),
        None => None,
    };

    let set_ops = doc! {
        "type_store": transaction.type_store,
        "url_download": transaction.url_download,
        "url_archives": transaction.url_archives,
        "consignation_url": consignation_url,
        "sync_intervalle": transaction.sync_intervalle,
        "sync_actif": sync_actif,
        "supporte_archives": supporte_archives,
        "data_chiffre": data_chiffre,
        "port_sftp": port_sftp,
        "hostname_sftp": transaction.hostname_sftp,
        "username_sftp": transaction.username_sftp,
        "remote_path_sftp": transaction.remote_path_sftp,
        "key_type_sftp": transaction.key_type_sftp,
        "s3_access_key_id": transaction.s3_access_key_id,
        "s3_region": transaction.s3_region,
        "s3_endpoint": transaction.s3_endpoint,
        "s3_bucket": transaction.s3_bucket,
        "type_backup": transaction.type_backup,
        "hostname_sftp_backup": transaction.hostname_sftp_backup,
        "port_sftp_backup": port_sftp_backup,
        "username_sftp_backup": transaction.username_sftp_backup,
        "remote_path_sftp_backup": transaction.remote_path_sftp_backup,
        "key_type_sftp_backup": transaction.key_type_sftp_backup,
        "backup_intervalle_secs": transaction.backup_intervalle_secs,
        "backup_limit_bytes": transaction.backup_limit_bytes,
    };

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {
            "instance_id": &transaction.instance_id,
            CHAMP_CREATION: Utc::now(),
            "primaire": false,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let options = FindOneAndUpdateOptions::builder()
        .return_document(ReturnDocument::After)
        .upsert(true)
        .build();

    let filtre = doc!{ "instance_id": &transaction.instance_id };
    let configuration = match collection.find_one_and_update(filtre, ops, Some(options)).await {
        Ok(inner) => match inner {
            Some(inner) => match convertir_bson_deserializable::<ReponseInformationConsignationFichiers>(inner) {
                Ok(inner) => inner,
                Err(e) => Err(format!("transaction_configurer_consignation Erreur mapper reponse : {:?}", e))?
            },
            None => Err(String::from("transaction_configurer_consignation Erreur sauvegarde configuration consignation : Aucun doc conserve"))?
        },
        Err(e) => Err(format!("transaction_configurer_consignation Erreur sauvegarde configuration consignation : {:?}", e))?
    };

    // Emettre commande de modification de configuration pour fichiers
    let routage = RoutageMessageAction::builder("fichiers", "modifierConfiguration", vec![Securite::L2Prive])
        .partition(transaction.instance_id.as_str())
        .blocking(false)
        .build();

    // Transmettre commande non-blocking
    middleware.transmettre_commande(routage, &configuration).await?;

    // Emettre evenement changement de consignation
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MODIFICATION_CONSIGNATION, vec![Securite::L1Public])
        .build();
    let evenement = json!({
        CHAMP_INSTANCE_ID: transaction.instance_id,
        "consignation_url": transaction.consignation_url,
    });
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn transaction_set_consignation_instance<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let transaction = match serde_json::from_str::<TransactionSetConsignationInstance>(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_set_consignation_instance Erreur convertir {:?}", e))?
    };
    debug!("transaction_set_consignation_instance Params : {:?}", transaction);

    let filtre = doc! { CHAMP_INSTANCE_ID: &transaction.instance_id };
    let set_ops = doc! {
        CHAMP_CONSIGNATION_ID: transaction.consignation_id.as_ref()
    };
    let ops = doc! {
        "$set": set_ops,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let collection = middleware.get_collection(NOM_COLLECTION_INSTANCES)?;
    if let Err(e) = collection.update_one(filtre, ops, None).await {
        Err(format!("core_topologie.transaction_set_consignation_instance Erreur sauvegarde consignation_id : {:?}", e))?
    }

    // Emettre evenement changement de consignation
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MODIFICATION_CONSIGNATION, vec![Securite::L1Public])
        .build();
    let evenement = json!({
        CHAMP_INSTANCE_ID: transaction.instance_id
    });
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn traiter_transaction_domaine<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let transaction = match serde_json::from_str::<PresenceDomaine>(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => {
            error!("traiter_transaction_domaine Erreur convertir {:?}\n{}", e, transaction.transaction.contenu);
            Err(format!("traiter_transaction_domaine Erreur convertir {:?}", e))?
        }
    };
    let domaine = match transaction.domaine {
        Some(d) => d,
        None => Err(String::from("traiter_transaction_domaine Erreur domaine absent"))?
    };

    let mut set_ops = doc!{"dirty": false};
    if let Some(instance_id) = transaction.instance_id {
        set_ops.insert("instance_id", instance_id);
    }

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {CHAMP_DOMAINE: &domaine, CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc! {CHAMP_DOMAINE: domaine};
    let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
    let options = UpdateOptions::builder().upsert(true).build();
    match collection.update_one(filtre, ops, options).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur maj transaction topologie domaine : {:?}", e))?
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn traiter_transaction_monitor<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let mut doc_transaction: PresenceMonitor = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(d) => d,
        Err(e) => Err(format!("core_topologie.traiter_transaction_monitor Erreur conversion transaction monitor : {:?}", e))?
    };
    debug!("traiter_transaction_monitor {:?}", doc_transaction);

    let instance_id = doc_transaction.instance_id;

    let ops = doc! {
        "$set": {"dirty": false, CHAMP_DOMAINE: doc_transaction.domaine},
        "$setOnInsert": {CHAMP_INSTANCE_ID: &instance_id, CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc! {CHAMP_INSTANCE_ID: &instance_id};
    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
    let options = UpdateOptions::builder().upsert(true).build();
    match collection.update_one(filtre, ops, options).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur maj transaction topologie domaine : {:?}", e))?
    }

    let reponse = middleware.reponse_ok(None, None)?;
    // let reponse = match middleware.formatter_reponse(json!({"ok": true}), None) {
    //     Ok(r) => r,
    //     Err(e) => Err(format!("Erreur reponse transaction : {:?}", e))?
    // };
    Ok(Some(reponse))
}

async fn traiter_transaction_supprimer_instance<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let mut doc_transaction: PresenceMonitor = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(d) => d,
        Err(e) => Err(format!("core_topologie.traiter_transaction_supprimer_instance Erreur conversion transaction monitor : {:?}", e))?
    };

    let instance_id = doc_transaction.instance_id;

    let filtre = doc! {CHAMP_NOEUD_ID: &instance_id};
    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
    match collection.delete_one(filtre, None).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur maj transaction topologie domaine : {:?}", e))?
    }

    // Emettre evenement d'instance supprimee
    let evenement_supprimee = json!({"instance_id": &instance_id});
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_INSTANCE_SUPPRIMEE, vec![Securite::L3Protege])
        .build();
    middleware.emettre_evenement(routage, &evenement_supprimee).await?;

    let reponse = middleware.reponse_ok(None, None)?;
    // let reponse = match middleware.formatter_reponse(json!({"ok": true}), None) {
    //     Ok(r) => r,
    //     Err(e) => Err(format!("Erreur reponse transaction : {:?}", e))?
    // };
    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PresenceDomaine {
    domaine: Option<String>,
    instance_id: Option<String>,
    reclame_fuuids: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PresenceMonitor {
    #[serde(serialize_with = "optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    date_presence: Option<chrono::DateTime<Utc>>,
    domaine: Option<String>,
    domaines: Option<Vec<String>>,
    instance_id: String,
    services: Option<HashMap<String, InfoService>>,
    applications_configurees: Option<Vec<Value>>,
    containers: Option<HashMap<String, Value>>,
    disk: Option<Vec<Value>>,
    fqdn_detecte: Option<String>,
    hostname: Option<String>,
    info: Option<HashMap<String, Value>>,
    ip_detectee: Option<String>,
    load_average: Option<Vec<Value>>,
    securite: Option<String>,
    system_battery: Option<Value>,
    system_fans: Option<Value>,
    system_temperature: Option<HashMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PresenceFichiers {
    type_store: Option<String>,
    url_download: Option<String>,
    url_archives: Option<String>,
    consignation_url: Option<String>,
    principal: Option<PresenceFichiersRepertoire>,
    archive: Option<PresenceFichiersRepertoire>,
    orphelin: Option<PresenceFichiersRepertoire>,
    manquant: Option<PresenceFichiersRepertoire>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InfoService {
    etat: Option<String>,
    labels: Option<HashMap<String, String>>,
    replicas: Option<usize>,
}

#[derive(Serialize)]
struct ReponseApplicationDeployee {
    instance_id: String,
    application: String,
    securite: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name_property: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supporte_usagers: Option<bool>,
}

#[derive(Serialize)]
struct ReponseListeApplicationsDeployees {
    ok: bool,
    resultats: Vec<ReponseApplicationDeployee>,
}

async fn liste_applications_deployees<M>(middleware: &M, message: MessageValide)
                                         -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    // Recuperer instance_id
    let certificat = message.certificat.as_ref();
    let instance_id = certificat.get_common_name()?;
    let extensions = certificat.extensions()?;
    let exchanges = extensions.exchanges.as_ref();
    debug!("liste_applications_deployees Instance_id {}, exchanges : {:?}", instance_id, exchanges);

    let niveau_securite = if certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        Securite::L3Protege
    } else if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        Securite::L3Protege
    } else if certificat.verifier_exchanges(vec![Securite::L2Prive])? {
        Securite::L2Prive
    } else if certificat.verifier_roles(vec![RolesCertificats::ComptePrive])? {
        Securite::L2Prive
    } else {
        warn!("liste_applications_deployees Acces refuse, aucunes conditions d'acces du certificat pour liste apps");
        // let reponse = json!({"ok": false, "err": "Acces refuse"});
        // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
    };
    debug!("liste_applications_deployees Niveau de securite : {:?}", niveau_securite);

    // Retour de toutes les applications (maitrecomptes est toujours sur exchange 2.prive)
    let sec_cascade = securite_cascade_public(niveau_securite);

    let mut curseur = {
        let filtre = doc! {};
        let projection = doc! {"instance_id": true, "domaine": true, "securite": true, "applications": true, "onion": true};
        let collection = middleware.get_collection_typed::<InformationMonitor>(NOM_COLLECTION_NOEUDS)?;
        let ops = FindOptions::builder().projection(Some(projection)).build();
        match collection.find(filtre, Some(ops)).await {
            Ok(c) => c,
            Err(e) => Err(format!("core_topologie.liste_applications_deployees Erreur chargement applications : {:?}", e))?
        }
    };

    // Extraire liste d'applications
    let mut resultats = Vec::new();
    while let Some(row) = curseur.next().await {
        let info_monitor = row?;
        let instance_id = info_monitor.instance_id.as_str();

        if let Some(applications) = info_monitor.applications {
            for app in applications {
                let securite = match app.securite {
                    Some(s) => match securite_enum(s.as_str()) {
                        Ok(s) => s,
                        Err(e) => continue   // Skip
                    },
                    None => continue  // Skip
                };

                // Verifier si le demandeur a le niveau de securite approprie
                if sec_cascade.contains(&securite) {

                    if let Some(url) = app.url.as_ref() {
                        // Preparer la valeur a exporter pour les applications
                        let onion = match info_monitor.onion.as_ref() {
                            Some(onion) => {
                                let mut url_onion = Url::parse(url.as_str())?;
                                url_onion.set_host(Some(onion.as_str()));
                                Some(url_onion.as_str().to_owned())
                            },
                            None => None
                        };

                        let mut info_app = ReponseApplicationDeployee {
                            instance_id: instance_id.to_owned(),
                            application: app.application.clone(),
                            securite: securite.get_str().to_owned(),
                            url: Some(url.to_owned()),
                            onion: onion.to_owned(),
                            name_property: None,
                            supporte_usagers: None,
                        };

                        if let Some(p) = app.name_property.as_ref() {
                            info_app.name_property = Some(p.to_string());
                        }

                        if let Some(p) = app.supporte_usagers.as_ref() {
                            info_app.supporte_usagers = Some(p.to_owned());
                        }

                        resultats.push(info_app);
                    }
                }
            }
        }
    }

    let liste = ReponseListeApplicationsDeployees {
        ok: true,
        resultats,
    };

    let reponse = match middleware.build_reponse(liste) {
        Ok(m) => m.0,
        Err(e) => Err(format!("core_topologie.liste_applications_deployees  Erreur preparation reponse applications : {:?}", e))?
    };
    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InformationMonitor {
    domaines: Option<Vec<String>>,
    instance_id: String,
    securite: Option<String>,
    onion: Option<String>,
    applications: Option<Vec<InformationApplication>>,
    applications_configurees: Option<Vec<ApplicationConfiguree>>,
    #[serde(serialize_with = "optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    date_presence: Option<chrono::DateTime<Utc>>,
}

impl InformationMonitor {
    fn exporter_applications(&self) -> Vec<Value> {
        vec!()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InformationApplication {
    application: String,
    securite: Option<String>,
    url: Option<String>,
    millegrille: Option<String>,
    name_property: Option<String>,
    supporte_usagers: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ApplicationConfiguree {
    nom: String,
    version: Option<String>,
}

#[derive(Clone, Deserialize)]
struct MessageInstanceId {
    instance_id: Option<String>
}

async fn liste_noeuds<M>(middleware: &M, message: MessageValide)
                         -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("liste_noeuds");
    if !message.certificat.verifier_exchanges_string(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE)))? {
        if !message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
            // let refus = json!({"ok": false, "err": "Acces refuse"});
            // let reponse = match middleware.formatter_reponse(&refus, None) {
            //     Ok(m) => m,
            //     Err(e) => Err(format!("core_topologie.liste_noeuds Erreur preparation reponse applications : {:?}", e))?
            // };
            // return Ok(Some(reponse));
            return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
        }
    }

    let mut curseur = {
        let mut filtre = doc! {};
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        let message_instance_id: MessageInstanceId = message_contenu.deserialize()?;
        if let Some(inner) = message_instance_id.instance_id.as_ref() {
            filtre.insert("instance_id", inner.to_owned());
        }
        let collection = middleware.get_collection_typed::<PresenceMonitor>(NOM_COLLECTION_NOEUDS)?;
        match collection.find(filtre, None).await {
            Ok(c) => c,
            Err(e) => Err(format!("core_topologie.liste_noeuds Erreur chargement applications : {:?}", e))?
        }
    };

    let mut noeuds = Vec::new();
    while let Some(r) = curseur.next().await {
        match r {
            Ok(d) => noeuds.push(d),
            Err(e) => warn!("core_topologie.liste_noeuds Erreur lecture document sous liste_noeuds() : {:?}", e)
        }
    }

    debug!("Noeuds : {:?}", noeuds);
    let liste = json!({"resultats": noeuds});
    let reponse = match middleware.build_reponse(liste) {
        Ok(m) => m.0,
        Err(e) => Err(format!("core_topologie.liste_noeuds Erreur preparation reponse noeuds : {:?}", e))?
    };
    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteListeDomaines {
    reclame_fuuids: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct DomaineRowBorrow<'a> {
    instance_id: &'a str,
    domaine: &'a str,
    #[serde(rename = "_mg-creation", serialize_with = "optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    creation: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "_mg-derniere-modification", serialize_with="optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    presence: Option<chrono::DateTime<Utc>>,
    dirty: Option<bool>,
    reclame_fuuids: Option<bool>,
}

async fn liste_domaines<M>(middleware: &M, message: MessageValide)
                           -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("liste_domaines {:?}", message);
    if !message.certificat.verifier_exchanges_string(vec!(String::from(SECURITE_2_PRIVE), String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE)))? {
        if message.certificat.get_user_id()?.is_some() && !message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
            let refus = json!({"ok": false, "err": "Acces refuse"});
            // let reponse = match middleware.formatter_reponse(&refus, None) {
            let reponse = match middleware.reponse_err(None, None, Some("Acces refuse")) {
                Ok(m) => m,
                Err(e) => Err(format!("core_topologie.liste_domaines Erreur preparation reponse applications : {:?}", e))?
            };
            return Ok(Some(reponse));
        }
    }

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteListeDomaines = message_contenu.deserialize()?;

    let mut curseur = {
        let projection = doc! {"instance_id": true, "domaine": true, CHAMP_MODIFICATION: true};
        let collection = middleware.get_collection_typed::<DomaineRowBorrow>(NOM_COLLECTION_DOMAINES)?;
        let ops = FindOptions::builder().projection(Some(projection)).build();

        let mut filtre = doc!{};
        if let Some(reclame_fuuids) = requete.reclame_fuuids {
            filtre.insert("reclame_fuuids", reclame_fuuids);
        }

        match collection.find(filtre, Some(ops)).await {
            Ok(c) => c,
            Err(e) => Err(format!("core_topologie.liste_domaines Erreur chargement domaines : {:?}", e))?
        }
    };

    // let mut domaines = Vec::new();
    // while let Some(r) = curseur.next().await {
    //     match r {
    //         Ok(mut d) => {
    //             // Convertir date bson en DateTimeEpochSeconds
    //             let date_presence = d.remove(CHAMP_MODIFICATION);
    //             if let Some(date) = date_presence {
    //                 if let Some(date) = date.as_datetime() {
    //                     let date = DateEpochSeconds::from(date.to_chrono());
    //                     d.insert("date_presence", date);
    //                 }
    //             }
    //             filtrer_doc_id(&mut d);
    //             domaines.push(d);
    //         }
    //         Err(e) => warn!("core_topologie.liste_domaines Erreur lecture document sous liste_noeuds() : {:?}", e)
    //     }
    // }

    let mut domaines = Vec::new();
    while curseur.advance().await? {
        match curseur.deserialize_current() {
            Ok(inner) => {
                // Serialiser sous forme de value json
                domaines.push(serde_json::to_value(inner)?)
            },
            Err(e) => {
                error!("Erreur deserialize valeur Domaine : {:?}", e);
                continue
            }
        };
    }

    debug!("Domaines : {:?}", domaines);
    let liste = json!({"ok": true, "resultats": domaines});
    // let reponse = match middleware.formatter_reponse(&liste, None) {
    let reponse = match middleware.build_reponse(liste) {
        Ok(m) => m.0,
        Err(e) => Err(format!("core_topologie.liste_domaines Erreur preparation reponse domaines : {:?}", e))?
    };
    Ok(Some(reponse))
}

async fn resolve_idmg<M>(middleware: &M, message: MessageValide)
                         -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("resolve_idmg");
    if !message.certificat.verifier_exchanges_string(vec!(String::from(SECURITE_2_PRIVE), String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE)))? {
        // let refus = json!({"ok": false, "err": "Acces refuse"});
        // let reponse = match middleware.formatter_reponse(&refus, None) {
        //     Ok(m) => m,
        //     Err(e) => Err(format!("core_topologie.liste_domaines Erreur preparation reponse applications : {:?}", e))?
        // };
        // return Ok(Some(reponse));
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
    }

    let idmg_local = middleware.get_enveloppe_signature().enveloppe_pub.idmg()?;

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteResolveIdmg = message_contenu.deserialize()?;
    let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;

    // Map reponse, associe toutes les adresses dans la requete aux idmg trouves
    let mut resolved_dns: HashMap<String, Option<String>> = HashMap::new();

    if let Some(adresses) = requete.dns {
        for dns in &adresses {
            resolved_dns.insert(dns.clone(), None);
        }
        let filtre = doc! {CHAMP_ADRESSE: {"$in": adresses}};
        debug!("liste_domaines Filtre adresses : {:?}", filtre);
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(record_adresse) = curseur.next().await {
            let record_adresse = record_adresse?;
            debug!("Record adresse: {:?}", record_adresse);
            let date_modification = record_adresse.get("_mg-derniere-modification").cloned();
            let doc_adresse: AdresseIdmg = convertir_bson_deserializable(record_adresse)?;

            if doc_adresse.idmg.as_str() == idmg_local.as_str() {
                // L'adresse correspond a la millegrille locale
                resolved_dns.insert(doc_adresse.adresse.clone(), Some(doc_adresse.idmg.clone()));
                continue;
            }

            let date_modification = match date_modification {
                Some(dm) => {
                    if let Some(date_modification) = dm.as_datetime() {
                        let date_chrono = date_modification.to_chrono();
                        let duration = chrono::Duration::minutes(1);
                        if Utc::now() - duration > date_chrono {
                            debug!("Expire, on recharge");

                            let etag = doc_adresse.etag.as_ref();
                            let hostname = doc_adresse.adresse.as_str();
                            match resoudre_url(middleware, hostname, etag).await {
                                Ok(idmg_option) => {
                                    match idmg_option {
                                        Some(i) => {
                                            resolved_dns.insert(hostname.into(), i.into());
                                        }
                                        None => {
                                            // Aucuns changements (e.g. 304). Utiliser la version de la DB.
                                            resolved_dns.insert(hostname.into(), Some(doc_adresse.idmg.clone()));
                                        }
                                    }
                                    Some(date_chrono)
                                }
                                Err(e) => {
                                    error!("core_topologie.resolve_idmg Erreur chargement hostname {} : {:?}", hostname, e);
                                    None
                                }
                            }
                        } else {
                            Some(date_chrono)
                        }
                    } else {
                        None
                    }
                }
                None => None
            };

            match date_modification {
                Some(d) => {
                    resolved_dns.insert(doc_adresse.adresse, Some(doc_adresse.idmg));
                }
                None => {
                    debug!("Recharger information idmg {}", doc_adresse.idmg);
                }
            }
        }
    }

    // Lancer requetes pour DNS inconnus
    for (hostname, idmg) in resolved_dns.clone().iter() {
        if idmg.is_none() {
            info!("Charger fiche a {}", hostname);
            match resoudre_url(middleware, hostname.as_str(), None).await {
                Ok(idmg_option) => {
                    if let Some(idmg) = idmg_option {
                        resolved_dns.insert(hostname.into(), idmg.into());
                    }
                }
                Err(e) => error!("core_topologie.resolve_idmg Erreur chargement hostname {} : {:?}", hostname, e)
            }
        }
    }

    let liste = json!({"dns": resolved_dns});
    let reponse = match middleware.build_reponse(liste) {
        Ok(m) => m.0,
        Err(e) => Err(format!("core_topologie.resolve_idmg Erreur preparation reponse resolve idmg : {:?}", e))?
    };

    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteResolveIdmg {
    dns: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AdresseIdmg {
    adresse: String,
    idmg: String,
    etag: Option<String>,
    // #[serde(rename = "_mg-derniere-modification", skip_serializing)]
    // derniere_modification: DateEpochSeconds,
}

async fn resoudre_url<M>(middleware: &M, hostname: &str, etag: Option<&String>)
                         -> Result<Option<String>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("resoudre_url {}", hostname);

    let routage = RoutageMessageAction::builder(DOMAINE_RELAIWEB, COMMANDE_RELAIWEB_GET, vec![Securite::L1Public])
        .build();

    let url_fiche = format!("https://{}/fiche.json", hostname);
    let requete = json!({
        "url": url_fiche,
        "headers": {
            "Cache-Control": "public, max-age=604800",
            "If-None-Match": etag,
        }
    });

    let reponse = {
        let reponse_http = middleware.transmettre_commande(routage, &requete).await?;
        debug!("Reponse http : {:?}", reponse_http);
        match reponse_http {
            Some(reponse) => match reponse {
                TypeMessage::Valide(reponse) => Ok(reponse),
                _ => Err(format!("core_topologie.resoudre_url Mauvais type de message recu en reponse"))
            },
            None => Err(format!("core_topologie.resoudre_url Aucun message recu en reponse"))
        }
    }?;

    // Mapper message avec la fiche
    let message_ref = reponse.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let reponse_fiche: ReponseFichePubliqueTierce = message_contenu.deserialize()?;
    debug!("Reponse fiche : {:?}", reponse);

    // Verifier code reponse HTTP
    match reponse_fiche.code {
        Some(c) => {
            if c == 304 {
                // Aucun changement sur le serveur
                // On fait juste faire un touch sur l'adresse du hostname verifie
                let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;
                let filtre = doc! {"adresse": hostname};
                let ops = doc! {"$currentDate": {CHAMP_MODIFICATION: true}};
                collection.update_one(filtre, ops, None).await?;
                return Ok(None);
            } else if c != 200 {
                Err(format!("core_topologie.resoudre_url Code reponse http {}", c))
            } else {
                Ok(())
            }
        }
        None => Err(format!("core_topologie.resoudre_url Code reponse http manquant"))
    }?;

    // Verifier presence fiche publique
    let fiche_json_value = match reponse_fiche.json {
        Some(f) => Ok(f),
        None => Err(format!("core_topologie.resoudre_url Fiche publique manquante"))
    }?;
    todo!("fix me")
    // debug!("resoudre_url Message json string : {}", fiche_json_value);
    // let mut fiche_publique_message = MessageSerialise::from_serializable(fiche_json_value)?;
    // debug!("resoudre_url Fiche publique message serialize : {:?}", fiche_publique_message);
    // let validation_option = ValidationOptions::new(true, true, true);
    // let resultat_validation = fiche_publique_message.valider(middleware, Some(&validation_option)).await?;
    // if ! resultat_validation.valide() {
    //     Err(format!("core_topologie.resoudre_url Erreur validation fiche publique : {:?}", resultat_validation))?
    // }
    //
    // let idmg_tiers = match &fiche_publique_message.certificat {
    //     Some(c) => c.idmg(),
    //     None => Err(format!("core_topologie.resoudre_url Erreur chargement certificat de fiche publique, certificat manquant"))
    // }?;
    //
    // let fiche_publique: FichePubliqueReception = fiche_publique_message.get_msg().map_contenu()?;
    // debug!("resoudre_url Fiche publique mappee : {:?}", fiche_publique);
    //
    // // Sauvegarder/mettre a jour fiche publique
    // {
    //     let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
    //     let filtre = doc! {"idmg": &idmg_tiers};
    //     let apps = match &fiche_publique.applications {
    //         Some(a) => {
    //             let mut map = Map::new();
    //             for (key, value) in a.iter() {
    //                 let value_serde = serde_json::to_value(value)?;
    //                 map.insert(key.into(), value_serde);
    //             }
    //             Some(map)
    //         }
    //         None => None
    //     };
    //     let set_json = json!({
    //         // "adresses": &fiche_publique.adresses,
    //         "applications": apps,
    //         "chiffrage": &fiche_publique.chiffrage,
    //         "ca": &fiche_publique.ca,
    //     });
    //     let set_bson = convertir_to_bson(set_json)?;
    //     let ops = doc! {
    //         "$set": set_bson,
    //         "$setOnInsert": {
    //             "idmg": &idmg_tiers,
    //             CHAMP_CREATION: Utc::now(),
    //         },
    //         "$currentDate": {CHAMP_MODIFICATION: true},
    //     };
    //     let options = UpdateOptions::builder()
    //         .upsert(true)
    //         .build();
    //     let resultat_update = collection.update_one(filtre, ops, Some(options)).await?;
    //     if resultat_update.modified_count != 1 && resultat_update.upserted_id.is_none() {
    //         error!("resoudre_url Erreur, fiche publique idmg {} n'a pas ete sauvegardee", idmg_tiers);
    //     }
    // }
    //
    // // // Sauvegarder adresses
    // // {
    // //     let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;
    // //     debug!("Verification headers : {:?}", reponse_fiche.headers);
    // //     let etag = match reponse_fiche.headers.as_ref() {
    // //         Some(e) => e.get("ETag").cloned(),
    // //         None => None
    // //     };
    // //     if let Some(adresses) = fiche_publique.adresses.as_ref() {
    // //         for adresse in adresses {
    // //             let filtre = doc! { "adresse": adresse };
    // //             let ops = doc! {
    // //                 "$set": {
    // //                     "idmg": &idmg_tiers,
    // //                     "etag": &etag,
    // //                 },
    // //                 "$setOnInsert": {
    // //                     "adresse": adresse,
    // //                     CHAMP_CREATION: Utc::now(),
    // //                 },
    // //                 "$currentDate": {CHAMP_MODIFICATION: true},
    // //             };
    // //             let options = UpdateOptions::builder().upsert(true).build();
    // //             let resultat_update = collection.update_one(filtre, ops, Some(options)).await?;
    // //             if resultat_update.modified_count != 1 && resultat_update.upserted_id.is_none() {
    // //                 error!("resoudre_url Erreur, adresse {} pour idmg {} n'a pas ete sauvegardee", adresse, idmg_tiers);
    // //             }
    // //         }
    // //     }
    // // }
    //
    // Ok(Some(idmg_tiers))
}

struct ResultatValidationTierce {
    idmg: Option<String>,

}

// async fn valider_message_tiers<M>(middleware: &M, fiche_publique_message: &mut MessageSerialise)
//                                   -> Result<String, ResultatValidation>
//     where M: ValidateurX509
// {
//     // Charger certificat CA du tiers
//     let certificat_ca_tiers = match &fiche_publique_message.millegrille {
//         Some(c) => Ok(c.clone()),
//         None => {
//             info!("valider_message_tiers Fiche publique manquante");
//             Err(ResultatValidation::new(false, None, false, false))
//         }
//     }?;
//
//     debug!("resoudre_url Certificat CA tiers : {:?}", certificat_ca_tiers);
//     let idmg_tiers = match certificat_ca_tiers.calculer_idmg() {
//         Ok(i) => Ok(i),
//         Err(e) => {
//             info!("valider_message_tiers Erreur calcul idmg sur certificat de millegrille : {}", e);
//             Err(ResultatValidation::new(false, None, false, false))
//         }
//     }?;
//     debug!("resoudre_url Certificat idmg tiers : {}", idmg_tiers);
//     fiche_publique_message.set_millegrille(certificat_ca_tiers.clone());
//
//     // Charger et verificat certificat tiers
//     let certificat_tiers = match &fiche_publique_message.parsed.certificat {
//         Some(c) => match middleware.charger_enveloppe(&c, None).await {
//             Ok(enveloppe) => {
//                 let valide = match middleware.valider_chaine(
//                     enveloppe.as_ref(), Some(certificat_ca_tiers.as_ref())) {
//                     Ok(v) => Ok(v),
//                     Err(e) => {
//                         info!("valider_message_tiers Erreur valider chaine de certificat : {}", e);
//                         Err(ResultatValidation::new(false, None, false, false))
//                     }
//                 }?;
//                 if valide &&
//                     enveloppe.verifier_exchanges(vec![Securite::L4Secure]) &&
//                     enveloppe.verifier_roles(vec![RolesCertificats::Core]) {
//                     Ok(enveloppe)
//                 } else {
//                     info!("core_topologie.resoudre_url Erreur verification certificat fiche publique : chaine invalide");
//                     Err(ResultatValidation::new(false, None, false, false))
//                 }
//             }
//             Err(e) => {
//                 info!("core_topologie.resoudre_url Certificat fiche publique ne peut pas etre charge : {:?}", e);
//                 Err(ResultatValidation::new(false, None, false, false))
//             }
//         },
//         None => {
//             info!("core_topologie.resoudre_url Certificat fiche publique manquant");
//             Err(ResultatValidation::new(false, None, false, false))
//         }
//     }?;
//     fiche_publique_message.set_certificat(certificat_tiers);
//
//     // Valider le message avec certificat de la millegrille tierce
//     let validation_option = ValidationOptions::new(true, true, true);
//     let resultat_validation = match fiche_publique_message.valider(middleware, Some(&validation_option)).await {
//         Ok(r) => Ok(r),
//         Err(e) => {
//             info!("valider_message_tiers Erreur execution de la validation : {}", e);
//             Err(ResultatValidation::new(false, None, true, false))
//         }
//     }?;
//
//     debug!("resoudre_url Resultat validation : {:?}", resultat_validation);
//     match resultat_validation.valide() {
//         true => Ok(idmg_tiers),
//         false => Err(resultat_validation)
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseFichePubliqueTierce {
    code: Option<u16>,
    verify_ok: Option<bool>,
    headers: Option<HashMap<String, String>>,
    json: Option<Value>,
    text: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FichePubliqueReception {
    adresses: Option<Vec<String>>,
    applications: Option<HashMap<String, Vec<ApplicationPublique>>>,
    chiffrage: Option<Vec<Vec<String>>>,
    ca: Option<String>,
}

async fn produire_fiche_publique<M>(middleware: &M)
                                    -> Result<(), millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("produire_fiche_publique");

    let fiche = generer_contenu_fiche_publique(middleware).await?;

    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM, EVENEMENT_FICHE_PUBLIQUE, vec![Securite::L1Public])
        .ajouter_ca(true)
        .build();
    middleware.emettre_evenement(routage, &fiche).await?;

    Ok(())
}

async fn generer_contenu_fiche_publique<M>(middleware: &M) -> Result<FichePublique, millegrilles_common_rust::error::Error>
    where M: MongoDao + ValidateurX509 + CleChiffrageHandler
{
    let collection = middleware.get_collection_typed::<InformationMonitor>(NOM_COLLECTION_NOEUDS)?;

    let filtre = doc! {};
    let mut curseur = collection.find(filtre, None).await?;

    // Extraire chaines pem de certificats de chiffrage
    let chiffrage_enveloppes = middleware.get_publickeys_chiffrage();
    let mut chiffrage = Vec::new();
    for cert in chiffrage_enveloppes {
        let chaine_pem = cert.chaine_pem()?;
        chiffrage.push(chaine_pem)
    }

    // let mut adresses = Vec::new();
    let mut instances: HashMap<String, InformationInstance> = HashMap::new();
    let mut applications: HashMap<String, Vec<ApplicationPublique>> = HashMap::new();
    let mut applications_v2: HashMap<String, ApplicationsV2> = HashMap::new();

    let map_ports = {
        let mut map_ports: HashMap<String, u16> = HashMap::new();
        map_ports.insert("http".to_string(), 80);
        map_ports.insert("https".to_string(), 443);
        map_ports.insert("wss".to_string(), 443);
        map_ports
    };

    while curseur.advance().await? {
        let info_instance: InformationMonitor = curseur.deserialize_current()?;
        // let info_instance: InformationMonitor = convertir_bson_deserializable(doc_instance)?;
        debug!("generer_contenu_fiche_publique Information instance : {:?}", info_instance);

        let securite_instance = match info_instance.securite.as_ref() {
            Some(inner) => inner.as_str(),
            None => {
                info!("generer_contenu_fiche_publique Instance {} sans niveau de securite, on skip", info_instance.instance_id);
                continue;
            }
        };

        let securite = Securite::try_from(securite_instance)?;
        match securite {
            Securite::L4Secure => {
                info!("generer_contenu_fiche_publique Instance {} 4.secure, skip pour fiche publique", securite_instance);
                continue;
            },
            _ => ()
        }

        let domaines = match info_instance.domaines {
            Some(inner) => {
                if inner.len() == 0 {
                    info!("generer_contenu_fiche_publique Instance {} n'as aucuns domaines, skip pour fiche publique (1)", info_instance.instance_id);
                    continue;
                }
                inner
            },
            None => {
                info!("generer_contenu_fiche_publique Instance {} n'as aucuns domaines, skip pour fiche publique (2)", info_instance.instance_id);
                continue;
            }
        };

        let presence_expiree = Utc::now() - Duration::from_secs(3600);
        match info_instance.date_presence {
            Some(inner) => {
                if inner < presence_expiree {
                    info!("generer_contenu_fiche_publique Instance {} expiree, skip", info_instance.instance_id);
                    continue;
                }
            },
            None => {
                info!("generer_contenu_fiche_publique Instance {} sans date de presence, skip", info_instance.instance_id);
                continue;
            }
        }

        // Preparer partie de la fiche publique d'instance
        let information_instance = InformationInstance {
            ports: map_ports.clone(),
            onion: None,
            securite: securite_instance.to_owned(),
            domaines: Some(domaines.clone())
        };
        instances.insert(info_instance.instance_id.clone(), information_instance);

        // Conserver la liste des applications/versions par nom d'application
        let mut app_versions = HashMap::new();
        if let Some(apps_config) = info_instance.applications_configurees {
            for app_config in apps_config {
                app_versions.insert(app_config.nom.clone(), app_config);
            }
        }

        // Generer la liste des applications avec leur url
        if let Some(apps) = info_instance.applications {
            for app in apps {
                let securite = match &app.securite {
                    Some(s) => {
                        let securite = match Securite::try_from(s.as_str()) {
                            Ok(inner) => inner,
                            Err(e) => {
                                warn!("generer_contenu_fiche_publique Securite app {} incorrecte : {:?}, skip", app.application, e);
                                continue;
                            }
                        };
                        match securite {
                            Securite::L1Public | Securite::L2Prive => securite,
                            _ => {
                                debug!("generer_contenu_fiche_publique Securite app {} n'est pas 1 ou 2, skip", app.application);
                                continue;
                            }
                        }
                    }
                    None => continue  // On assume securite protege ou secure, skip
                };

                // V2
                let mut application_v2 = match applications_v2.get_mut(&app.application) {
                    Some(inner) => inner,
                    None => {
                        let label = match app.name_property.clone() {
                            Some(inner) => {
                                if Some(false) != app.supporte_usagers {
                                    let mut label = HashMap::new();
                                    label.insert("fr".to_string(), inner);
                                    Some(label)
                                } else {
                                    None
                                }
                            },
                            None => None
                        };
                        let mut app_v2 = ApplicationsV2 {
                            instances: HashMap::new(),
                            name: label,
                            securite: securite.get_str().to_owned(),
                            supporte_usager: None,
                        };

                        applications_v2.insert(app.application.clone(), app_v2);

                        // Recuperer pointeur mut
                        applications_v2.get_mut(&app.application).expect("app_v2")
                    }
                };

                let pathname = {
                    let pathname = match app.url.as_ref() {
                        Some(inner) => match Url::parse(inner.as_str()) {
                            Ok(url) => Some(url.path().to_owned()),
                            Err(e) => {
                                debug!("Erreur parse URL {:}", e);
                                None
                            }
                        },
                        None => None
                    };

                    match pathname {
                        Some(inner) => inner,
                        None => {
                            // Utiliser pathname par defaut
                            format!("/{}", &app.application)
                        }
                    }
                };

                let mut appv2_info = InformationApplicationInstance {
                    pathname: format!("/{}", &app.application),
                    port: None,
                    version: "".to_string()
                };

                // V1
                let mut app_publique: ApplicationPublique = app.clone().try_into()?;
                let nom_app = app_publique.application.as_str();
                if let Some(v) = app_versions.get(nom_app) {
                    app_publique.version = v.version.to_owned();
                    if let Some(version) = v.version.as_ref() {
                        appv2_info.version = version.to_owned();
                    }
                }

                // Recuperer pointer mut pour vec applications. Creer si l'application n'existe pas deja.
                let apps_mut = match applications.get_mut(nom_app) {
                    Some(a) => a,
                    None => {
                        applications.insert(nom_app.to_owned(), Vec::new());
                        applications.get_mut(nom_app).expect("apps_mut")
                    }
                };

                apps_mut.push(app_publique);

                if let Some(hostname_onion) = info_instance.onion.as_ref() {
                    let mut app_onion: ApplicationPublique = app.try_into()?;
                    let nom_app = app_onion.application.as_str();
                    app_onion.nature = ADRESSE_NATURE_ONION.into();
                    app_onion.preference = ADRESSE_PREFERENCE_SECONDAIRE;

                    // Remplacer hostname par adresse .onion
                    let mut url_app = Url::parse(app_onion.url.as_str())?;
                    url_app.set_host(Some(hostname_onion))?;
                    app_onion.url = url_app.as_str().into();

                    if let Some(v) = app_versions.get(nom_app) {
                        app_onion.version = v.version.to_owned();
                    }

                    apps_mut.push(app_onion);
                }

                application_v2.instances.insert(info_instance.instance_id.clone(), appv2_info);
            }
        }
    }

    Ok(FichePublique {
        applications: Some(applications),
        applications_v2,
        chiffrage: Some(chiffrage),
        ca: Some(middleware.ca_pem().into()),
        idmg: middleware.idmg().into(),
        instances,
    })
}

// async fn get_cles_chiffrage<M>(middleware: &M) -> Vec<Vec<String>>
//     where M: ValidateurX509 /*+ ChiffrageFactoryTrait*/
// {
//     let mut chiffrage = Vec::new();
//     let public_keys = middleware.get_publickeys_chiffrage();
//     for key in public_keys {
//         let fingerprint = &key.fingerprint;
//         if let Some(certificat) = middleware.get_certificat(fingerprint).await {
//             let pem_vec: Vec<String> = certificat.get_pem_vec().into_iter().map(|c| c.pem).collect::<Vec<String>>();
//             // Skip certificat millegrille
//             if pem_vec.len() > 1 {
//                 chiffrage.push(pem_vec);
//             }
//         }
//     }
//     chiffrage
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InformationInstance {
    domaines: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onion: Option<Vec<String>>,
    ports: HashMap<String, u16>,
    securite: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InformationApplicationInstance {
    pathname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ApplicationsV2 {
    instances: HashMap<String, InformationApplicationInstance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<HashMap<String, String>>,
    securite: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    supporte_usager: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FichePublique {
    applications: Option<HashMap<String, Vec<ApplicationPublique>>>,
    #[serde(rename = "applicationsV2")]
    applications_v2: HashMap<String, ApplicationsV2>,
    chiffrage: Option<Vec<Vec<String>>>,
    ca: Option<String>,
    idmg: String,
    instances: HashMap<String, InformationInstance>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ApplicationPublique {
    application: String,
    version: Option<String>,
    url: String,
    preference: u8,
    nature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocumentApplicationsTiers {
    idmg: String,
    adresses: Option<Vec<String>>,
    applications: HashMap<String, Vec<ApplicationPublique>>,
    chiffrage: Vec<Vec<String>>,
    ca: String,
}

// impl TryInto<ReponseApplicationsTiers> for DocumentApplicationsTiers {
//     type Error = String;
//
//     fn try_into(self) -> Result<ReponseApplicationsTiers, Self::Error> {
//
//         let application = match self.applications.len() {
//             1 => {
//                 let (_, app_info) = self.applications.into_iter().next();
//                 app_info
//             },
//             _ => Err(format!("core_topologie.TryInto<ReponseApplicationsTiers> Erreur conversion, "))
//         }?;
//
//         Ok(ReponseApplicationsTiers {
//             idmg: self.idmg,
//             adresses: self.adresses,
//             application,
//             chiffrage: self.chiffrage,
//             ca: self.ca,
//         })
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseApplicationsTiers {
    idmg: String,
    adresses: Option<Vec<String>>,
    application: Vec<ApplicationPublique>,
    chiffrage: Vec<Vec<String>>,
    ca: String,
}

impl TryFrom<DocumentApplicationsTiers> for ReponseApplicationsTiers {
    type Error = String;

    fn try_from(value: DocumentApplicationsTiers) -> Result<Self, Self::Error> {
         let application = match value.applications.len() {
            1 => {
                 match value.applications.into_iter().next() {
                     Some((_, app_info)) => Ok(app_info),
                     None => Err(format!("core_topologie.TryFrom<DocumentApplicationsTiers> Erreur conversion"))
                 }
            },
            _ => Err(format!("core_topologie.TryFrom<DocumentApplicationsTiers> Erreur conversion, nombre d'applications doit etre 1"))
        }?;

        Ok(ReponseApplicationsTiers {
            idmg: value.idmg,
            adresses: value.adresses,
            application,
            chiffrage: value.chiffrage,
            ca: value.ca,
        })
    }
}

/// Genere information de resolution locale (urls, etc)
async fn produire_information_locale<M>(middleware: &M)
                                        -> Result<(), millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("produire_information_locale");
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let idmg_local = enveloppe_privee.enveloppe_pub.idmg()?;

    let adresses = {
        let mut adresses = Vec::new();

        let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
        let filtre = doc! {};
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(inst) = curseur.next().await {
            let doc_instance = inst?;
            let info_instance: InformationMonitor = convertir_bson_deserializable(doc_instance)?;
            debug!("Information instance : {:?}", info_instance);
            if let Some(d) = &info_instance.domaines {
                adresses.extend(d.iter().map(|d| d.to_owned()));
            }
        }
        adresses
    };

    {   // Collection millegrilles
        let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
        let filtre = doc! {TRANSACTION_CHAMP_IDMG: &idmg_local};
        let ops = doc! {
            "$setOnInsert": {
                TRANSACTION_CHAMP_IDMG: &idmg_local,
                CHAMP_CREATION: Utc::now(),
            },
            "$set": {
                CHAMP_ADRESSES: &adresses,
                "local": true,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let options = UpdateOptions::builder()
            .upsert(true)
            .build();
        collection.update_one(filtre, ops, Some(options)).await?;
    }

    {   // Collection millegrillesAdresses pour resolve par adresse (unique)
        let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;
        for adresse in &adresses {
            let filtre = doc! {CHAMP_ADRESSE: adresse};
            let ops = doc! {
                "$setOnInsert": {
                    CHAMP_ADRESSE: &adresse,
                    CHAMP_CREATION: Utc::now(),
                },
                "$set": {
                    TRANSACTION_CHAMP_IDMG: &idmg_local,
                },
                "$currentDate": {CHAMP_MODIFICATION: true}
            };
            let options = UpdateOptions::builder()
                .upsert(true)
                .build();
            collection.update_one(filtre, ops, Some(options)).await?;
        }
    }

    Ok(())
}

impl TryInto<ApplicationPublique> for InformationApplication {
    type Error = String;

    fn try_into(self) -> Result<ApplicationPublique, Self::Error> {
        let url = match self.url {
            Some(u) => u,
            None => Err(format!("core_topologie.TryInto<ApplicationPublique> URL manquant"))?
        };
        Ok(ApplicationPublique {
            application: self.application,
            version: None,
            url,
            preference: ADRESSE_PREFERENCE_PRIMAIRE,
            nature: ADRESSE_NATURE_DNS.into(),
        })
    }
}

async fn requete_fiche_millegrille<M>(middleware: &M, message: MessageValide)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("requete_fiche_millegrille");
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteFicheMillegrille = message_contenu.deserialize()?;
    debug!("requete_fiche_millegrille Parsed : {:?}", requete);

    let enveloppe_locale = middleware.get_enveloppe_signature();
    let idmg_local = enveloppe_locale.enveloppe_pub.idmg()?;

    let fiche = match requete.idmg.as_str() == idmg_local.as_str() {
        true => {
            // Fiche publique locale
            Some(generer_contenu_fiche_publique(middleware).await?)
        },
        false => {
            // Fiche publique d'une millegrille tierce
            let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
            let filtre = doc! {
                TRANSACTION_CHAMP_IDMG: &requete.idmg,
            };
            match collection.find_one(filtre, None).await? {
                Some(doc_fiche) => {
                    let mut fiche: FichePublique = convertir_bson_deserializable(doc_fiche)?;
                    Some(fiche)
                },
                None => None
            }
        }
    };

    let reponse = match fiche {
        Some(r) => {
            // middleware.formatter_reponse(fiche, None)
            let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, "fichePublique", vec![])
                .build();
            middleware.build_message_action(
                millegrilles_cryptographie::messages_structs::MessageKind::Commande, routage, r)?.0
            // middleware.formatter_message(
            //     MessageKind::Commande, &r, Some(DOMAINE_TOPOLOGIE), Some("fichePublique"),
            //     None::<&str>, None::<&str>,Some(1), true)
        }
        None => {
            // middleware.formatter_reponse(json!({"ok": false, "code": 404, "err": "Non trouve"}), None)
            middleware.reponse_err(404, None, Some("Non trouve"))?
        }
    };

    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteFicheMillegrille {
    idmg: String,
}

async fn requete_applications_tiers<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteApplicationsTiers = message_contenu.deserialize()?;
    debug!("requete_applications_tiers Parsed : {:?}", requete);

    let projection = doc! {
        "idmg": 1,
        "ca": 1,
        "chiffrage": 1,
        format!("applications.{}", requete.application): 1
    };

    let options = FindOptions::builder().projection(projection).build();

    let filtre = doc! {
        TRANSACTION_CHAMP_IDMG: {"$in": &requete.idmgs},
        format!("applications.{}", requete.application): {"$exists": true},
    };

    let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
    let mut curseur = collection.find(filtre, Some(options)).await?;
    let mut fiches = Vec::new();
    while let Some(doc_fiche) = curseur.next().await {
        let document_applications: DocumentApplicationsTiers = convertir_bson_deserializable(doc_fiche?)?;
        debug!("Document applications mappe : {:?}", document_applications);
        let reponse_applications: ReponseApplicationsTiers = document_applications.try_into()?;
        fiches.push(reponse_applications);
    }
    // let reponse = middleware.formatter_reponse(&json!({"fiches": fiches}), None)?;
    let reponse = middleware.build_reponse(json!({"fiches": fiches}))?.0;

    // let reponse = match collection.find_one(filtre, Some(options)).await? {
    //     Some(d) => {
    //         let document_applications: DocumentApplicationsTiers = convertir_bson_deserializable(d)?;
    //         let reponse_applications: ReponseApplicationsTiers = document_applications.try_into()?;
    //         middleware.formatter_reponse(reponse_applications, None)
    //     }
    //     None => {
    //         middleware.formatter_reponse(json!({"ok": false, "code": 404, "err": "Non trouve"}), None)
    //     }
    // }?;

    Ok(Some(reponse))
}

async fn requete_consignation_fichiers<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteConsignationFichiers = message_contenu.deserialize()?;
    debug!("requete_consignation_fichiers Parsed : {:?}", requete);

    let instance_id = match message.certificat.subject()?.get("commonName") {
        Some(inner) => inner.clone(),
        None => Err(format!("requete_consignation_fichiers Erreur chargement, certificat sans commonName"))?
    };

    let mut projection = doc! {
        "instance_id": 1,
        "consignation_url": 1,
        "type_store": 1,
        "url_download": 1,
        "url_archives": 1,
        "sync_intervalle": 1,
        "sync_actif": 1,
        "supporte_archives": 1,
        "data_chiffre": 1,
        "hostname_sftp": 1,
        "username_sftp": 1,
        "remote_path_sftp": 1,
        "key_type_sftp": 1,
        "s3_access_key_id": 1,
        "s3_region": 1,
        "s3_endpoint": 1,
        "s3_bucket": 1,
        "type_backup": 1,
        "hostname_sftp_backup": 1,
        "username_sftp_backup": 1,
        "remote_path_sftp_backup": 1,
        "key_type_sftp_backup": 1,
        "backup_intervalle_secs": 1,
        "backup_limit_bytes": 1,
    };

    if let Some(true) = requete.stats {
        // Inclure information des fichiers et espace
        projection.insert("principal", 1);
        projection.insert("archive", 1);
        projection.insert("orphelin", 1);
        projection.insert("manquant", 1);
    }

    let options = FindOneOptions::builder()
        .projection(projection)
        .build();

    let filtre = match requete.instance_id {
        Some(inner) => doc! { "instance_id": inner },
        None => match requete.hostname {
            Some(inner) => {
                // Trouver une instance avec le hostname demande
                let collection = middleware.get_collection(NOM_COLLECTION_INSTANCES)?;
                let filtre = doc! {"$or": [{"domaine": &inner}, {"onion": &inner}]};
                match collection.find_one(filtre, None).await? {
                    Some(inner) => {
                        let info_instance: InformationMonitor = convertir_bson_deserializable(inner)?;
                        doc! { "instance_id": info_instance.instance_id }
                    },
                    None => {
                        //let reponse = json!({"ok": false});
                        //return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                        return Ok(Some(middleware.reponse_err(None, None, None)?))
                    }
                }
            }
            None => {
                if let Some(true) = requete.primaire {
                    doc! { "primaire": true, }
                } else {
                    // Determiner la consignation a utiliser
                    // Charger instance et lire consignation_id. Si None, comportement par defaut.
                    let filtre_instance = doc! { CHAMP_INSTANCE_ID: &instance_id };
                    let collection_instance = middleware.get_collection_typed::<TransactionSetConsignationInstance>(
                        NOM_COLLECTION_INSTANCES)?;
                    match collection_instance.find_one(filtre_instance.clone(), None).await? {
                        Some(instance_info) => {
                            match instance_info.consignation_id {
                                Some(consignation_id) => {
                                    debug!("requete_consignation_fichiers Utilisation consignation_id {} pour instance_id {}", consignation_id, instance_id);
                                    doc! { CHAMP_INSTANCE_ID: consignation_id }
                                },
                                None => {
                                    // Determiner si l'instance possede un serveur de consignation de fichiers
                                    let collection_fichiers = middleware.get_collection_typed::<TransactionConfigurerConsignation>(
                                        NOM_COLLECTION_FICHIERS)?;
                                    match collection_fichiers.find_one(filtre_instance.clone(), None).await? {
                                        Some(inner) => filtre_instance,
                                        None => {
                                            // L'instance n'a pas de serveur de consignation de fichiers, utiliser primaire
                                            doc! { "primaire": true }
                                        }
                                    }
                                }
                            }
                        },
                        None => {
                            // L'instance est inconnue (anormal...), on selectionne le primaire
                            doc! { "primaire": true }
                        }
                    }

                    // // On ne veut pas le primaire si secondaire local est disponible
                    // let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
                    // let filtre = doc! { "instance_id": &instance_id };
                    // let compte_doc = collection.count_documents(filtre.clone(), None).await?;
                    // if compte_doc > 0 {
                    //     debug!("requete_consignation_fichiers Utilisation instance_id local {}", instance_id);
                    //     filtre
                    // } else {
                    //     // L'instance n'a pas de fichiers localement, on utilise le primaire
                    //     doc! { "primaire": true }
                    // }
                }
            }
        }
    };

    debug!("requete_consignation_fichiers Filtre {:?}", filtre);
    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
    let fiche_consignation = collection.find_one(filtre, Some(options)).await?;
    let reponse = match fiche_consignation {
        Some(f) => {
            let mut fiche_reponse: ReponseInformationConsignationFichiers = convertir_bson_deserializable(f)?;
            fiche_reponse.ok = Some(true);
            debug!("requete_consignation_fichiers Row consignation : {:?}", fiche_reponse);

            // Recuperer info instance pour domaine et onion
            let filtre = doc! {"instance_id": &fiche_reponse.instance_id};
            let collection = middleware.get_collection_typed::<InformationMonitor>(NOM_COLLECTION_INSTANCES)?;
            if let Some(info_instance) = collection.find_one(filtre, None).await? {
                // let info_instance: InformationMonitor = convertir_bson_deserializable(doc_instance)?;
                debug!("requete_consignation_fichiers Info instance chargee {:?}", info_instance);
                let mut domaines = match info_instance.domaines {
                    Some(inner) => inner.clone(),
                    None => Vec::new()
                };
                // if let Some(inner) = info_instance.domaine {
                //     domaines.push(inner);
                // }
                if let Some(inner) = info_instance.onion {
                    domaines.push(inner);
                }
                fiche_reponse.hostnames = Some(domaines);
            }

            // middleware.formatter_reponse(&fiche_reponse, None)
            middleware.build_reponse(fiche_reponse)?.0
        },
        None => middleware.reponse_err(None, None, None)?
    };

    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParametresGetCleConfiguration {
    // ref_hachage_bytes: String,
}

async fn requete_get_cle_configuration<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_cle_configuration Message : {:?}", &m.message);
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: ParametresGetCleConfiguration = message_contenu.deserialize()?;
    debug!("requete_get_cle_configuration cle parsed : {:?}", requete);

    if ! m.certificat.verifier_roles(vec![RolesCertificats::Fichiers])? {
        // let reponse = json!({"err": true, "message": "certificat doit etre de role fichiers"});
        // return Ok(Some(middleware.formatter_reponse(reponse, None)?));
        return Ok(Some(middleware.reponse_err(None, Some("Certificat doit etre de role fichiers"), None)?))
    }

    // Utiliser certificat du message client (requete) pour demande de rechiffrage
    let instance_id = m.certificat.get_common_name()?;
    let pem_rechiffrage = m.certificat.chaine_pem()?;
    // let pem_rechiffrage: Vec<String> = fp_certs.into_iter().map(|cert| cert.pem).collect();

    // Recuperer information de dechiffrage (avec cle_id) pour cette instance
    let filtre = doc!("instance_id": &instance_id);
    let collection = middleware.get_collection_typed::<ReponseConsignationSatellite>(NOM_COLLECTION_FICHIERS)?;
    let consignation_instance = match collection.find_one(filtre, None).await? {
        Some(inner) => inner,
        None => {
            info!("requete_get_cle_configuration Aucune configuration pour fichiers sur instance {}", instance_id);
            return Ok(Some(middleware.reponse_err(1, None, Some("Aucune configuration de fichiers trouvees"))?))
        }
    };

    let data_chiffre = match consignation_instance.data_chiffre {
        Some(inner) => inner,
        None => {
            info!("requete_get_cle_configuration Aucune configuration pour fichiers sur instance {}", instance_id);
            return Ok(Some(middleware.reponse_err(1, None, Some("Aucune configuration chiffree trouvee pour les fichiers"))?))
        }
    };

    let cle_id = match data_chiffre.cle_id {
        Some(inner) => inner,
        None => match data_chiffre.ref_hachage_bytes {
            Some(inner) => inner,
            None => {
                info!("requete_get_cle_configuration Aucune configuration cle_id/ref_hachage_bytes trouve pour {}", instance_id);
                return Ok(Some(middleware.reponse_err(1, None, Some("Aucune configuration cle_id/ref_hachage_bytes trouve trouvee pour les fichiers"))?))
            }
        }
    };

    let permission = RequeteDechiffrage {
        domaine: DOMAINE_NOM.to_string(),
        liste_hachage_bytes: None,
        cle_ids: Some(vec![cle_id]),
        certificat_rechiffrage: Some(pem_rechiffrage)
    };

    let (reply_to, correlation_id) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            let reply_q = match r.reply_to.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(String::from("requete_get_cle_configuration Reply to manquant"))?
            };
            let correlation_id = match r.correlation_id.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(String::from("requete_get_cle_configuration Correlation id manquant"))?
            };
            (reply_q, correlation_id)
        }
        _ => Err(String::from("requete_get_cle_configuration Mauvais type de message"))?
    };

    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege]
    )
        .reply_to(reply_to)
        .correlation_id(correlation_id)
        .blocking(false)
        .build();

    debug!("requete_get_cle_configuration Transmettre requete permission dechiffrage cle : {:?}", permission);
    middleware.transmettre_requete(routage, &permission).await?;

    Ok(None)  // Aucune reponse a transmettre, c'est le maitre des cles qui va repondre
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseConsignationSatellite {
    pub instance_id: String,
    pub consignation_url: Option<String>,
    pub type_store: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sync_intervalle: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync_actif: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supporte_archives: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_chiffre: Option<DataChiffre>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_download: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_archives: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostnames: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primaire: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_sftp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_sftp: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_sftp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_path_sftp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type_sftp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_bucket: Option<String>,

    // Backup
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_sftp_backup: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_path_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_intervalle_secs: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_limit_bytes: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphelin: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manquant: Option<PresenceFichiersRepertoire>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub espace_disponible: Option<usize>,
    #[serde(rename = "_mg-derniere-modification", skip_serializing_if = "Option::is_none", serialize_with="optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    pub derniere_modification: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseConfigurationFichiers {
    liste: Vec<ReponseConsignationSatellite>,
    ok: bool,
}

async fn requete_configuration_fichiers<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteConfigurationFichiers = message_contenu.deserialize()?;
    debug!("requete_configuration_fichiers Parsed : {:?}", requete);

    let mut liste = Vec::new();

    let filtre = doc! {};
    let collection = middleware.get_collection_typed::<ReponseConsignationSatellite>(NOM_COLLECTION_FICHIERS)?;
    let mut curseur = collection.find(filtre, None).await?;
    while let Some(fiche) = curseur.next().await {
        // let doc_inner = inner?;
        let fiche = fiche?;

        // Extraire date BSON separement
        // let date_modif = match doc_inner.get(CHAMP_MODIFICATION) {
        //     Some(inner) => Some(DateEpochSeconds::try_from(inner.to_owned())?),
        //     None => None
        // };

        // let fiche: ReponseConsignationSatellite = convertir_bson_deserializable(doc_inner)?;
        // fiche.derniere_modification = date_modif;  // Re-injecter date

        liste.push(fiche);
    }

    let reponse = ReponseConfigurationFichiers { liste, ok: true };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteConfigurationFichiers {
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteApplicationsTiers {
    idmgs: Vec<String>,
    application: String,
}

#[derive(Clone, Debug, Deserialize)]
struct RowInstanceActivite {
    instance_id: String,
    hostname: Option<String>,
    date_presence: Option<i64>,
    date_hors_ligne: Option<i64>,
}

async fn verifier_instances_horsligne<M>(middleware: &M)
    -> Result<(), millegrilles_common_rust::error::Error>
    where M: MongoDao + EmetteurNotificationsTrait
{
    debug!("verifier_instances_horsligne Debut verification");

    let now = Utc::now().timestamp();
    let expiration = now - 400;  // Date expiration epoch (secondes)

    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;

    let projection = doc!{"instance_id": 1, "hostname": 1, "date_presence": 1, "date_hors_ligne": 1};

    let nouveau_hors_ligne = {
        let mut nouveau_hors_ligne = Vec::new();
        let filtre_horsligne = doc! {
            "date_presence": {"$lt": &expiration},
            "date_hors_ligne": {"$exists": false}
        };
        let options = FindOptions::builder().projection(projection.clone()).build();
        let mut curseur = collection.find(filtre_horsligne, options).await?;

        while let Some(d) = curseur.next().await {
            let row: RowInstanceActivite = convertir_bson_deserializable(d?)?;
            debug!("Instance hors ligne : {:?}", row);
            nouveau_hors_ligne.push(row);
        }

        nouveau_hors_ligne
    };

    let nouveau_en_ligne = {
        let mut nouveau_en_ligne = Vec::new();
        let filtre_en_ligne = doc! {
            "date_presence": {"$gte": &expiration},
            "date_hors_ligne": {"$exists": true}
        };
        let options = FindOptions::builder().projection(projection.clone()).build();
        let mut curseur = collection.find(filtre_en_ligne, options).await?;

        while let Some(d) = curseur.next().await {
            let row: RowInstanceActivite = convertir_bson_deserializable(d?)?;
            debug!("Instance en ligne : {:?}", row);
            nouveau_en_ligne.push(row);
        }

        nouveau_en_ligne
    };

    if nouveau_hors_ligne.len() == 0 && nouveau_en_ligne.len() == 0 {
        debug!("Aucun changement hors ligne/en ligne pour instances");
    } else {
        let mut message_lignes = Vec::new();
        if nouveau_hors_ligne.len() > 0 {
            message_lignes.push("<p>Instances hors ligne</p>".to_string());
            for instance in &nouveau_hors_ligne {
                if let Some(h) = instance.hostname.as_ref() {
                    message_lignes.push(format!("<p>{:?}</p>", h))
                }
            }
        }
        message_lignes.push("<p></p>".to_string());
        if nouveau_en_ligne.len() > 0 {
            message_lignes.push("<p>Instances en ligne</p>".to_string());
            for instance in &nouveau_en_ligne {
                if let Some(h) = instance.hostname.as_ref() {
                    message_lignes.push(format!("<p>{}</p>", h))
                }
            }
        }

        let message_str = message_lignes.join("\n");
        debug!("verifier_instances_horsligne Message notification {}", message_str);

        let sujet = if nouveau_hors_ligne.len() == 1 {
            let row = &nouveau_hors_ligne.get(0).expect("get(0)");
            match &row.hostname {
                Some(h) => format!("{:?} est hors ligne", h),
                None => format!("{:?} est hors ligne", row.instance_id)
            }
        } else if nouveau_hors_ligne.len() > 1 {
            format!("{} instances hors ligne", nouveau_hors_ligne.len())
        } else {
            format!("{} instances de retour en ligne", nouveau_en_ligne.len())
        };

        let notification = NotificationMessageInterne {
            from: "CoreTopologie".to_string(),
            subject: Some(sujet),
            content: message_str,
            version: 1,
            format: "html".to_string(),
        };

        // Marquer les instances
        if nouveau_hors_ligne.len() > 0 {
            let instances_id: Vec<String> = nouveau_hors_ligne.iter().map(|r| r.instance_id.clone()).collect();
            let filtre = doc!{"instance_id": {"$in": instances_id}};
            let ops = doc!{"$set": {"date_hors_ligne": now}, "$currentDate": {CHAMP_MODIFICATION: true}};
            collection.update_many(filtre, ops, None).await?;
        }
        if nouveau_en_ligne.len() > 0 {
            let instances_id: Vec<String> = nouveau_en_ligne.iter().map(|r| r.instance_id.clone()).collect();
            let filtre = doc!{"instance_id": {"$in": instances_id}};
            let ops = doc!{"$unset": {"date_hors_ligne": 1}, "$currentDate": {CHAMP_MODIFICATION: true}};
            collection.update_many(filtre, ops, None).await?;
        }

        middleware.emettre_notification_proprietaire(
            notification,
            "warn",
            Some(now + 7 * 86400),  // Expiration epoch
            None
        ).await?;
    }

    Ok(())
}

#[cfg(test)]
mod test_integration {
    use millegrilles_common_rust::formatteur_messages::FormatteurMessage;
    use millegrilles_common_rust::tokio;

    use crate::test_setup::setup;
    use crate::validateur_pki_mongo::preparer_middleware_pki;

    use super::*;

// #[tokio::test]
// async fn test_liste_applications() {
//     setup("test_liste_applications");
//     let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
//     futures.push(spawn(async move {
//
//         let message = {
//             let contenu = json!({});
//             let mm = middleware.formatter_message(&contenu, None::<&str>, None, None, None).expect("mm");
//             let ms = MessageSerialise::from_parsed(mm).expect("ms");
//             let mut mva = MessageValideAction::new(ms, "", "", "", "", TypeMessageOut::Transaction);
//             mva.exchange = Some(String::from("3.protege"));
//             mva
//         };
//
//         debug!("Duree test_liste_applications");
//         let reponse = liste_applications_deployees(middleware.as_ref(), message).await.expect("reponse");
//         debug!("Reponse test_liste_applications : {:?}", reponse);
//
//     }));
//     // Execution async du test
//     futures.next().await.expect("resultat").expect("ok");
// }
}
