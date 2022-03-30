use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::restaurer;
use millegrilles_common_rust::bson::{Bson, DateTime, doc, to_bson};
use millegrilles_common_rust::bson::Array;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{Timelike, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L1Public, L2Prive, L3Protege};
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::formatteur_messages::MessageSerialise;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_traiter_transaction, sauvegarder_transaction_recue, thread_emettre_presence_domaine};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_deserializable, convertir_bson_value, convertir_to_bson, filtrer_doc_id, IndexOptions, MongoDao};
use millegrilles_common_rust::{chrono, mongodb as mongodb};
use millegrilles_common_rust::chiffrage::Chiffreur;
use millegrilles_common_rust::chiffrage_chacha20poly1305::{CipherMgs3, Mgs3CipherKeys};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::reqwest::Url;
use millegrilles_common_rust::serde_json::{json, Map, Value};
use millegrilles_common_rust::serde_json as serde_json;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, TraiterTransaction, Transaction, TransactionImpl, TriggerTransaction};
use millegrilles_common_rust::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage};
use mongodb::options::{FindOptions, UpdateOptions};
use serde::{Deserialize, Serialize};
use crate::core_maitredescomptes::NOM_COLLECTION_USAGERS;

use crate::validateur_pki_mongo::MiddlewareDbPki;

// Constantes
pub const DOMAINE_NOM: &str = "CoreTopologie";
pub const NOM_COLLECTION_DOMAINES: &str = "CoreTopologie/domaines";
pub const NOM_COLLECTION_NOEUDS: &str = "CoreTopologie/noeuds";
pub const NOM_COLLECTION_MILLEGRILLES: &str = "CoreTopologie/millegrilles";
pub const NOM_COLLECTION_MILLEGRILLES_ADRESSES: &str = "CoreTopologie/millegrillesAdresses";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

pub const DOMAINE_PRESENCE_NOM: &str = "CoreTopologie";

const NOM_Q_TRANSACTIONS: &str = "CoreTopologie/transactions";
const NOM_Q_VOLATILS: &str = "CoreTopologie/volatils";
const NOM_Q_TRIGGERS: &str = "CoreTopologie/triggers";

const REQUETE_APPLICATIONS_DEPLOYEES: &str = "listeApplicationsDeployees";
const REQUETE_LISTE_DOMAINES: &str = "listeDomaines";
const REQUETE_LISTE_NOEUDS: &str = "listeNoeuds";
const REQUETE_INFO_DOMAINE: &str = "infoDomaine";
const REQUETE_INFO_NOEUD: &str = "infoNoeud";
const REQUETE_RESOLVE_IDMG: &str = "resolveIdmg";
const REQUETE_FICHE_MILLEGRILLE: &str = "ficheMillegrille";
const REQUETE_APPLICATIONS_TIERS: &str = "applicationsTiers";

const TRANSACTION_DOMAINE: &str = "domaine";
const TRANSACTION_MONITOR: &str = "monitor";
const TRANSACTION_SUPPRIMER_INSTANCE: &str = "supprimerInstance";

const EVENEMENT_PRESENCE_MONITOR: &str = "presence";
// const EVENEMENT_PRESENCE_DOMAINE: &str = EVENEMENT_PRESENCE_DOMAINE;
const EVENEMENT_FICHE_PUBLIQUE: &str = "fichePublique";
const EVENEMENT_INSTANCE_SUPPRIMEE: &str = "instanceSupprimee";

const INDEX_DOMAINE: &str = "domaine";
const INDEX_NOEUDS: &str = "noeuds";
const INDEX_IDMG: &str = "idmg";
const INDEX_ADRESSES: &str = "adresses";
const INDEX_ADRESSE: &str = "adresse";

const CHAMP_DOMAINE: &str = "domaine";
const CHAMP_NOEUD_ID: &str = "noeud_id";
const CHAMP_ADRESSE: &str = "adresse";
const CHAMP_ADRESSES: &str = "adresses";

const ADRESSE_PREFERENCE_PRIMAIRE: u8 = 1;
const ADRESSE_PREFERENCE_SECONDAIRE: u8 = 2;

const ADRESSE_NATURE_DNS: &str = "dns";
const ADRESSE_NATURE_IP4: &str = "ip4";
const ADRESSE_NATURE_IP6: &str = "ip6";
const ADRESSE_NATURE_ONION: &str = "onion";

// permissionDechiffrage
// listerNoeudsAWSS3

/// Instance statique du gestionnaire de maitredescomptes
pub const GESTIONNAIRE_TOPOLOGIE: GestionnaireDomaineTopologie = GestionnaireDomaineTopologie {};

#[derive(Clone)]
pub struct GestionnaireDomaineTopologie {}

#[async_trait]
impl TraiterTransaction for GestionnaireDomaineTopologie {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireDomaineTopologie {
    #[inline]
    fn get_nom_domaine(&self) -> String { DOMAINE_NOM.into() }
    #[inline]
    fn get_collection_transactions(&self) -> String { NOM_COLLECTION_TRANSACTIONS.into() }

    fn get_collections_documents(&self) -> Vec<String> {
        vec![
            String::from(NOM_COLLECTION_DOMAINES),
            String::from(NOM_COLLECTION_NOEUDS),
        ]
    }

    #[inline]
    fn get_q_transactions(&self) -> String { NOM_Q_TRANSACTIONS.into() }
    #[inline]
    fn get_q_volatils(&self) -> String { NOM_Q_VOLATILS.into() }
    #[inline]
    fn get_q_triggers(&self) -> String { NOM_Q_TRIGGERS.into() }

    fn preparer_queues(&self) -> Vec<QueueType> { preparer_queues() }

    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao {
        preparer_index_mongodb_custom(middleware).await  // Fonction plus bas
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction)
                                  -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        consommer_requete(middleware, message).await  // Fonction plus bas
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction)
                                   -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        consommer_commande(middleware, message, self).await  // Fonction plus bas
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        consommer_transaction(middleware, message).await  // Fonction plus bas
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction)
                                    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        consommer_evenement(middleware, message).await  // Fonction plus bas
    }

    async fn entretien<M>(&self, middleware: Arc<M>)
        where M: Middleware + 'static
    {
        entretien(middleware).await  // Fonction plus bas
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Box<dyn Error>> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
                                          -> Result<Option<MessageMilleGrille>, String>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao,
            T: Transaction
    {
        aiguillage_transaction(middleware, transaction).await   // Fonction plus bas
    }
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 3.protege seulement
    let requetes_protegees = vec![
        REQUETE_LISTE_DOMAINES,
        REQUETE_LISTE_NOEUDS,
        REQUETE_INFO_DOMAINE,
        REQUETE_INFO_NOEUD,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege });
    }

    // RK 2.prive
    let requetes_privees = vec![
        REQUETE_APPLICATIONS_DEPLOYEES,
        // REQUETE_INFO_NOEUD,
        // REQUETE_RESOLVE_IDMG,
        REQUETE_FICHE_MILLEGRILLE,
        REQUETE_APPLICATIONS_TIERS,
    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive });
    }

    // RK 1.public
    let requetes_publiques = vec![
        REQUETE_FICHE_MILLEGRILLE,
        REQUETE_APPLICATIONS_TIERS,
    ];
    for req in requetes_publiques {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L1Public });
    }

    let commandes: Vec<&str> = vec![
        //TRANSACTION_APPLICATION,  // Transaction est initialement recue sous forme de commande uploadee par ServiceMonitor ou autre source
        TRANSACTION_MONITOR,
        TRANSACTION_SUPPRIMER_INSTANCE,
    ];
    for commande in commandes {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L3Protege });
    }

    let sec_monitor = vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure];
    for sec in sec_monitor {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.monitor.{}", EVENEMENT_PRESENCE_MONITOR), exchange: sec});
    }

    // Presence de domaines se fait sur l'evenement du domaine specifique (*)
    rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.*.{}", EVENEMENT_PRESENCE_DOMAINE), exchange: Securite::L4Secure });

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue(
        ConfigQueue {
            nom_queue: NOM_Q_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: 300000.into(),
            durable: false,
        }
    ));

    let mut rk_transactions = Vec::new();
    // rk_transactions.push(ConfigRoutingExchange {
    //     routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_MONITOR).into(),
    //     exchange: Securite::L3Protege,
    // });
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_MONITOR).into(),
        exchange: Securite::L4Secure,
    });
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_SUPPRIMER_INSTANCE).into(),
        exchange: Securite::L4Secure,
    });

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue(
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers(DOMAINE_NOM.into(), Securite::L3Protege));

    queues
}

/// Creer index MongoDB
async fn preparer_index_mongodb_custom<M>(middleware: &M) -> Result<(), String>
    where M: MongoDao
{

    // Transactions

    // Index transactions par uuid-transaction
    let options_unique_transactions = IndexOptions {
        nom_index: Some(String::from(TRANSACTION_CHAMP_UUID_TRANSACTION)),
        unique: true,
    };
    let champs_index_transactions = vec!(
        ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION), direction: 1 }
    );
    middleware.create_index(
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
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

async fn traiter_cedule<M>(middleware: &M, trigger: &MessageCedule) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + Chiffreur<CipherMgs3, Mgs3CipherKeys> {
    let date_epoch = trigger.get_date();
    debug!("Traiter cedule {}\n{:?}", DOMAINE_NOM, date_epoch);

    let minutes = date_epoch.get_datetime().minute();

    // Generer une fiche a toutes les 15 minutes
    if minutes % 15 == 1 {
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

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_APPLICATIONS_DEPLOYEES => liste_applications_deployees(middleware, message).await,
                REQUETE_LISTE_DOMAINES => liste_domaines(middleware, message).await,
                REQUETE_LISTE_NOEUDS => liste_noeuds(middleware, message).await,
                REQUETE_RESOLVE_IDMG => resolve_idmg(middleware, message).await,
                REQUETE_FICHE_MILLEGRILLE => requete_fiche_millegrille(middleware, message).await,
                REQUETE_APPLICATIONS_TIERS => requete_applications_tiers(middleware, message).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                }
            }
        }
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        }
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireDomaineTopologie)
                               -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: Middleware + 'static
{
    debug!("Consommer commande : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
            true => Ok(()),
            false => Err(format!("Commande autorisation invalide (pas 3.protege ou 4.secure)")),
        }
    }?;

    match m.action.as_str() {
        // Commandes standard
        TRANSACTION_MONITOR => traiter_commande_monitor(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_INSTANCE => traiter_commande_supprimer_instance(middleware, m, gestionnaire).await,
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
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
            true => Ok(()),
            false => Err(format!("core_topologie.consommer_transaction Autorisation invalide (pas 4.secure) : {}", m.routing_key))
        }
    }?;

    match m.action.as_str() {
        TRANSACTION_DOMAINE | TRANSACTION_MONITOR | TRANSACTION_SUPPRIMER_INSTANCE => {
            sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
            Ok(None)
        }
        _ => Err(format!("core_topologie.consommer_transaction Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_evenement(middleware: &(impl ValidateurX509 + GenerateurMessages + MongoDao), m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> {
    debug!("Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges(vec![
        Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure,
    ]) {
        true => Ok(()),
        false => Err(format!("Evenement autorisation invalide (pas exchange autorise)")),
    }?;

    match m.action.as_str() {
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

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        TRANSACTION_DOMAINE => traiter_transaction_domaine(middleware, transaction).await,
        TRANSACTION_MONITOR => traiter_transaction_monitor(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_INSTANCE => traiter_transaction_supprimer_instance(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn traiter_presence_domaine<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Evenement presence domaine : {:?}", m.message.get_msg());
    let event: PresenceDomaine = m.message.get_msg().map_contenu(None)?;
    debug!("Presence domaine : {:?}", event);

    let mut set_ops = m.message.get_msg().map_to_bson()?;
    filtrer_doc_id(&mut set_ops);

    // Retirer champ cle
    set_ops.remove("domaine");

    let domaine = match event.domaine.as_ref() {
        Some(d) => d,
        None => {
            // Rien a faire
            return Ok(None)
        }
    };
    let filtre = doc! {"domaine": domaine};
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {"domaine": domaine, CHAMP_CREATION: Utc::now(), "dirty": true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    debug!("Document monitor a sauvegarder : {:?}", ops);

    let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
    let options = FindOneAndUpdateOptions::builder().upsert(true).build();
    let result = match collection.find_one_and_update(filtre, ops, Some(options)).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur find document sur transaction domaine : {:?}", e))?
    };
    let creer_transaction = match result {
        Some(d) => d.get_bool("dirty")?,
        None => true,
    };

    if creer_transaction {
        debug!("Creer transaction topologie pour domaine {}", domaine);

        let tval = json!({
            "domaine": event.domaine,
            "noeud_id": event.noeud_id,
        });

        let transaction = middleware.formatter_message(
            &tval,
            Some(DOMAINE_NOM),
            Some(TRANSACTION_DOMAINE),
            None,
            None,
            false
        )?;

        // Sauvegarder la transation
        let msg = MessageSerialise::from_parsed(transaction)?;
        let msg_action = MessageValideAction::new(msg, "", "", DOMAINE_NOM, TRANSACTION_DOMAINE, TypeMessageOut::Transaction);
        sauvegarder_transaction_recue(middleware, msg_action, NOM_COLLECTION_TRANSACTIONS).await?;

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
    let estampille = &m.message.get_entete().estampille;
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
    set_ops.insert("date_presence", estampille);

    let filtre = doc! {"noeud_id": &event.noeud_id};
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {"noeud_id": &event.noeud_id, CHAMP_CREATION: Utc::now(), "dirty": true},
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
            "noeud_id": event.noeud_id,
        });

        let transaction = middleware.formatter_message(
            &tval, Some(DOMAINE_NOM), Some(TRANSACTION_MONITOR), None, None, false)?;

        // Sauvegarder la transation
        let msg = MessageSerialise::from_parsed(transaction)?;
        let msg_action = MessageValideAction::new(
            msg, "", "", DOMAINE_NOM, TRANSACTION_DOMAINE, TypeMessageOut::Transaction);
        sauvegarder_transaction_recue(middleware, msg_action, NOM_COLLECTION_TRANSACTIONS).await?;

        // Reset le flag dirty pour eviter multiple transactions sur le meme domaine
        let filtre = doc! {"noeud_id": &event.noeud_id};
        let ops = doc! {"$set": {"dirty": false}};
        let _ = collection.update_one(filtre, ops, None).await?;
    }

    Ok(None)
}


async fn traiter_commande_monitor<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireDomaineTopologie) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer traiter_commande_monitor : {:?}", &message.message);

    // Verifier autorisation
    if ! message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_cle autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err,None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        }
    }

    // Sauvegarder la transaction, marquer complete et repondre
    let reponse = sauvegarder_traiter_transaction(middleware, message, gestionnaire).await?;
    Ok(reponse)
}

async fn traiter_commande_supprimer_instance<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireDomaineTopologie) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer traiter_commande_supprimer_instance : {:?}", &message.message);

    // Verifier autorisation
    if ! message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_cle autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err,None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        }
    }

    // Sauvegarder la transaction, marquer complete et repondre
    let reponse = sauvegarder_traiter_transaction(middleware, message, gestionnaire).await?;
    Ok(reponse)
}

async fn traiter_transaction_domaine<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
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

async fn traiter_transaction_monitor<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    let mut doc = transaction.contenu();
    let mut doc_transaction: PresenceMonitor = match convertir_bson_deserializable(doc) {
        Ok(d) => d,
        Err(e) => Err(format!("core_topologie.traiter_transaction_monitor Erreur conversion transaction monitor : {:?}", e))?
    };
    let noeud_id = doc_transaction.noeud_id;

    let ops = doc! {
        "$set": {"dirty": false, CHAMP_DOMAINE: doc_transaction.domaine},
        "$setOnInsert": {CHAMP_NOEUD_ID: &noeud_id, CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc! {CHAMP_NOEUD_ID: &noeud_id};
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

async fn traiter_transaction_supprimer_instance<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    let mut doc = transaction.contenu();
    let mut doc_transaction: PresenceMonitor = match convertir_bson_deserializable(doc) {
        Ok(d) => d,
        Err(e) => Err(format!("core_topologie.traiter_transaction_supprimer_instance Erreur conversion transaction monitor : {:?}", e))?
    };

    let noeud_id = doc_transaction.noeud_id;

    let filtre = doc! {CHAMP_NOEUD_ID: &noeud_id};
    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
    match collection.delete_one(filtre, None).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur maj transaction topologie domaine : {:?}", e))?
    }

    // Emettre evenement d'instance supprimee
    let evenement_supprimee = json!({"noeud_id": &noeud_id});
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_INSTANCE_SUPPRIMEE)
        .exchanges(vec![L3Protege])
        .build();
    middleware.emettre_evenement(routage, &evenement_supprimee).await?;

    let reponse = match middleware.formatter_reponse(json!({"ok": true}), None) {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur reponse transaction : {:?}", e))?
    };
    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PresenceDomaine {
    domaine: Option<String>,
    noeud_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PresenceMonitor {
    domaine: Option<String>,
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
    // let sec_enum_opt = match message.message.get_extensions() {
    //     Some(extensions) => {
    //         // Verifier le type de securite
    //         match extensions.exchange_top() {
    //             Some(sec) => Some(sec),
    //             None => None
    //         }
    //     }
    //     None => None,
    // };
    // let sec_cascade = match sec_enum_opt {
    //     Some(s) => securite_cascade_public(&s),
    //     None => {
    //         // Aucun niveau de securite, abort
    //         let reponse = match middleware.formatter_reponse(json!({"ok": false}), None) {
    //             Ok(m) => m,
    //             Err(e) => Err(format!("core_topologie.liste_applications_deployees Erreur preparation reponse applications : {:?}", e))?
    //         };
    //         return Ok(Some(reponse));
    //     }
    // };

    // Retour de toutes les applications (maitrecomptes est toujours sur exchange 2.prive)
    let sec_cascade = securite_cascade_public(Securite::L3Protege);

    let mut curseur = {
        let filtre = doc! {};
        let projection = doc! {"noeud_id": true, "domaine": true, "securite": true, "applications": true, "onion": true};
        let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
        let ops = FindOptions::builder().projection(Some(projection)).build();
        match collection.find(filtre, Some(ops)).await {
            Ok(c) => c,
            Err(e) => Err(format!("core_topologie.liste_applications_deployees Erreur chargement applications : {:?}", e))?
        }
    };

    // Extraire liste d'applications
    let mut apps = Vec::new();
    while let Some(d) = curseur.next().await {
        match d {
            Ok(mut doc) => {
                let info_monitor: InformationMonitor = serde_json::from_value(serde_json::to_value(doc)?)?;

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

                                let info_app = json!({
                                    "application": app.application.as_str(),
                                    "securite": securite_str(&securite),
                                    "url": url,
                                    "onion": onion,
                                });

                                apps.push(info_app);

                                // if let Some(onion) = info_monitor.onion.as_ref() {
                                //     // Ajouter adresses .onion
                                //     let mut url_onion = Url::parse(url.as_str())?;
                                //     url_onion.set_host(Some(onion.as_str()));
                                //     let info_app_onion = json!({
                                //         "application": app.application.as_str(),
                                //         "securite": securite_str(&securite),
                                //         "url": url_onion.as_str(),
                                //     });
                                //
                                //     apps.push(info_app_onion);
                                // }
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("core_topologie.liste_applications_deployees  Erreur chargement document : {:?}", e)
        }
    }

    debug!("Apps : {:?}", apps);
    let liste = json!({"resultats": apps});
    let reponse = match middleware.formatter_reponse(&liste, None) {
        Ok(m) => m,
        Err(e) => Err(format!("core_topologie.liste_applications_deployees  Erreur preparation reponse applications : {:?}", e))?
    };
    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InformationMonitor {
    domaine: Option<String>,
    noeud_id: String,
    securite: Option<String>,
    onion: Option<String>,
    applications: Option<Vec<InformationApplication>>,
    applications_configurees: Option<Vec<ApplicationConfiguree>>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ApplicationConfiguree {
    nom: String,
    version: Option<String>,
}

async fn liste_noeuds<M>(middleware: &M, message: MessageValideAction)
                         -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("liste_noeuds");
    if !message.verifier_exchanges_string(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        let refus = json!({"ok": false, "err": "Acces refuse"});
        let reponse = match middleware.formatter_reponse(&refus, None) {
            Ok(m) => m,
            Err(e) => Err(format!("core_topologie.liste_noeuds Erreur preparation reponse applications : {:?}", e))?
        };
        return Ok(Some(reponse));
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
            Err(e) => Err(format!("core_topologie.liste_noeuds Erreur chargement applications : {:?}", e))?
        }
    };

    let mut noeuds = Vec::new();
    while let Some(r) = curseur.next().await {
        match r {
            Ok(mut d) => {
                filtrer_doc_id(&mut d);
                noeuds.push(d);
            }
            Err(e) => warn!("core_topologie.liste_noeuds Erreur lecture document sous liste_noeuds() : {:?}", e)
        }
    }

    debug!("Noeuds : {:?}", noeuds);
    let liste = json!({"resultats": noeuds});
    let reponse = match middleware.formatter_reponse(&liste, None) {
        Ok(m) => m,
        Err(e) => Err(format!("core_topologie.liste_noeuds Erreur preparation reponse noeuds : {:?}", e))?
    };
    Ok(Some(reponse))
}

async fn liste_domaines<M>(middleware: &M, message: MessageValideAction)
                           -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("liste_domaines");
    if !message.verifier_exchanges_string(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        let refus = json!({"ok": false, "err": "Acces refuse"});
        let reponse = match middleware.formatter_reponse(&refus, None) {
            Ok(m) => m,
            Err(e) => Err(format!("core_topologie.liste_domaines Erreur preparation reponse applications : {:?}", e))?
        };
        return Ok(Some(reponse));
    }

    let mut curseur = {
        let projection = doc! {"noeud_id": true, "domaine": true, CHAMP_MODIFICATION: true};
        let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
        let ops = FindOptions::builder().projection(Some(projection)).build();
        match collection.find(doc! {}, Some(ops)).await {
            Ok(c) => c,
            Err(e) => Err(format!("core_topologie.liste_domaines Erreur chargement domaines : {:?}", e))?
        }
    };

    let mut domaines = Vec::new();
    while let Some(r) = curseur.next().await {
        match r {
            Ok(mut d) => {
                // Convertir date bson en DateTimeEpochSeconds
                let date_presence = d.remove(CHAMP_MODIFICATION);
                if let Some(date) = date_presence {
                    if let Some(date) = date.as_datetime() {
                        let date = DateEpochSeconds::from(date.to_chrono());
                        d.insert("date_presence", date);
                    }
                }
                filtrer_doc_id(&mut d);
                domaines.push(d);
            }
            Err(e) => warn!("core_topologie.liste_domaines Erreur lecture document sous liste_noeuds() : {:?}", e)
        }
    }

    debug!("Domaines : {:?}", domaines);
    let liste = json!({"resultats": domaines});
    let reponse = match middleware.formatter_reponse(&liste, None) {
        Ok(m) => m,
        Err(e) => Err(format!("core_topologie.liste_domaines Erreur preparation reponse domaines : {:?}", e))?
    };
    Ok(Some(reponse))
}

async fn resolve_idmg<M>(middleware: &M, message: MessageValideAction)
                         -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("resolve_idmg");
    if !message.verifier_exchanges_string(vec!(String::from(SECURITE_2_PRIVE), String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        let refus = json!({"ok": false, "err": "Acces refuse"});
        let reponse = match middleware.formatter_reponse(&refus, None) {
            Ok(m) => m,
            Err(e) => Err(format!("core_topologie.liste_domaines Erreur preparation reponse applications : {:?}", e))?
        };
        return Ok(Some(reponse));
    }

    let idmg_local = middleware.get_enveloppe_privee().idmg()?;

    let requete: RequeteResolveIdmg = message.message.parsed.map_contenu(None)?;
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
    let reponse = match middleware.formatter_reponse(&liste, None) {
        Ok(m) => m,
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
                         -> Result<Option<String>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("resoudre_url {}", hostname);

    let routage = RoutageMessageAction::builder(DOMAINE_SERVICE_MONITOR, "relaiWeb")
        .exchanges(vec![L1Public])
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
        let reponse_http = middleware.transmettre_commande(routage, &requete, true).await?;
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
    let reponse_fiche: ReponseFichePubliqueTierce = reponse.message.get_msg().map_contenu(None)?;
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
    debug!("resoudre_url Message json string : {}", fiche_json_value);
    let mut fiche_publique_message = MessageSerialise::from_serializable(fiche_json_value)?;
    debug!("resoudre_url Fiche publique message serialize : {:?}", fiche_publique_message);
    let validation_option = ValidationOptions::new(true, true, true);
    let resultat_validation = fiche_publique_message.valider(middleware, Some(&validation_option)).await?;
    if ! resultat_validation.valide() {
        Err(format!("core_topologie.resoudre_url Erreur validation fiche publique : {:?}", resultat_validation))?
    }

    let idmg_tiers = match &fiche_publique_message.certificat {
        Some(c) => c.idmg(),
        None => Err(format!("core_topologie.resoudre_url Erreur chargement certificat de fiche publique, certificat manquant"))
    }?;

    let fiche_publique: FichePubliqueReception = fiche_publique_message.get_msg().map_contenu(None)?;
    // match fiche_publique.ca.clone() {
    //     Some(c) => {
    //         let enveloppe = middleware.charger_enveloppe(&vec![c], None).await?;
    //         fiche_publique_message.set_millegrille(enveloppe);
    //         Ok(())
    //     }
    //     None => Err(format!("core_topologie.resoudre_url Certificat CA manquant de la fiche publique"))
    // }?;
    debug!("resoudre_url Fiche publique mappee : {:?}", fiche_publique);
    //
    // // Valider la fiche (certificats et signature message)
    // let idmg_tiers = match fiche_publique_message.valider_message_tiers(middleware).await {
    //     Ok(idmg_tiers) => Ok(idmg_tiers),
    //     Err(e) => Err(format!("core_topologie.resoudre_url Erreur validation fiche publique : {:?}", e))
    // }?;

    // Sauvegarder/mettre a jour fiche publique
    {
        let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
        let filtre = doc! {"idmg": &idmg_tiers};
        let apps = match &fiche_publique.applications {
            Some(a) => {
                let mut map = Map::new();
                for (key, value) in a.iter() {
                    let value_serde = serde_json::to_value(value)?;
                    map.insert(key.into(), value_serde);
                }
                Some(map)
            }
            None => None
        };
        let set_json = json!({
            "adresses": &fiche_publique.adresses,
            "applications": apps,
            "chiffrage": &fiche_publique.chiffrage,
            "ca": &fiche_publique.ca,
        });
        let set_bson = convertir_to_bson(set_json)?;
        let ops = doc! {
            "$set": set_bson,
            "$setOnInsert": {
                "idmg": &idmg_tiers,
                CHAMP_CREATION: Utc::now(),
            },
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        let options = UpdateOptions::builder()
            .upsert(true)
            .build();
        let resultat_update = collection.update_one(filtre, ops, Some(options)).await?;
        if resultat_update.modified_count != 1 && resultat_update.upserted_id.is_none() {
            error!("resoudre_url Erreur, fiche publique idmg {} n'a pas ete sauvegardee", idmg_tiers);
        }
    }

    // Sauvegarder adresses
    {
        let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;
        debug!("Verification headers : {:?}", reponse_fiche.headers);
        let etag = match reponse_fiche.headers.as_ref() {
            Some(e) => e.get("ETag").cloned(),
            None => None
        };
        if let Some(adresses) = fiche_publique.adresses.as_ref() {
            for adresse in adresses {
                let filtre = doc! { "adresse": adresse };
                let ops = doc! {
                    "$set": {
                        "idmg": &idmg_tiers,
                        "etag": &etag,
                    },
                    "$setOnInsert": {
                        "adresse": adresse,
                        CHAMP_CREATION: Utc::now(),
                    },
                    "$currentDate": {CHAMP_MODIFICATION: true},
                };
                let options = UpdateOptions::builder().upsert(true).build();
                let resultat_update = collection.update_one(filtre, ops, Some(options)).await?;
                if resultat_update.modified_count != 1 && resultat_update.upserted_id.is_none() {
                    error!("resoudre_url Erreur, adresse {} pour idmg {} n'a pas ete sauvegardee", adresse, idmg_tiers);
                }
            }
        }
    }

    Ok(Some(idmg_tiers))
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
                                    -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + Chiffreur<CipherMgs3, Mgs3CipherKeys> + GenerateurMessages + MongoDao
{
    debug!("produire_fiche_publique");
    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;

    let filtre = doc! {};
    let mut curseur = collection.find(filtre, None).await?;

    let chiffrage = {
        let mut chiffrage = Vec::new();
        let public_keys = middleware.get_publickeys_chiffrage();
        for key in public_keys {
            let fingerprint = &key.fingerprint;
            if let Some(certificat) = middleware.get_certificat(fingerprint).await {
                let pem_vec: Vec<String> = certificat.get_pem_vec().into_iter().map(|c| c.pem).collect::<Vec<String>>();
                chiffrage.push(pem_vec);
            }
        }
        chiffrage
    };

    let mut adresses = Vec::new();
    let mut applications: HashMap<String, Vec<ApplicationPublique>> = HashMap::new();

    while let Some(inst) = curseur.next().await {
        let doc_instance = inst?;
        let info_instance: InformationMonitor = convertir_bson_deserializable(doc_instance)?;
        debug!("Information instance : {:?}", info_instance);
        if let Some(d) = &info_instance.domaine {
            adresses.push(d.to_owned());
        }
        if let Some(o) = &info_instance.onion {
            adresses.push(o.to_owned());
        }

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
                match &app.securite {
                    Some(s) => {
                        if s.as_str() != SECURITE_1_PUBLIC && s.as_str() != SECURITE_2_PRIVE {
                            continue;  // Pas public ou prive, on skip l'application
                        }
                    }
                    None => continue  // On assume securite protege ou secure, skip
                }

                let mut app_publique: ApplicationPublique = app.clone().try_into()?;
                let nom_app = app_publique.application.as_str();
                if let Some(v) = app_versions.get(nom_app) {
                    app_publique.version = v.version.to_owned();
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

            }
        }
    }

    let fiche = FichePublique {
        adresses: Some(adresses),
        applications,
        chiffrage,
        ca: middleware.ca_pem().into(),
        idmg: middleware.idmg().into(),
    };

    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM, EVENEMENT_FICHE_PUBLIQUE)
        .exchanges(vec![Securite::L1Public])
        .ajouter_ca(true)
        .build();
    middleware.emettre_evenement(routage, &fiche).await?;

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FichePublique {
    adresses: Option<Vec<String>>,
    applications: HashMap<String, Vec<ApplicationPublique>>,
    chiffrage: Vec<Vec<String>>,
    ca: String,
    idmg: String,
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
                                        -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("produire_information_locale");
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let idmg_local = enveloppe_privee.idmg()?;

    let adresses = {
        let mut adresses = Vec::new();

        let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
        let filtre = doc! {};
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(inst) = curseur.next().await {
            let doc_instance = inst?;
            let info_instance: InformationMonitor = convertir_bson_deserializable(doc_instance)?;
            debug!("Information instance : {:?}", info_instance);
            if let Some(d) = &info_instance.domaine {
                adresses.push(d.to_owned());
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

async fn requete_fiche_millegrille<M>(middleware: &M, message: MessageValideAction)
                                      -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("requete_fiche_millegrille");
    let requete: RequeteFicheMillegrille = message.message.parsed.map_contenu(None)?;
    debug!("requete_fiche_millegrille Parsed : {:?}", requete);

    let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
    let filtre = doc! {
        TRANSACTION_CHAMP_IDMG: &requete.idmg,
    };

    let reponse = match collection.find_one(filtre, None).await? {
        Some(doc_fiche) => {
            let fiche: FichePublique = convertir_bson_deserializable(doc_fiche)?;
            middleware.formatter_reponse(fiche, None)
        }
        None => {
            middleware.formatter_reponse(json!({"ok": false, "code": 404, "err": "Non trouve"}), None)
        }
    }?;

    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteFicheMillegrille {
    idmg: String,
}

async fn requete_applications_tiers<M>(middleware: &M, message: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("requete_applications_tiers");
    let requete: RequeteApplicationsTiers = message.message.parsed.map_contenu(None)?;
    debug!("requete_applications_tiers Parsed : {:?}", requete);

    let projection = doc! {
        "idmg": 1,
        "adresses": 1,
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
    let reponse = middleware.formatter_reponse(&json!({"fiches": fiches}), None)?;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteApplicationsTiers {
    idmgs: Vec<String>,
    application: String,
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
