use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::convert::TryInto;

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::{restaurer, CatalogueHoraire, CommandeDeclencherBackupQuotidien};
use millegrilles_common_rust::bson::{Bson, doc};
use millegrilles_common_rust::bson::Array;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::{Chiffreur, Dechiffreur};
use millegrilles_common_rust::chrono::{Utc, Timelike};
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{FormatteurMessage, MessageMilleGrille, Entete, DateEpochSeconds};
use millegrilles_common_rust::formatteur_messages::MessageSerialise;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageReponse, RoutageMessageAction};
use millegrilles_common_rust::middleware::{IsConfigurationPki, Middleware, sauvegarder_transaction_recue, thread_emettre_presence_domaine, sauvegarder_transaction};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_value, filtrer_doc_id, IndexOptions, MongoDao, convertir_bson_deserializable, convertir_to_bson};
use millegrilles_common_rust::mongodb as mongodb;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, Hint};
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
pub const DOMAINE_NOM: &str = BACKUP_NOM_DOMAINE;
pub const NOM_COLLECTION_CATALOGUES_HORAIRES: &str = "CoreBackup/cataloguesHoraires";
pub const NOM_COLLECTION_CATALOGUES_QUOTIDIENS: &str = "CoreBackup/cataloguesQuotidiens";
pub const NOM_COLLECTION_RAPPORTS: &str = "CoreBackup/rapports";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

const NOM_Q_TRANSACTIONS: &str = "CoreBackup/transactions";
const NOM_Q_VOLATILS: &str = "CoreBackup/volatils";
const NOM_Q_TRIGGERS: &str = "CoreBackup/triggers";

const REQUETE_DERNIER_HORAIRE: &str = BACKUP_REQUETE_DERNIER_HORAIRE;

const COMMANDE_DECLENCHER_BACKUP_QUOTIDIEN: &str = COMMANDE_BACKUP_QUOTIDIEN;

const TRANSACTION_CATALOGUE_HORAIRE: &str = BACKUP_TRANSACTION_CATALOGUE_HORAIRE;
const TRANSACTION_CATALOGUE_QUOTIDIEN: &str = BACKUP_TRANSACTION_CATALOGUE_QUOTIDIEN;
const TRANSACTION_CATALOGUE_QUOTIDIEN_INFO: &str = "archiveQuotidienneInfo";

const CHAMP_DOMAINE: &str = "domaine";
const CHAMP_PARTITION: &str = "partition";
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
impl TraiterTransaction for GestionnaireDomaineCoreBackup {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireDomaineCoreBackup {
    #[inline]
    fn get_nom_domaine(&self) -> &str {DOMAINE_NOM}
    #[inline]
    fn get_collection_transactions(&self) -> &str {NOM_COLLECTION_TRANSACTIONS}

    fn get_collections_documents(&self) -> Vec<String> {
        vec![
            String::from(NOM_COLLECTION_CATALOGUES_HORAIRES),
            String::from(NOM_COLLECTION_CATALOGUES_QUOTIDIENS),
            String::from(NOM_COLLECTION_RAPPORTS),
        ]
    }

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
        COMMANDE_DECLENCHER_BACKUP_QUOTIDIEN,
    ];
    for commande in commandes {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L4Secure});
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
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_CATALOGUE_HORAIRE).into(),
        exchange: Securite::L3Protege
    });
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_CATALOGUE_QUOTIDIEN).into(),
        exchange: Securite::L3Protege
    });
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_CATALOGUE_QUOTIDIEN_INFO).into(),
        exchange: Securite::L3Protege
    });

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
        ChampIndex {nom_champ: String::from(CHAMP_PARTITION), direction: 1},
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
        ChampIndex {nom_champ: String::from(CHAMP_PARTITION), direction: 1},
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
            let reponse = GESTIONNAIRE_BACKUP.traiter_transaction(middleware, message).await?;
            Ok(reponse)
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
    where M: GenerateurMessages + MongoDao
{
    debug!("consommer_commande : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_3_PROTEGE), String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("core_backup.consommer_commande: Commande autorisation invalide (pas 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        // Commandes standard
        COMMANDE_DECLENCHER_BACKUP_QUOTIDIEN => commande_declencher_backup_quotidien(middleware, m).await,
        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("core_backup.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        TRANSACTION_CATALOGUE_HORAIRE |
        TRANSACTION_CATALOGUE_QUOTIDIEN |
        TRANSACTION_CATALOGUE_QUOTIDIEN_INFO => {
            sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
            Ok(None)
        },
        _ => Err(format!("core_backup.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        TRANSACTION_CATALOGUE_HORAIRE => transaction_catalogue_horaire(middleware, transaction).await,
        TRANSACTION_CATALOGUE_QUOTIDIEN => transaction_catalogue_quotidien(middleware, transaction).await,
        TRANSACTION_CATALOGUE_QUOTIDIEN_INFO => transaction_catalogue_quotidien_info(middleware, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn requete_dernier_horaire<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &m.message);
    let requete: RequeteDernierCatalogueHoraire = m.message.get_msg().map_contenu(None)?;

    let mut filtre = doc! {
        "domaine": requete.domaine,
    };
    if let Some(partition) = requete.partition {
        filtre.insert("partition", partition);
    }
    debug!("requete_dernier_horaire Charger dernier backup pour : {:?}", filtre);

    let opts = FindOneOptions::builder()
        .hint(Some(Hint::Name(INDEX_CATALOGUES_HORAIRE.into())))
        .sort(Some(doc!{CHAMP_DOMAINE: 1, CHAMP_PARTITION: 1, CHAMP_HEURE: -1}))
        .build();

    let collection = middleware.get_collection(NOM_COLLECTION_CATALOGUES_HORAIRES)?;
    let val_reponse = match collection.find_one(filtre, Some(opts)).await? {
        Some(d) => {
            let doc_horaire: DocCatalogueHoraire = convertir_bson_deserializable(d)?;
            json!({
                "ok": true,
                "dernier_backup": {
                    "en-tete": doc_horaire.entete,
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
        Err(e) => Err(format!("core_backup.requete_dernier_horaire: Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteDernierCatalogueHoraire {
    domaine: String,
    partition: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocCatalogueHoraire {
    #[serde(rename = "en-tete")]
    entete: Entete,
    heure: DateEpochSeconds,
}

async fn transaction_catalogue_horaire<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_catalogue_horaire Consommer transaction : {:?}", &transaction);
    let catalogue_horaire: CatalogueHoraire = match convertir_bson_deserializable(transaction.contenu()) {
        Ok(c) => c,
        Err(e) => Err(format!("core_backup.transaction_catalogue_horaire: transaction_catalogue_horaire Erreur conversion bson : {:?}", e))?
    };

    let entete = match catalogue_horaire.entete {
        Some(e) => e,
        None => Err(format!("core_backup.transaction_catalogue_horaire: transaction_catalogue_horaire Entete manquante du catalogue"))?
    };
    let entete_bson: Document = entete.clone().try_into()?;
    let jour = catalogue_horaire.heure.get_jour();
    let jour_bson: Bson = jour.clone().into();
    let heure = catalogue_horaire.heure.clone();
    let heure_bson: Bson = catalogue_horaire.heure.into();

    // Mettre a jour la collection de catalogues horaires
    let ops_horaire = doc! {
        "$set": {
            "en-tete": entete_bson,
        },
        "$setOnInsert": {
            CHAMP_CREATION: Utc::now(),
            "domaine": &catalogue_horaire.domaine,
            "heure": &heure_bson,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let mut filtre_horaire = doc! {
        "domaine": &catalogue_horaire.domaine,
        "heure": &heure_bson,
    };
    let opts_horaire: FindOneAndUpdateOptions = FindOneAndUpdateOptions::builder().upsert(true).build();
    let collection_horaire = match middleware.get_collection(NOM_COLLECTION_CATALOGUES_HORAIRES) {
        Ok(c) => c,
        Err(e) => Err(format!("core_backup.transaction_catalogue_horaire: transaction_catalogue_horaire Erreur get_collection catalogues horaires :{:?}", e))?
    };
    let resultat_horaire = match collection_horaire.find_one_and_update(filtre_horaire, ops_horaire, opts_horaire).await {
        Ok(r) => r,
        Err(e) => Err(format!("core_backup.transaction_catalogue_horaire: transaction_catalogue_horaire Erreur find_one_and_update horaire : {:?}", e))?
    };
    debug!("transaction_catalogue_horaire Resultat update horaire : {:?}", resultat_horaire);

    // Ajouter l'information dans le document de catalogue quotidien
    let heure_int = heure.get_datetime().hour();
    let ops_quotidien = doc! {
        "$set": {
            "dirty_flag": true,
            format!("fichiers_horaire.{:02}", heure_int): {
                "catalogue_nomfichier": &catalogue_horaire.catalogue_nomfichier,
                "transactions_nomfichier": &catalogue_horaire.transactions_nomfichier,
                "uuid_transaction": &entete.uuid_transaction,
            }
        },
        "$setOnInsert": {
            CHAMP_CREATION: Utc::now(),
            "domaine": &catalogue_horaire.domaine,
            "jour": &jour_bson,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let mut filtre_quotidien = doc! {
        "domaine": &catalogue_horaire.domaine,
        "jour": &jour_bson,
    };
    let opts_quotidien: FindOneAndUpdateOptions = FindOneAndUpdateOptions::builder().upsert(true).build();
    let collection_quotidienne = middleware.get_collection(NOM_COLLECTION_CATALOGUES_QUOTIDIENS)?;
    let resultat_quotidien = match collection_quotidienne.find_one_and_update(
        filtre_quotidien, ops_quotidien, Some(opts_quotidien)).await {
        Ok(r) => r,
        Err(e) => Err(format!("core_backup.transaction_catalogue_horaire: transaction_catalogue_horaire Erreur maj quotidien {:?}", e))?
    };
    debug!("Resultat update quotidien : {:?}", resultat_quotidien);

    middleware.reponse_ok()
}

/// Sauvegarde un catalogue quotidien, set dirty_flag a false.
async fn transaction_catalogue_quotidien<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_catalogue_quotidien Consommer transaction : {:?}", &transaction);

    // Conserver le contenu complet du journal quotidien (override valeurs existantes)
    let mut doc_transaction = transaction.contenu();
    filtrer_doc_id(&mut doc_transaction);

    // Enlever les champs cles (vont etre mis dans setOnInsert)
    let domaine = doc_transaction.remove("domaine");
    let partition = doc_transaction.remove("partition");
    let jour = doc_transaction.remove("jour");

    // S'assurer de changer le dirty_flag a false
    doc_transaction.insert("dirty_flag", false);

    let filtre = doc! {
        "jour": jour.as_ref(),
        "domaine": domaine.as_ref(),
        "partition": partition.as_ref(),
    };

    let ops = doc! {
        "$set": doc_transaction,
        "$setOnInsert": {
            "jour": jour.as_ref(),
            "domaine": domaine.as_ref(),
            "partition": partition.as_ref(),
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_CATALOGUES_QUOTIDIENS)?;
    let opts: UpdateOptions = UpdateOptions::builder().upsert(true).build();
    let resultat = match collection.update_one(filtre, ops, Some(opts)).await {
        Ok(r) => r,
        Err(e) => Err(format!("core_backup.transaction_catalogue_quotidien: Erreur update document : {:?}", e))?
    };
    debug!("transaction_catalogue_quotidien resultat : {:?}", resultat);

    middleware.reponse_ok()
}

async fn commande_declencher_backup_quotidien<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: GenerateurMessages + MongoDao,
{
    debug ! ("commande_declencher_backup_quotidien Consommer commande : {:?}", & m.message);
    let commande: CommandeDeclencherBackupQuotidien = m.message.get_msg().map_contenu(None)?;

    let filtre = doc! {
        "domaine": &commande.domaine,
        "dirty_flag": true,
        "jour": {"$lte": &commande.jour}
    };
    debug!("commande_declencher_backup_quotidien Trouver catalogues quotidiens : {:?}", filtre);
    let collection = middleware.get_collection(NOM_COLLECTION_CATALOGUES_QUOTIDIENS)?;
    let mut curseur = collection.find(filtre, None).await?;
    while let Some(d) = curseur.next().await {
        debug!("catalogue trouve : {:?}", d);
        match d {
            Ok(mut doc_catalogue) => {
                filtrer_doc_id(&mut doc_catalogue);
                doc_catalogue.remove("dirty_flag");
                let catalogue_signe = middleware.formatter_message(
                    &doc_catalogue, BACKUP_NOM_DOMAINE.into(), TRANSACTION_CATALOGUE_QUOTIDIEN.into(), None, None)?;

                let commande_backup_domaine = json!({
                    "catalogue": catalogue_signe,
                    "uuid_rapport": &commande.uuid_rapport
                });
                debug!("Emettre commande backup quotidien pour {:?}", commande_backup_domaine);
                let routage = RoutageMessageAction::builder("backup", "genererBackupQuotidien")
                    .exchanges(vec!(Securite::L3Protege))
                    .build();
                middleware.transmettre_commande(routage, &commande_backup_domaine, false).await?;
            },
            Err(e) => Err(format!("core_backup.commande_declencher_backup_quotidien Erreur traitement curseur {:?}", e))?
        }
    }

    Ok(None)
}

async fn transaction_catalogue_quotidien_info<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_catalogue_quotidien_info Consommer transaction : {:?}", &transaction);

    // Conserver le contenu complet du journal quotidien (override valeurs existantes)
    let mut doc_transaction = transaction.contenu();
    filtrer_doc_id(&mut doc_transaction);

    // Enlever les champs cles (vont etre mis dans setOnInsert)
    let domaine = doc_transaction.remove("domaine");
    let partition = doc_transaction.remove("partition");
    let jour = doc_transaction.remove("jour");

    let filtre = doc! {
        "jour": jour.as_ref(),
        "domaine": domaine.as_ref(),
        "partition": partition.as_ref(),
    };

    let ops = doc! {
        "$set": doc_transaction,
        "$setOnInsert": {
            "dirty_flag": true,
            "jour": jour.as_ref(),
            "domaine": domaine.as_ref(),
            "partition": partition.as_ref(),
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = middleware.get_collection(NOM_COLLECTION_CATALOGUES_QUOTIDIENS)?;
    let opts: UpdateOptions = UpdateOptions::builder().upsert(true).build();
    let resultat = match collection.update_one(filtre, ops, Some(opts)).await {
        Ok(r) => r,
        Err(e) => Err(format!("core_backup.transaction_catalogue_quotidien: Erreur update document : {:?}", e))?
    };
    debug!("transaction_catalogue_quotidien_info resultat : {:?}", resultat);

    middleware.reponse_ok()
}

#[cfg(test)]
mod test_integration {
    use crate::test_setup::setup;
    use crate::validateur_pki_mongo::preparer_middleware_pki;
    use millegrilles_common_rust::tokio as tokio;

    use super::*;
    use millegrilles_common_rust::backup::CatalogueHoraire;
    use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
    use millegrilles_common_rust::mongo_dao::convertir_to_bson;

    #[tokio::test]
    async fn test_requete_dernier_horaire() {
        setup("test_requete_dernier_horaire");
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(spawn(async move {

            let message = {
                let contenu = json!({"domaine": "DUMMY"});
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
            // assert_eq!(resultat.contenu.get("dernier_backup").expect("dernier_backup").as_null().expect("null"), ());
            // assert_eq!(resultat.contenu.get("dernier_backup").expect("dernier_backup").as_object().expect("not null"), ());

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

    #[tokio::test]
    async fn test_generer_catalogue_horaire() {
        setup("test_generer_catalogue_horaire");
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(spawn(async move {

            let catalogue_horaire = CatalogueHoraire::builder(
                DateEpochSeconds::from_heure(2021, 09, 26, 08),
                "DUMMY".into(),
                "uuid-abcd-1234".into(),
                false,
                false
            ).build();
            let message = middleware.formatter_message(&catalogue_horaire, Some("Backup"), Some("catalogueHoraire"), None, None).expect("format");
            let mut doc_catalogue = convertir_to_bson(message).expect("bson");
            doc_catalogue.insert("_evenements", doc!{"_estampille": millegrilles_common_rust::bson::DateTime::now()});

            let transaction = TransactionImpl::new(doc_catalogue, None);

            let resultat = transaction_catalogue_horaire(middleware.as_ref(), transaction).await.expect("traitement");

            debug!("Resultat traitement nouveau catalogue backup : {:?}", resultat);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

}
