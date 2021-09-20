use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::restaurer;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::formatteur_messages::MessageSerialise;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::sauvegarder_transaction;
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
use serde::Deserialize;

use crate::validateur_pki_mongo::MiddlewareDbPki;

// Constantes
pub const DOMAINE_NOM: &str = "CoreCatalogues";
pub const NOM_COLLECTION_CATALOGUES: &str = "CoreCatalogues/catalogues";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

const NOM_Q_TRANSACTIONS: &str = "CoreCatalogues/transactions";
const NOM_Q_VOLATILS: &str = "CoreCatalogues/volatils";
const NOM_Q_TRIGGERS: &str = "CoreCatalogues/triggers";

const REQUETE_INFO_APPLICATION: &str = "infoApplication";
const REQUETE_LISTE_APPLICATIONS: &str = "listeApplications";
const TRANSACTION_APPLICATION: &str = "catalogueApplication";

const INDEX_NOMS_CATALOGUES: &str = "noms_catalogues";
const CHAMP_NOM_CATALOGUE: &str = "nom";
const CHAMP_VERSION: &str = "version";


/// Initialise le domaine.
pub async fn preparer_threads(middleware: Arc<MiddlewareDbPki>)
    -> Result<(HashMap<String, Sender<TypeMessage>>, FuturesUnordered<JoinHandle<()>>), Box<dyn Error>>
{
    // Preparer les index MongoDB
    preparer_index_mongodb(middleware.as_ref()).await?;

    // Channels pour traiter messages Pki
    let (tx_messages, rx_messages) = mpsc::channel::<TypeMessage>(20);
    let (tx_triggers, rx_triggers) = mpsc::channel::<TypeMessage>(5);

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

    Ok((routing, futures))
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 3.protege seulement
    let requetes = vec![REQUETE_INFO_APPLICATION, REQUETE_LISTE_APPLICATIONS];
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
        }
    ));

    let mut rk_transactions = Vec::new();
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_APPLICATION).into(),
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

    // Index catalogues
    let options_unique_catalogues = IndexOptions {
        nom_index: Some(String::from(INDEX_NOMS_CATALOGUES)),
        unique: true
    };
    let champs_index_catalogues = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_NOM_CATALOGUE), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_CATALOGUES,
        champs_index_catalogues,
        Some(options_unique_catalogues)
    ).await?;

    Ok(())
}

async fn consommer_messages(middleware: Arc<MiddlewareDbPki>, mut rx: Receiver<TypeMessage>) {
    while let Some(message) = rx.recv().await {
        debug!("Message {} recu : {:?}", DOMAINE_NOM, message);

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

async fn entretien(middleware: Arc<MiddlewareDbPki>) {

    let mut catalogues_charges = false;

    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);

        if ! catalogues_charges {
            debug!("Charger catalogues");

            let commande = json!({});
            match middleware.transmettre_commande(
                "servicemonitor",
                "transmettreCatalogues",
                None,
                &commande,
                None,
                true
            ).await {
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
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_LISTE_APPLICATIONS => liste_applications(middleware).await,
                REQUETE_INFO_APPLICATION => repondre_application(middleware, message.message.get_msg()).await,
                _ => {
                    error!("Message action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete domaine inconnu : '{}'. Message dropped.", message.domaine);
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
        TRANSACTION_APPLICATION => traiter_commande_application(middleware.as_ref(), m).await,
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

async fn restaurer_transactions(middleware: Arc<MiddlewareDbPki>) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> {
    let noms_collections_docs = vec! [
        String::from(NOM_COLLECTION_CATALOGUES)
    ];

    let processor = ProcesseurTransactions::new();

    restaurer(
        middleware.clone(),
        DOMAINE_NOM,
        NOM_COLLECTION_TRANSACTIONS,
        &noms_collections_docs,
        &processor
    ).await?;

    Ok(None)
}

async fn consommer_transaction<M>(_middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
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
    //     PKI_TRANSACTION_NOUVEAU_CERTIFICAT => {
    //         sauvegarder_transaction(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
    //         Ok(None)
    //     },
        _ => Err(format!("Mauvais type d'action pour une transaction : {}", m.action))?,
    }

    Ok(None)
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
        }
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", m.action))?,
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
    async fn traiter_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

async fn aiguillage_transaction<M>(middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
where M: ValidateurX509 + GenerateurMessages + MongoDao {
    match transaction.get_action() {
        TRANSACTION_APPLICATION => maj_catalogue(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
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

async fn traiter_cedule<M>(_middleware: &M, _trigger: MessageValideAction) -> Result<(), Box<dyn Error>>
where M: ValidateurX509 {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
}

async fn traiter_commande_application<M>(middleware: &M, commande: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where M: ValidateurX509 + MongoDao + GenerateurMessages
{
    // let message = commande.message.get_msg();

    let value_catalogue: MessageMilleGrille = match commande.message.parsed.contenu.get("catalogue") {
        Some(v) => serde_json::from_value(v.to_owned())?,
        None => Err(format!("Commande application sans champ catalogue"))?
    };
    let mut catalogue = MessageSerialise::from_parsed(value_catalogue)?;

    let info_catalogue: CatalogueApplication = serde_json::from_value(Value::Object(catalogue.get_msg().contenu.to_owned()))?;
    debug!("Information catalogue charge : {:?}", info_catalogue);

    let collection_catalogues = middleware.get_collection(NOM_COLLECTION_CATALOGUES)?;
    let filtre = doc! {CHAMP_NOM_CATALOGUE: info_catalogue.nom.as_str()};
    let doc_catalogue = collection_catalogues.find_one(filtre, None).await?;
    let version = match &doc_catalogue {
        Some(d) => {
            let version = d.get_str(CHAMP_VERSION)?;
            // Verifier si la version recue est plus grande que celle sauvegardee
            debug!("Version recue : {}, dans DB : {}", info_catalogue.version, version);

            // Si version moins grande, on skip
            if version == info_catalogue.version {
                debug!("Meme version de catalogue, on skip");
                return Ok(None)
            }

            Some(version)
        },
        None => None,
    };

    debug!("Verifier si catalogue present pour version {:?}", version);

    // Valider le catalogue
    let opts = ValidationOptions::new(true, true, true);
    let resultat_validation = catalogue.valider(middleware, Some(&opts)).await?;
    debug!("Resultat validation catalogue : {:?}", resultat_validation);

    if resultat_validation.valide() {
        // Conserver la transaction et la traiter immediatement
        let mva = MessageValideAction::new(
            catalogue,
            commande.q,
            commande.routing_key,
            DOMAINE_NOM.into(),
            TRANSACTION_APPLICATION.into(),
            TypeMessageOut::Transaction
        );
        sauvegarder_transaction(middleware, mva, NOM_COLLECTION_TRANSACTIONS).await?;
    }

    Ok(None)
}

#[derive(Clone, Debug, Deserialize)]
struct CatalogueApplication {
    nom: String,
    version: String,
}

async fn maj_catalogue<M>(middleware: &M, transaction: impl Transaction)
    -> Result<Option<MessageMilleGrille>, String>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Sauvegarder application recu via catalogue (transaction)");

    let contenu = transaction.contenu();
    let nom = match contenu.get_str("nom") {
        Ok(c) => Ok(c.to_owned()),
        Err(e) => Err(format!("Champ nom manquant de transaction application : {:?}", e)),
    }?;

    // Filtrer le contenu (retirer champs _)
    let mut set_ops = Document::new();
    let iter: millegrilles_common_rust::bson::document::IntoIter = contenu.into_iter();
    for (k, v) in iter {
        if ! k.starts_with("_") && k != TRANSACTION_CHAMP_ENTETE {
            set_ops.insert(k, v);
        }
    }

    debug!("set-ops : {:?}", set_ops);
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let filtre = doc! {
        "nom": nom,
    };

    let collection_catalogues = middleware.get_collection(NOM_COLLECTION_CATALOGUES)?;
    let opts = UpdateOptions::builder().upsert(true).build();
    let resultat = match collection_catalogues.update_one(filtre, ops, Some(opts)).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur maj document catalogue avec mongo : {:?}", e))?
    };

    debug!("Resultat maj document : {:?}", resultat);

    Ok(None)
}

async fn liste_applications<M>(middleware: &M)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let filtre = doc! {};
    let projection = doc!{
        "nom": true,
        "version": true,
        "images": true,
        "registries": true,
    };

    let collection = middleware.get_collection(NOM_COLLECTION_CATALOGUES)?;
    let ops = FindOptions::builder()
        .projection(Some(projection))
        .build();
    let mut curseur = match collection.find(filtre, Some(ops)).await {
        Ok(c) => c,
        Err(e) => Err(format!("Erreur chargement applications : {:?}", e))?
    };

    let mut apps = Vec::new();
    while let Some(d) = curseur.next().await {
        match d {
            Ok(mut doc) => {
                filtrer_doc_id(&mut doc);

                match convertir_bson_value(doc) {
                    Ok(v) => apps.push(v),
                    Err(e) => warn!("Erreur conversion doc vers json : {:?}", e)
                }

            },
            Err(e) => warn!("Erreur chargement document : {:?}", e)
        }
    }

    debug!("Apps : {:?}", apps);
    let liste = json!({
        "resultats": apps,
    });

    let reponse = match middleware.formatter_reponse(&liste,None) {
        Ok(m) => m,
        Err(e) => Err(format!("Erreur preparation reponse applications : {:?}", e))?
    };
    Ok(Some(reponse))
}

async fn repondre_application<M>(middleware: &M, param: &MessageMilleGrille)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let nom_application: String = param.map_contenu(Some("nom"))?;

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

    match middleware.formatter_reponse(&val,None) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse applications : {:?}", e))?
    }
}

#[cfg(test)]
mod test_integration {
    use super::*;

    use crate::test_setup::setup;
    use crate::validateur_pki_mongo::preparer_middleware_pki;

// use millegrilles_common_rust::middleware::preparer_middleware_pki;

    #[tokio::test]
    async fn test_liste_applications() {
        setup("test_liste_applications");
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(spawn(async move {

            debug!("Duree test_liste_applications");
            let reponse = liste_applications(middleware.as_ref()).await.expect("reponse");
            debug!("Reponse test_liste_applications : {:?}", reponse);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

    #[tokio::test]
    async fn test_application() {
        setup("test_application");
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(spawn(async move {

            debug!("Duree test_application");
            let param = middleware.formatter_reponse(json!({"nom": "blynk"}), None).expect("param");
            let reponse = repondre_application(middleware.as_ref(), &param).await.expect("reponse");
            debug!("Reponse test_application : {:?}", reponse);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }
}