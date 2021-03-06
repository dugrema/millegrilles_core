use std::collections::HashMap;
use std::convert::TryFrom;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::{reset_backup_flag, restaurer};
use millegrilles_common_rust::backup::backup;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{charger_enveloppe, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::middleware::{emettre_presence_domaine, formatter_message_certificat, Middleware, sauvegarder_transaction_recue, thread_emettre_presence_domaine, upsert_certificat};
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::serde_json as serde_json;
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, TraiterTransaction, Transaction, TransactionImpl, TriggerTransaction};

use crate::validateur_pki_mongo::MiddlewareDbPki;

// Constantes
pub const DOMAINE_NOM: &str = "CorePki";
pub const DOMAINE_LEGACY_NOM: &str = "Pki";
pub const COLLECTION_CERTIFICAT_NOM: &str = "CorePki/certificat";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

const NOM_Q_TRANSACTIONS: &str = "CorePki/transactions";
const NOM_Q_VOLATILS: &str = "CorePki/volatils";
const NOM_Q_TRIGGERS: &str = "CorePki/triggers";

const DOMAINE_CERTIFICAT_NOM: &str = "certificat";
const PKI_REQUETE_CERTIFICAT: &str = "infoCertificat";
const PKI_REQUETE_CERTIFICAT_PAR_PK: &str = "certificatParPk";
const PKI_COMMANDE_SAUVEGARDER_CERTIFICAT: &str = "certificat";
const PKI_COMMANDE_NOUVEAU_CERTIFICAT: &str = "nouveauCertificat";
const PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
const NOM_Q_TRANSACTIONS_PKI: &str = "CorePki/transactions";
const NOM_Q_TRANSACTIONS_VOLATILS: &str = "CorePki/volatils";
const NOM_Q_TRIGGERS_PKI: &str = "CorePki/triggers";
const NOM_DOMAINE_CERTIFICATS: &str = "certificat";

/// Instance statique du gestionnaire de maitredescomptes
pub const GESTIONNAIRE_PKI: GestionnaireDomainePki = GestionnaireDomainePki {};

#[derive(Clone)]
pub struct GestionnaireDomainePki {}

#[async_trait]
impl TraiterTransaction for GestionnaireDomainePki {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireDomainePki {
    #[inline]
    fn get_nom_domaine(&self) -> String {DOMAINE_NOM.into()}
    #[inline]
    fn get_collection_transactions(&self) -> String {NOM_COLLECTION_TRANSACTIONS.into()}

    fn get_collections_documents(&self) -> Vec<String> {
        vec![
            String::from(COLLECTION_CERTIFICAT_NOM),
        ]
    }

    #[inline]
    fn get_q_transactions(&self) -> String {NOM_Q_TRANSACTIONS.into()}
    #[inline]
    fn get_q_volatils(&self) -> String {NOM_Q_VOLATILS.into()}
    #[inline]
    fn get_q_triggers(&self) -> String {NOM_Q_TRIGGERS.into()}

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
        consommer_commande(middleware, message).await  // Fonction plus bas
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

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: MessageValideAction) -> Result<(), Box<dyn Error>> where M: Middleware + 'static {
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
    queues.push(QueueType::Triggers (DOMAINE_NOM.into()));

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
        COLLECTION_CERTIFICAT_NOM,
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
        COLLECTION_CERTIFICAT_NOM,
        champs_index_fingerprint_pk,
        Some(options_unique_fingerprint_pk)
    ).await?;

    Ok(())
}

async fn entretien<M>(middleware: Arc<M>)
    where M: Middleware + 'static
{
    let mut catalogues_charges = false;

    // Attente initiale
    tokio::time::sleep(tokio::time::Duration::new(15, 0)).await;
    loop {
        debug!("Cycle entretien {}", DOMAINE_NOM);
        tokio::time::sleep(tokio::time::Duration::new(120, 0)).await;
    }
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &message.message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.

    match message.domaine.as_str() {
        DOMAINE_LEGACY_NOM | DOMAINE_NOM => match message.action.as_str() {
            PKI_REQUETE_CERTIFICAT => requete_certificat(middleware, message).await,
            PKI_REQUETE_CERTIFICAT_PAR_PK => requete_certificat_par_pk(middleware, message).await,
            _ => {
                error!("Message requete action inconnue : {}. Message dropped.", message.action);
                Ok(None)
            },
        },
        DOMAINE_CERTIFICAT_NOM => requete_certificat(middleware, message).await,
        _ => {
            error!("Message requete domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: Middleware + 'static
{
    debug!("Consommer commande : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        // Commandes standard
        // COMMANDE_BACKUP_HORAIRE => backup(middleware.as_ref(), DOMAINE_NOM, NOM_COLLECTION_TRANSACTIONS, true).await,
        // COMMANDE_RESTAURER_TRANSACTIONS => restaurer_transactions(middleware.clone()).await,
        // COMMANDE_RESET_BACKUP => reset_backup_flag(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS).await,

        // Commandes specifiques au domaine
        PKI_COMMANDE_SAUVEGARDER_CERTIFICAT | PKI_COMMANDE_NOUVEAU_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware, m).await,

        // Commandes inconnues
        _ => Err(format!("Commande Pki inconnue : {}, message dropped", m.action))?,
    }
}

async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer transaction core_pki : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        PKI_TRANSACTION_NOUVEAU_CERTIFICAT => {
            sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
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
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", m.action))?,
    }
}

async fn requete_certificat<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let fingerprint = match m.domaine.as_str() {
        DOMAINE_NOM => {
            match m.message.get_msg().contenu.get(PKI_DOCUMENT_CHAMP_FINGERPRINT) {
                Some(fp) => match fp.as_str() {
                    Some(fp) => Ok(fp),
                    None =>Err("Fingerprint manquant pour requete de certificat"),
                },
                None => Err("Fingerprint manquant pour requete de certificat"),
            }
        },
        DOMAINE_CERTIFICAT_NOM => Ok(m.action.as_str()),
        _ => Err("Mauvais type de requete de certificat")
    }?;

    let enveloppe = match middleware.get_certificat(fingerprint).await {
        Some(inner) => inner,
        None => {
            debug!("Certificat inconnu : {}", fingerprint);
            return Ok(None);
        }
    };

    debug!("Requete certificat sur fingerprint {} trouve", fingerprint);

    let reponse_value = formatter_message_certificat(enveloppe.as_ref());

    // C'est une requete sur le domaine certificat, on emet l'evenement.infocertificat.fingerprint
    let mut builder_routage = RoutageMessageAction::builder("certificat", "infoCertificat");
    if let Some(e) = m.exchange {
        let securite = Securite::try_from(e)?;
        builder_routage = builder_routage.exchanges(vec![securite]);
    }

    let routage = builder_routage.build();
    if let Err(e) = middleware.emettre_evenement(routage, &reponse_value).await {
        warn!("Erreur emission evenement infocertificat pour {} : {}", fingerprint, e);
    }

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
    let collection = db.collection::<Document>(COLLECTION_CERTIFICAT_NOM);
    let filtre = doc! {
        PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: fingerprint_pk,
    };
    let document_certificat = match collection.find_one(filtre, None).await {
        Ok(inner) => match inner {
            Some(inner) => Ok(inner),
            None => {
                debug!("Certificat par PK non trouve : {:?}", fingerprint_pk);
                let reponse_value = json!({"resultat": false});
                let reponse = middleware.formatter_reponse(reponse_value, None)?;
                return Ok(Some(reponse));
            },
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
    debug!("requete_certificat_par_pk reponse pour fingerprint_pk {}\n{:?}", fingerprint_pk, reponse);
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
        PKI_TRANSACTION_NOUVEAU_CERTIFICAT => sauvegarder_certificat(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn sauvegarder_certificat<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: Transaction
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
    let collection_doc_pki = middleware.get_collection(COLLECTION_CERTIFICAT_NOM)?;
    upsert_certificat(&enveloppe, collection_doc_pki, Some(false)).await?;

    Ok(None)
}

async fn traiter_cedule<M>(_middleware: &M, _trigger: MessageValideAction) -> Result<(), Box<dyn Error>>
where M: ValidateurX509 {
    //let message = trigger.message;

    debug!("traiter_cedule corepki");

    Ok(())
}

#[cfg(test)]
mod test_integration {
    use millegrilles_common_rust::chrono::Utc;
    // use millegrilles_common_rust::certificats::certificats_tests::{CERT_DOMAINES, CERT_FICHIERS, charger_enveloppe_privee_env, prep_enveloppe};
    // use millegrilles_common_rust::middleware::preparer_middleware_pki;
    // use millegrilles_common_rust::regenerer;
    use millegrilles_common_rust::tokio_stream::StreamExt;
    use millegrilles_common_rust::transactions::regenerer;

    use crate::test_setup::setup;
    use crate::validateur_pki_mongo::preparer_middleware_pki;

    use super::*;

    #[tokio::test]
    async fn regenerer_transactions_integration() {
        setup("regenerer_transactions_integration");
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(spawn(async move {

            let debut_traitement = Utc::now();
            debug!("Debut regeneration : {:?}", debut_traitement);
            let mut colls = Vec::new();
            colls.push(String::from(COLLECTION_CERTIFICAT_NOM));
            todo!("Fix me")
            // let processor = TraiterTransactionPki{};
            // regenerer(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS, &colls, &processor)
            //     .await.expect("regenerer");
            //
            // let fin_traitemeent = Utc::now();
            // let duree = fin_traitemeent - debut_traitement;
            // debug!("Duree regeneration : {:?}", duree);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }
}