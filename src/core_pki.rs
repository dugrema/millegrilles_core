use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{charger_enveloppe, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::common_messages::DemandeSignature;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{ChiffrageFactoryTrait, emettre_presence_domaine, formatter_message_certificat, Middleware, sauvegarder_traiter_transaction, thread_emettre_presence_domaine, upsert_certificat};
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::{reqwest, reqwest::Url};
use millegrilles_common_rust::configuration::{ConfigMessages, IsConfigNoeud};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::serde_json as serde_json;
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, TraiterTransaction, Transaction, TransactionImpl, TriggerTransaction};
use millegrilles_common_rust::serde::{Deserialize, Serialize};

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
const PKI_COMMANDE_SIGNER_CSR: &str = "signerCsr";
const PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
const NOM_Q_TRANSACTIONS_PKI: &str = "CorePki/transactions";
const NOM_Q_TRANSACTIONS_VOLATILS: &str = "CorePki/volatils";
const NOM_Q_TRIGGERS_PKI: &str = "CorePki/triggers";
const NOM_DOMAINE_CERTIFICATS: &str = "certificat";
const EVENEMENT_CERTIFICAT_MAITREDESCLES: &str = "certMaitreDesCles";

/// Instance statique du gestionnaire de maitredescomptes
pub const GESTIONNAIRE_PKI: GestionnaireDomainePki = GestionnaireDomainePki {};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorePkiCertificat {
    pub fingerprint: String,
    pub certificat: Vec<String>,
    pub ca: Option<String>,
}

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
    fn get_collection_transactions(&self) -> Option<String> {Some(NOM_COLLECTION_TRANSACTIONS.into())}

    fn get_collections_documents(&self) -> Vec<String> {
        vec![
            String::from(COLLECTION_CERTIFICAT_NOM),
        ]
    }

    #[inline]
    fn get_q_transactions(&self) -> Option<String> {Some(NOM_Q_TRANSACTIONS.into())}
    #[inline]
    fn get_q_volatils(&self) -> Option<String> {Some(NOM_Q_VOLATILS.into())}
    #[inline]
    fn get_q_triggers(&self) -> Option<String> {Some(NOM_Q_TRIGGERS.into())}

    fn preparer_queues(&self) -> Vec<QueueType> { preparer_queues() }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao + ConfigMessages {
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
        consommer_transaction(self, middleware, message).await  // Fonction plus bas
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        consommer_evenement(middleware, message).await  // Fonction plus bas
    }

    async fn entretien<M>(self: &'static Self, middleware: Arc<M>)
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

    let niveaux_securite_public = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);
    let niveaux_securite_prive = vec!(Securite::L2Prive, Securite::L3Protege);

    // RK 1.public (inclus 2.prive et 3.protege)
    for niveau in niveaux_securite_public {
        // rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Pki.infoCertificat"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.CorePki.infoCertificat"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.certificat.*"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.CorePki.{}", PKI_COMMANDE_SIGNER_CSR), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", PKI_DOMAINE_CERTIFICAT_NOM, PKI_REQUETE_CERTIFICAT), exchange: niveau});
    }

    // Ajout evenement certificat pour 4.secure
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", PKI_DOMAINE_CERTIFICAT_NOM, PKI_REQUETE_CERTIFICAT), exchange: Securite::L4Secure});

    // RK 2.prive (inclus 3.protege)
    for niveau in niveaux_securite_prive {
        // rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Pki.certificatParPk"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.CorePki.certificatParPk"), exchange: niveau.clone()});
    }

    // RK 3.protege seulement
    // rk_volatils.push(ConfigRoutingExchange {routing_key: "commande.Pki.certificat".into(), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: "commande.CorePki.certificat".into(), exchange: Securite::L3Protege});
    // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.Pki.{}", PKI_COMMANDE_NOUVEAU_CERTIFICAT), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.CorePki.{}", PKI_COMMANDE_NOUVEAU_CERTIFICAT), exchange: Securite::L3Protege});

    // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS, EVENEMENT_BACKUP_DECLENCHER), exchange: Securite::L2Prive});

    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM_MAITREDESCLES, EVENEMENT_CERTIFICAT_MAITREDESCLES), exchange: Securite::L4Secure});

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: 300000.into(),
            durable: false,
            autodelete: false,
        }
    ));

    let mut rk_transactions = Vec::new();
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.CorePki.{}", PKI_TRANSACTION_NOUVEAU_CERTIFICAT).into(),
        exchange: Securite::L4Secure}
    );

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS_PKI.into(),
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
async fn preparer_index_mongodb_custom<M>(middleware: &M) -> Result<(), String>
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
        middleware,
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
        middleware,
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
    match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
        true => Ok(()),
        false => {
            match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                true => Ok(()),
                false => Err(format!("core_pki.consommer_commande Autorisation invalide (aucun exchange, pas delegation globale) : {}", m.routing_key))
            }
        },
    }?;

    match m.action.as_str() {
        // Commandes standard
        // COMMANDE_BACKUP_HORAIRE => backup(middleware.as_ref(), DOMAINE_NOM, NOM_COLLECTION_TRANSACTIONS, true).await,
        // COMMANDE_RESTAURER_TRANSACTIONS => restaurer_transactions(middleware.clone()).await,
        // COMMANDE_RESET_BACKUP => reset_backup_flag(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS).await,

        // Commandes specifiques au domaine
        PKI_COMMANDE_SAUVEGARDER_CERTIFICAT | PKI_COMMANDE_NOUVEAU_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware, m).await,
        PKI_COMMANDE_SIGNER_CSR => commande_signer_csr(middleware, m).await,

        // Commandes inconnues
        _ => Err(format!("Commande Pki inconnue : {}, message dropped", m.action))?,
    }
}

async fn consommer_transaction<M>(gestionnaire: &GestionnaireDomainePki, middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer transaction core_pki : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE))) {
        true => Ok(()),
        false => Err(format!("core_pki.consommer_transaction Autorisation invalide (pas 4.secure) : {}", m.routing_key)),
    }?;

    match m.action.as_str() {
        PKI_TRANSACTION_NOUVEAU_CERTIFICAT => {
            // sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        },
        _ => Err(format!("Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_evenement<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + ConfigMessages + ChiffrageFactoryTrait + ValidateurX509 + MongoDao
{
    debug!("Consommer evenement : {:?}", &m.message);

    // // Autorisation : doit etre de niveau 4.secure
    // match m.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE))) {
    //     true => Ok(()),
    //     false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    // }?;

    match m.action.as_str() {
        EVENEMENT_CERTIFICAT_MAITREDESCLES => evenement_certificat_maitredescles(middleware, m).await,
        PKI_REQUETE_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware, m).await,
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", m.action))?,
    }
}

#[derive(Clone, Deserialize)]
struct MessageFingerprint {
    fingerprint: String
}

async fn requete_certificat<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let fingerprint = match m.domaine.as_str() {
        DOMAINE_NOM => {
            let message_fingerprint: Result<String, String> = match m.message.parsed.map_contenu::<MessageFingerprint>() {
                Ok(inner) => Ok(inner.fingerprint),
                Err(e) => Err(format!("core_pki.requete_certificat Fingerprint manquant pour requete de certificat : {:?}", e)),
            };
            message_fingerprint

            // match m.message.get_msg().contenu.get(PKI_DOCUMENT_CHAMP_FINGERPRINT) {
            //     Some(fp) => match fp.as_str() {
            //         Some(fp) => Ok(fp),
            //         None =>Err("Fingerprint manquant pour requete de certificat"),
            //     },
            //     None => Err("Fingerprint manquant pour requete de certificat"),
            // }
        },
        DOMAINE_CERTIFICAT_NOM => {
            //Ok(m.message.parsed.routage.action.as_str())
            match m.message.parsed.routage.as_ref() {
                Some(inner) => match inner.action.as_ref() {
                    Some(inner) => Ok(inner.to_owned()),
                    None => Err(String::from("action manquante pour requete certificat (fingerprint)")),
                },
                None => Err(String::from("routage manquant pour requete certificat (fingerprint)")),
            }
        },
        _ => Err(String::from("Mauvais type de requete de certificat"))
    }?;

    let enveloppe = match middleware.get_certificat(fingerprint.as_str()).await {
        Some(inner) => inner,
        None => {
            debug!("Certificat inconnu : {}", fingerprint);
            let reponse = middleware.formatter_reponse(json!({"ok": false, "code": 2, "err": "Certificat inconnu"}), None)?;
            return Ok(Some(reponse));
        }
    };

    debug!("Requete certificat sur fingerprint {} trouve", fingerprint);

    let reponse_value = formatter_message_certificat(enveloppe.as_ref())?;

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
    // let fingerprint_pk = match m.message.get_msg().contenu.get(PKI_DOCUMENT_CHAMP_FINGERPRINT_PK) {
    let message_fingerprint: MessageFingerprint = match m.message.parsed.map_contenu() {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur fingerprint pk absent/erreur mapping {:?}", e))?,
    };
    let fingerprint_pk = message_fingerprint.fingerprint;

    let db = middleware.get_database()?;
    let collection = db.collection::<Document>(COLLECTION_CERTIFICAT_NOM);
    let filtre = doc! {
        PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: &fingerprint_pk,
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

    let enveloppe = middleware.charger_enveloppe(&chaine_pem, fingerprint, None).await?;

    // Certificat trouve, repondre
    debug!("requete_certificat_par_pk repondre fingerprint {:?} pour fingerprint_pk {}", fingerprint, fingerprint_pk);
    // repondre_enveloppe(middleware, &m, enveloppe.as_ref()).await?;
    let reponse_value = formatter_message_certificat(enveloppe.as_ref())?;
    let reponse = middleware.formatter_reponse(reponse_value, None)?;
    debug!("requete_certificat_par_pk reponse pour fingerprint_pk {}\n{:?}", fingerprint_pk, reponse);
    Ok(Some(reponse))
}

async fn traiter_commande_sauvegarder_certificat<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let commande: CommandeSauvegarderCertificat = m.message.get_msg().map_contenu()?;

    let ca_pem = match &commande.ca {
        Some(c) => Some(c.as_str()),
        None => None
    };
    let enveloppe = middleware.charger_enveloppe(&commande.chaine_pem, None, ca_pem).await?;
    debug!("Commande de sauvegarde de certificat {} traitee", enveloppe.fingerprint);

    if m.domaine.as_str() == PKI_DOMAINE_CERTIFICAT_NOM {
        // Sauvegarde de l'evenement de certificat - aucune reponse
        Ok(None)
    } else {
        let reponse = middleware.formatter_reponse(json!({"ok": true}), None)?;
        Ok(Some(reponse))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSauvegarderCertificat {
    chaine_pem: Vec<String>,
    ca: Option<String>
}

/// Commande de relai vers le certissuer pour signer un CSR. La commande doit etre
/// * signee par une delegation globale (e.g. proprietaire), ou
/// * signee par un monitor du meme niveau pour un role (e.g. monitor prive pour messagerie ou postmaster), ou
/// * etre un renouvellement pour les memes roles.
async fn commande_signer_csr<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + IsConfigNoeud
{
    let commande = match valider_demande_signature_csr(middleware, &m).await? {
        Some(c) => c,
        None => {
            return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Acces refuse"}), None)?))
        }
    };

    let config = middleware.get_configuration_noeud();
    let certissuer_url = match config.certissuer_url.as_ref() {
        Some(inner) => inner,
        None => Err(format!("core_maitredescomptes.signer_certificat_usager Certissuer URL manquant"))?
    };

    let client = reqwest::Client::builder()
        .timeout(core::time::Duration::new(7, 0))
        .build()?;

    let mut url_post = certissuer_url.clone();
    url_post.set_path("signerModule");

    // On retransmet le message recu tel quel
    match client.post(url_post).json(&commande).send().await {
        Ok(response) => {
            match response.status().is_success() {
                true => {
                    let reponse_json: ReponseCertificatSigne = response.json().await?;
                    debug!("commande_signer_csr Reponse certificat : {:?}", reponse_json);
                    return Ok(Some(middleware.formatter_reponse(reponse_json, None)?))
                },
                false => {
                    debug!("core_maitredescomptes.signer_certificat_usager Erreur reqwest : status {}", response.status());
                }
            }
        },
        Err(e) => {
            debug!("core_maitredescomptes.signer_certificat_usager Erreur reqwest : {:?}", e);
        }
    };

    // Une erreur est survenue dans le post, fallback vers noeuds 4.secure (si presents)
    debug!("Echec connexion a certissuer local, relai vers instances 4.secure");
    let routage = RoutageMessageAction::builder(DOMAINE_APPLICATION_INSTANCE, PKI_COMMANDE_SIGNER_CSR)
        .exchanges(vec![Securite::L4Secure])
        .build();

    match middleware.transmettre_commande(routage, &commande.contenu, true).await? {
        Some(reponse) => {
            if let TypeMessage::Valide(reponse) = reponse {
                let reponse_json: ReponseCertificatSigne = reponse.message.parsed.map_contenu()?;
                Ok(Some(middleware.formatter_reponse(reponse_json, None)?))
            } else {
                error!("core_pki.commande_signer_csr Erreur signature, echec local et relai 4.secure");
                Ok(Some(middleware.formatter_reponse(
                    json!({"ok": false, "err": "Erreur signature : aucun signateur disponible"}),
                    None
                )?))
            }
        },
        None => {
            error!("core_pki.commande_signer_csr Erreur signature, aucune reponse");
            Ok(Some(middleware.formatter_reponse(
                json!({"ok": false, "err": "Erreur signature : aucun signateur disponible"}),
                None
            )?))
        }
    }
}

async fn valider_demande_signature_csr<'a, M>(middleware: &M, m: &'a MessageValideAction) -> Result<Option<Cow<'a, MessageMilleGrille>>, Box<dyn Error>>
    where M: GenerateurMessages + IsConfigNoeud
{
    let mut message = None;

    // Valider format de la demande avec mapping
    let message_parsed: DemandeSignature = m.message.parsed.map_contenu()?;
    let certificat = match &m.message.certificat {
        Some(c) => c.clone(),
        None => {
            let e = json!({"ok": false, "err": "Certificat invalide"});
            return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
        }
    };

    if m.message.verifier_roles(vec![RolesCertificats::Instance]) {
        if m.message.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
            debug!("valider_demande_signature_csr Demande de CSR signee par une instance 3.protege ou 4.secure, demande approuvee");
            message = Some(Cow::Borrowed(&m.message.parsed));
        } else if m.message.verifier_exchanges(vec![Securite::L2Prive]) {
            debug!("valider_demande_signature_csr Demande de CSR signee par une instance 2.prive");
            message = Some(Cow::Borrowed(&m.message.parsed));
        } else if m.message.verifier_exchanges(vec![Securite::L1Public]) {
            debug!("valider_demande_signature_csr Demande de CSR signee par une instance 1.public, demande approuvee");
            message = Some(Cow::Borrowed(&m.message.parsed));
        } else {
            error!("valider_demande_signature_csr Demande de CSR signee par une instance sans exchanges, REFUSE");
        }
    } else if m.message.verifier_roles(vec![RolesCertificats::MaitreDesClesConnexion]) {
        if m.message.verifier_exchanges(vec![Securite::L4Secure]) {
            // Un certificat de maitre des cles connexion (4.secure) supporte une cle volatile

            // Validation des valeurs
            if message_parsed.domaines.is_some() || message_parsed.dns.is_some() {
                warn!("valider_demande_signature_csr Signature certificat maitre des cles volatil refuse (exchanges/domaines/dns presents)");
                return Ok(None);
            }

            // Verifier que le role demande est MaitreDesClesConnexionVolatil
            match message_parsed.roles {
                Some(r) => {
                    let role_maitre_des_cles_string = ROLE_MAITRE_DES_CLES.to_string();
                    let role_maitre_des_cles_volatil_string = ROLE_MAITRE_DES_CLES_VOLATIL.to_string();
                    if r.len() == 2 && r.contains(&role_maitre_des_cles_string) && r.contains(&role_maitre_des_cles_volatil_string) {
                        message = Some(Cow::Borrowed(&m.message.parsed))
                    } else {
                        warn!("valider_demande_signature_csr Signature certificat maitre des cles volatil refuse (mauvais role)");
                        let e = json!({"ok": false, "err": "Mauvais role"});
                        return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
                    }
                },
                None => {
                    let e = json!({"ok": false, "err": "Aucun role"});
                    return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
                }
            }
        } else {
            error!("valider_demande_signature_csr Demande de CSR signee par une un certificat MaitreDesClesConnexion de niveau != 4.secure, REFUSE");
            let e = json!({"ok": false, "err": "niveau != 4.secure"});
            return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
        }
    } else if m.message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        debug!("valider_demande_signature_csr Demande de CSR signee par une delegation globale (proprietaire), demande approuvee");
        message = Some(Cow::Borrowed(&m.message.parsed));
    } else if m.message.verifier_exchanges(vec![Securite::L4Secure]) {
        debug!("valider_demande_signature_csr Demande de CSR signee pour un domaine");
        if message_parsed.domaines.is_some() || message_parsed.exchanges.is_some() {
            Err(format!("domaines/exchanges/roles doivent etre vide"))?;
        }

        let domaines = match certificat.get_domaines()? {
            Some(d) => d,
            None => {
                Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee, demandeur sans domaines : {:?}", m.message.certificat))?
            }
        };

        let roles = match &message_parsed.roles {
            Some(r) => r,
            None => {
                Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee, demande sans roles : {:?}", m.message.certificat))?
            }
        };

        // S'assurer que tous les roles demandes sont l'equivalent de domaines en minuscules.
        let domaines_minuscules: Vec<String> = domaines.iter().map(|d| d.to_lowercase()).collect();
        for role in roles {
            debug!("Role {} in roles : {:?}?", role, domaines_minuscules);
            if ! domaines_minuscules.contains(role) {
                Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee, role {} non autorise pour domaines : {:?}", role, m.message.certificat))?
            }
        }

        message = Some(Cow::Borrowed(&m.message.parsed));
    } else {
        Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee pour demandeur qui n'est pas autorise : {:?}", m.message.certificat))?;
    }

    Ok(message)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCertificatSigne {
    ok: bool,
    certificat: Vec<String>,
}

async fn traiter_transaction<M>(_domaine: &str, middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    //let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
    let trigger: TriggerTransaction = match m.message.parsed.map_contenu() {
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

    let contenu: TransactionCertificat = match transaction.convertir() {
        Ok(c) => Ok(c),
        Err(e) => Err(format!("core_pki.sauvegarder_certificat Erreur conversion transaction en TransactionCertificat : {:?}", e)),
    }?;
    let certificat_pems = contenu.pem;
    let ca_pem = match &contenu.ca {
        Some(ca) => Some(ca.as_str()),
        None => None
    };

    // Utiliser validateur.charger_enveloppe. Va automatiquement sauvegarder le certificat (si manquant).
    let enveloppe = match charger_enveloppe(certificat_pems.as_str(), None, ca_pem) {
        Ok(e) => Ok(e),
        Err(e) => Err(format!("Erreur preparation enveloppe pour sauvegarder certificat : {:?}", e)),
    }?;

    let collection_doc_pki = middleware.get_collection(COLLECTION_CERTIFICAT_NOM)?;
    upsert_certificat(&enveloppe, collection_doc_pki, Some(false)).await?;

    Ok(None)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionCertificat {
    pem: String,
    ca: Option<String>
}

async fn traiter_cedule<M>(_middleware: &M, _trigger: &MessageCedule) -> Result<(), Box<dyn Error>>
where M: ValidateurX509 {
    //let message = trigger.message;

    debug!("traiter_cedule corepki");

    Ok(())
}

async fn evenement_certificat_maitredescles<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ConfigMessages + ChiffrageFactoryTrait
{
    info!("Recevoir certificat maitre des cles {:?}", m);
    middleware.recevoir_certificat_chiffrage(middleware, &m.message).await?;
    Ok(None)
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

    // #[tokio::test]
    // async fn regenerer_transactions_integration() {
    //     setup("regenerer_transactions_integration");
    //     let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
    //     futures.push(spawn(async move {
    //
    //         let debut_traitement = Utc::now();
    //         debug!("Debut regeneration : {:?}", debut_traitement);
    //         let mut colls = Vec::new();
    //         colls.push(String::from(COLLECTION_CERTIFICAT_NOM));
    //         todo!("Fix me")
    //         // let processor = TraiterTransactionPki{};
    //         // regenerer(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS, &colls, &processor)
    //         //     .await.expect("regenerer");
    //         //
    //         // let fin_traitemeent = Utc::now();
    //         // let duree = fin_traitemeent - debut_traitement;
    //         // debug!("Duree regeneration : {:?}", duree);
    //
    //     }));
    //     // Execution async du test
    //     futures.next().await.expect("resultat").expect("ok");
    // }
}