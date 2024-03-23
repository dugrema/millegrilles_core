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
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{emettre_presence_domaine, formatter_message_certificat, Middleware, sauvegarder_traiter_transaction, thread_emettre_presence_domaine, upsert_certificat};
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::{reqwest, reqwest::Url};
use millegrilles_common_rust::configuration::{ConfigMessages, IsConfigNoeud};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::serde_json as serde_json;
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, TraiterTransaction, Transaction, TriggerTransaction};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::error::Error as CommonError;

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
    async fn appliquer_transaction<M,T>(&self, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao,
            T: TryInto<TransactionValide> + Send
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

    async fn preparer_database<M>(&self, middleware: &M)
        -> Result<(), millegrilles_common_rust::error::Error> where M: MongoDao + ConfigMessages
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
        consommer_commande(middleware, message).await  // Fonction plus bas
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
        where M: Middleware + 'static
    {
        consommer_transaction(self, middleware, message).await  // Fonction plus bas
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
        where M: Middleware + 'static
    {
        consommer_evenement(middleware, message).await  // Fonction plus bas
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

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
            T: TryInto<TransactionValide> + Send
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    let niveaux_securite_public = vec!(Securite::L1Public);  //, Securite::L2Prive, Securite::L3Protege);
    let niveaux_securite_prive = vec!(Securite::L2Prive);  //, Securite::L3Protege);

    // RK 1.public (inclus 2.prive et 3.protege)
    for niveau in niveaux_securite_public {
        // rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Pki.infoCertificat"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.CorePki.infoCertificat"), exchange: niveau.clone()});
        // rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.certificat.*"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.CorePki.{}", PKI_COMMANDE_SIGNER_CSR), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", PKI_DOMAINE_CERTIFICAT_NOM, PKI_REQUETE_CERTIFICAT), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.CorePki.certificatParPk"), exchange: niveau.clone()});
        // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM_MAITREDESCLES, EVENEMENT_CERTIFICAT_MAITREDESCLES), exchange: niveau.clone()});
    }

    // Ajout evenement certificat pour 4.secure
    // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", PKI_DOMAINE_CERTIFICAT_NOM, PKI_REQUETE_CERTIFICAT), exchange: Securite::L4Secure});

    // RK 2.prive
    // for niveau in niveaux_securite_prive {
    //     // rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Pki.certificatParPk"), exchange: niveau.clone()});
    //     rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.CorePki.certificatParPk"), exchange: niveau.clone()});
    // }

    // RK 3.protege seulement
    // rk_volatils.push(ConfigRoutingExchange {routing_key: "commande.Pki.certificat".into(), exchange: Securite::L3Protege});
    // rk_volatils.push(ConfigRoutingExchange {routing_key: "commande.CorePki.certificat".into(), exchange: Securite::L3Protege});
    // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.Pki.{}", PKI_COMMANDE_NOUVEAU_CERTIFICAT), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.CorePki.{}", PKI_COMMANDE_NOUVEAU_CERTIFICAT), exchange: Securite::L3Protege});

    // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS, EVENEMENT_BACKUP_DECLENCHER), exchange: Securite::L2Prive});

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

async fn consommer_requete<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &m.message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.
    let (domaine, action) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_requete Mauvais type de message"))?
        }
    };

    match domaine.as_str() {
        DOMAINE_LEGACY_NOM | DOMAINE_NOM => match action.as_str() {
            PKI_REQUETE_CERTIFICAT => requete_certificat(middleware, m).await,
            PKI_REQUETE_CERTIFICAT_PAR_PK => requete_certificat_par_pk(middleware, m).await,
            _ => {
                error!("Message requete action inconnue : {}. Message dropped.", action);
                Ok(None)
            },
        },
        DOMAINE_CERTIFICAT_NOM => requete_certificat(middleware, m).await,
        _ => {
            error!("Message requete domaine inconnu : '{}'. Message dropped.", domaine);
            Ok(None)
        },
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: Middleware + 'static
{
    debug!("Consommer commande : {:?}", &m.message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.
    let (domaine, action) = match &m.type_message {
        TypeMessageOut::Commande(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_commande Mauvais type de message"))?
        }
    };

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
        true => Ok(()),
        false => {
            match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
                true => Ok(()),
                false => Err(String::from("core_pki.consommer_commande Autorisation invalide (aucun exchange, pas delegation globale)"))
            }
        },
    }?;

    match action.as_str() {
        // Commandes standard
        // COMMANDE_BACKUP_HORAIRE => backup(middleware.as_ref(), DOMAINE_NOM, NOM_COLLECTION_TRANSACTIONS, true).await,
        // COMMANDE_RESTAURER_TRANSACTIONS => restaurer_transactions(middleware.clone()).await,
        // COMMANDE_RESET_BACKUP => reset_backup_flag(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS).await,

        // Commandes specifiques au domaine
        PKI_COMMANDE_SAUVEGARDER_CERTIFICAT | PKI_COMMANDE_NOUVEAU_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware, m).await,
        PKI_COMMANDE_SIGNER_CSR => commande_signer_csr(middleware, m).await,

        // Commandes inconnues
        _ => Err(format!("Commande Pki inconnue : {}, message dropped", action))?,
    }
}

async fn consommer_transaction<M>(gestionnaire: &GestionnaireDomainePki, middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer transaction core_pki : {:?}", &m.message);
    let (domaine, action) = match &m.type_message {
        TypeMessageOut::Transaction(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_transaction Mauvais type de message"))?
        }
    };
    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges_string(vec!(String::from(SECURITE_4_SECURE)))? {
        true => Ok(()),
        false => Err(format!("core_pki.consommer_transaction Autorisation invalide (pas 4.secure) : {}", action)),
    }?;

    match action.as_str() {
        PKI_TRANSACTION_NOUVEAU_CERTIFICAT => {
            // sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        },
        _ => Err(format!("Mauvais type d'action pour une transaction : {}", action))?,
    }
}

async fn consommer_evenement<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: GenerateurMessages + ConfigMessages + ValidateurX509 + MongoDao /* + ChiffrageFactoryTrait */
{
    debug!("Consommer evenement : {:?}", &m.message);

    let (domaine, action) = match &m.type_message {
        TypeMessageOut::Evenement(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(String::from("consommer_evenement Mauvais type de message"))?
        }
    };

    match action.as_str() {
        EVENEMENT_CERTIFICAT_MAITREDESCLES => evenement_certificat_maitredescles(middleware, m).await,
        PKI_REQUETE_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware, m).await,
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", action))?,
    }
}

#[derive(Clone, Deserialize)]
struct MessageFingerprint {
    fingerprint: String
}

#[derive(Clone, Deserialize)]
struct MessageFingerprintPublicKey {
    fingerprint_pk: String
}

async fn requete_certificat<M>(middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let (domaine, exchange) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            (r.domaine.clone(), r.exchanges.clone())
        }
        _ => Err("requete_certificat Mauvais type de message")?
    };

    let fingerprint = match domaine.as_str() {
        DOMAINE_NOM => {
            let message_ref = m.message.parse()?;
            let message_contenu = match message_ref.contenu() {
                Ok(inner) => inner,
                Err(e) => Err(format!("core_pki.requete_certificat Erreur contenu() : {:?}", e))?,
            };
            let message_fingerprint: Result<String, String> = match message_contenu.deserialize::<MessageFingerprint>() {
                Ok(inner) => Ok(inner.fingerprint),
                Err(e) => Err(format!("core_pki.requete_certificat Fingerprint manquant pour requete de certificat : {:?}", e))?,
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
            let message_ref = m.message.parse()?;
            match message_ref.routage.as_ref() {
                Some(inner) => match inner.action.as_ref() {
                    Some(inner) => Ok(inner.to_string()),
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
            // let reponse = middleware.formatter_reponse(json!({"ok": false, "code": 2, "err": "Certificat inconnu"}), None)?;
            let reponse = middleware.reponse_err(2, None, Some("Certificat inconnu"))?;
            return Ok(Some(reponse));
        }
    };

    debug!("Requete certificat sur fingerprint {} trouve", fingerprint);

    let reponse_value = formatter_message_certificat(enveloppe.as_ref())?;

    // C'est une requete sur le domaine certificat, on emet l'evenement.infocertificat.fingerprint
    // let exchanges = match exchange {
    //     Some(e) => { vec![Securite::try_from(e)?] },
    //     None => { vec![Securite::L1Public] }
    // };
    let mut builder_routage = RoutageMessageAction::builder("certificat", "infoCertificat", exchange);
    // if let Some(e) = m.exchange {
    //     let securite = Securite::try_from(e)?;
    //     builder_routage = builder_routage.exchanges(vec![securite]);
    // }

    let routage = builder_routage.build();
    if let Err(e) = middleware.emettre_evenement(routage, &reponse_value).await {
        warn!("Erreur emission evenement infocertificat pour {} : {}", fingerprint, e);
    }

    // let reponse = middleware.formatter_reponse(reponse_value, None)?;
    Ok(Some(middleware.build_reponse(reponse_value)?.0))
}

async fn requete_certificat_par_pk<M>(middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    // let fingerprint_pk = match m.message.get_msg().contenu.get(PKI_DOCUMENT_CHAMP_FINGERPRINT_PK) {
    let message_ref = m.message.parse()?;
    let message_contenu = match message_ref.contenu() {
        Ok(inner) => inner,
        Err(e) => Err(format!("requete_certificat_par_pk Erreur contenu() {:?}", e))?,
    };
    let message_fingerprint: MessageFingerprintPublicKey = match message_contenu.deserialize() {
        Ok(inner) => inner,
        Err(e) => Err(format!("requete_certificat_par_pk Erreur fingerprint pk absent/erreur mapping {:?}", e))?,
    };
    let fingerprint_pk = message_fingerprint.fingerprint_pk;

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
                let reponse = middleware.build_reponse(reponse_value)?.0;
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
    let reponse = middleware.build_reponse(reponse_value)?.0;
    debug!("requete_certificat_par_pk reponse pour fingerprint_pk {}\n{:?}", fingerprint_pk, reponse);
    Ok(Some(reponse))
}

async fn traiter_commande_sauvegarder_certificat<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let domaine = match &m.type_message {
        TypeMessageOut::Evenement(r) |
        TypeMessageOut::Commande(r) => {
            r.domaine.clone()
        }
        _ => Err("traiter_commande_sauvegarder_certificat Mauvais type de message (doit etre Evenement ou Commande)")?
    };

    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: CommandeSauvegarderCertificat = message_contenu.deserialize()?;

    let ca_pem = match &commande.ca {
        Some(c) => Some(c.as_str()),
        None => None
    };
    let enveloppe = middleware.charger_enveloppe(&commande.chaine_pem, None, ca_pem).await?;
    debug!("traiter_commande_sauvegarder_certificat Certificat {} traite", enveloppe.fingerprint()?);

    if let TypeMessageOut::Evenement(_) = m.type_message {
        // Sauvegarde de l'evenement de certificat - aucune reponse
        Ok(None)
    } else {
        let reponse = middleware.reponse_ok(None, None)?;
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
async fn commande_signer_csr<M>(middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: GenerateurMessages + IsConfigNoeud
{
    if let Err(e) = valider_demande_signature_csr(middleware, &m).await {
        let err_string = format!("Acces refuse : {:?}", e);
        return Ok(Some(middleware.reponse_err(None, None, Some(err_string.as_str()))?))
    }

    // let commande = match valider_demande_signature_csr(middleware, &m).await? {
    //     Some(c) => c,
    //     None => {
    //         // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Acces refuse"}), None)?))
    //         return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
    //     }
    // };

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
    match client.post(url_post).body(m.message.buffer).send().await {
        Ok(response) => {
            match response.status().is_success() {
                true => {
                    let reponse_json: ReponseCertificatSigne = response.json().await?;
                    debug!("commande_signer_csr Reponse certificat : {:?}", reponse_json);
                    // return Ok(Some(middleware.formatter_reponse(reponse_json, None)?))
                    return Ok(Some(middleware.build_reponse(reponse_json)?.0))
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
    warn!("Echec connexion a certissuer local, relai vers instances 4.secure");
    // let routage = RoutageMessageAction::builder(DOMAINE_APPLICATION_INSTANCE, PKI_COMMANDE_SIGNER_CSR)
    //     .exchanges(vec![Securite::L4Secure])
    //     .build();
    //
    // let value: Value = commande.map_contenu()?;
    //
    // match middleware.transmettre_commande(routage, &value, true).await? {
    //     Some(reponse) => {
    //         if let TypeMessage::Valide(reponse) = reponse {
    //             let reponse_json: ReponseCertificatSigne = reponse.message.parsed.map_contenu()?;
    //             Ok(Some(middleware.formatter_reponse(reponse_json, None)?))
    //         } else {
    //             error!("core_pki.commande_signer_csr Erreur signature, echec local et relai 4.secure");
    //             Ok(Some(middleware.formatter_reponse(
    //                 json!({"ok": false, "err": "Erreur signature : aucun signateur disponible"}),
    //                 None
    //             )?))
    //         }
    //     },
    //     None => {
    //         error!("core_pki.commande_signer_csr Erreur signature, aucune reponse");
    //         Ok(Some(middleware.formatter_reponse(
    //             json!({"ok": false, "err": "Erreur signature : aucun signateur disponible"}),
    //             None
    //         )?))
    //     }
    // }

    // Ok(Some(middleware.formatter_reponse(
    //     json!({"ok": false, "err": "Erreur signature : aucun signateur disponible ou refus"}),
    //     None
    // )?))
    Ok(Some(
        middleware.reponse_err(None, None, Some("Erreur signature : aucun signateur disponible ou refus"))?
    ))
}

async fn valider_demande_signature_csr<'a, M>(middleware: &M, m: &'a MessageValide)
    -> Result<(), millegrilles_common_rust::error::Error>
    where M: GenerateurMessages + IsConfigNoeud
{
    // let mut message = None;

    // Valider format de la demande avec mapping
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let message_parsed: DemandeSignature = message_contenu.deserialize()?;
    let certificat = m.certificat.as_ref();

    if certificat.verifier_roles(vec![RolesCertificats::Instance])? {
        if certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
            debug!("valider_demande_signature_csr Demande de CSR signee par une instance 3.protege ou 4.secure, demande approuvee");
            // message = Some(Cow::Borrowed(&m.message.parsed));
            return Ok(())
        } else if certificat.verifier_exchanges(vec![Securite::L2Prive])? {
            debug!("valider_demande_signature_csr Demande de CSR signee par une instance 2.prive");
            // message = Some(Cow::Borrowed(&m.message.parsed));
            return Ok(())
        } else if certificat.verifier_exchanges(vec![Securite::L1Public])? {
            debug!("valider_demande_signature_csr Demande de CSR signee par une instance 1.public, demande approuvee");
            // message = Some(Cow::Borrowed(&m.message.parsed));
            return Ok(())
        } else {
            error!("valider_demande_signature_csr Demande de CSR signee par une instance sans exchanges, REFUSE");
        }
    } else if certificat.verifier_roles(vec![RolesCertificats::MaitreDesClesConnexion])? {
        if certificat.verifier_exchanges(vec![Securite::L4Secure])? {
            // Un certificat de maitre des cles connexion (4.secure) supporte une cle volatile

            // Validation des valeurs
            if message_parsed.domaines.is_some() || message_parsed.dns.is_some() {
                // warn!("valider_demande_signature_csr Signature certificat maitre des cles volatil refuse (exchanges/domaines/dns presents)");
                Err("valider_demande_signature_csr Signature certificat maitre des cles volatil refuse (exchanges/domaines/dns presents)")?
            }

            // Verifier que le role demande est MaitreDesClesConnexionVolatil
            match message_parsed.roles {
                Some(r) => {
                    let role_maitre_des_cles_string = ROLE_MAITRE_DES_CLES.to_string();
                    let role_maitre_des_cles_volatil_string = ROLE_MAITRE_DES_CLES_VOLATIL.to_string();
                    if r.len() == 2 && r.contains(&role_maitre_des_cles_string) && r.contains(&role_maitre_des_cles_volatil_string) {
                        // message = Some(Cow::Borrowed(&m.message.parsed))
                        return Ok(())
                    } else {
                        warn!("valider_demande_signature_csr Signature certificat maitre des cles volatil refuse (mauvais role)");
                        // let e = json!({"ok": false, "err": "Mauvais role"});
                        // return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
                        Err("Mauvais role")?
                    }
                },
                None => {
                    // let e = json!({"ok": false, "err": "Aucun role"});
                    // return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
                    Err("Aucun role")?
                }
            }
        } else {
            error!("valider_demande_signature_csr Demande de CSR signee par une un certificat MaitreDesClesConnexion de niveau != 4.secure, REFUSE");
            // let e = json!({"ok": false, "err": "niveau != 4.secure"});
            // return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
            Err("niveau != 4.secure")?
        }
    } else if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        debug!("valider_demande_signature_csr Demande de CSR signee par une delegation globale (proprietaire), demande approuvee");
        // message = Some(Cow::Borrowed(&m.message.parsed));
        return Ok(())
    } else if certificat.verifier_exchanges(vec![Securite::L4Secure])? {
        debug!("valider_demande_signature_csr Demande de CSR signee pour un domaine");
        if message_parsed.domaines.is_some() || message_parsed.exchanges.is_some() {
            Err(String::from("domaines/exchanges/roles doivent etre vide"))?;
        }

        let extensions = certificat.extensions()?;
        let domaines = match &extensions.domaines {
            Some(d) => d,
            None => {
                Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee, demandeur sans domaines : {:?}", certificat))?
            }
        };

        let roles = match &message_parsed.roles {
            Some(r) => r,
            None => {
                Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee, demande sans roles : {:?}", certificat))?
            }
        };

        // S'assurer que tous les roles demandes sont l'equivalent de domaines en minuscules.
        let domaines_minuscules: Vec<String> = domaines.iter().map(|d| d.to_lowercase()).collect();
        for role in roles {
            debug!("Role {} in roles : {:?}?", role, domaines_minuscules);
            if ! domaines_minuscules.contains(role) {
                Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee, role {} non autorise pour domaines : {:?}", role, certificat))?
            }
        }

        // message = Some(Cow::Borrowed(&m.message.parsed));
        return Ok(())
    } else {
        Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee pour demandeur qui n'est pas autorise : {:?}", certificat))?;
    }

    Err(String::from("Acces refuse (default)"))?
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCertificatSigne {
    ok: bool,
    certificat: Vec<String>,
}

async fn traiter_transaction<M>(_domaine: &str, middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    //let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
    let (message_id, trigger) = {
        let message_ref = m.message.parse()?;
        let message_contenu = match message_ref.contenu() {
            Ok(t) => t,
            Err(e) => Err(format!("Erreur conversion message contenu() {:?} : {:?}", m, e))?,
        };
        let trigger: TriggerTransaction = match message_contenu.deserialize() {
            Ok(t) => t,
            Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?,
        };
        let message_id = message_ref.id.to_owned();
        (message_id, trigger)
    };

    let transaction = charger_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &trigger).await?;
    debug!("Traitement transaction, chargee : {:?}", message_id);

    let reponse = aiguillage_transaction(middleware, transaction).await;
    if reponse.is_ok() {
        // Marquer transaction completee
        debug!("Transaction traitee {}, marquer comme completee", message_id);
        marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &message_id, EtatTransaction::Complete).await?;
    }

    reponse
}

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
        T: TryInto<TransactionValide>
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(String::from("aiguillage_transaction Erreur try_into"))?
    };

    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => {
            let action = match inner.action.as_ref() {
                Some(action) => action.to_string(),
                None => Err(String::from("aiguillage_transaction Action manquante"))?
            };
            action
        },
        None => Err(String::from("aiguillage_transaction Routage manquant"))?
    };

    match action.as_str() {
        PKI_TRANSACTION_NOUVEAU_CERTIFICAT => sauvegarder_certificat(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.transaction.id, action))?,
    }
}

async fn sauvegarder_certificat<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Sauvegarder certificat recu via transaction");

    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let contenu: TransactionCertificat = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
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

async fn traiter_cedule<M>(_middleware: &M, _trigger: &MessageCedule)
    -> Result<(), millegrilles_common_rust::error::Error>
    where M: ValidateurX509
{
    debug!("traiter_cedule corepki");
    Ok(())
}

async fn evenement_certificat_maitredescles<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + ConfigMessages /*+ ChiffrageFactoryTrait*/
{
    todo!("fix me")
    // info!("Recevoir certificat maitre des cles {:?}", m);
    // let type_message = TypeMessage::Valide(m);
    // middleware.recevoir_certificat_chiffrage(middleware, &type_message).await?;
    // Ok(None)
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