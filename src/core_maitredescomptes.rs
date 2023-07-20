use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::{base64_url, chrono, openssl, uuid};
use millegrilles_common_rust::hex;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, bson, DateTime as DateTimeBson, doc};
use millegrilles_common_rust::bson::Array;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::certificats::{calculer_fingerprint_pk, csr_calculer_fingerprintpk, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use millegrilles_common_rust::configuration::{ConfigMessages, IsConfigNoeud};
use millegrilles_common_rust::certificats::{charger_csr, get_csr_subject};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L2Prive, L3Protege, L4Secure};
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille, preparer_btree_recursif};
use millegrilles_common_rust::formatteur_messages::MessageSerialise;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::middleware::{sauvegarder_transaction, thread_emettre_presence_domaine, Middleware, sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_deserializable, convertir_bson_value, convertir_to_bson, filtrer_doc_id, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb as mongodb;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, InsertOneOptions};
use millegrilles_common_rust::multibase;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage, valider_message};
use millegrilles_common_rust::serde_json::{json, Map, Value};
use millegrilles_common_rust::serde_json as serde_json;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, TraiterTransaction, Transaction, TransactionImpl, TriggerTransaction};
use millegrilles_common_rust::verificateur::{ValidationOptions, VerificateurMessage, verifier_message, verifier_signature_serialize, verifier_signature_str};
use millegrilles_common_rust::{reqwest, reqwest::Url};
use millegrilles_common_rust::common_messages::{MessageConfirmation, ReponseSignatureCertificat};
use millegrilles_common_rust::constantes::MessageKind::Reponse;
use mongodb::options::{FindOptions, UpdateOptions};
use serde::{Deserialize, Serialize};

use crate::validateur_pki_mongo::MiddlewareDbPki;
use crate::webauthn::{authenticate_complete, ClientAssertionResponse, CompteCredential, ConfigChallenge, Credential, CredentialWebauthn, generer_challenge_authentification, generer_challenge_registration, multibase_to_safe, valider_commande, verifier_challenge_authentification, verifier_challenge_registration};
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::hachages::hacher_bytes_vu8;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongodb::Collection;
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::multibase::Base::Base64Url;
use millegrilles_common_rust::multihash::Code;
use webauthn_rs::prelude::{Base64UrlSafeData, CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse};
use crate::core_pki::COLLECTION_CERTIFICAT_NOM;

// Constantes
pub const DOMAINE_NOM: &str = "CoreMaitreDesComptes";
pub const NOM_COLLECTION_USAGERS: &str = "CoreMaitreDesComptes/usagers";
pub const NOM_COLLECTION_RECOVERY: &str = "CoreMaitreDesComptes/recovery";
pub const NOM_COLLECTION_ACTIVATIONS: &str = "CoreMaitreDesComptes/activations";
pub const NOM_COLLECTION_CHALLENGES: &str = "CoreMaitreDesComptes/challenges";
// pub const NOM_COLLECTION_WEBAUTHN_AUTHENTIFICATION: &str = "CoreMaitreDesComptes/webauthnAuthentification";
pub const NOM_COLLECTION_WEBAUTHN_CREDENTIALS: &str = "CoreMaitreDesComptes/webauthnCredentials";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;

const NOM_Q_TRANSACTIONS: &str = "CoreMaitreDesComptes/transactions";
const NOM_Q_VOLATILS: &str = "CoreMaitreDesComptes/volatils";
const NOM_Q_TRIGGERS: &str = "CoreMaitreDesComptes/triggers";

const REQUETE_CHARGER_USAGER: &str = "chargerUsager";
const REQUETE_LISTE_USAGERS: &str = "getListeUsagers";
const REQUETE_USERID_PAR_NOMUSAGER: &str = "getUserIdParNomUsager";
const REQUETE_GET_CSR_RECOVERY_PARCODE: &str = "getCsrRecoveryParcode";
const REQUETE_LISTE_PROPRIETAIRES: &str = "getListeProprietaires";
// const REQUETE_GET_TOKEN_SESSION: &str = "getTokenSession";

// const COMMANDE_CHALLENGE_COMPTEUSAGER: &str = "challengeCompteUsager";
const COMMANDE_SIGNER_COMPTEUSAGER: &str = "signerCompteUsager";
const COMMANDE_SIGNER_COMPTE_PAR_PROPRIETAIRE: &str = "signerCompteParProprietaire";
// const COMMANDE_ACTIVATION_TIERCE: &str = "activationTierce";
const COMMANDE_AJOUTER_CSR_RECOVERY: &str = "ajouterCsrRecovery";
const COMMANDE_AUTHENTIFIER_WEBAUTHN: &str = "authentifierWebauthn";
const COMMANDE_GENERER_CHALLENGE: &str = "genererChallenge";

const TRANSACTION_INSCRIRE_USAGER: &str = "inscrireUsager";
const TRANSACTION_AJOUTER_CLE: &str = "ajouterCle";
// const TRANSACTION_SUPPRIMER_CLES: &str = "supprimerCles";
const TRANSACTION_SUPPRIMER_USAGER: &str = "supprimerUsager";
const TRANSACTION_MAJ_USAGER_DELEGATIONS: &str = "majUsagerDelegations";
const TRANSACTION_AJOUTER_DELEGATION_SIGNEE: &str = "ajouterDelegationSignee";
const TRANSACTION_SUPPRIMER_CLES: &str = "supprimerCles";
const TRANSACTION_RESET_WEBAUTHN_USAGER: &str = "resetWebauthnUsager";

const EVENEMENT_EVICT_USAGER: &str = "evictUsager";

const INDEX_ID_USAGER: &str = "idusager_unique";
const INDEX_NOM_USAGER: &str = "nomusager_unique";
const INDEX_RECOVERY_UNIQUE: &str = "recovery_code_unique";
const INDEX_CHALLENGES_UNIQUE: &str = "challenges_unique";
const INDEX_WEBAUTHN_UNIQUE: &str = "webauthn_unique";

const CHAMP_USER_ID: &str = "userId";
const CHAMP_USAGER_NOM: &str = "nomUsager";
const CHAMP_COMPTE_PRIVE: &str = "compte_prive";
const CHAMP_DELEGATION_GLOBALE: &str = "delegation_globale";
const CHAMP_DELEGATION_DATE: &str = "delegations_date";
const CHAMP_DELEGATION_VERSION: &str = "delegations_version";
const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
const CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK: &str = "activations_par_fingerprint_pk";
const CHAMP_WEBAUTHN: &str = "webauthn";
const CHAMP_WEBAUTHN_HOSTNAMES: &str = "webauthn_hostnames";
const CHAMP_CODE: &str = "code";
const CHAMP_TYPE_CHALLENGE_WEBAUTHN: &str = "type_challenge";

const DELEGATION_PROPRIETAIRE: &str = "proprietaire";

/// Instance statique du gestionnaire de maitredescomptes
pub const GESTIONNAIRE_MAITREDESCOMPTES: GestionnaireDomaineMaitreDesComptes = GestionnaireDomaineMaitreDesComptes {};

#[derive(Clone)]
pub struct GestionnaireDomaineMaitreDesComptes {}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompteUsager {
    #[serde(rename="nomUsager")]
    nom_usager: String,
    #[serde(rename="userId")]
    user_id: String,

    compte_prive: Option<bool>,

    delegation_globale: Option<String>,
    delegations_date: Option<DateEpochSeconds>,
    delegations_version: Option<usize>,
}

#[async_trait]
impl TraiterTransaction for GestionnaireDomaineMaitreDesComptes {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireDomaineMaitreDesComptes {
    #[inline]
    fn get_nom_domaine(&self) -> String {DOMAINE_NOM.into()}
    #[inline]
    fn get_collection_transactions(&self) -> Option<String> {Some(NOM_COLLECTION_TRANSACTIONS.into())}

    fn get_collections_documents(&self) -> Vec<String> {
        vec![
            String::from(NOM_COLLECTION_USAGERS),
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
        consommer_commande(middleware, &self,message).await  // Fonction plus bas
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

    // RK 2.prive, 3.protege
    let requetes_privees_protegees: Vec<&str> = vec![
        REQUETE_CHARGER_USAGER,
        REQUETE_GET_CSR_RECOVERY_PARCODE,
        // REQUETE_GET_TOKEN_SESSION,
    ];
    for req in requetes_privees_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
    }

    let requetes_protegees: Vec<&str> = vec![
        REQUETE_LISTE_USAGERS,
        REQUETE_LISTE_PROPRIETAIRES,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
    }

    // RK 4.secure pour requetes internes
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_USERID_PAR_NOMUSAGER), exchange: Securite::L4Secure});

    let commandes: Vec<&str> = vec![
        // Transactions recues sous forme de commande pour validation
        TRANSACTION_INSCRIRE_USAGER,
        TRANSACTION_AJOUTER_CLE,
        TRANSACTION_AJOUTER_DELEGATION_SIGNEE,
        TRANSACTION_SUPPRIMER_CLES,

        // Commandes
        COMMANDE_AUTHENTIFIER_WEBAUTHN,
        COMMANDE_SIGNER_COMPTEUSAGER,
        COMMANDE_SIGNER_COMPTE_PAR_PROPRIETAIRE,
        // COMMANDE_ACTIVATION_TIERCE,
        COMMANDE_AJOUTER_CSR_RECOVERY,
        COMMANDE_GENERER_CHALLENGE,
    ];
    for commande in commandes {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L2Prive});
        // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L3Protege});
    }

    let commandes_protegees: Vec<&str> = vec![
        TRANSACTION_MAJ_USAGER_DELEGATIONS,
        TRANSACTION_RESET_WEBAUTHN_USAGER,
    ];
    for commande in commandes_protegees {
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
    let transactions: Vec<&str> = vec![
        TRANSACTION_INSCRIRE_USAGER,
        TRANSACTION_AJOUTER_CLE,
        TRANSACTION_AJOUTER_DELEGATION_SIGNEE,
        TRANSACTION_MAJ_USAGER_DELEGATIONS,
        TRANSACTION_SUPPRIMER_CLES,
        TRANSACTION_RESET_WEBAUTHN_USAGER,
    ];
    for transaction in transactions {
        rk_transactions.push(ConfigRoutingExchange {routing_key: format!("transaction.{}.{}", DOMAINE_NOM, transaction), exchange: Securite::L4Secure});
    }

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

    // Index userId
    let options_unique_noeuds = IndexOptions {
        nom_index: Some(String::from(INDEX_ID_USAGER)),
        unique: true
    };
    let champs_index_noeuds = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
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
        middleware,
        NOM_COLLECTION_USAGERS,
        champs_index_noeuds,
        Some(options_unique_noeuds)
    ).await?;

    // Account recovery
    let options_unique_recovery = IndexOptions {
        nom_index: Some(String::from(INDEX_RECOVERY_UNIQUE)),
        unique: true
    };
    let champs_index_recovery = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USAGER_NOM), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_CODE), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_RECOVERY,
        champs_index_recovery,
        Some(options_unique_recovery)
    ).await?;

    // challenges (incluant webauthn)
    let options_unique_challenges = IndexOptions {
        nom_index: Some(String::from(INDEX_CHALLENGES_UNIQUE)),
        unique: true
    };
    let champs_index_challenges = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ChampIndex {nom_champ: String::from("type_challenge"), direction: 1},
        ChampIndex {nom_champ: String::from("hostname"), direction: 1},
        ChampIndex {nom_champ: String::from("challenge"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_CHALLENGES,
        champs_index_challenges,
        Some(options_unique_challenges)
    ).await?;

    let options_unique_webauthncreds = IndexOptions {
        nom_index: Some(String::from(INDEX_WEBAUTHN_UNIQUE)),
        unique: true
    };
    let champs_index_webauthncreds = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ChampIndex {nom_champ: String::from("hostname"), direction: 1},
        ChampIndex {nom_champ: String::from("passkey.cred.cred_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_WEBAUTHN_CREDENTIALS,
        champs_index_webauthncreds,
        Some(options_unique_webauthncreds)
    ).await?;

    // let options_unique_webauthn_auth = IndexOptions {
    //     nom_index: Some(String::from(INDEX_WEBAUTHN_UNIQUE)),
    //     unique: true
    // };
    // let champs_index_webauthn_auth = vec!(
    //     ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
    //     ChampIndex {nom_champ: String::from("hostname"), direction: 1},
    //     ChampIndex {nom_champ: String::from("passkey_authentication.ast.challenge"), direction: 1},
    // );
    // middleware.create_index(
    //     middleware,
    //     NOM_COLLECTION_WEBAUTHN_AUTHENTIFICATION,
    //     champs_index_webauthn_auth,
    //     Some(options_unique_webauthn_auth)
    // ).await?;

    Ok(())
}

/// Supprime les state de registration ou authentication expires
async fn supprimer_webauthn_expire<M>(middleware: &M) -> Result<(), Box<dyn Error>>
    where M: MongoDao
{
    // Supprimer registration expires
    {
        let date_expiration_challenges = DateTimeBson::from_chrono(Utc::now() - chrono::Duration::minutes(5));
        let date_expiration_registration = DateTimeBson::from_chrono(Utc::now() - chrono::Duration::minutes(60));
        let collection_registration_state = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
        let filtre = doc! {
            "$or": [
                {
                    CHAMP_CREATION: {"$lt": date_expiration_registration},
                    "type_challenge": "registration"
                },{
                    CHAMP_CREATION: {"$lt": date_expiration_challenges},
                    "type_challenge": {"$in": ["authentication", "delegation"]}
                }
            ]
        };
        debug!("Suppression challenges registration expires depuis {:?}", filtre);
        if let Err(e) = collection_registration_state.delete_many(filtre, None).await {
            error!("Erreur suppression challenges registration expires : {:?}", e);
        }
    }

    Ok(())
}

async fn entretien<M>(_middleware: Arc<M>)
    where M: Middleware + 'static
{

    let mut catalogues_charges = false;

    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

async fn traiter_cedule<M>(middleware: &M, trigger: &MessageCedule) -> Result<(), Box<dyn Error>>
where M: MongoDao + GenerateurMessages {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    if middleware.get_mode_regeneration() == true {
        debug!("traiter_cedule Mode regeneration, skip entretien");
        return Ok(());
    }

    let date = trigger.get_date();
    if date.get_datetime().minute() % 3 == 2 {
        if let Err(e) = supprimer_webauthn_expire(middleware).await {
            error!("Erreur entretien webauthn challenges : {:?}", e);
        }
    }

    Ok(())
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &message.message);

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    let user_id = message.get_user_id();
    match message.verifier_exchanges(vec!(Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
        true => Ok(()),
        false => match user_id {
            Some(u) => Ok(()),
            None => Err(format!("Commande autorisation invalide (aucun user_id, pas 2.prive, 3.protege ou 4.secure)"))
        }
    }?;

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                // liste_applications_deployees(middleware, message).await,
                REQUETE_CHARGER_USAGER => charger_usager(middleware, message).await,
                REQUETE_LISTE_USAGERS => liste_usagers(middleware, message).await,
                REQUETE_USERID_PAR_NOMUSAGER => get_userid_par_nomusager(middleware, message).await,
                REQUETE_GET_CSR_RECOVERY_PARCODE => get_csr_recovery_parcode(middleware, message).await,
                REQUETE_LISTE_PROPRIETAIRES => get_liste_proprietaires(middleware, message).await,
                // REQUETE_GET_TOKEN_SESSION => get_token_session(middleware, message).await,
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

/// Consomme une commande
/// Verifie le niveau de securite approprie avant d'executer la commande
async fn consommer_commande<M>(middleware: &M, gestionnaire: &GestionnaireDomaineMaitreDesComptes, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: Middleware + 'static
{
    debug!("Consommer commande : {:?}", &m.message);

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    if m.verifier_exchanges(vec!(Securite::L2Prive, Securite::L3Protege)) {
        // Actions autorisees pour echanges prives
        match m.action.as_str() {
            TRANSACTION_INSCRIRE_USAGER => inscrire_usager(middleware, m).await,
            TRANSACTION_AJOUTER_CLE => commande_ajouter_cle(middleware, m, gestionnaire).await,
            TRANSACTION_AJOUTER_DELEGATION_SIGNEE => commande_ajouter_delegation_signee(middleware, m).await,

            COMMANDE_AUTHENTIFIER_WEBAUTHN => commande_authentifier_webauthn(middleware, m).await,
            COMMANDE_SIGNER_COMPTEUSAGER => commande_signer_compte_par_usager(middleware, m).await,
            COMMANDE_AJOUTER_CSR_RECOVERY => commande_ajouter_csr_recovery(middleware, m).await,
            COMMANDE_GENERER_CHALLENGE => commande_generer_challenge(middleware, m).await,

            // Commandes inconnues
            _ => Err(format!("Commande {} inconnue (section: exchange) : {}, message dropped", DOMAINE_NOM, m.action))?,
        }
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Commande proprietaire (administrateur)
        match m.action.as_str() {
            // Commandes delegation globale uniquement
            TRANSACTION_MAJ_USAGER_DELEGATIONS => commande_maj_usager_delegations(middleware, m).await,
            TRANSACTION_SUPPRIMER_CLES => commande_supprimer_cles(middleware, m).await,
            TRANSACTION_RESET_WEBAUTHN_USAGER => commande_reset_webauthn_usager(middleware, gestionnaire, m).await,

            // Commandes usager standard
            TRANSACTION_AJOUTER_CLE => commande_ajouter_cle(middleware, m, gestionnaire).await,
            COMMANDE_SIGNER_COMPTEUSAGER => commande_signer_compte_par_usager(middleware, m).await,
            COMMANDE_SIGNER_COMPTE_PAR_PROPRIETAIRE => commande_signer_compte_par_proprietaire(middleware, m).await,

            // Commandes inconnues
            _ => Ok(acces_refuse(middleware, 252)?)
        }
    } else if m.get_user_id().is_some() {
        match m.action.as_str() {
            // TRANSACTION_AJOUTER_CLE => commande_ajouter_cle(middleware, m, gestionnaire).await,
            COMMANDE_SIGNER_COMPTEUSAGER => commande_signer_compte_par_usager(middleware, m).await,

            // Commandes inconnues
            _ => Err(format!("Commande {} inconnue (section: user_id): {}, message dropped", DOMAINE_NOM, m.action))?,
        }
    } else {
        debug!("Commande {} non autorisee : {}, message dropped", DOMAINE_NOM, m.action);
        Err(format!("Commande {} non autorisee : {}, message dropped", DOMAINE_NOM, m.action))?
    }
}

fn acces_refuse<M>(middleware: &M, code: u32) -> Result<Option<MessageMilleGrille>, String>
    where M: GenerateurMessages
{
    let val = json!({
        "ok": false,
        "err": "Acces refuse",
        "code": code
    });
    match middleware.formatter_reponse(&val,None) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse charger_usager : {:?}", e))
    }
}

async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges(vec!(Securite::L4Secure)) {
        true => Ok(()),
        false => Err(format!("core_maitredescomptes.consommer_transaction Trigger cedule autorisation invalide (pas 4.secure) : {}", m.routing_key)),
    }?;

    match m.action.as_str() {
        TRANSACTION_INSCRIRE_USAGER |
        TRANSACTION_AJOUTER_CLE |
        TRANSACTION_AJOUTER_DELEGATION_SIGNEE |
        TRANSACTION_MAJ_USAGER_DELEGATIONS |
        TRANSACTION_SUPPRIMER_CLES => {
            sauvegarder_transaction(middleware, &m, NOM_COLLECTION_TRANSACTIONS).await?;
            Ok(None)
        },
        _ => Err(format!("Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_evenement(middleware: &(impl ValidateurX509 + GenerateurMessages + MongoDao), m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> {
    debug!("Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges(vec!(Securite::L4Secure)) {
        true => Ok(()),
        false => Err(format!("core_maitredescomptes.consommer_evenement Autorisation invalide (pas 4.secure) : {}", m.routing_key)),
    }?;

    match m.action.as_str() {
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", m.action))?,
    }
}

async fn traiter_transaction<M>(_domaine: &str, middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, String>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    // let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
    let trigger: TriggerTransaction = match m.message.parsed.map_contenu() {
        Ok(t) => t,
        Err(e) => Err(format!("core_maitredescomptes.traiter_transaction Erreur conversion message vers Trigger {:?} : {:?}", m, e))?,
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
    let action = match transaction.get_routage().action.as_ref() {
        Some(inner) => inner.as_str(),
        None => Err(format!("Transaction {} n'a pas d'action", transaction.get_uuid_transaction()))?
    };

    match action {
        TRANSACTION_INSCRIRE_USAGER => sauvegarder_inscrire_usager(middleware, transaction).await,
        TRANSACTION_AJOUTER_CLE => transaction_ajouter_cle(middleware, transaction).await,
        TRANSACTION_AJOUTER_DELEGATION_SIGNEE => transaction_ajouter_delegation_signee(middleware, transaction).await,
        TRANSACTION_MAJ_USAGER_DELEGATIONS => transaction_maj_usager_delegations(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_CLES => transaction_supprimer_cles(middleware, transaction).await,
        TRANSACTION_RESET_WEBAUTHN_USAGER => transaction_reset_webauthn_usager(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), action)),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeRegistrationWebauthn {
    pub user_uuid: String,
    pub registration_challenge: CreationChallengeResponse,
    pub resistration_state: PasskeyRegistration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeAuthenticationWebauthn {
    authentication_challenge: RequestChallengeResponse,
    passkey_authentication: PasskeyAuthentication,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocChallenge {
    #[serde(rename="userId")]
    pub user_id: String,
    pub type_challenge: String,
    pub hostname: String,
    pub challenge: String,

    #[serde(rename="_mg-creation")]
    pub date_creation: DateTimeBson,

    // Les elements suivants sont exlusifs (max 1 a la fois)

    /// Pour une registration webauthn
    pub webauthn_registration: Option<ChallengeRegistrationWebauthn>,

    /// Pour une authentification webauthn
    pub webauthn_authentication: Option<ChallengeAuthenticationWebauthn>,
}

impl DocChallenge {
    fn new_challenge_resgistration<T,U,V>(
        user_id: U, user_uuid: T, hostname: V, challenge: CreationChallengeResponse, registration: PasskeyRegistration
    ) -> Self
        where T: Into<String>, U: Into<String>, V: Into<String>
    {
        let webauthn_registration = ChallengeRegistrationWebauthn {
            user_uuid: user_uuid.into(),
            registration_challenge: challenge,
            resistration_state: registration,
        };

        let challenge = webauthn_registration.registration_challenge.public_key.challenge.to_string();

        Self {
            user_id: user_id.into(),
            type_challenge: "registration".to_string(),
            hostname: hostname.into(),
            challenge,
            date_creation: DateTimeBson::now(),
            webauthn_registration: Some(webauthn_registration),
            webauthn_authentication: None,
        }
    }

    fn new_challenge_authentication<U,V>(
        user_id: U, hostname: V, authentication_challenge: RequestChallengeResponse, passkey_authentication: PasskeyAuthentication
    ) -> Self
        where U: Into<String>, V: Into<String>
    {
        let challenge = authentication_challenge.public_key.challenge.to_string();

        let webauthn_authentication = ChallengeAuthenticationWebauthn {
            authentication_challenge, passkey_authentication };

        Self {
            user_id: user_id.into(),
            type_challenge: "authentication".to_string(),
            hostname: hostname.into(),
            challenge,
            date_creation: DateTimeBson::now(),
            webauthn_registration: None,
            webauthn_authentication: Some(webauthn_authentication),
        }
    }

    fn new_challenge_generique<U,V,S>(
        user_id: U, hostname: V, challenge: Base64UrlSafeData, type_challenge: S
    ) -> Self
        where U: Into<String>, V: Into<String>, S: Into<String>
    {
        let type_challenge = type_challenge.into();
        let challenge = challenge.to_string();

        Self {
            user_id: user_id.into(),
            type_challenge,
            hostname: hostname.into(),
            challenge,
            date_creation: DateTimeBson::now(),
            webauthn_registration: None,
            webauthn_authentication: None,
        }
    }
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct DocAuthentificationWebauthn {
//     #[serde(rename="userId")]
//     pub user_id: String,
//     pub hostname: String,
//     #[serde(rename="_mg-creation")]
//     pub date_creation: DateTimeBson,
//     pub passkey_authentication: PasskeyAuthentication,
// }

async fn preparer_registration_webauthn<M,S>(middleware: &M, compte: &CompteUsager, hostname: S)
    -> Result<DocChallenge, Box<dyn Error>>
    where M: MongoDao + ValidateurX509, S: AsRef<str>
{
    let hostname = hostname.as_ref();
    let rp_origin = format!("https://{}/", hostname);
    let user_id = compte.user_id.as_str();
    let nom_usager = compte.nom_usager.as_str();
    let user_uuid = uuid::Uuid::new_v4().to_string();
    let idmg = middleware.idmg();
    let filtre = doc! {
        CHAMP_USER_ID: user_id,
        CHAMP_TYPE_CHALLENGE_WEBAUTHN: "registration",
        "hostname": &hostname,
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let doc_registration: DocChallenge = match collection.find_one(filtre, None).await? {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => {
            let (challenge, registration) = generer_challenge_registration(
                rp_origin.as_str(), nom_usager, &user_uuid, idmg, None::<&Vec<&str>>, // existing_credentials
            )?;
            let doc_registration = DocChallenge::new_challenge_resgistration(
                user_id, user_uuid, hostname, challenge, registration);

            // Sauvegarder dans la base de donnees
            let doc_bson = convertir_to_bson(&doc_registration)?;
            collection.insert_one(doc_bson, None).await?;

            doc_registration
        }
    };

    Ok(doc_registration)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PasskeyAuthenticationStateAjuste {
    pub credentials: Value,
    pub policy: Value,
    pub challenge: Base64UrlSafeData,
    pub appid: Option<String>,
    pub allow_backup_eligible_upgrade: bool
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PasskeyAuthenticationAjuste {
    ast: PasskeyAuthenticationStateAjuste,
}

impl TryInto<PasskeyAuthentication> for PasskeyAuthenticationAjuste {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<PasskeyAuthentication, Self::Error> {
        let value = serde_json::to_value(self)?;
        Ok(serde_json::from_value(value)?)
    }
}

impl TryFrom<PasskeyAuthentication> for PasskeyAuthenticationAjuste {
    type Error = Box<dyn Error>;

    fn try_from(value: PasskeyAuthentication) -> Result<Self, Self::Error> {
        let value_conv = serde_json::to_value(value)?;
        Ok(serde_json::from_value(value_conv)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocPasskeyAuthentication {
    #[serde(rename="userId")]
    user_id: String,
    hostname: String,
    passkey_authentication: PasskeyAuthenticationAjuste,
    #[serde(rename="_mg-creation")]
    pub date_creation: DateTimeBson,
}

async fn preparer_authentification_webauthn<M,S>(middleware: &M, compte: &CompteUsager, hostname: S)
    -> Result<Option<DocChallenge>, Box<dyn Error>>
    where M: MongoDao + ValidateurX509, S: AsRef<str>
{
    let hostname = hostname.as_ref();
    let user_id = compte.user_id.as_str();
    let idmg = middleware.idmg();

    // Charger credentials existants
    let collection = middleware.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
    let filtre = doc! { CHAMP_USER_ID: user_id, "hostname": hostname };
    let mut credentials = Vec::new();
    let mut curseur = collection.find(filtre, None).await?;
    while let Some(r) = curseur.next().await {
        let cred: CredentialWebauthn = convertir_bson_deserializable(r?)?;
        credentials.push(cred);
    }

    if credentials.len() == 0 {
        debug!("preparer_authentification_webauthn Aucuns credentials webauthn pour {}/{}", user_id, hostname);
        return Ok(None);
    }

    let (challenge, passkey_authentication) = generer_challenge_authentification(
        hostname, idmg, credentials)?;

    // Sauvegarder challenge
    let doc_challenge = DocChallenge::new_challenge_authentication(
        user_id, hostname, challenge, passkey_authentication);
    let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let doc_passkey = convertir_to_bson(&doc_challenge)?;
    collection.insert_one(doc_passkey, None).await?;

    Ok(Some(doc_challenge))
}

async fn preparer_challenge_generique<M,S,C>(middleware: &M, compte: &CompteUsager, hostname: S, type_challenge: C)
    -> Result<DocChallenge, Box<dyn Error>>
    where M: MongoDao + ValidateurX509, S: AsRef<str>, C: Into<String>
{
    let hostname = hostname.as_ref();
    let user_id = compte.user_id.as_str();
    let type_challenge = type_challenge.into();

    // Genrer un challenge de 32 bytes
    let valeur_challenge =  {
        let mut buffer_random = [0u8; 32];
        openssl::rand::rand_bytes(&mut buffer_random).expect("rand");
        let challenge = buffer_random.to_vec();
        Base64UrlSafeData::from(challenge)
    };

    // Sauvegarder challenge
    let doc_challenge = DocChallenge::new_challenge_generique(user_id, hostname, valeur_challenge, type_challenge);
    let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let doc_passkey = convertir_to_bson(&doc_challenge)?;
    collection.insert_one(doc_passkey, None).await?;

    Ok(doc_challenge)
}


#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseChargerUsager {
    ok: bool,
    err: Option<String>,
    compte: Option<CompteUsager>,
    activations: Option<HashMap<String, DocActivationFingerprintPkUsager>>,
    registration_challenge: Option<CreationChallengeResponse>,
    authentication_challenge: Option<RequestChallengeResponse>,
    passkey_authentication: Option<PasskeyAuthentication>,
}

impl From<CompteUsager> for ReponseChargerUsager {
    fn from(value: CompteUsager) -> Self {
        Self {
            ok: true,
            err: None,
            compte: Some(value),
            activations: None,
            registration_challenge: None,
            authentication_challenge: None,
            passkey_authentication: None,
        }
    }
}

impl ReponseChargerUsager {
    fn erreur<E>(erreur: E) -> Self
        where E: Into<String>
    {
        Self {
            ok: false,
            err: Some(erreur.into()),
            compte: None,
            activations: None,
            registration_challenge: None,
            authentication_challenge: None,
            passkey_authentication: None,
        }
    }

    fn compte_inconnu<E, F>(nom_usager: Option<E>, user_id: Option<F>) -> Self
        where E: AsRef<str>, F: AsRef<str>
    {
        let nom_usager = match nom_usager.as_ref() {
            Some(inner) => inner.as_ref(),
            None => ""
        };

        let user_id = match user_id.as_ref() {
            Some(inner) => inner.as_ref(),
            None => ""
        };

        Self {
            ok: true,
            err: Some(format!("compte inconnu : nom_usager: {:?}, user_id: {:?}", nom_usager, user_id)),
            compte: None,
            activations: None,
            registration_challenge: None,
            authentication_challenge: None,
            passkey_authentication: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocActivationFingerprintPkUsager {
    #[serde(rename="userId")]
    user_id: String,
    fingerprint_pk: String,
}

async fn charger_usager<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("charger_usager : {:?}", &message.message);
    let est_delegation_globale = message.message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE);

    let requete: RequeteUsager = message.message.get_msg().map_contenu()?;

    let mut filtre = doc!{};

    // Le filtre utilise le user_id du certificat de preference (et ignore les parametres).
    // Pour un certificat 2.prive, 3.protege ou 4.public, va utiliser les parametres.
    if message.verifier_exchanges(vec![L2Prive, L3Protege, L4Secure]) || est_delegation_globale {
        if let Some(nom_usager) = requete.nom_usager.as_ref() {
            filtre.insert(CHAMP_USAGER_NOM, nom_usager);
        }
        if let Some(user_id) = requete.user_id.as_ref() {
            filtre.insert(CHAMP_USER_ID, user_id);
        }
    }

    if filtre.len() == 0 {
        match message.get_user_id() {
            Some(u) => {
                filtre.insert(CHAMP_USER_ID, u);
            },
            None => match message.verifier_exchanges(vec![L2Prive, L3Protege, L4Secure]) {
                true => {
                    if let Some(nom_usager) = requete.nom_usager.as_ref() {
                        filtre.insert(CHAMP_USAGER_NOM, nom_usager);
                    }
                    if let Some(user_id) = requete.user_id.as_ref() {
                        filtre.insert(CHAMP_USER_ID, user_id);
                    }
                },
                false => Err(format!("core_maitredescomptes.charger_usager Requete non autorisee en fonction du certificat"))?
            }
        }
    }

    debug!("charger_usager filtre: {:?}", filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let mut reponse_charger_usager: ReponseChargerUsager = match collection.find_one(filtre, None).await? {
        Some(mut doc_usager) => {
            match convertir_bson_deserializable::<CompteUsager>(doc_usager) {
                Ok(v) => ReponseChargerUsager::from(v),
                Err(e) => {
                    let msg_erreur = format!("Erreur conversion doc vers json : {:?}", e);
                    warn!("{}", msg_erreur);
                    ReponseChargerUsager::erreur(msg_erreur)
                }
            }
        },
        None => {
            ReponseChargerUsager::compte_inconnu(requete.nom_usager.as_ref(), requete.user_id.as_ref())
        }
    };

    if let Some(compte) = reponse_charger_usager.compte.as_ref() {
        let user_id = compte.user_id.as_str();

        debug!("Charger activations pour compte {}", user_id);
        let filtre = doc!{ CHAMP_USER_ID: user_id };
        let collection = middleware.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
        let mut activations = HashMap::new();
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(r) = curseur.next().await {
            let activation: DocActivationFingerprintPkUsager = convertir_bson_deserializable(r?)?;
            activations.insert(activation.fingerprint_pk.clone(), activation);
        }
        reponse_charger_usager.activations = Some(activations);

        if let Some(host_url) = requete.host_url.as_ref() {
            debug!("charger_usager host_url {}", host_url);
            let hostname = host_url;

            let registration_webauthn = preparer_registration_webauthn(middleware, compte, hostname).await?;
            reponse_charger_usager.registration_challenge = match registration_webauthn.webauthn_registration {
                Some(inner) => Some(inner.registration_challenge),
                None => Err(format!("core_maitredescomptes.charger_usager Mauvais format de challenge (registration_challenge=None"))?
            };

            let (challenge, passkey_authentication) = match preparer_authentification_webauthn(middleware, compte, hostname).await? {
                Some(doc_challenge) => {
                    match doc_challenge.webauthn_authentication {
                        Some(inner) => {
                            (Some(inner.authentication_challenge), Some(inner.passkey_authentication))
                        },
                        None => (None, None)
                    }
                },
                None => (None, None)
            };
            reponse_charger_usager.authentication_challenge = challenge;
            reponse_charger_usager.passkey_authentication = passkey_authentication;
        } else if ! est_delegation_globale {
            Err(format!("charger_usager host_url n'est pas fourni dans la requete usager"))?;
        }
    }

    debug!("charger_usager reponse {:?}", reponse_charger_usager);

    match middleware.formatter_reponse(&reponse_charger_usager,None) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse charger_usager : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteUsager {
    /// User_id, utilise de preference.
    #[serde(rename="userId")]
    user_id: Option<String>,

    /// Nom usager, utilise si le user_id est absent.
    #[serde(rename="nomUsager")]
    nom_usager: Option<String>,

    /// Url du serveur qui fait la demande (du point de vue usager).
    /// Requis pour webauthn, agit comme flag pour generer un nouveau challenge d'authentification.
    #[serde(rename="hostUrl")]
    host_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GetTokenSession {
    #[serde(rename="nomUsager")]
    nom_usager: String,
    #[serde(rename="userId")]
    user_id: String,
    challenge: String,
    webauthn: ClientAssertionResponse,
}

#[derive(Deserialize)]
struct DocUserWebAuthn {
    #[serde(rename="nomUsager")]
    nom_usager: String,
    #[serde(rename="userId")]
    user_id: String,
    webauthn: Option<Vec<Credential>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MessageAuthentificationClient {}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteListeUsagers {
    liste_userids: Option<Vec<String>>,
}

async fn liste_usagers<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("liste_usagers : {:?}", &message.message);
    let requete: RequeteListeUsagers = message.message.get_msg().map_contenu()?;

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

async fn get_liste_proprietaires<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("get_liste_proprietaires : {:?}", &message.message);
    let requete: RequeteListeUsagers = message.message.get_msg().map_contenu()?;

    let usagers = {
        let filtre = doc! { CHAMP_DELEGATION_GLOBALE: DELEGATION_PROPRIETAIRE };
        let projection = doc! {
            CHAMP_USAGER_NOM: true,
            CHAMP_USER_ID: true,
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

async fn get_userid_par_nomusager<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("get_userid_par_nomusager : {:?}", &message.message);
    let requete: RequeteUserIdParNomUsager = message.message.get_msg().map_contenu()?;

    // Inserer tous les nom_usagers demandes avec None. Assurer de retourner la reponse complete
    // si certains usagers sont inconnus.
    let mut usagers: HashMap<String, Option<String>> = HashMap::new();
    for nom_usager in &requete.noms_usagers {
        usagers.insert(nom_usager.into(), None);
    }

    {   // Extraire la liste des usagers de la DB
        let filtre = doc! { CHAMP_USAGER_NOM: {"$in": requete.noms_usagers}};
        debug!("get_userid_par_nomusager Requete noms usagers, filtre : {:?}", filtre);
        let projection = doc! {
            CHAMP_USAGER_NOM: true,
            CHAMP_USER_ID: true,
        };
        let ops = FindOptions::builder().projection(Some(projection)).build();
        let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
        let mut curseur = collection.find(filtre, ops).await?;

        while let Some(d) = curseur.next().await {
            let mut doc_usager = d?;
            debug!("get_userid_par_nomusager Usager trouve : {:?}", doc_usager);
            let nom_usager = doc_usager.get_str(CHAMP_USAGER_NOM)?;
            let user_id = doc_usager.get_str(CHAMP_USER_ID)?;
            usagers.insert(nom_usager.into(), Some(user_id.into()));
        }
    };

    let reponse = ReponseUserIdParNomUsager { usagers };

    match middleware.formatter_reponse(&reponse,None) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse liste_usagers : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteUserIdParNomUsager {
    noms_usagers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseUserIdParNomUsager {
    usagers: HashMap<String, Option<String>>,
}

async fn get_csr_recovery_parcode<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("get_userid_par_nomusager : {:?}", &message.message);
    let requete: RequeteCsrRecoveryParcode = message.message.get_msg().map_contenu()?;

    let collection_usagers = middleware.get_collection(NOM_COLLECTION_USAGERS)?;

    // Verifier si on a un usager avec delegation globale (permet d'utiliser le parametre nom_usager)
    let nom_usager_param = match message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        true => requete.nom_usager,
        false => None,
    };

    let nom_usager_option = match nom_usager_param {
        Some(u) => Some(u),
        None => {
            // Trouver nom d'usager qui correspond au user_id du certificat usager
            match message.get_user_id() {
                Some(user_id) => {
                    debug!("get_csr_recovery_parcode Get compte usager pour user_id {}", user_id);
                    let filtre = doc!{"userId": &user_id};
                    let doc_usager = collection_usagers.find_one(filtre, None).await?;
                    debug!("get_csr_recovery_parcode Get compte usager pour user_id {}", user_id);
                    match doc_usager {
                        Some(u) => {
                            let info_compte: CompteUsager = convertir_bson_deserializable(u)?;
                            Some(info_compte.nom_usager)
                        },
                        None => None
                    }
                },
                None => None
            }
        }
    };

    let code = requete.code;

    debug!("get_csr_recovery_parcode Verification csr pour usager {:?} avec code {}", nom_usager_option, code);

    let nom_usager = match nom_usager_option {
        Some(u) => u,
        None => {
            let reponse = json!({"ok": false, "err": "Acces refuse", "code": 1});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    // Charger csr
    let collection = middleware.get_collection(NOM_COLLECTION_RECOVERY)?;
    let filtre = doc! { "nomUsager": nom_usager, "code": code };
    let doc_recovery = collection.find_one(filtre, None).await?;

    match doc_recovery {
        Some(d) => {
            let info_compte: ReponseCsrRecovery = convertir_bson_deserializable(d)?;
            Ok(Some(middleware.formatter_reponse(&info_compte, None)?))
        },
        None => {
            let reponse = json!({"ok": false, "err": "Code de recovery introuvable pour l'usager", "code": 2});
            Ok(Some(middleware.formatter_reponse(&reponse, None)?))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteCsrRecoveryParcode {
    nom_usager: Option<String>,
    code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCsrRecovery {
    #[serde(rename="nomUsager")]
    nom_usager: String,
    code: String,
    csr: String,
}

async fn ajouter_fingerprint_pk_usager<M,S,T>(middleware: &M, user_id: S, fingerprint_pk: T) -> Result<(), Box<dyn Error>>
    where M: MongoDao, S: AsRef<str>, T: AsRef<str>
{
    let user_id = user_id.as_ref();
    let fingerprint_pk = fingerprint_pk.as_ref();

    let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FINGERPRINT_PK: fingerprint_pk };
    let ops = doc! {
        "$setOnInsert": {
            CHAMP_USER_ID: user_id,
            CHAMP_CREATION: Utc::now(),
            CHAMP_FINGERPRINT_PK: fingerprint_pk,
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let options = UpdateOptions::builder().upsert(true).build();

    let collection = middleware.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
    collection.update_one(filtre, ops, options).await?;

    Ok(())
}

async fn inscrire_usager<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("Consommer inscrire_usager : {:?}", &message.message);
    let transaction: TransactionInscrireUsager = message.message.get_msg().map_contenu()?;
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
            let uuid_transaction = message.message.parsed.id.as_str();
            debug!("L'usager '{}' n'existe pas, on genere un certificat", nom_usager);
            let user_id = &transaction.user_id;
            let securite = &transaction.securite;

            // Generer certificat usager si CSR present
            let certificat = match transaction.csr {
                Some(csr) => {
                    let fingerprint_pk = match csr_calculer_fingerprintpk(csr.as_str()) {
                        Ok(fp) => fp,
                        Err(e) => {
                            error!("Erreur calcul fingerprint_pk du csr : {:?}", e);
                            let val = json!({"ok": false, "err": format!("Erreur calcul fingerprint_pk du csr")});
                            return match middleware.formatter_reponse(&val,None) {
                                Ok(m) => Ok(Some(m)),
                                Err(e) => Err(format!("Erreur preparation reponse csr manquant : {:?}", e))?
                            }
                        }
                    };
                    debug!("Ajouter activation pour user_id: {}, fingerprint_pk: {}", user_id, fingerprint_pk);
                    ajouter_fingerprint_pk_usager(middleware, user_id, fingerprint_pk).await?;
                    signer_certificat_usager(middleware, nom_usager, user_id, csr, None).await?
                },
                None => {
                    error!("inscrire_usager Inscription usager {} sans CSR initial - ABORT", nom_usager);
                    let val = json!({"ok": false, "err": format!("Requete sans CSR")});
                    return match middleware.formatter_reponse(&val,None) {
                        Ok(m) => Ok(Some(m)),
                        Err(e) => Err(format!("Erreur preparation reponse csr manquant : {:?}", e))?
                    }
                }
            };

            sauvegarder_transaction(middleware, &message, NOM_COLLECTION_TRANSACTIONS).await?;
            let transaction: TransactionImpl = message.clone().try_into()?;
            let resultat_inscrire_usager = sauvegarder_inscrire_usager(middleware, transaction).await?;
            marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, uuid_transaction, EtatTransaction::Complete).await?;

            // let reponse = match certificat {
            //     Some(inner) => Some(inner),
            //     None => resultat_inscrire_usager
            // };

            Ok(Some(certificat))
        }
    }?;

    Ok(reponse)
}

async fn sauvegarder_inscrire_usager<M, T>(middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where T: Transaction,
          M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("sauvegarder_inscrire_usager {:?}", transaction);
    let transaction: TransactionInscrireUsager = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion en TransactionInscrireUsager : {:?}", e))?
    };
    let nom_usager = transaction.nom_usager.as_str();
    let user_id = transaction.user_id.as_str();

    // let fingerprint_pk = match transaction.csr.as_ref() {
    //     Some(csr) => match csr_calculer_fingerprintpk(csr.as_str()) {
    //         Ok(fp) => fp,
    //         Err(e) => {
    //             error!("Erreur calcul fingerprint_pk du csr, on utilise fingerprint fourni : {:?}", e);
    //             transaction.fingerprint_pk.clone()
    //         }
    //     },
    //     None => transaction.fingerprint_pk.clone()
    // };

    let filtre = doc! {CHAMP_USAGER_NOM: nom_usager};
    let ops = doc! {
        "$set": {
            CHAMP_USER_ID: user_id,
            // format!("{}.{}", CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk): {
            //     "associe": false,
            //     "date_activation": Utc::now(),
            // },
        },
        "$setOnInsert": {
            CHAMP_USAGER_NOM: nom_usager,
            CHAMP_CREATION: Utc::now(),
            CHAMP_DELEGATION_VERSION: 1,
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
    securite: String,
    csr: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResponseChallengeAuthenticationWebauthn {
    #[serde(rename = "authenticatorData")]
    authenticator_data: Base64UrlSafeData,
    #[serde(rename = "clientDataJSON")]
    client_data_json: Base64UrlSafeData,
    signature: Base64UrlSafeData,
    #[serde(rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientAuthentificationWebauthn {
    id64: Base64UrlSafeData,
    response: ResponseChallengeAuthenticationWebauthn,
    #[serde(rename = "type")]
    type_: Option<String>,
}

impl TryInto<PublicKeyCredential> for ClientAuthentificationWebauthn {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<PublicKeyCredential, Self::Error> {
        let id = self.id64;

        let pk_json = json!({
            "id": &id,
            "rawId": id,
            "response": self.response,
            "extensions": {},
            "type": self.type_,
        });

        Ok(serde_json::from_value(pk_json)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DemandeSignatureCertificatWebauthn {
    #[serde(rename="activationTierce", skip_serializing_if = "Option::is_none")]
    activation_tierce: Option<bool>,
    csr: String,
    date: DateEpochSeconds,
    #[serde(rename = "nomUsager")]
    nom_usager: String,
}

impl DemandeSignatureCertificatWebauthn {
    /// Valide le message et retourne un hachage du contenu.
    fn valider(&self) -> Result<Vec<u8>, Box<dyn Error>> {

        // Le message recu est valide pour 5 minutes
        // (aussi 1 minute dans l'autre sens si clock mal ajustee)
        let date_now = Utc::now();
        let date_message = self.date.get_datetime();
        if date_now - chrono::Duration::minutes(5) > *date_message ||
            date_now + chrono::Duration::minutes(1) < *date_message {
            Err(format!("core_maitredescomptes.DemandeSignatureCertificatWebauthn Date expire/invalide"))?
        }

        // Calculer le hachage du message
        self.hacher()
    }

    fn hacher(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let map = serde_json::to_value(&self)?.as_object().expect("value map").to_owned();
        let value_ordered = preparer_btree_recursif(map)?;
        let value_serialisee = serde_json::to_string(&value_ordered)?;
        let value_bytes = value_serialisee.as_bytes();
        Ok(hacher_bytes_vu8(value_bytes, Some(Code::Blake2s256)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeClientAuthentificationWebauthn {
    #[serde(rename = "demandeCertificat")]
    demande_certificat: Option<DemandeSignatureCertificatWebauthn>,
    webauthn: ClientAuthentificationWebauthn,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeAuthentificationUsager {
    #[serde(rename="userId")]
    user_id: String,
    hostname: String,
    challenge: String,
    #[serde(rename="reponseWebauthn")]
    commande_webauthn: CommandeClientAuthentificationWebauthn,
}

async fn commande_authentifier_webauthn<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("commande_authentifier_usager : {:?}", message);

    let idmg = middleware.idmg();
    let commande: CommandeAuthentificationUsager = message.message.get_msg().map_contenu()?;

    let doc_webauth_state= match charger_challenge_authentification(
        middleware, &commande.user_id, &commande.hostname, &commande.challenge).await
    {
        Ok(inner) => inner,
        Err(e) => {
            error!("core_maitredescomptes.commande_authentifier_webauthn Challenge webauthn inconnu ou expire : {:?}", e);
            let reponse_ok = json!({"ok": false, "err": "Challenge inconnu ou expire", "code": 1});
            return Ok(Some(middleware.formatter_reponse(reponse_ok, None)?))
        }
    };

    let mut passkey_authentication: PasskeyAuthenticationAjuste = doc_webauth_state.passkey_authentication.try_into()?;
    let flag_generer_nouveau_certificat = commande.commande_webauthn.demande_certificat.is_some();
    let demande_certificat = match commande.commande_webauthn.demande_certificat {
        Some(demande) => {
            debug!("commande_authentifier_usager Demande certificat recue : {:?}", demande);
            let hachage = demande.valider()?;
            debug!("commande_authentifier_usager Hachage calcule pour demande de certificat : {:?}", hachage);
            let challenge = &passkey_authentication.ast.challenge;
            debug!("commande_authentifier_usager Challenge existant : {:?} / {}", challenge, challenge.to_string());
            let mut vec_challenge_acjuste = Vec::new();
            vec_challenge_acjuste.extend_from_slice(&challenge.0[..]);
            vec_challenge_acjuste.extend(hachage);
            debug!("commande_authentifier_usager Hachage ajuste pour demande de certificat : {:?}", vec_challenge_acjuste);
            passkey_authentication.ast.challenge = Base64UrlSafeData::from(vec_challenge_acjuste);
            Some(demande)
        },
        None => None
    };

    // Verifier authentification
    let reg = commande.commande_webauthn.webauthn.try_into()?;
    let resultat = match verifier_challenge_authentification(
        &commande.hostname, idmg, reg, passkey_authentication.try_into()?
    ) {
        Ok(inner) => inner,
        Err(e) => {
            error!("core_maitredescomptes.commande_authentifier_webauthn Erreur verification challenge webauthn : {:?}", e);
            let reponse_ok = json!({"ok": false, "err": "Erreur verification challenge webauthn", "code": 2});
            return Ok(Some(middleware.formatter_reponse(reponse_ok, None)?))
        }
    };
    debug!("commande_authentifier_webauthn Resultat webauth OK : {:?}", resultat);

    // Supprimer challenge pour eviter reutilisation
    let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let filtre = doc! {
        CHAMP_USER_ID: &commande.user_id,
        "hostname": &commande.hostname,
        "type_challenge": "authentication",
        "challenge": &commande.challenge,
    };
    collection.delete_one(filtre, None).await?;

    let mut reponse_ok = json!({
        "ok": true,
        "counter": resultat.counter(),
        "userVerification": resultat.user_verified(),
    });

    if let Some(demande_certificat) = demande_certificat {
        debug!("Generer le nouveau certificat pour l'usager et le retourner");
        let user_id = &commande.user_id;
        let csr = demande_certificat.csr;
        let compte_usager = match charger_compte_user_id(middleware, &commande.user_id).await {
            Ok(inner) => match inner {
                Some(inner) => inner,
                None => {
                    error!("core_maitredescomptes.commande_authentifier_webauthn Compte usager inconnu pour generer certificat");
                    let reponse_ok = json!({"ok": false, "err": "Compte usager inconnu pour generer nouveau certificat", "code": 3});
                    return Ok(Some(middleware.formatter_reponse(reponse_ok, None)?))
                }
            },
            Err(e) => {
                error!("core_maitredescomptes.commande_authentifier_webauthn Erreur chargement compte usager pour generer certificat : {:?}", e);
                let reponse_ok = json!({"ok": false, "err": "Erreur verification challenge webauthn", "code": 4});
                return Ok(Some(middleware.formatter_reponse(reponse_ok, None)?))
            }
        };
        let nom_usager = &compte_usager.nom_usager;
        // let securite = SECURITE_1_PUBLIC;
        let reponse_commande = signer_certificat_usager(
            middleware, nom_usager, user_id, csr, Some(&compte_usager)).await?;
        let mut reponse_serialisee = MessageSerialise::from_parsed(reponse_commande)?;
        valider_message(middleware, &mut reponse_serialisee).await?;
        let info_certificat: ReponseSignatureCertificat = reponse_serialisee.parsed.map_contenu()?;
        if let Some(certificat) = info_certificat.certificat {
            // Inserer le certificat dans la reponse
            reponse_ok.as_object_mut().expect("as_object_mut")
                .insert("certificat".to_string(), certificat.into());
        }
    }

    debug!("Reponse authentification : {:?}", reponse_ok);

    Ok(Some(middleware.formatter_reponse(reponse_ok, None)?))
}

async fn charger_challenge_authentification<M,U,H,C>(middleware: &M, user_id: U, hostname: H, challenge: C)
    -> Result<ChallengeAuthenticationWebauthn, Box<dyn Error>>
    where M: MongoDao, U: AsRef<str>, H: AsRef<str>, C: AsRef<str>
{
    // Charger challenge correspondant
    let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let filtre = doc! {
        CHAMP_USER_ID: user_id.as_ref(),
        "hostname": hostname.as_ref(),
        "type_challenge": "authentication",
        "challenge": challenge.as_ref(),
    };

    debug!("Charger challenge webauthn {:?}", filtre);
    let doc_challenge: DocChallenge = match collection.find_one(filtre.clone(), None).await? {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => Err(format!("core_maitredescomptes.commande_authentifier_webauthn Challenge webauthn inconnu ou expire"))?
    };

    let doc_webauth_state = match doc_challenge.webauthn_authentication {
        Some(inner) => inner,
        None => Err(format!("core_maitredescomptes.commande_authentifier_webauthn Challenge webauthn absent (None)"))?
    };

    Ok(doc_webauth_state)
}

/// Verifie une demande de signature de certificat pour un compte usager
/// Emet une commande autorisant la signature lorsque c'est approprie
async fn commande_signer_compte_par_usager<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    // Valider information de reponse
    let (reply_to, correlation_id) = message.get_reply_info()?;

    // Pour cert usager, utiliser user_id du cert.
    let user_id = match message.message.get_user_id() {
        Some(inner) => inner,
        None => {
            error!("commande_signer_compte_usager Doit etre signe par un certificat usager qui inclus le user_id");
            let reponse_ok = json!({"ok": false, "err": "Certificat invalide, doit inclure user_id", "code": 1});
            return Ok(Some(middleware.formatter_reponse(reponse_ok, None)?))
        }
    };

    let commande: CommandeSignerCertificat = message.message.get_msg().map_contenu()?;
    debug!("commande_signer_compte_usager CommandeSignerCertificat : {:?}", commande);

    // Charger le compte usager
    let compte_usager = match charger_compte_user_id(middleware, &user_id).await? {
        Some(inner) => inner,
        None => {
            let err = json!({"ok": false, "code": 3, "err": format!("Usager inconnu : {}", user_id)});
            debug!("signer_compte_usager usager inconnu : {:?}", err);
            match middleware.formatter_reponse(&err,None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("core_maitredescomptes.commande_signer_compte_usager Erreur preparation reponse : {:?}", e))?
            }
        }
    };

    // Charger le challenge d'authentification
    let doc_webauth_state= match charger_challenge_authentification(
        middleware, &user_id, &commande.hostname, &commande.challenge).await
    {
        Ok(inner) => inner,
        Err(e) => {
            error!("commande_signer_compte_usager Challenge webauthn inconnu ou expire : {:?}", e);
            let reponse_ok = json!({"ok": false, "err": "Challenge inconnu ou expire", "code": 1});
            return Ok(Some(middleware.formatter_reponse(reponse_ok, None)?))
        }
    };

    let reg = commande.client_assertion_response.try_into()?;

    let (passkey_authentication, demande_certificat) = {
        let mut passkey_authentication: PasskeyAuthenticationAjuste = doc_webauth_state.passkey_authentication.try_into()?;
        let demande = commande.demande_certificat;

        debug!("commande_authentifier_usager Demande certificat recue : {:?}", demande);
        let hachage = demande.valider()?;
        debug!("commande_authentifier_usager Hachage calcule pour demande de certificat : {:?}", hachage);
        let challenge = &passkey_authentication.ast.challenge;
        debug!("commande_authentifier_usager Challenge existant : {:?} / {}", challenge, challenge.to_string());
        let mut vec_challenge_acjuste = Vec::new();
        vec_challenge_acjuste.extend_from_slice(&challenge.0[..]);
        vec_challenge_acjuste.extend(hachage);
        debug!("commande_authentifier_usager Hachage ajuste pour demande de certificat : {:?}", vec_challenge_acjuste);
        passkey_authentication.ast.challenge = Base64UrlSafeData::from(vec_challenge_acjuste);

        (passkey_authentication, demande)
    };

    let idmg = middleware.idmg();
    let hostname = commande.hostname.as_str();
    let resultat = match verifier_challenge_authentification(
        commande.hostname, idmg, reg, passkey_authentication.try_into()?
    ) {
        Ok(inner) => inner,
        Err(e) => {
            error!("commande_signer_compte_usager Erreur verification challenge webauthn : {:?}", e);
            let reponse_ok = json!({"ok": false, "err": "Erreur verification challenge webauthn", "code": 2});
            return Ok(Some(middleware.formatter_reponse(reponse_ok, None)?))
        }
    };

    debug!("commande_signer_compte_usager Resultat validation webauthn OK : {:?}", resultat);
    signer_demande_certificat_usager(middleware, compte_usager, demande_certificat).await
}

async fn commande_signer_compte_par_proprietaire<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    // Verifier autorisation, pour certificats systemes (Prive), charger param user_id.
    let est_delegation_proprietaire = message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE);
    if ! est_delegation_proprietaire {
        error!("commande_signer_compte_par_proprietaire Doit etre signe par un certificat avec delegation globale 'proprietaire'");
        let reponse_ok = json!({"ok": false, "err": "Certificat invalide, doit etre proprietaire", "code": 1});
        return Ok(Some(middleware.formatter_reponse(reponse_ok, None)?))
    }
    debug!("commande_signer_compte_par_proprietaire Resultat validation delegation proprietaire OK");

    let commande: CommandeSignerCertificatParProprietaire = message.message.get_msg().map_contenu()?;
    debug!("commande_signer_compte_par_proprietaire CommandeSignerCertificatParProprietaire : {:?}", commande);

    let user_id = commande.user_id.as_str();

    // Charger le compte usager
    let compte_usager = match charger_compte_user_id(middleware, user_id).await? {
        Some(inner) => inner,
        None => {
            let err = json!({"ok": false, "code": 2, "err": format!("Usager inconnu : {}", user_id)});
            debug!("commande_signer_compte_par_proprietaire usager inconnu : {:?}", err);
            match middleware.formatter_reponse(&err,None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("core_maitredescomptes.commande_signer_compte_par_proprietaire Erreur preparation reponse : {:?}", e))?
            }
        }
    };

    signer_demande_certificat_usager(middleware, compte_usager, commande.demande_certificat).await
}

async fn signer_demande_certificat_usager<M>(middleware: &M, compte_usager: CompteUsager,
                                             demande_certificat: DemandeSignatureCertificatWebauthn)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    let nom_usager = &compte_usager.nom_usager;
    let user_id = &compte_usager.user_id;
    let securite = SECURITE_1_PUBLIC;
    let reponse_commande = signer_certificat_usager(
        middleware, nom_usager, user_id, demande_certificat.csr, Some(&compte_usager)).await?;

    // Ajouter flag tiers si active d'un autre appareil que l'origine du CSR
    debug!("commande_signer_compte_usager Activation tierce : {:?}", demande_certificat.activation_tierce);
    if let Some(true) = demande_certificat.activation_tierce {
        // Calculer fingerprint du nouveau certificat
        let reponsecert_obj: ReponseCertificatUsager = reponse_commande.map_contenu()?;
        let pem = reponsecert_obj.certificat;
        let enveloppe_cert = middleware.charger_enveloppe(&pem, None, None).await?;
        let fingerprint_pk = enveloppe_cert.fingerprint_pk()?;

        // Donne le droit a l'usager de faire un login initial et enregistrer son appareil.
        let collection_activations = middleware.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
        let filtre = doc! { CHAMP_USER_ID: user_id, CHAMP_FINGERPRINT_PK: &fingerprint_pk };
        let commande_set = doc! { "certificat": &pem };
        let commande_set_on_insert = doc! { CHAMP_USER_ID: user_id, CHAMP_FINGERPRINT_PK: &fingerprint_pk, CHAMP_CREATION: Utc::now() };
        let ops = doc! {
            "$set": commande_set,
            "$setOnInsert": commande_set_on_insert,
            "$currentDate": { CHAMP_MODIFICATION: true }
        };
        let options = UpdateOptions::builder().upsert(true).build();
        let resultat_update_activations = collection_activations.update_one(filtre, ops, options).await?;
        debug!("commande_signer_compte_usager Update activations : {:?}", resultat_update_activations);

        // Emettre evenement de signature de certificat, inclus le nouveau certificat
        let evenement_activation = json!({
            "fingerprint_pk": fingerprint_pk,
            "certificat": &pem,
        });
        // domaine_action = 'evenement.MaitreDesComptes.' + ConstantesMaitreDesComptes.EVENEMENT_ACTIVATION_FINGERPRINTPK
        let routage_evenement = RoutageMessageAction::builder(
            DOMAINE_NOM, "activationFingerprintPk")
            .exchanges(vec![Securite::L2Prive])
            .build();
        middleware.emettre_evenement(routage_evenement, &evenement_activation).await?;

    } else {
      debug!("commande_signer_compte_usager Activation compte {} via meme appareil (pas tierce)", nom_usager);
    }

    debug!("commande_signer_compte_usager Reponse commande : {:?}", reponse_commande);

    Ok(Some(reponse_commande))    // Le message de reponse va etre emis par le module de signature de certificat
}

/// Ajouter un CSR pour recuperer un compte usager
async fn commande_ajouter_csr_recovery<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("commande_ajouter_csr_recovery : {:?}", message);

    let commande: CommandeAjouterCsrRecovery = message.message.get_msg().map_contenu()?;
    debug!("commande_ajouter_csr_recovery CommandeAjouterCsrRecovery : {:?}", commande);

    let csr = commande.csr;
    let nom_usager = commande.nom_usager;

    // Charger CSR et calculer fingerprint, code.
    let csr_parsed = charger_csr(csr.as_str())?;
    let csr_subject = get_csr_subject(&csr_parsed.as_ref())?;
    let common_name = match csr_subject.get("commonName") {
        Some(n) => n,
        None => {
            let reponse = json!({"ok": false, "err": "Common Name absent du CSR"});
            return Ok(Some(middleware.formatter_reponse(&reponse,None)?));
        }
    };

    let cle_publique = csr_parsed.public_key()?;
    let fingerprint = calculer_fingerprint_pk(&cle_publique)?;
    let code = {
        let len_fingerprint = fingerprint.len();
        let fingerprint_lc = fingerprint.to_lowercase();
        let code_part1 = &fingerprint_lc[len_fingerprint - 8..len_fingerprint - 4];
        let code_part2 = &fingerprint_lc[len_fingerprint - 4..len_fingerprint];
        let code = format!("{}-{}", code_part1, code_part2);
        debug!("Code : {}", code);
        code
    };

    let date_courante = Utc::now();
    let filtre = doc! {
        "code": &code,
        "nomUsager": &nom_usager,
    };
    let ops = doc! {
        "$set": {
            "csr": &csr,
        },
        "$setOnInsert": {
            "code": &code,
            "nomUsager": &nom_usager,
            CHAMP_CREATION: &date_courante,
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let options = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_RECOVERY)?;
    let resultat = collection.update_one(filtre, ops, Some(options)).await?;

    let reponse = json!({"ok": true, "code": &code});
    match middleware.formatter_reponse(&reponse,None) {
        Ok(m) => return Ok(Some(m)),
        Err(e) => Err(format!("Erreur preparation reponse commande_ajouter_csr_recovery : {:?}", e))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeAjouterCsrRecovery {
    csr: String,
    #[serde(rename="nomUsager")]
    nom_usager: String,
}

#[derive(Deserialize)]
struct CommandeGenererChallenge {
    #[serde(rename="userId")]
    user_id: String,
    hostname: String,
    delegation: Option<bool>,
    #[serde(rename="webauthnRegistration")]
    webauthn_registration: Option<bool>,
    #[serde(rename="webauthnAuthentication")]
    webauthn_authentication: Option<bool>,
}

#[derive(Serialize)]
struct ReponseCommandeGenererChallenge {
    challenge: Option<String>,
    registration_challenge: Option<CreationChallengeResponse>,
    authentication_challenge: Option<RequestChallengeResponse>,
    passkey_authentication: Option<PasskeyAuthentication>,
}

async fn commande_generer_challenge<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud
{
    debug!("commande_generer_challenge : {:?}", message);

    let commande: CommandeGenererChallenge = message.message.get_msg().map_contenu()?;
    let hostname = commande.hostname.as_str();

    let compte = {
        let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
        let filtre = doc! { CHAMP_USER_ID: &commande.user_id };
        let resultat = match collection.find_one(filtre, None).await? {
            Some(inner) => inner,
            None => {
                let reponse = json!({"ok": true, "code": 1, "err": "Usager inconnu"});
                match middleware.formatter_reponse(&reponse,None) {
                    Ok(m) => return Ok(Some(m)),
                    Err(e) => Err(format!("Erreur preparation reponse commande_generer_challenge : {:?}", e))?
                }
            }
        };
        convertir_bson_deserializable(resultat)?
    };

    let mut reponse = ReponseCommandeGenererChallenge {
        challenge: None,
        registration_challenge: None,
        authentication_challenge: None,
        passkey_authentication: None,
    };

    if let Some(true) = commande.delegation {
        let doc_challenge = preparer_challenge_generique(middleware, &compte, hostname, "delegation").await?;
        reponse.challenge = Some(doc_challenge.challenge);
    }

    if let Some(true) = commande.webauthn_registration {
        let doc_challenge = preparer_registration_webauthn(middleware, &compte, hostname).await?;
        reponse.registration_challenge = Some(doc_challenge.webauthn_registration.expect("webauthn_registration").registration_challenge);
    }

    if let Some(true) = commande.webauthn_authentication {
        match preparer_authentification_webauthn(middleware, &compte, hostname).await? {
            Some(inner) => {
                let challenge = inner.webauthn_authentication.expect("webauthn_authentication");
                reponse.authentication_challenge = Some(challenge.authentication_challenge);
                reponse.passkey_authentication = Some(challenge.passkey_authentication);
            },
            None => {
                error!("commande_generer_challenge Aucun credential webauthn pour l'usager");
            }
        };
    }

    Ok(Some(middleware.formatter_reponse(reponse, None)?))
}

/// Signe un certificat usager sans autre forme de validation. Utilise certissuerInterne/.
async fn signer_certificat_usager<M,S,T,U>(middleware: &M, nom_usager: S, user_id: T, csr: U, compte: Option<&CompteUsager>) -> Result<MessageMilleGrille, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + IsConfigNoeud,
          S: AsRef<str>, T: AsRef<str>, U: AsRef<str>
{
    let nom_usager_str = nom_usager.as_ref();
    let user_id_str = user_id.as_ref();
    let csr_str = csr.as_ref();
    debug!("signer_certificat_usager {} (id: {})", nom_usager_str, user_id_str);

    let config = middleware.get_configuration_noeud();
    let certissuer_url = match config.certissuer_url.as_ref() {
        Some(inner) => inner,
        None => Err(format!("core_maitredescomptes.signer_certificat_usager Certissuer URL manquant"))?
    };

    let client = reqwest::Client::builder()
        .timeout(core::time::Duration::new(7, 0))
        .build()?;

    let mut url_post = certissuer_url.clone();
    url_post.set_path("certissuerInterne/signerUsager");

    // let mut commande_signature = json!({
    //     "nom_usager": nom_usager_str,
    //     "user_id": user_id_str,
    //     "csr": csr_str
    // });

    let commande_signature = CommandeSignatureUsager::new(nom_usager_str, user_id_str, csr_str, compte);
    let commande_signee = middleware.formatter_message(
        MessageKind::Document, &commande_signature, None::<&str>, None::<&str>, None::<&str>, None, false)?;

    // On retransmet le message recu tel quel
    match client.post(url_post).json(&commande_signee).send().await {
        Ok(response) => {
            match response.status().is_success() {
                true => {
                    let reponse_json: ReponseCertificatSigne = response.json().await?;
                    debug!("signer_certificat_usager Reponse certificat : {:?}", reponse_json);
                    return Ok(middleware.formatter_reponse(reponse_json, None)?)
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
    let routage = RoutageMessageAction::builder(DOMAINE_APPLICATION_INSTANCE, COMMANDE_SIGNER_COMPTEUSAGER)
        .exchanges(vec![Securite::L4Secure])
        .build();

    match middleware.transmettre_commande(routage, &commande_signature, true).await? {
        Some(reponse) => {
            if let TypeMessage::Valide(reponse) = reponse {
                let reponse_json: ReponseCertificatSigne = reponse.message.parsed.map_contenu()?;
                Ok(middleware.formatter_reponse(reponse_json, None)?)
            } else {
                error!("core_pki.commande_signer_csr Erreur signature, echec local et relai 4.secure");
                Ok(middleware.formatter_reponse(
                    json!({"ok": false, "err": "Erreur signature : aucun signateur disponible"}),
                    None
                )?)
            }
        },
        None => {
            error!("core_pki.commande_signer_csr Erreur signature, aucune reponse");
            Ok(middleware.formatter_reponse(
                json!({"ok": false, "err": "Erreur signature : aucun signateur disponible"}),
                None
            )?)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCertificatUsager {
    ok: bool,
    certificat: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSignatureUsager {
    nom_usager: String,
    user_id: String,
    csr: String,
    delegation_globale: Option<String>,
    compte_prive: Option<bool>,
    delegations_version: Option<usize>,
}

impl CommandeSignatureUsager {
    fn new<S,T,U>(nom_usager: S, user_id: T, csr: U, compte: Option<&CompteUsager>) -> Self
        where S: Into<String>, T: Into<String>, U: Into<String>
    {
        let (compte_prive, delegation_globale, delegations_version) = match compte {
            Some(inner) => {
                (inner.compte_prive.to_owned(), inner.delegation_globale.to_owned(), inner.delegations_version.to_owned())
            },
            None => (None, None, None)
        };

        CommandeSignatureUsager {
            nom_usager: nom_usager.into(),
            user_id: user_id.into(),
            csr: csr.into(),
            delegation_globale,
            compte_prive,
            delegations_version,
        }
    }
}

async fn commande_ajouter_cle<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireDomaineMaitreDesComptes)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer ajouter_cle : {:?}", &message.message);

    let idmg = middleware.idmg();

    // Verifier autorisation du message
    // Doit provenir d'un maitre des comptes sur exchange 2.prive
    if ! message.verifier(
        Some(vec!(Securite::L2Prive)),
        Some(vec!(RolesCertificats::MaitreComptes)),
    ) {
        let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_cle autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err,None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        }
    }

    let commande: CommandeAjouterCle = message.message.get_msg().map_contenu()?;

    // Valider la signature du message client.
    let reponse_client_serialise = {
        let mut reponse_client_serialise = MessageSerialise::from_parsed(commande.transaction)?;
        if let Err(e) = valider_message(middleware, &mut reponse_client_serialise).await {
            let err = json!({"ok": false, "code": 3, "err": format!{"Permission refusee, reponseClient invalide : {:?}", e}});
            debug!("ajouter_cle autorisation acces refuse : {:?}", err);
            match middleware.formatter_reponse(&err, None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("ajouter_cle: Erreur preparation reponse commande_ajouter_cle : {:?}", e))?
            }
        }
        reponse_client_serialise
    };

    let transaction_ajouter_cle_contenu: TransactionAjouterCle = reponse_client_serialise.parsed.map_contenu()?;
    let hostname = match transaction_ajouter_cle_contenu.hostname.as_ref() {
        Some(inner) => inner.as_str(),
        None => {
            let err = json!({"ok": false, "code": 15, "err": format!{"Permission refusee, hostname manquant"}});
            debug!("ajouter_cle hostname manquant");
            match middleware.formatter_reponse(&err, None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("ajouter_cle: Erreur preparation reponse commande_ajouter_cle (15) : {:?}", e))?
            }
        }
    };

    // Verifier si on fait une association en utilisant un nouveau certificat active de maniere
    // externe (e.g. par le proprietaire dans Coup D'Oeil ou code QR). Utiliser fingperprint
    // de la cle publique du message signe par l'usager.
    let (user_id_certificat, fingerprint_pk) = match reponse_client_serialise.certificat.as_ref() {
        Some(inner) => {
            let user_id = match inner.get_user_id()? {
                Some(inner) => inner.as_str(),
                None => {
                    let err = json!({"ok": false, "code": 8, "err": "Permission refusee, certificat client sans user_id"});
                    debug!("ajouter_cle autorisation acces refuse certificat client sans user_id (8): {:?}", err);
                    match middleware.formatter_reponse(&err,None) {
                        Ok(m) => return Ok(Some(m)),
                        Err(e) => Err(format!("Erreur preparation reponse commande_ajouter_cle : {:?}", e))?
                    }
                }
            };

            (user_id, inner.fingerprint.as_str())
        },
        None => {
            let err = json!({"ok": false, "code": 6, "err": "Permission refusee, certificat client absent"});
            debug!("ajouter_cle autorisation acces refuse certificat client absent (6): {:?}", err);
            match middleware.formatter_reponse(&err,None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("Erreur preparation reponse commande_ajouter_cle : {:?}", e))?
            }
        }
    };

    // Validation - s'assurer que le compte usager existe
    let collection_webauthn = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let filtre_webauthn = doc! { CHAMP_USER_ID: user_id_certificat, "hostname": hostname, "type_challenge": "registration" };
    let doc_registration: DocChallenge = match collection_webauthn.find_one(filtre_webauthn, None).await? {
        Some(inner) => convertir_bson_deserializable(inner)?,
        None => {
            let err = json!({"ok": false, "code": 14, "err": format!("Permission refusee, registration webauthn absent pour userId : {}", user_id_certificat)});
            debug!("ajouter_cle registration inconnu pour user_id {} (14) : {:?}", user_id_certificat, err);
            match middleware.formatter_reponse(&err,None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("core_maitredescomptes.ajouter_cle Erreur preparation reponse commande_ajouter_cle (14) : {:?}", e))?
            }
        }
    };

    let compte_usager = match charger_compte_user_id(middleware, user_id_certificat).await? {
        Some(inner) => inner,
        None => {
            let err = json!({"ok": false, "code": 2, "err": format!("Usager inconnu pour userId (2) : {}", user_id_certificat)});
            debug!("ajouter_cle usager inconnu : {:?}", err);
            match middleware.formatter_reponse(&err,None) {
                Ok(m) => return Ok(Some(m)),
                Err(e) => Err(format!("core_maitredescomptes.ajouter_cle Erreur preparation reponse commande_ajouter_cle : {:?}", e))?
            }
        }
    };

    // Valider la commande de registration webauthn, sauvegarder nouvelle credential, retirer challenge registration
    let webauthn_credential = verifier_challenge_registration(idmg, &doc_registration, &transaction_ajouter_cle_contenu)?;
    let mut credential_interne = sauvegarder_credential(
        middleware, user_id_certificat, hostname, webauthn_credential, true).await?;

    {
        // Supprimer activation pour le certificat (si present)
        let collection = middleware.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
        let filtre = doc! { CHAMP_USER_ID: user_id_certificat, "fingerprint_pk": fingerprint_pk };
        collection.delete_one(filtre, None).await?;
    }

    // Transferer le flag reset_cles vers la transaction au besoin
    if let Some(true) = transaction_ajouter_cle_contenu.reset_cles {
        credential_interne.reset_cles = Some(true)
    }

    debug!("Credentials traite - sauvegarder sous forme de nouvelle transaction");
    let mut transaction_credential = middleware.formatter_message(
        MessageKind::Transaction, &credential_interne,
        Some(DOMAINE_NOM_MAITREDESCOMPTES), Some(TRANSACTION_AJOUTER_CLE),
        None, None, false)?;

    // Sauvegarder la transaction, marquer complete et repondre
    let uuid_transaction = reponse_client_serialise.parsed.id.clone();
    let mut mva = MessageValideAction::from_message_millegrille(
        transaction_credential, TypeMessageOut::Transaction)?;

    // Inserer le certificat local
    mva.message.certificat = Some(middleware.get_enveloppe_signature().enveloppe.clone());

    Ok(sauvegarder_traiter_transaction(middleware, mva, gestionnaire).await?)
}

async fn sauvegarder_credential<M,S,T>(middleware: &M, user_id: S, hostname: T, passkey_credential: Passkey, supprimer_registration: bool)
    -> Result<CredentialWebauthn, Box<dyn Error>>
    where M: MongoDao, S: Into<String>, T: Into<String>
{
    let user_id = user_id.into();
    let hostname = hostname.into();

    // Filtre pour supprimer registration pour user_id/hostname
    let filtre_delete = doc!( CHAMP_USER_ID: &user_id, "hostname": &hostname, "type_challenge": "registration" );

    // Inserer credential
    let cred = {
        let mut cred = CredentialWebauthn {
            user_id,
            hostname,
            passkey: passkey_credential,
            date_creation: Some(DateTimeBson::now()),
            derniere_utilisation: None,
            reset_cles: None,
        };
        let collection_credentials = middleware.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
        let cred_doc = convertir_to_bson(&cred)?;
        collection_credentials.insert_one(cred_doc, None).await?;

        // Retirer champs qui ne sont pas utiles pour une transaction
        cred.date_creation = None;

        cred
    };

    if supprimer_registration {
        // Supprimer registration challenge
        let collection_challenges = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
        collection_challenges.delete_one(filtre_delete, None).await?;
    }

    Ok(cred)
}

async fn transaction_ajouter_cle<M, T>(middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where T: Transaction,
          M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let certificat = match transaction.get_enveloppe_certificat() {
        Some(inner) => inner,
        None => Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur certificat absent - SKIP"))?
    };

    if ! certificat.verifier_exchanges(vec![Securite::L4Secure]) ||
        ! certificat.verifier_domaines(vec![DOMAINE_NOM_MAITREDESCOMPTES.to_string()]) ||
        ! certificat.verifier_roles(vec![RolesCertificats::Core]) {
        Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur exchanges/domaines/roles non autorise - SKIP"))?
    }

    let transaction_contenu: CredentialWebauthn = match transaction.convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur conversion en TransactionAjouterCle : {:?}", e))?
    };

    // Retirer flag reset_cles si preset
    let reset_cles = match transaction_contenu.reset_cles {
        Some(inner) => inner,
        None => false
    };

    let user_id = transaction_contenu.user_id.as_str();
    let hostname = transaction_contenu.hostname.as_str();
    let webauthn_credential = transaction_contenu.passkey;

    let collection = middleware.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
    if reset_cles {
        // Supprimer toutes les cles pour le user_id dans la collection credentials
        debug!("transaction_ajouter_cle Reset toutes les cles webautn pour user_id {}", user_id);
        let filtre = doc! { CHAMP_USER_ID: user_id };
        if let Err(e) = collection.delete_many(filtre, None).await {
            Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur delete cles webauthn"))?
        }
    }

    let mut inserer = reset_cles;
    if ! inserer {
        // Verifier si la cle existe deja
        let filtre = doc! {CHAMP_USER_ID: user_id, "hostname": hostname};
        let resultat = match collection.count_documents(filtre, None).await {
            Ok(inner) => inner,
            Err(e) => Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur count cles existantes : {:?}", e))?
        };
        if resultat == 0 { inserer = true }
    }
    if inserer {
        if let Err(e) = sauvegarder_credential(
            middleware, user_id, hostname, webauthn_credential, true).await {
            Err(format!("core_maitredescomptes.transaction_ajouter_cle Erreur sauvegarder credentials : {:?}", e))?
        }
    } else {
        debug!("transaction_ajouter_cle Credential existe deja - OK");
    }

    middleware.reponse_ok()
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

async fn charger_compte_user_id<M, S>(middleware: &M, user_id: S)
    -> Result<Option<CompteUsager>, Box<dyn Error>>
    where
        M: MongoDao,
        S: AsRef<str>
{
    let filtre = doc! {CHAMP_USER_ID: user_id.as_ref()};
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
    // csr: String,

    // Si true, va emettre un evenement pour indiquer a un listener que le certificat est pret.
    // activation_tierce: Option<bool>,

    #[serde(rename="demandeCertificat")]
    demande_certificat: DemandeSignatureCertificatWebauthn,

    // Champs pour demande de signature avec preuve webauthn
    challenge: String,
    hostname: String,

    /// Reponse webauthn
    #[serde(rename="clientAssertionResponse")]
    client_assertion_response: ClientAssertionResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSignerCertificatParProprietaire {
    #[serde(rename="userId")]
    user_id: String,
    #[serde(rename="demandeCertificat")]
    demande_certificat: DemandeSignatureCertificatWebauthn,
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
struct InfoAssociation {
    associe: Option<bool>,
    // date_activation: Option<usize>,

    /// Contenu du message autre que les elements structurels.
    #[serde(flatten)]
    pub contenu: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AjouterCleResponseClient {
    #[serde(rename="attestationObject")]
    pub attestation_object: String,
    #[serde(rename="clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AjouterClePublickKeyCredential {
    pub id: String,
    pub response: AjouterCleResponseClient,
    #[serde(rename="type")]
    pub type_: String,
}

impl TryInto<RegisterPublicKeyCredential> for AjouterClePublickKeyCredential {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<RegisterPublicKeyCredential, Self::Error> {
        let id = self.id;

        let json_attest = json!({
            "id": &id,
            "rawId": id,
            "response": self.response,
            "type": self.type_,
            "extensions": {},
        });

        debug!("TryInto<RegisterPublicKeyCredential> json_attest: {:?}", json_attest);
        let cred: RegisterPublicKeyCredential = serde_json::from_value(json_attest)?;
        debug!("TryInto<RegisterPublicKeyCredential> cred: {:?}", cred);

        Ok(cred)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAjouterCle {
    #[serde(rename="fingerprintPk")]
    pub fingerprint_pk: Option<String>,
    pub hostname: Option<String>,
    #[serde(rename="reponseChallenge")]
    pub reponse_client: AjouterClePublickKeyCredential,
    pub reset_cles: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeAjouterCle {
    transaction: MessageMilleGrille
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

/// Ajoute une delegation globale a partir d'un message signe par la cle de millegrille
async fn commande_ajouter_delegation_signee<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer ajouter_delegation_signee : {:?}", &message.message);
    // Verifier autorisation
    if !message.verifier(
        Some(vec!(Securite::L2Prive)),
        Some(vec!(RolesCertificats::MaitreComptes)),
    ) {
        let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err, None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("commande_ajouter_delegation_signee Erreur preparation reponse (1) ajouter_delegation_signee : {:?}", e))?
        }
    }

    // Valider contenu
    let commande: CommandeAjouterDelegationSignee = message.message.parsed.map_contenu()?;
    let mut message_confirmation = commande.confirmation;
    let user_id = commande.user_id.as_str();
    let hostname = commande.hostname.as_str();

    // S'assurer que la signature est recente (moins de 2 minutes, ajustement 10 secondes futur max)
    let date_signature = message_confirmation.estampille.get_datetime();
    let now = Utc::now();
    if now - chrono::Duration::minutes(2) > *date_signature || now + chrono::Duration::seconds(10) < *date_signature {
        warn!("ajouter_delegation_signee Commande delegation expiree - on rejette (2)");
        let err = json!({"ok": false, "code": 2, "err": "Permission refusee, estampille invalide"});
        match middleware.formatter_reponse(&err, None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("commande_ajouter_delegation_signee Erreur preparation reponse (2) : {:?}", e))?
        }
    }

    // Valider la signature de la cle de millegrille
    let (signature, hachage) = message_confirmation.verifier_contenu()?;
    if signature != true || hachage != true {
        let err = json!({"ok": false, "code": 3, "err": "Permission refusee, signature/hachage confirmation invalides"});
        debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err, None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse (3) ajouter_delegation_signee : {:?}", e))?
        }
    }
    debug!("ajouter_delegation_signee Signature message delegation (confirmation) OK");

    // Valider la pubkey, elle doit correspondre au certificat de la MilleGrille.
    let public_key_millegrille = middleware.ca_cert().public_key()?.raw_public_key()?;
    if hex::decode(message_confirmation.pubkey.as_str())? != public_key_millegrille {
        let err = json!({"ok": false, "code": 4, "err": "Permission refusee, pubkey n'est pas la cle de la MilleGrille"});
        debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err, None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse (4) ajouter_delegation_signee : {:?}", e))?
        }
    }
    debug!("ajouter_delegation_signee Correspondance cle publique millegrille OK");

    // Valider le format du contenu (parse)
    let commande_ajouter_delegation: ConfirmationSigneeDelegationGlobale = message_confirmation.map_contenu()?;
    if commande_ajouter_delegation.user_id.as_str() != user_id {
        let err = json!({"ok": false, "code": 5, "err": "Permission refusee, user_id signe et session serveur mismatch"});
        debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err, None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse (5) ajouter_delegation_signee : {:?}", e))?
        }
    }
    let challenge_recu = commande_ajouter_delegation.challenge.as_str();
    debug!("commande_ajouter_delegation_signee Commande ajouter delegation verifiee {:?}", commande_ajouter_delegation);

    // Verifier que le challenge est bien associe a cet usager pour une delegation
    let challenge = {
        let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
        let filtre = doc! { CHAMP_USER_ID: user_id, "type_challenge": "delegation", "hostname": hostname, "challenge": challenge_recu};
        let doc_challenge: DocChallenge = match collection.find_one(filtre, None).await? {
            Some(inner) => convertir_bson_deserializable(inner)?,
            None => {
                let err = json!({"ok": false, "code": 6, "err": "Permission refusee, challenge delegation inconnu"});
                debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
                match middleware.formatter_reponse(&err, None) {
                    Ok(m) => return Ok(Some(m)),
                    Err(e) => Err(format!("Erreur preparation reponse (6) ajouter_delegation_signee : {:?}", e))?
                }
            }
        };
        doc_challenge.challenge
    };

    if challenge == commande_ajouter_delegation.challenge {
        // Challenge est OK, supprimer pour eviter replay attacks
        let collection = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
        let filtre = doc! { CHAMP_USER_ID: user_id, "hostname": hostname, "challenge": challenge_recu};
        collection.delete_one(filtre, None).await?;
    } else {
        let err = json!({"ok": false, "code": 7, "err": "Permission refusee, challenge delegation inconnu"});
        debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err, None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse (7) ajouter_delegation_signee : {:?}", e))?
        }
    }

    // Signature valide, on sauvegarde et traite la transaction
    let uuid_transaction = message.message.parsed.id.clone();
    sauvegarder_transaction(middleware, &message, NOM_COLLECTION_TRANSACTIONS).await?;
    let transaction: TransactionImpl = message.try_into()?;
    let _ = transaction_ajouter_delegation_signee(middleware, transaction).await?;
    marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &uuid_transaction, EtatTransaction::Complete).await?;

    // Charger le document de compte et retourner comme reponse
    let reponse = match charger_compte_user_id(middleware, commande.user_id.as_str()).await? {
        Some(compte) => serde_json::to_value(&compte)?,
        None => json!({"ok": false, "err": "Compte usager introuvable apres maj"})  // Compte
    };

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn commande_reset_webauthn_usager<M>(middleware: &M, gestionnaire: &GestionnaireDomaineMaitreDesComptes, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer ajouter_delegation_signee : {:?}", &message.message);
    // Verifier autorisation
    if !message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_delegation_signee autorisation acces refuse : {:?}", err);
        match middleware.formatter_reponse(&err, None) {
            Ok(m) => return Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse (1) ajouter_delegation_signee : {:?}", e))?
        }
    }

    // Valider contenu en faisant le mapping
    let _commande_resultat: CommandeResetWebauthnUsager = match message.message.get_msg().map_contenu() {
        Ok(c) => c,
        Err(e) => {
            let reponse = json!({"ok": false, "code": 2, "err": format!("Format de la commande invalide : {:?}", e)});
            return Ok(Some(middleware.formatter_reponse(reponse, None)?))
        }
    };

    Ok(sauvegarder_traiter_transaction(middleware, message, gestionnaire).await?)
}

async fn transaction_ajouter_delegation_signee<M, T>(middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where T: Transaction,
          M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let commande: CommandeAjouterDelegationSignee = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur conversion en CommandeAjouterCle : {:?}", e))?
    };

    // Valider contenu
    let mut message_confirmation = commande.confirmation;

    // Valider la signature de la cle de millegrille
    let (signature, hachage) = match message_confirmation.verifier_contenu() {
        Ok(inner) => inner,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur verifier_contenu : {:?}", e))?
    };
    if signature != true || hachage != true {
        Err(format!("transaction_ajouter_delegation_signee Permission refusee, signature/hachage confirmation invalides"))?
    }

    // Valider la pubkey, elle doit correspondre au certificat de la MilleGrille.
    let public_key_millegrille = match middleware.ca_cert().public_key() {
        Ok(inner) => match inner.raw_public_key() {
            Ok(inner) => inner,
            Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur raw_public_key {:?}", e))?
        },
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur raw_public_key {:?}", e))?
    };

    let public_key_recue = match hex::decode(message_confirmation.pubkey.as_str()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur hex::decode {:?}", e))?
    } ;
    if public_key_recue != public_key_millegrille {
        Err(format!("transaction_ajouter_delegation_signee Permission refusee, pubkey n'est pas la cle de la MilleGrille"))?
    }

    debug!("transaction_ajouter_delegation_signee {:?}", message_confirmation);
    let commande_ajouter_delegation: ConfirmationSigneeDelegationGlobale = match message_confirmation.map_contenu() {
        Ok(inner) => inner,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur map_contenu : {:?}", e))?
    };
    debug!("commande_ajouter_delegation_signee Commande ajouter delegation verifiee {:?}", commande_ajouter_delegation);

    // Le filtre agit a la fois sur le nom usager (valide par la cle) et le user_id (valide par serveur)
    let filtre = doc! {
        CHAMP_USER_ID: commande.user_id.as_str(),
        CHAMP_USAGER_NOM: commande_ajouter_delegation.nom_usager.as_str(),
    };
    let ops = doc! {
        "$set": {"delegation_globale": "proprietaire", "delegations_date": &DateEpochSeconds::now()},
        "$inc": {CHAMP_DELEGATION_VERSION: 1},
        "$currentDate": { CHAMP_MODIFICATION: true }
    };

    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur maj pour usager {:?} : {:?}", message_confirmation, e))?
    };
    debug!("transaction_ajouter_delegation_signee resultat {:?}", resultat);
    if resultat.matched_count == 1 {
        Ok(None)
    } else {
        Err(format!("transaction_ajouter_delegation_signee Aucun match pour usager {:?}", commande.user_id.as_str()))
    }
}

async fn transaction_reset_webauthn_usager<M, T>(middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where T: Transaction,
          M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let commande: CommandeResetWebauthnUsager = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion en CommandeResetWebauthnUsager : {:?}", e))?
    };

    debug!("transaction_reset_webauthn_usager {:?}", commande);

    if let Some(evict) = commande.evict_all_sessions {
        if evict {
            // Emettre message pour fermer toutes les sessions en cours de l'usager
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_EVICT_USAGER)
                .exchanges(vec![L2Prive])
                .build();
            let message = json!({CHAMP_USER_ID: &commande.user_id});
            middleware.emettre_evenement(routage, &message).await?;
        }
    }

    // Le filtre agit a la fois sur le nom usager (valide par la cle) et le user_id (valide par serveur)
    let filtre = doc! {
        CHAMP_USER_ID: commande.user_id.as_str(),
    };
    let mut unset_opts = doc! {};
    if let Some(r) = commande.reset_webauthn { if(r) { unset_opts.insert(CHAMP_WEBAUTHN, true); } }
    if let Some(r) = commande.reset_activations { if(r) { unset_opts.insert(CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, true); } }
    let ops = doc! {
        "$unset": unset_opts,
        "$currentDate": { CHAMP_MODIFICATION: true }
    };

    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("transaction_ajouter_delegation_signee Erreur maj pour usager {:?} : {:?}", commande, e))?
    };
    debug!("transaction_reset_webauthn_usager resultat {:?}", resultat);
    if resultat.matched_count == 1 {
        Ok(None)
    } else {
        Err(format!("transaction_reset_webauthn_usager Aucun match pour usager {:?}", commande))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeResetWebauthnUsager {
    #[serde(rename="userId")]
    user_id: String,
    #[serde(rename="resetWebauthn")]
    reset_webauthn: Option<bool>,
    #[serde(rename="resetActivations")]
    reset_activations: Option<bool>,
    #[serde(rename="evictAllSessions")]
    evict_all_sessions: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeAjouterDelegationSignee {
    confirmation: MessageMilleGrille,
    #[serde(rename="userId")]
    user_id: String,
    hostname: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfirmationSigneeDelegationGlobale {
    #[serde(rename="activerDelegation")]
    activer_delegation: Option<bool>,
    challenge: String,
    #[serde(rename="nomUsager")]
    nom_usager: String,
    #[serde(rename="userId")]
    user_id: String,
}

/// Conserver confirmation d'activation tierce (certificat signe)
// async fn activation_tierce<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
//     where M: ValidateurX509 + GenerateurMessages + MongoDao,
// {
//     debug!("Consommer activation_tierce : {:?}", &message.message);
//     let reponse_activation: ReponseActivationTierce = message.message.get_msg().map_contenu(None)?;
//     let fingerprint_pk = reponse_activation.fingerprint_pk.as_str();
//
//     let filtre = doc! {CHAMP_USER_ID: reponse_activation.user_id};
//     let ops = doc! {
//         "$set": {
//             format!("{}.{}.{}", CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk, "associe"): false,
//         },
//         "$currentDate": {
//             CHAMP_MODIFICATION: true,
//             format!("{}.{}.{}", CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk, "date_activation"): true,
//         }
//     };
//     let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
//     let resultat = collection.update_one(filtre, ops, None).await?;
//     debug!("Resultat maj activation_tierce {:?}", resultat);
//
//     // Emettre evenement de maj pour le navigateur en attente
//     let activation = json!({CHAMP_FINGERPRINT_PK: fingerprint_pk});
//     let routage = RoutageMessageAction::builder("CoreMaitreDesComptes", "activationFingerprintPk")
//         .exchanges(vec!(Securite::L2Prive, Securite::L3Protege))
//         .build();
//     middleware.emettre_evenement(routage, &activation).await?;
//
//     // Ok
//     let ok = json!({"ok": true, CHAMP_FINGERPRINT_PK: fingerprint_pk});
//     debug!("activation_tierce ok : {:?}", ok);
//     match middleware.formatter_reponse(&ok, None) {
//         Ok(m) => return Ok(Some(m)),
//         Err(e) => Err(format!("activation_tierce Erreur preparation reponse (2) : {:?}", e))?
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseActivationTierce {
    fingerprint_pk: String,
    #[serde(rename="nomUsager")]
    nom_usager: String,
    #[serde(rename="userId")]
    user_id: String,
}

pub async fn commande_maj_usager_delegations<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer commande_maj_usager_delegations : {:?}", &message.message);

    // Valider contenu
    let commande: TransactionMajUsagerDelegations = message.message.get_msg().map_contenu()?;
    let user_id = commande.user_id.as_str();

    // Commande valide, on sauvegarde et traite la transaction
    let uuid_transaction = message.message.parsed.id.clone();
    sauvegarder_transaction(middleware, &message, NOM_COLLECTION_TRANSACTIONS).await?;
    let transaction: TransactionImpl = message.try_into()?;
    let _ = transaction_maj_usager_delegations(middleware, transaction).await?;
    marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &uuid_transaction, EtatTransaction::Complete).await?;

    // Charger le document de compte et retourner comme reponse
    let reponse = match charger_compte_user_id(middleware, commande.user_id.as_str()).await? {
        Some(compte) => serde_json::to_value(&compte)?,
        None => json!({"ok": false, "err": "Compte usager introuvable apres maj"})  // Compte
    };

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionMajUsagerDelegations {
    compte_prive: Option<bool>,
    delegation_globale: Option<String>,
    #[serde(rename="userId")]
    user_id: String,
}

pub async fn transaction_maj_usager_delegations<M, T>(middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where T: Transaction,
          M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let commande: TransactionMajUsagerDelegations = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion en CommandeAjouterDelegationSignee : {:?}", e))?
    };
    let user_id = commande.user_id.as_str();

    let filtre = doc! {CHAMP_USER_ID: user_id};
    let set_ops = doc! {
        CHAMP_COMPTE_PRIVE: commande.compte_prive,
        CHAMP_DELEGATION_GLOBALE: commande.delegation_globale,
        CHAMP_DELEGATION_DATE: &DateEpochSeconds::now(),
    };
    let ops = doc! {
        "$set": set_ops,
        "$inc": {CHAMP_DELEGATION_VERSION: 1},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur transaction_maj_usager_delegations, echec sauvegarde : {:?}", e))?
    };
    debug!("Resultat commande_maj_usager_delegations : {:?}", resultat);

    if resultat.matched_count != 1 {
        Err(format!("Erreur transaction_maj_usager_delegations usager {} non trouve", user_id))?
    }

    Ok(None)
}

pub async fn commande_supprimer_cles<M>(middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer commande_supprimer_cles : {:?}", &message.message);

    // Valider contenu
    let commande: TransactionSupprimerCles = message.message.get_msg().map_contenu()?;
    let user_id = commande.user_id.as_str();

    // Commande valide, on sauvegarde et traite la transaction
    let uuid_transaction = message.message.parsed.id.clone();
    sauvegarder_transaction(middleware, &message, NOM_COLLECTION_TRANSACTIONS).await?;
    let transaction: TransactionImpl = message.try_into()?;
    let _ = transaction_supprimer_cles(middleware, transaction).await?;
    marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &uuid_transaction, EtatTransaction::Complete).await?;

    Ok(middleware.reponse_ok()?)
}

pub async fn transaction_supprimer_cles<M, T>(middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where T: Transaction,
          M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let commande: TransactionSupprimerCles = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("Erreur conversion en CommandeAjouterDelegationSignee : {:?}", e))?
    };

    let filtre = doc! {CHAMP_USER_ID: &commande.user_id};
    let ops = doc! {
        "$unset": {CHAMP_WEBAUTHN: true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    let resultat = match collection.update_one(filtre, ops, None).await {
        Ok(r) => r,
        Err(e) => Err(format!("transaction_supprimer_cles Erreur maj collection usagers {:?}", e))?
    } ;
    debug!("transaction_supprimer_cles resultat : {:?}", resultat);

    Ok(None)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionSupprimerCles {
    #[serde(rename="userId")]
    user_id: String,
}

fn lire_date_valbson(date: Option<&Value>) -> Result<Option<DateTime<Utc>>, Box<dyn Error>> {
    let mut date_extraite = None;
    if let Some(a) = date {
        if let Some(b) = a.as_object() {
            if let Some(c) = b.get("$date") {
                if let Some(d) = c.as_object() {
                    if let Some(e) = d.get("$numberLong") {
                        if let Some(f) = e.as_str() {
                            let date_usize: i64 = f.parse::<i64>()?;
                            debug!("Date activation : {}", date_usize);
                            date_extraite = Some(date_usize);
                        }
                    }
                }
            }
        }
    }

    match date_extraite {
        Some(d) => {
            let date_secondes = d / 1000;
            let naive_datetime = NaiveDateTime::from_timestamp(date_secondes, 0);
            let datetime_again: DateTime<Utc> = DateTime::from_utc(naive_datetime, Utc);
            Ok(Some(datetime_again))
        },
        None => Ok(None)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TokenUsager {
    user_id: String,
    date_expiration: i64,
    autorisation_register_token: bool,
}

/// Genere un message signe avec user_id et une date d'expiration.
fn generer_token_compte<M,S>(middleware: &M, user_id: S) -> Result<MessageMilleGrille, Box<dyn Error>>
    where M: GenerateurMessages, S: Into<String>
{
    let date_expiration = Utc::now() + chrono::Duration::days(1);
    let token = TokenUsager {
        user_id: user_id.into(),
        date_expiration: date_expiration.timestamp(),
        autorisation_register_token: true,
    };
    let mut token_signe = middleware.formatter_reponse(token, None)?;

    // Retirer certificat
    // token_signe.certificat = None;

    Ok(token_signe)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCertificatSigne {
    ok: bool,
    certificat: Vec<String>,
}

#[cfg(test)]
mod test_integration {
    use crate::test_setup::setup;
    use crate::validateur_pki_mongo::preparer_middleware_pki;
    use millegrilles_common_rust::tokio as tokio;

    use super::*;

    // #[tokio::test]
    // async fn test_() {
    //     setup("test_liste_applications");
    //     let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
    //     futures.push(spawn(async move {
    //
    //         todo!("Test!")
    //
    //     }));
    //     // Execution async du test
    //     futures.next().await.expect("resultat").expect("ok");
    // }

}