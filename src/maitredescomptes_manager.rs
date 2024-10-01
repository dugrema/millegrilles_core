use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, BACKUP_CHAMP_BACKUP_TRANSACTIONS, TRANSACTION_CHAMP_BACKUP_FLAG, TRANSACTION_CHAMP_COMPLETE, TRANSACTION_CHAMP_EVENEMENT_COMPLETE, TRANSACTION_CHAMP_ID, TRANSACTION_CHAMP_TRANSACTION_TRAITEE};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValide;


use crate::maitredescomptes_constants::*;
use crate::maitredescomptes_requests::consommer_requete_maitredescomptes;

pub struct MaitreDesComptesManager {}

impl GestionnaireDomaineV2 for MaitreDesComptesManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(COLLECTION_NAME_TRANSACTIONS))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![String::from(NOM_COLLECTION_USAGERS)])
    }
}

impl GestionnaireBusMillegrilles for MaitreDesComptesManager {
    fn get_nom_domaine(&self) -> String {
        DOMAIN_NAME.to_string()
    }

    fn get_q_volatils(&self) -> String {
        format!("{}/volatiles", DOMAIN_NAME)
    }

    fn get_q_triggers(&self) -> String {
        format!("{}/triggers", DOMAIN_NAME)
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        preparer_queues(self)
    }
}

#[async_trait]
impl ConsommateurMessagesBus for MaitreDesComptesManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_requete_maitredescomptes(middleware, message).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        todo!()
        // consommer_commande(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        todo!()
        // consommer_evenement(middleware, self, message).await
    }
}

#[async_trait]
impl AiguillageTransactions for MaitreDesComptesManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        todo!()
        // aiguillage_transaction(self, middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for MaitreDesComptesManager {
    async fn traiter_cedule<M>(&self, middleware: &M, trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        Ok(())
    }
}

pub fn preparer_queues(manager: &MaitreDesComptesManager) -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 1.public
    let requetes_publiques: Vec<&str> = vec![
        REQUETE_CHARGER_USAGER,
        REQUETE_COOKIE_USAGER,
        // REQUETE_GET_TOKEN_SESSION,
    ];
    for req in requetes_publiques {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L1Public});
    }

    let requetes_privee: Vec<&str> = vec![
        REQUETE_GET_CSR_RECOVERY_PARCODE,
        REQUETE_PASSKEYS_USAGER,
    ];
    for req in requetes_privee {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L2Prive});
    }

    let requetes_protegees: Vec<&str> = vec![
        REQUETE_LISTE_USAGERS,
        REQUETE_LISTE_PROPRIETAIRES,
        REQUETE_USERID_PAR_NOMUSAGER
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L3Protege});
    }

    let commandes_publiques: Vec<&str> = vec![
        // Commandes
        COMMANDE_AUTHENTIFIER_WEBAUTHN,
        COMMANDE_SUPPRIMER_COOKIE,
    ];
    for commande in commandes_publiques {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAIN_NAME, commande), exchange: Securite::L1Public});
    }

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
        COMMANDE_SUPPRIMER_COOKIE,
    ];
    for commande in commandes {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAIN_NAME, commande), exchange: Securite::L2Prive});
        // rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAIN_NAME, commande), exchange: Securite::L3Protege});
    }

    let commandes_protegees: Vec<&str> = vec![
        TRANSACTION_MAJ_USAGER_DELEGATIONS,
        TRANSACTION_RESET_WEBAUTHN_USAGER,
    ];
    for commande in commandes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAIN_NAME, commande), exchange: Securite::L3Protege});
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
        rk_transactions.push(ConfigRoutingExchange {routing_key: format!("transaction.{}.{}", DOMAIN_NAME, transaction), exchange: Securite::L4Secure});
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
    queues.push(QueueType::Triggers (DOMAIN_NAME.into(), Securite::L3Protege));

    queues
}

pub async fn preparer_index_mongodb<M>(middleware: &M) -> Result<(), millegrilles_common_rust::error::Error>
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
        COLLECTION_NAME_TRANSACTIONS,
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
        COLLECTION_NAME_TRANSACTIONS,
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
        COLLECTION_NAME_TRANSACTIONS,
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

    let options_unique_cookie = IndexOptions {
        nom_index: Some(String::from(INDEX_COOKIE_UNIQUE)),
        unique: true
    };
    let champs_index_cookie = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_USER_ID), direction: 1},
        ChampIndex {nom_champ: String::from("hostname"), direction: 1},
        ChampIndex {nom_champ: String::from("challenge"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_COOKIES,
        champs_index_cookie,
        Some(options_unique_cookie)
    ).await?;

    Ok(())
}
