use std::sync::Mutex;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, BACKUP_CHAMP_BACKUP_TRANSACTIONS, TRANSACTION_CHAMP_BACKUP_FLAG, TRANSACTION_CHAMP_COMPLETE, TRANSACTION_CHAMP_EVENEMENT_COMPLETE, TRANSACTION_CHAMP_ID, TRANSACTION_CHAMP_TRANSACTION_TRAITEE};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::{prepare_mongodb_domain_indexes, GestionnaireDomaineSimple};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use crate::catalogues_commands::consommer_commande_catalogues;
use crate::catalogues_constants::*;
use crate::catalogues_events::consommer_evenement_catalogues;
use crate::catalogues_maintenance::traiter_cedule_catalogues;
use crate::catalogues_requests::consommer_requete_catalogues;
use crate::catalogues_transactions::aiguillage_transaction_catalogues;
use crate::maitredescomptes_manager::preparer_index_mongodb;

pub struct CataloguesManager {
    pub catalogues_charges: Mutex<bool>
}

impl GestionnaireDomaineV2 for CataloguesManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(COLLECTION_NAME_TRANSACTIONS))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![
            String::from(NOM_COLLECTION_CATALOGUES),
            String::from(NOM_COLLECTION_CATALOGUES_VERSIONS),
        ])
    }
}

impl GestionnaireBusMillegrilles for CataloguesManager {
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
impl ConsommateurMessagesBus for CataloguesManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_requete_catalogues(middleware, message).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_commande_catalogues(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_evenement_catalogues(middleware, message, self).await
    }
}

#[async_trait]
impl AiguillageTransactions for CataloguesManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction_catalogues(middleware, transaction, session).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for CataloguesManager {
    async fn traiter_cedule<M>(&self, middleware: &M, trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        traiter_cedule_catalogues(middleware, trigger, self).await
    }

    async fn preparer_database_mongodb<M>(&self, middleware: &M) -> Result<(), CommonError>
    where
        M: MongoDao + ConfigMessages
    {
        // Handle transaction collection init being overridden
        if let Some(collection_name) = self.get_collection_transactions() {
            prepare_mongodb_domain_indexes(middleware, collection_name).await?;
        }
        // Specialised indexes for domain collections
        preparer_index_mongodb_catalogues(middleware).await?;
        Ok(())
    }
}

pub fn preparer_queues(manager: &CataloguesManager) -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 3.protege seulement
    let requetes = vec![REQUETE_INFO_APPLICATION, REQUETE_LISTE_APPLICATIONS, REQUETE_VERSIONS_APPLICATION];
    for req in requetes {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L3Protege});
    }

    let commandes = vec![
        TRANSACTION_APPLICATION,  // Transaction est initialement recue sous forme de commande uploadee par ServiceMonitor ou autre source
        TRANSACTION_SET_PACKAGE_VERSION,
    ];
    for commande in commandes {
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
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAIN_NAME, TRANSACTION_APPLICATION).into(),
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
    queues.push(QueueType::Triggers (DOMAIN_NAME.into(), Securite::L3Protege));

    queues
}

pub async fn preparer_index_mongodb_catalogues<M>(middleware: &M) -> Result<(), millegrilles_common_rust::error::Error>
where M: MongoDao + ConfigMessages
{
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
