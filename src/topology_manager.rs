use crate::topology_commands::consommer_commande_topology;
use crate::topology_constants::*;
use crate::topology_events::consommer_evenement_topology;
use crate::topology_maintenance::traiter_cedule;
use crate::topology_requests::consommer_requete_topology;
use crate::topology_transactions::aiguillage_transaction_topology;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, BACKUP_EVENEMENT_MAJ, EVENEMENT_PRESENCE_DOMAINE, REQUETE_GET_FILEHOST_FOR_INSTANCE, TRANSACTION_CHAMP_IDMG};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::{prepare_mongodb_domain_indexes, GestionnaireDomaineSimple};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use crate::maitredescomptes_manager::preparer_index_mongodb;

pub struct TopologyManager {}

impl GestionnaireDomaineV2 for TopologyManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(COLLECTION_NAME_TRANSACTIONS))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![
            String::from(NOM_COLLECTION_INSTANCE_CONFIGURATION),
        ])
    }
}

impl GestionnaireBusMillegrilles for TopologyManager {
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
impl ConsommateurMessagesBus for TopologyManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_requete_topology(middleware, message).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_commande_topology(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_evenement_topology(middleware, message, self).await
    }
}

#[async_trait]
impl AiguillageTransactions for TopologyManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction_topology(middleware, transaction, session).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for TopologyManager {
    async fn traiter_cedule<M>(&self, middleware: &M, trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        traiter_cedule(middleware, trigger).await
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
        // preparer_index_mongodb(middleware).await?;
        preparer_index_mongodb_topologie(middleware).await?;
        Ok(())
    }
}

pub fn preparer_queues(manager: &TopologyManager) -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    // RK 3.protege seulement
    let requetes_protegees = vec![
        REQUETE_LISTE_DOMAINES,
        REQUEST_SERVER_INSTANCES,
        REQUEST_SERVER_INSTANCE_APPLICATIONS,
        REQUEST_SERVER_INSTANCE_CONFIGURATION,
        REQUETE_CONFIGURATION_FICHIERS,
        REQUETE_GET_CLEID_BACKUP_DOMAINE,
        REQUETE_CONFIGURATION_FILEHOSTS,
        REQUEST_FILEHOSTS_FOR_FUUIDS,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L3Protege });
    }

    // RK 2.prive
    let requetes_privees = vec![
        REQUETE_LISTE_DOMAINES,
        REQUETE_APPLICATIONS_DEPLOYEES,
        REQUETE_USERAPPS_DEPLOYEES,
        REQUETE_RESOLVE_IDMG,
        REQUETE_FICHE_MILLEGRILLE,
        REQUETE_APPLICATIONS_TIERS,
        REQUETE_CONSIGNATION_FICHIERS,
        REQUETE_GET_CLE_CONFIGURATION,
    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L2Prive });
    }

    // RK 1.public
    let requetes_publiques = vec![
        REQUETE_FICHE_MILLEGRILLE,
        REQUETE_APPLICATIONS_TIERS,
        REQUETE_CONSIGNATION_FICHIERS,
        REQUETE_GET_TOKEN_HEBERGEMENT,
        REQUETE_GET_FILEHOSTS,
        REQUETE_GET_FILECONTROLERS,
        REQUETE_GET_FILEHOST_FOR_INSTANCE,
        REQUETE_GET_FILEHOST_FOR_EXTERNAL,
        REQUETE_GET_DOMAINS_BACKUP_VERSIONS,
    ];
    for req in requetes_publiques {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, req), exchange: Securite::L1Public });
    }

    let commandes: Vec<&str> = vec![
        //TRANSACTION_APPLICATION,  // Transaction est initialement recue sous forme de commande uploadee par ServiceMonitor ou autre source
        TRANSACTION_MONITOR,
        TRANSACTION_SUPPRIMER_INSTANCE,
        TRANSACTION_CONFIGURER_CONSIGNATION,
        TRANSACTION_SET_FICHIERS_PRIMAIRE,
        TRANSACTION_SET_FILEHOST_FOR_INSTANCE,
        TRANSACTION_SUPPRIMER_CONSIGNATION_INSTANCE,
        TRANSACTION_FILEHOST_DEFAULT,

        COMMANDE_AJOUTER_CONSIGNATION_HEBERGEE,
        COMMANDE_SET_CLEID_BACKUP_DOMAINE,
        COMMANDE_CLAIM_AND_FILEHOST_VISITS_FOR_FUUIDS,
        COMMANDE_FILEHOST_RESET_VISITS_CLAIMS,
        COMMANDE_FILEHOST_RESET_TRANSFERS,
        COMMANDE_BACKUP_SET_DOMAIN_VERSION,
        COMMAND_DOMAIN_CLAIM_FILES,
    ];
    for commande in commandes {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, commande), exchange: Securite::L3Protege });
    }

    let commandes_publiques: Vec<&str> = vec![
        TRANSACTION_FILEHOST_ADD,
        TRANSACTION_FILEHOST_UPDATE,
        TRANSACTION_FILEHOST_DELETE,
        COMMANDE_FILE_VISIT,
        COMMANDE_FILEHOST_BATCH_TRANSFERS,
    ];
    for c in commandes_publiques {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, c), exchange: Securite::L1Public });
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

    // Evenements publics
    rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.filecontroler.{}", EVENEMENT_FILEHOST_USAGE), exchange: Securite::L1Public });
    rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.filecontroler.{}", EVENEMENT_FILEHOST_NEWFUUID), exchange: Securite::L1Public });

    // Presence de domaines se fait sur l'evenement du domaine specifique (*)
    rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.*.{}", EVENEMENT_PRESENCE_DOMAINE), exchange: Securite::L3Protege });
    rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_FICHIERS, EVENEMENT_PRESENCE_FICHIERS), exchange: Securite::L2Prive });
    rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.*.{}", BACKUP_EVENEMENT_MAJ), exchange: Securite::L1Public });

    for exchange in vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege] {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.instance.{}", EVENEMENT_PRESENCE_INSTANCE), exchange: exchange.clone() });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.instance.*.{}", EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS), exchange });
    }

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

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers(DOMAIN_NAME.into(), Securite::L3Protege));

    queues
}

pub async fn preparer_index_mongodb_topologie<M>(middleware: &M) -> Result<(), millegrilles_common_rust::error::Error>
where M: MongoDao + ConfigMessages
{
    // // Index noeuds
    // let options_unique_noeuds = IndexOptions {
    //     nom_index: Some(String::from(INDEX_NOEUDS)),
    //     unique: true,
    // };
    // let champs_index_noeuds = vec!(
    //     ChampIndex { nom_champ: String::from(CHAMP_NOEUD_ID), direction: 1 },
    // );
    // middleware.create_index(
    //     middleware,
    //     NOM_COLLECTION_NOEUDS,
    //     champs_index_noeuds,
    //     Some(options_unique_noeuds),
    // ).await?;

    let options_unique_server_instances = IndexOptions {
        nom_index: Some(String::from("server_instance_id")),
        unique: true,
    };
    let champs_index_server_instances = vec!(
        ChampIndex { nom_champ: String::from("instance_id"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_INSTANCE_STATUS,
        champs_index_server_instances,
        Some(options_unique_server_instances),
    ).await?;

    let options_unique_server_configured_applications = IndexOptions {
        nom_index: Some(String::from("unique_id")),
        unique: true,
    };
    let champs_index_server_configured_applications = vec!(
        ChampIndex { nom_champ: String::from("instance_id"), direction: 1 },
        ChampIndex { nom_champ: String::from("app_name"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_INSTANCE_CONFIGURED_APPLICATIONS,
        champs_index_server_configured_applications ,
        Some(options_unique_server_configured_applications),
    ).await?;

    let options_unique_server_containers = IndexOptions {
        nom_index: Some(String::from("unique_id")),
        unique: true,
    };
    let champs_index_server_containers = vec!(
        ChampIndex { nom_champ: String::from("instance_id"), direction: 1 },
        ChampIndex { nom_champ: String::from("service_name"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_INSTANCE_CONTAINERS,
        champs_index_server_containers ,
        Some(options_unique_server_containers),
    ).await?;

    let options_unique_server_services = IndexOptions {
        nom_index: Some(String::from("unique_id")),
        unique: true,
    };
    let champs_index_server_services = vec!(
        ChampIndex { nom_champ: String::from("instance_id"), direction: 1 },
        ChampIndex { nom_champ: String::from("service_name"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_INSTANCE_SERVICES,
        champs_index_server_services,
        Some(options_unique_server_services),
    ).await?;

    let options_unique_server_webapps = IndexOptions {
        nom_index: Some(String::from("unique_id")),
        unique: true,
    };
    let champs_index_server_webapps = vec!(
        ChampIndex { nom_champ: String::from("instance_id"), direction: 1 },
        ChampIndex { nom_champ: String::from("app_name"), direction: 1 },
        ChampIndex { nom_champ: String::from("url"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_INSTANCE_WEBAPPS,
        champs_index_server_webapps,
        Some(options_unique_server_webapps),
    ).await?;

    let options_unique_server_configuration = IndexOptions {
        nom_index: Some(String::from("unique_id")),
        unique: true,
    };
    let champs_index_server_configuration = vec!(
        ChampIndex { nom_champ: String::from("instance_id"), direction: 1 },
        ChampIndex { nom_champ: String::from("name"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_INSTANCE_CONFIGURATION,
        champs_index_server_configuration,
        Some(options_unique_server_configuration),
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

    // Filehosts
    // Index table fichiers
    let options_unique_filehosts = IndexOptions {
        nom_index: Some(String::from("filehost_unique")),
        unique: true,
    };
    let champs_index_filehosts = vec!(
        ChampIndex { nom_champ: String::from("filehost_id"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_FILEHOSTS,
        champs_index_filehosts,
        Some(options_unique_filehosts),
    ).await?;

    // Visites et claims pour fuuids
    // Index table fichiers
    let options_unique_claims = IndexOptions {
        nom_index: Some(String::from("fuuids")),
        unique: true,
    };
    let champs_index_claims = vec!(
        ChampIndex { nom_champ: String::from("fuuid"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_FILEHOSTING_FUUIDS,
        champs_index_claims,
        Some(options_unique_claims),
    ).await?;

    // Transferts entre filehosts
    // Index table fichiers
    let options_unique_transferts_filehostfuuid = IndexOptions {
        nom_index: Some(String::from("filehost_fuuid")),
        unique: true,
    };
    let champs_index__transferts_filehostfuuid = vec!(
        ChampIndex { nom_champ: String::from("destination_filehost_id"), direction: 1 },
        ChampIndex { nom_champ: String::from("fuuid"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_FILEHOSTING_TRANSFERS,
        champs_index__transferts_filehostfuuid,
        Some(options_unique_transferts_filehostfuuid),
    ).await?;

    Ok(())
}
