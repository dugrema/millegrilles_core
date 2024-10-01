use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, BACKUP_CHAMP_BACKUP_TRANSACTIONS, PKI_DOCUMENT_CHAMP_FINGERPRINT, PKI_DOMAINE_CERTIFICAT_NOM, PKI_TRANSACTION_NOUVEAU_CERTIFICAT, TRANSACTION_CHAMP_BACKUP_FLAG, TRANSACTION_CHAMP_COMPLETE, TRANSACTION_CHAMP_EVENEMENT_COMPLETE, TRANSACTION_CHAMP_ID, TRANSACTION_CHAMP_TRANSACTION_TRAITEE};
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
use crate::pki_commands::consommer_commande_pki;
use crate::pki_constants::*;
use crate::pki_events::consommer_evenement_pki;
use crate::pki_requests::consommer_requete_pki;
use crate::pki_transactions::aiguillage_transaction_pki;

pub struct PkiManager {}

impl GestionnaireDomaineV2 for PkiManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(COLLECTION_NAME_TRANSACTIONS))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![String::from(COLLECTION_CERTIFICAT_NOM)])
    }
}

impl GestionnaireBusMillegrilles for PkiManager {
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
impl ConsommateurMessagesBus for PkiManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_requete_pki(middleware, message).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_commande_pki(middleware, message).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_evenement_pki(middleware, message).await
    }
}

#[async_trait]
impl AiguillageTransactions for PkiManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction_pki(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for PkiManager {
    async fn traiter_cedule<M>(&self, _middleware: &M, _trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        Ok(())
    }
}

pub fn preparer_queues(manager: &PkiManager) -> Vec<QueueType> {
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
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.CorePki.{}", PKI_COMMANDE_SAUVEGARDER_CERTIFICAT), exchange: Securite::L3Protege});
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

    // let mut rk_transactions = Vec::new();
    // rk_transactions.push(ConfigRoutingExchange {
    //     routing_key: format!("transaction.CorePki.{}", PKI_TRANSACTION_NOUVEAU_CERTIFICAT).into(),
    //     exchange: Securite::L4Secure}
    // );
    //
    // // Queue de transactions
    // queues.push(QueueType::ExchangeQueue (
    //     ConfigQueue {
    //         nom_queue: NOM_Q_TRANSACTIONS_PKI.into(),
    //         routing_keys: rk_transactions,
    //         ttl: None,
    //         durable: true,
    //         autodelete: false,
    //     }
    // ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAIN_NAME.into(), Securite::L3Protege));

    queues
}

pub async fn preparer_index_mongodb<M>(middleware: &M) -> Result<(), millegrilles_common_rust::error::Error>
where M: MongoDao + ConfigMessages
{
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
