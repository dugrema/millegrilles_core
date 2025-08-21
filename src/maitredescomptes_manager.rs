use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Mutex;
use log::debug;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chiffrage_cle::{ajouter_cles_domaine, generer_cle_v2, get_cles_rechiffrees_v2};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, BACKUP_CHAMP_BACKUP_TRANSACTIONS, DOMAINE_NOM_MAITREDESCOMPTES, TRANSACTION_CHAMP_BACKUP_FLAG, TRANSACTION_CHAMP_COMPLETE, TRANSACTION_CHAMP_EVENEMENT_COMPLETE, TRANSACTION_CHAMP_ID, TRANSACTION_CHAMP_TRANSACTION_TRAITEE};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::{prepare_mongodb_domain_indexes, GestionnaireDomaineSimple};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::CleSecreteMgs4;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::{Cipher, CleChiffrageHandler, CleChiffrageX25519Impl, CleDechiffrageX25519Impl, CleSecreteSerialisee, Decipher};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, CleSecreteCipher, DecipherMgs4};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_mgs4::CleSecreteCipher::CleDerivee;
use millegrilles_common_rust::millegrilles_cryptographie::x25519::CleSecreteX25519;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use crate::maitredescomptes_commands::consommer_commande_maitredescomptes;
use crate::maitredescomptes_common::SecretKeyHandler;
use crate::maitredescomptes_constants::*;
use crate::maitredescomptes_events::consommer_evenement_maitredescomptes;
use crate::maitredescomptes_requests::consommer_requete_maitredescomptes;
use crate::maitredescomptes_transactions::aiguillage_transaction_maitredescomptes;

pub struct MaitreDesComptesManager {
    /// Lazy-initialized secret key handler. The key is created on first use.
    pub key_handler: Mutex<Option<SecretKeyHandler>>,
    /// Cache of keys used to decrypt content previously generated. Key is the key_id.
    pub key_cache: Mutex<HashMap<String, CleSecreteMgs4>>,
}

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
        consommer_commande_maitredescomptes(middleware, self, message).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_evenement_maitredescomptes(middleware, message).await
    }
}

#[async_trait]
impl AiguillageTransactions for MaitreDesComptesManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction_maitredescomptes(middleware, transaction, session).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for MaitreDesComptesManager {
    async fn traiter_cedule<M>(&self, _middleware: &M, _trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        Ok(())
    }

    async fn preparer_database_mongodb<M>(&self, middleware: &M) -> Result<(), CommonError>
    where
        M: MongoDao + ConfigMessages
    {
        // Handle transaction collection init being overridden
        if let Some(collection_name) = self.get_collection_transactions() {
            prepare_mongodb_domain_indexes(middleware, collection_name).await?;
        }
        preparer_index_mongodb(middleware).await?;  // Specialised indexes for domain collections
        Ok(())
    }
}

impl MaitreDesComptesManager {
    pub async fn encrypt_string<M,S>(&self, middleware: &M, value: S) -> Result<EncryptedDocument, CommonError>
        where M: GenerateurMessages + CleChiffrageHandler, S: Into<String>
    {
        let (secret_key, key_id) = {
            let mutex = self.key_handler.lock().expect("key_handler.lock()");
            match &*mutex {
                Some(handler) => (Some(handler.encryption_key.clone()), Some(handler.key_id.clone())),
                None => (None, None)
            }
        };

        let (secret_key, decryption_info) = match secret_key {
            Some(secret_key) => (secret_key, None),
            None => {
                // Generate and save a new encryption key with the keymaster
                let (decryption_info, secret_key) = generer_cle_v2(middleware, vec![DOMAINE_NOM_MAITREDESCOMPTES])?;
                if let Some(cle_id) = decryption_info.cle_id.clone() {
                    (CleDerivee((cle_id, secret_key)), Some(decryption_info))
                } else {
                    Err("KeyId was not generated for the key")?
                }
            }
        };

        let value = value.into();
        let cipher = CipherMgs4::with_secret(secret_key.clone())?;
        let encrypted_value = cipher.to_vec(value.as_bytes())?;
        let mut encrypted_document = EncryptedDocument::try_from(encrypted_value)?;
        encrypted_document.verification = None;  // Not used
        encrypted_document.cle_id = key_id;  // Put key_id in. No effect if the key was just generated

        if let Some(decryption_info) = decryption_info {
            match decryption_info.signature {
                Some(signature) => {
                    // Save key_id in document
                    let key_id = signature.get_cle_ref()?.to_string();
                    encrypted_document.cle_id = Some(key_id.clone());

                    match decryption_info.cles {
                        Some(keys) => {
                            let keys = keys.into_iter().collect();
                            ajouter_cles_domaine(middleware, signature, keys, Some(3_000)).await?;
                        }
                        None => Err("No keymaster decryption keys were generated")?
                    }

                    // Save key in memory for reuse
                    let key_handler = SecretKeyHandler {key_id, encryption_key: secret_key};
                    let mut mutex = self.key_handler.lock().expect("key_handler.lock()");
                    mutex.replace(key_handler);
                }
                None => Err("No key domain signature was generated")?
            }
        }

        encrypted_document.cle = None;  // Cleanup

        Ok(encrypted_document)
    }

    pub async fn decrypt_document<M>(&self, middleware: &M, document: &EncryptedDocument) -> Result<Vec<u8>, CommonError>
        where M: GenerateurMessages
    {
        let key_id = match &document.cle_id {
            Some(id) => id,
            None => Err("decrypt_document Document is missing the key_id")?
        };
        let secret_key = {
            let mutex = self.key_cache.lock().expect("key_cache.lock()");
            match (*mutex).get(key_id) {
                Some(secret) => Some(secret.clone()),
                None => None
            }
        };

        let secret_key = match secret_key {
            None => {
                // Load the key
                debug!("Load secret key {} from KeyMaster", key_id);
                let mut keys = get_cles_rechiffrees_v2(middleware, DOMAINE_NOM_MAITREDESCOMPTES, vec![key_id], Some(false)).await?;
                let secret: CleSecreteSerialisee = match keys.pop() {
                    Some(secret) => secret.try_into()?,
                    None => Err("Key not received")?
                };
                let secret = secret.cle_secrete()?;

                // Save key in the cache
                let mut mutex = self.key_cache.lock().expect("key_cache.lock()");
                if mutex.len() >= 128 {    // About 4kb of keys max
                    mutex.clear(); // Clear the whole cache, start over.
                }
                mutex.insert(key_id.clone(), secret.clone());

                secret
            }
            Some(secret_key) => secret_key,
        };

        let decrypted_content = document.clone().decrypt_with_secret(&secret_key)?;

        Ok(decrypted_content)
    }
}

pub fn preparer_queues(_manager: &MaitreDesComptesManager) -> Vec<QueueType> {
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
        COMMAND_GENERATE_OTP,
        TRANSACTION_REGISTER_OTP,
        COMMAND_AUTHENTICATE_TOTP,
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

    // let mut rk_transactions = Vec::new();
    // let transactions: Vec<&str> = vec![
    //     TRANSACTION_INSCRIRE_USAGER,
    //     TRANSACTION_AJOUTER_CLE,
    //     TRANSACTION_AJOUTER_DELEGATION_SIGNEE,
    //     TRANSACTION_MAJ_USAGER_DELEGATIONS,
    //     TRANSACTION_SUPPRIMER_CLES,
    //     TRANSACTION_RESET_WEBAUTHN_USAGER,
    // ];
    // for transaction in transactions {
    //     rk_transactions.push(ConfigRoutingExchange {routing_key: format!("transaction.{}.{}", DOMAIN_NAME, transaction), exchange: Securite::L4Secure});
    // }
    //
    // // Queue de transactions
    // queues.push(QueueType::ExchangeQueue (
    //     ConfigQueue {
    //         nom_queue: NOM_Q_TRANSACTIONS.into(),
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
