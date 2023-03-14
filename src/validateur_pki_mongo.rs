use std::collections::{HashMap, HashSet};
use std::collections::hash_map::RandomState;
use std::error::Error;
use std::sync::{Arc, Mutex};

use log::{debug, info, warn, error};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::{BackupStarter, CommandeBackup, thread_backup};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{emettre_commande_certificat_maitredescles, EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ValidateurX509, ValidateurX509Impl, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::{Chiffreur, Dechiffreur, MgsCipherData, CleChiffrageHandler, ChiffrageFactory, ChiffrageFactoryImpl};
use millegrilles_common_rust::chiffrage_aesgcm::CipherMgs2;
use millegrilles_common_rust::chiffrage_streamxchacha20poly1305::CipherMgs4;
// use millegrilles_common_rust::chiffrage_chacha20poly1305::{CipherMgs3, DecipherMgs3, Mgs3CipherData, Mgs3CipherKeys};
use millegrilles_common_rust::configuration::{ConfigMessages, ConfigurationMessagesDb, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl, RoutageMessageReponse, RoutageMessageAction};
use millegrilles_common_rust::middleware::{configurer as configurer_messages, EmetteurCertificat, formatter_message_certificat, IsConfigurationPki, ReponseCertificatMaitredescles, upsert_certificat, Middleware, MiddlewareMessages, RedisTrait, ChiffrageFactoryTrait, MiddlewareRessources, RabbitMqTrait, EmetteurNotificationsTrait};
use millegrilles_common_rust::middleware_db::MiddlewareDb;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao, MongoDaoImpl, initialiser as initialiser_mongodb};
use millegrilles_common_rust::mongodb::Database;
use millegrilles_common_rust::mongodb::options::FindOptions;
use millegrilles_common_rust::notifications::NotificationMessageInterne;
use millegrilles_common_rust::openssl::x509::store::X509Store;
use millegrilles_common_rust::openssl::x509::X509;
use millegrilles_common_rust::rabbitmq_dao::{Callback, EventMq, NamedQueue, QueueType, run_rabbitmq, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio as tokio;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::Receiver, Notify};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage, verifier_message};
use millegrilles_common_rust::redis_dao::RedisDao;
use millegrilles_common_rust::tokio::sync::mpsc::Sender;
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::core_pki::{COLLECTION_CERTIFICAT_NOM, CorePkiCertificat, DOMAINE_NOM as PKI_DOMAINE_NOM};

// Middleware avec MongoDB et validateur X509 lie a la base de donnees
pub struct MiddlewareDbPki {
    ressources: MiddlewareRessources,
    pub mongo: Arc<MongoDaoImpl>,
    pub redis: Option<RedisDao>,
    validateur: Arc<ValidateurX509Database>,
    tx_backup: Sender<CommandeBackup>,
    chiffrage_factory: Arc<ChiffrageFactoryImpl>,
}

impl MiddlewareDbPki {}

impl MiddlewareMessages for MiddlewareDbPki {}

impl Middleware for MiddlewareDbPki {}

#[async_trait]
impl EmetteurNotificationsTrait for MiddlewareDbPki {
    async fn emettre_notification_proprietaire(
        &self, contenu: NotificationMessageInterne, niveau: &str, expiration: Option<i64>, destinataires: Option<Vec<String>>
    )
        -> Result<(), Box<dyn Error>>
    {
        self.ressources.emetteur_notifications.emettre_notification_proprietaire(
            self, contenu, niveau, expiration, destinataires).await
    }
}

impl RedisTrait for MiddlewareDbPki {
    fn get_redis(&self) -> Option<&RedisDao> { self.redis.as_ref() }
}

impl RabbitMqTrait for MiddlewareDbPki {
    fn ajouter_named_queue<S>(&self, queue_name: S, named_queue: NamedQueue) where S: Into<String> {
        self.ressources.rabbitmq.ajouter_named_queue(queue_name, named_queue)
    }
    fn est_connecte(&self) -> bool { self.ressources.rabbitmq.est_connecte() }
    fn notify_attendre_connexion(&self) -> Arc<Notify> { self.ressources.rabbitmq.notify_attendre_connexion() }
}

impl ChiffrageFactoryTrait for MiddlewareDbPki {
    fn get_chiffrage_factory(&self) -> &ChiffrageFactoryImpl {
        self.chiffrage_factory.as_ref()
    }
}

impl ChiffrageFactory for MiddlewareDbPki {
    fn get_chiffreur(&self) -> Result<CipherMgs4, String> {
        self.chiffrage_factory.get_chiffreur()
    }

    fn get_chiffreur_mgs2(&self) -> Result<CipherMgs2, String> {
        self.chiffrage_factory.get_chiffreur_mgs2()
    }

    // fn get_chiffreur_mgs3(&self) -> Result<CipherMgs3, String> {
    //     self.chiffrage_factory.get_chiffreur_mgs3()
    // }

    fn get_chiffreur_mgs4(&self) -> Result<CipherMgs4, String> {
        self.chiffrage_factory.get_chiffreur_mgs4()
    }
}

/// Validateur X509 backe par une base de donnees (Mongo)
/// Permet de charger les certificats et generer les transactions pour les certificats inconnus.
struct ValidateurX509Database {
    mongo_dao: Arc<MongoDaoImpl>,
    redis_dao: Option<RedisDao>,
    validateur: Arc<ValidateurX509Impl>,
    generateur_messages: Arc<GenerateurMessagesImpl>
}

impl ValidateurX509Database {

    pub fn new(mongo_dao: Arc<MongoDaoImpl>, redis_dao: Option<RedisDao>, validateur: Arc<ValidateurX509Impl>, generateur_messages: Arc<GenerateurMessagesImpl>) -> ValidateurX509Database {
        ValidateurX509Database {
            mongo_dao,
            redis_dao,
            validateur,
            generateur_messages
        }
    }

    pub async fn entretien(&self) {
        debug!("ValidateurX509Database: Entretien ValidateurX509Database");
        self.validateur.entretien_validateur().await;
    }

    async fn upsert_enveloppe(&self, enveloppe: &EnveloppeCertificat) -> Result<(), String> {
        debug!("Upserting enveloppe {:?}, CA: {:?}", enveloppe.get_pem_vec(), enveloppe.get_pem_ca());

        let db = self.mongo_dao.get_database()?;
        let collection = db.collection(COLLECTION_CERTIFICAT_NOM);

        match upsert_certificat(enveloppe, collection, None).await? {
            Some(_) => {
                debug!("Certificat upserted, creer transaction pour sauvegarde permanente");
                // let domaine_action = format!("{}.{}", PKI_DOMAINE_NOM, PKI_TRANSACTION_NOUVEAU_CERTIFICAT);

                let fingerprint_certs = enveloppe.get_pem_vec();
                let mut pem_vec = Vec::new();
                for fp_cert in fingerprint_certs {
                    pem_vec.push(fp_cert.pem);
                }
                let pems = pem_vec.join("\n");
                let ca = enveloppe.get_pem_ca()?;

                let contenu = json!({
                    "pem": pems,
                    "ca": ca,
                });
                // let message = self.generateur_messages.formatter_message(
                //     contenu,
                //     Some(&domaine_action),
                //     None
                // );

                let routage = RoutageMessageAction::builder(PKI_DOMAINE_NOM,PKI_TRANSACTION_NOUVEAU_CERTIFICAT)
                    .exchanges(vec![Securite::L4Secure])
                    .build();
                match self.generateur_messages.soumettre_transaction(routage, &contenu,false).await {
                    Ok(_) => (),
                    Err(e) => error!("Erreur soumission transaction pour nouveau certificat : {}", e),
                };

                // Meme si la transaction echoue, le certificat est deja sauvegarde (dirty=true).
                Ok(())
            },
            None => Ok(()),
        }
    }

}

#[async_trait]
impl ValidateurX509 for ValidateurX509Database {

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        debug!("ValidateurX509Database: charger_enveloppe!");
        // let resultat = self.charger_cert_db();

        let enveloppe = self.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await?;

        // Verifier si le certificat existe dans la base de donnes, creer transaction au besoin
        self.upsert_enveloppe(&enveloppe).await?;

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, bool) {
        let (enveloppe, persiste) = self.validateur.cacher(certificat).await;

        let persiste = if ! persiste {
            // Conserver dans MongoDB
            let persiste = match self.upsert_enveloppe(enveloppe.as_ref()).await {
                Ok(()) => {
                    self.validateur.set_flag_persiste(enveloppe.fingerprint.as_str());
                    true
                },
                Err(e) => {
                    error!("Erreur sauvegarde certificat dans MongoDB : {:?}", e);
                    false
                }
            };

            // Cacher dans redis (utilise par tous les autres services)
            match self.redis_dao.as_ref() {
                Some(redis) => {
                    match redis.save_certificat(enveloppe.as_ref()).await {
                        Ok(()) => debug!("Certificat {} sauvegarde dans redis", enveloppe.fingerprint),
                        Err(e) => warn!("Erreur cache certificat {} dans redis : {:?}", enveloppe.fingerprint, e)
                    }
                },
                None => ()
            }

            // Retourner flag sauvegarde dans MongoDB
            persiste
        } else {
            persiste
        };

        /// Retourne le certificat et indicateur qu'il a ete persiste
        (enveloppe, persiste)
    }

    fn set_flag_persiste(&self, fingerprint: &str) {
        self.validateur.set_flag_persiste(fingerprint)
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        debug!("ValidateurX509Database: get_certificat {}", fingerprint);
        match self.validateur.get_certificat(fingerprint).await {
            Some(enveloppe) => Some(enveloppe),
            None => {
                // Tenter de charger a partir de redis
                let cert_option = if let Some(redis) = self.redis_dao.as_ref() {
                    match redis.get_certificat(fingerprint).await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!("Erreur chargement certificat redis : {:?}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                if let Some(certificat) = cert_option {
                    let ca_pem = match certificat.ca.as_ref() {
                        Some(c) => Some(c.as_str()),
                        None => None
                    };
                    match self.validateur.charger_enveloppe(
                                &certificat.pems,
                                None,
                                ca_pem
                    ).await {
                        Ok(enveloppe) => {
                            debug!("get_certificat Certificat {} charge de la DB", fingerprint);
                            if let Err(e) = self.upsert_enveloppe(&enveloppe).await {
                                warn!("Erreur sauvegarde certificat : {:?}", e);
                            }
                            return Some(enveloppe)
                        },
                        Err(_) => ()
                    }
                }

                // Tenter de charger a partir de la base de donnees
                match self.mongo_dao.get_database() {
                    Ok(db) => {

                        let collection = db.collection::<Document>(COLLECTION_CERTIFICAT_NOM);
                        let filtre = doc! {
                            PKI_DOCUMENT_CHAMP_FINGERPRINT: fingerprint,
                        };
                        let result = collection.find_one(filtre, None).await;
                        match result {
                            Ok(option) => match option {
                                Some(document) => {
                                    let certificat_pki: CorePkiCertificat = match convertir_bson_deserializable(document) {
                                        Ok(c) => c,
                                        Err(e) => {
                                            error!("get_certificat Erreur mapping certificat bson : {:?}", e);
                                            return None
                                        }
                                    };

                                    let ca_pem = match &certificat_pki.ca {
                                        Some(c) => Some(c.as_str()),
                                        None => None
                                    };
                                    match self.validateur.charger_enveloppe(
                                        &certificat_pki.certificat,
                                        Some(certificat_pki.fingerprint.as_str()),
                                        ca_pem
                                    ).await {
                                        Ok(enveloppe) => {
                                            debug!("get_certificat Certificat {} charge de la DB", fingerprint);
                                            Some(enveloppe)
                                        },
                                        Err(_) => None,
                                    }
                                },
                                None => {
                                    debug!("get_certificat Certificat inconnu (pas dans la DB) {:?}", fingerprint);
                                    None
                                },
                            },
                            Err(e) => {
                                debug!("get_certificat Erreur!!! {:?}", e);
                                None
                            },
                        }
                    },
                    Err(e) => {
                        debug!("get_certificatErreur {:?}", e);
                        None
                    }
                }
            }
        }
    }

    fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
        self.validateur.certificats_persister()
    }

    fn idmg(&self) -> &str {
        self.validateur.idmg()
    }

    fn ca_pem(&self) -> &str {
        self.validateur.ca_pem()
    }

    fn ca_cert(&self) -> &X509 {
        self.validateur.ca_cert()
    }

    fn store(&self) -> &X509Store {
        self.validateur.store()
    }

    fn store_notime(&self) -> &X509Store {
        self.validateur.store_notime()
    }

    async fn entretien_validateur(&self) {

        debug!("ValidateurX509Database.entretien_validateur Debut entretien certificats");

        // Conserver tous les certificats qui ne sont pas encore persiste
        if let Some(redis) = self.redis_dao.as_ref() {
            // Conserver les certificats qui n'ont pas encore ete persistes
            for certificat in self.validateur.certificats_persister().iter() {
                debug!("entretien_validateur Persister certificat {}", certificat.fingerprint);

                // Sauvegarder dans MongoDB
                match self.upsert_enveloppe(certificat.as_ref()).await {
                    Ok(()) => self.validateur.set_flag_persiste(certificat.fingerprint.as_str()),
                    Err(e) => {
                        error!("Erreur sauvegarde certificat dans MongoDB : {:?}", e);
                    }
                };
                // Sauvegarder dans redis
                if let Err(e) = redis.save_certificat(certificat.as_ref()).await {
                    warn!("entretien_validateur Erreur sauvegarde certificat {:?}", e)
                }
            }

            // Synchroniser certificats de redis vers mongodb
            if let Err(e) = synchroniser_certificats(&self, redis, self.mongo_dao.as_ref()).await {
                warn!("entretien_validateur Erreur synchronisation certificats entre redis et mongo : {:?}", e)
            }
        }

        self.validateur.entretien_validateur().await;
    }

}

async fn synchroniser_certificats<M>(validateur: &ValidateurX509Database, redis: &RedisDao, mongo_dao: &M)
    -> Result<(), Box<dyn Error>>
    where M: MongoDao
{
    let liste = match redis.liste_certificats_fingerprints().await {
        Ok(liste) => liste,
        Err(e) => {
            warn!("Erreur extraction liste certificats redis : {:?}", e);
            return Ok(())
        }
    };

    for fingerprints in liste.chunks(100) {
        // Verifier si le certificat est connu dans mongodb
        debug!("entretien_validateur Redis/Mongo sync fingerprints {:?}", fingerprints);

        let mut fingerprint_set = HashSet::new();
        for fp in fingerprints {
            fingerprint_set.insert(fp.as_str());
        }
        // let mut fingerprint_set = HashSet::from_iter(fingerprints.iter().map(|fp| fp.as_str()));

        let filtre = doc! {"fingerprint": {"$in": fingerprints}};
        let projection = doc! {"fingerprint": true};
        debug!("entretien_validateur filtre {:?}, projection {:?}", filtre, projection);
        let options = FindOptions::builder()
            .projection(projection)
            .build();
        let collection = mongo_dao.get_collection(COLLECTION_CERTIFICAT_NOM)?;
        let mut curseur = collection.find(filtre, options).await?;
        while let Some(row) = curseur.next().await {
            let row = row?;
            debug!("entretien_validateur Certificat connu {:?}", row);
            let row_fingerprint: RowFingerprint = convertir_bson_deserializable(row)?;
            fingerprint_set.remove(row_fingerprint.fingerprint.as_str());
        }

        debug!("Certificats manquants : {:?}", fingerprint_set);
        for fingerprint in fingerprint_set.into_iter() {
            match validateur.get_certificat(fingerprint).await {
                Some(certificat) => {
                    debug!("Certificat charge : {:?}", certificat);
                },
                None => panic!("Certificat manquant est present dans redis mais non charge")
            }

        }
    };

    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct RowFingerprint {
    fingerprint: String,
}

// pub fn configurer() -> MiddlewareDbPki
// {
//     let middeware_ressources = configurer_messages();
//     let configuration = middeware_ressources.configuration.as_ref().as_ref();
//
//     // Connecter au middleware mongo et MQ
//     let mongo= Arc::new(initialiser_mongodb(configuration).expect("initialiser_mongodb"));
//
//     MiddlewareDbRessources { ressources: middeware_ressources, mongo }
// }

/// Structure avec hooks interne de preparation du middleware
pub struct MiddlewareHooks {
    pub middleware: Arc<MiddlewareDbPki>,
    pub futures: FuturesUnordered<JoinHandle<()>>,
}

/// Version speciale du middleware avec un acces direct au sous-domaine Pki dans MongoDB
pub fn preparer_middleware_pki() -> MiddlewareHooks {

    let ressources_messages = configurer_messages();
    let configuration = ressources_messages.configuration.clone();

    // Extraire le cert millegrille comme base pour chiffrer les cles secretes
    let chiffrage_factory = {
        let env_privee = configuration.get_configuration_pki().get_enveloppe_privee();
        let cert_local = env_privee.enveloppe.as_ref();
        let mut fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");
        let list_fp_ca = env_privee.enveloppe_ca.fingerprint_cert_publickeys().expect("public keys CA");
        fp_certs.extend(list_fp_ca);

        let mut map: HashMap<String, FingerprintCertPublicKey> = HashMap::new();
        for f in fp_certs.iter().filter(|c| c.est_cle_millegrille).map(|c| c.to_owned()) {
            map.insert(f.fingerprint.clone(), f);
        }

        debug!("Map cles chiffrage : {:?}", map);

        Arc::new(ChiffrageFactoryImpl::new(map, env_privee))
    };

    let mongo = Arc::new(initialiser_mongodb(configuration.as_ref().as_ref()).expect("initialiser_mongodb"));

    let (tx_backup, rx_backup) = mpsc::channel::<CommandeBackup>(5);

    let redis_dao_validateur = match configuration.get_configuration_noeud().redis_password {
        Some(_) => Some(RedisDao::new(configuration.get_configuration_noeud().clone()).expect("connexion redis")),
        None => None
    };
    let validateur_db = Arc::new(ValidateurX509Database::new(
        mongo.clone(),
        redis_dao_validateur,
        ressources_messages.validateur.clone(),
        ressources_messages.generateur_messages.clone(),
    ));

    let redis_dao = match configuration.get_configuration_noeud().redis_password {
        Some(_) => Some(RedisDao::new(configuration.get_configuration_noeud().clone()).expect("connexion redis")),
        None => None
    };
    let middleware = Arc::new(MiddlewareDbPki {
        ressources: ressources_messages,
        mongo,
        redis: redis_dao,
        validateur: validateur_db,
        tx_backup,
        chiffrage_factory,
    });

    // Preparer threads execution
    let rabbitmq = middleware.ressources.rabbitmq.clone();
    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
    futures.push(tokio::spawn(thread_backup(middleware.clone(), rx_backup)));
    futures.push(tokio::spawn(run_rabbitmq(middleware.clone(), rabbitmq, configuration)));

    MiddlewareHooks { middleware, futures }

    // let (
    //     configuration,
    //     validateur,
    //     mongo,
    //     mq_executor_config,
    //     generateur_messages
    // ) = configurer_queues(queues, listeners);
    //
    // let generateur_messages_arc = Arc::new(generateur_messages);
    //
    // let validateur_db = Arc::new(ValidateurX509Database::new(
    //     mongo.clone(),
    //     validateur.clone(),
    //     generateur_messages_arc.clone(),
    // ));
    //
    // // let redis_url = match configuration.get_configuration_noeud().redis_url.as_ref() {
    // //     Some(u) => Some(u.as_str()),
    // //     None => None,
    // // };
    // let redis_dao = RedisDao::new(configuration.get_configuration_noeud().clone()).expect("connexion redis");
    //
    // // Extraire le cert millegrille comme base pour chiffrer les cles secretes
    // // let cles_chiffrage = {
    // //     let env_privee = configuration.get_configuration_pki().get_enveloppe_privee();
    // //     let cert_local = env_privee.enveloppe.as_ref();
    // //     let fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");
    // //
    // //     let mut map: HashMap<String, FingerprintCertPublicKey> = HashMap::new();
    // //     for f in fp_certs.iter().filter(|c| c.est_cle_millegrille).map(|c| c.to_owned()) {
    // //         map.insert(f.fingerprint.clone(), f);
    // //     }
    // //
    // //     map
    // // };
    //
    // let chiffrage_factory = {
    //     let env_privee = configuration.get_configuration_pki().get_enveloppe_privee();
    //     let cert_local = env_privee.enveloppe.as_ref();
    //     let mut fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");
    //     let list_fp_ca = env_privee.enveloppe_ca.fingerprint_cert_publickeys().expect("public keys CA");
    //     fp_certs.extend(list_fp_ca);
    //
    //     let mut map: HashMap<String, FingerprintCertPublicKey> = HashMap::new();
    //     for f in fp_certs.iter().filter(|c| c.est_cle_millegrille).map(|c| c.to_owned()) {
    //         map.insert(f.fingerprint.clone(), f);
    //     }
    //
    //     debug!("Map cles chiffrage : {:?}", map);
    //
    //     Arc::new(ChiffrageFactoryImpl::new(map, env_privee))
    // };
    //
    // let (tx_backup, rx_backup) = mpsc::channel::<CommandeBackup>(5);
    //
    // let middleware_ressources = configurer_messages();
    // let middleware = Arc::new(MiddlewareDbPki {
    //     configuration,
    //     mongo,
    //     validateur: validateur_db.clone(),
    //     generateur_messages: generateur_messages_arc.clone(),
    //     // cles_chiffrage: Mutex::new(cles_chiffrage),
    //     redis: redis_dao,
    //     tx_backup,
    //     chiffrage_factory,
    // });
    //
    // let (tx_messages_verifies, rx_messages_verifies) = mpsc::channel(3);
    // let (tx_messages_verif_reply, rx_messages_verif_reply) = mpsc::channel(3);
    // let (tx_triggers, rx_triggers) = mpsc::channel(3);
    //
    // let (tx_certificats_manquants, rx_certificats_manquants) = mpsc::channel(10);
    //
    // let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
    // let mq_executor = mq_executor_config.executor;  // Move
    // let mq_executor_rx = mq_executor_config.rx_queues;
    //
    // futures.push(tokio::spawn(recevoir_messages(
    //     middleware.clone(),
    //     mq_executor_rx.rx_messages,
    //     tx_messages_verifies.clone(),
    //     tx_certificats_manquants.clone()
    // )));
    //
    // futures.push(tokio::spawn(recevoir_messages(
    //     middleware.clone(),
    //     mq_executor_rx.rx_reply,
    //     tx_messages_verif_reply.clone(),
    //     tx_certificats_manquants.clone()
    // )));
    //
    // futures.push(tokio::spawn(recevoir_messages(
    //     middleware.clone(),
    //     mq_executor_rx.rx_triggers,
    //     tx_triggers,
    //     tx_certificats_manquants.clone()
    // )));
    //
    // // Thread requete certificats manquants
    // futures.push(tokio::spawn(task_requetes_certificats(
    //     middleware.clone(),
    //     rx_certificats_manquants,
    //     mq_executor.tx_reply.clone(),
    //     true   // On ne fait par de requete.certificat.FP (cause avalanche avec CorePki)
    // )));
    //
    // futures.push(tokio::spawn(thread_backup(middleware.clone(), rx_backup)));

    // (middleware, rx_messages_verifies, rx_messages_verif_reply, rx_triggers, futures)
}

#[async_trait]
impl ValidateurX509 for MiddlewareDbPki {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        let enveloppe = self.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await?;

        // Conserver dans redis (reset TTL)
        if let Some(redis) = self.redis.as_ref() {
            match redis.save_certificat(&enveloppe).await {
                Ok(()) => (),
                Err(e) => warn!("MiddlewareDbPki.charger_enveloppe Erreur sauvegarde certificat dans redis : {:?}", e)
            }
        }

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, bool) {
        let (enveloppe, persiste) = self.validateur.cacher(certificat).await;

        let persiste = if ! persiste {
            match self.redis.as_ref() {
                Some(redis) => {
                    match redis.save_certificat(enveloppe.as_ref()).await {
                        Ok(()) => {
                            debug!("Certificat {} sauvegarde dans redis", enveloppe.fingerprint);
                            self.validateur.set_flag_persiste(enveloppe.fingerprint.as_str());
                            true
                        },
                        Err(e) => {
                            warn!("Erreur cache certificat {} dans redis : {:?}", enveloppe.fingerprint, e);
                            false
                        }
                    }
                },
                None => false
            }
        } else {
            persiste
        };

        /// Retourne le certificat et indicateur qu'il a ete persiste
        (enveloppe, persiste)
    }

    fn set_flag_persiste(&self, fingerprint: &str) {
        self.validateur.set_flag_persiste(fingerprint)
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.validateur.get_certificat(fingerprint).await {
            Some(c) => Some(c),
            None => {
                // Cas special, certificat inconnu a PKI. Tenter de le charger de redis
                let redis_certificat = match self.redis.as_ref() {
                    Some(redis) => match redis.get_certificat(fingerprint).await {
                        Ok(c) => match c {
                            Some(cert_pem) => cert_pem,
                            None => return None
                        },
                        Err(e) => {
                            warn!("MiddlewareDbPki.get_certificat (2) Erreur acces certificat via redis : {:?}", e);
                            return None
                        }
                    },
                    None => return None
                };

                // Le certificat est dans redis, on le sauvegarde localement en chargeant l'enveloppe
                let ca_pem = match &redis_certificat.ca {
                    Some(c) => Some(c.as_str()),
                    None => None
                };
                match self.validateur.charger_enveloppe(&redis_certificat.pems, None, ca_pem).await {
                    Ok(c) => Some(c),
                    Err(e) => {
                        warn!("MiddlewareDbPki.get_certificat (1) Erreur acces certificat via redis : {:?}", e);
                        None
                    }
                }
            }
        }
    }

    fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
        self.validateur.certificats_persister()
    }

    fn idmg(&self) -> &str {
        self.validateur.idmg()
    }

    fn ca_pem(&self) -> &str {
        self.validateur.ca_pem()
    }

    fn ca_cert(&self) -> &X509 {
        self.validateur.ca_cert()
    }

    fn store(&self) -> &X509Store {
        self.validateur.store()
    }

    fn store_notime(&self) -> &X509Store {
        self.validateur.store_notime()
    }

    async fn entretien_validateur(&self) {
        debug!("MiddlewareDbPki.entretien_validateur Debut entretien certificats");
        self.validateur.entretien_validateur().await
    }
}

#[async_trait]
impl GenerateurMessages for MiddlewareDbPki {

    async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<(), String>
        where M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.emettre_evenement( routage, message).await
    }

    async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<TypeMessage, String>
        where M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.transmettre_requete(routage, message).await
    }

    async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.soumettre_transaction(routage, message, blocking).await
    }

    async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.transmettre_commande(routage, message, blocking).await
    }

    async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String> {
        self.ressources.generateur_messages.repondre(routage, message).await
    }

    async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool)
        -> Result<Option<TypeMessage>, String>
    {
        self.ressources.generateur_messages.emettre_message(routage, type_message, message,  blocking).await
    }

    async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille)
        -> Result<Option<TypeMessage>, String>
    {
        self.ressources.generateur_messages.emettre_message_millegrille(routage, blocking, type_message, message).await
    }

    fn mq_disponible(&self) -> bool {
        self.ressources.generateur_messages.mq_disponible()
    }

    fn set_regeneration(&self) {
        self.ressources.generateur_messages.set_regeneration();
    }

    fn reset_regeneration(&self) {
        self.ressources.generateur_messages.reset_regeneration();
    }

    fn get_mode_regeneration(&self) -> bool {
        self.ressources.generateur_messages.as_ref().get_mode_regeneration()
    }

    fn get_securite(&self) -> &Securite {
        self.ressources.generateur_messages.get_securite()
    }
}

impl IsConfigurationPki for MiddlewareDbPki {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        self.ressources.configuration.get_configuration_pki().get_enveloppe_privee()
    }
}

impl FormatteurMessage for MiddlewareDbPki {
    fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee> {
        self.ressources.generateur_messages.get_enveloppe_signature()
    }

    fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>) {
        self.ressources.generateur_messages.set_enveloppe_signature(enveloppe)
    }
}

#[async_trait]
impl MongoDao for MiddlewareDbPki {
    fn get_database(&self) -> Result<Database, String> {
        self.mongo.get_database()
    }
}

impl ConfigMessages for MiddlewareDbPki {
    fn get_configuration_mq(&self) -> &ConfigurationMq {
        self.ressources.configuration.get_configuration_mq()
    }

    fn get_configuration_pki(&self) -> &ConfigurationPki {
        self.ressources.configuration.get_configuration_pki()
    }
}

impl IsConfigNoeud for MiddlewareDbPki {
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud {
        self.ressources.configuration.get_configuration_noeud()
    }
}

#[async_trait]
impl CleChiffrageHandler for MiddlewareDbPki {

    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
        let guard = self.chiffrage_factory.cles_chiffrage.lock().expect("lock");

        // Copier les cles (extraire du mutex), retourner dans un vecteur
        let vals: Vec<FingerprintCertPublicKey> = guard.iter().map(|v| v.1.to_owned()).collect();

        vals
    }

    async fn charger_certificats_chiffrage<M>(&self, middleware: &M)
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages
    {
        debug!("Charger les certificats de maitre des cles pour chiffrage");
        Ok(self.chiffrage_factory.charger_certificats_chiffrage(middleware).await?)
    }

    async fn recevoir_certificat_chiffrage<M>(&self, middleware: &M, message: &MessageSerialise) -> Result<(), String>
        where M: ConfigMessages
    {
        self.chiffrage_factory.recevoir_certificat_chiffrage(middleware, message).await

        // let cert_chiffrage = match &message.certificat {
        //     Some(c) => c.clone(),
        //     None => {
        //         error!("recevoir_certificat_chiffrage Message de certificat de MilleGrille recu, certificat n'est pas extrait");
        //         Err(format!("recevoir_certificat_chiffrage Message de certificat de MilleGrille recu, certificat n'est pas extrait"))?
        //     }
        // };
        //
        // // Valider le certificat
        // if ! cert_chiffrage.presentement_valide {
        //     error!("recevoir_certificat_chiffrage Certificat de maitre des cles recu n'est pas presentement valide - rejete");
        //     Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'est pas presentement valide - rejete"))?;
        // }
        //
        // if ! cert_chiffrage.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
        //     format!("recevoir_certificat_chiffrage Certificat de maitre des cles recu n'a pas le role MaitreCles' - rejete");
        //     Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'a pas le role MaitreCles' - rejete"))?;
        // }
        //
        // info!("Certificat maitre des cles accepte {}", cert_chiffrage.fingerprint());
        // self.chiffrage_factory.recevoir_certificat_chiffrage(middleware, message).await

        // Stocker cles chiffrage du maitre des cles
        // {
        //     let fps = match cert_chiffrage.fingerprint_cert_publickeys() {
        //         Ok(f) => f,
        //         Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage cert_chiffrage.fingerprint_cert_publickeys : {:?}", e))?
        //     };
        //     let mut guard = match self.chiffrage_factory.cles_chiffrage.lock() {
        //         Ok(g) => g,
        //         Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage Erreur cles_chiffrage.lock() : {:?}", e))?
        //     };
        //     for fp in fps.iter().filter(|f| ! f.est_cle_millegrille) {
        //         guard.insert(fp.fingerprint.clone(), fp.clone());
        //     }
        //
        //     // S'assurer d'avoir le certificat de millegrille local
        //     let enveloppe_privee = middleware.get_configuration_pki().get_enveloppe_privee();
        //     let enveloppe_ca = &enveloppe_privee.enveloppe_ca;
        //     let public_keys_ca = match enveloppe_ca.fingerprint_cert_publickeys() {
        //         Ok(p) => p,
        //         Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage enveloppe_ca.fingerprint_cert_publickeys : {:?}", e))?
        //     }.pop();
        //     if let Some(pk_ca) = public_keys_ca {
        //         guard.insert(pk_ca.fingerprint.clone(), pk_ca);
        //     }
        //
        //     info!("Certificats chiffrage maj {:?}", guard);
        // }
        //
        // Ok(())
    }

}

impl VerificateurMessage for MiddlewareDbPki {
    fn verifier_message(&self, message: &mut MessageSerialise, options: Option<&ValidationOptions>) -> Result<ResultatValidation, Box<dyn Error>> {
        verifier_message(message, self, options)
    }
}

#[async_trait]
impl EmetteurCertificat for MiddlewareDbPki {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), String> {
        let enveloppe_privee = self.ressources.configuration.get_configuration_pki().get_enveloppe_privee();
        let enveloppe_certificat = enveloppe_privee.enveloppe.as_ref();
        let message = formatter_message_certificat(enveloppe_certificat)?;
        let exchanges = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);

        let routage = RoutageMessageAction::builder("certificat", "infoCertificat")
            .exchanges(exchanges)
            .build();

        // Sauvegarder dans redis
        if let Some(redis) = self.redis.as_ref() {
            match redis.save_certificat(enveloppe_certificat).await {
                Ok(()) => (),
                Err(e) => warn!("MiddlewareDbPki.emettre_certificat Erreur sauvegarde certificat local sous redis : {:?}", e)
            }
        }

        match generateur_message.emettre_evenement(routage, &message).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Erreur emettre_certificat: {:?}", e)),
        }
    }
}

#[async_trait]
impl BackupStarter for MiddlewareDbPki {
    fn get_tx_backup(&self) -> Sender<CommandeBackup> {
        self.tx_backup.clone()
    }
}
