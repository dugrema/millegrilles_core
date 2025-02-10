use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;

use log::{debug, warn, error, info};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::{BackupStarter, CommandeBackup};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, ValidateurX509Impl};
use millegrilles_common_rust::chiffrage_cle::{CleChiffrageCache, CleChiffrageHandlerImpl};
use millegrilles_common_rust::configuration::{ConfigMessages, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::FormatteurMessage;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl, RoutageMessageReponse, RoutageMessageAction};
use millegrilles_common_rust::middleware::{configurer as configurer_messages, EmetteurCertificat, formatter_message_certificat, IsConfigurationPki, ReponseCertificatMaitredescles, upsert_certificat, Middleware, MiddlewareMessages, RedisTrait, MiddlewareRessources, RabbitMqTrait, EmetteurNotificationsTrait, repondre_certificat, MiddlewareMessage};
use millegrilles_common_rust::middleware_db_v2::preparer as preparer_middleware_db_v2;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao, MongoDaoImpl, initialiser as initialiser_mongodb};
use millegrilles_common_rust::mongodb::{ClientSession, Database};
use millegrilles_common_rust::mongodb::options::FindOptions;
use millegrilles_common_rust::notifications::NotificationMessageInterne;
use millegrilles_common_rust::openssl::x509::store::X509Store;
use millegrilles_common_rust::openssl::x509::X509;
use millegrilles_common_rust::rabbitmq_dao::{NamedQueue, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{ErreurVerification, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio::sync::{mpsc, Notify};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::redis_dao::RedisDao;
use millegrilles_common_rust::tokio::sync::mpsc::Sender;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::static_cell::StaticCell;
use millegrilles_common_rust::tokio;
use crate::pki_constants::{COLLECTION_CERTIFICAT_NOM, DOMAIN_NAME as PKI_DOMAINE_NOM, PKI_DOCUMENT_CHAMP_FINGERPRINT_PK};
use crate::pki_structs::CorePkiCertificat;

use millegrilles_common_rust::backup_v2::thread_backup_v2;

// Middleware avec MongoDB et validateur X509 lie a la base de donnees
pub struct MiddlewareDbPki {
    ressources: MiddlewareRessources,
    pub mongo: Arc<MongoDaoImpl>,
    pub redis: Option<RedisDao>,
    validateur: Arc<ValidateurX509Database>,
    tx_backup: Sender<CommandeBackup>,
    // chiffrage_factory: Arc<ChiffrageFactoryImpl>,
    cle_chiffrage_handler: &'static CleChiffrageHandlerImpl,
}

impl MiddlewareDbPki {}

impl MiddlewareMessages for MiddlewareDbPki {}

impl CleChiffrageHandler for MiddlewareDbPki {
    fn get_publickeys_chiffrage(&self) -> Vec<Arc<EnveloppeCertificat>> {
        self.cle_chiffrage_handler.get_publickeys_chiffrage()
    }
}

impl CleChiffrageCache for MiddlewareDbPki {
    fn entretien_cle_chiffrage(&self) {
        self.cle_chiffrage_handler.entretien_cle_chiffrage();
    }

    fn ajouter_certificat_chiffrage(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), millegrilles_common_rust::error::Error> {
        self.cle_chiffrage_handler.ajouter_certificat_chiffrage(certificat)
    }
}

impl Middleware for MiddlewareDbPki {}

#[async_trait]
impl EmetteurNotificationsTrait for MiddlewareDbPki {
    async fn emettre_notification_proprietaire(
        &self, contenu: NotificationMessageInterne, niveau: &str, expiration: Option<i64>, destinataires: Option<Vec<String>>
    )
        -> Result<(), millegrilles_common_rust::error::Error>
    {
        self.ressources.emetteur_notifications.emettre_notification_proprietaire(
            self, contenu, niveau, expiration, destinataires).await
    }

    async fn emettre_notification_usager<D, S, N>(
        &self, _user_id: S, _contenu: NotificationMessageInterne, _niveau: N, _domaine: D, _expiration: Option<i64>)
        -> Result<String, millegrilles_common_rust::error::Error>
        where D: AsRef<str> + Send, S: AsRef<str> + Send, N: AsRef<str> + Send
    {
        todo!()
        //     self.ressources.emetteur_notifications.emettre_notification_usager(
        //         self, user_id, contenu, niveau, domaine, expiration, cle_dechiffree).await
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

// impl ChiffrageFactoryTrait for MiddlewareDbPki {
//     fn get_chiffrage_factory(&self) -> &ChiffrageFactoryImpl {
//         self.chiffrage_factory.as_ref()
//     }
// }
//
// impl ChiffrageFactory for MiddlewareDbPki {
//     fn get_chiffreur(&self) -> Result<CipherMgs4, String> {
//         self.chiffrage_factory.get_chiffreur()
//     }
//
//     // fn get_chiffreur_mgs2(&self) -> Result<CipherMgs2, String> {
//     //     self.chiffrage_factory.get_chiffreur_mgs2()
//     // }
//
//     // fn get_chiffreur_mgs3(&self) -> Result<CipherMgs3, String> {
//     //     self.chiffrage_factory.get_chiffreur_mgs3()
//     // }
//
//     fn get_chiffreur_mgs4(&self) -> Result<CipherMgs4, String> {
//         self.chiffrage_factory.get_chiffreur_mgs4()
//     }
// }

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

    // pub async fn entretien(&self) {
    //     debug!("ValidateurX509Database: Entretien ValidateurX509Database");
    //     self.validateur.entretien_validateur().await;
    // }

    async fn upsert_enveloppe(&self, enveloppe: &EnveloppeCertificat)
        -> Result<(), millegrilles_common_rust::error::Error>
    {
        debug!("Upserting enveloppe {:?}, CA: {:?}", enveloppe.chaine_pem()?, enveloppe.ca_pem()?);

        let db = self.mongo_dao.get_database()?;
        let collection = db.collection(COLLECTION_CERTIFICAT_NOM);

        match upsert_certificat(enveloppe, collection, None).await? {
            Some(_) => {
                debug!("Certificat upserted, creer transaction pour sauvegarde permanente");
                // let domaine_action = format!("{}.{}", PKI_DOMAINE_NOM, PKI_TRANSACTION_NOUVEAU_CERTIFICAT);

                let fingerprint_certs = enveloppe.chaine_fingerprint_pem()?;
                let mut pem_vec = Vec::new();
                for fp_cert in fingerprint_certs {
                    pem_vec.push(fp_cert.pem);
                }
                let pems = pem_vec.join("\n");
                let ca = enveloppe.ca_pem()?;

                let contenu = json!({
                    "pem": pems,
                    "ca": ca,
                });
                // let message = self.generateur_messages.formatter_message(
                //     contenu,
                //     Some(&domaine_action),
                //     None
                // );

                let routage = RoutageMessageAction::builder(PKI_DOMAINE_NOM,PKI_TRANSACTION_NOUVEAU_CERTIFICAT, vec![Securite::L4Secure])
                    .blocking(false)
                    .build();
                match self.generateur_messages.soumettre_transaction(routage, &contenu).await {
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

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>)
        -> Result<Arc<EnveloppeCertificat>, millegrilles_common_rust::error::Error> {
        debug!("ValidateurX509Database: charger_enveloppe!");
        // let resultat = self.charger_cert_db();

        let enveloppe = self.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await?;

        // Verifier si le certificat existe dans la base de donnes, creer transaction au besoin
        self.upsert_enveloppe(&enveloppe).await?;

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat)
        -> Result<(Arc<EnveloppeCertificat>, bool), millegrilles_common_rust::error::Error>
    {
        let (enveloppe, persiste) = self.validateur.cacher(certificat).await?;

        let persiste = if ! persiste {
            // Conserver dans MongoDB
            let persiste = match self.upsert_enveloppe(enveloppe.as_ref()).await {
                Ok(()) => {
                    self.validateur.set_flag_persiste(enveloppe.fingerprint()?.as_str());
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
                    let fingerprint = enveloppe.fingerprint()?;
                    match redis.save_certificat(enveloppe.as_ref()).await {
                        Ok(()) => debug!("Certificat {} sauvegarde dans redis", fingerprint),
                        Err(e) => warn!("Erreur cache certificat {} dans redis : {:?}", fingerprint, e)
                    }
                },
                None => ()
            }

            // Retourner flag sauvegarde dans MongoDB
            persiste
        } else {
            persiste
        };

        // Retourne le certificat et indicateur qu'il a ete persiste
        Ok((enveloppe, persiste))
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

    fn est_cache(&self, fingerprint: &str) -> bool {
        self.validateur.est_cache(fingerprint)
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
                let fingerprint = match certificat.fingerprint() {
                    Ok(inner) => inner,
                    Err(_) => {
                        error!("Erreur fingerprint() durant entretien certificat - SKIP");
                        continue  // Skip le certificat
                    }
                };
                debug!("entretien_validateur Persister certificat {}", fingerprint);

                // Sauvegarder dans MongoDB
                match self.upsert_enveloppe(certificat.as_ref()).await {
                    Ok(()) => self.validateur.set_flag_persiste(fingerprint.as_str()),
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
    -> Result<(), CommonError>
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

        debug!("Missing certificates : {:?}", fingerprint_set);
        for fingerprint in fingerprint_set.into_iter() {
            match validateur.get_certificat(fingerprint).await {
                Some(certificat) => {
                    debug!("synchroniser_certificats Certificate loaded from CorePki : {:?}", certificat);
                },
                None => {
                    debug!("synchroniser_certificats A certificate not in CorePki found in redis - attempting to recover and save in CorePki");
                    let (pems, ca) = if let Ok(Some(certificate)) = redis.get_certificat(fingerprint).await {
                        (certificate.pems, certificate.ca)
                    } else {
                        panic!("synchroniser_certificats Unable to load a certificate from redis that is missing in the CorePki database");
                    };
                    let ca = match ca.as_ref() {Some(inner)=>Some(inner.as_str()), None=>None};
                    match validateur.charger_enveloppe(&pems, None, ca).await {
                        Ok(enveloppe) => {
                            info!("synchroniser_certificats Certificate {} recovered from redis and saved in CorePki", enveloppe.fingerprint()?);
                        },
                        Err(CommonError::ErreurVerification(ErreurVerification::CertificatCaManquant(idmg))) => {
                            debug!("Third party certificate (idmg: {}) in redis is missing its CA certificate - ignoring", idmg);
                        },
                        Err(e) => {
                            panic!("synchroniser_certificats Unable to save a certificate from redis to CorePki\nCertificate: {:?}\nException: {:?}", pems, e);
                        }
                    }
                }
            }
        }
    };

    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(crate = "millegrilles_common_rust::serde")]
struct RowFingerprint {
    fingerprint: String,
}

/// Structure avec hooks interne de preparation du middleware
pub struct MiddlewareHooks {
    pub middleware: &'static MiddlewareDbPki,
    pub futures: FuturesUnordered<JoinHandle<()>>,
}

static MIDDLEWARE_DB_PKI: StaticCell<MiddlewareDbPki> = StaticCell::new();

/// Version speciale du middleware avec un acces direct au sous-domaine Pki dans MongoDB
pub fn preparer_middleware_pki() -> MiddlewareHooks {

    let (middleware, mut futures) = preparer_middleware_db_v2().expect("preparer_middleware_db_v2");

    let config = middleware.ressources.ressources.configuration.as_ref().as_ref();
    let resources = &middleware.ressources.ressources;

    let mongo = Arc::new(initialiser_mongodb(config).expect("initialiser_mongodb"));

    let redis_dao_validateur = match config.get_configuration_noeud().redis_password {
        Some(_) => Some(RedisDao::new(config.get_configuration_noeud().clone()).expect("connexion redis")),
        None => None
    };
    let validateur_db = Arc::new(ValidateurX509Database::new(
        mongo.clone(),
        redis_dao_validateur,
        resources.validateur.clone(),
        resources.generateur_messages.clone(),
    ));

    let redis_dao = match config.get_configuration_noeud().redis_password {
        Some(_) => Some(RedisDao::new(config.get_configuration_noeud().clone()).expect("connexion redis")),
        None => None
    };

    let middleware_db = MiddlewareDbPki {
        ressources: resources.clone(),
        mongo,
        redis: redis_dao,
        validateur: validateur_db,
        tx_backup: middleware.tx_backup.clone(),
        cle_chiffrage_handler: &middleware.cle_chiffrage_handler
    };

    // Conserver dans static cell pour retourner &'static
    let middleware = MIDDLEWARE_DB_PKI.try_init(middleware_db)
        .expect("staticell MIDDLEWARE_DB_PKI");

    MiddlewareHooks { middleware, futures }
}

#[async_trait]
impl ValidateurX509 for MiddlewareDbPki {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>)
        -> Result<Arc<EnveloppeCertificat>, millegrilles_common_rust::error::Error>
    {
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

    async fn cacher(&self, certificat: EnveloppeCertificat)
        -> Result<(Arc<EnveloppeCertificat>, bool), millegrilles_common_rust::error::Error>
    {
        let (enveloppe, persiste) = self.validateur.cacher(certificat).await?;

        let persiste = if ! persiste {
            match self.redis.as_ref() {
                Some(redis) => {
                    match redis.save_certificat(enveloppe.as_ref()).await {
                        Ok(()) => {
                            let fingerprint = enveloppe.fingerprint()?;
                            debug!("Certificat {} sauvegarde dans redis", fingerprint);
                            self.validateur.set_flag_persiste(fingerprint.as_str());
                            true
                        },
                        Err(e) => {
                            warn!("Erreur cache certificat {} dans redis : {:?}", enveloppe.fingerprint()?, e);
                            false
                        }
                    }
                },
                None => false
            }
        } else {
            persiste
        };

        // Retourne le certificat et indicateur qu'il a ete persiste
        Ok((enveloppe, persiste))
    }

    fn set_flag_persiste(&self, fingerprint: &str) {
        self.validateur.set_flag_persiste(fingerprint)
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.validateur.get_certificat(fingerprint).await {
            Some(c) => Some(c),
            None => {
                // Charger le certificat a partir de CorePki (MongoDB
                if let Ok(Some(inner)) = charger_certificat_pki(self, fingerprint).await {
                    let ca = match inner.ca.as_ref() {
                        Some(inner) => Some(inner.as_str()),
                        None => None
                    };
                    match self.charger_enveloppe(&inner.certificat, Some(inner.fingerprint.as_str()), ca).await {
                        Ok(inner) => return Some(inner),
                        Err(e) => {
                            error!("get_certificat Erreur chargement certificat avec CorePki db : {:?}", e)
                        }
                    }
                };

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

    fn est_cache(&self, fingerprint: &str) -> bool {
        self.validateur.est_cache(fingerprint)
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

    async fn emettre_evenement<R,M>(&self, routage: R, message: M)
                                    -> Result<(), millegrilles_common_rust::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.emettre_evenement(routage, message).await
    }

    async fn transmettre_requete<R,M>(&self, routage: R, message: M)
                                      -> Result<Option<TypeMessage>, millegrilles_common_rust::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.transmettre_requete(routage, message).await
    }

    async fn soumettre_transaction<R,M>(&self, routage: R, message: M)
                                        -> Result<Option<TypeMessage>, millegrilles_common_rust::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.soumettre_transaction(routage, message).await
    }

    async fn transmettre_commande<R,M>(&self, routage: R, message: M)
                                       -> Result<Option<TypeMessage>, millegrilles_common_rust::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.transmettre_commande(routage, message).await
    }

    async fn repondre<R,M>(&self, routage: R, message: M) -> Result<(), millegrilles_common_rust::error::Error>
        where R: Into<RoutageMessageReponse> + Send, M: Serialize + Send + Sync {
        self.ressources.generateur_messages.repondre(routage, message).await
    }

    async fn emettre_message<M>(&self, type_message: TypeMessageOut, message: M)
                                -> Result<Option<TypeMessage>, millegrilles_common_rust::error::Error>
        where M: Into<MessageMilleGrillesBufferDefault> + Send
    {
        self.ressources.generateur_messages.emettre_message(type_message, message).await
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
    fn get_database(&self) -> Result<Database, CommonError> {
        self.mongo.get_database()
    }
    fn get_admin_database(&self) -> Result<Database, CommonError> { self.mongo.get_admin_database() }

    fn get_db_name(&self) -> &str {
        self.mongo.get_db_name()
    }

    async fn get_session(&self) -> Result<ClientSession, CommonError> {
        self.mongo.get_session().await
    }

    async fn get_session_rebuild(&self) -> Result<ClientSession, CommonError> {
        self.mongo.get_session_rebuild().await
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

async fn charger_certificat_pki<M,S>(middleware: &M, fingerprint: S)
    -> Result<Option<CorePkiCertificat>, CommonError>
    where M: MongoDao, S: AsRef<str>
{
    let collection = middleware.get_collection_typed::<CorePkiCertificat>(DOMAINE_PKI)?;
    let filtre = doc!{ PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: fingerprint.as_ref() };
    Ok(collection.find_one(filtre, None).await?)
}

#[async_trait]
impl EmetteurCertificat for MiddlewareDbPki {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages)
        -> Result<(), millegrilles_common_rust::error::Error>
    {
        let enveloppe_privee = self.ressources.configuration.get_configuration_pki().get_enveloppe_privee();
        let enveloppe_certificat = enveloppe_privee.enveloppe_pub.as_ref();
        let message = formatter_message_certificat(enveloppe_certificat)?;
        let exchanges = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);

        let routage = RoutageMessageAction::builder("certificat", "infoCertificat", exchanges)
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
            Err(e) => Err(format!("Erreur emettre_certificat: {:?}", e))?
        }
    }

    async fn repondre_certificat<S, T>(&self, reply_q: S, correlation_id: T)
        -> Result<(), millegrilles_common_rust::error::Error>
        where S: AsRef<str> + Send, T: AsRef<str> + Send
    {
        repondre_certificat(self, reply_q, correlation_id).await
    }
}

#[async_trait]
impl BackupStarter for MiddlewareDbPki {
    fn get_tx_backup(&self) -> Sender<CommandeBackup> {
        self.tx_backup.clone()
    }
}
