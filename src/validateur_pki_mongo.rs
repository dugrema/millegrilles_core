use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use log::{debug, info, warn, error};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::{BackupStarter, CommandeBackup, thread_backup};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{emettre_commande_certificat_maitredescles, EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ValidateurX509, ValidateurX509Impl, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::{Chiffreur, Dechiffreur, MgsCipherData};
use millegrilles_common_rust::chiffrage_chacha20poly1305::{CipherMgs3, DecipherMgs3, Mgs3CipherData, Mgs3CipherKeys};
use millegrilles_common_rust::configuration::{ConfigMessages, ConfigurationMessagesDb, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl, RoutageMessageReponse, RoutageMessageAction};
use millegrilles_common_rust::middleware::{configurer as configurer_queues, EmetteurCertificat, formatter_message_certificat, IsConfigurationPki, ReponseCertificatMaitredescles, ReponseDechiffrageCle, upsert_certificat, Middleware};
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoImpl};
use millegrilles_common_rust::mongodb::Database;
use millegrilles_common_rust::openssl::x509::store::X509Store;
use millegrilles_common_rust::openssl::x509::X509;
use millegrilles_common_rust::rabbitmq_dao::{Callback, EventMq, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{recevoir_messages, task_requetes_certificats, TypeMessage};
use millegrilles_common_rust::serde::Serialize;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio as tokio;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::Receiver};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage, verifier_message};
use millegrilles_common_rust::redis_dao::RedisDao;
use millegrilles_common_rust::tokio::sync::mpsc::Sender;

use crate::core_pki::{COLLECTION_CERTIFICAT_NOM, DOMAINE_NOM as PKI_DOMAINE_NOM};

// Middleware avec MongoDB et validateur X509 lie a la base de donnees
pub struct MiddlewareDbPki {
    pub configuration: Arc<ConfigurationMessagesDb>,
    pub mongo: Arc<MongoDaoImpl>,
    pub validateur: Arc<ValidateurX509Database>,
    pub generateur_messages: Arc<GenerateurMessagesImpl>,
    pub cles_chiffrage: Mutex<HashMap<String, FingerprintCertPublicKey>>,
    pub redis: RedisDao,
    tx_backup: Sender<CommandeBackup>,
}

impl MiddlewareDbPki {}

impl Middleware for MiddlewareDbPki {}

/// Validateur X509 backe par une base de donnees (Mongo)
/// Permet de charger les certificats et generer les transactions pour les certificats inconnus.
pub struct ValidateurX509Database {
    mongo_dao: Arc<MongoDaoImpl>,
    validateur: Arc<ValidateurX509Impl>,
    generateur_messages: Arc<GenerateurMessagesImpl>
}

impl ValidateurX509Database {

    pub fn new(mongo_dao: Arc<MongoDaoImpl>, validateur: Arc<ValidateurX509Impl>, generateur_messages: Arc<GenerateurMessagesImpl>) -> ValidateurX509Database {
        ValidateurX509Database {
            mongo_dao,
            validateur,
            generateur_messages
        }
    }

    pub async fn entretien(&self) {
        debug!("ValidateurX509Database: Entretien ValidateurX509Database");
        self.validateur.entretien_validateur().await;
    }

    async fn upsert_enveloppe(&self, enveloppe: &EnveloppeCertificat) -> Result<(), String> {
        debug!("Upserting enveloppe");

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

                let contenu = json!({
                    "pem": pems
                });
                // let message = self.generateur_messages.formatter_message(
                //     contenu,
                //     Some(&domaine_action),
                //     None
                // );

                let routage = RoutageMessageAction::builder(PKI_DOMAINE_NOM,PKI_TRANSACTION_NOUVEAU_CERTIFICAT)
                    .exchanges(vec![Securite::L3Protege])
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

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        debug!("ValidateurX509Database: charger_enveloppe!");
        // let resultat = self.charger_cert_db();

        let enveloppe = self.validateur.charger_enveloppe(chaine_pem, fingerprint).await?;

        // Verifier si le certificat existe dans la base de donnes, creer transaction au besoin
        self.upsert_enveloppe(&enveloppe).await?;

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
        debug!("ValidateurX509Database: cacher!");
        self.validateur.cacher(certificat).await
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        debug!("ValidateurX509Database: get_certificat {}", fingerprint);
        match self.validateur.get_certificat(fingerprint).await {
            Some(enveloppe) => Some(enveloppe),
            None => {
                // Tenter de charger a partir de la base de donnes
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
                                    match document.get(PKI_DOCUMENT_CHAMP_CERTIFICAT) {
                                        Some(chaine_pem) => {
                                            let mut vec_pems = Vec::new();
                                            for pem in chaine_pem.as_array().expect("pems") {
                                                vec_pems.push(String::from(pem.as_str().expect("un pem")));
                                            }
                                            match self.validateur.charger_enveloppe(&vec_pems, None).await {
                                                Ok(enveloppe) => {
                                                    debug!("Certificat {} charge de la DB", fingerprint);
                                                    Some(enveloppe)
                                                },
                                                Err(_) => None,
                                            }
                                        },
                                        None => None,
                                    }
                                },
                                None => {
                                    debug!("Certificat inconnu (pas dans la DB) {:?}", fingerprint);
                                    None
                                },
                            },
                            Err(e) => {
                                debug!("Erreur!!! {:?}", e);
                                None
                            },
                        }
                    },
                    Err(e) => {
                        debug!("Erreur!!! {:?}", e);
                        None
                    }
                }
            }
        }
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

    /// Pas invoque
    async fn entretien_validateur(&self) {
        self.validateur.entretien_validateur().await;
    }

}

/// Version speciale du middleware avec un acces direct au sous-domaine Pki dans MongoDB
pub fn preparer_middleware_pki(
    queues: Vec<QueueType>,
    listeners: Option<Mutex<Callback<'static, EventMq>>>
) -> (Arc<MiddlewareDbPki>, Receiver<TypeMessage>, Receiver<TypeMessage>, Receiver<TypeMessage>, FuturesUnordered<JoinHandle<()>>) {
    let (
        configuration,
        validateur,
        mongo,
        mq_executor_config,
        generateur_messages
    ) = configurer_queues(queues, listeners);

    let generateur_messages_arc = Arc::new(generateur_messages);

    let validateur_db = Arc::new(ValidateurX509Database::new(
        mongo.clone(),
        validateur.clone(),
        generateur_messages_arc.clone(),
    ));

    let redis_url = match configuration.get_configuration_noeud().redis_url.as_ref() {
        Some(u) => Some(u.as_str()),
        None => None,
    };
    let redis_dao = RedisDao::new(redis_url).expect("connexion redis");

    // Extraire le cert millegrille comme base pour chiffrer les cles secretes
    let cles_chiffrage = {
        let env_privee = configuration.get_configuration_pki().get_enveloppe_privee();
        let cert_local = env_privee.enveloppe.as_ref();
        let fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");

        let mut map: HashMap<String, FingerprintCertPublicKey> = HashMap::new();
        for f in fp_certs.iter().filter(|c| c.est_cle_millegrille).map(|c| c.to_owned()) {
            map.insert(f.fingerprint.clone(), f);
        }

        map
    };

    let (tx_backup, rx_backup) = mpsc::channel::<CommandeBackup>(5);

    let middleware = Arc::new(MiddlewareDbPki {
        configuration,
        mongo,
        validateur: validateur_db.clone(),
        generateur_messages: generateur_messages_arc.clone(),
        cles_chiffrage: Mutex::new(cles_chiffrage),
        redis: redis_dao,
        tx_backup,
    });

    let (tx_messages_verifies, rx_messages_verifies) = mpsc::channel(3);
    let (tx_messages_verif_reply, rx_messages_verif_reply) = mpsc::channel(3);
    let (tx_triggers, rx_triggers) = mpsc::channel(3);

    let (tx_certificats_manquants, rx_certificats_manquants) = mpsc::channel(10);

    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
    let mq_executor = mq_executor_config.executor;  // Move
    let mq_executor_rx = mq_executor_config.rx_queues;

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor_rx.rx_messages,
        tx_messages_verifies.clone(),
        tx_certificats_manquants.clone()
    )));

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor_rx.rx_reply,
        tx_messages_verif_reply.clone(),
        tx_certificats_manquants.clone()
    )));

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor_rx.rx_triggers,
        tx_triggers,
        tx_certificats_manquants.clone()
    )));

    // Thread requete certificats manquants
    futures.push(tokio::spawn(task_requetes_certificats(
        middleware.clone(),
        rx_certificats_manquants,
        mq_executor.tx_reply.clone(),
        true   // On ne fait par de requete.certificat.FP (cause avalanche avec CorePki)
    )));

    futures.push(tokio::spawn(thread_backup(middleware.clone(), rx_backup)));

    (middleware, rx_messages_verifies, rx_messages_verif_reply, rx_triggers, futures)
}

#[async_trait]
impl ValidateurX509 for MiddlewareDbPki {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        let enveloppe = self.validateur.charger_enveloppe(chaine_pem, fingerprint).await?;

        // Conserver dans redis (reset TTL)
        match self.redis.save_certificat(&enveloppe).await {
            Ok(()) => (),
            Err(e) => warn!("MiddlewareDbPki.charger_enveloppe Erreur sauvegarde certificat dans redis : {:?}", e)
        }

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
        match self.redis.save_certificat(&certificat).await {
            Ok(()) => debug!("Certificat {} sauvegarde dans redis", &certificat.fingerprint),
            Err(e) => warn!("Erreur cache certificat {} dans redis : {:?}", certificat.fingerprint(), e)
        }
        self.validateur.cacher(certificat).await
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.validateur.get_certificat(fingerprint).await {
            Some(c) => Some(c),
            None => {
                // Cas special, certificat inconnu a PKI. Tenter de le charger de redis
                let pems_vec = match self.redis.get_certificat(fingerprint).await {
                    Ok(c) => match c {
                        Some(cert_pem) => cert_pem,
                        None => return None
                    },
                    Err(e) => {
                        warn!("MiddlewareDbPki.get_certificat (2) Erreur acces certificat via redis : {:?}", e);
                        return None
                    }
                };

                // Le certificat est dans redis, on le sauvegarde localement en chargeant l'enveloppe
                match self.validateur.charger_enveloppe(&pems_vec, None).await {
                    Ok(c) => Some(c),
                    Err(e) => {
                        warn!("MiddlewareDbPki.get_certificat (1) Erreur acces certificat via redis : {:?}", e);
                        None
                    }
                }
            }
        }
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
        self.validateur.entretien().await;
    }
}

#[async_trait]
impl GenerateurMessages for MiddlewareDbPki {

    async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<(), String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.emettre_evenement( routage, message).await
    }

    async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<TypeMessage, String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.transmettre_requete(routage, message).await
    }

    async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.soumettre_transaction(routage, message, blocking).await
    }

    async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.transmettre_commande(routage, message, blocking).await
    }

    async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String> {
        self.generateur_messages.repondre(routage, message).await
    }

    async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool)
        -> Result<Option<TypeMessage>, String>
    {
        self.generateur_messages.emettre_message(routage, type_message, message,  blocking).await
    }

    async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille)
        -> Result<Option<TypeMessage>, String>
    {
        self.generateur_messages.emettre_message_millegrille(routage, blocking, type_message, message).await
    }

    fn mq_disponible(&self) -> bool {
        self.generateur_messages.mq_disponible()
    }

    fn set_regeneration(&self) {
        self.generateur_messages.set_regeneration();
    }

    fn reset_regeneration(&self) {
        self.generateur_messages.reset_regeneration();
    }

    fn get_mode_regeneration(&self) -> bool {
        self.generateur_messages.as_ref().get_mode_regeneration()
    }
}

impl IsConfigurationPki for MiddlewareDbPki {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        self.configuration.get_configuration_pki().get_enveloppe_privee()
    }
}

impl FormatteurMessage for MiddlewareDbPki {}

#[async_trait]
impl MongoDao for MiddlewareDbPki {
    fn get_database(&self) -> Result<Database, String> {
        self.mongo.get_database()
    }
}

impl ConfigMessages for MiddlewareDbPki {
    fn get_configuration_mq(&self) -> &ConfigurationMq {
        self.configuration.get_configuration_mq()
    }

    fn get_configuration_pki(&self) -> &ConfigurationPki {
        self.configuration.get_configuration_pki()
    }
}

impl IsConfigNoeud for MiddlewareDbPki {
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud {
        self.configuration.get_configuration_noeud()
    }
}

#[async_trait]
impl Chiffreur<CipherMgs3, Mgs3CipherKeys> for MiddlewareDbPki {
    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
        let guard = self.cles_chiffrage.lock().expect("lock");

        // Copier les cles (extraire du mutex), retourner dans un vecteur
        let vals: Vec<FingerprintCertPublicKey> = guard.iter().map(|v| v.1.to_owned()).collect();

        vals
    }

    fn get_cipher(&self) -> Result<CipherMgs3, Box<dyn Error>> {
        let fp_public_keys = self.get_publickeys_chiffrage();
        Ok(CipherMgs3::new(&fp_public_keys)?)
    }

    async fn charger_certificats_chiffrage(&self, cert_local: &EnveloppeCertificat) -> Result<(), Box<dyn Error>> {
        debug!("Charger les certificats de maitre des cles pour chiffrage");

        // Reset certificats maitredescles. Reinserer cert millegrille immediatement.
        {
            let fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");
            let mut guard = self.cles_chiffrage.lock().expect("lock");
            guard.clear();
            for f in fp_certs.iter().filter(|c| c.est_cle_millegrille).map(|c| c.to_owned()) {
                guard.insert(f.fingerprint.clone(), f);
            }
        }

        emettre_commande_certificat_maitredescles(self).await?;

        // Donner une chance aux certificats de rentrer
        tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;

        // Verifier si on a au moins un certificat
        let nb_certs = self.cles_chiffrage.lock().expect("lock").len();
        if nb_certs <= 1 {  // 1 => le cert millegrille est deja charge
            Err(format!("Echec, aucuns certificats de maitre des cles recus"))?
        } else {
            debug!("On a {} certificats de chiffrage valides (incluant celui de la millegrille)", nb_certs);
        }

        Ok(())
    }

    // async fn charger_certificats_chiffrage(&self) -> Result<(), Box<dyn Error>> {
    //     debug!("Charger les certificats de maitre des cles pour chiffrage");
    //     let requete = json!({});
    //     let routage = RoutageMessageAction::new("MaitreDesCles", "certMaitreDesCles");
    //     let message_reponse = match self.generateur_messages.transmettre_requete(routage, &requete).await {
    //         Ok(r) => r,
    //         Err(e) => {
    //             error!("Erreur demande certificats : {}", e);
    //             return Ok(())
    //         }
    //     };
    //
    //     debug!("Message reponse : {:?}", message_reponse);
    //     let message = match message_reponse {
    //         TypeMessage::Valide(m) => m,
    //         _ => {
    //             error!("Reponse de type non gere : {:?}", message_reponse);
    //             return Ok(())  // Abort
    //         }
    //     };
    //
    //     let m = message.message.get_msg();
    //     let value = match serde_json::to_value(m.contenu.clone()) {
    //         Ok(v) => v,
    //         Err(e) => {
    //             error!("Erreur conversion message reponse certificats maitre des cles : {:?}", e);
    //             return Ok(())  // Abort
    //         }
    //     };
    //     let rep_cert: ReponseCertificatMaitredescles = match serde_json::from_value(value) {
    //         Ok(c) => c,
    //         Err(e) => {
    //             error!("Erreur lecture message reponse certificats maitre des cles : {:?}", e);
    //             return Ok(())  // Abort
    //         }
    //     };
    //
    //     let cert_chiffrage = match rep_cert.get_enveloppe_maitredescles(self).await {
    //         Ok(c) => c,
    //         Err(e) => {
    //             error!("Erreur chargement enveloppe certificat chiffrage maitredescles : {:?}", e);
    //             return Ok(())  // Abort
    //         }
    //     };
    //
    //     debug!("Certificat de maitre des cles charges dans {:?}", cert_chiffrage.as_ref());
    //
    //     // Stocker cles chiffrage du maitre des cles
    //     {
    //         let fps = cert_chiffrage.fingerprint_cert_publickeys().expect("public keys");
    //         let mut guard = self.cles_chiffrage.lock().expect("lock");
    //         for fp in fps.iter().filter(|f| ! f.est_cle_millegrille) {
    //             guard.insert(fp.fingerprint.clone(), fp.clone());
    //         }
    //     }
    //
    //     Ok(())
    // }

    async fn recevoir_certificat_chiffrage<'a>(&'a self, message: &MessageSerialise) -> Result<(), Box<dyn Error + 'a>> {
        let cert_chiffrage = match &message.certificat {
            Some(c) => c.clone(),
            None => {
                Err(format!("recevoir_certificat_chiffrage Message de certificat de MilleGrille recu, certificat n'est pas extrait"))?
            }
        };

        // Valider le certificat
        if ! cert_chiffrage.presentement_valide {
            Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'est pas presentement valide - rejete"))?;
        }

        if ! cert_chiffrage.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
            Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'a pas le role MaitreCles' - rejete"))?;
        }

        info!("Certificat maitre des cles accepte {}", cert_chiffrage.fingerprint());

        // Stocker cles chiffrage du maitre des cles
        {
            let fps = cert_chiffrage.fingerprint_cert_publickeys()?;
            let mut guard = self.cles_chiffrage.lock()?;
            for fp in fps.iter().filter(|f| ! f.est_cle_millegrille) {
                guard.insert(fp.fingerprint.clone(), fp.clone());
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Dechiffreur<DecipherMgs3, Mgs3CipherData> for MiddlewareDbPki {

    async fn get_cipher_data(&self, hachage_bytes: &str) -> Result<Mgs3CipherData, Box<dyn Error>> {
        let requete = {
            let mut liste_hachage_bytes = Vec::new();
            liste_hachage_bytes.push(hachage_bytes);
            json!({
                "liste_hachage_bytes": liste_hachage_bytes,
            })
        };
        let routage = RoutageMessageAction::new("MaitreDesCles", "dechiffrage");
        let reponse_cle_rechiffree = self.transmettre_requete(routage, &requete).await?;

        let m = match reponse_cle_rechiffree {
            TypeMessage::Valide(m) => m.message,
            _ => Err(format!("Mauvais type de reponse : {:?}", reponse_cle_rechiffree))?
        };

        let contenu_dechiffrage: ReponseDechiffrageCle = serde_json::from_value(
            serde_json::to_value(m.get_msg().contenu.clone())?
        )?;

        contenu_dechiffrage.to_cipher_data()
    }

    async fn get_decipher(&self, hachage_bytes: &str) -> Result<DecipherMgs3, Box<dyn Error>> {
        let mut info_cle = self.get_cipher_data(hachage_bytes).await?;
        let env_privee = self.get_enveloppe_privee();
        let cle_privee = env_privee.cle_privee();
        info_cle.dechiffrer_cle(cle_privee)?;

        Ok(DecipherMgs3::new(&info_cle)?)
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
        let enveloppe_privee = self.configuration.get_configuration_pki().get_enveloppe_privee();
        let enveloppe_certificat = enveloppe_privee.enveloppe.as_ref();
        let message = formatter_message_certificat(enveloppe_certificat);
        let exchanges = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);

        let routage = RoutageMessageAction::builder("certificat", "infoCertificat")
            .exchanges(exchanges)
            .build();

        // Sauvegarder dans redis
        match self.redis.save_certificat(enveloppe_certificat).await {
            Ok(()) => (),
            Err(e) => warn!("MiddlewareDbPki.emettre_certificat Erreur sauvegarde certificat local sous redis : {:?}", e)
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
