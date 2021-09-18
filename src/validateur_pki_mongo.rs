use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use log::{debug, error};
use millegrilles_common_rust::{Callback, Chiffreur, ConfigMessages, ConfigurationMessagesDb, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, Dechiffreur, EmetteurCertificat, EnveloppeCertificat, EnveloppePrivee, EventMq, FingerprintCertPublicKey, formatter_message_certificat, FormatteurMessage, GenerateurMessagesImpl, IsConfigNoeud, IsConfigurationPki, MessageMilleGrille, MessageSerialise, Mgs2CipherData, MongoDaoImpl, PKI_DOCUMENT_CHAMP_CERTIFICAT, PKI_TRANSACTION_NOUVEAU_CERTIFICAT, QueueType, recevoir_messages, ResultatValidation, Securite, task_requetes_certificats, TypeMessage, TypeMessageOut, upsert_certificat, ValidateurX509, ValidateurX509Impl, ValidationOptions, VerificateurMessage, verifier_message, PKI_DOCUMENT_CHAMP_FINGERPRINT, ReponseCertificatMaitredescles, ReponseDechiffrageCle};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::Database;
use millegrilles_common_rust::serde::Serialize;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio as tokio;
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::middleware::configurer as configurer_queues;
use crate::corepki::{COLLECTION_CERTIFICAT_NOM, DOMAINE_NOM as PKI_DOMAINE_NOM};

use millegrilles_common_rust::openssl::x509::store::X509Store;
use millegrilles_common_rust::openssl::x509::X509;

// Middleware avec MongoDB et validateur X509 lie a la base de donnees
pub struct MiddlewareDbPki {
    pub configuration: Arc<ConfigurationMessagesDb>,
    pub mongo: Arc<MongoDaoImpl>,
    pub validateur: Arc<ValidateurX509Database>,
    pub generateur_messages: Arc<GenerateurMessagesImpl>,
    pub cles_chiffrage: Mutex<HashMap<String, FingerprintCertPublicKey>>,
}

impl MiddlewareDbPki {
    pub async fn charger_certificats_chiffrage(&self) {
        debug!("Charger les certificats de maitre des cles pour chiffrage");
        let requete = json!({});
        let message_reponse = match self.generateur_messages.transmettre_requete(
            "MaitreDesCles", "certMaitreDesCles", None, &requete, None).await {
            Ok(r) => r,
            Err(e) => {
                error!("Erreur demande certificats : {}", e);
                return
            }
        };

        debug!("Message reponse : {:?}", message_reponse);
        let message = match message_reponse {
            TypeMessage::Valide(m) => m,
            _ => {
                error!("Reponse de type non gere : {:?}", message_reponse);
                return  // Abort
            }
        };

        let m = message.message.get_msg();
        let value = match serde_json::to_value(m.contenu.clone()) {
            Ok(v) => v,
            Err(e) => {
                error!("Erreur conversion message reponse certificats maitre des cles : {:?}", e);
                return  // Abort
            }
        };
        let rep_cert: ReponseCertificatMaitredescles = match serde_json::from_value(value) {
            Ok(c) => c,
            Err(e) => {
                error!("Erreur lecture message reponse certificats maitre des cles : {:?}", e);
                return  // Abort
            }
        };

        let cert_chiffrage = match rep_cert.get_enveloppe_maitredescles(self).await {
            Ok(c) => c,
            Err(e) => {
                error!("Erreur chargement enveloppe certificat chiffrage maitredescles : {:?}", e);
                return  // Abort
            }
        };

        debug!("Certificat de maitre des cles charges dans {:?}", cert_chiffrage.as_ref());

        // Stocker cles chiffrage du maitre des cles
        {
            let fps = cert_chiffrage.fingerprint_cert_publickeys().expect("public keys");
            let mut guard = self.cles_chiffrage.lock().expect("lock");
            for fp in fps.iter().filter(|f| ! f.est_cle_millegrille) {
                guard.insert(fp.fingerprint.clone(), fp.clone());
            }
        }
    }
}

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
        self.validateur.entretien().await;
    }

    async fn upsert_enveloppe(&self, enveloppe: &EnveloppeCertificat) -> Result<(), String> {
        debug!("Upserting enveloppe");

        let db = self.mongo_dao.get_database()?;
        let collection = db.collection(COLLECTION_CERTIFICAT_NOM);

        match upsert_certificat(enveloppe, collection, None).await? {
            Some(upserted_id) => {
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

                match self.generateur_messages.soumettre_transaction(
                    PKI_DOMAINE_NOM,
                    PKI_TRANSACTION_NOUVEAU_CERTIFICAT,
                    None,
                    &contenu,
                    Some(Securite::L3Protege),
                    false
                ).await {
                    Ok(t) => (),
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
                                                Err(t) => None,
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
    async fn entretien(&self) {
        self.validateur.entretien().await;
    }

}

/// Version speciale du middleware avec un acces direct au sous-domaine Pki dans MongoDB
pub fn preparer_middleware_pki(
    queues: Vec<QueueType>,
    listeners: Option<Mutex<Callback<'static, EventMq>>>
) -> (Arc<MiddlewareDbPki>, Receiver<TypeMessage>, Receiver<TypeMessage>, FuturesUnordered<JoinHandle<()>>) {
    let (
        configuration,
        validateur,
        mongo,
        mq_executor,
        generateur_messages
    ) = configurer_queues(queues, listeners);

    let generateur_messages_arc = Arc::new(generateur_messages);

    let validateur_db = Arc::new(ValidateurX509Database::new(
        mongo.clone(),
        validateur.clone(),
        generateur_messages_arc.clone(),
    ));

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

    let middleware = Arc::new(MiddlewareDbPki {
        configuration,
        mongo,
        validateur: validateur_db.clone(),
        generateur_messages: generateur_messages_arc.clone(),
        cles_chiffrage: Mutex::new(cles_chiffrage),
    });

    let (tx_messages_verifies, rx_messages_verifies) = mpsc::channel(3);
    let (tx_triggers, rx_triggers) = mpsc::channel(3);

    let (tx_certificats_manquants, rx_certificats_manquants) = mpsc::channel(10);

    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor.rx_messages,
        tx_messages_verifies.clone(),
        tx_certificats_manquants.clone()
    )));

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor.rx_triggers,
        tx_triggers,
        tx_certificats_manquants.clone()
    )));

    // Thread requete certificats manquants
    futures.push(tokio::spawn(task_requetes_certificats(
        middleware.clone(),
        rx_certificats_manquants,
        mq_executor.tx_interne.clone()
    )));

    (middleware, rx_messages_verifies, rx_triggers, futures)
}

#[async_trait]
impl ValidateurX509 for MiddlewareDbPki {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        self.validateur.charger_enveloppe(chaine_pem, fingerprint).await
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
        self.validateur.cacher(certificat).await
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        self.validateur.get_certificat(fingerprint).await
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

    async fn entretien(&self) {

        self.validateur.entretien().await;

        self.charger_certificats_chiffrage().await;

        // match emettre_presence_domaine(self, PKI_DOMAINE_NOM).await {
        //     Ok(()) => (),
        //     Err(e) => warn!("Erreur emission presence du domaine : {}", e),
        // };

    }
}

#[async_trait]
impl GenerateurMessages for MiddlewareDbPki {

    async fn emettre_evenement(&self, domaine: &str, action: &str, partition: Option<&str>, message: &(impl Serialize + Send + Sync), exchanges: Option<Vec<Securite>>) -> Result<(), String> {
        self.generateur_messages.emettre_evenement( domaine, action, partition, message, exchanges).await
    }

    async fn transmettre_requete<M>(&self, domaine: &str, action: &str, partition: Option<&str>, message: &M, exchange: Option<Securite>) -> Result<TypeMessage, String>
    where
        M: Serialize + Send + Sync,
    {
        self.generateur_messages.transmettre_requete(domaine, action, partition, message, exchange).await
    }

    async fn soumettre_transaction(&self, domaine: &str, action: &str, partition: Option<&str>, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String> {
        self.generateur_messages.soumettre_transaction(domaine, action, partition, message, exchange, blocking).await
    }

    async fn transmettre_commande(&self, domaine: &str, action: &str, partition: Option<&str>, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String> {
        self.generateur_messages.transmettre_commande(domaine, action, partition, message, exchange, blocking).await
    }

    async fn repondre(&self, message: MessageMilleGrille, reply_q: &str, correlation_id: &str) -> Result<(), String> {
        self.generateur_messages.repondre(message, reply_q, correlation_id).await
    }

    async fn emettre_message(&self, domaine: &str, action: &str, partition: Option<&str>, type_message: TypeMessageOut, message: &str, exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String> {
        self.generateur_messages.emettre_message(domaine, action, partition, type_message, message, exchange, blocking).await
    }

    async fn emettre_message_millegrille(&self, domaine: &str, action: &str, partition: Option<&str>, exchange: Option<Securite>, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille) -> Result<Option<TypeMessage>, String> {
        self.generateur_messages.emettre_message_millegrille(domaine, action, partition, exchange, blocking, type_message, message).await
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

impl Chiffreur for MiddlewareDbPki {
    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
        let guard = self.cles_chiffrage.lock().expect("lock");

        // Copier les cles (extraire du mutex), retourner dans un vecteur
        let vals: Vec<FingerprintCertPublicKey> = guard.iter().map(|v| v.1.to_owned()).collect();

        vals
    }
}

#[async_trait]
impl Dechiffreur for MiddlewareDbPki {

    async fn get_cipher_data(&self, hachage_bytes: &str) -> Result<Mgs2CipherData, Box<dyn Error>> {
        let requete = {
            let mut liste_hachage_bytes = Vec::new();
            liste_hachage_bytes.push(hachage_bytes);
            json!({
                "liste_hachage_bytes": liste_hachage_bytes,
            })
        };
        let reponse_cle_rechiffree = self.transmettre_requete(
            "MaitreDesCles.dechiffrage", "dechiffrage", None, &requete, None).await?;

        let m = match reponse_cle_rechiffree {
            TypeMessage::Valide(m) => m.message,
            _ => Err(format!("Mauvais type de reponse : {:?}", reponse_cle_rechiffree))?
        };

        let contenu_dechiffrage: ReponseDechiffrageCle = serde_json::from_value(
            serde_json::to_value(m.get_msg().contenu.clone())?
        )?;

        contenu_dechiffrage.to_cipher_data()
    }

    // fn get_enveloppe_privee_dechiffrage(&self) -> Arc<EnveloppePrivee> {
    //     self.configuration.get_configuration_pki().get_enveloppe_privee().clone()
    // }
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
        let message = formatter_message_certificat(enveloppe_privee.enveloppe.as_ref());
        let exchanges = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);

        match generateur_message.emettre_evenement("certificat", "infoCertificat", None, &message, Some(exchanges)).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Erreur emettre_certificat: {:?}", e)),
        }
    }
}
