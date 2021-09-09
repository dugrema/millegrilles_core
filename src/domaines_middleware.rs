//! Core de millegrilles installe sur un noeud 3.protege.
//! Sous-domaines : Core.Backup, Core.CatalogueApplications, Core.MaitreDesComptes, Core.Pki, Core.Topologie

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::stream::FuturesUnordered;
use log::{debug, info, error, warn};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{EmetteurCertificat, preparer_middleware_pki};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{Callback, ConfigQueue, ConfigRoutingExchange, EventMq, QueueType};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::transactions::resoumettre_transactions;
use tokio::{sync::{mpsc, mpsc::{Receiver, Sender}}, time::{Duration as DurationTokio, timeout}};
use tokio_stream::StreamExt;

use crate::sousdomaine_pki::{consommer_messages as consommer_pki, preparer_index_mongodb as preparer_index_mongodb_pki};
use tokio::time::sleep;

const DUREE_ATTENTE: u64 = 20000;

pub async fn build() {
    // Preparer configuration
    let queues = preparer_config_queues();

    let (tx, rx) = mpsc::channel(1);

    let listeners = {
        let mut callbacks: Callback<EventMq> = Callback::new();
        callbacks.register(Box::new(move |event| {
            debug!("Ceci est un test de callback sur connexion, event : {:?}", event);
            // tx.blocking_send(event).expect("Event connexion MQ");
            let tx_ref = tx.clone();
            let _ = tokio::spawn(async move{
                match tx_ref.send(event).await {
                    Ok(_) => (),
                    Err(e) => error!("Erreur queuing via callback : {:?}", e)
                }
            });
        }));

        Some(Mutex::new(callbacks))
    };

    let (
        middleware,
        rx_messages_verifies,
        rx_triggers,
        future_recevoir_messages
    ) = preparer_middleware_pki(queues, listeners);

    debug!("Creer index sous mongo");
    preparer_index_mongodb(middleware.as_ref()).await.expect("Index mongo");
    debug!("Index mongodb crees");

    // Demarrer threads
    let mut futures = FuturesUnordered::new();

    // Thread consommation
    let (tx_pki_messages, rx_pki_messages) = mpsc::channel::<TypeMessage>(20);
    let (tx_pki_triggers, rx_pki_triggers) = mpsc::channel::<TypeMessage>(5);

    let mut map_senders: HashMap<String, Sender<TypeMessage>> = HashMap::new();
    map_senders.insert(String::from("Pki"), tx_pki_messages.clone());
    map_senders.insert(String::from("Core"), tx_pki_messages.clone());
    map_senders.insert(String::from("certificat"), tx_pki_messages.clone());
    map_senders.insert(String::from("Pki/triggers"), tx_pki_triggers.clone());
    map_senders.insert(String::from("Core/triggers"), tx_pki_triggers.clone());
    futures.push(tokio::spawn(consommer( middleware.clone(), rx_messages_verifies, map_senders.clone())));
    futures.push(tokio::spawn(consommer( middleware.clone(), rx_triggers, map_senders)));

    // Thread d'entretien
    futures.push(tokio::spawn(entretien(middleware.clone(), rx)));

    // Thread ecoute et validation des messages
    for f in future_recevoir_messages {
        futures.push(f);
    }

    futures.push(tokio::spawn(consommer_pki(middleware.clone(), rx_pki_messages)));
    futures.push(tokio::spawn(consommer_pki(middleware.clone(), rx_pki_triggers)));

    debug!("domaines_middleware: Demarrage traitement domaines middleware");
    let arret = futures.next().await;
    debug!("domaines_middleware: Fermeture du contexte, task daemon terminee : {:?}", arret);
}

fn preparer_config_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    let niveaux_securite_public = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);
    let niveaux_securite_prive = vec!(Securite::L2Prive, Securite::L3Protege);

    // RK 1.public (inclus 2.prive et 3.protege)
    for niveau in niveaux_securite_public {
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Pki.infoCertificat"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Core.infoCertificat"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.certificat.*"), exchange: niveau.clone()});
    }

    // RK 2.prive (inclus 3.protege)
    for niveau in niveaux_securite_prive {
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Pki.certificatParPk"), exchange: niveau.clone()});
        rk_volatils.push(ConfigRoutingExchange {routing_key: String::from("requete.Core.certificatParPk"), exchange: niveau.clone()});
    }

    // RK 3.protege seulement
    rk_volatils.push(ConfigRoutingExchange {routing_key: "commande.Pki.certificat".into(), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: "commande.Core.certificat".into(), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.Pki.{}", PKI_COMMANDE_NOUVEAU_CERTIFICAT), exchange: Securite::L3Protege});
    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.Core.{}", PKI_COMMANDE_NOUVEAU_CERTIFICAT), exchange: Securite::L3Protege});

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: "Core/volatils".into(),
            routing_keys: rk_volatils,
            ttl: 300000.into(),
            durable: false,
        }
    ));

    let mut rk_transactions = Vec::new();
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.Pki.{}", PKI_TRANSACTION_NOUVEAU_CERTIFICAT).into(),
        exchange: Securite::L3Protege}
    );
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.Core.{}", PKI_TRANSACTION_NOUVEAU_CERTIFICAT).into(),
        exchange: Securite::L3Protege}
    );

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: "Core/transactions".into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers ("Core".into()));

    queues
}

async fn preparer_index_mongodb(middleware: &impl MongoDao) -> Result<(), String> {
    preparer_index_mongodb_pki(middleware).await?;

    Ok(())
}

async fn entretien<M>(middleware: Arc<M>, mut rx: Receiver<EventMq>)
where
    M: GenerateurMessages + ValidateurX509 + EmetteurCertificat + MongoDao,
{

    let mut certificat_emis = false;

    let collections_transaction = vec!(PKI_COLLECTION_TRANSACTIONS_NOM);

    let mut prochain_entretien_transactions = chrono::Utc::now();
    let intervalle_entretien_transactions = chrono::Duration::minutes(5);

    // for i in 1..11 {
    loop {
        debug!("Task d'entretien");

        let maintenant = chrono::Utc::now();

        middleware.entretien().await;

        if prochain_entretien_transactions < maintenant {
            let resultat = resoumettre_transactions(
                middleware.as_ref(),
                "Core",
                &collections_transaction
            ).await;

            match resultat {
                Ok(_) => {
                    prochain_entretien_transactions = maintenant + intervalle_entretien_transactions;
                },
                Err(e) => {
                    warn!("Erreur resoumission transactions (entretien) : {:?}", e);
                }
            }
        }

        // Sleep jusqu'au prochain entretien
        debug!("Contexte pret, rester ouvert {} secondes", DUREE_ATTENTE / 1000);
        let duration = DurationTokio::from_millis(DUREE_ATTENTE);
        let result = timeout(duration, rx.recv()).await;

        match result {
            Ok(inner) => {
                debug!("Recu event MQ : {:?}", inner);
                match inner {
                    Some(e) => {
                        match e {
                            EventMq::Connecte => {
                            },
                            EventMq::Deconnecte => {
                                // Reset flag certificat
                                certificat_emis = false;
                            }
                        }
                    },
                    None => {
                        warn!("MQ n'est pas disponible, on ferme");
                        break
                        // let duration = DurationTokio::from_millis(DUREE_ATTENTE);
                        // let result = sleep(duration).await;
                        // info!("MQ n'est pas disponible, tentative de reconnexion");
                    },
                }

            },
            Err(_) => {
                debug!("Timeout, entretien est du");
            }
        }

        if certificat_emis == false {
            debug!("Emettre certificat");
            match middleware.emettre_certificat(middleware.as_ref()).await {
                Ok(()) => certificat_emis = true,
                Err(e) => error!("Erreur emission certificat local : {:?}", e),
            }
            debug!("Fin emission traitement certificat local, resultat : {}", certificat_emis);
        }
    }

    // panic!("Forcer fermeture");

}

async fn consommer(
    _middleware: Arc<impl ValidateurX509 + GenerateurMessages + MongoDao>,
    mut rx: Receiver<TypeMessage>,
    map_senders: HashMap<String, Sender<TypeMessage>>
) {
    while let Some(message) = rx.recv().await {
        match &message {
            TypeMessage::Valide(m) => {
                debug!("traiter_messages_valides: Message valide sans routing key/action : {:?}", m.message);
            },
            TypeMessage::ValideAction(m) => {
                let contenu = &m.message;
                let rk = &m.routing_key;
                let action = &m.action;
                debug!("domaines_middleware.consommer: Traiter message valide (action: {}, rk: {}): {:?}", action, rk, contenu);

                match map_senders.get(m.domaine.as_str()) {
                    Some(sender) => {sender.send(message).await.expect("send message vers sous-domaine")},
                    None => error!("Message de domaine inconnu {}, on le drop", m.domaine),
                }
            },
            TypeMessage::Certificat(_) => (),  // Rien a faire
            TypeMessage::Regeneration => (),   // Rien a faire
        }
    }
}



