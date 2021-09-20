//! Core de millegrilles installe sur un noeud 3.protege.
//! Sous-domaines : CoreBackup, CoreCatalogueApplications, CoreMaitreDesComptes, CorePki, CoreTopologie

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use log::{debug, error, warn};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono as chrono;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::EmetteurCertificat;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{Callback, EventMq, QueueType};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::tokio::{sync::{mpsc, mpsc::{Receiver, Sender}}, time::{Duration as DurationTokio, timeout}};
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::resoumettre_transactions;

use crate::ceduleur::preparer_threads as preparer_threads_ceduleur;
use crate::corepki::{preparer_queues as preparer_q_corepki, preparer_threads as preparer_threads_corepki, NOM_COLLECTION_TRANSACTIONS as PKI_NOM_COLLECTION_TRANSACTIONS};
use crate::corecatalogues::{preparer_queues as preparer_q_catalogues, preparer_threads as preparer_threads_corecatalogues, NOM_COLLECTION_TRANSACTIONS as CATALOGUES_NOM_COLLECTION_TRANSACTIONS};
use crate::coretopologie::{preparer_queues as preparer_q_topologie, preparer_threads as preparer_threads_coretopologie, NOM_COLLECTION_TRANSACTIONS as TOPOLOGIE_NOM_COLLECTION_TRANSACTIONS};
use crate::validateur_pki_mongo::preparer_middleware_pki;

const DUREE_ATTENTE: u64 = 20000;

pub async fn build() {

    // Recuperer configuration des Q de tous les domaines
    let mut queues: Vec<QueueType> = preparer_q_corepki();
    queues.extend(preparer_q_corepki());
    queues.extend(preparer_q_catalogues());
    queues.extend(preparer_q_topologie());

    // Listeners de connexion MQ
    let (tx_entretien, rx_entretien) = mpsc::channel(1);
    let listeners = {
        let mut callbacks: Callback<EventMq> = Callback::new();
        callbacks.register(Box::new(move |event| {
            debug!("Callback sur connexion a MQ, event : {:?}", event);
            let tx_ref = tx_entretien.clone();
            let _ = spawn(async move{
                match tx_ref.send(event).await {
                    Ok(_) => (),
                    Err(e) => error!("Erreur queuing via callback : {:?}", e)
                }
            });
        }));

        Some(Mutex::new(callbacks))
    };

    // Preparer middleware avec acces direct aux tables Pki (le domaine est local)
    let (
        middleware,
        rx_messages_verifies,
        rx_triggers,
        future_recevoir_messages
    ) = preparer_middleware_pki(queues, listeners);

    // Preparer les green threads de tous les domaines/processus
    let mut futures = FuturesUnordered::new();
    {
        let mut map_senders: HashMap<String, Sender<TypeMessage>> = HashMap::new();

        // ** Domaines **

        // Preparer domaine CorePki
        let (
            routing_pki,
            futures_pki
        ) = preparer_threads_corepki(middleware.clone()).await.expect("core pki");
        futures.extend(futures_pki);        // Deplacer vers futures globaux
        map_senders.extend(routing_pki);    // Deplacer vers mapping global

        // Preparer domaine CoreCatalogues
        let (
            routing_catalogues,
            futures_catalogues
        ) = preparer_threads_corecatalogues(middleware.clone()).await.expect("core catalogues");
        futures.extend(futures_catalogues);        // Deplacer vers futures globaux
        map_senders.extend(routing_catalogues);    // Deplacer vers mapping global

        // Preparer domaine CoreTopologie
        let (
            routing_topologie,
            futures_topologie
        ) = preparer_threads_coretopologie(middleware.clone()).await.expect("core topologie");
        futures.extend(futures_topologie);        // Deplacer vers futures globaux
        map_senders.extend(routing_topologie);    // Deplacer vers mapping global

        // Preparer ceduleur (emet triggers a toutes les minutes)
        let ceduleur = preparer_threads_ceduleur(middleware.clone()).await.expect("ceduleur");
        futures.extend(ceduleur);           // Deplacer vers futures globaux

        // ** Wiring global **

        // Creer consommateurs MQ globaux pour rediriger messages recus vers Q internes appropriees
        futures.push(spawn(
            consommer( middleware.clone(), rx_messages_verifies, map_senders.clone())
        ));
        futures.push(spawn(
            consommer( middleware.clone(), rx_triggers, map_senders)
        ));

        // ** Thread d'entretien **
        futures.push(spawn(entretien(middleware.clone(), rx_entretien)));

        // Thread ecoute et validation des messages
        for f in future_recevoir_messages {
            futures.push(f);
        }

    }

    debug!("domaines_middleware: Demarrage traitement domaines middleware");
    let arret = futures.next().await;
    debug!("domaines_middleware: Fermeture du contexte, task daemon terminee : {:?}", arret);
}

/// Thread d'entretien de Core
async fn entretien<M>(middleware: Arc<M>, mut rx: Receiver<EventMq>)
where
    M: GenerateurMessages + ValidateurX509 + EmetteurCertificat + MongoDao,
{

    let mut certificat_emis = false;

    // Liste de collections de transactions pour tous les domaines geres par Core
    let collections_transaction = vec! [
        PKI_NOM_COLLECTION_TRANSACTIONS,
        CATALOGUES_NOM_COLLECTION_TRANSACTIONS,
        TOPOLOGIE_NOM_COLLECTION_TRANSACTIONS,
    ];

    let mut prochain_entretien_transactions = chrono::Utc::now();
    let intervalle_entretien_transactions = chrono::Duration::minutes(5);

    loop {
        let maintenant = chrono::Utc::now();
        debug!("Execution task d'entretien Core {:?}", maintenant);

        middleware.entretien().await;

        if prochain_entretien_transactions < maintenant {
            let resultat = resoumettre_transactions(
                middleware.as_ref(),
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
        debug!("Task entretien core fin cycle, sleep {} secondes", DUREE_ATTENTE / 1000);
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
                let rk = m.routing_key.as_str();
                let action = m.action.as_str();
                let domaine = m.domaine.as_str();
                let nom_q = m.q.as_str();
                debug!("domaines_middleware.consommer: Traiter message valide (action: {}, rk: {}, q: {}): {:?}", action, rk, nom_q, contenu);

                // Tenter de mapper avec le nom de la Q (ne fonctionnera pas pour la Q de reponse)
                let sender = match map_senders.get(nom_q) {
                    Some(sender) => sender,
                    None => {
                        match map_senders.get(domaine) {
                            Some(sender) => sender,
                            None => {
                                error!("Message de queue ({}) et domaine ({}) inconnu, on le drop", nom_q, domaine);
                                continue  // On skip
                            },
                        }
                    }
                };

                match sender.send(message).await {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Erreur consommer message {:?}", e)
                    }
                }
            },
            TypeMessage::Certificat(_) => (),  // Rien a faire
            TypeMessage::Regeneration => (),   // Rien a faire
        }
    }
}



