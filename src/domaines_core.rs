//! Core de millegrilles installe sur un noeud 3.protege.
//! Sous-domaines : CoreBackup, CoreCatalogueApplications, CoreMaitreDesComptes, CorePki, CoreTopologie

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chiffrage::Chiffreur;
use millegrilles_common_rust::chrono as chrono;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{EmetteurCertificat, Middleware};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{Callback, EventMq, QueueType};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::tokio::{sync::{mpsc, mpsc::{Receiver, Sender}}, time::{Duration as DurationTokio, timeout}};
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::resoumettre_transactions;

use crate::ceduleur::preparer_threads as preparer_threads_ceduleur;
// use crate::core_backup::GESTIONNAIRE_BACKUP;
// use crate::core_catalogues::{NOM_COLLECTION_TRANSACTIONS as CATALOGUES_NOM_COLLECTION_TRANSACTIONS, preparer_queues as preparer_q_catalogues, preparer_threads as preparer_threads_corecatalogues};
use crate::core_catalogues::{GESTIONNAIRE_CATALOGUES, init_regles_validation as init_validation_catalogues};
use crate::core_maitredescomptes::GESTIONNAIRE_MAITREDESCOMPTES;
use crate::core_pki::GESTIONNAIRE_PKI;
use crate::core_topologie::GESTIONNAIRE_TOPOLOGIE;
use crate::validateur_pki_mongo::preparer_middleware_pki;

const DUREE_ATTENTE: u64 = 20000;

pub async fn build() -> FuturesUnordered<JoinHandle<()>> {

    init_validation_catalogues();

    let middleware_hooks = preparer_middleware_pki();
    let middleware = middleware_hooks.middleware;

    // Tester connexion redis
    if let Some(redis) = middleware.redis.as_ref() {
        match redis.liste_certificats_fingerprints().await {
            Ok(fingerprints_redis) => {
                info!("redis.liste_certificats_fingerprints Resultat : {:?}", fingerprints_redis);
            },
            Err(e) => warn!("redis.liste_certificats_fingerprints Erreur test de connexion redis : {:?}", e)
        }
    }

    // Preparer les green threads de tous les domaines/processus
    let mut futures = FuturesUnordered::new();

    // ** Domaines **
    futures.extend( GESTIONNAIRE_PKI.preparer_threads(middleware.clone()).await.expect("core pki") );
    futures.extend( GESTIONNAIRE_CATALOGUES.preparer_threads(middleware.clone()).await.expect("core pki") );
    futures.extend( GESTIONNAIRE_TOPOLOGIE.preparer_threads(middleware.clone()).await.expect("core pki") );
    futures.extend( GESTIONNAIRE_MAITREDESCOMPTES.preparer_threads(middleware.clone()).await.expect("core pki") );

    // Preparer ceduleur (emet triggers a toutes les minutes)
    futures.extend(preparer_threads_ceduleur(middleware.clone()).await.expect("ceduleur"));

    // ** Thread d'entretien **
    futures.push(spawn(entretien(middleware.clone())));

    // Thread ecoute et validation des messages
    info!("domaines_maitredescles.build Ajout {} futures dans middleware_hooks", futures.len());
    for f in middleware_hooks.futures {
        futures.push(f);
    }

    futures

    // Recuperer configuration des Q de tous les domaines
    // let mut queues: Vec<QueueType> = Vec::new();
    // queues.extend(GESTIONNAIRE_PKI.preparer_queues());
    // queues.extend(GESTIONNAIRE_CATALOGUES.preparer_queues());
    // queues.extend(GESTIONNAIRE_TOPOLOGIE.preparer_queues());
    // queues.extend(GESTIONNAIRE_MAITREDESCOMPTES.preparer_queues());
    // // queues.extend(GESTIONNAIRE_BACKUP.preparer_queues());

    // // Listeners de connexion MQ
    // let (tx_entretien, rx_entretien) = mpsc::channel(1);
    // let listeners = {
    //     let mut callbacks: Callback<EventMq> = Callback::new();
    //     callbacks.register(Box::new(move |event| {
    //         debug!("Callback sur connexion a MQ, event : {:?}", event);
    //         let tx_ref = tx_entretien.clone();
    //         let _ = spawn(async move{
    //             match tx_ref.send(event).await {
    //                 Ok(_) => (),
    //                 Err(e) => error!("Erreur queuing via callback : {:?}", e)
    //             }
    //         });
    //     }));
    //
    //     Some(Mutex::new(callbacks))
    // };

    // // Preparer middleware avec acces direct aux tables Pki (le domaine est local)
    // let ressources = preparer_middleware_pki();
    //
    // debug!("Preparer middleware pki complete");
    //
    // // Tester connexion redis
    // match middleware.redis.liste_certificats_fingerprints().await {
    //      Ok(fingerprints_redis) => {
    //          info!("redis.liste_certificats_fingerprints Resultat : {:?}", fingerprints_redis);
    //      },
    //      Err(e) => warn!("redis.liste_certificats_fingerprints Erreur test de connexion redis : {:?}", e)
    // }
    //
    // // Preparer les green threads de tous les domaines/processus
    // let mut futures = FuturesUnordered::new();
    // {
    //     let mut map_senders: HashMap<String, Sender<TypeMessage>> = HashMap::new();
    //
    //     // ** Domaines **
    //
    //     // Preparer domaine CorePki
    //     let (
    //         routing_pki,
    //         futures_pki,
    //         _, _
    //     ) = GESTIONNAIRE_PKI.preparer_threads(middleware.clone()).await.expect("core pki");
    //     futures.extend(futures_pki);        // Deplacer vers futures globaux
    //     map_senders.extend(routing_pki);    // Deplacer vers mapping global
    //
    //     // Preparer domaine CoreCatalogues
    //     let (
    //         routing_catalogues,
    //         futures_catalogues,
    //         _, _
    //     ) = GESTIONNAIRE_CATALOGUES.preparer_threads(middleware.clone()).await.expect("core catalogues");
    //     futures.extend(futures_catalogues);        // Deplacer vers futures globaux
    //     map_senders.extend(routing_catalogues);    // Deplacer vers mapping global
    //
    //     // Preparer domaine CoreTopologie
    //     let (
    //         routing_topologie,
    //         futures_topologie,
    //         _, _
    //     ) = GESTIONNAIRE_TOPOLOGIE.preparer_threads(middleware.clone()).await.expect("core topologie");
    //     futures.extend(futures_topologie);        // Deplacer vers futures globaux
    //     map_senders.extend(routing_topologie);    // Deplacer vers mapping global
    //
    //     // Preparer domaine CoreMaitreDesComptes
    //     let (
    //         routing_maitredescomptes,
    //         futures_maitredescomptes,
    //         _, _
    //     ) = GESTIONNAIRE_MAITREDESCOMPTES.preparer_threads(middleware.clone()).await.expect("core maitredescomptes");
    //     futures.extend(futures_maitredescomptes);        // Deplacer vers futures globaux
    //     map_senders.extend(routing_maitredescomptes);    // Deplacer vers mapping global
    //
    //     // Preparer ceduleur (emet triggers a toutes les minutes)
    //     let ceduleur = preparer_threads_ceduleur(middleware.clone()).await.expect("ceduleur");
    //     futures.extend(ceduleur);           // Deplacer vers futures globaux
    //
    //     // ** Wiring global **
    //
    //     // Creer consommateurs MQ globaux pour rediriger messages recus vers Q internes appropriees
    //     futures.push(spawn(
    //         consommer( middleware.clone(), rx_messages_verifies, map_senders.clone())
    //     ));
    //     futures.push(spawn(
    //         consommer( middleware.clone(), rs_messages_verif_reply, map_senders.clone())
    //     ));
    //     futures.push(spawn(
    //         consommer( middleware.clone(), rx_triggers, map_senders)
    //     ));
    //
    //     // ** Thread d'entretien **
    //     futures.push(spawn(entretien(middleware.clone(), rx_entretien)));
    //
    //     // Thread ecoute et validation des messages
    //     for f in future_recevoir_messages {
    //         futures.push(f);
    //     }
    //
    // }
    //
    // info!("domaines_middleware: Demarrage traitement domaines middleware, top level threads {}", futures.len());
    // let arret = futures.next().await;
    // info!("domaines_middleware: Fermeture du contexte, task daemon terminee : {:?}", arret);
}

/// Thread d'entretien de Core
async fn entretien<M>(middleware: Arc<M>)
    where M: Middleware
{
    let mut certificat_emis = false;

    // Liste de collections de transactions pour tous les domaines geres par Core
    let collections_transaction = {
        let mut coll_docs_strings = Vec::new();
        // coll_docs_strings.push(String::from(GESTIONNAIRE_BACKUP.get_collection_transactions()));
        if let Some(nom_collection) = GESTIONNAIRE_MAITREDESCOMPTES.get_collection_transactions() {
            coll_docs_strings.push(String::from(nom_collection));
        }
        if let Some(nom_collection) = GESTIONNAIRE_CATALOGUES.get_collection_transactions() {
            coll_docs_strings.push(String::from(nom_collection));
        }
        if let Some(nom_collection) = GESTIONNAIRE_TOPOLOGIE.get_collection_transactions() {
            coll_docs_strings.push(String::from(nom_collection));
        }
        if let Some(nom_collection) = GESTIONNAIRE_PKI.get_collection_transactions() {
            coll_docs_strings.push(String::from(nom_collection));
        }
        coll_docs_strings
    };

    let mut prochain_entretien_transactions = chrono::Utc::now();
    let intervalle_entretien_transactions = chrono::Duration::minutes(5);

    let mut prochain_chargement_certificats_maitredescles = chrono::Utc::now();
    let intervalle_chargement_certificats_maitredescles = chrono::Duration::minutes(5);

    let mut prochain_entretien_validateur = chrono::Utc::now();
    let intervalle_entretien_validateur = chrono::Duration::minutes(2);

    loop {
        let maintenant = chrono::Utc::now();
        debug!("Execution task d'entretien Core {:?}", maintenant);

        if prochain_entretien_validateur < maintenant {
            prochain_entretien_validateur = maintenant + intervalle_entretien_validateur;
            middleware.entretien_validateur().await;
        }

        if prochain_chargement_certificats_maitredescles < maintenant {
            match middleware.charger_certificats_chiffrage(middleware.as_ref()).await {
                Ok(()) => {
                    prochain_chargement_certificats_maitredescles = maintenant + intervalle_chargement_certificats_maitredescles;
                    debug!("Prochain chargement cert maitredescles: {:?}", prochain_chargement_certificats_maitredescles);
                },
                Err(e) => warn!("Erreur chargement certificats de maitre des cles : {:?}", e)
            }
        }

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
        sleep(duration).await;

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
    info!("consommer: Mapping senders core : {:?}", map_senders.keys());

    while let Some(message) = rx.recv().await {
        match &message {
            TypeMessage::Valide(m) => {
                warn!("traiter_messages_valides: Message valide sans routing key/action : {:?}", m.message);
            },
            TypeMessage::ValideAction(m) => {
                let contenu = &m.message;
                let rk = m.routing_key.as_str();
                let action = m.action.as_str();
                let domaine = m.domaine.as_str();
                let nom_q = m.q.as_str();
                debug!("domaines_middleware.consommer: Traiter message valide (action: {}, rk: {}, q: {})", action, rk, nom_q);
                trace!("domaines_middleware.consommer: Traiter message valide (action: {}, rk: {}, q: {}): {:?}", action, rk, nom_q, contenu);

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



