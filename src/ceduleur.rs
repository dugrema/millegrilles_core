use std::sync::Arc;

use tokio::task::JoinHandle;
use futures::stream::FuturesUnordered;
use async_trait::async_trait;
use bson::Document;
use log::{debug, error, info, warn};
use millegrilles_common_rust::certificats::{charger_enveloppe, ValidateurX509};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{formatter_message_certificat, MiddlewareDbPki, upsert_certificat};
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::transactions::{charger_transaction, EtatTransaction, marquer_transaction, Transaction};
use mongodb::bson::doc;
use serde_json::{json, Value};
use std::error::Error;
use millegrilles_common_rust::{TraiterTransaction, sauvegarder_transaction, TriggerTransaction, TransactionImpl, QueueType, ConfigRoutingExchange, ConfigQueue, MessageCedule};
use std::collections::HashMap;
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use tokio::time::{Duration, sleep_until, Instant};
use std::ops::Add;
use chrono::{Utc, Timelike};

/// Emet un message signe avec le temps epoch courant a toutes les minutes.
/// Permet aux modules de facilement executer des taches cedulees.
pub async fn preparer_threads(middleware: Arc<MiddlewareDbPki>) -> Result<FuturesUnordered<JoinHandle<()>>, Box<dyn Error>> {

    // Thread consommation
    let futures = FuturesUnordered::new();
    futures.push(tokio::spawn(thread_emettre_heure(middleware.clone())));

    Ok(futures)
}

/// Thread qui emet le temps epoch courant a toutes les minutes
async fn thread_emettre_heure(middleware: Arc<MiddlewareDbPki>) {

    loop {
        let instant = calculer_delai_prochaines_minute();
        debug!("Prochain trigger cedule : {:?}", instant);
        sleep_until(instant).await;
        match emettre_trigger(middleware.as_ref()).await {
            Ok(()) => (),
            Err(e) => {
                error!("Erreur emission trigger cedule : {:?}", e);
            }
        }
    }

}

fn calculer_delai_prochaines_minute() -> Instant {
    let current = Utc::now();
    let delai = (62 - current.time().second()) as u64;
    let duration = Duration::new(delai, 0);

    let instant = Instant::now();
    instant.add(duration)
}

async fn emettre_trigger<M>(middleware: &M) -> Result<(), Box<dyn Error>>
where M: GenerateurMessages
{

    let message = MessageCedule::now();
    debug!("Emettre trigger cedule {:?}", message);

    let mut exchanges = Vec::new();
    exchanges.push(Securite::L1Public);
    exchanges.push(Securite::L2Prive);
    exchanges.push(Securite::L3Protege);
    exchanges.push(Securite::L4Secure);

    middleware.emettre_evenement(
        "global",
        "cedule",
        None, &message,
        Some(exchanges)
    ).await?;

    Ok(())
}