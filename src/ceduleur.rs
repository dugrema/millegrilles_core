use std::error::Error;
use std::ops::Add;
use std::sync::Arc;

use log::{debug, error};
use millegrilles_common_rust::chrono::{Timelike, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::{Duration, Instant, sleep_until};

/// Emet un message signe avec le temps epoch courant a toutes les minutes.
/// Permet aux modules de facilement executer des taches cedulees.
pub async fn preparer_threads<M>(middleware: Arc<M>) -> Result<FuturesUnordered<JoinHandle<()>>, Box<dyn Error>>
    where M: GenerateurMessages + 'static
{

    // Thread consommation
    let futures = FuturesUnordered::new();
    futures.push(spawn(thread_emettre_heure(middleware.clone())));

    Ok(futures)
}

/// Thread qui emet le temps epoch courant a toutes les minutes
async fn thread_emettre_heure<M>(middleware: Arc<M>)
    where M: GenerateurMessages
{

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

    let exchanges = vec![
        Securite::L1Public,
        Securite::L2Prive,
        Securite::L3Protege,
        Securite::L4Secure
    ];

    let routage = RoutageMessageAction::builder("global", "cedule", exchanges)
        .build();

    middleware.emettre_evenement(routage, &message).await?;

    Ok(())
}