use log::{debug, error};
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::constantes::{Securite, DOMAINE_APPLICATION_INSTANCE};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::MiddlewareMessages;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::serde_json::json;
use crate::catalogues_manager::CataloguesManager;

pub async fn traiter_cedule_catalogues<M>(middleware: &M, _trigger: &MessageCedule, gestionnaire: &CataloguesManager) -> Result<(), Error>
where
    M: MiddlewareMessages + BackupStarter + MongoDao
{
    // Every minute
    let catalogues_charges = {
        let guard = gestionnaire.catalogues_charges.try_lock().expect("lock");
        *guard
    };
    if ! catalogues_charges {
        debug!("Charger catalogues");
        charger_catalogues(middleware).await;
        // Set true
        let mut guard = gestionnaire.catalogues_charges.try_lock().expect("lock");
        *guard = true;
    }

    Ok(())
}

async fn charger_catalogues<M>(middleware: &M)
    where M: GenerateurMessages
{
    let commande = json!({});

    let routage = RoutageMessageAction::builder(
        DOMAINE_APPLICATION_INSTANCE, "transmettreCatalogues", vec![Securite::L3Protege])
        .build();

    // Cette commande est un trigger pour emettre les catalogues - on n'a pas a traiter la reponse.
    match middleware.transmettre_commande(routage, &commande).await {
        Ok(r) => {
            debug!("Reponse demande catalogues : {:?}", r);
        },
        Err(e) => {
            error!("Erreur demande catalogues : {:?}", e);
        }
    }

}
