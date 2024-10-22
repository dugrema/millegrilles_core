use log::{debug, error, warn};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::constantes::DOMAINE_PKI;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_serializable_v2, EmetteurNotificationsTrait};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::mongo_dao::MongoDao;

use crate::pki_constants::*;
use crate::pki_manager::PkiManager;
use crate::pki_structs::CorePkiCollectionRow;
use crate::pki_transactions::TransactionCertificat;
use crate::topology_events::produire_fiche_publique;

pub async fn traiter_cedule_pki<M>(middleware: &M, gestionnaire: &PkiManager, trigger: &MessageCedule) -> Result<(), millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler + EmetteurNotificationsTrait
{
    let date_epoch = trigger.get_date();
    debug!("Traiter cedule {}\n{:?}", DOMAIN_NAME, date_epoch);

    if middleware.get_mode_regeneration() == true {
        debug!("traiter_cedule Mode regeneration, skip entretien");
        return Ok(());
    }

    let minutes = date_epoch.minute();

    // Sauvegarder certificats dirty
    // if minutes % 5 == 2 {
    {
        if let Err(e) = sauvegarder_certificats_dirty(middleware, gestionnaire).await {
            error!("pki_maintenance.traiter_cedule Erreur sauvegarde certificats dirty : {:?}", e);
        }
    }

    Ok(())
}

async fn sauvegarder_certificats_dirty<M>(middleware: &M, gestionnaire: &PkiManager) -> Result<(), millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("sauvegarder_certificats_dirty");
    let filtre = doc!(CONST_CHAMP_DIRTY: true);
    let collection = middleware.get_collection_typed::<CorePkiCollectionRow>(COLLECTION_CERTIFICAT_NOM)?;
    let mut cursor = collection.find(filtre, None).await?;
    while(cursor.advance().await?) {
        let row = cursor.deserialize_current()?;
        let transaction: TransactionCertificat = row.into();
        sauvegarder_traiter_transaction_serializable_v2(
            middleware, &transaction, gestionnaire, DOMAINE_PKI, PKI_COMMANDE_SAUVEGARDER_CERTIFICAT).await?;
    }
    Ok(())
}
