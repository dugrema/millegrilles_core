use crate::catalogues_manager::CataloguesManager;
use log::debug;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use crate::catalogues_commands::traiter_commande_application;
use crate::catalogues_constants::*;

pub async fn consommer_evenement_catalogues<M>(middleware: &M, m: MessageValide, gestionnaire: &CataloguesManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer evenement : {:?}", &m.type_message);

    let action = match &m.type_message {
        TypeMessageOut::Transaction(r) => {
            r.action.clone()
        },
        _ => Err(format!("consommer_evenement Mauvais type de message"))?
    };

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        true => Ok(()),
        false => Err(format!("core_catalogues.consommer_evenement Autorisation invalide (pas 3.protege/4.secure) : action = {}", action)),
    }?;

    match action.as_str() {
        TRANSACTION_APPLICATION => traiter_commande_application(middleware, m, gestionnaire).await,
        _ => Err(format!("core_catalogues.consommer_evenement Mauvais type d'action pour un evenement : {}", action))?,
    }
}
