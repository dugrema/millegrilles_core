use log::debug;

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;

pub async fn consommer_evenement_maitredescomptes<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer evenement : {:?}", &m.type_message);

    let action = match &m.type_message {
        TypeMessageOut::Evenement(r) => {
            r.action.clone()
        },
        _ => Err(format!("consommer_transaction Mauvais type de message"))?
    };

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges(vec!(Securite::L4Secure))? {
        true => Ok(()),
        false => Err(format!("core_maitredescomptes.consommer_evenement Autorisation invalide (pas 4.secure) : {}", action)),
    }?;

    match action.as_str() {
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", action))?,
    }
}
