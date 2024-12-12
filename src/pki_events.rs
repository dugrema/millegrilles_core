use log::debug;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::get_domaine_action;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{start_transaction_regular, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::error::Error;

use crate::pki_commands::traiter_commande_sauvegarder_certificat;
use crate::pki_constants::*;

pub async fn consommer_evenement_pki<M>(middleware: &M, m: MessageValide)
                                -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + ConfigMessages + ValidateurX509 + MongoDao
{
    debug!("Consommer evenement : {:?}", &m.message);
    let (_domaine, action) = get_domaine_action!(&m.type_message);

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    let result = match action.as_str() {
        PKI_REQUETE_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware, m, &mut session).await,
        _ => Err(format!("pki_events.consommer_evenement_pki Mauvais type d'action pour un evenement : {}", action))?,
    };

    match result {
        Ok(result) => {
            session.commit_transaction().await?;
            Ok(result)
        }
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}
