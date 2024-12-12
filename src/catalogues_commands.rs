use log::{debug, error};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::{Securite, DELEGATION_GLOBALE_PROPRIETAIRE};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_v2, Middleware};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::mongo_dao::{start_transaction_regular, MongoDao};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use serde::Deserialize;
use crate::catalogues_manager::CataloguesManager;
use crate::catalogues_constants::*;
use crate::catalogues_structs::MessageCatalogue;

pub async fn consommer_commande_catalogues<M>(middleware: &M, m: MessageValide, gestionnaire: &CataloguesManager)
                                              -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: Middleware
{
    debug!("Consommer commande : {:?}", &m.type_message);

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges(vec!(Securite::L3Protege, Securite::L4Secure))? {
        true => Ok(()),
        false => {
            match m.certificat.verifier_delegation_globale(String::from(DELEGATION_GLOBALE_PROPRIETAIRE))? {
                true => Ok(()),
                false => Err("Commande autorisation invalide (pas 3.protege ou 4.secure)")
            }
        },
    }?;

    let action = match &m.type_message {
        TypeMessageOut::Commande(r) => {
            r.action.clone()
        }
        _ => Err(format!("consommer_commande Mauvais type de de message"))?
    };

    let result = match action.as_str() {
        // Commandes standard
        TRANSACTION_APPLICATION => traiter_commande_application(middleware, m, gestionnaire, &mut session).await,
        _ => Err(format!("Commande {} inconnue : {}, message dropped", DOMAIN_NAME, action))?,
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


#[derive(Clone, Debug, Deserialize)]
struct CatalogueApplication {
    nom: String,
    version: String,
}

pub async fn traiter_commande_application<M>(middleware: &M, commande: MessageValide, gestionnaire: &CataloguesManager, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + MongoDao + GenerateurMessages
{
    debug!("traiter_commande_application Traitement catalogue application {:?}", commande.type_message);

    let mut message_catalogue: MessageCatalogue = {
        let message_ref = commande.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        message_contenu.deserialize()?
    };

    let info_catalogue: CatalogueApplication = message_catalogue.catalogue.deserialize()?;
    debug!("traiter_commande_application Information catalogue charge : {:?}", info_catalogue);

    // Verifier la signature du catalogue (ne verifie pas le certificat)
    let catalogue_buffer: MessageMilleGrillesBufferDefault = message_catalogue.catalogue.try_into()?;
    let mut catalogue_ref = catalogue_buffer.parse()?;
    catalogue_ref.verifier_signature()?;

    let collection_catalogues = middleware.get_collection(NOM_COLLECTION_CATALOGUES_VERSIONS)?;
    let version = info_catalogue.version.as_str();
    let filtre = doc! {
        CHAMP_NOM_CATALOGUE: info_catalogue.nom.as_str(),
        CHAMP_VERSION: version,
    };

    let doc_catalogue = collection_catalogues.find_one_with_session(filtre, None, session).await?;
    if doc_catalogue.is_some() {
        debug!("traiter_commande_application Catalogue {} version {} deja dans DB, skip.", info_catalogue.nom, info_catalogue.version);
        return Ok(None)
    }

    match &doc_catalogue {
        Some(d) => {
            let version = d.get_str(CHAMP_VERSION)?;
            // Verifier si la version recue est plus grande que celle sauvegardee
            debug!("Version recue : {}, dans DB : {}", info_catalogue.version, version);

            // Si version moins grande, on skip
            if version == info_catalogue.version {
                debug!("Meme version de catalogue, on skip");
                return Ok(None)
            }
        },
        None => (),
    };

    // Valider le certificat et regles du catalogues.
    match middleware.valider_certificat_idmg(&catalogue_ref, "catalogues").await {
        Ok(inner) => {
            debug!("traiter_commande_application Catalogue accepte - certificat valide : {}/{}",
                &info_catalogue.nom, &info_catalogue.version);
            // Conserver la transaction et la traiter immediatement
            sauvegarder_traiter_transaction_v2(middleware, commande, gestionnaire, session).await?;
        },
        Err(e) => {
            error!("traiter_commande_application Catalogue rejete - certificat invalide : {}/{} : {:?}", &info_catalogue.nom, &info_catalogue.version, e);
        }
    }

    Ok(None)
}
