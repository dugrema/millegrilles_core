use crate::catalogues_constants::*;
use crate::catalogues_structs::{Catalogue, MessageCatalogue, PackageVersion};
use log::debug;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::{CHAMP_CREATION, CHAMP_MODIFICATION};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use millegrilles_common_rust::serde_json;

pub async fn aiguillage_transaction_catalogues<M, T>(middleware: &M, transaction: T, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: TryInto<TransactionValide>
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(format!("aiguillage_transaction Erreur try_into"))?
    };
    let message_id = transaction.transaction.id.clone();
    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => {
            match inner.action.as_ref() {
                Some(inner) => inner.clone(),
                None => Err(format!("Transaction {} n'a pas d'action", message_id))?
            }
        },
        None => Err(format!("Transaction {} n'a pas de routage", message_id))?
    };

    match action.as_str() {
        TRANSACTION_APPLICATION => maj_catalogue(middleware, transaction, session).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", message_id, action))?,
    }
}

async fn maj_catalogue<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
                          -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("maj_catalogue Sauvegarder application recu via catalogue (transaction)");
    debug!("maj_catalogue Parse catalogue\n{}", transaction.transaction.contenu);
    // let escaped_catalogue: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;

    let transaction_catalogue: MessageCatalogue = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("core_catalogues.maj_catalogue Erreur transaction.convertir {:?}", e))?
    };

    let catalogue: Catalogue = match transaction_catalogue.catalogue.deserialize() {
        Ok(inner) => inner,
        Err(e) => Err(format!("core_catalogues.maj_catalogue Erreur catalogue map_contenu vers Catalogue {:?}", e))?
    };

    let nom = catalogue.nom.clone();
    let version = catalogue.version.clone();

    // Filtrer le contenu (retirer champs _)
    let set_ops = match convertir_to_bson(catalogue) {
        Ok(inner) => inner,
        Err(e) => Err(format!("core_catalogues.maj_catalogue Erreur convertir_to_bson {:?}", e))?
    };

    debug!("set-ops : {:?}", set_ops);
    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    {
        let collection_catalogues_versions = middleware.get_collection(NOM_COLLECTION_CATALOGUES_VERSIONS)?;
        let filtre = doc! { CHAMP_NOM_CATALOGUE: &nom, CHAMP_VERSION: &version };
        let opts = UpdateOptions::builder().upsert(true).build();
        let resultat = match collection_catalogues_versions.update_one_with_session(filtre, ops.clone(), Some(opts), session).await {
            Ok(r) => r,
            Err(e) => Err(format!("core_catalogues.maj_catalogue Erreur maj document catalogue avec mongo : {:?}", e))?
        };
        debug!("Resultat maj catalogue_versions : {:?}", resultat);
    }
    
    {
        // Determine if the new version should be bumped up automatically
        let filtre = doc! { "nom": &nom };
        let collection_catalogues = middleware.get_collection_typed::<Catalogue>(NOM_COLLECTION_CATALOGUES)?;

        let mut update = true;  // This is used to avoid updating if the version is older/equal
        if let Ok(new_version) = PackageVersion::try_from(version.clone()) {
            let current_version = collection_catalogues.find_one(filtre.clone(), None).await?;
            if let Some(current_version) = current_version {
                if let Ok(current_version) = PackageVersion::try_from(current_version.version.clone()) {
                    update = current_version < new_version;
                }

                debug!("Update {} to {} -> {}", current_version.version, version, update);
            }
        }

        debug!("Update {} to {} -> {}", nom, version, update);
        
        if update {
            let opts = UpdateOptions::builder().upsert(true).build();
            let resultat = match collection_catalogues.update_one_with_session(filtre, ops, Some(opts), session).await {
                Ok(r) => r,
                Err(e) => Err(format!("Erreur maj document catalogue avec mongo : {:?}", e))?
            };
            debug!("Resultat maj catalogues : {:?}", resultat);
        }
    }

    Ok(None)
}
