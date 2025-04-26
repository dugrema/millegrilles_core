use std::collections::HashMap;
use log::{debug, error, warn};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::get_domaine_action;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_value, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::mongodb::options::FindOptions;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::tokio_stream::StreamExt;
use serde::{Deserialize, Serialize};

use crate::catalogues_constants::*;
use crate::catalogues_structs::Catalogue;

pub async fn consommer_requete_catalogues<M>(middleware: &M, message: MessageValide)
                                             -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &message.type_message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.
    let (domaine, action) = get_domaine_action!(message.type_message);

    match domaine.as_str() {
        DOMAIN_NAME => {
            match action.as_str() {
                REQUETE_LISTE_APPLICATIONS => liste_applications(middleware).await,
                REQUETE_VERSIONS_APPLICATION => liste_versions_application(middleware, message).await,
                REQUETE_INFO_APPLICATION => repondre_application(middleware, message).await,
                _ => {
                    error!("Message action inconnue : '{}'. Message dropped.", action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete domaine inconnu : '{}'. Message dropped.", domaine);
            Ok(None)
        },
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogueDependance {
    name: Option<String>,
    image: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogueApplicationDeps {
    nom: String,
    version: String,
    securite: Option<String>,
    description: Option<HashMap<String, String>>,
    #[serde(rename="securityLevels")]
    security_levels: Option<Vec<String>>,
    dependances: Option<Vec<CatalogueDependance>>,
    nginx: Option<HashMap<String, Value>>,
    web: Option<HashMap<String, Value>>,
}

#[derive(Serialize)]
struct ReponseListeApplications {
    ok: bool,
    resultats: Option<Vec<CatalogueApplicationDeps>>,
    current_version: Option<String>,
}

async fn liste_applications<M>(middleware: &M)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let filtre = doc! {};
    let projection = doc!{
        "nom": true,
        "version": true,
        "securite": true,
        "securityLevels": true,
        "dependances.name": true,
        "dependances.image": true,
    };

    let collection = middleware.get_collection_typed::<CatalogueApplicationDeps>(NOM_COLLECTION_CATALOGUES)?;
    let ops = FindOptions::builder()
        .projection(Some(projection))
        .build();
    let mut curseur = match collection.find(filtre, Some(ops)).await {
        Ok(c) => c,
        Err(e) => Err(format!("Erreur chargement applications : {:?}", e))?
    };

    let mut apps = Vec::new();
    while let Some(row) = curseur.next().await {
        let catalogue = row?;
        apps.push(catalogue);
    }

    debug!("Apps : {:?}", apps);
    let reponse = ReponseListeApplications { ok: true, resultats: Some(apps), current_version: None };

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Deserialize)]
struct RequeteVersionsApplication {
    nom: String,
}

async fn liste_versions_application<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteVersionsApplication = message_contenu.deserialize()?;

    let filtre = doc! { "nom": &requete.nom };

    let collection = middleware.get_collection_typed::<Catalogue>(NOM_COLLECTION_CATALOGUES)?;
    let current_version: Option<String> = if let Some(current) = collection.find_one(filtre.clone(), None).await? {
        Some(current.version)
    } else {
        None
    };

    let projection = doc!{
        "nom": true,
        "version": true,
        "dependances.name": true,
        "dependances.image": true,
        "securite": true,
    };

    let collection = middleware.get_collection_typed::<CatalogueApplicationDeps>(NOM_COLLECTION_CATALOGUES_VERSIONS)?;
    let ops = FindOptions::builder()
        .projection(Some(projection))
        .build();
    let mut curseur = match collection.find(filtre, Some(ops)).await {
        Ok(c) => c,
        Err(e) => Err(format!("Erreur chargement applications : {:?}", e))?
    };

    let mut apps = Vec::new();
    while let Some(row) = curseur.next().await {
        let catalogue = row?;
        apps.push(catalogue);
    }

    debug!("Apps : {:?}", apps);
    let reponse = ReponseListeApplications { ok: true, resultats: Some(apps), current_version };

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Deserialize)]
struct ReponseNom {
    nom: String,
}

#[derive(Serialize)]
struct CatalogueInformationResponse {
    ok: bool,
    nom: String,
    securite: Option<String>,
    version: String,
    description: Option<HashMap<String, String>>,
    dependances: Option<Vec<Value>>,
    nginx: Option<HashMap<String, Value>>,
    web: Option<HashMap<String, Value>>,
    #[serde(rename="securityLevels")]
    security_levels: Option<Vec<String>>,
}

async fn repondre_application<M>(middleware: &M, m: MessageValide)
                                 -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let message_nom: ReponseNom = message_contenu.deserialize()?;
    let nom_application = message_nom.nom;

    let filtre = doc! {"nom": &nom_application};
    let collection = middleware.get_collection_typed::<Catalogue>(NOM_COLLECTION_CATALOGUES)?;
    let mut catalogue = match collection.find_one(filtre, None).await? {
        Some(c) => c,
        None => return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown application"))?))
    };

    let filtre_version = doc!{"nom": nom_application, "version": catalogue.version};
    let collection_versions = middleware.get_collection_typed::<Catalogue>(NOM_COLLECTION_CATALOGUES_VERSIONS)?;
    let package_version = match collection_versions.find_one(filtre_version, None).await? {
        Some(c) => c,
        None => return Ok(Some(middleware.reponse_err(Some(404), None, Some("Unknown application version"))?))
    };

    let response = CatalogueInformationResponse {
        ok: true,
        nom: package_version.nom,
        version: package_version.version,
        securite: Some(package_version.securite),
        security_levels: package_version.security_levels,
        dependances: package_version.dependances,
        nginx: package_version.nginx,
        description: package_version.description,
        web: package_version.web,
    };

    Ok(Some(middleware.build_reponse(&response)?.0))
}
