use std::collections::{HashMap, HashSet};
use std::time::Duration;
use log::{debug, error, info, warn};
use millegrilles_common_rust::bson;
use crate::topology_constants::*;
use crate::topology_events::produire_fiche_publique;
use crate::topology_structs::{FichePublique, FilehostServerRow, FilehostTransfer, InformationMonitor, RowFilehostFuuid};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono::{DateTime, Datelike, Timelike, Utc};
use millegrilles_common_rust::common_messages::EventFilehost;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, CHAMP_CREATION, CHAMP_MODIFICATION, DOMAINE_TOPOLOGIE, TOPOLOGIE_NOM_DOMAINE, TRANSACTION_CHAMP_IDMG};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::EmetteurNotificationsTrait;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb::options::{AggregateOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::notifications::NotificationMessageInterne;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use serde::Deserialize;

pub async fn traiter_cedule<M>(middleware: &M, trigger: &MessageCedule) -> Result<(), millegrilles_common_rust::error::Error>
where M: ConfigMessages + ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    let date_epoch = trigger.get_date();
    debug!("Traiter cedule {}\n{:?}", DOMAIN_NAME, date_epoch);

    if middleware.get_mode_regeneration() == true {
        debug!("traiter_cedule Mode regeneration, skip entretien");
        return Ok(());
    }

    let minutes = date_epoch.minute();
    // let hours = date_epoch.hour();

    if minutes % 5 == 1
    {
        debug!("Produire fiche publique");
        if let Err(e) = produire_fiche_publique(middleware).await {
            error!("core_topoologie.entretien Erreur production fiche publique initiale : {:?}", e);
        }
    }

    //if minutes % 5 == 2
    {
        if let Err(e) = regenerate_filehosting_fuuids(middleware).await {
            error!("core_topoologie.entretien Error in maintenance of files claims and visits : {:?}", e);
        }
    }

    // Mettre a jour information locale a toutes les 5 minutes
    // if minutes % 5 == 2 {
    //     if let Err(e) = produire_information_locale(middleware).await {
    //         error!("core_topoologie.entretien Erreur production information locale : {:?}", e);
    //     }
    // }

    // if minutes == 4 {
    //     if let Err(e) = rafraichir_fiches_millegrilles(middleware).await {
    //         error!("core_topoologie.entretien Erreur rafraichir fiches millegrilles : {:?}", e);
    //     }
    // }

    // if let Err(e) = verifier_instances_horsligne(middleware).await {
    //     warn!("Erreur verification etat instances hors ligne {:?}", e);
    // }

    if minutes % 15 == 6
    {
        if let Err(e) = entretien_transfert_fichiers(middleware).await {
            error!("core_topologie.entretien Erreur entretien transferts fichiers : {:?}", e);
        }
    }

    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct RowInstanceActivite {
    instance_id: String,
    hostname: Option<String>,
    date_presence: Option<i64>,
    date_hors_ligne: Option<i64>,
}

/// Genere les transferts de fichiers manquants et supprime ceux qui ne s'appliquent plus.
pub async fn entretien_transfert_fichiers<M>(middleware: &M) -> Result<(), millegrilles_common_rust::error::Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("entretien_transfert_fichiers Debut");

    let (filehosts_active, filehosts_inactive) = {
        let collection_filehosts =
            middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;
        let filtre = doc!{};
        let mut cursor = collection_filehosts.find(filtre, None).await?;

        let mut filehosts_active = HashMap::new();
        let mut filehosts_inactive = HashMap::new();
        while cursor.advance().await? {
            let row = cursor.deserialize_current()?;
            let active = row.sync_active && !row.deleted;
            match active {
                true => { filehosts_active.insert(row.filehost_id.clone(), row); }
                false => { filehosts_inactive.insert(row.filehost_id.clone(), row); }
            }
        }
        (filehosts_active, filehosts_inactive)
    };

    // Supprimer transferts de filehosts inactifs
    let collection_transfers =
        middleware.get_collection_typed::<FilehostTransfer>(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;
    if filehosts_inactive.len() > 0 {
        debug!("entretien_transfert_fichiers {} filehosts inactifs", filehosts_inactive.len());
        let filehost_ids: Vec<&String> = filehosts_inactive.keys().into_iter().collect();
        let filtre = doc!{"destination_filehost_id": {"$in": filehost_ids}};
        collection_transfers.delete_many(filtre, None).await?;
    }

    let collection_fuuids = middleware.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;

    // Verifier que chaque transfert restant est toujours applicable
    let mut curseur_transfers = collection_transfers.find(doc!{}, None).await?;
    while curseur_transfers.advance().await? {
        let row = curseur_transfers.deserialize_current()?;
        let filtre_visite = doc!{
            "fuuid": &row.fuuid,
            "$or": [
                {"filehost": {}},
                {format!("filehost.{}", row.destination_filehost_id): {"$exists": true}}
            ]
        };
        let count_visite = collection_fuuids.count_documents(filtre_visite, None).await?;
        if count_visite > 0 {
            debug!("entretien_transfert_fichiers Le transfert {} vers {} ne s'applique plus", row.fuuid, row.destination_filehost_id);
            let filtre_delete = doc!{"fuuid": row.fuuid, "destination_filehost_id": row.destination_filehost_id};
            collection_transfers.delete_one(filtre_delete, None).await?;
        }
    }

    if filehosts_active.len() > 0 {
        debug!("entretien_transfert_fichiers {} filehosts actifs", filehosts_active.len());
        let reclamation_expiration = Utc::now() - Duration::new(7*86_400, 0);
        let mut filehost_doc = Vec::new();
        for (filehost_id, _) in &filehosts_active {
            filehost_doc.push(doc!{format!("filehost.{}", filehost_id): {"$exists": false}});
        }
        let filtre = doc!{
            "$or": filehost_doc,
            FIELD_LAST_CLAIM_DATE: {"$gte": reclamation_expiration}
        };
        debug!("entretien_transfert_fichiers Filtre: {:?}", filtre);
        let mut cursor = collection_fuuids.find(filtre, None).await?;
        let filehosts_active_list: HashSet<&String> = filehosts_active.keys().collect();
        while cursor.advance().await? {
            let row = cursor.deserialize_current()?;
            if let Some(filehost) = row.filehost.as_ref() {
                if filehost.len() == 0 {
                    // File not present on any filehost, skip
                    continue
                }
                let fuuid_filehost: HashSet<&String> = filehost.keys().collect();
                let missing_from = filehosts_active_list.difference(&fuuid_filehost);
                debug!("entretien_transfert_fichiers File {} missing from {:?}", row.fuuid, missing_from);

                let options = UpdateOptions::builder().upsert(true).build();
                let ops = doc! {
                    "$setOnInsert": {"created": Utc::now()},
                    "$currentDate": {"modified": true},
                };
                for missing_from_filehost_id in missing_from {
                    let filtre = doc! {
                        "destination_filehost_id": &missing_from_filehost_id,
                        "fuuid": &row.fuuid,
                    };
                    collection_transfers.update_one(filtre, ops.clone(), options.clone()).await?;
                }
            }
        }
    }

    emit_filehost_transfersupdated_event(middleware).await?;

    debug!("entretien_transfert_fichiers Fin");
    Ok(())
}

pub async fn emit_filehost_transfersupdated_event<M>(middleware: &M) -> Result<(), Error> where M: GenerateurMessages {
    let event = json!({});
    let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, EVENEMENT_FILEHOST_TRANSFERSUPDATED, vec![Securite::L1Public])
        .build();
    middleware.emettre_evenement(routage, &event).await?;
    Ok(())
}


#[derive(Deserialize)]
struct SyncStatusRow {
    claimer: String,
    claimer_type: String,
    #[serde(default, with = "opt_chrono_datetime_as_bson_datetime")]
    date_ready: Option<DateTime<Utc>>,
}

/// Regenerates the filehosting_fuuids table from claims and visits
async fn regenerate_filehosting_fuuids<M>(middleware: &M)
    -> Result<(), Error>
    where M: ConfigMessages + MongoDao
{
    merge_filehosting_fuuids_claims(middleware).await?;
    merge_filehosting_fuuids_visits(middleware).await?;

    // let mut statuses = Vec::new();
    // let collection_status = middleware.get_collection_typed::<SyncStatusRow>(NOM_COLLECTION_FILEHOSTING_SYNC_STATUS)?;
    // let mut cursor = collection_status.find(doc!{}, None).await?;
    // while cursor.advance().await? {
    //     let row = cursor.deserialize_current()?;
    //     if row.date_ready.is_none() {
    //         info!("regenerate_filehosting_fuuids At least one previous claimer is not ready, cancel regeneration of claims/visits");
    //         return Ok(())
    //     }
    //     statuses.push(row);
    // }
    //
    // // Reset the sync status
    // let ops = doc!{"$set": {"date_ready": None::<&str>}};
    // collection_status.update_many(doc!{}, ops, None).await?;
    //
    // let claims_work_name = format!("{}_WORK", NOM_COLLECTION_FILEHOSTING_CLAIMS);
    // let visits_work_name = format!("{}_WORK", NOM_COLLECTION_FILEHOSTING_VISITS);
    // // Rename the collections
    // // If any WORK tables exist, drop them
    // middleware.rename_collection(NOM_COLLECTION_FILEHOSTING_CLAIMS, &claims_work_name, true).await?;
    // middleware.rename_collection(NOM_COLLECTION_FILEHOSTING_VISITS, &visits_work_name, true).await?;
    //
    // // Prepare the collection indexes by fuuid
    // let options_index = IndexOptions { nom_index: Some(String::from("fuuids")), unique: false};
    // let champs_index_claims = vec!(ChampIndex { nom_champ: String::from("fuuid"), direction: 1 });
    // middleware.create_index(middleware, claims_work_name.as_str(), champs_index_claims, Some(options_index)).await?;
    //
    // let options_index = IndexOptions { nom_index: Some(String::from("fuuids")), unique: false};
    // let champs_index_claims = vec!(ChampIndex { nom_champ: String::from("fuuid"), direction: 1 });
    // middleware.create_index(middleware, visits_work_name.as_str(), champs_index_claims, Some(options_index)).await?;
    //
    // // Merge claims into the filehosting fuuids table
    // let claim_pipeline = vec![
    //     doc!{"$sort": {"fuuid": 1}},
    //     doc!{"$group": {"_id": "$fuuid", "last_claim_date": {"$max": "$claim_date"}}},
    //     doc!{"$set": {"fuuid": "$_id"}},  // Copy field claim_date to last_claim_date (merge value)
    //     doc!{"$unset": ["_id"]},          // Remove _id field for merge
    //     doc!{"$merge": {
    //         "into": NOM_COLLECTION_FILEHOSTING_FUUIDS,
    //         "on": "fuuid",
    //         "whenNotMatched": "insert",
    //     }}
    // ];
    // info!("regenerate_filehosting_fuuids Merging claims START");
    // let claims_work_collection = middleware.get_collection(claims_work_name)?;
    // let options_claims = AggregateOptions::builder().hint(Hint::Name("fuuids".to_string())).build();
    // claims_work_collection.aggregate(claim_pipeline.clone(), options_claims).await?;
    // info!("regenerate_filehosting_fuuids Merging claims DONE");
    //
    // // All values processed
    // claims_work_collection.drop(None).await?;
    //
    // // Merge visits
    // // let visits_work_collection = middleware.get_collection(visits_work_name)?;
    // // visits_work_collection.aggregate(fuuid_pipeline, None).await?;

    Ok(())
}

/// Regenerates the filehosting_fuuids table from claims and visits
async fn merge_filehosting_fuuids_claims<M>(middleware: &M)
    -> Result<(), Error>
    where M: ConfigMessages + MongoDao
{
    // Ensure that all claimer components have sent their data
    let collection_status = middleware.get_collection_typed::<SyncStatusRow>(NOM_COLLECTION_FILEHOSTING_SYNC_STATUS)?;
    let claimers_filtre = doc!{"claimer_type": "domain"};
    let mut cursor = collection_status.find(claimers_filtre.clone(), None).await?;
    let mut count = 0;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        if row.date_ready.is_none() {
            info!("merge_filehosting_fuuids_claims At least one previous claimer is not ready, cancel regeneration of claims");
            return Ok(())
        }
        count += 1;
    }

    if count == 0 {
        info!("merge_filehosting_fuuids_claims No claimer in status list, cancel regeneration of claims");
        return Ok(())
    }

    // Reset the sync status
    let ops = doc!{"$set": {"date_ready": None::<&str>}};
    collection_status.update_many(claimers_filtre, ops, None).await?;

    // Rename the collections
    // If any WORK tables exist, drop them
    let claims_work_name = format!("{}_WORK", NOM_COLLECTION_FILEHOSTING_CLAIMS);
    middleware.rename_collection(NOM_COLLECTION_FILEHOSTING_CLAIMS, &claims_work_name, true).await?;

    // Prepare the collection indexes by fuuid
    let options_index = IndexOptions { nom_index: Some(String::from("fuuids")), unique: false};
    let champs_index_claims = vec!(ChampIndex { nom_champ: String::from("fuuid"), direction: 1 });
    middleware.create_index(middleware, claims_work_name.as_str(), champs_index_claims, Some(options_index)).await?;

    // Merge claims into the filehosting fuuids table
    let claim_pipeline = vec![
        doc!{"$sort": {"fuuid": 1}},
        doc!{"$group": {"_id": "$fuuid", "last_claim_date": {"$max": "$claim_date"}}},
        doc!{"$set": {"fuuid": "$_id"}},  // Copy field claim_date to last_claim_date (merge value)
        doc!{"$unset": ["_id"]},          // Remove _id field for merge
        doc!{"$merge": {
            "into": NOM_COLLECTION_FILEHOSTING_FUUIDS,
            "on": "fuuid",
            "whenNotMatched": "insert",
        }}
    ];
    info!("regenerate_filehosting_fuuids Merging claims START");
    let claims_work_collection = middleware.get_collection(claims_work_name)?;
    let options_claims = AggregateOptions::builder().hint(Hint::Name("fuuids".to_string())).build();
    claims_work_collection.aggregate(claim_pipeline.clone(), options_claims).await?;
    info!("regenerate_filehosting_fuuids Merging claims DONE");

    // All values processed
    claims_work_collection.drop(None).await?;

    Ok(())
}

async fn merge_filehosting_fuuids_visits<M>(middleware: &M)
    -> Result<(), Error>
    where M: ConfigMessages + MongoDao
{
    // Ensure that all claimer components have sent their data
    let collection_status = middleware.get_collection_typed::<SyncStatusRow>(NOM_COLLECTION_FILEHOSTING_SYNC_STATUS)?;
    let claimers_filtre = doc! {"claimer_type": "filehost"};
    let mut count = 0;
    let mut cursor = collection_status.find(claimers_filtre.clone(), None).await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        if row.date_ready.is_none() {
            info!("merge_filehosting_fuuids_visits At least one previous claimer is not ready, cancel regeneration of visits");
            return Ok(())
        }
        count += 1;
    }

    if count == 0 {
        info!("merge_filehosting_fuuids_visits No claimer in status list, cancel regeneration of visits");
        return Ok(())
    }

    let ops = doc!{"$set": {"date_ready": None::<&str>}};
    collection_status.update_many(claimers_filtre, ops, None).await?;

    // Rename the collections
    // If any WORK tables exist, drop them
    let visits_work_name = format!("{}_WORK", NOM_COLLECTION_FILEHOSTING_VISITS);
    middleware.rename_collection(NOM_COLLECTION_FILEHOSTING_VISITS, &visits_work_name, true).await?;

    // Prepare the collection indexes by fuuid
    let options_index = IndexOptions { nom_index: Some(String::from("fuuids")), unique: false};
    let champs_index_claims = vec!(ChampIndex { nom_champ: String::from("fuuid"), direction: 1 });
    middleware.create_index(middleware, visits_work_name.as_str(), champs_index_claims, Some(options_index)).await?;

    // Merge claims into the filehosting fuuids table
    let visits_pipeline = vec![
        doc!{"$sort": {"fuuid": 1}},
        doc!{"$addFields": {"obj": {"k": "$filehost_id", "v": "$visit_time"}}},
        doc!{"$group": {"_id": "$fuuid", "items": {"$push": "$obj"}}},
        doc!{"$addFields": {"fuuid": "$_id", "filehost": {"$arrayToObject": "$items"} }},
        doc!{"$unset": ["_id", "items"]},
        doc!{"$merge": {
            // "into": NOM_COLLECTION_FILEHOSTING_FUUIDS_WORK,
            "into": NOM_COLLECTION_FILEHOSTING_FUUIDS,
            "on": "fuuid",
            "whenNotMatched": "insert",
        }}
    ];
    info!("merge_filehosting_fuuids_visits Merging visits START");
    let visits_work_collection = middleware.get_collection(visits_work_name)?;
    let options_visits = AggregateOptions::builder().hint(Hint::Name("fuuids".to_string())).build();
    visits_work_collection.aggregate(visits_pipeline.clone(), options_visits).await?;
    info!("merge_filehosting_fuuids_visits Merging visits DONE");

    // All values processed
    visits_work_collection.drop(None).await?;

    Ok(())
}
