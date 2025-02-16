use std::collections::{HashMap, HashSet};
use std::time::Duration;
use log::{debug, error, info, warn};
use millegrilles_common_rust::bson;
use crate::topology_constants::*;
use crate::topology_events::produire_fiche_publique;
use crate::topology_structs::{FichePublique, FilehostServerRow, FilehostTransfer, InformationMonitor, RowFilehostFuuid};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::bson::oid::ObjectId;
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
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use serde::Deserialize;
use crate::topology_commands::{FuuidVisitResponseItem, RequeteGetVisitesFuuidsResponse};

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

    // Check every 10 minutes if claims/visits can be processed (low impact if no work).
    if minutes % 10 == 2
    {
        if let Err(e) = regenerate_filehosting_fuuids(middleware).await {
            error!("core_topoologie.entretien Error in maintenance of files claims and visits : {:?}", e);
        }
    }

    // Maintain file transfers between filehosts
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

#[derive(Deserialize)]
struct FuuidFilehostRow {
    #[serde(rename="_id")]
    id: ObjectId,
    fuuid: String,
    destination_filehost_id: String,
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

    // Remove all transfers going to currently inactive filehosts
    let collection_transfers =
        middleware.get_collection_typed::<FilehostTransfer>(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;
    if filehosts_inactive.len() > 0 {
        debug!("entretien_transfert_fichiers {} filehosts inactifs", filehosts_inactive.len());
        let filehost_ids: Vec<&String> = filehosts_inactive.keys().into_iter().collect();
        let filtre = doc!{"destination_filehost_id": {"$in": filehost_ids}};
        collection_transfers.delete_many(filtre, None).await?;
    }

    // Check each transfer to ensure it is still required
    let active_transfer_pipeline = vec![
        doc!{"$lookup": {
            "from": NOM_COLLECTION_FILEHOSTING_FUUIDS,
            "localField": "fuuid",
            "foreignField": "fuuid",
            "as": "visits",
        }},

        // Turn the filehost document into an array
        doc!{"$addFields": {"visit_entry": {"$arrayElemAt": ["$visits", 0]}}},
        doc!{"$addFields": {"visit_list": {"$objectToArray": "$visit_entry.filehost"}}},

        // Extract entry with visit_list[].k == destination_filehost_id
        doc!{"$addFields": {"last_visit": {"$filter": {
            "input": "$visit_list",
            "as": "visit",
            "cond": {"$eq": ["$$visit.k", "$destination_filehost_id"]}
        }}}},

        // Keep entry (for removal) if file is already present on destination
        // If file is missing on destination => exists false, we want the transfer to happen.
        doc!{"$match": {"last_visit.0": {"$exists": true}}},

        doc!{"$project": {"_id": "$_id", "fuuid": 1, "destination_filehost_id": 1}},
        // doc!{"$out":{"db": middleware.get_database()?.name(), "coll": "CoreTopologie/test",}},
    ];
    debug!("Cleanup expired active transfers START");
    // collection_transfers.aggregate(active_transfer_pipeline, None).await?;
    let mut transfers_expired = 0;
    let mut cursor = collection_transfers.aggregate(active_transfer_pipeline, None).await?;
    const BATCH_SIZE: usize = 100;
    let mut batch_to_delete = Vec::new();
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let row: FuuidFilehostRow = convertir_bson_deserializable(row)?;
        batch_to_delete.push(row.id);
        transfers_expired += 1;

        if batch_to_delete.len() >= BATCH_SIZE {
            let filtre_delete = doc!{"_id": {"$in": &batch_to_delete}};
            collection_transfers.delete_many(filtre_delete, None).await?;
            batch_to_delete.clear();
        }
    }
    if batch_to_delete.len() > 0 {
        let filtre_delete = doc!{"_id": {"$in": batch_to_delete}};
        collection_transfers.delete_many(filtre_delete, None).await?;
    }
    debug!("Cleanup {} expired active transfers DONE", transfers_expired);

    if filehosts_active.len() > 0 {
        let mut filehost_doc = doc!{};
        for (filehost_id, _) in &filehosts_active {
            filehost_doc.insert(filehost_id.to_string(), false);
        }
        let claim_expiration = Utc::now() - Duration::new(7*86_400, 0);
        let fuuids_pipeline = vec![
            // Filter out entries without a recent claim
            doc!{"$match": {"last_claim_date": {"$gte": claim_expiration}}},
            // Pad all filehost entries with active filehosts. Will result in false if no visit date exists.
            doc!{"$addFields": {"filehost_padded": {"$mergeObjects": [filehost_doc, "$filehost"]}}},
            doc!{"$addFields": {"filehost_elem": {"$objectToArray": "$filehost_padded"}}},
            doc!{"$unwind": {"path": "$filehost_elem"}},

            // Retain entries with filehost value of false, means there is no entry (no date).
            doc!{"$match": {"filehost_elem.v": false}},
            doc!{"$addFields": {"destination_filehost_id": "$filehost_elem.k", "created": "$$NOW", "modified": "$$NOW"}},
            doc!{"$project": {"fuuid": 1, "destination_filehost_id": 1, "created": 1, "modified": 1}},

            doc!{"$unset": "_id"},
            // doc!{"$out": {"db": middleware.get_database()?.name(), "coll": "CoreTopologie/transfer_test"}},
            doc!{"$merge": {
                "into": NOM_COLLECTION_FILEHOSTING_TRANSFERS,
                "on": ["destination_filehost_id", "fuuid"],
                "whenMatched": "keepExisting",
                "whenNotMatched": "insert",
            }}

        ];
        let collection_transfers =
            middleware.get_collection_typed::<FilehostTransfer>(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
        debug!("Creating missing transfer items START");
        collection_transfers.aggregate(fuuids_pipeline, None).await?;
        debug!("Creating missing transfer items DONE");
    }

    emit_filehost_transfersupdated_event(middleware).await?;

    debug!("entretien_transfert_fichiers Fin");
    Ok(())
}

pub async fn add_missing_file_transfers<M>(middleware: &M, session: &mut ClientSession, new_claims: Vec<RowFilehostFuuid>)
    -> Result<(), Error>
    where M: GenerateurMessages + MongoDao
{
    // Get active filehosts
    let filehosts_active = {
        let collection_filehosts =
            middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;
        let filtre = doc!{"sync_active": true, "deleted": false};
        let mut cursor = collection_filehosts.find(filtre, None).await?;

        let mut filehosts_active = HashSet::new();
        while cursor.advance().await? {
            let row = cursor.deserialize_current()?;
            filehosts_active.insert(row.filehost_id.clone());
        }
        filehosts_active
    };

    for claim in new_claims {
        let mut missing_from = Vec::new();
        // Find all filehost_ids this file is missing from
        match claim.filehost {
            Some(visits) => {
                for filehost in &filehosts_active {
                    if visits.get(filehost).is_none() {
                        missing_from.push(filehost.clone());
                    }
                }
            }
            None => {
                for filehost in &filehosts_active {
                    missing_from.push(filehost.clone());
                }
            }
        };

        let mut transfers_to_add = Vec::new();
        for filehost_id in missing_from {
            debug!("Create missing file transfer for fuuid:{} on filehost_id:{}", claim.fuuid, filehost_id);
            let transfer = FilehostTransfer {
                destination_filehost_id: filehost_id,
                fuuid: claim.fuuid.clone(),
                created: Utc::now(),
                modified: Utc::now(),
                job_picked_up: None,
            };
            transfers_to_add.push(transfer);
        }
        if ! transfers_to_add.is_empty() {
            let collection_transfers =
                middleware.get_collection_typed::<FilehostTransfer>(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;
            collection_transfers.insert_many_with_session(transfers_to_add, None, session).await?;
        }
    }

    // Tell filecontroler that new transfers are available
    emit_filehost_transfersupdated_event(middleware).await?;

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

/// Regenerates the filehosting_fuuids table from claims and visits when ready.
/// Data is regularly provided by claimants at their discretion. Claims and visits are
/// processed independently.
async fn regenerate_filehosting_fuuids<M>(middleware: &M)
    -> Result<(), Error>
    where M: ConfigMessages + GenerateurMessages + MongoDao
{
    merge_filehosting_fuuids_claims(middleware).await?;
    merge_filehosting_fuuids_visits(middleware).await?;
    Ok(())
}

#[derive(Deserialize)]
struct ClaimVisitsRow {
    #[serde(rename="_id")]
    id: String,
    visits: Option<Vec<RowFilehostFuuid>>
}

/// Regenerates the filehosting_fuuids table from claims and visits
async fn merge_filehosting_fuuids_claims<M>(middleware: &M)
    -> Result<(), Error>
    where M: ConfigMessages + GenerateurMessages + MongoDao
{
    // Ensure that all claimer components have sent their data
    let claimer_domains = {
        let mut count = 0;
        let mut claimer_domains = Vec::new();

        let collection_status = middleware.get_collection_typed::<SyncStatusRow>(NOM_COLLECTION_FILEHOSTING_SYNC_STATUS)?;
        let claimers_filtre = doc!{"claimer_type": "domain"};
        let mut cursor = collection_status.find(claimers_filtre.clone(), None).await?;

        while cursor.advance().await? {
            let row = cursor.deserialize_current()?;
            if row.date_ready.is_none() {
                info!("merge_filehosting_fuuids_claims At least one previous claimer is not ready, cancel regeneration of claims");
                return Ok(())
            }
            claimer_domains.push(row.claimer);
            count += 1;
        }

        if count == 0 {
            info!("merge_filehosting_fuuids_claims No claimer in status list, cancel regeneration of claims");
            return Ok(())
        }

        // Reset the sync status
        let ops = doc!{"$set": {"date_ready": None::<&str>}};
        collection_status.update_many(claimers_filtre, ops, None).await?;

        claimer_domains
    };

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
    let claims_work_collection = middleware.get_collection(&claims_work_name)?;
    let options_claims = AggregateOptions::builder().hint(Hint::Name("fuuids".to_string())).build();
    claims_work_collection.aggregate(claim_pipeline.clone(), options_claims.clone()).await?;
    info!("regenerate_filehosting_fuuids Merging claims DONE");

    // Respond to claims by domain.
    respond_to_file_claims(middleware, claims_work_name.as_str(), &claimer_domains).await?;

    // All values processed. Cleanup.
    claims_work_collection.drop(None).await?;

    Ok(())
}

async fn respond_to_file_claims<M>(middleware: &M, work_collection_name: &str, claimer_domains: &Vec<String>)
    -> Result<(), Error>
    where M: GenerateurMessages + MongoDao
{
    const BATCH_SIZE: usize = 500;
    let claims_work_collection = middleware.get_collection(work_collection_name)?;
    let options_claims = AggregateOptions::builder().hint(Hint::Name("fuuids".to_string())).build();

    for domain in claimer_domains {
        debug!("response_to_file_claims Sending response to claims from {}", domain);
        let claim_pipeline = vec![
            doc!{"$sort": {"fuuid": 1}},
            doc!{"$match": {"domains": domain}},
            doc!{"$group": {"_id": "$fuuid"}},
            doc!{"$lookup": {
                // Lookup the rep table to get the user ids.
                "from": NOM_COLLECTION_FILEHOSTING_FUUIDS,
                "localField": "_id",
                "foreignField": "fuuid",
                "as": "visits",
            }},
        ];

        // Prepare a response to receive the content
        let mut reponse = RequeteGetVisitesFuuidsResponse {
            ok: true,
            visits: Vec::with_capacity(BATCH_SIZE),
            unknown: Vec::new(),
            done: Some(false),
        };
        // Response routing for this domain
        let routage = RoutageMessageAction::builder(domain, "visits", vec![Securite::L3Protege])
            .build();

        let mut cursor = claims_work_collection.aggregate(claim_pipeline, options_claims.clone()).await?;
        while cursor.advance().await? {
            let row = cursor.deserialize_current()?;
            let row: ClaimVisitsRow = convertir_bson_deserializable(row)?;
            if let Some(visits) = row.visits {
                if let Some(visit) = visits.get(0) {
                    // debug!("Fuuid {} filehost visits: {:?}", row.id, visit.filehost);
                    let mut visit_map = HashMap::new();
                    if let Some(inner) = visit.filehost.as_ref() {
                        for (k,v) in inner {
                            if let Some(visit_date) = v {
                                visit_map.insert(k.to_owned(), visit_date.timestamp());
                            }
                        }
                    };

                    let visit_entry = FuuidVisitResponseItem {fuuid: row.id, visits: visit_map};
                    reponse.visits.push(visit_entry);
                } else {
                    reponse.unknown.push(row.id);
                }
            } else {
                reponse.unknown.push(row.id);
            }

            if reponse.visits.len() >= BATCH_SIZE || reponse.unknown.len() >= BATCH_SIZE {
                // Emit batch to domain
                match middleware.transmettre_commande(routage.clone(), &reponse).await {
                    Ok(Some(TypeMessage::Valide(_))) => {}  // Ok
                    Err(e) => {
                        warn!("response_to_file_claims Error sending file visits to claimant domain {}: {:?}", domain, e);
                        break;  // Abort for this domain
                    },
                    _ =>  {
                        warn!("response_to_file_claims Error sending file visits to claimant domain {}, wrong response type", domain);
                        break;  // Abort for this domain
                    }
                }

                // Reset response for next batch
                reponse = RequeteGetVisitesFuuidsResponse {
                    ok: true,
                    visits: Vec::with_capacity(BATCH_SIZE),
                    unknown: Vec::new(),
                    done: Some(false),
                }
            }
        }

        reponse.done = Some(true);
        if let Err(e) = middleware.transmettre_commande(routage.clone(), &reponse).await {
            warn!("response_to_file_claims Error sending last batch of file visits to claimant domain {}: {:?}", domain, e);
        }
    }
    debug!("response_to_file_claims Sending response to claims - DONE");

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
