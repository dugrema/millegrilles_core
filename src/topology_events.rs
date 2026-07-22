use std::collections::{HashMap, HashSet};
use log::{debug, error, info, warn};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::common_messages::BackupEvent;
use millegrilles_common_rust::constantes::{Securite, EVENEMENT_PRESENCE_DOMAINE, CHAMP_CREATION, CHAMP_MODIFICATION, RolesCertificats, BACKUP_EVENEMENT_MAJ};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, start_transaction_regular, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde_json::Value;
use serde::{Deserialize, Serialize};

use crate::topology_common::generer_contenu_fiche_publique;
use crate::topology_manager::TopologyManager;
use crate::topology_constants::*;
use crate::topology_structs::{ApplicationInfo, ApplicationStatusV2, EventFilehostUsage, EventNewFuuid, ManagerStatusV2, PresenceDomaine, RowFilehostFuuid, RowFilehostId, SystemState};
use millegrilles_common_rust::mongodb::ClientSession;
use crate::topology_maintenance::emit_filehost_transfersupdated_event;

pub async fn consommer_evenement_topology<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
                                             -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("Consommer evenement : {:?}", &m.type_message);

    let (_domaine, action) = match &m.type_message {
        TypeMessageOut::Evenement(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_evenement Mauvais type de message"))?
        }
    };

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges(vec![
        Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure,
    ])? {
        true => Ok(()),
        false => Err(format!("Evenement autorisation invalide (pas exchange autorise)")),
    }?;

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    let result = match action.as_str() {
        EVENEMENT_PRESENCE_DOMAINE => traiter_presence_domaine(middleware, m, gestionnaire).await,
        // EVENEMENT_PRESENCE_MONITOR | EVENEMENT_PRESENCE_FICHIERS => {
        //     match domaine.as_str() {
        //         // DOMAINE_FICHIERS => traiter_presence_fichiers(middleware, m, gestionnaire).await,
        //         DOMAINE_APPLICATION_INSTANCE => traiter_presence_monitor(middleware, m, gestionnaire).await,
        //         _ => Err(format!("Mauvais domaine ({}) pour un evenement de presence", domaine))?,
        //     }
        // },
        EVENEMENT_PRESENCE_INSTANCE => process_presence_instance(middleware, m, &mut session).await,
        EVENEMENT_PRESENCE_INSTANCE_V2 => process_presence_instance_v2(middleware, m, &mut session).await,
        EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS => process_presence_instance_applications(middleware, m, &mut session).await,
        EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS_V2 => process_presence_instance_applications_v2(middleware, m, &mut session).await,
        EVENEMENT_APPLICATION_DEMARREE | EVENEMENT_APPLICATION_ARRETEE => traiter_evenement_application(middleware, m).await,
        EVENEMENT_FILEHOST_USAGE => traiter_evenement_filehost_usage(middleware, m, &mut session).await,
        EVENEMENT_FILEHOST_NEWFUUID => traiter_evenement_filehost_newfuuid(middleware, m, &mut session).await,
        BACKUP_EVENEMENT_MAJ => traiter_evenement_backup_maj(middleware, m, &mut session).await,
        _ => Err(format!("Mauvais type d'action pour un evenement : {}", action))?,
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

async fn traiter_presence_domaine<M>(middleware: &M, m: MessageValide, _gestionnaire: &TopologyManager)
                                     -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Evenement presence domaine : {:?}", m.type_message);
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let event: PresenceDomaine = message_contenu.deserialize()?;
    debug!("Presence domaine : {:?}", event);

    let domaine = match event.domaine.as_ref() {
        Some(d) => d,
        None => {
            // Rien a faire
            return Ok(None)
        }
    };

    let certificat = m.certificat.as_ref();

    if ! certificat.verifier_domaines(vec![domaine.to_owned()])? {
        Err(format!("core_topologie.traiter_presence_domaine Erreur domaine message ({}) mismatch certificat ", domaine))?
    }

    let instance_id = certificat.get_common_name()?;

    let filtre = doc! {"domaine": domaine};
    let mut ops = doc! {
        // "$set": {
        //     "reclame_fuuids": event.reclame_fuuids,
        // },
        "$setOnInsert": {
            "domaine": domaine,
            "instance_id": instance_id,
            CHAMP_CREATION: Utc::now(),
            "dirty": true
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    if let Some(reclame_fuuids) = event.reclame_fuuids {
        ops.insert("$set", doc!{"reclame_fuuids": reclame_fuuids});
    }

    debug!("Document monitor a sauvegarder : {:?}", ops);

    let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
    let options = FindOneAndUpdateOptions::builder().upsert(true).build();
    let _result = match collection.find_one_and_update(filtre, ops, Some(options)).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur find document sur transaction domaine : {:?}", e))?
    };

    Ok(None)
}

pub async fn produire_fiche_publique<M>(middleware: &M)
                                    -> Result<(), millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("produire_fiche_publique");

    let fiche = generer_contenu_fiche_publique(middleware).await?;

    let routage = RoutageMessageAction::builder(
        DOMAIN_NAME, EVENEMENT_FICHE_PUBLIQUE, vec![Securite::L1Public])
        .ajouter_ca(true)
        .build();
    middleware.emettre_evenement(routage, &fiche).await?;

    Ok(())
}

async fn traiter_evenement_application<M>(middleware: &M, m: MessageValide)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    // let event: PresenceMonitor = m.message.get_msg().map_contenu(None)?;
    debug!("Evenement application monitor : {:?}", m.type_message);

    // Regenerer fiche publique
    produire_fiche_publique(middleware).await?;

    Ok(None)
}

async fn traiter_evenement_filehost_usage<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    if ! m.certificat.verifier_roles_string(vec!["filecontroler".to_string()])? {
        debug!("traiter_evenement_filehost_usage Wrong certificate for event - DROPPED");
        return Ok(None)
    }

    let commande: EventFilehostUsage = {
        let message_ref = m.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        match message_contenu.deserialize() {
            Ok(inner) => inner,
            Err(e) => {
                error!("traiter_evenement_filehost_usage Error parsing EventFilehostUsage: {:?}", e);
                return Ok(None)
            }
        }
    };
    let filtre = doc! {"filehost_id": &commande.filehost_id};
    let ops = doc!{
        "$set": {
            "stats_updated": &commande.date,
            "fuuid": convertir_to_bson(commande.fuuid)?,
        },
        "$currentDate": {"modified": true}
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTS)?;
    let result = collection.update_one_with_session(filtre, ops, None, session).await?;

    if result.matched_count == 0 {
        warn!("traiter_evenement_filehost_usage Received event for unknown filehost_id {}", commande.filehost_id);
    }

    Ok(None)
}

async fn traiter_evenement_filehost_newfuuid<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: GenerateurMessages + MongoDao
{
    if ! m.certificat.verifier_roles_string(vec!["filecontroler".to_string()])? {
        debug!("traiter_evenement_filehost_newfuuid Wrong certificate for event - DROPPED");
        return Ok(None)
    }

    let (commande, estampille): (EventNewFuuid, chrono::DateTime<Utc>) = {
        let message_ref = m.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        let estampille = message_ref.estampille;
        (message_contenu.deserialize()?, estampille)
    };

    {
        // Add filehost_id/fuuid to the visit aggregation table
        let collection_visits = middleware.get_collection(NOM_COLLECTION_FILEHOSTING_VISITS)?;
        let row = doc!{"fuuid": &commande.fuuid, "filehost_id": &commande.filehost_id, "visit_time": &estampille};
        collection_visits.insert_one(row, None).await?;
    }

    let filtre = doc! {"fuuid": &commande.fuuid};
    let options = UpdateOptions::builder().upsert(true).build();
    let ops = doc! {
        "$set": {
            format!("filehost.{}", &commande.filehost_id): &estampille,
        }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
    collection.update_one_with_session(filtre, ops, Some(options), session).await?;

    process_transfers(middleware, commande.filehost_id.as_str(), commande.fuuid.as_str(), session).await?;

    Ok(None)
}

async fn process_transfers<M>(middleware: &M, filehost_id: &str, fuuid: &str, session: &mut ClientSession) -> Result<(), millegrilles_common_rust::error::Error>
    where M: GenerateurMessages + MongoDao
{
    // Supprimer le transfert vers ce filehost (si applicable)
    let filtre_transfer = doc!{"fuuid": fuuid, "destination_filehost_id": filehost_id};
    let collection_transfers = middleware.get_collection(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;
    collection_transfers.delete_one_with_session(filtre_transfer, None, session).await?;

    // Creer les transferts vers filehosts sans ce fuuid

    // Recuperer liste de filehost_ids actifs
    let collection_filehosts = middleware.get_collection_typed::<RowFilehostId>(NOM_COLLECTION_FILEHOSTS)?;
    let options = FindOptions::builder().projection(doc!{"filehost_id": 1}).build();
    let filtre = doc! { "deleted": false, "sync_active": true };
    let mut curseur = collection_filehosts.find(filtre, options).await?;
    let mut filehost_ids = HashSet::new();
    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        filehost_ids.insert(row.filehost_id);
    }

    let collection_fuuids = middleware.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
    let fuuid_info = collection_fuuids.find_one(doc!{"fuuid": fuuid}, None).await?;
    if let Some(row) = fuuid_info {
        if let Some(visits) = row.filehost {
            let mut filehost_ids_visits: HashSet<String> = visits.into_iter().map(|(k,_)| k).collect();
            // Ajouter le filehost_id qui vient d'emettre l'evenement newFuuid (meme s'il devrait deja etre dans la liste).
            filehost_ids_visits.insert(filehost_id.to_owned());

            let missing_from = filehost_ids.difference(&filehost_ids_visits);
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
                collection_transfers.update_one_with_session(filtre, ops.clone(), options.clone(), session).await?;
            }
        }
    }

    emit_filehost_transfersupdated_event(middleware).await?;

    Ok(())
}

async fn traiter_evenement_backup_maj<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: MongoDao
{
    if !m.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        debug!("traiter_evenement_backup_maj Wrong security level for event - DROPPED");
        return Ok(None)
    }

    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let event: BackupEvent = message_contenu.deserialize()?;

    let domaine = event.domaine.as_str();

    if !m.certificat.verifier_domaines(vec![domaine.to_owned()])? {
        debug!("traiter_evenement_backup_maj Wrong domain for event - DROPPED");
        return Ok(None)
    }

    if event.ok && event.done {
        if let Some(version) = event.version {
            // Backup complete et on a une version - conserver pour le domaine
            let filtre = doc!{"domaine": domaine};
            let ops = doc!{
                "$set": {"backup_version": &version},
                "$currentDate": {CHAMP_MODIFICATION: true},
            };
            let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
            collection.update_one_with_session(filtre, ops, None, session).await?;
        }
    }

    Ok(None)
}

#[derive(Serialize, Deserialize)]
struct PresenceInstanceDisk {
    free: usize,
    mountpoint: String,
    total: usize,
    used: usize
}

#[derive(Serialize, Deserialize)]
struct PresenceInstanceStatus {
    disk: Option<Vec<PresenceInstanceDisk>>,
    hostname: String,
    hostnames: Vec<String>,
    ip: Option<String>,
    load_average: Option<Vec<f32>>,
    security: String,
    system_battery: Option<Value>,
    system_fans: Option<HashMap<String, Value>>,
    system_temperature: Option<HashMap<String, Value>>,
}

#[derive(Deserialize)]
struct PresenceInstanceEvent {
    status: PresenceInstanceStatus,
}

async fn process_presence_instance<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: MongoDao
{
    let message_ref = message.message.parse()?;
    let event: PresenceInstanceEvent = message_ref.contenu()?.deserialize()?;

    if ! message.certificat.verifier_roles(vec![RolesCertificats::Instance])? {
        info!("process_presence_instance Rejecting message not from an instance");
        return Ok(None)
    }

    let instance_id = message.certificat.get_common_name()?;
    let timestamp = message_ref.estampille;

    let collection = middleware.get_collection(NOM_COLLECTION_INSTANCE_STATUS)?;

    let filtre = doc! {"instance_id": instance_id};

    let mut set_ops = convertir_to_bson(event.status)?;
    set_ops.insert("timestamp", timestamp);

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {
            CHAMP_CREATION: timestamp,
            "supprime": false,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let options = UpdateOptions::builder().upsert(true).build();
    collection.update_one_with_session(filtre, ops, options, session).await?;

    Ok(None)
}

#[derive(Serialize, Deserialize)]
struct PresenceInstanceEventV2 {
    system_state: SystemState,
}

async fn process_presence_instance_v2<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: MongoDao
{
    let message_ref = message.message.parse()?;
    let event: PresenceInstanceEventV2 = message_ref.contenu()?.deserialize()?;

    if ! message.certificat.verifier_roles(vec![RolesCertificats::Instance])? {
        warn!("process_presence_instance_v2 Rejecting message not from an instance");
        return Ok(None)
    }

    let instance_id = message.certificat.get_common_name()?;
    let timestamp = message_ref.estampille;

    let collection = middleware.get_collection(NOM_COLLECTION_INSTANCE_STATUS_V2)?;

    let securite = match message.certificat.extensions() {
        Ok(e) => {
            match e.exchanges {
                Some(e) => match e.get(0) {
                    Some(e) => e.clone(),
                    None => {
                        warn!("process_presence_instance_v2 Rejecting message from instance with no configured exchanges (empty list) in certificate");
                        return Ok(None);
                    }
                },
                None => {
                    warn!("process_presence_instance_v2 Rejecting message from instance with no configured exchanges in certificate");
                    return Ok(None);
                }
            }
        }
        Err(e) => {
            warn!("process_presence_instance_v2 Rejecting message from instance with no configured extensions in certificate (error: {})", e);
            return Ok(None);
        }
    };

    let filtre = doc! {"instance_id": instance_id.clone()};

    let row_content = ManagerStatusV2 {
        instance_id,
        system_state: event.system_state,
        securite,
        supprime: false,
        timestamp,
    };

    // Override the content of the table with the received event information
    let set_ops = convertir_to_bson(row_content)?;

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {
            CHAMP_CREATION: timestamp,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let options = UpdateOptions::builder().upsert(true).build();
    collection.update_one_with_session(filtre, ops, options, session).await?;

    Ok(None)
}

#[derive(Serialize, Deserialize)]
pub struct PresenceInstanceContainer {
    pub creation: String,
    pub dead: Option<bool>,
    pub etat: Option<String>,
    pub finished_at: Option<String>,
    pub labels: Option<HashMap<String, String>>,
    pub restart_count: u32,
    pub running: bool,
}

impl PresenceInstanceContainer {
    fn service_name(&self) -> Option<&str> {
        match &self.labels {
            Some(inner) => match inner.get("com.docker.swarm.service.name") {
                Some(name) => Some(name.as_str()),
                None => None
            },
            None => None
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PresenceInstanceService {
    creation_service: String,
    etat: Option<String>,
    image: String,
    labels: Option<HashMap<String, String>>,
    maj_service: Option<String>,
    message_tache: Option<String>,
    replicas: Option<u32>,
    version: Option<String>
}

#[derive(Serialize, Deserialize)]
pub struct PresenceInstanceWebApplication {
    pub labels: Option<HashMap<String, HashMap<String, String>>>,  // language.label = text
    pub name: String,
    pub securite: String,
    pub url: Option<String>,
    pub users: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct PresenceInstanceConfiguredApplications {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Deserialize)]
struct PresenceInstanceApplicationsEvent {
    complete: bool,
    containers: HashMap<String, PresenceInstanceContainer>,
    services: HashMap<String, PresenceInstanceService>,
    webapps: Vec<PresenceInstanceWebApplication>,
    configured_applications: Vec<PresenceInstanceConfiguredApplications>,
}

async fn process_presence_instance_applications<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: MongoDao
{
    let message_ref = message.message.parse()?;
    let event: PresenceInstanceApplicationsEvent = message_ref.contenu()?.deserialize()?;

    if ! message.certificat.verifier_roles(vec![RolesCertificats::Instance])? {
        info!("process_presence_instance Rejecting message not from an instance");
        return Ok(None)
    }

    let instance_id = message.certificat.get_common_name()?;
    let timestamp = &message_ref.estampille;

    {
        let collection = middleware.get_collection(NOM_COLLECTION_INSTANCE_CONTAINERS)?;
        let mut names = Vec::new();
        for (name, status) in event.containers {
            let service_name = match status.service_name() {
                Some(inner) => inner,
                None => name.as_str()
            };
            names.push(service_name.to_string());
            let filtre = doc!{"instance_id": &instance_id, "service_name": &service_name};
            let mut set_ops = convertir_to_bson(status)?;
            set_ops.insert("timestamp", timestamp);
            let ops = doc! {
                "$set": set_ops,
                "$setOnInsert": {CHAMP_CREATION: timestamp},
                "$currentDate": {CHAMP_MODIFICATION: true},
            };
            let options = UpdateOptions::builder().upsert(true).build();
            collection.update_one_with_session(filtre, ops, options, session).await?;
        }

        if event.complete {
            let filtre = doc!{"instance_id": &instance_id, "service_name": {"$not": {"$in": names}}};
            collection.delete_many_with_session(filtre, None, session).await?;
        }
    }

    {
        let collection = middleware.get_collection(NOM_COLLECTION_INSTANCE_SERVICES)?;
        let mut names = Vec::new();
        for (service_name, status) in event.services {
            names.push(service_name.clone());
            let filtre = doc!{"instance_id": &instance_id, "service_name": &service_name};
            let mut set_ops = convertir_to_bson(status)?;
            set_ops.insert("timestamp", timestamp);
            let ops = doc! {
                "$set": set_ops,
                "$setOnInsert": {CHAMP_CREATION: timestamp},
                "$currentDate": {CHAMP_MODIFICATION: true},
            };
            let options = UpdateOptions::builder().upsert(true).build();
            collection.update_one_with_session(filtre, ops, options, session).await?;
        }

        if event.complete {
            let filtre = doc!{"instance_id": &instance_id, "service_name": {"$not": {"$in": names}}};
            collection.delete_many_with_session(filtre, None, session).await?;
        }
    }

    {
        let collection = middleware.get_collection(NOM_COLLECTION_INSTANCE_WEBAPPS)?;
        let mut names = Vec::new();
        let mut urls = Vec::new();
        for webapp in event.webapps {
            names.push(webapp.name.clone());
            urls.push(webapp.url.clone());
            let filtre = doc!{"instance_id": &instance_id, "app_name": &webapp.name, "url": &webapp.url};
            let mut set_ops = convertir_to_bson(webapp)?;
            set_ops.insert("timestamp", timestamp);
            let ops = doc! {
                "$set": set_ops,
                "$setOnInsert": {CHAMP_CREATION: timestamp},
                "$currentDate": {CHAMP_MODIFICATION: true},
            };
            let options = UpdateOptions::builder().upsert(true).build();
            collection.update_one_with_session(filtre, ops, options, session).await?;
        }

        if event.complete {
            let filtre = doc!{"instance_id": &instance_id, "app_name": {"$not": {"$in": names}}, "url": {"$not": {"$in": urls}}};
            collection.delete_many_with_session(filtre, None, session).await?;
        }
    }

    {
        let collection = middleware.get_collection(NOM_COLLECTION_INSTANCE_CONFIGURED_APPLICATIONS)?;
        let mut names = Vec::new();
        for webapp in event.configured_applications {
            names.push(webapp.name.clone());
            let filtre = doc!{"instance_id": &instance_id, "app_name": &webapp.name};
            let mut set_ops = convertir_to_bson(webapp)?;
            set_ops.insert("timestamp", timestamp);
            let ops = doc! {
                "$set": set_ops,
                "$setOnInsert": {CHAMP_CREATION: timestamp},
                "$currentDate": {CHAMP_MODIFICATION: true},
            };
            let options = UpdateOptions::builder().upsert(true).build();
            collection.update_one_with_session(filtre, ops, options, session).await?;
        }

        if event.complete {
            let filtre = doc!{"instance_id": &instance_id, "app_name": {"$not": {"$in": names}}};
            collection.delete_many_with_session(filtre, None, session).await?;
        }
    }

    Ok(None)
}

#[derive(Debug, Serialize, Deserialize)]
struct InstalledApplicationV2 {
    applications: HashMap<String, ApplicationInfo>
}

async fn process_presence_instance_applications_v2<M>(middleware: &M, message: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: MongoDao
{
    let message_ref = message.message.parse()?;
    let event: InstalledApplicationV2 = message_ref.contenu()?.deserialize()?;

    if ! message.certificat.verifier_roles(vec![RolesCertificats::Instance])? {
        info!("process_presence_instance Rejecting message not from an instance");
        return Ok(None)
    }

    let instance_id = message.certificat.get_common_name()?;
    let timestamp = message_ref.estampille;

    let collection = middleware.get_collection(NOM_COLLECTION_INSTANCE_CONFIGURED_APPLICATIONS_V2)?;

    let securite = match message.certificat.extensions() {
        Ok(e) => {
            match e.exchanges {
                Some(e) => match e.get(0) {
                    Some(e) => e.clone(),
                    None => {
                        warn!("process_presence_instance_v2 Rejecting message from instance with no configured exchanges (empty list) in certificate");
                        return Ok(None);
                    }
                },
                None => {
                    warn!("process_presence_instance_v2 Rejecting message from instance with no configured exchanges in certificate");
                    return Ok(None);
                }
            }
        }
        Err(e) => {
            warn!("process_presence_instance_v2 Rejecting message from instance with no configured extensions in certificate (error: {})", e);
            return Ok(None);
        }
    };

    let filtre = doc! {"instance_id": instance_id.clone()};

    let row_content = ApplicationStatusV2 {
        instance_id,
        applications: event.applications,
        securite,
        supprime: false,
        timestamp,
    };

    // Override the content of the table with the received event information
    let set_ops = convertir_to_bson(row_content)?;

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {
            CHAMP_CREATION: timestamp,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let options = UpdateOptions::builder().upsert(true).build();
    collection.update_one_with_session(filtre, ops, options, session).await?;

    Ok(None)
}
