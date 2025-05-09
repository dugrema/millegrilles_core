use std::collections::{HashMap, HashSet};
use log::{debug, error, info, warn};
use log::kv::Source;
use millegrilles_common_rust::bson::{doc, Bson, Array, DateTime};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::common_messages::{BackupEvent, PresenceFichiersRepertoire};
use millegrilles_common_rust::constantes::{Securite, EVENEMENT_PRESENCE_DOMAINE, CHAMP_CREATION, CHAMP_MODIFICATION, DOMAINE_APPLICATION_INSTANCE, RolesCertificats, BACKUP_EVENEMENT_MAJ};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction_serializable_v2;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, start_transaction_regular, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde_json::{json, Value};
use serde::{Deserialize, Serialize};

use crate::topology_common::generer_contenu_fiche_publique;
use crate::topology_manager::TopologyManager;
use crate::topology_constants::*;
use crate::topology_structs::{EventFilehostUsage, EventNewFuuid, PresenceDomaine, PresenceMonitor, RowFilehostFuuid, RowFilehostId, RowFuuid, TransactionSetFichiersPrimaire};
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::mongodb::ClientSession;
use crate::topology_maintenance::emit_filehost_transfersupdated_event;

pub async fn consommer_evenement_topology<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
                                             -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("Consommer evenement : {:?}", &m.type_message);

    let (domaine, action) = match &m.type_message {
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
        EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS => process_presence_instance_applications(middleware, m, &mut session).await,
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

async fn traiter_presence_domaine<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
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
    let result = match collection.find_one_and_update(filtre, ops, Some(options)).await {
        Ok(r) => r,
        Err(e) => Err(format!("Erreur find document sur transaction domaine : {:?}", e))?
    };

    Ok(None)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PresenceFichiers {
    type_store: Option<String>,
    url_download: Option<String>,
    url_archives: Option<String>,
    consignation_url: Option<String>,
    principal: Option<PresenceFichiersRepertoire>,
    archive: Option<PresenceFichiersRepertoire>,
    orphelin: Option<PresenceFichiersRepertoire>,
    manquant: Option<PresenceFichiersRepertoire>,
}

// async fn traiter_presence_fichiers<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
//                                       -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
// where M: ValidateurX509 + GenerateurMessages + MongoDao
// {
//     let message_ref = m.message.parse()?;
//     let message_contenu = message_ref.contenu()?;
//     let event: PresenceFichiers = message_contenu.deserialize()?;
//     debug!("traiter_presence_fichiers Presence fichiers : {:?}", event);
//
//     if ! m.certificat.verifier_roles(vec![RolesCertificats::Fichiers])? {
//         Err(format!("core_topologie.traiter_presence_fichiers Certificat n'a pas le role 'fichiers'"))?
//     }
//     let subject = m.certificat.subject()?;
//     debug!("traiter_presence_fichiers Subject enveloppe : {:?}", subject);
//     let instance_id = match subject.get("commonName") {
//         Some(instance_id) => instance_id.clone(),
//         None => Err(format!("core_topologie.traiter_presence_fichiers organizationalUnit absent du message"))?
//     };
//
//     debug!("traiter_presence_fichiers Presence fichiers recue pour instance_id {}", instance_id);
//
//     let mut unset_ops = doc! {};
//     let mut set_ops = doc! {
//         "principal": event.principal,
//         "archive": event.archive,
//         "orphelin": event.orphelin,
//         "manquant": event.manquant,
//         "supprime": false,
//     };
//
//     let mut ops = doc! {
//         "$setOnInsert": {
//             "instance_id": &instance_id, CHAMP_CREATION: Utc::now(),
//             // Defaut pour nouvelle instance
//             "type_store": "millegrille",
//             "consignation_url": DEFAULT_CONSIGNATION_URL,
//             "sync_actif": true,
//         },
//         "$set": set_ops,
//         "$currentDate": {CHAMP_MODIFICATION: true}
//     };
//     if unset_ops.len() > 0 {
//         ops.insert("$unset", unset_ops);
//     }
//
//     let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
//     let filtre = doc! {"instance_id": &instance_id};
//     let options = UpdateOptions::builder()
//         .upsert(true)
//         .build();
//     let resultat = collection.update_one_with_session(filtre, ops, options).await?;
//     debug!("traiter_presence_fichiers Resultat update : {:?}", resultat);
//
//     // Verifier si on a un primaire - sinon generer transaction pour set primaire par defaut
//     let filtre = doc! {"primaire": true};
//     let resultat = collection.find_one(filtre, None).await?;
//     if resultat.is_none() {
//         debug!("traiter_presence_fichiers Assigne le role de fichiers primaire a {}", instance_id);
//         let transaction = TransactionSetFichiersPrimaire { instance_id };
//
//         // Sauvegarder la transaction
//         sauvegarder_traiter_transaction_serializable_v2(
//             middleware, &transaction, gestionnaire, DOMAIN_NAME, TRANSACTION_SET_FICHIERS_PRIMAIRE).await?;
//     }
//
//     Ok(None)
// }

// async fn traiter_presence_monitor<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
//                                      -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
// where M: ValidateurX509 + GenerateurMessages + MongoDao
// {
//     let message_ref = m.message.parse()?;
//     let estampille = message_ref.estampille;
//     let message_contenu = message_ref.contenu()?;
//     let event: PresenceMonitor = message_contenu.deserialize()?;
//     debug!("Presence monitor : {:?}", event);
//
//     // Preparer valeurs applications
//     let mut applications = Array::new();
//     if let Some(map) = &event.services {
//         for (nom_service, info_service) in map.iter() {
//             if let Some(labels) = &info_service.labels {
//                 let nom_application = match labels.get("application") {
//                     Some(a) => a.as_str(),
//                     None => nom_service.as_str()
//                 };
//
//                 if let Some(url) = labels.get("url") {
//                     if let Some(securite) = labels.get("securite") {
//                         let mut info_app = doc! {
//                             "application": nom_application,
//                             "securite": securite,
//                             "url": url,
//                         };
//
//                         if let Some(millegrille) = labels.get("millegrille") {
//                             info_app.insert("millegrille", millegrille);
//                         }
//
//                         if let Some(a) = labels.get("nom_application") {
//                             info_app.insert("name_property", a.as_str());
//                         };
//
//                         if let Some(s) = labels.get("supporte_usagers") {
//                             info_app.insert("supporte_usagers", s.as_str() != "false");
//                         };
//
//                         applications.push(Bson::Document(info_app));
//                     }
//                 }
//             }
//         }
//     }
//
//     // debug!("Applications noeud : {:?}", &applications);
//
//     // let mut set_ops = m.message.get_msg().map_to_bson()?;
//     // filtrer_doc_id(&mut set_ops);
//
//     let mut set_ops = convertir_to_bson(event.clone())?;
//
//     // Retirer champ cle
//     set_ops.remove("instance_id");
//     set_ops.remove("filehost_id");  // Ce setting est manuel
//     set_ops.insert("applications", applications);
//     set_ops.insert("date_presence", estampille);
//
//     let filtre = doc! {"instance_id": &event.instance_id};
//     let ops = doc! {
//         "$set": set_ops,
//         "$setOnInsert": {"instance_id": &event.instance_id, CHAMP_CREATION: Utc::now(), "dirty": true},
//         "$currentDate": {CHAMP_MODIFICATION: true}
//     };
//
//     debug!("Document monitor a sauvegarder : {:?}", ops);
//     let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
//     let options = FindOneAndUpdateOptions::builder().upsert(true).build();
//     let result = collection.find_one_and_update(filtre, ops, Some(options)).await?;
//     debug!("Result update monitor : {:?}", result);
//
//     // Verifier si on doit creer une nouvelle transaction
//     let creer_transaction = match result {
//         Some(d) => d.get_bool("dirty")?,
//         None => true,
//     };
//
//     if creer_transaction {
//         debug!("Creer transaction topologie pour monitor/noeud {:?}", &event.domaine);
//
//         let tval = json!({
//             "domaine": event.domaine,
//             "instance_id": event.instance_id,
//         });
//
//         sauvegarder_traiter_transaction_serializable_v2(middleware, &tval, gestionnaire, DOMAIN_NAME, TRANSACTION_INSTANCE).await?;
//
//         // Reset le flag dirty pour eviter multiple transactions sur le meme domaine
//         let filtre = doc! {"instance_id": &event.instance_id};
//         let ops = doc! {"$set": {"dirty": false}};
//         let _ = collection.update_one_with_session(filtre, ops, None).await?;
//     }
//
//     Ok(None)
// }

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

            let mut missing_from = filehost_ids.difference(&filehost_ids_visits);
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
