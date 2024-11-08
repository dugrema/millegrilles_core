use log::{debug, error};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::serde_json;
use crate::topology_constants::*;
use crate::topology_structs::{FilehostServerRow, FilehostingCongurationRow, PresenceDomaine, PresenceMonitor, TransactionConfigurerConsignation, TransactionSetConsignationInstance, TransactionSetFichiersPrimaire, TransactionSupprimerConsignationInstance};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::common_messages::ReponseInformationConsignationFichiers;
use millegrilles_common_rust::constantes::{CHAMP_MODIFICATION, CHAMP_CREATION, Securite};
use millegrilles_common_rust::jwt_simple::prelude::{Deserialize, Serialize};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::serde_json::json;

pub async fn aiguillage_transaction_topology<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: TryInto<TransactionValide>
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(String::from("aiguillage_transaction Erreur try_into"))?
    };

    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.to_owned(),
            None => Err(format!("Transaction {} n'a pas d'action", transaction.transaction.id))?
        },
        None => Err(format!("Transaction {} n'a pas de routage", transaction.transaction.id))?
    };

    match action.as_str() {
        TRANSACTION_DOMAINE => traiter_transaction_domaine(middleware, transaction).await,
        TRANSACTION_MONITOR => traiter_transaction_monitor(middleware, transaction).await,
        TRANSACTION_SUPPRIMER_INSTANCE => traiter_transaction_supprimer_instance(middleware, transaction).await,
        // TRANSACTION_SET_FICHIERS_PRIMAIRE => transaction_set_fichiers_primaire(middleware, transaction).await,
        // TRANSACTION_CONFIGURER_CONSIGNATION => transaction_configurer_consignation(middleware, transaction).await,
        TRANSACTION_SET_CONSIGNATION_INSTANCE => transaction_set_consignation_instance(middleware, transaction).await,
        // TRANSACTION_SUPPRIMER_CONSIGNATION_INSTANCE => traiter_transaction_supprimer_consignation(middleware, transaction).await,
        TRANSACTION_FILEHOST_ADD => filehost_add(middleware, transaction).await,
        TRANSACTION_FILEHOST_UPDATE => filehost_update(middleware, transaction).await,
        TRANSACTION_FILEHOST_DELETE => filehost_delete(middleware, transaction).await,
        TRANSACTION_FILEHOST_RESTORE => filehost_restore(middleware, transaction).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.transaction.id, action))?,
    }
}

async fn traiter_transaction_domaine<M>(middleware: &M, transaction: TransactionValide)
                                        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let transaction = match serde_json::from_str::<PresenceDomaine>(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => {
            error!("traiter_transaction_domaine Erreur convertir {:?}\n{}", e, transaction.transaction.contenu);
            Err(format!("traiter_transaction_domaine Erreur convertir {:?}", e))?
        }
    };
    let domaine = match transaction.domaine {
        Some(d) => d,
        None => Err(String::from("traiter_transaction_domaine Erreur domaine absent"))?
    };

    let mut set_ops = doc!{"dirty": false};
    if let Some(instance_id) = transaction.instance_id {
        set_ops.insert("instance_id", instance_id);
    }

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {CHAMP_DOMAINE: &domaine, CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc! {CHAMP_DOMAINE: domaine};
    let collection = middleware.get_collection(NOM_COLLECTION_DOMAINES)?;
    let options = UpdateOptions::builder().upsert(true).build();
    match collection.update_one(filtre, ops, options).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur maj transaction topologie domaine : {:?}", e))?
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn traiter_transaction_monitor<M>(middleware: &M, transaction: TransactionValide)
                                        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let mut doc_transaction: PresenceMonitor = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(d) => d,
        Err(e) => Err(format!("core_topologie.traiter_transaction_monitor Erreur conversion transaction monitor : {:?}", e))?
    };
    debug!("traiter_transaction_monitor {:?}", doc_transaction);

    let instance_id = doc_transaction.instance_id;

    let ops = doc! {
        "$set": {"dirty": false, CHAMP_DOMAINE: doc_transaction.domaine},
        "$setOnInsert": {CHAMP_INSTANCE_ID: &instance_id, CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc! {CHAMP_INSTANCE_ID: &instance_id};
    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
    let options = UpdateOptions::builder().upsert(true).build();
    match collection.update_one(filtre, ops, options).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur maj transaction topologie domaine : {:?}", e))?
    }

    let reponse = middleware.reponse_ok(None, None)?;
    // let reponse = match middleware.formatter_reponse(json!({"ok": true}), None) {
    //     Ok(r) => r,
    //     Err(e) => Err(format!("Erreur reponse transaction : {:?}", e))?
    // };
    Ok(Some(reponse))
}

async fn traiter_transaction_supprimer_instance<M>(middleware: &M, transaction: TransactionValide)
                                                   -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let mut doc_transaction: PresenceMonitor = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(d) => d,
        Err(e) => Err(format!("core_topologie.traiter_transaction_supprimer_instance Erreur conversion transaction monitor : {:?}", e))?
    };

    let instance_id = doc_transaction.instance_id;

    let filtre = doc! {CHAMP_NOEUD_ID: &instance_id};
    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
    match collection.delete_one(filtre, None).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur maj transaction topologie domaine : {:?}", e))?
    }

    // Emettre evenement d'instance supprimee
    let evenement_supprimee = json!({"instance_id": &instance_id});
    let routage = RoutageMessageAction::builder(DOMAIN_NAME, EVENEMENT_INSTANCE_SUPPRIMEE, vec![Securite::L3Protege])
        .build();
    middleware.emettre_evenement(routage, &evenement_supprimee).await?;

    let reponse = middleware.reponse_ok(None, None)?;
    Ok(Some(reponse))
}

// async fn transaction_set_fichiers_primaire<M>(middleware: &M, transaction: TransactionValide)
//     -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
//     where M: ValidateurX509 + GenerateurMessages + MongoDao
// {
//     // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
//     let transaction = match serde_json::from_str::<TransactionSetFichiersPrimaire>(transaction.transaction.contenu.as_str()) {
//         Ok(t) => t,
//         Err(e) => Err(format!("transaction_set_fichiers_primaire Erreur convertir {:?}\n{}", e, transaction.transaction.contenu))?
//     };
//     debug!("transaction_set_fichiers_primaire Set fichiers primaire : {:?}", transaction);
//
//     let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
//
//     // Retirer le flag primaire de toutes les instances
//     let filtre = doc! {"instance_id": {"$ne": &transaction.instance_id}};
//     let ops = doc!{
//         "$set": {"primaire": false},
//         "$currentDate": {CHAMP_MODIFICATION: true},
//     };
//     if let Err(e) = collection.update_many(filtre, ops, None).await {
//         Err(format!("transaction_set_fichiers_primaire Erreur update_many : {:?}", e))?
//     }
//
//     // Set flag primaire sur la bonne instance
//     let filtre = doc! {"instance_id": &transaction.instance_id};
//     let ops = doc!{
//         "$set": {"primaire": true, "supprime": false},
//         "$currentDate": {CHAMP_MODIFICATION: true},
//     };
//     if let Err(e) = collection.update_one(filtre, ops, None).await {
//         Err(format!("transaction_set_fichiers_primaire Erreur update_one : {:?}", e))?
//     }
//
//     // Emettre evenement de changement de consignation primaire
//     let routage = RoutageMessageAction::builder(DOMAIN_NAME, "changementConsignationPrimaire", vec![Securite::L2Prive])
//         .build();
//     middleware.emettre_evenement(routage, &transaction).await?;
//
//     Ok(Some(middleware.reponse_ok(None, None)?))
// }

// async fn transaction_configurer_consignation<M>(middleware: &M, transaction: TransactionValide)
//                                                 -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
// where M: ValidateurX509 + GenerateurMessages + MongoDao
// {
//     // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
//     debug!("transaction_configurer_consignation Contenu de la transaction\n{}", transaction.transaction.contenu);
//     let transaction = match serde_json::from_str::<TransactionConfigurerConsignation>(transaction.transaction.contenu.as_str()) {
//         Ok(t) => t,
//         Err(e) => Err(format!("transaction_configurer_consignation Erreur convertir {:?}", e))?
//     };
//     debug!("transaction_configurer_consignation Transaction : {:?}", transaction);
//
//     let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
//
//     let data_chiffre = match transaction.data_chiffre {
//         Some(d) => match convertir_to_bson(d) {
//             Ok(d) => Some(d),
//             Err(e) => Err(format!("transaction_configurer_consignation Erreur conversion data_chiffre {:?}", e))?
//         },
//         None => None
//     };
//
//     // Defaults
//     let consignation_url = match transaction.consignation_url.as_ref() {
//         Some(inner) => inner.as_str(),
//         None => DEFAULT_CONSIGNATION_URL
//     };
//     let supporte_archives = match transaction.supporte_archives.as_ref() {
//         Some(inner) => inner.to_owned(),
//         None => true
//     };
//     let sync_actif = match transaction.sync_actif.as_ref() {
//         Some(inner) => inner.to_owned(),
//         None => true
//     };
//
//     let port_sftp = match transaction.port_sftp {
//         Some(inner) => Some(inner as i64),
//         None => None,
//     };
//
//     let port_sftp_backup = match transaction.port_sftp_backup {
//         Some(inner) => Some(inner as i64),
//         None => None,
//     };
//
//     let set_ops = doc! {
//         "type_store": transaction.type_store,
//         "url_download": transaction.url_download,
//         "url_archives": transaction.url_archives,
//         "consignation_url": consignation_url,
//         "sync_intervalle": transaction.sync_intervalle,
//         "sync_actif": sync_actif,
//         "supporte_archives": supporte_archives,
//         "data_chiffre": data_chiffre,
//         "port_sftp": port_sftp,
//         "hostname_sftp": transaction.hostname_sftp,
//         "username_sftp": transaction.username_sftp,
//         "remote_path_sftp": transaction.remote_path_sftp,
//         "key_type_sftp": transaction.key_type_sftp,
//         "s3_access_key_id": transaction.s3_access_key_id,
//         "s3_region": transaction.s3_region,
//         "s3_endpoint": transaction.s3_endpoint,
//         "s3_bucket": transaction.s3_bucket,
//         "type_backup": transaction.type_backup,
//         "hostname_sftp_backup": transaction.hostname_sftp_backup,
//         "port_sftp_backup": port_sftp_backup,
//         "username_sftp_backup": transaction.username_sftp_backup,
//         "remote_path_sftp_backup": transaction.remote_path_sftp_backup,
//         "key_type_sftp_backup": transaction.key_type_sftp_backup,
//         "backup_intervalle_secs": transaction.backup_intervalle_secs,
//         "backup_limit_bytes": transaction.backup_limit_bytes,
//         "supprime": false,
//     };
//
//     let ops = doc! {
//         "$set": set_ops,
//         "$setOnInsert": {
//             "instance_id": &transaction.instance_id,
//             CHAMP_CREATION: Utc::now(),
//             "primaire": false,
//         },
//         "$currentDate": {CHAMP_MODIFICATION: true}
//     };
//
//     let options = FindOneAndUpdateOptions::builder()
//         .return_document(ReturnDocument::After)
//         .upsert(true)
//         .build();
//
//     let filtre = doc!{ "instance_id": &transaction.instance_id };
//     let configuration = match collection.find_one_and_update(filtre, ops, Some(options)).await {
//         Ok(inner) => match inner {
//             Some(inner) => match convertir_bson_deserializable::<ReponseInformationConsignationFichiers>(inner) {
//                 Ok(inner) => inner,
//                 Err(e) => Err(format!("transaction_configurer_consignation Erreur mapper reponse : {:?}", e))?
//             },
//             None => Err(String::from("transaction_configurer_consignation Erreur sauvegarde configuration consignation : Aucun doc conserve"))?
//         },
//         Err(e) => Err(format!("transaction_configurer_consignation Erreur sauvegarde configuration consignation : {:?}", e))?
//     };
//
//     // Emettre commande de modification de configuration pour fichiers
//     let routage = RoutageMessageAction::builder("fichiers", "modifierConfiguration", vec![Securite::L2Prive])
//         .partition(transaction.instance_id.as_str())
//         .blocking(false)
//         .build();
//
//     // Transmettre commande non-blocking
//     middleware.transmettre_commande(routage, &configuration).await?;
//
//     // Emettre evenement changement de consignation
//     let routage = RoutageMessageAction::builder(DOMAIN_NAME, EVENEMENT_MODIFICATION_CONSIGNATION, vec![Securite::L1Public])
//         .build();
//     let evenement = json!({
//         CHAMP_INSTANCE_ID: transaction.instance_id,
//         "consignation_url": transaction.consignation_url,
//     });
//     middleware.emettre_evenement(routage, &evenement).await?;
//
//     Ok(Some(middleware.reponse_ok(None, None)?))
// }

async fn transaction_set_consignation_instance<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let transaction = match serde_json::from_str::<TransactionSetConsignationInstance>(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_set_consignation_instance Erreur convertir {:?}", e))?
    };
    debug!("transaction_set_consignation_instance Params : {:?}", transaction);

    let filtre = doc! { CHAMP_INSTANCE_ID: &transaction.instance_id };
    let set_ops = doc! {
        CHAMP_CONSIGNATION_ID: transaction.consignation_id.as_ref(),
        "supprime": false,
    };
    let ops = doc! {
        "$set": set_ops,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let collection = middleware.get_collection(NOM_COLLECTION_INSTANCES)?;
    if let Err(e) = collection.update_one(filtre, ops, None).await {
        Err(format!("core_topologie.transaction_set_consignation_instance Erreur sauvegarde consignation_id : {:?}", e))?
    }

    // Emettre evenement changement de consignation
    let routage = RoutageMessageAction::builder(DOMAIN_NAME, EVENEMENT_MODIFICATION_CONSIGNATION, vec![Securite::L1Public])
        .build();
    let evenement = json!({
        CHAMP_INSTANCE_ID: transaction.instance_id
    });
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

// async fn traiter_transaction_supprimer_consignation<M>(middleware: &M, transaction: TransactionValide)
//                                                        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
// where M: GenerateurMessages + MongoDao
// {
//     // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
//     let mut doc_transaction: TransactionSupprimerConsignationInstance = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
//         Ok(d) => d,
//         Err(e) => Err(format!("core_topologie.traiter_transaction_supprimer_consignation Erreur conversion transaction monitor : {:?}", e))?
//     };
//
//     let instance_id = doc_transaction.instance_id;
//
//     let filtre = doc! {CHAMP_INSTANCE_ID: &instance_id};
//     let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
//     let ops = doc!{
//         "$set": {"supprime": true},
//         "$currentDate": {CHAMP_MODIFICATION: true}
//     };
//     match collection.update_one(filtre, ops, None).await {
//         Ok(_) => (),
//         Err(e) => Err(format!("traiter_transaction_supprimer_consignation Erreur maj transaction topologie domaine : {:?}", e))?
//     }
//
//     let reponse = middleware.reponse_ok(None, None)?;
//     Ok(Some(reponse))
// }

#[derive(Deserialize)]
pub struct FilehostAddTransaction {
    pub tls_external: Option<String>,
    pub url_external: Option<String>,
    pub url_internal: Option<String>,
}

#[derive(Deserialize)]
pub struct FilehostUpdateTransaction {
    pub filehost_id: String,
    pub instance_id: Option<String>,
    pub sync_active: Option<bool>,
    pub tls_external: Option<String>,
    pub url_external: Option<String>,
    pub url_internal: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct FilehostRestoreTransaction {
    pub filehost_id: String,
}

#[derive(Serialize)]
struct HostfileAddTransactionResponse {
    ok: bool,
    filehost_id: String
}

async fn filehost_add<M>(middleware: &M, transaction: TransactionValide)
                         -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    let doc_transaction: FilehostAddTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;
    let transaction_id = &transaction.transaction.id;

    let mut instance_id = None;
    if transaction.certificat.verifier_exchanges(vec![Securite::L1Public])? && transaction.certificat.verifier_roles_string(vec!["filecontroler".to_string()])? {
        instance_id = Some(transaction.certificat.get_common_name()?);
    }

    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTS)?;
    let now = Utc::now();
    let filehost = FilehostServerRow {
        filehost_id: transaction_id.clone(),  // Assign new hostfile_id from transaction id
        instance_id,
        url_internal: doc_transaction.url_internal,
        url_external: doc_transaction.url_external,
        tls_external: doc_transaction.tls_external,
        deleted: false,
        sync_active: true,
        created: now.clone(),
        modified: now,
    };
    let filehost_bson = convertir_to_bson(filehost)?;
    collection.insert_one(filehost_bson, None).await?;

    let response = HostfileAddTransactionResponse {ok: true, filehost_id: transaction_id.clone()};
    let response = middleware.build_reponse(response)?.0;
    Ok(Some(response))
}

async fn filehost_update<M>(middleware: &M, transaction: TransactionValide)
                         -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    let doc_transaction: FilehostUpdateTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTS)?;
    let filtre = doc! {"filehost_id": doc_transaction.filehost_id};
    let mut set_ops = doc!{};
    if let Some(inner) = doc_transaction.instance_id {
        set_ops.insert("instance_id", inner);
    }
    if let Some(inner) = doc_transaction.url_internal {
        set_ops.insert("url_internal", inner);
    }
    if let Some(inner) = doc_transaction.url_external {
        set_ops.insert("url_external", inner);
    }
    if let Some(inner) = doc_transaction.tls_external {
        set_ops.insert("tls_external", inner);
    }
    if let Some(inner) = doc_transaction.sync_active {
        set_ops.insert("sync_active", inner);
    }

    if set_ops.len() == 0 {
        return Ok(Some(middleware.reponse_err(Some(400), None, Some("No changes"))?));
    }

    let ops = doc!{
        "$set": set_ops,
        "$currentDate": {"modified": true}
    };
    let result = collection.update_one(filtre, ops, None).await?;

    if result.matched_count == 1 {
        Ok(Some(middleware.reponse_ok(None, None)?))
    } else {
        Ok(Some(middleware.reponse_err(Some(404), None, Some("No match"))?))
    }
}

#[derive(Deserialize)]
pub struct FilehostDeleteTransaction {
    pub filehost_id: String,
}

async fn filehost_delete<M>(middleware: &M, transaction: TransactionValide)
                         -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    let doc_transaction: FilehostDeleteTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTS)?;
    let filter = doc!{"filehost_id": &doc_transaction.filehost_id };
    let ops = doc !{
        "$set": {"deleted": true},
        "$currentDate": {"modified": true},
    };
    let result = collection.update_one(filter, ops, None).await?;

    // Delete default filhost configuration item if matches filehost_id
    let collection_configuration = middleware.get_collection_typed::<FilehostingCongurationRow>(NOM_COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let filtre_configuration = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT, "value": doc_transaction.filehost_id};
    collection_configuration.delete_one(filtre_configuration, None).await?;

    let ok = result.matched_count == 1;
    if ok {
        Ok(Some(middleware.reponse_ok(None, None)?))
    } else {
        Ok(Some(middleware.reponse_err(Some(404), None, Some("No filehost item updated"))?))
    }
}

async fn filehost_restore<M>(middleware: &M, transaction: TransactionValide)
                            -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    let doc_transaction: FilehostRestoreTransaction = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTS)?;
    let filter = doc!{"filehost_id": &doc_transaction.filehost_id };
    let ops = doc !{
        "$set": {"deleted": false},
        "$currentDate": {"modified": true},
    };
    let result = collection.update_one(filter, ops, None).await?;

    let ok = result.matched_count == 1;
    if ok {
        let response = HostfileAddTransactionResponse {ok: true, filehost_id: doc_transaction.filehost_id};
        let response = middleware.build_reponse(response)?.0;
        Ok(Some(response))
    } else {
        Ok(Some(middleware.reponse_err(Some(404), None, Some("No filehost item updated"))?))
    }
}
