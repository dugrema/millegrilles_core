use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::from_utf8;
use webauthn_rs::prelude::Url;

use crate::topology_common::{demander_jwt_hebergement, maj_fiche_publique};
use crate::topology_constants::*;
use crate::topology_manager::TopologyManager;
use crate::topology_structs::{FichePublique, FilehostServerRow, FilehostingCongurationRow, ReponseUrlEtag, TransactionConfigurerConsignation, TransactionSetCleidBackupDomaine, TransactionSetConsignationInstance, TransactionSetFichiersPrimaire};

use crate::topology_transactions::{FilehostDeleteTransaction, FilehostRestoreTransaction, FilehostUpdateTransaction, HostfileAddTransaction};

use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::RequeteFilehostItem;
use millegrilles_common_rust::constantes::{Securite, CHAMP_CREATION, CHAMP_MODIFICATION, COMMANDE_RELAIWEB_GET, COMMANDE_SAUVEGARDER_CLE, DELEGATION_GLOBALE_PROPRIETAIRE, DOMAINE_NOM_MAITREDESCLES, DOMAINE_RELAIWEB, DOMAINE_TOPOLOGIE, TOPOLOGIE_NOM_DOMAINE};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::ReponseCommande;
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_serializable_v2, sauvegarder_traiter_transaction_v2, Middleware};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, InsertManyOptions, UpdateOptions, WriteConcern};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::{get_domaine_action, serde_json};
use millegrilles_common_rust::redis::Commands;
use millegrilles_common_rust::mongo_dao::{opt_chrono_datetime_as_bson_datetime, map_opt_chrono_datetime_as_bson_datetime};

pub async fn consommer_commande_topology<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
                                            -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: Middleware
{
    debug!("Consommer commande : {:?}", &m.type_message);
    let (_domaine, action) = get_domaine_action!(&m.type_message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L3Protege, Securite::L4Secure))? {
        true => Ok(()),
        false => match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
            true => Ok(()),
            false => Err(format!("Commande autorisation invalide (pas 1.public, 3.protege ou 4.secure)")),
        }
    }?;

    match action.as_str() {
        // Commandes standard
        TRANSACTION_MONITOR => traiter_commande_monitor(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_INSTANCE => traiter_commande_supprimer_instance(middleware, m, gestionnaire).await,
        TRANSACTION_CONFIGURER_CONSIGNATION => traiter_commande_configurer_consignation(middleware, m, gestionnaire).await,
        TRANSACTION_SET_FICHIERS_PRIMAIRE => traiter_commande_set_fichiers_primaire(middleware, m, gestionnaire).await,
        TRANSACTION_SET_CONSIGNATION_INSTANCE => traiter_commande_set_consignation_instance(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_CONSIGNATION_INSTANCE => traiter_commande_supprimer_consignation_instance(middleware, m, gestionnaire).await,
        TRANSACTION_FILEHOST_ADD => command_filehost_add(middleware, m, gestionnaire).await,
        TRANSACTION_FILEHOST_UPDATE => command_filehost_update(middleware, m, gestionnaire).await,
        TRANSACTION_FILEHOST_DELETE => command_filehost_delete(middleware, m, gestionnaire).await,
        COMMANDE_AJOUTER_CONSIGNATION_HEBERGEE => commande_ajouter_consignation_hebergee(middleware, m, gestionnaire).await,
        COMMANDE_SET_CLEID_BACKUP_DOMAINE => commande_set_cleid_backup_domaine(middleware, m, gestionnaire).await,
        COMMANDE_FILE_VISIT => command_file_visit(middleware, m, gestionnaire).await,
        COMMANDE_CLAIM_AND_FILEHOST_VISITS_FOR_FUUIDS => commande_claim_and_filehost_visits(middleware, m).await,
        _ => Err(format!("Commande {} inconnue : {}, message dropped", DOMAIN_NAME, action))?,
    }
}

async fn traiter_commande_monitor<M>(middleware: &M, message: MessageValide, gestionnaire: &TopologyManager)
                                     -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer traiter_commande_monitor : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_cle autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Sauvegarder la transaction, marquer complete et repondre
    sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire).await
}

async fn traiter_commande_supprimer_instance<M>(middleware: &M, message: MessageValide, gestionnaire: &TopologyManager)
                                                -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer traiter_commande_supprimer_instance : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("ajouter_cle autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        //     Ok(m) => return Ok(Some(m)),
        //     Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        // }
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Sauvegarder la transaction, marquer complete et repondre
    sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire).await
}

async fn transmettre_cle_attachee<M>(middleware: &M, cle: Value) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let mut message_cle: MessageMilleGrillesOwned = serde_json::from_value(cle)?;

    let mut routage_builder = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L3Protege])
        .correlation_id(&message_cle.id)
        .partition("all");

    match message_cle.attachements.take() {
        Some(inner) => {
            if let Some(partition) = inner.get("partition") {
                if let Some(partition) = partition.as_str() {
                    // Override la partition
                    routage_builder = routage_builder.partition(partition);
                }
            }
        },
        None => ()
    }

    let routage = routage_builder.build();
    let type_message = TypeMessageOut::Commande(routage);

    let buffer_message: MessageMilleGrillesBufferDefault = message_cle.try_into()?;
    let reponse = middleware.emettre_message(type_message, buffer_message).await?;

    match reponse {
        Some(inner) => match inner {
            TypeMessage::Valide(reponse) => {
                let message_ref = reponse.message.parse()?;
                let contenu = message_ref.contenu()?;
                let reponse: ReponseCommande = contenu.deserialize()?;
                if let Some(true) = reponse.ok {
                    debug!("Cle sauvegardee ok");
                    Ok(None)
                } else {
                    error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : {:?}", reponse);
                    Ok(Some(middleware.reponse_err(3, reponse.message, reponse.err)?))
                }
            },
            _ => {
                error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Mauvais type de reponse");
                Ok(Some(middleware.reponse_err(2, None, Some("Erreur sauvegarde cle"))?))
            }
        },
        None => {
            error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Timeout sur confirmation de sauvegarde");
            Ok(Some(middleware.reponse_err(1, None, Some("Timeout"))?))
        }
    }
}

async fn traiter_commande_configurer_consignation<M>(middleware: &M, mut message: MessageValide, gestionnaire: &TopologyManager)
                                                     -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("traiter_commande_configurer_consignation : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("traiter_commande_configurer_consignation autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        //     Ok(m) => return Ok(Some(m)),
        //     Err(e) => Err(format!("Erreur preparation reponse sauvegarder_inscrire_usager : {:?}", e))?
        // }
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Valider commande
    {
        let mut message_owned = message.message.parse_to_owned()?;
        // let message_contenu = message_ref.contenu()?;
        let commande: TransactionSetFichiersPrimaire = match message_owned.deserialize() {
            Ok(inner) => inner,
            Err(e) => {
                Err(format!("traiter_commande_configurer_consignation Erreur convertir {:?}", e))?
            }
        };

        // Traiter la cle
        if let Some(mut attachements) = message_owned.attachements.take() {
            if let Some(cle) = attachements.remove("cle") {
                if let Some(reponse) = transmettre_cle_attachee(middleware, cle).await? {
                    error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : {:?}", reponse);
                    return Ok(Some(reponse));
                }
            }
        }
    }

    // Sauvegarder la transaction, marquer complete et repondre
    sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire).await
}

async fn traiter_commande_set_fichiers_primaire<M>(middleware: &M, message: MessageValide, gestionnaire: &TopologyManager)
                                                   -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("traiter_commande_set_fichiers_primaire : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("traiter_commande_set_fichiers_primaire autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        //     Ok(m) => return Ok(Some(m)),
        //     Err(e) => Err(format!("core_topologie.traiter_commande_set_fichiers_primaire Erreur preparation reponse  : {:?}", e))?
        // }
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Valider commande
    {
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        if let Err(e) = message_contenu.deserialize::<TransactionSetFichiersPrimaire>() {
            Err(format!("traiter_commande_set_fichiers_primaire Erreur convertir {:?}", e))?;
        };
    }

    // Sauvegarder la transaction, marquer complete et repondre
    sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire).await
}

async fn traiter_commande_set_consignation_instance<M>(middleware: &M, message: MessageValide, gestionnaire: &TopologyManager)
                                                       -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("traiter_commande_set_consignation_instance : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // let err = json!({"ok": false, "code": 1, "err": "Permission refusee, certificat non autorise"});
        debug!("traiter_commande_set_consignation_instance autorisation acces refuse");
        // match middleware.formatter_reponse(&err,None) {
        //     Ok(m) => return Ok(Some(m)),
        //     Err(e) => Err(format!("core_topologie.traiter_commande_set_fichiers_primaire Erreur preparation reponse  : {:?}", e))?
        // }
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Valider commande
    {
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        if let Err(e) = message_contenu.deserialize::<TransactionSetConsignationInstance>() {
            Err(format!("traiter_commande_set_consignation_instance Erreur convertir {:?}", e))?;
        };
    }

    // Sauvegarder la transaction, marquer complete et repondre
    sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire).await
}

async fn traiter_commande_supprimer_consignation_instance<M>(
    middleware: &M, message: MessageValide, gestionnaire: &TopologyManager
)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("traiter_commande_supprimer_consignation_instance : {:?}", &message.type_message);

    // Verifier autorisation
    if ! message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        debug!("traiter_commande_supprimer_consignation_instance autorisation acces refuse");
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Valider commande
    let instance_id = {
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        let contenu = match message_contenu.deserialize::<TransactionSetConsignationInstance>() {
            Ok(inner) => inner,
            Err(e) => Err(format!("traiter_commande_supprimer_consignation_instance Erreur convertir {:?}", e))?
        };
        contenu.instance_id
    };

    // Sauvegarder la transaction, marquer complete et repondre
    let reponse = sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire).await?;

    // Emettre evenement d'instance consignation supprimee
    let evenement_supprimee = json!({"instance_id": &instance_id});
    let routage = RoutageMessageAction::builder(
        DOMAIN_NAME, EVENEMENT_INSTANCE_CONSIGNATION_SUPPRIMEE, vec![Securite::L2Prive])
        .build();
    middleware.emettre_evenement(routage, &evenement_supprimee).await?;

    Ok(reponse)
}

#[derive(Deserialize)]
struct CommandeAjouterConsignationHebergee {
    url: String,
}

struct ReponseCommandeAjouterConsignationHebergee {
    ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseRelaiWeb {
    code: Option<u16>,
    verify_ok: Option<bool>,
    headers: Option<HashMap<String, String>>,
    json: Option<Value>,
    text: Option<String>,
}

async fn charger_fiche<M>(middleware: &M, url: &Url, etag: Option<&String>)
                          -> Result<Option<FichePublique>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("charger_fiche {:?}", url);

    let routage = RoutageMessageAction::builder(DOMAINE_RELAIWEB, COMMANDE_RELAIWEB_GET, vec![Securite::L1Public])
        .build();

    let hostname = match url.host_str() {
        Some(inner) => inner,
        None => Err(Error::Str("charger_fiche Url sans hostname"))?
    };
    let mut url_fiche = url.clone();
    url_fiche.set_path("fiche.json");
    let requete = json!({
        "url": url_fiche.as_str(),
        "headers": {
            "Cache-Control": "public, max-age=604800",
            "If-None-Match": etag,
        }
    });

    let reponse = {
        let reponse_http = middleware.transmettre_commande(routage, &requete).await?;
        debug!("charger_fiche Reponse http : {:?}", reponse_http);
        match reponse_http {
            Some(reponse) => match reponse {
                TypeMessage::Valide(reponse) => Ok(reponse),
                _ => Err(format!("core_topologie.charger_fiche Mauvais type de message recu en reponse"))
            },
            None => Err(format!("core_topologie.charger_fiche Aucun message recu en reponse"))
        }
    }?;

    // Mapper message avec la fiche
    let message_ref = reponse.message.parse()?;
    debug!("charger_fiche Reponse fiche :\n{}", from_utf8(&reponse.message.buffer)?);
    let message_contenu = message_ref.contenu()?;
    let reponse_fiche: ReponseRelaiWeb = message_contenu.deserialize()?;

    // Verifier code reponse HTTP
    match reponse_fiche.code {
        Some(c) => {
            if c == 304 {
                // Aucun changement sur le serveur
                // On fait un touch sur l'adresse du hostname verifie et on retourne la fiche
                let filtre = doc! {"adresse": hostname};
                let ops = doc! {"$currentDate": {CHAMP_MODIFICATION: true}};
                let collection_adresses = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;
                collection_adresses.update_one(filtre, ops.clone(), None).await?;

                let filtre = doc! {"adresses": hostname};
                let collection_fiches = middleware.get_collection_typed::<FichePublique>(NOM_COLLECTION_MILLEGRILLES)?;
                match collection_fiches.find_one_and_update(filtre, ops, None).await? {
                    Some(fiche) => {
                        return Ok(Some(fiche));
                    },
                    None => ()
                }
            } else if c != 200 {
                Err(format!("core_topologie.charger_fiche Code reponse http {}", c))?
            }
        }
        None => Err(Error::Str("core_topologie.charger_fiche Code reponse http manquant"))?
    };

    // Verifier presence fiche publique
    let mut fiche_publique_message: MessageMilleGrillesOwned = match reponse_fiche.json {
        Some(f) => match serde_json::from_value(f) {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("core_topologie.resoudre_url Fiche publique invalide : {:?}", e)))?
        },
        None => Err(Error::Str("core_topologie.resoudre_url Fiche publique manquante"))?
    };

    // Verifier la fiche
    fiche_publique_message.verifier_signature()?;

    // TODO : Valider le certificat de la fiche

    debug!("Verification headers : {:?}", reponse_fiche.headers);
    let etag = match reponse_fiche.headers.as_ref() {
        Some(e) => match e.get("ETag").cloned() {
            Some(inner) => Some(ReponseUrlEtag {url: url_fiche.clone(), etag: inner}),
            None => None
        },
        None => None
    };

    // Sauvegarder et retourner la fiche
    let fiche_publique: FichePublique = fiche_publique_message.deserialize()?;
    maj_fiche_publique(middleware, &fiche_publique, etag).await?;
    Ok(Some(fiche_publique))
}

async fn commande_ajouter_consignation_hebergee<M>(middleware: &M, message: MessageValide, gestionnaire: &TopologyManager)
                                                   -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("commande_ajouter_consignation_hebergee : {:?}", &message.type_message);

    // Verifier autorisation
    if !message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        error!("commande_ajouter_consignation_hebergee autorisation acces refuse");
        return Ok(Some(middleware.reponse_err(1, None, Some("Permission refusee, certificat non autorise"))?))
    }

    // Valider commande
    let commande = {
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        match message_contenu.deserialize::<CommandeAjouterConsignationHebergee>() {
            Ok(inner) => inner,
            Err(e) => {
                error!("commande_ajouter_consignation_hebergee Erreur convertir {:?}", e);
                return Ok(Some(middleware.reponse_err(2, None, Some("Permission refusee, certificat non autorise"))?))
            }
        }
    };

    let url_connexion = Url::parse(commande.url.as_str())?;
    let fiche_publique = match charger_fiche(middleware, &url_connexion, None).await {
        Ok(inner) => match inner {
            Some(fiche) => fiche,
            None => {
                error!("commande_ajouter_consignation_hebergee Erreur acces fiche - non trouvee");
                return Ok(Some(middleware.reponse_err(Some(3), None, Some("Erreur acces fiche - non trouvee"))?))
            }
        },
        Err(e) => {
            error!("charger_fiche Erreur chargement fiche : {:?}", e);
            return Ok(Some(middleware.reponse_err(Some(4), None, Some("Erreur acces fiche"))?))
        }
    };

    // Verifier si on a deja une configuration d'hebergement pour cette millegrille
    let idmg = fiche_publique.idmg.as_str();

    let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS)?;
    let filtre = doc!{"instance_id": idmg};
    if collection.find_one(filtre, None).await?.is_some() {
        error!("commande_ajouter_consignation_hebergee Erreur ajout consignation existante sur idmg : {}", idmg);
        return Ok(Some(middleware.reponse_err(Some(6), None, Some("Une configuration d'hebergement existe deja pour cette millegrille"))?))
    }

    let (jwt, url_verifie) = match demander_jwt_hebergement(middleware, &fiche_publique, Some(url_connexion.clone())).await {
        Ok(inner) => inner,
        Err(e) => {
            error!("charger_fiche Erreur demande JWT pour hebergement : {:?}", e);
            return Ok(Some(middleware.reponse_err(Some(5), None, Some("Erreur demande tokens"))?))
        }
    };

    // Ajouter la consignation
    let transaction = TransactionConfigurerConsignation {
        instance_id: idmg.to_owned(),
        type_store: Some("heberge".to_string()),
        url_download: None,
        url_archives: None,
        consignation_url: Some(url_verifie.to_string()),
        sync_intervalle: Some(86400),
        sync_actif: Some(true),
        supporte_archives: None,
        data_chiffre: None,
        hostname_sftp: None,
        username_sftp: None,
        port_sftp: None,
        remote_path_sftp: None,
        key_type_sftp: None,
        s3_access_key_id: None,
        s3_region: None,
        s3_endpoint: None,
        s3_bucket: None,
        type_backup: None,
        hostname_sftp_backup: None,
        port_sftp_backup: None,
        username_sftp_backup: None,
        remote_path_sftp_backup: None,
        key_type_sftp_backup: None,
        backup_intervalle_secs: None,
        backup_limit_bytes: None,
    };

    sauvegarder_traiter_transaction_serializable_v2(
        middleware, &transaction, gestionnaire,
        TOPOLOGIE_NOM_DOMAINE, TRANSACTION_CONFIGURER_CONSIGNATION).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Deserialize)]
struct RowCoreTopologieDomaines {
    domaine: String,
    instance_id: String,
    dirty: Option<bool>,
    reclame_fuuids: Option<bool>,
    cle_id_backup: Option<String>,
}

async fn commande_set_cleid_backup_domaine<M>(middleware: &M, m: MessageValide, _gestionnaire: &TopologyManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("commande_set_cleid_backup_domaine Message : {:?}", &m.type_message);
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: TransactionSetCleidBackupDomaine = message_contenu.deserialize()?;

    let now = Utc::now();
    let certificat_subject = m.certificat.subject()?;
    let instance_id = match certificat_subject.get("commonName") {
        Some(inner) => inner.as_str(),
        None => Err("Certificat sans commonName")?
    };

    let domaine = commande.domaine;

    if !m.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        return Ok(Some(middleware.reponse_err(None, Some("Certificat doit avoir la securite 3.protege"), None)?))
    }
    if !m.certificat.verifier_domaines(vec![domaine.clone()])? {
        return Ok(Some(middleware.reponse_err(None, Some("Certificat doit etre de meme domaine que le domaine demande"), None)?))
    }

    let filtre = doc!{"domaine": &domaine};
    let collection = middleware.get_collection_typed::<RowCoreTopologieDomaines>(NOM_COLLECTION_DOMAINES)?;
    let cle_id_backup = match commande.reset {
        Some(true) => None,
        _ => match commande.cle_id {
            Some(inner) => Some(inner),
            None => Err("cle_id manquant de la commande")?
        }
    };
    let ops = doc! {
        "$setOnInsert": {"instance_id": instance_id, CHAMP_CREATION: now, "dirty": true, "reclame_fuuids": false},
        "$set": { "cle_id_backup": cle_id_backup },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let options = UpdateOptions::builder().upsert(true).build();
    let result = collection.update_one(filtre, ops, options).await?;
    if result.modified_count != 1 {
        Err(format!("Erreur mise a jour de cle_id de backup du domaine {}, aucuns changements apportes a la DB", domaine))?
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn command_filehost_add<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
                                 -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("command_filehost_add Message : {:?}", &m.type_message);
    let (commande, message_id) = {
        let message_ref = m.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        let message_id = message_ref.id.to_owned();
        let transaction: HostfileAddTransaction = message_contenu.deserialize()?;
        (transaction, message_id)
    };

    let certificat = m.certificat.as_ref();
    if certificat.verifier_roles_string(vec!["filecontroler".to_string()])? && certificat.verifier_exchanges(vec![Securite::L1Public])?{
        if commande.url_internal.is_some() {
            // This is a file controler trying to automatically add a local file host.
            // Ensure that no file host exists for the instance_id of the file controler.
            let certificate = m.certificat.as_ref();
            let instance_id = certificate.get_common_name()?;
            let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTS)?;
            let filtre = doc!{"instance_id": instance_id};
            let count = collection.count_documents(filtre, None).await?;
            if count > 0 {
                return Ok(Some(middleware.reponse_err(Some(409), None, Some("Filehost for instance exists"))?))
            }
        } else {
            return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
        }
    } else if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        if let Some(url_external) = commande.url_external.as_ref() {
            // Admin adding an external file host.
            // Ensure no file host exists for this url.
            let collection = middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;
            let filtre = doc!{"url_external": url_external};
            match collection.find_one(filtre, None).await? {
                Some(inner) => {
                    // Exists, check if deleted (this would be a restore)
                    if inner.deleted {
                        info!("command_filehost_add Restoring filehost, rewriting add as update delete=false");
                        let filehost_update = FilehostRestoreTransaction {filehost_id: inner.filehost_id.clone()};
                        let result = sauvegarder_traiter_transaction_serializable_v2(
                            middleware, &filehost_update, gestionnaire, DOMAINE_TOPOLOGIE, TRANSACTION_FILEHOST_RESTORE).await?.0;

                        check_default_filehost(middleware, inner.filehost_id.as_str()).await?;

                        // Load the new filehost, emit as event
                        let filtre = doc!{"filehost_id": &inner.filehost_id};
                        let collection = middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;
                        match collection.find_one(filtre, None).await? {
                            Some(inner) => {
                                let routing = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, "filehostRestore", vec![Securite::L1Public])
                                    .build();
                                let filehost_item: RequeteFilehostItem = inner.into();
                                middleware.emettre_evenement(routing, filehost_item).await?;
                            }
                            None => {
                                warn!("command_filehost_add Transaction successful but no item in database for {}", message_id);
                            }
                        }

                        return Ok(result);
                    } else {
                        // Conflict, already exists
                        return Ok(Some(middleware.reponse_err(Some(409), None, Some("Url exists"))?))
                    }
                }
                None => {
                    // Ok, this is a new filehost
                }
            }
        } else {
            return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
        }
    } else {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
    }

    let result = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire).await?;

    // Check if we have a default filehost. If not, set this new filehost as default.
    check_default_filehost(middleware, message_id.as_str()).await?;

    // Load the new filehost, emit as event
    let filtre = doc!{"filehost_id": &message_id};
    let collection = middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;
    match collection.find_one(filtre, None).await? {
        Some(inner) => {
            let routing = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, "filehostAdd", vec![Securite::L1Public])
                .build();
            let filehost_item: RequeteFilehostItem = inner.into();
            middleware.emettre_evenement(routing, filehost_item).await?;
        }
        None => {
            warn!("command_filehost_add Transaction successful but no item in database for {}", message_id);
        }
    }

    Ok(result)
}

async fn check_default_filehost<M>(middleware: &M, filehost_id: &str) -> Result<(), Error>
    where M: MongoDao
{
    let filtre = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT};
    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let count = collection.count_documents(filtre, None).await?;
    if count == 0 {
        info!("Initialize default filehost to {}", filehost_id);
        // Initialize in a volatile way. User can override manually later.
        let row = FilehostingCongurationRow {name: FIELD_CONFIGURATION_FILEHOST_DEFAULT.into(), value: filehost_id.to_string()};
        let row_bson = convertir_to_bson(row)?;
        collection.insert_one(row_bson, None).await?;
    }
    Ok(())
}

async fn command_filehost_update<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
                                    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("command_filehost_update Message : {:?}", &m.type_message);
    let commande: FilehostUpdateTransaction = {
        let message_ref = m.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        message_contenu.deserialize()?
    };

    let certificat = m.certificat.as_ref();
    if certificat.verifier_roles_string(vec!["filecontroler".to_string()])? && certificat.verifier_exchanges(vec![Securite::L1Public])?{
        // File controler
    } else if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Admin
    } else {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
    }

    let filehost_id = commande.filehost_id;
    // Check that filehost exists
    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTS)?;
    let filtre = doc!{"filehost_id": &filehost_id};
    let count = collection.count_documents(filtre, None).await?;
    if count == 0 {
        return Ok(Some(middleware.reponse_err(Some(404), None, Some("Filehost does not exist"))?))
    }

    let result = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire).await?;

    // Load the new filehost, emit as event
    let filtre = doc!{"filehost_id": &filehost_id};
    let collection = middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;
    match collection.find_one(filtre, None).await? {
        Some(inner) => {
            let routing = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, "filehostUpdate", vec![Securite::L1Public])
                .build();
            let filehost_item: RequeteFilehostItem = inner.into();
            middleware.emettre_evenement(routing, filehost_item).await?;
        }
        None => {
            warn!("command_filehost_add Transaction successful but no item in database for {}", filehost_id);
        }
    }

    Ok(result)
}

#[derive(Serialize)]
struct EventFilehostDeleted { filehost_id: String }

async fn command_filehost_delete<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
                                    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("command_filehost_remove Message : {:?}", &m.type_message);
    let commande: FilehostDeleteTransaction = {
        let message_ref = m.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        message_contenu.deserialize()?
    };

    let certificat = m.certificat.as_ref();
    if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok, admin removing file host.
    } else {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
    }

    let filehost_id = commande.filehost_id;
    // Check that filehost exists and is not deleted (flag).
    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTS)?;
    let filtre = doc!{"filehost_id": &filehost_id, "deleted": false};
    let count = collection.count_documents(filtre, None).await?;
    if count == 0 {
        return Ok(Some(middleware.reponse_err(Some(404), None, Some("Filehost does not exist or is already deleted"))?))
    }

    let result = sauvegarder_traiter_transaction_v2(middleware, m, gestionnaire).await?;

    let event = EventFilehostDeleted { filehost_id };
    let routing = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, "filehostDelete", vec![Securite::L1Public])
        .build();
    middleware.emettre_evenement(routing, event).await?;

    Ok(result)
}

#[derive(Deserialize)]
struct CommandFileVisit {
    filehost_id: String,
    #[serde(with="epochseconds")]
    visit_time: DateTime<Utc>,
    fuuids: Vec<String>,
}

async fn command_file_visit<M>(middleware: &M, m: MessageValide, gestionnaire: &TopologyManager)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("command_file_visit Message : {:?}", &m.type_message);

    if ! m.certificat.verifier_roles_string(vec!["filecontroler".to_string()])? {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
    }

    let commande: CommandFileVisit = {
        let message_ref = m.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        message_contenu.deserialize()?
    };

    // {
    //     let options = UpdateOptions::builder().upsert(true).build();
    //     for fuuid in &commande.fuuids {
    //         let filtre = doc! {"fuuid": fuuid, "filehost_id": &commande.filehost_id};
    //         let ops = doc! {
    //             "$set": {"visit_time": &commande.visit_time},
    //         };
    //         let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTING_VISITS)?;
    //         collection.update_one(filtre, ops, options.clone()).await?;
    //     }
    // }

    let collection = middleware.get_collection(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
    let options = UpdateOptions::builder().upsert(true).build();
    {
        let filehost_id = commande.filehost_id.as_str();
        for fuuid in &commande.fuuids {
            let filtre = doc! {"fuuid": fuuid};
            let ops = doc! {
                "$set": {
                    format!("filehost.{}", filehost_id): &commande.visit_time,
                },
            };
            debug!("command_file_visit Update filtre: {:?}\nOps: {:?}", filtre, ops);
            collection.update_one(filtre, ops, options.clone()).await?;
        }
    }

    Ok(Some(middleware.reponse_ok(None, None)?))
}

#[derive(Deserialize)]
struct RequeteGetVisitesFuuids {
    fuuids: Vec<String>,
}

// #[derive(Serialize, Deserialize)]
// struct RowFuuidVisit {
//     fuuid: String,
//     filehost_id: String,
//     #[serde(with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
//     visit_time: DateTime<Utc>,
// }

#[derive(Serialize, Deserialize)]
struct RowFilehostFuuid {
    fuuid: String,
    #[serde(default, with="opt_chrono_datetime_as_bson_datetime")]
    last_claim_date: Option<DateTime<Utc>>,
    #[serde(default, with="map_opt_chrono_datetime_as_bson_datetime")]
    filehost: Option<HashMap<String, Option<DateTime<Utc>>>>,
}

#[derive(Serialize)]
struct FuuidVisitResponseItem {
    fuuid: String,
    visits: HashMap<String, i64>
}

impl From<RowFilehostFuuid> for FuuidVisitResponseItem {
    fn from(value: RowFilehostFuuid) -> Self {
        let mut visits = HashMap::new();
        if let Some(filehost) = value.filehost {
            for (k, v) in filehost {
                if let Some(date) = v {
                    visits.insert(k, date.timestamp());
                }
            }
        }

        Self {
            fuuid: value.fuuid,
            visits
        }
    }
}

#[derive(Deserialize)]
struct RowFuuid {
    fuuid: String,
}

#[derive(Serialize)]
struct RequeteGetVisitesFuuidsResponse {
    ok: bool,
    visits: Vec<FuuidVisitResponseItem>,
    unknown: Vec<String>
}

async fn commande_claim_and_filehost_visits<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    debug!("commande_claim_and_filehost_visits Message : {:?}", &m.type_message);

    if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
    }

    let message_ref = m.message.parse()?;
    let estampille_date = &message_ref.estampille;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteGetVisitesFuuids = message_contenu.deserialize()?;

    let mut fuuids_set = HashSet::new();
    fuuids_set.extend(requete.fuuids.iter());
    // let mut response_fuuids: HashMap<String, RowFuuidVisitResponse> = HashMap::new();
    let mut response_fuuids: Vec<FuuidVisitResponseItem> = Vec::new();

    let filtre = doc! {"fuuid": {"$in": &requete.fuuids}};
    let collection = middleware.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
    let mut curseur = collection.find(filtre, None).await?;
    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        fuuids_set.remove(&row.fuuid);
        response_fuuids.push(row.into());
    }

    // Conserver les reclamations.
    // let collection_claims = middleware.get_collection_typed::<RowFuuid>(NOM_COLLECTION_FILEHOSTING_CLAIMS)?;
    let collection_claims = middleware.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
    let filtre_reclamations = doc!{ "fuuid": {"$in": &requete.fuuids} };
    let ops_reclamations = doc! {"$currentDate": {FIELD_LAST_CLAIM_DATE: true}};
    let update_result = collection_claims.update_many(filtre_reclamations.clone(), ops_reclamations, None).await?;
    if update_result.matched_count as usize != requete.fuuids.len() {
        debug!("Mismatch updates {} et claims {}. Inserer nouveaux claims.", requete.fuuids.len(), update_result.matched_count);
        let mut fuuids_requis = HashSet::new();
        for f in &requete.fuuids {
            fuuids_requis.insert(f);
        }
        let options = FindOptions::builder()
            .projection(doc!{"fuuid": 1})
            .build();
        let mut curseur = collection_claims.find(filtre_reclamations, options).await?;
        while curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            fuuids_requis.remove(&row.fuuid);
        }

        let mut rows = Vec::new();
        for f in fuuids_requis {
            debug!("Ajouter nouveau fuuid reclame {}", f);
            let row = RowFilehostFuuid { fuuid: f.to_owned(), last_claim_date: Some(estampille_date.to_owned()), filehost: Some(HashMap::new()) };
            rows.push(row);
        }
        let collection_insert_claims =
            middleware.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
        collection_insert_claims.insert_many(rows, None).await?;
    }

    let reponse = RequeteGetVisitesFuuidsResponse {
        ok: true,
        visits: response_fuuids,
        unknown: Vec::from_iter(fuuids_set.into_iter().map(|f|f.to_string()))
    };

    Ok(Some(middleware.build_reponse(reponse)?.0))
}
