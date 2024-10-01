use log::{debug, error, warn};

use crate::topology_constants::*;
use crate::topology_events::produire_fiche_publique;
use crate::topology_structs::{FichePublique, InformationMonitor};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono::{Datelike, Timelike, Utc};
use millegrilles_common_rust::constantes::{CHAMP_CREATION, CHAMP_MODIFICATION, TRANSACTION_CHAMP_IDMG};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::EmetteurNotificationsTrait;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOptions, UpdateOptions};
use millegrilles_common_rust::notifications::NotificationMessageInterne;
use millegrilles_common_rust::tokio_stream::StreamExt;
use serde::Deserialize;

pub async fn traiter_cedule<M>(middleware: &M, trigger: &MessageCedule) -> Result<(), millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler + EmetteurNotificationsTrait
{
    let date_epoch = trigger.get_date();
    debug!("Traiter cedule {}\n{:?}", DOMAIN_NAME, date_epoch);

    if middleware.get_mode_regeneration() == true {
        debug!("traiter_cedule Mode regeneration, skip entretien");
        return Ok(());
    }

    let minutes = date_epoch.minute();

    if minutes % 5 == 1 {
        debug!("Produire fiche publique");
        if let Err(e) = produire_fiche_publique(middleware).await {
            error!("core_topoologie.entretien Erreur production fiche publique initiale : {:?}", e);
        }
    }

    // Mettre a jour information locale a toutes les 5 minutes
    if minutes % 5 == 2 {
        if let Err(e) = produire_information_locale(middleware).await {
            error!("core_topoologie.entretien Erreur production information locale : {:?}", e);
        }
    }

    if minutes == 4 {
        if let Err(e) = rafraichir_fiches_millegrilles(middleware).await {
            error!("core_topoologie.entretien Erreur rafraichir fiches millegrilles : {:?}", e);
        }
    }

    if let Err(e) = verifier_instances_horsligne(middleware).await {
        warn!("Erreur verification etat instances hors ligne {:?}", e);
    }

    Ok(())
}

async fn produire_information_locale<M>(middleware: &M)
                                        -> Result<(), millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("produire_information_locale");
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let idmg_local = enveloppe_privee.enveloppe_pub.idmg()?;

    let adresses = {
        let mut adresses = Vec::new();

        let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;
        let filtre = doc! {};
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(inst) = curseur.next().await {
            let doc_instance = inst?;
            let info_instance: InformationMonitor = convertir_bson_deserializable(doc_instance)?;
            debug!("Information instance : {:?}", info_instance);
            if let Some(d) = &info_instance.domaines {
                adresses.extend(d.iter().map(|d| d.to_owned()));
            }
        }
        adresses
    };

    {   // Collection millegrilles
        let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
        let filtre = doc! {TRANSACTION_CHAMP_IDMG: &idmg_local};
        let ops = doc! {
            "$setOnInsert": {
                TRANSACTION_CHAMP_IDMG: &idmg_local,
                CHAMP_CREATION: Utc::now(),
            },
            "$set": {
                CHAMP_ADRESSES: &adresses,
                "local": true,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let options = UpdateOptions::builder()
            .upsert(true)
            .build();
        collection.update_one(filtre, ops, Some(options)).await?;
    }

    {   // Collection millegrillesAdresses pour resolve par adresse (unique)
        let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;
        for adresse in &adresses {
            let filtre = doc! {CHAMP_ADRESSE: adresse};
            let ops = doc! {
                "$setOnInsert": {
                    CHAMP_ADRESSE: &adresse,
                    CHAMP_CREATION: Utc::now(),
                },
                "$set": {
                    TRANSACTION_CHAMP_IDMG: &idmg_local,
                },
                "$currentDate": {CHAMP_MODIFICATION: true}
            };
            let options = UpdateOptions::builder()
                .upsert(true)
                .build();
            collection.update_one(filtre, ops, Some(options)).await?;
        }
    }

    Ok(())
}

async fn rafraichir_fiches_millegrilles<M>(middleware: &M)
    -> Result<(), millegrilles_common_rust::error::Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("rafraichir_fiches_millegrilles Debut");

    let filtre = doc!{
        "$or": [
            {"local": false},
            {"local": {"$exists": false}}
        ]
    };
    let collection = middleware.get_collection_typed::<FichePublique>(NOM_COLLECTION_MILLEGRILLES)?;
    let mut curseur = collection.find(filtre, None).await?;

    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        todo!("fix rafraichir fiche")
    }

    debug!("rafraichir_fiches_millegrilles Fin");
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct RowInstanceActivite {
    instance_id: String,
    hostname: Option<String>,
    date_presence: Option<i64>,
    date_hors_ligne: Option<i64>,
}

async fn verifier_instances_horsligne<M>(middleware: &M)
    -> Result<(), millegrilles_common_rust::error::Error>
    where M: MongoDao + EmetteurNotificationsTrait
{
    debug!("verifier_instances_horsligne Debut verification");

    let now = Utc::now().timestamp();
    let expiration = now - 400;  // Date expiration epoch (secondes)

    let collection = middleware.get_collection(NOM_COLLECTION_NOEUDS)?;

    let projection = doc!{"instance_id": 1, "hostname": 1, "date_presence": 1, "date_hors_ligne": 1};

    let nouveau_hors_ligne = {
        let mut nouveau_hors_ligne = Vec::new();
        let filtre_horsligne = doc! {
            "date_presence": {"$lt": &expiration},
            "date_hors_ligne": {"$exists": false}
        };
        let options = FindOptions::builder().projection(projection.clone()).build();
        let mut curseur = collection.find(filtre_horsligne, options).await?;

        while let Some(d) = curseur.next().await {
            let row: RowInstanceActivite = convertir_bson_deserializable(d?)?;
            debug!("Instance hors ligne : {:?}", row);
            nouveau_hors_ligne.push(row);
        }

        nouveau_hors_ligne
    };

    let nouveau_en_ligne = {
        let mut nouveau_en_ligne = Vec::new();
        let filtre_en_ligne = doc! {
            "date_presence": {"$gte": &expiration},
            "date_hors_ligne": {"$exists": true}
        };
        let options = FindOptions::builder().projection(projection.clone()).build();
        let mut curseur = collection.find(filtre_en_ligne, options).await?;

        while let Some(d) = curseur.next().await {
            let row: RowInstanceActivite = convertir_bson_deserializable(d?)?;
            debug!("Instance en ligne : {:?}", row);
            nouveau_en_ligne.push(row);
        }

        nouveau_en_ligne
    };

    if nouveau_hors_ligne.len() == 0 && nouveau_en_ligne.len() == 0 {
        debug!("Aucun changement hors ligne/en ligne pour instances");
    } else {
        let mut message_lignes = Vec::new();
        if nouveau_hors_ligne.len() > 0 {
            message_lignes.push("<p>Instances hors ligne</p>".to_string());
            for instance in &nouveau_hors_ligne {
                if let Some(h) = instance.hostname.as_ref() {
                    message_lignes.push(format!("<p>{:?}</p>", h))
                }
            }
        }
        message_lignes.push("<p></p>".to_string());
        if nouveau_en_ligne.len() > 0 {
            message_lignes.push("<p>Instances en ligne</p>".to_string());
            for instance in &nouveau_en_ligne {
                if let Some(h) = instance.hostname.as_ref() {
                    message_lignes.push(format!("<p>{}</p>", h))
                }
            }
        }

        let message_str = message_lignes.join("\n");
        debug!("verifier_instances_horsligne Message notification {}", message_str);

        let sujet = if nouveau_hors_ligne.len() == 1 {
            let row = &nouveau_hors_ligne.get(0).expect("get(0)");
            match &row.hostname {
                Some(h) => format!("{:?} est hors ligne", h),
                None => format!("{:?} est hors ligne", row.instance_id)
            }
        } else if nouveau_hors_ligne.len() > 1 {
            format!("{} instances hors ligne", nouveau_hors_ligne.len())
        } else {
            format!("{} instances de retour en ligne", nouveau_en_ligne.len())
        };

        let notification = NotificationMessageInterne {
            from: "CoreTopologie".to_string(),
            subject: Some(sujet),
            content: message_str,
            version: 1,
            format: "html".to_string(),
        };

        // Marquer les instances
        if nouveau_hors_ligne.len() > 0 {
            let instances_id: Vec<String> = nouveau_hors_ligne.iter().map(|r| r.instance_id.clone()).collect();
            let filtre = doc!{"instance_id": {"$in": instances_id}};
            let ops = doc!{"$set": {"date_hors_ligne": now}, "$currentDate": {CHAMP_MODIFICATION: true}};
            collection.update_many(filtre, ops, None).await?;
        }
        if nouveau_en_ligne.len() > 0 {
            let instances_id: Vec<String> = nouveau_en_ligne.iter().map(|r| r.instance_id.clone()).collect();
            let filtre = doc!{"instance_id": {"$in": instances_id}};
            let ops = doc!{"$unset": {"date_hors_ligne": 1}, "$currentDate": {CHAMP_MODIFICATION: true}};
            collection.update_many(filtre, ops, None).await?;
        }

        middleware.emettre_notification_proprietaire(
            notification,
            "warn",
            Some(now + 7 * 86400),  // Expiration epoch
            None
        ).await?;
    }

    Ok(())
}
