use std::collections::HashMap;
use std::str::from_utf8;
use std::time::Duration;
use log::{debug, error, info, warn};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::constantes::{Securite, CHAMP_CREATION, CHAMP_MODIFICATION, COMMANDE_RELAIWEB_GET, DOMAINE_RELAIWEB};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{millegrilles_cryptographie, serde_json};
use millegrilles_common_rust::jwt_simple::prelude::{Deserialize, Serialize};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::reqwest::Url;
use crate::topology_constants::*;
use crate::topology_requests::InstanceWebappsRow;
use crate::topology_structs::{ApplicationPublique, ApplicationsV2, FichePublique, InformationApplicationInstance, InformationInstance, InformationMonitor, JwtHebergement, ReponseRelaiWeb, ReponseUrlEtag, RequeteRelaiWeb, ServerInstanceStatus};

pub async fn maj_fiche_publique<M>(middleware: &M, fiche: &FichePublique, etag: Option<ReponseUrlEtag>) -> Result<(), Error>
where M: MongoDao
{
    let idmg_tiers = fiche.idmg.as_str();

    let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
    let filtre = doc! {"idmg": &idmg_tiers};
    let set_json = json!({
        "applicationsV2": fiche.applications_v2,
        "chiffrage": fiche.chiffrage,
        "ca": fiche.ca,
        "instances": fiche.instances,
    });
    let set_bson = convertir_to_bson(set_json)?;
    let ops = doc! {
        "$set": set_bson,
        "$setOnInsert": {
            "idmg": &idmg_tiers,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let options = UpdateOptions::builder()
        .upsert(true)
        .build();
    let resultat_update = collection.update_one(filtre, ops, Some(options)).await?;
    if resultat_update.modified_count != 1 && resultat_update.upserted_id.is_none() {
        error!("maj_fiche_publique Erreur, fiche publique idmg {} n'a pas ete sauvegardee", idmg_tiers);
    }

    let domaine_etag = match etag.as_ref() {
        Some(inner) => inner.url.host_str(),
        None => None
    };

    let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;
    for (instance_id, instance) in &fiche.instances {
        if let Some(domaines) = instance.domaines.as_ref() {
            for domaine in domaines {

                let filtre = doc! { "adresse": domaine };

                let mut set_ops = doc!{"idmg": &idmg_tiers};
                match domaine_etag {
                    Some(inner) => match etag.as_ref() {
                        Some(inner) => {
                            set_ops.insert("etag", inner.etag.as_str());
                        },
                        None => ()
                    },
                    None => ()
                }

                let ops = doc! {
                    "$set": set_ops,
                    "$setOnInsert": {
                        // "adresse": domaine,
                        CHAMP_CREATION: Utc::now(),
                    },
                    "$currentDate": {CHAMP_MODIFICATION: true},
                };
                let options = UpdateOptions::builder().upsert(true).build();
                let resultat_update = collection.update_one(filtre, ops, Some(options)).await?;
                if resultat_update.modified_count != 1 && resultat_update.upserted_id.is_none() {
                    error!("resoudre_url Erreur, adresse {} pour idmg {} n'a pas ete sauvegardee", domaine, idmg_tiers);
                }
            }
        }
    }

    Ok(())
}

pub async fn demander_jwt_hebergement<M>(middleware: &M, fiche: &FichePublique, url: Option<Url>)
                                     -> Result<(JwtHebergement, Url), Error>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let idmg = fiche.idmg.as_str();
    let cert_ca_pem = match fiche.ca.as_ref() {
        Some(inner) => inner.as_str(),
        None => Err(Error::Str("demander_jwt_hebergement Fiche sans CA"))?
    };

    // Mapper les instances avec hebergement_python
    let mut liste_url_hebergement = Vec::new();
    for (nom, application) in &fiche.applications_v2 {
        if nom != "hebergement_python" { continue }  // On est juste interesse par hebergement
        for (instance_id, instance) in &application.instances {
            let pathname = instance.pathname.as_str();
            if let Some(instance_info) = fiche.instances.get(instance_id.as_str()) {
                let port_https = instance_info.ports.get("https").unwrap_or_else(|| &443);
                if let Some(domaines) = instance_info.domaines.as_ref() {
                    for domaine in domaines {
                        let url_domaine = Url::parse(format!("https://{}:{}{}", domaine, port_https, pathname).as_str())?;
                        liste_url_hebergement.push(url_domaine);
                    }
                }
            }
        }
    }
    debug!("demander_jwt_hebergement List url hebergement : {:?}", liste_url_hebergement);

    if let Some(url) = url {
        // Verifier que le URL existe encore dans la fiche
        if let Some(hostname) = url.host_str() {
            // TODO
        }
    }

    let mut headers = HashMap::new();
    headers.insert("Cache-Control".to_string(), "no-store".to_string());
    let routage = RoutageMessageAction::builder(DOMAINE_RELAIWEB, COMMANDE_RELAIWEB_GET, vec![Securite::L1Public])
        .build();
    let contenu_message = json!({"roles": ["fichiers"]});
    let message_requete = middleware.build_message_action(
        millegrilles_cryptographie::messages_structs::MessageKind::Requete, routage.clone(), &contenu_message)?.0;
    let mut message_requete_ref = message_requete.parse_to_owned()?;
    let enveloppe_signature = middleware.get_enveloppe_signature();
    message_requete_ref.millegrille = Some(enveloppe_signature.ca_pem.clone());
    let message_requete_value = serde_json::to_value(message_requete_ref)?;

    let mut reponse_jwt: Option<JwtHebergement> = None;
    let mut url_verifie: Option<Url> = None;
    for url_hebergement in liste_url_hebergement {
        let mut url_jwt = url_hebergement.clone();
        url_jwt.set_path(format!("{}/jwt", url_hebergement.path()).as_str());
        let requete_web = RequeteRelaiWeb {
            url: url_jwt.to_string(),
            headers: headers.clone(),
            json: Some(message_requete_value.clone()),
        };
        let reponse = {
            let reponse_http = middleware.transmettre_commande(routage.clone(), &requete_web).await?;
            match reponse_http {
                Some(reponse) => match reponse {
                    TypeMessage::Valide(reponse) => Ok(reponse),
                    _ => Err(format!("core_topologie.demander_jwt_hebergement Mauvais type de message recu en reponse"))
                },
                None => Err(format!("core_topologie.demander_jwt_hebergement Aucun message recu en reponse"))
            }
        }?;
        debug!("demander_jwt_hebergement Reponse http :\n{}", from_utf8(&reponse.message.buffer)?);

        // Mapper message avec la fiche
        let message_ref = reponse.message.parse()?;
        debug!("demander_jwt_hebergement Reponse fiche :\n{}", from_utf8(&reponse.message.buffer)?);
        let message_contenu = message_ref.contenu()?;
        let reponse: ReponseRelaiWeb = message_contenu.deserialize()?;

        let mut message_owned = match reponse.code {
            Some(c) => {
                if c == 200 {
                    if let Some(value) = reponse.json {
                        match serde_json::from_value::<MessageMilleGrillesOwned>(value) {
                            Ok(inner) => inner,
                            Err(e) => {
                                error!("demander_jwt_hebergement Erreur deserialize reponse, ** SKIP **");
                                continue
                            }
                        }
                    } else {
                        continue
                    }
                } else {
                    continue
                }
            }
            None => Err(Error::Str("core_topologie.demander_jwt_hebergement Code reponse http manquant"))?
        };

        // Verifier le message recu
        if let Err(e) = message_owned.verifier_signature() {
            error!("demander_jwt_hebergement Erreur verification signature message JWT, **SKIP**");
            continue
        }

        // TODO Verifier certificat du message recu
        let enveloppe_ca = middleware.charger_enveloppe(&vec![cert_ca_pem.to_string()], None, None).await?;
        let certificat_pem = match message_owned.certificat.as_ref() {
            Some(inner) => inner,
            None => Err(Error::Str("core_topologie.demander_jwt_hebergement Certificat manquant de la reponse"))?
        };
        let enveloppe_certificat = middleware.charger_enveloppe(certificat_pem, None, Some(cert_ca_pem)).await?;
        if ! enveloppe_certificat.verifier_domaines(vec!["Hebergement".to_string()])? {
            Err(Error::Str("core_topologie.demander_jwt_hebergement Certificat de la reponse JWT n'est pas domaine Hebergement"))?
        }
        if ! enveloppe_certificat.verifier_exchanges(vec![Securite::L4Secure])? {
            Err(Error::Str("core_topologie.demander_jwt_hebergement Certificat de la reponse JWT n'est pas 4.secure"))?
        }
        // Valider le certificat avec le CA qui provient de la fiche
        if ! middleware.valider_chaine(enveloppe_certificat.as_ref(), Some(enveloppe_ca.as_ref()), true)? {
            Err(Error::Str("core_topologie.demander_jwt_hebergement Certificat reponse invalide"))?
        }

        // Dechiffrer le message
        let message_buffer: MessageMilleGrillesBufferDefault = message_owned.try_into()?;
        let message_ref = message_buffer.parse()?;

        // Conserver le token et URL verifie
        reponse_jwt = Some(message_ref.dechiffrer(enveloppe_signature.as_ref())?);
        url_verifie = Some(url_hebergement);

        break
    }

    let reponse_jwt = match reponse_jwt {
        Some(inner) => inner,
        None => Err(Error::Str("core_topologie.charger_fiche Aucun token JWT recu"))?
    };
    let url_verifie = match url_verifie {
        Some(inner) => inner,
        None => Err(Error::Str("core_topologie.charger_fiche Aucun URL verifie pour hebergement"))?
    };

    debug!("Reponse JWT url : {}\nRW:{}\nRO:{}", url_verifie.to_string(), reponse_jwt.jwt_readwrite, reponse_jwt.jwt_readonly);

    // TODO Verifier tokens JWT, recuperer expirations
    let expiration = Utc::now() + Duration::new(1800, 0);

    // TODO Conserver token dans la base de donnees
    let collection = middleware.get_collection(NOM_COLLECTION_TOKENS)?;
    let options = UpdateOptions::builder().upsert(true).build();

    let filtre = doc!{"idmg": idmg, "role": "hebergement_readonly"};
    let ops = doc!{
        "$set": {
            "token": &reponse_jwt.jwt_readonly,
            "expiration": expiration,
        },
        "$setOnInsert": {CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    collection.update_one(filtre, ops, options.clone()).await?;

    let filtre = doc!{"idmg": idmg, "role": "hebergement_readwrite"};
    let ops = doc!{
        "$set": {
            "token": &reponse_jwt.jwt_readwrite,
            "expiration": expiration,
        },
        "$setOnInsert": {CHAMP_CREATION: Utc::now()},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    collection.update_one(filtre, ops, options.clone()).await?;

    Ok((reponse_jwt, url_verifie))
}

// pub async fn generer_contenu_fiche_publique<M>(middleware: &M) -> Result<FichePublique, Error>
// where M: MongoDao + ValidateurX509 + CleChiffrageHandler
// {
//     let collection = middleware.get_collection_typed::<InformationMonitor>(NOM_COLLECTION_NOEUDS)?;
//
//     let filtre = doc! {};
//     let mut curseur = collection.find(filtre, None).await?;
//
//     // Extraire chaines pem de certificats de chiffrage
//     let chiffrage_enveloppes = middleware.get_publickeys_chiffrage();
//     let mut chiffrage = Vec::new();
//     for cert in chiffrage_enveloppes {
//         let chaine_pem = cert.chaine_pem()?;
//         chiffrage.push(chaine_pem)
//     }
//
//     // let mut adresses = Vec::new();
//     let mut instances: HashMap<String, InformationInstance> = HashMap::new();
//     let mut applications: HashMap<String, Vec<ApplicationPublique>> = HashMap::new();
//     let mut applications_v2: HashMap<String, ApplicationsV2> = HashMap::new();
//
//     let map_ports = {
//         let mut map_ports: HashMap<String, u16> = HashMap::new();
//         map_ports.insert("http".to_string(), 80);
//         map_ports.insert("https".to_string(), 443);
//         map_ports.insert("wss".to_string(), 443);
//         map_ports
//     };
//
//     while curseur.advance().await? {
//         let info_instance: InformationMonitor = curseur.deserialize_current()?;
//         debug!("generer_contenu_fiche_publique Information instance : {:?}", info_instance);
//
//         let securite_instance = match info_instance.securite.as_ref() {
//             Some(inner) => inner.as_str(),
//             None => {
//                 info!("generer_contenu_fiche_publique Instance {} sans niveau de securite, on skip", info_instance.instance_id);
//                 continue;
//             }
//         };
//
//         let securite = Securite::try_from(securite_instance)?;
//         match securite {
//             Securite::L4Secure => {
//                 info!("generer_contenu_fiche_publique Instance {} 4.secure, skip pour fiche publique", securite_instance);
//                 continue;
//             },
//             _ => ()
//         }
//
//         let domaines = match info_instance.domaines {
//             Some(inner) => {
//                 if inner.len() == 0 {
//                     info!("generer_contenu_fiche_publique Instance {} n'as aucuns domaines, skip pour fiche publique (1)", info_instance.instance_id);
//                     continue;
//                 }
//                 inner
//             },
//             None => {
//                 info!("generer_contenu_fiche_publique Instance {} n'as aucuns domaines, skip pour fiche publique (2)", info_instance.instance_id);
//                 continue;
//             }
//         };
//
//         let presence_expiree = Utc::now() - Duration::from_secs(3600);
//         match info_instance.date_presence {
//             Some(inner) => {
//                 if inner < presence_expiree {
//                     info!("generer_contenu_fiche_publique Instance {} expiree, skip", info_instance.instance_id);
//                     continue;
//                 }
//             },
//             None => {
//                 info!("generer_contenu_fiche_publique Instance {} sans date de presence, skip", info_instance.instance_id);
//                 continue;
//             }
//         }
//
//         // Preparer partie de la fiche publique d'instance
//         let information_instance = InformationInstance {
//             ports: map_ports.clone(),
//             onion: None,
//             securite: securite_instance.to_owned(),
//             domaines: Some(domaines.clone())
//         };
//         instances.insert(info_instance.instance_id.clone(), information_instance);
//
//         // Conserver la liste des applications/versions par nom d'application
//         let mut app_versions = HashMap::new();
//         if let Some(apps_config) = info_instance.applications_configurees {
//             for app_config in apps_config {
//                 app_versions.insert(app_config.nom.clone(), app_config);
//             }
//         }
//
//         // Generer la liste des applications avec leur url
//         if let Some(apps) = info_instance.applications {
//             for app in apps {
//                 let securite = match &app.securite {
//                     Some(s) => {
//                         let securite = match Securite::try_from(s.as_str()) {
//                             Ok(inner) => inner,
//                             Err(e) => {
//                                 warn!("generer_contenu_fiche_publique Securite app {} incorrecte : {:?}, skip", app.application, e);
//                                 continue;
//                             }
//                         };
//                         match securite {
//                             Securite::L1Public | Securite::L2Prive => securite,
//                             _ => {
//                                 debug!("generer_contenu_fiche_publique Securite app {} n'est pas 1 ou 2, skip", app.application);
//                                 continue;
//                             }
//                         }
//                     }
//                     None => continue  // On assume securite protege ou secure, skip
//                 };
//
//                 // V2
//                 let mut application_v2 = match applications_v2.get_mut(&app.application) {
//                     Some(inner) => inner,
//                     None => {
//                         let label = match app.name_property.clone() {
//                             Some(inner) => {
//                                 if Some(false) != app.supporte_usagers {
//                                     let mut label = HashMap::new();
//                                     label.insert("fr".to_string(), inner);
//                                     Some(label)
//                                 } else {
//                                     None
//                                 }
//                             },
//                             None => None
//                         };
//                         let app_v2 = ApplicationsV2 {
//                             instances: HashMap::new(),
//                             name: label,
//                             securite: securite.get_str().to_owned(),
//                             supporte_usager: None,
//                         };
//
//                         applications_v2.insert(app.application.clone(), app_v2);
//
//                         // Recuperer pointeur mut
//                         applications_v2.get_mut(&app.application).expect("app_v2")
//                     }
//                 };
//
//                 let pathname = {
//                     let pathname = match app.url.as_ref() {
//                         Some(inner) => match Url::parse(inner.as_str()) {
//                             Ok(url) => Some(url.path().to_owned()),
//                             Err(e) => {
//                                 debug!("Erreur parse URL {:}", e);
//                                 None
//                             }
//                         },
//                         None => None
//                     };
//
//                     match pathname {
//                         Some(inner) => inner,
//                         None => {
//                             // Utiliser pathname par defaut
//                             format!("/{}", &app.application)
//                         }
//                     }
//                 };
//
//                 let mut appv2_info = InformationApplicationInstance {
//                     // pathname: format!("/{}", &app.application),
//                     pathname,
//                     port: None,
//                     version: "".to_string()
//                 };
//
//                 // V1
//                 let mut app_publique: ApplicationPublique = app.clone().try_into()?;
//                 let nom_app = app_publique.application.as_str();
//                 if let Some(v) = app_versions.get(nom_app) {
//                     app_publique.version = v.version.to_owned();
//                     if let Some(version) = v.version.as_ref() {
//                         appv2_info.version = version.to_owned();
//                     }
//                 }
//
//                 // Recuperer pointer mut pour vec applications. Creer si l'application n'existe pas deja.
//                 let apps_mut = match applications.get_mut(nom_app) {
//                     Some(a) => a,
//                     None => {
//                         applications.insert(nom_app.to_owned(), Vec::new());
//                         applications.get_mut(nom_app).expect("apps_mut")
//                     }
//                 };
//
//                 apps_mut.push(app_publique);
//
//                 if let Some(hostname_onion) = info_instance.onion.as_ref() {
//                     let mut app_onion: ApplicationPublique = app.try_into()?;
//                     let nom_app = app_onion.application.as_str();
//                     app_onion.nature = ADRESSE_NATURE_ONION.into();
//                     app_onion.preference = ADRESSE_PREFERENCE_SECONDAIRE;
//
//                     // Remplacer hostname par adresse .onion
//                     let mut url_app = Url::parse(app_onion.url.as_str())?;
//                     url_app.set_host(Some(hostname_onion))?;
//                     app_onion.url = url_app.as_str().into();
//
//                     if let Some(v) = app_versions.get(nom_app) {
//                         app_onion.version = v.version.to_owned();
//                     }
//
//                     apps_mut.push(app_onion);
//                 }
//
//                 application_v2.instances.insert(info_instance.instance_id.clone(), appv2_info);
//             }
//         }
//     }
//
//     Ok(FichePublique {
//         applications: None,   //Some(applications),
//         applications_v2,
//         chiffrage: Some(chiffrage),
//         ca: Some(middleware.ca_pem().into()),
//         idmg: middleware.idmg().into(),
//         instances,
//     })
// }

#[derive(Deserialize)]
struct InstanceConfiguredAppRow {
    instance_id: String,
    app_name: String,
    version: Option<String>,
}

pub async fn generer_contenu_fiche_publique<M>(middleware: &M) -> Result<FichePublique, Error>
where M: MongoDao + ValidateurX509 + CleChiffrageHandler
{
    // Extraire chaines pem de certificats de chiffrage
    let chiffrage_enveloppes = middleware.get_publickeys_chiffrage();
    let mut chiffrage = Vec::new();
    for cert in chiffrage_enveloppes {
        let chaine_pem = cert.chaine_pem()?;
        chiffrage.push(chaine_pem)
    }

    // let mut adresses = Vec::new();
    let mut instances: HashMap<String, InformationInstance> = HashMap::new();
    // let mut applications: HashMap<String, Vec<ApplicationPublique>> = HashMap::new();
    let mut applications_v2: HashMap<String, ApplicationsV2> = HashMap::new();

    let map_ports = {
        let mut map_ports: HashMap<String, u16> = HashMap::new();
        map_ports.insert("http".to_string(), 80);
        map_ports.insert("https".to_string(), 443);
        map_ports.insert("wss".to_string(), 443);
        map_ports
    };

    let presence_expiree = Utc::now() - Duration::from_secs(3600);

    let configured_app_collection =
        middleware.get_collection_typed::<InstanceConfiguredAppRow>(NOM_COLLECTION_INSTANCE_CONFIGURED_APPLICATIONS)?;

    let webapps_collection =
        middleware.get_collection_typed::<InstanceWebappsRow>(NOM_COLLECTION_INSTANCE_WEBAPPS)?;

    let collection = middleware.get_collection_typed::<ServerInstanceStatus>(NOM_COLLECTION_INSTANCE_STATUS)?;
    let mut curseur = collection.find(None, None).await?;
    while curseur.advance().await? {
        let info_instance = curseur.deserialize_current()?;
        debug!("generer_contenu_fiche_publique Information instance : {:?}", info_instance);

        let securite_instance = match info_instance.security.as_ref() {
            Some(inner) => inner.as_str(),
            None => {
                info!("generer_contenu_fiche_publique Instance {} sans niveau de securite, on skip", info_instance.instance_id);
                continue;
            }
        };

        let securite = Securite::try_from(securite_instance)?;
        match securite {
            Securite::L4Secure => continue,  // Do not expose 4.secure instances
            _ => ()
        }

        let hostnames = match info_instance.hostnames {
            Some(inner) => {
                if inner.len() == 0 {
                    info!("generer_contenu_fiche_publique Instance {} n'as aucuns domaines, skip pour fiche publique (1)", info_instance.instance_id);
                    continue;
                }
                inner
            },
            None => {
                info!("generer_contenu_fiche_publique Instance {} n'as aucuns domaines, skip pour fiche publique (2)", info_instance.instance_id);
                continue;
            }
        };

        match info_instance.timestamp {
            Some(inner) => {
                if inner < presence_expiree {
                    info!("generer_contenu_fiche_publique Instance {} expiree, skip", info_instance.instance_id);
                    continue;
                }
            },
            None => {
                info!("generer_contenu_fiche_publique Instance {} sans date de presence, skip", info_instance.instance_id);
                continue;
            }
        }

        // Preparer partie de la fiche publique d'instance
        let information_instance = InformationInstance {
            ports: map_ports.clone(),
            onion: None,
            securite: securite_instance.to_owned(),
            domaines: Some(hostnames.clone())
        };
        instances.insert(info_instance.instance_id.clone(), information_instance);

        // Conserver la liste des applications/versions par nom d'application
        let mut app_versions = HashMap::new();
        let filtre_configured_apps = doc!{"instance_id": &info_instance.instance_id};
        let mut cursor_app_versions = configured_app_collection.find(filtre_configured_apps.clone(), None).await?;
        while cursor_app_versions.advance().await? {
            let row = cursor_app_versions.deserialize_current()?;
            if let Some(version) = row.version {
                app_versions.insert(row.app_name, version);
            }
        }

        // Generer la liste des applications avec leur url
        let mut cursor_webapps = webapps_collection.find(filtre_configured_apps, None).await?;
        while cursor_webapps.advance().await? {
            let row = cursor_webapps.deserialize_current()?;

            let securite = {
                let securite = match Securite::try_from(row.securite.as_str()) {
                    Ok(inner) => inner,
                    Err(e) => {
                        warn!("generer_contenu_fiche_publique Securite app {} incorrecte : {:?}, skip", row.app_name, e);
                        continue;
                    }
                };
                match securite {
                    Securite::L1Public | Securite::L2Prive => securite,
                    _ => {
                        debug!("generer_contenu_fiche_publique Securite app {} n'est pas 1 ou 2, skip", row.app_name);
                        continue;
                    }
                }
            };

            // V2
            let label = if Some(false) != row.supporte_usagers {
                let mut label = HashMap::new();
                label.insert("fr".to_string(), row.app_name.clone());
                Some(label)
            } else {
                None
            };

            let app_v2 = ApplicationsV2 {
                instances: HashMap::new(),
                name: label,
                securite: securite.get_str().to_owned(),
                supporte_usager: None,
            };

            applications_v2.insert(row.app_name.clone(), app_v2);

            // Recuperer pointeur mut
            let application_v2 = applications_v2.get_mut(&row.app_name).expect("app_v2");

            let pathname = {
                let pathname = match row.url.as_ref() {
                    Some(inner) => match Url::parse(inner.as_str()) {
                        Ok(url) => Some(url.path().to_owned()),
                        Err(e) => {
                            debug!("Erreur parse URL {:}", e);
                            None
                        }
                    },
                    None => None
                };

                match pathname {
                    Some(inner) => inner,
                    None => {
                        // Utiliser pathname par defaut
                        format!("/{}", &row.app_name)
                    }
                }
            };

            // Find version
            let version = match app_versions.get(&row.app_name) {
                Some(v) => v.clone(),
                None => "".to_string()
            };
            let appv2_info = InformationApplicationInstance {pathname, port: None, version};

            // if let Some(hostname_onion) = info_instance.onion.as_ref() {
            //     let mut app_onion: ApplicationPublique = app.try_into()?;
            //     let nom_app = app_onion.application.as_str();
            //     app_onion.nature = ADRESSE_NATURE_ONION.into();
            //     app_onion.preference = ADRESSE_PREFERENCE_SECONDAIRE;
            //
            //     // Remplacer hostname par adresse .onion
            //     let mut url_app = Url::parse(app_onion.url.as_str())?;
            //     url_app.set_host(Some(hostname_onion))?;
            //     app_onion.url = url_app.as_str().into();
            //
            //     if let Some(v) = app_versions.get(nom_app) {
            //         app_onion.version = v.version.to_owned();
            //     }
            //
            //     apps_mut.push(app_onion);
            // }

            application_v2.instances.insert(info_instance.instance_id.clone(), appv2_info);
        }
    }

    let fiche = FichePublique {
        applications_v2,
        chiffrage: Some(chiffrage),
        ca: Some(middleware.ca_pem().into()),
        idmg: middleware.idmg().into(),
        instances,
    };

    debug!("New fiche: {}", serde_json::to_string(&fiche)?);

    Ok(fiche)
}
