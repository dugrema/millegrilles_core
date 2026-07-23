use std::collections::HashMap;
use std::str::from_utf8;
use std::time::Duration;
use log::{debug, error};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::constantes::{Securite, CHAMP_CREATION, CHAMP_MODIFICATION, COMMANDE_RELAIWEB_GET, DOMAINE_RELAIWEB, SECURITE_2_PRIVE};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{millegrilles_cryptographie, serde_json};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::reqwest::Url;
use crate::topology_constants::*;
use crate::topology_structs::{ApplicationsV2, FichePublique, InformationApplicationInstance, InformationInstance, JwtHebergement, ReponseRelaiWeb, ReponseUrlEtag, RequeteRelaiWeb, ManagerStatusV2, ApplicationStatusV2, WebItem};

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
    for (_instance_id, instance) in &fiche.instances {
        if let Some(domaines) = instance.domaines.as_ref() {
            for domaine in domaines {

                let filtre = doc! { "adresse": domaine };

                let mut set_ops = doc!{"idmg": &idmg_tiers};
                match domaine_etag {
                    Some(_inner) => match etag.as_ref() {
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
        if let Some(_hostname) = url.host_str() {
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
                            Err(_e) => {
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
        if let Err(_e) = message_owned.verifier_signature() {
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

    let mut instances: HashMap<String, InformationInstance> = HashMap::new();
    let mut applications_v2: HashMap<String, ApplicationsV2> = HashMap::new();

    let default_map_ports = {
        let mut map_ports: HashMap<String, u16> = HashMap::new();
        map_ports.insert("http".to_string(), 80);
        map_ports.insert("https".to_string(), 443);
        map_ports.insert("wss".to_string(), 443);
        map_ports.insert("https_mtls".to_string(), 444);
        map_ports.insert("wss_mtls".to_string(), 444);
        map_ports
    };

    let presence_expiree = Utc::now() - Duration::from_secs(3600);

    // Fetch and Map Instances (ManagerStatusV2)
    let instance_collection = middleware.get_collection_typed::<ManagerStatusV2>(NOM_COLLECTION_INSTANCE_STATUS_V2)?;
    let mut instance_cursor = instance_collection.find(None, None).await?;

    while instance_cursor.advance().await? {
        let status = instance_cursor.deserialize_current()?;

        if status.supprime || status.securite == "4.secure" {
            continue;
        }

        if status.timestamp < presence_expiree {
            continue;
        }

        let (hostname, ports) = match status.system_state.host {
            Some(host) => (host.hostname.clone(), host.ports.clone()),
            None => ("hostname".to_string(), default_map_ports.clone()),
        };
        let info_instance = InformationInstance {
            ports,
            onion: None,
            securite: status.securite,
            domaines: Some(vec![hostname]),
        };
        instances.insert(status.instance_id.clone(), info_instance);
    }

    // Fetch and Map Applications (ApplicationStatusV2)
    let app_collection = middleware.get_collection_typed::<ApplicationStatusV2>(NOM_COLLECTION_INSTANCE_CONFIGURED_APPLICATIONS_V2)?;
    let mut app_cursor = app_collection.find(None, None).await?;

    while app_cursor.advance().await? {
        let app_status = app_cursor.deserialize_current()?;

        for (app_name, app_info) in app_status.applications {
            // Web application filtering (remove back-end and admin apps)
            let web_apps: Vec<WebItem> = match app_info.web {
                Some(web_apps) => {
                    let mut non_admin_web_apps = Vec::new();
                    for web_app in web_apps {
                        // Keep non-admin apps only (this is a public card)
                        if ! web_app.admin.unwrap_or(false) {
                            non_admin_web_apps.push(web_app);
                        }
                    }
                    non_admin_web_apps
                }
                None => {
                    continue;  // Not a web exposed application
                }
            };

            if web_apps.is_empty() {
                continue;  // No remaining exposed endpoints
            }

            let is_api = web_apps.iter().any(|item| item.api == Some(true));
            let securite = app_info.securite.unwrap_or_else(||SECURITE_2_PRIVE.to_string());  // Default to 2.prive

            // let supporte_usager = if app_info.portal.is_some() { Some(true) } else { None };
            let app_v2 = applications_v2.entry(app_name.clone()).or_insert_with(|| ApplicationsV2 {
                instances: HashMap::new(),
                name: Some(app_info.labels.clone()),
                securite,
                supporte_usager: Some(!is_api),
            });

            let appv2_info = InformationApplicationInstance {
                pathname: app_info.path.unwrap_or_else(|| format!("/{}", app_name)),
                // port: app_info.web.and_then(|p| p.first().and_then(|i| i.port)),
                port: web_apps.first().and_then(|i| i.port),
                version: app_info.version,
            };

            app_v2.instances.insert(app_status.instance_id.clone(), appv2_info);
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