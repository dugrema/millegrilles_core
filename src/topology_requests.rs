use std::collections::{HashMap, HashSet};
use std::str::from_utf8;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};

use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::{bson, bson::doc};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{chrono, millegrilles_cryptographie, serde_json};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::url::Url;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::common_messages::{ReponseInformationConsignationFichiers, RequeteConsignationFichiers, PresenceFichiersRepertoire, RequeteDechiffrage, RequeteFilehostItem, RequestFilehostForInstanceResponse};
use millegrilles_common_rust::dechiffrage::DataChiffre;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};
use millegrilles_common_rust::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction_v2;
use millegrilles_common_rust::common_messages::FilehostForInstanceRequest;

use crate::topology_common::{demander_jwt_hebergement, generer_contenu_fiche_publique, maj_fiche_publique};
use crate::topology_constants::*;
use crate::topology_manager::TopologyManager;
use crate::topology_structs::{ApplicationConfiguree, ApplicationPublique, ApplicationsV2, FichePublique, FilehostServerRow, FilehostingCongurationRow, InformationApplication, InformationApplicationInstance, InformationInstance, InformationMonitor, PresenceMonitor, ReponseRelaiWeb, ReponseUrlEtag, TransactionConfigurerConsignation, TransactionSetConsignationInstance, WebAppLink};

pub async fn consommer_requete_topology<M>(middleware: &M, m: MessageValide)
                              -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("Consommer requete : {:?}", &m.type_message);

    let (domaine, action, mut exchanges) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            (r.domaine.clone(), r.action.clone(), r.exchanges.clone())
        }
        _ => {
            Err(format!("consommer_requete Mauvais type de message"))?
        }
    };

    let exchange = match exchanges.pop() {
        Some(inner) => inner,
        None => Err(String::from("consommer_requete Exchange manquant"))?
    };

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.
    match exchange {
        Securite::L1Public => {
            match domaine.as_str() {
                DOMAIN_NAME => {
                    match action.as_str() {
                        REQUETE_FICHE_MILLEGRILLE => requete_fiche_millegrille(middleware, m).await,
                        REQUETE_APPLICATIONS_TIERS => requete_applications_tiers(middleware, m).await,
                        REQUETE_CONSIGNATION_FICHIERS => requete_consignation_fichiers(middleware, m).await,
                        REQUETE_GET_TOKEN_HEBERGEMENT => requete_get_token_hebergement(middleware, m).await,
                        REQUETE_GET_FILEHOSTS => requete_filehosts(middleware, m).await,
                        REQUETE_GET_FILECONTROLERS => requete_filecontrolers(middleware, m).await,
                        REQUETE_GET_FILEHOST_FOR_INSTANCE => request_filehost_for_instance(middleware, m).await,
                        REQUETE_GET_FILEHOST_FOR_EXTERNAL => request_filehost_for_external(middleware, m).await,
                        _ => {
                            error!("Message requete/action non autorisee sur 1.public : '{:?}'. Message dropped.", m.type_message);
                            Ok(None)
                        }
                    }
                },
                _ => {
                    error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
                    Ok(None)
                }
            }
        },
        Securite::L2Prive => {
            match domaine.as_str() {
                DOMAIN_NAME => {
                    match action.as_str() {
                        REQUETE_LISTE_DOMAINES => liste_domaines(middleware, m).await,
                        REQUETE_APPLICATIONS_DEPLOYEES => liste_applications_deployees(middleware, m).await,
                        REQUETE_USERAPPS_DEPLOYEES => liste_userapps_deployees(middleware, m).await,
                        REQUETE_RESOLVE_IDMG => resolve_idmg(middleware, m).await,
                        REQUETE_FICHE_MILLEGRILLE => requete_fiche_millegrille(middleware, m).await,
                        REQUETE_APPLICATIONS_TIERS => requete_applications_tiers(middleware, m).await,
                        REQUETE_CONSIGNATION_FICHIERS => requete_consignation_fichiers(middleware, m).await,
                        REQUETE_GET_CLE_CONFIGURATION => requete_get_cle_configuration(middleware, m).await,
                        _ => {
                            error!("Message requete/action inconnue : '{}'. Message dropped.", action);
                            Ok(None)
                        }
                    }
                },
                _ => {
                    error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
                    Ok(None)
                }
            }
        },
        Securite::L3Protege | Securite::L4Secure => {
            match domaine.as_str() {
                DOMAINE_NOM => {
                    match action.as_str() {
                        REQUETE_LISTE_DOMAINES => liste_domaines(middleware, m).await,
                        REQUETE_LISTE_NOEUDS => liste_noeuds(middleware, m).await,
                        REQUETE_CONFIGURATION_FICHIERS => requete_configuration_fichiers(middleware, m).await,
                        REQUETE_GET_CLE_CONFIGURATION => requete_get_cle_configuration(middleware, m).await,
                        REQUETE_GET_CLEID_BACKUP_DOMAINE => requete_get_cleid_backup_domaine(middleware, m).await,
                        _ => {
                            error!("Message requete/action inconnue : '{}'. Message dropped.", action);
                            Ok(None)
                        }
                    }
                },
                _ => {
                    error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
                    Ok(None)
                }
            }
        },
        _ => {
            error!("Message requete/action sans exchange autorise : '{}'. Message dropped.", action);
            Ok(None)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteFicheMillegrille {
    idmg: String,
}

impl TryInto<ApplicationPublique> for InformationApplication {
    type Error = String;

    fn try_into(self) -> Result<ApplicationPublique, Self::Error> {
        let url = match self.url {
            Some(u) => u,
            None => Err(format!("core_topologie.TryInto<ApplicationPublique> URL manquant"))?
        };
        Ok(ApplicationPublique {
            application: self.application,
            version: None,
            url,
            preference: ADRESSE_PREFERENCE_PRIMAIRE,
            nature: ADRESSE_NATURE_DNS.into(),
        })
    }
}

async fn requete_fiche_millegrille<M>(middleware: &M, message: MessageValide)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("requete_fiche_millegrille");
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteFicheMillegrille = message_contenu.deserialize()?;
    debug!("requete_fiche_millegrille Parsed : {:?}", requete);

    let enveloppe_locale = middleware.get_enveloppe_signature();
    let idmg_local = enveloppe_locale.enveloppe_pub.idmg()?;

    let fiche = match requete.idmg.as_str() == idmg_local.as_str() {
        true => {
            // Fiche publique locale
            Some(generer_contenu_fiche_publique(middleware).await?)
        },
        false => {
            // Fiche publique d'une millegrille tierce
            let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
            let filtre = doc! {
                TRANSACTION_CHAMP_IDMG: &requete.idmg,
            };
            match collection.find_one(filtre, None).await? {
                Some(doc_fiche) => {
                    let mut fiche: FichePublique = convertir_bson_deserializable(doc_fiche)?;
                    Some(fiche)
                },
                None => None
            }
        }
    };

    let reponse = match fiche {
        Some(r) => {
            // middleware.formatter_reponse(fiche, None)
            let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, "fichePublique", vec![])
                .build();
            middleware.build_message_action(
                millegrilles_cryptographie::messages_structs::MessageKind::Commande, routage, r)?.0
            // middleware.formatter_message(
            //     MessageKind::Commande, &r, Some(DOMAINE_TOPOLOGIE), Some("fichePublique"),
            //     None::<&str>, None::<&str>,Some(1), true)
        }
        None => {
            // middleware.formatter_reponse(json!({"ok": false, "code": 404, "err": "Non trouve"}), None)
            middleware.reponse_err(404, None, Some("Non trouve"))?
        }
    };

    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteApplicationsTiers {
    idmgs: Vec<String>,
    application: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocumentApplicationsTiers {
    idmg: String,
    adresses: Option<Vec<String>>,
    applications: HashMap<String, Vec<ApplicationPublique>>,
    chiffrage: Vec<Vec<String>>,
    ca: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseApplicationsTiers {
    idmg: String,
    adresses: Option<Vec<String>>,
    application: Vec<ApplicationPublique>,
    chiffrage: Vec<Vec<String>>,
    ca: String,
}

impl TryFrom<DocumentApplicationsTiers> for ReponseApplicationsTiers {
    type Error = String;

    fn try_from(value: DocumentApplicationsTiers) -> Result<Self, Self::Error> {
        let application = match value.applications.len() {
            1 => {
                match value.applications.into_iter().next() {
                    Some((_, app_info)) => Ok(app_info),
                    None => Err(format!("core_topologie.TryFrom<DocumentApplicationsTiers> Erreur conversion"))
                }
            },
            _ => Err(format!("core_topologie.TryFrom<DocumentApplicationsTiers> Erreur conversion, nombre d'applications doit etre 1"))
        }?;

        Ok(ReponseApplicationsTiers {
            idmg: value.idmg,
            adresses: value.adresses,
            application,
            chiffrage: value.chiffrage,
            ca: value.ca,
        })
    }
}

async fn requete_applications_tiers<M>(middleware: &M, message: MessageValide)
                                       -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteApplicationsTiers = message_contenu.deserialize()?;
    debug!("requete_applications_tiers Parsed : {:?}", requete);

    let projection = doc! {
        "idmg": 1,
        "ca": 1,
        "chiffrage": 1,
        format!("applications.{}", requete.application): 1
    };

    let options = FindOptions::builder().projection(projection).build();

    let filtre = doc! {
        TRANSACTION_CHAMP_IDMG: {"$in": &requete.idmgs},
        format!("applications.{}", requete.application): {"$exists": true},
    };

    let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
    let mut curseur = collection.find(filtre, Some(options)).await?;
    let mut fiches = Vec::new();
    while let Some(doc_fiche) = curseur.next().await {
        let document_applications: DocumentApplicationsTiers = convertir_bson_deserializable(doc_fiche?)?;
        debug!("Document applications mappe : {:?}", document_applications);
        let reponse_applications: ReponseApplicationsTiers = document_applications.try_into()?;
        fiches.push(reponse_applications);
    }

    Ok(Some(middleware.build_reponse(json!({"fiches": fiches}))?.0))
}

async fn requete_consignation_fichiers<M>(middleware: &M, message: MessageValide)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteConsignationFichiers = message_contenu.deserialize()?;
    debug!("requete_consignation_fichiers Parsed : {:?}", requete);

    let instance_id = match message.certificat.subject()?.get("commonName") {
        Some(inner) => inner.clone(),
        None => Err(format!("requete_consignation_fichiers Erreur chargement, certificat sans commonName"))?
    };

    let mut projection = doc! {
        "instance_id": 1,
        "primaire": 1,
        "consignation_url": 1,
        "type_store": 1,
        "url_download": 1,
        "url_archives": 1,
        "sync_intervalle": 1,
        "sync_actif": 1,
        "supporte_archives": 1,
        "data_chiffre": 1,
        "hostname_sftp": 1,
        "username_sftp": 1,
        "remote_path_sftp": 1,
        "key_type_sftp": 1,
        "s3_access_key_id": 1,
        "s3_region": 1,
        "s3_endpoint": 1,
        "s3_bucket": 1,
        "type_backup": 1,
        "hostname_sftp_backup": 1,
        "username_sftp_backup": 1,
        "remote_path_sftp_backup": 1,
        "key_type_sftp_backup": 1,
        "backup_intervalle_secs": 1,
        "backup_limit_bytes": 1,
        "supprime": 1,
    };

    if let Some(true) = requete.stats {
        // Inclure information des fichiers et espace
        projection.insert("principal", 1);
        projection.insert("archive", 1);
        projection.insert("orphelin", 1);
        projection.insert("manquant", 1);
    }

    let options = FindOneOptions::builder()
        .projection(projection)
        .build();

    let filtre = match requete.instance_id {
        Some(inner) => doc! { "instance_id": inner },
        None => match requete.hostname {
            Some(inner) => {
                // Trouver une instance avec le hostname demande
                let collection = middleware.get_collection(NOM_COLLECTION_INSTANCES)?;
                let filtre = doc! {"$or": [{"domaine": &inner}, {"onion": &inner}]};
                match collection.find_one(filtre, None).await? {
                    Some(inner) => {
                        let info_instance: InformationMonitor = convertir_bson_deserializable(inner)?;
                        doc! { "instance_id": info_instance.instance_id }
                    },
                    None => {
                        //let reponse = json!({"ok": false});
                        //return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                        return Ok(Some(middleware.reponse_err(None, None, None)?))
                    }
                }
            }
            None => {
                if let Some(true) = requete.primaire {
                    doc! { "primaire": true, }
                } else {
                    // Determiner la consignation a utiliser
                    // Charger instance et lire consignation_id. Si None, comportement par defaut.
                    let filtre_instance = doc! { CHAMP_INSTANCE_ID: &instance_id };
                    let collection_instance = middleware.get_collection_typed::<TransactionSetConsignationInstance>(
                        NOM_COLLECTION_INSTANCES)?;
                    match collection_instance.find_one(filtre_instance.clone(), None).await? {
                        Some(instance_info) => {
                            match instance_info.consignation_id {
                                Some(consignation_id) => {
                                    debug!("requete_consignation_fichiers Utilisation consignation_id {} pour instance_id {}", consignation_id, instance_id);
                                    doc! { CHAMP_INSTANCE_ID: consignation_id }
                                },
                                None => {
                                    // Determiner si l'instance possede un serveur de consignation de fichiers
                                    let collection_fichiers = middleware.get_collection_typed::<TransactionConfigurerConsignation>(
                                        NOM_COLLECTION_FICHIERS)?;
                                    match collection_fichiers.find_one(filtre_instance.clone(), None).await? {
                                        Some(inner) => filtre_instance,
                                        None => {
                                            // L'instance n'a pas de serveur de consignation de fichiers, utiliser primaire
                                            doc! { "primaire": true }
                                        }
                                    }
                                }
                            }
                        },
                        None => {
                            // L'instance est inconnue (anormal...), on selectionne le primaire
                            doc! { "primaire": true }
                        }
                    }
                }
            }
        }
    };

    debug!("requete_consignation_fichiers Filtre {:?}", filtre);
    let collection = middleware.get_collection_typed::<ReponseInformationConsignationFichiers>(NOM_COLLECTION_FICHIERS)?;
    let fiche_consignation = collection.find_one(filtre, Some(options)).await?;
    let reponse = match fiche_consignation {
        Some(mut fiche_reponse) => {
            // let mut fiche_reponse: ReponseInformationConsignationFichiers = convertir_bson_deserializable(f)?;
            fiche_reponse.ok = Some(true);
            debug!("requete_consignation_fichiers Row consignation : {:?}", fiche_reponse);

            // Recuperer info instance pour domaine et onion
            let filtre = doc! {"instance_id": &fiche_reponse.instance_id};
            let collection = middleware.get_collection_typed::<InformationMonitor>(NOM_COLLECTION_INSTANCES)?;
            if let Some(info_instance) = collection.find_one(filtre, None).await? {
                debug!("requete_consignation_fichiers Info instance chargee {:?}", info_instance);
                let mut domaines = match info_instance.domaines {
                    Some(inner) => inner.clone(),
                    None => Vec::new()
                };
                if let Some(inner) = info_instance.onion {
                    domaines.push(inner);
                }
                fiche_reponse.hostnames = Some(domaines);
            }

            middleware.build_reponse(fiche_reponse)?.0
        },
        None => middleware.reponse_err(None, None, None)?
    };

    Ok(Some(reponse))
}

#[derive(Deserialize)]
struct RequeteGetTokenHebergement {
    idmg: String,
    readwrite: Option<bool>,
}

#[derive(Deserialize)]
struct HebergementTokenRow {
    idmg: String,
    role: String,
    token: String,
    #[serde(with="bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    expiration: chrono::DateTime<Utc>,
}

#[derive(Serialize)]
struct ReponseGetTokenHebergement {
    jwt: String
}

async fn requete_get_token_hebergement<M>(middleware: &M, m: MessageValide)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("requete_get_token_hebergement Message :\n{}", from_utf8(&m.message.buffer)?);
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteGetTokenHebergement = message_contenu.deserialize()?;

    if !m.certificat.verifier_roles_string(vec![
        "collections".to_string(),
        "fichiers".to_string(),
        "media".to_string(),
        "stream".to_string(),
        "backup".to_string(),
    ])? {
        return Ok(Some(middleware.reponse_err(Some(1), None, Some("Acces refuse. Le certificat de la requete doit etre un des roles : collections, fichiers, media, backup, stream"))?))
    }
    let supporte_readwrite = m.certificat.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])?;
    if !supporte_readwrite && !m.certificat.verifier_exchanges(vec![Securite::L1Public])? {
        return Ok(Some(middleware.reponse_err(Some(2), None, Some("Acces refuse. Le certificat de la requete doit etre systeme (au moins securite 1.public)"))?))
    }

    let requete_readwrite = requete.readwrite.unwrap_or_else(|| false);
    if requete_readwrite && !supporte_readwrite {
        return Ok(Some(middleware.reponse_err(Some(3), None, Some("Acces refuse. Le certificat ne supporte pas l'acces read-write"))?))
    }

    let idmg = requete.idmg;
    let filtre = match requete_readwrite {
        true => doc!{"idmg": &idmg, "role": "hebergement_readwrite"},
        false => doc!{"idmg": &idmg, "role": "hebergement_readonly"},
    };
    let collection = middleware.get_collection_typed::<HebergementTokenRow>(NOM_COLLECTION_TOKENS)?;
    let token_row_opt = collection.find_one(filtre, None).await?;

    let now = Utc::now();
    let reset_tokens = match token_row_opt.as_ref() {
        Some(inner) => {
            if inner.expiration < now {
                true
            } else {
                false
            }
        },
        None => true
    };

    let token = match reset_tokens {
        true => {
            // Charger la fiche et demander de nouveaux tokens
            let collection = middleware.get_collection_typed::<FichePublique>(NOM_COLLECTION_MILLEGRILLES)?;
            let filtre = doc!{"idmg": &idmg};
            let fiche_publique = match collection.find_one(filtre, None).await? {
                Some(inner) => inner,
                None => {
                    error!("requete_get_token_hebergement Erreur ajout consignation existante sur idmg : {}", idmg);
                    return Ok(Some(middleware.reponse_err(Some(4), None, Some("Une configuration d'hebergement existe deja pour cette millegrille"))?))
                }
            };

            let (jwt, url_verifie) = match demander_jwt_hebergement(middleware, &fiche_publique, None).await {
                Ok(inner) => inner,
                Err(e) => {
                    error!("requete_get_token_hebergement Erreur demande JWT pour hebergement : {:?}", e);
                    return Ok(Some(middleware.reponse_err(Some(5), None, Some("Erreur demande tokens"))?))
                }
            };

            match requete_readwrite {
                true => jwt.jwt_readwrite,
                false => jwt.jwt_readonly
            }
        },
        false => {
            let token_row = token_row_opt.expect("token_row");
            token_row.token
        }
    };

    let reponse = ReponseGetTokenHebergement {jwt: token};

    Ok(Some(middleware.build_reponse_chiffree(reponse, m.certificat.as_ref())?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteListeDomaines {
    reclame_fuuids: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct DomaineRowOwned {
    instance_id: String,
    domaine: String,
    #[serde(rename(deserialize="_mg-creation"), serialize_with = "optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    creation: Option<chrono::DateTime<Utc>>,
    #[serde(rename(deserialize="_mg-derniere-modification"), serialize_with="optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    presence: Option<chrono::DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dirty: Option<bool>,
    reclame_fuuids: Option<bool>,
}

#[derive(Serialize)]
struct ReponseListDomaines {
    ok: bool,
    resultats: Vec<DomaineRowOwned>,
}

async fn liste_domaines<M>(middleware: &M, message: MessageValide)
                           -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("liste_domaines {:?}", message.type_message);
    if !message.certificat.verifier_exchanges(vec!(Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
        if message.certificat.get_user_id()?.is_some() && !message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
            let refus = json!({"ok": false, "err": "Acces refuse"});
            // let reponse = match middleware.formatter_reponse(&refus, None) {
            let reponse = match middleware.reponse_err(None, None, Some("Acces refuse")) {
                Ok(m) => m,
                Err(e) => Err(format!("core_topologie.liste_domaines Erreur preparation reponse applications : {:?}", e))?
            };
            return Ok(Some(reponse));
        }
    }

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteListeDomaines = message_contenu.deserialize()?;

    let mut curseur = {
        let projection = doc! {"instance_id": true, "domaine": true, CHAMP_MODIFICATION: true, "reclame_fuuids": true, "_mg-creation": true};
        let collection = middleware.get_collection_typed::<DomaineRowOwned>(NOM_COLLECTION_DOMAINES)?;
        let ops = FindOptions::builder().projection(Some(projection)).build();

        let mut filtre = doc!{};
        if let Some(reclame_fuuids) = requete.reclame_fuuids {
            filtre.insert("reclame_fuuids", reclame_fuuids);
        }

        match collection.find(filtre, Some(ops)).await {
            Ok(c) => c,
            Err(e) => Err(format!("core_topologie.liste_domaines Erreur chargement domaines : {:?}", e))?
        }
    };
    let mut reponse_liste_domaines = ReponseListDomaines { ok: true, resultats: Vec::new() };
    while curseur.advance().await? {
        match curseur.deserialize_current() {
            Ok(inner) => {
                // Serialiser sous forme de value json
                reponse_liste_domaines.resultats.push(inner);
            },
            Err(e) => {
                error!("liste_domaines Erreur deserialize valeur Domaine : {:?}", e);
                continue
            }
        };
    }

    Ok(Some(middleware.build_reponse(reponse_liste_domaines)?.0))
}

#[derive(Serialize)]
struct ReponseApplicationDeployee {
    instance_id: String,
    application: String,
    securite: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name_property: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supporte_usagers: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<HashMap<String, Value>>,
}

#[derive(Serialize)]
struct ReponseListeApplicationsDeployees {
    ok: bool,
    resultats: Vec<ReponseApplicationDeployee>,
}

async fn liste_applications_deployees<M>(middleware: &M, message: MessageValide)
                                         -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    // Recuperer instance_id
    let certificat = message.certificat.as_ref();
    let instance_id = certificat.get_common_name()?;
    let extensions = certificat.extensions()?;
    let exchanges = extensions.exchanges.as_ref();
    debug!("liste_applications_deployees Instance_id {}, exchanges : {:?}", instance_id, exchanges);

    let niveau_securite = if certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        Securite::L3Protege
    } else if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        Securite::L3Protege
    } else if certificat.verifier_exchanges(vec![Securite::L2Prive])? {
        Securite::L2Prive
    } else if certificat.verifier_roles(vec![RolesCertificats::ComptePrive])? {
        Securite::L2Prive
    } else {
        warn!("liste_applications_deployees Acces refuse, aucunes conditions d'acces du certificat pour liste apps");
        // let reponse = json!({"ok": false, "err": "Acces refuse"});
        // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
    };
    debug!("liste_applications_deployees Niveau de securite : {:?}", niveau_securite);

    // Retour de toutes les applications (maitrecomptes est toujours sur exchange 2.prive)
    let sec_cascade = securite_cascade_public(niveau_securite);

    let mut curseur = {
        let filtre = doc! {};
        let projection = doc! {"instance_id": true, "domaine": true, "securite": true, "applications": true, "onion": true};
        let collection = middleware.get_collection_typed::<InformationMonitor>(NOM_COLLECTION_NOEUDS)?;
        let ops = FindOptions::builder().projection(Some(projection)).build();
        match collection.find(filtre, Some(ops)).await {
            Ok(c) => c,
            Err(e) => Err(format!("core_topologie.liste_applications_deployees Erreur chargement applications : {:?}", e))?
        }
    };

    // Extraire liste d'applications
    let mut resultats = Vec::new();
    while let Some(row) = curseur.next().await {
        let info_monitor = row?;
        let instance_id = info_monitor.instance_id.as_str();

        if let Some(applications) = info_monitor.applications {
            for app in applications {
                let securite = match app.securite {
                    Some(s) => match securite_enum(s.as_str()) {
                        Ok(s) => s,
                        Err(e) => continue   // Skip
                    },
                    None => continue  // Skip
                };

                // Verifier si le demandeur a le niveau de securite approprie
                if sec_cascade.contains(&securite) {

                    if let Some(url) = app.url.as_ref() {
                        // Preparer la valeur a exporter pour les applications
                        let onion = match info_monitor.onion.as_ref() {
                            Some(onion) => {
                                let mut url_onion = Url::parse(url.as_str())?;
                                url_onion.set_host(Some(onion.as_str()));
                                Some(url_onion.as_str().to_owned())
                            },
                            None => None
                        };

                        let mut info_app = ReponseApplicationDeployee {
                            instance_id: instance_id.to_owned(),
                            application: app.application.clone(),
                            securite: securite.get_str().to_owned(),
                            url: Some(url.to_owned()),
                            onion: onion.to_owned(),
                            name_property: None,
                            supporte_usagers: None,
                            labels: None,
                        };

                        if let Some(p) = app.name_property.as_ref() {
                            info_app.name_property = Some(p.to_string());
                        }

                        if let Some(p) = app.supporte_usagers.as_ref() {
                            info_app.supporte_usagers = Some(p.to_owned());
                        }

                        resultats.push(info_app);
                    }
                }
            }
        }
    }

    let liste = ReponseListeApplicationsDeployees {
        ok: true,
        resultats,
    };

    let reponse = match middleware.build_reponse(liste) {
        Ok(m) => m.0,
        Err(e) => Err(format!("core_topologie.liste_applications_deployees  Erreur preparation reponse applications : {:?}", e))?
    };
    Ok(Some(reponse))
}

async fn liste_userapps_deployees<M>(middleware: &M, message: MessageValide)
                                     -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    // Recuperer instance_id
    let certificat = message.certificat.as_ref();
    let instance_id = certificat.get_common_name()?;
    let extensions = certificat.extensions()?;
    let exchanges = extensions.exchanges.as_ref();
    debug!("liste_userapps_deployees Instance_id {}, exchanges : {:?}", instance_id, exchanges);

    let niveau_securite = if certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        Securite::L3Protege
    } else if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        Securite::L3Protege
    } else if certificat.verifier_exchanges(vec![Securite::L2Prive])? {
        Securite::L2Prive
    } else if certificat.verifier_roles(vec![RolesCertificats::ComptePrive])? {
        Securite::L2Prive
    } else {
        warn!("liste_userapps_deployees Acces refuse, aucunes conditions d'acces du certificat pour liste apps");
        // let reponse = json!({"ok": false, "err": "Acces refuse"});
        // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
    };
    debug!("liste_userapps_deployees Niveau de securite : {:?}", niveau_securite);

    // Retour de toutes les applications (maitrecomptes est toujours sur exchange 2.prive)
    let sec_cascade = securite_cascade_public(niveau_securite);

    let mut curseur = {
        let filtre = doc! {};
        let projection = doc! {"instance_id": true, "domaine": true, "securite": true, "applications": true, "onion": true, "webapps": true};
        let collection = middleware.get_collection_typed::<InformationMonitor>(NOM_COLLECTION_NOEUDS)?;
        let ops = FindOptions::builder().projection(Some(projection)).build();
        match collection.find(filtre, Some(ops)).await {
            Ok(c) => c,
            Err(e) => Err(format!("topology_requests.liste_userapps_deployees Erreur chargement applications : {:?}", e))?
        }
    };

    // Extraire liste d'applications
    let mut resultats = Vec::new();
    while let Some(row) = curseur.next().await {
        let info_monitor = row?;
        let instance_id = info_monitor.instance_id.as_str();

        if let Some(applications) = info_monitor.webapps {
            for app in applications {
                let securite = match securite_enum(app.securite.as_str()) {
                    Ok(s) => s,
                    Err(e) => continue   // Skip
                };

                debug!("liste_userapps_deployees App {} securite {:?}", app.name, securite);

                // Verifier si le demandeur a le niveau de securite approprie
                if sec_cascade.contains(&securite) {
                    // Preparer la valeur a exporter pour les applications
                    let onion = match info_monitor.onion.as_ref() {
                        Some(onion) => {
                            let mut url_onion = Url::parse(app.url.as_str())?;
                            if let Err(e) = url_onion.set_host(Some(onion.as_str())) {
                                warn!("liste_userapps_deployees Error parsing onion url: {:?}", e);
                                None
                            } else {
                                Some(url_onion.as_str().to_owned())
                            }
                        },
                        None => None
                    };

                    let info_app = ReponseApplicationDeployee {
                        instance_id: instance_id.to_owned(),
                        application: app.name.clone(),
                        securite: securite.get_str().to_owned(),
                        url: Some(app.url.clone()),
                        onion: onion.to_owned(),
                        name_property: Some(app.name.clone()),
                        supporte_usagers: Some(true),
                        labels: Some(app.labels),
                    };

                    resultats.push(info_app);
                } else {
                    debug!("liste_userapps_deployees App {} refuse, securite insuffisante", app.name);
                }
            }
        }
    }

    let liste = ReponseListeApplicationsDeployees {
        ok: true,
        resultats,
    };

    let reponse = match middleware.build_reponse(liste) {
        Ok(m) => m.0,
        Err(e) => Err(format!("topology_requests.liste_userapps_deployees  Erreur preparation reponse applications : {:?}", e))?
    };
    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteResolveIdmg {
    dns: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AdresseIdmg {
    adresse: String,
    idmg: String,
    etag: Option<String>,
}

async fn resoudre_url<M>(middleware: &M, hostname: &str, etag: Option<&String>)
                         -> Result<Option<String>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("resoudre_url {}", hostname);

    let routage = RoutageMessageAction::builder(DOMAINE_RELAIWEB, COMMANDE_RELAIWEB_GET, vec![Securite::L1Public])
        .build();

    let url_fiche = format!("https://{}/fiche.json", hostname);
    let requete = json!({
        "url": url_fiche,
        "headers": {
            "Cache-Control": "public, max-age=604800",
            "If-None-Match": etag,
        }
    });

    let reponse = {
        let reponse_http = middleware.transmettre_commande(routage, &requete).await?;
        debug!("Reponse http : {:?}", reponse_http);
        match reponse_http {
            Some(reponse) => match reponse {
                TypeMessage::Valide(reponse) => Ok(reponse),
                _ => Err(format!("core_topologie.resoudre_url Mauvais type de message recu en reponse"))
            },
            None => Err(format!("core_topologie.resoudre_url Aucun message recu en reponse"))
        }
    }?;

    // Mapper message avec la fiche
    let message_ref = reponse.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let reponse_fiche: ReponseRelaiWeb = message_contenu.deserialize()?;
    debug!("Reponse fiche : {:?}", reponse);

    // Verifier code reponse HTTP
    match reponse_fiche.code {
        Some(c) => {
            if c == 304 {
                // Aucun changement sur le serveur
                // On fait juste faire un touch sur l'adresse du hostname verifie
                let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;
                let filtre = doc! {"adresse": hostname};
                let ops = doc! {"$currentDate": {CHAMP_MODIFICATION: true}};
                collection.update_one(filtre, ops, None).await?;
                return Ok(None);
            } else if c != 200 {
                Err(format!("core_topologie.resoudre_url Code reponse http {}", c))
            } else {
                Ok(())
            }
        }
        None => Err(format!("core_topologie.resoudre_url Code reponse http manquant"))
    }?;

    // Verifier presence fiche publique
    let fiche_json_value: FichePublique = match reponse_fiche.json {
        Some(f) => match serde_json::from_value(f) {
            Ok(inner) => inner,
            Err(e) => Err(CommonError::String(format!("core_topologie.resoudre_url Fiche publique invalide : {:?}", e)))?
        },
        None => Err(CommonError::Str("core_topologie.resoudre_url Fiche publique manquante"))?
    };

    maj_fiche_publique(middleware, &fiche_json_value, None).await?;

    todo!("fix me")
    // debug!("resoudre_url Message json string : {}", fiche_json_value);
    // let mut fiche_publique_message = MessageSerialise::from_serializable(fiche_json_value)?;
    // debug!("resoudre_url Fiche publique message serialize : {:?}", fiche_publique_message);
    // let validation_option = ValidationOptions::new(true, true, true);
    // let resultat_validation = fiche_publique_message.valider(middleware, Some(&validation_option)).await?;
    // if ! resultat_validation.valide() {
    //     Err(format!("core_topologie.resoudre_url Erreur validation fiche publique : {:?}", resultat_validation))?
    // }
    //
    // let idmg_tiers = match &fiche_publique_message.certificat {
    //     Some(c) => c.idmg(),
    //     None => Err(format!("core_topologie.resoudre_url Erreur chargement certificat de fiche publique, certificat manquant"))
    // }?;
    //
    // let fiche_publique: FichePubliqueReception = fiche_publique_message.get_msg().map_contenu()?;
    // debug!("resoudre_url Fiche publique mappee : {:?}", fiche_publique);
    //
    // // Sauvegarder/mettre a jour fiche publique
    // {
    //     let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES)?;
    //     let filtre = doc! {"idmg": &idmg_tiers};
    //     let apps = match &fiche_publique.applications {
    //         Some(a) => {
    //             let mut map = Map::new();
    //             for (key, value) in a.iter() {
    //                 let value_serde = serde_json::to_value(value)?;
    //                 map.insert(key.into(), value_serde);
    //             }
    //             Some(map)
    //         }
    //         None => None
    //     };
    //     let set_json = json!({
    //         // "adresses": &fiche_publique.adresses,
    //         "applications": apps,
    //         "chiffrage": &fiche_publique.chiffrage,
    //         "ca": &fiche_publique.ca,
    //     });
    //     let set_bson = convertir_to_bson(set_json)?;
    //     let ops = doc! {
    //         "$set": set_bson,
    //         "$setOnInsert": {
    //             "idmg": &idmg_tiers,
    //             CHAMP_CREATION: Utc::now(),
    //         },
    //         "$currentDate": {CHAMP_MODIFICATION: true},
    //     };
    //     let options = UpdateOptions::builder()
    //         .upsert(true)
    //         .build();
    //     let resultat_update = collection.update_one(filtre, ops, Some(options)).await?;
    //     if resultat_update.modified_count != 1 && resultat_update.upserted_id.is_none() {
    //         error!("resoudre_url Erreur, fiche publique idmg {} n'a pas ete sauvegardee", idmg_tiers);
    //     }
    // }
    //
    // // // Sauvegarder adresses
    // // {
    // //     let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;
    // //     debug!("Verification headers : {:?}", reponse_fiche.headers);
    // //     let etag = match reponse_fiche.headers.as_ref() {
    // //         Some(e) => e.get("ETag").cloned(),
    // //         None => None
    // //     };
    // //     if let Some(adresses) = fiche_publique.adresses.as_ref() {
    // //         for adresse in adresses {
    // //             let filtre = doc! { "adresse": adresse };
    // //             let ops = doc! {
    // //                 "$set": {
    // //                     "idmg": &idmg_tiers,
    // //                     "etag": &etag,
    // //                 },
    // //                 "$setOnInsert": {
    // //                     "adresse": adresse,
    // //                     CHAMP_CREATION: Utc::now(),
    // //                 },
    // //                 "$currentDate": {CHAMP_MODIFICATION: true},
    // //             };
    // //             let options = UpdateOptions::builder().upsert(true).build();
    // //             let resultat_update = collection.update_one(filtre, ops, Some(options)).await?;
    // //             if resultat_update.modified_count != 1 && resultat_update.upserted_id.is_none() {
    // //                 error!("resoudre_url Erreur, adresse {} pour idmg {} n'a pas ete sauvegardee", adresse, idmg_tiers);
    // //             }
    // //         }
    // //     }
    // // }
    //
    // Ok(Some(idmg_tiers))
}

async fn resolve_idmg<M>(middleware: &M, message: MessageValide)
                         -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("resolve_idmg");
    if !message.certificat.verifier_exchanges(vec!(Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
        return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
    }

    let idmg_local = middleware.get_enveloppe_signature().enveloppe_pub.idmg()?;

    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteResolveIdmg = message_contenu.deserialize()?;
    let collection = middleware.get_collection(NOM_COLLECTION_MILLEGRILLES_ADRESSES)?;

    // Map reponse, associe toutes les adresses dans la requete aux idmg trouves
    let mut resolved_dns: HashMap<String, Option<String>> = HashMap::new();

    if let Some(adresses) = requete.dns {
        for dns in &adresses {
            resolved_dns.insert(dns.clone(), None);
        }
        let filtre = doc! {CHAMP_ADRESSE: {"$in": adresses}};
        debug!("liste_domaines Filtre adresses : {:?}", filtre);
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(record_adresse) = curseur.next().await {
            let record_adresse = record_adresse?;
            debug!("Record adresse: {:?}", record_adresse);
            let date_modification = record_adresse.get("_mg-derniere-modification").cloned();
            let doc_adresse: AdresseIdmg = convertir_bson_deserializable(record_adresse)?;

            if doc_adresse.idmg.as_str() == idmg_local.as_str() {
                // L'adresse correspond a la millegrille locale
                resolved_dns.insert(doc_adresse.adresse.clone(), Some(doc_adresse.idmg.clone()));
                continue;
            }

            let date_modification = match date_modification {
                Some(dm) => {
                    if let Some(date_modification) = dm.as_datetime() {
                        let date_chrono = date_modification.to_chrono();
                        let duration = chrono::Duration::minutes(1);
                        if Utc::now() - duration > date_chrono {
                            debug!("Expire, on recharge");

                            let etag = doc_adresse.etag.as_ref();
                            let hostname = doc_adresse.adresse.as_str();
                            match resoudre_url(middleware, hostname, etag).await {
                                Ok(idmg_option) => {
                                    match idmg_option {
                                        Some(i) => {
                                            resolved_dns.insert(hostname.into(), i.into());
                                        }
                                        None => {
                                            // Aucuns changements (e.g. 304). Utiliser la version de la DB.
                                            resolved_dns.insert(hostname.into(), Some(doc_adresse.idmg.clone()));
                                        }
                                    }
                                    Some(date_chrono)
                                }
                                Err(e) => {
                                    error!("core_topologie.resolve_idmg Erreur chargement hostname {} : {:?}", hostname, e);
                                    None
                                }
                            }
                        } else {
                            Some(date_chrono)
                        }
                    } else {
                        None
                    }
                }
                None => None
            };

            match date_modification {
                Some(d) => {
                    resolved_dns.insert(doc_adresse.adresse, Some(doc_adresse.idmg));
                }
                None => {
                    debug!("Recharger information idmg {}", doc_adresse.idmg);
                }
            }
        }
    }

    // Lancer requetes pour DNS inconnus
    for (hostname, idmg) in resolved_dns.clone().iter() {
        if idmg.is_none() {
            info!("Charger fiche a {}", hostname);
            match resoudre_url(middleware, hostname.as_str(), None).await {
                Ok(idmg_option) => {
                    if let Some(idmg) = idmg_option {
                        resolved_dns.insert(hostname.into(), idmg.into());
                    }
                }
                Err(e) => error!("core_topologie.resolve_idmg Erreur chargement hostname {} : {:?}", hostname, e)
            }
        }
    }

    let liste = json!({"dns": resolved_dns});
    let reponse = match middleware.build_reponse(liste) {
        Ok(m) => m.0,
        Err(e) => Err(format!("core_topologie.resolve_idmg Erreur preparation reponse resolve idmg : {:?}", e))?
    };

    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParametresGetCleConfiguration {
    // ref_hachage_bytes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseConsignationSatellite {
    pub instance_id: String,
    pub consignation_url: Option<String>,
    pub type_store: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sync_intervalle: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync_actif: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supporte_archives: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_chiffre: Option<DataChiffre>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_download: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_archives: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostnames: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primaire: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_sftp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_sftp: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_sftp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_path_sftp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type_sftp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_bucket: Option<String>,

    // Backup
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_sftp_backup: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_path_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_intervalle_secs: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_limit_bytes: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphelin: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manquant: Option<PresenceFichiersRepertoire>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub espace_disponible: Option<usize>,
    #[serde(rename = "_mg-derniere-modification", skip_serializing_if = "Option::is_none", serialize_with="optionepochseconds::serialize", deserialize_with = "opt_chrono_datetime_as_bson_datetime::deserialize")]
    #[serde(default)]
    pub derniere_modification: Option<chrono::DateTime<Utc>>,

    pub supprime: Option<bool>,
}

async fn requete_get_cle_configuration<M>(middleware: &M, m: MessageValide)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_cle_configuration Message : {:?}", &m.type_message);
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: ParametresGetCleConfiguration = message_contenu.deserialize()?;
    debug!("requete_get_cle_configuration cle parsed : {:?}", requete);

    if ! m.certificat.verifier_roles(vec![RolesCertificats::Fichiers])? {
        // let reponse = json!({"err": true, "message": "certificat doit etre de role fichiers"});
        // return Ok(Some(middleware.formatter_reponse(reponse, None)?));
        return Ok(Some(middleware.reponse_err(None, Some("Certificat doit etre de role fichiers"), None)?))
    }

    // Utiliser certificat du message client (requete) pour demande de rechiffrage
    let instance_id = m.certificat.get_common_name()?;
    let pem_rechiffrage = m.certificat.chaine_pem()?;
    // let pem_rechiffrage: Vec<String> = fp_certs.into_iter().map(|cert| cert.pem).collect();

    // Recuperer information de dechiffrage (avec cle_id) pour cette instance
    let filtre = doc!("instance_id": &instance_id);
    let collection = middleware.get_collection_typed::<ReponseConsignationSatellite>(NOM_COLLECTION_FICHIERS)?;
    let consignation_instance = match collection.find_one(filtre, None).await? {
        Some(inner) => inner,
        None => {
            info!("requete_get_cle_configuration Aucune configuration pour fichiers sur instance {}", instance_id);
            return Ok(Some(middleware.reponse_err(1, None, Some("Aucune configuration de fichiers trouvees"))?))
        }
    };

    let data_chiffre = match consignation_instance.data_chiffre {
        Some(inner) => inner,
        None => {
            info!("requete_get_cle_configuration Aucune configuration pour fichiers sur instance {}", instance_id);
            return Ok(Some(middleware.reponse_err(1, None, Some("Aucune configuration chiffree trouvee pour les fichiers"))?))
        }
    };

    let cle_id = match data_chiffre.cle_id {
        Some(inner) => inner,
        None => match data_chiffre.ref_hachage_bytes {
            Some(inner) => inner,
            None => {
                info!("requete_get_cle_configuration Aucune configuration cle_id/ref_hachage_bytes trouve pour {}", instance_id);
                return Ok(Some(middleware.reponse_err(1, None, Some("Aucune configuration cle_id/ref_hachage_bytes trouve trouvee pour les fichiers"))?))
            }
        }
    };

    let permission = RequeteDechiffrage {
        domaine: DOMAIN_NAME.to_string(),
        liste_hachage_bytes: None,
        cle_ids: Some(vec![cle_id]),
        certificat_rechiffrage: Some(pem_rechiffrage),
        inclure_signature: None,
    };

    let (reply_to, correlation_id) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            let reply_q = match r.reply_to.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(String::from("requete_get_cle_configuration Reply to manquant"))?
            };
            let correlation_id = match r.correlation_id.as_ref() {
                Some(inner) => inner.as_str(),
                None => Err(String::from("requete_get_cle_configuration Correlation id manquant"))?
            };
            (reply_q, correlation_id)
        }
        _ => Err(String::from("requete_get_cle_configuration Mauvais type de message"))?
    };

    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege]
    )
        .reply_to(reply_to)
        .correlation_id(correlation_id)
        .blocking(false)
        .build();

    debug!("requete_get_cle_configuration Transmettre requete permission dechiffrage cle : {:?}", permission);
    middleware.transmettre_requete(routage, &permission).await?;

    Ok(None)  // Aucune reponse a transmettre, c'est le maitre des cles qui va repondre
}

#[derive(Clone, Deserialize)]
struct MessageInstanceId {
    instance_id: Option<String>
}

async fn liste_noeuds<M>(middleware: &M, message: MessageValide)
                         -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("liste_noeuds");
    if !message.certificat.verifier_exchanges(vec!(Securite::L3Protege, Securite::L4Secure))? {
        if !message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
            return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
        }
    }

    let mut curseur = {
        let mut filtre = doc! {};
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        let message_instance_id: MessageInstanceId = message_contenu.deserialize()?;
        if let Some(inner) = message_instance_id.instance_id.as_ref() {
            filtre.insert("instance_id", inner.to_owned());
        }
        let collection = middleware.get_collection_typed::<PresenceMonitor>(NOM_COLLECTION_NOEUDS)?;
        match collection.find(filtre, None).await {
            Ok(c) => c,
            Err(e) => Err(format!("core_topologie.liste_noeuds Erreur chargement applications : {:?}", e))?
        }
    };

    let mut noeuds = Vec::new();
    while let Some(r) = curseur.next().await {
        match r {
            Ok(d) => noeuds.push(d),
            Err(e) => warn!("core_topologie.liste_noeuds Erreur lecture document sous liste_noeuds() : {:?}", e)
        }
    }

    debug!("Noeuds : {:?}", noeuds);
    let liste = json!({"resultats": noeuds});
    let reponse = match middleware.build_reponse(liste) {
        Ok(m) => m.0,
        Err(e) => Err(format!("core_topologie.liste_noeuds Erreur preparation reponse noeuds : {:?}", e))?
    };
    Ok(Some(reponse))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteConfigurationFichiers {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseConfigurationFichiers {
    liste: Vec<ReponseConsignationSatellite>,
    ok: bool,
}

async fn requete_configuration_fichiers<M>(middleware: &M, message: MessageValide)
                                           -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteConfigurationFichiers = message_contenu.deserialize()?;
    debug!("requete_configuration_fichiers Parsed : {:?}", requete);

    let mut liste = Vec::new();

    let filtre = doc! {};
    let collection = middleware.get_collection_typed::<ReponseConsignationSatellite>(NOM_COLLECTION_FICHIERS)?;
    let mut curseur = collection.find(filtre, None).await?;
    while let Some(fiche) = curseur.next().await {
        // let doc_inner = inner?;
        let fiche = fiche?;

        // Extraire date BSON separement
        // let date_modif = match doc_inner.get(CHAMP_MODIFICATION) {
        //     Some(inner) => Some(DateEpochSeconds::try_from(inner.to_owned())?),
        //     None => None
        // };

        // let fiche: ReponseConsignationSatellite = convertir_bson_deserializable(doc_inner)?;
        // fiche.derniere_modification = date_modif;  // Re-injecter date

        liste.push(fiche);
    }

    let reponse = ReponseConfigurationFichiers { liste, ok: true };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Deserialize)]
struct RequeteGetCleidBackupDomaine {
    domaine: String,
}

#[derive(Deserialize)]
struct RowCoreTopologieDomaines {
    domaine: String,
    instance_id: String,
    dirty: Option<bool>,
    reclame_fuuids: Option<bool>,
    cle_id_backup: Option<String>,
}

#[derive(Serialize)]
struct ReponseGetCleidBackupDomaine {
    ok: bool,
    cle_id: String,
}

async fn requete_get_cleid_backup_domaine<M>(middleware: &M, m: MessageValide)
                                             -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_cleid_backup_domaine Message : {:?}", &m.type_message);
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteGetCleidBackupDomaine = message_contenu.deserialize()?;

    let domaine = requete.domaine;

    if !m.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        return Ok(Some(middleware.reponse_err(None, Some("Certificat doit avoir la securite 3.protege"), None)?))
    }
    if !m.certificat.verifier_domaines(vec![domaine.clone()])? {
        return Ok(Some(middleware.reponse_err(None, Some("Certificat doit etre de meme domaine que le domaine demande"), None)?))
    }

    let filtre = doc!{"domaine": &domaine};
    let collection = middleware.get_collection_typed::<RowCoreTopologieDomaines>(NOM_COLLECTION_DOMAINES)?;
    let row_domaine = collection.find_one(filtre, None).await?;

    let reponse = match row_domaine {
        Some(inner) => match inner.cle_id_backup {
            Some(cle_id) => {
                let reponse = ReponseGetCleidBackupDomaine { ok: true, cle_id };
                middleware.build_reponse(reponse)?.0
            },
            None => middleware.reponse_err(Some(1), None, Some("Aucune cle presente"))?
        },
        None => middleware.reponse_err(Some(2), None, Some("Domaine non configure"))?
    };

    Ok(Some(reponse))
}

#[derive(Serialize)]
struct RequeteFilehostListResponse {
    ok: bool,
    list: Vec<RequeteFilehostItem>,
}

#[derive(Deserialize)]
struct RequeteFilehostListRequest {
    filehost_id: Option<String>,
}

#[derive(Serialize)]
struct RequeteFilecontrolersListResponse {
    ok: bool,
    list: Vec<RequeteFilehostItem>,
    filecontroler_primary: Option<String>,
}

async fn requete_filehosts<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteFilehostListRequest = message_contenu.deserialize()?;

    let collection = middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;

    let filtre = match requete.filehost_id {
        Some(inner) => doc!{"filehost_id": inner},
        None => doc!{"deleted": false, "sync_active": true}
    };

    let mut cursor = collection.find(filtre, None).await?;
    let mut list = Vec::new();
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let item: RequeteFilehostItem = row.into();
        list.push(item);
    }

    let response = RequeteFilehostListResponse { ok: true, list };
    Ok(Some(middleware.build_reponse(response)?.0))
}

#[derive(Deserialize)]
struct RequeteFilecontrolersListRequest {
    instance_id: Option<String>,
}

async fn requete_filecontrolers<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: RequeteFilecontrolersListRequest = message_contenu.deserialize()?;

    let collection = middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILECONTROLERS)?;
    let filtre = match requete.instance_id {
        Some(inner) => doc!{"instance_id": inner},
        None => doc!{"deleted": false}
    };

    let mut cursor = collection.find(filtre, None).await?;
    let mut list = Vec::new();
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let item: RequeteFilehostItem = row.into();
        list.push(item);
    }

    let collection_config =
        middleware.get_collection_typed::<FilehostingCongurationRow>(NOM_COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let filtre = doc!{"name": FIELD_CONFIGURATION_FILECONTROLER_PRIMARY};
    let filecontroler_primary = match collection_config.find_one(filtre, None).await? {
        Some(inner) => Some(inner.value),
        None => None
    };

    let response = RequeteFilecontrolersListResponse { ok: true, list, filecontroler_primary };
    Ok(Some(middleware.build_reponse(response)?.0))
}

async fn request_filehost_for_instance<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: FilehostForInstanceRequest = message_contenu.deserialize()?;

    let certificat = message.certificat.as_ref();
    let certificate_instance_id = if certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
        // Back-end component, use common name (instance_id)
        certificat.get_common_name()?
    } else {
        return Ok(Some(middleware.reponse_err(Some(403), None, Some("Access denied"))?))
    };

    // Select the instance_id
    let instance_id = requete.instance_id.unwrap_or_else(|| certificate_instance_id);

    let collection_filehosts = middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;

    // Identify the filehost_id from the instance_id if possible
    let filehost_id = match requete.filehost_id {
        Some(inner) => Some(inner),  // Filehost provided
        None => {
            // Check if instance configuration overrides with filehost_id
            let collection_instances = middleware.get_collection_typed::<PresenceMonitor>(NOM_COLLECTION_INSTANCES)?;
            let filtre = doc! {"instance_id": &instance_id};
            match collection_instances.find_one(filtre, None).await? {
                Some(inner) => match inner.filehost_id {
                    Some(inner) => Some(inner),
                    None => {
                        // Check if there is a filehost directly on this instance
                        let filtre_filehosts = doc! {"instance_id": &instance_id, "deleted": false};
                        match collection_filehosts.find_one(filtre_filehosts, None).await? {
                            Some(inner) => Some(inner.filehost_id),
                            None => None
                        }
                    }
                },
                None => None
            }
        }
    };

    let filehost_id = match filehost_id {
        Some(inner) => Some(inner),  // Alrady got it
        None => {
            // Load the default filehost_id
            let collection_configuration = middleware.get_collection_typed::<FilehostingCongurationRow>(NOM_COLLECTION_FILEHOSTINGCONFIGURATION)?;
            let filtre = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT};
            match collection_configuration.find_one(filtre, None).await? {
                Some(inner) => Some(inner.value),
                None => None
            }
        }
    };

    let filtre = match filehost_id.as_ref() {
        Some(inner) => doc!{"filehost_id": inner, "deleted": false},
        None => doc!{"deleted": false, "external_url": {"$exists": true}}  // Pick random with external_url if any available
    };
    match collection_filehosts.find_one(filtre, None).await? {
        Some(inner) => {
            let filehost: RequeteFilehostItem = inner.into();
            Ok(Some(middleware.build_reponse(RequestFilehostForInstanceResponse { ok: true, filehost })?.0))
        }
        None => {
            Ok(Some(middleware.reponse_err(Some(404), None, Some("no filehost available"))?))
        }
    }

}

#[derive(Deserialize)]
struct FilehostForExternalRequest {
    instance_id: Option<String>,
    filehost_id: Option<String>,
}

#[derive(Serialize)]
struct RequestFilehostForExternalResponse {
    ok: bool,
    url_external: String,
    tls_external: Option<String>,
}

async fn request_filehost_for_external<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let message_ref = message.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let requete: FilehostForInstanceRequest = message_contenu.deserialize()?;

    // Select the instance_id
    let instance_id = requete.instance_id;

    let collection_filehosts = middleware.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;

    // Identify the filehost_id from the instance_id if possible
    let filehost_id = match requete.filehost_id {
        Some(inner) => Some(inner),  // Filehost provided
        None => match instance_id {
            Some(instance_id) => {
                // Check if instance configuration overrides with filehost_id
                let collection_instances = middleware.get_collection_typed::<PresenceMonitor>(NOM_COLLECTION_INSTANCES)?;
                let filtre = doc! {"instance_id": &instance_id};
                match collection_instances.find_one(filtre, None).await? {
                    Some(inner) => match inner.filehost_id {
                        Some(inner) => Some(inner),
                        None => {
                            // Check if there is a filehost directly on this instance
                            let filtre_filehosts = doc! {"instance_id": &instance_id, "deleted": false};
                            match collection_filehosts.find_one(filtre_filehosts, None).await? {
                                Some(inner) => Some(inner.filehost_id),
                                None => None
                            }
                        }
                    },
                    None => None
                }
            },
            None => None
        }
    };

    let filehost_id = match filehost_id {
        Some(inner) => Some(inner),  // Alrady got it
        None => {
            // Load the default filehost_id
            let collection_configuration = middleware.get_collection_typed::<FilehostingCongurationRow>(NOM_COLLECTION_FILEHOSTINGCONFIGURATION)?;
            let filtre = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT};
            match collection_configuration.find_one(filtre, None).await? {
                Some(inner) => Some(inner.value),
                None => None
            }
        }
    };

    let filtre = match filehost_id.as_ref() {
        Some(inner) => doc!{"filehost_id": inner, "external_url": {"$exists": true}, "deleted": false},
        None => doc!{"deleted": false, "external_url": {"$exists": true}}  // Pick random with external_url if any available
    };

    match collection_filehosts.find_one(filtre, None).await? {
        Some(inner) => {
            let url_external = inner.url_external.expect("url_external");
            Ok(Some(middleware.build_reponse(RequestFilehostForExternalResponse { ok: true, url_external, tls_external: inner.tls_external })?.0))
        }
        None => {
            Ok(Some(middleware.reponse_err(Some(404), None, Some("no filehost available"))?))
        }
    }
}
