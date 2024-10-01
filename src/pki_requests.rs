use log::{debug, error, warn};
use millegrilles_common_rust::bson::{doc, Document};
use serde::Deserialize;

use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::constantes::{PKI_DOCUMENT_CHAMP_CERTIFICAT, PKI_DOCUMENT_CHAMP_FINGERPRINT};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::middleware::{formatter_message_certificat};
use millegrilles_common_rust::serde_json::json;
use crate::pki_constants::*;

pub async fn consommer_requete_pki<M>(middleware: &M, m: MessageValide)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &m.message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.
    let (domaine, action) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_requete Mauvais type de message"))?
        }
    };

    match domaine.as_str() {
        DOMAINE_LEGACY_NOM | DOMAIN_NAME => match action.as_str() {
            PKI_REQUETE_CERTIFICAT => requete_certificat(middleware, m).await,
            PKI_REQUETE_CERTIFICAT_PAR_PK => requete_certificat_par_pk(middleware, m).await,
            _ => {
                error!("Message requete action inconnue : {}. Message dropped.", action);
                Ok(None)
            },
        },
        DOMAINE_CERTIFICAT_NOM => requete_certificat(middleware, m).await,
        _ => {
            error!("Message requete domaine inconnu : '{}'. Message dropped.", domaine);
            Ok(None)
        },
    }
}

#[derive(Clone, Deserialize)]
struct MessageFingerprint {
    fingerprint: String
}

async fn requete_certificat<M>(middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let (domaine, exchange) = match &m.type_message {
        TypeMessageOut::Requete(r) => {
            (r.domaine.clone(), r.exchanges.clone())
        }
        _ => Err("requete_certificat Mauvais type de message")?
    };

    let fingerprint = match domaine.as_str() {
        DOMAINE_NOM => {
            let message_ref = m.message.parse()?;
            let message_contenu = match message_ref.contenu() {
                Ok(inner) => inner,
                Err(e) => Err(format!("core_pki.requete_certificat Erreur contenu() : {:?}", e))?,
            };
            let message_fingerprint: Result<String, String> = match message_contenu.deserialize::<MessageFingerprint>() {
                Ok(inner) => Ok(inner.fingerprint),
                Err(e) => Err(format!("core_pki.requete_certificat Fingerprint manquant pour requete de certificat : {:?}", e))?,
            };
            message_fingerprint

            // match m.message.get_msg().contenu.get(PKI_DOCUMENT_CHAMP_FINGERPRINT) {
            //     Some(fp) => match fp.as_str() {
            //         Some(fp) => Ok(fp),
            //         None =>Err("Fingerprint manquant pour requete de certificat"),
            //     },
            //     None => Err("Fingerprint manquant pour requete de certificat"),
            // }
        },
        DOMAINE_CERTIFICAT_NOM => {
            //Ok(m.message.parsed.routage.action.as_str())
            let message_ref = m.message.parse()?;
            match message_ref.routage.as_ref() {
                Some(inner) => match inner.action.as_ref() {
                    Some(inner) => Ok(inner.to_string()),
                    None => Err(String::from("action manquante pour requete certificat (fingerprint)")),
                },
                None => Err(String::from("routage manquant pour requete certificat (fingerprint)")),
            }
        },
        _ => Err(String::from("Mauvais type de requete de certificat"))
    }?;

    let enveloppe = match middleware.get_certificat(fingerprint.as_str()).await {
        Some(inner) => inner,
        None => {
            debug!("Certificat inconnu : {}", fingerprint);
            // let reponse = middleware.formatter_reponse(json!({"ok": false, "code": 2, "err": "Certificat inconnu"}), None)?;
            let reponse = middleware.reponse_err(2, None, Some("Certificat inconnu"))?;
            return Ok(Some(reponse));
        }
    };

    debug!("Requete certificat sur fingerprint {} trouve", fingerprint);

    let reponse_value = formatter_message_certificat(enveloppe.as_ref())?;

    // C'est une requete sur le domaine certificat, on emet l'evenement.infocertificat.fingerprint
    // let exchanges = match exchange {
    //     Some(e) => { vec![Securite::try_from(e)?] },
    //     None => { vec![Securite::L1Public] }
    // };
    let mut builder_routage = RoutageMessageAction::builder("certificat", "infoCertificat", exchange);
    // if let Some(e) = m.exchange {
    //     let securite = Securite::try_from(e)?;
    //     builder_routage = builder_routage.exchanges(vec![securite]);
    // }

    let routage = builder_routage.build();
    if let Err(e) = middleware.emettre_evenement(routage, &reponse_value).await {
        warn!("Erreur emission evenement infocertificat pour {} : {}", fingerprint, e);
    }

    // let reponse = middleware.formatter_reponse(reponse_value, None)?;
    Ok(Some(middleware.build_reponse(reponse_value)?.0))
}

#[derive(Clone, Deserialize)]
struct MessageFingerprintPublicKey {
    fingerprint_pk: String
}

async fn requete_certificat_par_pk<M>(middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    // let fingerprint_pk = match m.message.get_msg().contenu.get(PKI_DOCUMENT_CHAMP_FINGERPRINT_PK) {
    let message_ref = m.message.parse()?;
    let message_contenu = match message_ref.contenu() {
        Ok(inner) => inner,
        Err(e) => Err(format!("requete_certificat_par_pk Erreur contenu() {:?}", e))?,
    };
    let message_fingerprint: MessageFingerprintPublicKey = match message_contenu.deserialize() {
        Ok(inner) => inner,
        Err(e) => Err(format!("requete_certificat_par_pk Erreur fingerprint pk absent/erreur mapping {:?}", e))?,
    };
    let fingerprint_pk = message_fingerprint.fingerprint_pk;

    let db = middleware.get_database()?;
    let collection = db.collection::<Document>(COLLECTION_CERTIFICAT_NOM);
    let filtre = doc! {
        PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: &fingerprint_pk,
    };
    let document_certificat = match collection.find_one(filtre, None).await {
        Ok(inner) => match inner {
            Some(inner) => Ok(inner),
            None => {
                debug!("Certificat par PK non trouve : {:?}", fingerprint_pk);
                let reponse_value = json!({"resultat": false});
                let reponse = middleware.build_reponse(reponse_value)?.0;
                return Ok(Some(reponse));
            },
        },
        Err(e) => Err(format!("Erreur chargement certificat par pk pour fingerprint pk : {}, {:?}", fingerprint_pk, e)),
    }?;

    let chaine_pem_doc= document_certificat.get(PKI_DOCUMENT_CHAMP_CERTIFICAT);
    let mut chaine_pem = Vec::new();
    for pem in chaine_pem_doc.expect("certificat").as_array().expect("array") {
        chaine_pem.push(String::from(pem.as_str().expect("str")));
    }
    let fingerprint = match document_certificat.get(PKI_DOCUMENT_CHAMP_FINGERPRINT) {
        Some(fp) => Some(fp.as_str().expect("fingerprint")),
        None => None,
    };

    let enveloppe = middleware.charger_enveloppe(&chaine_pem, fingerprint, None).await?;

    // Certificat trouve, repondre
    debug!("requete_certificat_par_pk repondre fingerprint {:?} pour fingerprint_pk {}", fingerprint, fingerprint_pk);
    // repondre_enveloppe(middleware, &m, enveloppe.as_ref()).await?;
    let reponse_value = formatter_message_certificat(enveloppe.as_ref())?;
    let reponse = middleware.build_reponse(reponse_value)?.0;
    debug!("requete_certificat_par_pk reponse pour fingerprint_pk {}\n{:?}", fingerprint_pk, reponse);
    Ok(Some(reponse))
}
