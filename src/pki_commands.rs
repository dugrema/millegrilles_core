use log::{debug, error, warn};

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::common_messages::DemandeSignature;
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, DELEGATION_GLOBALE_PROPRIETAIRE, ROLE_MAITRE_DES_CLES, ROLE_MAITRE_DES_CLES_VOLATIL};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{start_transaction_regular, MongoDao};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::reqwest;
use serde::{Deserialize, Serialize};

use crate::pki_constants::*;


pub async fn consommer_commande_pki<M>(middleware: &M, m: MessageValide)
                                       -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: Middleware
{
    debug!("Consommer commande : {:?}", &m.message);

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.
    let (domaine, action) = match &m.type_message {
        TypeMessageOut::Commande(r) => {
            (r.domaine.clone(), r.action.clone())
        }
        _ => {
            Err(format!("consommer_commande Mauvais type de message"))?
        }
    };

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
        true => Ok(()),
        false => {
            match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
                true => Ok(()),
                false => Err(String::from("core_pki.consommer_commande Autorisation invalide (aucun exchange, pas delegation globale)"))
            }
        },
    }?;

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    let result = match action.as_str() {
        // Commandes standard
        // COMMANDE_BACKUP_HORAIRE => backup(middleware.as_ref(), DOMAINE_NOM, NOM_COLLECTION_TRANSACTIONS, true).await,
        // COMMANDE_RESTAURER_TRANSACTIONS => restaurer_transactions(middleware.clone()).await,
        // COMMANDE_RESET_BACKUP => reset_backup_flag(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS).await,

        // Commandes specifiques au domaine
        PKI_COMMANDE_SAUVEGARDER_CERTIFICAT | PKI_COMMANDE_NOUVEAU_CERTIFICAT => traiter_commande_sauvegarder_certificat(middleware, m, &mut session).await,
        PKI_COMMANDE_SIGNER_CSR => commande_signer_csr(middleware, m).await,

        // Commandes inconnues
        _ => Err(format!("Commande Pki inconnue : {}, message dropped", action))?,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSauvegarderCertificat {
    chaine_pem: Vec<String>,
    ca: Option<String>
}

pub async fn traiter_commande_sauvegarder_certificat<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let domaine = match &m.type_message {
        TypeMessageOut::Evenement(r) |
        TypeMessageOut::Commande(r) => {
            r.domaine.clone()
        }
        _ => Err("traiter_commande_sauvegarder_certificat Mauvais type de message (doit etre Evenement ou Commande)")?
    };

    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let commande: CommandeSauvegarderCertificat = message_contenu.deserialize()?;

    let ca_pem = match &commande.ca {
        Some(c) => Some(c.as_str()),
        None => None
    };
    let enveloppe = middleware.charger_enveloppe(&commande.chaine_pem, None, ca_pem).await?;
    debug!("traiter_commande_sauvegarder_certificat Certificat {} traite", enveloppe.fingerprint()?);

    if let TypeMessageOut::Evenement(_) = m.type_message {
        // Sauvegarde de l'evenement de certificat - aucune reponse
        Ok(None)
    } else {
        let reponse = middleware.reponse_ok(None, None)?;
        Ok(Some(reponse))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCertificatSigne {
    ok: bool,
    certificat: Vec<String>,
}

async fn valider_demande_signature_csr<'a, M>(middleware: &M, m: &'a MessageValide)
                                              -> Result<(), millegrilles_common_rust::error::Error>
where M: GenerateurMessages + IsConfigNoeud
{
    // let mut message = None;

    // Valider format de la demande avec mapping
    let message_ref = m.message.parse()?;
    let message_contenu = message_ref.contenu()?;
    let message_parsed: DemandeSignature = message_contenu.deserialize()?;
    let certificat = m.certificat.as_ref();

    if certificat.verifier_roles(vec![RolesCertificats::Instance])? {
        if certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
            debug!("valider_demande_signature_csr Demande de CSR signee par une instance 3.protege ou 4.secure, demande approuvee");
            // message = Some(Cow::Borrowed(&m.message.parsed));
            return Ok(())
        } else if certificat.verifier_exchanges(vec![Securite::L2Prive])? {
            debug!("valider_demande_signature_csr Demande de CSR signee par une instance 2.prive");
            // message = Some(Cow::Borrowed(&m.message.parsed));
            return Ok(())
        } else if certificat.verifier_exchanges(vec![Securite::L1Public])? {
            debug!("valider_demande_signature_csr Demande de CSR signee par une instance 1.public, demande approuvee");
            // message = Some(Cow::Borrowed(&m.message.parsed));
            return Ok(())
        } else {
            error!("valider_demande_signature_csr Demande de CSR signee par une instance sans exchanges, REFUSE");
        }
    } else if certificat.verifier_roles(vec![RolesCertificats::MaitreDesClesConnexion])? {
        if certificat.verifier_exchanges(vec![Securite::L4Secure])? {
            // Un certificat de maitre des cles connexion (4.secure) supporte une cle volatile

            // Validation des valeurs
            if message_parsed.domaines.is_some() || message_parsed.dns.is_some() {
                // warn!("valider_demande_signature_csr Signature certificat maitre des cles volatil refuse (exchanges/domaines/dns presents)");
                Err("valider_demande_signature_csr Signature certificat maitre des cles volatil refuse (exchanges/domaines/dns presents)")?
            }

            // Verifier que le role demande est MaitreDesClesConnexionVolatil
            match message_parsed.roles {
                Some(r) => {
                    let role_maitre_des_cles_string = ROLE_MAITRE_DES_CLES.to_string();
                    let role_maitre_des_cles_volatil_string = ROLE_MAITRE_DES_CLES_VOLATIL.to_string();
                    if r.len() == 2 && r.contains(&role_maitre_des_cles_string) && r.contains(&role_maitre_des_cles_volatil_string) {
                        // message = Some(Cow::Borrowed(&m.message.parsed))
                        return Ok(())
                    } else {
                        warn!("valider_demande_signature_csr Signature certificat maitre des cles volatil refuse (mauvais role)");
                        // let e = json!({"ok": false, "err": "Mauvais role"});
                        // return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
                        Err("Mauvais role")?
                    }
                },
                None => {
                    // let e = json!({"ok": false, "err": "Aucun role"});
                    // return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
                    Err("Aucun role")?
                }
            }
        } else {
            error!("valider_demande_signature_csr Demande de CSR signee par une un certificat MaitreDesClesConnexion de niveau != 4.secure, REFUSE");
            // let e = json!({"ok": false, "err": "niveau != 4.secure"});
            // return Ok(Some(Cow::Owned(middleware.formatter_reponse(e, None)?)));
            Err("niveau != 4.secure")?
        }
    } else if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        debug!("valider_demande_signature_csr Demande de CSR signee par une delegation globale (proprietaire), demande approuvee");
        // message = Some(Cow::Borrowed(&m.message.parsed));
        return Ok(())
    } else if certificat.verifier_exchanges(vec![Securite::L4Secure])? {
        debug!("valider_demande_signature_csr Demande de CSR signee pour un domaine");
        if message_parsed.domaines.is_some() || message_parsed.exchanges.is_some() {
            Err(String::from("domaines/exchanges/roles doivent etre vide"))?;
        }

        let extensions = certificat.extensions()?;
        let domaines = match &extensions.domaines {
            Some(d) => d,
            None => {
                Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee, demandeur sans domaines : {:?}", certificat))?
            }
        };

        let roles = match &message_parsed.roles {
            Some(r) => r,
            None => {
                Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee, demande sans roles : {:?}", certificat))?
            }
        };

        // S'assurer que tous les roles demandes sont l'equivalent de domaines en minuscules.
        let domaines_minuscules: Vec<String> = domaines.iter().map(|d| d.to_lowercase()).collect();
        for role in roles {
            debug!("Role {} in roles : {:?}?", role, domaines_minuscules);
            if ! domaines_minuscules.contains(role) {
                Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee, role {} non autorise pour domaines : {:?}", role, certificat))?
            }
        }

        // message = Some(Cow::Borrowed(&m.message.parsed));
        return Ok(())
    } else {
        Err(format!("valider_demande_signature_csr Demande de signature de CSR refusee pour demandeur qui n'est pas autorise : {:?}", certificat))?;
    }

    Err(String::from("Acces refuse (default)"))?
}

/// Commande de relai vers le certissuer pour signer un CSR. La commande doit etre
/// * signee par une delegation globale (e.g. proprietaire), ou
/// * signee par un monitor du meme niveau pour un role (e.g. monitor prive pour messagerie ou postmaster), ou
/// * etre un renouvellement pour les memes roles.
async fn commande_signer_csr<M>(middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: GenerateurMessages + IsConfigNoeud
{
    if let Err(e) = valider_demande_signature_csr(middleware, &m).await {
        let err_string = format!("Acces refuse : {:?}", e);
        return Ok(Some(middleware.reponse_err(None, None, Some(err_string.as_str()))?))
    }

    // let commande = match valider_demande_signature_csr(middleware, &m).await? {
    //     Some(c) => c,
    //     None => {
    //         // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Acces refuse"}), None)?))
    //         return Ok(Some(middleware.reponse_err(None, None, Some("Acces refuse"))?))
    //     }
    // };

    let config = middleware.get_configuration_noeud();
    let certissuer_url = match config.certissuer_url.as_ref() {
        Some(inner) => inner,
        None => Err(format!("core_maitredescomptes.signer_certificat_usager Certissuer URL manquant"))?
    };

    let client = reqwest::Client::builder()
        .timeout(core::time::Duration::new(7, 0))
        .build()?;

    let mut url_post = certissuer_url.clone();
    url_post.set_path("signerModule");

    // On retransmet le message recu tel quel
    match client.post(url_post).body(m.message.buffer).send().await {
        Ok(response) => {
            match response.status().is_success() {
                true => {
                    let reponse_json: ReponseCertificatSigne = response.json().await?;
                    debug!("commande_signer_csr Reponse certificat : {:?}", reponse_json);
                    // return Ok(Some(middleware.formatter_reponse(reponse_json, None)?))
                    return Ok(Some(middleware.build_reponse(reponse_json)?.0))
                },
                false => {
                    debug!("core_maitredescomptes.signer_certificat_usager Erreur reqwest : status {}", response.status());
                }
            }
        },
        Err(e) => {
            debug!("core_maitredescomptes.signer_certificat_usager Erreur reqwest : {:?}", e);
        }
    };

    // Une erreur est survenue dans le post, fallback vers noeuds 4.secure (si presents)
    warn!("Echec connexion a certissuer local, relai vers instances 4.secure");

    Ok(Some(
        middleware.reponse_err(None, None, Some("Erreur signature : aucun signateur disponible ou refus"))?
    ))
}
