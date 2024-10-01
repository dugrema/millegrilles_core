use log::{debug, warn};
use millegrilles_common_rust::bson::{Bson, bson, DateTime as DateTimeBson, doc};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction_v2;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::json;
use webauthn_rs::prelude::Passkey;
use crate::maitredescomptes_constants::*;
use crate::maitredescomptes_manager::MaitreDesComptesManager;
use crate::maitredescomptes_structs::{CompteUsager, EvenementMajCompteUsager, TransactionMajUsagerDelegations};
use crate::webauthn::CredentialWebauthn;

pub async fn emettre_maj_compte_usager<M,S>(middleware: &M, user_id: S, action: Option<&str>)
                                            -> Result<(), millegrilles_common_rust::error::Error>
where
    M: GenerateurMessages + MongoDao,
    S: AsRef<str>
{
    let user_id = user_id.as_ref();
    let action = match action {
        Some(inner) => inner,
        None => EVENEMENT_MAJ_COMPTE_USAGER
    };

    let filtre = doc! {CHAMP_USER_ID: user_id};
    let collection = middleware.get_collection_typed::<EvenementMajCompteUsager>(NOM_COLLECTION_USAGERS)?;
    if let Some(compte) = collection.find_one(filtre, None).await? {
        debug!("emettre_maj_compte_usager compte : {:?}", compte);
        let routage = RoutageMessageAction::builder(DOMAIN_NAME, action, vec![Securite::L3Protege])
            .build();
        middleware.emettre_evenement(routage, &compte).await?;

        // Emettre message pour l'usager (e.g. maitredescomptes)
        let routage = RoutageMessageAction::builder(DOMAIN_NAME, action, vec![Securite::L2Prive])
            .partition(&compte.user_id)
            .build();
        middleware.emettre_evenement(routage, &compte).await?;
    }
    Ok(())
}

pub async fn sauvegarder_credential<M,S,T>(middleware: &M, user_id: S, hostname: T, passkey_credential: Passkey, supprimer_registration: bool)
                                       -> Result<CredentialWebauthn, millegrilles_common_rust::error::Error>
where M: MongoDao, S: Into<String>, T: Into<String>
{
    let user_id = user_id.into();
    let hostname = hostname.into();

    // Filtre pour supprimer registration pour user_id/hostname
    let filtre_delete = doc!( CHAMP_USER_ID: &user_id, "hostname": &hostname, "type_challenge": "registration" );

    // Inserer credential
    let cred = {
        let mut cred = CredentialWebauthn {
            user_id,
            hostname,
            passkey: passkey_credential,
            date_creation: Some(DateTimeBson::now()),
            derniere_utilisation: None,
            reset_cles: None,
        };
        let collection_credentials = middleware.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
        let cred_doc = convertir_to_bson(&cred)?;
        collection_credentials.insert_one(cred_doc, None).await?;

        // Retirer champs qui ne sont pas utiles pour une transaction
        cred.date_creation = None;

        cred
    };

    if supprimer_registration {
        // Supprimer registration challenge
        let collection_challenges = middleware.get_collection(NOM_COLLECTION_CHALLENGES)?;
        collection_challenges.delete_one(filtre_delete, None).await?;
    }

    Ok(cred)
}

pub async fn charger_compte_user_id<M, S>(middleware: &M, user_id: S)
                                      -> Result<Option<CompteUsager>, millegrilles_common_rust::error::Error>
where
    M: MongoDao,
    S: AsRef<str>
{
    let filtre = doc! {CHAMP_USER_ID: user_id.as_ref()};
    let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    match collection.find_one(filtre, None).await? {
        Some(c) => {
            let compte: CompteUsager = convertir_bson_deserializable(c)?;
            Ok(Some(compte))
        },
        None => Ok(None)
    }
}

pub async fn commande_maj_usager_delegations<M>(middleware: &M, message: MessageValide, gestionnaire: &MaitreDesComptesManager)
                                                -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer commande_maj_usager_delegations : {:?}", &message.type_message);

    // Valider contenu
    let (message_id, commande) = {
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        let commande: TransactionMajUsagerDelegations = message_contenu.deserialize()?;
        let message_id = message_ref.id.to_owned();
        (message_id, commande)
    };
    let user_id = commande.user_id.as_str();

    // Commande valide, on sauvegarde et traite la transaction
    // let uuid_transaction = message_ref.id;
    sauvegarder_traiter_transaction_v2(middleware, message, gestionnaire).await?;
    // let transaction: TransactionImpl = message.try_into()?;
    // let _ = transaction_maj_usager_delegations(middleware, message.try_into()?).await?;
    // marquer_transaction(middleware, NOM_COLLECTION_TRANSACTIONS, &message_id, EtatTransaction::Complete).await?;

    // Charger le document de compte et retourner comme reponse
    let reponse = match charger_compte_user_id(middleware, commande.user_id.as_str()).await? {
        Some(compte) => serde_json::to_value(&compte)?,
        None => json!({"ok": false, "err": "Compte usager introuvable apres maj"})  // Compte
    };

    if let Err(e) = emettre_maj_compte_usager(middleware, &commande.user_id, None).await {
        warn!("commande_maj_usager_delegations Erreur emission evenement maj : {:?}", e);
    }

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}
