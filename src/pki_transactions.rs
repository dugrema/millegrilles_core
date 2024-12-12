use log::debug;
use millegrilles_common_rust::certificats::{charger_enveloppe, ValidateurX509};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::upsert_certificat;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::serde_json;
use serde::{Deserialize, Serialize};

use crate::pki_constants::*;
use crate::pki_structs::CorePkiCollectionRow;

pub async fn aiguillage_transaction_pki<M, T>(middleware: &M, transaction: T, session: &mut ClientSession)
                                              -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: TryInto<TransactionValide>
{
    let transaction = match transaction.try_into() {
        Ok(inner) => inner,
        Err(_) => Err(String::from("aiguillage_transaction Erreur try_into"))?
    };

    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => {
            let action = match inner.action.as_ref() {
                Some(action) => action.to_string(),
                None => Err(String::from("aiguillage_transaction Action manquante"))?
            };
            action
        },
        None => Err(String::from("aiguillage_transaction Routage manquant"))?
    };

    match action.as_str() {
        PKI_COMMANDE_NOUVEAU_CERTIFICAT | PKI_COMMANDE_SAUVEGARDER_CERTIFICAT => sauvegarder_certificat(middleware, transaction, session).await,
        _ => Err(format!("Transaction {} est de type non gere : {}", transaction.transaction.id, action))?,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCertificat {
    pem: String,
    ca: Option<String>
}

impl From<CorePkiCollectionRow> for TransactionCertificat {
    fn from(value: CorePkiCollectionRow) -> Self {
        Self {
            pem: value.certificat.join("\n"),
            ca: value.ca,
        }
    }
}

async fn sauvegarder_certificat<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
                                   -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Sauvegarder certificat recu via transaction");

    // let escaped_contenu: String = serde_json::from_str(format!("\"{}\"", transaction.transaction.contenu).as_str())?;
    let contenu: TransactionCertificat = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(c) => Ok(c),
        Err(e) => Err(format!("core_pki.sauvegarder_certificat Erreur conversion transaction en TransactionCertificat : {:?}", e)),
    }?;
    let certificat_pems = contenu.pem;
    let ca_pem = match &contenu.ca {
        Some(ca) => Some(ca.as_str()),
        None => None
    };

    // Utiliser validateur.charger_enveloppe. Va automatiquement sauvegarder le certificat (si manquant).
    let enveloppe = match charger_enveloppe(certificat_pems.as_str(), None, ca_pem) {
        Ok(e) => Ok(e),
        Err(e) => Err(format!("Erreur preparation enveloppe pour sauvegarder certificat : {:?}", e)),
    }?;

    let collection_doc_pki = middleware.get_collection(COLLECTION_CERTIFICAT_NOM)?;
    upsert_certificat(&enveloppe, collection_doc_pki, Some(false)).await?;

    Ok(None)
}
