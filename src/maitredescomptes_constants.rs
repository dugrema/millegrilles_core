pub const DOMAIN_NAME: &str = "CoreMaitreDesComptes";
pub const COLLECTION_NAME_TRANSACTIONS: &str = DOMAIN_NAME;
pub const NOM_COLLECTION_USAGERS: &str = "CoreMaitreDesComptes/usagers";
pub const NOM_COLLECTION_RECOVERY: &str = "CoreMaitreDesComptes/recovery";
pub const NOM_COLLECTION_ACTIVATIONS: &str = "CoreMaitreDesComptes/activations";
pub const NOM_COLLECTION_CHALLENGES: &str = "CoreMaitreDesComptes/challenges";
pub const NOM_COLLECTION_WEBAUTHN_CREDENTIALS: &str = "CoreMaitreDesComptes/webauthnCredentials";
pub const NOM_COLLECTION_TOTP_CREDENTIALS: &str = "CoreMaitreDesComptes/totpCredentials";
pub const NOM_COLLECTION_COOKIES: &str = "CoreMaitreDesComptes/cookies";

pub const NOM_Q_TRANSACTIONS: &str = "CoreMaitreDesComptes/transactions";
pub const NOM_Q_VOLATILS: &str = "CoreMaitreDesComptes/volatils";
pub const NOM_Q_TRIGGERS: &str = "CoreMaitreDesComptes/triggers";

pub const REQUETE_CHARGER_USAGER: &str = "chargerUsager";
pub const REQUETE_LISTE_USAGERS: &str = "getListeUsagers";
pub const REQUETE_USERID_PAR_NOMUSAGER: &str = "getUserIdParNomUsager";
pub const REQUETE_GET_CSR_RECOVERY_PARCODE: &str = "getCsrRecoveryParcode";
pub const REQUETE_LISTE_PROPRIETAIRES: &str = "getListeProprietaires";
pub const REQUETE_COOKIE_USAGER: &str = "getCookieUsager";
pub const REQUETE_PASSKEYS_USAGER: &str = "getPasskeysUsager";
// const REQUETE_GET_TOKEN_SESSION: &str = "getTokenSession";

// const COMMANDE_CHALLENGE_COMPTEUSAGER: &str = "challengeCompteUsager";
pub const COMMANDE_SIGNER_COMPTEUSAGER: &str = "signerCompteUsager";
pub const COMMANDE_SIGNER_COMPTE_PAR_PROPRIETAIRE: &str = "signerCompteParProprietaire";
// const COMMANDE_ACTIVATION_TIERCE: &str = "activationTierce";
pub const COMMANDE_AJOUTER_CSR_RECOVERY: &str = "ajouterCsrRecovery";
pub const COMMANDE_AUTHENTIFIER_WEBAUTHN: &str = "authentifierWebauthn";
pub const COMMAND_AUTHENTICATE_TOTP: &str = "authenticateTotp";
pub const COMMANDE_GENERER_CHALLENGE: &str = "genererChallenge";
pub const COMMAND_GENERATE_OTP: &str = "generateOtp";
pub const COMMANDE_SUPPRIMER_COOKIE: &str = "supprimerCookieSession";

pub const TRANSACTION_INSCRIRE_USAGER: &str = "inscrireUsager";
pub const TRANSACTION_AJOUTER_CLE: &str = "ajouterCle";
pub const TRANSACTION_SUPPRIMER_USAGER: &str = "supprimerUsager";
pub const TRANSACTION_MAJ_USAGER_DELEGATIONS: &str = "majUsagerDelegations";
pub const TRANSACTION_AJOUTER_DELEGATION_SIGNEE: &str = "ajouterDelegationSignee";
pub const TRANSACTION_SUPPRIMER_CLES: &str = "supprimerCles";
pub const TRANSACTION_RESET_WEBAUTHN_USAGER: &str = "resetWebauthnUsager";
pub const TRANSACTION_REGISTER_OTP: &str = "registerOtp";

pub const EVENEMENT_EVICT_USAGER: &str = "evictUsager";
pub const EVENEMENT_MAJ_COMPTE_USAGER: &str = "majCompteUsager";
pub const EVENEMENT_INSCRIRE_COMPTE_USAGER: &str = "inscrireCompteUsager";
pub const EVENEMENT_SUPPRIMER_COMPTE_USAGER: &str = "supprimerCompteUsager";

pub const INDEX_ID_USAGER: &str = "idusager_unique";
pub const INDEX_NOM_USAGER: &str = "nomusager_unique";
pub const INDEX_RECOVERY_UNIQUE: &str = "recovery_code_unique";
pub const INDEX_CHALLENGES_UNIQUE: &str = "challenges_unique";
pub const INDEX_WEBAUTHN_UNIQUE: &str = "webauthn_unique";
pub const INDEX_COOKIE_UNIQUE: &str = "cookie_unique";

pub const CHAMP_USER_ID: &str = "userId";
pub const CHAMP_USAGER_NOM: &str = "nomUsager";
pub const CHAMP_COMPTE_PRIVE: &str = "compte_prive";
pub const CHAMP_DELEGATION_GLOBALE: &str = "delegation_globale";
pub const CHAMP_DELEGATION_DATE: &str = "delegations_date";
pub const CHAMP_DELEGATION_VERSION: &str = "delegations_version";
pub const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
pub const CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK: &str = "activations_par_fingerprint_pk";
pub const CHAMP_WEBAUTHN: &str = "webauthn";
pub const CHAMP_WEBAUTHN_HOSTNAMES: &str = "webauthn_hostnames";
pub const CHAMP_CODE: &str = "code";
pub const CHAMP_TYPE_CHALLENGE_WEBAUTHN: &str = "type_challenge";
pub const CHAMP_DERNIER_AUTH: &str = "dernier_auth";

pub const DELEGATION_PROPRIETAIRE: &str = "proprietaire";