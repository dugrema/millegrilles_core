pub const DOMAIN_NAME: &str = "CoreTopologie";
pub const NOM_COLLECTION_DOMAINES: &str = "CoreTopologie/domaines";
pub const NOM_COLLECTION_INSTANCES: &str = "CoreTopologie/instances";
pub const NOM_COLLECTION_NOEUDS: &str = NOM_COLLECTION_INSTANCES;
pub const NOM_COLLECTION_MILLEGRILLES: &str = "CoreTopologie/millegrilles";
pub const NOM_COLLECTION_MILLEGRILLES_ADRESSES: &str = "CoreTopologie/millegrillesAdresses";
pub const NOM_COLLECTION_FICHIERS: &str = "CoreTopologie/fichiers";
pub const COLLECTION_NAME_TRANSACTIONS: &str = DOMAIN_NAME;
pub const NOM_COLLECTION_TOKENS: &str = "CoreTopologie/tokens";
pub const NOM_COLLECTION_FILEHOSTS: &str = "CoreTopologie/filehosts";
pub const NOM_COLLECTION_FILECONTROLERS: &str = "CoreTopologie/filecontrolers";
pub const NOM_COLLECTION_FILEHOSTINGCONFIGURATION: &str = "CoreTopologie/filehostingConfiguration";
// pub const NOM_COLLECTION_FILEHOSTING_VISITS: &str = "CoreTopologie/filehostingVisits";
// pub const NOM_COLLECTION_FILEHOSTING_CLAIMS: &str = "CoreTopologie/filehostingClaims";
pub const NOM_COLLECTION_FILEHOSTING_FUUIDS: &str = "CoreTopologie/filehostingFuuids";

pub const DOMAINE_PRESENCE_NOM: &str = "CoreTopologie";
pub const DOMAINE_FICHIERS: &str = "fichiers";

pub const NOM_Q_TRANSACTIONS: &str = "CoreTopologie/transactions";
pub const NOM_Q_VOLATILS: &str = "CoreTopologie/volatils";
pub const NOM_Q_TRIGGERS: &str = "CoreTopologie/triggers";

pub const REQUETE_APPLICATIONS_DEPLOYEES: &str = "listeApplicationsDeployees";
pub const REQUETE_USERAPPS_DEPLOYEES: &str = "listeUserappsDeployees";

pub const REQUETE_LISTE_DOMAINES: &str = "listeDomaines";
pub const REQUETE_LISTE_NOEUDS: &str = "listeNoeuds";
pub const REQUETE_RESOLVE_IDMG: &str = "resolveIdmg";
pub const REQUETE_FICHE_MILLEGRILLE: &str = "ficheMillegrille";
pub const REQUETE_APPLICATIONS_TIERS: &str = "applicationsTiers";
pub const REQUETE_CONSIGNATION_FICHIERS: &str = "getConsignationFichiers";
pub const REQUETE_CONFIGURATION_FICHIERS: &str = "getConfigurationFichiers";
pub const REQUETE_GET_CLE_CONFIGURATION: &str = "getCleConfiguration";
pub const REQUETE_GET_TOKEN_HEBERGEMENT: &str = "getTokenHebergement";
pub const REQUETE_GET_CLEID_BACKUP_DOMAINE: &str = "getCleidBackupDomaine";
pub const REQUETE_GET_FILEHOSTS: &str = "getFilehosts";
pub const REQUETE_GET_FILECONTROLERS: &str = "getFilecontrolers";
pub const REQUETE_GET_FILEHOST_FOR_EXTERNAL: &str = "getFilehostForExternal";

pub const TRANSACTION_DOMAINE: &str = "domaine";
pub const TRANSACTION_INSTANCE: &str = "instance";
pub const TRANSACTION_MONITOR: &str = TRANSACTION_INSTANCE;
pub const TRANSACTION_SUPPRIMER_INSTANCE: &str = "supprimerInstance";
pub const TRANSACTION_SET_FICHIERS_PRIMAIRE: &str = "setFichiersPrimaire";
pub const TRANSACTION_CONFIGURER_CONSIGNATION: &str = "configurerConsignation";
pub const TRANSACTION_SET_CONSIGNATION_INSTANCE: &str = "setConsignationInstance";
pub const TRANSACTION_SUPPRIMER_CONSIGNATION_INSTANCE: &str = "supprimerConsignation";
pub const TRANSACTION_FILEHOST_ADD: &str = "filehostAdd";
pub const TRANSACTION_FILEHOST_UPDATE: &str = "filehostUpdate";
pub const TRANSACTION_FILEHOST_DELETE: &str = "filehostDelete";
pub const TRANSACTION_FILEHOST_RESTORE: &str = "filehostRestore";

pub const COMMANDE_AJOUTER_CONSIGNATION_HEBERGEE: &str = "ajouterConsignationHebergee";
pub const COMMANDE_SET_CLEID_BACKUP_DOMAINE: &str = "setCleidBackupDomaine";
pub const COMMANDE_FILE_VISIT: &str = "fileVisit";
pub const COMMANDE_CLAIM_AND_FILEHOST_VISITS_FOR_FUUIDS: &str = "claimAndFilehostVisits";

pub const EVENEMENT_PRESENCE_MONITOR: &str = "presence";
pub const EVENEMENT_PRESENCE_FICHIERS: &str = EVENEMENT_PRESENCE_MONITOR;
pub const EVENEMENT_FICHE_PUBLIQUE: &str = "fichePublique";
pub const EVENEMENT_INSTANCE_SUPPRIMEE: &str = "instanceSupprimee";
pub const EVENEMENT_INSTANCE_CONSIGNATION_SUPPRIMEE: &str = "instanceConsignationSupprimee";
pub const EVENEMENT_APPLICATION_DEMARREE: &str = "applicationDemarree";
pub const EVENEMENT_APPLICATION_ARRETEE: &str = "applicationArretee";
pub const EVENEMENT_MODIFICATION_CONSIGNATION: &str = "modificationConsignation";
pub const EVENEMENT_FILEHOST_USAGE: &str = "filehostUsage";
pub const EVENEMENT_FILEHOST_NEWFUUID: &str = "filehostNewFuuid";

pub const EVENEMENT_FILEHOST_EVENT: &str = "filehost";
pub const EVENEMENT_FILEHOST_EVENTNEW: &str = "new";
pub const EVENEMENT_FILEHOST_EVENTUPDATE: &str = "update";
pub const EVENEMENT_FILEHOST_EVENTDELETE: &str = "delete";

pub const INDEX_DOMAINE: &str = "domaine";
pub const INDEX_NOEUDS: &str = "noeuds";
pub const INDEX_IDMG: &str = "idmg";
pub const INDEX_ADRESSES: &str = "adresses";
pub const INDEX_ADRESSE: &str = "adresse";
pub const INDEX_INSTANCE_ID: &str = "instance_id";

pub const CHAMP_DOMAINE: &str = "domaine";
pub const CHAMP_INSTANCE_ID: &str = "instance_id";
pub const CHAMP_NOEUD_ID: &str = CHAMP_INSTANCE_ID;
pub const CHAMP_ADRESSE: &str = "adresse";
pub const CHAMP_ADRESSES: &str = "adresses";
pub const CHAMP_CONSIGNATION_ID: &str = "consignation_id";

pub const ADRESSE_PREFERENCE_PRIMAIRE: u8 = 1;
pub const ADRESSE_PREFERENCE_SECONDAIRE: u8 = 2;

pub const ADRESSE_NATURE_DNS: &str = "dns";
pub const ADRESSE_NATURE_IP4: &str = "ip4";
pub const ADRESSE_NATURE_IP6: &str = "ip6";
pub const ADRESSE_NATURE_ONION: &str = "onion";

pub const DEFAULT_CONSIGNATION_URL: &str = "https://fichiers:1443";

pub const FIELD_CONFIGURATION_FILEHOST_DEFAULT: &str = "filehost.default";
pub const FIELD_LAST_CLAIM_DATE: &str = "last_claim_date";
