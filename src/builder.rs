use crate::maitredescomptes_manager::{preparer_index_mongodb as preparer_index_mongodb_maitredescomptes, MaitreDesComptesManager};
use log::{debug, info, warn};
use millegrilles_common_rust::configuration::IsConfigNoeud;
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::static_cell::StaticCell;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::middleware::Middleware;
use crate::catalogues_manager::CataloguesManager;
use crate::pki_manager::{preparer_index_mongodb_pki, PkiManager};
use crate::topology_manager::{preparer_index_mongodb_topologie, TopologyManager};
use crate::validateur_pki_mongo::preparer_middleware_pki;

pub struct Managers {
    pub maitredescomptes: MaitreDesComptesManager,
    pub topology: TopologyManager,
    pub catalogues: CataloguesManager,
    pub pki: PkiManager,
}

static MANAGERS: StaticCell<Managers> = StaticCell::new();

pub async fn run() {

    let middleware_hooks = preparer_middleware_pki();
    let futures_middleware = middleware_hooks.futures;
    let middleware = middleware_hooks.middleware;

    let (_gestionnaires, futures_domaines) = initialiser(middleware).await
        .expect("initialiser domaines");

    // Test redis connection
    if let Some(redis) = middleware.redis.as_ref() {
        match redis.liste_certificats_fingerprints().await {
            Ok(fingerprints_redis) => {
                debug!("run liste_certificats_fingerprints Result : {:?}", fingerprints_redis);
            },
            Err(e) => warn!("run liste_certificats_fingerprints Error testing redis connection : {:?}", e)
        }
    }

    // Combiner les JoinHandles recus
    let mut futures = FuturesUnordered::new();
    futures.extend(futures_middleware);
    futures.extend(futures_domaines);

    // Le "await" maintien l'application ouverte. Des qu'une task termine, l'application arrete.
    futures.next().await;

    for f in &futures {
        f.abort()
    }

    info!("run Attendre {} tasks restantes", futures.len());
    while futures.len() > 0 {
        futures.next().await;
    }

    info!("run Fin execution");
}

/// Initialise le gestionnaire. Retourne les spawned tasks dans une liste de futures
/// (peut servir a canceller).
async fn initialiser<M>(middleware: &'static M) -> Result<
    (&'static Managers, FuturesUnordered<JoinHandle<()>>), CommonError>
where M: Middleware + IsConfigNoeud
{
    let managers = Managers {
        maitredescomptes: MaitreDesComptesManager {},
        topology: TopologyManager {},
        catalogues: CataloguesManager {},
        pki: PkiManager {},
    };

    let managers = MANAGERS.try_init(managers)
        .expect("staticcell MANAGERS");

    // Preparer la collection avec index
    let mut futures = FuturesUnordered::new();
    futures.extend(managers.maitredescomptes.initialiser(middleware).await
        .expect("maitredescomptes_manager initialiser"));
    futures.extend(managers.topology.initialiser(middleware).await
        .expect("topology_manager initialiser"));
    futures.extend(managers.catalogues.initialiser(middleware).await
        .expect("catalogues_manager initialiser"));
    futures.extend(managers.pki.initialiser(middleware).await
        .expect("pki_manager initialiser"));

    // Preparer des ressources additionnelles
    preparer_index_mongodb_maitredescomptes(middleware).await
        .expect("preparer_index_maitredescomptes_mongodb");
    preparer_index_mongodb_topologie(middleware).await
        .expect("preparer_index_mongodb_topologie");
    // preparer_index_mongodb_catalogues(middleware).await
    //     .expect("preparer_index_mongodb_catalogues");
    preparer_index_mongodb_pki(middleware).await
        .expect("preparer_index_mongodb_pki");

    Ok((managers, futures))
}
