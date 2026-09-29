use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::middleware_db::MiddlewareDb;
use millegrilles_common_rust::middleware_db_v2::preparer as preparer_middleware_db_v2;
use millegrilles_common_rust::tokio::task::JoinHandle;


/// Structure avec hooks interne de preparation du middleware
pub struct MiddlewareHooks {
    // pub middleware: &'static MiddlewareDbPki,
    pub middleware: &'static MiddlewareDb,
    pub futures: FuturesUnordered<JoinHandle<()>>,
}

/// Version speciale du middleware avec un acces direct au sous-domaine Pki dans MongoDB
pub fn preparer_middleware_pki() -> MiddlewareHooks {
    let (middleware, futures) = preparer_middleware_db_v2().expect("preparer_middleware_db_v2");
    MiddlewareHooks { middleware, futures }
}
