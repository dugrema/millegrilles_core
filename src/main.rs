// Domaines Core (obsolete)
// mod domaines_core;
// mod core_catalogues;
// mod core_maitredescomptes;
// mod core_pki;
// mod core_topologie;

// mod ceduleur;
mod validateur_pki_mongo;
mod webauthn;
mod error;
mod builder;
mod common;

// Maitre des comptes
mod maitredescomptes_manager;
mod maitredescomptes_commands;
mod maitredescomptes_requests;
mod maitredescomptes_events;
mod maitredescomptes_constants;
mod pki_constants;
mod pki_structs;
mod maitredescomptes_structs;
mod topology_manager;
mod topology_constants;
mod catalogues_manager;
mod catalogues_constants;
mod pki_manager;
mod maitredescomptes_transactions;
mod maitredescomptes_common;
mod pki_requests;
mod pki_commands;
mod pki_events;
mod pki_transactions;
mod topology_requests;
mod topology_structs;
mod topology_commands;
mod topology_common;
mod topology_events;
mod topology_transactions;
mod topology_maintenance;
mod catalogues_requests;
mod catalogues_commands;
mod catalogues_events;
mod catalogues_transactions;
mod catalogues_structs;
mod catalogues_maintenance;
mod pki_maintenance;

use log::{info};
use millegrilles_common_rust::tokio as tokio;

use crate::builder::run;

fn main() {
    env_logger::init();
    info!("Demarrer le contexte");
    executer()
}

#[tokio::main(flavor = "current_thread")]
// #[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn executer() { run().await }

#[cfg(test)]
pub mod test_setup {
    use log::{debug};

    pub fn setup(nom: &str) {
        let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
