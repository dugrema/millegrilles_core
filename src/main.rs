mod domaines_core;
mod ceduleur;
mod validateur_pki_mongo;
mod webauthn;

// Domaines Core
mod core_catalogues;
mod core_maitredescomptes;
mod core_pki;
mod core_topologie;
mod core_backup;

use crate::domaines_core::build;
use log::{info};
use millegrilles_common_rust::tokio as tokio;

fn main() {
    env_logger::init();
    info!("Demarrer le contexte");
    executer()
}

// #[tokio::main(flavor = "current_thread")]
#[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn executer() {
    build().await
}

#[cfg(test)]
pub mod test_setup {
    use log::{debug};

    pub fn setup(nom: &str) {
        let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
