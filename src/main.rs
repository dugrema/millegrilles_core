mod domaines_middleware;
mod sousdomaine_pki;

use crate::domaines_middleware::build;
use log::{info};

fn main() {
    env_logger::init();
    info!("Demarrer le contexte");
    executer()
}

// #[tokio::main(flavor = "current_thread")]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
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
