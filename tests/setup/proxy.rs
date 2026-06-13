use std::sync::Arc;

use porto::config::PortoConfig;

pub async fn run_proxy(config: Arc<PortoConfig>) {
    porto::server::run(&config).await.unwrap();
}
