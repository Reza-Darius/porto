use porto::config::PortoConfig;

pub async fn run_proxy(config: PortoConfig) {
    porto::server::run(&config).await;
}
