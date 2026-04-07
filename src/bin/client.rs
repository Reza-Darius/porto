use std::env;

use anyhow::Result;
use futures::{StreamExt, stream::FuturesUnordered};
use hyper::{
    HeaderMap,
    header::{HOST, HeaderValue},
};
use tokio::time::Instant;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("proxy=error,tower_http=warn"))?,
        )
        .init();

    info!("starting client");
    let mut header = HeaderMap::new();
    header.insert(HOST, HeaderValue::from_str("RezaDarius.de")?);

    let client = reqwest::ClientBuilder::new()
        .https_only(true)
        .danger_accept_invalid_certs(true)
        .default_headers(header)
        .build()?;

    let mut futs = FuturesUnordered::new();
    let n_reqs = args
        .get(1)
        .map(|arg| arg.parse::<usize>().unwrap())
        .unwrap_or_else(|| 10);
    let concurrently = 20;
    let mut completed = 0;
    let mut launched = 0;

    let now = Instant::now();
    for _ in 0..concurrently {
        futs.push(client.get("https://127.0.0.1:3000").send());
        launched += 1;
    }

    while completed < n_reqs {
        if let Some(res) = futs.next().await {
            completed += 1;
            match res {
                Ok(_) => {}
                Err(e) => error!("request failed {e}"),
            }
        }
        if launched < n_reqs {
            futs.push(client.get("https://127.0.0.1:3000").send());
            launched += 1;
        }
    }

    let duration = now.elapsed();
    let mean = n_reqs as f64 / duration.as_secs_f64();

    println!(
        "\nDuration: {}ms with {} total requests at concurrency {}\nMean requests per second: {mean:.0}  --> per request: {:.1}us",
        duration.as_millis(),
        n_reqs,
        concurrently,
        1000000. / mean
    );
    Ok(())
}
