mod cli;
mod server;

use std::{net::ToSocketAddrs, sync::Arc};

use anyhow::Context;
use clap::Parser;
use log::debug;
use openid::DiscoveredClient;
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = cli::Opts::parse();

    init_logging(&opts)?;

    let bind_addr = opts
        .bind_address
        .to_socket_addrs()
        .context("invalid bind address")?
        .into_iter()
        .next()
        .ok_or(anyhow::anyhow!("Invalid bind_addr"))?;

    let openid_client = Arc::new(
        DiscoveredClient::discover(
            opts.client_id.to_string(),
            opts.client_secret.to_string(),
            None,
            reqwest::Url::parse(&opts.issuer)?,
        )
        .await?,
    );

    debug!("Openid client: {:?}", openid_client);

    server::run_server(bind_addr).await;

    Ok(())
}

fn init_logging(opts: &cli::Opts) -> anyhow::Result<()> {
    if opts.json_log {
        let mut subscriber = tracing_subscriber::fmt().json();
        if opts.debug {
            subscriber = subscriber.with_max_level(Level::DEBUG);
        }
        subscriber.finish().try_init()?;
    } else {
        let mut subscriber = tracing_subscriber::fmt();
        if opts.debug {
            subscriber = subscriber.with_max_level(Level::DEBUG);
        }
        subscriber.finish().try_init()?;
    };

    Ok(())
}
