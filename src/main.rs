mod cli;
mod server;

use std::net::ToSocketAddrs;

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

    // Parse/validate the given bind address.
    let bind_addr = opts
        .bind_address
        .to_socket_addrs()
        .context("invalid bind address")?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid bind_addr"))?;
    // Parse/validate the backend url
    let backend_url = reqwest::Url::parse(&opts.backend)?;

    // Initialize the openid client.
    // This will implicitly perform an openid discovery, i.e. the
    // proxy will not startup if the openid provider is not available
    // or misconfigured.
    let openid_client = DiscoveredClient::discover(
        opts.client_id.to_string(),
        opts.client_secret.to_string(),
        None,
        reqwest::Url::parse(&opts.issuer)?,
    )
    .await?;
    // Configure http client used to forward requests to the backend
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    debug!("Openid client: {:?}", openid_client);

    server::run_server(server::Settings {
        bind_addr,
        http_client,
        openid_client,
        backend_url,
        permit_login: opts.permit_login,
        scopes: opts.scopes,
        cookie_secret: opts.cookie_secret,
        login_cookie: opts.login_cookie,
        auth_cookie: opts.auth_cookie,
        refresh_cookie: opts.refresh_cookie,
        cookie_path: opts.cookie_path,
        cookie_secure: opts.cookie_secure,
        cookie_domain: opts.cookie_domain,
    })
    .await;

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
