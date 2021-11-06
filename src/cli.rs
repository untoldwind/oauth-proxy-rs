use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "oauth-proxy-rs")]
pub struct Opts {
    #[clap(long)]
    pub debug: bool,

    #[clap(long)]
    pub json_log: bool,

    #[clap(long, env = "OAUTH_PROXY_CLIENT_ID")]
    pub client_id: String,

    #[clap(long, env = "OAUTH_PROXY_CLIENT_SECRET")]
    pub client_secret: String,

    #[clap(long, env = "OAUTH_PROXY_ISSUER")]
    pub issuer: String,

    #[clap(long, default_value = "0.0.0.0:3000", env = "OAUTH_PROXY_BIND_ADDRESS")]
    pub bind_address: String,
}
