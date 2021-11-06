use std::net::SocketAddr;

use warp::Filter;

mod api;
mod handlers;

#[derive(Debug)]
pub struct Settings {
    pub bind_addr: SocketAddr,
    pub http_client: reqwest::Client,
    pub openid_client: openid::Client,
    pub backend_url: reqwest::Url,
    pub permit_login: bool,
    pub login_cookie: String,
    pub auth_cookie: String,
    pub refresh_cookie: String,
    pub cookie_path: String,
    pub cookie_secure: bool,
    pub cookie_domain: Option<String>,
}

pub async fn run_server(settings: Settings) {
    let bind_addr = settings.bind_addr;
    let routes = api::routes(settings).with(warp::log("server"));

    warp::serve(routes).run(bind_addr).await;
}
