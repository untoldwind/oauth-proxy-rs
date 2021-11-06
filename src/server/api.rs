use std::sync::Arc;

use super::handlers;
use super::Settings;
use futures::future;
use serde::Deserialize;
use std::convert::Infallible;
use warp::Filter;

#[derive(Deserialize, Debug)]
pub struct LoginQuery {
    pub code: String,
    pub state: Option<String>,
}

pub fn routes(
    settings: Settings,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let settings = Arc::new(settings);

    oauth_callback(settings.clone()).or(proxy_request(settings))
}

fn oauth_callback(
    settings: Arc<Settings>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("oauth" / "callback")
        .and(warp::get())
        .and(with_settings(settings))
        .and(warp::query::<LoginQuery>())
        .and_then(handlers::oauth_callback)
}

fn proxy_request(
    settings: Arc<Settings>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .and(with_settings(settings))
        .and(warp::method())
        .and(warp::path::full())
        .and(optional_raw_query())
        .and(warp::header::headers_cloned())
        .and(warp::body::stream())
        .and_then(handlers::proxy_request)
}

fn with_settings(
    settings: Arc<Settings>,
) -> impl Filter<Extract = (Arc<Settings>,), Error = Infallible> + Clone {
    warp::any().map(move || settings.clone())
}

fn optional_raw_query() -> impl Filter<Extract = (Option<String>,), Error = Infallible> + Clone {
    warp::query::raw()
        .map(Some)
        .or_else(|_| future::ok::<(Option<String>,), Infallible>((None,)))
}
