use std::sync::Arc;

use super::handlers;
use super::Settings;
use futures::future;
use log::error;
use reqwest::Url;
use serde::Deserialize;
use std::convert::Infallible;
use warp::Filter;

// Helper to extract the relevant query parameters from an oauth callback.
#[derive(Deserialize, Debug)]
pub struct LoginQuery {
    pub code: String,
    pub state: Option<String>,
}

// All the http routes of the application.
// As of now there is only the oauth callback (for login), any other request
// will be forwarded to the backend.
pub fn routes(
    settings: Settings,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let settings = Arc::new(settings);

    oauth_callback(settings.clone()).or(proxy_request(settings))
}

// The oauth callback route.
fn oauth_callback(
    settings: Arc<Settings>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("oauth" / "callback")
        .and(warp::get())
        .and(with_settings(settings))
        .and(warp::query::<LoginQuery>())
        .and(warp::header::headers_cloned())
        .and_then(handlers::oauth_callback)
}

// Proxy/forward any other request.
fn proxy_request(
    settings: Arc<Settings>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .and(with_settings(settings))
        .and(warp::method())
        .and(external_url())
        .and(warp::header::headers_cloned())
        .and(warp::body::stream())
        .and_then(handlers::proxy_request)
}

// Helper wrap the server settings as parameter for the handler function.
fn with_settings(
    settings: Arc<Settings>,
) -> impl Filter<Extract = (Arc<Settings>,), Error = Infallible> + Clone {
    warp::any().map(move || settings.clone())
}

// Little workaround as warp does not support an optional raw query by itself.
fn optional_raw_query() -> impl Filter<Extract = (Option<String>,), Error = Infallible> + Clone {
    warp::query::raw()
        .map(Some)
        .or_else(|_| future::ok::<(Option<String>,), Infallible>((None,)))
}

// Helper to reconstruct the original url of the request.
// This will honour the X-Forwarded-Host and X-Forwarded-Proto headers if the
// oauth-proxy operates behind a load-balancer (which it usually should do).
fn external_url() -> impl Filter<Extract = (Url,), Error = warp::Rejection> + Clone {
    warp::host::optional()
        .and(warp::header::optional("x-forwarded-host"))
        .and(warp::header::optional("x-forwarded-proto"))
        .and(warp::path::full())
        .and(optional_raw_query())
        .and_then(
            |maybe_host: Option<warp::http::uri::Authority>,
             maybe_forwarded_host: Option<String>,
             maybe_forward_proto: Option<String>,
             path: warp::path::FullPath,
             maybe_query: Option<String>| {
                let scheme = maybe_forward_proto.as_deref().unwrap_or("http");
                let host = maybe_forwarded_host
                    .as_deref()
                    .or_else(|| maybe_host.as_ref().map(|a| a.as_str()))
                    .unwrap_or("localhost");
                match Url::parse(&format!("{}://{}{}", scheme, host, path.as_str())) {
                    Ok(mut url) => {
                        url.set_query(maybe_query.as_deref());
                        future::ok(url)
                    }
                    Err(err) => {
                        error!("Invalid url: {}", err);
                        future::err(warp::reject())
                    }
                }
            },
        )
}
