use std::net::SocketAddr;

use warp::Filter;

#[derive(Debug)]
pub struct Settings {
    pub bind_addr: SocketAddr,
    pub http_client: reqwest::Client,
    pub openid_client: openid::Client,
    pub backend_url: reqwest::Url,
    pub permit_login: bool,
    pub login_cookie: String,
}

pub async fn run_server(settings: Settings) {
    let bind_addr = settings.bind_addr;
    let routes = api::routes(settings).with(warp::log("server"));

    warp::serve(routes).run(bind_addr).await;
}

mod api {
    use std::sync::Arc;

    use super::handlers;
    use super::Settings;
    use std::convert::Infallible;
    use futures::future;
    use warp::Filter;

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
            .and(with_settings(settings))
            .and(warp::header::headers_cloned())
            .and_then(handlers::oauth_callback)
    }

    fn proxy_request(
        settings: Arc<Settings>,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::any()
            .and(with_settings(settings))
            .and(warp::method())
            .and(warp::path::full())
            .and(warp::query::raw().map(Some).or_else(|_| future::ok::<(Option<String>, ), Infallible>((None, ))))
            .and(warp::header::headers_cloned())
            .and(warp::body::stream())
            .and_then(handlers::proxy_request)
    }

    fn with_settings(
        settings: Arc<Settings>,
    ) -> impl Filter<Extract = (Arc<Settings>,), Error = Infallible> + Clone {
        warp::any().map(move || settings.clone())
    }
}

mod handlers {
    use super::Settings;
    use futures::TryStreamExt;
    use log::{error, warn};
    use reqwest::{header::HeaderMap, Method};
    use std::{convert::Infallible, sync::Arc};

    pub async fn oauth_callback(
        settings: Arc<Settings>,
        headers: HeaderMap,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        if !settings.permit_login {
            warn!("Invalid login attempt (login not permitted)");
            return Err(warp::reject());
        }
        Ok(warp::reply())
    }

    pub async fn proxy_request<S, B, E>(
        settings: Arc<Settings>,
        method: Method,
        path: warp::path::FullPath,
        query: Option<String>,
        headers: HeaderMap,
        body: S,
    ) -> Result<Box<dyn warp::Reply>, Infallible>
    where
        S: futures::stream::Stream<Item = Result<B, E>> + Sync + Send + 'static,
        B: bytes::Buf,
        E: std::error::Error + Send + Sync + 'static,
    {
        println!("{} {}", method, path.as_str());

        let mut url = match settings.backend_url.join(path.as_str()) {
            Ok(url) => url,
            Err(err) => { 
                error!("Invalid proxy url: {}", err);
                return Ok(Box::new(warp::reply::with_status("Invalid url", warp::http::StatusCode::INTERNAL_SERVER_ERROR)))
            }
        };
        url.set_query(query.as_deref());

        let response = settings
            .http_client
            .request(method, url)
            .body(reqwest::Body::wrap_stream(
                body.map_ok(|mut buf| buf.copy_to_bytes(buf.remaining())),
            ))
            .send()
            .await
            .unwrap();
        Ok(Box::new(
            warp::http::Response::builder()
                .status(response.status())
                .body(warp::hyper::Body::wrap_stream(response.bytes_stream())),
        ))
    }
}
