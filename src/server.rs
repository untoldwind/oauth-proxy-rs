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
    pub auth_cookie: String,
    pub refresh_cookie: String,
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
    use futures::future;
    use std::convert::Infallible;
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
            .and(warp::get())
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

    fn optional_raw_query() -> impl Filter<Extract = (Option<String>,), Error = Infallible> + Clone
    {
        warp::query::raw()
            .map(Some)
            .or_else(|_| future::ok::<(Option<String>,), Infallible>((None,)))
    }
}

mod handlers {
    use super::Settings;
    use chrono::{DateTime, NaiveDateTime, Utc};
    use futures::TryStreamExt;
    use headers::HeaderMapExt;
    use log::{error, warn};
    use reqwest::{header::HeaderMap, Method};
    use std::{convert::Infallible, sync::Arc};

    struct Token {
        raw: String,
        expires: Option<DateTime<Utc>>,
        raw_refresh: Option<String>,
    }

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
        let mut url = match settings.backend_url.join(path.as_str()) {
            Ok(url) => url,
            Err(err) => {
                error!("Invalid proxy url: {}", err);
                return Ok(Box::new(warp::reply::with_status(
                    "Invalid url",
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                )));
            }
        };
        url.set_query(query.as_deref());

        let token = match find_or_refresh_token(settings.clone(), &headers).await {
            Some(token) => token,
            None if settings.permit_login => {
                let login_url = settings.openid_client.auth_url(&openid::Options {
                    scope: Some("openid email profile".to_string()),
                    ..Default::default()
                });
                return Ok(Box::new(warp::reply::with_header(
                    warp::http::StatusCode::FOUND,
                    warp::http::header::LOCATION,
                    login_url.as_str(),
                )))
            }
            None => {
                return Ok(Box::new(warp::reply::with_status(
                    "Unauthorized",
                    warp::http::StatusCode::UNAUTHORIZED,
                )))
            }
        };

        let backend_response = settings
            .http_client
            .request(method, url)
            .body(reqwest::Body::wrap_stream(
                body.map_ok(|mut buf| buf.copy_to_bytes(buf.remaining())),
            ))
            .bearer_auth(token.raw)
            .send()
            .await
            .unwrap();
        Ok(Box::new(
            warp::http::Response::builder()
                .status(backend_response.status())
                .body(warp::hyper::Body::wrap_stream(backend_response.bytes_stream())),
        ))
    }

    async fn find_or_refresh_token(settings: Arc<Settings>, headers: &HeaderMap) -> Option<Token> {
        let maybe_token = headers
            .typed_get::<headers::Authorization<headers::authorization::Bearer>>()
            .map(|auth| auth.0.token().to_string())
            .or_else(|| {
                headers
                    .typed_get::<headers::Cookie>()
                    .and_then(|cookie| cookie.get(&settings.auth_cookie).map(str::to_string))
            });

        match maybe_token
            .and_then(|raw_token| parse_and_validate_token(settings.clone(), raw_token))
        {
            Some(token) => Some(token),
            None => refresh_token(settings, headers).await,
        }
    }

    async fn refresh_token(settings: Arc<Settings>, headers: &HeaderMap) -> Option<Token> {
        let refresh_token = match headers
            .typed_get::<headers::Cookie>()
            .and_then(|cookie| cookie.get(&settings.auth_cookie).map(str::to_string))
        {
            Some(token) => token,
            None => return None,
        };
        match settings
            .openid_client
            .refresh_token(
                openid::Bearer {
                    access_token: "".to_string(),
                    refresh_token: Some(refresh_token),
                    expires: None,
                    id_token: None,
                    scope: None,
                },
                None,
            )
            .await
        {
            Ok(bearer) => Some(Token {
                raw: bearer.access_token,
                expires: bearer.expires,
                raw_refresh: bearer.refresh_token,
            }),
            Err(err) => {
                error!("Token refresh failed: {}", err);
                None
            }
        }
    }

    fn parse_and_validate_token(settings: Arc<Settings>, raw: String) -> Option<Token> {
        let mut token = openid::IdToken::new_encoded(&raw);
        if let Err(err) = settings.openid_client.decode_token(&mut token) {
            warn!("Invalid id token, trying refresh: {}", err);
            return None;
        }
        if let Err(err) = settings.openid_client.validate_token(&token, None, None) {
            warn!("Token validation failed, trying refresh: {}", err);
            return None;
        }
        let expires = token
            .payload()
            .ok()
            .map(|claims| claims.exp)
            .filter(|exp| *exp > 0)
            .map(|exp| DateTime::from_utc(NaiveDateTime::from_timestamp(exp, 0), Utc));
        Some(Token {
            raw,
            expires,
            raw_refresh: None,
        })
    }
}
