use std::net::SocketAddr;
use warp::Filter;

pub async fn run_server(addr: SocketAddr) {
    let routes = api().with(warp::log("proxy"));
    
    warp::serve(routes).run(addr).await;
}

fn api() -> impl Filter<Extract = impl warp::Reply> + Clone {
    warp::any().map(warp::reply)
}

fn with_state<T: Clone + Sync + Send>(state: T) -> impl Filter<Extract = (T,)> + Clone {
    warp::any().map(move || state.clone())
}
