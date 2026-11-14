//! An axum application protected by `modsecurity::middleware`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, Request};
use axum::routing::any;
use modsecurity::middleware::{Connection, ModSecurityLayer};
use modsecurity::{ModSecurity, RulesSet};

/// The application: echoes the request body.
pub fn app(rules: RulesSet) -> Router {
    let layer = ModSecurityLayer::new(Arc::new(ModSecurity::new()), Arc::new(rules));
    Router::new()
        .route("/", any(|body: String| async move { body }))
        .route("/{*path}", any(|body: String| async move { body }))
        .layer(layer)
        // Runs before the ModSecurity layer (the last layer added is the
        // outermost): give it the connection's addresses.
        .layer(axum::middleware::map_request(connection))
}

/// Adds the [`Connection`] extension from axum's connection information.
async fn connection(mut request: Request) -> Request {
    if let Some(ConnectInfo(client)) = request.extensions().get::<ConnectInfo<SocketAddr>>().copied() {
        let server = request.extensions().get::<ServerAddr>().map_or(client, |s| s.0);
        request.extensions_mut().insert(Connection { client, server });
    }
    request
}

/// The address the server listens on, added by [`serve`].
#[derive(Clone, Copy)]
struct ServerAddr(SocketAddr);

/// Serves `app` on `listener` until the process ends.
pub async fn serve(listener: tokio::net::TcpListener, app: Router) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    let app = app.layer(axum::Extension(ServerAddr(local)));
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
}
