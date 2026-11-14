//! A tower middleware that inspects the requests and responses of an HTTP
//! service (the `tower` feature).
//!
//! [`ModSecurityLayer`] wraps a service of the Rust HTTP ecosystem (hyper,
//! axum, tonic, ...) and runs a [`Transaction`] around each request, in
//! the order the nginx connector does: the connection and the request head
//! (phases 0 and 1), the request body (phase 2), the inner service, the
//! response head (phase 3), the response body (phase 4) and the logging
//! (phase 5). When the rules intervene, the middleware answers with
//! [`Intervention::to_response`](crate::Intervention::to_response)
//! instead of calling the inner service (or instead of its response).
//!
//! ```no_run
//! use std::sync::Arc;
//! use modsecurity::middleware::ModSecurityLayer;
//! use modsecurity::{ModSecurity, RulesSet};
//!
//! let mut rules = RulesSet::new();
//! rules.load_from_uri("modsecurity.conf").expect("valid rules");
//! let layer = ModSecurityLayer::new(Arc::new(ModSecurity::new()), Arc::new(rules));
//! // e.g. axum: Router::new().route(...).layer(layer)
//! ```
//!
//! `examples/axum` in the repository is a complete server.
//!
//! Bodies: the request body is read completely before the inner service is
//! called, as nginx reads it for the connector, so put a body size limit in
//! front of the middleware. The inner service gets it back in the same body
//! type, rebuilt from the bytes read (any body type that converts from
//! [`Bytes`], such as axum's `Body` or [`Full`]). A request body that cannot
//! be read is answered with 400, a response body with 502. The response
//! body is buffered only when `SecResponseBodyAccess` is `On` and the rule
//! engine is not off; otherwise it streams through.
//!
//! The middleware's error type is the inner service's: it adds no errors
//! of its own (axum requires infallible services).
//!
//! The addresses of the connection come from a [`Connection`] request
//! extension, which the server inserts.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Either, Full};
use tower_layer::Layer;
use tower_service::Service;

use crate::modsecurity::ModSecurity;
use crate::rules_set::RulesSet;
use crate::rules_set_properties::RuleEngine;
use crate::transaction::Transaction;

/// The response body: buffered by the middleware (its own responses, and
/// inspected bodies), or the inner service's.
pub type ResponseBody<B> = Either<Full<Bytes>, B>;

/// The client and server addresses of a request, given to the middleware
/// as a request extension. Without it, the connection phase sees both
/// addresses as `0.0.0.0` port 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connection {
    pub client: SocketAddr,
    pub server: SocketAddr,
}

/// The middleware's [`Layer`]: wraps services in [`ModSecurityService`].
#[derive(Clone)]
pub struct ModSecurityLayer {
    engine: Arc<ModSecurity>,
    rules: Arc<RulesSet>,
}

impl ModSecurityLayer {
    /// A layer that inspects with `rules`, on behalf of `engine`.
    pub fn new(engine: Arc<ModSecurity>, rules: Arc<RulesSet>) -> Self {
        ModSecurityLayer { engine, rules }
    }
}

impl<S> Layer<S> for ModSecurityLayer {
    type Service = ModSecurityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ModSecurityService { inner, engine: self.engine.clone(), rules: self.rules.clone() }
    }
}

/// A service that runs a transaction around each request of `S`.
#[derive(Clone)]
pub struct ModSecurityService<S> {
    inner: S,
    engine: Arc<ModSecurity>,
    rules: Arc<RulesSet>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ModSecurityService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send + 'static,
    ReqBody: Body + From<Bytes> + Send + 'static,
    ReqBody::Data: Send,
    ResBody: Body<Data = Bytes> + Send + 'static,
{
    type Response = Response<ResponseBody<ResBody>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        // The service that was polled ready handles this request; the clone
        // waits for the next one.
        let clone = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, clone);
        let (engine, rules) = (self.engine.clone(), self.rules.clone());
        Box::pin(async move { inspect(&engine, &rules, inner, request).await })
    }
}

/// The response that ends the transaction when the rules intervene, after
/// recording its status and running the logging phase. A disruptive
/// intervention with nothing to send (status 200, no URL) lets the
/// request go on, as in the nginx connector.
fn intercept<B>(t: &mut Transaction<'_>) -> Option<Response<ResponseBody<B>>> {
    let it = t.intervention()?;
    let response = it.to_response::<Full<Bytes>>()?;
    if it.url.is_none() {
        t.update_status_code(it.status);
    }
    t.process_logging();
    Some(response.map(Either::Left))
}

/// An empty response with `status` that ends the transaction.
fn fail<B>(t: &mut Transaction<'_>, status: StatusCode) -> Response<ResponseBody<B>> {
    t.update_status_code(status.as_u16().into());
    t.process_logging();
    let mut response = Response::new(Either::Left(Full::default()));
    *response.status_mut() = status;
    response
}

async fn inspect<S, ReqBody, ResBody>(
    engine: &ModSecurity,
    rules: &RulesSet,
    mut inner: S,
    request: Request<ReqBody>,
) -> Result<Response<ResponseBody<ResBody>>, S::Error>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Body + From<Bytes>,
    ResBody: Body<Data = Bytes>,
{
    let mut t = Transaction::new(engine, rules, None);

    let unknown = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let c = request.extensions().get::<Connection>().copied();
    t.process_connection_addrs(c.map_or(unknown, |c| c.client), c.map_or(unknown, |c| c.server));
    if let Some(response) = intercept(&mut t) {
        return Ok(response);
    }
    t.process_request_head(&request);
    if let Some(response) = intercept(&mut t) {
        return Ok(response);
    }

    let (parts, body) = request.into_parts();
    let Ok(body) = body.collect().await.map(|b| b.to_bytes()) else {
        return Ok(fail(&mut t, StatusCode::BAD_REQUEST));
    };
    t.append_request_body(&body);
    t.process_request_body();
    if let Some(response) = intercept(&mut t) {
        return Ok(response);
    }

    let response = inner.call(Request::from_parts(parts, ReqBody::from(body))).await?;
    t.process_response_head(&response);
    if let Some(response) = intercept(&mut t) {
        return Ok(response);
    }

    let inspected =
        rules.properties.sec_response_body_access == Some(true) && t.rule_engine_state() != Some(RuleEngine::Disabled);
    let response = if inspected {
        let (parts, body) = response.into_parts();
        let Ok(body) = body.collect().await.map(|b| b.to_bytes()) else {
            return Ok(fail(&mut t, StatusCode::BAD_GATEWAY));
        };
        t.append_response_body(&body);
        t.process_response_body();
        Response::from_parts(parts, Either::Left(Full::new(body)))
    } else {
        t.process_response_body();
        response.map(Either::Right)
    };
    if let Some(response) = intercept(&mut t) {
        return Ok(response);
    }

    t.process_logging();
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Runs a future that never waits (the services here are synchronous).
    fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        match f.as_mut().poll(&mut Context::from_waker(std::task::Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("the future waits"),
        }
    }

    /// The inner service: echoes the request body, counts its calls.
    #[derive(Clone)]
    struct Echo {
        calls: Arc<AtomicUsize>,
        content_type: &'static str,
    }

    impl Service<Request<Full<Bytes>>> for Echo {
        type Response = Response<Full<Bytes>>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<Full<Bytes>>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let body = block_on(request.into_body().collect()).unwrap().to_bytes();
            let response = Response::builder().header("Content-Type", self.content_type).body(Full::new(body));
            std::future::ready(Ok(response.unwrap()))
        }
    }

    struct Setup {
        service: ModSecurityService<Echo>,
        calls: Arc<AtomicUsize>,
    }

    fn setup(conf: &str) -> Setup {
        let mut rules = RulesSet::new();
        rules
            .load(&format!(
                "SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n\
                 SecResponseBodyMimeType text/plain\n{conf}"
            ))
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let echo = Echo { calls: calls.clone(), content_type: "text/plain" };
        let service = ModSecurityLayer::new(Arc::new(ModSecurity::new()), Arc::new(rules)).layer(echo);
        Setup { service, calls }
    }

    /// Sends `request` through the middleware: (status, location, body).
    fn send(s: &mut Setup, request: Request<Full<Bytes>>) -> (u16, Option<String>, Vec<u8>) {
        block_on(std::future::poll_fn(|cx| Service::<Request<Full<Bytes>>>::poll_ready(&mut s.service, cx))).unwrap();
        let response = block_on(s.service.call(request)).unwrap();
        let location = response.headers().get("location").map(|l| l.to_str().unwrap().to_string());
        let status = response.status().as_u16();
        let body = block_on(response.into_body().collect()).unwrap().to_bytes().to_vec();
        (status, location, body)
    }

    fn post(uri: &str, body: &'static str) -> Request<Full<Bytes>> {
        Request::post(uri)
            .header("Host", "example.com")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from_static(body.as_bytes())))
            .unwrap()
    }

    #[test]
    fn passes_requests_through() {
        let mut s = setup("SecRule ARGS \"@contains attack\" \"id:1,phase:2,deny,status:403\"\n");
        assert_eq!(send(&mut s, post("/?a=1", "b=2")), (200, None, b"b=2".to_vec()));
        assert_eq!(s.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn denies_in_request_phases() {
        let mut s = setup(
            "SecRule ARGS_GET \"@contains attack\" \"id:1,phase:1,deny,status:403\"\n\
             SecRule ARGS_POST \"@contains attack\" \"id:2,phase:2,deny,status:406\"\n",
        );
        assert_eq!(send(&mut s, post("/?q=attack", "")).0, 403);
        assert_eq!(send(&mut s, post("/", "q=attack")).0, 406);
        // The inner service never saw them.
        assert_eq!(s.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn denies_in_response_phases() {
        let mut s = setup(
            "SecRule RESPONSE_STATUS \"@streq 200\" \"id:1,phase:3,chain,deny,status:502\"\n\
             SecRule REQUEST_URI \"@streq /head\" \"\"\n\
             SecRule RESPONSE_BODY \"@contains secret\" \"id:2,phase:4,deny,status:500\"\n",
        );
        assert_eq!(send(&mut s, post("/head", "")).0, 502);
        let (status, _, body) = send(&mut s, post("/", "the secret"));
        assert_eq!((status, body.is_empty()), (500, true));
        assert_eq!(s.calls.load(Ordering::SeqCst), 2);
        assert_eq!(send(&mut s, post("/", "public")), (200, None, b"public".to_vec()));
    }

    #[test]
    fn redirects() {
        let mut s = setup("SecRule ARGS:go \"@streq away\" \"id:1,phase:1,redirect:https://example.com/elsewhere\"\n");
        let (status, location, _) = send(&mut s, post("/?go=away", ""));
        assert_eq!((status, location.as_deref()), (302, Some("https://example.com/elsewhere")));
    }

    #[test]
    fn connection_addresses() {
        let mut s = setup(
            "SecRule REMOTE_ADDR \"@ipMatch 192.0.2.0/24\" \"id:1,phase:1,deny,status:403\"\n\
             SecRule SERVER_PORT \"@eq 0\" \"id:2,phase:1,deny,status:400\"\n",
        );
        let mut request = post("/", "");
        let server = SocketAddr::from(([127, 0, 0, 1], 8080));
        request.extensions_mut().insert(Connection { client: SocketAddr::from(([192, 0, 2, 7], 5000)), server });
        assert_eq!(send(&mut s, request).0, 403);
        let mut request = post("/", "");
        request.extensions_mut().insert(Connection { client: SocketAddr::from(([198, 51, 100, 1], 5000)), server });
        assert_eq!(send(&mut s, request).0, 200);
        // Without the extension.
        assert_eq!(send(&mut s, post("/", "")).0, 400);
    }

    #[test]
    fn uninspected_response_bodies_stream_through() {
        let mut rules = RulesSet::new();
        rules.load("SecRuleEngine On\nSecResponseBodyAccess Off\n").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let echo = Echo { calls, content_type: "text/plain" };
        let mut service = ModSecurityLayer::new(Arc::new(ModSecurity::new()), Arc::new(rules)).layer(echo);
        block_on(std::future::poll_fn(|cx| Service::<Request<Full<Bytes>>>::poll_ready(&mut service, cx))).unwrap();
        let response = block_on(service.call(post("/", "x"))).unwrap();
        assert!(matches!(response.body(), Either::Right(_)));
    }

    /// A body that yields its bytes, or fails.
    enum TestBody {
        Data(Option<Bytes>),
        Broken,
    }

    impl Body for TestBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
            Poll::Ready(match &mut *self {
                TestBody::Data(data) => data.take().map(|b| Ok(http_body::Frame::data(b))),
                TestBody::Broken => Some(Err(std::io::Error::other("broken"))),
            })
        }
    }

    impl From<Bytes> for TestBody {
        fn from(b: Bytes) -> Self {
            TestBody::Data(Some(b))
        }
    }

    /// Answers with a body that fails.
    #[derive(Clone)]
    struct BrokenResponse(Arc<AtomicUsize>);

    impl Service<Request<TestBody>> for BrokenResponse {
        type Response = Response<TestBody>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<TestBody>) -> Self::Future {
            self.0.fetch_add(1, Ordering::SeqCst);
            let response = Response::builder().header("Content-Type", "text/plain").body(TestBody::Broken);
            std::future::ready(Ok(response.unwrap()))
        }
    }

    #[test]
    fn unreadable_bodies() {
        let mut rules = RulesSet::new();
        rules.load("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let layer = ModSecurityLayer::new(Arc::new(ModSecurity::new()), Arc::new(rules));
        let mut service = layer.layer(BrokenResponse(calls.clone()));
        let mut status = |body| {
            block_on(std::future::poll_fn(|cx| Service::<Request<TestBody>>::poll_ready(&mut service, cx))).unwrap();
            block_on(service.call(Request::post("/").body(body).unwrap())).unwrap().status().as_u16()
        };
        // The request body: 400, without calling the service.
        assert_eq!(status(TestBody::Broken), 400);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // The response body: 502.
        assert_eq!(status(TestBody::from(Bytes::from_static(b"x"))), 502);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
