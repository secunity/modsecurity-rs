//! A tower middleware that inspects the requests and responses of an HTTP
//! service (the `tower` feature).
//!
//! [`ModSecurityLayer`] wraps a service of the Rust HTTP ecosystem (hyper,
//! axum, tonic, ...) and runs a [`Transaction`](crate::Transaction) around
//! each request, in the order the nginx connector does: the connection and
//! the request head (phases 0 and 1), the request body (phase 2), the inner
//! service, the response head (phase 3), the response body (phase 4) and
//! the logging (phase 5). When the rules intervene, the middleware answers with
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
//! Bodies: the middleware reads a body frame by frame and gives each piece
//! to the transaction, up to the end of the body or until the body goes
//! past its limit (`SecRequestBodyLimit`, `SecResponseBodyLimit`): the
//! rules see no more of it then. A limit that rejects interrupts the
//! exchange there; otherwise the rules of the phase run, and the body goes
//! on as an [`InspectedBody`]: the frames read, then the rest, read as it
//! is polled. So the middleware holds at most the part of a body the rules
//! inspect (the whole body when no limit is set). The inner service gets
//! the request body as an `InspectedBody` of the request's body type (axum
//! routers accept any body). A request body that cannot be read before
//! phase 2 is answered with 400, a response body with 502; an error after
//! that reaches the reader of the body. The response body is inspected
//! only when `SecResponseBodyAccess` is `On` and the rule engine is not
//! off; otherwise it streams through.
//!
//! The middleware's error type is the inner service's: it adds no errors
//! of its own (axum requires infallible services).
//!
//! The addresses of the connection come from a [`Connection`] request
//! extension, which the server inserts.

use std::collections::VecDeque;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Either, Full};
use tower_layer::Layer;
use tower_service::Service;

use crate::inspection::{self, Blocked, Inspection};
use crate::instance::ModSecurity;
use crate::rules_set::RulesSet;

/// The response body: the middleware's own responses, or the inner
/// service's body.
pub type ResponseBody<B> = Either<Full<Bytes>, InspectedBody<B>>;

/// A body passed on after inspection: the frames the middleware read, then
/// the rest of the body, which is read only as it is polled.
pub struct InspectedBody<B> {
    read: VecDeque<Frame<Bytes>>,
    /// The rest of the body; `None` once it ended.
    rest: Option<Pin<Box<B>>>,
}

impl<B> InspectedBody<B> {
    /// The body of the frames `read`, then of `rest`.
    fn new(read: VecDeque<Frame<Bytes>>, rest: Option<Pin<Box<B>>>) -> Self {
        InspectedBody { read, rest }
    }
}

impl<B: Body> Body for InspectedBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        if let Some(frame) = this.read.pop_front() {
            return Poll::Ready(Some(Ok(frame)));
        }
        let Some(rest) = this.rest.as_mut() else {
            return Poll::Ready(None);
        };
        match ready!(rest.as_mut().poll_frame(cx)) {
            Some(frame) => Poll::Ready(Some(frame.map(|f| f.map_data(|mut d| d.copy_to_bytes(d.remaining()))))),
            None => {
                this.rest = None;
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.read.is_empty() && self.rest.as_ref().is_none_or(|rest| rest.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        let read: u64 = self.read.iter().filter_map(Frame::data_ref).map(|d| d.len() as u64).sum();
        let rest = self.rest.as_ref().map_or_else(|| SizeHint::with_exact(0), |rest| rest.size_hint());
        let mut hint = SizeHint::new();
        if let Some(upper) = rest.upper() {
            hint.set_upper(upper.saturating_add(read));
        }
        hint.set_lower(rest.lower().saturating_add(read));
        hint
    }
}

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
    S: Service<Request<InspectedBody<ReqBody>>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send + 'static,
    ReqBody: Body + Send + 'static,
    ReqBody::Data: Send,
    ResBody: Body + Send + 'static,
    ResBody::Data: Send,
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

/// The response that ends the exchange when the rules interrupt it: the
/// intervention's (the logging phase runs as `blocked` is dropped).
fn intercepted<B>(blocked: Blocked<'_>) -> Response<ResponseBody<B>> {
    let response = blocked.intervention().to_response::<Full<Bytes>>();
    // A `Blocked` always has something to send: `inspection` lets an
    // intervention with status 200 and no redirect go on.
    response.unwrap_or_default().map(Either::Left)
}

/// An empty response with `status`.
fn empty<B>(status: StatusCode) -> Response<ResponseBody<B>> {
    let mut response = Response::new(Either::Left(Full::default()));
    *response.status_mut() = status;
    response
}

/// The stage of an exchange that takes a body.
trait BodyStage<'a>: Sized {
    fn write(self, piece: &[u8]) -> Result<Self, Blocked<'a>>;
    fn limit_reached(&self) -> bool;
}

impl<'a> BodyStage<'a> for inspection::RequestBody<'a> {
    fn write(self, piece: &[u8]) -> Result<Self, Blocked<'a>> {
        inspection::RequestBody::write(self, piece)
    }

    fn limit_reached(&self) -> bool {
        inspection::RequestBody::limit_reached(self)
    }
}

impl<'a> BodyStage<'a> for inspection::ResponseBody<'a> {
    fn write(self, piece: &[u8]) -> Result<Self, Blocked<'a>> {
        inspection::ResponseBody::write(self, piece)
    }

    fn limit_reached(&self) -> bool {
        inspection::ResponseBody::limit_reached(self)
    }
}

/// Why a body was not read to its end or its limit.
enum Unread<'a, St> {
    /// The rules interrupted the exchange (a limit that rejects).
    Blocked(Blocked<'a>),
    /// The body failed.
    Failed(St),
}

/// What was read of a body: the stage after it, the frames read, and the
/// rest of the body (`None` when it ended).
type Read<St, B> = (St, VecDeque<Frame<Bytes>>, Option<Pin<Box<B>>>);

/// Gives `body` to `stage` frame by frame, until its end or until it goes
/// past its limit.
async fn read_body<'a, St: BodyStage<'a>, B: Body>(
    mut stage: St,
    mut body: Pin<Box<B>>,
) -> Result<Read<St, B>, Unread<'a, St>> {
    let mut read = VecDeque::new();
    while !stage.limit_reached() {
        let Some(frame) = body.frame().await else {
            return Ok((stage, read, None));
        };
        let Ok(frame) = frame else {
            return Err(Unread::Failed(stage));
        };
        let frame = frame.map_data(|mut d| d.copy_to_bytes(d.remaining()));
        if let Some(data) = frame.data_ref() {
            stage = stage.write(data).map_err(Unread::Blocked)?;
        }
        read.push_back(frame);
    }
    Ok((stage, read, Some(body)))
}

async fn inspect<S, ReqBody, ResBody>(
    engine: &ModSecurity,
    rules: &RulesSet,
    mut inner: S,
    request: Request<ReqBody>,
) -> Result<Response<ResponseBody<ResBody>>, S::Error>
where
    S: Service<Request<InspectedBody<ReqBody>>, Response = Response<ResBody>>,
    ReqBody: Body,
    ResBody: Body,
{
    let unknown = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let c = request.extensions().get::<Connection>().copied();
    let head =
        Inspection::new(engine, rules).connection(c.map_or(unknown, |c| c.client), c.map_or(unknown, |c| c.server));
    let request_body = match head.and_then(|head| head.request(&request)) {
        Ok(stage) => stage,
        Err(blocked) => return Ok(intercepted(blocked)),
    };

    let (parts, body) = request.into_parts();
    let (request_body, read, rest) = match read_body(request_body, Box::pin(body)).await {
        Ok(read) => read,
        Err(Unread::Blocked(blocked)) => return Ok(intercepted(blocked)),
        Err(Unread::Failed(stage)) => {
            stage.abort(StatusCode::BAD_REQUEST.as_u16());
            return Ok(empty(StatusCode::BAD_REQUEST));
        }
    };
    let response_head = match request_body.finish() {
        Ok(stage) => stage,
        Err(blocked) => return Ok(intercepted(blocked)),
    };

    let response = inner.call(Request::from_parts(parts, InspectedBody::new(read, rest))).await?;
    let response_body = match response_head.response(&response) {
        Ok(stage) => stage,
        Err(blocked) => return Ok(intercepted(blocked)),
    };

    // An inspected body is read up to its limit; another one streams
    // through.
    let (parts, body) = response.into_parts();
    let (read, rest, verdict) = if response_body.is_inspected() {
        match read_body(response_body, Box::pin(body)).await {
            Ok((stage, read, rest)) => (read, rest, stage.finish()),
            Err(Unread::Blocked(blocked)) => return Ok(intercepted(blocked)),
            Err(Unread::Failed(stage)) => {
                stage.abort(StatusCode::BAD_GATEWAY.as_u16());
                return Ok(empty(StatusCode::BAD_GATEWAY));
            }
        }
    } else {
        (VecDeque::new(), Some(Box::pin(body)), response_body.finish())
    };
    match verdict {
        Ok(()) => Ok(Response::from_parts(parts, Either::Right(InspectedBody::new(read, rest)))),
        Err(blocked) => Ok(intercepted(blocked)),
    }
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

    impl<B: Body<Error: std::fmt::Debug>> Service<Request<B>> for Echo {
        type Response = Response<Full<Bytes>>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<B>) -> Self::Future {
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
        assert!(matches!(response.body(), Either::Right(body) if body.read.is_empty()));
    }

    /// A body that yields its pieces, then fails or ends.
    struct TestBody {
        pieces: VecDeque<&'static [u8]>,
        fails: bool,
    }

    impl TestBody {
        fn new(pieces: &[&'static [u8]], fails: bool) -> Self {
            TestBody { pieces: pieces.iter().copied().collect(), fails }
        }
    }

    impl Body for TestBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            Poll::Ready(match self.pieces.pop_front() {
                Some(piece) => Some(Ok(Frame::data(Bytes::from_static(piece)))),
                None if self.fails => Some(Err(std::io::Error::other("broken"))),
                None => None,
            })
        }
    }

    /// Answers with a body that fails.
    #[derive(Clone)]
    struct BrokenResponse(Arc<AtomicUsize>);

    impl<B> Service<Request<B>> for BrokenResponse {
        type Response = Response<TestBody>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<B>) -> Self::Future {
            self.0.fetch_add(1, Ordering::SeqCst);
            let response = Response::builder().header("Content-Type", "text/plain").body(TestBody::new(&[], true));
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
        assert_eq!(status(TestBody::new(&[b"x"], true)), 400);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // The response body: 502.
        assert_eq!(status(TestBody::new(&[b"x"], false)), 502);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Sends a request with `body` through `rules`: the status, and the
    /// body the inner service answered (it echoes the request body).
    fn send_body(conf: &str, body: TestBody) -> (u16, Vec<u8>) {
        let mut rules = RulesSet::new();
        rules
            .load(&format!(
                "SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n\
                 SecResponseBodyMimeType text/plain\n{conf}"
            ))
            .unwrap();
        let echo = Echo { calls: Arc::new(AtomicUsize::new(0)), content_type: "text/plain" };
        let mut service = ModSecurityLayer::new(Arc::new(ModSecurity::new()), Arc::new(rules)).layer(echo);
        block_on(std::future::poll_fn(|cx| Service::<Request<TestBody>>::poll_ready(&mut service, cx))).unwrap();
        let response = block_on(service.call(Request::post("/").body(body).unwrap())).unwrap();
        let status = response.status().as_u16();
        (status, block_on(response.into_body().collect()).unwrap().to_bytes().to_vec())
    }

    /// A body past a limit that rejects is not read further: the request
    /// is answered before the rest (here, a failure) is read.
    #[test]
    fn a_body_over_a_rejecting_limit_is_not_read_further() {
        let conf = "SecRequestBodyLimit 5\nSecRequestBodyLimitAction Reject\n";
        assert_eq!(send_body(conf, TestBody::new(&[b"abc", b"defgh"], true)).0, 403);
        // Within the limit, the failure is read: 400.
        assert_eq!(send_body(conf, TestBody::new(&[b"abc"], true)).0, 400);
    }

    /// Past a limit that processes partially, the rules see the body up to
    /// the limit and the whole body goes on, to the service and back.
    #[test]
    fn a_body_over_a_partial_limit_goes_through_whole() {
        let conf = "SecRequestBodyLimit 5\nSecRequestBodyLimitAction ProcessPartial\n\
                    SecResponseBodyLimit 5\nSecResponseBodyLimitAction ProcessPartial\n\
                    SecRule REQUEST_BODY \"!@streq abcde\" \"id:1,phase:2,deny,status:401\"\n\
                    SecRule RESPONSE_BODY \"!@streq abcde\" \"id:2,phase:4,deny,status:500\"\n";
        let body = TestBody::new(&[b"abc", b"defgh", b"ij"], false);
        assert_eq!(send_body(conf, body), (200, b"abcdefghij".to_vec()));
    }
}
