//! An opt-in line per request on the peer-facing listener, for an operator who wants to see what the hub is doing.
//!
//! Off unless asked for ([`enabled`]). A line holds the method, the route template the request matched, and the
//! status: `[mimi-activity] method=POST route=/mimi/pl/update/:room_id status=200`. It never holds a path, a query
//! string, a header, a certificate or a body. The route is the template from this crate's own router, not what the peer
//! typed, so a room URI, a domain or any other byte a peer chose does not reach the line, and a request no route matched
//! reads `route=unmatched`. A method outside the usual set reads `OTHER`.

use std::sync::Arc;

use axum::{
    extract::{MatchedPath, Request, State},
    http::Method,
    middleware::Next,
    response::Response,
    Router,
};

/// Where a finished line goes. The daemon prints it to stderr; a test collects it.
pub type ActivitySink = Arc<dyn Fn(String) + Send + Sync>;

/// The setting that turns the log on is exactly `1`; anything else, including no setting, leaves it off.
pub fn enabled(setting: Option<&str>) -> bool {
    setting == Some("1")
}

/// The router with the activity line added when [`enabled`] says so, and as it was otherwise.
pub fn with_activity_log(router: Router, on: bool, sink: ActivitySink) -> Router {
    if on {
        router.layer(axum::middleware::from_fn_with_state(sink, log_request))
    } else {
        router
    }
}

async fn log_request(State(sink): State<ActivitySink>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_owned());
    let response = next.run(request).await;
    sink(activity_line(
        &method,
        route.as_deref(),
        response.status().as_u16(),
    ));
    response
}

/// The line for one request.
pub fn activity_line(method: &Method, route: Option<&str>, status: u16) -> String {
    let method = match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::PATCH => "PATCH",
        _ => "OTHER",
    };
    format!(
        "[mimi-activity] method={method} route={} status={status}",
        route.unwrap_or("unmatched")
    )
}

#[cfg(test)]
#[path = "activity_tests.rs"]
mod tests;
