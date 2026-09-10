//! Bind the pinned dispatcher's detached request reader to this route's owner.
//! Input-reader termination is not acknowledgment of broker refresh/sign drain.

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http_body::{Frame, SizeHint};
use tokio_util::sync::{CancellationToken, DropGuard, WaitForCancellationFutureOwned};

#[derive(Clone)]
struct InputLifetime(CancellationToken);

/// Cancel failed/cancelled handler admission even when the protocol renders its
/// error in an unread HTTP200 response body. Disarm only after admission succeeds;
/// the middleware's response owner then retains the same cancellation token.
pub(super) fn admission_guard(ctx: &connectrpc::RequestContext) -> Option<DropGuard> {
    ctx.extensions()
        .get::<InputLifetime>()
        .map(|bound| bound.0.clone().drop_guard())
}

pub(super) async fn bind(mut request: Request, next: Next) -> Response {
    let cancellation = CancellationToken::new();
    // This guard is held across next.run, including cancellation before any
    // response exists. It is moved, never replaced, into the response body.
    let guard = cancellation.clone().drop_guard();
    request
        .extensions_mut()
        .insert(InputLifetime(cancellation.clone()));
    let (parts, body) = request.into_parts();
    let request = Request::from_parts(
        parts,
        Body::new(InputBody {
            body: Some(Box::pin(body)),
            cancelled: Box::pin(cancellation.cancelled_owned()),
        }),
    );
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let guard = if body.is_end_stream() {
        drop(guard);
        None
    } else {
        Some(guard)
    };
    Response::from_parts(
        parts,
        Body::new(OutputBody {
            body: Box::pin(body),
            guard,
        }),
    )
}

struct InputBody {
    body: Option<Pin<Box<Body>>>,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl HttpBody for InputBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.cancelled.as_mut().poll(cx).is_ready() {
            // Release the underlying body now, not only when the detached
            // dispatcher reader eventually drops this wrapper.
            this.body = None;
            return Poll::Ready(None);
        }
        let Some(body) = this.body.as_mut() else {
            return Poll::Ready(None);
        };
        let frame = body.as_mut().poll_frame(cx);
        if matches!(frame, Poll::Ready(None | Some(Err(_)))) {
            this.body = None;
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.as_ref().is_none_or(|body| body.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        self.body
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), |body| body.size_hint())
    }
}

struct OutputBody {
    body: Pin<Box<Body>>,
    guard: Option<DropGuard>,
}

impl HttpBody for OutputBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let frame = this.body.as_mut().poll_frame(cx);
        if matches!(frame, Poll::Ready(None | Some(Err(_)))) || this.body.is_end_stream() {
            drop(this.guard.take());
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests;
