use std::{
    pin::Pin,
    task::{Context, Poll},
};

use axum::{extract::Request, http, response::Response};
use http::HeaderValue;
use tower::Service;

use crate::{PUBLIC_VERSION_HEADER, server::DefguardVersionService};

impl<S, B> Service<Request> for DefguardVersionService<S>
where
    S: Service<Request, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = Response<B>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let mut inner = self.inner.clone();
        let parsed_info = self
            .component_info
            .version
            .to_string()
            .parse::<HeaderValue>()
            .ok();

        Box::pin(async move {
            let mut response = inner.call(request).await?;

            // Public HTTP responses use S-Metric branding. Internal gRPC metadata keeps
            // the legacy compatibility header names used by existing components.
            if let Some(version) = parsed_info {
                response.headers_mut().insert(PUBLIC_VERSION_HEADER, version);
            }

            Ok(response)
        })
    }
}
