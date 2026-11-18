//! The Connect auth layer's cache rule (AUTH-POLICY "Credential rules",
//! #5054): every response it handles is `no-store`, whatever the method or
//! outcome. A cache decides by the response, not by intent, so storing is
//! never the default.

use axum::response::Response;
use http::{HeaderValue, header};

const NO_STORE: &str = "no-store, private";

/// Edge caches obey these over `Cache-Control`: Cloudflare reads
/// `Cloudflare-CDN-Cache-Control` and `CDN-Cache-Control`, other CDNs
/// `Surrogate-Control`. A handler's copy could still let the edge store a
/// response, so none of them leaves the layer.
const EDGE_DIRECTIVES: [&str; 3] = [
    "cloudflare-cdn-cache-control",
    "cdn-cache-control",
    "surrogate-control",
];

/// Marks `resp` `no-store, private`, keeping a handler's own `no-store`
/// directive and replacing any other, such as `public` or `max-age`, and
/// removes every edge-only cache directive.
pub(crate) fn forbid_storage(mut resp: Response) -> Response {
    for name in EDGE_DIRECTIVES {
        resp.headers_mut().remove(name);
    }
    let stores_nothing = resp
        .headers()
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"));
    if !stores_nothing {
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_control(directives: &[&str]) -> Vec<String> {
        let mut resp = Response::new(axum::body::Body::empty());
        for directive in directives {
            resp.headers_mut().append(
                header::CACHE_CONTROL,
                HeaderValue::from_str(directive).unwrap(),
            );
        }
        forbid_storage(resp)
            .headers()
            .get_all(header::CACHE_CONTROL)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn a_response_without_a_directive_is_no_store() {
        assert_eq!(cache_control(&[]), [NO_STORE]);
    }

    #[test]
    fn a_handler_cannot_make_its_response_cacheable() {
        assert_eq!(cache_control(&["public, max-age=300"]), [NO_STORE]);
        assert_eq!(cache_control(&["private"]), [NO_STORE]);
        assert_eq!(cache_control(&["max-age=60", "public"]), [NO_STORE]);
    }

    #[test]
    fn a_handler_cannot_let_the_edge_store_its_response() {
        for name in EDGE_DIRECTIVES {
            let mut resp = Response::new(axum::body::Body::empty());
            resp.headers_mut()
                .append(name, HeaderValue::from_static("public, max-age=300"));
            resp.headers_mut()
                .append(name, HeaderValue::from_static("max-age=60"));
            let resp = forbid_storage(resp);
            assert!(resp.headers().get(name).is_none(), "{name} left the layer");
            assert_eq!(resp.headers()[header::CACHE_CONTROL], NO_STORE);
        }
    }

    #[test]
    fn a_handler_no_store_is_kept() {
        assert_eq!(cache_control(&["no-store"]), ["no-store"]);
        assert_eq!(cache_control(&["private, No-Store"]), ["private, No-Store"]);
    }
}
