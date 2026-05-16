use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::protocol::types::build_capabilities_catalog;
use crate::services::database::{self, CatalogCursor, CatalogFilter};
use crate::AppState;

/// Query params for `/v1/capabilities` (W3 — cursor pagination).
#[derive(Debug, Deserialize, Default)]
pub struct CatalogQuery {
    /// Opaque cursor from a previous response's `next_cursor`.
    pub cursor: Option<String>,
    /// Page size, clamped to [1, 200] server-side. Default 50.
    pub page_size: Option<i64>,
    /// Optional namespace filter (e.g. `?namespace=jobdonebot`).
    pub namespace: Option<String>,
    /// Comma-separated tag filter (e.g. `?tags=image,pdf`).
    pub tags: Option<String>,
    /// Legacy mode — return all in one shot, no cursor.
    /// `?paginated=false` returns up to 200 items inline (W3 transition aid).
    pub paginated: Option<bool>,
}

/// GET /v1/capabilities — Catalog of available capabilities.
///
/// Default behavior (W3, since 2026-05-09): cursor-paginated with 50 items per page.
/// Legacy callers can pass `?paginated=false` to receive up to 200 items inline.
///
/// Response includes:
///   - `capabilities`: built-in JECP core capabilities (always full)
///   - `third_party_capabilities`: this page's third-party Provider items
///   - `next_cursor`: opaque cursor for next page (null on last page)
///   - `has_more`: true if more pages exist
///   - `page_size`: actual page size used
///
/// Headers:
///   - `ETag`: SHA256 of cursor+filter+content (304 on If-None-Match match)
///   - `Cache-Control: public, max-age=60`
pub async fn list_capabilities(
    State(state): State<AppState>,
    Query(q): Query<CatalogQuery>,
    headers: HeaderMap,
) -> Response {
    let catalog = build_capabilities_catalog();
    let mut value = serde_json::to_value(&catalog).unwrap_or_default();

    // TIER A.7 — read pool for catalog queries (separate from invoke hot path).
    let Some(pool) = state.read_pool() else {
        return Json(value).into_response();
    };

    let paginated_mode = q.paginated.unwrap_or(true);

    if !paginated_mode {
        // Legacy: full dump up to 200 items
        match database::list_active_capabilities(pool, 200).await {
            Ok(rows) if !rows.is_empty() => {
                if let Some(obj) = value.as_object_mut() {
                    let third_party: Vec<Value> = rows.iter().map(serialize_third_party).collect();
                    obj.insert("third_party_capabilities".to_string(), json!(third_party));
                    obj.insert("third_party_count".to_string(), json!(third_party.len()));
                    obj.insert("paginated".to_string(), json!(false));
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("list_active_capabilities failed (non-fatal): {}", e),
        }
        return Json(value).into_response();
    }

    // Paginated mode (default)
    let page_size = q.page_size.unwrap_or(50).clamp(1, 200);
    let cursor = match q.cursor.as_ref() {
        Some(s) => match CatalogCursor::decode(s) {
            Ok(c) => Some(c),
            Err(reason) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "jecp": "1.0",
                        "status": "failed",
                        "error": {
                            "code": "INVALID_CURSOR",
                            "message": reason,
                        },
                        "next_action": {
                            "type": "discover",
                            "api": "https://jecp.dev/v1/capabilities",
                            "hint": "Drop the cursor parameter to start from the first page.",
                        },
                    })),
                ).into_response();
            }
        },
        None => None,
    };
    let filter = CatalogFilter {
        namespace: q.namespace.clone(),
        tags: q.tags.as_ref()
            .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
            .unwrap_or_default(),
    };

    let page = match database::list_active_capabilities_paginated(pool, cursor, page_size, &filter).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("paginated catalog query failed (non-fatal): {}", e);
            return Json(value).into_response();
        }
    };

    if let Some(obj) = value.as_object_mut() {
        let third_party: Vec<Value> = page.items.iter().map(serialize_third_party).collect();
        obj.insert("third_party_capabilities".to_string(), json!(third_party));
        obj.insert("third_party_count".to_string(), json!(third_party.len()));
        obj.insert("page_size".to_string(), json!(page_size));
        obj.insert("has_more".to_string(), json!(page.has_more));
        obj.insert("next_cursor".to_string(), match &page.next_cursor {
            Some(c) => json!(c),
            None => json!(null),
        });
        obj.insert("paginated".to_string(), json!(true));
    }

    // ETag for caching — SHA256 of the response body
    let body_bytes = serde_json::to_vec(&value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&body_bytes);
    let etag = format!("\"{}\"", hex::encode(&hasher.finalize()[..16])); // first 128 bits

    // If-None-Match → 304
    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if if_none_match == etag {
            let mut resp = Response::new(axum::body::Body::empty());
            *resp.status_mut() = StatusCode::NOT_MODIFIED;
            resp.headers_mut().insert(header::ETAG, etag.parse().unwrap());
            resp.headers_mut().insert(header::CACHE_CONTROL, "public, max-age=60".parse().unwrap());
            return resp;
        }
    }

    let mut resp = Json(value).into_response();
    resp.headers_mut().insert(header::ETAG, etag.parse().unwrap());
    resp.headers_mut().insert(header::CACHE_CONTROL, "public, max-age=60".parse().unwrap());
    resp
}

fn serialize_third_party(r: &database::PublishedCapabilityInfo) -> Value {
    // v1.1.0 x402 (locked-design v1.1.1 §3.6): expose `payment_methods` per
    // action at the top level so SDK consumers don't need to parse the full
    // manifest. The field is sourced from
    // `manifest.actions[].pricing.payment_methods` and defaults to `["stripe"]`
    // when omitted. Old SDKs (no x402 awareness) ignore the field — additive.
    let actions_with_payment_methods = extract_actions_with_payment_methods(&r.parsed_json);

    json!({
        "id": r.full_id,
        "namespace": r.provider_namespace,
        "name": r.provider_display_name.clone().unwrap_or_else(|| r.full_id.clone()),
        "version": r.version,
        "description": r.description,
        "tags": r.tags,
        "total_calls": r.total_calls,
        "source": "third_party",
        "actions": actions_with_payment_methods,
        "manifest": r.parsed_json,
    })
}

/// Extract `actions[]` from a third-party manifest and project each one to
/// `{ id, payment_methods }`, defaulting `payment_methods` to `["stripe"]`
/// when the manifest omits it (locked-design v1.1.1 §3.6).
///
/// Returns an empty array when the manifest lacks an `actions` field so the
/// catalog response shape stays stable.
fn extract_actions_with_payment_methods(manifest: &Value) -> Vec<Value> {
    let Some(actions) = manifest.get("actions").and_then(|a| a.as_array()) else {
        return Vec::new();
    };
    actions
        .iter()
        .filter_map(|a| {
            let id = a.get("id").and_then(|i| i.as_str())?;
            let payment_methods: Vec<String> = a
                .get("pricing")
                .and_then(|p| p.get("payment_methods"))
                .and_then(|m| m.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| vec!["stripe".to_string()]);
            Some(json!({ "id": id, "payment_methods": payment_methods }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_methods_defaults_to_stripe_when_absent() {
        // locked-design v1.1.1 §3.6: omitted `payment_methods` MUST default to ["stripe"].
        let manifest = json!({
            "actions": [
                { "id": "translate", "pricing": { "base": 0.005 } }
            ]
        });
        let out = extract_actions_with_payment_methods(&manifest);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], "translate");
        assert_eq!(out[0]["payment_methods"], json!(["stripe"]));
    }

    #[test]
    fn payment_methods_passes_through_stripe_x402() {
        // locked-design v1.1.1 §3.6: when manifest declares both, surface both.
        let manifest = json!({
            "actions": [
                {
                    "id": "bg-remover-pro",
                    "pricing": {
                        "base": 0.20,
                        "payment_methods": ["stripe", "x402"]
                    }
                }
            ]
        });
        let out = extract_actions_with_payment_methods(&manifest);
        assert_eq!(out[0]["payment_methods"], json!(["stripe", "x402"]));
    }

    #[test]
    fn payment_methods_x402_only_capability() {
        let manifest = json!({
            "actions": [
                {
                    "id": "stream",
                    "pricing": {
                        "base": 0.001,
                        "payment_methods": ["x402"]
                    }
                }
            ]
        });
        let out = extract_actions_with_payment_methods(&manifest);
        assert_eq!(out[0]["payment_methods"], json!(["x402"]));
    }

    #[test]
    fn payment_methods_missing_actions_field_yields_empty() {
        let manifest = json!({ "capability": "foo" });
        let out = extract_actions_with_payment_methods(&manifest);
        assert!(out.is_empty());
    }

    #[test]
    fn payment_methods_empty_pricing_methods_array_falls_back_to_default() {
        // Defensive: an explicit `payment_methods: []` is treated like absent.
        let manifest = json!({
            "actions": [
                { "id": "x", "pricing": { "base": 0.01, "payment_methods": [] } }
            ]
        });
        let out = extract_actions_with_payment_methods(&manifest);
        assert_eq!(out[0]["payment_methods"], json!(["stripe"]));
    }
}
