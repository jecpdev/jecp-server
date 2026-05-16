//! GET /.well-known/agent-guide.json — JECP Hub Discovery Document.
//!
//! Spec: 05-discovery §4 + schemas/v1/agent-guide.json (JSON Schema 2020-12).
//!
//! v1.0.2 K4.1 — Required for v1.0.2 conformance. Conformant Hubs MUST publish
//! this document so AI clients (and the Phase 2 `npx jecp doctor` harness)
//! can discover endpoints, claimed conformance levels, supported Provenance
//! versions, and operator contact without reading the source.
//!
//! Cache strategy (per locked design §5):
//! - Body is rebuilt on each request (cheap — ~1KB JSON, no DB).
//! - `last_updated` is set to the current Hub time. Per spec, clients SHOULD
//!   treat documents older than 7 days as stale.
//! - `Cache-Control: public, max-age=300, must-revalidate` so CDN / clients
//!   may cache for 5 minutes (matches the spec's recommendation).

use axum::{extract::State, http::header, response::IntoResponse, Json};
use chrono::Utc;
use serde_json::{json, Value};

use crate::protocol::types::build_capabilities_catalog;
use crate::AppState;

/// GET /.well-known/agent-guide.json
///
/// v1.1.0 x402 (locked-design v1.1.1 §6.4): when the Hub is configured with
/// an x402 facilitator (`state.x402.is_some()`), the response includes a
/// top-level `payment` block advertising the JecpSplitter contract address,
/// the 85/10/5 split ratio, and the trusted facilitator URL. When x402 is
/// disabled at the Hub level (kill-switch off), the `payment` block is
/// omitted entirely — the Hub MUST NOT advertise a feature that is off.
pub async fn agent_guide(State(state): State<AppState>) -> impl IntoResponse {
    // v1.1.0 x402 (spec §4.4.1, locked-design v1.1.1 §6.4) — payment
    // discovery. Audit A-C8 corrected: the spec mandates a top-level
    // `payment_methods_supported` array plus a top-level `x402` block (NOT
    // `payment`). Present only when the Hub is configured for x402
    // (X402_FACILITATOR_URL set + valid Splitter address at boot). When
    // `state.x402` is None, the Hub runs in wallet-only mode and emits
    // `payment_methods_supported: ["stripe"]` with no `x402` block.
    let x402_cfg = state.x402.as_ref();
    let x402_block: Option<Value> = x402_cfg.map(|cfg| {
        let usdc_addr = format!("{}", cfg.usdc_asset);
        json!({
            "facilitator_url": cfg.facilitator.base_url_str(),
            "facilitator_operator": "x402.org",
            "supported_networks": [cfg.network.clone()],
            "supported_assets": [
                {
                    "address": usdc_addr,
                    "symbol": "USDC",
                    "decimals": 6,
                    "network": cfg.network.clone(),
                }
            ],
            "splitter_contract": format!("{}", cfg.splitter_address),
            "split_ratio": "85/10/5",
            "x402_version": 1,
            "spec_url": "https://jecp.dev/spec/v1.1.0/06-x402-integration",
        })
    });
    let payment_methods_supported: Vec<&'static str> = if x402_cfg.is_some() {
        vec!["stripe", "x402"]
    } else {
        vec!["stripe"]
    };

    let body = build_agent_guide_body(x402_block, &payment_methods_supported);

    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300, must-revalidate"),
        ],
        Json(body),
    )
}

/// Pure builder for the `/.well-known/agent-guide.json` body.
///
/// Split from the handler so unit tests can verify both the wallet-only shape
/// (`x402_block == None`) and the x402-enabled shape without constructing
/// a full `AppState`.
fn build_agent_guide_body(
    x402_block: Option<Value>,
    payment_methods_supported: &[&str],
) -> Value {
    let catalog = build_capabilities_catalog();
    let supported_capabilities: Vec<Value> = catalog
        .capabilities
        .iter()
        .map(|cap| Value::String(cap.id.clone()))
        .collect();

    // Hub origin — the Hub publishes its own URL so clients hitting either
    // setsuna-jobdonebot.fly.dev OR jecp.dev (when proxied) get correct
    // self-references. JECP_HUB_PUBLIC_URL overrides for staging/canary.
    let hub_url = std::env::var("JECP_HUB_PUBLIC_URL")
        .unwrap_or_else(|_| "https://setsuna-jobdonebot.fly.dev".to_string());

    // Spec version this Hub claims conformance with. Matches the SPEC version
    // shipped at https://jecp.dev/spec/v1.0 — bump on each errata patch.
    const SPEC_VERSION: &str = "1.0.2";

    let mut body = json!({
        "$schema":      "https://jecp.dev/schemas/v1/agent-guide.json",
        "version":       SPEC_VERSION,
        "spec_version_pinned": SPEC_VERSION,
        "last_updated":  Utc::now().to_rfc3339(),

        "vendor_prefix": "jdb",
        "hub_name":      "JobDoneBot Hub",
        "hub_operator":  "Tufe Company Inc.",
        "hub_url":       hub_url,

        "endpoints": {
            "invoke":              format!("{hub_url}/v1/invoke",        hub_url = hub_url),
            "invoke_legacy_alias": format!("{hub_url}/v1/jecp",          hub_url = hub_url),
            "capabilities":        format!("{hub_url}/v1/capabilities",  hub_url = hub_url),
            "refunds":             format!("{hub_url}/v1/refunds",       hub_url = hub_url),
            "subscriptions":       format!("{hub_url}/v1/subscriptions", hub_url = hub_url),
            "openapi":             format!("{hub_url}/openapi.json",     hub_url = hub_url),
            "health":              format!("{hub_url}/health",           hub_url = hub_url),
        },

        "supported_capabilities": supported_capabilities,

        // Phase 2 harness will retroactively define each level with PASS/FAIL
        // criteria. Listing them today is honest claim — verifiable via
        // `docker run ghcr.io/jecpdev/conformance:v1.x --target <hub_url>`
        // when that image ships in Phase 2.
        "conformance_levels": [
            "Hub-Core",
            "Hub-Streaming"
        ],

        // Provenance v2 RECOMMENDED at silver+, REQUIRED at platinum (per
        // spec 02-authentication §5.2). v1 sunset 2026-11-01.
        "provenance_versions_supported": ["v1", "v2"],

        // Auth surfaces.
        "register_endpoint": "https://jecp.dev/api/agents/register",

        "contact": {
            "support":      "support@jecp.dev",
            "security":     "security@jecp.dev",
            "security_txt": "https://jecp.dev/.well-known/security.txt",
            "status_url":   "https://status.jecp.dev"
        },

        "documentation": {
            "homepage":   "https://jecp.dev",
            "spec":       format!("https://jecp.dev/spec/v{SPEC_VERSION}/"),
            "quickstart": "https://jecp.dev/quickstart",
            "errors":     "https://jecp.dev/errors"
        },

        // Capacity-planning hint, not enforced. Real limits are per-Agent
        // tier in the rate_limit middleware (Bronze=10rpm at v1.0.2).
        "rate_limits_default_rpm": {
            "bronze":   10,
            "silver":   60,
            "gold":    300,
            "platinum": 1200
        },

        "currencies_accepted": ["USD", "USDC"],

        // D6 admiral decision: disclose single-region today (creates Phase 3
        // multi-region pull + builds operator trust through honesty).
        "regions": ["nrt"],

        "replay_cache_mode": "local",

        "trust_policy": {
            "default_tier":             "bronze",
            "provenance_v2_recommended": "silver",
            "provenance_v2_required":    "platinum",
            "v1_sunset":                 "2026-11-01"
        },

        "extensions": {
            "x-jdb-streaming_protocol": "SSE",
            "x-jdb-revenue_split":      { "provider": 0.85, "platform": 0.10, "hub": 0.05 }
        }
    });

    // Spec §4.4.1 requires `payment_methods_supported` array at the top level
    // (always present; defaults to ["stripe"] for wallet-only Hubs).
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "payment_methods_supported".to_string(),
            Value::Array(
                payment_methods_supported
                    .iter()
                    .map(|s| Value::String((*s).to_string()))
                    .collect(),
            ),
        );
    }

    if let Some(x402) = x402_block {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("x402".to_string(), x402);
        }
    }

    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_guide_has_all_required_fields() {
        // Wallet-only Hub (no x402 config): x402 block MUST be absent.
        let v = build_agent_guide_body(None, &["stripe"]);

        // Schema 2020-12 required fields.
        for key in [
            "version", "last_updated", "vendor_prefix",
            "hub_name", "hub_url",
            "supported_capabilities", "conformance_levels",
            "register_endpoint", "contact",
        ] {
            assert!(
                v.get(key).is_some(),
                "missing required field: {} (schema-required)",
                key
            );
        }

        // contact.support is required-nested.
        let contact = v.get("contact").unwrap();
        assert!(contact.get("support").is_some(),
            "contact.support is schema-required");

        // version pattern: ^\d+\.\d+\.\d+$
        let version = v["version"].as_str().unwrap();
        let re = regex::Regex::new(r"^\d+\.\d+\.\d+$").unwrap();
        assert!(re.is_match(version), "version='{version}' must match semver");

        // vendor_prefix pattern: ^[a-z]{2,8}$
        let vp = v["vendor_prefix"].as_str().unwrap();
        assert!(vp.len() >= 2 && vp.len() <= 8, "vendor_prefix '{vp}' length");
        assert!(vp.chars().all(|c| c.is_ascii_lowercase()),
            "vendor_prefix '{vp}' must be lowercase");

        // hub_url MUST be HTTPS.
        let hub_url = v["hub_url"].as_str().unwrap();
        assert!(hub_url.starts_with("https://"), "hub_url '{hub_url}' must be HTTPS");

        // conformance_levels MUST have ≥1 entry from the enum.
        let levels = v["conformance_levels"].as_array().unwrap();
        assert!(!levels.is_empty(), "conformance_levels MUST have ≥1 entry");
        let allowed = [
            "Hub-Core", "Hub-Streaming", "Hub-Composite",
            "Provider-API", "SDK-Client",
        ];
        for l in levels {
            let s = l.as_str().unwrap();
            assert!(allowed.contains(&s),
                "conformance level '{s}' not in spec enum");
        }

        // Spec §4.4.1 / Audit A-C8: `payment_methods_supported` MUST be present
        // (defaults to ["stripe"] when x402 is disabled). Top-level `x402`
        // block MUST be absent when x402 is off.
        assert_eq!(
            v["payment_methods_supported"], json!(["stripe"]),
            "payment_methods_supported must be ['stripe'] when x402 is off"
        );
        assert!(
            v.get("x402").is_none(),
            "x402 block must be omitted when x402 is disabled at the Hub"
        );
    }

    #[test]
    fn agent_guide_includes_x402_block_when_x402_enabled() {
        // Spec §4.4.1 / Audit A-C8: when x402 is configured, the response MUST
        // include top-level `payment_methods_supported: ["stripe","x402"]` and
        // a top-level `x402` block with splitter_contract, supported_assets,
        // x402_version=1, spec_url, etc.
        let x402 = json!({
            "facilitator_url": "https://x402.org/facilitator",
            "facilitator_operator": "x402.org",
            "supported_networks": ["base"],
            "supported_assets": [{
                "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "symbol": "USDC",
                "decimals": 6,
                "network": "base"
            }],
            "splitter_contract": "0x0000000000000000000000000000000000000001",
            "split_ratio": "85/10/5",
            "x402_version": 1,
            "spec_url": "https://jecp.dev/spec/v1.1.0/06-x402-integration",
        });
        let v = build_agent_guide_body(Some(x402.clone()), &["stripe", "x402"]);
        assert_eq!(v["payment_methods_supported"], json!(["stripe", "x402"]));
        let block = v.get("x402").expect("x402 block must be present");
        assert_eq!(block["x402_version"], 1);
        assert_eq!(block["split_ratio"], "85/10/5");
        assert_eq!(block["splitter_contract"], "0x0000000000000000000000000000000000000001");
        assert_eq!(block["facilitator_url"], "https://x402.org/facilitator");
        assert_eq!(block["supported_networks"], json!(["base"]));
        let assets = block["supported_assets"].as_array().expect("supported_assets array");
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0]["symbol"], "USDC");
        assert_eq!(assets[0]["decimals"], 6);
        assert!(block["spec_url"].as_str().unwrap().contains("x402-integration"));
    }

    #[test]
    fn agent_guide_omits_x402_block_when_x402_disabled() {
        // Kill-switch off: MUST omit the x402 block entirely. We MUST NOT
        // lie about a feature that's off.
        let v = build_agent_guide_body(None, &["stripe"]);
        assert!(v.get("x402").is_none());
        assert_eq!(v["payment_methods_supported"], json!(["stripe"]));
    }
}
