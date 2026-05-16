use axum::Json;
use serde_json::{json, Value};

use crate::protocol::types::build_capabilities_catalog;

/// GET /.well-known/agent.json — JECP-extended Agent Card
pub async fn agent_card() -> Json<Value> {
    let catalog = build_capabilities_catalog();

    let capabilities_json: Vec<Value> = catalog.capabilities.iter().map(|cap| {
        json!({
            "id": cap.id,
            "name": cap.name,
            "description": cap.description,
            "actions": cap.actions.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
            "pricing": cap.pricing
        })
    }).collect();

    Json(json!({
        "name": "JECP Reference Hub",
        "description": "JECP — Joint Execution Capability Protocol. Open commerce protocol for AI agents.",
        "url": "https://jecp.dev",
        "version": "1.0.0",
        "protocol": {
            "name": "JECP",
            "spec": "https://github.com/jecpdev/jecp-spec",
            "operator_disclosure": "https://jecp.dev/about"
        },
        "jecp": {
            "endpoint": "https://jecp.dev/v1/jecp",
            "version": "1.0",
            "engine": "jecp",
            "capabilities": capabilities_json,
            "streaming": true,
            "mandate_required": false
        },
        "authentication": {
            "schemes": ["api_key", "mandate"],
            "api_key_header": "X-API-Key",
            "agent_id_header": "X-Agent-ID",
            "registration": "https://jecp.dev/api/agents/register"
        }
    }))
}
