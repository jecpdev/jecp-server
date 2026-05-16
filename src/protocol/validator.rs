use super::errors::JecpErrorCode;
use super::types::{Capability, JecpRequest};
use chrono::Utc;

/// Validate a JECP request before processing
pub fn validate_request(req: &JecpRequest) -> Result<(), JecpErrorCode> {
    // 1. Protocol version
    if req.jecp != "1.0" {
        return Err(JecpErrorCode::UnsupportedVersion(req.jecp.clone()));
    }

    // 2. Request ID must conform to spec pattern: ^[A-Za-z0-9_-]{4,64}$
    //    (Sprint 4.5 / Spec compliance C2)
    if req.id.len() < 4 || req.id.len() > 64 {
        return Err(JecpErrorCode::InvalidRequest(format!(
            "id length must be 4..=64 chars (got {})",
            req.id.len()
        )));
    }
    if !req
        .id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(JecpErrorCode::InvalidRequest(
            "id must match ^[A-Za-z0-9_-]+$".to_string(),
        ));
    }

    // 3. Action must not be empty
    if req.action.is_empty() {
        return Err(JecpErrorCode::InvalidRequest(
            "Action is required".to_string(),
        ));
    }

    // 4. Validate action exists for capability
    validate_action(&req.capability, &req.action)?;

    // 5. Validate mandate if present
    if let Some(ref mandate) = req.mandate {
        if mandate.agent_id.is_empty() || mandate.api_key.is_empty() {
            return Err(JecpErrorCode::InvalidRequest(
                "Mandate requires agent_id and api_key".to_string(),
            ));
        }
        if let Some(expires) = mandate.expires_at {
            if expires < Utc::now() {
                return Err(JecpErrorCode::MandateExpired);
            }
        }
    }

    Ok(())
}

/// Validate that the action is valid for the given capability
fn validate_action(capability: &Capability, action: &str) -> Result<(), JecpErrorCode> {
    let valid_actions: &[&str] = match capability {
        Capability::DocumentPipeline => &[
            "generate-invoice",
            "generate-quote",
            "generate-report",
            "generate-contract",
            "generate-receipt",
        ],
        Capability::FileChain => &["image-pipeline", "pdf-pipeline", "batch-convert"],
        Capability::ContentFactory => &[
            "generate-blog",
            "generate-social",
            "rewrite",
            "translate",
            "summarize",
        ],
        Capability::DataInsight => &["analyze-csv", "analyze-json", "forecast"],
        Capability::Workflow => &["invoice-and-notify", "content-campaign", "data-report-mail"],
        Capability::SnsEngine => &[
            "campaign-orchestrate",
            "trend-pulse",
            "ab-test-launch",
            "engagement-analyze",
            "thread-weave",
            "growth-autopilot",
        ],
    };

    if !valid_actions.contains(&action) {
        return Err(JecpErrorCode::UnknownAction(format!(
            "{} is not a valid action for {}",
            action, capability
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::{Delivery, Mandate};
    use serde_json::json;

    fn make_request(capability: Capability, action: &str) -> JecpRequest {
        JecpRequest {
            jecp: "1.0".to_string(),
            id: "test-001".to_string(),
            capability,
            action: action.to_string(),
            mandate: None,
            input: json!({}),
            delivery: Delivery::default(),
        }
    }

    #[test]
    fn test_valid_request() {
        let req = make_request(Capability::ContentFactory, "generate-blog");
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn test_invalid_version() {
        let mut req = make_request(Capability::ContentFactory, "generate-blog");
        req.jecp = "2.0".to_string();
        let err = validate_request(&req).unwrap_err();
        assert_eq!(err.code(), "UNSUPPORTED_VERSION");
    }

    #[test]
    fn test_empty_id() {
        let mut req = make_request(Capability::ContentFactory, "generate-blog");
        req.id = "".to_string();
        let err = validate_request(&req).unwrap_err();
        assert_eq!(err.code(), "INVALID_REQUEST");
    }

    #[test]
    fn test_invalid_action() {
        let req = make_request(Capability::ContentFactory, "nonexistent-action");
        let err = validate_request(&req).unwrap_err();
        assert_eq!(err.code(), "UNKNOWN_ACTION");
    }

    #[test]
    fn test_expired_mandate() {
        let mut req = make_request(Capability::ContentFactory, "generate-blog");
        req.mandate = Some(Mandate {
            agent_id: "jdb_ag_test".to_string(),
            api_key: "jdb_ak_test".to_string(),
            budget_usdc: Some(1.0),
            expires_at: Some(chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc)),
            provenance_hash: None,
        });
        let err = validate_request(&req).unwrap_err();
        assert_eq!(err.code(), "MANDATE_EXPIRED");
    }

    #[test]
    fn test_all_capabilities_have_valid_actions() {
        let tests = vec![
            (Capability::DocumentPipeline, "generate-invoice"),
            (Capability::DocumentPipeline, "generate-quote"),
            (Capability::FileChain, "image-pipeline"),
            (Capability::ContentFactory, "generate-blog"),
            (Capability::ContentFactory, "summarize"),
            (Capability::DataInsight, "analyze-csv"),
            (Capability::DataInsight, "forecast"),
            (Capability::Workflow, "invoice-and-notify"),
            (Capability::Workflow, "content-campaign"),
        ];
        for (cap, action) in tests {
            let req = make_request(cap, action);
            assert!(validate_request(&req).is_ok());
        }
    }
}
