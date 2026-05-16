use chrono::Utc;

use crate::protocol::errors::JecpErrorCode;
use crate::protocol::types::{Mandate, get_action_price, Capability};

/// Validated mandate with remaining budget info
#[derive(Debug, Clone)]
pub struct ValidatedMandate {
    pub agent_id: String,
    pub api_key: String,
    pub budget_remaining: Option<f64>,
    pub cost: f64,
}

/// Validate a mandate has sufficient budget for the requested action
pub fn validate_mandate(
    mandate: &Option<Mandate>,
    capability: &Capability,
    action: &str,
) -> Result<ValidatedMandate, JecpErrorCode> {
    let cost = get_action_price(capability, action);

    match mandate {
        Some(m) => {
            // Check expiry
            if let Some(expires) = m.expires_at {
                if expires < Utc::now() {
                    return Err(JecpErrorCode::MandateExpired);
                }
            }

            // Check budget
            if let Some(budget) = m.budget_usdc {
                if budget < cost {
                    return Err(JecpErrorCode::InsufficientBudget {
                        needed: cost,
                        remaining: budget,
                    });
                }
            }

            Ok(ValidatedMandate {
                agent_id: m.agent_id.clone(),
                api_key: m.api_key.clone(),
                budget_remaining: m.budget_usdc.map(|b| b - cost),
                cost,
            })
        }
        None => {
            // No mandate — will use free tier or API key from headers
            Ok(ValidatedMandate {
                agent_id: String::new(),
                api_key: String::new(),
                budget_remaining: None,
                cost,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_valid_mandate() {
        let mandate = Some(Mandate {
            agent_id: "jdb_ag_test".to_string(),
            api_key: "jdb_ak_test".to_string(),
            budget_usdc: Some(1.0),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            provenance_hash: None,
        });
        let result = validate_mandate(&mandate, &Capability::ContentFactory, "generate-blog");
        assert!(result.is_ok());
        let vm = result.unwrap();
        assert_eq!(vm.cost, 0.02);
        assert!((vm.budget_remaining.unwrap() - 0.98).abs() < f64::EPSILON);
    }

    #[test]
    fn test_insufficient_budget() {
        let mandate = Some(Mandate {
            agent_id: "jdb_ag_test".to_string(),
            api_key: "jdb_ak_test".to_string(),
            budget_usdc: Some(0.001),
            expires_at: None,
            provenance_hash: None,
        });
        let result = validate_mandate(&mandate, &Capability::ContentFactory, "generate-blog");
        assert!(matches!(result, Err(JecpErrorCode::InsufficientBudget { .. })));
    }

    #[test]
    fn test_no_mandate() {
        let result = validate_mandate(&None, &Capability::ContentFactory, "summarize");
        assert!(result.is_ok());
    }
}
