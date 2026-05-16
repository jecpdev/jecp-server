pub mod ab_test;
pub mod analytics;
pub mod autopilot;
pub mod brand;
pub mod campaign;
pub mod thread;
pub mod trend;
pub mod types;
pub mod utils;

use crate::protocol::errors::JecpErrorCode;
use crate::protocol::types::{JecpRequest, JecpResult};

use super::CapabilityContext;

/// Route SNS Engine actions to their handlers
pub async fn execute(
    ctx: &CapabilityContext,
    req: &JecpRequest,
) -> Result<JecpResult, JecpErrorCode> {
    let output = match req.action.as_str() {
        "campaign-orchestrate" => campaign::execute(ctx, &req.input).await,
        "trend-pulse" => trend::execute(ctx, &req.input).await,
        "ab-test-launch" => ab_test::execute(ctx, &req.input).await,
        "engagement-analyze" => analytics::execute(ctx, &req.input).await,
        "thread-weave" => thread::execute(ctx, &req.input).await,
        "growth-autopilot" => autopilot::execute(ctx, &req.input).await,
        _ => Err(JecpErrorCode::UnknownAction(req.action.clone())),
    }?;

    Ok(JecpResult {
        capability: "sns-engine".to_string(),
        action: req.action.clone(),
        output,
    })
}
