pub mod content_factory;
pub mod data_insight;
pub mod document_pipeline;
pub mod file_chain;
pub mod sns_engine;
pub mod workflow;

use crate::protocol::errors::JecpErrorCode;
use crate::protocol::types::{Capability, JecpRequest, JecpResult};
use crate::services::claude::ClaudeClient;
use crate::services::sns_bridge::SnsBridge;
use crate::services::storage::TempStorage;
use sqlx::PgPool;

/// Shared state passed to capability handlers
#[derive(Clone)]
pub struct CapabilityContext {
    pub claude: ClaudeClient,
    pub storage: TempStorage,
    pub pool: Option<PgPool>,
    pub sns_bridge: Option<SnsBridge>,
}

/// Route a JECP request to the appropriate capability handler
pub async fn execute_capability(
    ctx: &CapabilityContext,
    req: &JecpRequest,
) -> Result<JecpResult, JecpErrorCode> {
    match req.capability {
        Capability::DocumentPipeline => document_pipeline::execute(ctx, req).await,
        Capability::FileChain => file_chain::execute(ctx, req).await,
        Capability::ContentFactory => content_factory::execute(ctx, req).await,
        Capability::DataInsight => data_insight::execute(ctx, req).await,
        Capability::Workflow => workflow::execute(ctx, req).await,
        Capability::SnsEngine => sns_engine::execute(ctx, req).await,
    }
}
