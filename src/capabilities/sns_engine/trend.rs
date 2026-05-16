use serde_json::json;

use crate::capabilities::CapabilityContext;
use crate::protocol::errors::JecpErrorCode;
use crate::services::claude::ClaudeMessage;
use crate::services::sns_bridge::BridgePostRequest;

use super::brand::{self, BRAND_SYSTEM_PROMPT, PRIORITY_TOOL_IDS};
use super::utils::parse_json_response;

/// trend-pulse action
///
/// 1. Ask Claude to identify trending topics relevant to JobDoneBot tools
/// 2. Generate viral content using Hook→Pain→Solution→Result→CTA framework
/// 3. If auto_post=true, post immediately via Bridge
pub async fn execute(
    ctx: &CapabilityContext,
    input: &serde_json::Value,
) -> Result<serde_json::Value, JecpErrorCode> {
    let platform = input["platform"].as_str().unwrap_or("x");
    let auto_post = input["auto_post"].as_bool().unwrap_or(false);
    let language = input["language"].as_str().unwrap_or("ja");

    let tool_ids: Vec<String> = input["tool_ids"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(|| PRIORITY_TOOL_IDS.iter().map(|s| s.to_string()).collect());

    let char_limit = match platform {
        "tiktok" => brand::TIKTOK_CHAR_LIMIT,
        _ => brand::X_CHAR_LIMIT,
    };

    // ─── Step 1: Trend detection + content generation ──────────
    let prompt = format!(
        "You are monitoring social media trends in Japan right now.\n\n\
         Available tools to promote: {tool_ids}\n\
         Platform: {platform}\n\
         Language: {language}\n\
         Character limit: {char_limit}\n\n\
         Tasks:\n\
         1. Identify 3 current trending topics/pain points that relate to these tools\n\
         2. For the BEST trend, generate a viral post using this framework:\n\
            Hook (attention grab) → Pain (problem) → Solution (tool) → Result (outcome) → CTA\n\
         3. Generate 2 alternative posts with different creative angles\n\n\
         Return a JSON object with:\n\
         - detected_trends: Array of 3 objects with: topic, relevance_score (0-1), related_tool_id\n\
         - primary_post: Object with: text (under {char_limit} chars), hashtags (array), \
           hook_type, tool_id, framework (the 5 steps used)\n\
         - alternative_posts: Array of 2 objects with same structure as primary_post",
        tool_ids = tool_ids.join(", "),
    );

    let response = ctx
        .claude
        .complete(
            Some(BRAND_SYSTEM_PROMPT),
            vec![ClaudeMessage {
                role: "user".to_string(),
                content: prompt,
            }],
            4096,
        )
        .await
        .map_err(|e| JecpErrorCode::ServiceError(format!("Claude trend analysis failed: {}", e)))?;

    let result: serde_json::Value = parse_json_response(&response).unwrap_or_else(|| {
        json!({
            "detected_trends": [],
            "primary_post": { "text": "", "hashtags": [], "tool_id": "" },
            "alternative_posts": []
        })
    });

    // ─── Step 2: Brand voice validation ────────────────────────
    if let Some(text) = result["primary_post"]["text"].as_str() {
        let violations = brand::validate_brand_voice(text, platform);
        if !violations.is_empty() {
            tracing::warn!("Brand violations in trend-pulse post: {:?}", violations);
        }
    }

    // ─── Step 3: Auto-post if requested ────────────────────────
    let mut post_result = json!(null);

    if auto_post {
        if let Some(bridge) = &ctx.sns_bridge {
            let text = result["primary_post"]["text"]
                .as_str()
                .unwrap_or("")
                .to_string();

            let hashtags: Option<Vec<String>> = result["primary_post"]["hashtags"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());

            if !text.is_empty() {
                let tool_id_str = result["primary_post"]["tool_id"]
                    .as_str()
                    .unwrap_or("");
                let video_url = if !tool_id_str.is_empty() {
                    brand::get_random_video_url(tool_id_str)
                } else {
                    None
                };

                let req = BridgePostRequest {
                    platform: platform.to_string(),
                    text,
                    hashtags,
                    media_url: video_url,
                    reply_to_external_id: None,
                };

                match bridge.post(&req).await {
                    Ok(resp) => {
                        post_result = json!({
                            "posted": true,
                            "external_id": resp.external_id,
                            "mock": resp.mock,
                        });
                    }
                    Err(e) => {
                        post_result = json!({
                            "posted": false,
                            "error": e,
                        });
                    }
                }
            }
        } else {
            post_result = json!({
                "posted": false,
                "error": "SNS Bridge not configured",
            });
        }
    }

    Ok(json!({
        "detected_trends": result["detected_trends"],
        "primary_post": result["primary_post"],
        "alternative_posts": result["alternative_posts"],
        "auto_post_result": post_result,
        "platform": platform,
    }))
}
