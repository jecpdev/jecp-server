use serde_json::json;

use crate::capabilities::CapabilityContext;
use crate::protocol::errors::JecpErrorCode;
use crate::services::claude::ClaudeMessage;
use crate::services::sns_bridge::{BridgePostRequest, BridgeScheduleRequest};

use super::brand::{self, BRAND_SYSTEM_PROMPT, PRIORITY_TOOL_IDS};
use super::types::{jst_to_utc, OPTIMAL_HOURS_JST};
use super::utils::parse_json_response;

/// thread-weave action
///
/// 1. Ask Claude to generate a multi-post thread on a topic
/// 2. Each post works standalone AND forms a coherent narrative
/// 3. If auto_post=true, post immediately with reply_to chaining
/// 4. Otherwise schedule with thread_position metadata
pub async fn execute(
    ctx: &CapabilityContext,
    input: &serde_json::Value,
) -> Result<serde_json::Value, JecpErrorCode> {
    let platform = input["platform"].as_str().unwrap_or("x");
    let topic = input["topic"]
        .as_str()
        .ok_or_else(|| JecpErrorCode::ValidationFailed("topic is required".to_string()))?;
    let thread_length = input["thread_length"].as_u64().unwrap_or(5).min(10).max(3) as u32;
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

    // ─── Step 1: Generate thread content ──────────────────────
    let prompt = format!(
        "Create a {thread_length}-post thread for {platform} about: {topic}\n\n\
         Tools to weave in: {tool_ids}\n\
         Language: {language}\n\
         Character limit per post: {char_limit}\n\n\
         Rules:\n\
         - Post 1 must be a strong hook that makes people want to read the whole thread\n\
         - Each post MUST work as a standalone post if seen alone\n\
         - Together they tell a complete story/argument\n\
         - Naturally mention JobDoneBot tools where relevant (don't force it)\n\
         - For X: include 1/N numbering at the start of each post\n\
         - Last post must have a clear CTA\n\n\
         Return a JSON object with:\n\
         - thread_title: A title describing the thread theme\n\
         - posts: Array of {thread_length} objects, each with:\n\
           - position: Number (1 to {thread_length})\n\
           - text: Post text (under {char_limit} chars, include N/M numbering)\n\
           - hashtags: Array of 1-3 hashtags (without # prefix)\n\
           - tool_id: Tool mentioned in this post (null if none)\n\
           - hook_type: What makes this post engaging standalone",
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
        .map_err(|e| JecpErrorCode::ServiceError(format!("Claude thread generation failed: {}", e)))?;

    let result: serde_json::Value = parse_json_response(&response).unwrap_or_else(|| {
        json!({
            "thread_title": topic,
            "posts": []
        })
    });

    // ─── Step 2: Brand voice validation ───────────────────────
    let posts = result["posts"].as_array().cloned().unwrap_or_default();
    for post in &posts {
        if let Some(text) = post["text"].as_str() {
            let violations = brand::validate_brand_voice(text, platform);
            if !violations.is_empty() {
                tracing::warn!(
                    "Brand violations in thread post {}: {:?}",
                    post["position"],
                    violations
                );
            }
        }
    }

    // ─── Step 3: Post or schedule ─────────────────────────────
    let thread_total = posts.len() as i32;
    let mut post_results = Vec::new();

    if auto_post {
        // Post immediately with reply_to chaining
        if let Some(bridge) = &ctx.sns_bridge {
            let mut prev_external_id: Option<String> = None;

            for post in &posts {
                let text = post["text"].as_str().unwrap_or("").to_string();
                if text.is_empty() {
                    continue;
                }

                let hashtags: Option<Vec<String>> = post["hashtags"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());

                // Attach video only to the first post in the thread
                let video_url = if prev_external_id.is_none() {
                    post["tool_id"]
                        .as_str()
                        .and_then(brand::get_random_video_url)
                } else {
                    None
                };

                let req = BridgePostRequest {
                    platform: platform.to_string(),
                    text,
                    hashtags,
                    media_url: video_url,
                    reply_to_external_id: prev_external_id.clone(),
                };

                match bridge.post(&req).await {
                    Ok(resp) => {
                        let posted = resp.success;
                        if posted {
                            prev_external_id = resp.external_id.clone();
                        }
                        post_results.push(json!({
                            "position": post["position"],
                            "posted": posted,
                            "external_id": resp.external_id,
                            "mock": resp.mock,
                        }));
                    }
                    Err(e) => {
                        post_results.push(json!({
                            "position": post["position"],
                            "posted": false,
                            "error": e,
                        }));
                        // Stop the chain on error
                        break;
                    }
                }

                // Small delay between posts to avoid rate limits
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        } else {
            post_results.push(json!({
                "posted": false,
                "error": "SNS Bridge not configured",
            }));
        }
    } else {
        // Schedule posts with 5-minute intervals
        if let Some(bridge) = &ctx.sns_bridge {
            let thread_id = format!("thrd_{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]);
            let today = chrono::Utc::now().date_naive();
            let base_hour_jst = OPTIMAL_HOURS_JST[0];
            let base_hour_utc = jst_to_utc(base_hour_jst);

            for (i, post) in posts.iter().enumerate() {
                let text = post["text"].as_str().unwrap_or("").to_string();
                if text.is_empty() {
                    continue;
                }

                let hashtags: Option<Vec<String>> = post["hashtags"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());

                let tool_id = post["tool_id"].as_str().map(|s| s.to_string());
                let minutes = (i as u32) * 5; // 5-minute intervals

                let post_id = format!("snsp_{}_{:02}", thread_id, i + 1);
                let scheduled_at = format!("{}T{:02}:{:02}:00Z", today, base_hour_utc, minutes);

                // Attach video only to the first post in the thread
                let thread_video_url = if i == 0 {
                    tool_id.as_ref().and_then(|tid| brand::get_random_video_url(tid))
                } else {
                    None
                };

                let schedule_req = BridgeScheduleRequest {
                    id: post_id.clone(),
                    campaign_id: None,
                    platform: platform.to_string(),
                    text,
                    hashtags,
                    media_url: thread_video_url,
                    reply_to_external_id: None, // Worker will chain replies
                    thread_position: Some(i as i32 + 1),
                    thread_total: Some(thread_total),
                    language: language.to_string(),
                    creative_angle: Some("thread".to_string()),
                    tool_id,
                    scheduled_at,
                };

                match bridge.schedule(&schedule_req).await {
                    Ok(resp) => {
                        post_results.push(json!({
                            "position": i + 1,
                            "scheduled": resp.success,
                            "post_id": resp.id,
                        }));
                    }
                    Err(e) => {
                        post_results.push(json!({
                            "position": i + 1,
                            "scheduled": false,
                            "error": e,
                        }));
                    }
                }
            }
        }
    }

    Ok(json!({
        "thread_title": result["thread_title"],
        "thread_length": thread_total,
        "posts": result["posts"],
        "post_results": post_results,
        "auto_posted": auto_post,
        "platform": platform,
    }))
}
