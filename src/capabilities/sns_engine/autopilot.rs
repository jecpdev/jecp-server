use serde_json::json;

use crate::capabilities::CapabilityContext;
use crate::protocol::errors::JecpErrorCode;
use crate::services::claude::ClaudeMessage;
use crate::services::sns_bridge::BridgeScheduleRequest;

use super::brand::{self, BRAND_SYSTEM_PROMPT, PRIORITY_TOOL_IDS, POST_TYPE_WEIGHTS};
use super::types::{jst_to_utc, OPTIMAL_HOURS_JST};
use super::utils::parse_json_response;

/// growth-autopilot action
///
/// Fully autonomous daily growth cycle:
/// 1. Fetch past 7 days of engagement data from DB
/// 2. Load content learnings (what works, what doesn't)
/// 3. Ask Claude to analyze + generate optimized content plan
/// 4. Generate next day's posts with data-driven parameters
/// 5. Schedule all posts via Bridge
/// 6. Store new learnings in DB
/// 7. Return summary report
pub async fn execute(
    ctx: &CapabilityContext,
    input: &serde_json::Value,
) -> Result<serde_json::Value, JecpErrorCode> {
    let platforms: Vec<String> = input["platforms"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(|| vec!["x".to_string()]);

    let posts_per_day = input["posts_per_day"].as_u64().unwrap_or(4).min(8).max(2) as u32;
    let language = input["language"].as_str().unwrap_or("ja");
    let lookback_days = input["lookback_days"].as_u64().unwrap_or(7).min(30).max(3) as i32;

    let tool_ids: Vec<String> = input["tool_ids"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(|| PRIORITY_TOOL_IDS.iter().map(|s| s.to_string()).collect());

    // ─── Step 1: Gather historical performance ────────────────
    let mut recent_posts = Vec::new();
    let mut recent_engagement = Vec::new();
    let mut content_learnings = Vec::new();

    if let Some(pool) = &ctx.pool {
        // Recent published posts with their engagement
        let posts: Vec<(String, String, String, Option<String>, Option<String>, Option<String>)> =
            sqlx::query_as(
                "SELECT sp.id, sp.platform, sp.text, sp.creative_angle, sp.tool_id, sp.external_id \
                 FROM sns_scheduled_posts sp \
                 WHERE sp.status = 'published' \
                   AND sp.posted_at > NOW() - make_interval(days => $1) \
                 ORDER BY sp.posted_at DESC \
                 LIMIT 50"
            )
            .persistent(false)
            .bind(lookback_days)
            .fetch_all(pool)
            .await
            .unwrap_or_default();

        for (id, platform, text, angle, tool_id, external_id) in &posts {
            recent_posts.push(json!({
                "id": id,
                "platform": platform,
                "text": text.chars().take(100).collect::<String>(),
                "creative_angle": angle,
                "tool_id": tool_id,
                "external_id": external_id,
            }));
        }

        // Engagement snapshots for those posts
        let snapshots: Vec<(String, i32, i32, i32, i32, i32)> = sqlx::query_as(
            "SELECT es.post_id, es.views, es.likes, es.comments, es.shares, es.link_clicks \
             FROM sns_engagement_snapshots es \
             INNER JOIN sns_scheduled_posts sp ON sp.id = es.post_id \
             WHERE sp.posted_at > NOW() - make_interval(days => $1) \
             ORDER BY es.snapshot_at DESC \
             LIMIT 100"
        )
        .persistent(false)
        .bind(lookback_days)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        for (post_id, views, likes, comments, shares, clicks) in &snapshots {
            recent_engagement.push(json!({
                "post_id": post_id,
                "views": views,
                "likes": likes,
                "comments": comments,
                "shares": shares,
                "link_clicks": clicks,
                "engagement_rate": if *views > 0 {
                    (*likes + *comments + *shares) as f64 / *views as f64
                } else { 0.0 },
            }));
        }

        // Existing content learnings
        let learnings: Vec<(String, String, String, f64, i32)> = sqlx::query_as(
            "SELECT platform, learning_type, key, score::float8, sample_size \
             FROM sns_content_learnings \
             WHERE period_end > NOW() - INTERVAL '30 days' \
             ORDER BY score DESC \
             LIMIT 20"
        )
        .persistent(false)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        for (platform, ltype, key, score, sample_size) in &learnings {
            content_learnings.push(json!({
                "platform": platform,
                "type": ltype,
                "key": key,
                "score": score,
                "sample_size": sample_size,
            }));
        }
    }

    // ─── Step 2: Claude analysis + content generation ─────────
    let default_weights: Vec<serde_json::Value> = POST_TYPE_WEIGHTS
        .iter()
        .map(|(name, weight)| json!({"type": name, "weight": weight}))
        .collect();

    let platform_guidelines: Vec<String> = platforms
        .iter()
        .map(|p| format!("- {}: {}", p, brand::get_platform_prompt(p)))
        .collect();

    let prompt = format!(
        "You are the Growth Autopilot for JobDoneBot's SNS accounts.\n\n\
         === CONTEXT ===\n\
         Platforms: {platforms}\n\
         Language: {language}\n\
         Posts to generate: {posts_per_day}\n\
         Available tools: {tool_ids}\n\
         Default post type weights: {default_weights}\n\n\
         === PLATFORM GUIDELINES ===\n\
         {platform_guidelines}\n\n\
         === HISTORICAL DATA (past {lookback_days} days) ===\n\
         Recent posts ({post_count}):\n{recent_posts}\n\n\
         Engagement data ({eng_count} snapshots):\n{recent_engagement}\n\n\
         Content learnings:\n{content_learnings}\n\n\
         === TASKS ===\n\
         1. ANALYZE: Review the historical data. What's working? What's not?\n\
         2. OPTIMIZE: Adjust post type distribution based on data (or keep defaults if no data)\n\
         3. GENERATE: Create {posts_per_day} posts for tomorrow, each optimized based on learnings\n\
         4. LEARN: Extract 2-3 new content learnings from the data\n\n\
         Return a JSON object with:\n\
         - analysis_summary: 2-3 sentence performance summary\n\
         - optimized_weights: Array of objects with type and weight (must sum to 100)\n\
         - posts: Array of {posts_per_day} objects, each with:\n\
           - platform: Target platform\n\
           - text: Post text (under platform char limit)\n\
           - hashtags: Array of 2-4 hashtags (without #)\n\
           - post_type: One of tool-tip, speed-flex, new-feature, trending\n\
           - creative_angle: The approach used\n\
           - tool_id: Tool promoted (from available list)\n\
           - confidence: 0-1 how confident you are this will perform well\n\
         - new_learnings: Array of 2-3 objects with:\n\
           - learning_type: category (e.g., best_time, best_angle, best_tool, best_hashtag)\n\
           - key: specific finding\n\
           - score: effectiveness score 0-1\n\
           - reasoning: why this learning was extracted",
        platforms = platforms.join(", "),
        tool_ids = tool_ids.join(", "),
        default_weights = serde_json::to_string(&default_weights).unwrap_or_default(),
        platform_guidelines = platform_guidelines.join("\n         "),
        post_count = recent_posts.len(),
        recent_posts = serde_json::to_string_pretty(&recent_posts).unwrap_or("[]".to_string()),
        eng_count = recent_engagement.len(),
        recent_engagement = serde_json::to_string_pretty(&recent_engagement).unwrap_or("[]".to_string()),
        content_learnings = serde_json::to_string_pretty(&content_learnings).unwrap_or("[]".to_string()),
    );

    // Build system prompt with platform-specific guidelines
    let platform_system_addendum: String = platforms
        .iter()
        .map(|p| format!("\n\nPLATFORM GUIDELINE [{}]: {}", p, brand::get_platform_prompt(p)))
        .collect();
    let system_prompt = format!("{}{}", BRAND_SYSTEM_PROMPT, platform_system_addendum);

    let response = ctx
        .claude
        .complete(
            Some(&system_prompt),
            vec![ClaudeMessage {
                role: "user".to_string(),
                content: prompt,
            }],
            4096,
        )
        .await
        .map_err(|e| JecpErrorCode::ServiceError(format!("Claude autopilot generation failed: {}", e)))?;

    let result: serde_json::Value = parse_json_response(&response).unwrap_or_else(|| {
        json!({
            "analysis_summary": "No historical data available. Using default strategy.",
            "optimized_weights": default_weights,
            "posts": [],
            "new_learnings": [],
        })
    });

    // ─── Step 3: Brand validation + scheduling ────────────────
    let posts = result["posts"].as_array().cloned().unwrap_or_default();
    let tomorrow = (chrono::Utc::now() + chrono::Duration::days(1)).date_naive();
    let mut scheduled_posts = Vec::new();
    let autopilot_id = format!("auto_{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]);

    if let Some(bridge) = &ctx.sns_bridge {
        for (i, post) in posts.iter().enumerate() {
            let text = post["text"].as_str().unwrap_or("").to_string();
            if text.is_empty() {
                continue;
            }

            let platform = post["platform"].as_str().unwrap_or("x");

            // Brand voice check (platform-aware)
            let violations = brand::validate_brand_voice(&text, platform);
            if !violations.is_empty() {
                tracing::warn!("Brand violations in autopilot post {}: {:?}", i, violations);
            }

            let char_limit = match platform {
                "instagram" => brand::IG_CHAR_LIMIT,
                "youtube" => brand::YT_TITLE_LIMIT,
                "tiktok" => brand::TIKTOK_CHAR_LIMIT,
                _ => brand::X_CHAR_LIMIT,
            };

            let content_format = match platform {
                "x" => "tweet",
                "tiktok" => "tiktok-video",
                "instagram" => "reel",
                "youtube" => "short",
                _ => "tweet",
            };

            let mut final_text = text.clone();
            if final_text.chars().count() > char_limit {
                final_text = final_text.chars().take(char_limit - 3).collect::<String>() + "...";
            }

            let hashtags: Option<Vec<String>> = post["hashtags"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());

            let tool_id = post["tool_id"].as_str().map(|s| s.to_string());
            let creative_angle = post["creative_angle"].as_str().map(|s| s.to_string());

            // Distribute across optimal hours
            let hour_jst = OPTIMAL_HOURS_JST[i % OPTIMAL_HOURS_JST.len()];
            let hour_utc = jst_to_utc(hour_jst);
            let minutes = (i as u32 * 7) % 15; // Small jitter

            let post_id = format!("snsp_{}_{:02}", autopilot_id, i + 1);
            let scheduled_at = format!("{}T{:02}:{:02}:00Z", tomorrow, hour_utc, minutes);

            let video_url = tool_id.as_ref().and_then(|tid| brand::get_random_video_url(tid));

            let schedule_req = BridgeScheduleRequest {
                id: post_id.clone(),
                campaign_id: None,
                platform: platform.to_string(),
                text: final_text,
                hashtags,
                media_url: video_url,
                reply_to_external_id: None,
                thread_position: None,
                thread_total: None,
                language: language.to_string(),
                creative_angle,
                tool_id,
                scheduled_at: scheduled_at.clone(),
            };

            match bridge.schedule(&schedule_req).await {
                Ok(resp) => {
                    scheduled_posts.push(json!({
                        "post_id": resp.id,
                        "scheduled": resp.success,
                        "scheduled_at": scheduled_at,
                        "platform": platform,
                        "content_format": content_format,
                        "post_type": post["post_type"],
                        "confidence": post["confidence"],
                    }));
                }
                Err(e) => {
                    scheduled_posts.push(json!({
                        "scheduled": false,
                        "error": e,
                    }));
                }
            }
        }
    }

    // ─── Step 4: Store new learnings in DB ────────────────────
    let new_learnings = result["new_learnings"].as_array().cloned().unwrap_or_default();

    if let Some(pool) = &ctx.pool {
        let today = chrono::Utc::now().date_naive();
        let period_start = today - chrono::Duration::days(lookback_days as i64);

        for learning in &new_learnings {
            let ltype = learning["learning_type"].as_str().unwrap_or("unknown");
            let key = learning["key"].as_str().unwrap_or("");
            let score = learning["score"].as_f64().unwrap_or(0.0);

            if key.is_empty() {
                continue;
            }

            let _ = sqlx::query(
                "INSERT INTO sns_content_learnings \
                 (platform, learning_type, key, score, sample_size, metadata, period_start, period_end) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
            )
            .persistent(false)
            .bind(platforms.first().unwrap_or(&"x".to_string()))
            .bind(ltype)
            .bind(key)
            .bind(score)
            .bind(recent_posts.len() as i32)
            .bind(&json!({"reasoning": learning["reasoning"]}))
            .bind(period_start.to_string())
            .bind(today.to_string())
            .execute(pool)
            .await
            .map_err(|e| tracing::warn!("Failed to store learning: {}", e));
        }
    }

    Ok(json!({
        "autopilot_id": autopilot_id,
        "analysis_summary": result["analysis_summary"],
        "optimized_weights": result["optimized_weights"],
        "posts_generated": posts.len(),
        "posts_scheduled": scheduled_posts.len(),
        "scheduled_posts": scheduled_posts,
        "new_learnings": new_learnings,
        "schedule_date": tomorrow.to_string(),
        "platforms": platforms,
        "historical_data": {
            "posts_analyzed": recent_posts.len(),
            "engagement_snapshots": recent_engagement.len(),
            "existing_learnings": content_learnings.len(),
        },
    }))
}
