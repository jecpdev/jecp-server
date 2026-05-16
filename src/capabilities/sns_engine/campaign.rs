use chrono::{NaiveDate, Utc};
use serde_json::json;

use crate::capabilities::CapabilityContext;
use crate::protocol::errors::JecpErrorCode;
use crate::services::claude::ClaudeMessage;
use crate::services::sns_bridge::BridgeScheduleRequest;

use super::brand::{self, BRAND_SYSTEM_PROMPT};
use super::types::{jst_to_utc, GeneratedPost, OPTIMAL_HOURS_JST};
use super::utils::parse_json_response;

/// Execute the campaign-orchestrate action.
///
/// 1. Use Claude (Haiku) to generate a campaign strategy + content calendar
/// 2. Generate platform-optimized posts for each day
/// 3. Validate brand voice
/// 4. Schedule via Next.js Bridge
/// 5. Record campaign in sns_campaigns table
pub async fn execute(
    ctx: &CapabilityContext,
    input: &serde_json::Value,
) -> Result<serde_json::Value, JecpErrorCode> {
    // ─── Parse input ───────────────────────────────────────────
    let goal = input["goal"]
        .as_str()
        .ok_or_else(|| JecpErrorCode::ValidationFailed("goal is required".to_string()))?;

    let platforms: Vec<String> = input["platforms"]
        .as_array()
        .ok_or_else(|| JecpErrorCode::ValidationFailed("platforms is required".to_string()))?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    if platforms.is_empty() {
        return Err(JecpErrorCode::ValidationFailed(
            "platforms must contain at least one platform (x, tiktok)".to_string(),
        ));
    }

    let languages: Vec<String> = input["languages"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(|| vec!["ja".to_string()]);

    let duration_days = input["duration_days"].as_u64().unwrap_or(7) as u32;
    let posts_per_day = input["posts_per_day"].as_u64().unwrap_or(3) as u32;
    let tone = input["tone"].as_str().unwrap_or("confident");

    let tool_ids: Vec<String> = input["tool_ids"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(|| {
            brand::PRIORITY_TOOL_IDS
                .iter()
                .map(|s| s.to_string())
                .collect()
        });

    // ─── Step 1: Generate campaign strategy ────────────────────
    let strategy_prompt = format!(
        "Create a {duration_days}-day SNS campaign strategy.\n\
         Goal: {goal}\n\
         Platforms: {platforms}\n\
         Languages: {languages}\n\
         Posts per day: {posts_per_day}\n\
         Tone: {tone}\n\
         Available tools to promote: {tool_ids}\n\n\
         Return a JSON object with:\n\
         - theme: Campaign theme (1 sentence)\n\
         - target_audience: Who this campaign targets\n\
         - key_messages: Array of 3-5 key messages\n\
         - content_calendar: Array of objects, one per day, with:\n\
           - day: Day number (1-{duration_days})\n\
           - focus: What to focus on that day\n\
           - angles: Array of {posts_per_day} creative angles for posts",
        platforms = platforms.join(", "),
        languages = languages.join(", "),
        tool_ids = tool_ids.join(", "),
    );

    let strategy_response = ctx
        .claude
        .complete(
            Some(BRAND_SYSTEM_PROMPT),
            vec![ClaudeMessage {
                role: "user".to_string(),
                content: strategy_prompt,
            }],
            4096,
        )
        .await
        .map_err(|e| JecpErrorCode::ServiceError(format!("Claude strategy generation failed: {}", e)))?;

    let strategy: serde_json::Value = parse_json_response(&strategy_response).unwrap_or_else(|| {
        json!({
            "theme": goal,
            "target_audience": "general",
            "key_messages": [goal],
            "content_calendar": []
        })
    });

    // ─── Step 2: Generate posts for each day ───────────────────
    let mut all_posts: Vec<GeneratedPost> = Vec::new();
    let today = Utc::now().date_naive();

    for day in 1..=duration_days {
        let post_date = today + chrono::Duration::days(day as i64 - 1);
        let day_focus = strategy["content_calendar"]
            .as_array()
            .and_then(|cal| cal.iter().find(|d| d["day"].as_u64() == Some(day as u64)))
            .and_then(|d| d["focus"].as_str())
            .unwrap_or(goal);

        let day_angles: Vec<String> = strategy["content_calendar"]
            .as_array()
            .and_then(|cal| cal.iter().find(|d| d["day"].as_u64() == Some(day as u64)))
            .and_then(|d| d["angles"].as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        for (slot, platform) in allocate_slots(posts_per_day, &platforms).iter().enumerate() {
            let char_limit = match platform.as_str() {
                "instagram" => brand::IG_CHAR_LIMIT,
                "youtube" => brand::YT_TITLE_LIMIT,
                "tiktok" => brand::TIKTOK_CHAR_LIMIT,
                _ => brand::X_CHAR_LIMIT,
            };

            let tool_id = &tool_ids[((day as usize - 1) * posts_per_day as usize + slot) % tool_ids.len()];
            let angle = day_angles
                .get(slot)
                .map(|s| s.as_str())
                .unwrap_or("general tip");
            let language = &languages[slot % languages.len()];

            let platform_guideline = brand::get_platform_prompt(platform);
            let post_prompt = format!(
                "Write ONE social media post for {platform}.\n\
                 Topic: {day_focus}\n\
                 Creative angle: {angle}\n\
                 Tool to mention: {tool_id}\n\
                 Language: {language}\n\
                 Character limit: {char_limit}\n\
                 Campaign goal: {goal}\n\
                 Platform guideline: {platform_guideline}\n\n\
                 Return a JSON object with:\n\
                 - text: The post text (MUST be under {char_limit} characters)\n\
                 - hashtags: Array of 2-5 relevant hashtags (without # prefix)",
            );

            let post_response = ctx
                .claude
                .complete(
                    Some(BRAND_SYSTEM_PROMPT),
                    vec![ClaudeMessage {
                        role: "user".to_string(),
                        content: post_prompt,
                    }],
                    1024,
                )
                .await
                .map_err(|e| JecpErrorCode::ServiceError(format!("Claude post generation failed: {}", e)))?;

            let post_data: serde_json::Value =
                parse_json_response(&post_response).unwrap_or_else(|| {
                    json!({
                        "text": format!("{}を試してみて！ #JobDoneBot", tool_id),
                        "hashtags": ["JobDoneBot"]
                    })
                });

            let mut text = post_data["text"]
                .as_str()
                .unwrap_or("")
                .to_string();

            // Truncate if over limit
            if text.chars().count() > char_limit {
                text = text.chars().take(char_limit - 3).collect::<String>() + "...";
            }

            // Brand voice validation (platform-aware)
            let violations = brand::validate_brand_voice(&text, platform);
            if !violations.is_empty() {
                tracing::warn!(
                    "Brand voice violations in post (day={}, slot={}): {:?}",
                    day,
                    slot,
                    violations
                );
            }

            let hashtags: Vec<String> = post_data["hashtags"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_else(|| vec!["JobDoneBot".to_string()]);

            let scheduled_at = calculate_post_time(post_date, slot as u32);

            let content_format = match platform.as_str() {
                "x" => "tweet",
                "tiktok" => "tiktok-video",
                "instagram" => "reel",
                "youtube" => "short",
                _ => "tweet",
            };

            all_posts.push(GeneratedPost {
                platform: platform.clone(),
                text,
                hashtags,
                language: language.clone(),
                creative_angle: angle.to_string(),
                tool_id: Some(tool_id.clone()),
                content_format: Some(content_format.to_string()),
                scheduled_at,
                day,
                slot: slot as u32,
            });
        }
    }

    // ─── Step 3: Schedule via Bridge (if bridge is configured) ─
    let campaign_id = format!("camp_{}", uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string());
    let mut scheduled_ids: Vec<String> = Vec::new();

    if let Some(bridge) = &ctx.sns_bridge {
        for post in &all_posts {
            let post_id = format!(
                "snsp_{}_{}",
                campaign_id,
                uuid::Uuid::new_v4().to_string().replace('-', "")[..8].to_string()
            );

            let video_url = post.tool_id.as_ref().and_then(|tid| brand::get_random_video_url(tid));

            let schedule_req = BridgeScheduleRequest {
                id: post_id.clone(),
                campaign_id: Some(campaign_id.clone()),
                platform: post.platform.clone(),
                text: post.text.clone(),
                hashtags: Some(post.hashtags.clone()),
                media_url: video_url,
                reply_to_external_id: None,
                thread_position: None,
                thread_total: None,
                language: post.language.clone(),
                creative_angle: Some(post.creative_angle.clone()),
                tool_id: post.tool_id.clone(),
                scheduled_at: post.scheduled_at.clone(),
            };

            match bridge.schedule(&schedule_req).await {
                Ok(resp) => {
                    if resp.success {
                        scheduled_ids.push(resp.id);
                    } else {
                        tracing::warn!("Failed to schedule post: {:?}", resp.error);
                    }
                }
                Err(e) => {
                    tracing::warn!("Bridge schedule error: {}", e);
                }
            }
        }
    }

    // ─── Step 4: Record campaign in DB ─────────────────────────
    let end_date = today + chrono::Duration::days(duration_days as i64 - 1);

    if let Some(pool) = &ctx.pool {
        let _ = sqlx::query(
            "INSERT INTO sns_campaigns (id, goal, platforms, languages, tool_ids, strategy, \
             start_date, end_date, status, total_posts_planned, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, NOW(), NOW())"
        )
        .persistent(false)
        .bind(&campaign_id)
        .bind(goal)
        .bind(&platforms)
        .bind(&languages)
        .bind(&tool_ids)
        .bind(&strategy)
        .bind(today.to_string())
        .bind(end_date.to_string())
        .bind(all_posts.len() as i32)
        .execute(pool)
        .await
        .map_err(|e| tracing::warn!("Failed to record campaign: {}", e));
    }

    // ─── Return result ─────────────────────────────────────────
    Ok(json!({
        "campaign_id": campaign_id,
        "strategy": strategy,
        "posts": all_posts,
        "total_posts": all_posts.len(),
        "scheduled_ids": scheduled_ids,
        "duration_days": duration_days,
        "platforms": platforms,
        "start_date": today.to_string(),
        "end_date": end_date.to_string(),
    }))
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Distribute `n` slots across platforms in round-robin
fn allocate_slots(n: u32, platforms: &[String]) -> Vec<String> {
    (0..n)
        .map(|i| platforms[i as usize % platforms.len()].clone())
        .collect()
}

/// Calculate scheduled time for a post on a given date + slot index.
/// Uses optimal JST hours with random jitter.
fn calculate_post_time(date: NaiveDate, slot: u32) -> String {
    let hour_jst = OPTIMAL_HOURS_JST[slot as usize % OPTIMAL_HOURS_JST.len()];
    let hour_utc = jst_to_utc(hour_jst);
    // Add small jitter (0-14 minutes) based on slot for natural timing
    let minutes = (slot * 7) % 15;

    format!(
        "{}T{:02}:{:02}:00Z",
        date, hour_utc, minutes
    )
}

