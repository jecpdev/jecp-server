use serde_json::json;

use crate::capabilities::CapabilityContext;
use crate::protocol::errors::JecpErrorCode;
use crate::services::claude::ClaudeMessage;
use crate::services::sns_bridge::BridgeScheduleRequest;

use super::brand::{self, BRAND_SYSTEM_PROMPT, PRIORITY_TOOL_IDS};
use super::types::{jst_to_utc, OPTIMAL_HOURS_JST};
use super::utils::parse_json_response;

/// ab-test-launch action
///
/// 1. Generate 2-4 content variants on the same topic with different creative angles
/// 2. Schedule them at 30-60 min intervals for fair comparison
/// 3. Record the test in sns_ab_tests table
/// 4. After test_duration_hours, engagement-analyze can determine winner
pub async fn execute(
    ctx: &CapabilityContext,
    input: &serde_json::Value,
) -> Result<serde_json::Value, JecpErrorCode> {
    let platform = input["platform"].as_str().unwrap_or("x");
    let topic = input["topic"]
        .as_str()
        .ok_or_else(|| JecpErrorCode::ValidationFailed("topic is required".to_string()))?;
    let num_variants = input["num_variants"].as_u64().unwrap_or(3).min(4).max(2) as u32;
    let interval_minutes = input["interval_minutes"].as_u64().unwrap_or(45).min(120).max(15) as u32;
    let test_duration_hours = input["test_duration_hours"].as_u64().unwrap_or(24).min(72).max(6) as u32;
    let language = input["language"].as_str().unwrap_or("ja");

    let tool_id = input["tool_id"]
        .as_str()
        .unwrap_or(PRIORITY_TOOL_IDS[0]);

    let char_limit = match platform {
        "tiktok" => brand::TIKTOK_CHAR_LIMIT,
        _ => brand::X_CHAR_LIMIT,
    };

    // ─── Step 1: Generate variants ────────────────────────────
    let prompt = format!(
        "Generate {num_variants} different social media post variants for an A/B test.\n\n\
         Topic: {topic}\n\
         Tool to promote: {tool_id}\n\
         Platform: {platform}\n\
         Language: {language}\n\
         Character limit: {char_limit}\n\n\
         Each variant MUST use a different creative approach:\n\
         - Variant A: Speed/surprise angle (\"え、もう終わった？\")\n\
         - Variant B: Pain point angle (problem → solution)\n\
         - Variant C: Social proof / authority angle\n\
         - Variant D: Privacy / security angle\n\
         Only generate {num_variants} variants (A through {last_letter}).\n\n\
         Return a JSON object with:\n\
         - variants: Array of {num_variants} objects, each with:\n\
           - variant_id: Letter (A, B, C, D)\n\
           - creative_angle: Name of the creative approach used\n\
           - text: Post text (under {char_limit} chars)\n\
           - hashtags: Array of 2-4 hashtags (without # prefix)\n\
           - hypothesis: What this variant tests (1 sentence)",
        last_letter = (b'A' + num_variants as u8 - 1) as char,
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
        .map_err(|e| JecpErrorCode::ServiceError(format!("Claude variant generation failed: {}", e)))?;

    let result: serde_json::Value = parse_json_response(&response).unwrap_or_else(|| {
        json!({ "variants": [] })
    });

    let variants = result["variants"].as_array().cloned().unwrap_or_default();

    if variants.is_empty() {
        return Err(JecpErrorCode::ExecutionFailed(
            "Failed to generate variants".to_string(),
        ));
    }

    // ─── Step 2: Brand voice validation ───────────────────────
    for variant in &variants {
        if let Some(text) = variant["text"].as_str() {
            let violations = brand::validate_brand_voice(text, platform);
            if !violations.is_empty() {
                tracing::warn!(
                    "Brand violations in variant {}: {:?}",
                    variant["variant_id"],
                    violations
                );
            }
        }
    }

    // ─── Step 3: Create test record + schedule variants ───────
    let test_id = format!("abtest_{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]);
    let mut scheduled_variants = Vec::new();

    if let Some(bridge) = &ctx.sns_bridge {
        let today = chrono::Utc::now().date_naive();
        let base_hour_jst = OPTIMAL_HOURS_JST[1]; // Use noon JST as base
        let base_hour_utc = jst_to_utc(base_hour_jst);

        for (i, variant) in variants.iter().enumerate() {
            let text = variant["text"].as_str().unwrap_or("").to_string();
            if text.is_empty() {
                continue;
            }

            let hashtags: Option<Vec<String>> = variant["hashtags"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());

            let variant_id = variant["variant_id"]
                .as_str()
                .unwrap_or(&format!("{}", (b'A' + i as u8) as char))
                .to_string();

            let creative_angle = variant["creative_angle"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();

            // Stagger variants by interval_minutes
            let total_minutes = base_hour_utc * 60 + (i as u32 * interval_minutes);
            let sched_hour = (total_minutes / 60) % 24;
            let sched_min = total_minutes % 60;

            let post_id = format!("snsp_{}_v{}", test_id, variant_id);
            let scheduled_at = format!("{}T{:02}:{:02}:00Z", today, sched_hour, sched_min);

            let video_url = brand::get_random_video_url(tool_id);

            let schedule_req = BridgeScheduleRequest {
                id: post_id.clone(),
                campaign_id: None,
                platform: platform.to_string(),
                text: text.clone(),
                hashtags,
                media_url: video_url,
                reply_to_external_id: None,
                thread_position: None,
                thread_total: None,
                language: language.to_string(),
                creative_angle: Some(creative_angle.clone()),
                tool_id: Some(tool_id.to_string()),
                scheduled_at: scheduled_at.clone(),
            };

            match bridge.schedule(&schedule_req).await {
                Ok(resp) => {
                    scheduled_variants.push(json!({
                        "variant_id": variant_id,
                        "post_id": resp.id,
                        "scheduled": resp.success,
                        "scheduled_at": scheduled_at,
                        "creative_angle": creative_angle,
                    }));
                }
                Err(e) => {
                    scheduled_variants.push(json!({
                        "variant_id": variant_id,
                        "scheduled": false,
                        "error": e,
                    }));
                }
            }
        }
    }

    // ─── Step 4: Record A/B test in DB ────────────────────────
    if let Some(pool) = &ctx.pool {
        let variant_ids: Vec<String> = variants.iter()
            .filter_map(|v| v["variant_id"].as_str().map(|s| s.to_string()))
            .collect();

        let _ = sqlx::query(
            "INSERT INTO sns_ab_tests \
             (id, platform, topic, tool_id, num_variants, variant_ids, \
              interval_minutes, test_duration_hours, status, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'running', NOW())"
        )
        .persistent(false)
        .bind(&test_id)
        .bind(platform)
        .bind(topic)
        .bind(tool_id)
        .bind(num_variants as i32)
        .bind(&variant_ids)
        .bind(interval_minutes as i32)
        .bind(test_duration_hours as i32)
        .execute(pool)
        .await
        .map_err(|e| tracing::warn!("Failed to record A/B test: {}", e));
    }

    Ok(json!({
        "test_id": test_id,
        "platform": platform,
        "topic": topic,
        "tool_id": tool_id,
        "num_variants": variants.len(),
        "variants": result["variants"],
        "scheduled_variants": scheduled_variants,
        "interval_minutes": interval_minutes,
        "test_duration_hours": test_duration_hours,
        "evaluate_after": format!("Use engagement-analyze with test posts after {} hours", test_duration_hours),
    }))
}
