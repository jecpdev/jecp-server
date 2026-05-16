use serde_json::json;

use crate::capabilities::CapabilityContext;
use crate::protocol::errors::JecpErrorCode;
use crate::services::claude::ClaudeMessage;

use super::brand::BRAND_SYSTEM_PROMPT;
use super::utils::parse_json_response;

/// engagement-analyze action
///
/// 1. Fetch engagement metrics via Bridge for given post IDs or campaign
/// 2. Use Claude to analyze the data and find patterns
/// 3. Return performance insights + actionable recommendations for next posts
pub async fn execute(
    ctx: &CapabilityContext,
    input: &serde_json::Value,
) -> Result<serde_json::Value, JecpErrorCode> {
    let platform = input["platform"].as_str().unwrap_or("x");
    let language = input["language"].as_str().unwrap_or("ja");

    // Accept either explicit post IDs or a campaign_id to look up
    let external_ids: Vec<String> = input["external_ids"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let campaign_id = input["campaign_id"].as_str();

    // ─── Step 1: Gather metrics ───────────────────────────────
    let mut metrics_data = Vec::new();

    // If campaign_id given, load post external_ids from DB
    let mut all_ids = external_ids.clone();
    if let (Some(cid), Some(pool)) = (campaign_id, &ctx.pool) {
        let db_ids: Vec<String> = sqlx::query_scalar(
            "SELECT external_id FROM sns_scheduled_posts \
             WHERE campaign_id = $1 AND external_id IS NOT NULL AND status = 'published'"
        )
        .persistent(false)
        .bind(cid)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        all_ids.extend(db_ids);
    }

    if all_ids.is_empty() {
        return Err(JecpErrorCode::ValidationFailed(
            "No post IDs to analyze. Provide external_ids or campaign_id with published posts.".to_string(),
        ));
    }

    // Fetch metrics from Bridge
    if let Some(bridge) = &ctx.sns_bridge {
        match bridge.fetch_metrics(&all_ids, platform).await {
            Ok(resp) => {
                if let Some(m) = resp.metrics {
                    metrics_data = m.into_iter().map(|metric| {
                        json!({
                            "external_id": metric.external_id,
                            "platform": metric.platform,
                            "views": metric.views,
                            "likes": metric.likes,
                            "comments": metric.comments,
                            "shares": metric.shares,
                            "link_clicks": metric.link_clicks,
                            "engagement_rate": if metric.views > 0 {
                                (metric.likes + metric.comments + metric.shares) as f64 / metric.views as f64
                            } else {
                                0.0
                            },
                        })
                    }).collect();
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch metrics from Bridge: {}", e);
            }
        }
    } else {
        return Err(JecpErrorCode::ServiceError(
            "SNS Bridge not configured".to_string(),
        ));
    }

    // ─── Step 2: Load post content for context ────────────────
    let mut post_context = Vec::new();
    if let Some(pool) = &ctx.pool {
        for eid in &all_ids {
            let row: Option<(String, String, Option<String>)> = sqlx::query_as(
                "SELECT text, platform, creative_angle FROM sns_scheduled_posts \
                 WHERE external_id = $1 LIMIT 1"
            )
            .persistent(false)
            .bind(eid)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            if let Some((text, plat, angle)) = row {
                post_context.push(json!({
                    "external_id": eid,
                    "text": text,
                    "platform": plat,
                    "creative_angle": angle,
                }));
            }
        }
    }

    // ─── Step 3: Claude analysis ──────────────────────────────
    let analysis_prompt = format!(
        "Analyze the following SNS engagement data and provide actionable insights.\n\n\
         Platform: {platform}\n\
         Language for response: {language}\n\n\
         Metrics per post:\n{metrics}\n\n\
         Post content context:\n{context}\n\n\
         Provide a JSON response with:\n\
         - summary: 2-3 sentence overall performance summary\n\
         - top_performing: Object with external_id and reason why it performed best\n\
         - worst_performing: Object with external_id and reason + improvement suggestion\n\
         - patterns: Array of 3-5 observed patterns (e.g., best posting time, content type, etc.)\n\
         - recommendations: Array of 3-5 specific actionable recommendations for next posts\n\
         - optimal_posting: Object with best_hours (array), best_content_types (array), best_hashtag_count (number)\n\
         - predicted_engagement_boost: Percentage improvement expected if recommendations are followed",
        metrics = serde_json::to_string_pretty(&metrics_data).unwrap_or_default(),
        context = serde_json::to_string_pretty(&post_context).unwrap_or_default(),
    );

    let response = ctx
        .claude
        .complete(
            Some(BRAND_SYSTEM_PROMPT),
            vec![ClaudeMessage {
                role: "user".to_string(),
                content: analysis_prompt,
            }],
            4096,
        )
        .await
        .map_err(|e| JecpErrorCode::ServiceError(format!("Claude analysis failed: {}", e)))?;

    let analysis: serde_json::Value = parse_json_response(&response).unwrap_or_else(|| {
        json!({
            "summary": "Insufficient data for detailed analysis.",
            "patterns": [],
            "recommendations": ["Collect more engagement data before detailed analysis."],
        })
    });

    // ─── Step 4: Store snapshots in DB ────────────────────────
    if let Some(pool) = &ctx.pool {
        for metric in &metrics_data {
            let _ = sqlx::query(
                "INSERT INTO sns_engagement_snapshots \
                 (post_id, platform, snapshot_at, views, likes, comments, shares, link_clicks, engagement_rate) \
                 SELECT id, $2, NOW(), $3, $4, $5, $6, $7, $8 \
                 FROM sns_scheduled_posts WHERE external_id = $1 LIMIT 1"
            )
            .persistent(false)
            .bind(metric["external_id"].as_str().unwrap_or(""))
            .bind(platform)
            .bind(metric["views"].as_i64().unwrap_or(0) as i32)
            .bind(metric["likes"].as_i64().unwrap_or(0) as i32)
            .bind(metric["comments"].as_i64().unwrap_or(0) as i32)
            .bind(metric["shares"].as_i64().unwrap_or(0) as i32)
            .bind(metric["link_clicks"].as_i64().unwrap_or(0) as i32)
            .bind(metric["engagement_rate"].as_f64().unwrap_or(0.0))
            .execute(pool)
            .await
            .map_err(|e| tracing::warn!("Failed to store engagement snapshot: {}", e));
        }
    }

    Ok(json!({
        "platform": platform,
        "total_posts_analyzed": all_ids.len(),
        "metrics": metrics_data,
        "analysis": analysis,
        "campaign_id": campaign_id,
    }))
}
