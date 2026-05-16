use serde_json::json;

use crate::protocol::errors::JecpErrorCode;
use crate::protocol::types::{JecpRequest, JecpResult};
use crate::services::claude::ClaudeMessage;

use super::CapabilityContext;

pub async fn execute(ctx: &CapabilityContext, req: &JecpRequest) -> Result<JecpResult, JecpErrorCode> {
    match req.action.as_str() {
        "generate-blog" => generate_blog(ctx, &req.input).await,
        "generate-social" => generate_social(ctx, &req.input).await,
        "rewrite" => rewrite(ctx, &req.input).await,
        "translate" => translate(ctx, &req.input).await,
        "summarize" => summarize(ctx, &req.input).await,
        _ => Err(JecpErrorCode::UnknownAction(req.action.clone())),
    }
    .map(|output| JecpResult {
        capability: "content-factory".to_string(),
        action: req.action.clone(),
        output,
    })
}

async fn generate_blog(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let topic = input["topic"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("topic is required".to_string())
    })?;

    let keywords: Vec<&str> = input["keywords"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let length = input["length"].as_str().unwrap_or("medium");
    let language = input["language"].as_str().unwrap_or("en");

    let word_count = match length {
        "short" => "500-800",
        "long" => "2000-3000",
        _ => "1000-1500",
    };

    let system = format!(
        "You are a professional content writer. Write high-quality, SEO-optimized blog posts.\n\
         Language: {language}\n\
         IMPORTANT: Respond ONLY with valid JSON, no markdown fences."
    );

    let prompt = format!(
        "Write a blog post about: {topic}\n\
         Target length: {word_count} words\n\
         Keywords to include: {keywords}\n\n\
         Return a JSON object with these fields:\n\
         - title: The blog post title\n\
         - meta_description: SEO meta description (150-160 chars)\n\
         - body: The full blog post in markdown\n\
         - tags: Array of relevant tags\n\
         - reading_time_minutes: Estimated reading time",
        keywords = keywords.join(", ")
    );

    let response = ctx.claude.complete(
        Some(&system),
        vec![ClaudeMessage { role: "user".to_string(), content: prompt }],
        4096,
    ).await.map_err(|e| JecpErrorCode::ServiceError(e.to_string()))?;

    // Parse the JSON response from Claude
    let parsed: serde_json::Value = serde_json::from_str(&response)
        .or_else(|_| {
            // Try to extract JSON from markdown fences
            let trimmed = response.trim();
            let json_str = if trimmed.starts_with("```json") {
                trimmed.strip_prefix("```json").unwrap_or(trimmed)
                    .strip_suffix("```").unwrap_or(trimmed).trim()
            } else if trimmed.starts_with("```") {
                trimmed.strip_prefix("```").unwrap_or(trimmed)
                    .strip_suffix("```").unwrap_or(trimmed).trim()
            } else {
                trimmed
            };
            serde_json::from_str(json_str)
        })
        .unwrap_or_else(|_| json!({
            "title": topic,
            "body": response,
            "meta_description": "",
            "tags": [],
            "reading_time_minutes": 5
        }));

    Ok(parsed)
}

async fn generate_social(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let topic = input["topic"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("topic is required".to_string())
    })?;

    let platforms: Vec<&str> = input["platforms"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_else(|| vec!["twitter", "instagram"]);

    let count = input["count"].as_u64().unwrap_or(5);

    let system = "You are a social media content specialist. Create engaging posts optimized for each platform.\n\
                  IMPORTANT: Respond ONLY with valid JSON, no markdown fences.".to_string();

    let prompt = format!(
        "Create {count} social media posts about: {topic}\n\
         Platforms: {platforms}\n\n\
         Return a JSON object with:\n\
         - posts: Array of objects with fields: platform, text, hashtags (array), \
           suggested_time (best posting time), character_count\n\
         - campaign_summary: Brief summary of the content strategy",
        platforms = platforms.join(", ")
    );

    let response = ctx.claude.complete(
        Some(&system),
        vec![ClaudeMessage { role: "user".to_string(), content: prompt }],
        4096,
    ).await.map_err(|e| JecpErrorCode::ServiceError(e.to_string()))?;

    parse_json_response(&response, json!({ "posts": [], "campaign_summary": "" }))
}

async fn rewrite(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let text = input["text"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("text is required".to_string())
    })?;

    let tone = input["tone"].as_str().unwrap_or("professional");
    let audience = input["target_audience"].as_str().unwrap_or("general");

    let system = "You are a professional editor. Rewrite text while preserving the core meaning.\n\
                  IMPORTANT: Respond ONLY with valid JSON, no markdown fences.".to_string();

    let prompt = format!(
        "Rewrite the following text.\n\
         Tone: {tone}\n\
         Target audience: {audience}\n\n\
         Text:\n{text}\n\n\
         Return a JSON object with:\n\
         - rewritten: The rewritten text\n\
         - changes_summary: Brief summary of changes made\n\
         - word_count: Word count of rewritten text"
    );

    let response = ctx.claude.complete(
        Some(&system),
        vec![ClaudeMessage { role: "user".to_string(), content: prompt }],
        4096,
    ).await.map_err(|e| JecpErrorCode::ServiceError(e.to_string()))?;

    parse_json_response(&response, json!({ "rewritten": text, "changes_summary": "", "word_count": 0 }))
}

async fn translate(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let text = input["text"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("text is required".to_string())
    })?;

    let target_lang = input["target_lang"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("target_lang is required".to_string())
    })?;

    let source_lang = input["source_lang"].as_str().unwrap_or("auto-detect");

    let system = "You are a professional translator. Provide accurate, natural translations.\n\
                  IMPORTANT: Respond ONLY with valid JSON, no markdown fences.".to_string();

    let prompt = format!(
        "Translate the following text.\n\
         Source language: {source_lang}\n\
         Target language: {target_lang}\n\n\
         Text:\n{text}\n\n\
         Return a JSON object with:\n\
         - translated: The translated text\n\
         - source_language: Detected source language\n\
         - target_language: Target language\n\
         - confidence: Translation confidence (0-1)"
    );

    let response = ctx.claude.complete(
        Some(&system),
        vec![ClaudeMessage { role: "user".to_string(), content: prompt }],
        4096,
    ).await.map_err(|e| JecpErrorCode::ServiceError(e.to_string()))?;

    parse_json_response(&response, json!({ "translated": "", "source_language": source_lang, "target_language": target_lang, "confidence": 0.0 }))
}

async fn summarize(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let text = input["text"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("text is required".to_string())
    })?;

    let max_length = input["max_length"].as_u64().unwrap_or(200);

    let system = "You are a concise summarizer. Create clear, accurate summaries.\n\
                  IMPORTANT: Respond ONLY with valid JSON, no markdown fences.".to_string();

    let prompt = format!(
        "Summarize the following text in at most {max_length} words.\n\n\
         Text:\n{text}\n\n\
         Return a JSON object with:\n\
         - summary: The summary\n\
         - key_points: Array of key points\n\
         - original_word_count: Word count of original\n\
         - summary_word_count: Word count of summary"
    );

    let response = ctx.claude.complete(
        Some(&system),
        vec![ClaudeMessage { role: "user".to_string(), content: prompt }],
        2048,
    ).await.map_err(|e| JecpErrorCode::ServiceError(e.to_string()))?;

    parse_json_response(&response, json!({ "summary": "", "key_points": [], "original_word_count": 0, "summary_word_count": 0 }))
}

/// Helper to parse JSON from Claude response, with fallback
fn parse_json_response(response: &str, fallback: serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let trimmed = response.trim();

    // Try direct parse
    if let Ok(v) = serde_json::from_str(trimmed) {
        return Ok(v);
    }

    // Try stripping markdown fences
    let json_str = if trimmed.starts_with("```json") {
        trimmed.strip_prefix("```json").unwrap_or(trimmed)
            .strip_suffix("```").unwrap_or(trimmed).trim()
    } else if trimmed.starts_with("```") {
        trimmed.strip_prefix("```").unwrap_or(trimmed)
            .strip_suffix("```").unwrap_or(trimmed).trim()
    } else {
        trimmed
    };

    serde_json::from_str(json_str).or_else(|_| Ok(fallback))
}
