use serde_json::json;

use crate::protocol::errors::JecpErrorCode;
use crate::protocol::types::{JecpRequest, JecpResult};
use crate::services::claude::ClaudeMessage;

use super::CapabilityContext;

pub async fn execute(ctx: &CapabilityContext, req: &JecpRequest) -> Result<JecpResult, JecpErrorCode> {
    match req.action.as_str() {
        "analyze-csv" => analyze_csv(ctx, &req.input).await,
        "analyze-json" => analyze_json(ctx, &req.input).await,
        "forecast" => forecast(ctx, &req.input).await,
        _ => Err(JecpErrorCode::UnknownAction(req.action.clone())),
    }
    .map(|output| JecpResult {
        capability: "data-insight".to_string(),
        action: req.action.clone(),
        output,
    })
}

async fn analyze_csv(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let csv_data = input["csv_data"].as_str().ok_or_else(|| {
        JecpErrorCode::ValidationFailed("csv_data is required".to_string())
    })?;

    let question = input["question"].as_str().unwrap_or("Provide a comprehensive analysis");

    // Parse CSV to get basic stats
    let mut reader = csv::Reader::from_reader(csv_data.as_bytes());
    let headers: Vec<String> = reader.headers()
        .map(|h| h.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let records: Vec<Vec<String>> = reader.records()
        .filter_map(|r| r.ok())
        .map(|r| r.iter().map(|s| s.to_string()).collect())
        .collect();

    let row_count = records.len();
    let col_count = headers.len();

    // Compute basic numeric stats per column
    let mut column_stats = Vec::new();
    for (i, header) in headers.iter().enumerate() {
        let values: Vec<f64> = records.iter()
            .filter_map(|row| row.get(i)?.parse::<f64>().ok())
            .collect();

        if !values.is_empty() {
            let sum: f64 = values.iter().sum();
            let mean = sum / values.len() as f64;
            let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

            column_stats.push(json!({
                "column": header,
                "type": "numeric",
                "count": values.len(),
                "mean": (mean * 100.0).round() / 100.0,
                "min": min,
                "max": max,
                "sum": sum
            }));
        } else {
            // Categorical column
            let unique: std::collections::HashSet<&str> = records.iter()
                .filter_map(|row| row.get(i).map(|s| s.as_str()))
                .collect();
            column_stats.push(json!({
                "column": header,
                "type": "categorical",
                "unique_values": unique.len()
            }));
        }
    }

    // Use Claude for deeper insights
    let system = "You are a data analyst. Analyze the provided CSV data and return insights.\n\
                  IMPORTANT: Respond ONLY with valid JSON, no markdown fences.".to_string();

    // Truncate CSV data for Claude (first 50 rows max)
    let preview_lines: Vec<&str> = csv_data.lines().take(51).collect();
    let preview = preview_lines.join("\n");

    let prompt = format!(
        "Analyze this CSV data ({} rows, {} columns).\n\
         Question: {}\n\n\
         Headers: {:?}\n\
         Data preview:\n{}\n\n\
         Column statistics:\n{}\n\n\
         Return a JSON object with:\n\
         - summary: Brief overall summary\n\
         - trends: Array of identified trends\n\
         - anomalies: Array of anomalies found\n\
         - recommendations: Array of actionable recommendations\n\
         - key_metrics: Object with important calculated metrics",
        row_count, col_count, question,
        headers, preview,
        serde_json::to_string_pretty(&column_stats).unwrap_or_default()
    );

    let ai_response = ctx.claude.complete(
        Some(&system),
        vec![ClaudeMessage { role: "user".to_string(), content: prompt }],
        4096,
    ).await.map_err(|e| JecpErrorCode::ServiceError(e.to_string()))?;

    let ai_insights = parse_json_response(&ai_response);

    Ok(json!({
        "statistics": {
            "row_count": row_count,
            "column_count": col_count,
            "columns": column_stats
        },
        "insights": ai_insights,
    }))
}

async fn analyze_json(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let json_data = &input["json_data"];
    if json_data.is_null() {
        return Err(JecpErrorCode::ValidationFailed("json_data is required".to_string()));
    }

    let question = input["question"].as_str().unwrap_or("Provide a comprehensive analysis");

    // Basic structural analysis
    let structure = analyze_json_structure(json_data);

    let system = "You are a data analyst. Analyze the provided JSON data.\n\
                  IMPORTANT: Respond ONLY with valid JSON, no markdown fences.".to_string();

    let data_preview = serde_json::to_string_pretty(json_data)
        .unwrap_or_else(|_| json_data.to_string());
    // Truncate large data
    let preview = if data_preview.len() > 5000 {
        format!("{}...(truncated)", &data_preview[..5000])
    } else {
        data_preview
    };

    let prompt = format!(
        "Analyze this JSON data.\n\
         Question: {}\n\n\
         Structure: {}\n\
         Data:\n{}\n\n\
         Return a JSON object with:\n\
         - summary: Brief overall summary\n\
         - structure_analysis: Description of the data structure\n\
         - key_findings: Array of important findings\n\
         - anomalies: Array of anomalies or issues found\n\
         - recommendations: Array of recommendations",
        question, structure, preview
    );

    let ai_response = ctx.claude.complete(
        Some(&system),
        vec![ClaudeMessage { role: "user".to_string(), content: prompt }],
        4096,
    ).await.map_err(|e| JecpErrorCode::ServiceError(e.to_string()))?;

    let ai_insights = parse_json_response(&ai_response);

    Ok(json!({
        "structure": structure,
        "insights": ai_insights,
    }))
}

async fn forecast(ctx: &CapabilityContext, input: &serde_json::Value) -> Result<serde_json::Value, JecpErrorCode> {
    let time_series = input["time_series"]
        .as_array()
        .ok_or_else(|| JecpErrorCode::ValidationFailed("time_series array is required".to_string()))?;

    let horizon = input["horizon"].as_u64().unwrap_or(7);

    // Extract numeric values
    let values: Vec<f64> = time_series.iter()
        .filter_map(|v| v.as_f64().or_else(|| v["value"].as_f64()))
        .collect();

    if values.is_empty() {
        return Err(JecpErrorCode::ValidationFailed("time_series must contain numeric values".to_string()));
    }

    // Simple statistical forecast (moving average + trend)
    let n = values.len();
    let mean: f64 = values.iter().sum::<f64>() / n as f64;

    // Calculate trend (simple linear regression)
    let x_mean = (n as f64 - 1.0) / 2.0;
    let mut slope_num = 0.0_f64;
    let mut slope_den = 0.0_f64;
    for (i, &v) in values.iter().enumerate() {
        let x_diff = i as f64 - x_mean;
        slope_num += x_diff * (v - mean);
        slope_den += x_diff * x_diff;
    }
    let slope = if slope_den.abs() > f64::EPSILON { slope_num / slope_den } else { 0.0 };
    let intercept = mean - slope * x_mean;

    // Generate forecasts
    let mut predictions = Vec::new();
    for i in 0..horizon {
        let x = (n + i as usize) as f64;
        let predicted = intercept + slope * x;
        predictions.push(json!({
            "step": i + 1,
            "predicted": (predicted * 100.0).round() / 100.0,
            "lower_bound": ((predicted - 2.0 * mean.abs() * 0.1) * 100.0).round() / 100.0,
            "upper_bound": ((predicted + 2.0 * mean.abs() * 0.1) * 100.0).round() / 100.0,
        }));
    }

    // Use Claude for narrative interpretation
    let system = "You are a data analyst providing forecast interpretations.\n\
                  IMPORTANT: Respond ONLY with valid JSON, no markdown fences.".to_string();

    let prompt = format!(
        "Given a time series with {} data points (mean: {:.2}, trend slope: {:.4}), \
         I've generated {} forecast steps.\n\n\
         Recent values: {:?}\n\n\
         Return a JSON object with:\n\
         - interpretation: Natural language interpretation of the forecast\n\
         - confidence_note: Note about forecast confidence\n\
         - risk_factors: Array of potential risk factors",
        n, mean, slope, horizon,
        &values[n.saturating_sub(10)..]
    );

    let ai_response = ctx.claude.complete(
        Some(&system),
        vec![ClaudeMessage { role: "user".to_string(), content: prompt }],
        2048,
    ).await.map_err(|e| JecpErrorCode::ServiceError(e.to_string()))?;

    let ai_insights = parse_json_response(&ai_response);

    Ok(json!({
        "input_stats": {
            "count": n,
            "mean": (mean * 100.0).round() / 100.0,
            "trend_slope": (slope * 10000.0).round() / 10000.0,
        },
        "predictions": predictions,
        "narrative": ai_insights,
    }))
}

fn analyze_json_structure(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            format!("Object with {} keys: [{}]", map.len(),
                map.keys().take(10).cloned().collect::<Vec<_>>().join(", "))
        }
        serde_json::Value::Array(arr) => {
            format!("Array with {} elements", arr.len())
        }
        serde_json::Value::String(_) => "String".to_string(),
        serde_json::Value::Number(_) => "Number".to_string(),
        serde_json::Value::Bool(_) => "Boolean".to_string(),
        serde_json::Value::Null => "Null".to_string(),
    }
}

fn parse_json_response(response: &str) -> serde_json::Value {
    let trimmed = response.trim();
    serde_json::from_str(trimmed)
        .or_else(|_| {
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
        .unwrap_or_else(|_| json!({ "raw_response": response }))
}
