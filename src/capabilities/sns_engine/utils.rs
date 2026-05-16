/// Parse JSON from Claude response, handling markdown code fences.
///
/// Claude sometimes wraps JSON in ```json ... ``` blocks.
/// This function handles both raw JSON and fenced JSON.
pub fn parse_json_response(response: &str) -> Option<serde_json::Value> {
    let trimmed = response.trim();
    if let Ok(v) = serde_json::from_str(trimmed) {
        return Some(v);
    }
    let json_str = if trimmed.starts_with("```json") {
        trimmed
            .strip_prefix("```json")
            .unwrap_or(trimmed)
            .strip_suffix("```")
            .unwrap_or(trimmed)
            .trim()
    } else if trimmed.starts_with("```") {
        trimmed
            .strip_prefix("```")
            .unwrap_or(trimmed)
            .strip_suffix("```")
            .unwrap_or(trimmed)
            .trim()
    } else {
        trimmed
    };
    serde_json::from_str(json_str).ok()
}
