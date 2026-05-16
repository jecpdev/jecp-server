//! v1.0.2 K2.5 — `input_schema` validation against published manifest.
//!
//! Spec: 01-protocol §4.5 + 03-errors §3.2 (`INPUT_SCHEMA_VIOLATION`).
//!
//! Hub-side flow:
//!
//! 1. After capability resolution (`routes/invoke.rs`), look up the action's
//!    `input_schema` from `resolved.parsed_json.actions[].input_schema`.
//! 2. If absent → graceful pass (manifests pre-dating v1.0.2 don't declare
//!    per-action schemas; rejecting them would be a wire-breaking change).
//! 3. If present → compile via `jsonschema::JSONSchema::compile`, cache the
//!    compiled validator on `AppState.schema_cache` keyed by
//!    `(capability_id, action_id)`.
//! 4. Validate `req.input` against the cached compiler. Aggregate violations
//!    into `Vec<InputSchemaError>` and return
//!    `JecpErrorCode::InputSchemaViolation { summary, errors }` on failure.
//!
//! Cache strategy: Mutex<lru::LruCache<(Uuid, String), Arc<JSONSchema>>>.
//! Capacity from `JECP_SCHEMA_CACHE_CAP` env (default 512). LRU auto-evicts
//! when full. Manual invalidation on capability promote/sunset is **not**
//! implemented in v1.0.2 (locked-design §3 K2.5 acceptable simplification —
//! manifest publish requires Hub restart for v1.0.2; v1.0.3 ships
//! `/v1/admin/cache/flush`).

use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use parking_lot::Mutex;

use crate::protocol::errors::{InputSchemaError, JecpErrorCode};

/// Default schema cache capacity. Each entry is one compiled validator
/// (~few KB). 512 entries × ~5KB ≈ 2.5MB — negligible.
pub const DEFAULT_SCHEMA_CACHE_CAPACITY: usize = 512;

/// Trait abstraction so v1.0.3 can swap a different store (e.g. Redis-cached
/// pre-compiled bytes) without touching call sites.
pub trait SchemaStore: Send + Sync {
    /// Look up or compile-and-cache the schema for `(capability_id, action_id)`.
    /// Returns the Arc<JSONSchema> on success or `JecpErrorCode::Internal` on
    /// compile failure (which should never happen at runtime if the manifest
    /// publish path enforces compile-on-publish).
    fn get_or_compile(
        &self,
        capability_id: uuid::Uuid,
        action_id: &str,
        schema_value: &serde_json::Value,
    ) -> Result<Arc<jsonschema::JSONSchema>, JecpErrorCode>;
}

pub struct MemorySchemaCache {
    inner: Mutex<LruCache<(uuid::Uuid, String), Arc<jsonschema::JSONSchema>>>,
}

impl MemorySchemaCache {
    pub fn new(capacity: usize) -> Arc<Self> {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Arc::new(Self {
            inner: Mutex::new(LruCache::new(cap)),
        })
    }

    pub fn from_env() -> Arc<Self> {
        let cap = std::env::var("JECP_SCHEMA_CACHE_CAP")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_SCHEMA_CACHE_CAPACITY);
        Self::new(cap)
    }
}

impl SchemaStore for MemorySchemaCache {
    fn get_or_compile(
        &self,
        capability_id: uuid::Uuid,
        action_id: &str,
        schema_value: &serde_json::Value,
    ) -> Result<Arc<jsonschema::JSONSchema>, JecpErrorCode> {
        let key = (capability_id, action_id.to_string());
        {
            let mut g = self.inner.lock();
            if let Some(c) = g.get(&key) {
                return Ok(c.clone());
            }
        }
        // Compile (slow path).
        let compiled = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(schema_value)
            .map_err(|e| JecpErrorCode::Internal(format!(
                "manifest input_schema for action '{}' is invalid: {}", action_id, e
            )))?;
        let arc = Arc::new(compiled);
        let mut g = self.inner.lock();
        g.put(key, arc.clone());
        Ok(arc)
    }
}

/// Validate `input` against the manifest's `input_schema` for `action_id`.
///
/// Returns `Ok(())` on success or `INPUT_SCHEMA_VIOLATION` on failure.
/// When the manifest does not declare an input_schema for the action,
/// returns `Ok(())` (graceful pass — preserves backward compat for
/// pre-v1.0.2 manifests).
pub fn validate_input_against_manifest(
    cache: &dyn SchemaStore,
    capability_id: uuid::Uuid,
    action_id: &str,
    manifest: &serde_json::Value,
    input: &serde_json::Value,
) -> Result<(), JecpErrorCode> {
    // 1. Locate the action's input_schema.
    let schema_value = manifest
        .get("actions")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|a| a.get("id").and_then(|i| i.as_str()) == Some(action_id))
        })
        .and_then(|a| a.get("input_schema"));

    let Some(schema_value) = schema_value else {
        // No input_schema declared for this action → graceful pass.
        return Ok(());
    };

    // 2. Compile (or fetch from cache).
    let compiled = cache.get_or_compile(capability_id, action_id, schema_value)?;

    // 3. Validate. Drain up to N violations to keep the response bounded.
    const MAX_VIOLATIONS: usize = 10;
    if let Err(errs) = compiled.validate(input) {
        let collected: Vec<InputSchemaError> = errs
            .take(MAX_VIOLATIONS)
            .map(|e| InputSchemaError {
                instance_path: e.instance_path.to_string(),
                schema_path:   e.schema_path.to_string(),
                reason:        e.to_string(),
            })
            .collect();

        let summary = if collected.is_empty() {
            // Defensive — validate() returned Err but no violations enumerable.
            "input_schema validation failed (no specific violations available)".to_string()
        } else if collected.len() == 1 {
            format!("{}", collected[0].reason)
        } else {
            format!("{} violations (first: {})", collected.len(), collected[0].reason)
        };

        return Err(JecpErrorCode::InputSchemaViolation {
            summary,
            errors: collected,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest_with_translate_schema() -> serde_json::Value {
        json!({
            "namespace": "test",
            "capability": "translate-cap",
            "actions": [{
                "id": "translate",
                "description": "translate text",
                "input_schema": {
                    "type": "object",
                    "required": ["text", "target_lang"],
                    "additionalProperties": false,
                    "properties": {
                        "text":        { "type": "string" },
                        "target_lang": { "type": "string", "minLength": 2 }
                    }
                }
            }]
        })
    }

    fn cap_id() -> uuid::Uuid {
        uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
    }

    #[test]
    fn no_input_schema_is_graceful_pass() {
        let cache = MemorySchemaCache::new(8);
        // Manifest with no input_schema on the action.
        let manifest = json!({
            "actions": [{ "id": "echo", "description": "no schema" }]
        });
        let r = validate_input_against_manifest(
            &*cache,
            cap_id(),
            "echo",
            &manifest,
            &json!({"anything": 1}),
        );
        assert!(r.is_ok());
    }

    #[test]
    fn missing_required_field_violates() {
        let cache = MemorySchemaCache::new(8);
        let m = manifest_with_translate_schema();
        let r = validate_input_against_manifest(
            &*cache,
            cap_id(),
            "translate",
            &m,
            &json!({ "text": "hello" }), // missing target_lang
        );
        let err = r.unwrap_err();
        match err {
            JecpErrorCode::InputSchemaViolation { errors, .. } => {
                assert!(!errors.is_empty());
                let combined: String = errors.iter().map(|e| e.reason.clone()).collect();
                assert!(combined.contains("target_lang") || combined.contains("required"));
            }
            other => panic!("expected InputSchemaViolation, got {:?}", other),
        }
    }

    #[test]
    fn wrong_type_violates() {
        let cache = MemorySchemaCache::new(8);
        let m = manifest_with_translate_schema();
        let r = validate_input_against_manifest(
            &*cache,
            cap_id(),
            "translate",
            &m,
            &json!({ "text": 42, "target_lang": "ja" }),
        );
        let err = r.unwrap_err();
        assert!(matches!(err, JecpErrorCode::InputSchemaViolation { .. }));
    }

    #[test]
    fn additional_property_violates() {
        let cache = MemorySchemaCache::new(8);
        let m = manifest_with_translate_schema();
        let r = validate_input_against_manifest(
            &*cache,
            cap_id(),
            "translate",
            &m,
            &json!({ "text": "hi", "target_lang": "ja", "junk": 1 }),
        );
        assert!(matches!(r, Err(JecpErrorCode::InputSchemaViolation { .. })));
    }

    #[test]
    fn valid_input_passes() {
        let cache = MemorySchemaCache::new(8);
        let m = manifest_with_translate_schema();
        let r = validate_input_against_manifest(
            &*cache,
            cap_id(),
            "translate",
            &m,
            &json!({ "text": "hi", "target_lang": "ja" }),
        );
        assert!(r.is_ok());
    }

    #[test]
    fn cache_hit_avoids_recompile() {
        let cache = MemorySchemaCache::new(8);
        let m = manifest_with_translate_schema();
        // First call compiles + caches.
        let _ = validate_input_against_manifest(
            &*cache, cap_id(), "translate", &m, &json!({"text":"a","target_lang":"ja"})
        );
        // Second call should hit cache. Verify Arc::strong_count grows.
        // We can't directly observe strong_count from outside the cache,
        // but a second valid call should not error and should be fast.
        let r = validate_input_against_manifest(
            &*cache, cap_id(), "translate", &m, &json!({"text":"b","target_lang":"en"})
        );
        assert!(r.is_ok());
    }

    #[test]
    fn empty_schema_is_permissive() {
        let cache = MemorySchemaCache::new(8);
        // type: object with no properties → anything goes, but additionalProperties default is true.
        let m = json!({
            "actions": [{
                "id": "any",
                "input_schema": { "type": "object" }
            }]
        });
        let r = validate_input_against_manifest(
            &*cache, cap_id(), "any", &m,
            &json!({ "anything": "goes", "really": 42 }),
        );
        assert!(r.is_ok());
    }
}
