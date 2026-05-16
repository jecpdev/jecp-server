use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// In-memory temporary file storage with auto-expiry
/// Files are stored for at most 10 minutes
#[derive(Clone)]
pub struct TempStorage {
    files: Arc<RwLock<HashMap<String, StoredFile>>>,
}

struct StoredFile {
    data: Vec<u8>,
    content_type: String,
    created_at: std::time::Instant,
}

impl TempStorage {
    pub fn new() -> Self {
        let storage = Self {
            files: Arc::new(RwLock::new(HashMap::new())),
        };

        // Spawn cleanup task
        let files = storage.files.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut store = files.write().await;
                let now = std::time::Instant::now();
                store.retain(|_, f| now.duration_since(f.created_at).as_secs() < 600);
            }
        });

        storage
    }

    /// Store a file and return its ID
    pub async fn store(&self, data: Vec<u8>, content_type: &str) -> String {
        let id = format!("tmp_{}", Uuid::new_v4().to_string().replace('-', ""));
        let file = StoredFile {
            data,
            content_type: content_type.to_string(),
            created_at: std::time::Instant::now(),
        };
        self.files.write().await.insert(id.clone(), file);
        id
    }

    /// Store base64-encoded data
    pub async fn store_base64(&self, b64: &str, content_type: &str) -> Result<String, anyhow::Error> {
        let data = STANDARD.decode(b64)?;
        Ok(self.store(data, content_type).await)
    }

    /// Retrieve file data
    pub async fn get(&self, id: &str) -> Option<(Vec<u8>, String)> {
        let store = self.files.read().await;
        store.get(id).map(|f| (f.data.clone(), f.content_type.clone()))
    }

    /// Get file as base64
    pub async fn get_base64(&self, id: &str) -> Option<String> {
        self.get(id).await.map(|(data, _)| STANDARD.encode(data))
    }

    /// Remove a file
    pub async fn remove(&self, id: &str) {
        self.files.write().await.remove(id);
    }
}
