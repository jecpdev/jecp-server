use std::env;

/// Application configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct Config {
    /// Server host (default: 0.0.0.0)
    pub host: String,
    /// Server port (default: 3001)
    pub port: u16,
    /// PostgreSQL database URL (Supabase)
    pub database_url: String,
    /// Anthropic API key for Claude
    pub anthropic_api_key: String,
    /// Anthropic model to use (default: claude-haiku-4-5-20251001 — 安いモデルを使う)
    pub anthropic_model: String,
    /// CORS allowed origins
    pub cors_origins: Vec<String>,
    /// Max database pool connections
    pub db_max_connections: u32,
    /// Free tier daily call limit per agent
    pub free_tier_daily_limit: u32,
    /// Environment (development/production)
    pub environment: String,
    /// Next.js base URL for internal SNS Bridge API calls.
    /// 注: これは Hub→自社 Provider(JobDoneBot Next.js)への内部呼出用。
    /// Phase 5(専用 Supabase + 専用 Stripe Connect 移行時)に廃止予定。
    /// JECP プロトコル仕様で公開する URL は jecp.dev に統一。
    pub nextjs_base_url: String,
    /// Shared secret for JECP→Next.js Bridge authentication
    pub jecp_bridge_secret: String,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, env::VarError> {
        Ok(Self {
            host: env::var("JECP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("JECP_PORT")
                .unwrap_or_else(|_| "3001".to_string())
                .parse()
                .unwrap_or(3001),
            database_url: env::var("DATABASE_URL").unwrap_or_default(),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY")?,
            anthropic_model: env::var("ANTHROPIC_MODEL")
                .unwrap_or_else(|_| "claude-haiku-4-5-20251001".to_string()),
            cors_origins: env::var("CORS_ORIGINS")
                .unwrap_or_else(|_| {
                    "https://jecp.dev,https://api.jecp.dev,https://jobdonebot.com,http://localhost:3000".to_string()
                })
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            db_max_connections: env::var("DB_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .unwrap_or(15),
            free_tier_daily_limit: env::var("FREE_TIER_DAILY_LIMIT")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            environment: env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
            nextjs_base_url: env::var("NEXTJS_BASE_URL")
                .unwrap_or_else(|_| "https://jobdonebot.com".to_string()),
            jecp_bridge_secret: env::var("JECP_BRIDGE_SECRET").unwrap_or_default(),
        })
    }

    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// v1.1.0 x402 — config (locked-design §5.2)
// ─────────────────────────────────────────────────────────────────────────────

use alloy_primitives::Address;
use std::sync::Arc;

use crate::services::splitter_registry::SplitterRegistry;
use crate::services::x402_facilitator::FacilitatorClient;
use crate::services::x402_relayer::{RelayerSigner, StubRelayerSigner};

/// Runtime configuration for the x402 payment path. `None` on AppState when
/// `X402_FACILITATOR_URL` is unset → Hub runs in wallet-only mode.
#[derive(Clone)]
pub struct X402Config {
    pub facilitator: FacilitatorClient,
    pub splitter_registry: SplitterRegistry,
    pub relayer: Arc<dyn RelayerSigner>,
    pub splitter_address: Address,
    pub treasury_address: Address,
    pub reserve_address: Address,
    pub relayer_address: Address,
    pub base_rpc_url: String,
    pub network: String,
    pub usdc_asset: Address,
    /// v1.1.1 H-3 (locked-design Am-5): EVM chain id used by the AWS KMS
    /// signer for EIP-1559 tx assembly. Default 8453 (Base mainnet); set to
    /// 84532 for Sepolia. Sourced from `JECP_RELAYER_CHAIN_ID`.
    pub relayer_chain_id: u64,
    /// v1.1.1 H-3: AWS KMS key id (ARN or alias) for the RELAYER signer.
    /// `None` → AppState wires `StubRelayerSigner` (v1.1.0 behavior). When
    /// set + non-empty, `main.rs` overrides `relayer` with `AwsKmsRelayerSigner`
    /// at boot.
    pub relayer_kms_key_id: Option<String>,
    /// Dedicated reqwest client for the reconciler RPC calls (separate
    /// connection pool from the facilitator client so a Base RPC stall
    /// cannot block facilitator verify/settle).
    pub reconciler_client: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum X402ConfigError {
    #[error("X402_FACILITATOR_URL is set but {0}")]
    Missing(String),
    #[error("invalid address for {field}: {message}")]
    InvalidAddress { field: String, message: String },
    #[error("facilitator init: {0}")]
    Facilitator(String),
    #[error("invalid base_rpc_url: {0}")]
    InvalidRpcUrl(String),
}

impl X402Config {
    /// Build from env. Returns `Ok(None)` when `X402_FACILITATOR_URL` unset
    /// (Hub-wide kill switch at boot per locked-design §5.10).
    ///
    /// Audit B TM-X1 (spec §6.1 ¶2): both `X402_FACILITATOR_URL` and
    /// `BASE_RPC_URL` are pushed through the SSRF preflight pipeline so a
    /// typo'd internal IP (`https://10.0.0.1/...`) can't bring the Hub
    /// up clean. Full async DNS-resolve check is deferred until first call —
    /// the preflight here covers literal-IP deny + scheme + parse without
    /// taking on a tokio dependency.
    pub fn from_env() -> Result<Option<Self>, X402ConfigError> {
        let facilitator_url = match env::var("X402_FACILITATOR_URL") {
            Ok(s) if !s.trim().is_empty() => s,
            _ => return Ok(None),
        };

        // TM-X1: SSRF preflight on the facilitator URL.
        crate::protocol::url_guard::validate_outbound_url_preflight(&facilitator_url)
            .map_err(|e| X402ConfigError::InvalidRpcUrl(format!(
                "X402_FACILITATOR_URL failed SSRF guard: {:?}", e
            )))?;

        let response_pubkey = env::var("X402_FACILITATOR_PUBKEY")
            .map_err(|_| X402ConfigError::Missing("X402_FACILITATOR_PUBKEY".into()))?;
        let cert_pin = env::var("X402_FACILITATOR_CERT_PIN")
            .map_err(|_| X402ConfigError::Missing("X402_FACILITATOR_CERT_PIN".into()))?;

        let facilitator =
            FacilitatorClient::new(&facilitator_url, &response_pubkey, &cert_pin)
                .map_err(|e| X402ConfigError::Facilitator(e.to_string()))?;

        // v1.1.1 H-1 (ADR-0005 resolution): cert pin is now enforced inside
        // a custom rustls ServerCertVerifier in FacilitatorClient. Two
        // boot-time states are possible:
        //
        // - Real 32-byte pin configured → enforced at TLS handshake. No warn.
        // - All-zeros sentinel → backward-compat fallback to default rustls
        //   validation; emit a loud warn so operators see the gap. This
        //   replaces the unconditional v1.1.0 warning, which has been
        //   removed now that real pins are actually enforced.
        let zero_pin_bytes = hex::decode(cert_pin.trim_start_matches("sha256:"))
            .unwrap_or_default();
        if zero_pin_bytes.len() == 32 && zero_pin_bytes.iter().all(|&b| b == 0) {
            tracing::warn!(
                "x402 cert_pin_sha256 is the all-zeros sentinel — TLS pin NOT \
                 enforced (backward-compat mode). Provision a real SPKI hash \
                 in X402_FACILITATOR_CERT_PIN to close ADR-0005."
            );
        }

        let splitter_address = parse_address_env("JECP_SPLITTER_ADDRESS")?;
        let treasury_address = parse_address_env("JECP_TREASURY_ADDRESS")?;
        let reserve_address = parse_address_env("JECP_RESERVE_ADDRESS")?;
        let relayer_address = parse_address_env("JECP_RELAYER_ADDRESS")?;
        let usdc_asset = parse_address_env_or_default(
            "X402_USDC_ASSET",
            "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // Base mainnet USDC
        )?;

        let base_rpc_url = env::var("BASE_RPC_URL")
            .map_err(|_| X402ConfigError::Missing("BASE_RPC_URL".into()))?;
        if !base_rpc_url.starts_with("https://") {
            return Err(X402ConfigError::InvalidRpcUrl(base_rpc_url));
        }
        // TM-X1: SSRF preflight on the Base RPC URL.
        crate::protocol::url_guard::validate_outbound_url_preflight(&base_rpc_url)
            .map_err(|e| X402ConfigError::InvalidRpcUrl(format!(
                "BASE_RPC_URL failed SSRF guard: {:?}", e
            )))?;

        let network = env::var("X402_NETWORK").unwrap_or_else(|_| "base".to_string());

        let splitter_registry = SplitterRegistry::new(splitter_address, &base_rpc_url);

        // v1.1.1 H-3: default to StubRelayerSigner here. main.rs may swap in
        // `AwsKmsRelayerSigner` after boot (it requires async KMS init that
        // can't run in this sync constructor). When `JECP_RELAYER_KMS_KEY_ID`
        // is unset, the stub stays and v1.1.0 behavior is preserved bit-for-bit.
        let relayer: Arc<dyn RelayerSigner> =
            Arc::new(StubRelayerSigner::new(relayer_address));

        // v1.1.1 H-3: chain id (default Base mainnet 8453; sepolia override
        // = 84532). Used only by the AWS KMS signer when active.
        let relayer_chain_id = env::var("JECP_RELAYER_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(8453);

        let relayer_kms_key_id = env::var("JECP_RELAYER_KMS_KEY_ID")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let reconciler_client = reqwest::Client::builder()
            .pool_max_idle_per_host(4)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| X402ConfigError::Facilitator(format!("reconciler client: {}", e)))?;

        Ok(Some(Self {
            facilitator,
            splitter_registry,
            relayer,
            splitter_address,
            treasury_address,
            reserve_address,
            relayer_address,
            base_rpc_url,
            network,
            usdc_asset,
            relayer_chain_id,
            relayer_kms_key_id,
            reconciler_client,
        }))
    }
}

fn parse_address_env(var: &str) -> Result<Address, X402ConfigError> {
    let raw = env::var(var).map_err(|_| X402ConfigError::Missing(var.to_string()))?;
    raw.trim()
        .parse::<Address>()
        .map_err(|e| X402ConfigError::InvalidAddress {
            field: var.to_string(),
            message: e.to_string(),
        })
}

fn parse_address_env_or_default(var: &str, default: &str) -> Result<Address, X402ConfigError> {
    let raw = env::var(var).unwrap_or_else(|_| default.to_string());
    raw.trim()
        .parse::<Address>()
        .map_err(|e| X402ConfigError::InvalidAddress {
            field: var.to_string(),
            message: e.to_string(),
        })
}
