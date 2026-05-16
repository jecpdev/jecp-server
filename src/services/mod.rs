pub mod audit;
pub mod claude;
pub mod database;
pub mod sns_bridge;
pub mod storage;
pub mod supervisor;
pub mod webhooks;

// v1.1.0 x402 (locked-design §5)
pub mod splitter_registry;
pub mod x402_cert_pin; // v1.1.1 H-1 — ADR-0005 resolution
pub mod x402_facilitator;
pub mod x402_reconciler;
pub mod x402_relayer;
// v1.1.1 H-3: production AWS KMS RELAYER signer (locked-design Am-5).
// Selected at boot via JECP_RELAYER_KMS_KEY_ID env; falls back to
// StubRelayerSigner when unset (zero behavior change for existing deploys).
pub mod x402_relayer_aws_kms;
pub mod x402_settlements;
