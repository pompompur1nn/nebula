use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractOracleCallbackSandboxRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ORACLE_CALLBACK_SANDBOX_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-oracle-callback-sandbox-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ORACLE_CALLBACK_SANDBOX_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CALLBACK_MANIFEST_SUITE: &str = "confidential-contract-oracle-callback-manifest-root-v1";
pub const EXECUTION_ENVELOPE_SUITE: &str =
    "bounded-confidential-oracle-callback-execution-envelope-v1";
pub const RESPONSE_COMMITMENT_SUITE: &str = "zk-oracle-response-commitment-root-v1";
pub const PQ_CALLBACK_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-oracle-callback-attestation-v1";
pub const REPLAY_GUARD_SUITE: &str = "confidential-oracle-callback-replay-guard-nullifier-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-confidential-oracle-callback-batch-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-oracle-callback-sandbox-public-record-and-roots-v1";
pub const DEVNET_HEIGHT: u64 = 2_178_400;
pub const DEVNET_EPOCH: u64 = 3_025;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_CALLBACK_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_ENVELOPE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_REPLAY_GUARD_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_GAS_UNITS: u64 = 12_000_000;
pub const DEFAULT_MAX_IO_BYTES: u64 = 4_194_304;
pub const DEFAULT_MAX_CALLBACK_BYTES: u64 = 131_072;
pub const DEFAULT_MAX_PUBLIC_RECORD_BYTES: u64 = 4_096;
pub const DEFAULT_BASE_CALLBACK_FEE_MICRO_CREDITS: u128 = 2_500;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 900;
pub const DEFAULT_BATCHER_REBATE_BPS: u64 = 450;
pub const DEFAULT_MIN_ATTESTER_WEIGHT: u64 = 7;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_400;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_MANIFESTS: usize = 1_048_576;
pub const MAX_ENVELOPES: usize = 4_194_304;
pub const MAX_COMMITMENTS: usize = 4_194_304;
pub const MAX_ATTESTATIONS: usize = 8_388_608;
pub const MAX_REPLAY_GUARDS: usize = 8_388_608;
pub const MAX_BATCHES: usize = 2_097_152;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackKind {
    PriceUpdate,
    RiskUpdate,
    LiquiditySnapshot,
    ReserveProof,
    VolatilitySurface,
    FundingRate,
    CrossContractState,
    EventFilterResult,
    BridgeHealth,
    EmergencyCircuit,
    Custom,
}

impl CallbackKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriceUpdate => "price_update",
            Self::RiskUpdate => "risk_update",
            Self::LiquiditySnapshot => "liquidity_snapshot",
            Self::ReserveProof => "reserve_proof",
            Self::VolatilitySurface => "volatility_surface",
            Self::FundingRate => "funding_rate",
            Self::CrossContractState => "cross_contract_state",
            Self::EventFilterResult => "event_filter_result",
            Self::BridgeHealth => "bridge_health",
            Self::EmergencyCircuit => "emergency_circuit",
            Self::Custom => "custom",
        }
    }

    pub fn emergency_weight(self) -> u64 {
        match self {
            Self::EmergencyCircuit => 1_000,
            Self::BridgeHealth => 880,
            Self::ReserveProof => 820,
            Self::RiskUpdate => 760,
            Self::PriceUpdate => 700,
            Self::LiquiditySnapshot => 640,
            Self::VolatilitySurface => 600,
            Self::FundingRate => 560,
            Self::CrossContractState => 520,
            Self::EventFilterResult => 480,
            Self::Custom => 400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Draft,
    Active,
    Throttled,
    Suspended,
    Retired,
}

impl ManifestStatus {
    pub fn accepts_callbacks(self) -> bool {
        matches!(self, Self::Draft | Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Opened,
    ResponseCommitted,
    Attested,
    Batched,
    Delivered,
    Expired,
    Rejected,
    Slashed,
}

impl EnvelopeStatus {
    pub fn batchable(self) -> bool {
        matches!(self, Self::ResponseCommitted | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Settled,
    Rebated,
    Expired,
    Disputed,
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub callback_manifest_suite: String,
    pub execution_envelope_suite: String,
    pub response_commitment_suite: String,
    pub pq_callback_attestation_suite: String,
    pub replay_guard_suite: String,
    pub low_fee_batch_suite: String,
    pub public_record_scheme: String,
    pub monero_network: String,
    pub l2_network: String,
    pub callback_ttl_blocks: u64,
    pub envelope_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub replay_guard_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_gas_units: u64,
    pub max_io_bytes: u64,
    pub max_callback_bytes: u64,
    pub max_public_record_bytes: u64,
    pub base_callback_fee_micro_credits: u128,
    pub target_rebate_bps: u64,
    pub batcher_rebate_bps: u64,
    pub min_attester_weight: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_manifests: usize,
    pub max_envelopes: usize,
    pub max_commitments: usize,
    pub max_attestations: usize,
    pub max_replay_guards: usize,
    pub max_batches: usize,
    pub max_public_records: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            callback_manifest_suite: CALLBACK_MANIFEST_SUITE.to_string(),
            execution_envelope_suite: EXECUTION_ENVELOPE_SUITE.to_string(),
            response_commitment_suite: RESPONSE_COMMITMENT_SUITE.to_string(),
            pq_callback_attestation_suite: PQ_CALLBACK_ATTESTATION_SUITE.to_string(),
            replay_guard_suite: REPLAY_GUARD_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            callback_ttl_blocks: DEFAULT_CALLBACK_TTL_BLOCKS,
            envelope_ttl_blocks: DEFAULT_ENVELOPE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            replay_guard_ttl_blocks: DEFAULT_REPLAY_GUARD_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_gas_units: DEFAULT_MAX_GAS_UNITS,
            max_io_bytes: DEFAULT_MAX_IO_BYTES,
            max_callback_bytes: DEFAULT_MAX_CALLBACK_BYTES,
            max_public_record_bytes: DEFAULT_MAX_PUBLIC_RECORD_BYTES,
            base_callback_fee_micro_credits: DEFAULT_BASE_CALLBACK_FEE_MICRO_CREDITS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            batcher_rebate_bps: DEFAULT_BATCHER_REBATE_BPS,
            min_attester_weight: DEFAULT_MIN_ATTESTER_WEIGHT,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_manifests: MAX_MANIFESTS,
            max_envelopes: MAX_ENVELOPES,
            max_commitments: MAX_COMMITMENTS,
            max_attestations: MAX_ATTESTATIONS,
            max_replay_guards: MAX_REPLAY_GUARDS,
            max_batches: MAX_BATCHES,
            max_public_records: MAX_PUBLIC_RECORDS,
        }
    }
}

impl PublicRecord for Config {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub manifests_registered: u64,
    pub envelopes_opened: u64,
    pub response_commitments_posted: u64,
    pub pq_attestations_accepted: u64,
    pub replay_guards_inserted: u64,
    pub callback_batches_sealed: u64,
    pub callbacks_delivered: u64,
    pub gas_units_reserved: u128,
    pub gas_units_spent: u128,
    pub io_bytes_reserved: u128,
    pub low_fee_rebates_accrued: u128,
    pub deterministic_public_records: u64,
}

impl PublicRecord for Counters {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub manifest_root: String,
    pub envelope_root: String,
    pub response_commitment_root: String,
    pub attestation_root: String,
    pub replay_guard_root: String,
    pub batch_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            manifest_root: empty_root("MANIFEST"),
            envelope_root: empty_root("ENVELOPE"),
            response_commitment_root: empty_root("RESPONSE-COMMITMENT"),
            attestation_root: empty_root("ATTESTATION"),
            replay_guard_root: empty_root("REPLAY-GUARD"),
            batch_root: empty_root("BATCH"),
            public_record_root: empty_root("PUBLIC-RECORD"),
            state_root: empty_root("STATE"),
        }
    }
}

impl PublicRecord for Roots {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallbackManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub callback_kind: CallbackKind,
    pub status: ManifestStatus,
    pub oracle_set_root: String,
    pub callback_selector_commitment: String,
    pub argument_schema_root: String,
    pub result_schema_root: String,
    pub policy_root: String,
    pub max_gas_units: u64,
    pub max_io_bytes: u64,
    pub max_callback_bytes: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PublicRecord for CallbackManifest {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedExecutionEnvelope {
    pub envelope_id: String,
    pub manifest_id: String,
    pub request_commitment: String,
    pub replay_nullifier: String,
    pub status: EnvelopeStatus,
    pub gas_limit: u64,
    pub io_limit: u64,
    pub callback_bytes_limit: u64,
    pub fee_escrow_micro_credits: u128,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PublicRecord for BoundedExecutionEnvelope {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleResponseCommitment {
    pub commitment_id: String,
    pub envelope_id: String,
    pub response_root: String,
    pub redacted_public_root: String,
    pub transcript_root: String,
    pub observed_at_height: u64,
    pub gas_used: u64,
    pub io_bytes_used: u64,
    pub callback_bytes: u64,
}

impl PublicRecord for OracleResponseCommitment {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCallbackAttestation {
    pub attestation_id: String,
    pub envelope_id: String,
    pub commitment_id: String,
    pub status: AttestationStatus,
    pub signer_set_root: String,
    pub attestation_root: String,
    pub quorum_weight: u64,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PublicRecord for PqCallbackAttestation {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayGuard {
    pub replay_nullifier: String,
    pub envelope_id: String,
    pub manifest_id: String,
    pub inserted_at_height: u64,
    pub expires_at_height: u64,
}

impl PublicRecord for ReplayGuard {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCallbackBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub batcher_commitment: String,
    pub envelope_ids: BTreeSet<String>,
    pub batch_root: String,
    pub fee_floor_micro_credits: u128,
    pub rebate_micro_credits: u128,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
}

impl PublicRecord for LowFeeCallbackBatch {
    fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status,
            "batcher_commitment": self.batcher_commitment,
            "envelope_ids": sorted_strings(&self.envelope_ids),
            "batch_root": self.batch_root,
            "fee_floor_micro_credits": self.fee_floor_micro_credits,
            "rebate_micro_credits": self.rebate_micro_credits,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub domain: String,
    pub subject_id: String,
    pub record_root: String,
    pub emitted_at_height: u64,
}

impl PublicRecord for DeterministicPublicRecord {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterManifestRequest {
    pub contract_id: String,
    pub callback_kind: CallbackKind,
    pub oracle_set_root: String,
    pub callback_selector_commitment: String,
    pub argument_schema_root: String,
    pub result_schema_root: String,
    pub policy_root: String,
    pub max_gas_units: u64,
    pub max_io_bytes: u64,
    pub max_callback_bytes: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl PublicRecord for RegisterManifestRequest {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenEnvelopeRequest {
    pub manifest_id: String,
    pub request_commitment: String,
    pub replay_nullifier: String,
    pub gas_limit: u64,
    pub io_limit: u64,
    pub callback_bytes_limit: u64,
    pub fee_escrow_micro_credits: u128,
}

impl PublicRecord for OpenEnvelopeRequest {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub manifests: BTreeMap<String, CallbackManifest>,
    pub envelopes: BTreeMap<String, BoundedExecutionEnvelope>,
    pub response_commitments: BTreeMap<String, OracleResponseCommitment>,
    pub attestations: BTreeMap<String, PqCallbackAttestation>,
    pub replay_guards: BTreeMap<String, ReplayGuard>,
    pub low_fee_batches: BTreeMap<String, LowFeeCallbackBatch>,
    pub deterministic_public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            manifests: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            response_commitments: BTreeMap::new(),
            attestations: BTreeMap::new(),
            replay_guards: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            deterministic_public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH);
        state.seed_devnet();
        state
    }

    fn seed_devnet(&mut self) {
        let manifest = RegisterManifestRequest {
            contract_id: "confidential-perps-vault-devnet".to_string(),
            callback_kind: CallbackKind::FundingRate,
            oracle_set_root: deterministic_record_root(
                "DEVNET-ORACLE-SET",
                &json!(["oracle-alpha", "oracle-beta", "oracle-gamma"]),
            ),
            callback_selector_commitment: deterministic_record_root(
                "DEVNET-CALLBACK-SELECTOR",
                &json!("apply_funding_callback(bytes32,bytes)"),
            ),
            argument_schema_root: deterministic_record_root("DEVNET-ARGS", &json!("funding-v1")),
            result_schema_root: deterministic_record_root("DEVNET-RESULT", &json!("rate-v1")),
            policy_root: deterministic_record_root("DEVNET-POLICY", &json!("bounded-low-fee")),
            max_gas_units: 3_500_000,
            max_io_bytes: 524_288,
            max_callback_bytes: 32_768,
            min_privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        };
        let manifest_id = self.register_manifest(manifest).unwrap_or_default();
        let envelope = OpenEnvelopeRequest {
            manifest_id: manifest_id.clone(),
            request_commitment: deterministic_record_root(
                "DEVNET-REQUEST",
                &json!({"market": "XMR-USD", "epoch": self.epoch}),
            ),
            replay_nullifier: deterministic_record_root(
                "DEVNET-REPLAY-NULLIFIER",
                &json!({"manifest_id": manifest_id, "slot": self.height}),
            ),
            gas_limit: 2_400_000,
            io_limit: 262_144,
            callback_bytes_limit: 16_384,
            fee_escrow_micro_credits: self.config.base_callback_fee_micro_credits,
        };
        let _ = self.open_envelope(envelope);
        self.refresh_roots();
    }

    pub fn register_manifest(
        &mut self,
        request: RegisterManifestRequest,
    ) -> PrivateL2PqConfidentialContractOracleCallbackSandboxRuntimeResult<String> {
        ensure!(
            self.manifests.len() < self.config.max_manifests,
            "manifest capacity exceeded"
        );
        ensure!(
            request.max_gas_units <= self.config.max_gas_units,
            "manifest gas limit exceeds runtime maximum"
        );
        ensure!(
            request.max_io_bytes <= self.config.max_io_bytes,
            "manifest io limit exceeds runtime maximum"
        );
        ensure!(
            request.max_callback_bytes <= self.config.max_callback_bytes,
            "manifest callback bytes limit exceeds runtime maximum"
        );
        ensure!(
            request.min_privacy_set_size >= self.config.min_privacy_set_size,
            "manifest privacy set below runtime minimum"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "manifest pq security bits below runtime minimum"
        );

        let sequence = self.counters.manifests_registered + 1;
        let manifest_id = deterministic_id("MANIFEST-ID", sequence, &request.public_record());
        let record = CallbackManifest {
            manifest_id: manifest_id.clone(),
            contract_id: request.contract_id,
            callback_kind: request.callback_kind,
            status: ManifestStatus::Active,
            oracle_set_root: request.oracle_set_root,
            callback_selector_commitment: request.callback_selector_commitment,
            argument_schema_root: request.argument_schema_root,
            result_schema_root: request.result_schema_root,
            policy_root: request.policy_root,
            max_gas_units: request.max_gas_units,
            max_io_bytes: request.max_io_bytes,
            max_callback_bytes: request.max_callback_bytes,
            min_privacy_set_size: request.min_privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.callback_ttl_blocks,
        };
        self.manifests.insert(manifest_id.clone(), record);
        self.counters.manifests_registered = sequence;
        self.emit_public_record("manifest", &manifest_id);
        self.refresh_roots();
        Ok(manifest_id)
    }

    pub fn open_envelope(
        &mut self,
        request: OpenEnvelopeRequest,
    ) -> PrivateL2PqConfidentialContractOracleCallbackSandboxRuntimeResult<String> {
        ensure!(
            self.envelopes.len() < self.config.max_envelopes,
            "envelope capacity exceeded"
        );
        ensure!(
            !self.replay_guards.contains_key(&request.replay_nullifier),
            "replay nullifier already spent"
        );
        let manifest = self
            .manifests
            .get(&request.manifest_id)
            .ok_or_else(|| format!("unknown manifest {}", request.manifest_id))?;
        ensure!(
            manifest.status.accepts_callbacks(),
            "manifest does not accept callbacks"
        );
        ensure!(
            request.gas_limit <= manifest.max_gas_units,
            "envelope gas limit exceeds manifest maximum"
        );
        ensure!(
            request.io_limit <= manifest.max_io_bytes,
            "envelope io limit exceeds manifest maximum"
        );
        ensure!(
            request.callback_bytes_limit <= manifest.max_callback_bytes,
            "envelope callback bytes limit exceeds manifest maximum"
        );

        let sequence = self.counters.envelopes_opened + 1;
        let envelope_id = deterministic_id("ENVELOPE-ID", sequence, &request.public_record());
        let envelope = BoundedExecutionEnvelope {
            envelope_id: envelope_id.clone(),
            manifest_id: request.manifest_id.clone(),
            request_commitment: request.request_commitment,
            replay_nullifier: request.replay_nullifier.clone(),
            status: EnvelopeStatus::Opened,
            gas_limit: request.gas_limit,
            io_limit: request.io_limit,
            callback_bytes_limit: request.callback_bytes_limit,
            fee_escrow_micro_credits: request.fee_escrow_micro_credits,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.envelope_ttl_blocks,
        };
        let guard = ReplayGuard {
            replay_nullifier: request.replay_nullifier.clone(),
            envelope_id: envelope_id.clone(),
            manifest_id: request.manifest_id,
            inserted_at_height: self.height,
            expires_at_height: self.height + self.config.replay_guard_ttl_blocks,
        };
        self.envelopes.insert(envelope_id.clone(), envelope);
        self.replay_guards.insert(request.replay_nullifier, guard);
        self.counters.envelopes_opened = sequence;
        self.counters.replay_guards_inserted += 1;
        self.counters.gas_units_reserved += request.gas_limit as u128;
        self.counters.io_bytes_reserved += request.io_limit as u128;
        self.emit_public_record("envelope", &envelope_id);
        self.refresh_roots();
        Ok(envelope_id)
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "manifest_root": self.roots.manifest_root,
                "envelope_root": self.roots.envelope_root,
                "response_commitment_root": self.roots.response_commitment_root,
                "attestation_root": self.roots.attestation_root,
                "replay_guard_root": self.roots.replay_guard_root,
                "batch_root": self.roots.batch_root,
                "public_record_root": self.roots.public_record_root,
            },
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["roots"]["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn emit_public_record(&mut self, domain: &str, subject_id: &str) {
        if self.deterministic_public_records.len() >= self.config.max_public_records {
            return;
        }
        let record_id = deterministic_record_root(
            "PUBLIC-RECORD-ID",
            &json!({
                "domain": domain,
                "subject_id": subject_id,
                "height": self.height,
                "index": self.counters.deterministic_public_records + 1,
            }),
        );
        let record_root = deterministic_record_root(
            "PUBLIC-RECORD",
            &json!({
                "domain": domain,
                "subject_id": subject_id,
                "height": self.height,
            }),
        );
        self.deterministic_public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id,
                domain: domain.to_string(),
                subject_id: subject_id.to_string(),
                record_root,
                emitted_at_height: self.height,
            },
        );
        self.counters.deterministic_public_records += 1;
    }

    fn refresh_roots(&mut self) {
        self.roots.manifest_root = public_record_root("MANIFEST", &values_record(&self.manifests));
        self.roots.envelope_root = public_record_root("ENVELOPE", &values_record(&self.envelopes));
        self.roots.response_commitment_root = public_record_root(
            "RESPONSE-COMMITMENT",
            &values_record(&self.response_commitments),
        );
        self.roots.attestation_root =
            public_record_root("ATTESTATION", &values_record(&self.attestations));
        self.roots.replay_guard_root =
            public_record_root("REPLAY-GUARD", &values_record(&self.replay_guards));
        self.roots.batch_root =
            public_record_root("LOW-FEE-BATCH", &values_record(&self.low_fee_batches));
        self.roots.public_record_root = public_record_root(
            "DETERMINISTIC-PUBLIC-RECORD",
            &values_record(&self.deterministic_public_records),
        );
        self.roots.state_root = self.state_root();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-ORACLE-CALLBACK-SANDBOX:{domain}-ROOT"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ORACLE-CALLBACK-SANDBOX:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-ORACLE-CALLBACK-SANDBOX:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_id(domain: &str, sequence: u64, record: &Value) -> String {
    deterministic_record_root(domain, &json!({"sequence": sequence, "record": record}))
}

pub fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

fn values_record<T>(records: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    records.values().map(PublicRecord::public_record).collect()
}

fn sorted_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}
