use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlKemSponsorKeyRecoveryBondRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_SPONSOR_KEY_RECOVERY_BOND_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-ml-kem-sponsor-key-recovery-bond-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_SPONSOR_KEY_RECOVERY_BOND_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ML_KEM_RECOVERY_ENVELOPE_SUITE: &str = "ML-KEM-1024-sponsor-key-recovery-envelope-v1";
pub const SPONSOR_RECOVERY_BOND_POLICY_SUITE: &str =
    "private-l2-pq-confidential-sponsor-key-recovery-bond-policy-v1";
pub const PRIVATE_RECOVERY_EVIDENCE_SUITE: &str = "sealed-private-sponsor-key-recovery-evidence-v1";
pub const KEY_ROTATION_WINDOW_SUITE: &str = "ml-kem-sponsor-recovery-key-rotation-window-v1";
pub const NULLIFIER_GUARD_SUITE: &str = "private-l2-session-key-nullifier-replay-guard-v1";
pub const LOW_FEE_BOND_REFUND_LEDGER_SUITE: &str =
    "confidential-sponsored-recovery-bond-low-fee-refund-ledger-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-sponsor-key-recovery-bond-attestation-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-sponsor-key-recovery-bond-summary-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-deterministic-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_312_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_016_000;
pub const DEVNET_EPOCH: u64 = 12_444;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_SPONSOR_CREDIT_ASSET_ID: &str = "pq-recovery-sponsor-credit-devnet";
pub const DEFAULT_ESCROW_COLLATERAL_ASSET_ID: &str = "sponsor-key-recovery-bond-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_ESCROW_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_ROTATION_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_REPLAY_RETENTION_BLOCKS: u64 = 17_280;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_MAX_PAYMASTER_FEE_BPS: u64 = 10;
pub const DEFAULT_TARGET_SPONSORED_DISCOUNT_BPS: u64 = 40;
pub const DEFAULT_MIN_OPERATOR_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MAX_SPONSORED_GAS_PER_SESSION: u64 = 3_000_000;
pub const DEFAULT_MAX_SPONSORED_GAS_PER_PAYMASTER: u64 = 160_000_000;
pub const DEFAULT_MAX_ESCROWED_SESSIONS_PER_ACCOUNT: usize = 64;
pub const DEFAULT_LOW_FEE_CREDIT_BUCKETS: usize = 512;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_ENVELOPES: usize = 8_388_608;
pub const MAX_POLICIES: usize = 1_048_576;
pub const MAX_INTENTS: usize = 8_388_608;
pub const MAX_ROTATION_WINDOWS: usize = 2_097_152;
pub const MAX_NULLIFIERS: usize = 16_777_216;
pub const MAX_CREDIT_LEDGERS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 8_388_608;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;
pub const MAX_PUBLIC_EVENTS: usize = 16_777_216;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlKemParameterSet {
    MlKem512,
    MlKem768,
    MlKem1024,
    HybridX25519MlKem768,
    HybridX25519MlKem1024,
}
impl MlKemParameterSet {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem512 => "ml_kem_512",
            Self::MlKem768 => "ml_kem_768",
            Self::MlKem1024 => "ml_kem_1024",
            Self::HybridX25519MlKem768 => "hybrid_x25519_ml_kem_768",
            Self::HybridX25519MlKem1024 => "hybrid_x25519_ml_kem_1024",
        }
    }
    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlKem512 => 128,
            Self::MlKem768 | Self::HybridX25519MlKem768 => 192,
            Self::MlKem1024 | Self::HybridX25519MlKem1024 => 256,
        }
    }
    pub fn preferred_for_escrow(self) -> bool {
        matches!(self, Self::MlKem1024 | Self::HybridX25519MlKem1024)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowLane {
    WalletTransfer,
    PrivateContractCall,
    DefiIntent,
    BridgeExit,
    RecoverySession,
    GovernanceVote,
    ProofPublication,
    EmergencyEscape,
}
impl EscrowLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::PrivateContractCall => "private_contract_call",
            Self::DefiIntent => "defi_intent",
            Self::BridgeExit => "bridge_exit",
            Self::RecoverySession => "recovery_session",
            Self::GovernanceVote => "governance_vote",
            Self::ProofPublication => "proof_publication",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
    pub fn gas_weight(self) -> u64 {
        match self {
            Self::WalletTransfer => 2,
            Self::PrivateContractCall => 5,
            Self::DefiIntent => 8,
            Self::BridgeExit => 9,
            Self::RecoverySession => 6,
            Self::GovernanceVote => 3,
            Self::ProofPublication => 4,
            Self::EmergencyEscape => 10,
        }
    }
    pub fn high_priority(self) -> bool {
        matches!(
            self,
            Self::DefiIntent | Self::BridgeExit | Self::RecoverySession | Self::EmergencyEscape
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Drafted,
    Sealed,
    Escrowed,
    PolicyLinked,
    IntentBound,
    RotationPending,
    Released,
    Revoked,
    Expired,
    Quarantined,
}
impl EnvelopeStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::Escrowed
                | Self::PolicyLinked
                | Self::IntentBound
                | Self::RotationPending
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterPolicyStatus {
    Registered,
    Active,
    Sponsoring,
    BudgetConstrained,
    RotationRequired,
    Paused,
    Retired,
    Slashed,
}
impl PaymasterPolicyStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Sponsoring | Self::BudgetConstrained | Self::RotationRequired
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    PolicyChecked,
    CreditReserved,
    NullifierLocked,
    Sponsored,
    Settled,
    Expired,
    Rejected,
    ReplayDetected,
}
impl IntentStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::PolicyChecked
                | Self::CreditReserved
                | Self::NullifierLocked
                | Self::Sponsored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Scheduled,
    AcceptingEnvelopes,
    Attesting,
    Activated,
    Grace,
    Retired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Open,
    Reserved,
    Debited,
    Refilled,
    Frozen,
    Exhausted,
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    MlKemCiphertextWellFormed,
    SessionScopeProof,
    PaymasterBudgetProof,
    NullifierUniquenessProof,
    RotationFreshnessProof,
    LowFeeSettlementProof,
    OperatorQuorumProof,
}
impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKemCiphertextWellFormed => "ml_kem_ciphertext_well_formed",
            Self::SessionScopeProof => "session_scope_proof",
            Self::PaymasterBudgetProof => "paymaster_budget_proof",
            Self::NullifierUniquenessProof => "nullifier_uniqueness_proof",
            Self::RotationFreshnessProof => "rotation_freshness_proof",
            Self::LowFeeSettlementProof => "low_fee_settlement_proof",
            Self::OperatorQuorumProof => "operator_quorum_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Pending,
    Accepted,
    AcceptedWithRedactions,
    NeedsRotation,
    Rejected,
    Quarantined,
}
impl AttestationVerdict {
    pub fn accepted(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::AcceptedWithRedactions | Self::NeedsRotation
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorSummaryStatus {
    Drafted,
    Published,
    QuorumMet,
    SettlementReady,
    Disputed,
    Superseded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub fee_asset_id: String,
    pub sponsor_credit_asset_id: String,
    pub escrow_collateral_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub escrow_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub rotation_window_blocks: u64,
    pub replay_retention_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub max_paymaster_fee_bps: u64,
    pub target_sponsored_discount_bps: u64,
    pub min_operator_quorum_bps: u64,
    pub max_sponsored_gas_per_session: u64,
    pub max_sponsored_gas_per_paymaster: u64,
    pub max_escrowed_sessions_per_account: usize,
    pub low_fee_credit_buckets: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            sponsor_credit_asset_id: DEFAULT_SPONSOR_CREDIT_ASSET_ID.to_string(),
            escrow_collateral_asset_id: DEFAULT_ESCROW_COLLATERAL_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size: DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            escrow_ttl_blocks: DEFAULT_ESCROW_TTL_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            rotation_window_blocks: DEFAULT_ROTATION_WINDOW_BLOCKS,
            replay_retention_blocks: DEFAULT_REPLAY_RETENTION_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            max_paymaster_fee_bps: DEFAULT_MAX_PAYMASTER_FEE_BPS,
            target_sponsored_discount_bps: DEFAULT_TARGET_SPONSORED_DISCOUNT_BPS,
            min_operator_quorum_bps: DEFAULT_MIN_OPERATOR_QUORUM_BPS,
            max_sponsored_gas_per_session: DEFAULT_MAX_SPONSORED_GAS_PER_SESSION,
            max_sponsored_gas_per_paymaster: DEFAULT_MAX_SPONSORED_GAS_PER_PAYMASTER,
            max_escrowed_sessions_per_account: DEFAULT_MAX_ESCROWED_SESSIONS_PER_ACCOUNT,
            low_fee_credit_buckets: DEFAULT_LOW_FEE_CREDIT_BUCKETS,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": self.chain_id, "l2_network": self.l2_network, "monero_network": self.monero_network, "l2_height": self.l2_height, "monero_height": self.monero_height, "epoch": self.epoch, "fee_asset_id": self.fee_asset_id, "sponsor_credit_asset_id": self.sponsor_credit_asset_id, "escrow_collateral_asset_id": self.escrow_collateral_asset_id, "min_pq_security_bits": self.min_pq_security_bits, "min_privacy_set_size": self.min_privacy_set_size, "min_batch_privacy_set_size": self.min_batch_privacy_set_size, "escrow_ttl_blocks": self.escrow_ttl_blocks, "intent_ttl_blocks": self.intent_ttl_blocks, "rotation_window_blocks": self.rotation_window_blocks, "replay_retention_blocks": self.replay_retention_blocks, "attestation_ttl_blocks": self.attestation_ttl_blocks, "max_paymaster_fee_bps": self.max_paymaster_fee_bps, "target_sponsored_discount_bps": self.target_sponsored_discount_bps, "min_operator_quorum_bps": self.min_operator_quorum_bps, "max_sponsored_gas_per_session": self.max_sponsored_gas_per_session, "max_sponsored_gas_per_paymaster": self.max_sponsored_gas_per_paymaster, "max_escrowed_sessions_per_account": self.max_escrowed_sessions_per_account, "low_fee_credit_buckets": self.low_fee_credit_buckets })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub envelopes_opened: u64,
    pub envelopes_escrowed: u64,
    pub envelopes_released: u64,
    pub policies_registered: u64,
    pub policies_activated: u64,
    pub intents_submitted: u64,
    pub intents_sponsored: u64,
    pub intents_settled: u64,
    pub rotation_windows_opened: u64,
    pub rotation_windows_activated: u64,
    pub nullifiers_reserved: u64,
    pub nullifiers_consumed: u64,
    pub replay_attempts_blocked: u64,
    pub ledgers_opened: u64,
    pub credits_reserved: u64,
    pub credits_debited: u64,
    pub attestations_submitted: u64,
    pub attestations_accepted: u64,
    pub operator_summaries_published: u64,
    pub sponsored_gas_units: u64,
    pub sponsor_fee_piconero: u64,
    pub public_events_emitted: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({ "envelopes_opened": self.envelopes_opened, "envelopes_escrowed": self.envelopes_escrowed, "envelopes_released": self.envelopes_released, "policies_registered": self.policies_registered, "policies_activated": self.policies_activated, "intents_submitted": self.intents_submitted, "intents_sponsored": self.intents_sponsored, "intents_settled": self.intents_settled, "rotation_windows_opened": self.rotation_windows_opened, "rotation_windows_activated": self.rotation_windows_activated, "nullifiers_reserved": self.nullifiers_reserved, "nullifiers_consumed": self.nullifiers_consumed, "replay_attempts_blocked": self.replay_attempts_blocked, "ledgers_opened": self.ledgers_opened, "credits_reserved": self.credits_reserved, "credits_debited": self.credits_debited, "attestations_submitted": self.attestations_submitted, "attestations_accepted": self.attestations_accepted, "operator_summaries_published": self.operator_summaries_published, "sponsored_gas_units": self.sponsored_gas_units, "sponsor_fee_piconero": self.sponsor_fee_piconero, "public_events_emitted": self.public_events_emitted })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub ml_kem_envelopes_root: String,
    pub paymaster_policies_root: String,
    pub private_sponsored_intents_root: String,
    pub key_rotation_windows_root: String,
    pub nullifier_replay_guards_root: String,
    pub low_fee_credit_ledgers_root: String,
    pub pq_attestations_root: String,
    pub operator_summaries_root: String,
    pub account_index_root: String,
    pub paymaster_index_root: String,
    pub lane_index_root: String,
    pub active_nullifier_root: String,
    pub deterministic_public_events_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({ "ml_kem_envelopes_root": self.ml_kem_envelopes_root, "paymaster_policies_root": self.paymaster_policies_root, "private_sponsored_intents_root": self.private_sponsored_intents_root, "key_rotation_windows_root": self.key_rotation_windows_root, "nullifier_replay_guards_root": self.nullifier_replay_guards_root, "low_fee_credit_ledgers_root": self.low_fee_credit_ledgers_root, "pq_attestations_root": self.pq_attestations_root, "operator_summaries_root": self.operator_summaries_root, "account_index_root": self.account_index_root, "paymaster_index_root": self.paymaster_index_root, "lane_index_root": self.lane_index_root, "active_nullifier_root": self.active_nullifier_root, "deterministic_public_events_root": self.deterministic_public_events_root })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MlKemSessionEnvelope {
    pub envelope_id: String,
    pub account_commitment: String,
    pub session_key_commitment: String,
    pub paymaster_id: String,
    pub policy_id: String,
    pub lane: EscrowLane,
    pub parameter_set: MlKemParameterSet,
    pub ciphertext_commitment: String,
    pub encapsulated_secret_commitment: String,
    pub delegate_scope_root: String,
    pub view_tag: String,
    pub encrypted_metadata_root: String,
    pub nullifier_seed_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub rotation_window_id: Option<String>,
    pub status: EnvelopeStatus,
    pub privacy_set_size: u64,
    pub max_sponsored_gas: u64,
}
impl MlKemSessionEnvelope {
    pub fn public_record(&self) -> Value {
        json!({ "envelope_id": self.envelope_id, "account_commitment": self.account_commitment, "session_key_commitment": self.session_key_commitment, "paymaster_id": self.paymaster_id, "policy_id": self.policy_id, "lane": self.lane, "parameter_set": self.parameter_set, "ciphertext_commitment": self.ciphertext_commitment, "encapsulated_secret_commitment": self.encapsulated_secret_commitment, "delegate_scope_root": self.delegate_scope_root, "view_tag": self.view_tag, "encrypted_metadata_root": self.encrypted_metadata_root, "nullifier_seed_commitment": self.nullifier_seed_commitment, "created_at_height": self.created_at_height, "expires_at_height": self.expires_at_height, "rotation_window_id": self.rotation_window_id, "status": self.status, "privacy_set_size": self.privacy_set_size, "max_sponsored_gas": self.max_sponsored_gas })
    }
    pub fn expired(&self, height: u64) -> bool {
        height > self.expires_at_height || matches!(self.status, EnvelopeStatus::Expired)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaymasterEscrowPolicy {
    pub policy_id: String,
    pub paymaster_id: String,
    pub operator_commitment: String,
    pub accepted_lanes: BTreeSet<EscrowLane>,
    pub allowed_contract_root: String,
    pub selector_allowlist_root: String,
    pub session_scope_root: String,
    pub max_fee_bps: u64,
    pub target_discount_bps: u64,
    pub per_session_gas_limit: u64,
    pub per_epoch_gas_limit: u64,
    pub escrow_bond_piconero: u64,
    pub credit_ledger_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub status: PaymasterPolicyStatus,
}
impl PaymasterEscrowPolicy {
    pub fn public_record(&self) -> Value {
        json!({ "policy_id": self.policy_id, "paymaster_id": self.paymaster_id, "operator_commitment": self.operator_commitment, "accepted_lanes": self.accepted_lanes, "allowed_contract_root": self.allowed_contract_root, "selector_allowlist_root": self.selector_allowlist_root, "session_scope_root": self.session_scope_root, "max_fee_bps": self.max_fee_bps, "target_discount_bps": self.target_discount_bps, "per_session_gas_limit": self.per_session_gas_limit, "per_epoch_gas_limit": self.per_epoch_gas_limit, "escrow_bond_piconero": self.escrow_bond_piconero, "credit_ledger_id": self.credit_ledger_id, "min_pq_security_bits": self.min_pq_security_bits, "min_privacy_set_size": self.min_privacy_set_size, "valid_from_height": self.valid_from_height, "valid_until_height": self.valid_until_height, "status": self.status })
    }
    pub fn accepts(&self, lane: EscrowLane, height: u64) -> bool {
        self.status.usable()
            && self.accepted_lanes.contains(&lane)
            && height >= self.valid_from_height
            && height <= self.valid_until_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSponsoredIntent {
    pub intent_id: String,
    pub envelope_id: String,
    pub account_commitment: String,
    pub paymaster_id: String,
    pub lane: EscrowLane,
    pub sealed_call_root: String,
    pub encrypted_calldata_root: String,
    pub spend_limit_commitment: String,
    pub fee_quote_commitment: String,
    pub nullifier: String,
    pub requested_gas_units: u64,
    pub max_user_fee_piconero: u64,
    pub sponsor_credit_reserved: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: IntentStatus,
}
impl PrivateSponsoredIntent {
    pub fn public_record(&self) -> Value {
        json!({ "intent_id": self.intent_id, "envelope_id": self.envelope_id, "account_commitment": self.account_commitment, "paymaster_id": self.paymaster_id, "lane": self.lane, "sealed_call_root": self.sealed_call_root, "encrypted_calldata_root": self.encrypted_calldata_root, "spend_limit_commitment": self.spend_limit_commitment, "fee_quote_commitment": self.fee_quote_commitment, "nullifier": self.nullifier, "requested_gas_units": self.requested_gas_units, "max_user_fee_piconero": self.max_user_fee_piconero, "sponsor_credit_reserved": self.sponsor_credit_reserved, "created_at_height": self.created_at_height, "expires_at_height": self.expires_at_height, "status": self.status })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRotationWindow {
    pub window_id: String,
    pub paymaster_id: String,
    pub old_session_root: String,
    pub new_session_root: String,
    pub activation_height: u64,
    pub grace_end_height: u64,
    pub min_attestation_quorum_bps: u64,
    pub affected_envelope_count: u64,
    pub status: RotationStatus,
}
impl KeyRotationWindow {
    pub fn public_record(&self) -> Value {
        json!({ "window_id": self.window_id, "paymaster_id": self.paymaster_id, "old_session_root": self.old_session_root, "new_session_root": self.new_session_root, "activation_height": self.activation_height, "grace_end_height": self.grace_end_height, "min_attestation_quorum_bps": self.min_attestation_quorum_bps, "affected_envelope_count": self.affected_envelope_count, "status": self.status })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierReplayGuard {
    pub nullifier: String,
    pub intent_id: String,
    pub account_commitment: String,
    pub paymaster_id: String,
    pub lane: EscrowLane,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub status: NullifierStatus,
}
impl NullifierReplayGuard {
    pub fn public_record(&self) -> Value {
        json!({ "nullifier": self.nullifier, "intent_id": self.intent_id, "account_commitment": self.account_commitment, "paymaster_id": self.paymaster_id, "lane": self.lane, "first_seen_height": self.first_seen_height, "expires_at_height": self.expires_at_height, "status": self.status })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCreditLedger {
    pub ledger_id: String,
    pub paymaster_id: String,
    pub asset_id: String,
    pub epoch: u64,
    pub opening_credit_piconero: u64,
    pub available_credit_piconero: u64,
    pub reserved_credit_piconero: u64,
    pub debited_credit_piconero: u64,
    pub sponsored_gas_units: u64,
    pub bucket_count: usize,
    pub status: CreditStatus,
}
impl LowFeeCreditLedger {
    pub fn public_record(&self) -> Value {
        json!({ "ledger_id": self.ledger_id, "paymaster_id": self.paymaster_id, "asset_id": self.asset_id, "epoch": self.epoch, "opening_credit_piconero": self.opening_credit_piconero, "available_credit_piconero": self.available_credit_piconero, "reserved_credit_piconero": self.reserved_credit_piconero, "debited_credit_piconero": self.debited_credit_piconero, "sponsored_gas_units": self.sponsored_gas_units, "bucket_count": self.bucket_count, "status": self.status })
    }
    pub fn reserve(&mut self, amount: u64) -> Result<()> {
        ensure!(
            matches!(
                self.status,
                CreditStatus::Open | CreditStatus::Reserved | CreditStatus::Refilled
            ),
            "ledger {} is not reservable",
            self.ledger_id
        );
        ensure!(
            self.available_credit_piconero >= amount,
            "ledger {} insufficient credit",
            self.ledger_id
        );
        self.available_credit_piconero = self.available_credit_piconero.saturating_sub(amount);
        self.reserved_credit_piconero = self.reserved_credit_piconero.saturating_add(amount);
        self.status = CreditStatus::Reserved;
        Ok(())
    }
    pub fn debit_reserved(&mut self, amount: u64, gas_units: u64) -> Result<()> {
        ensure!(
            self.reserved_credit_piconero >= amount,
            "ledger {} insufficient reserved credit",
            self.ledger_id
        );
        self.reserved_credit_piconero = self.reserved_credit_piconero.saturating_sub(amount);
        self.debited_credit_piconero = self.debited_credit_piconero.saturating_add(amount);
        self.sponsored_gas_units = self.sponsored_gas_units.saturating_add(gas_units);
        self.status = if self.available_credit_piconero == 0 && self.reserved_credit_piconero == 0 {
            CreditStatus::Exhausted
        } else {
            CreditStatus::Debited
        };
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub paymaster_id: String,
    pub operator_commitment: String,
    pub kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub pq_signature_commitment: String,
    pub proof_root: String,
    pub security_bits: u16,
    pub privacy_set_size: u64,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}
impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({ "attestation_id": self.attestation_id, "subject_id": self.subject_id, "paymaster_id": self.paymaster_id, "operator_commitment": self.operator_commitment, "kind": self.kind, "verdict": self.verdict, "pq_signature_commitment": self.pq_signature_commitment, "proof_root": self.proof_root, "security_bits": self.security_bits, "privacy_set_size": self.privacy_set_size, "attested_at_height": self.attested_at_height, "expires_at_height": self.expires_at_height })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub paymaster_id: String,
    pub epoch: u64,
    pub envelopes_escrowed: u64,
    pub intents_sponsored: u64,
    pub sponsored_gas_units: u64,
    pub credits_spent_piconero: u64,
    pub accepted_attestations: u64,
    pub replay_attempts_blocked: u64,
    pub summary_root: String,
    pub status: OperatorSummaryStatus,
}
impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({ "summary_id": self.summary_id, "operator_commitment": self.operator_commitment, "paymaster_id": self.paymaster_id, "epoch": self.epoch, "envelopes_escrowed": self.envelopes_escrowed, "intents_sponsored": self.intents_sponsored, "sponsored_gas_units": self.sponsored_gas_units, "credits_spent_piconero": self.credits_spent_piconero, "accepted_attestations": self.accepted_attestations, "replay_attempts_blocked": self.replay_attempts_blocked, "summary_root": self.summary_root, "status": self.status })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEvidenceKind {
    WalletLostKey,
    GuardianQuorum,
    SocialRecovery,
    PaymasterSponsoredRecovery,
    OperatorBreakGlass,
    CourtAttestedRecovery,
}
impl RecoveryEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletLostKey => "wallet_lost_key",
            Self::GuardianQuorum => "guardian_quorum",
            Self::SocialRecovery => "social_recovery",
            Self::PaymasterSponsoredRecovery => "paymaster_sponsored_recovery",
            Self::OperatorBreakGlass => "operator_break_glass",
            Self::CourtAttestedRecovery => "court_attested_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondAuctionStatus {
    Commit,
    Reveal,
    Clearing,
    Settled,
    Refunded,
    Challenged,
    Cancelled,
}
impl BondAuctionStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Commit | Self::Reveal | Self::Clearing)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscrowCommittee {
    pub committee_id: String,
    pub threshold_bps: u64,
    pub member_commitment_root: String,
    pub encrypted_share_root: String,
    pub ml_kem_parameter_set: MlKemParameterSet,
    pub min_pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}
impl EscrowCommittee {
    pub fn public_record(&self) -> Value {
        json!({ "committee_id": self.committee_id, "threshold_bps": self.threshold_bps, "member_commitment_root": self.member_commitment_root, "encrypted_share_root": self.encrypted_share_root, "ml_kem_parameter_set": self.ml_kem_parameter_set, "min_pq_security_bits": self.min_pq_security_bits, "privacy_set_size": self.privacy_set_size, "valid_from_height": self.valid_from_height, "valid_until_height": self.valid_until_height })
    }

    pub fn can_recover(&self, height: u64, quorum_bps: u64) -> bool {
        height >= self.valid_from_height
            && height <= self.valid_until_height
            && quorum_bps >= self.threshold_bps
            && self.ml_kem_parameter_set.pq_security_bits() >= self.min_pq_security_bits
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateRecoveryEvidence {
    pub evidence_id: String,
    pub envelope_id: String,
    pub committee_id: String,
    pub kind: RecoveryEvidenceKind,
    pub sealed_claim_root: String,
    pub guardian_approval_root: String,
    pub recovery_nullifier: String,
    pub zk_validity_proof_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}
impl PrivateRecoveryEvidence {
    pub fn public_record(&self) -> Value {
        json!({ "evidence_id": self.evidence_id, "envelope_id": self.envelope_id, "committee_id": self.committee_id, "kind": self.kind, "sealed_claim_root": self.sealed_claim_root, "guardian_approval_root": self.guardian_approval_root, "recovery_nullifier": self.recovery_nullifier, "zk_validity_proof_root": self.zk_validity_proof_root, "created_at_height": self.created_at_height, "expires_at_height": self.expires_at_height })
    }

    pub fn expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorRecoveryBond {
    pub bond_id: String,
    pub sponsor_id: String,
    pub paymaster_id: String,
    pub committee_id: String,
    pub recovery_envelope_id: String,
    pub notional_piconero: u64,
    pub reserved_fee_credit_piconero: u64,
    pub max_user_fee_bps: u64,
    pub slashable_bps: u64,
    pub low_fee_refund_bps: u64,
    pub opened_at_height: u64,
    pub unlock_height: u64,
    pub status: BondAuctionStatus,
}
impl SponsorRecoveryBond {
    pub fn public_record(&self) -> Value {
        json!({ "bond_id": self.bond_id, "sponsor_id": self.sponsor_id, "paymaster_id": self.paymaster_id, "committee_id": self.committee_id, "recovery_envelope_id": self.recovery_envelope_id, "notional_piconero": self.notional_piconero, "reserved_fee_credit_piconero": self.reserved_fee_credit_piconero, "max_user_fee_bps": self.max_user_fee_bps, "slashable_bps": self.slashable_bps, "low_fee_refund_bps": self.low_fee_refund_bps, "opened_at_height": self.opened_at_height, "unlock_height": self.unlock_height, "status": self.status })
    }

    pub fn refund_amount(&self) -> u64 {
        self.reserved_fee_credit_piconero
            .saturating_mul(self.low_fee_refund_bps)
            / MAX_BPS
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BondAuction {
    pub auction_id: String,
    pub bond_id: String,
    pub sealed_bid_root: String,
    pub clearing_price_piconero: u64,
    pub sponsor_discount_bps: u64,
    pub opened_at_height: u64,
    pub reveal_height: u64,
    pub settle_height: u64,
    pub status: BondAuctionStatus,
}
impl BondAuction {
    pub fn public_record(&self) -> Value {
        json!({ "auction_id": self.auction_id, "bond_id": self.bond_id, "sealed_bid_root": self.sealed_bid_root, "clearing_price_piconero": self.clearing_price_piconero, "sponsor_discount_bps": self.sponsor_discount_bps, "opened_at_height": self.opened_at_height, "reveal_height": self.reveal_height, "settle_height": self.settle_height, "status": self.status })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditRefund {
    pub refund_id: String,
    pub bond_id: String,
    pub recipient_commitment: String,
    pub refund_amount_piconero: u64,
    pub refund_nullifier: String,
    pub proof_root: String,
    pub settled_at_height: u64,
}
impl FeeCreditRefund {
    pub fn public_record(&self) -> Value {
        json!({ "refund_id": self.refund_id, "bond_id": self.bond_id, "recipient_commitment": self.recipient_commitment, "refund_amount_piconero": self.refund_amount_piconero, "refund_nullifier": self.refund_nullifier, "proof_root": self.proof_root, "settled_at_height": self.settled_at_height })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub ml_kem_envelopes: BTreeMap<String, MlKemSessionEnvelope>,
    pub paymaster_policies: BTreeMap<String, PaymasterEscrowPolicy>,
    pub private_sponsored_intents: BTreeMap<String, PrivateSponsoredIntent>,
    pub key_rotation_windows: BTreeMap<String, KeyRotationWindow>,
    pub nullifier_replay_guards: BTreeMap<String, NullifierReplayGuard>,
    pub low_fee_credit_ledgers: BTreeMap<String, LowFeeCreditLedger>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub envelopes_by_account: BTreeMap<String, BTreeSet<String>>,
    pub envelopes_by_paymaster: BTreeMap<String, BTreeSet<String>>,
    pub intents_by_paymaster: BTreeMap<String, BTreeSet<String>>,
    pub policies_by_lane: BTreeMap<EscrowLane, BTreeSet<String>>,
    pub active_nullifiers: BTreeSet<String>,
    pub deterministic_public_events: Vec<Value>,
}
impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            ml_kem_envelopes: BTreeMap::new(),
            paymaster_policies: BTreeMap::new(),
            private_sponsored_intents: BTreeMap::new(),
            key_rotation_windows: BTreeMap::new(),
            nullifier_replay_guards: BTreeMap::new(),
            low_fee_credit_ledgers: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            envelopes_by_account: BTreeMap::new(),
            envelopes_by_paymaster: BTreeMap::new(),
            intents_by_paymaster: BTreeMap::new(),
            policies_by_lane: BTreeMap::new(),
            active_nullifiers: BTreeSet::new(),
            deterministic_public_events: Vec::new(),
        };
        state.recompute_roots();
        state
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        seed_devnet(&mut state);
        state
    }
    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let intent_id =
            private_intent_id("env:demo:swap", "acct:demo:swap", "pm:demo:universal", 2);
        let _ = state.submit_private_intent(PrivateSponsoredIntent {
            intent_id: intent_id.clone(),
            envelope_id: "env:demo:swap".to_string(),
            account_commitment: "acct:demo:swap".to_string(),
            paymaster_id: "pm:demo:universal".to_string(),
            lane: EscrowLane::DefiIntent,
            sealed_call_root: root_for("demo-second-sealed-call"),
            encrypted_calldata_root: root_for("demo-second-calldata"),
            spend_limit_commitment: root_for("spend-limit-25-xmr-notional"),
            fee_quote_commitment: root_for("low-fee-quote-2"),
            nullifier: nullifier_id("env:demo:swap", 2),
            requested_gas_units: 710_000,
            max_user_fee_piconero: 7_100,
            sponsor_credit_reserved: 35_500,
            created_at_height: state.config.l2_height + 3,
            expires_at_height: state.config.l2_height + state.config.intent_ttl_blocks + 3,
            status: IntentStatus::Sealed,
        });
        let _ = state.reserve_intent_credit(&intent_id);
        let _ = state.sponsor_intent(&intent_id);
        state
    }
    pub fn register_paymaster_policy(&mut self, mut policy: PaymasterEscrowPolicy) -> Result<()> {
        ensure!(
            self.paymaster_policies.len() < MAX_POLICIES,
            "policy capacity exceeded"
        );
        ensure!(
            !self.paymaster_policies.contains_key(&policy.policy_id),
            "duplicate policy {}",
            policy.policy_id
        );
        ensure!(
            policy.max_fee_bps <= self.config.max_paymaster_fee_bps,
            "policy fee bps exceeds cap"
        );
        ensure!(
            policy.min_pq_security_bits >= self.config.min_pq_security_bits,
            "policy pq security below runtime floor"
        );
        ensure!(
            policy.min_privacy_set_size >= self.config.min_privacy_set_size,
            "policy privacy set below runtime floor"
        );
        if matches!(policy.status, PaymasterPolicyStatus::Registered) {
            policy.status = PaymasterPolicyStatus::Active;
        }
        for lane in &policy.accepted_lanes {
            self.policies_by_lane
                .entry(*lane)
                .or_default()
                .insert(policy.policy_id.clone());
        }
        self.counters.policies_registered = self.counters.policies_registered.saturating_add(1);
        if policy.status.usable() {
            self.counters.policies_activated = self.counters.policies_activated.saturating_add(1);
        }
        let id = policy.policy_id.clone();
        self.paymaster_policies.insert(id.clone(), policy);
        self.emit_event("paymaster_policy_registered", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn open_credit_ledger(&mut self, ledger: LowFeeCreditLedger) -> Result<()> {
        ensure!(
            self.low_fee_credit_ledgers.len() < MAX_CREDIT_LEDGERS,
            "ledger capacity exceeded"
        );
        ensure!(
            !self.low_fee_credit_ledgers.contains_key(&ledger.ledger_id),
            "duplicate ledger {}",
            ledger.ledger_id
        );
        ensure!(
            ledger.bucket_count >= 1,
            "ledger {} must have buckets",
            ledger.ledger_id
        );
        self.counters.ledgers_opened = self.counters.ledgers_opened.saturating_add(1);
        let id = ledger.ledger_id.clone();
        self.low_fee_credit_ledgers.insert(id.clone(), ledger);
        self.emit_event("low_fee_credit_ledger_opened", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn escrow_envelope(&mut self, mut envelope: MlKemSessionEnvelope) -> Result<()> {
        ensure!(
            self.ml_kem_envelopes.len() < MAX_ENVELOPES,
            "envelope capacity exceeded"
        );
        ensure!(
            !self.ml_kem_envelopes.contains_key(&envelope.envelope_id),
            "duplicate envelope {}",
            envelope.envelope_id
        );
        ensure!(
            envelope.parameter_set.pq_security_bits() >= self.config.min_pq_security_bits,
            "envelope {} pq security below floor",
            envelope.envelope_id
        );
        ensure!(
            envelope.privacy_set_size >= self.config.min_privacy_set_size,
            "envelope {} privacy set below floor",
            envelope.envelope_id
        );
        ensure!(
            envelope.max_sponsored_gas <= self.config.max_sponsored_gas_per_session,
            "envelope {} gas limit exceeds runtime cap",
            envelope.envelope_id
        );
        let policy = self
            .paymaster_policies
            .get(&envelope.policy_id)
            .ok_or_else(|| format!("missing policy {}", envelope.policy_id))?;
        ensure!(
            policy.paymaster_id == envelope.paymaster_id,
            "policy paymaster mismatch for envelope {}",
            envelope.envelope_id
        );
        ensure!(
            policy.accepts(envelope.lane, envelope.created_at_height),
            "policy {} does not accept envelope lane",
            policy.policy_id
        );
        let account_count = self
            .envelopes_by_account
            .get(&envelope.account_commitment)
            .map(BTreeSet::len)
            .unwrap_or_default();
        ensure!(
            account_count < self.config.max_escrowed_sessions_per_account,
            "account {} has too many escrowed sessions",
            envelope.account_commitment
        );
        if matches!(
            envelope.status,
            EnvelopeStatus::Drafted | EnvelopeStatus::Sealed
        ) {
            envelope.status = EnvelopeStatus::Escrowed;
        }
        let id = envelope.envelope_id.clone();
        self.envelopes_by_account
            .entry(envelope.account_commitment.clone())
            .or_default()
            .insert(id.clone());
        self.envelopes_by_paymaster
            .entry(envelope.paymaster_id.clone())
            .or_default()
            .insert(id.clone());
        self.ml_kem_envelopes.insert(id.clone(), envelope);
        self.counters.envelopes_opened = self.counters.envelopes_opened.saturating_add(1);
        self.counters.envelopes_escrowed = self.counters.envelopes_escrowed.saturating_add(1);
        self.emit_event("ml_kem_session_envelope_escrowed", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn submit_private_intent(&mut self, intent: PrivateSponsoredIntent) -> Result<()> {
        ensure!(
            self.private_sponsored_intents.len() < MAX_INTENTS,
            "intent capacity exceeded"
        );
        ensure!(
            !self
                .private_sponsored_intents
                .contains_key(&intent.intent_id),
            "duplicate intent {}",
            intent.intent_id
        );
        if self.active_nullifiers.contains(&intent.nullifier) {
            self.counters.replay_attempts_blocked =
                self.counters.replay_attempts_blocked.saturating_add(1);
            return Err(format!("nullifier {} is already active", intent.nullifier));
        }
        let envelope = self
            .ml_kem_envelopes
            .get(&intent.envelope_id)
            .ok_or_else(|| format!("missing envelope {}", intent.envelope_id))?;
        ensure!(
            envelope.status.live(),
            "envelope {} is not live",
            envelope.envelope_id
        );
        ensure!(
            !envelope.expired(intent.created_at_height),
            "envelope {} expired",
            envelope.envelope_id
        );
        ensure!(
            envelope.account_commitment == intent.account_commitment,
            "intent account mismatch"
        );
        ensure!(
            envelope.paymaster_id == intent.paymaster_id,
            "intent paymaster mismatch"
        );
        ensure!(envelope.lane == intent.lane, "intent lane mismatch");
        ensure!(
            intent.requested_gas_units <= envelope.max_sponsored_gas,
            "intent gas exceeds envelope cap"
        );
        self.active_nullifiers.insert(intent.nullifier.clone());
        self.nullifier_replay_guards.insert(
            intent.nullifier.clone(),
            NullifierReplayGuard {
                nullifier: intent.nullifier.clone(),
                intent_id: intent.intent_id.clone(),
                account_commitment: intent.account_commitment.clone(),
                paymaster_id: intent.paymaster_id.clone(),
                lane: intent.lane,
                first_seen_height: intent.created_at_height,
                expires_at_height: intent.created_at_height + self.config.replay_retention_blocks,
                status: NullifierStatus::Reserved,
            },
        );
        self.intents_by_paymaster
            .entry(intent.paymaster_id.clone())
            .or_default()
            .insert(intent.intent_id.clone());
        self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
        self.counters.nullifiers_reserved = self.counters.nullifiers_reserved.saturating_add(1);
        let id = intent.intent_id.clone();
        self.private_sponsored_intents.insert(id.clone(), intent);
        self.emit_event("private_sponsored_intent_submitted", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn reserve_intent_credit(&mut self, intent_id: &str) -> Result<()> {
        let (paymaster_id, amount) = {
            let intent = self
                .private_sponsored_intents
                .get(intent_id)
                .ok_or_else(|| format!("missing intent {intent_id}"))?;
            ensure!(intent.status.live(), "intent {intent_id} is not live");
            (intent.paymaster_id.clone(), intent.sponsor_credit_reserved)
        };
        let ledger_id = self
            .policy_for_paymaster(&paymaster_id)?
            .credit_ledger_id
            .clone();
        let ledger = self
            .low_fee_credit_ledgers
            .get_mut(&ledger_id)
            .ok_or_else(|| format!("missing ledger {ledger_id}"))?;
        ledger.reserve(amount)?;
        if let Some(intent) = self.private_sponsored_intents.get_mut(intent_id) {
            intent.status = IntentStatus::CreditReserved;
        }
        self.counters.credits_reserved = self.counters.credits_reserved.saturating_add(amount);
        self.emit_event("sponsor_credit_reserved", intent_id);
        self.recompute_roots();
        Ok(())
    }
    pub fn sponsor_intent(&mut self, intent_id: &str) -> Result<()> {
        let (paymaster_id, amount, gas_units, nullifier) = {
            let intent = self
                .private_sponsored_intents
                .get(intent_id)
                .ok_or_else(|| format!("missing intent {intent_id}"))?;
            ensure!(
                matches!(
                    intent.status,
                    IntentStatus::CreditReserved | IntentStatus::NullifierLocked
                ),
                "intent {intent_id} credit not reserved"
            );
            (
                intent.paymaster_id.clone(),
                intent.sponsor_credit_reserved,
                intent.requested_gas_units,
                intent.nullifier.clone(),
            )
        };
        let ledger_id = self
            .policy_for_paymaster(&paymaster_id)?
            .credit_ledger_id
            .clone();
        let ledger = self
            .low_fee_credit_ledgers
            .get_mut(&ledger_id)
            .ok_or_else(|| format!("missing ledger {ledger_id}"))?;
        ledger.debit_reserved(amount, gas_units)?;
        if let Some(intent) = self.private_sponsored_intents.get_mut(intent_id) {
            intent.status = IntentStatus::Sponsored;
        }
        if let Some(guard) = self.nullifier_replay_guards.get_mut(&nullifier) {
            guard.status = NullifierStatus::Consumed;
        }
        self.counters.intents_sponsored = self.counters.intents_sponsored.saturating_add(1);
        self.counters.nullifiers_consumed = self.counters.nullifiers_consumed.saturating_add(1);
        self.counters.credits_debited = self.counters.credits_debited.saturating_add(amount);
        self.counters.sponsored_gas_units =
            self.counters.sponsored_gas_units.saturating_add(gas_units);
        self.counters.sponsor_fee_piconero =
            self.counters.sponsor_fee_piconero.saturating_add(amount);
        self.emit_event("private_sponsored_intent_sponsored", intent_id);
        self.recompute_roots();
        Ok(())
    }
    pub fn settle_intent(&mut self, intent_id: &str) -> Result<()> {
        let intent = self
            .private_sponsored_intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("missing intent {intent_id}"))?;
        ensure!(
            matches!(intent.status, IntentStatus::Sponsored),
            "intent {intent_id} not sponsored"
        );
        intent.status = IntentStatus::Settled;
        self.counters.intents_settled = self.counters.intents_settled.saturating_add(1);
        self.emit_event("private_sponsored_intent_settled", intent_id);
        self.recompute_roots();
        Ok(())
    }
    pub fn schedule_rotation_window(&mut self, window: KeyRotationWindow) -> Result<()> {
        ensure!(
            self.key_rotation_windows.len() < MAX_ROTATION_WINDOWS,
            "rotation window capacity exceeded"
        );
        ensure!(
            !self.key_rotation_windows.contains_key(&window.window_id),
            "duplicate rotation window {}",
            window.window_id
        );
        ensure!(
            window.min_attestation_quorum_bps >= self.config.min_operator_quorum_bps,
            "rotation quorum below runtime floor"
        );
        let id = window.window_id.clone();
        self.key_rotation_windows.insert(id.clone(), window);
        self.counters.rotation_windows_opened =
            self.counters.rotation_windows_opened.saturating_add(1);
        self.emit_event("key_rotation_window_scheduled", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn activate_rotation_window(&mut self, window_id: &str) -> Result<()> {
        let window = self
            .key_rotation_windows
            .get_mut(window_id)
            .ok_or_else(|| format!("missing rotation window {window_id}"))?;
        ensure!(
            matches!(
                window.status,
                RotationStatus::Scheduled
                    | RotationStatus::Attesting
                    | RotationStatus::AcceptingEnvelopes
            ),
            "window {window_id} cannot activate"
        );
        window.status = RotationStatus::Activated;
        for envelope in self.ml_kem_envelopes.values_mut().filter(|envelope| {
            envelope.paymaster_id == window.paymaster_id && envelope.status.live()
        }) {
            envelope.status = EnvelopeStatus::RotationPending;
            envelope.rotation_window_id = Some(window_id.to_string());
        }
        self.counters.rotation_windows_activated =
            self.counters.rotation_windows_activated.saturating_add(1);
        self.emit_event("key_rotation_window_activated", window_id);
        self.recompute_roots();
        Ok(())
    }
    pub fn submit_pq_attestation(&mut self, attestation: PqAttestation) -> Result<()> {
        ensure!(
            self.pq_attestations.len() < MAX_ATTESTATIONS,
            "attestation capacity exceeded"
        );
        ensure!(
            !self
                .pq_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate attestation {}",
            attestation.attestation_id
        );
        ensure!(
            attestation.security_bits >= self.config.min_pq_security_bits,
            "attestation security below floor"
        );
        ensure!(
            attestation.privacy_set_size >= self.config.min_privacy_set_size,
            "attestation privacy set below floor"
        );
        if attestation.verdict.accepted() {
            self.counters.attestations_accepted =
                self.counters.attestations_accepted.saturating_add(1);
        }
        let id = attestation.attestation_id.clone();
        self.pq_attestations.insert(id.clone(), attestation);
        self.counters.attestations_submitted =
            self.counters.attestations_submitted.saturating_add(1);
        self.emit_event("pq_attestation_submitted", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn publish_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        ensure!(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity exceeded"
        );
        ensure!(
            !self.operator_summaries.contains_key(&summary.summary_id),
            "duplicate summary {}",
            summary.summary_id
        );
        let id = summary.summary_id.clone();
        self.operator_summaries.insert(id.clone(), summary);
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.emit_event("operator_summary_published", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn block_replay_attempt(&mut self, nullifier: &str) -> Result<()> {
        ensure!(
            self.active_nullifiers.contains(nullifier),
            "nullifier {nullifier} is not active"
        );
        if let Some(guard) = self.nullifier_replay_guards.get_mut(nullifier) {
            guard.status = NullifierStatus::Quarantined;
        }
        for intent in self
            .private_sponsored_intents
            .values_mut()
            .filter(|intent| intent.nullifier == nullifier)
        {
            intent.status = IntentStatus::ReplayDetected;
        }
        self.counters.replay_attempts_blocked =
            self.counters.replay_attempts_blocked.saturating_add(1);
        self.emit_event("replay_attempt_blocked", nullifier);
        self.recompute_roots();
        Ok(())
    }
    pub fn release_envelope(&mut self, envelope_id: &str) -> Result<()> {
        let envelope = self
            .ml_kem_envelopes
            .get_mut(envelope_id)
            .ok_or_else(|| format!("missing envelope {envelope_id}"))?;
        ensure!(envelope.status.live(), "envelope {envelope_id} is not live");
        envelope.status = EnvelopeStatus::Released;
        self.counters.envelopes_released = self.counters.envelopes_released.saturating_add(1);
        self.emit_event("ml_kem_session_envelope_released", envelope_id);
        self.recompute_roots();
        Ok(())
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({ "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "hash_suite": HASH_SUITE, "ML_KEM_RECOVERY_ENVELOPE_SUITE": ML_KEM_RECOVERY_ENVELOPE_SUITE, "SPONSOR_RECOVERY_BOND_POLICY_SUITE": SPONSOR_RECOVERY_BOND_POLICY_SUITE, "PRIVATE_RECOVERY_EVIDENCE_SUITE": PRIVATE_RECOVERY_EVIDENCE_SUITE, "KEY_ROTATION_WINDOW_SUITE": KEY_ROTATION_WINDOW_SUITE, "nullifier_guard_suite": NULLIFIER_GUARD_SUITE, "LOW_FEE_BOND_REFUND_LEDGER_SUITE": LOW_FEE_BOND_REFUND_LEDGER_SUITE, "pq_attestation_suite": PQ_ATTESTATION_SUITE, "operator_summary_suite": OPERATOR_SUMMARY_SUITE, "public_record_suite": PUBLIC_RECORD_SUITE, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.roots.public_record(), "ml_kem_envelopes": self.ml_kem_envelopes.values().map(MlKemSessionEnvelope::public_record).collect::<Vec<_>>(), "paymaster_policies": self.paymaster_policies.values().map(PaymasterEscrowPolicy::public_record).collect::<Vec<_>>(), "private_sponsored_intents": self.private_sponsored_intents.values().map(PrivateSponsoredIntent::public_record).collect::<Vec<_>>(), "key_rotation_windows": self.key_rotation_windows.values().map(KeyRotationWindow::public_record).collect::<Vec<_>>(), "nullifier_replay_guards": self.nullifier_replay_guards.values().map(NullifierReplayGuard::public_record).collect::<Vec<_>>(), "low_fee_credit_ledgers": self.low_fee_credit_ledgers.values().map(LowFeeCreditLedger::public_record).collect::<Vec<_>>(), "pq_attestations": self.pq_attestations.values().map(PqAttestation::public_record).collect::<Vec<_>>(), "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(), "deterministic_public_events": self.deterministic_public_events })
    }
    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
    fn policy_for_paymaster(&self, paymaster_id: &str) -> Result<&PaymasterEscrowPolicy> {
        self.paymaster_policies
            .values()
            .find(|policy| policy.paymaster_id == paymaster_id && policy.status.usable())
            .ok_or_else(|| format!("missing active policy for paymaster {paymaster_id}"))
    }
    fn recompute_roots(&mut self) {
        self.roots = Roots {
            ml_kem_envelopes_root: collection_root(
                "ML-KEM-ENVELOPES",
                self.ml_kem_envelopes
                    .values()
                    .map(MlKemSessionEnvelope::public_record)
                    .collect(),
            ),
            paymaster_policies_root: collection_root(
                "PAYMASTER-POLICIES",
                self.paymaster_policies
                    .values()
                    .map(PaymasterEscrowPolicy::public_record)
                    .collect(),
            ),
            private_sponsored_intents_root: collection_root(
                "PRIVATE-SPONSORED-INTENTS",
                self.private_sponsored_intents
                    .values()
                    .map(PrivateSponsoredIntent::public_record)
                    .collect(),
            ),
            key_rotation_windows_root: collection_root(
                "KEY-ROTATION-WINDOWS",
                self.key_rotation_windows
                    .values()
                    .map(KeyRotationWindow::public_record)
                    .collect(),
            ),
            nullifier_replay_guards_root: collection_root(
                "NULLIFIER-REPLAY-GUARDS",
                self.nullifier_replay_guards
                    .values()
                    .map(NullifierReplayGuard::public_record)
                    .collect(),
            ),
            low_fee_credit_ledgers_root: collection_root(
                "LOW-FEE-CREDIT-LEDGERS",
                self.low_fee_credit_ledgers
                    .values()
                    .map(LowFeeCreditLedger::public_record)
                    .collect(),
            ),
            pq_attestations_root: collection_root(
                "PQ-ATTESTATIONS",
                self.pq_attestations
                    .values()
                    .map(PqAttestation::public_record)
                    .collect(),
            ),
            operator_summaries_root: collection_root(
                "OPERATOR-SUMMARIES",
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record)
                    .collect(),
            ),
            account_index_root: index_root("ACCOUNT-INDEX", &self.envelopes_by_account),
            paymaster_index_root: index_root("PAYMASTER-INDEX", &self.envelopes_by_paymaster),
            lane_index_root: lane_index_root(&self.policies_by_lane),
            active_nullifier_root: merkle_root(
                &domain("ACTIVE-NULLIFIERS"),
                &self
                    .active_nullifiers
                    .iter()
                    .map(|value| json!(value))
                    .collect::<Vec<_>>(),
            ),
            deterministic_public_events_root: merkle_root(
                &domain("PUBLIC-EVENTS"),
                &self.deterministic_public_events,
            ),
        };
    }
    fn emit_event(&mut self, kind: &str, subject_id: &str) {
        if self.deterministic_public_events.len() >= MAX_PUBLIC_EVENTS {
            return;
        }
        let event_id = domain_hash(
            &domain("EVENT"),
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.counters.public_events_emitted),
            ],
            32,
        );
        self.deterministic_public_events.push(json!({ "event_id": event_id, "kind": kind, "subject_id": subject_id, "l2_height": self.config.l2_height, "epoch": self.config.epoch }));
        self.counters.public_events_emitted = self.counters.public_events_emitted.saturating_add(1);
    }
}

pub fn devnet() -> State {
    State::devnet()
}
pub fn demo() -> State {
    State::demo()
}
pub fn public_record(state: &State) -> Value {
    state.public_record()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}
pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn state_root_from_public_record(record: &Value) -> String {
    record
        .get("state_root")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| record_root("STATE-FROM-PUBLIC-RECORD", record))
}
pub fn paymaster_policy_id(paymaster_id: &str, operator_commitment: &str, nonce: u64) -> String {
    domain_hash(
        &domain("PAYMASTER-POLICY-ID"),
        &[
            HashPart::Str(paymaster_id),
            HashPart::Str(operator_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn ml_kem_envelope_id(
    account_commitment: &str,
    session_key_commitment: &str,
    paymaster_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        &domain("ML-KEM-ENVELOPE-ID"),
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(session_key_commitment),
            HashPart::Str(paymaster_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn private_intent_id(
    envelope_id: &str,
    account_commitment: &str,
    paymaster_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        &domain("PRIVATE-INTENT-ID"),
        &[
            HashPart::Str(envelope_id),
            HashPart::Str(account_commitment),
            HashPart::Str(paymaster_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn rotation_window_id(
    paymaster_id: &str,
    old_session_root: &str,
    new_session_root: &str,
    activation_height: u64,
) -> String {
    domain_hash(
        &domain("ROTATION-WINDOW-ID"),
        &[
            HashPart::Str(paymaster_id),
            HashPart::Str(old_session_root),
            HashPart::Str(new_session_root),
            HashPart::U64(activation_height),
        ],
        32,
    )
}
pub fn nullifier_id(envelope_id: &str, nonce: u64) -> String {
    domain_hash(
        &domain("NULLIFIER-ID"),
        &[HashPart::Str(envelope_id), HashPart::U64(nonce)],
        32,
    )
}
pub fn credit_ledger_id(paymaster_id: &str, epoch: u64) -> String {
    domain_hash(
        &domain("CREDIT-LEDGER-ID"),
        &[HashPart::Str(paymaster_id), HashPart::U64(epoch)],
        32,
    )
}
pub fn pq_attestation_id(
    subject_id: &str,
    operator_commitment: &str,
    kind: AttestationKind,
    nonce: u64,
) -> String {
    domain_hash(
        &domain("PQ-ATTESTATION-ID"),
        &[
            HashPart::Str(subject_id),
            HashPart::Str(operator_commitment),
            HashPart::Str(kind.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn operator_summary_id(operator_commitment: &str, paymaster_id: &str, epoch: u64) -> String {
    domain_hash(
        &domain("OPERATOR-SUMMARY-ID"),
        &[
            HashPart::Str(operator_commitment),
            HashPart::Str(paymaster_id),
            HashPart::U64(epoch),
        ],
        32,
    )
}

fn seed_devnet(state: &mut State) {
    let ledger_id = "ledger:demo:universal".to_string();
    let _ = state.open_credit_ledger(LowFeeCreditLedger {
        ledger_id: ledger_id.clone(),
        paymaster_id: "pm:demo:universal".to_string(),
        asset_id: state.config.sponsor_credit_asset_id.clone(),
        epoch: state.config.epoch,
        opening_credit_piconero: 2_500_000_000,
        available_credit_piconero: 2_500_000_000,
        reserved_credit_piconero: 0,
        debited_credit_piconero: 0,
        sponsored_gas_units: 0,
        bucket_count: state.config.low_fee_credit_buckets,
        status: CreditStatus::Open,
    });
    let accepted_lanes = [
        EscrowLane::WalletTransfer,
        EscrowLane::PrivateContractCall,
        EscrowLane::DefiIntent,
        EscrowLane::BridgeExit,
        EscrowLane::RecoverySession,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let _ = state.register_paymaster_policy(PaymasterEscrowPolicy {
        policy_id: "policy:demo:universal".to_string(),
        paymaster_id: "pm:demo:universal".to_string(),
        operator_commitment: "operator:demo:paymaster-quorum".to_string(),
        accepted_lanes,
        allowed_contract_root: root_for("demo-allowed-contracts"),
        selector_allowlist_root: root_for("demo-selector-allowlist"),
        session_scope_root: root_for("demo-session-scope"),
        max_fee_bps: DEFAULT_MAX_PAYMASTER_FEE_BPS,
        target_discount_bps: DEFAULT_TARGET_SPONSORED_DISCOUNT_BPS,
        per_session_gas_limit: DEFAULT_MAX_SPONSORED_GAS_PER_SESSION,
        per_epoch_gas_limit: DEFAULT_MAX_SPONSORED_GAS_PER_PAYMASTER,
        escrow_bond_piconero: 50_000_000_000,
        credit_ledger_id: ledger_id,
        min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        valid_from_height: state.config.l2_height,
        valid_until_height: state.config.l2_height + 21_600,
        status: PaymasterPolicyStatus::Registered,
    });
    let _ = state.escrow_envelope(MlKemSessionEnvelope {
        envelope_id: "env:demo:swap".to_string(),
        account_commitment: "acct:demo:swap".to_string(),
        session_key_commitment: "session-key:demo:swap".to_string(),
        paymaster_id: "pm:demo:universal".to_string(),
        policy_id: "policy:demo:universal".to_string(),
        lane: EscrowLane::DefiIntent,
        parameter_set: MlKemParameterSet::MlKem1024,
        ciphertext_commitment: root_for("demo-ml-kem-ciphertext"),
        encapsulated_secret_commitment: root_for("demo-encapsulated-secret"),
        delegate_scope_root: root_for("demo-delegate-scope"),
        view_tag: "viewtag:demo:7f".to_string(),
        encrypted_metadata_root: root_for("demo-envelope-metadata"),
        nullifier_seed_commitment: root_for("demo-nullifier-seed"),
        created_at_height: state.config.l2_height,
        expires_at_height: state.config.l2_height + state.config.escrow_ttl_blocks,
        rotation_window_id: None,
        status: EnvelopeStatus::Sealed,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        max_sponsored_gas: 1_200_000,
    });
    let intent_id = private_intent_id("env:demo:swap", "acct:demo:swap", "pm:demo:universal", 1);
    let _ = state.submit_private_intent(PrivateSponsoredIntent {
        intent_id: intent_id.clone(),
        envelope_id: "env:demo:swap".to_string(),
        account_commitment: "acct:demo:swap".to_string(),
        paymaster_id: "pm:demo:universal".to_string(),
        lane: EscrowLane::DefiIntent,
        sealed_call_root: root_for("demo-sealed-call"),
        encrypted_calldata_root: root_for("demo-calldata"),
        spend_limit_commitment: root_for("spend-limit-10-xmr-notional"),
        fee_quote_commitment: root_for("low-fee-quote-1"),
        nullifier: nullifier_id("env:demo:swap", 1),
        requested_gas_units: 640_000,
        max_user_fee_piconero: 6_400,
        sponsor_credit_reserved: 32_000,
        created_at_height: state.config.l2_height + 1,
        expires_at_height: state.config.l2_height + state.config.intent_ttl_blocks + 1,
        status: IntentStatus::Sealed,
    });
    let _ = state.reserve_intent_credit(&intent_id);
    let _ = state.sponsor_intent(&intent_id);
    let _ = state.settle_intent(&intent_id);
    let window_id = rotation_window_id(
        "pm:demo:universal",
        &root_for("old-session-root"),
        &root_for("new-session-root"),
        state.config.l2_height + 64,
    );
    let _ = state.schedule_rotation_window(KeyRotationWindow {
        window_id: window_id.clone(),
        paymaster_id: "pm:demo:universal".to_string(),
        old_session_root: root_for("old-session-root"),
        new_session_root: root_for("new-session-root"),
        activation_height: state.config.l2_height + 64,
        grace_end_height: state.config.l2_height + 64 + state.config.rotation_window_blocks,
        min_attestation_quorum_bps: DEFAULT_MIN_OPERATOR_QUORUM_BPS,
        affected_envelope_count: 1,
        status: RotationStatus::Scheduled,
    });
    let _ = state.submit_pq_attestation(PqAttestation {
        attestation_id: pq_attestation_id(
            "env:demo:swap",
            "operator:demo:paymaster-quorum",
            AttestationKind::MlKemCiphertextWellFormed,
            1,
        ),
        subject_id: "env:demo:swap".to_string(),
        paymaster_id: "pm:demo:universal".to_string(),
        operator_commitment: "operator:demo:paymaster-quorum".to_string(),
        kind: AttestationKind::MlKemCiphertextWellFormed,
        verdict: AttestationVerdict::Accepted,
        pq_signature_commitment: root_for("demo-pq-signature"),
        proof_root: root_for("demo-attestation-proof"),
        security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        attested_at_height: state.config.l2_height + 2,
        expires_at_height: state.config.l2_height + state.config.attestation_ttl_blocks + 2,
    });
    let summary_root = record_root("DEMO-SUMMARY", &state.counters.public_record());
    let _ = state.publish_operator_summary(OperatorSummary {
        summary_id: operator_summary_id(
            "operator:demo:paymaster-quorum",
            "pm:demo:universal",
            state.config.epoch,
        ),
        operator_commitment: "operator:demo:paymaster-quorum".to_string(),
        paymaster_id: "pm:demo:universal".to_string(),
        epoch: state.config.epoch,
        envelopes_escrowed: state.counters.envelopes_escrowed,
        intents_sponsored: state.counters.intents_sponsored,
        sponsored_gas_units: state.counters.sponsored_gas_units,
        credits_spent_piconero: state.counters.credits_debited,
        accepted_attestations: state.counters.attestations_accepted,
        replay_attempts_blocked: state.counters.replay_attempts_blocked,
        summary_root,
        status: OperatorSummaryStatus::QuorumMet,
    });
}

fn domain(label: &str) -> String {
    format!("{PROTOCOL_VERSION}:{label}")
}
fn record_root(label: &str, record: &Value) -> String {
    domain_hash(&domain(label), &[HashPart::Json(record)], 32)
}
fn root_for(label: &str) -> String {
    domain_hash(&domain("FIXTURE-ROOT"), &[HashPart::Str(label)], 32)
}
fn collection_root(label: &str, records: Vec<Value>) -> String {
    merkle_root(&domain(label), &records)
}
fn index_root(label: &str, index: &BTreeMap<String, BTreeSet<String>>) -> String {
    let leaves = index
        .iter()
        .map(|(key, values)| json!({ "key": key, "values": values }))
        .collect::<Vec<_>>();
    merkle_root(&domain(label), &leaves)
}
fn lane_index_root(index: &BTreeMap<EscrowLane, BTreeSet<String>>) -> String {
    let leaves = index
        .iter()
        .map(|(key, values)| json!({ "lane": key, "values": values }))
        .collect::<Vec<_>>();
    merkle_root(&domain("LANE-INDEX"), &leaves)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicCommitment {
    pub label: String,
    pub subject: String,
    pub nonce: u64,
    pub root: String,
}

impl DeterministicCommitment {
    pub fn new(label: &str, subject: &str, nonce: u64) -> Self {
        Self {
            label: label.to_string(),
            subject: subject.to_string(),
            nonce,
            root: domain_hash(
                &domain("DETERMINISTIC-COMMITMENT"),
                &[
                    HashPart::Str(label),
                    HashPart::Str(subject),
                    HashPart::U64(nonce),
                ],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({ "label": self.label, "subject": self.subject, "nonce": self.nonce, "root": self.root })
    }
}

pub fn account_privacy_set_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("ACCOUNT-PRIVACY-SET-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn paymaster_budget_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("PAYMASTER-BUDGET-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn session_scope_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SESSION-SCOPE-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn selector_allowlist_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SELECTOR-ALLOWLIST-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn contract_allowlist_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("CONTRACT-ALLOWLIST-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn encrypted_metadata_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("ENCRYPTED-METADATA-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn sealed_call_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SEALED-CALL-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn fee_quote_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("FEE-QUOTE-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn spend_limit_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SPEND-LIMIT-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn rotation_old_root_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("ROTATION-OLD-ROOT-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn rotation_new_root_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("ROTATION-NEW-ROOT-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn operator_quorum_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("OPERATOR-QUORUM-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn sponsored_batch_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SPONSORED-BATCH-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn settlement_receipt_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SETTLEMENT-RECEIPT-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn redaction_budget_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("REDACTION-BUDGET-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn view_tag_bucket_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("VIEW-TAG-BUCKET-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn escrow_bond_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("ESCROW-BOND-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn credit_bucket_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("CREDIT-BUCKET-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn replay_epoch_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("REPLAY-EPOCH-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn attestation_batch_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("ATTESTATION-BATCH-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn policy_epoch_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("POLICY-EPOCH-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn intent_batch_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("INTENT-BATCH-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn envelope_cohort_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("ENVELOPE-COHORT-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn low_fee_market_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("LOW-FEE-MARKET-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn sponsor_rebate_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SPONSOR-REBATE-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn session_release_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SESSION-RELEASE-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn session_revocation_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SESSION-REVOCATION-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn quarantine_case_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("QUARANTINE-CASE-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn emergency_escape_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("EMERGENCY-ESCAPE-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn bridge_exit_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("BRIDGE-EXIT-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn defi_solver_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("DEFI-SOLVER-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn wallet_recovery_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("WALLET-RECOVERY-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn governance_vote_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("GOVERNANCE-VOTE-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn proof_publication_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("PROOF-PUBLICATION-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn contract_call_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("CONTRACT-CALL-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn wallet_transfer_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("WALLET-TRANSFER-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn batch_privacy_set_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("BATCH-PRIVACY-SET-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn operator_dispute_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("OPERATOR-DISPUTE-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn slashing_evidence_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("SLASHING-EVIDENCE-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn ledger_refill_root(subject: &str, nonce: u64) -> String {
    domain_hash(
        &domain("LEDGER-REFILL-ROOT"),
        &[HashPart::Str(subject), HashPart::U64(nonce)],
        32,
    )
}

pub fn generated_escrow_audit_leaf_000(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_000",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-000"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_001(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_001",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-001"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_002(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_002",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-002"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_003(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_003",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-003"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_004(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_004",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-004"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_005(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_005",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-005"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_006(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_006",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-006"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_007(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_007",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-007"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_008(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_008",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-008"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_009(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_009",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-009"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_010(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_010",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-010"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_011(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_011",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-011"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_012(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_012",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-012"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_013(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_013",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-013"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_014(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_014",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-014"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_015(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_015",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-015"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_016(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_016",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-016"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_017(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_017",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-017"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_018(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_018",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-018"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_019(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_019",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-019"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_020(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_020",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-020"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_021(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_021",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-021"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_022(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_022",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-022"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}

pub fn generated_escrow_audit_leaf_023(subject: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "leaf_kind": "escrow_audit_023",
        "subject": subject,
        "amount": amount,
        "nonce": nonce,
        "root": domain_hash(
            &domain("ESCROW-AUDIT-023"),
            &[HashPart::Str(subject), HashPart::U64(amount), HashPart::U64(nonce)],
            32,
        ),
    })
}
