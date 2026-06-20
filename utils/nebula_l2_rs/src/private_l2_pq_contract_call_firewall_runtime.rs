use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqContractCallFirewallRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-contract-call-firewall-runtime-v1";
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-contract-call-firewall-v1";
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+Poseidon2-transcript+AEAD-private-call-intent-v1";
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT: u64 = 812_000;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_POLICIES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_INTENTS: usize = 16_777_216;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize = 33_554_432;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_DEPENDENCY_PROOFS: usize =
    16_777_216;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_BATCHES: usize = 2_097_152;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 33_554_432;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_REBATES: usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_QUARANTINES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize = 256;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: usize = 2_048;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_FIREWALL_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 12;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 64;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 43_200;
pub const PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_BATCH_SIZE: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallPolicyKind {
    ContractAllowlist,
    ContractDenylist,
    MethodSelector,
    SpendLimit,
    DependencyBounded,
    SignerQuorum,
    SponsorBounded,
    PrivacyFloor,
    EmergencyQuarantine,
}

impl FirewallPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractAllowlist => "contract_allowlist",
            Self::ContractDenylist => "contract_denylist",
            Self::MethodSelector => "method_selector",
            Self::SpendLimit => "spend_limit",
            Self::DependencyBounded => "dependency_bounded",
            Self::SignerQuorum => "signer_quorum",
            Self::SponsorBounded => "sponsor_bounded",
            Self::PrivacyFloor => "privacy_floor",
            Self::EmergencyQuarantine => "emergency_quarantine",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallPolicyStatus {
    Proposed,
    Active,
    Learning,
    Paused,
    Quarantining,
    Revoked,
    Expired,
}

impl FirewallPolicyStatus {
    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Active | Self::Learning | Self::Quarantining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateCallLane {
    Wallet,
    Dex,
    Lending,
    Perpetuals,
    Bridge,
    Governance,
    Oracle,
    Compliance,
    Emergency,
    Custom,
}

impl PrivateCallLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Bridge => "bridge",
            Self::Governance => "governance",
            Self::Oracle => "oracle",
            Self::Compliance => "compliance",
            Self::Emergency => "emergency",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Encrypted,
    Attested,
    DependencyProved,
    Sponsored,
    Batched,
    Allowed,
    Denied,
    Quarantined,
    Expired,
    Cancelled,
}

impl IntentStatus {
    pub fn pending_decision(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::Attested
                | Self::DependencyProved
                | Self::Sponsored
                | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationKind {
    AccountSigner,
    ContractSigner,
    SessionKey,
    SponsorKey,
    DependencyWitness,
    EmergencyCouncil,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationVerdict {
    Valid,
    ValidWithWarning,
    NeedsMoreWitnesses,
    Invalid,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyProofKind {
    StorageRead,
    StateRoot,
    ReceiptInclusion,
    OracleRound,
    CrossContractCall,
    NullifierFence,
    ReplayFence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyProofStatus {
    Submitted,
    Verified,
    Stale,
    Conflicted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    BoundToIntent,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDecision {
    Allow,
    AllowWithRateLimit,
    RequireMoreProofs,
    Deny,
    Quarantine,
    DropReplay,
}

impl FirewallDecision {
    pub fn permits_execution(self) -> bool {
        matches!(self, Self::Allow | Self::AllowWithRateLimit)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionBatchStatus {
    Proposed,
    Verifying,
    Settled,
    PartiallySettled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    PolicyRegistered,
    IntentAccepted,
    AttestationAccepted,
    DependencyVerified,
    SponsorReserved,
    BatchDecided,
    IntentAllowed,
    IntentDenied,
    IntentQuarantined,
    RebatePaid,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyRegistered => "policy_registered",
            Self::IntentAccepted => "intent_accepted",
            Self::AttestationAccepted => "attestation_accepted",
            Self::DependencyVerified => "dependency_verified",
            Self::SponsorReserved => "sponsor_reserved",
            Self::BatchDecided => "batch_decided",
            Self::IntentAllowed => "intent_allowed",
            Self::IntentDenied => "intent_denied",
            Self::IntentQuarantined => "intent_quarantined",
            Self::RebatePaid => "rebate_paid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    EmergencyPause,
    DependencyConflict,
    SignerRevoked,
    ReplaySuspected,
    NullifierCollision,
    FeeSponsorAbuse,
    PolicyViolation,
    UnknownRisk,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub encryption_suite: String,
    pub max_policies: usize,
    pub max_intents: usize,
    pub max_attestations: usize,
    pub max_dependency_proofs: usize,
    pub max_sponsor_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_quarantines: usize,
    pub min_privacy_set: usize,
    pub batch_privacy_set: usize,
    pub min_pq_security_bits: u16,
    pub max_firewall_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub intent_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub max_batch_size: usize,
}

impl Config {
    pub fn devnet() -> PrivateL2PqContractCallFirewallRuntimeResult<Self> {
        let config = Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT,
            hash_suite: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_PQ_AUTH_SUITE.to_string(),
            encryption_suite: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_ENCRYPTION_SUITE
                .to_string(),
            max_policies: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_POLICIES,
            max_intents: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_INTENTS,
            max_attestations: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_dependency_proofs:
                PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_DEPENDENCY_PROOFS,
            max_sponsor_reservations:
                PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_REBATES,
            max_quarantines: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_QUARANTINES,
            min_privacy_set: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set:
                PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_firewall_fee_bps:
                PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_FIREWALL_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            intent_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            quarantine_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_QUARANTINE_TTL_BLOCKS,
            max_batch_size: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEFAULT_MAX_BATCH_SIZE,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_eq("chain_id", &self.chain_id, CHAIN_ID)?;
        require_nonempty("protocol_version", &self.protocol_version)?;
        require_nonempty("hash_suite", &self.hash_suite)?;
        require_nonempty("pq_auth_suite", &self.pq_auth_suite)?;
        require_nonempty("encryption_suite", &self.encryption_suite)?;
        require_min("schema_version", self.schema_version, 1)?;
        require_min_usize("max_policies", self.max_policies, 1)?;
        require_min_usize("max_intents", self.max_intents, 1)?;
        require_min_usize("max_attestations", self.max_attestations, 1)?;
        require_min_usize("max_dependency_proofs", self.max_dependency_proofs, 1)?;
        require_min_usize("max_sponsor_reservations", self.max_sponsor_reservations, 1)?;
        require_min_usize("max_batches", self.max_batches, 1)?;
        require_min_usize("max_receipts", self.max_receipts, 1)?;
        require_min_usize("max_rebates", self.max_rebates, 1)?;
        require_min_usize("max_quarantines", self.max_quarantines, 1)?;
        require_min_usize("min_privacy_set", self.min_privacy_set, 2)?;
        require_min_usize(
            "batch_privacy_set",
            self.batch_privacy_set,
            self.min_privacy_set,
        )?;
        require_min_u16("min_pq_security_bits", self.min_pq_security_bits, 128)?;
        require_bps("max_firewall_fee_bps", self.max_firewall_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        if self.target_rebate_bps > self.max_firewall_fee_bps {
            return Err("target_rebate_bps cannot exceed max_firewall_fee_bps".to_string());
        }
        require_min("intent_ttl_blocks", self.intent_ttl_blocks, 1)?;
        require_min("reservation_ttl_blocks", self.reservation_ttl_blocks, 1)?;
        require_min(
            "quarantine_ttl_blocks",
            self.quarantine_ttl_blocks,
            self.intent_ttl_blocks,
        )?;
        require_min_usize("max_batch_size", self.max_batch_size, 1)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "encryption_suite": self.encryption_suite,
            "max_policies": self.max_policies,
            "max_intents": self.max_intents,
            "max_attestations": self.max_attestations,
            "max_dependency_proofs": self.max_dependency_proofs,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_quarantines": self.max_quarantines,
            "min_privacy_set": self.min_privacy_set,
            "batch_privacy_set": self.batch_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_firewall_fee_bps": self.max_firewall_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "max_batch_size": self.max_batch_size,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_policy_sequence: u64,
    pub next_intent_sequence: u64,
    pub next_attestation_sequence: u64,
    pub next_dependency_proof_sequence: u64,
    pub next_sponsor_reservation_sequence: u64,
    pub next_batch_sequence: u64,
    pub next_receipt_sequence: u64,
    pub next_rebate_sequence: u64,
    pub next_quarantine_sequence: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_policy_sequence: 1,
            next_intent_sequence: 1,
            next_attestation_sequence: 1,
            next_dependency_proof_sequence: 1,
            next_sponsor_reservation_sequence: 1,
            next_batch_sequence: 1,
            next_receipt_sequence: 1,
            next_rebate_sequence: 1,
            next_quarantine_sequence: 1,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "next_policy_sequence": self.next_policy_sequence,
            "next_intent_sequence": self.next_intent_sequence,
            "next_attestation_sequence": self.next_attestation_sequence,
            "next_dependency_proof_sequence": self.next_dependency_proof_sequence,
            "next_sponsor_reservation_sequence": self.next_sponsor_reservation_sequence,
            "next_batch_sequence": self.next_batch_sequence,
            "next_receipt_sequence": self.next_receipt_sequence,
            "next_rebate_sequence": self.next_rebate_sequence,
            "next_quarantine_sequence": self.next_quarantine_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractFirewallPolicyRequest {
    pub policy_owner_commitment: String,
    pub contract_commitment: String,
    pub policy_kind: FirewallPolicyKind,
    pub status: FirewallPolicyStatus,
    pub lane: PrivateCallLane,
    pub method_selector_root: String,
    pub contract_state_root: String,
    pub signer_set_root: String,
    pub dependency_rule_root: String,
    pub spend_limit_commitment: String,
    pub max_fee_bps: u64,
    pub min_privacy_set: usize,
    pub min_pq_security_bits: u16,
    pub activation_height: u64,
    pub expiry_height: u64,
    pub emergency_quarantine_enabled: bool,
    pub metadata_commitment: String,
}

impl ContractFirewallPolicyRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("policy_owner_commitment", &self.policy_owner_commitment)?;
        require_nonempty("contract_commitment", &self.contract_commitment)?;
        require_root("method_selector_root", &self.method_selector_root)?;
        require_root("contract_state_root", &self.contract_state_root)?;
        require_root("signer_set_root", &self.signer_set_root)?;
        require_root("dependency_rule_root", &self.dependency_rule_root)?;
        require_nonempty("spend_limit_commitment", &self.spend_limit_commitment)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_firewall_fee_bps {
            return Err("policy max_fee_bps exceeds runtime max_firewall_fee_bps".to_string());
        }
        require_min_usize(
            "min_privacy_set",
            self.min_privacy_set,
            config.min_privacy_set,
        )?;
        require_min_u16(
            "min_pq_security_bits",
            self.min_pq_security_bits,
            config.min_pq_security_bits,
        )?;
        require_height_window(self.activation_height, self.expiry_height)?;
        require_nonempty("metadata_commitment", &self.metadata_commitment)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_owner_commitment": self.policy_owner_commitment,
            "contract_commitment": self.contract_commitment,
            "policy_kind": self.policy_kind,
            "status": self.status,
            "lane": self.lane,
            "method_selector_root": self.method_selector_root,
            "contract_state_root": self.contract_state_root,
            "signer_set_root": self.signer_set_root,
            "dependency_rule_root": self.dependency_rule_root,
            "spend_limit_commitment": self.spend_limit_commitment,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "activation_height": self.activation_height,
            "expiry_height": self.expiry_height,
            "emergency_quarantine_enabled": self.emergency_quarantine_enabled,
            "metadata_commitment": self.metadata_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractFirewallPolicyRecord {
    pub policy_id: String,
    pub sequence: u64,
    pub request: ContractFirewallPolicyRequest,
    pub policy_root: String,
    pub registered_height: u64,
}

impl ContractFirewallPolicyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "policy_root": self.policy_root,
            "registered_height": self.registered_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCallIntentRequest {
    pub policy_id: String,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub lane: PrivateCallLane,
    pub encrypted_payload_root: String,
    pub call_selector_commitment: String,
    pub calldata_ciphertext_commitment: String,
    pub value_commitment: String,
    pub dependency_hint_root: String,
    pub replay_nullifier: String,
    pub intent_nullifier: String,
    pub fee_asset_commitment: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: usize,
    pub valid_after_height: u64,
    pub expires_at_height: u64,
    pub status: IntentStatus,
}

impl EncryptedCallIntentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("policy_id", &self.policy_id)?;
        require_nonempty("sender_commitment", &self.sender_commitment)?;
        require_nonempty("contract_commitment", &self.contract_commitment)?;
        require_root("encrypted_payload_root", &self.encrypted_payload_root)?;
        require_nonempty("call_selector_commitment", &self.call_selector_commitment)?;
        require_nonempty(
            "calldata_ciphertext_commitment",
            &self.calldata_ciphertext_commitment,
        )?;
        require_nonempty("value_commitment", &self.value_commitment)?;
        require_root("dependency_hint_root", &self.dependency_hint_root)?;
        require_nonempty("replay_nullifier", &self.replay_nullifier)?;
        require_nonempty("intent_nullifier", &self.intent_nullifier)?;
        require_nonempty("fee_asset_commitment", &self.fee_asset_commitment)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_firewall_fee_bps {
            return Err("intent max_fee_bps exceeds runtime max_firewall_fee_bps".to_string());
        }
        require_min_usize(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set,
        )?;
        require_height_window(self.valid_after_height, self.expires_at_height)?;
        if self.expires_at_height - self.valid_after_height > config.intent_ttl_blocks {
            return Err("intent validity window exceeds intent_ttl_blocks".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "sender_commitment": self.sender_commitment,
            "contract_commitment": self.contract_commitment,
            "lane": self.lane,
            "encrypted_payload_root": self.encrypted_payload_root,
            "call_selector_commitment": self.call_selector_commitment,
            "calldata_ciphertext_commitment": self.calldata_ciphertext_commitment,
            "value_commitment": self.value_commitment,
            "dependency_hint_root": self.dependency_hint_root,
            "replay_nullifier": self.replay_nullifier,
            "intent_nullifier": self.intent_nullifier,
            "fee_asset_commitment": self.fee_asset_commitment,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "valid_after_height": self.valid_after_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCallIntentRecord {
    pub intent_id: String,
    pub sequence: u64,
    pub request: EncryptedCallIntentRequest,
    pub intent_root: String,
    pub accepted_height: u64,
}

impl EncryptedCallIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "intent_root": self.intent_root,
            "accepted_height": self.accepted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignerAttestationRequest {
    pub intent_id: String,
    pub attestation_kind: PqAttestationKind,
    pub signer_commitment: String,
    pub pq_public_key_commitment: String,
    pub signature_transcript_root: String,
    pub signer_policy_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub kem_ciphertext_root: String,
    pub verdict: PqAttestationVerdict,
    pub pq_security_bits: u16,
    pub issued_height: u64,
    pub expires_at_height: u64,
}

impl PqSignerAttestationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("intent_id", &self.intent_id)?;
        require_nonempty("signer_commitment", &self.signer_commitment)?;
        require_nonempty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        require_root("signature_transcript_root", &self.signature_transcript_root)?;
        require_root("signer_policy_root", &self.signer_policy_root)?;
        require_root("ml_dsa_signature_root", &self.ml_dsa_signature_root)?;
        require_root("slh_dsa_signature_root", &self.slh_dsa_signature_root)?;
        require_root("kem_ciphertext_root", &self.kem_ciphertext_root)?;
        require_min_u16(
            "pq_security_bits",
            self.pq_security_bits,
            config.min_pq_security_bits,
        )?;
        require_height_window(self.issued_height, self.expires_at_height)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "attestation_kind": self.attestation_kind,
            "signer_commitment": self.signer_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "signature_transcript_root": self.signature_transcript_root,
            "signer_policy_root": self.signer_policy_root,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "slh_dsa_signature_root": self.slh_dsa_signature_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "verdict": self.verdict,
            "pq_security_bits": self.pq_security_bits,
            "issued_height": self.issued_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignerAttestationRecord {
    pub attestation_id: String,
    pub sequence: u64,
    pub request: PqSignerAttestationRequest,
    pub attestation_root: String,
    pub accepted_height: u64,
}

impl PqSignerAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "attestation_root": self.attestation_root,
            "accepted_height": self.accepted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DependencyProofRequest {
    pub intent_id: String,
    pub proof_kind: DependencyProofKind,
    pub status: DependencyProofStatus,
    pub dependency_contract_commitment: String,
    pub witness_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub receipt_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub proof_system: String,
    pub proof_commitment: String,
    pub verified_height: u64,
}

impl DependencyProofRequest {
    pub fn validate(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("intent_id", &self.intent_id)?;
        require_nonempty(
            "dependency_contract_commitment",
            &self.dependency_contract_commitment,
        )?;
        require_root("witness_root", &self.witness_root)?;
        require_root("state_root_before", &self.state_root_before)?;
        require_root("state_root_after", &self.state_root_after)?;
        require_root("receipt_root", &self.receipt_root)?;
        require_root("nullifier_fence_root", &self.nullifier_fence_root)?;
        require_root("replay_fence_root", &self.replay_fence_root)?;
        require_nonempty("proof_system", &self.proof_system)?;
        require_nonempty("proof_commitment", &self.proof_commitment)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "proof_kind": self.proof_kind,
            "status": self.status,
            "dependency_contract_commitment": self.dependency_contract_commitment,
            "witness_root": self.witness_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "receipt_root": self.receipt_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "proof_system": self.proof_system,
            "proof_commitment": self.proof_commitment,
            "verified_height": self.verified_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DependencyProofRecord {
    pub dependency_proof_id: String,
    pub sequence: u64,
    pub request: DependencyProofRequest,
    pub dependency_proof_root: String,
}

impl DependencyProofRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "dependency_proof_id": self.dependency_proof_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "dependency_proof_root": self.dependency_proof_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSponsorReservationRequest {
    pub intent_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_commitment: String,
    pub max_fee_commitment: String,
    pub reserved_fee_units: u64,
    pub rebate_bps: u64,
    pub status: SponsorReservationStatus,
    pub reservation_nullifier: String,
    pub valid_after_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeSponsorReservationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("intent_id", &self.intent_id)?;
        require_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        require_nonempty("fee_asset_commitment", &self.fee_asset_commitment)?;
        require_nonempty("max_fee_commitment", &self.max_fee_commitment)?;
        require_min("reserved_fee_units", self.reserved_fee_units, 1)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps > config.target_rebate_bps {
            return Err("rebate_bps exceeds runtime target_rebate_bps".to_string());
        }
        require_nonempty("reservation_nullifier", &self.reservation_nullifier)?;
        require_height_window(self.valid_after_height, self.expires_at_height)?;
        if self.expires_at_height - self.valid_after_height > config.reservation_ttl_blocks {
            return Err("reservation validity window exceeds reservation_ttl_blocks".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_commitment": self.fee_asset_commitment,
            "max_fee_commitment": self.max_fee_commitment,
            "reserved_fee_units": self.reserved_fee_units,
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "reservation_nullifier": self.reservation_nullifier,
            "valid_after_height": self.valid_after_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSponsorReservationRecord {
    pub reservation_id: String,
    pub sequence: u64,
    pub request: LowFeeSponsorReservationRequest,
    pub reservation_root: String,
    pub reserved_height: u64,
}

impl LowFeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "reservation_root": self.reservation_root,
            "reserved_height": self.reserved_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallDecisionBatchRequest {
    pub batch_policy_root: String,
    pub intent_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub dependency_proof_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub decision_root: String,
    pub allowed_intent_root: String,
    pub denied_intent_root: String,
    pub quarantined_intent_root: String,
    pub replay_nullifier_root: String,
    pub consumed_nullifier_root: String,
    pub status: DecisionBatchStatus,
    pub sequencer_commitment: String,
    pub proving_time_micros: u64,
    pub settled_height: u64,
}

impl FirewallDecisionBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_root("batch_policy_root", &self.batch_policy_root)?;
        require_unique("intent_ids", &self.intent_ids)?;
        require_unique("attestation_ids", &self.attestation_ids)?;
        require_unique("dependency_proof_ids", &self.dependency_proof_ids)?;
        require_unique("sponsor_reservation_ids", &self.sponsor_reservation_ids)?;
        require_min_usize("intent_ids length", self.intent_ids.len(), 1)?;
        if self.intent_ids.len() > config.max_batch_size {
            return Err("decision batch exceeds max_batch_size".to_string());
        }
        require_root("decision_root", &self.decision_root)?;
        require_root("allowed_intent_root", &self.allowed_intent_root)?;
        require_root("denied_intent_root", &self.denied_intent_root)?;
        require_root("quarantined_intent_root", &self.quarantined_intent_root)?;
        require_root("replay_nullifier_root", &self.replay_nullifier_root)?;
        require_root("consumed_nullifier_root", &self.consumed_nullifier_root)?;
        require_nonempty("sequencer_commitment", &self.sequencer_commitment)?;
        require_min("proving_time_micros", self.proving_time_micros, 1)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_policy_root": self.batch_policy_root,
            "intent_ids": self.intent_ids,
            "attestation_ids": self.attestation_ids,
            "dependency_proof_ids": self.dependency_proof_ids,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
            "decision_root": self.decision_root,
            "allowed_intent_root": self.allowed_intent_root,
            "denied_intent_root": self.denied_intent_root,
            "quarantined_intent_root": self.quarantined_intent_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "status": self.status,
            "sequencer_commitment": self.sequencer_commitment,
            "proving_time_micros": self.proving_time_micros,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallDecisionBatchRecord {
    pub batch_id: String,
    pub sequence: u64,
    pub request: FirewallDecisionBatchRequest,
    pub batch_root: String,
}

impl FirewallDecisionBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "batch_root": self.batch_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallReceiptRequest {
    pub receipt_kind: ReceiptKind,
    pub intent_id: String,
    pub batch_id: String,
    pub decision: FirewallDecision,
    pub receipt_payload_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub fee_charged_units: u64,
    pub emitted_height: u64,
}

impl FirewallReceiptRequest {
    pub fn validate(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("intent_id", &self.intent_id)?;
        require_nonempty("batch_id", &self.batch_id)?;
        require_root("receipt_payload_root", &self.receipt_payload_root)?;
        require_root("state_root_before", &self.state_root_before)?;
        require_root("state_root_after", &self.state_root_after)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_kind": self.receipt_kind,
            "intent_id": self.intent_id,
            "batch_id": self.batch_id,
            "decision": self.decision,
            "receipt_payload_root": self.receipt_payload_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "fee_charged_units": self.fee_charged_units,
            "emitted_height": self.emitted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallReceiptRecord {
    pub receipt_id: String,
    pub sequence: u64,
    pub request: FirewallReceiptRequest,
    pub receipt_root: String,
}

impl FirewallReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallRebateRequest {
    pub receipt_id: String,
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub recipient_commitment: String,
    pub rebate_asset_commitment: String,
    pub rebate_amount_commitment: String,
    pub rebate_nullifier: String,
    pub paid_height: u64,
}

impl FirewallRebateRequest {
    pub fn validate(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("receipt_id", &self.receipt_id)?;
        require_nonempty("reservation_id", &self.reservation_id)?;
        require_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        require_nonempty("recipient_commitment", &self.recipient_commitment)?;
        require_nonempty("rebate_asset_commitment", &self.rebate_asset_commitment)?;
        require_nonempty("rebate_amount_commitment", &self.rebate_amount_commitment)?;
        require_nonempty("rebate_nullifier", &self.rebate_nullifier)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "recipient_commitment": self.recipient_commitment,
            "rebate_asset_commitment": self.rebate_asset_commitment,
            "rebate_amount_commitment": self.rebate_amount_commitment,
            "rebate_nullifier": self.rebate_nullifier,
            "paid_height": self.paid_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallRebateRecord {
    pub rebate_id: String,
    pub sequence: u64,
    pub request: FirewallRebateRequest,
    pub rebate_root: String,
}

impl FirewallRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyQuarantineRequest {
    pub intent_id: String,
    pub policy_id: String,
    pub reason: QuarantineReason,
    pub council_commitment: String,
    pub evidence_root: String,
    pub quarantine_nullifier: String,
    pub opened_height: u64,
    pub expires_at_height: u64,
    pub release_condition_root: String,
}

impl EmergencyQuarantineRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("intent_id", &self.intent_id)?;
        require_nonempty("policy_id", &self.policy_id)?;
        require_nonempty("council_commitment", &self.council_commitment)?;
        require_root("evidence_root", &self.evidence_root)?;
        require_nonempty("quarantine_nullifier", &self.quarantine_nullifier)?;
        require_height_window(self.opened_height, self.expires_at_height)?;
        if self.expires_at_height - self.opened_height > config.quarantine_ttl_blocks {
            return Err("quarantine window exceeds quarantine_ttl_blocks".to_string());
        }
        require_root("release_condition_root", &self.release_condition_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "policy_id": self.policy_id,
            "reason": self.reason,
            "council_commitment": self.council_commitment,
            "evidence_root": self.evidence_root,
            "quarantine_nullifier": self.quarantine_nullifier,
            "opened_height": self.opened_height,
            "expires_at_height": self.expires_at_height,
            "release_condition_root": self.release_condition_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyQuarantineRecord {
    pub quarantine_id: String,
    pub sequence: u64,
    pub request: EmergencyQuarantineRequest,
    pub quarantine_root: String,
}

impl EmergencyQuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "quarantine_root": self.quarantine_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallRiskSignal {
    pub signal_id: String,
    pub intent_id: String,
    pub policy_id: String,
    pub lane: PrivateCallLane,
    pub decision: FirewallDecision,
    pub score_bps: u64,
    pub evidence_root: String,
    pub replay_fence_root: String,
    pub dependency_fence_root: String,
}

impl FirewallRiskSignal {
    pub fn validate(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("signal_id", &self.signal_id)?;
        require_nonempty("intent_id", &self.intent_id)?;
        require_nonempty("policy_id", &self.policy_id)?;
        require_bps("score_bps", self.score_bps)?;
        require_root("evidence_root", &self.evidence_root)?;
        require_root("replay_fence_root", &self.replay_fence_root)?;
        require_root("dependency_fence_root", &self.dependency_fence_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "intent_id": self.intent_id,
            "policy_id": self.policy_id,
            "lane": self.lane,
            "decision": self.decision,
            "score_bps": self.score_bps,
            "evidence_root": self.evidence_root,
            "replay_fence_root": self.replay_fence_root,
            "dependency_fence_root": self.dependency_fence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallFeeQuote {
    pub quote_id: String,
    pub intent_id: String,
    pub sponsor_reservation_id: String,
    pub fee_asset_commitment: String,
    pub base_fee_units: u64,
    pub priority_fee_units: u64,
    pub rebate_bps: u64,
    pub quote_root: String,
    pub expires_at_height: u64,
}

impl FirewallFeeQuote {
    pub fn validate(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("quote_id", &self.quote_id)?;
        require_nonempty("intent_id", &self.intent_id)?;
        require_nonempty("sponsor_reservation_id", &self.sponsor_reservation_id)?;
        require_nonempty("fee_asset_commitment", &self.fee_asset_commitment)?;
        require_min("base_fee_units", self.base_fee_units, 1)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require_root("quote_root", &self.quote_root)?;
        require_min("expires_at_height", self.expires_at_height, 1)?;
        Ok(())
    }

    pub fn total_fee_units(&self) -> u64 {
        self.base_fee_units.saturating_add(self.priority_fee_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "intent_id": self.intent_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "fee_asset_commitment": self.fee_asset_commitment,
            "base_fee_units": self.base_fee_units,
            "priority_fee_units": self.priority_fee_units,
            "total_fee_units": self.total_fee_units(),
            "rebate_bps": self.rebate_bps,
            "quote_root": self.quote_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallPrivacyEnvelope {
    pub envelope_id: String,
    pub intent_id: String,
    pub anonymity_set_root: String,
    pub decoy_contract_root: String,
    pub timing_bucket_root: String,
    pub encrypted_memo_root: String,
    pub privacy_set_size: usize,
    pub min_pq_security_bits: u16,
}

impl FirewallPrivacyEnvelope {
    pub fn validate(&self, config: &Config) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("envelope_id", &self.envelope_id)?;
        require_nonempty("intent_id", &self.intent_id)?;
        require_root("anonymity_set_root", &self.anonymity_set_root)?;
        require_root("decoy_contract_root", &self.decoy_contract_root)?;
        require_root("timing_bucket_root", &self.timing_bucket_root)?;
        require_root("encrypted_memo_root", &self.encrypted_memo_root)?;
        require_min_usize(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set,
        )?;
        require_min_u16(
            "min_pq_security_bits",
            self.min_pq_security_bits,
            config.min_pq_security_bits,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "intent_id": self.intent_id,
            "anonymity_set_root": self.anonymity_set_root,
            "decoy_contract_root": self.decoy_contract_root,
            "timing_bucket_root": self.timing_bucket_root,
            "encrypted_memo_root": self.encrypted_memo_root,
            "privacy_set_size": self.privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FirewallThroughputWindow {
    pub window_id: String,
    pub lane: PrivateCallLane,
    pub start_height: u64,
    pub end_height: u64,
    pub accepted_intents: u64,
    pub allowed_intents: u64,
    pub denied_intents: u64,
    pub quarantined_intents: u64,
    pub median_decision_micros: u64,
    pub p99_decision_micros: u64,
    pub fee_rebate_units: u64,
}

impl FirewallThroughputWindow {
    pub fn validate(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        require_nonempty("window_id", &self.window_id)?;
        require_height_window(self.start_height, self.end_height)?;
        require_min("median_decision_micros", self.median_decision_micros, 1)?;
        require_min(
            "p99_decision_micros",
            self.p99_decision_micros,
            self.median_decision_micros,
        )?;
        if self.allowed_intents + self.denied_intents + self.quarantined_intents
            > self.accepted_intents
        {
            return Err("throughput window decisions exceed accepted intents".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane": self.lane,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "accepted_intents": self.accepted_intents,
            "allowed_intents": self.allowed_intents,
            "denied_intents": self.denied_intents,
            "quarantined_intents": self.quarantined_intents,
            "median_decision_micros": self.median_decision_micros,
            "p99_decision_micros": self.p99_decision_micros,
            "fee_rebate_units": self.fee_rebate_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub policy_root: String,
    pub encrypted_intent_root: String,
    pub pq_attestation_root: String,
    pub dependency_proof_root: String,
    pub sponsor_reservation_root: String,
    pub decision_batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub replay_nullifier_root: String,
    pub consumed_nullifier_root: String,
    pub quarantine_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "policy_root": self.policy_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "pq_attestation_root": self.pq_attestation_root,
            "dependency_proof_root": self.dependency_proof_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "decision_batch_root": self.decision_batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "quarantine_root": self.quarantine_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub policies: BTreeMap<String, ContractFirewallPolicyRecord>,
    pub encrypted_intents: BTreeMap<String, EncryptedCallIntentRecord>,
    pub pq_attestations: BTreeMap<String, PqSignerAttestationRecord>,
    pub dependency_proofs: BTreeMap<String, DependencyProofRecord>,
    pub sponsor_reservations: BTreeMap<String, LowFeeSponsorReservationRecord>,
    pub decision_batches: BTreeMap<String, FirewallDecisionBatchRecord>,
    pub receipts: BTreeMap<String, FirewallReceiptRecord>,
    pub rebates: BTreeMap<String, FirewallRebateRecord>,
    pub replay_nullifiers: BTreeSet<String>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub quarantines: BTreeMap<String, EmergencyQuarantineRecord>,
}

impl State {
    pub fn devnet() -> PrivateL2PqContractCallFirewallRuntimeResult<Self> {
        let config = Config::devnet()?;
        let counters = Counters::devnet();
        let mut state = Self {
            config,
            counters,
            policies: BTreeMap::new(),
            encrypted_intents: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            dependency_proofs: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            decision_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
            consumed_nullifiers: BTreeSet::new(),
            quarantines: BTreeMap::new(),
        };

        let policy = ContractFirewallPolicyRequest {
            policy_owner_commitment: "devnet-policy-owner-commitment".to_string(),
            contract_commitment: "devnet-private-contract-amm-vault".to_string(),
            policy_kind: FirewallPolicyKind::MethodSelector,
            status: FirewallPolicyStatus::Active,
            lane: PrivateCallLane::Dex,
            method_selector_root: sample_root("method-selector-root"),
            contract_state_root: sample_root("contract-state-root"),
            signer_set_root: sample_root("signer-set-root"),
            dependency_rule_root: sample_root("dependency-rule-root"),
            spend_limit_commitment: "devnet-spend-limit-commitment".to_string(),
            max_fee_bps: 12,
            min_privacy_set: 512,
            min_pq_security_bits: 256,
            activation_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT,
            expiry_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 86_400,
            emergency_quarantine_enabled: true,
            metadata_commitment: "devnet-policy-metadata".to_string(),
        };
        let policy_id = state.register_contract_policy(policy)?;

        let intent = EncryptedCallIntentRequest {
            policy_id: policy_id.clone(),
            sender_commitment: "devnet-sender-note-commitment".to_string(),
            contract_commitment: "devnet-private-contract-amm-vault".to_string(),
            lane: PrivateCallLane::Dex,
            encrypted_payload_root: sample_root("encrypted-payload-root"),
            call_selector_commitment: "devnet-call-selector-swap-exact-private".to_string(),
            calldata_ciphertext_commitment: "devnet-call-ciphertext-commitment".to_string(),
            value_commitment: "devnet-value-commitment".to_string(),
            dependency_hint_root: sample_root("dependency-hint-root"),
            replay_nullifier: "devnet-replay-nullifier-0001".to_string(),
            intent_nullifier: "devnet-intent-nullifier-0001".to_string(),
            fee_asset_commitment: "devnet-fee-asset-commitment".to_string(),
            max_fee_bps: 10,
            privacy_set_size: 2_048,
            valid_after_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 1,
            expires_at_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 64,
            status: IntentStatus::Encrypted,
        };
        let intent_id = state.accept_encrypted_call_intent(intent)?;

        let attestation = PqSignerAttestationRequest {
            intent_id: intent_id.clone(),
            attestation_kind: PqAttestationKind::SessionKey,
            signer_commitment: "devnet-session-signer-commitment".to_string(),
            pq_public_key_commitment: "devnet-ml-dsa-public-key-commitment".to_string(),
            signature_transcript_root: sample_root("signature-transcript-root"),
            signer_policy_root: sample_root("signer-policy-root"),
            ml_dsa_signature_root: sample_root("ml-dsa-signature-root"),
            slh_dsa_signature_root: sample_root("slh-dsa-signature-root"),
            kem_ciphertext_root: sample_root("kem-ciphertext-root"),
            verdict: PqAttestationVerdict::Valid,
            pq_security_bits: 256,
            issued_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 2,
            expires_at_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 66,
        };
        let attestation_id = state.accept_pq_signer_attestation(attestation)?;

        let dependency = DependencyProofRequest {
            intent_id: intent_id.clone(),
            proof_kind: DependencyProofKind::StateRoot,
            status: DependencyProofStatus::Verified,
            dependency_contract_commitment: "devnet-oracle-router-commitment".to_string(),
            witness_root: sample_root("dependency-witness-root"),
            state_root_before: sample_root("dependency-state-before"),
            state_root_after: sample_root("dependency-state-after"),
            receipt_root: sample_root("dependency-receipt-root"),
            nullifier_fence_root: sample_root("dependency-nullifier-fence-root"),
            replay_fence_root: sample_root("dependency-replay-fence-root"),
            proof_system: "plonkish-poseidon2-recursive-pq-friendly".to_string(),
            proof_commitment: "devnet-dependency-proof-commitment".to_string(),
            verified_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 3,
        };
        let dependency_id = state.verify_dependency_proof(dependency)?;

        let reservation = LowFeeSponsorReservationRequest {
            intent_id: intent_id.clone(),
            sponsor_commitment: "devnet-low-fee-sponsor-commitment".to_string(),
            fee_asset_commitment: "devnet-fee-asset-commitment".to_string(),
            max_fee_commitment: "devnet-max-fee-commitment".to_string(),
            reserved_fee_units: 42_000,
            rebate_bps: 8,
            status: SponsorReservationStatus::Reserved,
            reservation_nullifier: "devnet-reservation-nullifier-0001".to_string(),
            valid_after_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 3,
            expires_at_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 67,
        };
        let reservation_id = state.reserve_low_fee_sponsor(reservation)?;

        let batch = FirewallDecisionBatchRequest {
            batch_policy_root: sample_root("batch-policy-root"),
            intent_ids: vec![intent_id.clone()],
            attestation_ids: vec![attestation_id],
            dependency_proof_ids: vec![dependency_id],
            sponsor_reservation_ids: vec![reservation_id.clone()],
            decision_root: sample_root("decision-root"),
            allowed_intent_root: id_list_root(
                "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DEVNET-ALLOWED",
                vec![&intent_id].into_iter(),
            ),
            denied_intent_root: id_list_root(
                "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DEVNET-DENIED",
                Vec::<&String>::new().into_iter(),
            ),
            quarantined_intent_root: id_list_root(
                "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DEVNET-QUARANTINED",
                Vec::<&String>::new().into_iter(),
            ),
            replay_nullifier_root: state.replay_fence_root(),
            consumed_nullifier_root: state.consumed_nullifier_root(),
            status: DecisionBatchStatus::Settled,
            sequencer_commitment: "devnet-fast-pq-sequencer-commitment".to_string(),
            proving_time_micros: 38_000,
            settled_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 4,
        };
        let batch_id = state.publish_firewall_decision_batch(batch)?;

        let receipt = FirewallReceiptRequest {
            receipt_kind: ReceiptKind::IntentAllowed,
            intent_id: intent_id.clone(),
            batch_id,
            decision: FirewallDecision::Allow,
            receipt_payload_root: sample_root("receipt-payload-root"),
            state_root_before: sample_root("receipt-state-before"),
            state_root_after: sample_root("receipt-state-after"),
            fee_charged_units: 36_000,
            emitted_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 5,
        };
        let receipt_id = state.publish_firewall_receipt(receipt)?;

        let rebate = FirewallRebateRequest {
            receipt_id,
            reservation_id,
            sponsor_commitment: "devnet-low-fee-sponsor-commitment".to_string(),
            recipient_commitment: "devnet-sender-note-commitment".to_string(),
            rebate_asset_commitment: "devnet-fee-asset-commitment".to_string(),
            rebate_amount_commitment: "devnet-rebate-amount-commitment".to_string(),
            rebate_nullifier: "devnet-rebate-nullifier-0001".to_string(),
            paid_height: PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_DEVNET_HEIGHT + 6,
        };
        state.publish_firewall_rebate(rebate)?;

        Ok(state)
    }

    pub fn register_contract_policy(
        &mut self,
        request: ContractFirewallPolicyRequest,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<String> {
        self.ensure_policy_capacity()?;
        request.validate(&self.config)?;
        if !request.status.accepts_intents() {
            return Err("contract firewall policy must accept intents at registration".to_string());
        }
        let sequence = self.counters.next_policy_sequence;
        let policy_id = contract_firewall_policy_id(&request, sequence);
        if self.policies.contains_key(&policy_id) {
            return Err(format!("policy {policy_id} already exists"));
        }
        let policy_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-POLICY-ROOT",
            &request.public_record(),
        );
        let record = ContractFirewallPolicyRecord {
            policy_id: policy_id.clone(),
            sequence,
            request,
            policy_root,
            registered_height: self.config.devnet_height,
        };
        self.policies.insert(policy_id.clone(), record);
        self.counters.next_policy_sequence += 1;
        Ok(policy_id)
    }

    pub fn accept_encrypted_call_intent(
        &mut self,
        request: EncryptedCallIntentRequest,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<String> {
        self.ensure_intent_capacity()?;
        request.validate(&self.config)?;
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| format!("policy {} is unknown", request.policy_id))?;
        if !policy.request.status.accepts_intents() {
            return Err("policy does not currently accept intents".to_string());
        }
        if policy.request.contract_commitment != request.contract_commitment {
            return Err("intent contract commitment does not match policy".to_string());
        }
        if policy.request.lane != request.lane {
            return Err("intent lane does not match policy lane".to_string());
        }
        if self.replay_nullifiers.contains(&request.replay_nullifier) {
            return Err("replay nullifier has already been fenced".to_string());
        }
        if self.consumed_nullifiers.contains(&request.intent_nullifier) {
            return Err("intent nullifier has already been consumed".to_string());
        }
        let sequence = self.counters.next_intent_sequence;
        let intent_id = encrypted_call_intent_id(&request, sequence);
        let intent_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-INTENT-ROOT",
            &request.public_record(),
        );
        self.replay_nullifiers
            .insert(request.replay_nullifier.clone());
        let record = EncryptedCallIntentRecord {
            intent_id: intent_id.clone(),
            sequence,
            request,
            intent_root,
            accepted_height: self.config.devnet_height,
        };
        self.encrypted_intents.insert(intent_id.clone(), record);
        self.counters.next_intent_sequence += 1;
        Ok(intent_id)
    }

    pub fn accept_pq_signer_attestation(
        &mut self,
        request: PqSignerAttestationRequest,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<String> {
        self.ensure_attestation_capacity()?;
        request.validate(&self.config)?;
        self.require_intent(&request.intent_id)?;
        if matches!(
            request.verdict,
            PqAttestationVerdict::Invalid | PqAttestationVerdict::Revoked
        ) {
            return Err("invalid or revoked attestations cannot be accepted".to_string());
        }
        let sequence = self.counters.next_attestation_sequence;
        let attestation_id = pq_signer_attestation_id(&request, sequence);
        let attestation_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-ATTESTATION-ROOT",
            &request.public_record(),
        );
        let record = PqSignerAttestationRecord {
            attestation_id: attestation_id.clone(),
            sequence,
            request,
            attestation_root,
            accepted_height: self.config.devnet_height,
        };
        self.pq_attestations.insert(attestation_id.clone(), record);
        self.counters.next_attestation_sequence += 1;
        Ok(attestation_id)
    }

    pub fn verify_dependency_proof(
        &mut self,
        request: DependencyProofRequest,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<String> {
        self.ensure_dependency_proof_capacity()?;
        request.validate()?;
        self.require_intent(&request.intent_id)?;
        if request.status != DependencyProofStatus::Verified {
            return Err("dependency proof must be verified before recording".to_string());
        }
        let sequence = self.counters.next_dependency_proof_sequence;
        let dependency_proof_id = dependency_proof_id(&request, sequence);
        let dependency_proof_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DEPENDENCY-PROOF-ROOT",
            &request.public_record(),
        );
        let record = DependencyProofRecord {
            dependency_proof_id: dependency_proof_id.clone(),
            sequence,
            request,
            dependency_proof_root,
        };
        self.dependency_proofs
            .insert(dependency_proof_id.clone(), record);
        self.counters.next_dependency_proof_sequence += 1;
        Ok(dependency_proof_id)
    }

    pub fn reserve_low_fee_sponsor(
        &mut self,
        request: LowFeeSponsorReservationRequest,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<String> {
        self.ensure_sponsor_reservation_capacity()?;
        request.validate(&self.config)?;
        self.require_intent(&request.intent_id)?;
        if self
            .consumed_nullifiers
            .contains(&request.reservation_nullifier)
        {
            return Err("reservation nullifier has already been consumed".to_string());
        }
        let sequence = self.counters.next_sponsor_reservation_sequence;
        let reservation_id = sponsor_reservation_id(&request, sequence);
        let reservation_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-SPONSOR-RESERVATION-ROOT",
            &request.public_record(),
        );
        let record = LowFeeSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            sequence,
            request,
            reservation_root,
            reserved_height: self.config.devnet_height,
        };
        self.sponsor_reservations
            .insert(reservation_id.clone(), record);
        self.counters.next_sponsor_reservation_sequence += 1;
        Ok(reservation_id)
    }

    pub fn publish_firewall_decision_batch(
        &mut self,
        request: FirewallDecisionBatchRequest,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<String> {
        self.ensure_batch_capacity()?;
        request.validate(&self.config)?;
        for intent_id in &request.intent_ids {
            self.require_intent(intent_id)?;
        }
        for attestation_id in &request.attestation_ids {
            if !self.pq_attestations.contains_key(attestation_id) {
                return Err(format!("attestation {attestation_id} is unknown"));
            }
        }
        for dependency_proof_id in &request.dependency_proof_ids {
            if !self.dependency_proofs.contains_key(dependency_proof_id) {
                return Err(format!("dependency proof {dependency_proof_id} is unknown"));
            }
        }
        for reservation_id in &request.sponsor_reservation_ids {
            if !self.sponsor_reservations.contains_key(reservation_id) {
                return Err(format!("sponsor reservation {reservation_id} is unknown"));
            }
        }
        let sequence = self.counters.next_batch_sequence;
        let batch_id = firewall_decision_batch_id(&request, sequence);
        let batch_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DECISION-BATCH-ROOT",
            &request.public_record(),
        );
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.encrypted_intents.get(intent_id) {
                self.consumed_nullifiers
                    .insert(intent.request.intent_nullifier.clone());
            }
        }
        let record = FirewallDecisionBatchRecord {
            batch_id: batch_id.clone(),
            sequence,
            request,
            batch_root,
        };
        self.decision_batches.insert(batch_id.clone(), record);
        self.counters.next_batch_sequence += 1;
        Ok(batch_id)
    }

    pub fn publish_firewall_receipt(
        &mut self,
        request: FirewallReceiptRequest,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<String> {
        self.ensure_receipt_capacity()?;
        request.validate()?;
        self.require_intent(&request.intent_id)?;
        if !self.decision_batches.contains_key(&request.batch_id) {
            return Err(format!("decision batch {} is unknown", request.batch_id));
        }
        let sequence = self.counters.next_receipt_sequence;
        let receipt_id = firewall_receipt_id(&request, sequence);
        let receipt_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-RECEIPT-ROOT",
            &request.public_record(),
        );
        let record = FirewallReceiptRecord {
            receipt_id: receipt_id.clone(),
            sequence,
            request,
            receipt_root,
        };
        self.receipts.insert(receipt_id.clone(), record);
        self.counters.next_receipt_sequence += 1;
        Ok(receipt_id)
    }

    pub fn publish_firewall_rebate(
        &mut self,
        request: FirewallRebateRequest,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<String> {
        self.ensure_rebate_capacity()?;
        request.validate()?;
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err(format!("receipt {} is unknown", request.receipt_id));
        }
        if !self
            .sponsor_reservations
            .contains_key(&request.reservation_id)
        {
            return Err(format!(
                "sponsor reservation {} is unknown",
                request.reservation_id
            ));
        }
        if self.consumed_nullifiers.contains(&request.rebate_nullifier) {
            return Err("rebate nullifier has already been consumed".to_string());
        }
        let sequence = self.counters.next_rebate_sequence;
        let rebate_id = firewall_rebate_id(&request, sequence);
        let rebate_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-REBATE-ROOT",
            &request.public_record(),
        );
        self.consumed_nullifiers
            .insert(request.rebate_nullifier.clone());
        let record = FirewallRebateRecord {
            rebate_id: rebate_id.clone(),
            sequence,
            request,
            rebate_root,
        };
        self.rebates.insert(rebate_id.clone(), record);
        self.counters.next_rebate_sequence += 1;
        Ok(rebate_id)
    }

    pub fn open_emergency_quarantine(
        &mut self,
        request: EmergencyQuarantineRequest,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<String> {
        self.ensure_quarantine_capacity()?;
        request.validate(&self.config)?;
        self.require_intent(&request.intent_id)?;
        if !self.policies.contains_key(&request.policy_id) {
            return Err(format!("policy {} is unknown", request.policy_id));
        }
        if self
            .consumed_nullifiers
            .contains(&request.quarantine_nullifier)
        {
            return Err("quarantine nullifier has already been consumed".to_string());
        }
        let sequence = self.counters.next_quarantine_sequence;
        let quarantine_id = emergency_quarantine_id(&request, sequence);
        let quarantine_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-QUARANTINE-ROOT",
            &request.public_record(),
        );
        self.consumed_nullifiers
            .insert(request.quarantine_nullifier.clone());
        let record = EmergencyQuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            sequence,
            request,
            quarantine_root,
        };
        self.quarantines.insert(quarantine_id.clone(), record);
        self.counters.next_quarantine_sequence += 1;
        Ok(quarantine_id)
    }

    pub fn roots(&self) -> Roots {
        let config_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-CONFIG-ROOT",
            &self.config.public_record(),
        );
        let counters_root = payload_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-COUNTERS-ROOT",
            &self.counters.public_record(),
        );
        let policy_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-POLICY-RECORDS",
            &self
                .policies
                .values()
                .map(ContractFirewallPolicyRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let encrypted_intent_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-INTENT-RECORDS",
            &self
                .encrypted_intents
                .values()
                .map(EncryptedCallIntentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let pq_attestation_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-ATTESTATION-RECORDS",
            &self
                .pq_attestations
                .values()
                .map(PqSignerAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let dependency_proof_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DEPENDENCY-PROOF-RECORDS",
            &self
                .dependency_proofs
                .values()
                .map(DependencyProofRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_reservation_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-SPONSOR-RESERVATION-RECORDS",
            &self
                .sponsor_reservations
                .values()
                .map(LowFeeSponsorReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let decision_batch_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DECISION-BATCH-RECORDS",
            &self
                .decision_batches
                .values()
                .map(FirewallDecisionBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-RECEIPT-RECORDS",
            &self
                .receipts
                .values()
                .map(FirewallReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-REBATE-RECORDS",
            &self
                .rebates
                .values()
                .map(FirewallRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let replay_nullifier_root = self.replay_fence_root();
        let consumed_nullifier_root = self.consumed_nullifier_root();
        let quarantine_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-QUARANTINE-RECORDS",
            &self
                .quarantines
                .values()
                .map(EmergencyQuarantineRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let public_record_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-PUBLIC-RECORDS",
            &self
                .public_records_without_state_root()
                .into_values()
                .collect::<Vec<_>>(),
        );
        let state_root = state_root_from_record(&json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_PROTOCOL_VERSION,
            "config_root": config_root,
            "counters_root": counters_root,
            "policy_root": policy_root,
            "encrypted_intent_root": encrypted_intent_root,
            "pq_attestation_root": pq_attestation_root,
            "dependency_proof_root": dependency_proof_root,
            "sponsor_reservation_root": sponsor_reservation_root,
            "decision_batch_root": decision_batch_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "replay_nullifier_root": replay_nullifier_root,
            "consumed_nullifier_root": consumed_nullifier_root,
            "quarantine_root": quarantine_root,
            "public_record_root": public_record_root,
        }));
        Roots {
            config_root,
            counters_root,
            policy_root,
            encrypted_intent_root,
            pq_attestation_root,
            dependency_proof_root,
            sponsor_reservation_root,
            decision_batch_root,
            receipt_root,
            rebate_root,
            replay_nullifier_root,
            consumed_nullifier_root,
            quarantine_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn replay_fence_root(&self) -> String {
        id_list_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-REPLAY-FENCE",
            self.replay_nullifiers.iter(),
        )
    }

    pub fn consumed_nullifier_root(&self) -> String {
        id_list_root(
            "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-CONSUMED-NULLIFIERS",
            self.consumed_nullifiers.iter(),
        )
    }

    fn public_records_without_state_root(&self) -> BTreeMap<String, Value> {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        records.insert("counters".to_string(), self.counters.public_record());
        for (policy_id, policy) in &self.policies {
            records.insert(format!("policy:{policy_id}"), policy.public_record());
        }
        for (intent_id, intent) in &self.encrypted_intents {
            records.insert(format!("intent:{intent_id}"), intent.public_record());
        }
        for (attestation_id, attestation) in &self.pq_attestations {
            records.insert(
                format!("attestation:{attestation_id}"),
                attestation.public_record(),
            );
        }
        for (dependency_proof_id, proof) in &self.dependency_proofs {
            records.insert(
                format!("dependency_proof:{dependency_proof_id}"),
                proof.public_record(),
            );
        }
        for (reservation_id, reservation) in &self.sponsor_reservations {
            records.insert(
                format!("sponsor_reservation:{reservation_id}"),
                reservation.public_record(),
            );
        }
        for (batch_id, batch) in &self.decision_batches {
            records.insert(format!("batch:{batch_id}"), batch.public_record());
        }
        for (receipt_id, receipt) in &self.receipts {
            records.insert(format!("receipt:{receipt_id}"), receipt.public_record());
        }
        for (rebate_id, rebate) in &self.rebates {
            records.insert(format!("rebate:{rebate_id}"), rebate.public_record());
        }
        for (quarantine_id, quarantine) in &self.quarantines {
            records.insert(
                format!("quarantine:{quarantine_id}"),
                quarantine.public_record(),
            );
        }
        records
    }

    fn require_intent(
        &self,
        intent_id: &str,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<&EncryptedCallIntentRecord> {
        self.encrypted_intents
            .get(intent_id)
            .ok_or_else(|| format!("intent {intent_id} is unknown"))
    }

    fn ensure_policy_capacity(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        if self.policies.len() >= self.config.max_policies {
            return Err("contract firewall policy capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_intent_capacity(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        if self.encrypted_intents.len() >= self.config.max_intents {
            return Err("encrypted call intent capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_attestation_capacity(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        if self.pq_attestations.len() >= self.config.max_attestations {
            return Err("PQ signer attestation capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_dependency_proof_capacity(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        if self.dependency_proofs.len() >= self.config.max_dependency_proofs {
            return Err("dependency proof capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_sponsor_reservation_capacity(
        &self,
    ) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("low-fee sponsor reservation capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_batch_capacity(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        if self.decision_batches.len() >= self.config.max_batches {
            return Err("firewall decision batch capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_receipt_capacity(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("firewall receipt capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_rebate_capacity(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("firewall rebate capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_quarantine_capacity(&self) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
        if self.quarantines.len() >= self.config.max_quarantines {
            return Err("emergency quarantine capacity exhausted".to_string());
        }
        Ok(())
    }
}

pub type Runtime = State;

pub fn private_l2_pq_contract_call_firewall_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_pq_contract_call_firewall_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn devnet() -> PrivateL2PqContractCallFirewallRuntimeResult<State> {
    State::devnet()
}

pub fn contract_firewall_policy_id(
    request: &ContractFirewallPolicyRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-POLICY-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn encrypted_call_intent_id(request: &EncryptedCallIntentRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-INTENT-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn pq_signer_attestation_id(request: &PqSignerAttestationRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-ATTESTATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn dependency_proof_id(request: &DependencyProofRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DEPENDENCY-PROOF-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn sponsor_reservation_id(request: &LowFeeSponsorReservationRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-SPONSOR-RESERVATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn firewall_decision_batch_id(request: &FirewallDecisionBatchRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DECISION-BATCH-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn firewall_receipt_id(request: &FirewallReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-RECEIPT-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn firewall_rebate_id(request: &FirewallRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-REBATE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn emergency_quarantine_id(request: &EmergencyQuarantineRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-QUARANTINE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn replay_fence_leaf(intent_id: &str, replay_nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-REPLAY-FENCE-LEAF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(replay_nullifier),
        ],
        32,
    )
}

pub fn nullifier_fence_leaf(kind: &str, nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-NULLIFIER-FENCE-LEAF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            Value::String(root_from_record(
                domain,
                &json!({
                    "index": index,
                    "record": record,
                }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-STATE-ROOT", record)
}

fn payload_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn id_list_root<'a, I>(domain: &str, ids: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let leaves = ids
        .enumerate()
        .map(|(index, id)| {
            Value::String(domain_hash(
                domain,
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::U64(index as u64),
                    HashPart::Str(id),
                ],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-CALL-FIREWALL-DEVNET-SAMPLE-ROOT",
        &[
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
        ],
        32,
    )
}

fn require_nonempty(field: &str, value: &str) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}

fn require_eq(
    field: &str,
    value: &str,
    expected: &str,
) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
    if value != expected {
        return Err(format!("{field} must be {expected}"));
    }
    Ok(())
}

fn require_root(field: &str, value: &str) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
    require_nonempty(field, value)
}

fn require_min(
    field: &str,
    value: u64,
    min: u64,
) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
    if value < min {
        return Err(format!("{field} must be at least {min}"));
    }
    Ok(())
}

fn require_min_usize(
    field: &str,
    value: usize,
    min: usize,
) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
    if value < min {
        return Err(format!("{field} must be at least {min}"));
    }
    Ok(())
}

fn require_min_u16(
    field: &str,
    value: u16,
    min: u16,
) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
    if value < min {
        return Err(format!("{field} must be at least {min}"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
    if value > PRIVATE_L2_PQ_CONTRACT_CALL_FIREWALL_RUNTIME_MAX_BPS {
        return Err(format!("{field} cannot exceed 10000 bps"));
    }
    Ok(())
}

fn require_height_window(start: u64, end: u64) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
    if end <= start {
        return Err("height window end must be greater than start".to_string());
    }
    Ok(())
}

fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2PqContractCallFirewallRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            return Err(format!("{field} cannot contain empty ids"));
        }
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate id {value}"));
        }
    }
    Ok(())
}
