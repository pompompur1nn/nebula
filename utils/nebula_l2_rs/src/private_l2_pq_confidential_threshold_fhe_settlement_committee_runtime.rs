use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialThresholdFheSettlementCommitteeRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_THRESHOLD_FHE_SETTLEMENT_COMMITTEE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-threshold-fhe-settlement-committee-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_THRESHOLD_FHE_SETTLEMENT_COMMITTEE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_COMMITTEE_NAMESPACE: &str =
    "private-l2-pq-confidential-threshold-fhe-settlement-committee-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PQ_FALLBACK_ATTESTATION_SUITE: &str = "Falcon-1024+SPHINCS+-SHAKE-256f";
pub const FHE_SUITE: &str = "threshold-tfhe-radix64-settlement-share-v1";
pub const KEM_SUITE: &str = "ML-KEM-1024 committee epoch envelope";
pub const COMMITTEE_EPOCH_SCHEME: &str = "committee-epoch-membership-root-v1";
pub const ENCRYPTED_SHARE_SCHEME: &str = "encrypted-settlement-share-root-v1";
pub const THRESHOLD_DECRYPT_SCHEME: &str = "threshold-decrypt-receipt-root-v1";
pub const ROTATION_SCHEME: &str = "pq-fhe-committee-rotation-root-v1";
pub const REBATE_SCHEME: &str = "low-fee-confidential-settlement-rebate-root-v1";
pub const QUARANTINE_SCHEME: &str = "stale-encrypted-share-quarantine-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "privacy-redaction-budget-root-v1";
pub const PUBLIC_SUMMARY_SCHEME: &str = "operator-safe-threshold-fhe-public-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_amounts_addresses_view_keys_decrypt_shares_or_member_secret_keys";
pub const DEVNET_HEIGHT: u64 = 1_344_128;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 720;
pub const DEFAULT_ROTATION_GRACE_BLOCKS: u64 = 144;
pub const DEFAULT_SHARE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 10_080;
pub const DEFAULT_MIN_COMMITTEE_MEMBERS: u16 = 7;
pub const DEFAULT_THRESHOLD_MEMBERS: u16 = 5;
pub const DEFAULT_MAX_COMMITTEE_MEMBERS: u16 = 31;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_FHE_SECURITY_BITS: u16 = 128;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 12;
pub const DEFAULT_MAX_REDACTIONS_PER_WINDOW: u64 = 64;
pub const DEFAULT_MAX_REDACTION_WEIGHT: u64 = 1_024;
pub const DEFAULT_DEMO_CURRENT_EPOCH: u64 = 42;
pub const MAX_COMMITTEE_EPOCHS: usize = 262_144;
pub const MAX_COMMITTEE_MEMBERS: usize = 1_048_576;
pub const MAX_MEMBER_ATTESTATIONS: usize = 1_048_576;
pub const MAX_SETTLEMENT_BATCHES: usize = 524_288;
pub const MAX_ENCRYPTED_SHARES: usize = 2_097_152;
pub const MAX_DECRYPT_RECEIPTS: usize = 1_048_576;
pub const MAX_ROTATIONS: usize = 262_144;
pub const MAX_REBATES: usize = 524_288;
pub const MAX_QUARANTINES: usize = 262_144;
pub const MAX_REDACTION_BUDGETS: usize = 262_144;
pub const MAX_PUBLIC_SUMMARIES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    Coordinator,
    CiphertextAuditor,
    FheEvaluator,
    DecryptSigner,
    RotationWitness,
    RebateSponsor,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::CiphertextAuditor => "ciphertext_auditor",
            Self::FheEvaluator => "fhe_evaluator",
            Self::DecryptSigner => "decrypt_signer",
            Self::RotationWitness => "rotation_witness",
            Self::RebateSponsor => "rebate_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Planned,
    Warmup,
    Active,
    Draining,
    Rotated,
    Paused,
    Slashed,
}

impl EpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Warmup => "warmup",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Rotated => "rotated",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_new_shares(self) -> bool {
        matches!(self, Self::Warmup | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Draft,
    Submitted,
    Accepted,
    Superseded,
    Challenged,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    BridgeWithdrawal,
    DexNetting,
    MerchantPayout,
    VaultSweep,
    LiquidityRebate,
    IncidentRecovery,
}

impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::DexNetting => "dex_netting",
            Self::MerchantPayout => "merchant_payout",
            Self::VaultSweep => "vault_sweep",
            Self::LiquidityRebate => "liquidity_rebate",
            Self::IncidentRecovery => "incident_recovery",
        }
    }

    pub fn redaction_weight(self) -> u64 {
        match self {
            Self::BridgeWithdrawal => 8,
            Self::DexNetting => 12,
            Self::MerchantPayout => 6,
            Self::VaultSweep => 16,
            Self::LiquidityRebate => 4,
            Self::IncidentRecovery => 24,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Open,
    SharesCollecting,
    ThresholdReached,
    Decrypted,
    Rebated,
    Settled,
    Disputed,
    Quarantined,
}

impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SharesCollecting => "shares_collecting",
            Self::ThresholdReached => "threshold_reached",
            Self::Decrypted => "decrypted",
            Self::Rebated => "rebated",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Rebated | Self::Settled | Self::Disputed | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    Submitted,
    Verified,
    Counted,
    Stale,
    Quarantined,
    Rejected,
}

impl ShareStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Counted => "counted",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }

    pub fn counted(self) -> bool {
        matches!(self, Self::Verified | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    ThresholdSigned,
    Published,
    Replayed,
    Rejected,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::ThresholdSigned => "threshold_signed",
            Self::Published => "published",
            Self::Replayed => "replayed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Proposed,
    Attesting,
    Queued,
    Activated,
    Superseded,
    Cancelled,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Attesting => "attesting",
            Self::Queued => "queued",
            Self::Activated => "activated",
            Self::Superseded => "superseded",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Estimated,
    Reserved,
    Credited,
    Expired,
    Cancelled,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Estimated => "estimated",
            Self::Reserved => "reserved",
            Self::Credited => "credited",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    ShareTtlExpired,
    EpochMismatch,
    DuplicateMember,
    InvalidCiphertextProof,
    MissingPqAttestation,
    PrivacyBudgetExceeded,
    RotationBoundary,
    OperatorPause,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShareTtlExpired => "share_ttl_expired",
            Self::EpochMismatch => "epoch_mismatch",
            Self::DuplicateMember => "duplicate_member",
            Self::InvalidCiphertextProof => "invalid_ciphertext_proof",
            Self::MissingPqAttestation => "missing_pq_attestation",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::RotationBoundary => "rotation_boundary",
            Self::OperatorPause => "operator_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    AmountCommitment,
    AddressGraph,
    MemberIdentity,
    DecryptShare,
    FeePath,
    RotationEvidence,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmountCommitment => "amount_commitment",
            Self::AddressGraph => "address_graph",
            Self::MemberIdentity => "member_identity",
            Self::DecryptShare => "decrypt_share",
            Self::FeePath => "fee_path",
            Self::RotationEvidence => "rotation_evidence",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub committee_namespace: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub pq_fallback_attestation_suite: String,
    pub fhe_suite: String,
    pub kem_suite: String,
    pub min_committee_members: u16,
    pub threshold_members: u16,
    pub max_committee_members: u16,
    pub min_pq_security_bits: u16,
    pub min_fhe_security_bits: u16,
    pub epoch_length_blocks: u64,
    pub rotation_grace_blocks: u64,
    pub share_ttl_blocks: u64,
    pub redaction_window_blocks: u64,
    pub max_redactions_per_window: u64,
    pub max_redaction_weight: u64,
    pub low_fee_rebate_bps: u64,
    pub privacy_boundary: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            committee_namespace: DEVNET_COMMITTEE_NAMESPACE.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            pq_fallback_attestation_suite: PQ_FALLBACK_ATTESTATION_SUITE.to_string(),
            fhe_suite: FHE_SUITE.to_string(),
            kem_suite: KEM_SUITE.to_string(),
            min_committee_members: DEFAULT_MIN_COMMITTEE_MEMBERS,
            threshold_members: DEFAULT_THRESHOLD_MEMBERS,
            max_committee_members: DEFAULT_MAX_COMMITTEE_MEMBERS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_fhe_security_bits: DEFAULT_MIN_FHE_SECURITY_BITS,
            epoch_length_blocks: DEFAULT_EPOCH_LENGTH_BLOCKS,
            rotation_grace_blocks: DEFAULT_ROTATION_GRACE_BLOCKS,
            share_ttl_blocks: DEFAULT_SHARE_TTL_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            max_redactions_per_window: DEFAULT_MAX_REDACTIONS_PER_WINDOW,
            max_redaction_weight: DEFAULT_MAX_REDACTION_WEIGHT,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.threshold_members == 0 {
            return Err("threshold_members must be positive".to_string());
        }
        if self.threshold_members < self.min_committee_members.saturating_div(2) + 1 {
            return Err("threshold_members must exceed half of min_committee_members".to_string());
        }
        if self.min_committee_members > self.max_committee_members {
            return Err("min_committee_members exceeds max_committee_members".to_string());
        }
        if self.low_fee_rebate_bps > MAX_BPS {
            return Err("low_fee_rebate_bps exceeds MAX_BPS".to_string());
        }
        if self.epoch_length_blocks <= self.rotation_grace_blocks {
            return Err("epoch_length_blocks must exceed rotation_grace_blocks".to_string());
        }
        if self.share_ttl_blocks == 0 {
            return Err("share_ttl_blocks must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "committee_namespace": self.committee_namespace,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "pq_fallback_attestation_suite": self.pq_fallback_attestation_suite,
            "fhe_suite": self.fhe_suite,
            "kem_suite": self.kem_suite,
            "min_committee_members": self.min_committee_members,
            "threshold_members": self.threshold_members,
            "max_committee_members": self.max_committee_members,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_fhe_security_bits": self.min_fhe_security_bits,
            "epoch_length_blocks": self.epoch_length_blocks,
            "rotation_grace_blocks": self.rotation_grace_blocks,
            "share_ttl_blocks": self.share_ttl_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "max_redactions_per_window": self.max_redactions_per_window,
            "max_redaction_weight": self.max_redaction_weight,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "privacy_boundary": self.privacy_boundary,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub committee_epochs: u64,
    pub committee_members: u64,
    pub member_attestations: u64,
    pub settlement_batches: u64,
    pub encrypted_settlement_shares: u64,
    pub threshold_decrypt_receipts: u64,
    pub committee_rotations: u64,
    pub low_fee_rebates: u64,
    pub quarantined_shares: u64,
    pub privacy_redaction_budgets: u64,
    pub public_summaries: u64,
    pub rejected_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_sequence": self.next_sequence,
            "committee_epochs": self.committee_epochs,
            "committee_members": self.committee_members,
            "member_attestations": self.member_attestations,
            "settlement_batches": self.settlement_batches,
            "encrypted_settlement_shares": self.encrypted_settlement_shares,
            "threshold_decrypt_receipts": self.threshold_decrypt_receipts,
            "committee_rotations": self.committee_rotations,
            "low_fee_rebates": self.low_fee_rebates,
            "quarantined_shares": self.quarantined_shares,
            "privacy_redaction_budgets": self.privacy_redaction_budgets,
            "public_summaries": self.public_summaries,
            "rejected_records": self.rejected_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub committee_epoch_root: String,
    pub committee_member_root: String,
    pub member_attestation_root: String,
    pub settlement_batch_root: String,
    pub encrypted_share_root: String,
    pub threshold_decrypt_receipt_root: String,
    pub committee_rotation_root: String,
    pub low_fee_rebate_root: String,
    pub stale_share_quarantine_root: String,
    pub privacy_redaction_budget_root: String,
    pub public_summary_root: String,
    pub event_root: String,
    pub deterministic_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: record_root("CONFIG", &config.public_record()),
            counter_root: record_root("COUNTERS", &counters.public_record()),
            committee_epoch_root: merkle_root("PRIVATE-L2-PQ-FHE-COMMITTEE-EPOCH", &[]),
            committee_member_root: merkle_root("PRIVATE-L2-PQ-FHE-COMMITTEE-MEMBER", &[]),
            member_attestation_root: merkle_root("PRIVATE-L2-PQ-FHE-MEMBER-ATTESTATION", &[]),
            settlement_batch_root: merkle_root("PRIVATE-L2-PQ-FHE-SETTLEMENT-BATCH", &[]),
            encrypted_share_root: merkle_root("PRIVATE-L2-PQ-FHE-ENCRYPTED-SHARE", &[]),
            threshold_decrypt_receipt_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-THRESHOLD-DECRYPT-RECEIPT",
                &[],
            ),
            committee_rotation_root: merkle_root("PRIVATE-L2-PQ-FHE-COMMITTEE-ROTATION", &[]),
            low_fee_rebate_root: merkle_root("PRIVATE-L2-PQ-FHE-LOW-FEE-REBATE", &[]),
            stale_share_quarantine_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-STALE-SHARE-QUARANTINE",
                &[],
            ),
            privacy_redaction_budget_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-PRIVACY-REDACTION-BUDGET",
                &[],
            ),
            public_summary_root: merkle_root("PRIVATE-L2-PQ-FHE-PUBLIC-SUMMARY", &[]),
            event_root: merkle_root("PRIVATE-L2-PQ-FHE-EVENT", &[]),
            deterministic_root: String::new(),
            state_root: String::new(),
        };
        roots.deterministic_root = deterministic_root_from_roots(&roots);
        roots.state_root = record_root("STATE", &roots.public_record_without_state_root());
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "committee_epoch_root": self.committee_epoch_root,
            "committee_member_root": self.committee_member_root,
            "member_attestation_root": self.member_attestation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "encrypted_share_root": self.encrypted_share_root,
            "threshold_decrypt_receipt_root": self.threshold_decrypt_receipt_root,
            "committee_rotation_root": self.committee_rotation_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "stale_share_quarantine_root": self.stale_share_quarantine_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "public_summary_root": self.public_summary_root,
            "event_root": self.event_root,
            "deterministic_root": self.deterministic_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignatureCommitment {
    pub scheme: String,
    pub public_key_commitment: String,
    pub transcript_hash: String,
    pub signature_commitment: String,
    pub security_bits: u16,
}

impl PqSignatureCommitment {
    pub fn demo(label: &str, security_bits: u16) -> Self {
        Self {
            scheme: PQ_ATTESTATION_SUITE.to_string(),
            public_key_commitment: tagged_hash("pq-public-key", label),
            transcript_hash: tagged_hash("pq-transcript", label),
            signature_commitment: tagged_hash("pq-signature", label),
            security_bits,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": self.scheme,
            "public_key_commitment": self.public_key_commitment,
            "transcript_hash": self.transcript_hash,
            "signature_commitment": self.signature_commitment,
            "security_bits": self.security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FheKeyShareCommitment {
    pub suite: String,
    pub evaluation_key_commitment: String,
    pub decrypt_share_key_commitment: String,
    pub key_refresh_commitment: String,
    pub security_bits: u16,
}

impl FheKeyShareCommitment {
    pub fn demo(member_id: &str) -> Self {
        Self {
            suite: FHE_SUITE.to_string(),
            evaluation_key_commitment: tagged_hash("fhe-evaluation-key", member_id),
            decrypt_share_key_commitment: tagged_hash("fhe-decrypt-share-key", member_id),
            key_refresh_commitment: tagged_hash("fhe-key-refresh", member_id),
            security_bits: DEFAULT_MIN_FHE_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "suite": self.suite,
            "evaluation_key_commitment": self.evaluation_key_commitment,
            "decrypt_share_key_commitment": self.decrypt_share_key_commitment,
            "key_refresh_commitment": self.key_refresh_commitment,
            "security_bits": self.security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_commitment: String,
    pub epoch_id: u64,
    pub roles: BTreeSet<CommitteeRole>,
    pub pq_key_commitment: PqSignatureCommitment,
    pub fhe_key_share: FheKeyShareCommitment,
    pub stake_bond_commitment: String,
    pub network_route_commitment: String,
    pub joined_height: u64,
    pub retired_height: Option<u64>,
    pub active: bool,
}

impl CommitteeMember {
    pub fn new(
        member_id: impl Into<String>,
        epoch_id: u64,
        roles: BTreeSet<CommitteeRole>,
    ) -> Self {
        let member_id = member_id.into();
        Self {
            operator_commitment: tagged_hash("operator", &member_id),
            pq_key_commitment: PqSignatureCommitment::demo(
                &member_id,
                DEFAULT_MIN_PQ_SECURITY_BITS,
            ),
            fhe_key_share: FheKeyShareCommitment::demo(&member_id),
            stake_bond_commitment: tagged_hash("stake-bond", &member_id),
            network_route_commitment: tagged_hash("network-route", &member_id),
            joined_height: DEVNET_HEIGHT,
            retired_height: None,
            active: true,
            member_id,
            epoch_id,
            roles,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "epoch_id": self.epoch_id,
            "roles": role_strings(&self.roles),
            "pq_key_commitment": self.pq_key_commitment.public_record(),
            "fhe_key_share": self.fhe_key_share.public_record(),
            "stake_bond_commitment": self.stake_bond_commitment,
            "network_route_commitment": self.network_route_commitment,
            "joined_height": self.joined_height,
            "retired_height": self.retired_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeEpoch {
    pub epoch_id: u64,
    pub status: EpochStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub activation_height: u64,
    pub threshold_members: u16,
    pub member_ids: BTreeSet<String>,
    pub membership_root: String,
    pub fhe_public_key_root: String,
    pub pq_attestation_root: String,
    pub previous_epoch_root: String,
    pub rotation_policy_root: String,
    pub low_fee_rebate_pool_commitment: String,
}

impl CommitteeEpoch {
    pub fn new(
        epoch_id: u64,
        start_height: u64,
        config: &Config,
        member_ids: BTreeSet<String>,
    ) -> Self {
        let member_records = member_ids
            .iter()
            .map(|member_id| json!({ "member_id": member_id, "epoch_id": epoch_id }))
            .collect::<Vec<_>>();
        Self {
            epoch_id,
            status: EpochStatus::Active,
            start_height,
            end_height: start_height + config.epoch_length_blocks,
            activation_height: start_height,
            threshold_members: config.threshold_members,
            membership_root: merkle_root("PRIVATE-L2-PQ-FHE-EPOCH-MEMBERSHIP", &member_records),
            fhe_public_key_root: tagged_hash("epoch-fhe-public-key-root", &epoch_id.to_string()),
            pq_attestation_root: tagged_hash("epoch-pq-attestation-root", &epoch_id.to_string()),
            previous_epoch_root: tagged_hash("previous-epoch-root", &epoch_id.to_string()),
            rotation_policy_root: tagged_hash("rotation-policy-root", &epoch_id.to_string()),
            low_fee_rebate_pool_commitment: tagged_hash("rebate-pool", &epoch_id.to_string()),
            member_ids,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "activation_height": self.activation_height,
            "threshold_members": self.threshold_members,
            "member_ids": sorted_set(&self.member_ids),
            "membership_root": self.membership_root,
            "fhe_public_key_root": self.fhe_public_key_root,
            "pq_attestation_root": self.pq_attestation_root,
            "previous_epoch_root": self.previous_epoch_root,
            "rotation_policy_root": self.rotation_policy_root,
            "low_fee_rebate_pool_commitment": self.low_fee_rebate_pool_commitment,
            "scheme": COMMITTEE_EPOCH_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMemberAttestation {
    pub attestation_id: String,
    pub member_id: String,
    pub epoch_id: u64,
    pub status: AttestationStatus,
    pub pq_signature: PqSignatureCommitment,
    pub device_quote_commitment: String,
    pub fhe_key_share_commitment: String,
    pub network_route_commitment: String,
    pub privacy_boundary_ack: String,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl PqMemberAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "member_id": self.member_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "pq_signature": self.pq_signature.public_record(),
            "device_quote_commitment": self.device_quote_commitment,
            "fhe_key_share_commitment": self.fhe_key_share_commitment,
            "network_route_commitment": self.network_route_commitment,
            "privacy_boundary_ack": self.privacy_boundary_ack,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub epoch_id: u64,
    pub lane: SettlementLane,
    pub status: SettlementBatchStatus,
    pub monero_anchor_height: u64,
    pub l2_anchor_height: u64,
    pub encrypted_input_root: String,
    pub encrypted_output_root: String,
    pub fee_commitment_root: String,
    pub nullifier_root: String,
    pub settlement_intent_root: String,
    pub share_count: u16,
    pub required_threshold: u16,
    pub privacy_budget_id: String,
    pub low_fee_rebate_id: Option<String>,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "monero_anchor_height": self.monero_anchor_height,
            "l2_anchor_height": self.l2_anchor_height,
            "encrypted_input_root": self.encrypted_input_root,
            "encrypted_output_root": self.encrypted_output_root,
            "fee_commitment_root": self.fee_commitment_root,
            "nullifier_root": self.nullifier_root,
            "settlement_intent_root": self.settlement_intent_root,
            "share_count": self.share_count,
            "required_threshold": self.required_threshold,
            "privacy_budget_id": self.privacy_budget_id,
            "low_fee_rebate_id": self.low_fee_rebate_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedSettlementShare {
    pub share_id: String,
    pub batch_id: String,
    pub epoch_id: u64,
    pub member_id: String,
    pub status: ShareStatus,
    pub ciphertext_commitment: String,
    pub ciphertext_proof_root: String,
    pub fhe_evaluation_trace_root: String,
    pub pq_attestation_id: String,
    pub share_index: u16,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl EncryptedSettlementShare {
    pub fn public_record(&self) -> Value {
        json!({
            "share_id": self.share_id,
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "member_id": self.member_id,
            "status": self.status.as_str(),
            "ciphertext_commitment": self.ciphertext_commitment,
            "ciphertext_proof_root": self.ciphertext_proof_root,
            "fhe_evaluation_trace_root": self.fhe_evaluation_trace_root,
            "pq_attestation_id": self.pq_attestation_id,
            "share_index": self.share_index,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "scheme": ENCRYPTED_SHARE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ThresholdDecryptReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub epoch_id: u64,
    pub status: ReceiptStatus,
    pub counted_share_ids: BTreeSet<String>,
    pub decrypt_transcript_root: String,
    pub plaintext_commitment_root: String,
    pub settlement_result_root: String,
    pub threshold_signature: PqSignatureCommitment,
    pub published_height: u64,
}

impl ThresholdDecryptReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "counted_share_ids": sorted_set(&self.counted_share_ids),
            "decrypt_transcript_root": self.decrypt_transcript_root,
            "plaintext_commitment_root": self.plaintext_commitment_root,
            "settlement_result_root": self.settlement_result_root,
            "threshold_signature": self.threshold_signature.public_record(),
            "published_height": self.published_height,
            "scheme": THRESHOLD_DECRYPT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeRotation {
    pub rotation_id: String,
    pub from_epoch_id: u64,
    pub to_epoch_id: u64,
    pub status: RotationStatus,
    pub departing_member_ids: BTreeSet<String>,
    pub joining_member_ids: BTreeSet<String>,
    pub carryover_member_ids: BTreeSet<String>,
    pub new_membership_root: String,
    pub key_refresh_root: String,
    pub pq_witness_root: String,
    pub queued_height: u64,
    pub activation_height: u64,
}

impl CommitteeRotation {
    pub fn public_record(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "from_epoch_id": self.from_epoch_id,
            "to_epoch_id": self.to_epoch_id,
            "status": self.status.as_str(),
            "departing_member_ids": sorted_set(&self.departing_member_ids),
            "joining_member_ids": sorted_set(&self.joining_member_ids),
            "carryover_member_ids": sorted_set(&self.carryover_member_ids),
            "new_membership_root": self.new_membership_root,
            "key_refresh_root": self.key_refresh_root,
            "pq_witness_root": self.pq_witness_root,
            "queued_height": self.queued_height,
            "activation_height": self.activation_height,
            "scheme": ROTATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSettlementRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub epoch_id: u64,
    pub status: RebateStatus,
    pub sponsor_commitment: String,
    pub fee_quote_commitment: String,
    pub rebate_amount_commitment: String,
    pub rebate_bps: u64,
    pub eligibility_root: String,
    pub credited_height: Option<u64>,
}

impl LowFeeSettlementRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "fee_quote_commitment": self.fee_quote_commitment,
            "rebate_amount_commitment": self.rebate_amount_commitment,
            "rebate_bps": self.rebate_bps,
            "eligibility_root": self.eligibility_root,
            "credited_height": self.credited_height,
            "scheme": REBATE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleShareQuarantine {
    pub quarantine_id: String,
    pub share_id: String,
    pub batch_id: String,
    pub epoch_id: u64,
    pub member_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub quarantined_height: u64,
    pub release_height: Option<u64>,
}

impl StaleShareQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "share_id": self.share_id,
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "member_id": self.member_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "quarantined_height": self.quarantined_height,
            "release_height": self.release_height,
            "scheme": QUARANTINE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub epoch_id: u64,
    pub lane: SettlementLane,
    pub scope: RedactionScope,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_redactions: u64,
    pub redactions_used: u64,
    pub max_weight: u64,
    pub weight_used: u64,
    pub redacted_field_root: String,
}

impl PrivacyRedactionBudget {
    pub fn remaining_redactions(&self) -> u64 {
        self.max_redactions.saturating_sub(self.redactions_used)
    }

    pub fn remaining_weight(&self) -> u64 {
        self.max_weight.saturating_sub(self.weight_used)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "epoch_id": self.epoch_id,
            "lane": self.lane.as_str(),
            "scope": self.scope.as_str(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_redactions": self.max_redactions,
            "redactions_used": self.redactions_used,
            "remaining_redactions": self.remaining_redactions(),
            "max_weight": self.max_weight,
            "weight_used": self.weight_used,
            "remaining_weight": self.remaining_weight(),
            "redacted_field_root": self.redacted_field_root,
            "scheme": REDACTION_BUDGET_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicSummary {
    pub summary_id: String,
    pub epoch_id: u64,
    pub active_committee_members: u16,
    pub threshold_members: u16,
    pub accepted_attestations: u64,
    pub counted_shares: u64,
    pub quarantined_shares: u64,
    pub settled_batches: u64,
    pub rebate_bps: u64,
    pub privacy_budget_remaining_weight: u64,
    pub deterministic_root: String,
}

impl PublicSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "epoch_id": self.epoch_id,
            "active_committee_members": self.active_committee_members,
            "threshold_members": self.threshold_members,
            "accepted_attestations": self.accepted_attestations,
            "counted_shares": self.counted_shares,
            "quarantined_shares": self.quarantined_shares,
            "settled_batches": self.settled_batches,
            "rebate_bps": self.rebate_bps,
            "privacy_budget_remaining_weight": self.privacy_budget_remaining_weight,
            "deterministic_root": self.deterministic_root,
            "scheme": PUBLIC_SUMMARY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_epoch_id: u64,
    pub committee_epochs: BTreeMap<u64, CommitteeEpoch>,
    pub committee_members: BTreeMap<String, CommitteeMember>,
    pub member_attestations: BTreeMap<String, PqMemberAttestation>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub encrypted_settlement_shares: BTreeMap<String, EncryptedSettlementShare>,
    pub threshold_decrypt_receipts: BTreeMap<String, ThresholdDecryptReceipt>,
    pub committee_rotations: BTreeMap<String, CommitteeRotation>,
    pub low_fee_rebates: BTreeMap<String, LowFeeSettlementRebate>,
    pub stale_share_quarantines: BTreeMap<String, StaleShareQuarantine>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub public_summaries: BTreeMap<String, PublicSummary>,
    pub event_log: Vec<Value>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_epoch_id: 0,
            committee_epochs: BTreeMap::new(),
            committee_members: BTreeMap::new(),
            member_attestations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            encrypted_settlement_shares: BTreeMap::new(),
            threshold_decrypt_receipts: BTreeMap::new(),
            committee_rotations: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            stale_share_quarantines: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
            event_log: Vec::new(),
        })
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("devnet config validates")
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.install_demo_epoch();
        state.install_demo_settlement();
        state.install_demo_rotation();
        state.install_demo_summary();
        state
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: record_root("CONFIG", &self.config.public_record()),
            counter_root: record_root("COUNTERS", &self.counters.public_record()),
            committee_epoch_root: map_root(
                "PRIVATE-L2-PQ-FHE-COMMITTEE-EPOCH",
                &self.committee_epochs,
            ),
            committee_member_root: map_root(
                "PRIVATE-L2-PQ-FHE-COMMITTEE-MEMBER",
                &self.committee_members,
            ),
            member_attestation_root: map_root(
                "PRIVATE-L2-PQ-FHE-MEMBER-ATTESTATION",
                &self.member_attestations,
            ),
            settlement_batch_root: map_root(
                "PRIVATE-L2-PQ-FHE-SETTLEMENT-BATCH",
                &self.settlement_batches,
            ),
            encrypted_share_root: map_root(
                "PRIVATE-L2-PQ-FHE-ENCRYPTED-SHARE",
                &self.encrypted_settlement_shares,
            ),
            threshold_decrypt_receipt_root: map_root(
                "PRIVATE-L2-PQ-FHE-THRESHOLD-DECRYPT-RECEIPT",
                &self.threshold_decrypt_receipts,
            ),
            committee_rotation_root: map_root(
                "PRIVATE-L2-PQ-FHE-COMMITTEE-ROTATION",
                &self.committee_rotations,
            ),
            low_fee_rebate_root: map_root(
                "PRIVATE-L2-PQ-FHE-LOW-FEE-REBATE",
                &self.low_fee_rebates,
            ),
            stale_share_quarantine_root: map_root(
                "PRIVATE-L2-PQ-FHE-STALE-SHARE-QUARANTINE",
                &self.stale_share_quarantines,
            ),
            privacy_redaction_budget_root: map_root(
                "PRIVATE-L2-PQ-FHE-PRIVACY-REDACTION-BUDGET",
                &self.privacy_redaction_budgets,
            ),
            public_summary_root: map_root(
                "PRIVATE-L2-PQ-FHE-PUBLIC-SUMMARY",
                &self.public_summaries,
            ),
            event_root: merkle_root("PRIVATE-L2-PQ-FHE-EVENT", &self.event_log),
            deterministic_root: String::new(),
            state_root: String::new(),
        };
        roots.deterministic_root = deterministic_root_from_roots(&roots);
        roots.state_root = record_root("STATE", &roots.public_record_without_state_root());
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "current_epoch_id": self.current_epoch_id,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "privacy_boundary": self.config.privacy_boundary,
            "fixtures": {
                "devnet_height": DEVNET_HEIGHT,
                "demo_current_epoch": DEFAULT_DEMO_CURRENT_EPOCH,
            },
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn install_demo_epoch(&mut self) {
        let epoch_id = DEFAULT_DEMO_CURRENT_EPOCH;
        self.current_epoch_id = epoch_id;
        let mut member_ids = BTreeSet::new();
        for index in 0..self.config.min_committee_members {
            let member_id = format!("fhe-committee-{epoch_id}-member-{index:02}");
            member_ids.insert(member_id.clone());
            let roles = demo_roles(index);
            let member = CommitteeMember::new(member_id.clone(), epoch_id, roles);
            self.committee_members.insert(member_id.clone(), member);
            let attestation_id = format!("pq-attestation-{epoch_id}-{index:02}");
            let attestation = PqMemberAttestation {
                attestation_id: attestation_id.clone(),
                member_id: member_id.clone(),
                epoch_id,
                status: AttestationStatus::Accepted,
                pq_signature: PqSignatureCommitment::demo(
                    &attestation_id,
                    DEFAULT_MIN_PQ_SECURITY_BITS,
                ),
                device_quote_commitment: tagged_hash("device-quote", &member_id),
                fhe_key_share_commitment: tagged_hash("fhe-share-commitment", &member_id),
                network_route_commitment: tagged_hash("attested-route", &member_id),
                privacy_boundary_ack: tagged_hash("privacy-boundary-ack", &member_id),
                issued_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + self.config.epoch_length_blocks,
            };
            self.member_attestations.insert(attestation_id, attestation);
        }
        let epoch = CommitteeEpoch::new(epoch_id, DEVNET_HEIGHT, &self.config, member_ids);
        self.committee_epochs.insert(epoch_id, epoch);
        self.recount();
        self.record_event("demo_epoch_installed", json!({ "epoch_id": epoch_id }));
    }

    fn install_demo_settlement(&mut self) {
        let epoch_id = self.current_epoch_id;
        let batch_id = "settlement-batch-demo-0001".to_string();
        let budget_id = "redaction-budget-demo-0001".to_string();
        let rebate_id = "rebate-demo-0001".to_string();
        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            epoch_id,
            lane: SettlementLane::BridgeWithdrawal,
            scope: RedactionScope::DecryptShare,
            window_start_height: DEVNET_HEIGHT,
            window_end_height: DEVNET_HEIGHT + self.config.redaction_window_blocks,
            max_redactions: self.config.max_redactions_per_window,
            redactions_used: 3,
            max_weight: self.config.max_redaction_weight,
            weight_used: 24,
            redacted_field_root: tagged_hash("redacted-field-root", &budget_id),
        };
        self.privacy_redaction_budgets
            .insert(budget_id.clone(), budget);

        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            epoch_id,
            lane: SettlementLane::BridgeWithdrawal,
            status: SettlementBatchStatus::Rebated,
            monero_anchor_height: DEVNET_HEIGHT - 32,
            l2_anchor_height: DEVNET_HEIGHT,
            encrypted_input_root: tagged_hash("encrypted-input-root", &batch_id),
            encrypted_output_root: tagged_hash("encrypted-output-root", &batch_id),
            fee_commitment_root: tagged_hash("fee-commitment-root", &batch_id),
            nullifier_root: tagged_hash("nullifier-root", &batch_id),
            settlement_intent_root: tagged_hash("settlement-intent-root", &batch_id),
            share_count: self.config.threshold_members,
            required_threshold: self.config.threshold_members,
            privacy_budget_id: budget_id,
            low_fee_rebate_id: Some(rebate_id.clone()),
        };
        self.settlement_batches.insert(batch_id.clone(), batch);

        let mut counted_share_ids = BTreeSet::new();
        for index in 0..self.config.threshold_members {
            let member_id = format!("fhe-committee-{epoch_id}-member-{index:02}");
            let share_id = format!("encrypted-share-demo-{index:02}");
            counted_share_ids.insert(share_id.clone());
            let share = EncryptedSettlementShare {
                share_id: share_id.clone(),
                batch_id: batch_id.clone(),
                epoch_id,
                member_id: member_id.clone(),
                status: ShareStatus::Counted,
                ciphertext_commitment: tagged_hash("ciphertext-share", &share_id),
                ciphertext_proof_root: tagged_hash("ciphertext-proof", &share_id),
                fhe_evaluation_trace_root: tagged_hash("fhe-evaluation-trace", &share_id),
                pq_attestation_id: format!("pq-attestation-{epoch_id}-{index:02}"),
                share_index: index,
                submitted_height: DEVNET_HEIGHT + index as u64,
                expires_height: DEVNET_HEIGHT + self.config.share_ttl_blocks,
            };
            self.encrypted_settlement_shares.insert(share_id, share);
        }

        let stale_share_id = "encrypted-share-demo-stale".to_string();
        self.encrypted_settlement_shares.insert(
            stale_share_id.clone(),
            EncryptedSettlementShare {
                share_id: stale_share_id.clone(),
                batch_id: batch_id.clone(),
                epoch_id,
                member_id: format!("fhe-committee-{epoch_id}-member-06"),
                status: ShareStatus::Quarantined,
                ciphertext_commitment: tagged_hash("ciphertext-share", &stale_share_id),
                ciphertext_proof_root: tagged_hash("ciphertext-proof", &stale_share_id),
                fhe_evaluation_trace_root: tagged_hash("fhe-evaluation-trace", &stale_share_id),
                pq_attestation_id: format!("pq-attestation-{epoch_id}-06"),
                share_index: 6,
                submitted_height: DEVNET_HEIGHT - self.config.share_ttl_blocks - 1,
                expires_height: DEVNET_HEIGHT - 1,
            },
        );
        let quarantine = StaleShareQuarantine {
            quarantine_id: "quarantine-demo-0001".to_string(),
            share_id: stale_share_id,
            batch_id: batch_id.clone(),
            epoch_id,
            member_id: format!("fhe-committee-{epoch_id}-member-06"),
            reason: QuarantineReason::ShareTtlExpired,
            evidence_root: tagged_hash("quarantine-evidence", &batch_id),
            quarantined_height: DEVNET_HEIGHT,
            release_height: Some(DEVNET_HEIGHT + self.config.rotation_grace_blocks),
        };
        self.stale_share_quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine);

        let receipt = ThresholdDecryptReceipt {
            receipt_id: "threshold-decrypt-receipt-demo-0001".to_string(),
            batch_id: batch_id.clone(),
            epoch_id,
            status: ReceiptStatus::Published,
            counted_share_ids,
            decrypt_transcript_root: tagged_hash("decrypt-transcript", &batch_id),
            plaintext_commitment_root: tagged_hash("plaintext-commitment", &batch_id),
            settlement_result_root: tagged_hash("settlement-result", &batch_id),
            threshold_signature: PqSignatureCommitment::demo(
                "threshold-decrypt-receipt-demo-0001",
                DEFAULT_MIN_PQ_SECURITY_BITS,
            ),
            published_height: DEVNET_HEIGHT + self.config.threshold_members as u64,
        };
        self.threshold_decrypt_receipts
            .insert(receipt.receipt_id.clone(), receipt);

        let rebate = LowFeeSettlementRebate {
            rebate_id: rebate_id.clone(),
            batch_id: batch_id.clone(),
            epoch_id,
            status: RebateStatus::Credited,
            sponsor_commitment: tagged_hash("rebate-sponsor", &rebate_id),
            fee_quote_commitment: tagged_hash("fee-quote", &rebate_id),
            rebate_amount_commitment: tagged_hash("rebate-amount", &rebate_id),
            rebate_bps: self.config.low_fee_rebate_bps,
            eligibility_root: tagged_hash("rebate-eligibility", &rebate_id),
            credited_height: Some(DEVNET_HEIGHT + self.config.threshold_members as u64 + 1),
        };
        self.low_fee_rebates.insert(rebate_id, rebate);
        self.recount();
        self.record_event("demo_settlement_installed", json!({ "batch_id": batch_id }));
    }

    fn install_demo_rotation(&mut self) {
        let from_epoch_id = self.current_epoch_id;
        let to_epoch_id = from_epoch_id + 1;
        let departing = BTreeSet::from([format!("fhe-committee-{from_epoch_id}-member-06")]);
        let joining = BTreeSet::from([format!("fhe-committee-{to_epoch_id}-member-00")]);
        let carryover = self
            .committee_epochs
            .get(&from_epoch_id)
            .map(|epoch| {
                epoch
                    .member_ids
                    .iter()
                    .filter(|member_id| !departing.contains(*member_id))
                    .cloned()
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let rotation_id = "committee-rotation-demo-0001".to_string();
        let membership_records = joining
            .iter()
            .chain(carryover.iter())
            .map(|member_id| json!({ "member_id": member_id, "epoch_id": to_epoch_id }))
            .collect::<Vec<_>>();
        let rotation = CommitteeRotation {
            rotation_id: rotation_id.clone(),
            from_epoch_id,
            to_epoch_id,
            status: RotationStatus::Queued,
            departing_member_ids: departing,
            joining_member_ids: joining,
            carryover_member_ids: carryover,
            new_membership_root: merkle_root(
                "PRIVATE-L2-PQ-FHE-ROTATION-NEW-MEMBERSHIP",
                &membership_records,
            ),
            key_refresh_root: tagged_hash("rotation-key-refresh", &rotation_id),
            pq_witness_root: tagged_hash("rotation-pq-witness", &rotation_id),
            queued_height: DEVNET_HEIGHT + self.config.rotation_grace_blocks,
            activation_height: DEVNET_HEIGHT + self.config.epoch_length_blocks,
        };
        self.committee_rotations
            .insert(rotation_id.clone(), rotation);
        self.recount();
        self.record_event(
            "demo_rotation_installed",
            json!({ "rotation_id": rotation_id }),
        );
    }

    fn install_demo_summary(&mut self) {
        let roots = self.roots();
        let summary = PublicSummary {
            summary_id: "public-summary-demo-0001".to_string(),
            epoch_id: self.current_epoch_id,
            active_committee_members: self
                .committee_members
                .values()
                .filter(|member| member.active && member.epoch_id == self.current_epoch_id)
                .count() as u16,
            threshold_members: self.config.threshold_members,
            accepted_attestations: self
                .member_attestations
                .values()
                .filter(|attestation| attestation.status.accepted())
                .count() as u64,
            counted_shares: self
                .encrypted_settlement_shares
                .values()
                .filter(|share| share.status.counted())
                .count() as u64,
            quarantined_shares: self.stale_share_quarantines.len() as u64,
            settled_batches: self
                .settlement_batches
                .values()
                .filter(|batch| batch.status.terminal())
                .count() as u64,
            rebate_bps: self.config.low_fee_rebate_bps,
            privacy_budget_remaining_weight: self
                .privacy_redaction_budgets
                .values()
                .map(PrivacyRedactionBudget::remaining_weight)
                .sum(),
            deterministic_root: roots.deterministic_root,
        };
        self.public_summaries
            .insert(summary.summary_id.clone(), summary);
        self.recount();
        self.record_event(
            "demo_public_summary_installed",
            json!({ "summary_id": "public-summary-demo-0001" }),
        );
    }

    fn recount(&mut self) {
        self.counters.committee_epochs = self.committee_epochs.len() as u64;
        self.counters.committee_members = self.committee_members.len() as u64;
        self.counters.member_attestations = self.member_attestations.len() as u64;
        self.counters.settlement_batches = self.settlement_batches.len() as u64;
        self.counters.encrypted_settlement_shares = self.encrypted_settlement_shares.len() as u64;
        self.counters.threshold_decrypt_receipts = self.threshold_decrypt_receipts.len() as u64;
        self.counters.committee_rotations = self.committee_rotations.len() as u64;
        self.counters.low_fee_rebates = self.low_fee_rebates.len() as u64;
        self.counters.quarantined_shares = self.stale_share_quarantines.len() as u64;
        self.counters.privacy_redaction_budgets = self.privacy_redaction_budgets.len() as u64;
        self.counters.public_summaries = self.public_summaries.len() as u64;
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
    }

    fn record_event(&mut self, kind: &str, payload: Value) {
        let event = json!({
            "sequence": self.event_log.len() as u64,
            "kind": kind,
            "payload_root": record_root("EVENT-PAYLOAD", &payload),
        });
        self.event_log.push(event);
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

fn deterministic_root_from_roots(roots: &Roots) -> String {
    let leaves = vec![
        json!({ "name": "config", "root": roots.config_root }),
        json!({ "name": "counters", "root": roots.counter_root }),
        json!({ "name": "committee_epochs", "root": roots.committee_epoch_root }),
        json!({ "name": "committee_members", "root": roots.committee_member_root }),
        json!({ "name": "member_attestations", "root": roots.member_attestation_root }),
        json!({ "name": "settlement_batches", "root": roots.settlement_batch_root }),
        json!({ "name": "encrypted_shares", "root": roots.encrypted_share_root }),
        json!({
            "name": "threshold_decrypt_receipts",
            "root": roots.threshold_decrypt_receipt_root
        }),
        json!({ "name": "committee_rotations", "root": roots.committee_rotation_root }),
        json!({ "name": "low_fee_rebates", "root": roots.low_fee_rebate_root }),
        json!({
            "name": "stale_share_quarantines",
            "root": roots.stale_share_quarantine_root
        }),
        json!({
            "name": "privacy_redaction_budgets",
            "root": roots.privacy_redaction_budget_root
        }),
        json!({ "name": "public_summaries", "root": roots.public_summary_root }),
        json!({ "name": "events", "root": roots.event_root }),
    ];
    merkle_root("PRIVATE-L2-PQ-FHE-DETERMINISTIC-ROOT", &leaves)
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-FHE-{kind}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn map_root<T: PublicRecord>(domain: &str, records: &BTreeMap<impl Ord, T>) -> String {
    let leaves = records
        .values()
        .map(PublicRecord::public_record_value)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn tagged_hash(tag: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-TAGGED",
        &[HashPart::Str(tag), HashPart::Str(label)],
        32,
    )
}

fn sorted_set(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}

fn role_strings(values: &BTreeSet<CommitteeRole>) -> Vec<&'static str> {
    values.iter().map(|role| role.as_str()).collect()
}

fn demo_roles(index: u16) -> BTreeSet<CommitteeRole> {
    let mut roles = BTreeSet::from([CommitteeRole::DecryptSigner, CommitteeRole::FheEvaluator]);
    if index == 0 {
        roles.insert(CommitteeRole::Coordinator);
    }
    if index % 2 == 0 {
        roles.insert(CommitteeRole::CiphertextAuditor);
    }
    if index % 3 == 0 {
        roles.insert(CommitteeRole::RotationWitness);
    }
    if index % 5 == 0 {
        roles.insert(CommitteeRole::RebateSponsor);
    }
    roles
}

trait PublicRecord {
    fn public_record_value(&self) -> Value;
}

impl PublicRecord for CommitteeEpoch {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for CommitteeMember {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PqMemberAttestation {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for SettlementBatch {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for EncryptedSettlementShare {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for ThresholdDecryptReceipt {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for CommitteeRotation {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for LowFeeSettlementRebate {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for StaleShareQuarantine {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PrivacyRedactionBudget {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PublicSummary {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
