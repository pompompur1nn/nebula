use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_VIEWKEY_SELECTIVE_DISCLOSURE_ORACLE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-viewkey-selective-disclosure-oracle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_VIEWKEY_SELECTIVE_DISCLOSURE_ORACLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_BRIDGE_ID: &str =
    "monero-l2-pq-private-viewkey-selective-disclosure-oracle-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_AUDIT_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_HEIGHT: u64 = 912_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUDIT_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-viewkey-selective-disclosure-v1";
pub const VIEWKEY_POLICY_SCHEME: &str =
    "selective-monero-viewkey-selective-disclosure-oracle-policy-root-v1";
pub const ENCRYPTED_GRANT_SCHEME: &str = "ml-kem-sealed-audit-grant-root-v1";
pub const AUDITOR_ATTESTATION_SCHEME: &str = "pq-auditor-attestation-root-v1";
pub const DISCLOSURE_BATCH_SCHEME: &str = "private-disclosure-batch-root-v1";
pub const VIEW_TAG_COMMITMENT_SCHEME: &str = "monero-view-tag-commitment-sync-root-v1";
pub const AUDIT_RECEIPT_SCHEME: &str = "private-viewkey-selective-disclosure-receipt-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str =
    "viewkey-selective-disclosure-oracle-low-fee-rebate-root-v1";
pub const AUDITOR_SLASHING_SCHEME: &str =
    "viewkey-selective-disclosure-oracle-auditor-slashing-root-v1";
pub const REPLAY_DOMAIN: &str =
    "nebula-monero-l2-pq-private-viewkey-selective-disclosure-oracle-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_POLICY_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_GRANT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_VIEW_TAG_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 32_768;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_AUDITOR_STAKE: u64 = 5_000_000;
pub const DEFAULT_MIN_AUDITOR_WEIGHT: u64 = 2;
pub const DEFAULT_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_FAST_FEE_BPS: u64 = 8;
pub const DEFAULT_DEFI_FEE_BPS: u64 = 6;
pub const DEFAULT_TOKEN_FEE_BPS: u64 = 5;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_REBATE_BPS: u64 = 4;
pub const DEFAULT_SLASH_INVALID_BPS: u64 = 2_500;
pub const DEFAULT_SLASH_STALE_BPS: u64 = 900;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 512;
pub const MAX_POLICIES: usize = 1_048_576;
pub const MAX_GRANTS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_DISCLOSURE_BATCHES: usize = 524_288;
pub const MAX_VIEW_TAG_COMMITMENTS: usize = 2_097_152;
pub const MAX_RECEIPTS: usize = 4_194_304;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_SLASHINGS: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditScope {
    ViewTagsOnly,
    IncomingOutputs,
    OutgoingKeyImages,
    ReserveProof,
    DefiPosition,
    TokenBalance,
    ContractEvent,
    ComplianceWindow,
}

impl AuditScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagsOnly => "view_tags_only",
            Self::IncomingOutputs => "incoming_outputs",
            Self::OutgoingKeyImages => "outgoing_key_images",
            Self::ReserveProof => "reserve_proof",
            Self::DefiPosition => "defi_position",
            Self::TokenBalance => "token_balance",
            Self::ContractEvent => "contract_event",
            Self::ComplianceWindow => "compliance_window",
        }
    }

    pub fn requires_contract_lane(self) -> bool {
        matches!(
            self,
            Self::DefiPosition | Self::TokenBalance | Self::ContractEvent
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLane {
    LowFee,
    Fast,
    Defi,
    Token,
    SmartContract,
    Emergency,
}

impl AuditLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Fast => "fast",
            Self::Defi => "defi",
            Self::Token => "token",
            Self::SmartContract => "smart_contract",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_bps,
            Self::Fast | Self::Emergency => config.fast_fee_bps,
            Self::Defi => config.defi_fee_bps,
            Self::Token => config.token_fee_bps,
            Self::SmartContract => config.max_user_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::SmartContract => 880,
            Self::Defi => 850,
            Self::Token => 790,
            Self::LowFee => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Drafted,
    Registered,
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Submitted,
    PolicyLinked,
    Attested,
    Batched,
    Receipted,
    Revoked,
    Rejected,
    Expired,
    Slashed,
}

impl GrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::PolicyLinked => "policy_linked",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::Receipted => "receipted",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::PolicyLinked | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    Superseded,
    Rejected,
    Stale,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakQuorum => "weak_quorum",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Stale => "stale",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    Anchored,
    Receipted,
    Disputed,
    Finalized,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Anchored => "anchored",
            Self::Receipted => "receipted",
            Self::Disputed => "disputed",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTagStatus {
    Synced,
    Linked,
    Batched,
    Receipted,
    Expired,
}

impl ViewTagStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Linked => "linked",
            Self::Batched => "batched",
            Self::Receipted => "receipted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    GrantAccepted,
    DisclosureBuilt,
    ViewTagSynced,
    AuditCompleted,
    RebateIssued,
    AuditorSlashed,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GrantAccepted => "grant_accepted",
            Self::DisclosureBuilt => "disclosure_built",
            Self::ViewTagSynced => "view_tag_synced",
            Self::AuditCompleted => "audit_completed",
            Self::RebateIssued => "rebate_issued",
            Self::AuditorSlashed => "auditor_slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Issued,
    Settled,
    Voided,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Issued => "issued",
            Self::Settled => "settled",
            Self::Voided => "voided",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidPqSignature,
    InvalidDisclosureRoot,
    StaleAttestation,
    PolicyMismatch,
    ViewTagEquivocation,
    PrivacySetTooSmall,
    FeeOvercharge,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::InvalidDisclosureRoot => "invalid_disclosure_root",
            Self::StaleAttestation => "stale_attestation",
            Self::PolicyMismatch => "policy_mismatch",
            Self::ViewTagEquivocation => "view_tag_equivocation",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::FeeOvercharge => "fee_overcharge",
        }
    }

    pub fn stale(self) -> bool {
        matches!(self, Self::StaleAttestation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub bridge_id: String,
    pub fee_asset_id: String,
    pub audit_asset_id: String,
    pub hash_suite: String,
    pub pq_audit_suite: String,
    pub policy_scheme: String,
    pub grant_scheme: String,
    pub attestation_scheme: String,
    pub disclosure_batch_scheme: String,
    pub view_tag_commitment_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub slashing_scheme: String,
    pub replay_domain: String,
    pub policy_ttl_blocks: u64,
    pub grant_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub view_tag_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_auditor_stake: u64,
    pub min_auditor_weight: u64,
    pub attestation_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub defi_fee_bps: u64,
    pub token_fee_bps: u64,
    pub low_fee_bps: u64,
    pub rebate_bps: u64,
    pub slash_invalid_bps: u64,
    pub slash_stale_bps: u64,
    pub max_batch_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            audit_asset_id: DEVNET_AUDIT_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_audit_suite: PQ_AUDIT_SUITE.to_string(),
            policy_scheme: VIEWKEY_POLICY_SCHEME.to_string(),
            grant_scheme: ENCRYPTED_GRANT_SCHEME.to_string(),
            attestation_scheme: AUDITOR_ATTESTATION_SCHEME.to_string(),
            disclosure_batch_scheme: DISCLOSURE_BATCH_SCHEME.to_string(),
            view_tag_commitment_scheme: VIEW_TAG_COMMITMENT_SCHEME.to_string(),
            receipt_scheme: AUDIT_RECEIPT_SCHEME.to_string(),
            rebate_scheme: LOW_FEE_REBATE_SCHEME.to_string(),
            slashing_scheme: AUDITOR_SLASHING_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            policy_ttl_blocks: DEFAULT_POLICY_TTL_BLOCKS,
            grant_ttl_blocks: DEFAULT_GRANT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            view_tag_ttl_blocks: DEFAULT_VIEW_TAG_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_auditor_stake: DEFAULT_MIN_AUDITOR_STAKE,
            min_auditor_weight: DEFAULT_MIN_AUDITOR_WEIGHT,
            attestation_quorum_bps: DEFAULT_ATTESTATION_QUORUM_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            fast_fee_bps: DEFAULT_FAST_FEE_BPS,
            defi_fee_bps: DEFAULT_DEFI_FEE_BPS,
            token_fee_bps: DEFAULT_TOKEN_FEE_BPS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_invalid_bps: DEFAULT_SLASH_INVALID_BPS,
            slash_stale_bps: DEFAULT_SLASH_STALE_BPS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub policies: usize,
    pub grants: usize,
    pub attestations: usize,
    pub disclosure_batches: usize,
    pub view_tag_commitments: usize,
    pub receipts: usize,
    pub rebates: usize,
    pub slashings: usize,
    pub public_records: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub policy_root: String,
    pub grant_root: String,
    pub attestation_root: String,
    pub disclosure_batch_root: String,
    pub view_tag_commitment_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub slashing_root: String,
    pub auditor_index_root: String,
    pub policy_owner_index_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditPolicy {
    pub policy_id: String,
    pub sequence: u64,
    pub owner_id: String,
    pub auditor_set_id: String,
    pub permitted_scopes: BTreeSet<AuditScope>,
    pub lane: AuditLane,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub viewkey_commitment_root: String,
    pub disclosure_constraint_root: String,
    pub contract_scope_root: String,
    pub token_scope_root: String,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: PolicyStatus,
}

impl AuditPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "sequence": self.sequence,
            "owner_id": self.owner_id,
            "auditor_set_id": self.auditor_set_id,
            "permitted_scopes": self.permitted_scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "lane": self.lane.as_str(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "pq_security_bits": self.pq_security_bits,
            "viewkey_commitment_root": self.viewkey_commitment_root,
            "disclosure_constraint_root": self.disclosure_constraint_root,
            "contract_scope_root": self.contract_scope_root,
            "token_scope_root": self.token_scope_root,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditGrant {
    pub grant_id: String,
    pub sequence: u64,
    pub policy_id: String,
    pub owner_id: String,
    pub auditor_id: String,
    pub lane: AuditLane,
    pub scopes: BTreeSet<AuditScope>,
    pub encrypted_viewkey_payload_root: String,
    pub pq_ciphertext_root: String,
    pub grant_nullifier: String,
    pub fee_commitment_piconero: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: GrantStatus,
}

impl AuditGrant {
    pub fn public_record(&self) -> Value {
        json!({
            "grant_id": self.grant_id,
            "sequence": self.sequence,
            "policy_id": self.policy_id,
            "owner_id": self.owner_id,
            "auditor_id": self.auditor_id,
            "lane": self.lane.as_str(),
            "scopes": self.scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "encrypted_viewkey_payload_root": self.encrypted_viewkey_payload_root,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "grant_nullifier": self.grant_nullifier,
            "fee_commitment_piconero": self.fee_commitment_piconero,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditorAttestation {
    pub attestation_id: String,
    pub sequence: u64,
    pub grant_id: String,
    pub policy_id: String,
    pub auditor_id: String,
    pub auditor_weight: u64,
    pub auditor_stake: u64,
    pub observed_monero_height: u64,
    pub view_tag_commitment_root: String,
    pub disclosure_root: String,
    pub token_delta_root: String,
    pub contract_event_root: String,
    pub pq_signature_root: String,
    pub fee_claim_piconero: u64,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: AttestationStatus,
}

impl AuditorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "grant_id": self.grant_id,
            "policy_id": self.policy_id,
            "auditor_id": self.auditor_id,
            "auditor_weight": self.auditor_weight,
            "auditor_stake": self.auditor_stake,
            "observed_monero_height": self.observed_monero_height,
            "view_tag_commitment_root": self.view_tag_commitment_root,
            "disclosure_root": self.disclosure_root,
            "token_delta_root": self.token_delta_root,
            "contract_event_root": self.contract_event_root,
            "pq_signature_root": self.pq_signature_root,
            "fee_claim_piconero": self.fee_claim_piconero,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosureBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub builder_id: String,
    pub lane: AuditLane,
    pub grant_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub view_tag_commitment_ids: Vec<String>,
    pub disclosure_batch_root: String,
    pub encrypted_disclosure_bundle_root: String,
    pub defi_state_delta_root: String,
    pub token_state_delta_root: String,
    pub contract_receipt_root: String,
    pub total_fee_piconero: u64,
    pub rebate_commitment_root: String,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: BatchStatus,
}

impl DisclosureBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "builder_id": self.builder_id,
            "lane": self.lane.as_str(),
            "grant_ids": self.grant_ids,
            "attestation_ids": self.attestation_ids,
            "view_tag_commitment_ids": self.view_tag_commitment_ids,
            "disclosure_batch_root": self.disclosure_batch_root,
            "encrypted_disclosure_bundle_root": self.encrypted_disclosure_bundle_root,
            "defi_state_delta_root": self.defi_state_delta_root,
            "token_state_delta_root": self.token_state_delta_root,
            "contract_receipt_root": self.contract_receipt_root,
            "total_fee_piconero": self.total_fee_piconero,
            "rebate_commitment_root": self.rebate_commitment_root,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewTagCommitment {
    pub view_tag_commitment_id: String,
    pub sequence: u64,
    pub grant_id: String,
    pub wallet_id: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub view_tag_root: String,
    pub output_commitment_root: String,
    pub key_image_hint_root: String,
    pub decoy_set_root: String,
    pub privacy_set_size: u64,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: ViewTagStatus,
}

impl ViewTagCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "view_tag_commitment_id": self.view_tag_commitment_id,
            "sequence": self.sequence,
            "grant_id": self.grant_id,
            "wallet_id": self.wallet_id,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "view_tag_root": self.view_tag_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_hint_root": self.key_image_hint_root,
            "decoy_set_root": self.decoy_set_root,
            "privacy_set_size": self.privacy_set_size,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub kind: ReceiptKind,
    pub subject_id: String,
    pub batch_id: Option<String>,
    pub grant_id: Option<String>,
    pub auditor_id: Option<String>,
    pub receipt_root: String,
    pub state_root_after: String,
    pub fee_paid_piconero: u64,
    pub rebate_id: Option<String>,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
}

impl AuditReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "batch_id": self.batch_id,
            "grant_id": self.grant_id,
            "auditor_id": self.auditor_id,
            "receipt_root": self.receipt_root,
            "state_root_after": self.state_root_after,
            "fee_paid_piconero": self.fee_paid_piconero,
            "rebate_id": self.rebate_id,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub sequence: u64,
    pub grant_id: String,
    pub batch_id: String,
    pub recipient_id: String,
    pub lane: AuditLane,
    pub original_fee_piconero: u64,
    pub rebate_piconero: u64,
    pub rebate_root: String,
    pub sponsor_commitment_root: String,
    pub created_l2_height: u64,
    pub status: RebateStatus,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "sequence": self.sequence,
            "grant_id": self.grant_id,
            "batch_id": self.batch_id,
            "recipient_id": self.recipient_id,
            "lane": self.lane.as_str(),
            "original_fee_piconero": self.original_fee_piconero,
            "rebate_piconero": self.rebate_piconero,
            "rebate_root": self.rebate_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "created_l2_height": self.created_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditorSlashing {
    pub slashing_id: String,
    pub sequence: u64,
    pub auditor_id: String,
    pub attestation_id: Option<String>,
    pub grant_id: Option<String>,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub slash_bps: u64,
    pub slashed_stake_piconero: u64,
    pub challenger_id: String,
    pub created_l2_height: u64,
}

impl AuditorSlashing {
    pub fn public_record(&self) -> Value {
        json!({
            "slashing_id": self.slashing_id,
            "sequence": self.sequence,
            "auditor_id": self.auditor_id,
            "attestation_id": self.attestation_id,
            "grant_id": self.grant_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "slash_bps": self.slash_bps,
            "slashed_stake_piconero": self.slashed_stake_piconero,
            "challenger_id": self.challenger_id,
            "created_l2_height": self.created_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterAuditPolicyRequest {
    pub owner_id: String,
    pub auditor_set_id: String,
    pub permitted_scopes: BTreeSet<AuditScope>,
    pub lane: AuditLane,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub viewkey_commitment_root: String,
    pub disclosure_constraint_root: String,
    pub contract_scope_root: String,
    pub token_scope_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitEncryptedAuditGrantRequest {
    pub policy_id: String,
    pub owner_id: String,
    pub auditor_id: String,
    pub scopes: BTreeSet<AuditScope>,
    pub encrypted_viewkey_payload_root: String,
    pub pq_ciphertext_root: String,
    pub grant_nullifier: String,
    pub fee_commitment_piconero: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachPqAuditorAttestationRequest {
    pub grant_id: String,
    pub auditor_id: String,
    pub auditor_weight: u64,
    pub auditor_stake: u64,
    pub observed_monero_height: u64,
    pub view_tag_commitment_root: String,
    pub disclosure_root: String,
    pub token_delta_root: String,
    pub contract_event_root: String,
    pub pq_signature_root: String,
    pub fee_claim_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildPrivateDisclosureBatchRequest {
    pub builder_id: String,
    pub lane: AuditLane,
    pub grant_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub view_tag_commitment_ids: Vec<String>,
    pub encrypted_disclosure_bundle_root: String,
    pub defi_state_delta_root: String,
    pub token_state_delta_root: String,
    pub contract_receipt_root: String,
    pub rebate_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncMoneroViewTagCommitmentRequest {
    pub grant_id: String,
    pub wallet_id: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub view_tag_root: String,
    pub output_commitment_root: String,
    pub key_image_hint_root: String,
    pub decoy_set_root: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProduceAuditReceiptRequest {
    pub kind: ReceiptKind,
    pub subject_id: String,
    pub batch_id: Option<String>,
    pub grant_id: Option<String>,
    pub auditor_id: Option<String>,
    pub receipt_root: String,
    pub fee_paid_piconero: u64,
    pub rebate_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueLowFeeRebateRequest {
    pub grant_id: String,
    pub batch_id: String,
    pub recipient_id: String,
    pub sponsor_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashAuditorRequest {
    pub auditor_id: String,
    pub attestation_id: Option<String>,
    pub grant_id: Option<String>,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub challenger_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_l2_height: u64,
    pub policies: BTreeMap<String, AuditPolicy>,
    pub grants: BTreeMap<String, AuditGrant>,
    pub attestations: BTreeMap<String, AuditorAttestation>,
    pub disclosure_batches: BTreeMap<String, DisclosureBatch>,
    pub view_tag_commitments: BTreeMap<String, ViewTagCommitment>,
    pub receipts: BTreeMap<String, AuditReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashings: BTreeMap<String, AuditorSlashing>,
    pub nullifiers: BTreeSet<String>,
    pub auditor_index: BTreeMap<String, BTreeSet<String>>,
    pub policy_owner_index: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            current_l2_height: DEVNET_HEIGHT,
            config,
            policies: BTreeMap::new(),
            grants: BTreeMap::new(),
            attestations: BTreeMap::new(),
            disclosure_batches: BTreeMap::new(),
            view_tag_commitments: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashings: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            auditor_index: BTreeMap::new(),
            policy_owner_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::try_devnet().unwrap_or_else(|_| Self::new(Config::devnet()))
    }

    pub fn try_devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet());
        let mut scopes = BTreeSet::new();
        scopes.insert(AuditScope::ViewTagsOnly);
        scopes.insert(AuditScope::IncomingOutputs);
        scopes.insert(AuditScope::DefiPosition);
        scopes.insert(AuditScope::TokenBalance);
        let policy = state.register_selective_viewkey_audit_policy(RegisterAuditPolicyRequest {
            owner_id: "devnet-wallet-owner-0".to_string(),
            auditor_set_id: "devnet-pq-auditor-set-0".to_string(),
            permitted_scopes: scopes.clone(),
            lane: AuditLane::Defi,
            min_privacy_set_size: state.config.min_privacy_set_size,
            max_fee_bps: state.config.defi_fee_bps,
            pq_security_bits: state.config.target_pq_security_bits,
            viewkey_commitment_root: root_from_parts("DEVNET-VIEWKEY", &[HashPart::Str("viewkey")]),
            disclosure_constraint_root: root_from_parts(
                "DEVNET-DISCLOSURE-CONSTRAINT",
                &[HashPart::Str("constraint")],
            ),
            contract_scope_root: root_from_parts(
                "DEVNET-CONTRACT-SCOPE",
                &[HashPart::Str("contracts")],
            ),
            token_scope_root: root_from_parts("DEVNET-TOKEN-SCOPE", &[HashPart::Str("tokens")]),
        })?;
        let grant = state.submit_encrypted_audit_grant(SubmitEncryptedAuditGrantRequest {
            policy_id: policy.policy_id.clone(),
            owner_id: policy.owner_id.clone(),
            auditor_id: "devnet-pq-auditor-0".to_string(),
            scopes,
            encrypted_viewkey_payload_root: root_from_parts(
                "DEVNET-SEALED-VIEWKEY",
                &[HashPart::Str("sealed")],
            ),
            pq_ciphertext_root: root_from_parts("DEVNET-PQ-CIPHERTEXT", &[HashPart::Str("kem")]),
            grant_nullifier: "devnet-audit-grant-nullifier-0".to_string(),
            fee_commitment_piconero: 12_000,
            max_fee_bps: state.config.defi_fee_bps,
            privacy_set_size: state.config.batch_privacy_set_size,
            pq_security_bits: state.config.target_pq_security_bits,
            monero_start_height: DEVNET_HEIGHT,
            monero_end_height: DEVNET_HEIGHT + 48,
        })?;
        let view_tag =
            state.sync_monero_view_tag_commitment(SyncMoneroViewTagCommitmentRequest {
                grant_id: grant.grant_id.clone(),
                wallet_id: policy.owner_id.clone(),
                monero_start_height: DEVNET_HEIGHT,
                monero_end_height: DEVNET_HEIGHT + 48,
                view_tag_root: root_from_parts("DEVNET-VIEW-TAGS", &[HashPart::Str("tags")]),
                output_commitment_root: root_from_parts(
                    "DEVNET-OUTPUTS",
                    &[HashPart::Str("outputs")],
                ),
                key_image_hint_root: root_from_parts(
                    "DEVNET-KEY-IMAGE-HINTS",
                    &[HashPart::Str("key-images")],
                ),
                decoy_set_root: root_from_parts("DEVNET-DECOYS", &[HashPart::Str("decoys")]),
                privacy_set_size: state.config.batch_privacy_set_size,
            })?;
        let attestation =
            state.attach_pq_auditor_attestation(AttachPqAuditorAttestationRequest {
                grant_id: grant.grant_id.clone(),
                auditor_id: "devnet-pq-auditor-0".to_string(),
                auditor_weight: state.config.min_auditor_weight,
                auditor_stake: state.config.min_auditor_stake,
                observed_monero_height: DEVNET_HEIGHT + 49,
                view_tag_commitment_root: view_tag.view_tag_root.clone(),
                disclosure_root: root_from_parts(
                    "DEVNET-DISCLOSURE",
                    &[HashPart::Str("disclosure")],
                ),
                token_delta_root: root_from_parts("DEVNET-TOKEN-DELTA", &[HashPart::Str("token")]),
                contract_event_root: root_from_parts(
                    "DEVNET-CONTRACT-EVENTS",
                    &[HashPart::Str("events")],
                ),
                pq_signature_root: root_from_parts(
                    "DEVNET-PQ-AUDITOR-SIG",
                    &[HashPart::Str("sig")],
                ),
                fee_claim_piconero: 3_000,
            })?;
        let batch = state.build_private_disclosure_batch(BuildPrivateDisclosureBatchRequest {
            builder_id: "devnet-disclosure-builder-0".to_string(),
            lane: AuditLane::Defi,
            grant_ids: vec![grant.grant_id.clone()],
            attestation_ids: vec![attestation.attestation_id],
            view_tag_commitment_ids: vec![view_tag.view_tag_commitment_id],
            encrypted_disclosure_bundle_root: root_from_parts(
                "DEVNET-ENCRYPTED-DISCLOSURE-BUNDLE",
                &[HashPart::Str("bundle")],
            ),
            defi_state_delta_root: root_from_parts("DEVNET-DEFI-DELTA", &[HashPart::Str("defi")]),
            token_state_delta_root: root_from_parts(
                "DEVNET-TOKEN-STATE-DELTA",
                &[HashPart::Str("token-state")],
            ),
            contract_receipt_root: root_from_parts(
                "DEVNET-CONTRACT-RECEIPTS",
                &[HashPart::Str("receipts")],
            ),
            rebate_commitment_root: root_from_parts(
                "DEVNET-REBATE-COMMITMENT",
                &[HashPart::Str("rebate")],
            ),
        })?;
        let rebate = state.issue_low_fee_rebate(IssueLowFeeRebateRequest {
            grant_id: grant.grant_id.clone(),
            batch_id: batch.batch_id.clone(),
            recipient_id: policy.owner_id,
            sponsor_commitment_root: root_from_parts("DEVNET-SPONSOR", &[HashPart::Str("sponsor")]),
        })?;
        state.produce_audit_receipt(ProduceAuditReceiptRequest {
            kind: ReceiptKind::AuditCompleted,
            subject_id: batch.batch_id,
            batch_id: Some(rebate.batch_id),
            grant_id: Some(grant.grant_id),
            auditor_id: Some("devnet-pq-auditor-0".to_string()),
            receipt_root: root_from_parts("DEVNET-AUDIT-RECEIPT", &[HashPart::Str("receipt")]),
            fee_paid_piconero: 3_000,
            rebate_id: Some(rebate.rebate_id),
        })?;
        Ok(state)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            next_sequence: self.next_sequence_peek(),
            policies: self.policies.len(),
            grants: self.grants.len(),
            attestations: self.attestations.len(),
            disclosure_batches: self.disclosure_batches.len(),
            view_tag_commitments: self.view_tag_commitments.len(),
            receipts: self.receipts.len(),
            rebates: self.rebates.len(),
            slashings: self.slashings.len(),
            public_records: self.public_records.len(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            policy_root: records_root(
                "AUDIT-POLICIES",
                self.policies.values().map(AuditPolicy::public_record),
            ),
            grant_root: records_root(
                "AUDIT-GRANTS",
                self.grants.values().map(AuditGrant::public_record),
            ),
            attestation_root: records_root(
                "AUDITOR-ATTESTATIONS",
                self.attestations
                    .values()
                    .map(AuditorAttestation::public_record),
            ),
            disclosure_batch_root: records_root(
                "DISCLOSURE-BATCHES",
                self.disclosure_batches
                    .values()
                    .map(DisclosureBatch::public_record),
            ),
            view_tag_commitment_root: records_root(
                "VIEW-TAG-COMMITMENTS",
                self.view_tag_commitments
                    .values()
                    .map(ViewTagCommitment::public_record),
            ),
            receipt_root: records_root(
                "AUDIT-RECEIPTS",
                self.receipts.values().map(AuditReceipt::public_record),
            ),
            rebate_root: records_root(
                "LOW-FEE-REBATES",
                self.rebates.values().map(FeeRebate::public_record),
            ),
            slashing_root: records_root(
                "AUDITOR-SLASHINGS",
                self.slashings.values().map(AuditorSlashing::public_record),
            ),
            auditor_index_root: map_set_root("AUDITOR-INDEX", &self.auditor_index),
            policy_owner_index_root: map_set_root("POLICY-OWNER-INDEX", &self.policy_owner_index),
            public_record_root: records_root(
                "PUBLIC-RECORDS",
                self.public_records.values().cloned(),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots().public_record();
        let counters = self.counters().public_record();
        domain_hash(
            "MONERO-L2-PQ-PRIVATE-VIEWKEY-SELECTIVE-DISCLOSURE-ORACLE-BRIDGE-STATE",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.current_l2_height),
                HashPart::Json(&roots),
                HashPart::Json(&counters),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "current_l2_height": self.current_l2_height,
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn register_selective_viewkey_audit_policy(
        &mut self,
        request: RegisterAuditPolicyRequest,
    ) -> Result<AuditPolicy> {
        self.ensure_capacity("policies", self.policies.len(), MAX_POLICIES)?;
        if request.owner_id.is_empty() || request.auditor_set_id.is_empty() {
            return Err("policy owner and auditor set are required".to_string());
        }
        if request.permitted_scopes.is_empty() {
            return Err("policy must permit at least one audit scope".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("policy privacy set below configured floor".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps || request.max_fee_bps > MAX_BPS {
            return Err("policy fee cap exceeds configured maximum".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("policy pq security below minimum".to_string());
        }
        if request.lane == AuditLane::LowFee && request.max_fee_bps > self.config.low_fee_bps {
            return Err("low fee policy exceeds low fee lane cap".to_string());
        }
        if request
            .permitted_scopes
            .iter()
            .any(|scope| scope.requires_contract_lane())
            && matches!(request.lane, AuditLane::LowFee)
        {
            return Err("contract aware scopes require defi/token/contract lane".to_string());
        }
        let sequence = self.next_sequence();
        let policy_id = policy_id(sequence, &request);
        if self.policies.contains_key(&policy_id) {
            return Err("policy already registered".to_string());
        }
        let policy = AuditPolicy {
            policy_id: policy_id.clone(),
            sequence,
            owner_id: request.owner_id,
            auditor_set_id: request.auditor_set_id,
            permitted_scopes: request.permitted_scopes,
            lane: request.lane,
            min_privacy_set_size: request.min_privacy_set_size,
            max_fee_bps: request.max_fee_bps,
            pq_security_bits: request.pq_security_bits,
            viewkey_commitment_root: request.viewkey_commitment_root,
            disclosure_constraint_root: request.disclosure_constraint_root,
            contract_scope_root: request.contract_scope_root,
            token_scope_root: request.token_scope_root,
            created_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.policy_ttl_blocks,
            status: PolicyStatus::Registered,
        };
        self.policy_owner_index
            .entry(policy.owner_id.clone())
            .or_default()
            .insert(policy_id.clone());
        self.policies.insert(policy_id.clone(), policy.clone());
        self.record_public(format!("policy:{policy_id}"), policy.public_record())?;
        Ok(policy)
    }

    pub fn submit_encrypted_audit_grant(
        &mut self,
        request: SubmitEncryptedAuditGrantRequest,
    ) -> Result<AuditGrant> {
        self.ensure_capacity("grants", self.grants.len(), MAX_GRANTS)?;
        if self.nullifiers.contains(&request.grant_nullifier) {
            return Err("grant nullifier already consumed".to_string());
        }
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| "unknown audit policy".to_string())?
            .clone();
        if !policy.status.usable() || policy.expires_l2_height <= self.current_l2_height {
            return Err("audit policy is not active".to_string());
        }
        if policy.owner_id != request.owner_id {
            return Err("grant owner does not match policy owner".to_string());
        }
        if !request
            .scopes
            .iter()
            .all(|scope| policy.permitted_scopes.contains(scope))
        {
            return Err("grant requests a scope outside policy".to_string());
        }
        if request.max_fee_bps > policy.max_fee_bps
            || request.max_fee_bps > policy.lane.fee_bps(&self.config)
        {
            return Err("grant fee cap exceeds policy or lane".to_string());
        }
        if request.privacy_set_size < policy.min_privacy_set_size {
            return Err("grant privacy set below policy floor".to_string());
        }
        if request.pq_security_bits < policy.pq_security_bits {
            return Err("grant pq security below policy requirement".to_string());
        }
        if request.monero_end_height <= request.monero_start_height {
            return Err("grant monero height range is empty".to_string());
        }
        let sequence = self.next_sequence();
        let grant_id = grant_id(sequence, &request);
        let grant = AuditGrant {
            grant_id: grant_id.clone(),
            sequence,
            policy_id: request.policy_id,
            owner_id: request.owner_id,
            auditor_id: request.auditor_id,
            lane: policy.lane,
            scopes: request.scopes,
            encrypted_viewkey_payload_root: request.encrypted_viewkey_payload_root,
            pq_ciphertext_root: request.pq_ciphertext_root,
            grant_nullifier: request.grant_nullifier,
            fee_commitment_piconero: request.fee_commitment_piconero,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            created_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.grant_ttl_blocks,
            status: GrantStatus::PolicyLinked,
        };
        self.nullifiers.insert(grant.grant_nullifier.clone());
        self.auditor_index
            .entry(grant.auditor_id.clone())
            .or_default()
            .insert(grant_id.clone());
        self.grants.insert(grant_id.clone(), grant.clone());
        self.record_public(format!("grant:{grant_id}"), grant.public_record())?;
        Ok(grant)
    }

    pub fn attach_pq_auditor_attestation(
        &mut self,
        request: AttachPqAuditorAttestationRequest,
    ) -> Result<AuditorAttestation> {
        self.ensure_capacity("attestations", self.attestations.len(), MAX_ATTESTATIONS)?;
        let mut grant = self
            .grants
            .get(&request.grant_id)
            .ok_or_else(|| "unknown audit grant".to_string())?
            .clone();
        if grant.expires_l2_height <= self.current_l2_height {
            return Err("audit grant expired".to_string());
        }
        if grant.auditor_id != request.auditor_id {
            return Err("attestation auditor mismatch".to_string());
        }
        if request.auditor_weight < self.config.min_auditor_weight {
            return Err("auditor weight below quorum floor".to_string());
        }
        if request.auditor_stake < self.config.min_auditor_stake {
            return Err("auditor stake below minimum".to_string());
        }
        if request.observed_monero_height < grant.monero_end_height {
            return Err("attestation observed before grant range end".to_string());
        }
        if request.fee_claim_piconero > grant.fee_commitment_piconero {
            return Err("attestation fee claim exceeds grant commitment".to_string());
        }
        let sequence = self.next_sequence();
        let attestation_id = attestation_id(sequence, &request);
        let status = if request.auditor_weight.saturating_mul(MAX_BPS)
            >= self
                .config
                .min_auditor_weight
                .saturating_mul(self.config.attestation_quorum_bps)
        {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::WeakQuorum
        };
        let attestation = AuditorAttestation {
            attestation_id: attestation_id.clone(),
            sequence,
            grant_id: request.grant_id.clone(),
            policy_id: grant.policy_id.clone(),
            auditor_id: request.auditor_id,
            auditor_weight: request.auditor_weight,
            auditor_stake: request.auditor_stake,
            observed_monero_height: request.observed_monero_height,
            view_tag_commitment_root: request.view_tag_commitment_root,
            disclosure_root: request.disclosure_root,
            token_delta_root: request.token_delta_root,
            contract_event_root: request.contract_event_root,
            pq_signature_root: request.pq_signature_root,
            fee_claim_piconero: request.fee_claim_piconero,
            created_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.attestation_ttl_blocks,
            status,
        };
        if status == AttestationStatus::Accepted {
            grant.status = GrantStatus::Attested;
        }
        self.grants.insert(grant.grant_id.clone(), grant.clone());
        self.attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.record_public(format!("grant:{}", grant.grant_id), grant.public_record())?;
        self.record_public(
            format!("attestation:{attestation_id}"),
            attestation.public_record(),
        )?;
        Ok(attestation)
    }

    pub fn sync_monero_view_tag_commitment(
        &mut self,
        request: SyncMoneroViewTagCommitmentRequest,
    ) -> Result<ViewTagCommitment> {
        self.ensure_capacity(
            "view tag commitments",
            self.view_tag_commitments.len(),
            MAX_VIEW_TAG_COMMITMENTS,
        )?;
        let grant = self
            .grants
            .get(&request.grant_id)
            .ok_or_else(|| "unknown audit grant for view tag sync".to_string())?;
        if request.monero_start_height < grant.monero_start_height
            || request.monero_end_height > grant.monero_end_height
        {
            return Err("view tag commitment outside grant height range".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("view tag privacy set below configured floor".to_string());
        }
        let sequence = self.next_sequence();
        let view_tag_commitment_id = view_tag_commitment_id(sequence, &request);
        let commitment = ViewTagCommitment {
            view_tag_commitment_id: view_tag_commitment_id.clone(),
            sequence,
            grant_id: request.grant_id,
            wallet_id: request.wallet_id,
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            view_tag_root: request.view_tag_root,
            output_commitment_root: request.output_commitment_root,
            key_image_hint_root: request.key_image_hint_root,
            decoy_set_root: request.decoy_set_root,
            privacy_set_size: request.privacy_set_size,
            created_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.view_tag_ttl_blocks,
            status: ViewTagStatus::Synced,
        };
        self.view_tag_commitments
            .insert(view_tag_commitment_id.clone(), commitment.clone());
        self.record_public(
            format!("view_tag_commitment:{view_tag_commitment_id}"),
            commitment.public_record(),
        )?;
        Ok(commitment)
    }

    pub fn build_private_disclosure_batch(
        &mut self,
        request: BuildPrivateDisclosureBatchRequest,
    ) -> Result<DisclosureBatch> {
        self.ensure_capacity(
            "disclosure batches",
            self.disclosure_batches.len(),
            MAX_DISCLOSURE_BATCHES,
        )?;
        if request.grant_ids.is_empty() || request.grant_ids.len() > self.config.max_batch_items {
            return Err("batch grant count outside bounds".to_string());
        }
        if request.attestation_ids.len() < request.grant_ids.len() {
            return Err("batch must include at least one attestation per grant".to_string());
        }
        let mut total_fee_piconero = 0_u64;
        for grant_id in &request.grant_ids {
            let grant = self
                .grants
                .get(grant_id)
                .ok_or_else(|| format!("unknown grant {grant_id}"))?;
            if !grant.status.batchable() {
                return Err(format!("grant {grant_id} is not batchable"));
            }
            if grant.lane != request.lane {
                return Err(format!("grant {grant_id} is on a different lane"));
            }
            total_fee_piconero = total_fee_piconero.saturating_add(grant.fee_commitment_piconero);
        }
        for attestation_id in &request.attestation_ids {
            let attestation = self
                .attestations
                .get(attestation_id)
                .ok_or_else(|| format!("unknown attestation {attestation_id}"))?;
            if attestation.status != AttestationStatus::Accepted {
                return Err(format!("attestation {attestation_id} not accepted"));
            }
        }
        for commitment_id in &request.view_tag_commitment_ids {
            let commitment = self
                .view_tag_commitments
                .get(commitment_id)
                .ok_or_else(|| format!("unknown view tag commitment {commitment_id}"))?;
            if commitment.expires_l2_height <= self.current_l2_height {
                return Err(format!("view tag commitment {commitment_id} expired"));
            }
        }
        let sequence = self.next_sequence();
        let disclosure_batch_root = disclosure_batch_root(sequence, &request);
        let batch_id = batch_id(sequence, &request.builder_id, &disclosure_batch_root);
        let batch = DisclosureBatch {
            batch_id: batch_id.clone(),
            sequence,
            builder_id: request.builder_id,
            lane: request.lane,
            grant_ids: request.grant_ids.clone(),
            attestation_ids: request.attestation_ids,
            view_tag_commitment_ids: request.view_tag_commitment_ids.clone(),
            disclosure_batch_root,
            encrypted_disclosure_bundle_root: request.encrypted_disclosure_bundle_root,
            defi_state_delta_root: request.defi_state_delta_root,
            token_state_delta_root: request.token_state_delta_root,
            contract_receipt_root: request.contract_receipt_root,
            total_fee_piconero,
            rebate_commitment_root: request.rebate_commitment_root,
            created_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.batch_ttl_blocks,
            status: BatchStatus::Built,
        };
        for grant_id in &batch.grant_ids {
            if let Some(grant) = self.grants.get_mut(grant_id) {
                grant.status = GrantStatus::Batched;
            }
        }
        for commitment_id in &batch.view_tag_commitment_ids {
            if let Some(commitment) = self.view_tag_commitments.get_mut(commitment_id) {
                commitment.status = ViewTagStatus::Batched;
            }
        }
        self.disclosure_batches
            .insert(batch_id.clone(), batch.clone());
        self.refresh_records_for_ids("grant", &batch.grant_ids)?;
        self.refresh_records_for_ids("view_tag_commitment", &batch.view_tag_commitment_ids)?;
        self.record_public(format!("batch:{batch_id}"), batch.public_record())?;
        Ok(batch)
    }

    pub fn produce_audit_receipt(
        &mut self,
        request: ProduceAuditReceiptRequest,
    ) -> Result<AuditReceipt> {
        self.ensure_capacity("receipts", self.receipts.len(), MAX_RECEIPTS)?;
        if let Some(batch_id) = &request.batch_id {
            if !self.disclosure_batches.contains_key(batch_id) {
                return Err("receipt references unknown batch".to_string());
            }
        }
        if let Some(grant_id) = &request.grant_id {
            if !self.grants.contains_key(grant_id) {
                return Err("receipt references unknown grant".to_string());
            }
        }
        let sequence = self.next_sequence();
        let receipt_id = receipt_id(sequence, &request);
        let receipt = AuditReceipt {
            receipt_id: receipt_id.clone(),
            sequence,
            kind: request.kind,
            subject_id: request.subject_id,
            batch_id: request.batch_id.clone(),
            grant_id: request.grant_id.clone(),
            auditor_id: request.auditor_id,
            receipt_root: request.receipt_root,
            state_root_after: self.state_root(),
            fee_paid_piconero: request.fee_paid_piconero,
            rebate_id: request.rebate_id,
            created_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.receipt_ttl_blocks,
        };
        if let Some(batch_id) = request.batch_id {
            if let Some(batch) = self.disclosure_batches.get_mut(&batch_id) {
                batch.status = BatchStatus::Receipted;
            }
        }
        if let Some(grant_id) = request.grant_id {
            if let Some(grant) = self.grants.get_mut(&grant_id) {
                grant.status = GrantStatus::Receipted;
            }
        }
        self.receipts.insert(receipt_id.clone(), receipt.clone());
        self.record_public(format!("receipt:{receipt_id}"), receipt.public_record())?;
        Ok(receipt)
    }

    pub fn issue_low_fee_rebate(&mut self, request: IssueLowFeeRebateRequest) -> Result<FeeRebate> {
        self.ensure_capacity("rebates", self.rebates.len(), MAX_REBATES)?;
        let grant = self
            .grants
            .get(&request.grant_id)
            .ok_or_else(|| "rebate references unknown grant".to_string())?
            .clone();
        let batch = self
            .disclosure_batches
            .get(&request.batch_id)
            .ok_or_else(|| "rebate references unknown batch".to_string())?;
        if !batch.grant_ids.contains(&request.grant_id) {
            return Err("rebate grant not included in batch".to_string());
        }
        let lane_fee_bps = grant.lane.fee_bps(&self.config);
        let charged_bps = grant.max_fee_bps.min(lane_fee_bps);
        let rebate_bps = self.config.rebate_bps.min(charged_bps);
        let rebate_piconero = mul_bps(grant.fee_commitment_piconero, rebate_bps);
        let sequence = self.next_sequence();
        let rebate_root = root_from_parts(
            "LOW-FEE-REBATE",
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.grant_id),
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.recipient_id),
                HashPart::U64(rebate_piconero),
            ],
        );
        let rebate_id = rebate_id(sequence, &request, rebate_piconero);
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            sequence,
            grant_id: request.grant_id,
            batch_id: request.batch_id,
            recipient_id: request.recipient_id,
            lane: grant.lane,
            original_fee_piconero: grant.fee_commitment_piconero,
            rebate_piconero,
            rebate_root,
            sponsor_commitment_root: request.sponsor_commitment_root,
            created_l2_height: self.current_l2_height,
            status: RebateStatus::Issued,
        };
        self.rebates.insert(rebate_id.clone(), rebate.clone());
        self.record_public(format!("rebate:{rebate_id}"), rebate.public_record())?;
        Ok(rebate)
    }

    pub fn slash_invalid_or_stale_auditor(
        &mut self,
        request: SlashAuditorRequest,
    ) -> Result<AuditorSlashing> {
        self.ensure_capacity("slashings", self.slashings.len(), MAX_SLASHINGS)?;
        if let Some(attestation_id) = &request.attestation_id {
            let attestation = self
                .attestations
                .get(attestation_id)
                .ok_or_else(|| "slashing references unknown attestation".to_string())?;
            if attestation.auditor_id != request.auditor_id {
                return Err("slashing auditor mismatch".to_string());
            }
        }
        let sequence = self.next_sequence();
        let slash_bps = if request.reason.stale() {
            self.config.slash_stale_bps
        } else {
            self.config.slash_invalid_bps
        };
        let auditor_stake = request
            .attestation_id
            .as_ref()
            .and_then(|id| self.attestations.get(id))
            .map(|attestation| attestation.auditor_stake)
            .unwrap_or(self.config.min_auditor_stake);
        let slashed_stake_piconero = mul_bps(auditor_stake, slash_bps);
        let slashing_id = slashing_id(sequence, &request);
        let slashing = AuditorSlashing {
            slashing_id: slashing_id.clone(),
            sequence,
            auditor_id: request.auditor_id.clone(),
            attestation_id: request.attestation_id.clone(),
            grant_id: request.grant_id.clone(),
            reason: request.reason,
            evidence_root: request.evidence_root,
            slash_bps,
            slashed_stake_piconero,
            challenger_id: request.challenger_id,
            created_l2_height: self.current_l2_height,
        };
        if let Some(attestation_id) = &request.attestation_id {
            if let Some(attestation) = self.attestations.get_mut(attestation_id) {
                attestation.status = if request.reason.stale() {
                    AttestationStatus::Stale
                } else {
                    AttestationStatus::Slashed
                };
            }
        }
        if let Some(grant_id) = &request.grant_id {
            if let Some(grant) = self.grants.get_mut(grant_id) {
                grant.status = GrantStatus::Slashed;
            }
        }
        self.slashings.insert(slashing_id.clone(), slashing.clone());
        self.record_public(format!("slashing:{slashing_id}"), slashing.public_record())?;
        Ok(slashing)
    }

    pub fn advance_l2_height(&mut self, height: u64) -> Result<()> {
        if height < self.current_l2_height {
            return Err("cannot rewind l2 height".to_string());
        }
        self.current_l2_height = height;
        self.expire_stale_records()?;
        Ok(())
    }

    fn expire_stale_records(&mut self) -> Result<()> {
        let height = self.current_l2_height;
        let expired_policies = self
            .policies
            .iter_mut()
            .filter_map(|(id, policy)| {
                if policy.expires_l2_height <= height && policy.status.usable() {
                    policy.status = PolicyStatus::Expired;
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let expired_grants = self
            .grants
            .iter_mut()
            .filter_map(|(id, grant)| {
                if grant.expires_l2_height <= height && grant.status.batchable() {
                    grant.status = GrantStatus::Expired;
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let expired_view_tags = self
            .view_tag_commitments
            .iter_mut()
            .filter_map(|(id, commitment)| {
                if commitment.expires_l2_height <= height
                    && commitment.status == ViewTagStatus::Synced
                {
                    commitment.status = ViewTagStatus::Expired;
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        self.refresh_records_for_ids("policy", &expired_policies)?;
        self.refresh_records_for_ids("grant", &expired_grants)?;
        self.refresh_records_for_ids("view_tag_commitment", &expired_view_tags)?;
        Ok(())
    }

    fn next_sequence(&mut self) -> u64 {
        let next = self.next_sequence_peek();
        self.public_records
            .entry("__sequence_clock".to_string())
            .and_modify(|value| *value = json!(next))
            .or_insert_with(|| json!(next));
        next
    }

    fn next_sequence_peek(&self) -> u64 {
        self.public_records
            .get("__sequence_clock")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            + 1
    }

    fn ensure_capacity(&self, label: &str, current: usize, max: usize) -> Result<()> {
        if current >= max {
            Err(format!("{label} capacity exhausted"))
        } else {
            Ok(())
        }
    }

    fn record_public(&mut self, key: String, value: Value) -> Result<()> {
        if !self.public_records.contains_key(&key)
            && self.public_records.len() >= MAX_PUBLIC_RECORDS
        {
            return Err("public record capacity exhausted".to_string());
        }
        self.public_records.insert(key, value);
        Ok(())
    }

    fn refresh_records_for_ids(&mut self, prefix: &str, ids: &[String]) -> Result<()> {
        for id in ids {
            let value = match prefix {
                "policy" => self.policies.get(id).map(AuditPolicy::public_record),
                "grant" => self.grants.get(id).map(AuditGrant::public_record),
                "view_tag_commitment" => self
                    .view_tag_commitments
                    .get(id)
                    .map(ViewTagCommitment::public_record),
                _ => None,
            };
            if let Some(value) = value {
                self.record_public(format!("{prefix}:{id}"), value)?;
            }
        }
        Ok(())
    }
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn records_root(domain: &str, records: impl IntoIterator<Item = Value>) -> String {
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn map_set_root(domain: &str, map: &BTreeMap<String, BTreeSet<String>>) -> String {
    let leaves = map
        .iter()
        .map(|(key, values)| json!({"key": key, "values": values.iter().collect::<Vec<_>>()}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn mul_bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

pub fn policy_id(sequence: u64, request: &RegisterAuditPolicyRequest) -> String {
    root_from_parts(
        "AUDIT-POLICY-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.owner_id),
            HashPart::Str(&request.auditor_set_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.viewkey_commitment_root),
        ],
    )
}

pub fn grant_id(sequence: u64, request: &SubmitEncryptedAuditGrantRequest) -> String {
    root_from_parts(
        "AUDIT-GRANT-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&request.owner_id),
            HashPart::Str(&request.auditor_id),
            HashPart::Str(&request.grant_nullifier),
        ],
    )
}

pub fn attestation_id(sequence: u64, request: &AttachPqAuditorAttestationRequest) -> String {
    root_from_parts(
        "AUDITOR-ATTESTATION-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.grant_id),
            HashPart::Str(&request.auditor_id),
            HashPart::Str(&request.pq_signature_root),
        ],
    )
}

pub fn disclosure_batch_root(
    sequence: u64,
    request: &BuildPrivateDisclosureBatchRequest,
) -> String {
    let grants = json!(request.grant_ids);
    let attestations = json!(request.attestation_ids);
    let view_tags = json!(request.view_tag_commitment_ids);
    root_from_parts(
        "DISCLOSURE-BATCH-ROOT",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.builder_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Json(&grants),
            HashPart::Json(&attestations),
            HashPart::Json(&view_tags),
            HashPart::Str(&request.encrypted_disclosure_bundle_root),
            HashPart::Str(&request.defi_state_delta_root),
            HashPart::Str(&request.token_state_delta_root),
            HashPart::Str(&request.contract_receipt_root),
        ],
    )
}

pub fn batch_id(sequence: u64, builder_id: &str, batch_root: &str) -> String {
    root_from_parts(
        "DISCLOSURE-BATCH-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(builder_id),
            HashPart::Str(batch_root),
        ],
    )
}

pub fn view_tag_commitment_id(
    sequence: u64,
    request: &SyncMoneroViewTagCommitmentRequest,
) -> String {
    root_from_parts(
        "VIEW-TAG-COMMITMENT-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.grant_id),
            HashPart::Str(&request.wallet_id),
            HashPart::U64(request.monero_start_height),
            HashPart::U64(request.monero_end_height),
            HashPart::Str(&request.view_tag_root),
        ],
    )
}

pub fn receipt_id(sequence: u64, request: &ProduceAuditReceiptRequest) -> String {
    root_from_parts(
        "AUDIT-RECEIPT-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.receipt_root),
        ],
    )
}

pub fn rebate_id(sequence: u64, request: &IssueLowFeeRebateRequest, amount: u64) -> String {
    root_from_parts(
        "LOW-FEE-REBATE-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.grant_id),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.recipient_id),
            HashPart::U64(amount),
        ],
    )
}

pub fn slashing_id(sequence: u64, request: &SlashAuditorRequest) -> String {
    root_from_parts(
        "AUDITOR-SLASHING-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.auditor_id),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.challenger_id),
        ],
    )
}
