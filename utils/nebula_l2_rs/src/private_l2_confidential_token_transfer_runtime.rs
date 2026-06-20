use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialTokenTransferRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-token-transfer-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-token-transfer-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_NOTE_SCHEME: &str =
    "private-l2-confidential-token-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_NULLIFIER_SCHEME: &str =
    "private-l2-confidential-token-nullifier-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_BALANCE_PROOF_SCHEME: &str =
    "private-l2-confidential-balance-conservation-proof-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_COMPLIANCE_SCHEME: &str =
    "private-l2-selective-compliance-attestation-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-token-transfer-sponsor-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_BATCH_SCHEME: &str =
    "private-l2-confidential-token-transfer-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEVNET_HEIGHT: u64 = 324_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_REGISTERED_ASSETS: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_TRANSFERS: usize = 2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_BATCHES: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    131_072;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 10;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_TRANSFER_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClass {
    ConfidentialAsset,
    WrappedMonero,
    StableAsset,
    VaultShare,
    LiquidityReceipt,
    GovernanceNote,
    SyntheticClaim,
}

impl TokenClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialAsset => "confidential_asset",
            Self::WrappedMonero => "wrapped_monero",
            Self::StableAsset => "stable_asset",
            Self::VaultShare => "vault_share",
            Self::LiquidityReceipt => "liquidity_receipt",
            Self::GovernanceNote => "governance_note",
            Self::SyntheticClaim => "synthetic_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetStatus {
    Registered,
    Active,
    Paused,
    Frozen,
    Retired,
}

impl AssetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_transfers(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferLane {
    RetailPrivate,
    DefiSettlement,
    BridgeIn,
    BridgeOut,
    SponsorRebate,
    ContractCall,
    LiquidityNetting,
}

impl TransferLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailPrivate => "retail_private",
            Self::DefiSettlement => "defi_settlement",
            Self::BridgeIn => "bridge_in",
            Self::BridgeOut => "bridge_out",
            Self::SponsorRebate => "sponsor_rebate",
            Self::ContractCall => "contract_call",
            Self::LiquidityNetting => "liquidity_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Submitted,
    ComplianceAttested,
    SponsorReserved,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl TransferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::ComplianceAttested => "compliance_attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::ComplianceAttested | Self::SponsorReserved
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceVerdict {
    Allowed,
    AllowedWithDisclosure,
    Watch,
    Hold,
    Rejected,
}

impl ComplianceVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::AllowedWithDisclosure => "allowed_with_disclosure",
            Self::Watch => "watch",
            Self::Hold => "hold",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_batching(self) -> bool {
        matches!(
            self,
            Self::Allowed | Self::AllowedWithDisclosure | Self::Watch
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    Sealed,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub max_registered_assets: usize,
    pub max_transfers: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub transfer_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            fee_asset_id: PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_FEE_ASSET_ID
                .to_string(),
            max_registered_assets:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_REGISTERED_ASSETS,
            max_transfers: PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_TRANSFERS,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_BATCHES,
            max_batch_items: PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            transfer_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_TRANSFER_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_transfer_config",
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "max_registered_assets": self.max_registered_assets,
            "max_transfers": self.max_transfers,
            "max_attestations": self.max_attestations,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "transfer_ttl_blocks": self.transfer_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-TRANSFER-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub assets_registered: u64,
    pub transfers_submitted: u64,
    pub attestations_recorded: u64,
    pub sponsor_reservations: u64,
    pub batches_built: u64,
    pub receipts_published: u64,
    pub transfers_settled: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_transfer_counters",
            "assets_registered": self.assets_registered,
            "transfers_submitted": self.transfers_submitted,
            "attestations_recorded": self.attestations_recorded,
            "sponsor_reservations": self.sponsor_reservations,
            "batches_built": self.batches_built,
            "receipts_published": self.receipts_published,
            "transfers_settled": self.transfers_settled,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterTokenAssetRequest {
    pub asset_id: String,
    pub token_class: TokenClass,
    pub issuer_commitment: String,
    pub supply_commitment_root: String,
    pub metadata_commitment_root: String,
    pub pq_issuer_key_root: String,
    pub transfer_policy_root: String,
    pub compliance_policy_root: String,
    pub low_fee_policy_root: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
}

impl RegisterTokenAssetRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "token_class": self.token_class.as_str(),
            "issuer_commitment": self.issuer_commitment,
            "supply_commitment_root": self.supply_commitment_root,
            "metadata_commitment_root": self.metadata_commitment_root,
            "pq_issuer_key_root": self.pq_issuer_key_root,
            "transfer_policy_root": self.transfer_policy_root,
            "compliance_policy_root": self.compliance_policy_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitConfidentialTransferRequest {
    pub asset_id: String,
    pub lane: TransferLane,
    pub sender_commitment: String,
    pub receiver_commitment: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub amount_commitment_root: String,
    pub balance_proof_root: String,
    pub nullifier_root: String,
    pub encrypted_memo_root: String,
    pub pq_authorization_root: String,
    pub fee_commitment_root: String,
    pub sponsor_hint_root: Option<String>,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitConfidentialTransferRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "lane": self.lane.as_str(),
            "sender_commitment": self.sender_commitment,
            "receiver_commitment": self.receiver_commitment,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "amount_commitment_root": self.amount_commitment_root,
            "balance_proof_root": self.balance_proof_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_memo_root": self.encrypted_memo_root,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_commitment_root": self.fee_commitment_root,
            "sponsor_hint_root": self.sponsor_hint_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestTransferComplianceRequest {
    pub transfer_id: String,
    pub attestor_commitment: String,
    pub verdict: ComplianceVerdict,
    pub selective_disclosure_root: String,
    pub risk_score_bps: u64,
    pub proof_root: String,
    pub pq_attestation_root: String,
    pub attested_at_height: u64,
}

impl AttestTransferComplianceRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "selective_disclosure_root": self.selective_disclosure_root,
            "risk_score_bps": self.risk_score_bps,
            "proof_root": self.proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveTransferFeeSponsorRequest {
    pub transfer_id: String,
    pub sponsor_commitment: String,
    pub budget_root: String,
    pub fee_asset_id: String,
    pub reserved_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub pq_reservation_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveTransferFeeSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_root": self.budget_root,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_bps": self.reserved_fee_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "pq_reservation_root": self.pq_reservation_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildTransferBatchRequest {
    pub operator_commitment: String,
    pub lane: TransferLane,
    pub asset_ids: Vec<String>,
    pub transfer_ids: Vec<String>,
    pub aggregate_input_root: String,
    pub aggregate_output_root: String,
    pub aggregate_nullifier_root: String,
    pub aggregate_balance_proof_root: String,
    pub aggregate_compliance_root: String,
    pub aggregate_fee_sponsor_root: String,
    pub recursive_proof_root: String,
    pub pq_batch_authorization_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl BuildTransferBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_commitment": self.operator_commitment,
            "lane": self.lane.as_str(),
            "asset_ids": self.asset_ids,
            "transfer_ids": self.transfer_ids,
            "aggregate_input_root": self.aggregate_input_root,
            "aggregate_output_root": self.aggregate_output_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "aggregate_balance_proof_root": self.aggregate_balance_proof_root,
            "aggregate_compliance_root": self.aggregate_compliance_root,
            "aggregate_fee_sponsor_root": self.aggregate_fee_sponsor_root,
            "recursive_proof_root": self.recursive_proof_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleTransferBatchRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub fee_receipt_root: String,
    pub pq_settlement_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleTransferBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenAssetRecord {
    pub asset_record_id: String,
    pub request: RegisterTokenAssetRequest,
    pub status: AssetStatus,
    pub created_at_height: u64,
}

impl TokenAssetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_asset",
            "asset_record_id": self.asset_record_id,
            "asset_id": self.request.asset_id,
            "token_class": self.request.token_class.as_str(),
            "issuer_commitment": self.request.issuer_commitment,
            "supply_commitment_root": self.request.supply_commitment_root,
            "metadata_commitment_root": self.request.metadata_commitment_root,
            "pq_issuer_key_root": self.request.pq_issuer_key_root,
            "transfer_policy_root": self.request.transfer_policy_root,
            "compliance_policy_root": self.request.compliance_policy_root,
            "low_fee_policy_root": self.request.low_fee_policy_root,
            "min_privacy_set_size": self.request.min_privacy_set_size,
            "pq_security_bits": self.request.pq_security_bits,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialTransferRecord {
    pub transfer_id: String,
    pub request: SubmitConfidentialTransferRequest,
    pub status: TransferStatus,
    pub compliance_attestation_id: Option<String>,
    pub sponsor_reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub submitted_at_height: u64,
}

impl ConfidentialTransferRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_transfer",
            "transfer_id": self.transfer_id,
            "asset_id": self.request.asset_id,
            "lane": self.request.lane.as_str(),
            "sender_commitment": self.request.sender_commitment,
            "receiver_commitment": self.request.receiver_commitment,
            "input_note_root": self.request.input_note_root,
            "output_note_root": self.request.output_note_root,
            "amount_commitment_root": self.request.amount_commitment_root,
            "balance_proof_root": self.request.balance_proof_root,
            "nullifier_root": self.request.nullifier_root,
            "encrypted_memo_root": self.request.encrypted_memo_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "fee_commitment_root": self.request.fee_commitment_root,
            "sponsor_hint_root": self.request.sponsor_hint_root,
            "max_fee_bps": self.request.max_fee_bps,
            "privacy_set_size": self.request.privacy_set_size,
            "pq_security_bits": self.request.pq_security_bits,
            "status": self.status.as_str(),
            "compliance_attestation_id": self.compliance_attestation_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "batch_id": self.batch_id,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceAttestationRecord {
    pub attestation_id: String,
    pub request: AttestTransferComplianceRequest,
}

impl ComplianceAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_compliance_attestation",
            "attestation_id": self.attestation_id,
            "transfer_id": self.request.transfer_id,
            "attestor_commitment": self.request.attestor_commitment,
            "verdict": self.request.verdict.as_str(),
            "selective_disclosure_root": self.request.selective_disclosure_root,
            "risk_score_bps": self.request.risk_score_bps,
            "proof_root": self.request.proof_root,
            "pq_attestation_root": self.request.pq_attestation_root,
            "attested_at_height": self.request.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveTransferFeeSponsorRequest,
    pub status: ReservationStatus,
}

impl FeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_fee_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "transfer_id": self.request.transfer_id,
            "sponsor_commitment": self.request.sponsor_commitment,
            "budget_root": self.request.budget_root,
            "fee_asset_id": self.request.fee_asset_id,
            "reserved_fee_bps": self.request.reserved_fee_bps,
            "rebate_commitment_root": self.request.rebate_commitment_root,
            "pq_reservation_root": self.request.pq_reservation_root,
            "status": self.status.as_str(),
            "reserved_at_height": self.request.reserved_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferBatchRecord {
    pub batch_id: String,
    pub request: BuildTransferBatchRequest,
    pub status: BatchStatus,
    pub settlement_receipt_id: Option<String>,
}

impl TransferBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_transfer_batch",
            "batch_id": self.batch_id,
            "operator_commitment": self.request.operator_commitment,
            "lane": self.request.lane.as_str(),
            "asset_ids": self.request.asset_ids,
            "transfer_ids": self.request.transfer_ids,
            "aggregate_input_root": self.request.aggregate_input_root,
            "aggregate_output_root": self.request.aggregate_output_root,
            "aggregate_nullifier_root": self.request.aggregate_nullifier_root,
            "aggregate_balance_proof_root": self.request.aggregate_balance_proof_root,
            "aggregate_compliance_root": self.request.aggregate_compliance_root,
            "aggregate_fee_sponsor_root": self.request.aggregate_fee_sponsor_root,
            "recursive_proof_root": self.request.recursive_proof_root,
            "pq_batch_authorization_root": self.request.pq_batch_authorization_root,
            "max_fee_bps": self.request.max_fee_bps,
            "privacy_set_size": self.request.privacy_set_size,
            "status": self.status.as_str(),
            "settlement_receipt_id": self.settlement_receipt_id,
            "built_at_height": self.request.built_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferSettlementReceipt {
    pub receipt_id: String,
    pub request: SettleTransferBatchRequest,
    pub status: ReceiptStatus,
    pub settled_transfer_ids: Vec<String>,
}

impl TransferSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_transfer_settlement_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.request.batch_id,
            "settlement_tx_root": self.request.settlement_tx_root,
            "settlement_proof_root": self.request.settlement_proof_root,
            "state_root_before": self.request.state_root_before,
            "state_root_after": self.request.state_root_after,
            "fee_receipt_root": self.request.fee_receipt_root,
            "pq_settlement_root": self.request.pq_settlement_root,
            "settled_fee_bps": self.request.settled_fee_bps,
            "settled_transfer_ids": self.settled_transfer_ids,
            "status": self.status.as_str(),
            "settled_at_height": self.request.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub asset_root: String,
    pub transfer_root: String,
    pub attestation_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_root": self.asset_root,
            "transfer_root": self.transfer_root,
            "attestation_root": self.attestation_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub assets: BTreeMap<String, TokenAssetRecord>,
    pub transfers: BTreeMap<String, ConfidentialTransferRecord>,
    pub attestations: BTreeMap<String, ComplianceAttestationRecord>,
    pub reservations: BTreeMap<String, FeeSponsorReservationRecord>,
    pub batches: BTreeMap<String, TransferBatchRecord>,
    pub receipts: BTreeMap<String, TransferSettlementReceipt>,
    pub seen_nullifier_roots: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialTokenTransferRuntimeResult<Self> {
        Self::with_config(Config::devnet())
    }

    pub fn with_config(config: Config) -> PrivateL2ConfidentialTokenTransferRuntimeResult<Self> {
        if config.min_privacy_set_size == 0 {
            return Err("min privacy set size must be non-zero".to_string());
        }
        if config.batch_privacy_set_size < config.min_privacy_set_size {
            return Err("batch privacy set must cover the minimum privacy set".to_string());
        }
        if config.min_pq_security_bits < 192 {
            return Err("minimum pq security bits must be at least 192".to_string());
        }
        if config.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_MAX_BPS {
            return Err("max user fee exceeds bps denominator".to_string());
        }
        if config.max_sponsor_fee_bps > config.max_user_fee_bps {
            return Err("sponsor fee cap must not exceed user fee cap".to_string());
        }
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_DEVNET_HEIGHT,
            assets: BTreeMap::new(),
            transfers: BTreeMap::new(),
            attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            seen_nullifier_roots: BTreeSet::new(),
            public_records: Vec::new(),
        })
    }

    pub fn register_asset(
        &mut self,
        request: RegisterTokenAssetRequest,
    ) -> PrivateL2ConfidentialTokenTransferRuntimeResult<TokenAssetRecord> {
        if self.assets.len() >= self.config.max_registered_assets {
            return Err("confidential token asset registry is full".to_string());
        }
        if self.assets.contains_key(&request.asset_id) {
            return Err("asset already registered".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("asset privacy set is below runtime minimum".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("asset pq security bits below runtime minimum".to_string());
        }
        self.counters.assets_registered = self.counters.assets_registered.saturating_add(1);
        let asset_record_id = token_asset_record_id(&request, self.counters.assets_registered);
        let record = TokenAssetRecord {
            asset_record_id: asset_record_id.clone(),
            created_at_height: request.registered_at_height,
            request,
            status: AssetStatus::Registered,
        };
        self.public_records.push(record.public_record());
        self.assets
            .insert(record.request.asset_id.clone(), record.clone());
        Ok(record)
    }

    pub fn submit_transfer(
        &mut self,
        request: SubmitConfidentialTransferRequest,
    ) -> PrivateL2ConfidentialTokenTransferRuntimeResult<ConfidentialTransferRecord> {
        if self.transfers.len() >= self.config.max_transfers {
            return Err("confidential token transfer queue is full".to_string());
        }
        let asset = self
            .assets
            .get(&request.asset_id)
            .ok_or_else(|| "asset not registered for confidential transfers".to_string())?;
        if !asset.status.accepts_transfers() {
            return Err("asset does not currently accept transfers".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("transfer max fee exceeds runtime fee cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("transfer privacy set is below runtime minimum".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("transfer pq security bits below runtime minimum".to_string());
        }
        if request.expires_at_height <= request.submitted_at_height {
            return Err("transfer expiry must be after submission height".to_string());
        }
        if self.seen_nullifier_roots.contains(&request.nullifier_root) {
            return Err("transfer nullifier root already seen".to_string());
        }
        self.counters.transfers_submitted = self.counters.transfers_submitted.saturating_add(1);
        let transfer_id = transfer_id(&request, self.counters.transfers_submitted);
        let nullifier_root = request.nullifier_root.clone();
        let record = ConfidentialTransferRecord {
            transfer_id: transfer_id.clone(),
            submitted_at_height: request.submitted_at_height,
            request,
            status: TransferStatus::Submitted,
            compliance_attestation_id: None,
            sponsor_reservation_id: None,
            batch_id: None,
        };
        self.seen_nullifier_roots.insert(nullifier_root);
        self.public_records.push(record.public_record());
        self.transfers.insert(transfer_id, record.clone());
        Ok(record)
    }

    pub fn attest_compliance(
        &mut self,
        request: AttestTransferComplianceRequest,
    ) -> PrivateL2ConfidentialTokenTransferRuntimeResult<ComplianceAttestationRecord> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("compliance attestation store is full".to_string());
        }
        let transfer = self
            .transfers
            .get_mut(&request.transfer_id)
            .ok_or_else(|| "transfer missing for compliance attestation".to_string())?;
        if !transfer.status.batchable() {
            return Err("transfer no longer accepts compliance attestations".to_string());
        }
        if request.risk_score_bps > PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_MAX_BPS {
            return Err("risk score exceeds bps denominator".to_string());
        }
        if !request.verdict.allows_batching() {
            transfer.status = TransferStatus::Rejected;
        } else {
            transfer.status = TransferStatus::ComplianceAttested;
        }
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        let attestation_id =
            compliance_attestation_id(&request, self.counters.attestations_recorded);
        transfer.compliance_attestation_id = Some(attestation_id.clone());
        let record = ComplianceAttestationRecord {
            attestation_id,
            request,
        };
        self.public_records.push(record.public_record());
        self.attestations
            .insert(record.attestation_id.clone(), record.clone());
        Ok(record)
    }

    pub fn reserve_fee_sponsor(
        &mut self,
        request: ReserveTransferFeeSponsorRequest,
    ) -> PrivateL2ConfidentialTokenTransferRuntimeResult<FeeSponsorReservationRecord> {
        if self.reservations.len() >= self.config.max_reservations {
            return Err("fee sponsor reservation store is full".to_string());
        }
        let transfer = self
            .transfers
            .get_mut(&request.transfer_id)
            .ok_or_else(|| "transfer missing for sponsor reservation".to_string())?;
        if !transfer.status.batchable() {
            return Err("transfer is not sponsor-reservable".to_string());
        }
        if request.reserved_fee_bps > self.config.max_sponsor_fee_bps {
            return Err("reserved sponsor fee exceeds runtime cap".to_string());
        }
        if request.expires_at_height <= request.reserved_at_height {
            return Err("sponsor reservation expiry must be after reservation height".to_string());
        }
        self.counters.sponsor_reservations = self.counters.sponsor_reservations.saturating_add(1);
        let reservation_id =
            fee_sponsor_reservation_id(&request, self.counters.sponsor_reservations);
        transfer.sponsor_reservation_id = Some(reservation_id.clone());
        transfer.status = TransferStatus::SponsorReserved;
        let record = FeeSponsorReservationRecord {
            reservation_id,
            request,
            status: ReservationStatus::Reserved,
        };
        self.public_records.push(record.public_record());
        self.reservations
            .insert(record.reservation_id.clone(), record.clone());
        Ok(record)
    }

    pub fn build_transfer_batch(
        &mut self,
        request: BuildTransferBatchRequest,
    ) -> PrivateL2ConfidentialTokenTransferRuntimeResult<TransferBatchRecord> {
        if self.batches.len() >= self.config.max_batches {
            return Err("confidential transfer batch store is full".to_string());
        }
        if request.transfer_ids.is_empty() {
            return Err("transfer batch must include at least one transfer".to_string());
        }
        if request.transfer_ids.len() > self.config.max_batch_items {
            return Err("transfer batch exceeds max batch item count".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("batch fee exceeds runtime fee cap".to_string());
        }
        if request.privacy_set_size < self.config.batch_privacy_set_size {
            return Err("batch privacy set below runtime batch target".to_string());
        }
        let mut unique_transfer_ids = BTreeSet::new();
        for transfer_id in &request.transfer_ids {
            if !unique_transfer_ids.insert(transfer_id.clone()) {
                return Err("transfer batch contains a duplicate transfer id".to_string());
            }
            let transfer = self
                .transfers
                .get(transfer_id)
                .ok_or_else(|| format!("transfer missing from runtime: {transfer_id}"))?;
            if !transfer.status.batchable() {
                return Err(format!("transfer is not batchable: {transfer_id}"));
            }
        }
        let requested_asset_ids = request.asset_ids.iter().cloned().collect::<BTreeSet<_>>();
        for transfer_id in &request.transfer_ids {
            let transfer = self
                .transfers
                .get(transfer_id)
                .ok_or_else(|| format!("transfer missing from runtime: {transfer_id}"))?;
            if !requested_asset_ids.contains(&transfer.request.asset_id) {
                return Err(format!("batch asset list missing asset for {transfer_id}"));
            }
        }
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        let batch_id = transfer_batch_id(&request, self.counters.batches_built);
        for transfer_id in &request.transfer_ids {
            if let Some(transfer) = self.transfers.get_mut(transfer_id) {
                transfer.status = TransferStatus::Batched;
                transfer.batch_id = Some(batch_id.clone());
            }
        }
        let record = TransferBatchRecord {
            batch_id,
            request,
            status: BatchStatus::Built,
            settlement_receipt_id: None,
        };
        self.public_records.push(record.public_record());
        self.batches.insert(record.batch_id.clone(), record.clone());
        Ok(record)
    }

    pub fn settle_transfer_batch(
        &mut self,
        request: SettleTransferBatchRequest,
    ) -> PrivateL2ConfidentialTokenTransferRuntimeResult<TransferSettlementReceipt> {
        if self.receipts.len() >= self.config.max_batches {
            return Err("transfer settlement receipt store is full".to_string());
        }
        if request.settled_fee_bps > self.config.max_user_fee_bps {
            return Err("settled fee exceeds runtime fee cap".to_string());
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "transfer batch missing for settlement".to_string())?;
        if !matches!(batch.status, BatchStatus::Built | BatchStatus::Sealed) {
            return Err("transfer batch cannot be settled from its current status".to_string());
        }
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        let receipt_id = settlement_receipt_id(&request, self.counters.receipts_published);
        let settled_transfer_ids = batch.request.transfer_ids.clone();
        batch.status = BatchStatus::Settled;
        batch.settlement_receipt_id = Some(receipt_id.clone());
        for transfer_id in &settled_transfer_ids {
            if let Some(transfer) = self.transfers.get_mut(transfer_id) {
                transfer.status = TransferStatus::Settled;
                self.counters.transfers_settled = self.counters.transfers_settled.saturating_add(1);
            }
        }
        for reservation in self.reservations.values_mut() {
            if settled_transfer_ids.contains(&reservation.request.transfer_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let receipt = TransferSettlementReceipt {
            receipt_id,
            request,
            status: ReceiptStatus::Published,
            settled_transfer_ids,
        };
        self.public_records.push(receipt.public_record());
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let asset_records = self
            .assets
            .values()
            .map(TokenAssetRecord::public_record)
            .collect::<Vec<_>>();
        let transfer_records = self
            .transfers
            .values()
            .map(ConfidentialTransferRecord::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .attestations
            .values()
            .map(ComplianceAttestationRecord::public_record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .reservations
            .values()
            .map(FeeSponsorReservationRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(TransferBatchRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(TransferSettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .seen_nullifier_roots
            .iter()
            .map(|root| json!({ "nullifier_root": root }))
            .collect::<Vec<_>>();
        Roots {
            asset_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-TOKEN-ASSET", &asset_records),
            transfer_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-TOKEN-TRANSFER", &transfer_records),
            attestation_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-COMPLIANCE",
                &attestation_records,
            ),
            reservation_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-SPONSOR",
                &reservation_records,
            ),
            batch_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-TOKEN-BATCH", &batch_records),
            receipt_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-TOKEN-RECEIPT", &receipt_records),
            nullifier_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-NULLIFIER",
                &nullifier_records,
            ),
            public_record_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-PUBLIC-RECORD",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_transfer_runtime",
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_PQ_AUTH_SUITE,
            "note_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_NOTE_SCHEME,
            "nullifier_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_NULLIFIER_SCHEME,
            "balance_proof_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_BALANCE_PROOF_SCHEME,
            "compliance_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_COMPLIANCE_SCHEME,
            "sponsor_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_SPONSOR_SCHEME,
            "batch_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_BATCH_SCHEME,
            "config": self.config.public_record(),
            "config_root": self.config.state_root(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        let state_root = root_from_record("PRIVATE-L2-CONFIDENTIAL-TOKEN-TRANSFER-STATE", &record);
        json!({
            "state_root": state_root,
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-TRANSFER-STATE",
            &self.public_record_without_state_root(),
        )
    }
}

pub fn token_asset_record_id(request: &RegisterTokenAssetRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-ASSET-ID",
        &[
            HashPart::Str(&request.asset_id),
            HashPart::Str(request.token_class.as_str()),
            HashPart::Str(&request.issuer_commitment),
            HashPart::Str(&request.supply_commitment_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn transfer_id(request: &SubmitConfidentialTransferRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-TRANSFER-ID",
        &[
            HashPart::Str(&request.asset_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.sender_commitment),
            HashPart::Str(&request.receiver_commitment),
            HashPart::Str(&request.input_note_root),
            HashPart::Str(&request.output_note_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn compliance_attestation_id(
    request: &AttestTransferComplianceRequest,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-COMPLIANCE-ID",
        &[
            HashPart::Str(&request.transfer_id),
            HashPart::Str(&request.attestor_commitment),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.proof_root),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn fee_sponsor_reservation_id(
    request: &ReserveTransferFeeSponsorRequest,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-SPONSOR-ID",
        &[
            HashPart::Str(&request.transfer_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.budget_root),
            HashPart::Str(&request.fee_asset_id),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn transfer_batch_id(request: &BuildTransferBatchRequest, counter: u64) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-BATCH-ID",
        &[
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &SettleTransferBatchRequest, counter: u64) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-RECEIPT-ID",
        &[
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_TRANSFER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}
