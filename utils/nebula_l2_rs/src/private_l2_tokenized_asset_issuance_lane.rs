use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2TokenizedAssetIssuanceLaneResult<T> = Result<T, String>;

pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION: &str =
    "private-l2-tokenized-asset-issuance-lane-v1";
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_HASH_SUITE: &str =
    "shake256-merkle-domain-separated";
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PRIVACY_PROOF_SCHEME: &str =
    "confidential-asset-membership-v1";
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_SUPPLY_PROOF_SCHEME: &str =
    "private-supply-conservation-v1";
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_FEE_SPONSOR_SCHEME: &str =
    "low-fee-token-issuance-sponsor-v1";
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MAX_ASSETS: usize = 65_536;
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MAX_OPS_PER_BATCH: usize = 512;
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MIN_PRIVACY_SET: u64 = 128;
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MAX_FEE_BPS: u64 = 22;
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_BATCH_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    ConfidentialToken,
    WrappedMonero,
    StableAsset,
    VaultShare,
    GovernanceNote,
    SyntheticClaim,
}

impl AssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialToken => "confidential_token",
            Self::WrappedMonero => "wrapped_monero",
            Self::StableAsset => "stable_asset",
            Self::VaultShare => "vault_share",
            Self::GovernanceNote => "governance_note",
            Self::SyntheticClaim => "synthetic_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetStatus {
    Draft,
    Registered,
    Minting,
    Active,
    Frozen,
    Retired,
}

impl AssetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Registered => "registered",
            Self::Minting => "minting",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetOperationKind {
    Register,
    Mint,
    Burn,
    Transfer,
    Freeze,
    Unfreeze,
    RotateAuthority,
}

impl AssetOperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Transfer => "transfer",
            Self::Freeze => "freeze",
            Self::Unfreeze => "unfreeze",
            Self::RotateAuthority => "rotate_authority",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Submitted,
    Accepted,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl OperationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceBatchStatus {
    Open,
    Sealed,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl IssuanceBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub privacy_proof_scheme: String,
    pub supply_proof_scheme: String,
    pub fee_sponsor_scheme: String,
    pub max_assets: usize,
    pub max_ops_per_batch: usize,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub batch_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PQ_SIGNATURE_SCHEME
                .to_string(),
            privacy_proof_scheme: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PRIVACY_PROOF_SCHEME
                .to_string(),
            supply_proof_scheme: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_SUPPLY_PROOF_SCHEME
                .to_string(),
            fee_sponsor_scheme: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_FEE_SPONSOR_SCHEME
                .to_string(),
            max_assets: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MAX_ASSETS,
            max_ops_per_batch: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MAX_OPS_PER_BATCH,
            min_privacy_set: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_MAX_FEE_BPS,
            batch_ttl_blocks: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEFAULT_BATCH_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateL2TokenizedAssetIssuanceLaneResult<()> {
        if self.protocol_version.trim().is_empty()
            || self.chain_id.trim().is_empty()
            || self.hash_suite.trim().is_empty()
            || self.pq_signature_scheme.trim().is_empty()
            || self.privacy_proof_scheme.trim().is_empty()
            || self.supply_proof_scheme.trim().is_empty()
            || self.fee_sponsor_scheme.trim().is_empty()
        {
            return Err("tokenized asset issuance config labels cannot be empty".to_string());
        }
        if self.max_assets == 0
            || self.max_ops_per_batch == 0
            || self.min_privacy_set == 0
            || self.min_pq_security_bits == 0
            || self.batch_ttl_blocks == 0
        {
            return Err("tokenized asset issuance limits must be positive".to_string());
        }
        if self.max_fee_bps == 0
            || self.max_fee_bps > PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_MAX_BPS
        {
            return Err("tokenized asset issuance fee cap is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset_issuance_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_SCHEMA_VERSION,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "privacy_proof_scheme": self.privacy_proof_scheme,
            "supply_proof_scheme": self.supply_proof_scheme,
            "fee_sponsor_scheme": self.fee_sponsor_scheme,
            "max_assets": self.max_assets,
            "max_ops_per_batch": self.max_ops_per_batch,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "batch_ttl_blocks": self.batch_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_asset_nonce: u64,
    pub next_operation_nonce: u64,
    pub next_batch_nonce: u64,
    pub next_receipt_nonce: u64,
    pub assets_registered: u64,
    pub operations_submitted: u64,
    pub operations_accepted: u64,
    pub operations_rejected: u64,
    pub batches_built: u64,
    pub batches_settled: u64,
    pub receipts_issued: u64,
    pub nullifiers_consumed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset_issuance_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION,
            "next_asset_nonce": self.next_asset_nonce,
            "next_operation_nonce": self.next_operation_nonce,
            "next_batch_nonce": self.next_batch_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "assets_registered": self.assets_registered,
            "operations_submitted": self.operations_submitted,
            "operations_accepted": self.operations_accepted,
            "operations_rejected": self.operations_rejected,
            "batches_built": self.batches_built,
            "batches_settled": self.batches_settled,
            "receipts_issued": self.receipts_issued,
            "nullifiers_consumed": self.nullifiers_consumed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAssetRequest {
    pub issuer_commitment: String,
    pub asset_kind: AssetKind,
    pub metadata_root: String,
    pub symbol_commitment: String,
    pub decimals_root: String,
    pub supply_cap_root: String,
    pub reserve_binding_root: String,
    pub compliance_policy_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub fee_sponsor_root: String,
    pub opened_at_height: u64,
}

impl RegisterAssetRequest {
    pub fn validate(&self) -> PrivateL2TokenizedAssetIssuanceLaneResult<()> {
        validate_root("issuer_commitment", &self.issuer_commitment)?;
        validate_root("metadata_root", &self.metadata_root)?;
        validate_root("symbol_commitment", &self.symbol_commitment)?;
        validate_root("decimals_root", &self.decimals_root)?;
        validate_root("supply_cap_root", &self.supply_cap_root)?;
        validate_root("reserve_binding_root", &self.reserve_binding_root)?;
        validate_root("compliance_policy_root", &self.compliance_policy_root)?;
        validate_root("pq_authority_root", &self.pq_authority_root)?;
        validate_root("privacy_policy_root", &self.privacy_policy_root)?;
        validate_root("fee_sponsor_root", &self.fee_sponsor_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset_register_request",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION,
            "issuer_commitment": self.issuer_commitment,
            "asset_kind": self.asset_kind.as_str(),
            "metadata_root": self.metadata_root,
            "symbol_commitment": self.symbol_commitment,
            "decimals_root": self.decimals_root,
            "supply_cap_root": self.supply_cap_root,
            "reserve_binding_root": self.reserve_binding_root,
            "compliance_policy_root": self.compliance_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredAsset {
    pub asset_id: String,
    pub nonce: u64,
    pub status: AssetStatus,
    pub issuer_commitment: String,
    pub asset_kind: AssetKind,
    pub metadata_root: String,
    pub symbol_commitment: String,
    pub decimals_root: String,
    pub supply_cap_root: String,
    pub reserve_binding_root: String,
    pub compliance_policy_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub fee_sponsor_root: String,
    pub total_supply_root: String,
    pub holder_set_root: String,
    pub opened_at_height: u64,
    pub asset_root: String,
}

impl RegisteredAsset {
    pub fn new(
        nonce: u64,
        request: RegisterAssetRequest,
    ) -> PrivateL2TokenizedAssetIssuanceLaneResult<Self> {
        let seed = request.public_record();
        let asset_root = issuance_payload_root("ASSET-SEED", &seed);
        let asset_id = asset_id(
            nonce,
            request.asset_kind,
            &request.issuer_commitment,
            &asset_root,
        );
        Ok(Self {
            asset_id,
            nonce,
            status: AssetStatus::Registered,
            issuer_commitment: request.issuer_commitment,
            asset_kind: request.asset_kind,
            metadata_root: request.metadata_root,
            symbol_commitment: request.symbol_commitment,
            decimals_root: request.decimals_root,
            supply_cap_root: request.supply_cap_root,
            reserve_binding_root: request.reserve_binding_root,
            compliance_policy_root: request.compliance_policy_root,
            pq_authority_root: request.pq_authority_root,
            privacy_policy_root: request.privacy_policy_root,
            fee_sponsor_root: request.fee_sponsor_root,
            total_supply_root: empty_root("PRIVATE-L2-TOKENIZED-ASSET-SUPPLY"),
            holder_set_root: empty_root("PRIVATE-L2-TOKENIZED-ASSET-HOLDERS"),
            opened_at_height: request.opened_at_height,
            asset_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION,
            "asset_id": self.asset_id,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "issuer_commitment": self.issuer_commitment,
            "asset_kind": self.asset_kind.as_str(),
            "metadata_root": self.metadata_root,
            "symbol_commitment": self.symbol_commitment,
            "decimals_root": self.decimals_root,
            "supply_cap_root": self.supply_cap_root,
            "reserve_binding_root": self.reserve_binding_root,
            "compliance_policy_root": self.compliance_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "total_supply_root": self.total_supply_root,
            "holder_set_root": self.holder_set_root,
            "opened_at_height": self.opened_at_height,
            "asset_root": self.asset_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitOperationRequest {
    pub asset_id: String,
    pub operation_kind: AssetOperationKind,
    pub actor_commitment: String,
    pub amount_commitment_root: String,
    pub source_account_root: String,
    pub destination_account_root: String,
    pub memo_ciphertext_root: String,
    pub supply_delta_root: String,
    pub reserve_delta_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub supply_proof_root: String,
    pub fee_sponsor_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitOperationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2TokenizedAssetIssuanceLaneResult<()> {
        validate_identifier("asset_id", &self.asset_id)?;
        validate_root("actor_commitment", &self.actor_commitment)?;
        validate_root("amount_commitment_root", &self.amount_commitment_root)?;
        validate_root("source_account_root", &self.source_account_root)?;
        validate_root("destination_account_root", &self.destination_account_root)?;
        validate_root("memo_ciphertext_root", &self.memo_ciphertext_root)?;
        validate_root("supply_delta_root", &self.supply_delta_root)?;
        validate_root("reserve_delta_root", &self.reserve_delta_root)?;
        validate_root("pq_authorization_root", &self.pq_authorization_root)?;
        validate_root("privacy_proof_root", &self.privacy_proof_root)?;
        validate_root("supply_proof_root", &self.supply_proof_root)?;
        validate_root("fee_sponsor_root", &self.fee_sponsor_root)?;
        validate_root("nullifier_root", &self.nullifier_root)?;
        if self.privacy_set_size < config.min_privacy_set {
            return Err("asset operation privacy set below policy".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("asset operation pq security below policy".to_string());
        }
        if self.max_fee_bps == 0 || self.max_fee_bps > config.max_fee_bps {
            return Err("asset operation fee exceeds policy".to_string());
        }
        if self.opened_at_height >= self.expires_at_height {
            return Err("asset operation expiry must follow opening".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset_operation_request",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION,
            "asset_id": self.asset_id,
            "operation_kind": self.operation_kind.as_str(),
            "actor_commitment": self.actor_commitment,
            "amount_commitment_root": self.amount_commitment_root,
            "source_account_root": self.source_account_root,
            "destination_account_root": self.destination_account_root,
            "memo_ciphertext_root": self.memo_ciphertext_root,
            "supply_delta_root": self.supply_delta_root,
            "reserve_delta_root": self.reserve_delta_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "supply_proof_root": self.supply_proof_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetOperation {
    pub operation_id: String,
    pub nonce: u64,
    pub status: OperationStatus,
    pub asset_id: String,
    pub operation_kind: AssetOperationKind,
    pub actor_commitment: String,
    pub amount_commitment_root: String,
    pub source_account_root: String,
    pub destination_account_root: String,
    pub memo_ciphertext_root: String,
    pub supply_delta_root: String,
    pub reserve_delta_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub supply_proof_root: String,
    pub fee_sponsor_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub operation_root: String,
    pub batch_id: Option<String>,
}

impl AssetOperation {
    pub fn new(nonce: u64, request: SubmitOperationRequest) -> Self {
        let operation_root = issuance_payload_root("OPERATION-SEED", &request.public_record());
        let operation_id = operation_id(
            nonce,
            request.operation_kind,
            &request.asset_id,
            &operation_root,
        );
        Self {
            operation_id,
            nonce,
            status: OperationStatus::Accepted,
            asset_id: request.asset_id,
            operation_kind: request.operation_kind,
            actor_commitment: request.actor_commitment,
            amount_commitment_root: request.amount_commitment_root,
            source_account_root: request.source_account_root,
            destination_account_root: request.destination_account_root,
            memo_ciphertext_root: request.memo_ciphertext_root,
            supply_delta_root: request.supply_delta_root,
            reserve_delta_root: request.reserve_delta_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            supply_proof_root: request.supply_proof_root,
            fee_sponsor_root: request.fee_sponsor_root,
            nullifier_root: request.nullifier_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            operation_root,
            batch_id: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset_operation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION,
            "operation_id": self.operation_id,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "operation_kind": self.operation_kind.as_str(),
            "actor_commitment": self.actor_commitment,
            "amount_commitment_root": self.amount_commitment_root,
            "source_account_root": self.source_account_root,
            "destination_account_root": self.destination_account_root,
            "memo_ciphertext_root": self.memo_ciphertext_root,
            "supply_delta_root": self.supply_delta_root,
            "reserve_delta_root": self.reserve_delta_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "supply_proof_root": self.supply_proof_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "operation_root": self.operation_root,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildIssuanceBatchRequest {
    pub operation_ids: Vec<String>,
    pub builder_commitment: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_privacy_proof_root: String,
    pub aggregate_supply_proof_root: String,
    pub fee_sponsor_root: String,
    pub token_registry_root_before: String,
    pub token_registry_root_after: String,
    pub account_delta_root: String,
    pub reserve_delta_root: String,
    pub max_fee_bps: u64,
    pub sealed_at_height: u64,
}

impl BuildIssuanceBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2TokenizedAssetIssuanceLaneResult<()> {
        if self.operation_ids.is_empty() {
            return Err("issuance batch requires operations".to_string());
        }
        if self.operation_ids.len() > config.max_ops_per_batch {
            return Err("issuance batch exceeds operation limit".to_string());
        }
        validate_root("builder_commitment", &self.builder_commitment)?;
        validate_root(
            "aggregate_pq_authorization_root",
            &self.aggregate_pq_authorization_root,
        )?;
        validate_root(
            "aggregate_privacy_proof_root",
            &self.aggregate_privacy_proof_root,
        )?;
        validate_root(
            "aggregate_supply_proof_root",
            &self.aggregate_supply_proof_root,
        )?;
        validate_root("fee_sponsor_root", &self.fee_sponsor_root)?;
        validate_root(
            "token_registry_root_before",
            &self.token_registry_root_before,
        )?;
        validate_root("token_registry_root_after", &self.token_registry_root_after)?;
        validate_root("account_delta_root", &self.account_delta_root)?;
        validate_root("reserve_delta_root", &self.reserve_delta_root)?;
        if self.max_fee_bps == 0 || self.max_fee_bps > config.max_fee_bps {
            return Err("issuance batch fee exceeds policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceBatch {
    pub batch_id: String,
    pub nonce: u64,
    pub status: IssuanceBatchStatus,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub settlement_deadline_height: u64,
    pub builder_commitment: String,
    pub operation_root: String,
    pub asset_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_privacy_proof_root: String,
    pub aggregate_supply_proof_root: String,
    pub fee_sponsor_root: String,
    pub token_registry_root_before: String,
    pub token_registry_root_after: String,
    pub account_delta_root: String,
    pub reserve_delta_root: String,
    pub max_fee_bps: u64,
    pub operation_ids: Vec<String>,
    pub asset_ids: Vec<String>,
}

impl IssuanceBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset_issuance_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "builder_commitment": self.builder_commitment,
            "operation_root": self.operation_root,
            "asset_root": self.asset_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "aggregate_privacy_proof_root": self.aggregate_privacy_proof_root,
            "aggregate_supply_proof_root": self.aggregate_supply_proof_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "token_registry_root_before": self.token_registry_root_before,
            "token_registry_root_after": self.token_registry_root_after,
            "account_delta_root": self.account_delta_root,
            "reserve_delta_root": self.reserve_delta_root,
            "max_fee_bps": self.max_fee_bps,
            "operation_ids": self.operation_ids,
            "asset_ids": self.asset_ids,
        })
    }

    pub fn state_root(&self) -> String {
        issuance_payload_root("BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleIssuanceBatchRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub token_registry_root_after: String,
    pub pq_settlement_attestation_root: String,
    pub fee_receipt_root: String,
    pub finalized_at_height: Option<u64>,
    pub settled_at_height: u64,
}

impl SettleIssuanceBatchRequest {
    pub fn validate(&self) -> PrivateL2TokenizedAssetIssuanceLaneResult<()> {
        validate_identifier("batch_id", &self.batch_id)?;
        validate_root("settlement_tx_root", &self.settlement_tx_root)?;
        validate_root("settlement_proof_root", &self.settlement_proof_root)?;
        validate_root("token_registry_root_after", &self.token_registry_root_after)?;
        validate_root(
            "pq_settlement_attestation_root",
            &self.pq_settlement_attestation_root,
        )?;
        validate_root("fee_receipt_root", &self.fee_receipt_root)?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.settled_at_height {
                return Err("issuance finalization cannot precede settlement".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub nonce: u64,
    pub batch_id: String,
    pub status: ReceiptStatus,
    pub batch_root: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub token_registry_root_after: String,
    pub pq_settlement_attestation_root: String,
    pub fee_receipt_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub published_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset_issuance_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "nonce": self.nonce,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "token_registry_root_after": self.token_registry_root_after,
            "pq_settlement_attestation_root": self.pq_settlement_attestation_root,
            "fee_receipt_root": self.fee_receipt_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "published_at_height": self.published_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub asset_root: String,
    pub operation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub consumed_nullifier_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset_issuance_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "asset_root": self.asset_root,
            "operation_root": self.operation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub token_registry_root: String,
    pub assets: BTreeMap<String, RegisteredAsset>,
    pub operations: BTreeMap<String, AssetOperation>,
    pub batches: BTreeMap<String, IssuanceBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub consumed_nullifier_roots: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            current_height: PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_DEVNET_HEIGHT,
            token_registry_root: empty_root("PRIVATE-L2-TOKENIZED-ASSET-REGISTRY"),
            assets: BTreeMap::new(),
            operations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
        }
    }

    pub fn register_asset(
        &mut self,
        request: RegisterAssetRequest,
    ) -> PrivateL2TokenizedAssetIssuanceLaneResult<RegisteredAsset> {
        self.config.validate()?;
        request.validate()?;
        if self.assets.len() >= self.config.max_assets {
            return Err("tokenized asset capacity exhausted".to_string());
        }
        let nonce = self.counters.next_asset_nonce;
        let asset = RegisteredAsset::new(nonce, request)?;
        if self
            .assets
            .insert(asset.asset_id.clone(), asset.clone())
            .is_some()
        {
            return Err("tokenized asset already exists".to_string());
        }
        self.counters.next_asset_nonce = self.counters.next_asset_nonce.saturating_add(1);
        self.counters.assets_registered = self.counters.assets_registered.saturating_add(1);
        self.current_height = self.current_height.max(asset.opened_at_height);
        self.refresh_registry_root();
        Ok(asset)
    }

    pub fn submit_operation(
        &mut self,
        request: SubmitOperationRequest,
    ) -> PrivateL2TokenizedAssetIssuanceLaneResult<AssetOperation> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if !self.assets.contains_key(&request.asset_id) {
            return Err("asset operation references unknown asset".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&request.nullifier_root)
            || self
                .operations
                .values()
                .any(|operation| operation.nullifier_root == request.nullifier_root)
        {
            self.counters.operations_rejected = self.counters.operations_rejected.saturating_add(1);
            return Err("asset operation nullifier already exists".to_string());
        }
        let nonce = self.counters.next_operation_nonce;
        let operation = AssetOperation::new(nonce, request);
        self.counters.next_operation_nonce = self.counters.next_operation_nonce.saturating_add(1);
        self.counters.operations_submitted = self.counters.operations_submitted.saturating_add(1);
        self.counters.operations_accepted = self.counters.operations_accepted.saturating_add(1);
        self.current_height = self.current_height.max(operation.opened_at_height);
        self.operations
            .insert(operation.operation_id.clone(), operation.clone());
        Ok(operation)
    }

    pub fn build_batch(
        &mut self,
        request: BuildIssuanceBatchRequest,
    ) -> PrivateL2TokenizedAssetIssuanceLaneResult<IssuanceBatch> {
        self.config.validate()?;
        request.validate(&self.config)?;
        ensure_unique("operation_ids", &request.operation_ids)?;

        let mut operations = Vec::with_capacity(request.operation_ids.len());
        let mut asset_ids = BTreeSet::new();
        for operation_id in &request.operation_ids {
            let operation = self
                .operations
                .get(operation_id)
                .ok_or_else(|| format!("unknown asset operation {operation_id}"))?;
            if !operation.status.selectable() {
                return Err(format!("asset operation {operation_id} is not selectable"));
            }
            if operation.expires_at_height < request.sealed_at_height {
                return Err(format!("asset operation {operation_id} expired"));
            }
            operations.push(operation.clone());
            asset_ids.insert(operation.asset_id.clone());
        }

        let asset_records = asset_ids
            .iter()
            .filter_map(|asset_id| self.assets.get(asset_id))
            .map(RegisteredAsset::public_record)
            .collect::<Vec<_>>();
        let operation_records = operations
            .iter()
            .map(AssetOperation::public_record)
            .collect::<Vec<_>>();
        let asset_root = merkle_root(
            "PRIVATE-L2-TOKENIZED-ASSET-ISSUANCE-BATCH-ASSETS",
            &asset_records,
        );
        let operation_root = merkle_root(
            "PRIVATE-L2-TOKENIZED-ASSET-ISSUANCE-BATCH-OPERATIONS",
            &operation_records,
        );
        let nonce = self.counters.next_batch_nonce;
        let batch_id = issuance_batch_id(nonce, &operation_root, &asset_root);
        let opened_at_height = operations
            .iter()
            .map(|operation| operation.opened_at_height)
            .min()
            .unwrap_or(request.sealed_at_height);
        let batch = IssuanceBatch {
            batch_id: batch_id.clone(),
            nonce,
            status: IssuanceBatchStatus::SettlementReady,
            opened_at_height,
            sealed_at_height: request.sealed_at_height,
            settlement_deadline_height: request
                .sealed_at_height
                .saturating_add(self.config.batch_ttl_blocks),
            builder_commitment: request.builder_commitment,
            operation_root,
            asset_root,
            aggregate_pq_authorization_root: request.aggregate_pq_authorization_root,
            aggregate_privacy_proof_root: request.aggregate_privacy_proof_root,
            aggregate_supply_proof_root: request.aggregate_supply_proof_root,
            fee_sponsor_root: request.fee_sponsor_root,
            token_registry_root_before: request.token_registry_root_before,
            token_registry_root_after: request.token_registry_root_after,
            account_delta_root: request.account_delta_root,
            reserve_delta_root: request.reserve_delta_root,
            max_fee_bps: request.max_fee_bps,
            operation_ids: request.operation_ids.clone(),
            asset_ids: asset_ids.into_iter().collect::<Vec<_>>(),
        };
        for operation_id in &batch.operation_ids {
            if let Some(operation) = self.operations.get_mut(operation_id) {
                operation.status = OperationStatus::Batched;
                operation.batch_id = Some(batch.batch_id.clone());
            }
        }
        for asset_id in &batch.asset_ids {
            if let Some(asset) = self.assets.get_mut(asset_id) {
                asset.status = AssetStatus::Minting;
                asset.total_supply_root = batch.aggregate_supply_proof_root.clone();
                asset.holder_set_root = batch.account_delta_root.clone();
            }
        }
        self.token_registry_root = batch.token_registry_root_after.clone();
        self.current_height = self.current_height.max(batch.sealed_at_height);
        self.counters.next_batch_nonce = self.counters.next_batch_nonce.saturating_add(1);
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn settle_batch(
        &mut self,
        request: SettleIssuanceBatchRequest,
    ) -> PrivateL2TokenizedAssetIssuanceLaneResult<SettlementReceipt> {
        request.validate()?;
        let state_root_before = self.state_root();
        let batch = self
            .batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| "issuance batch not found".to_string())?;
        if batch.status != IssuanceBatchStatus::SettlementReady {
            return Err("issuance batch is not settlement ready".to_string());
        }
        if request.settled_at_height > batch.settlement_deadline_height {
            return Err("issuance batch settlement deadline elapsed".to_string());
        }
        if request.token_registry_root_after != batch.token_registry_root_after {
            return Err("issuance batch registry root mismatch".to_string());
        }
        for operation_id in &batch.operation_ids {
            if let Some(operation) = self.operations.get_mut(operation_id) {
                operation.status = OperationStatus::Settled;
                self.consumed_nullifier_roots
                    .insert(operation.nullifier_root.clone());
            }
        }
        for asset_id in &batch.asset_ids {
            if let Some(asset) = self.assets.get_mut(asset_id) {
                asset.status = AssetStatus::Active;
            }
        }
        if let Some(stored_batch) = self.batches.get_mut(&request.batch_id) {
            stored_batch.status = IssuanceBatchStatus::Settled;
        }
        self.token_registry_root = request.token_registry_root_after.clone();
        self.current_height = self.current_height.max(request.settled_at_height);
        self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        self.counters.nullifiers_consumed = self
            .counters
            .nullifiers_consumed
            .saturating_add(batch.operation_ids.len() as u64);
        let state_root_after = self.state_root();
        let nonce = self.counters.next_receipt_nonce;
        let receipt_id = settlement_receipt_id(
            nonce,
            &batch.batch_id,
            &request.settlement_tx_root,
            &request.settlement_proof_root,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            nonce,
            batch_id: request.batch_id,
            status: if request.finalized_at_height.is_some() {
                ReceiptStatus::Finalized
            } else {
                ReceiptStatus::Published
            },
            batch_root: batch.state_root(),
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            token_registry_root_after: request.token_registry_root_after,
            pq_settlement_attestation_root: request.pq_settlement_attestation_root,
            fee_receipt_root: request.fee_receipt_root,
            state_root_before,
            state_root_after,
            published_at_height: request.settled_at_height,
            finalized_at_height: request.finalized_at_height,
        };
        self.counters.next_receipt_nonce = self.counters.next_receipt_nonce.saturating_add(1);
        self.counters.receipts_issued = self.counters.receipts_issued.saturating_add(1);
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let asset_records = self
            .assets
            .values()
            .map(RegisteredAsset::public_record)
            .collect::<Vec<_>>();
        let operation_records = self
            .operations
            .values()
            .map(AssetOperation::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(IssuanceBatch::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let consumed_records = self
            .consumed_nullifier_roots
            .iter()
            .map(|root| json!(root))
            .collect::<Vec<_>>();
        Roots {
            config_root: issuance_payload_root("CONFIG", &self.config.public_record()),
            asset_root: merkle_root("PRIVATE-L2-TOKENIZED-ASSET-ASSETS", &asset_records),
            operation_root: merkle_root(
                "PRIVATE-L2-TOKENIZED-ASSET-OPERATIONS",
                &operation_records,
            ),
            batch_root: merkle_root("PRIVATE-L2-TOKENIZED-ASSET-BATCHES", &batch_records),
            receipt_root: merkle_root("PRIVATE-L2-TOKENIZED-ASSET-RECEIPTS", &receipt_records),
            consumed_nullifier_root: merkle_root(
                "PRIVATE-L2-TOKENIZED-ASSET-CONSUMED-NULLIFIERS",
                &consumed_records,
            ),
            counter_root: issuance_payload_root("COUNTERS", &self.counters.public_record()),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_tokenized_asset_issuance_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_SCHEMA_VERSION,
            "current_height": self.current_height,
            "token_registry_root": self.token_registry_root,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "asset_count": self.assets.len(),
            "operation_count": self.operations.len(),
            "batch_count": self.batches.len(),
            "receipt_count": self.receipts.len(),
            "consumed_nullifier_count": self.consumed_nullifier_roots.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
            object.insert(
                "recent_assets".to_string(),
                json!(self
                    .assets
                    .values()
                    .rev()
                    .take(16)
                    .map(RegisteredAsset::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "recent_batches".to_string(),
                json!(self
                    .batches
                    .values()
                    .rev()
                    .take(16)
                    .map(IssuanceBatch::public_record)
                    .collect::<Vec<_>>()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        issuance_payload_root("STATE", &self.public_record_without_root())
    }

    fn refresh_registry_root(&mut self) {
        let asset_records = self
            .assets
            .values()
            .map(RegisteredAsset::public_record)
            .collect::<Vec<_>>();
        self.token_registry_root =
            merkle_root("PRIVATE-L2-TOKENIZED-ASSET-REGISTRY", &asset_records);
    }
}

pub fn root_from_record(record: &Value) -> String {
    issuance_payload_root("RECORD", record)
}

pub fn devnet() -> State {
    State::devnet()
}

fn issuance_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-TOKENIZED-ASSET-ISSUANCE-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn asset_id(nonce: u64, kind: AssetKind, issuer_commitment: &str, asset_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-TOKENIZED-ASSET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION),
            HashPart::Int(nonce as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(issuer_commitment),
            HashPart::Str(asset_root),
        ],
        32,
    )
}

fn operation_id(
    nonce: u64,
    kind: AssetOperationKind,
    asset_id: &str,
    operation_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-TOKENIZED-ASSET-OPERATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION),
            HashPart::Int(nonce as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Str(operation_root),
        ],
        32,
    )
}

fn issuance_batch_id(nonce: u64, operation_root: &str, asset_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-TOKENIZED-ASSET-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION),
            HashPart::Int(nonce as i128),
            HashPart::Str(operation_root),
            HashPart::Str(asset_root),
        ],
        32,
    )
}

fn settlement_receipt_id(
    nonce: u64,
    batch_id: &str,
    settlement_tx_root: &str,
    settlement_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-TOKENIZED-ASSET-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_TOKENIZED_ASSET_ISSUANCE_LANE_PROTOCOL_VERSION),
            HashPart::Int(nonce as i128),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_tx_root),
            HashPart::Str(settlement_proof_root),
        ],
        32,
    )
}

fn ensure_unique(label: &str, values: &[String]) -> PrivateL2TokenizedAssetIssuanceLaneResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{label} cannot contain duplicates"));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> PrivateL2TokenizedAssetIssuanceLaneResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    if value.len() > 256 {
        return Err(format!("{label} is too long"));
    }
    Ok(())
}

fn validate_root(label: &str, value: &str) -> PrivateL2TokenizedAssetIssuanceLaneResult<()> {
    validate_identifier(label, value)?;
    if value.len() < 16 {
        return Err(format!("{label} must be root-like"));
    }
    Ok(())
}
