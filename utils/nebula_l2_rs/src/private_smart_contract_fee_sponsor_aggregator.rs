use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateSmartContractFeeSponsorAggregatorResult<T> = Result<T, String>;

pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_PROTOCOL_VERSION: &str =
    "nebula-private-smart-contract-fee-sponsor-aggregator-v1";
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_HASH_SUITE: &str =
    "SHAKE256-domain-separated";
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_ZK_RECEIPT_SUITE: &str =
    "zk-private-contract-fee-sponsor-receipt-v1";
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_PQ_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256s-fee-sponsor-v1";
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_COMMITMENT_SUITE: &str =
    "pedersen-note-commitment-poseidon-bridge-v1";
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT: u64 = 4_096;
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 18;
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_REVOCATION_DELAY_BLOCKS: u64 = 12;
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_MAX_SPEND_BPS: u64 = 6_500;
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 =
    1_200;
pub const PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorVaultStatus {
    Active,
    Rebalancing,
    Draining,
    Revoked,
    Settled,
    Frozen,
}

impl SponsorVaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rebalancing => "rebalancing",
            Self::Draining => "draining",
            Self::Revoked => "revoked",
            Self::Settled => "settled",
            Self::Frozen => "frozen",
        }
    }

    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active | Self::Rebalancing | Self::Draining)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Settled | Self::Frozen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasCreditStatus {
    Minted,
    Reserved,
    Applied,
    Settled,
    Revoked,
    Expired,
}

impl GasCreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Minted | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractLaneKind {
    PrivateDefiSwap,
    ConfidentialTokenTransfer,
    ShieldedLending,
    PrivateNftMint,
    OracleCallback,
    AccountRecovery,
    MoneroBridgeExit,
}

impl ContractLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
            Self::ShieldedLending => "shielded_lending",
            Self::PrivateNftMint => "private_nft_mint",
            Self::OracleCallback => "oracle_callback",
            Self::AccountRecovery => "account_recovery",
            Self::MoneroBridgeExit => "monero_bridge_exit",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::AccountRecovery => 96,
            Self::MoneroBridgeExit => 90,
            Self::ShieldedLending => 82,
            Self::PrivateDefiSwap => 78,
            Self::ConfidentialTokenTransfer => 72,
            Self::OracleCallback => 64,
            Self::PrivateNftMint => 58,
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::AccountRecovery => 700,
            Self::ConfidentialTokenTransfer => 850,
            Self::OracleCallback => 900,
            Self::PrivateDefiSwap => 1_200,
            Self::ShieldedLending => 1_450,
            Self::PrivateNftMint => 1_600,
            Self::MoneroBridgeExit => 1_900,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractLaneStatus {
    Open,
    LowFeeOnly,
    Throttled,
    Paused,
    Retired,
}

impl ContractLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::LowFeeOnly => "low_fee_only",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn admits_bundles(self) -> bool {
        matches!(self, Self::Open | Self::LowFeeOnly | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Open,
    Proving,
    Submitted,
    Settled,
    Revoked,
    Expired,
    Challenged,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proving => "proving",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Proving | Self::Submitted | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Accepted,
    Settled,
    Rejected,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerPolicyStatus {
    Active,
    Rotating,
    Paused,
    Revoked,
}

impl SignerPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
        }
    }

    pub fn allows_signing(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapStatus {
    Active,
    CoolingDown,
    Exhausted,
    Revoked,
}

impl CapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::CoolingDown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    Aggregated,
    Anchored,
    Finalized,
    Revoked,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Aggregated => "aggregated",
            Self::Anchored => "anchored",
            Self::Finalized => "finalized",
            Self::Revoked => "revoked",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Revoked)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub revocation_delay_blocks: u64,
    pub min_privacy_set_size: u64,
    pub max_spend_bps: u64,
    pub low_fee_target_micro_units: u64,
    pub hash_suite: String,
    pub zk_receipt_suite: String,
    pub pq_auth_suite: String,
    pub commitment_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            fee_asset_id: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_FEE_ASSET_ID
                .to_string(),
            epoch_blocks: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_EPOCH_BLOCKS,
            bundle_ttl_blocks:
                PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_BUNDLE_TTL_BLOCKS,
            settlement_delay_blocks:
                PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            revocation_delay_blocks:
                PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_REVOCATION_DELAY_BLOCKS,
            min_privacy_set_size:
                PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_spend_bps: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_MAX_SPEND_BPS,
            low_fee_target_micro_units:
                PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            hash_suite: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_HASH_SUITE.to_string(),
            zk_receipt_suite: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_ZK_RECEIPT_SUITE
                .to_string(),
            pq_auth_suite: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_PQ_AUTH_SUITE.to_string(),
            commitment_suite: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_COMMITMENT_SUITE
                .to_string(),
        }
    }

    pub fn validate(&self) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("config.epoch_blocks", self.epoch_blocks)?;
        ensure_positive("config.bundle_ttl_blocks", self.bundle_ttl_blocks)?;
        ensure_positive(
            "config.settlement_delay_blocks",
            self.settlement_delay_blocks,
        )?;
        ensure_positive(
            "config.revocation_delay_blocks",
            self.revocation_delay_blocks,
        )?;
        ensure_positive("config.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_bps("config.max_spend_bps", self.max_spend_bps)?;
        ensure_positive(
            "config.low_fee_target_micro_units",
            self.low_fee_target_micro_units,
        )?;
        ensure_non_empty("config.hash_suite", &self.hash_suite)?;
        ensure_non_empty("config.zk_receipt_suite", &self.zk_receipt_suite)?;
        ensure_non_empty("config.pq_auth_suite", &self.pq_auth_suite)?;
        ensure_non_empty("config.commitment_suite", &self.commitment_suite)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "revocation_delay_blocks": self.revocation_delay_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_spend_bps": self.max_spend_bps,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "hash_suite": self.hash_suite,
            "zk_receipt_suite": self.zk_receipt_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "commitment_suite": self.commitment_suite,
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorVault {
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub reserve_commitment_root: String,
    pub fee_asset_id: String,
    pub total_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub refundable_units: u64,
    pub status: SponsorVaultStatus,
    pub opened_at_height: u64,
    pub settlement_epoch: u64,
    pub view_tag_root: String,
}

impl SponsorVault {
    pub fn devnet(
        label: &str,
        sponsor_commitment: &str,
        total_units: u64,
        spent_units: u64,
        status: SponsorVaultStatus,
        config: &Config,
    ) -> Self {
        let vault_id = deterministic_id("VAULT-ID", label);
        let reserve_commitment_root = private_root("VAULT-RESERVE", &[label, sponsor_commitment]);
        let view_tag_root = private_root("VAULT-VIEW-TAGS", &[label, &config.fee_asset_id]);
        Self {
            vault_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            reserve_commitment_root,
            fee_asset_id: config.fee_asset_id.clone(),
            total_units,
            reserved_units: total_units.saturating_sub(spent_units) / 5,
            spent_units,
            refundable_units: total_units.saturating_sub(spent_units),
            status,
            opened_at_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT - 120,
            settlement_epoch: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT
                / config.epoch_blocks,
            view_tag_root,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "fee_asset_id": self.fee_asset_id,
            "total_units": self.total_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "refundable_units": self.refundable_units,
            "available_units": self.available_units(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "settlement_epoch": self.settlement_epoch,
            "view_tag_root": self.view_tag_root,
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("VAULT", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("vault.vault_id", &self.vault_id)?;
        ensure_non_empty("vault.sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty(
            "vault.reserve_commitment_root",
            &self.reserve_commitment_root,
        )?;
        ensure_non_empty("vault.fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("vault.total_units", self.total_units)?;
        ensure_non_empty("vault.view_tag_root", &self.view_tag_root)?;
        if self.fee_asset_id != config.fee_asset_id {
            return Err(format!(
                "vault {} uses unsupported fee asset",
                self.vault_id
            ));
        }
        if self.reserved_units.saturating_add(self.spent_units) > self.total_units {
            return Err(format!("vault {} is over reserved", self.vault_id));
        }
        if self.refundable_units > self.total_units {
            return Err(format!("vault {} refund exceeds total", self.vault_id));
        }
        if self.status.terminal()
            && self.available_units() > 0
            && self.status != SponsorVaultStatus::Frozen
        {
            return Err(format!(
                "vault {} terminal state still exposes spendable balance",
                self.vault_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasCredit {
    pub credit_id: String,
    pub vault_id: String,
    pub owner_note_commitment: String,
    pub lane_id: String,
    pub credit_units: u64,
    pub spent_units: u64,
    pub nullifier_root: String,
    pub blinding_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: GasCreditStatus,
}

impl PrivateGasCredit {
    pub fn devnet(
        label: &str,
        vault_id: &str,
        lane_id: &str,
        credit_units: u64,
        spent_units: u64,
        status: GasCreditStatus,
        config: &Config,
    ) -> Self {
        let credit_id = deterministic_id("CREDIT-ID", label);
        Self {
            credit_id,
            vault_id: vault_id.to_string(),
            owner_note_commitment: private_root("CREDIT-OWNER", &[label, vault_id]),
            lane_id: lane_id.to_string(),
            credit_units,
            spent_units,
            nullifier_root: private_root("CREDIT-NULLIFIER", &[label, lane_id]),
            blinding_root: private_root("CREDIT-BLINDING", &[label, &config.commitment_suite]),
            issued_at_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT - 60,
            expires_at_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT
                + config.bundle_ttl_blocks
                + 60,
            status,
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.credit_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "vault_id": self.vault_id,
            "owner_note_commitment": self.owner_note_commitment,
            "lane_id": self.lane_id,
            "credit_units": self.credit_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "nullifier_root": self.nullifier_root,
            "blinding_root": self.blinding_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("GAS-CREDIT", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("credit.credit_id", &self.credit_id)?;
        ensure_non_empty("credit.vault_id", &self.vault_id)?;
        ensure_non_empty("credit.owner_note_commitment", &self.owner_note_commitment)?;
        ensure_non_empty("credit.lane_id", &self.lane_id)?;
        ensure_positive("credit.credit_units", self.credit_units)?;
        ensure_non_empty("credit.nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("credit.blinding_root", &self.blinding_root)?;
        if self.spent_units > self.credit_units {
            return Err(format!("credit {} spent more than minted", self.credit_id));
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err(format!(
                "credit {} expiry precedes issuance",
                self.credit_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallLane {
    pub lane_id: String,
    pub kind: ContractLaneKind,
    pub status: ContractLaneStatus,
    pub contract_registry_root: String,
    pub method_selector_root: String,
    pub min_privacy_set_size: u64,
    pub fee_cap_micro_units: u64,
    pub priority_weight: u64,
    pub max_bundle_call_count: u64,
    pub active_epoch: u64,
}

impl ContractCallLane {
    pub fn devnet(kind: ContractLaneKind, status: ContractLaneStatus, config: &Config) -> Self {
        let label = kind.as_str();
        let lane_id = deterministic_id("LANE-ID", label);
        Self {
            lane_id,
            kind,
            status,
            contract_registry_root: private_root("LANE-CONTRACT-REGISTRY", &[label, "contracts"]),
            method_selector_root: private_root("LANE-METHOD-SELECTORS", &[label, "selectors"]),
            min_privacy_set_size: config.min_privacy_set_size + kind.default_priority(),
            fee_cap_micro_units: kind.default_fee_cap_micro_units(),
            priority_weight: kind.default_priority(),
            max_bundle_call_count: 96,
            active_epoch: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT
                / config.epoch_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "contract_registry_root": self.contract_registry_root,
            "method_selector_root": self.method_selector_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "priority_weight": self.priority_weight,
            "max_bundle_call_count": self.max_bundle_call_count,
            "active_epoch": self.active_epoch,
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("CONTRACT-LANE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("lane.lane_id", &self.lane_id)?;
        ensure_non_empty("lane.contract_registry_root", &self.contract_registry_root)?;
        ensure_non_empty("lane.method_selector_root", &self.method_selector_root)?;
        ensure_positive("lane.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive("lane.fee_cap_micro_units", self.fee_cap_micro_units)?;
        ensure_positive("lane.priority_weight", self.priority_weight)?;
        ensure_positive("lane.max_bundle_call_count", self.max_bundle_call_count)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "lane {} privacy set below config floor",
                self.lane_id
            ));
        }
        if self.fee_cap_micro_units > config.low_fee_target_micro_units.saturating_mul(2) {
            return Err(format!(
                "lane {} exceeds low fee target envelope",
                self.lane_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkReceipt {
    pub receipt_id: String,
    pub bundle_id: String,
    pub lane_id: String,
    pub proof_commitment_root: String,
    pub public_input_root: String,
    pub spent_nullifier_root: String,
    pub settlement_commitment_root: String,
    pub fee_paid_micro_units: u64,
    pub call_count: u64,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub status: ReceiptStatus,
}

impl ZkReceipt {
    pub fn devnet(
        label: &str,
        bundle_id: &str,
        lane_id: &str,
        fee_paid_micro_units: u64,
        call_count: u64,
        status: ReceiptStatus,
        config: &Config,
    ) -> Self {
        let receipt_id = deterministic_id("RECEIPT-ID", label);
        Self {
            receipt_id,
            bundle_id: bundle_id.to_string(),
            lane_id: lane_id.to_string(),
            proof_commitment_root: private_root(
                "RECEIPT-PROOF",
                &[label, &config.zk_receipt_suite],
            ),
            public_input_root: private_root("RECEIPT-PUBLIC-INPUT", &[label, lane_id]),
            spent_nullifier_root: private_root("RECEIPT-NULLIFIERS", &[label, bundle_id]),
            settlement_commitment_root: private_root("RECEIPT-SETTLEMENT", &[label, "settlement"]),
            fee_paid_micro_units,
            call_count,
            privacy_set_size: config.min_privacy_set_size + call_count,
            issued_at_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT - 8,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "lane_id": self.lane_id,
            "proof_commitment_root": self.proof_commitment_root,
            "public_input_root": self.public_input_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "settlement_commitment_root": self.settlement_commitment_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "call_count": self.call_count,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("ZK-RECEIPT", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("receipt.receipt_id", &self.receipt_id)?;
        ensure_non_empty("receipt.bundle_id", &self.bundle_id)?;
        ensure_non_empty("receipt.lane_id", &self.lane_id)?;
        ensure_non_empty("receipt.proof_commitment_root", &self.proof_commitment_root)?;
        ensure_non_empty("receipt.public_input_root", &self.public_input_root)?;
        ensure_non_empty("receipt.spent_nullifier_root", &self.spent_nullifier_root)?;
        ensure_non_empty(
            "receipt.settlement_commitment_root",
            &self.settlement_commitment_root,
        )?;
        ensure_positive("receipt.fee_paid_micro_units", self.fee_paid_micro_units)?;
        ensure_positive("receipt.call_count", self.call_count)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "receipt {} privacy set below floor",
                self.receipt_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBundle {
    pub bundle_id: String,
    pub lane_id: String,
    pub sponsor_vault_id: String,
    pub credit_ids: BTreeSet<String>,
    pub call_commitment_root: String,
    pub calldata_commitment_root: String,
    pub max_fee_micro_units: u64,
    pub actual_fee_micro_units: u64,
    pub call_count: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub receipt_id: String,
    pub status: BundleStatus,
}

impl LowFeeBundle {
    pub fn devnet(
        label: &str,
        lane_id: &str,
        vault_id: &str,
        credit_ids: BTreeSet<String>,
        call_count: u64,
        actual_fee_micro_units: u64,
        status: BundleStatus,
        config: &Config,
    ) -> Self {
        let bundle_id = deterministic_id("BUNDLE-ID", label);
        Self {
            bundle_id: bundle_id.clone(),
            lane_id: lane_id.to_string(),
            sponsor_vault_id: vault_id.to_string(),
            credit_ids,
            call_commitment_root: private_root("BUNDLE-CALLS", &[label, lane_id]),
            calldata_commitment_root: private_root("BUNDLE-CALLDATA", &[label, vault_id]),
            max_fee_micro_units: config.low_fee_target_micro_units,
            actual_fee_micro_units,
            call_count,
            submitted_at_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT - 6,
            expires_at_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT
                + config.bundle_ttl_blocks,
            receipt_id: deterministic_id("RECEIPT-ID", label),
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "lane_id": self.lane_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "credit_ids": self.credit_ids.iter().cloned().collect::<Vec<_>>(),
            "call_commitment_root": self.call_commitment_root,
            "calldata_commitment_root": self.calldata_commitment_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "actual_fee_micro_units": self.actual_fee_micro_units,
            "call_count": self.call_count,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("LOW-FEE-BUNDLE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("bundle.bundle_id", &self.bundle_id)?;
        ensure_non_empty("bundle.lane_id", &self.lane_id)?;
        ensure_non_empty("bundle.sponsor_vault_id", &self.sponsor_vault_id)?;
        ensure_non_empty("bundle.call_commitment_root", &self.call_commitment_root)?;
        ensure_non_empty(
            "bundle.calldata_commitment_root",
            &self.calldata_commitment_root,
        )?;
        ensure_positive("bundle.max_fee_micro_units", self.max_fee_micro_units)?;
        ensure_positive("bundle.actual_fee_micro_units", self.actual_fee_micro_units)?;
        ensure_positive("bundle.call_count", self.call_count)?;
        ensure_non_empty("bundle.receipt_id", &self.receipt_id)?;
        if self.credit_ids.is_empty() {
            return Err(format!(
                "bundle {} has no private gas credits",
                self.bundle_id
            ));
        }
        if self.actual_fee_micro_units > self.max_fee_micro_units {
            return Err(format!("bundle {} fee exceeds private cap", self.bundle_id));
        }
        if self.max_fee_micro_units > config.low_fee_target_micro_units {
            return Err(format!(
                "bundle {} exceeds configured low fee target",
                self.bundle_id
            ));
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err(format!(
                "bundle {} expires before submission",
                self.bundle_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerPolicy {
    pub policy_id: String,
    pub sponsor_vault_id: String,
    pub signer_commitment_root: String,
    pub pq_public_key_root: String,
    pub threshold: u64,
    pub signer_count: u64,
    pub allowed_lane_root: String,
    pub daily_spend_cap_units: u64,
    pub status: SignerPolicyStatus,
    pub rotated_at_height: u64,
}

impl SignerPolicy {
    pub fn devnet(
        label: &str,
        sponsor_vault_id: &str,
        signer_count: u64,
        threshold: u64,
        daily_spend_cap_units: u64,
        status: SignerPolicyStatus,
    ) -> Self {
        Self {
            policy_id: deterministic_id("SIGNER-POLICY-ID", label),
            sponsor_vault_id: sponsor_vault_id.to_string(),
            signer_commitment_root: private_root("SIGNER-COMMITMENTS", &[label, sponsor_vault_id]),
            pq_public_key_root: private_root("SIGNER-PQ-PUBLIC-KEYS", &[label, "pq"]),
            threshold,
            signer_count,
            allowed_lane_root: private_root("SIGNER-ALLOWED-LANES", &[label, "lanes"]),
            daily_spend_cap_units,
            status,
            rotated_at_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT - 44,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "signer_commitment_root": self.signer_commitment_root,
            "pq_public_key_root": self.pq_public_key_root,
            "threshold": self.threshold,
            "signer_count": self.signer_count,
            "allowed_lane_root": self.allowed_lane_root,
            "daily_spend_cap_units": self.daily_spend_cap_units,
            "status": self.status.as_str(),
            "rotated_at_height": self.rotated_at_height,
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("SIGNER-POLICY", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("policy.policy_id", &self.policy_id)?;
        ensure_non_empty("policy.sponsor_vault_id", &self.sponsor_vault_id)?;
        ensure_non_empty(
            "policy.signer_commitment_root",
            &self.signer_commitment_root,
        )?;
        ensure_non_empty("policy.pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("policy.allowed_lane_root", &self.allowed_lane_root)?;
        ensure_positive("policy.signer_count", self.signer_count)?;
        ensure_positive("policy.threshold", self.threshold)?;
        ensure_positive("policy.daily_spend_cap_units", self.daily_spend_cap_units)?;
        if self.threshold > self.signer_count {
            return Err(format!(
                "policy {} threshold exceeds signer set",
                self.policy_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingCap {
    pub cap_id: String,
    pub sponsor_vault_id: String,
    pub lane_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub cap_units: u64,
    pub spent_units: u64,
    pub nullifier_root: String,
    pub status: CapStatus,
}

impl SpendingCap {
    pub fn devnet(
        label: &str,
        sponsor_vault_id: &str,
        lane_id: &str,
        cap_units: u64,
        spent_units: u64,
        status: CapStatus,
        config: &Config,
    ) -> Self {
        Self {
            cap_id: deterministic_id("SPENDING-CAP-ID", label),
            sponsor_vault_id: sponsor_vault_id.to_string(),
            lane_id: lane_id.to_string(),
            window_start_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT
                - config.epoch_blocks / 2,
            window_end_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT
                + config.epoch_blocks / 2,
            cap_units,
            spent_units,
            nullifier_root: private_root("SPENDING-CAP-NULLIFIERS", &[label, sponsor_vault_id]),
            status,
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.cap_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "lane_id": self.lane_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "cap_units": self.cap_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("SPENDING-CAP", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("cap.cap_id", &self.cap_id)?;
        ensure_non_empty("cap.sponsor_vault_id", &self.sponsor_vault_id)?;
        ensure_non_empty("cap.lane_id", &self.lane_id)?;
        ensure_positive("cap.cap_units", self.cap_units)?;
        ensure_non_empty("cap.nullifier_root", &self.nullifier_root)?;
        if self.spent_units > self.cap_units {
            return Err(format!("cap {} spent units exceed cap", self.cap_id));
        }
        if self.window_end_height <= self.window_start_height {
            return Err(format!("cap {} invalid spend window", self.cap_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub revocation_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub revoker_commitment: String,
    pub evidence_root: String,
    pub effective_at_height: u64,
    pub nullifier_root: String,
}

impl RevocationRecord {
    pub fn devnet(label: &str, subject_id: &str, subject_kind: &str, height: u64) -> Self {
        Self {
            revocation_id: deterministic_id("REVOCATION-ID", label),
            subject_id: subject_id.to_string(),
            subject_kind: subject_kind.to_string(),
            revoker_commitment: private_root("REVOCATION-REVOKER", &[label, subject_kind]),
            evidence_root: private_root("REVOCATION-EVIDENCE", &[label, subject_id]),
            effective_at_height: height,
            nullifier_root: private_root("REVOCATION-NULLIFIER", &[label, "nullifier"]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "revocation_id": self.revocation_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "revoker_commitment": self.revoker_commitment,
            "evidence_root": self.evidence_root,
            "effective_at_height": self.effective_at_height,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("REVOCATION", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("revocation.revocation_id", &self.revocation_id)?;
        ensure_non_empty("revocation.subject_id", &self.subject_id)?;
        ensure_non_empty("revocation.subject_kind", &self.subject_kind)?;
        ensure_non_empty("revocation.revoker_commitment", &self.revoker_commitment)?;
        ensure_non_empty("revocation.evidence_root", &self.evidence_root)?;
        ensure_non_empty("revocation.nullifier_root", &self.nullifier_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub settlement_id: String,
    pub bundle_id: String,
    pub vault_id: String,
    pub receipt_id: String,
    pub debit_units: u64,
    pub refund_units: u64,
    pub settlement_root: String,
    pub monero_anchor_root: String,
    pub queued_at_height: u64,
    pub finalized_at_height: u64,
    pub status: SettlementStatus,
}

impl SettlementRecord {
    pub fn devnet(
        label: &str,
        bundle_id: &str,
        vault_id: &str,
        receipt_id: &str,
        debit_units: u64,
        status: SettlementStatus,
        config: &Config,
    ) -> Self {
        Self {
            settlement_id: deterministic_id("SETTLEMENT-ID", label),
            bundle_id: bundle_id.to_string(),
            vault_id: vault_id.to_string(),
            receipt_id: receipt_id.to_string(),
            debit_units,
            refund_units: debit_units / 20,
            settlement_root: private_root("SETTLEMENT-ROOT", &[label, bundle_id]),
            monero_anchor_root: private_root(
                "SETTLEMENT-MONERO-ANCHOR",
                &[label, &config.fee_asset_id],
            ),
            queued_at_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT - 4,
            finalized_at_height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT
                + config.settlement_delay_blocks,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "bundle_id": self.bundle_id,
            "vault_id": self.vault_id,
            "receipt_id": self.receipt_id,
            "debit_units": self.debit_units,
            "refund_units": self.refund_units,
            "settlement_root": self.settlement_root,
            "monero_anchor_root": self.monero_anchor_root,
            "queued_at_height": self.queued_at_height,
            "finalized_at_height": self.finalized_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("SETTLEMENT", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("settlement.settlement_id", &self.settlement_id)?;
        ensure_non_empty("settlement.bundle_id", &self.bundle_id)?;
        ensure_non_empty("settlement.vault_id", &self.vault_id)?;
        ensure_non_empty("settlement.receipt_id", &self.receipt_id)?;
        ensure_positive("settlement.debit_units", self.debit_units)?;
        ensure_non_empty("settlement.settlement_root", &self.settlement_root)?;
        ensure_non_empty("settlement.monero_anchor_root", &self.monero_anchor_root)?;
        if self.finalized_at_height <= self.queued_at_height {
            return Err(format!(
                "settlement {} has invalid finality window",
                self.settlement_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub disclosure_root: String,
    pub publisher_commitment: String,
    pub published_at_height: u64,
}

impl PrivacyPublicRecord {
    pub fn new(
        label: &str,
        record_kind: &str,
        subject_id: &str,
        subject_root: &str,
        publisher_commitment: &str,
        height: u64,
    ) -> Self {
        Self {
            record_id: deterministic_id("PUBLIC-RECORD-ID", label),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            disclosure_root: private_root("PUBLIC-RECORD-DISCLOSURE", &[label, subject_id]),
            publisher_commitment: publisher_commitment.to_string(),
            published_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "disclosure_root": self.disclosure_root,
            "publisher_commitment": self.publisher_commitment,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("PUBLIC-RECORD", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_non_empty("public_record.record_id", &self.record_id)?;
        ensure_non_empty("public_record.record_kind", &self.record_kind)?;
        ensure_non_empty("public_record.subject_id", &self.subject_id)?;
        ensure_non_empty("public_record.subject_root", &self.subject_root)?;
        ensure_non_empty("public_record.disclosure_root", &self.disclosure_root)?;
        ensure_non_empty(
            "public_record.publisher_commitment",
            &self.publisher_commitment,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub sponsor_vault_root: String,
    pub private_gas_credit_root: String,
    pub contract_lane_root: String,
    pub zk_receipt_root: String,
    pub low_fee_bundle_root: String,
    pub signer_policy_root: String,
    pub spending_cap_root: String,
    pub revocation_root: String,
    pub settlement_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> serde_json::Value {
        json!({
            "config_root": self.config_root,
            "sponsor_vault_root": self.sponsor_vault_root,
            "private_gas_credit_root": self.private_gas_credit_root,
            "contract_lane_root": self.contract_lane_root,
            "zk_receipt_root": self.zk_receipt_root,
            "low_fee_bundle_root": self.low_fee_bundle_root,
            "signer_policy_root": self.signer_policy_root,
            "spending_cap_root": self.spending_cap_root,
            "revocation_root": self.revocation_root,
            "settlement_root": self.settlement_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub sponsor_vault_count: u64,
    pub active_vault_count: u64,
    pub private_gas_credit_count: u64,
    pub live_credit_count: u64,
    pub contract_lane_count: u64,
    pub active_lane_count: u64,
    pub zk_receipt_count: u64,
    pub accepted_receipt_count: u64,
    pub low_fee_bundle_count: u64,
    pub active_bundle_count: u64,
    pub signer_policy_count: u64,
    pub active_signer_policy_count: u64,
    pub spending_cap_count: u64,
    pub spendable_cap_count: u64,
    pub revocation_count: u64,
    pub settlement_count: u64,
    pub finalized_settlement_count: u64,
    pub public_record_count: u64,
    pub total_sponsored_units: u64,
    pub total_reserved_units: u64,
    pub total_spent_units: u64,
    pub total_bundle_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> serde_json::Value {
        json!({
            "sponsor_vault_count": self.sponsor_vault_count,
            "active_vault_count": self.active_vault_count,
            "private_gas_credit_count": self.private_gas_credit_count,
            "live_credit_count": self.live_credit_count,
            "contract_lane_count": self.contract_lane_count,
            "active_lane_count": self.active_lane_count,
            "zk_receipt_count": self.zk_receipt_count,
            "accepted_receipt_count": self.accepted_receipt_count,
            "low_fee_bundle_count": self.low_fee_bundle_count,
            "active_bundle_count": self.active_bundle_count,
            "signer_policy_count": self.signer_policy_count,
            "active_signer_policy_count": self.active_signer_policy_count,
            "spending_cap_count": self.spending_cap_count,
            "spendable_cap_count": self.spendable_cap_count,
            "revocation_count": self.revocation_count,
            "settlement_count": self.settlement_count,
            "finalized_settlement_count": self.finalized_settlement_count,
            "public_record_count": self.public_record_count,
            "total_sponsored_units": self.total_sponsored_units,
            "total_reserved_units": self.total_reserved_units,
            "total_spent_units": self.total_spent_units,
            "total_bundle_fee_micro_units": self.total_bundle_fee_micro_units,
        })
    }

    pub fn root(&self) -> String {
        aggregator_hash("COUNTERS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub sponsor_vaults: BTreeMap<String, SponsorVault>,
    pub private_gas_credits: BTreeMap<String, PrivateGasCredit>,
    pub contract_lanes: BTreeMap<String, ContractCallLane>,
    pub zk_receipts: BTreeMap<String, ZkReceipt>,
    pub low_fee_bundles: BTreeMap<String, LowFeeBundle>,
    pub signer_policies: BTreeMap<String, SignerPolicy>,
    pub spending_caps: BTreeMap<String, SpendingCap>,
    pub revocations: BTreeMap<String, RevocationRecord>,
    pub settlements: BTreeMap<String, SettlementRecord>,
    pub public_records: BTreeMap<String, PrivacyPublicRecord>,
}

impl State {
    pub fn devnet() -> PrivateSmartContractFeeSponsorAggregatorResult<Self> {
        let config = Config::devnet();
        let mut state = Self {
            height: PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_DEFAULT_HEIGHT,
            config,
            sponsor_vaults: BTreeMap::new(),
            private_gas_credits: BTreeMap::new(),
            contract_lanes: BTreeMap::new(),
            zk_receipts: BTreeMap::new(),
            low_fee_bundles: BTreeMap::new(),
            signer_policies: BTreeMap::new(),
            spending_caps: BTreeMap::new(),
            revocations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.populate_devnet();
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        self.config.validate()?;
        ensure_positive("state.height", self.height)?;

        let mut seen_roots = BTreeSet::new();
        for (vault_id, vault) in &self.sponsor_vaults {
            if vault_id != &vault.vault_id {
                return Err(format!("vault key mismatch for {}", vault_id));
            }
            vault.validate(&self.config)?;
            ensure_unique("vault.root", &vault.root(), &mut seen_roots)?;
        }

        for (lane_id, lane) in &self.contract_lanes {
            if lane_id != &lane.lane_id {
                return Err(format!("lane key mismatch for {}", lane_id));
            }
            lane.validate(&self.config)?;
        }

        for (credit_id, credit) in &self.private_gas_credits {
            if credit_id != &credit.credit_id {
                return Err(format!("credit key mismatch for {}", credit_id));
            }
            credit.validate()?;
            require_key("credit.vault_id", &credit.vault_id, &self.sponsor_vaults)?;
            require_key("credit.lane_id", &credit.lane_id, &self.contract_lanes)?;
            if credit.expires_at_height <= self.height && credit.status.live() {
                return Err(format!("credit {} is live after expiry", credit.credit_id));
            }
        }

        for (bundle_id, bundle) in &self.low_fee_bundles {
            if bundle_id != &bundle.bundle_id {
                return Err(format!("bundle key mismatch for {}", bundle_id));
            }
            bundle.validate(&self.config)?;
            require_key("bundle.lane_id", &bundle.lane_id, &self.contract_lanes)?;
            require_key(
                "bundle.sponsor_vault_id",
                &bundle.sponsor_vault_id,
                &self.sponsor_vaults,
            )?;
            require_key("bundle.receipt_id", &bundle.receipt_id, &self.zk_receipts)?;
            for credit_id in &bundle.credit_ids {
                require_key("bundle.credit_id", credit_id, &self.private_gas_credits)?;
            }
            if bundle.expires_at_height <= self.height && bundle.status.active() {
                return Err(format!(
                    "bundle {} is active after expiry",
                    bundle.bundle_id
                ));
            }
        }

        for (receipt_id, receipt) in &self.zk_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err(format!("receipt key mismatch for {}", receipt_id));
            }
            receipt.validate(&self.config)?;
            require_key("receipt.lane_id", &receipt.lane_id, &self.contract_lanes)?;
            require_key(
                "receipt.bundle_id",
                &receipt.bundle_id,
                &self.low_fee_bundles,
            )?;
        }

        for (policy_id, policy) in &self.signer_policies {
            if policy_id != &policy.policy_id {
                return Err(format!("policy key mismatch for {}", policy_id));
            }
            policy.validate()?;
            require_key(
                "policy.sponsor_vault_id",
                &policy.sponsor_vault_id,
                &self.sponsor_vaults,
            )?;
        }

        for (cap_id, cap) in &self.spending_caps {
            if cap_id != &cap.cap_id {
                return Err(format!("cap key mismatch for {}", cap_id));
            }
            cap.validate()?;
            require_key(
                "cap.sponsor_vault_id",
                &cap.sponsor_vault_id,
                &self.sponsor_vaults,
            )?;
            require_key("cap.lane_id", &cap.lane_id, &self.contract_lanes)?;
            let max_allowed = self.config.max_spend_bps.saturating_mul(cap.cap_units)
                / PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_MAX_BPS;
            if cap.spent_units > max_allowed && cap.status.spendable() {
                return Err(format!("cap {} exceeds configured spend bps", cap.cap_id));
            }
        }

        for (revocation_id, revocation) in &self.revocations {
            if revocation_id != &revocation.revocation_id {
                return Err(format!("revocation key mismatch for {}", revocation_id));
            }
            revocation.validate()?;
            if revocation.effective_at_height > self.height + self.config.revocation_delay_blocks {
                return Err(format!("revocation {} is too far in future", revocation_id));
            }
        }

        for (settlement_id, settlement) in &self.settlements {
            if settlement_id != &settlement.settlement_id {
                return Err(format!("settlement key mismatch for {}", settlement_id));
            }
            settlement.validate()?;
            require_key(
                "settlement.bundle_id",
                &settlement.bundle_id,
                &self.low_fee_bundles,
            )?;
            require_key(
                "settlement.vault_id",
                &settlement.vault_id,
                &self.sponsor_vaults,
            )?;
            require_key(
                "settlement.receipt_id",
                &settlement.receipt_id,
                &self.zk_receipts,
            )?;
        }

        for (record_id, record) in &self.public_records {
            if record_id != &record.record_id {
                return Err(format!("public record key mismatch for {}", record_id));
            }
            record.validate()?;
        }

        Ok(())
    }

    pub fn set_height(
        &mut self,
        height: u64,
    ) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        ensure_positive("state.height", height)?;
        self.height = height;
        Ok(())
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
        if height < self.height {
            return Err("state height cannot move backwards".to_string());
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            sponsor_vault_root: map_root(
                "SPONSOR-VAULTS",
                self.sponsor_vaults
                    .values()
                    .map(SponsorVault::public_record),
            ),
            private_gas_credit_root: map_root(
                "PRIVATE-GAS-CREDITS",
                self.private_gas_credits
                    .values()
                    .map(PrivateGasCredit::public_record),
            ),
            contract_lane_root: map_root(
                "CONTRACT-CALL-LANES",
                self.contract_lanes
                    .values()
                    .map(ContractCallLane::public_record),
            ),
            zk_receipt_root: map_root(
                "ZK-RECEIPTS",
                self.zk_receipts.values().map(ZkReceipt::public_record),
            ),
            low_fee_bundle_root: map_root(
                "LOW-FEE-BUNDLES",
                self.low_fee_bundles
                    .values()
                    .map(LowFeeBundle::public_record),
            ),
            signer_policy_root: map_root(
                "SIGNER-POLICIES",
                self.signer_policies
                    .values()
                    .map(SignerPolicy::public_record),
            ),
            spending_cap_root: map_root(
                "SPENDING-CAPS",
                self.spending_caps.values().map(SpendingCap::public_record),
            ),
            revocation_root: map_root(
                "REVOCATIONS",
                self.revocations
                    .values()
                    .map(RevocationRecord::public_record),
            ),
            settlement_root: map_root(
                "SETTLEMENTS",
                self.settlements
                    .values()
                    .map(SettlementRecord::public_record),
            ),
            public_record_root: map_root(
                "PRIVACY-PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(PrivacyPublicRecord::public_record),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            sponsor_vault_count: self.sponsor_vaults.len() as u64,
            active_vault_count: self
                .sponsor_vaults
                .values()
                .filter(|vault| vault.status.can_sponsor())
                .count() as u64,
            private_gas_credit_count: self.private_gas_credits.len() as u64,
            live_credit_count: self
                .private_gas_credits
                .values()
                .filter(|credit| credit.status.live())
                .count() as u64,
            contract_lane_count: self.contract_lanes.len() as u64,
            active_lane_count: self
                .contract_lanes
                .values()
                .filter(|lane| lane.status.admits_bundles())
                .count() as u64,
            zk_receipt_count: self.zk_receipts.len() as u64,
            accepted_receipt_count: self
                .zk_receipts
                .values()
                .filter(|receipt| {
                    matches!(
                        receipt.status,
                        ReceiptStatus::Accepted | ReceiptStatus::Settled
                    )
                })
                .count() as u64,
            low_fee_bundle_count: self.low_fee_bundles.len() as u64,
            active_bundle_count: self
                .low_fee_bundles
                .values()
                .filter(|bundle| bundle.status.active())
                .count() as u64,
            signer_policy_count: self.signer_policies.len() as u64,
            active_signer_policy_count: self
                .signer_policies
                .values()
                .filter(|policy| policy.status.allows_signing())
                .count() as u64,
            spending_cap_count: self.spending_caps.len() as u64,
            spendable_cap_count: self
                .spending_caps
                .values()
                .filter(|cap| cap.status.spendable())
                .count() as u64,
            revocation_count: self.revocations.len() as u64,
            settlement_count: self.settlements.len() as u64,
            finalized_settlement_count: self
                .settlements
                .values()
                .filter(|settlement| settlement.status == SettlementStatus::Finalized)
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_sponsored_units: self
                .sponsor_vaults
                .values()
                .map(|vault| vault.total_units)
                .sum(),
            total_reserved_units: self
                .sponsor_vaults
                .values()
                .map(|vault| vault.reserved_units)
                .sum(),
            total_spent_units: self
                .sponsor_vaults
                .values()
                .map(|vault| vault.spent_units)
                .sum(),
            total_bundle_fee_micro_units: self
                .low_fee_bundles
                .values()
                .map(|bundle| bundle.actual_fee_micro_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> serde_json::Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn populate_devnet(&mut self) {
        let lanes = [
            (ContractLaneKind::PrivateDefiSwap, ContractLaneStatus::Open),
            (
                ContractLaneKind::ConfidentialTokenTransfer,
                ContractLaneStatus::LowFeeOnly,
            ),
            (ContractLaneKind::ShieldedLending, ContractLaneStatus::Open),
            (
                ContractLaneKind::OracleCallback,
                ContractLaneStatus::Throttled,
            ),
            (ContractLaneKind::MoneroBridgeExit, ContractLaneStatus::Open),
        ];
        for (kind, status) in lanes {
            let lane = ContractCallLane::devnet(kind, status, &self.config);
            self.contract_lanes.insert(lane.lane_id.clone(), lane);
        }

        let vault_alpha = SponsorVault::devnet(
            "devnet-alpha",
            &private_root("SPONSOR", &["alpha", "reserve"]),
            240_000,
            34_500,
            SponsorVaultStatus::Active,
            &self.config,
        );
        let vault_beta = SponsorVault::devnet(
            "devnet-beta",
            &private_root("SPONSOR", &["beta", "defi"]),
            180_000,
            27_000,
            SponsorVaultStatus::Rebalancing,
            &self.config,
        );
        let vault_gamma = SponsorVault::devnet(
            "devnet-gamma",
            &private_root("SPONSOR", &["gamma", "bridge"]),
            120_000,
            120_000,
            SponsorVaultStatus::Settled,
            &self.config,
        );
        self.sponsor_vaults
            .insert(vault_alpha.vault_id.clone(), vault_alpha);
        self.sponsor_vaults
            .insert(vault_beta.vault_id.clone(), vault_beta);
        self.sponsor_vaults
            .insert(vault_gamma.vault_id.clone(), vault_gamma);

        let lane_ids = self.contract_lanes.keys().cloned().collect::<Vec<_>>();
        let vault_ids = self.sponsor_vaults.keys().cloned().collect::<Vec<_>>();
        if lane_ids.len() >= 3 && vault_ids.len() >= 3 {
            let credit_a = PrivateGasCredit::devnet(
                "credit-alpha-defi",
                &vault_ids[0],
                &lane_ids[0],
                25_000,
                8_200,
                GasCreditStatus::Applied,
                &self.config,
            );
            let credit_b = PrivateGasCredit::devnet(
                "credit-beta-transfer",
                &vault_ids[1],
                &lane_ids[1],
                18_000,
                3_900,
                GasCreditStatus::Reserved,
                &self.config,
            );
            let credit_c = PrivateGasCredit::devnet(
                "credit-gamma-bridge",
                &vault_ids[2],
                &lane_ids[2],
                14_000,
                14_000,
                GasCreditStatus::Settled,
                &self.config,
            );
            self.private_gas_credits
                .insert(credit_a.credit_id.clone(), credit_a);
            self.private_gas_credits
                .insert(credit_b.credit_id.clone(), credit_b);
            self.private_gas_credits
                .insert(credit_c.credit_id.clone(), credit_c);

            let credit_ids = self.private_gas_credits.keys().cloned().collect::<Vec<_>>();
            let mut bundle_a_credits = BTreeSet::new();
            if let Some(credit_id) = credit_ids.first() {
                bundle_a_credits.insert(credit_id.clone());
            }
            let bundle_a = LowFeeBundle::devnet(
                "bundle-alpha-defi",
                &lane_ids[0],
                &vault_ids[0],
                bundle_a_credits,
                32,
                980,
                BundleStatus::Submitted,
                &self.config,
            );
            let mut bundle_b_credits = BTreeSet::new();
            if let Some(credit_id) = credit_ids.get(1) {
                bundle_b_credits.insert(credit_id.clone());
            }
            let bundle_b = LowFeeBundle::devnet(
                "bundle-beta-transfer",
                &lane_ids[1],
                &vault_ids[1],
                bundle_b_credits,
                18,
                640,
                BundleStatus::Proving,
                &self.config,
            );
            self.low_fee_bundles
                .insert(bundle_a.bundle_id.clone(), bundle_a.clone());
            self.low_fee_bundles
                .insert(bundle_b.bundle_id.clone(), bundle_b.clone());

            let receipt_a = ZkReceipt::devnet(
                "bundle-alpha-defi",
                &bundle_a.bundle_id,
                &bundle_a.lane_id,
                bundle_a.actual_fee_micro_units,
                bundle_a.call_count,
                ReceiptStatus::Accepted,
                &self.config,
            );
            let receipt_b = ZkReceipt::devnet(
                "bundle-beta-transfer",
                &bundle_b.bundle_id,
                &bundle_b.lane_id,
                bundle_b.actual_fee_micro_units,
                bundle_b.call_count,
                ReceiptStatus::Pending,
                &self.config,
            );
            self.zk_receipts
                .insert(receipt_a.receipt_id.clone(), receipt_a.clone());
            self.zk_receipts
                .insert(receipt_b.receipt_id.clone(), receipt_b.clone());

            let settlement = SettlementRecord::devnet(
                "settlement-alpha-defi",
                &bundle_a.bundle_id,
                &vault_ids[0],
                &receipt_a.receipt_id,
                980,
                SettlementStatus::Anchored,
                &self.config,
            );
            self.settlements
                .insert(settlement.settlement_id.clone(), settlement);
        }

        for (index, vault_id) in self
            .sponsor_vaults
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .iter()
            .enumerate()
        {
            let label = format!("policy-{index}");
            let policy = SignerPolicy::devnet(
                &label,
                vault_id,
                5,
                3,
                50_000 + (index as u64 * 10_000),
                if index == 1 {
                    SignerPolicyStatus::Rotating
                } else {
                    SignerPolicyStatus::Active
                },
            );
            self.signer_policies
                .insert(policy.policy_id.clone(), policy);
        }

        let lane_ids = self.contract_lanes.keys().cloned().collect::<Vec<_>>();
        let vault_ids = self.sponsor_vaults.keys().cloned().collect::<Vec<_>>();
        for (index, vault_id) in vault_ids.iter().enumerate() {
            if let Some(lane_id) = lane_ids.get(index % lane_ids.len()) {
                let label = format!("cap-{index}");
                let cap = SpendingCap::devnet(
                    &label,
                    vault_id,
                    lane_id,
                    60_000,
                    18_000 + (index as u64 * 2_000),
                    CapStatus::Active,
                    &self.config,
                );
                self.spending_caps.insert(cap.cap_id.clone(), cap);
            }
        }

        if let Some(vault_id) = vault_ids.get(2) {
            let revocation = RevocationRecord::devnet(
                "revoke-gamma-settled-credit",
                vault_id,
                "sponsor_vault",
                self.height - 2,
            );
            self.revocations
                .insert(revocation.revocation_id.clone(), revocation);
        }

        self.publish_initial_records();
    }

    fn publish_initial_records(&mut self) {
        let mut records = Vec::new();
        records.push(PrivacyPublicRecord::new(
            "config-root",
            "config",
            PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_PROTOCOL_VERSION,
            &self.config.root(),
            &private_root("PUBLISHER", &["config", "committee"]),
            self.height,
        ));
        for vault in self.sponsor_vaults.values() {
            records.push(PrivacyPublicRecord::new(
                &format!("vault-{}", vault.vault_id),
                "sponsor_vault",
                &vault.vault_id,
                &vault.root(),
                &vault.sponsor_commitment,
                self.height,
            ));
        }
        for lane in self.contract_lanes.values() {
            records.push(PrivacyPublicRecord::new(
                &format!("lane-{}", lane.lane_id),
                "contract_call_lane",
                &lane.lane_id,
                &lane.root(),
                &private_root("PUBLISHER", &[&lane.lane_id, "lane"]),
                self.height,
            ));
        }
        for receipt in self.zk_receipts.values() {
            records.push(PrivacyPublicRecord::new(
                &format!("receipt-{}", receipt.receipt_id),
                "zk_receipt",
                &receipt.receipt_id,
                &receipt.root(),
                &private_root("PUBLISHER", &[&receipt.receipt_id, "receipt"]),
                self.height,
            ));
        }
        for record in records {
            self.public_records.insert(record.record_id.clone(), record);
        }
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_smart_contract_fee_sponsor_aggregator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.root(),
            "counters": counters.public_record(),
            "counters_root": counters.root(),
            "sponsor_vaults": self.sponsor_vaults.values().map(SponsorVault::public_record).collect::<Vec<_>>(),
            "private_gas_credits": self.private_gas_credits.values().map(PrivateGasCredit::public_record).collect::<Vec<_>>(),
            "contract_lanes": self.contract_lanes.values().map(ContractCallLane::public_record).collect::<Vec<_>>(),
            "zk_receipts": self.zk_receipts.values().map(ZkReceipt::public_record).collect::<Vec<_>>(),
            "low_fee_bundles": self.low_fee_bundles.values().map(LowFeeBundle::public_record).collect::<Vec<_>>(),
            "signer_policies": self.signer_policies.values().map(SignerPolicy::public_record).collect::<Vec<_>>(),
            "spending_caps": self.spending_caps.values().map(SpendingCap::public_record).collect::<Vec<_>>(),
            "revocations": self.revocations.values().map(RevocationRecord::public_record).collect::<Vec<_>>(),
            "settlements": self.settlements.values().map(SettlementRecord::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(PrivacyPublicRecord::public_record).collect::<Vec<_>>(),
        })
    }
}

pub fn root_from_record(record: &serde_json::Value) -> String {
    aggregator_hash("STATE-ROOT", &[HashPart::Json(record)])
}

pub fn devnet() -> PrivateSmartContractFeeSponsorAggregatorResult<State> {
    State::devnet()
}

fn aggregator_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-SMART-CONTRACT-FEE-SPONSOR-AGGREGATOR:{domain}"),
        parts,
        32,
    )
}

fn deterministic_id(domain: &str, label: &str) -> String {
    aggregator_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)])
}

fn private_root(domain: &str, labels: &[&str]) -> String {
    let mut records = Vec::new();
    for label in labels {
        records.push(json!({
            "label": label,
            "commitment": aggregator_hash(domain, &[HashPart::Str(label)]),
        }));
    }
    merkle_root(
        &format!("PRIVATE-SMART-CONTRACT-FEE-SPONSOR-AGGREGATOR:{domain}"),
        &records,
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: Iterator<Item = Value>,
{
    let values = records.collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-SMART-CONTRACT-FEE-SPONSOR-AGGREGATOR:{domain}"),
        &values,
    )
}

fn ensure_non_empty(
    field: &str,
    value: &str,
) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
    if value.is_empty() {
        return Err(format!("{field} must be populated"));
    }
    Ok(())
}

fn ensure_positive(field: &str, value: u64) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
    if value > PRIVATE_SMART_CONTRACT_FEE_SPONSOR_AGGREGATOR_MAX_BPS {
        return Err(format!("{field} exceeds 10000 basis points"));
    }
    Ok(())
}

fn ensure_unique(
    field: &str,
    value: &str,
    seen: &mut BTreeSet<String>,
) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
    if !seen.insert(value.to_string()) {
        return Err(format!("{field} duplicate value {value}"));
    }
    Ok(())
}

fn require_key<T>(
    field: &str,
    key: &str,
    map: &BTreeMap<String, T>,
) -> PrivateSmartContractFeeSponsorAggregatorResult<()> {
    if !map.contains_key(key) {
        return Err(format!("{field} references missing key {key}"));
    }
    Ok(())
}
