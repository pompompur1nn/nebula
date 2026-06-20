use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateCrossChainCollateralBridgeResult<T> = Result<T, String>;

pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_PROTOCOL_VERSION: &str =
    "nebula-private-cross-chain-collateral-bridge-v1";
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEVNET_HEIGHT: u64 = 512;
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_PQ_APPROVAL_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-guardian-approval";
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_RESERVE_PROOF_SCHEME: &str =
    "monero-viewkey-reserve-proof-commitment-v1";
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_ADAPTER_COMMITMENT_SCHEME: &str =
    "cross-chain-adapter-transcript-commitment-v1";
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_ESCROW_COMMITMENT_SCHEME: &str =
    "private-collateral-escrow-commitment-v1";
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEBT_LOCK_SCHEME: &str =
    "private-debt-lock-nullifier-commitment-v1";
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_SETTLEMENT_RECEIPT_SCHEME: &str =
    "privacy-preserving-settlement-receipt-v1";
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_MIN_CONFIRMATIONS: u64 = 12;
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_CHALLENGE_BLOCKS: u64 = 36;
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_LIQUIDATION_DELAY_BLOCKS: u64 = 18;
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_MIN_GUARDIAN_WEIGHT: u64 = 5;
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainKind {
    Monero,
    NebulaL2,
    Ethereum,
    Bitcoin,
    Cosmos,
    Appchain,
}

impl ChainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monero => "monero",
            Self::NebulaL2 => "nebula_l2",
            Self::Ethereum => "ethereum",
            Self::Bitcoin => "bitcoin",
            Self::Cosmos => "cosmos",
            Self::Appchain => "appchain",
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::NebulaL2 => 350,
            Self::Monero => 850,
            Self::Ethereum => 1_200,
            Self::Bitcoin => 1_500,
            Self::Cosmos => 1_900,
            Self::Appchain => 2_400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Pending,
    Active,
    DebtLocked,
    Rebalancing,
    LiquidationPending,
    Liquidating,
    Settled,
    Released,
    Frozen,
}

impl EscrowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::DebtLocked => "debt_locked",
            Self::Rebalancing => "rebalancing",
            Self::LiquidationPending => "liquidation_pending",
            Self::Liquidating => "liquidating",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Frozen => "frozen",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::Active
                | Self::DebtLocked
                | Self::Rebalancing
                | Self::LiquidationPending
                | Self::Liquidating
                | Self::Frozen
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebtLockStatus {
    Requested,
    Locked,
    RateLimited,
    LiquidationArmed,
    Settled,
    Released,
    Expired,
}

impl DebtLockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Locked => "locked",
            Self::RateLimited => "rate_limited",
            Self::LiquidationArmed => "liquidation_armed",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::Locked | Self::RateLimited | Self::LiquidationArmed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Observed,
    Attested,
    Disputed,
    Finalized,
    Superseded,
}

impl ReserveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Attested => "attested",
            Self::Disputed => "disputed",
            Self::Finalized => "finalized",
            Self::Superseded => "superseded",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Attested | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterStatus {
    Proposed,
    Active,
    RateLimited,
    Quarantined,
    Retired,
}

impl AdapterStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Slashed,
}

impl GuardianApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn counts(self) -> bool {
        matches!(self, Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationHookStatus {
    Armed,
    Triggered,
    Executed,
    Cancelled,
    Expired,
}

impl LiquidationHookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Triggered => "triggered",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Armed | Self::Triggered)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Pending,
    Accepted,
    Challenged,
    Finalized,
    Reversed,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Reversed => "reversed",
        }
    }

    pub fn final_state(self) -> bool {
        matches!(self, Self::Finalized | Self::Reversed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub min_monero_confirmations: u64,
    pub challenge_window_blocks: u64,
    pub liquidation_delay_blocks: u64,
    pub min_guardian_weight: u64,
    pub min_privacy_set_size: u64,
    pub min_reserve_coverage_bps: u64,
    pub allow_emergency_freeze: bool,
    pub low_fee_lane: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            min_monero_confirmations:
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_MIN_CONFIRMATIONS,
            challenge_window_blocks: PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_CHALLENGE_BLOCKS,
            liquidation_delay_blocks:
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_LIQUIDATION_DELAY_BLOCKS,
            min_guardian_weight: PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_MIN_GUARDIAN_WEIGHT,
            min_privacy_set_size:
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reserve_coverage_bps:
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            allow_emergency_freeze: true,
            low_fee_lane: "private-cross-chain-collateral-fast-lane".to_string(),
        }
    }

    pub fn validate(&self) -> PrivateCrossChainCollateralBridgeResult<()> {
        if self.min_monero_confirmations == 0 {
            return Err("min monero confirmations must be positive".to_string());
        }
        if self.challenge_window_blocks == 0 || self.liquidation_delay_blocks == 0 {
            return Err("bridge safety windows must be positive".to_string());
        }
        if self.min_guardian_weight == 0 {
            return Err("min guardian weight must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("min privacy set size must be positive".to_string());
        }
        if self.min_reserve_coverage_bps < PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_MAX_BPS {
            return Err("reserve coverage must be at least 100 percent".to_string());
        }
        if self.low_fee_lane.is_empty() {
            return Err("low fee lane cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_collateral_bridge_config",
            "min_monero_confirmations": self.min_monero_confirmations,
            "challenge_window_blocks": self.challenge_window_blocks,
            "liquidation_delay_blocks": self.liquidation_delay_blocks,
            "min_guardian_weight": self.min_guardian_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "allow_emergency_freeze": self.allow_emergency_freeze,
            "low_fee_lane": self.low_fee_lane,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainAdapter {
    pub adapter_id: String,
    pub label: String,
    pub source_chain: ChainKind,
    pub target_chain: ChainKind,
    pub commitment: String,
    pub finality_blocks: u64,
    pub max_notional_piconero: u64,
    pub status: AdapterStatus,
}

impl ChainAdapter {
    pub fn new(
        label: &str,
        source_chain: ChainKind,
        target_chain: ChainKind,
        finality_blocks: u64,
        max_notional_piconero: u64,
        status: AdapterStatus,
    ) -> PrivateCrossChainCollateralBridgeResult<Self> {
        if label.is_empty() {
            return Err("adapter label cannot be empty".to_string());
        }
        if source_chain == target_chain {
            return Err("adapter source and target chains must differ".to_string());
        }
        if finality_blocks == 0 || max_notional_piconero == 0 {
            return Err("adapter finality and notional limits must be positive".to_string());
        }
        let adapter_id = bridge_id(
            "ADAPTER",
            &[
                label,
                source_chain.as_str(),
                target_chain.as_str(),
                &finality_blocks.to_string(),
            ],
        );
        let commitment = bridge_id(
            "ADAPTER-COMMITMENT",
            &[
                &adapter_id,
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_ADAPTER_COMMITMENT_SCHEME,
            ],
        );
        Ok(Self {
            adapter_id,
            label: label.to_string(),
            source_chain,
            target_chain,
            commitment,
            finality_blocks,
            max_notional_piconero,
            status,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainCollateralBridgeResult<()> {
        if self.adapter_id.is_empty() || self.label.is_empty() || self.commitment.is_empty() {
            return Err("adapter identifiers cannot be empty".to_string());
        }
        if self.source_chain == self.target_chain {
            return Err("adapter source and target chains must differ".to_string());
        }
        if self.finality_blocks == 0 || self.max_notional_piconero == 0 {
            return Err("adapter finality and notional limits must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "chain_adapter",
            "adapter_id": self.adapter_id,
            "label": self.label,
            "source_chain": self.source_chain.as_str(),
            "target_chain": self.target_chain.as_str(),
            "source_risk_weight_bps": self.source_chain.risk_weight_bps(),
            "target_risk_weight_bps": self.target_chain.risk_weight_bps(),
            "commitment": self.commitment,
            "finality_blocks": self.finality_blocks,
            "max_notional_piconero": self.max_notional_piconero,
            "status": self.status.as_str(),
            "usable": self.status.usable(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralEscrow {
    pub escrow_id: String,
    pub adapter_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub status: EscrowStatus,
}

impl CollateralEscrow {
    pub fn new(
        adapter_id: &str,
        owner_label: &str,
        asset_id: &str,
        amount_label: &str,
        privacy_set_size: u64,
        opened_height: u64,
        status: EscrowStatus,
    ) -> PrivateCrossChainCollateralBridgeResult<Self> {
        if adapter_id.is_empty()
            || owner_label.is_empty()
            || asset_id.is_empty()
            || amount_label.is_empty()
        {
            return Err("escrow inputs cannot be empty".to_string());
        }
        if privacy_set_size == 0 {
            return Err("escrow privacy set size must be positive".to_string());
        }
        let owner_commitment = bridge_id("OWNER-COMMITMENT", &[owner_label]);
        let amount_commitment = bridge_id(
            "ESCROW-AMOUNT-COMMITMENT",
            &[
                amount_label,
                asset_id,
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_ESCROW_COMMITMENT_SCHEME,
            ],
        );
        let escrow_id = bridge_id(
            "ESCROW",
            &[adapter_id, &owner_commitment, asset_id, &amount_commitment],
        );
        Ok(Self {
            escrow_id,
            adapter_id: adapter_id.to_string(),
            owner_commitment,
            asset_id: asset_id.to_string(),
            amount_commitment,
            privacy_set_size,
            opened_height,
            status,
        })
    }

    pub fn validate(&self, config: &Config) -> PrivateCrossChainCollateralBridgeResult<()> {
        if self.escrow_id.is_empty()
            || self.adapter_id.is_empty()
            || self.owner_commitment.is_empty()
            || self.asset_id.is_empty()
            || self.amount_commitment.is_empty()
        {
            return Err("escrow identifiers cannot be empty".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("escrow privacy set size below bridge minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "collateral_escrow",
            "escrow_id": self.escrow_id,
            "adapter_id": self.adapter_id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
            "status": self.status.as_str(),
            "live": self.status.live(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDebtLock {
    pub lock_id: String,
    pub escrow_id: String,
    pub debt_commitment: String,
    pub debt_nullifier: String,
    pub stable_asset_id: String,
    pub health_bucket: String,
    pub expires_height: u64,
    pub status: DebtLockStatus,
}

impl PrivateDebtLock {
    pub fn new(
        escrow_id: &str,
        debt_label: &str,
        stable_asset_id: &str,
        health_bucket: &str,
        expires_height: u64,
        status: DebtLockStatus,
    ) -> PrivateCrossChainCollateralBridgeResult<Self> {
        if escrow_id.is_empty()
            || debt_label.is_empty()
            || stable_asset_id.is_empty()
            || health_bucket.is_empty()
        {
            return Err("debt lock inputs cannot be empty".to_string());
        }
        let debt_commitment = bridge_id(
            "DEBT-COMMITMENT",
            &[
                debt_label,
                stable_asset_id,
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEBT_LOCK_SCHEME,
            ],
        );
        let debt_nullifier = bridge_id("DEBT-NULLIFIER", &[escrow_id, &debt_commitment]);
        let lock_id = bridge_id("DEBT-LOCK", &[escrow_id, &debt_nullifier]);
        Ok(Self {
            lock_id,
            escrow_id: escrow_id.to_string(),
            debt_commitment,
            debt_nullifier,
            stable_asset_id: stable_asset_id.to_string(),
            health_bucket: health_bucket.to_string(),
            expires_height,
            status,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainCollateralBridgeResult<()> {
        if self.lock_id.is_empty()
            || self.escrow_id.is_empty()
            || self.debt_commitment.is_empty()
            || self.debt_nullifier.is_empty()
            || self.stable_asset_id.is_empty()
            || self.health_bucket.is_empty()
        {
            return Err("debt lock identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_debt_lock",
            "lock_id": self.lock_id,
            "escrow_id": self.escrow_id,
            "debt_commitment": self.debt_commitment,
            "debt_nullifier": self.debt_nullifier,
            "stable_asset_id": self.stable_asset_id,
            "health_bucket": self.health_bucket,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "open": self.status.open(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReserveProof {
    pub proof_id: String,
    pub reserve_account_commitment: String,
    pub view_tag_root: String,
    pub output_set_root: String,
    pub proven_reserve_piconero: u64,
    pub required_coverage_bps: u64,
    pub confirmations: u64,
    pub attested_height: u64,
    pub status: ReserveProofStatus,
}

impl MoneroReserveProof {
    pub fn new(
        reserve_label: &str,
        output_labels: &[&str],
        proven_reserve_piconero: u64,
        required_coverage_bps: u64,
        confirmations: u64,
        attested_height: u64,
        status: ReserveProofStatus,
    ) -> PrivateCrossChainCollateralBridgeResult<Self> {
        if reserve_label.is_empty() || output_labels.is_empty() {
            return Err("reserve proof labels cannot be empty".to_string());
        }
        if output_labels.iter().any(|label| label.is_empty()) {
            return Err("reserve proof output labels cannot be empty".to_string());
        }
        if proven_reserve_piconero == 0 {
            return Err("reserve proof amount must be positive".to_string());
        }
        let reserve_account_commitment = bridge_id("RESERVE-ACCOUNT", &[reserve_label]);
        let output_records = output_labels
            .iter()
            .map(|label| json!({"output_commitment": bridge_id("MONERO-OUTPUT", &[*label])}))
            .collect::<Vec<_>>();
        let output_set_root = merkle_root("PCCCB-MONERO-OUTPUT", &output_records);
        let view_tag_root = bridge_id(
            "VIEW-TAG-ROOT",
            &[&reserve_account_commitment, &output_set_root],
        );
        let proof_id = bridge_id(
            "RESERVE-PROOF",
            &[&reserve_account_commitment, &output_set_root],
        );
        Ok(Self {
            proof_id,
            reserve_account_commitment,
            view_tag_root,
            output_set_root,
            proven_reserve_piconero,
            required_coverage_bps,
            confirmations,
            attested_height,
            status,
        })
    }

    pub fn validate(&self, config: &Config) -> PrivateCrossChainCollateralBridgeResult<()> {
        if self.proof_id.is_empty()
            || self.reserve_account_commitment.is_empty()
            || self.view_tag_root.is_empty()
            || self.output_set_root.is_empty()
        {
            return Err("reserve proof identifiers cannot be empty".to_string());
        }
        if self.proven_reserve_piconero == 0 {
            return Err("reserve proof amount must be positive".to_string());
        }
        if self.confirmations < config.min_monero_confirmations {
            return Err("reserve proof confirmations below bridge minimum".to_string());
        }
        if self.required_coverage_bps < config.min_reserve_coverage_bps {
            return Err("reserve proof coverage below bridge minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_reserve_proof",
            "proof_id": self.proof_id,
            "scheme": PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_RESERVE_PROOF_SCHEME,
            "reserve_account_commitment": self.reserve_account_commitment,
            "view_tag_root": self.view_tag_root,
            "output_set_root": self.output_set_root,
            "proven_reserve_piconero": self.proven_reserve_piconero,
            "required_coverage_bps": self.required_coverage_bps,
            "confirmations": self.confirmations,
            "attested_height": self.attested_height,
            "status": self.status.as_str(),
            "usable": self.status.usable(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGuardianApproval {
    pub approval_id: String,
    pub guardian_id: String,
    pub subject_root: String,
    pub approval_weight: u64,
    pub pq_signature_commitment: String,
    pub status: GuardianApprovalStatus,
}

impl PqGuardianApproval {
    pub fn new(
        guardian_label: &str,
        subject_root: &str,
        approval_weight: u64,
        status: GuardianApprovalStatus,
    ) -> PrivateCrossChainCollateralBridgeResult<Self> {
        if guardian_label.is_empty() || subject_root.is_empty() {
            return Err("guardian approval inputs cannot be empty".to_string());
        }
        if approval_weight == 0 {
            return Err("guardian approval weight must be positive".to_string());
        }
        let guardian_id = bridge_id("GUARDIAN", &[guardian_label]);
        let pq_signature_commitment = bridge_id(
            "GUARDIAN-PQ-SIGNATURE",
            &[
                &guardian_id,
                subject_root,
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_PQ_APPROVAL_SUITE,
            ],
        );
        let approval_id = bridge_id("GUARDIAN-APPROVAL", &[&guardian_id, subject_root]);
        Ok(Self {
            approval_id,
            guardian_id,
            subject_root: subject_root.to_string(),
            approval_weight,
            pq_signature_commitment,
            status,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainCollateralBridgeResult<()> {
        if self.approval_id.is_empty()
            || self.guardian_id.is_empty()
            || self.subject_root.is_empty()
            || self.pq_signature_commitment.is_empty()
        {
            return Err("guardian approval identifiers cannot be empty".to_string());
        }
        if self.approval_weight == 0 {
            return Err("guardian approval weight must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_guardian_approval",
            "approval_id": self.approval_id,
            "guardian_id": self.guardian_id,
            "subject_root": self.subject_root,
            "approval_weight": self.approval_weight,
            "pq_signature_commitment": self.pq_signature_commitment,
            "status": self.status.as_str(),
            "counts": self.status.counts(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationHook {
    pub hook_id: String,
    pub lock_id: String,
    pub escrow_id: String,
    pub risk_commitment: String,
    pub execution_adapter_id: String,
    pub trigger_height: u64,
    pub status: LiquidationHookStatus,
}

impl LiquidationHook {
    pub fn new(
        lock_id: &str,
        escrow_id: &str,
        risk_label: &str,
        execution_adapter_id: &str,
        trigger_height: u64,
        status: LiquidationHookStatus,
    ) -> PrivateCrossChainCollateralBridgeResult<Self> {
        if lock_id.is_empty()
            || escrow_id.is_empty()
            || risk_label.is_empty()
            || execution_adapter_id.is_empty()
        {
            return Err("liquidation hook inputs cannot be empty".to_string());
        }
        let risk_commitment = bridge_id("LIQUIDATION-RISK", &[risk_label, lock_id]);
        let hook_id = bridge_id("LIQUIDATION-HOOK", &[lock_id, escrow_id, &risk_commitment]);
        Ok(Self {
            hook_id,
            lock_id: lock_id.to_string(),
            escrow_id: escrow_id.to_string(),
            risk_commitment,
            execution_adapter_id: execution_adapter_id.to_string(),
            trigger_height,
            status,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainCollateralBridgeResult<()> {
        if self.hook_id.is_empty()
            || self.lock_id.is_empty()
            || self.escrow_id.is_empty()
            || self.risk_commitment.is_empty()
            || self.execution_adapter_id.is_empty()
        {
            return Err("liquidation hook identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_hook",
            "hook_id": self.hook_id,
            "lock_id": self.lock_id,
            "escrow_id": self.escrow_id,
            "risk_commitment": self.risk_commitment,
            "execution_adapter_id": self.execution_adapter_id,
            "trigger_height": self.trigger_height,
            "status": self.status.as_str(),
            "open": self.status.open(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub escrow_id: String,
    pub lock_id: String,
    pub adapter_id: String,
    pub settlement_commitment: String,
    pub fee_commitment: String,
    pub settled_height: u64,
    pub status: SettlementReceiptStatus,
}

impl SettlementReceipt {
    pub fn new(
        escrow_id: &str,
        lock_id: &str,
        adapter_id: &str,
        settlement_label: &str,
        fee_label: &str,
        settled_height: u64,
        status: SettlementReceiptStatus,
    ) -> PrivateCrossChainCollateralBridgeResult<Self> {
        if escrow_id.is_empty()
            || lock_id.is_empty()
            || adapter_id.is_empty()
            || settlement_label.is_empty()
            || fee_label.is_empty()
        {
            return Err("settlement receipt inputs cannot be empty".to_string());
        }
        let settlement_commitment = bridge_id(
            "SETTLEMENT-COMMITMENT",
            &[
                settlement_label,
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_SETTLEMENT_RECEIPT_SCHEME,
            ],
        );
        let fee_commitment = bridge_id("SETTLEMENT-FEE", &[fee_label, adapter_id]);
        let receipt_id = bridge_id(
            "SETTLEMENT-RECEIPT",
            &[escrow_id, lock_id, adapter_id, &settlement_commitment],
        );
        Ok(Self {
            receipt_id,
            escrow_id: escrow_id.to_string(),
            lock_id: lock_id.to_string(),
            adapter_id: adapter_id.to_string(),
            settlement_commitment,
            fee_commitment,
            settled_height,
            status,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainCollateralBridgeResult<()> {
        if self.receipt_id.is_empty()
            || self.escrow_id.is_empty()
            || self.lock_id.is_empty()
            || self.adapter_id.is_empty()
            || self.settlement_commitment.is_empty()
            || self.fee_commitment.is_empty()
        {
            return Err("settlement receipt identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "receipt_id": self.receipt_id,
            "escrow_id": self.escrow_id,
            "lock_id": self.lock_id,
            "adapter_id": self.adapter_id,
            "settlement_commitment": self.settlement_commitment,
            "fee_commitment": self.fee_commitment,
            "settled_height": self.settled_height,
            "status": self.status.as_str(),
            "final_state": self.status.final_state(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPreservingPublicRecord {
    pub record_id: String,
    pub subject_kind: String,
    pub subject_root: String,
    pub visibility_group: String,
    pub disclosure_digest: String,
    pub emitted_height: u64,
}

impl PrivacyPreservingPublicRecord {
    pub fn new(
        subject_kind: &str,
        subject_root: &str,
        visibility_group: &str,
        disclosure_label: &str,
        emitted_height: u64,
    ) -> PrivateCrossChainCollateralBridgeResult<Self> {
        if subject_kind.is_empty()
            || subject_root.is_empty()
            || visibility_group.is_empty()
            || disclosure_label.is_empty()
        {
            return Err("public record inputs cannot be empty".to_string());
        }
        let disclosure_digest = bridge_id("DISCLOSURE-DIGEST", &[disclosure_label, subject_root]);
        let record_id = bridge_id(
            "PUBLIC-RECORD",
            &[
                subject_kind,
                subject_root,
                visibility_group,
                &disclosure_digest,
            ],
        );
        Ok(Self {
            record_id,
            subject_kind: subject_kind.to_string(),
            subject_root: subject_root.to_string(),
            visibility_group: visibility_group.to_string(),
            disclosure_digest,
            emitted_height,
        })
    }

    pub fn validate(&self) -> PrivateCrossChainCollateralBridgeResult<()> {
        if self.record_id.is_empty()
            || self.subject_kind.is_empty()
            || self.subject_root.is_empty()
            || self.visibility_group.is_empty()
            || self.disclosure_digest.is_empty()
        {
            return Err("public record identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_preserving_public_record",
            "record_id": self.record_id,
            "subject_kind": self.subject_kind,
            "subject_root": self.subject_root,
            "visibility_group": self.visibility_group,
            "disclosure_digest": self.disclosure_digest,
            "emitted_height": self.emitted_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub adapter_root: String,
    pub escrow_root: String,
    pub debt_lock_root: String,
    pub monero_reserve_proof_root: String,
    pub guardian_approval_root: String,
    pub liquidation_hook_root: String,
    pub settlement_receipt_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_collateral_bridge_roots",
            "config_root": self.config_root,
            "adapter_root": self.adapter_root,
            "escrow_root": self.escrow_root,
            "debt_lock_root": self.debt_lock_root,
            "monero_reserve_proof_root": self.monero_reserve_proof_root,
            "guardian_approval_root": self.guardian_approval_root,
            "liquidation_hook_root": self.liquidation_hook_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub adapters: usize,
    pub active_adapters: usize,
    pub escrows: usize,
    pub live_escrows: usize,
    pub debt_locks: usize,
    pub open_debt_locks: usize,
    pub monero_reserve_proofs: usize,
    pub usable_monero_reserve_proofs: usize,
    pub guardian_approvals: usize,
    pub approved_guardian_weight: u64,
    pub liquidation_hooks: usize,
    pub open_liquidation_hooks: usize,
    pub settlement_receipts: usize,
    pub finalized_settlement_receipts: usize,
    pub public_records: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_chain_collateral_bridge_counters",
            "adapters": self.adapters,
            "active_adapters": self.active_adapters,
            "escrows": self.escrows,
            "live_escrows": self.live_escrows,
            "debt_locks": self.debt_locks,
            "open_debt_locks": self.open_debt_locks,
            "monero_reserve_proofs": self.monero_reserve_proofs,
            "usable_monero_reserve_proofs": self.usable_monero_reserve_proofs,
            "guardian_approvals": self.guardian_approvals,
            "approved_guardian_weight": self.approved_guardian_weight,
            "liquidation_hooks": self.liquidation_hooks,
            "open_liquidation_hooks": self.open_liquidation_hooks,
            "settlement_receipts": self.settlement_receipts,
            "finalized_settlement_receipts": self.finalized_settlement_receipts,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub adapters: BTreeMap<String, ChainAdapter>,
    pub collateral_escrows: BTreeMap<String, CollateralEscrow>,
    pub private_debt_locks: BTreeMap<String, PrivateDebtLock>,
    pub monero_reserve_proofs: BTreeMap<String, MoneroReserveProof>,
    pub pq_guardian_approvals: BTreeMap<String, PqGuardianApproval>,
    pub liquidation_hooks: BTreeMap<String, LiquidationHook>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub privacy_public_records: BTreeMap<String, PrivacyPreservingPublicRecord>,
}

impl State {
    pub fn devnet() -> PrivateCrossChainCollateralBridgeResult<Self> {
        let config = Config::devnet();
        let monero_to_l2 = ChainAdapter::new(
            "monero-devnet-to-nebula-l2",
            ChainKind::Monero,
            ChainKind::NebulaL2,
            config.min_monero_confirmations,
            75_000_000_000_000,
            AdapterStatus::Active,
        )?;
        let l2_to_eth = ChainAdapter::new(
            "nebula-l2-to-ethereum-holesky",
            ChainKind::NebulaL2,
            ChainKind::Ethereum,
            18,
            40_000_000_000_000,
            AdapterStatus::RateLimited,
        )?;
        let mut adapters = BTreeMap::new();
        adapters.insert(monero_to_l2.adapter_id.clone(), monero_to_l2.clone());
        adapters.insert(l2_to_eth.adapter_id.clone(), l2_to_eth.clone());

        let escrow_a = CollateralEscrow::new(
            &monero_to_l2.adapter_id,
            "devnet-alice-stealth-owner",
            "wxmr-devnet",
            "alice-locked-520-xmr",
            256,
            490,
            EscrowStatus::DebtLocked,
        )?;
        let escrow_b = CollateralEscrow::new(
            &monero_to_l2.adapter_id,
            "devnet-bob-stealth-owner",
            "wxmr-devnet",
            "bob-locked-180-xmr",
            192,
            501,
            EscrowStatus::Active,
        )?;
        let mut collateral_escrows = BTreeMap::new();
        collateral_escrows.insert(escrow_a.escrow_id.clone(), escrow_a.clone());
        collateral_escrows.insert(escrow_b.escrow_id.clone(), escrow_b.clone());

        let debt_a = PrivateDebtLock::new(
            &escrow_a.escrow_id,
            "alice-private-dusd-debt-180k",
            "dusd-devnet",
            "healthy",
            740,
            DebtLockStatus::Locked,
        )?;
        let debt_b = PrivateDebtLock::new(
            &escrow_b.escrow_id,
            "bob-private-dusd-debt-request-22k",
            "dusd-devnet",
            "super_safe",
            704,
            DebtLockStatus::Requested,
        )?;
        let mut private_debt_locks = BTreeMap::new();
        private_debt_locks.insert(debt_a.lock_id.clone(), debt_a.clone());
        private_debt_locks.insert(debt_b.lock_id.clone(), debt_b.clone());

        let reserve_proof = MoneroReserveProof::new(
            "devnet-bridge-reserve-view-account",
            &[
                "reserve-output-a",
                "reserve-output-b",
                "reserve-output-c",
                "reserve-output-d",
            ],
            1_250_000_000_000_000,
            config.min_reserve_coverage_bps,
            18,
            506,
            ReserveProofStatus::Finalized,
        )?;
        let reserve_proof_observed = MoneroReserveProof::new(
            "devnet-bridge-pending-rotation-reserve",
            &["rotation-output-a", "rotation-output-b"],
            320_000_000_000_000,
            config.min_reserve_coverage_bps,
            12,
            511,
            ReserveProofStatus::Attested,
        )?;
        let mut monero_reserve_proofs = BTreeMap::new();
        monero_reserve_proofs.insert(reserve_proof.proof_id.clone(), reserve_proof.clone());
        monero_reserve_proofs.insert(
            reserve_proof_observed.proof_id.clone(),
            reserve_proof_observed.clone(),
        );

        let approval_subject = root_from_record(&json!({
            "adapter_root": monero_to_l2.root(),
            "reserve_root": reserve_proof.root(),
            "debt_root": debt_a.root(),
        }));
        let approval_a = PqGuardianApproval::new(
            "guardian-kestrel",
            &approval_subject,
            3,
            GuardianApprovalStatus::Approved,
        )?;
        let approval_b = PqGuardianApproval::new(
            "guardian-aurora",
            &approval_subject,
            2,
            GuardianApprovalStatus::Approved,
        )?;
        let approval_c = PqGuardianApproval::new(
            "guardian-zenith",
            &l2_to_eth.root(),
            2,
            GuardianApprovalStatus::Pending,
        )?;
        let mut pq_guardian_approvals = BTreeMap::new();
        pq_guardian_approvals.insert(approval_a.approval_id.clone(), approval_a);
        pq_guardian_approvals.insert(approval_b.approval_id.clone(), approval_b);
        pq_guardian_approvals.insert(approval_c.approval_id.clone(), approval_c);

        let hook = LiquidationHook::new(
            &debt_a.lock_id,
            &escrow_a.escrow_id,
            "alice-health-watch-private-oracle",
            &l2_to_eth.adapter_id,
            548,
            LiquidationHookStatus::Armed,
        )?;
        let mut liquidation_hooks = BTreeMap::new();
        liquidation_hooks.insert(hook.hook_id.clone(), hook.clone());

        let receipt = SettlementReceipt::new(
            &escrow_a.escrow_id,
            &debt_a.lock_id,
            &monero_to_l2.adapter_id,
            "alice-bridge-debt-lock-settlement",
            "sponsored-low-fee-lane",
            508,
            SettlementReceiptStatus::Finalized,
        )?;
        let mut settlement_receipts = BTreeMap::new();
        settlement_receipts.insert(receipt.receipt_id.clone(), receipt.clone());

        let public_inputs = [
            ("adapter", monero_to_l2.root(), "bridge-index"),
            ("escrow", escrow_a.root(), "risk-index"),
            ("debt_lock", debt_a.root(), "debt-index"),
            (
                "monero_reserve_proof",
                reserve_proof.root(),
                "reserve-index",
            ),
            ("settlement_receipt", receipt.root(), "settlement-index"),
            ("liquidation_hook", hook.root(), "keeper-index"),
        ];
        let mut privacy_public_records = BTreeMap::new();
        for (subject_kind, subject_root, visibility_group) in public_inputs {
            let record = PrivacyPreservingPublicRecord::new(
                subject_kind,
                &subject_root,
                visibility_group,
                &format!("{subject_kind}-{visibility_group}"),
                PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEVNET_HEIGHT,
            )?;
            privacy_public_records.insert(record.record_id.clone(), record);
        }

        let state = Self {
            height: PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_DEVNET_HEIGHT,
            config,
            adapters,
            collateral_escrows,
            private_debt_locks,
            monero_reserve_proofs,
            pq_guardian_approvals,
            liquidation_hooks,
            settlement_receipts,
            privacy_public_records,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PrivateCrossChainCollateralBridgeResult<()> {
        self.config.validate()?;
        for adapter in self.adapters.values() {
            adapter.validate()?;
        }
        for escrow in self.collateral_escrows.values() {
            escrow.validate(&self.config)?;
            if !self.adapters.contains_key(&escrow.adapter_id) {
                return Err("escrow references unknown adapter".to_string());
            }
        }
        for lock in self.private_debt_locks.values() {
            lock.validate()?;
            if !self.collateral_escrows.contains_key(&lock.escrow_id) {
                return Err("debt lock references unknown escrow".to_string());
            }
        }
        for proof in self.monero_reserve_proofs.values() {
            proof.validate(&self.config)?;
        }
        let mut guardian_ids = BTreeSet::new();
        for approval in self.pq_guardian_approvals.values() {
            approval.validate()?;
            guardian_ids.insert(approval.guardian_id.clone());
        }
        if self.counters().approved_guardian_weight < self.config.min_guardian_weight {
            return Err("approved guardian weight below bridge minimum".to_string());
        }
        if guardian_ids.is_empty() {
            return Err("bridge must have at least one guardian approval".to_string());
        }
        for hook in self.liquidation_hooks.values() {
            hook.validate()?;
            if !self.private_debt_locks.contains_key(&hook.lock_id) {
                return Err("liquidation hook references unknown debt lock".to_string());
            }
            if !self.collateral_escrows.contains_key(&hook.escrow_id) {
                return Err("liquidation hook references unknown escrow".to_string());
            }
            if !self.adapters.contains_key(&hook.execution_adapter_id) {
                return Err("liquidation hook references unknown adapter".to_string());
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            if !self.collateral_escrows.contains_key(&receipt.escrow_id) {
                return Err("settlement receipt references unknown escrow".to_string());
            }
            if !self.private_debt_locks.contains_key(&receipt.lock_id) {
                return Err("settlement receipt references unknown debt lock".to_string());
            }
            if !self.adapters.contains_key(&receipt.adapter_id) {
                return Err("settlement receipt references unknown adapter".to_string());
            }
        }
        for record in self.privacy_public_records.values() {
            record.validate()?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateCrossChainCollateralBridgeResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> PrivateCrossChainCollateralBridgeResult<()> {
        if height < self.height {
            return Err("bridge height cannot move backwards".to_string());
        }
        self.height = height;
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(&self.config.public_record()),
            adapter_root: merkle_root(
                "PCCCB-ADAPTER",
                &self
                    .adapters
                    .values()
                    .map(ChainAdapter::public_record)
                    .collect::<Vec<_>>(),
            ),
            escrow_root: merkle_root(
                "PCCCB-ESCROW",
                &self
                    .collateral_escrows
                    .values()
                    .map(CollateralEscrow::public_record)
                    .collect::<Vec<_>>(),
            ),
            debt_lock_root: merkle_root(
                "PCCCB-DEBT-LOCK",
                &self
                    .private_debt_locks
                    .values()
                    .map(PrivateDebtLock::public_record)
                    .collect::<Vec<_>>(),
            ),
            monero_reserve_proof_root: merkle_root(
                "PCCCB-MONERO-RESERVE-PROOF",
                &self
                    .monero_reserve_proofs
                    .values()
                    .map(MoneroReserveProof::public_record)
                    .collect::<Vec<_>>(),
            ),
            guardian_approval_root: merkle_root(
                "PCCCB-GUARDIAN-APPROVAL",
                &self
                    .pq_guardian_approvals
                    .values()
                    .map(PqGuardianApproval::public_record)
                    .collect::<Vec<_>>(),
            ),
            liquidation_hook_root: merkle_root(
                "PCCCB-LIQUIDATION-HOOK",
                &self
                    .liquidation_hooks
                    .values()
                    .map(LiquidationHook::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_receipt_root: merkle_root(
                "PCCCB-SETTLEMENT-RECEIPT",
                &self
                    .settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_record_root: merkle_root(
                "PCCCB-PUBLIC-RECORD",
                &self
                    .privacy_public_records
                    .values()
                    .map(PrivacyPreservingPublicRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            adapters: self.adapters.len(),
            active_adapters: self
                .adapters
                .values()
                .filter(|adapter| adapter.status.usable())
                .count(),
            escrows: self.collateral_escrows.len(),
            live_escrows: self
                .collateral_escrows
                .values()
                .filter(|escrow| escrow.status.live())
                .count(),
            debt_locks: self.private_debt_locks.len(),
            open_debt_locks: self
                .private_debt_locks
                .values()
                .filter(|lock| lock.status.open())
                .count(),
            monero_reserve_proofs: self.monero_reserve_proofs.len(),
            usable_monero_reserve_proofs: self
                .monero_reserve_proofs
                .values()
                .filter(|proof| proof.status.usable())
                .count(),
            guardian_approvals: self.pq_guardian_approvals.len(),
            approved_guardian_weight: self
                .pq_guardian_approvals
                .values()
                .filter(|approval| approval.status.counts())
                .map(|approval| approval.approval_weight)
                .sum(),
            liquidation_hooks: self.liquidation_hooks.len(),
            open_liquidation_hooks: self
                .liquidation_hooks
                .values()
                .filter(|hook| hook.status.open())
                .count(),
            settlement_receipts: self.settlement_receipts.len(),
            finalized_settlement_receipts: self
                .settlement_receipts
                .values()
                .filter(|receipt| receipt.status.final_state())
                .count(),
            public_records: self.privacy_public_records.len(),
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        domain_hash(
            "PRIVATE-CROSS-CHAIN-COLLATERAL-BRIDGE-STATE",
            &[
                HashPart::Str(PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.height.to_string()),
                HashPart::Json(&roots.public_record()),
                HashPart::Json(&counters.public_record()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_cross_chain_collateral_bridge_state",
            "protocol_version": PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_PROTOCOL_VERSION,
            "hash_suite": PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_HASH_SUITE,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "state_root": self.state_root(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "config": self.config.public_record(),
            "adapters": self.adapters.values().map(ChainAdapter::public_record).collect::<Vec<_>>(),
            "collateral_escrows": self.collateral_escrows.values().map(CollateralEscrow::public_record).collect::<Vec<_>>(),
            "private_debt_locks": self.private_debt_locks.values().map(PrivateDebtLock::public_record).collect::<Vec<_>>(),
            "monero_reserve_proofs": self.monero_reserve_proofs.values().map(MoneroReserveProof::public_record).collect::<Vec<_>>(),
            "pq_guardian_approvals": self.pq_guardian_approvals.values().map(PqGuardianApproval::public_record).collect::<Vec<_>>(),
            "liquidation_hooks": self.liquidation_hooks.values().map(LiquidationHook::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "privacy_public_records": self.privacy_public_records.values().map(PrivacyPreservingPublicRecord::public_record).collect::<Vec<_>>(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-CROSS-CHAIN-COLLATERAL-BRIDGE-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PrivateCrossChainCollateralBridgeResult<State> {
    State::devnet()
}

fn bridge_id(domain: &str, parts: &[&str]) -> String {
    let record = json!({
        "protocol_version": PRIVATE_CROSS_CHAIN_COLLATERAL_BRIDGE_PROTOCOL_VERSION,
        "chain_id": CHAIN_ID,
        "domain": domain,
        "parts": parts,
    });
    domain_hash(
        "PRIVATE-CROSS-CHAIN-COLLATERAL-BRIDGE-ID",
        &[HashPart::Json(&record)],
        32,
    )
}
