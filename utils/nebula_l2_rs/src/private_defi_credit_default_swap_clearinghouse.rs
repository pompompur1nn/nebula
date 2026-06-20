use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateDefiCreditDefaultSwapClearinghouseResult<T> = Result<T, String>;

pub const PRIVATE_DEFI_CREDIT_DEFAULT_SWAP_CLEARINGHOUSE_PROTOCOL_VERSION: &str =
    "nebula-private-defi-credit-default-swap-clearinghouse-v1";
pub const PRIVATE_DEFI_CDS_MAX_POOLS: usize = 32;
pub const PRIVATE_DEFI_CDS_MAX_ORDERS: usize = 256;
pub const PRIVATE_DEFI_CDS_MAX_ATTESTATIONS: usize = 192;
pub const PRIVATE_DEFI_CDS_MAX_SETTLEMENTS: usize = 192;
pub const PRIVATE_DEFI_CDS_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_DEFI_CDS_DEFAULT_CHALLENGE_BLOCKS: u64 = 120;
pub const PRIVATE_DEFI_CDS_MIN_COLLATERAL_BPS: u64 = 10_500;
pub const PRIVATE_DEFI_CDS_MAX_PREMIUM_BPS: u64 = 2_500;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReferenceRiskClass {
    MoneroBridgeMaker,
    PrivateStablecoinVault,
    ConfidentialLendingMarket,
    TokenLaunchPool,
    CrossRollupLiquidityLane,
    Custom(String),
}

impl ReferenceRiskClass {
    pub fn as_str(&self) -> String {
        match self {
            Self::MoneroBridgeMaker => "monero_bridge_maker".to_string(),
            Self::PrivateStablecoinVault => "private_stablecoin_vault".to_string(),
            Self::ConfidentialLendingMarket => "confidential_lending_market".to_string(),
            Self::TokenLaunchPool => "token_launch_pool".to_string(),
            Self::CrossRollupLiquidityLane => "cross_rollup_liquidity_lane".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    fn risk_weight_bps(&self) -> u64 {
        match self {
            Self::MoneroBridgeMaker => 1_250,
            Self::PrivateStablecoinVault => 950,
            Self::ConfidentialLendingMarket => 1_550,
            Self::TokenLaunchPool => 1_800,
            Self::CrossRollupLiquidityLane => 1_350,
            Self::Custom(_) => 2_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtectionSide {
    Buyer,
    Seller,
}

impl ProtectionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Buyer => "buyer",
            Self::Seller => "seller",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtectionOrderStatus {
    Open,
    Matched,
    Settled,
    Cancelled,
    Expired,
}

impl ProtectionOrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DefaultEventKind {
    BridgeMakerInsolvency,
    VaultPegBreak,
    LendingBadDebt,
    LaunchPoolFailure,
    LiquidityLaneTimeout,
    OracleConsensus,
}

impl DefaultEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeMakerInsolvency => "bridge_maker_insolvency",
            Self::VaultPegBreak => "vault_peg_break",
            Self::LendingBadDebt => "lending_bad_debt",
            Self::LaunchPoolFailure => "launch_pool_failure",
            Self::LiquidityLaneTimeout => "liquidity_lane_timeout",
            Self::OracleConsensus => "oracle_consensus",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttestationStatus {
    Pending,
    QuorumReached,
    Challenged,
    Finalized,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::QuorumReached => "quorum_reached",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettlementStatus {
    PendingChallenge,
    Ready,
    Paid,
    Challenged,
    Cancelled,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingChallenge => "pending_challenge",
            Self::Ready => "ready",
            Self::Paid => "paid",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub epoch_blocks: u64,
    pub challenge_blocks: u64,
    pub min_collateral_bps: u64,
    pub max_premium_bps: u64,
    pub max_pools: usize,
    pub max_orders: usize,
    pub max_attestations: usize,
    pub max_settlements: usize,
    pub pq_attestation_scheme: String,
    pub private_match_policy: String,
    pub fee_sponsor_commitment: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_DEFI_CDS_DEFAULT_EPOCH_BLOCKS,
            challenge_blocks: PRIVATE_DEFI_CDS_DEFAULT_CHALLENGE_BLOCKS,
            min_collateral_bps: PRIVATE_DEFI_CDS_MIN_COLLATERAL_BPS,
            max_premium_bps: PRIVATE_DEFI_CDS_MAX_PREMIUM_BPS,
            max_pools: PRIVATE_DEFI_CDS_MAX_POOLS,
            max_orders: PRIVATE_DEFI_CDS_MAX_ORDERS,
            max_attestations: PRIVATE_DEFI_CDS_MAX_ATTESTATIONS,
            max_settlements: PRIVATE_DEFI_CDS_MAX_SETTLEMENTS,
            pq_attestation_scheme: "ml-dsa-87+shake256-domain-separated".to_string(),
            private_match_policy: "sealed-batch-price-time-with-risk-band-cap".to_string(),
            fee_sponsor_commitment: private_defi_cds_commitment("fee-sponsor", "devnet"),
        }
    }

    pub fn validate(&self) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.epoch_blocks == 0 {
            return Err("cds epoch blocks must be non-zero".to_string());
        }
        if self.challenge_blocks == 0 || self.challenge_blocks >= self.epoch_blocks {
            return Err("cds challenge window must fit inside an epoch".to_string());
        }
        if self.min_collateral_bps < 10_000 {
            return Err("cds minimum collateral must cover notional".to_string());
        }
        if self.max_premium_bps == 0 || self.max_premium_bps > 10_000 {
            return Err("cds maximum premium is invalid".to_string());
        }
        if self.max_pools == 0
            || self.max_orders == 0
            || self.max_attestations == 0
            || self.max_settlements == 0
        {
            return Err("cds capacity limits must be non-zero".to_string());
        }
        if self.pq_attestation_scheme.trim().is_empty() {
            return Err("cds pq attestation scheme cannot be empty".to_string());
        }
        if self.private_match_policy.trim().is_empty() {
            return Err("cds private match policy cannot be empty".to_string());
        }
        if self.fee_sponsor_commitment.trim().is_empty() {
            return Err("cds fee sponsor commitment cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "challenge_blocks": self.challenge_blocks,
            "min_collateral_bps": self.min_collateral_bps,
            "max_premium_bps": self.max_premium_bps,
            "max_pools": self.max_pools,
            "max_orders": self.max_orders,
            "max_attestations": self.max_attestations,
            "max_settlements": self.max_settlements,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "private_match_policy": self.private_match_policy,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReferenceEntity {
    pub reference_id: String,
    pub risk_class: ReferenceRiskClass,
    pub private_reference_commitment: String,
    pub oracle_committee_root: String,
    pub recovery_committee_root: String,
    pub max_notional_units: u64,
    pub risk_score_bps: u64,
}

impl ReferenceEntity {
    pub fn new(
        label: &str,
        risk_class: ReferenceRiskClass,
        max_notional_units: u64,
        oracle_committee_root: &str,
        recovery_committee_root: &str,
    ) -> Self {
        let class_name = risk_class.as_str();
        let private_reference_commitment =
            private_defi_cds_commitment("reference", &format!("{label}:{class_name}"));
        let reference_id = private_defi_cds_id(
            "reference",
            &[label, &class_name, &private_reference_commitment],
        );
        let risk_score_bps = risk_class.risk_weight_bps();
        Self {
            reference_id,
            risk_class,
            private_reference_commitment,
            oracle_committee_root: oracle_committee_root.to_string(),
            recovery_committee_root: recovery_committee_root.to_string(),
            max_notional_units,
            risk_score_bps,
        }
    }

    pub fn validate(&self) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.reference_id.trim().is_empty() {
            return Err("cds reference id cannot be empty".to_string());
        }
        if self.private_reference_commitment.trim().is_empty() {
            return Err("cds reference commitment cannot be empty".to_string());
        }
        if self.oracle_committee_root.trim().is_empty() {
            return Err("cds oracle committee root cannot be empty".to_string());
        }
        if self.recovery_committee_root.trim().is_empty() {
            return Err("cds recovery committee root cannot be empty".to_string());
        }
        if self.max_notional_units == 0 {
            return Err("cds reference max notional must be non-zero".to_string());
        }
        if self.risk_score_bps == 0 {
            return Err("cds reference risk score must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reference_id": self.reference_id,
            "risk_class": self.risk_class.as_str(),
            "private_reference_commitment": self.private_reference_commitment,
            "oracle_committee_root": self.oracle_committee_root,
            "recovery_committee_root": self.recovery_committee_root,
            "max_notional_units": self.max_notional_units,
            "risk_score_bps": self.risk_score_bps,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtectionPool {
    pub pool_id: String,
    pub reference_id: String,
    pub collateral_asset_commitment: String,
    pub liquidity_commitment_root: String,
    pub seller_commitment_root: String,
    pub available_collateral_units: u64,
    pub locked_collateral_units: u64,
    pub covered_notional_units: u64,
    pub min_premium_bps: u64,
    pub maturity_height: u64,
    pub risk_band: String,
}

impl ProtectionPool {
    pub fn new(
        reference_id: &str,
        collateral_label: &str,
        available_collateral_units: u64,
        min_premium_bps: u64,
        maturity_height: u64,
        risk_band: &str,
    ) -> Self {
        let collateral_asset_commitment =
            private_defi_cds_commitment("collateral", collateral_label);
        let pool_id = private_defi_cds_id(
            "pool",
            &[reference_id, &collateral_asset_commitment, risk_band],
        );
        let liquidity_commitment_root = private_defi_cds_string_root(
            "pool-liquidity",
            &[
                collateral_asset_commitment.as_str(),
                &available_collateral_units.to_string(),
                risk_band,
            ],
        );
        let seller_commitment_root =
            private_defi_cds_string_root("pool-sellers", &[reference_id, risk_band]);
        Self {
            pool_id,
            reference_id: reference_id.to_string(),
            collateral_asset_commitment,
            liquidity_commitment_root,
            seller_commitment_root,
            available_collateral_units,
            locked_collateral_units: 0,
            covered_notional_units: 0,
            min_premium_bps,
            maturity_height,
            risk_band: risk_band.to_string(),
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.pool_id.trim().is_empty() {
            return Err("cds pool id cannot be empty".to_string());
        }
        if self.reference_id.trim().is_empty() {
            return Err("cds pool reference id cannot be empty".to_string());
        }
        if self.collateral_asset_commitment.trim().is_empty() {
            return Err("cds pool collateral commitment cannot be empty".to_string());
        }
        if self.min_premium_bps > config.max_premium_bps {
            return Err("cds pool premium exceeds configured cap".to_string());
        }
        if self.available_collateral_units + self.locked_collateral_units == 0 {
            return Err("cds pool must have collateral".to_string());
        }
        if self.maturity_height == 0 {
            return Err("cds pool maturity must be non-zero".to_string());
        }
        if self.risk_band.trim().is_empty() {
            return Err("cds pool risk band cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn utilization_bps(&self) -> u64 {
        let total = self.available_collateral_units + self.locked_collateral_units;
        if total == 0 {
            return 0;
        }
        self.locked_collateral_units.saturating_mul(10_000) / total
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "reference_id": self.reference_id,
            "collateral_asset_commitment": self.collateral_asset_commitment,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "seller_commitment_root": self.seller_commitment_root,
            "available_collateral_units": self.available_collateral_units,
            "locked_collateral_units": self.locked_collateral_units,
            "covered_notional_units": self.covered_notional_units,
            "min_premium_bps": self.min_premium_bps,
            "maturity_height": self.maturity_height,
            "risk_band": self.risk_band,
            "utilization_bps": self.utilization_bps(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtectionOrder {
    pub order_id: String,
    pub pool_id: String,
    pub reference_id: String,
    pub buyer_commitment: String,
    pub side: ProtectionSide,
    pub notional_units: u64,
    pub premium_bps: u64,
    pub collateral_reservation_units: u64,
    pub max_fee_units: u64,
    pub created_height: u64,
    pub expiry_height: u64,
    pub status: ProtectionOrderStatus,
    pub private_terms_root: String,
    pub pq_authorization_root: String,
}

impl ProtectionOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        reference_id: &str,
        buyer_label: &str,
        side: ProtectionSide,
        notional_units: u64,
        premium_bps: u64,
        max_fee_units: u64,
        created_height: u64,
        expiry_height: u64,
    ) -> Self {
        let buyer_commitment = private_defi_cds_commitment("buyer", buyer_label);
        let side_label = side.as_str();
        let order_id = private_defi_cds_id(
            "order",
            &[
                pool_id,
                reference_id,
                buyer_commitment.as_str(),
                side_label,
                &created_height.to_string(),
            ],
        );
        let collateral_reservation_units =
            private_defi_cds_collateral_reservation(notional_units, premium_bps);
        let private_terms_root = private_defi_cds_string_root(
            "order-terms",
            &[
                pool_id,
                reference_id,
                buyer_commitment.as_str(),
                side_label,
                &notional_units.to_string(),
                &premium_bps.to_string(),
                &expiry_height.to_string(),
            ],
        );
        let pq_authorization_root =
            private_defi_cds_string_root("order-pq-auth", &[order_id.as_str(), buyer_label]);
        Self {
            order_id,
            pool_id: pool_id.to_string(),
            reference_id: reference_id.to_string(),
            buyer_commitment,
            side,
            notional_units,
            premium_bps,
            collateral_reservation_units,
            max_fee_units,
            created_height,
            expiry_height,
            status: ProtectionOrderStatus::Open,
            private_terms_root,
            pq_authorization_root,
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.order_id.trim().is_empty() {
            return Err("cds order id cannot be empty".to_string());
        }
        if self.pool_id.trim().is_empty() || self.reference_id.trim().is_empty() {
            return Err("cds order must reference pool and reference entity".to_string());
        }
        if self.buyer_commitment.trim().is_empty() {
            return Err("cds order buyer commitment cannot be empty".to_string());
        }
        if self.notional_units == 0 {
            return Err("cds order notional must be non-zero".to_string());
        }
        if self.premium_bps == 0 || self.premium_bps > config.max_premium_bps {
            return Err("cds order premium is outside configured bounds".to_string());
        }
        if self.collateral_reservation_units == 0 {
            return Err("cds order collateral reservation must be non-zero".to_string());
        }
        if self.expiry_height <= self.created_height {
            return Err("cds order expiry must be after creation".to_string());
        }
        if self.private_terms_root.trim().is_empty() || self.pq_authorization_root.trim().is_empty()
        {
            return Err("cds order roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn is_live(&self, height: u64) -> bool {
        matches!(
            self.status,
            ProtectionOrderStatus::Open | ProtectionOrderStatus::Matched
        ) && self.expiry_height >= height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "pool_id": self.pool_id,
            "reference_id": self.reference_id,
            "buyer_commitment": self.buyer_commitment,
            "side": self.side.as_str(),
            "notional_units": self.notional_units,
            "premium_bps": self.premium_bps,
            "collateral_reservation_units": self.collateral_reservation_units,
            "max_fee_units": self.max_fee_units,
            "created_height": self.created_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
            "private_terms_root": self.private_terms_root,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefaultAttestation {
    pub attestation_id: String,
    pub reference_id: String,
    pub event_kind: DefaultEventKind,
    pub evidence_root: String,
    pub pq_committee_root: String,
    pub signer_commitment_root: String,
    pub observed_loss_bps: u64,
    pub quorum_weight_bps: u64,
    pub created_height: u64,
    pub challenge_deadline: u64,
    pub status: AttestationStatus,
}

impl DefaultAttestation {
    pub fn new(
        reference_id: &str,
        event_kind: DefaultEventKind,
        evidence_label: &str,
        observed_loss_bps: u64,
        quorum_weight_bps: u64,
        created_height: u64,
        challenge_blocks: u64,
    ) -> Self {
        let event_label = event_kind.as_str();
        let evidence_root = private_defi_cds_string_root(
            "default-evidence",
            &[reference_id, event_label, evidence_label],
        );
        let pq_committee_root = private_defi_cds_string_root(
            "default-pq-committee",
            &[reference_id, event_label, &created_height.to_string()],
        );
        let signer_commitment_root = private_defi_cds_string_root(
            "default-signers",
            &[pq_committee_root.as_str(), evidence_root.as_str()],
        );
        let attestation_id = private_defi_cds_id(
            "attestation",
            &[reference_id, event_label, evidence_root.as_str()],
        );
        let status = if quorum_weight_bps >= 6_700 {
            AttestationStatus::QuorumReached
        } else {
            AttestationStatus::Pending
        };
        Self {
            attestation_id,
            reference_id: reference_id.to_string(),
            event_kind,
            evidence_root,
            pq_committee_root,
            signer_commitment_root,
            observed_loss_bps,
            quorum_weight_bps,
            created_height,
            challenge_deadline: created_height.saturating_add(challenge_blocks),
            status,
        }
    }

    pub fn validate(&self) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.attestation_id.trim().is_empty() || self.reference_id.trim().is_empty() {
            return Err("cds default attestation ids cannot be empty".to_string());
        }
        if self.evidence_root.trim().is_empty()
            || self.pq_committee_root.trim().is_empty()
            || self.signer_commitment_root.trim().is_empty()
        {
            return Err("cds default attestation roots cannot be empty".to_string());
        }
        if self.observed_loss_bps > 10_000 || self.quorum_weight_bps > 10_000 {
            return Err("cds default attestation bps fields exceed 10000".to_string());
        }
        if self.challenge_deadline <= self.created_height {
            return Err("cds default attestation challenge deadline is invalid".to_string());
        }
        Ok(())
    }

    pub fn finalizable(&self, height: u64) -> bool {
        matches!(self.status, AttestationStatus::QuorumReached) && height >= self.challenge_deadline
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "reference_id": self.reference_id,
            "event_kind": self.event_kind.as_str(),
            "evidence_root": self.evidence_root,
            "pq_committee_root": self.pq_committee_root,
            "signer_commitment_root": self.signer_commitment_root,
            "observed_loss_bps": self.observed_loss_bps,
            "quorum_weight_bps": self.quorum_weight_bps,
            "created_height": self.created_height,
            "challenge_deadline": self.challenge_deadline,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub order_id: String,
    pub pool_id: String,
    pub attestation_id: String,
    pub payout_commitment: String,
    pub payout_units: u64,
    pub sponsor_fee_units: u64,
    pub challenge_deadline: u64,
    pub status: SettlementStatus,
    pub nullifier_root: String,
}

impl SettlementReceipt {
    pub fn new(
        order: &ProtectionOrder,
        attestation: &DefaultAttestation,
        payout_units: u64,
        sponsor_fee_units: u64,
        challenge_deadline: u64,
    ) -> Self {
        let payout_commitment = private_defi_cds_string_root(
            "settlement-payout",
            &[
                order.order_id.as_str(),
                attestation.attestation_id.as_str(),
                &payout_units.to_string(),
            ],
        );
        let receipt_id = private_defi_cds_id(
            "settlement",
            &[
                order.order_id.as_str(),
                order.pool_id.as_str(),
                attestation.attestation_id.as_str(),
                payout_commitment.as_str(),
            ],
        );
        let nullifier_root =
            private_defi_cds_string_root("settlement-nullifier", &[receipt_id.as_str()]);
        Self {
            receipt_id,
            order_id: order.order_id.clone(),
            pool_id: order.pool_id.clone(),
            attestation_id: attestation.attestation_id.clone(),
            payout_commitment,
            payout_units,
            sponsor_fee_units,
            challenge_deadline,
            status: SettlementStatus::PendingChallenge,
            nullifier_root,
        }
    }

    pub fn validate(&self) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.receipt_id.trim().is_empty()
            || self.order_id.trim().is_empty()
            || self.pool_id.trim().is_empty()
            || self.attestation_id.trim().is_empty()
        {
            return Err("cds settlement ids cannot be empty".to_string());
        }
        if self.payout_commitment.trim().is_empty() || self.nullifier_root.trim().is_empty() {
            return Err("cds settlement roots cannot be empty".to_string());
        }
        if self.payout_units == 0 {
            return Err("cds settlement payout must be non-zero".to_string());
        }
        if self.challenge_deadline == 0 {
            return Err("cds settlement challenge deadline must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn ready(&self, height: u64) -> bool {
        matches!(self.status, SettlementStatus::PendingChallenge)
            && height >= self.challenge_deadline
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "order_id": self.order_id,
            "pool_id": self.pool_id,
            "attestation_id": self.attestation_id,
            "payout_commitment": self.payout_commitment,
            "payout_units": self.payout_units,
            "sponsor_fee_units": self.sponsor_fee_units,
            "challenge_deadline": self.challenge_deadline,
            "status": self.status.as_str(),
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarginAccount {
    pub account_id: String,
    pub owner_commitment: String,
    pub collateral_commitment_root: String,
    pub reserved_units: u64,
    pub free_units: u64,
    pub realized_pnl_units: i128,
    pub liquidation_guard_root: String,
}

impl MarginAccount {
    pub fn new(owner_label: &str, free_units: u64, reserved_units: u64) -> Self {
        let owner_commitment = private_defi_cds_commitment("margin-owner", owner_label);
        let account_id = private_defi_cds_id("margin-account", &[owner_commitment.as_str()]);
        let collateral_commitment_root = private_defi_cds_string_root(
            "margin-collateral",
            &[
                owner_commitment.as_str(),
                &free_units.to_string(),
                &reserved_units.to_string(),
            ],
        );
        let liquidation_guard_root =
            private_defi_cds_string_root("margin-liquidation-guard", &[account_id.as_str()]);
        Self {
            account_id,
            owner_commitment,
            collateral_commitment_root,
            reserved_units,
            free_units,
            realized_pnl_units: 0,
            liquidation_guard_root,
        }
    }

    pub fn validate(&self) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.account_id.trim().is_empty() || self.owner_commitment.trim().is_empty() {
            return Err("cds margin account ids cannot be empty".to_string());
        }
        if self.collateral_commitment_root.trim().is_empty()
            || self.liquidation_guard_root.trim().is_empty()
        {
            return Err("cds margin account roots cannot be empty".to_string());
        }
        if self.free_units + self.reserved_units == 0 {
            return Err("cds margin account must hold collateral".to_string());
        }
        Ok(())
    }

    pub fn collateral_units(&self) -> u64 {
        self.free_units.saturating_add(self.reserved_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "collateral_commitment_root": self.collateral_commitment_root,
            "reserved_units": self.reserved_units,
            "free_units": self.free_units,
            "realized_pnl_units": self.realized_pnl_units,
            "liquidation_guard_root": self.liquidation_guard_root,
            "collateral_units": self.collateral_units(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorCredit {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub available_fee_units: u64,
    pub reserved_fee_units: u64,
    pub policy_root: String,
}

impl SponsorCredit {
    pub fn new(label: &str, available_fee_units: u64, reserved_fee_units: u64) -> Self {
        let sponsor_commitment = private_defi_cds_commitment("cds-sponsor", label);
        let sponsor_id = private_defi_cds_id("sponsor", &[sponsor_commitment.as_str()]);
        let policy_root = private_defi_cds_string_root(
            "sponsor-policy",
            &[
                sponsor_commitment.as_str(),
                &available_fee_units.to_string(),
                &reserved_fee_units.to_string(),
            ],
        );
        Self {
            sponsor_id,
            sponsor_commitment,
            available_fee_units,
            reserved_fee_units,
            policy_root,
        }
    }

    pub fn validate(&self) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.sponsor_id.trim().is_empty() || self.sponsor_commitment.trim().is_empty() {
            return Err("cds sponsor ids cannot be empty".to_string());
        }
        if self.policy_root.trim().is_empty() {
            return Err("cds sponsor policy root cannot be empty".to_string());
        }
        if self.available_fee_units + self.reserved_fee_units == 0 {
            return Err("cds sponsor must have fee units".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "available_fee_units": self.available_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub reference_root: String,
    pub pool_root: String,
    pub order_root: String,
    pub attestation_root: String,
    pub settlement_root: String,
    pub margin_root: String,
    pub sponsor_root: String,
    pub live_order_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "reference_root": self.reference_root,
            "pool_root": self.pool_root,
            "order_root": self.order_root,
            "attestation_root": self.attestation_root,
            "settlement_root": self.settlement_root,
            "margin_root": self.margin_root,
            "sponsor_root": self.sponsor_root,
            "live_order_root": self.live_order_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub reference_count: u64,
    pub pool_count: u64,
    pub order_count: u64,
    pub live_order_count: u64,
    pub matched_order_count: u64,
    pub default_attestation_count: u64,
    pub finalizable_attestation_count: u64,
    pub settlement_count: u64,
    pub ready_settlement_count: u64,
    pub total_notional_units: u64,
    pub locked_collateral_units: u64,
    pub sponsored_fee_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reference_count": self.reference_count,
            "pool_count": self.pool_count,
            "order_count": self.order_count,
            "live_order_count": self.live_order_count,
            "matched_order_count": self.matched_order_count,
            "default_attestation_count": self.default_attestation_count,
            "finalizable_attestation_count": self.finalizable_attestation_count,
            "settlement_count": self.settlement_count,
            "ready_settlement_count": self.ready_settlement_count,
            "total_notional_units": self.total_notional_units,
            "locked_collateral_units": self.locked_collateral_units,
            "sponsored_fee_units": self.sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub references: BTreeMap<String, ReferenceEntity>,
    pub pools: BTreeMap<String, ProtectionPool>,
    pub orders: BTreeMap<String, ProtectionOrder>,
    pub default_attestations: BTreeMap<String, DefaultAttestation>,
    pub settlements: BTreeMap<String, SettlementReceipt>,
    pub margin_accounts: BTreeMap<String, MarginAccount>,
    pub sponsor_credits: BTreeMap<String, SponsorCredit>,
    pub challenged_attestations: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateDefiCreditDefaultSwapClearinghouseResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        let mut state = Self {
            height: 24,
            config,
            references: BTreeMap::new(),
            pools: BTreeMap::new(),
            orders: BTreeMap::new(),
            default_attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            margin_accounts: BTreeMap::new(),
            sponsor_credits: BTreeMap::new(),
            challenged_attestations: BTreeSet::new(),
        };

        let monero_reference = ReferenceEntity::new(
            "devnet-monero-bridge-maker-alpha",
            ReferenceRiskClass::MoneroBridgeMaker,
            10_000_000,
            "oracle-committee-root-monero-maker-alpha",
            "recovery-committee-root-monero-maker-alpha",
        );
        let stablecoin_reference = ReferenceEntity::new(
            "devnet-private-stable-vault-delta",
            ReferenceRiskClass::PrivateStablecoinVault,
            14_000_000,
            "oracle-committee-root-private-stable-delta",
            "recovery-committee-root-private-stable-delta",
        );
        state.insert_reference(monero_reference.clone())?;
        state.insert_reference(stablecoin_reference.clone())?;

        let mut monero_pool = ProtectionPool::new(
            &monero_reference.reference_id,
            "xmr-bridge-collateral-bucket-alpha",
            2_400_000,
            180,
            1_200,
            "risk-band-green",
        );
        let mut stable_pool = ProtectionPool::new(
            &stablecoin_reference.reference_id,
            "stable-vault-collateral-bucket-delta",
            3_800_000,
            140,
            1_440,
            "risk-band-blue",
        );

        let order_a = ProtectionOrder::new(
            &monero_pool.pool_id,
            &monero_reference.reference_id,
            "buyer-alpha",
            ProtectionSide::Buyer,
            420_000,
            210,
            950,
            state.height,
            state.height + 360,
        );
        let order_b = ProtectionOrder::new(
            &stable_pool.pool_id,
            &stablecoin_reference.reference_id,
            "buyer-beta",
            ProtectionSide::Buyer,
            760_000,
            175,
            1_250,
            state.height,
            state.height + 480,
        );

        monero_pool.locked_collateral_units = order_a.collateral_reservation_units;
        monero_pool.available_collateral_units = monero_pool
            .available_collateral_units
            .saturating_sub(order_a.collateral_reservation_units);
        monero_pool.covered_notional_units = order_a.notional_units;
        stable_pool.locked_collateral_units = order_b.collateral_reservation_units;
        stable_pool.available_collateral_units = stable_pool
            .available_collateral_units
            .saturating_sub(order_b.collateral_reservation_units);
        stable_pool.covered_notional_units = order_b.notional_units;

        state.insert_pool(monero_pool.clone())?;
        state.insert_pool(stable_pool.clone())?;
        state.insert_order(order_a.clone())?;
        state.insert_order(order_b.clone())?;

        state.insert_margin_account(MarginAccount::new("buyer-alpha", 1_200_000, 92_000))?;
        state.insert_margin_account(MarginAccount::new("buyer-beta", 1_500_000, 140_000))?;
        state.insert_sponsor_credit(SponsorCredit::new("cds-fee-sponsor-alpha", 80_000, 4_200))?;
        state.insert_sponsor_credit(SponsorCredit::new("cds-fee-sponsor-beta", 120_000, 6_800))?;

        let attestation = DefaultAttestation::new(
            &monero_reference.reference_id,
            DefaultEventKind::BridgeMakerInsolvency,
            "maker-alpha-late-reserve-proof",
            3_300,
            7_200,
            state.height + 2,
            state.config.challenge_blocks,
        );
        let settlement = SettlementReceipt::new(
            &order_a,
            &attestation,
            private_defi_cds_payout(order_a.notional_units, attestation.observed_loss_bps),
            430,
            attestation.challenge_deadline,
        );
        state.insert_default_attestation(attestation)?;
        state.insert_settlement(settlement)?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_reference(
        &mut self,
        reference: ReferenceEntity,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.references.len() >= self.config.max_pools {
            return Err("cds reference capacity exceeded".to_string());
        }
        reference.validate()?;
        self.references
            .insert(reference.reference_id.clone(), reference);
        Ok(())
    }

    pub fn insert_pool(
        &mut self,
        pool: ProtectionPool,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.pools.len() >= self.config.max_pools {
            return Err("cds pool capacity exceeded".to_string());
        }
        if !self.references.contains_key(&pool.reference_id) {
            return Err("cds pool references unknown reference entity".to_string());
        }
        pool.validate(&self.config)?;
        self.pools.insert(pool.pool_id.clone(), pool);
        Ok(())
    }

    pub fn insert_order(
        &mut self,
        mut order: ProtectionOrder,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.orders.len() >= self.config.max_orders {
            return Err("cds order capacity exceeded".to_string());
        }
        if !self.pools.contains_key(&order.pool_id) {
            return Err("cds order references unknown pool".to_string());
        }
        if order.expiry_height < self.height {
            order.status = ProtectionOrderStatus::Expired;
        }
        order.validate(&self.config)?;
        self.orders.insert(order.order_id.clone(), order);
        Ok(())
    }

    pub fn insert_default_attestation(
        &mut self,
        attestation: DefaultAttestation,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.default_attestations.len() >= self.config.max_attestations {
            return Err("cds attestation capacity exceeded".to_string());
        }
        if !self.references.contains_key(&attestation.reference_id) {
            return Err("cds attestation references unknown entity".to_string());
        }
        attestation.validate()?;
        self.default_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_settlement(
        &mut self,
        settlement: SettlementReceipt,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if self.settlements.len() >= self.config.max_settlements {
            return Err("cds settlement capacity exceeded".to_string());
        }
        if !self.orders.contains_key(&settlement.order_id) {
            return Err("cds settlement references unknown order".to_string());
        }
        if !self
            .default_attestations
            .contains_key(&settlement.attestation_id)
        {
            return Err("cds settlement references unknown attestation".to_string());
        }
        settlement.validate()?;
        self.settlements
            .insert(settlement.receipt_id.clone(), settlement);
        Ok(())
    }

    pub fn insert_margin_account(
        &mut self,
        account: MarginAccount,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        account.validate()?;
        self.margin_accounts
            .insert(account.account_id.clone(), account);
        Ok(())
    }

    pub fn insert_sponsor_credit(
        &mut self,
        sponsor: SponsorCredit,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        sponsor.validate()?;
        self.sponsor_credits
            .insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(())
    }

    pub fn challenge_attestation(
        &mut self,
        attestation_id: &str,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        let attestation = self
            .default_attestations
            .get_mut(attestation_id)
            .ok_or_else(|| "cds attestation not found for challenge".to_string())?;
        if self.height > attestation.challenge_deadline {
            return Err("cds attestation challenge window has closed".to_string());
        }
        attestation.status = AttestationStatus::Challenged;
        self.challenged_attestations
            .insert(attestation_id.to_string());
        Ok(())
    }

    pub fn set_height(
        &mut self,
        height: u64,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        if height < self.height {
            return Err("cds height cannot move backwards".to_string());
        }
        self.height = height;
        self.refresh_timeouts();
        self.refresh_finality();
        Ok(())
    }

    pub fn update_height(
        &mut self,
        delta: u64,
    ) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        let next = self.height.saturating_add(delta);
        self.set_height(next)
    }

    fn refresh_timeouts(&mut self) {
        for order in self.orders.values_mut() {
            if matches!(order.status, ProtectionOrderStatus::Open)
                && order.expiry_height < self.height
            {
                order.status = ProtectionOrderStatus::Expired;
            }
        }
    }

    fn refresh_finality(&mut self) {
        for attestation in self.default_attestations.values_mut() {
            if attestation.finalizable(self.height) {
                attestation.status = AttestationStatus::Finalized;
            }
        }
        for settlement in self.settlements.values_mut() {
            if settlement.ready(self.height) {
                settlement.status = SettlementStatus::Ready;
            }
        }
    }

    pub fn validate(&self) -> PrivateDefiCreditDefaultSwapClearinghouseResult<()> {
        self.config.validate()?;
        if self.pools.len() > self.config.max_pools {
            return Err("cds pool count exceeds capacity".to_string());
        }
        if self.orders.len() > self.config.max_orders {
            return Err("cds order count exceeds capacity".to_string());
        }
        if self.default_attestations.len() > self.config.max_attestations {
            return Err("cds attestation count exceeds capacity".to_string());
        }
        if self.settlements.len() > self.config.max_settlements {
            return Err("cds settlement count exceeds capacity".to_string());
        }
        for reference in self.references.values() {
            reference.validate()?;
        }
        for pool in self.pools.values() {
            pool.validate(&self.config)?;
            if !self.references.contains_key(&pool.reference_id) {
                return Err("cds pool points to missing reference".to_string());
            }
        }
        for order in self.orders.values() {
            order.validate(&self.config)?;
            if !self.pools.contains_key(&order.pool_id) {
                return Err("cds order points to missing pool".to_string());
            }
        }
        for attestation in self.default_attestations.values() {
            attestation.validate()?;
            if !self.references.contains_key(&attestation.reference_id) {
                return Err("cds attestation points to missing reference".to_string());
            }
        }
        for settlement in self.settlements.values() {
            settlement.validate()?;
            if !self.orders.contains_key(&settlement.order_id) {
                return Err("cds settlement points to missing order".to_string());
            }
        }
        for account in self.margin_accounts.values() {
            account.validate()?;
        }
        for sponsor in self.sponsor_credits.values() {
            sponsor.validate()?;
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let reference_leaves = self
            .references
            .values()
            .map(ReferenceEntity::public_record)
            .collect::<Vec<_>>();
        let pool_leaves = self
            .pools
            .values()
            .map(ProtectionPool::public_record)
            .collect::<Vec<_>>();
        let order_leaves = self
            .orders
            .values()
            .map(ProtectionOrder::public_record)
            .collect::<Vec<_>>();
        let attestation_leaves = self
            .default_attestations
            .values()
            .map(DefaultAttestation::public_record)
            .collect::<Vec<_>>();
        let settlement_leaves = self
            .settlements
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let margin_leaves = self
            .margin_accounts
            .values()
            .map(MarginAccount::public_record)
            .collect::<Vec<_>>();
        let sponsor_leaves = self
            .sponsor_credits
            .values()
            .map(SponsorCredit::public_record)
            .collect::<Vec<_>>();
        let live_order_leaves = self
            .orders
            .values()
            .filter(|order| order.is_live(self.height))
            .map(ProtectionOrder::public_record)
            .collect::<Vec<_>>();
        Roots {
            reference_root: merkle_root("PRIVATE-DEFI-CDS:references", &reference_leaves),
            pool_root: merkle_root("PRIVATE-DEFI-CDS:pools", &pool_leaves),
            order_root: merkle_root("PRIVATE-DEFI-CDS:orders", &order_leaves),
            attestation_root: merkle_root("PRIVATE-DEFI-CDS:attestations", &attestation_leaves),
            settlement_root: merkle_root("PRIVATE-DEFI-CDS:settlements", &settlement_leaves),
            margin_root: merkle_root("PRIVATE-DEFI-CDS:margins", &margin_leaves),
            sponsor_root: merkle_root("PRIVATE-DEFI-CDS:sponsors", &sponsor_leaves),
            live_order_root: merkle_root("PRIVATE-DEFI-CDS:live-orders", &live_order_leaves),
        }
    }

    pub fn counters(&self) -> Counters {
        let live_order_count = self
            .orders
            .values()
            .filter(|order| order.is_live(self.height))
            .count() as u64;
        let matched_order_count = self
            .orders
            .values()
            .filter(|order| matches!(order.status, ProtectionOrderStatus::Matched))
            .count() as u64;
        let finalizable_attestation_count = self
            .default_attestations
            .values()
            .filter(|attestation| attestation.finalizable(self.height))
            .count() as u64;
        let ready_settlement_count = self
            .settlements
            .values()
            .filter(|settlement| {
                matches!(
                    settlement.status,
                    SettlementStatus::Ready | SettlementStatus::PendingChallenge
                ) && settlement.challenge_deadline <= self.height
            })
            .count() as u64;
        let total_notional_units = self
            .orders
            .values()
            .map(|order| order.notional_units)
            .sum::<u64>();
        let locked_collateral_units = self
            .pools
            .values()
            .map(|pool| pool.locked_collateral_units)
            .sum::<u64>();
        let sponsored_fee_units = self
            .sponsor_credits
            .values()
            .map(|sponsor| sponsor.reserved_fee_units)
            .sum::<u64>();
        Counters {
            reference_count: self.references.len() as u64,
            pool_count: self.pools.len() as u64,
            order_count: self.orders.len() as u64,
            live_order_count,
            matched_order_count,
            default_attestation_count: self.default_attestations.len() as u64,
            finalizable_attestation_count,
            settlement_count: self.settlements.len() as u64,
            ready_settlement_count,
            total_notional_units,
            locked_collateral_units,
            sponsored_fee_units,
        }
    }

    pub fn active_pool_ids(&self) -> Vec<String> {
        self.pools
            .values()
            .filter(|pool| pool.maturity_height >= self.height)
            .map(|pool| pool.pool_id.clone())
            .collect()
    }

    pub fn live_order_ids(&self) -> Vec<String> {
        self.orders
            .values()
            .filter(|order| order.is_live(self.height))
            .map(|order| order.order_id.clone())
            .collect()
    }

    pub fn ready_settlement_ids(&self) -> Vec<String> {
        self.settlements
            .values()
            .filter(|settlement| settlement.ready(self.height))
            .map(|settlement| settlement.receipt_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_defi_credit_default_swap_clearinghouse",
            "version": PRIVATE_DEFI_CREDIT_DEFAULT_SWAP_CLEARINGHOUSE_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "references": self.references.values().map(ReferenceEntity::public_record).collect::<Vec<_>>(),
            "pools": self.pools.values().map(ProtectionPool::public_record).collect::<Vec<_>>(),
            "orders": self.orders.values().map(ProtectionOrder::public_record).collect::<Vec<_>>(),
            "default_attestations": self.default_attestations.values().map(DefaultAttestation::public_record).collect::<Vec<_>>(),
            "settlements": self.settlements.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "margin_accounts": self.margin_accounts.values().map(MarginAccount::public_record).collect::<Vec<_>>(),
            "sponsor_credits": self.sponsor_credits.values().map(SponsorCredit::public_record).collect::<Vec<_>>(),
            "challenged_attestations": self.challenged_attestations.iter().cloned().collect::<Vec<_>>(),
            "active_pool_ids": self.active_pool_ids(),
            "live_order_ids": self.live_order_ids(),
            "ready_settlement_ids": self.ready_settlement_ids(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash("PRIVATE-DEFI-CDS:state-root", &[HashPart::Json(record)], 32)
}

pub fn devnet() -> PrivateDefiCreditDefaultSwapClearinghouseResult<State> {
    State::devnet()
}

fn private_defi_cds_id(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| json!({"part": part}))
        .collect::<Vec<_>>();
    let root = merkle_root(&format!("PRIVATE-DEFI-CDS:{domain}:id"), &leaves);
    domain_hash(
        &format!("PRIVATE-DEFI-CDS:{domain}:id-final"),
        &[HashPart::Str(root.as_str())],
        16,
    )
}

fn private_defi_cds_commitment(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("PRIVATE-DEFI-CDS:{domain}:commitment"),
        &[HashPart::Str(label)],
        32,
    )
}

fn private_defi_cds_string_root(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| json!({"value": part}))
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-DEFI-CDS:{domain}"), &leaves)
}

fn private_defi_cds_collateral_reservation(notional_units: u64, premium_bps: u64) -> u64 {
    let base = notional_units.saturating_mul(PRIVATE_DEFI_CDS_MIN_COLLATERAL_BPS) / 10_000;
    let premium_buffer = notional_units.saturating_mul(premium_bps) / 10_000;
    base.saturating_add(premium_buffer)
}

fn private_defi_cds_payout(notional_units: u64, observed_loss_bps: u64) -> u64 {
    notional_units.saturating_mul(observed_loss_bps.min(10_000)) / 10_000
}
