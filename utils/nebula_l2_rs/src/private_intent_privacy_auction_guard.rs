use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateIntentPrivacyAuctionGuardResult<T> = Result<T, String>;

pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_PROTOCOL_VERSION: &str =
    "nebula-private-intent-privacy-auction-guard-v1";
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_SCHEMA_VERSION: &str =
    "private-intent-privacy-auction-guard-state-v1";
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_HASH_SUITE: &str =
    "shake256-domain-separated-canonical-json";
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_PQ_AUTH_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_PROOF_SYSTEM: &str =
    "zk-private-intent-auction-guard-v1";
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_COMMIT_REVEAL_SCHEME: &str =
    "sealed-intent-commit-reveal-v1";
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_LOW_FEE_SPONSOR_SCHEME: &str =
    "private-low-fee-intent-sponsor-v1";
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEVNET_HEIGHT: u64 = 640;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 8;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_AUCTION_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 72;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MAX_FEE_UNITS: u64 = 7;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MAX_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MAX_BUILDER_EDGE_BPS: u64 = 150;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 25_000;
pub const PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateIntentLaneKind {
    Swap,
    BridgeExit,
    Liquidation,
    VaultRebalance,
    ContractCall,
    Recovery,
}

impl PrivateIntentLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::BridgeExit => "bridge_exit",
            Self::Liquidation => "liquidation",
            Self::VaultRebalance => "vault_rebalance",
            Self::ContractCall => "contract_call",
            Self::Recovery => "recovery",
        }
    }

    pub fn default_max_fee_units(self) -> u64 {
        match self {
            Self::Swap => 6,
            Self::BridgeExit => 7,
            Self::Liquidation => 5,
            Self::VaultRebalance => 6,
            Self::ContractCall => 7,
            Self::Recovery => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionGuardStatus {
    Draft,
    Open,
    Reveal,
    Matched,
    Settled,
    Expired,
    Challenged,
    Slashed,
}

impl AuctionGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Reveal => "reveal",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Reveal | Self::Matched)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Expired | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverBondStatus {
    Pending,
    Active,
    Locked,
    Released,
    Slashed,
}

impl SolverBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Locked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyAuctionChallengeKind {
    EarlyReveal,
    SolverCensorship,
    FeeOvercharge,
    PrivacySetUnderflow,
    SandwichEvidence,
    InvalidSettlement,
}

impl PrivacyAuctionChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EarlyReveal => "early_reveal",
            Self::SolverCensorship => "solver_censorship",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacySetUnderflow => "privacy_set_underflow",
            Self::SandwichEvidence => "sandwich_evidence",
            Self::InvalidSettlement => "invalid_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyAuctionChallengeStatus {
    Open,
    EvidenceSubmitted,
    Accepted,
    Rejected,
    Expired,
}

impl PrivacyAuctionChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceSubmitted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentPrivacyAuctionGuardConfig {
    pub protocol_version: String,
    pub schema_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub proof_system: String,
    pub commit_reveal_scheme: String,
    pub low_fee_sponsor_scheme: String,
    pub epoch_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub default_max_fee_units: u64,
    pub max_rebate_bps: u64,
    pub max_builder_edge_bps: u64,
    pub min_solver_bond_units: u64,
}

impl PrivateIntentPrivacyAuctionGuardConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_SCHEMA_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_HASH_SUITE.to_string(),
            pq_auth_scheme: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_PQ_AUTH_SCHEME.to_string(),
            proof_system: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_PROOF_SYSTEM.to_string(),
            commit_reveal_scheme: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_COMMIT_REVEAL_SCHEME
                .to_string(),
            low_fee_sponsor_scheme: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_LOW_FEE_SPONSOR_SCHEME
                .to_string(),
            epoch_blocks: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_EPOCH_BLOCKS,
            reveal_delay_blocks: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_REVEAL_DELAY_BLOCKS,
            auction_ttl_blocks: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_AUCTION_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_RECEIPT_TTL_BLOCKS,
            challenge_window_blocks:
                PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MIN_PQ_SECURITY_BITS,
            default_max_fee_units: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MAX_FEE_UNITS,
            max_rebate_bps: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MAX_REBATE_BPS,
            max_builder_edge_bps: PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MAX_BUILDER_EDGE_BPS,
            min_solver_bond_units:
                PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEFAULT_MIN_SOLVER_BOND_UNITS,
        }
    }

    pub fn validate(&self) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        ensure_nonempty("protocol version", &self.protocol_version)?;
        ensure_nonempty("schema version", &self.schema_version)?;
        ensure_nonempty("chain id", &self.chain_id)?;
        ensure_nonempty("hash suite", &self.hash_suite)?;
        ensure_nonempty("PQ auth scheme", &self.pq_auth_scheme)?;
        ensure_positive("epoch blocks", self.epoch_blocks)?;
        ensure_positive("auction ttl blocks", self.auction_ttl_blocks)?;
        ensure_positive("receipt ttl blocks", self.receipt_ttl_blocks)?;
        ensure_positive("challenge window blocks", self.challenge_window_blocks)?;
        ensure_positive("min privacy set size", self.min_privacy_set_size)?;
        ensure_positive("default max fee units", self.default_max_fee_units)?;
        ensure_bps("max rebate bps", self.max_rebate_bps)?;
        ensure_bps("max builder edge bps", self.max_builder_edge_bps)?;
        if self.min_pq_security_bits < 128 {
            return Err("min PQ security bits below 128".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_auth_scheme": self.pq_auth_scheme,
            "proof_system": self.proof_system,
            "commit_reveal_scheme": self.commit_reveal_scheme,
            "low_fee_sponsor_scheme": self.low_fee_sponsor_scheme,
            "epoch_blocks": self.epoch_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "default_max_fee_units": self.default_max_fee_units,
            "max_rebate_bps": self.max_rebate_bps,
            "max_builder_edge_bps": self.max_builder_edge_bps,
            "min_solver_bond_units": self.min_solver_bond_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentAuctionLane {
    pub lane_id: String,
    pub lane_kind: PrivateIntentLaneKind,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub min_privacy_set_size: u64,
    pub solver_bond_units: u64,
    pub enabled: bool,
}

impl PrivateIntentAuctionLane {
    pub fn devnet(
        lane_kind: PrivateIntentLaneKind,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> Self {
        let lane_id = private_intent_lane_id(lane_kind, &format!("epoch:{}", config.epoch_blocks));
        Self {
            lane_id,
            lane_kind,
            fee_asset_id: "wxmr-devnet".to_string(),
            max_fee_units: lane_kind
                .default_max_fee_units()
                .min(config.default_max_fee_units),
            min_privacy_set_size: config.min_privacy_set_size,
            solver_bond_units: config.min_solver_bond_units,
            enabled: true,
        }
    }

    pub fn accepts_intents(&self) -> bool {
        self.enabled
    }

    pub fn validate(
        &self,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_nonempty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("lane max fee units", self.max_fee_units)?;
        ensure_positive("lane min privacy set size", self.min_privacy_set_size)?;
        ensure_positive("lane solver bond units", self.solver_bond_units)?;
        if self.max_fee_units > config.default_max_fee_units {
            return Err(format!(
                "lane {} exceeds default max fee units",
                self.lane_id
            ));
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "lane {} privacy set below config floor",
                self.lane_id
            ));
        }
        if self.solver_bond_units < config.min_solver_bond_units {
            return Err(format!(
                "lane {} solver bond below config floor",
                self.lane_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "solver_bond_units": self.solver_bond_units,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedIntentAuction {
    pub auction_id: String,
    pub lane_id: String,
    pub intent_commitment: String,
    pub privacy_group_root: String,
    pub solver_set_root: String,
    pub nullifier_root: String,
    pub created_height: u64,
    pub reveal_height: u64,
    pub expires_height: u64,
    pub max_fee_units: u64,
    pub privacy_set_size: u64,
    pub status: AuctionGuardStatus,
}

impl SealedIntentAuction {
    pub fn devnet(
        auction_label: &str,
        lane: &PrivateIntentAuctionLane,
        height: u64,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> Self {
        let intent_commitment = piag_hash(
            "INTENT-COMMITMENT",
            &[
                HashPart::Str(auction_label),
                HashPart::Str(&lane.lane_id),
                HashPart::Int(height as i128),
            ],
        );
        let privacy_group_root = piag_string_root("PRIVACY-GROUP", auction_label);
        let solver_set_root = piag_string_root("SOLVER-SET", &lane.lane_id);
        let nullifier_root = piag_string_root("NULLIFIER-SET", &intent_commitment);
        let auction_id = private_intent_auction_id(&intent_commitment, height);
        Self {
            auction_id,
            lane_id: lane.lane_id.clone(),
            intent_commitment,
            privacy_group_root,
            solver_set_root,
            nullifier_root,
            created_height: height,
            reveal_height: height.saturating_add(config.reveal_delay_blocks),
            expires_height: height.saturating_add(config.auction_ttl_blocks),
            max_fee_units: lane.max_fee_units,
            privacy_set_size: lane.min_privacy_set_size.saturating_add(16),
            status: AuctionGuardStatus::Open,
        }
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, PrivateIntentAuctionLane>,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        ensure_nonempty("auction id", &self.auction_id)?;
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_nonempty("intent commitment", &self.intent_commitment)?;
        ensure_nonempty("privacy group root", &self.privacy_group_root)?;
        ensure_nonempty("solver set root", &self.solver_set_root)?;
        ensure_nonempty("nullifier root", &self.nullifier_root)?;
        ensure_positive("auction max fee units", self.max_fee_units)?;
        ensure_positive("auction privacy set size", self.privacy_set_size)?;
        if self.reveal_height <= self.created_height {
            return Err(format!(
                "auction {} reveal height too early",
                self.auction_id
            ));
        }
        if self.expires_height <= self.created_height {
            return Err(format!("auction {} expiration too early", self.auction_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "auction {} privacy set below floor",
                self.auction_id
            ));
        }
        let lane = lanes
            .get(&self.lane_id)
            .ok_or_else(|| format!("auction {} references missing lane", self.auction_id))?;
        if self.max_fee_units > lane.max_fee_units {
            return Err(format!("auction {} exceeds lane max fee", self.auction_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "lane_id": self.lane_id,
            "intent_commitment": self.intent_commitment,
            "privacy_group_root": self.privacy_group_root,
            "solver_set_root": self.solver_set_root,
            "nullifier_root": self.nullifier_root,
            "created_height": self.created_height,
            "reveal_height": self.reveal_height,
            "expires_height": self.expires_height,
            "max_fee_units": self.max_fee_units,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBondCommitment {
    pub bond_id: String,
    pub solver_commitment: String,
    pub lane_ids: BTreeSet<String>,
    pub pq_key_root: String,
    pub bond_units: u64,
    pub locked_units: u64,
    pub status: SolverBondStatus,
}

impl SolverBondCommitment {
    pub fn devnet(
        solver_label: &str,
        lane_ids: &[String],
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> Self {
        let solver_commitment = piag_string_root("SOLVER-COMMITMENT", solver_label);
        let lane_set = lane_ids.iter().cloned().collect::<BTreeSet<_>>();
        let pq_key_root = piag_string_root("SOLVER-PQ-KEY", solver_label);
        let bond_id = solver_bond_id(&solver_commitment, &pq_key_root);
        Self {
            bond_id,
            solver_commitment,
            lane_ids: lane_set,
            pq_key_root,
            bond_units: config.min_solver_bond_units.saturating_mul(2),
            locked_units: config.min_solver_bond_units / 2,
            status: SolverBondStatus::Active,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.bond_units.saturating_sub(self.locked_units)
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, PrivateIntentAuctionLane>,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        ensure_nonempty("bond id", &self.bond_id)?;
        ensure_nonempty("solver commitment", &self.solver_commitment)?;
        ensure_nonempty("PQ key root", &self.pq_key_root)?;
        ensure_positive("bond units", self.bond_units)?;
        if self.bond_units < config.min_solver_bond_units {
            return Err(format!("solver bond {} below minimum", self.bond_id));
        }
        if self.locked_units > self.bond_units {
            return Err(format!(
                "solver bond {} locks more than posted",
                self.bond_id
            ));
        }
        if self.lane_ids.is_empty() {
            return Err(format!("solver bond {} has no lanes", self.bond_id));
        }
        for lane_id in &self.lane_ids {
            if !lanes.contains_key(lane_id) {
                return Err(format!(
                    "solver bond {} references missing lane {}",
                    self.bond_id, lane_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bond_id": self.bond_id,
            "solver_commitment": self.solver_commitment,
            "lane_ids": self.lane_ids.iter().cloned().collect::<Vec<_>>(),
            "pq_key_root": self.pq_key_root,
            "bond_units": self.bond_units,
            "locked_units": self.locked_units,
            "available_units": self.available_units(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeIntentSponsorship {
    pub sponsorship_id: String,
    pub auction_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub rebate_bps: u64,
    pub expires_height: u64,
}

impl LowFeeIntentSponsorship {
    pub fn devnet(
        auction: &SealedIntentAuction,
        sponsor_label: &str,
        height: u64,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> Self {
        let sponsor_commitment = piag_string_root("INTENT-FEE-SPONSOR", sponsor_label);
        let sponsorship_id = sponsorship_id(&auction.auction_id, &sponsor_commitment);
        Self {
            sponsorship_id,
            auction_id: auction.auction_id.clone(),
            sponsor_commitment,
            fee_asset_id: "wxmr-devnet".to_string(),
            max_fee_units: auction.max_fee_units,
            rebate_bps: config.max_rebate_bps.min(5_000),
            expires_height: height.saturating_add(config.receipt_ttl_blocks),
        }
    }

    pub fn validate(
        &self,
        auctions: &BTreeMap<String, SealedIntentAuction>,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        ensure_nonempty("sponsorship id", &self.sponsorship_id)?;
        ensure_nonempty("auction id", &self.auction_id)?;
        ensure_nonempty("sponsor commitment", &self.sponsor_commitment)?;
        ensure_nonempty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("sponsor max fee units", self.max_fee_units)?;
        ensure_bps("sponsor rebate bps", self.rebate_bps)?;
        if self.rebate_bps > config.max_rebate_bps {
            return Err(format!(
                "sponsorship {} exceeds rebate cap",
                self.sponsorship_id
            ));
        }
        let auction = auctions.get(&self.auction_id).ok_or_else(|| {
            format!(
                "sponsorship {} references missing auction",
                self.sponsorship_id
            )
        })?;
        if self.max_fee_units > auction.max_fee_units {
            return Err(format!(
                "sponsorship {} exceeds auction fee",
                self.sponsorship_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "auction_id": self.auction_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "rebate_bps": self.rebate_bps,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySettlementReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub solver_bond_id: String,
    pub settlement_root: String,
    pub filled_amount_commitment: String,
    pub fee_units: u64,
    pub builder_edge_bps: u64,
    pub inclusion_height: u64,
    pub finality_height: u64,
}

impl PrivacySettlementReceipt {
    pub fn devnet(
        auction: &SealedIntentAuction,
        solver: &SolverBondCommitment,
        height: u64,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> Self {
        let settlement_root = piag_hash(
            "SETTLEMENT",
            &[
                HashPart::Str(&auction.auction_id),
                HashPart::Str(&solver.bond_id),
                HashPart::Int(height as i128),
            ],
        );
        let filled_amount_commitment = piag_string_root("FILLED-AMOUNT", &settlement_root);
        let receipt_id = settlement_receipt_id(&auction.auction_id, &settlement_root, height);
        Self {
            receipt_id,
            auction_id: auction.auction_id.clone(),
            solver_bond_id: solver.bond_id.clone(),
            settlement_root,
            filled_amount_commitment,
            fee_units: auction.max_fee_units.min(config.default_max_fee_units),
            builder_edge_bps: config.max_builder_edge_bps / 2,
            inclusion_height: height,
            finality_height: height.saturating_add(2),
        }
    }

    pub fn validate(
        &self,
        auctions: &BTreeMap<String, SealedIntentAuction>,
        solvers: &BTreeMap<String, SolverBondCommitment>,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        ensure_nonempty("receipt id", &self.receipt_id)?;
        ensure_nonempty("auction id", &self.auction_id)?;
        ensure_nonempty("solver bond id", &self.solver_bond_id)?;
        ensure_nonempty("settlement root", &self.settlement_root)?;
        ensure_nonempty("filled amount commitment", &self.filled_amount_commitment)?;
        ensure_positive("receipt fee units", self.fee_units)?;
        ensure_bps("builder edge bps", self.builder_edge_bps)?;
        if self.builder_edge_bps > config.max_builder_edge_bps {
            return Err(format!(
                "receipt {} exceeds builder edge cap",
                self.receipt_id
            ));
        }
        if self.finality_height < self.inclusion_height {
            return Err(format!(
                "receipt {} finality precedes inclusion",
                self.receipt_id
            ));
        }
        if !auctions.contains_key(&self.auction_id) {
            return Err(format!(
                "receipt {} references missing auction",
                self.receipt_id
            ));
        }
        if !solvers.contains_key(&self.solver_bond_id) {
            return Err(format!(
                "receipt {} references missing solver",
                self.receipt_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "auction_id": self.auction_id,
            "solver_bond_id": self.solver_bond_id,
            "settlement_root": self.settlement_root,
            "filled_amount_commitment": self.filled_amount_commitment,
            "fee_units": self.fee_units,
            "builder_edge_bps": self.builder_edge_bps,
            "inclusion_height": self.inclusion_height,
            "finality_height": self.finality_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyAuctionChallenge {
    pub challenge_id: String,
    pub auction_id: String,
    pub target_receipt_id: Option<String>,
    pub challenger_commitment: String,
    pub challenge_kind: PrivacyAuctionChallengeKind,
    pub evidence_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: PrivacyAuctionChallengeStatus,
}

impl PrivacyAuctionChallenge {
    pub fn devnet(
        auction: &SealedIntentAuction,
        receipt: Option<&PrivacySettlementReceipt>,
        challenge_kind: PrivacyAuctionChallengeKind,
        height: u64,
        config: &PrivateIntentPrivacyAuctionGuardConfig,
    ) -> Self {
        let target_receipt_id = receipt.map(|item| item.receipt_id.clone());
        let challenger_commitment = piag_string_root("CHALLENGER", &auction.auction_id);
        let evidence_root = piag_hash(
            "CHALLENGE-EVIDENCE",
            &[
                HashPart::Str(&auction.auction_id),
                HashPart::Str(challenge_kind.as_str()),
                HashPart::Int(height as i128),
            ],
        );
        let challenge_id = challenge_id(&auction.auction_id, challenge_kind, height);
        Self {
            challenge_id,
            auction_id: auction.auction_id.clone(),
            target_receipt_id,
            challenger_commitment,
            challenge_kind,
            evidence_root,
            opened_height: height,
            expires_height: height.saturating_add(config.challenge_window_blocks),
            status: PrivacyAuctionChallengeStatus::Open,
        }
    }

    pub fn validate(
        &self,
        auctions: &BTreeMap<String, SealedIntentAuction>,
        receipts: &BTreeMap<String, PrivacySettlementReceipt>,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        ensure_nonempty("challenge id", &self.challenge_id)?;
        ensure_nonempty("auction id", &self.auction_id)?;
        ensure_nonempty("challenger commitment", &self.challenger_commitment)?;
        ensure_nonempty("evidence root", &self.evidence_root)?;
        if self.expires_height <= self.opened_height {
            return Err(format!(
                "challenge {} expiration too early",
                self.challenge_id
            ));
        }
        if !auctions.contains_key(&self.auction_id) {
            return Err(format!(
                "challenge {} references missing auction",
                self.challenge_id
            ));
        }
        if let Some(receipt_id) = &self.target_receipt_id {
            if !receipts.contains_key(receipt_id) {
                return Err(format!(
                    "challenge {} references missing receipt",
                    self.challenge_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "auction_id": self.auction_id,
            "target_receipt_id": self.target_receipt_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.challenge_kind.as_str(),
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentPrivacyAuctionGuardRoots {
    pub config_root: String,
    pub lane_root: String,
    pub auction_root: String,
    pub solver_bond_root: String,
    pub sponsorship_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
    pub consumed_nullifier_root: String,
}

impl PrivateIntentPrivacyAuctionGuardRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "auction_root": self.auction_root,
            "solver_bond_root": self.solver_bond_root,
            "sponsorship_root": self.sponsorship_root,
            "receipt_root": self.receipt_root,
            "challenge_root": self.challenge_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentPrivacyAuctionGuardCounters {
    pub lane_count: u64,
    pub enabled_lane_count: u64,
    pub auction_count: u64,
    pub live_auction_count: u64,
    pub solver_bond_count: u64,
    pub usable_solver_bond_count: u64,
    pub sponsorship_count: u64,
    pub receipt_count: u64,
    pub challenge_count: u64,
    pub live_challenge_count: u64,
    pub total_solver_bond_units: u64,
    pub total_fee_units: u64,
}

impl PrivateIntentPrivacyAuctionGuardCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "enabled_lane_count": self.enabled_lane_count,
            "auction_count": self.auction_count,
            "live_auction_count": self.live_auction_count,
            "solver_bond_count": self.solver_bond_count,
            "usable_solver_bond_count": self.usable_solver_bond_count,
            "sponsorship_count": self.sponsorship_count,
            "receipt_count": self.receipt_count,
            "challenge_count": self.challenge_count,
            "live_challenge_count": self.live_challenge_count,
            "total_solver_bond_units": self.total_solver_bond_units,
            "total_fee_units": self.total_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentPrivacyAuctionGuardState {
    pub config: PrivateIntentPrivacyAuctionGuardConfig,
    pub current_height: u64,
    pub current_epoch: u64,
    pub lanes: BTreeMap<String, PrivateIntentAuctionLane>,
    pub auctions: BTreeMap<String, SealedIntentAuction>,
    pub solver_bonds: BTreeMap<String, SolverBondCommitment>,
    pub sponsorships: BTreeMap<String, LowFeeIntentSponsorship>,
    pub receipts: BTreeMap<String, PrivacySettlementReceipt>,
    pub challenges: BTreeMap<String, PrivacyAuctionChallenge>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl PrivateIntentPrivacyAuctionGuardState {
    pub fn devnet() -> PrivateIntentPrivacyAuctionGuardResult<Self> {
        let config = PrivateIntentPrivacyAuctionGuardConfig::devnet();
        let current_height = PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_DEVNET_HEIGHT;
        let current_epoch = current_height / config.epoch_blocks;
        let mut state = Self {
            config,
            current_height,
            current_epoch,
            lanes: BTreeMap::new(),
            auctions: BTreeMap::new(),
            solver_bonds: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        for lane_kind in [
            PrivateIntentLaneKind::Swap,
            PrivateIntentLaneKind::BridgeExit,
            PrivateIntentLaneKind::Liquidation,
            PrivateIntentLaneKind::VaultRebalance,
            PrivateIntentLaneKind::ContractCall,
            PrivateIntentLaneKind::Recovery,
        ] {
            state.insert_lane(PrivateIntentAuctionLane::devnet(lane_kind, &state.config))?;
        }
        let lane_ids = state.lanes.keys().cloned().collect::<Vec<_>>();
        let solver =
            SolverBondCommitment::devnet("solver:privacy-auction:devnet", &lane_ids, &state.config);
        state.insert_solver_bond(solver.clone())?;
        let lane = state
            .lanes
            .values()
            .find(|lane| lane.lane_kind == PrivateIntentLaneKind::Swap)
            .cloned()
            .ok_or_else(|| "missing devnet private swap lane".to_string())?;
        let mut auction = SealedIntentAuction::devnet(
            "auction:private-swap:devnet",
            &lane,
            current_height,
            &state.config,
        );
        auction.status = AuctionGuardStatus::Matched;
        state.insert_auction(auction.clone())?;
        let sponsorship = LowFeeIntentSponsorship::devnet(
            &auction,
            "sponsor:private-intent:devnet",
            current_height,
            &state.config,
        );
        state.insert_sponsorship(sponsorship)?;
        let receipt = PrivacySettlementReceipt::devnet(
            &auction,
            &solver,
            current_height.saturating_add(2),
            &state.config,
        );
        state.insert_receipt(receipt.clone())?;
        state.insert_challenge(PrivacyAuctionChallenge::devnet(
            &auction,
            Some(&receipt),
            PrivacyAuctionChallengeKind::FeeOvercharge,
            current_height.saturating_add(3),
            &state.config,
        ))?;
        state.consumed_nullifiers.insert(piag_hash(
            "CONSUMED-NULLIFIER",
            &[
                HashPart::Str(&auction.auction_id),
                HashPart::Str(&receipt.receipt_id),
            ],
        ));
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        if height < self.current_height {
            return Err(format!(
                "private intent privacy auction guard height cannot move backward from {} to {}",
                self.current_height, height
            ));
        }
        self.current_height = height;
        if self.config.epoch_blocks > 0 {
            self.current_epoch = height / self.config.epoch_blocks;
        }
        for auction in self.auctions.values_mut() {
            if auction.status.live() && height > auction.expires_height {
                auction.status = AuctionGuardStatus::Expired;
            } else if auction.status == AuctionGuardStatus::Open && height >= auction.reveal_height
            {
                auction.status = AuctionGuardStatus::Reveal;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status.live() && height > challenge.expires_height {
                challenge.status = PrivacyAuctionChallengeStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn insert_lane(
        &mut self,
        lane: PrivateIntentAuctionLane,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        lane.validate(&self.config)?;
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_auction(
        &mut self,
        auction: SealedIntentAuction,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        auction.validate(&self.lanes, &self.config)?;
        self.auctions.insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_solver_bond(
        &mut self,
        solver: SolverBondCommitment,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        solver.validate(&self.lanes, &self.config)?;
        self.solver_bonds.insert(solver.bond_id.clone(), solver);
        Ok(())
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeIntentSponsorship,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        sponsorship.validate(&self.auctions, &self.config)?;
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: PrivacySettlementReceipt,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        receipt.validate(&self.auctions, &self.solver_bonds, &self.config)?;
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: PrivacyAuctionChallenge,
    ) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        challenge.validate(&self.auctions, &self.receipts)?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn live_auction_ids(&self) -> Vec<String> {
        self.auctions
            .values()
            .filter(|auction| auction.status.live())
            .map(|auction| auction.auction_id.clone())
            .collect()
    }

    pub fn enabled_lane_ids(&self) -> Vec<String> {
        self.lanes
            .values()
            .filter(|lane| lane.accepts_intents())
            .map(|lane| lane.lane_id.clone())
            .collect()
    }

    pub fn roots(&self) -> PrivateIntentPrivacyAuctionGuardRoots {
        PrivateIntentPrivacyAuctionGuardRoots {
            config_root: piag_payload_root("CONFIG", &self.config.public_record()),
            lane_root: map_root(
                "LANES",
                &self.lanes,
                PrivateIntentAuctionLane::public_record,
            ),
            auction_root: map_root(
                "AUCTIONS",
                &self.auctions,
                SealedIntentAuction::public_record,
            ),
            solver_bond_root: map_root(
                "SOLVER-BONDS",
                &self.solver_bonds,
                SolverBondCommitment::public_record,
            ),
            sponsorship_root: map_root(
                "SPONSORSHIPS",
                &self.sponsorships,
                LowFeeIntentSponsorship::public_record,
            ),
            receipt_root: map_root(
                "RECEIPTS",
                &self.receipts,
                PrivacySettlementReceipt::public_record,
            ),
            challenge_root: map_root(
                "CHALLENGES",
                &self.challenges,
                PrivacyAuctionChallenge::public_record,
            ),
            consumed_nullifier_root: string_set_root(
                "CONSUMED-NULLIFIERS",
                &self.consumed_nullifiers,
            ),
        }
    }

    pub fn counters(&self) -> PrivateIntentPrivacyAuctionGuardCounters {
        PrivateIntentPrivacyAuctionGuardCounters {
            lane_count: self.lanes.len() as u64,
            enabled_lane_count: self
                .lanes
                .values()
                .filter(|lane| lane.accepts_intents())
                .count() as u64,
            auction_count: self.auctions.len() as u64,
            live_auction_count: self
                .auctions
                .values()
                .filter(|item| item.status.live())
                .count() as u64,
            solver_bond_count: self.solver_bonds.len() as u64,
            usable_solver_bond_count: self
                .solver_bonds
                .values()
                .filter(|solver| solver.status.usable())
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            receipt_count: self.receipts.len() as u64,
            challenge_count: self.challenges.len() as u64,
            live_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.status.live())
                .count() as u64,
            total_solver_bond_units: self
                .solver_bonds
                .values()
                .map(|solver| solver.bond_units)
                .sum(),
            total_fee_units: self
                .receipts
                .values()
                .map(|receipt| receipt.fee_units)
                .sum(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_intent_privacy_auction_guard_state",
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        private_intent_privacy_auction_guard_state_root_from_record(
            &self.public_record_without_root(),
        )
    }

    pub fn validate(&self) -> PrivateIntentPrivacyAuctionGuardResult<()> {
        self.config.validate()?;
        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
        }
        for solver in self.solver_bonds.values() {
            solver.validate(&self.lanes, &self.config)?;
        }
        for auction in self.auctions.values() {
            auction.validate(&self.lanes, &self.config)?;
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate(&self.auctions, &self.config)?;
        }
        for receipt in self.receipts.values() {
            receipt.validate(&self.auctions, &self.solver_bonds, &self.config)?;
        }
        for challenge in self.challenges.values() {
            challenge.validate(&self.auctions, &self.receipts)?;
        }
        Ok(())
    }
}

pub fn private_intent_privacy_auction_guard_state_root_from_record(record: &Value) -> String {
    piag_payload_root("STATE", record)
}

pub fn private_intent_lane_id(lane_kind: PrivateIntentLaneKind, epoch_label: &str) -> String {
    piag_hash(
        "LANE-ID",
        &[
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(epoch_label),
        ],
    )
}

pub fn private_intent_auction_id(intent_commitment: &str, created_height: u64) -> String {
    piag_hash(
        "AUCTION-ID",
        &[
            HashPart::Str(intent_commitment),
            HashPart::Int(created_height as i128),
        ],
    )
}

pub fn solver_bond_id(solver_commitment: &str, pq_key_root: &str) -> String {
    piag_hash(
        "SOLVER-BOND-ID",
        &[HashPart::Str(solver_commitment), HashPart::Str(pq_key_root)],
    )
}

pub fn sponsorship_id(auction_id: &str, sponsor_commitment: &str) -> String {
    piag_hash(
        "SPONSORSHIP-ID",
        &[HashPart::Str(auction_id), HashPart::Str(sponsor_commitment)],
    )
}

pub fn settlement_receipt_id(auction_id: &str, settlement_root: &str, height: u64) -> String {
    piag_hash(
        "SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(settlement_root),
            HashPart::Int(height as i128),
        ],
    )
}

pub fn challenge_id(
    auction_id: &str,
    challenge_kind: PrivacyAuctionChallengeKind,
    height: u64,
) -> String {
    piag_hash(
        "CHALLENGE-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Int(height as i128),
        ],
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, value)| json!({"id": id, "record": record(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-INTENT-PRIVACY-AUCTION-GUARD-{domain}"),
        &leaves,
    )
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-INTENT-PRIVACY-AUCTION-GUARD-{domain}"),
        &leaves,
    )
}

fn piag_payload_root(domain: &str, payload: &Value) -> String {
    piag_hash(domain, &[HashPart::Json(payload)])
}

fn piag_string_root(domain: &str, value: &str) -> String {
    piag_hash(domain, &[HashPart::Str(value)])
}

fn piag_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-INTENT-PRIVACY-AUCTION-GUARD-{domain}"),
        parts,
        32,
    )
}

fn ensure_nonempty(label: &str, value: &str) -> PrivateIntentPrivacyAuctionGuardResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> PrivateIntentPrivacyAuctionGuardResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> PrivateIntentPrivacyAuctionGuardResult<()> {
    if value > PRIVATE_INTENT_PRIVACY_AUCTION_GUARD_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}
