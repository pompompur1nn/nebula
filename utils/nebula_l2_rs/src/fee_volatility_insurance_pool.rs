use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type FeeVolatilityInsurancePoolResult<T> = Result<T, String>;

pub const FEE_VOLATILITY_INSURANCE_POOL_PROTOCOL_VERSION: u32 = 1;
pub const FEE_VOLATILITY_INSURANCE_POOL_PROTOCOL_LABEL: &str =
    "nebula-fee-volatility-insurance-pool-v1";
pub const FEE_VOLATILITY_INSURANCE_POOL_SCHEMA_VERSION: u64 = 1;
pub const FEE_VOLATILITY_INSURANCE_POOL_DEVNET_HEIGHT: u64 = 1_536;
pub const FEE_VOLATILITY_INSURANCE_POOL_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const FEE_VOLATILITY_INSURANCE_POOL_PQ_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-128f-fee-insurance";
pub const FEE_VOLATILITY_INSURANCE_POOL_RESERVE_PROOF_SUITE: &str =
    "monero-view-key-reserve-proof+zk-spend-cap-v1";
pub const FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_CLAIM_WINDOW_BLOCKS: u64 = 96;
pub const FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_REBALANCE_WINDOW_BLOCKS: u64 = 24;
pub const FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_MIN_RESERVE_UNITS: u64 = 75_000;
pub const FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_MAX_COVERAGE_BPS: u64 = 8_500;
pub const FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_TARGET_SOLVENCY_BPS: u64 = 12_500;
pub const FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_000;
pub const FEE_VOLATILITY_INSURANCE_POOL_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeInsuranceLane {
    PrivateTransfer,
    MoneroExit,
    ContractCall,
    ProofJob,
    OracleUpdate,
    BridgeRelease,
    Emergency,
}

impl FeeInsuranceLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroExit => "monero_exit",
            Self::ContractCall => "contract_call",
            Self::ProofJob => "proof_job",
            Self::OracleUpdate => "oracle_update",
            Self::BridgeRelease => "bridge_release",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 100,
            Self::BridgeRelease => 92,
            Self::MoneroExit => 88,
            Self::ContractCall => 80,
            Self::ProofJob => 74,
            Self::OracleUpdate => 68,
            Self::PrivateTransfer => 62,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Quoted,
    Active,
    CoolingDown,
    Claimed,
    Expired,
    Cancelled,
}

impl CoverageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Quoted | Self::Active | Self::CoolingDown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Open,
    Attested,
    Approved,
    Paid,
    Challenged,
    Rejected,
    Expired,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attested => "attested",
            Self::Approved => "approved",
            Self::Paid => "paid",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Attested | Self::Approved | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveStatus {
    Active,
    Rebalancing,
    Guarded,
    Draining,
    Paused,
}

impl ReserveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rebalancing => "rebalancing",
            Self::Guarded => "guarded",
            Self::Draining => "draining",
            Self::Paused => "paused",
        }
    }

    pub fn can_underwrite(self) -> bool {
        matches!(self, Self::Active | Self::Rebalancing | Self::Guarded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeVolatilityInsurancePoolConfig {
    pub epoch_blocks: u64,
    pub claim_window_blocks: u64,
    pub rebalance_window_blocks: u64,
    pub min_reserve_units: u64,
    pub max_coverage_bps: u64,
    pub target_solvency_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub pq_auth_suite: String,
    pub reserve_proof_suite: String,
    pub hash_suite: String,
}

impl FeeVolatilityInsurancePoolConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_EPOCH_BLOCKS,
            claim_window_blocks: FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_CLAIM_WINDOW_BLOCKS,
            rebalance_window_blocks: FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_REBALANCE_WINDOW_BLOCKS,
            min_reserve_units: FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_MIN_RESERVE_UNITS,
            max_coverage_bps: FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_MAX_COVERAGE_BPS,
            target_solvency_bps: FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_TARGET_SOLVENCY_BPS,
            low_fee_rebate_bps: FEE_VOLATILITY_INSURANCE_POOL_DEFAULT_LOW_FEE_REBATE_BPS,
            pq_auth_suite: FEE_VOLATILITY_INSURANCE_POOL_PQ_AUTH_SUITE.to_string(),
            reserve_proof_suite: FEE_VOLATILITY_INSURANCE_POOL_RESERVE_PROOF_SUITE.to_string(),
            hash_suite: FEE_VOLATILITY_INSURANCE_POOL_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "claim_window_blocks": self.claim_window_blocks,
            "rebalance_window_blocks": self.rebalance_window_blocks,
            "min_reserve_units": self.min_reserve_units,
            "max_coverage_bps": self.max_coverage_bps,
            "target_solvency_bps": self.target_solvency_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "pq_auth_suite": self.pq_auth_suite,
            "reserve_proof_suite": self.reserve_proof_suite,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn config_root(&self) -> String {
        fee_insurance_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> FeeVolatilityInsurancePoolResult<()> {
        if self.epoch_blocks == 0
            || self.claim_window_blocks == 0
            || self.rebalance_window_blocks == 0
            || self.min_reserve_units == 0
        {
            return Err("fee insurance windows and reserves must be positive".to_string());
        }
        if self.max_coverage_bps > FEE_VOLATILITY_INSURANCE_POOL_MAX_BPS
            || self.low_fee_rebate_bps > FEE_VOLATILITY_INSURANCE_POOL_MAX_BPS
        {
            return Err("fee insurance bps value exceeds max".to_string());
        }
        if self.target_solvency_bps < FEE_VOLATILITY_INSURANCE_POOL_MAX_BPS {
            return Err("fee insurance target solvency must exceed full coverage".to_string());
        }
        if self.pq_auth_suite.is_empty()
            || self.reserve_proof_suite.is_empty()
            || self.hash_suite.is_empty()
        {
            return Err("fee insurance crypto suite labels must be populated".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeInsuranceReserve {
    pub reserve_id: String,
    pub custodian_commitment: String,
    pub asset_id: String,
    pub status: ReserveStatus,
    pub available_units: u64,
    pub reserved_units: u64,
    pub claim_liability_units: u64,
    pub reserve_proof_root: String,
    pub pq_attestation_root: String,
    pub last_rebalance_height: u64,
    pub public_metadata_root: String,
}

impl FeeInsuranceReserve {
    pub fn new(
        reserve_id: &str,
        custodian_commitment: &str,
        asset_id: &str,
        available_units: u64,
        height: u64,
    ) -> FeeVolatilityInsurancePoolResult<Self> {
        if reserve_id.is_empty() || custodian_commitment.is_empty() || asset_id.is_empty() {
            return Err("fee insurance reserve identifiers must be populated".to_string());
        }
        if available_units == 0 {
            return Err("fee insurance reserve must have available units".to_string());
        }
        let reserve_proof_root = fee_insurance_hash(
            "RESERVE-PROOF",
            &[
                HashPart::Str(reserve_id),
                HashPart::Str(custodian_commitment),
                HashPart::Str(asset_id),
                HashPart::Int(available_units as i128),
                HashPart::Int(height as i128),
            ],
        );
        let pq_attestation_root = fee_insurance_hash(
            "RESERVE-PQ-ATTESTATION",
            &[
                HashPart::Str(reserve_id),
                HashPart::Str(&reserve_proof_root),
            ],
        );
        let public_metadata_root = fee_insurance_hash(
            "RESERVE-METADATA",
            &[HashPart::Str(reserve_id), HashPart::Str(asset_id)],
        );
        Ok(Self {
            reserve_id: reserve_id.to_string(),
            custodian_commitment: custodian_commitment.to_string(),
            asset_id: asset_id.to_string(),
            status: ReserveStatus::Active,
            available_units,
            reserved_units: 0,
            claim_liability_units: 0,
            reserve_proof_root,
            pq_attestation_root,
            last_rebalance_height: height,
            public_metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "custodian_commitment": self.custodian_commitment,
            "asset_id": self.asset_id,
            "status": self.status.as_str(),
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "claim_liability_units": self.claim_liability_units,
            "reserve_proof_root": self.reserve_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "last_rebalance_height": self.last_rebalance_height,
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn root(&self) -> String {
        fee_insurance_hash("RESERVE", &[HashPart::Json(&self.public_record())])
    }

    pub fn solvency_units(&self) -> u64 {
        self.available_units
            .saturating_add(self.reserved_units)
            .saturating_sub(self.claim_liability_units)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCoveragePolicy {
    pub policy_id: String,
    pub lane: FeeInsuranceLane,
    pub buyer_commitment: String,
    pub covered_fee_units: u64,
    pub premium_units: u64,
    pub max_payout_units: u64,
    pub baseline_fee_quote_units: u64,
    pub trigger_fee_quote_units: u64,
    pub start_height: u64,
    pub expiry_height: u64,
    pub status: CoverageStatus,
    pub reserve_id: String,
    pub low_fee_sponsor_ticket_root: String,
    pub disclosure_policy_root: String,
}

impl FeeCoveragePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: &str,
        lane: FeeInsuranceLane,
        buyer_commitment: &str,
        covered_fee_units: u64,
        premium_units: u64,
        max_payout_units: u64,
        baseline_fee_quote_units: u64,
        trigger_fee_quote_units: u64,
        start_height: u64,
        expiry_height: u64,
        reserve_id: &str,
    ) -> FeeVolatilityInsurancePoolResult<Self> {
        if policy_id.is_empty() || buyer_commitment.is_empty() || reserve_id.is_empty() {
            return Err("fee coverage policy identifiers must be populated".to_string());
        }
        if covered_fee_units == 0 || max_payout_units == 0 || trigger_fee_quote_units == 0 {
            return Err("fee coverage policy amounts must be positive".to_string());
        }
        if expiry_height <= start_height {
            return Err("fee coverage policy expiry must be after start".to_string());
        }
        if trigger_fee_quote_units <= baseline_fee_quote_units {
            return Err("fee coverage policy trigger must exceed baseline".to_string());
        }
        let low_fee_sponsor_ticket_root = fee_insurance_hash(
            "LOW-FEE-SPONSOR-TICKET",
            &[
                HashPart::Str(policy_id),
                HashPart::Str(lane.as_str()),
                HashPart::Int(premium_units as i128),
                HashPart::Int(start_height as i128),
            ],
        );
        let disclosure_policy_root = fee_insurance_hash(
            "DISCLOSURE-POLICY",
            &[
                HashPart::Str(policy_id),
                HashPart::Str(buyer_commitment),
                HashPart::Str("roots_only"),
            ],
        );
        Ok(Self {
            policy_id: policy_id.to_string(),
            lane,
            buyer_commitment: buyer_commitment.to_string(),
            covered_fee_units,
            premium_units,
            max_payout_units,
            baseline_fee_quote_units,
            trigger_fee_quote_units,
            start_height,
            expiry_height,
            status: CoverageStatus::Active,
            reserve_id: reserve_id.to_string(),
            low_fee_sponsor_ticket_root,
            disclosure_policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "lane": self.lane.as_str(),
            "buyer_commitment": self.buyer_commitment,
            "covered_fee_units": self.covered_fee_units,
            "premium_units": self.premium_units,
            "max_payout_units": self.max_payout_units,
            "baseline_fee_quote_units": self.baseline_fee_quote_units,
            "trigger_fee_quote_units": self.trigger_fee_quote_units,
            "start_height": self.start_height,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
            "reserve_id": self.reserve_id,
            "low_fee_sponsor_ticket_root": self.low_fee_sponsor_ticket_root,
            "disclosure_policy_root": self.disclosure_policy_root,
        })
    }

    pub fn root(&self) -> String {
        fee_insurance_hash("POLICY", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && height <= self.expiry_height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeInsuranceClaim {
    pub claim_id: String,
    pub policy_id: String,
    pub observed_fee_quote_units: u64,
    pub claimed_units: u64,
    pub status: ClaimStatus,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub fee_oracle_attestation_root: String,
    pub pq_claim_signature_root: String,
    pub payout_commitment_root: String,
}

impl FeeInsuranceClaim {
    pub fn new(
        claim_id: &str,
        policy: &FeeCoveragePolicy,
        observed_fee_quote_units: u64,
        opened_height: u64,
        claim_window_blocks: u64,
    ) -> FeeVolatilityInsurancePoolResult<Self> {
        if claim_id.is_empty() {
            return Err("fee insurance claim id must be populated".to_string());
        }
        if observed_fee_quote_units <= policy.trigger_fee_quote_units {
            return Err("fee insurance claim does not exceed trigger quote".to_string());
        }
        let delta = observed_fee_quote_units.saturating_sub(policy.baseline_fee_quote_units);
        let claimed_units = delta.min(policy.max_payout_units);
        if claimed_units == 0 {
            return Err("fee insurance claim payout is zero".to_string());
        }
        let fee_oracle_attestation_root = fee_insurance_hash(
            "CLAIM-ORACLE-ATTESTATION",
            &[
                HashPart::Str(claim_id),
                HashPart::Str(&policy.policy_id),
                HashPart::Int(observed_fee_quote_units as i128),
                HashPart::Int(opened_height as i128),
            ],
        );
        let pq_claim_signature_root = fee_insurance_hash(
            "CLAIM-PQ-SIGNATURE",
            &[
                HashPart::Str(claim_id),
                HashPart::Str(&fee_oracle_attestation_root),
            ],
        );
        let payout_commitment_root = fee_insurance_hash(
            "CLAIM-PAYOUT-COMMITMENT",
            &[
                HashPart::Str(claim_id),
                HashPart::Str(&policy.buyer_commitment),
                HashPart::Int(claimed_units as i128),
            ],
        );
        Ok(Self {
            claim_id: claim_id.to_string(),
            policy_id: policy.policy_id.clone(),
            observed_fee_quote_units,
            claimed_units,
            status: ClaimStatus::Open,
            opened_height,
            deadline_height: opened_height.saturating_add(claim_window_blocks),
            fee_oracle_attestation_root,
            pq_claim_signature_root,
            payout_commitment_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "observed_fee_quote_units": self.observed_fee_quote_units,
            "claimed_units": self.claimed_units,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "deadline_height": self.deadline_height,
            "fee_oracle_attestation_root": self.fee_oracle_attestation_root,
            "pq_claim_signature_root": self.pq_claim_signature_root,
            "payout_commitment_root": self.payout_commitment_root,
        })
    }

    pub fn root(&self) -> String {
        fee_insurance_hash("CLAIM", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeInsuranceRebalance {
    pub rebalance_id: String,
    pub reserve_id: String,
    pub target_lane: FeeInsuranceLane,
    pub transfer_units: u64,
    pub source_commitment_root: String,
    pub destination_commitment_root: String,
    pub pq_authorization_root: String,
    pub height: u64,
}

impl FeeInsuranceRebalance {
    pub fn new(
        rebalance_id: &str,
        reserve_id: &str,
        target_lane: FeeInsuranceLane,
        transfer_units: u64,
        height: u64,
    ) -> FeeVolatilityInsurancePoolResult<Self> {
        if rebalance_id.is_empty() || reserve_id.is_empty() {
            return Err("fee insurance rebalance identifiers must be populated".to_string());
        }
        if transfer_units == 0 {
            return Err("fee insurance rebalance transfer must be positive".to_string());
        }
        let source_commitment_root = fee_insurance_hash(
            "REBALANCE-SOURCE",
            &[HashPart::Str(rebalance_id), HashPart::Str(reserve_id)],
        );
        let destination_commitment_root = fee_insurance_hash(
            "REBALANCE-DESTINATION",
            &[
                HashPart::Str(rebalance_id),
                HashPart::Str(target_lane.as_str()),
                HashPart::Int(transfer_units as i128),
            ],
        );
        let pq_authorization_root = fee_insurance_hash(
            "REBALANCE-PQ-AUTHORIZATION",
            &[
                HashPart::Str(rebalance_id),
                HashPart::Str(&source_commitment_root),
                HashPart::Str(&destination_commitment_root),
            ],
        );
        Ok(Self {
            rebalance_id: rebalance_id.to_string(),
            reserve_id: reserve_id.to_string(),
            target_lane,
            transfer_units,
            source_commitment_root,
            destination_commitment_root,
            pq_authorization_root,
            height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebalance_id": self.rebalance_id,
            "reserve_id": self.reserve_id,
            "target_lane": self.target_lane.as_str(),
            "transfer_units": self.transfer_units,
            "source_commitment_root": self.source_commitment_root,
            "destination_commitment_root": self.destination_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "height": self.height,
        })
    }

    pub fn root(&self) -> String {
        fee_insurance_hash("REBALANCE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeVolatilityInsurancePoolRoots {
    pub config_root: String,
    pub reserve_root: String,
    pub policy_root: String,
    pub claim_root: String,
    pub rebalance_root: String,
    pub lane_exposure_root: String,
    pub state_root: String,
}

impl FeeVolatilityInsurancePoolRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "reserve_root": self.reserve_root,
            "policy_root": self.policy_root,
            "claim_root": self.claim_root,
            "rebalance_root": self.rebalance_root,
            "lane_exposure_root": self.lane_exposure_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeVolatilityInsurancePoolCounters {
    pub reserve_count: u64,
    pub policy_count: u64,
    pub live_policy_count: u64,
    pub claim_count: u64,
    pub open_claim_count: u64,
    pub rebalance_count: u64,
    pub available_reserve_units: u64,
    pub reserved_policy_units: u64,
    pub open_claim_units: u64,
}

impl FeeVolatilityInsurancePoolCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_count": self.reserve_count,
            "policy_count": self.policy_count,
            "live_policy_count": self.live_policy_count,
            "claim_count": self.claim_count,
            "open_claim_count": self.open_claim_count,
            "rebalance_count": self.rebalance_count,
            "available_reserve_units": self.available_reserve_units,
            "reserved_policy_units": self.reserved_policy_units,
            "open_claim_units": self.open_claim_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeVolatilityInsurancePoolState {
    pub height: u64,
    pub config: FeeVolatilityInsurancePoolConfig,
    pub reserves: BTreeMap<String, FeeInsuranceReserve>,
    pub policies: BTreeMap<String, FeeCoveragePolicy>,
    pub claims: BTreeMap<String, FeeInsuranceClaim>,
    pub rebalances: BTreeMap<String, FeeInsuranceRebalance>,
    pub lane_exposures: BTreeMap<FeeInsuranceLane, u64>,
    pub paused: bool,
}

impl FeeVolatilityInsurancePoolState {
    pub fn devnet() -> FeeVolatilityInsurancePoolResult<Self> {
        let config = FeeVolatilityInsurancePoolConfig::devnet();
        config.validate()?;
        let mut state = Self {
            height: FEE_VOLATILITY_INSURANCE_POOL_DEVNET_HEIGHT,
            config,
            reserves: BTreeMap::new(),
            policies: BTreeMap::new(),
            claims: BTreeMap::new(),
            rebalances: BTreeMap::new(),
            lane_exposures: BTreeMap::new(),
            paused: false,
        };
        let reserve = FeeInsuranceReserve::new(
            "devnet-fee-reserve-a",
            "reserve-custodian-commitment-a",
            "wxmr-devnet",
            525_000,
            state.height,
        )?;
        state.insert_reserve(reserve)?;
        let reserve_b = FeeInsuranceReserve::new(
            "devnet-fee-reserve-b",
            "reserve-custodian-commitment-b",
            "dnr-devnet",
            375_000,
            state.height,
        )?;
        state.insert_reserve(reserve_b)?;
        let policy = FeeCoveragePolicy::new(
            "devnet-contract-call-spike-cover",
            FeeInsuranceLane::ContractCall,
            "buyer-commitment-contract-desk",
            12_500,
            175,
            6_000,
            1_200,
            1_900,
            state.height,
            state.height.saturating_add(288),
            "devnet-fee-reserve-a",
        )?;
        state.insert_policy(policy)?;
        let policy_b = FeeCoveragePolicy::new(
            "devnet-monero-exit-spike-cover",
            FeeInsuranceLane::MoneroExit,
            "buyer-commitment-exit-router",
            20_000,
            240,
            9_500,
            1_500,
            2_250,
            state.height,
            state.height.saturating_add(360),
            "devnet-fee-reserve-b",
        )?;
        state.insert_policy(policy_b)?;
        let rebalance = FeeInsuranceRebalance::new(
            "devnet-rebalance-contract-lane",
            "devnet-fee-reserve-a",
            FeeInsuranceLane::ContractCall,
            22_000,
            state.height,
        )?;
        state.insert_rebalance(rebalance)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> FeeVolatilityInsurancePoolResult<()> {
        if height < self.height {
            return Err("fee insurance height cannot move backwards".to_string());
        }
        self.height = height;
        for policy in self.policies.values_mut() {
            if policy.status.is_live() && height > policy.expiry_height {
                policy.status = CoverageStatus::Expired;
            }
        }
        for claim in self.claims.values_mut() {
            if claim.status.is_open() && height > claim.deadline_height {
                claim.status = ClaimStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn insert_reserve(
        &mut self,
        reserve: FeeInsuranceReserve,
    ) -> FeeVolatilityInsurancePoolResult<()> {
        if self.reserves.contains_key(&reserve.reserve_id) {
            return Err("fee insurance reserve already exists".to_string());
        }
        self.reserves.insert(reserve.reserve_id.clone(), reserve);
        Ok(())
    }

    pub fn insert_policy(
        &mut self,
        policy: FeeCoveragePolicy,
    ) -> FeeVolatilityInsurancePoolResult<()> {
        if self.paused {
            return Err("fee insurance pool is paused".to_string());
        }
        if self.policies.contains_key(&policy.policy_id) {
            return Err("fee insurance policy already exists".to_string());
        }
        let reserve = self
            .reserves
            .get_mut(&policy.reserve_id)
            .ok_or_else(|| "fee insurance policy reserve missing".to_string())?;
        if !reserve.status.can_underwrite() {
            return Err("fee insurance reserve cannot underwrite".to_string());
        }
        if reserve.available_units < policy.max_payout_units {
            return Err("fee insurance reserve has insufficient available units".to_string());
        }
        reserve.available_units = reserve
            .available_units
            .saturating_sub(policy.max_payout_units);
        reserve.reserved_units = reserve
            .reserved_units
            .saturating_add(policy.max_payout_units);
        let lane_exposure = self.lane_exposures.entry(policy.lane).or_insert(0);
        *lane_exposure = lane_exposure.saturating_add(policy.max_payout_units);
        self.policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub fn open_claim(
        &mut self,
        claim_id: &str,
        policy_id: &str,
        observed_fee_quote_units: u64,
    ) -> FeeVolatilityInsurancePoolResult<String> {
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| "fee insurance policy missing".to_string())?;
        if !policy.is_live_at(self.height) {
            return Err("fee insurance policy is not live".to_string());
        }
        let claim = FeeInsuranceClaim::new(
            claim_id,
            policy,
            observed_fee_quote_units,
            self.height,
            self.config.claim_window_blocks,
        )?;
        let claim_root = claim.root();
        self.claims.insert(claim.claim_id.clone(), claim);
        Ok(claim_root)
    }

    pub fn insert_rebalance(
        &mut self,
        rebalance: FeeInsuranceRebalance,
    ) -> FeeVolatilityInsurancePoolResult<()> {
        if self.rebalances.contains_key(&rebalance.rebalance_id) {
            return Err("fee insurance rebalance already exists".to_string());
        }
        let reserve = self
            .reserves
            .get_mut(&rebalance.reserve_id)
            .ok_or_else(|| "fee insurance rebalance reserve missing".to_string())?;
        reserve.last_rebalance_height = rebalance.height;
        reserve.status = ReserveStatus::Rebalancing;
        self.rebalances
            .insert(rebalance.rebalance_id.clone(), rebalance);
        Ok(())
    }

    pub fn active_policy_ids(&self) -> Vec<String> {
        self.policies
            .values()
            .filter(|policy| policy.is_live_at(self.height))
            .map(|policy| policy.policy_id.clone())
            .collect()
    }

    pub fn open_claim_ids(&self) -> Vec<String> {
        self.claims
            .values()
            .filter(|claim| claim.status.is_open())
            .map(|claim| claim.claim_id.clone())
            .collect()
    }

    pub fn available_reserve_units(&self) -> u64 {
        self.reserves
            .values()
            .map(|reserve| reserve.available_units)
            .sum()
    }

    pub fn reserved_policy_units(&self) -> u64 {
        self.reserves
            .values()
            .map(|reserve| reserve.reserved_units)
            .sum()
    }

    pub fn open_claim_units(&self) -> u64 {
        self.claims
            .values()
            .filter(|claim| claim.status.is_open())
            .map(|claim| claim.claimed_units)
            .sum()
    }

    pub fn lane_exposure_map(&self) -> BTreeMap<String, u64> {
        self.lane_exposures
            .iter()
            .map(|(lane, units)| (lane.as_str().to_string(), *units))
            .collect()
    }

    pub fn roots(&self) -> FeeVolatilityInsurancePoolRoots {
        let config_root = self.config.config_root();
        let reserve_records = self
            .reserves
            .values()
            .map(FeeInsuranceReserve::public_record)
            .collect::<Vec<_>>();
        let policy_records = self
            .policies
            .values()
            .map(FeeCoveragePolicy::public_record)
            .collect::<Vec<_>>();
        let claim_records = self
            .claims
            .values()
            .map(FeeInsuranceClaim::public_record)
            .collect::<Vec<_>>();
        let rebalance_records = self
            .rebalances
            .values()
            .map(FeeInsuranceRebalance::public_record)
            .collect::<Vec<_>>();
        let lane_exposure_root = fee_insurance_hash(
            "LANE-EXPOSURE",
            &[HashPart::Json(&json!(self.lane_exposure_map()))],
        );
        let reserve_root = merkle_root("FEE-INSURANCE-RESERVE", &reserve_records);
        let policy_root = merkle_root("FEE-INSURANCE-POLICY", &policy_records);
        let claim_root = merkle_root("FEE-INSURANCE-CLAIM", &claim_records);
        let rebalance_root = merkle_root("FEE-INSURANCE-REBALANCE", &rebalance_records);
        let state_root = fee_insurance_hash(
            "STATE",
            &[
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&reserve_root),
                HashPart::Str(&policy_root),
                HashPart::Str(&claim_root),
                HashPart::Str(&rebalance_root),
                HashPart::Str(&lane_exposure_root),
            ],
        );
        FeeVolatilityInsurancePoolRoots {
            config_root,
            reserve_root,
            policy_root,
            claim_root,
            rebalance_root,
            lane_exposure_root,
            state_root,
        }
    }

    pub fn counters(&self) -> FeeVolatilityInsurancePoolCounters {
        FeeVolatilityInsurancePoolCounters {
            reserve_count: self.reserves.len() as u64,
            policy_count: self.policies.len() as u64,
            live_policy_count: self.active_policy_ids().len() as u64,
            claim_count: self.claims.len() as u64,
            open_claim_count: self.open_claim_ids().len() as u64,
            rebalance_count: self.rebalances.len() as u64,
            available_reserve_units: self.available_reserve_units(),
            reserved_policy_units: self.reserved_policy_units(),
            open_claim_units: self.open_claim_units(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "fee_volatility_insurance_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_VOLATILITY_INSURANCE_POOL_PROTOCOL_VERSION,
            "protocol_label": FEE_VOLATILITY_INSURANCE_POOL_PROTOCOL_LABEL,
            "schema_version": FEE_VOLATILITY_INSURANCE_POOL_SCHEMA_VERSION,
            "height": self.height,
            "paused": self.paused,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "active_policy_ids": self.active_policy_ids(),
            "open_claim_ids": self.open_claim_ids(),
            "lane_exposure_map": self.lane_exposure_map(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> FeeVolatilityInsurancePoolResult<String> {
        self.config.validate()?;
        let mut reserve_ids = BTreeSet::new();
        for reserve in self.reserves.values() {
            if !reserve_ids.insert(reserve.reserve_id.clone()) {
                return Err("duplicate fee insurance reserve id".to_string());
            }
            if reserve.asset_id.is_empty() || reserve.reserve_proof_root.is_empty() {
                return Err("fee insurance reserve record incomplete".to_string());
            }
        }
        for policy in self.policies.values() {
            if !self.reserves.contains_key(&policy.reserve_id) {
                return Err("fee insurance policy references missing reserve".to_string());
            }
            if policy.expiry_height <= policy.start_height {
                return Err("fee insurance policy has invalid height range".to_string());
            }
        }
        for claim in self.claims.values() {
            if !self.policies.contains_key(&claim.policy_id) {
                return Err("fee insurance claim references missing policy".to_string());
            }
            if claim.deadline_height < claim.opened_height {
                return Err("fee insurance claim deadline invalid".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn fee_volatility_insurance_pool_state_root_from_record(record: &Value) -> String {
    fee_insurance_hash("STATE-FROM-RECORD", &[HashPart::Json(record)])
}

fn fee_insurance_hash(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            FEE_VOLATILITY_INSURANCE_POOL_PROTOCOL_LABEL, CHAIN_ID, label
        ),
        parts,
        32,
    )
}
