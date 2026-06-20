use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedLiquidityInsuranceTrancheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_INSURANCE_TRANCHE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-liquidity-insurance-tranche-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_INSURANCE_TRANCHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_LOSS_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-liquidity-loss-attestation-v1";
pub const CONFIDENTIAL_PREMIUM_BID_SUITE: &str =
    "ml-kem-1024-sealed-confidential-liquidity-insurance-premium-bid-v1";
pub const TOKENIZED_TRANCHE_SHARE_SUITE: &str =
    "confidential-fungible-liquidity-insurance-tranche-share-v1";
pub const RESERVE_PROOF_SUITE: &str = "pq-confidential-liquidity-insurance-reserve-proof-v1";
pub const CLAIM_SETTLEMENT_SUITE: &str =
    "low-fee-confidential-liquidity-insurance-claim-settlement-v1";
pub const REDACTION_BUDGET_SUITE: &str = "redacted-operator-safe-liquidity-insurance-budget-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "redacted-operator-safe-liquidity-insurance-tranche-summary-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_936_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_880_000;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_RESERVE_ASSET_ID: &str = "xmr-liquidity-insurance-reserve-devnet";
pub const DEVNET_TRANCHE_SHARE_ASSET_ID: &str = "lit-share-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_ORACLE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_BPS: u64 = 8_000;
pub const DEFAULT_MAX_PREMIUM_BPS: u64 = 550;
pub const DEFAULT_MAX_SETTLEMENT_FEE_BPS: u64 = 8;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 32;
pub const DEFAULT_MIN_RESERVE_RATIO_BPS: u64 = 8_500;
pub const DEFAULT_JUNIOR_ATTACHMENT_BPS: u64 = 0;
pub const DEFAULT_MEZZANINE_ATTACHMENT_BPS: u64 = 1_500;
pub const DEFAULT_SENIOR_ATTACHMENT_BPS: u64 = 4_000;
pub const DEFAULT_CATASTROPHE_ATTACHMENT_BPS: u64 = 7_500;
pub const DEFAULT_POLICY_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_CLAIM_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_RESERVE_PROOF_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 128;
pub const DEFAULT_MAX_VAULTS: usize = 262_144;
pub const DEFAULT_MAX_POLICIES: usize = 1_048_576;
pub const DEFAULT_MAX_PREMIUM_BIDS: usize = 2_097_152;
pub const DEFAULT_MAX_LOSS_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_CLAIMS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 1_048_576;
pub const DEFAULT_MAX_RESERVE_PROOFS: usize = 524_288;
pub const DEFAULT_MAX_REBATES: usize = 1_048_576;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const DEFAULT_MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheSeniority {
    Junior,
    Mezzanine,
    Senior,
    Catastrophe,
}

impl TrancheSeniority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Junior => "junior",
            Self::Mezzanine => "mezzanine",
            Self::Senior => "senior",
            Self::Catastrophe => "catastrophe",
        }
    }

    pub fn default_attachment_bps(self) -> u64 {
        match self {
            Self::Junior => DEFAULT_JUNIOR_ATTACHMENT_BPS,
            Self::Mezzanine => DEFAULT_MEZZANINE_ATTACHMENT_BPS,
            Self::Senior => DEFAULT_SENIOR_ATTACHMENT_BPS,
            Self::Catastrophe => DEFAULT_CATASTROPHE_ATTACHMENT_BPS,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Open,
    Underwriting,
    Active,
    ReserveLocked,
    SettlingClaims,
    Paused,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Underwriting => "underwriting",
            Self::Active => "active",
            Self::ReserveLocked => "reserve_locked",
            Self::SettlingClaims => "settling_claims",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_policies(self) -> bool {
        matches!(self, Self::Open | Self::Underwriting | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Quoted,
    BidMatched,
    Active,
    GracePeriod,
    ClaimPending,
    Settled,
    Expired,
    Cancelled,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::BidMatched => "bid_matched",
            Self::Active => "active",
            Self::GracePeriod => "grace_period",
            Self::ClaimPending => "claim_pending",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn can_claim(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod | Self::ClaimPending)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    Opened,
    Matched,
    Repriced,
    Refunded,
    Expired,
    Cancelled,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Opened => "opened",
            Self::Matched => "matched",
            Self::Repriced => "repriced",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LossEventKind {
    BridgeDefault,
    MakerInsolvency,
    LiquidityTimeout,
    SequencerCensorship,
    WithdrawalQueueStress,
    OracleDislocation,
    ReserveImpairment,
    ProtocolEmergency,
}

impl LossEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeDefault => "bridge_default",
            Self::MakerInsolvency => "maker_insolvency",
            Self::LiquidityTimeout => "liquidity_timeout",
            Self::SequencerCensorship => "sequencer_censorship",
            Self::WithdrawalQueueStress => "withdrawal_queue_stress",
            Self::OracleDislocation => "oracle_dislocation",
            Self::ReserveImpairment => "reserve_impairment",
            Self::ProtocolEmergency => "protocol_emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    QuorumForming,
    QuorumReached,
    Challenged,
    Accepted,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::QuorumForming => "quorum_forming",
            Self::QuorumReached => "quorum_reached",
            Self::Challenged => "challenged",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Filed,
    Attested,
    ReserveChecked,
    Approved,
    PartiallySettled,
    Settled,
    Rejected,
    Expired,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::Attested => "attested",
            Self::ReserveChecked => "reserve_checked",
            Self::Approved => "approved",
            Self::PartiallySettled => "partially_settled",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Prepared,
    ReserveDebited,
    ClaimantCredited,
    RebateIssued,
    Finalized,
    Disputed,
    Reversed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::ReserveDebited => "reserve_debited",
            Self::ClaimantCredited => "claimant_credited",
            Self::RebateIssued => "rebate_issued",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Draft,
    Posted,
    Fresh,
    Stale,
    Deficient,
    Challenged,
    Superseded,
}

impl ReserveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Posted => "posted",
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Deficient => "deficient",
            Self::Challenged => "challenged",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    Vault,
    Policy,
    PremiumBid,
    LossAttestation,
    Claim,
    Settlement,
    ReserveProof,
    OperatorSummary,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Policy => "policy",
            Self::PremiumBid => "premium_bid",
            Self::LossAttestation => "loss_attestation",
            Self::Claim => "claim",
            Self::Settlement => "settlement",
            Self::ReserveProof => "reserve_proof",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub reserve_asset_id: String,
    pub tranche_share_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub oracle_quorum_bps: u64,
    pub supermajority_bps: u64,
    pub max_premium_bps: u64,
    pub max_settlement_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_reserve_ratio_bps: u64,
    pub policy_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub claim_window_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub reserve_proof_ttl_blocks: u64,
    pub redaction_budget_units: u64,
    pub max_vaults: usize,
    pub max_policies: usize,
    pub max_premium_bids: usize,
    pub max_loss_attestations: usize,
    pub max_claims: usize,
    pub max_settlements: usize,
    pub max_reserve_proofs: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub max_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_INSURANCE_TRANCHE_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            reserve_asset_id: DEVNET_RESERVE_ASSET_ID.to_string(),
            tranche_share_asset_id: DEVNET_TRANCHE_SHARE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            oracle_quorum_bps: DEFAULT_ORACLE_QUORUM_BPS,
            supermajority_bps: DEFAULT_SUPERMAJORITY_BPS,
            max_premium_bps: DEFAULT_MAX_PREMIUM_BPS,
            max_settlement_fee_bps: DEFAULT_MAX_SETTLEMENT_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_reserve_ratio_bps: DEFAULT_MIN_RESERVE_RATIO_BPS,
            policy_ttl_blocks: DEFAULT_POLICY_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            claim_window_blocks: DEFAULT_CLAIM_WINDOW_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            reserve_proof_ttl_blocks: DEFAULT_RESERVE_PROOF_TTL_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_vaults: DEFAULT_MAX_VAULTS,
            max_policies: DEFAULT_MAX_POLICIES,
            max_premium_bids: DEFAULT_MAX_PREMIUM_BIDS,
            max_loss_attestations: DEFAULT_MAX_LOSS_ATTESTATIONS,
            max_claims: DEFAULT_MAX_CLAIMS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_reserve_proofs: DEFAULT_MAX_RESERVE_PROOFS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "config",
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "tranche_share_asset_id": self.tranche_share_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "oracle_quorum_bps": self.oracle_quorum_bps,
            "supermajority_bps": self.supermajority_bps,
            "max_premium_bps": self.max_premium_bps,
            "max_settlement_fee_bps": self.max_settlement_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_reserve_ratio_bps": self.min_reserve_ratio_bps,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "claim_window_blocks": self.claim_window_blocks,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "reserve_proof_ttl_blocks": self.reserve_proof_ttl_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "max_vaults": self.max_vaults,
            "max_policies": self.max_policies,
            "max_premium_bids": self.max_premium_bids,
            "max_loss_attestations": self.max_loss_attestations,
            "max_claims": self.max_claims,
            "max_settlements": self.max_settlements,
            "max_reserve_proofs": self.max_reserve_proofs,
            "max_rebates": self.max_rebates,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_operator_summaries": self.max_operator_summaries,
            "max_events": self.max_events,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version
                == PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_INSURANCE_TRANCHE_RUNTIME_PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security too low")?;
        require(self.min_privacy_set_size > 0, "privacy set is zero")?;
        require(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum",
        )?;
        require(
            self.oracle_quorum_bps <= MAX_BPS,
            "oracle quorum exceeds bps",
        )?;
        require(
            self.supermajority_bps <= MAX_BPS,
            "supermajority exceeds bps",
        )?;
        require(self.max_premium_bps <= MAX_BPS, "premium cap exceeds bps")?;
        require(
            self.max_settlement_fee_bps <= MAX_BPS,
            "settlement fee cap exceeds bps",
        )?;
        require(self.max_rebate_bps <= MAX_BPS, "rebate cap exceeds bps")?;
        require(
            self.low_fee_rebate_bps <= self.max_rebate_bps,
            "low fee rebate exceeds cap",
        )?;
        require(
            self.min_reserve_ratio_bps <= MAX_BPS,
            "reserve ratio exceeds bps",
        )?;
        require(self.max_vaults > 0, "max vaults is zero")?;
        require(self.max_policies > 0, "max policies is zero")?;
        require(self.max_events > 0, "max events is zero")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub policies: u64,
    pub premium_bids: u64,
    pub loss_attestations: u64,
    pub claims: u64,
    pub settlements: u64,
    pub reserve_proofs: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub events: u64,
    pub sealed_bid_notional: u64,
    pub active_coverage_notional: u64,
    pub locked_reserves: u64,
    pub settled_claim_amount: u64,
    pub issued_rebate_amount: u64,
    pub next_event_index: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "counters",
            "vaults": self.vaults,
            "policies": self.policies,
            "premium_bids": self.premium_bids,
            "loss_attestations": self.loss_attestations,
            "claims": self.claims,
            "settlements": self.settlements,
            "reserve_proofs": self.reserve_proofs,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "events": self.events,
            "sealed_bid_notional": self.sealed_bid_notional,
            "active_coverage_notional": self.active_coverage_notional,
            "locked_reserves": self.locked_reserves,
            "settled_claim_amount": self.settled_claim_amount,
            "issued_rebate_amount": self.issued_rebate_amount,
            "next_event_index": self.next_event_index,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub vaults_root: String,
    pub policies_root: String,
    pub premium_bids_root: String,
    pub loss_attestations_root: String,
    pub claims_root: String,
    pub settlements_root: String,
    pub reserve_proofs_root: String,
    pub rebates_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub events_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "vaults_root": self.vaults_root,
            "policies_root": self.policies_root,
            "premium_bids_root": self.premium_bids_root,
            "loss_attestations_root": self.loss_attestations_root,
            "claims_root": self.claims_root,
            "settlements_root": self.settlements_root,
            "reserve_proofs_root": self.reserve_proofs_root,
            "rebates_root": self.rebates_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "events_root": self.events_root,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrancheVault {
    pub vault_id: String,
    pub sponsor_id: String,
    pub operator_id: String,
    pub seniority: TrancheSeniority,
    pub status: VaultStatus,
    pub reserve_asset_id: String,
    pub share_asset_id: String,
    pub reserve_commitment: String,
    pub share_supply_commitment: String,
    pub liability_commitment: String,
    pub attachment_point_bps: u64,
    pub exhaustion_point_bps: u64,
    pub target_reserve_bps: u64,
    pub premium_floor_bps: u64,
    pub max_policy_notional: u64,
    pub locked_reserve_amount: u64,
    pub issued_share_amount: u64,
    pub active_policy_count: u64,
    pub loss_event_count: u64,
    pub inception_height: u64,
    pub last_rebalance_height: u64,
    pub metadata_commitment: String,
    pub privacy_set_size: u64,
}

impl TrancheVault {
    pub fn new(
        sponsor_id: impl Into<String>,
        operator_id: impl Into<String>,
        seniority: TrancheSeniority,
        max_policy_notional: u64,
        locked_reserve_amount: u64,
        height: u64,
    ) -> Self {
        let sponsor_id = sponsor_id.into();
        let operator_id = operator_id.into();
        let mut record = Self {
            vault_id: String::new(),
            sponsor_id,
            operator_id,
            seniority,
            status: VaultStatus::Open,
            reserve_asset_id: DEVNET_RESERVE_ASSET_ID.to_string(),
            share_asset_id: DEVNET_TRANCHE_SHARE_ASSET_ID.to_string(),
            reserve_commitment: commitment(
                "VAULT-RESERVE",
                &[HashPart::U64(locked_reserve_amount)],
            ),
            share_supply_commitment: commitment("VAULT-SHARES", &[HashPart::U64(0)]),
            liability_commitment: commitment("VAULT-LIABILITY", &[HashPart::U64(0)]),
            attachment_point_bps: seniority.default_attachment_bps(),
            exhaustion_point_bps: seniority
                .default_attachment_bps()
                .saturating_add(2_500)
                .min(MAX_BPS),
            target_reserve_bps: DEFAULT_MIN_RESERVE_RATIO_BPS,
            premium_floor_bps: 12 + seniority.default_attachment_bps() / 1_000,
            max_policy_notional,
            locked_reserve_amount,
            issued_share_amount: 0,
            active_policy_count: 0,
            loss_event_count: 0,
            inception_height: height,
            last_rebalance_height: height,
            metadata_commitment: String::new(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        };
        record.metadata_commitment =
            value_root("VAULT-METADATA", &record.public_record_without_id());
        record.vault_id = id_from_record("VAULT-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "vault_id", json!(self.vault_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "tranche_vault",
            "sponsor_id": self.sponsor_id,
            "operator_id": self.operator_id,
            "seniority": self.seniority.as_str(),
            "status": self.status.as_str(),
            "reserve_asset_id": self.reserve_asset_id,
            "share_asset_id": self.share_asset_id,
            "reserve_commitment": self.reserve_commitment,
            "share_supply_commitment": self.share_supply_commitment,
            "liability_commitment": self.liability_commitment,
            "attachment_point_bps": self.attachment_point_bps,
            "exhaustion_point_bps": self.exhaustion_point_bps,
            "target_reserve_bps": self.target_reserve_bps,
            "premium_floor_bps": self.premium_floor_bps,
            "max_policy_notional": self.max_policy_notional,
            "locked_reserve_amount": self.locked_reserve_amount,
            "issued_share_amount": self.issued_share_amount,
            "active_policy_count": self.active_policy_count,
            "loss_event_count": self.loss_event_count,
            "inception_height": self.inception_height,
            "last_rebalance_height": self.last_rebalance_height,
            "metadata_commitment": self.metadata_commitment,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("VAULT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoveragePolicy {
    pub policy_id: String,
    pub vault_id: String,
    pub holder_commitment: String,
    pub coverage_commitment: String,
    pub premium_commitment: String,
    pub status: PolicyStatus,
    pub covered_notional: u64,
    pub premium_bps: u64,
    pub deductible_bps: u64,
    pub max_payout_bps: u64,
    pub start_height: u64,
    pub expiry_height: u64,
    pub bid_id: String,
    pub reserve_lock_commitment: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
}

impl CoveragePolicy {
    pub fn new(
        vault_id: impl Into<String>,
        holder_commitment: impl Into<String>,
        bid_id: impl Into<String>,
        covered_notional: u64,
        premium_bps: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let holder_commitment = holder_commitment.into();
        let bid_id = bid_id.into();
        let premium_amount = covered_notional.saturating_mul(premium_bps) / MAX_BPS;
        let mut record = Self {
            policy_id: String::new(),
            vault_id,
            holder_commitment: holder_commitment.clone(),
            coverage_commitment: commitment("POLICY-COVERAGE", &[HashPart::U64(covered_notional)]),
            premium_commitment: commitment("POLICY-PREMIUM", &[HashPart::U64(premium_amount)]),
            status: PolicyStatus::Active,
            covered_notional,
            premium_bps,
            deductible_bps: 250,
            max_payout_bps: 9_500,
            start_height: height,
            expiry_height: height.saturating_add(ttl_blocks),
            bid_id,
            reserve_lock_commitment: commitment(
                "POLICY-RESERVE-LOCK",
                &[
                    HashPart::Str(&holder_commitment),
                    HashPart::U64(covered_notional),
                ],
            ),
            nullifier_root: String::new(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        };
        record.nullifier_root = value_root("POLICY-NULLIFIERS", &record.public_record_without_id());
        record.policy_id = id_from_record("POLICY-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "policy_id", json!(self.policy_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "coverage_policy",
            "vault_id": self.vault_id,
            "holder_commitment": self.holder_commitment,
            "coverage_commitment": self.coverage_commitment,
            "premium_commitment": self.premium_commitment,
            "status": self.status.as_str(),
            "covered_notional": self.covered_notional,
            "premium_bps": self.premium_bps,
            "deductible_bps": self.deductible_bps,
            "max_payout_bps": self.max_payout_bps,
            "start_height": self.start_height,
            "expiry_height": self.expiry_height,
            "bid_id": self.bid_id,
            "reserve_lock_commitment": self.reserve_lock_commitment,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("POLICY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedPremiumBid {
    pub bid_id: String,
    pub vault_id: String,
    pub bidder_commitment: String,
    pub encrypted_bid_blob: String,
    pub bid_ciphertext_root: String,
    pub max_premium_commitment: String,
    pub desired_coverage_commitment: String,
    pub status: BidStatus,
    pub desired_coverage_notional: u64,
    pub max_premium_bps_hint: u64,
    pub fee_cap_bps: u64,
    pub submitted_height: u64,
    pub expiry_height: u64,
    pub pq_recipient_root: String,
    pub replay_nullifier: String,
    pub privacy_set_size: u64,
}

impl EncryptedPremiumBid {
    pub fn new(
        vault_id: impl Into<String>,
        bidder_commitment: impl Into<String>,
        desired_coverage_notional: u64,
        max_premium_bps_hint: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let bidder_commitment = bidder_commitment.into();
        let encrypted_bid_blob = commitment(
            "ENCRYPTED-PREMIUM-BID-BLOB",
            &[
                HashPart::Str(&vault_id),
                HashPart::Str(&bidder_commitment),
                HashPart::U64(desired_coverage_notional),
            ],
        );
        let mut record = Self {
            bid_id: String::new(),
            vault_id,
            bidder_commitment: bidder_commitment.clone(),
            encrypted_bid_blob: encrypted_bid_blob.clone(),
            bid_ciphertext_root: value_root(
                "BID-CIPHERTEXT",
                &json!({ "blob": encrypted_bid_blob }),
            ),
            max_premium_commitment: commitment(
                "BID-MAX-PREMIUM",
                &[HashPart::U64(max_premium_bps_hint)],
            ),
            desired_coverage_commitment: commitment(
                "BID-DESIRED-COVERAGE",
                &[HashPart::U64(desired_coverage_notional)],
            ),
            status: BidStatus::Sealed,
            desired_coverage_notional,
            max_premium_bps_hint,
            fee_cap_bps: DEFAULT_MAX_SETTLEMENT_FEE_BPS,
            submitted_height: height,
            expiry_height: height.saturating_add(ttl_blocks),
            pq_recipient_root: commitment("BID-PQ-RECIPIENT", &[HashPart::Str(&bidder_commitment)]),
            replay_nullifier: String::new(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        };
        record.replay_nullifier =
            value_root("BID-REPLAY-NULLIFIER", &record.public_record_without_id());
        record.bid_id = id_from_record("BID-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "bid_id", json!(self.bid_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "encrypted_premium_bid",
            "vault_id": self.vault_id,
            "bidder_commitment": self.bidder_commitment,
            "encrypted_bid_blob": self.encrypted_bid_blob,
            "bid_ciphertext_root": self.bid_ciphertext_root,
            "max_premium_commitment": self.max_premium_commitment,
            "desired_coverage_commitment": self.desired_coverage_commitment,
            "status": self.status.as_str(),
            "desired_coverage_notional": self.desired_coverage_notional,
            "max_premium_bps_hint": self.max_premium_bps_hint,
            "fee_cap_bps": self.fee_cap_bps,
            "submitted_height": self.submitted_height,
            "expiry_height": self.expiry_height,
            "pq_recipient_root": self.pq_recipient_root,
            "replay_nullifier": self.replay_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "suite": CONFIDENTIAL_PREMIUM_BID_SUITE,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("PREMIUM-BID", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqLossAttestation {
    pub attestation_id: String,
    pub vault_id: String,
    pub policy_id: String,
    pub event_kind: LossEventKind,
    pub status: AttestationStatus,
    pub loss_commitment: String,
    pub affected_liquidity_root: String,
    pub oracle_committee_root: String,
    pub pq_signature_root: String,
    pub quorum_weight_bps: u64,
    pub claimed_loss_amount: u64,
    pub confidence_bps: u64,
    pub submitted_height: u64,
    pub expiry_height: u64,
    pub challenge_window_end_height: u64,
    pub evidence_uri_commitment: String,
    pub privacy_set_size: u64,
}

impl PqLossAttestation {
    pub fn new(
        vault_id: impl Into<String>,
        policy_id: impl Into<String>,
        event_kind: LossEventKind,
        claimed_loss_amount: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let policy_id = policy_id.into();
        let mut record = Self {
            attestation_id: String::new(),
            vault_id,
            policy_id,
            event_kind,
            status: AttestationStatus::QuorumReached,
            loss_commitment: commitment("LOSS-COMMITMENT", &[HashPart::U64(claimed_loss_amount)]),
            affected_liquidity_root: String::new(),
            oracle_committee_root: String::new(),
            pq_signature_root: String::new(),
            quorum_weight_bps: DEFAULT_ORACLE_QUORUM_BPS,
            claimed_loss_amount,
            confidence_bps: 9_250,
            submitted_height: height,
            expiry_height: height.saturating_add(ttl_blocks),
            challenge_window_end_height: height.saturating_add(ttl_blocks / 2),
            evidence_uri_commitment: String::new(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        };
        record.affected_liquidity_root =
            value_root("AFFECTED-LIQUIDITY", &record.public_record_without_id());
        record.oracle_committee_root =
            commitment("LOSS-ORACLE-COMMITTEE", &[HashPart::Str(&record.vault_id)]);
        record.pq_signature_root =
            value_root("LOSS-PQ-SIGNATURES", &record.public_record_without_id());
        record.evidence_uri_commitment =
            commitment("LOSS-EVIDENCE-URI", &[HashPart::Str(&record.policy_id)]);
        record.attestation_id =
            id_from_record("LOSS-ATTESTATION-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "attestation_id", json!(self.attestation_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "pq_loss_attestation",
            "vault_id": self.vault_id,
            "policy_id": self.policy_id,
            "event_kind": self.event_kind.as_str(),
            "status": self.status.as_str(),
            "loss_commitment": self.loss_commitment,
            "affected_liquidity_root": self.affected_liquidity_root,
            "oracle_committee_root": self.oracle_committee_root,
            "pq_signature_root": self.pq_signature_root,
            "quorum_weight_bps": self.quorum_weight_bps,
            "claimed_loss_amount": self.claimed_loss_amount,
            "confidence_bps": self.confidence_bps,
            "submitted_height": self.submitted_height,
            "expiry_height": self.expiry_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "evidence_uri_commitment": self.evidence_uri_commitment,
            "privacy_set_size": self.privacy_set_size,
            "suite": PQ_LOSS_ATTESTATION_SUITE,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("LOSS-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Claim {
    pub claim_id: String,
    pub policy_id: String,
    pub vault_id: String,
    pub attestation_id: String,
    pub claimant_commitment: String,
    pub status: ClaimStatus,
    pub claimed_amount: u64,
    pub approved_amount: u64,
    pub deductible_amount: u64,
    pub filed_height: u64,
    pub settlement_deadline_height: u64,
    pub claim_nullifier: String,
    pub payout_commitment: String,
    pub redacted_evidence_root: String,
}

impl Claim {
    pub fn new(
        policy_id: impl Into<String>,
        vault_id: impl Into<String>,
        attestation_id: impl Into<String>,
        claimant_commitment: impl Into<String>,
        claimed_amount: u64,
        height: u64,
        window_blocks: u64,
    ) -> Self {
        let policy_id = policy_id.into();
        let vault_id = vault_id.into();
        let attestation_id = attestation_id.into();
        let claimant_commitment = claimant_commitment.into();
        let deductible_amount = claimed_amount / 40;
        let approved_amount = claimed_amount.saturating_sub(deductible_amount);
        let mut record = Self {
            claim_id: String::new(),
            policy_id,
            vault_id,
            attestation_id,
            claimant_commitment: claimant_commitment.clone(),
            status: ClaimStatus::Approved,
            claimed_amount,
            approved_amount,
            deductible_amount,
            filed_height: height,
            settlement_deadline_height: height.saturating_add(window_blocks),
            claim_nullifier: String::new(),
            payout_commitment: commitment("CLAIM-PAYOUT", &[HashPart::U64(approved_amount)]),
            redacted_evidence_root: String::new(),
        };
        record.claim_nullifier =
            commitment("CLAIM-NULLIFIER", &[HashPart::Str(&claimant_commitment)]);
        record.redacted_evidence_root = value_root(
            "CLAIM-REDACTED-EVIDENCE",
            &record.public_record_without_id(),
        );
        record.claim_id = id_from_record("CLAIM-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "claim_id", json!(self.claim_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "claim",
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "attestation_id": self.attestation_id,
            "claimant_commitment": self.claimant_commitment,
            "status": self.status.as_str(),
            "claimed_amount": self.claimed_amount,
            "approved_amount": self.approved_amount,
            "deductible_amount": self.deductible_amount,
            "filed_height": self.filed_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "claim_nullifier": self.claim_nullifier,
            "payout_commitment": self.payout_commitment,
            "redacted_evidence_root": self.redacted_evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("CLAIM", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimSettlement {
    pub settlement_id: String,
    pub claim_id: String,
    pub policy_id: String,
    pub vault_id: String,
    pub status: SettlementStatus,
    pub gross_payout_amount: u64,
    pub fee_amount: u64,
    pub net_payout_amount: u64,
    pub reserve_debit_commitment: String,
    pub claimant_credit_commitment: String,
    pub settlement_proof_root: String,
    pub finalized_height: u64,
    pub low_fee_rebate_id: Option<String>,
}

impl ClaimSettlement {
    pub fn new(
        claim_id: impl Into<String>,
        policy_id: impl Into<String>,
        vault_id: impl Into<String>,
        gross_payout_amount: u64,
        max_fee_bps: u64,
        height: u64,
    ) -> Self {
        let claim_id = claim_id.into();
        let policy_id = policy_id.into();
        let vault_id = vault_id.into();
        let fee_amount = gross_payout_amount.saturating_mul(max_fee_bps) / MAX_BPS;
        let net_payout_amount = gross_payout_amount.saturating_sub(fee_amount);
        let mut record = Self {
            settlement_id: String::new(),
            claim_id,
            policy_id,
            vault_id,
            status: SettlementStatus::Finalized,
            gross_payout_amount,
            fee_amount,
            net_payout_amount,
            reserve_debit_commitment: commitment(
                "SETTLEMENT-RESERVE-DEBIT",
                &[HashPart::U64(gross_payout_amount)],
            ),
            claimant_credit_commitment: commitment(
                "SETTLEMENT-CLAIMANT-CREDIT",
                &[HashPart::U64(net_payout_amount)],
            ),
            settlement_proof_root: String::new(),
            finalized_height: height,
            low_fee_rebate_id: None,
        };
        record.settlement_proof_root =
            value_root("SETTLEMENT-PROOF", &record.public_record_without_id());
        record.settlement_id = id_from_record("SETTLEMENT-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "settlement_id", json!(self.settlement_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "claim_settlement",
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "gross_payout_amount": self.gross_payout_amount,
            "fee_amount": self.fee_amount,
            "net_payout_amount": self.net_payout_amount,
            "reserve_debit_commitment": self.reserve_debit_commitment,
            "claimant_credit_commitment": self.claimant_credit_commitment,
            "settlement_proof_root": self.settlement_proof_root,
            "finalized_height": self.finalized_height,
            "low_fee_rebate_id": self.low_fee_rebate_id,
            "suite": CLAIM_SETTLEMENT_SUITE,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("CLAIM-SETTLEMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveProof {
    pub proof_id: String,
    pub vault_id: String,
    pub status: ReserveProofStatus,
    pub reserve_asset_id: String,
    pub reserve_commitment: String,
    pub liability_commitment: String,
    pub reserve_ratio_bps: u64,
    pub proved_reserve_amount: u64,
    pub proved_liability_amount: u64,
    pub proof_height: u64,
    pub expiry_height: u64,
    pub auditor_committee_root: String,
    pub pq_signature_root: String,
    pub redacted_balance_sheet_root: String,
}

impl ReserveProof {
    pub fn new(
        vault_id: impl Into<String>,
        proved_reserve_amount: u64,
        proved_liability_amount: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let vault_id = vault_id.into();
        let reserve_ratio_bps = if proved_liability_amount == 0 {
            MAX_BPS
        } else {
            proved_reserve_amount.saturating_mul(MAX_BPS) / proved_liability_amount
        };
        let mut record = Self {
            proof_id: String::new(),
            vault_id,
            status: ReserveProofStatus::Fresh,
            reserve_asset_id: DEVNET_RESERVE_ASSET_ID.to_string(),
            reserve_commitment: commitment(
                "RESERVE-PROOF-RESERVE",
                &[HashPart::U64(proved_reserve_amount)],
            ),
            liability_commitment: commitment(
                "RESERVE-PROOF-LIABILITY",
                &[HashPart::U64(proved_liability_amount)],
            ),
            reserve_ratio_bps,
            proved_reserve_amount,
            proved_liability_amount,
            proof_height: height,
            expiry_height: height.saturating_add(ttl_blocks),
            auditor_committee_root: String::new(),
            pq_signature_root: String::new(),
            redacted_balance_sheet_root: String::new(),
        };
        record.auditor_committee_root =
            commitment("RESERVE-AUDITORS", &[HashPart::Str(&record.vault_id)]);
        record.pq_signature_root =
            value_root("RESERVE-PQ-SIGNATURES", &record.public_record_without_id());
        record.redacted_balance_sheet_root =
            value_root("RESERVE-BALANCE-SHEET", &record.public_record_without_id());
        record.proof_id = id_from_record("RESERVE-PROOF-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "proof_id", json!(self.proof_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "reserve_proof",
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "reserve_asset_id": self.reserve_asset_id,
            "reserve_commitment": self.reserve_commitment,
            "liability_commitment": self.liability_commitment,
            "reserve_ratio_bps": self.reserve_ratio_bps,
            "proved_reserve_amount": self.proved_reserve_amount,
            "proved_liability_amount": self.proved_liability_amount,
            "proof_height": self.proof_height,
            "expiry_height": self.expiry_height,
            "auditor_committee_root": self.auditor_committee_root,
            "pq_signature_root": self.pq_signature_root,
            "redacted_balance_sheet_root": self.redacted_balance_sheet_root,
            "suite": RESERVE_PROOF_SUITE,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("RESERVE-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub policy_id: String,
    pub recipient_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_commitment: String,
    pub settlement_fee_bps: u64,
    pub rebate_bps: u64,
    pub rebate_amount: u64,
    pub issued_height: u64,
    pub nullifier: String,
}

impl LowFeeRebate {
    pub fn new(
        settlement_id: impl Into<String>,
        policy_id: impl Into<String>,
        recipient_commitment: impl Into<String>,
        gross_amount: u64,
        settlement_fee_bps: u64,
        rebate_bps: u64,
        height: u64,
    ) -> Self {
        let settlement_id = settlement_id.into();
        let policy_id = policy_id.into();
        let recipient_commitment = recipient_commitment.into();
        let rebate_amount = gross_amount.saturating_mul(rebate_bps) / MAX_BPS;
        let mut record = Self {
            rebate_id: String::new(),
            settlement_id,
            policy_id,
            recipient_commitment: recipient_commitment.clone(),
            rebate_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_commitment: commitment("LOW-FEE-REBATE", &[HashPart::U64(rebate_amount)]),
            settlement_fee_bps,
            rebate_bps,
            rebate_amount,
            issued_height: height,
            nullifier: String::new(),
        };
        record.nullifier = commitment("REBATE-NULLIFIER", &[HashPart::Str(&recipient_commitment)]);
        record.rebate_id = id_from_record("REBATE-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "rebate_id", json!(self.rebate_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "low_fee_rebate",
            "settlement_id": self.settlement_id,
            "policy_id": self.policy_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_commitment": self.rebate_commitment,
            "settlement_fee_bps": self.settlement_fee_bps,
            "rebate_bps": self.rebate_bps,
            "rebate_amount": self.rebate_amount,
            "issued_height": self.issued_height,
            "nullifier": self.nullifier,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("LOW-FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub scope: RedactionScope,
    pub subject_id: String,
    pub total_units: u64,
    pub used_units: u64,
    pub remaining_units: u64,
    pub expires_height: u64,
    pub audit_commitment: String,
}

impl RedactionBudget {
    pub fn new(
        operator_id: impl Into<String>,
        scope: RedactionScope,
        subject_id: impl Into<String>,
        total_units: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let operator_id = operator_id.into();
        let subject_id = subject_id.into();
        let mut record = Self {
            budget_id: String::new(),
            operator_id,
            scope,
            subject_id,
            total_units,
            used_units: 0,
            remaining_units: total_units,
            expires_height: height.saturating_add(ttl_blocks),
            audit_commitment: String::new(),
        };
        record.audit_commitment =
            value_root("REDACTION-BUDGET-AUDIT", &record.public_record_without_id());
        record.budget_id =
            id_from_record("REDACTION-BUDGET-ID", &record.public_record_without_id());
        record
    }

    pub fn consume(&mut self, units: u64) -> Result<()> {
        require(self.remaining_units >= units, "redaction budget exhausted")?;
        self.used_units = self.used_units.saturating_add(units);
        self.remaining_units = self.remaining_units.saturating_sub(units);
        self.audit_commitment =
            value_root("REDACTION-BUDGET-AUDIT", &self.public_record_without_id());
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "budget_id", json!(self.budget_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "redaction_budget",
            "operator_id": self.operator_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "total_units": self.total_units,
            "used_units": self.used_units,
            "remaining_units": self.remaining_units,
            "expires_height": self.expires_height,
            "audit_commitment": self.audit_commitment,
            "suite": REDACTION_BUDGET_SUITE,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("REDACTION-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub vault_count: u64,
    pub active_policy_count: u64,
    pub sealed_bid_count: u64,
    pub accepted_attestation_count: u64,
    pub open_claim_count: u64,
    pub finalized_settlement_count: u64,
    pub reserve_ratio_floor_bps: u64,
    pub redacted_notional_commitment: String,
    pub redacted_loss_commitment: String,
    pub low_fee_rebate_total: u64,
    pub generated_height: u64,
    pub disclosure_budget_id: String,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn new(
        operator_id: impl Into<String>,
        disclosure_budget_id: impl Into<String>,
        counters: &Counters,
        reserve_ratio_floor_bps: u64,
        height: u64,
    ) -> Self {
        let operator_id = operator_id.into();
        let disclosure_budget_id = disclosure_budget_id.into();
        let mut record = Self {
            summary_id: String::new(),
            operator_id,
            vault_count: counters.vaults,
            active_policy_count: counters.policies,
            sealed_bid_count: counters.premium_bids,
            accepted_attestation_count: counters.loss_attestations,
            open_claim_count: counters.claims.saturating_sub(counters.settlements),
            finalized_settlement_count: counters.settlements,
            reserve_ratio_floor_bps,
            redacted_notional_commitment: commitment(
                "SUMMARY-NOTIONAL",
                &[HashPart::U64(counters.active_coverage_notional)],
            ),
            redacted_loss_commitment: commitment(
                "SUMMARY-LOSS",
                &[HashPart::U64(counters.settled_claim_amount)],
            ),
            low_fee_rebate_total: counters.issued_rebate_amount,
            generated_height: height,
            disclosure_budget_id,
            summary_root: String::new(),
        };
        record.summary_root = value_root(
            "OPERATOR-SUMMARY-PAYLOAD",
            &record.public_record_without_id(),
        );
        record.summary_id =
            id_from_record("OPERATOR-SUMMARY-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "summary_id", json!(self.summary_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "operator_summary",
            "operator_id": self.operator_id,
            "vault_count": self.vault_count,
            "active_policy_count": self.active_policy_count,
            "sealed_bid_count": self.sealed_bid_count,
            "accepted_attestation_count": self.accepted_attestation_count,
            "open_claim_count": self.open_claim_count,
            "finalized_settlement_count": self.finalized_settlement_count,
            "reserve_ratio_floor_bps": self.reserve_ratio_floor_bps,
            "redacted_notional_commitment": self.redacted_notional_commitment,
            "redacted_loss_commitment": self.redacted_loss_commitment,
            "low_fee_rebate_total": self.low_fee_rebate_total,
            "generated_height": self.generated_height,
            "disclosure_budget_id": self.disclosure_budget_id,
            "summary_root": self.summary_root,
            "suite": OPERATOR_SUMMARY_SUITE,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("OPERATOR-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub index: u64,
    pub kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}

impl RuntimeEvent {
    pub fn new(
        index: u64,
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        payload: &Value,
        height: u64,
    ) -> Self {
        let kind = kind.into();
        let subject_id = subject_id.into();
        let payload_root = value_root("EVENT-PAYLOAD", payload);
        let event_id = domain_hash(
            "LIQUIDITY-INSURANCE-EVENT-ID",
            &[
                HashPart::U64(index),
                HashPart::Str(&kind),
                HashPart::Str(&subject_id),
                HashPart::Str(&payload_root),
                HashPart::U64(height),
            ],
            32,
        );
        Self {
            event_id,
            index,
            kind,
            subject_id,
            payload_root,
            height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_event",
            "event_id": self.event_id,
            "index": self.index,
            "event_kind": self.kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub vaults: BTreeMap<String, TrancheVault>,
    pub policies: BTreeMap<String, CoveragePolicy>,
    pub premium_bids: BTreeMap<String, EncryptedPremiumBid>,
    pub loss_attestations: BTreeMap<String, PqLossAttestation>,
    pub claims: BTreeMap<String, Claim>,
    pub settlements: BTreeMap<String, ClaimSettlement>,
    pub reserve_proofs: BTreeMap<String, ReserveProof>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            vaults: BTreeMap::new(),
            policies: BTreeMap::new(),
            premium_bids: BTreeMap::new(),
            loss_attestations: BTreeMap::new(),
            claims: BTreeMap::new(),
            settlements: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh();
        state
    }

    pub fn devnet() -> Self {
        demo()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_tokenized_liquidity_insurance_tranche_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_tokenized_liquidity_insurance_tranche_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        value_root("STATE", &self.public_record_without_state_root())
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(
            self.vaults.len() <= self.config.max_vaults,
            "too many vaults",
        )?;
        require(
            self.policies.len() <= self.config.max_policies,
            "too many policies",
        )?;
        require(
            self.premium_bids.len() <= self.config.max_premium_bids,
            "too many premium bids",
        )?;
        require(
            self.loss_attestations.len() <= self.config.max_loss_attestations,
            "too many loss attestations",
        )?;
        require(
            self.claims.len() <= self.config.max_claims,
            "too many claims",
        )?;
        require(
            self.settlements.len() <= self.config.max_settlements,
            "too many settlements",
        )?;
        require(
            self.reserve_proofs.len() <= self.config.max_reserve_proofs,
            "too many reserve proofs",
        )?;
        require(
            self.rebates.len() <= self.config.max_rebates,
            "too many rebates",
        )?;
        require(
            self.redaction_budgets.len() <= self.config.max_redaction_budgets,
            "too many redaction budgets",
        )?;
        require(
            self.operator_summaries.len() <= self.config.max_operator_summaries,
            "too many operator summaries",
        )?;
        require(
            self.events.len() <= self.config.max_events,
            "too many events",
        )?;
        for policy in self.policies.values() {
            require(
                self.vaults.contains_key(&policy.vault_id),
                "policy references missing vault",
            )?;
            require(
                policy.premium_bps <= self.config.max_premium_bps,
                "premium exceeds cap",
            )?;
        }
        for bid in self.premium_bids.values() {
            require(
                self.vaults.contains_key(&bid.vault_id),
                "bid references missing vault",
            )?;
        }
        for claim in self.claims.values() {
            require(
                self.policies.contains_key(&claim.policy_id),
                "claim references missing policy",
            )?;
        }
        Ok(())
    }

    pub fn create_vault(
        &mut self,
        sponsor_id: impl Into<String>,
        operator_id: impl Into<String>,
        seniority: TrancheSeniority,
        max_policy_notional: u64,
        locked_reserve_amount: u64,
        height: u64,
    ) -> Result<String> {
        require(
            self.vaults.len() < self.config.max_vaults,
            "vault capacity reached",
        )?;
        require(max_policy_notional > 0, "max policy notional is zero")?;
        require(locked_reserve_amount > 0, "locked reserve amount is zero")?;
        let vault = TrancheVault::new(
            sponsor_id,
            operator_id,
            seniority,
            max_policy_notional,
            locked_reserve_amount,
            height,
        );
        let vault_id = vault.vault_id.clone();
        self.vaults.insert(vault_id.clone(), vault);
        self.push_event("vault_created", &vault_id, height)?;
        self.refresh();
        Ok(vault_id)
    }

    pub fn submit_premium_bid(
        &mut self,
        vault_id: impl Into<String>,
        bidder_commitment: impl Into<String>,
        desired_coverage_notional: u64,
        max_premium_bps_hint: u64,
        height: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        let vault = self
            .vaults
            .get(&vault_id)
            .ok_or_else(|| "unknown vault".to_string())?;
        require(
            vault.status.accepts_policies(),
            "vault is not accepting bids",
        )?;
        require(
            desired_coverage_notional <= vault.max_policy_notional,
            "desired coverage exceeds vault limit",
        )?;
        require(
            max_premium_bps_hint <= self.config.max_premium_bps,
            "premium hint exceeds cap",
        )?;
        require(
            self.premium_bids.len() < self.config.max_premium_bids,
            "premium bid capacity reached",
        )?;
        let bid = EncryptedPremiumBid::new(
            vault_id.clone(),
            bidder_commitment,
            desired_coverage_notional,
            max_premium_bps_hint,
            height,
            self.config.bid_ttl_blocks,
        );
        let bid_id = bid.bid_id.clone();
        self.premium_bids.insert(bid_id.clone(), bid);
        self.push_event("premium_bid_submitted", &bid_id, height)?;
        self.refresh();
        Ok(bid_id)
    }

    pub fn bind_policy_from_bid(
        &mut self,
        vault_id: impl Into<String>,
        bid_id: impl Into<String>,
        holder_commitment: impl Into<String>,
        covered_notional: u64,
        premium_bps: u64,
        height: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        let bid_id = bid_id.into();
        require(
            self.policies.len() < self.config.max_policies,
            "policy capacity reached",
        )?;
        require(
            premium_bps <= self.config.max_premium_bps,
            "premium exceeds cap",
        )?;
        let vault = self
            .vaults
            .get_mut(&vault_id)
            .ok_or_else(|| "unknown vault".to_string())?;
        require(
            vault.status.accepts_policies(),
            "vault is not accepting policies",
        )?;
        require(
            covered_notional <= vault.max_policy_notional,
            "coverage exceeds vault limit",
        )?;
        let bid = self
            .premium_bids
            .get_mut(&bid_id)
            .ok_or_else(|| "unknown bid".to_string())?;
        require(bid.vault_id == vault_id, "bid vault mismatch")?;
        require(
            matches!(bid.status, BidStatus::Sealed | BidStatus::Opened),
            "bid not matchable",
        )?;
        bid.status = BidStatus::Matched;
        let policy = CoveragePolicy::new(
            vault_id.clone(),
            holder_commitment,
            bid_id.clone(),
            covered_notional,
            premium_bps,
            height,
            self.config.policy_ttl_blocks,
        );
        let policy_id = policy.policy_id.clone();
        vault.active_policy_count = vault.active_policy_count.saturating_add(1);
        vault.liability_commitment = commitment(
            "VAULT-LIABILITY",
            &[
                HashPart::U64(vault.active_policy_count),
                HashPart::U64(covered_notional),
            ],
        );
        self.policies.insert(policy_id.clone(), policy);
        self.push_event("policy_bound", &policy_id, height)?;
        self.refresh();
        Ok(policy_id)
    }

    pub fn attest_loss(
        &mut self,
        vault_id: impl Into<String>,
        policy_id: impl Into<String>,
        event_kind: LossEventKind,
        claimed_loss_amount: u64,
        height: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        let policy_id = policy_id.into();
        require(
            self.loss_attestations.len() < self.config.max_loss_attestations,
            "loss attestation capacity reached",
        )?;
        let policy = self
            .policies
            .get(&policy_id)
            .ok_or_else(|| "unknown policy".to_string())?;
        require(policy.vault_id == vault_id, "policy vault mismatch")?;
        require(policy.status.can_claim(), "policy cannot claim")?;
        let vault = self
            .vaults
            .get_mut(&vault_id)
            .ok_or_else(|| "unknown vault".to_string())?;
        vault.loss_event_count = vault.loss_event_count.saturating_add(1);
        let attestation = PqLossAttestation::new(
            vault_id,
            policy_id,
            event_kind,
            claimed_loss_amount,
            height,
            self.config.attestation_ttl_blocks,
        );
        let attestation_id = attestation.attestation_id.clone();
        self.loss_attestations
            .insert(attestation_id.clone(), attestation);
        self.push_event("loss_attested", &attestation_id, height)?;
        self.refresh();
        Ok(attestation_id)
    }

    pub fn file_claim(
        &mut self,
        policy_id: impl Into<String>,
        attestation_id: impl Into<String>,
        claimant_commitment: impl Into<String>,
        claimed_amount: u64,
        height: u64,
    ) -> Result<String> {
        let policy_id = policy_id.into();
        let attestation_id = attestation_id.into();
        require(
            self.claims.len() < self.config.max_claims,
            "claim capacity reached",
        )?;
        let policy = self
            .policies
            .get_mut(&policy_id)
            .ok_or_else(|| "unknown policy".to_string())?;
        require(policy.status.can_claim(), "policy cannot claim")?;
        let attestation = self
            .loss_attestations
            .get(&attestation_id)
            .ok_or_else(|| "unknown attestation".to_string())?;
        require(
            attestation.policy_id == policy_id,
            "attestation policy mismatch",
        )?;
        require(
            claimed_amount <= policy.covered_notional,
            "claim exceeds covered notional",
        )?;
        policy.status = PolicyStatus::ClaimPending;
        let claim = Claim::new(
            policy_id.clone(),
            policy.vault_id.clone(),
            attestation_id,
            claimant_commitment,
            claimed_amount,
            height,
            self.config.claim_window_blocks,
        );
        let claim_id = claim.claim_id.clone();
        self.claims.insert(claim_id.clone(), claim);
        self.push_event("claim_filed", &claim_id, height)?;
        self.refresh();
        Ok(claim_id)
    }

    pub fn settle_claim(&mut self, claim_id: impl Into<String>, height: u64) -> Result<String> {
        let claim_id = claim_id.into();
        require(
            self.settlements.len() < self.config.max_settlements,
            "settlement capacity reached",
        )?;
        let claim = self
            .claims
            .get_mut(&claim_id)
            .ok_or_else(|| "unknown claim".to_string())?;
        require(
            matches!(
                claim.status,
                ClaimStatus::Approved | ClaimStatus::ReserveChecked
            ),
            "claim not approved",
        )?;
        let settlement = ClaimSettlement::new(
            claim_id.clone(),
            claim.policy_id.clone(),
            claim.vault_id.clone(),
            claim.approved_amount,
            self.config.max_settlement_fee_bps,
            height,
        );
        claim.status = ClaimStatus::Settled;
        if let Some(policy) = self.policies.get_mut(&claim.policy_id) {
            policy.status = PolicyStatus::Settled;
        }
        if let Some(vault) = self.vaults.get_mut(&claim.vault_id) {
            vault.locked_reserve_amount = vault
                .locked_reserve_amount
                .saturating_sub(settlement.gross_payout_amount);
            vault.reserve_commitment = commitment(
                "VAULT-RESERVE",
                &[HashPart::U64(vault.locked_reserve_amount)],
            );
        }
        let settlement_id = settlement.settlement_id.clone();
        self.settlements.insert(settlement_id.clone(), settlement);
        self.push_event("claim_settled", &settlement_id, height)?;
        self.refresh();
        Ok(settlement_id)
    }

    pub fn post_reserve_proof(
        &mut self,
        vault_id: impl Into<String>,
        proved_reserve_amount: u64,
        proved_liability_amount: u64,
        height: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        require(
            self.reserve_proofs.len() < self.config.max_reserve_proofs,
            "reserve proof capacity reached",
        )?;
        require(self.vaults.contains_key(&vault_id), "unknown vault")?;
        let proof = ReserveProof::new(
            vault_id,
            proved_reserve_amount,
            proved_liability_amount,
            height,
            self.config.reserve_proof_ttl_blocks,
        );
        require(
            proof.reserve_ratio_bps >= self.config.min_reserve_ratio_bps,
            "reserve proof below minimum ratio",
        )?;
        let proof_id = proof.proof_id.clone();
        self.reserve_proofs.insert(proof_id.clone(), proof);
        self.push_event("reserve_proof_posted", &proof_id, height)?;
        self.refresh();
        Ok(proof_id)
    }

    pub fn issue_low_fee_rebate(
        &mut self,
        settlement_id: impl Into<String>,
        recipient_commitment: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        let settlement_id = settlement_id.into();
        require(
            self.rebates.len() < self.config.max_rebates,
            "rebate capacity reached",
        )?;
        let settlement = self
            .settlements
            .get_mut(&settlement_id)
            .ok_or_else(|| "unknown settlement".to_string())?;
        require(
            settlement.fee_amount.saturating_mul(MAX_BPS)
                <= settlement
                    .gross_payout_amount
                    .saturating_mul(self.config.max_settlement_fee_bps),
            "settlement fee above configured cap",
        )?;
        let rebate = LowFeeRebate::new(
            settlement_id.clone(),
            settlement.policy_id.clone(),
            recipient_commitment,
            settlement.gross_payout_amount,
            self.config.max_settlement_fee_bps,
            self.config.low_fee_rebate_bps,
            height,
        );
        let rebate_id = rebate.rebate_id.clone();
        settlement.low_fee_rebate_id = Some(rebate_id.clone());
        self.rebates.insert(rebate_id.clone(), rebate);
        self.push_event("low_fee_rebate_issued", &rebate_id, height)?;
        self.refresh();
        Ok(rebate_id)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        operator_id: impl Into<String>,
        scope: RedactionScope,
        subject_id: impl Into<String>,
        total_units: u64,
        height: u64,
    ) -> Result<String> {
        require(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity reached",
        )?;
        require(total_units > 0, "redaction budget is zero")?;
        let budget = RedactionBudget::new(
            operator_id,
            scope,
            subject_id,
            total_units,
            height,
            self.config.policy_ttl_blocks,
        );
        let budget_id = budget.budget_id.clone();
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.push_event("redaction_budget_allocated", &budget_id, height)?;
        self.refresh();
        Ok(budget_id)
    }

    pub fn publish_operator_summary(
        &mut self,
        operator_id: impl Into<String>,
        budget_id: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        let operator_id = operator_id.into();
        let budget_id = budget_id.into();
        require(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity reached",
        )?;
        let budget = self
            .redaction_budgets
            .get_mut(&budget_id)
            .ok_or_else(|| "unknown redaction budget".to_string())?;
        require(
            budget.operator_id == operator_id,
            "operator budget mismatch",
        )?;
        budget.consume(8)?;
        let reserve_ratio_floor_bps = self
            .reserve_proofs
            .values()
            .map(|proof| proof.reserve_ratio_bps)
            .min()
            .unwrap_or(MAX_BPS);
        let summary = OperatorSummary::new(
            operator_id,
            budget_id,
            &self.counters,
            reserve_ratio_floor_bps,
            height,
        );
        let summary_id = summary.summary_id.clone();
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.push_event("operator_summary_published", &summary_id, height)?;
        self.refresh();
        Ok(summary_id)
    }

    pub fn redacted_subject_record(
        &self,
        scope: RedactionScope,
        subject_id: &str,
    ) -> Option<Value> {
        match scope {
            RedactionScope::Vault => self.vaults.get(subject_id).map(TrancheVault::public_record),
            RedactionScope::Policy => self
                .policies
                .get(subject_id)
                .map(CoveragePolicy::public_record),
            RedactionScope::PremiumBid => self
                .premium_bids
                .get(subject_id)
                .map(EncryptedPremiumBid::public_record),
            RedactionScope::LossAttestation => self
                .loss_attestations
                .get(subject_id)
                .map(PqLossAttestation::public_record),
            RedactionScope::Claim => self.claims.get(subject_id).map(Claim::public_record),
            RedactionScope::Settlement => self
                .settlements
                .get(subject_id)
                .map(ClaimSettlement::public_record),
            RedactionScope::ReserveProof => self
                .reserve_proofs
                .get(subject_id)
                .map(ReserveProof::public_record),
            RedactionScope::OperatorSummary => self
                .operator_summaries
                .get(subject_id)
                .map(OperatorSummary::public_record),
        }
    }

    fn push_event(&mut self, kind: &str, subject_id: &str, height: u64) -> Result<()> {
        require(
            self.events.len() < self.config.max_events,
            "event capacity reached",
        )?;
        let payload = json!({
            "kind": kind,
            "subject_id": subject_id,
            "height": height,
            "state_hint": self.roots.state_root(),
        });
        let event = RuntimeEvent::new(
            self.counters.next_event_index,
            kind,
            subject_id,
            &payload,
            height,
        );
        self.counters.next_event_index = self.counters.next_event_index.saturating_add(1);
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    fn refresh(&mut self) {
        self.counters.vaults = self.vaults.len() as u64;
        self.counters.policies = self.policies.len() as u64;
        self.counters.premium_bids = self.premium_bids.len() as u64;
        self.counters.loss_attestations = self.loss_attestations.len() as u64;
        self.counters.claims = self.claims.len() as u64;
        self.counters.settlements = self.settlements.len() as u64;
        self.counters.reserve_proofs = self.reserve_proofs.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.events = self.events.len() as u64;
        self.counters.sealed_bid_notional = self
            .premium_bids
            .values()
            .filter(|bid| matches!(bid.status, BidStatus::Sealed | BidStatus::Opened))
            .map(|bid| bid.desired_coverage_notional)
            .sum();
        self.counters.active_coverage_notional = self
            .policies
            .values()
            .filter(|policy| {
                matches!(
                    policy.status,
                    PolicyStatus::Active | PolicyStatus::ClaimPending
                )
            })
            .map(|policy| policy.covered_notional)
            .sum();
        self.counters.locked_reserves = self
            .vaults
            .values()
            .map(|vault| vault.locked_reserve_amount)
            .sum();
        self.counters.settled_claim_amount = self
            .settlements
            .values()
            .filter(|settlement| settlement.status == SettlementStatus::Finalized)
            .map(|settlement| settlement.gross_payout_amount)
            .sum();
        self.counters.issued_rebate_amount = self
            .rebates
            .values()
            .map(|rebate| rebate.rebate_amount)
            .sum();
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            vaults_root: map_root("VAULTS", &self.vaults, TrancheVault::public_record),
            policies_root: map_root("POLICIES", &self.policies, CoveragePolicy::public_record),
            premium_bids_root: map_root(
                "PREMIUM-BIDS",
                &self.premium_bids,
                EncryptedPremiumBid::public_record,
            ),
            loss_attestations_root: map_root(
                "LOSS-ATTESTATIONS",
                &self.loss_attestations,
                PqLossAttestation::public_record,
            ),
            claims_root: map_root("CLAIMS", &self.claims, Claim::public_record),
            settlements_root: map_root(
                "SETTLEMENTS",
                &self.settlements,
                ClaimSettlement::public_record,
            ),
            reserve_proofs_root: map_root(
                "RESERVE-PROOFS",
                &self.reserve_proofs,
                ReserveProof::public_record,
            ),
            rebates_root: map_root("REBATES", &self.rebates, LowFeeRebate::public_record),
            redaction_budgets_root: map_root(
                "REDACTION-BUDGETS",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            operator_summaries_root: map_root(
                "OPERATOR-SUMMARIES",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            events_root: map_root("EVENTS", &self.events, RuntimeEvent::public_record),
        };
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::new(Config::default());
    let vault_id = state
        .create_vault(
            "sponsor:devnet-liquidity-insurance-dao",
            "operator:tranche-insurance-operator-0",
            TrancheSeniority::Mezzanine,
            25_000_000_000,
            100_000_000_000,
            DEVNET_HEIGHT,
        )
        .expect("devnet vault");
    let bid_id = state
        .submit_premium_bid(
            vault_id.clone(),
            "holder:sealed-liquidity-maker-alpha",
            10_000_000_000,
            120,
            DEVNET_HEIGHT + 1,
        )
        .expect("devnet premium bid");
    let policy_id = state
        .bind_policy_from_bid(
            vault_id.clone(),
            bid_id,
            "holder:sealed-liquidity-maker-alpha",
            10_000_000_000,
            90,
            DEVNET_HEIGHT + 2,
        )
        .expect("devnet policy");
    let proof_id = state
        .post_reserve_proof(
            vault_id.clone(),
            100_000_000_000,
            10_000_000_000,
            DEVNET_HEIGHT + 3,
        )
        .expect("devnet reserve proof");
    let attestation_id = state
        .attest_loss(
            vault_id.clone(),
            policy_id.clone(),
            LossEventKind::LiquidityTimeout,
            1_500_000_000,
            DEVNET_HEIGHT + 4,
        )
        .expect("devnet loss attestation");
    let claim_id = state
        .file_claim(
            policy_id,
            attestation_id,
            "claimant:sealed-liquidity-maker-alpha",
            1_500_000_000,
            DEVNET_HEIGHT + 5,
        )
        .expect("devnet claim");
    let settlement_id = state
        .settle_claim(claim_id, DEVNET_HEIGHT + 6)
        .expect("devnet settlement");
    state
        .issue_low_fee_rebate(
            settlement_id,
            "claimant:sealed-liquidity-maker-alpha",
            DEVNET_HEIGHT + 7,
        )
        .expect("devnet rebate");
    let budget_id = state
        .allocate_redaction_budget(
            "operator:tranche-insurance-operator-0",
            RedactionScope::OperatorSummary,
            proof_id,
            DEFAULT_REDACTION_BUDGET_UNITS,
            DEVNET_HEIGHT + 8,
        )
        .expect("devnet budget");
    state
        .publish_operator_summary(
            "operator:tranche-insurance-operator-0",
            budget_id,
            DEVNET_HEIGHT + 9,
        )
        .expect("devnet operator summary");
    state.refresh();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn hash_json(domain: &str, payload: &Value) -> String {
    value_root(domain, payload)
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn commitment(domain: &str, parts: &[HashPart<'_>]) -> String {
    let copied = parts.iter().map(hash_part_ref).collect::<Vec<_>>();
    domain_hash(domain, &copied, 32)
}

fn hash_part_ref<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(value) => HashPart::Bytes(value),
        HashPart::Str(value) => HashPart::Str(value),
        HashPart::U64(value) => HashPart::U64(*value),
        HashPart::Int(value) => HashPart::Int(*value),
        HashPart::Json(value) => HashPart::Json(value),
    }
}

fn value_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 20)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_json_field(record: &mut Value, field: &str, value: Value) {
    if let Some(object) = record.as_object_mut() {
        object.insert(field.to_string(), value);
    }
}

#[allow(dead_code)]
fn set_root(values: impl IntoIterator<Item = String>) -> String {
    let unique = values.into_iter().collect::<BTreeSet<_>>();
    let leaves = unique.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root("SET", &leaves)
}
