use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSeraphisJamtisDualViewtagScanMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_DUAL_VIEWTAG_SCAN_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-seraphis-jamtis-dual-viewtag-scan-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_DUAL_VIEWTAG_SCAN_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROUTER_SCHEME: &str = "seraphis-jamtis-dual-viewtag-scan-market-v1";
pub const PROOF_COHORT_SCHEME: &str = "seraphis-jamtis-private-scan-lane-root-v1";
pub const AGGREGATION_CREDIT_SCHEME: &str = "jamtis-dual-viewtag-scan-speed-credit-root-v1";
pub const REBATE_INTENT_SCHEME: &str = "low-fee-private-scan-rebate-order-root-v1";
pub const PQ_ORACLE_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-scan-sponsor-authorization-v1";
pub const SPONSOR_SETTLEMENT_SCHEME: &str = "pq-sponsor-scan-receipt-netting-root-v1";
pub const ABUSE_THROTTLE_SCHEME: &str = "dual-viewtag-reuse-throttle-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str =
    "view-key-safe-seraphis-jamtis-scan-privacy-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-dual-viewtag-scan-market-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_addresses_view_keys_key_images_amounts_decoy_graphs_viewtag_values_or_scan_transcripts";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const DEFAULT_MIN_OUTPUT_COMMITMENTS: u64 = 16;
pub const DEFAULT_MIN_COHORT_PROOFS: u64 = 8;
pub const DEFAULT_TARGET_COHORT_PROOFS: u64 = 128;
pub const DEFAULT_MAX_COHORT_PROOFS: u64 = 512;
pub const DEFAULT_MAX_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ORACLE_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 12;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_250;
pub const DEFAULT_AGGREGATION_CREDIT_BPS: u64 = 3_500;
pub const DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 240;
pub const DEFAULT_MAX_INTENTS_PER_BUCKET: u64 = 64;
pub const DEFAULT_MAX_REBATE_UNITS_PER_BUCKET: u64 = 2_048;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_EPOCH: u64 = 4_096;
pub const DEFAULT_OPERATOR_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Open,
    IntakeClosed,
    Aggregating,
    CreditIssued,
    Attesting,
    RebateQueued,
    Settling,
    Settled,
    Throttled,
    Quarantined,
    Rejected,
    Expired,
}

impl CohortStatus {
    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open | Self::IntakeClosed)
    }

    pub fn is_operator_visible(self) -> bool {
        matches!(
            self,
            Self::CreditIssued
                | Self::Attesting
                | Self::RebateQueued
                | Self::Settling
                | Self::Settled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateIntentStatus {
    Submitted,
    PrivacyChecked,
    AggregationMatched,
    AttestationPending,
    SponsorReserved,
    Payable,
    Paid,
    Refunded,
    Throttled,
    Rejected,
    Expired,
}

impl RebateIntentStatus {
    pub fn eligible_for_settlement(self) -> bool {
        matches!(self, Self::Payable | Self::SponsorReserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationCreditStatus {
    Draft,
    Metered,
    Matched,
    OracleAttested,
    RebateApplied,
    Superseded,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleAttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl OracleAttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorSettlementStatus {
    Open,
    Reserved,
    Netting,
    Posted,
    Finalized,
    Refunded,
    Slashed,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseThrottleStatus {
    Observing,
    SoftLimited,
    HardLimited,
    CoolingDown,
    Cleared,
    Escalated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionBudgetStatus {
    Open,
    Reserved,
    Applied,
    Exhausted,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryAudience {
    Operator,
    Sponsor,
    Oracle,
    Watchtower,
    Public,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    CohortOpened,
    CreditIssued,
    IntentQueued,
    OracleAttested,
    SponsorReserved,
    SettlementFinalized,
    ThrottleApplied,
    RedactionBudgetApplied,
    SummaryPublished,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub router_scheme: String,
    pub proof_cohort_scheme: String,
    pub aggregation_credit_scheme: String,
    pub rebate_intent_scheme: String,
    pub pq_oracle_attestation_scheme: String,
    pub sponsor_settlement_scheme: String,
    pub abuse_throttle_scheme: String,
    pub redaction_budget_scheme: String,
    pub operator_summary_scheme: String,
    pub privacy_boundary: String,
    pub min_ring_size: u64,
    pub min_output_commitments: u64,
    pub min_cohort_proofs: u64,
    pub target_cohort_proofs: u64,
    pub max_cohort_proofs: u64,
    pub max_window_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub oracle_quorum_bps: u64,
    pub strong_oracle_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub aggregation_credit_bps: u64,
    pub throttle_window_blocks: u64,
    pub max_intents_per_bucket: u64,
    pub max_rebate_units_per_bucket: u64,
    pub max_redaction_units_per_epoch: u64,
    pub operator_bucket_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            router_scheme: ROUTER_SCHEME.to_string(),
            proof_cohort_scheme: PROOF_COHORT_SCHEME.to_string(),
            aggregation_credit_scheme: AGGREGATION_CREDIT_SCHEME.to_string(),
            rebate_intent_scheme: REBATE_INTENT_SCHEME.to_string(),
            pq_oracle_attestation_scheme: PQ_ORACLE_ATTESTATION_SCHEME.to_string(),
            sponsor_settlement_scheme: SPONSOR_SETTLEMENT_SCHEME.to_string(),
            abuse_throttle_scheme: ABUSE_THROTTLE_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_output_commitments: DEFAULT_MIN_OUTPUT_COMMITMENTS,
            min_cohort_proofs: DEFAULT_MIN_COHORT_PROOFS,
            target_cohort_proofs: DEFAULT_TARGET_COHORT_PROOFS,
            max_cohort_proofs: DEFAULT_MAX_COHORT_PROOFS,
            max_window_blocks: DEFAULT_MAX_WINDOW_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            oracle_quorum_bps: DEFAULT_ORACLE_QUORUM_BPS,
            strong_oracle_quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            aggregation_credit_bps: DEFAULT_AGGREGATION_CREDIT_BPS,
            throttle_window_blocks: DEFAULT_THROTTLE_WINDOW_BLOCKS,
            max_intents_per_bucket: DEFAULT_MAX_INTENTS_PER_BUCKET,
            max_rebate_units_per_bucket: DEFAULT_MAX_REBATE_UNITS_PER_BUCKET,
            max_redaction_units_per_epoch: DEFAULT_MAX_REDACTION_UNITS_PER_EPOCH,
            operator_bucket_size: DEFAULT_OPERATOR_BUCKET_SIZE,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "router_scheme": self.router_scheme,
            "proof_cohort_scheme": self.proof_cohort_scheme,
            "aggregation_credit_scheme": self.aggregation_credit_scheme,
            "rebate_intent_scheme": self.rebate_intent_scheme,
            "pq_oracle_attestation_scheme": self.pq_oracle_attestation_scheme,
            "sponsor_settlement_scheme": self.sponsor_settlement_scheme,
            "abuse_throttle_scheme": self.abuse_throttle_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "privacy_boundary": self.privacy_boundary,
            "min_ring_size": self.min_ring_size,
            "min_output_commitments": self.min_output_commitments,
            "min_cohort_proofs": self.min_cohort_proofs,
            "target_cohort_proofs": self.target_cohort_proofs,
            "max_cohort_proofs": self.max_cohort_proofs,
            "max_window_blocks": self.max_window_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "oracle_quorum_bps": self.oracle_quorum_bps,
            "strong_oracle_quorum_bps": self.strong_oracle_quorum_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "aggregation_credit_bps": self.aggregation_credit_bps,
            "throttle_window_blocks": self.throttle_window_blocks,
            "max_intents_per_bucket": self.max_intents_per_bucket,
            "max_rebate_units_per_bucket": self.max_rebate_units_per_bucket,
            "max_redaction_units_per_epoch": self.max_redaction_units_per_epoch,
            "operator_bucket_size": self.operator_bucket_size
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_cohort_proofs == 0 || self.min_cohort_proofs > self.target_cohort_proofs {
            return Err("cohort proof bounds are invalid".to_string());
        }
        if self.target_cohort_proofs > self.max_cohort_proofs {
            return Err("target cohort proofs exceed max cohort proofs".to_string());
        }
        if self.max_user_fee_bps > self.max_rebate_bps || self.max_rebate_bps > MAX_BPS {
            return Err("fee rebate bps bounds are invalid".to_string());
        }
        if self.oracle_quorum_bps > self.strong_oracle_quorum_bps
            || self.strong_oracle_quorum_bps > MAX_BPS
        {
            return Err("oracle quorum bps bounds are invalid".to_string());
        }
        if self.min_pq_security_bits > self.target_pq_security_bits {
            return Err("pq security bits are invalid".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub proof_cohorts: u64,
    pub aggregation_credits: u64,
    pub rebate_intents: u64,
    pub oracle_attestations: u64,
    pub sponsor_settlements: u64,
    pub abuse_throttles: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub events: u64,
    pub open_rebate_units: u64,
    pub settled_rebate_units: u64,
    pub throttled_buckets: u64,
    pub redaction_units_reserved: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_cohorts": self.proof_cohorts,
            "aggregation_credits": self.aggregation_credits,
            "rebate_intents": self.rebate_intents,
            "oracle_attestations": self.oracle_attestations,
            "sponsor_settlements": self.sponsor_settlements,
            "abuse_throttles": self.abuse_throttles,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "events": self.events,
            "open_rebate_units": self.open_rebate_units,
            "settled_rebate_units": self.settled_rebate_units,
            "throttled_buckets": self.throttled_buckets,
            "redaction_units_reserved": self.redaction_units_reserved
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub proof_cohort_root: String,
    pub aggregation_credit_root: String,
    pub rebate_intent_root: String,
    pub oracle_attestation_root: String,
    pub sponsor_settlement_root: String,
    pub abuse_throttle_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub event_root: String,
    pub public_record_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            proof_cohort_root: empty_root("PROOF-COHORT"),
            aggregation_credit_root: empty_root("AGGREGATION-CREDIT"),
            rebate_intent_root: empty_root("REBATE-INTENT"),
            oracle_attestation_root: empty_root("ORACLE-ATTESTATION"),
            sponsor_settlement_root: empty_root("SPONSOR-SETTLEMENT"),
            abuse_throttle_root: empty_root("ABUSE-THROTTLE"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            operator_summary_root: empty_root("OPERATOR-SUMMARY"),
            event_root: empty_root("EVENT"),
            public_record_root: empty_root("PUBLIC-RECORD"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "proof_cohort_root": self.proof_cohort_root,
            "aggregation_credit_root": self.aggregation_credit_root,
            "rebate_intent_root": self.rebate_intent_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "sponsor_settlement_root": self.sponsor_settlement_root,
            "abuse_throttle_root": self.abuse_throttle_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCohort {
    pub cohort_id: String,
    pub status: CohortStatus,
    pub opened_height: u64,
    pub close_height: u64,
    pub proof_count: u64,
    pub output_commitment_count: u64,
    pub min_ring_size: u64,
    pub transcript_root: String,
    pub aggregation_root: String,
    pub privacy_floor_root: String,
    pub sponsor_policy_id: String,
    pub route_bucket: String,
    pub expected_rebate_bps: u64,
    pub privacy_notes: Vec<String>,
}

impl ProofCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "status": self.status,
            "opened_height": self.opened_height,
            "close_height": self.close_height,
            "proof_count": self.proof_count,
            "output_commitment_count": self.output_commitment_count,
            "min_ring_size": self.min_ring_size,
            "transcript_root": self.transcript_root,
            "aggregation_root": self.aggregation_root,
            "privacy_floor_root": self.privacy_floor_root,
            "sponsor_policy_id": self.sponsor_policy_id,
            "route_bucket": self.route_bucket,
            "expected_rebate_bps": self.expected_rebate_bps,
            "privacy_notes": self.privacy_notes
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregationCredit {
    pub credit_id: String,
    pub cohort_id: String,
    pub status: AggregationCreditStatus,
    pub credit_units: u64,
    pub aggregation_factor_bps: u64,
    pub proof_count: u64,
    pub output_commitment_count: u64,
    pub marginal_fee_saved_piconero: u64,
    pub transcript_root: String,
    pub metering_root: String,
    pub nullifier_root: String,
    pub issued_height: u64,
}

impl AggregationCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "credit_units": self.credit_units,
            "aggregation_factor_bps": self.aggregation_factor_bps,
            "proof_count": self.proof_count,
            "output_commitment_count": self.output_commitment_count,
            "marginal_fee_saved_piconero": self.marginal_fee_saved_piconero,
            "transcript_root": self.transcript_root,
            "metering_root": self.metering_root,
            "nullifier_root": self.nullifier_root,
            "issued_height": self.issued_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateIntent {
    pub intent_id: String,
    pub cohort_id: String,
    pub credit_id: String,
    pub status: RebateIntentStatus,
    pub wallet_bucket: String,
    pub route_bucket: String,
    pub fee_commitment_root: String,
    pub rebate_commitment_root: String,
    pub nullifier: String,
    pub requested_rebate_bps: u64,
    pub rebate_units: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub sponsor_policy_id: String,
    pub redaction_budget_id: String,
}

impl FeeRebateIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "cohort_id": self.cohort_id,
            "credit_id": self.credit_id,
            "status": self.status,
            "wallet_bucket": self.wallet_bucket,
            "route_bucket": self.route_bucket,
            "fee_commitment_root": self.fee_commitment_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "nullifier": self.nullifier,
            "requested_rebate_bps": self.requested_rebate_bps,
            "rebate_units": self.rebate_units,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "sponsor_policy_id": self.sponsor_policy_id,
            "redaction_budget_id": self.redaction_budget_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub oracle_id: String,
    pub cohort_id: String,
    pub credit_id: String,
    pub status: OracleAttestationStatus,
    pub pq_security_bits: u16,
    pub attested_height: u64,
    pub expires_height: u64,
    pub statement_root: String,
    pub signature_root: String,
    pub rebate_ceiling_bps: u64,
    pub aggregation_credit_units: u64,
    pub observed_fee_saved_piconero: u64,
}

impl PqOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "oracle_id": self.oracle_id,
            "cohort_id": self.cohort_id,
            "credit_id": self.credit_id,
            "status": self.status,
            "pq_security_bits": self.pq_security_bits,
            "attested_height": self.attested_height,
            "expires_height": self.expires_height,
            "statement_root": self.statement_root,
            "signature_root": self.signature_root,
            "rebate_ceiling_bps": self.rebate_ceiling_bps,
            "aggregation_credit_units": self.aggregation_credit_units,
            "observed_fee_saved_piconero": self.observed_fee_saved_piconero
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorSettlement {
    pub settlement_id: String,
    pub sponsor_id: String,
    pub sponsor_policy_id: String,
    pub status: SponsorSettlementStatus,
    pub cohort_id: String,
    pub intent_ids: Vec<String>,
    pub reserved_piconero: u64,
    pub paid_piconero: u64,
    pub refunded_piconero: u64,
    pub settlement_root: String,
    pub settlement_height: u64,
    pub expires_height: u64,
}

impl SponsorSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "sponsor_id": self.sponsor_id,
            "sponsor_policy_id": self.sponsor_policy_id,
            "status": self.status,
            "cohort_id": self.cohort_id,
            "intent_ids": self.intent_ids,
            "reserved_piconero": self.reserved_piconero,
            "paid_piconero": self.paid_piconero,
            "refunded_piconero": self.refunded_piconero,
            "settlement_root": self.settlement_root,
            "settlement_height": self.settlement_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseThrottle {
    pub throttle_id: String,
    pub bucket_id: String,
    pub status: AbuseThrottleStatus,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub intents_seen: u64,
    pub rebate_units_seen: u64,
    pub duplicate_nullifiers: u64,
    pub rejected_intents: u64,
    pub throttle_bps: u64,
    pub evidence_root: String,
}

impl AbuseThrottle {
    pub fn public_record(&self) -> Value {
        json!({
            "throttle_id": self.throttle_id,
            "bucket_id": self.bucket_id,
            "status": self.status,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "intents_seen": self.intents_seen,
            "rebate_units_seen": self.rebate_units_seen,
            "duplicate_nullifiers": self.duplicate_nullifiers,
            "rejected_intents": self.rejected_intents,
            "throttle_bps": self.throttle_bps,
            "evidence_root": self.evidence_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_bucket: String,
    pub status: RedactionBudgetStatus,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub reserved_units: u64,
    pub applied_units: u64,
    pub remaining_units: u64,
    pub redaction_policy_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_bucket": self.owner_bucket,
            "status": self.status,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "reserved_units": self.reserved_units,
            "applied_units": self.applied_units,
            "remaining_units": self.remaining_units,
            "redaction_policy_root": self.redaction_policy_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub audience: SummaryAudience,
    pub cohort_id: String,
    pub height: u64,
    pub bucket_size: u64,
    pub proof_count_bucket: u64,
    pub rebate_units_bucket: u64,
    pub settled_units_bucket: u64,
    pub throttle_count_bucket: u64,
    pub public_root: String,
    pub omitted_fields: Vec<String>,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "audience": self.audience,
            "cohort_id": self.cohort_id,
            "height": self.height,
            "bucket_size": self.bucket_size,
            "proof_count_bucket": self.proof_count_bucket,
            "rebate_units_bucket": self.rebate_units_bucket,
            "settled_units_bucket": self.settled_units_bucket,
            "throttle_count_bucket": self.throttle_count_bucket,
            "public_root": self.public_root,
            "omitted_fields": self.omitted_fields
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: RuntimeEventKind,
    pub height: u64,
    pub subject_id: String,
    pub detail_root: String,
    pub operator_safe: bool,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "height": self.height,
            "subject_id": self.subject_id,
            "detail_root": self.detail_root,
            "operator_safe": self.operator_safe
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SeraphisJamtisScanLane {
    pub lane_id: String,
    pub route_bucket: String,
    pub status: CohortStatus,
    pub output_count_bucket: u64,
    pub expected_scan_millis_bucket: u64,
    pub seraphis_membership_root: String,
    pub jamtis_address_commitment_root: String,
    pub dual_viewtag_root: String,
    pub decoy_shield_root: String,
    pub privacy_budget_id: String,
    pub sponsor_policy_id: String,
}

impl SeraphisJamtisScanLane {
    pub fn from_cohort(cohort: &ProofCohort, budget_id: impl Into<String>) -> Self {
        Self {
            lane_id: cohort.cohort_id.clone(),
            route_bucket: cohort.route_bucket.clone(),
            status: cohort.status,
            output_count_bucket: cohort.output_commitment_count,
            expected_scan_millis_bucket: cohort
                .proof_count
                .saturating_mul(1_000)
                .div_ceil(DEFAULT_TARGET_COHORT_PROOFS.max(1)),
            seraphis_membership_root: cohort.privacy_floor_root.clone(),
            jamtis_address_commitment_root: cohort.transcript_root.clone(),
            dual_viewtag_root: cohort.aggregation_root.clone(),
            decoy_shield_root: deterministic_id(
                "SERAPHIS-DECOY-SHIELD",
                &[HashPart::Str(&cohort.cohort_id)],
            ),
            privacy_budget_id: budget_id.into(),
            sponsor_policy_id: cohort.sponsor_policy_id.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "route_bucket": self.route_bucket,
            "status": self.status,
            "output_count_bucket": self.output_count_bucket,
            "expected_scan_millis_bucket": self.expected_scan_millis_bucket,
            "seraphis_membership_root": self.seraphis_membership_root,
            "jamtis_address_commitment_root": self.jamtis_address_commitment_root,
            "dual_viewtag_root": self.dual_viewtag_root,
            "decoy_shield_root": self.decoy_shield_root,
            "privacy_budget_id": self.privacy_budget_id,
            "sponsor_policy_id": self.sponsor_policy_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DualViewtagScanHint {
    pub hint_id: String,
    pub lane_id: String,
    pub primary_viewtag_bucket: String,
    pub secondary_viewtag_bucket: String,
    pub combined_hint_root: String,
    pub false_positive_budget: u64,
    pub anonymity_set_size: u64,
    pub nullifier: String,
}

impl DualViewtagScanHint {
    pub fn from_intent(intent: &FeeRebateIntent, anonymity_set_size: u64) -> Self {
        Self {
            hint_id: deterministic_id("DUAL-VIEWTAG-HINT", &[HashPart::Str(&intent.intent_id)]),
            lane_id: intent.cohort_id.clone(),
            primary_viewtag_bucket: intent.wallet_bucket.clone(),
            secondary_viewtag_bucket: intent.route_bucket.clone(),
            combined_hint_root: intent.fee_commitment_root.clone(),
            false_positive_budget: intent.rebate_units,
            anonymity_set_size,
            nullifier: intent.nullifier.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "lane_id": self.lane_id,
            "primary_viewtag_bucket": self.primary_viewtag_bucket,
            "secondary_viewtag_bucket": self.secondary_viewtag_bucket,
            "combined_hint_root": self.combined_hint_root,
            "false_positive_budget": self.false_positive_budget,
            "anonymity_set_size": self.anonymity_set_size,
            "nullifier": self.nullifier,
        })
    }
}

pub type ScanRebateOrder = FeeRebateIntent;
pub type PqSponsorReceipt = SponsorSettlement;
pub type SeraphisJamtisPrivacyBudget = RedactionBudget;
pub type DecoyScanShield = AbuseThrottle;
pub type SeraphisNullifierGuard = AggregationCredit;
pub type ScanOperatorSummary = OperatorSafeSummary;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub proof_cohorts: BTreeMap<String, ProofCohort>,
    pub aggregation_credits: BTreeMap<String, AggregationCredit>,
    pub rebate_intents: BTreeMap<String, FeeRebateIntent>,
    pub oracle_attestations: BTreeMap<String, PqOracleAttestation>,
    pub sponsor_settlements: BTreeMap<String, SponsorSettlement>,
    pub abuse_throttles: BTreeMap<String, AbuseThrottle>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: 1_024_000,
            proof_cohorts: BTreeMap::new(),
            aggregation_credits: BTreeMap::new(),
            rebate_intents: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            sponsor_settlements: BTreeMap::new(),
            abuse_throttles: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        };
        state.recompute();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default()).expect("default config is valid");
        state.seed_devnet();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn open_proof_cohort(
        &mut self,
        proof_count: u64,
        output_commitment_count: u64,
        route_bucket: impl Into<String>,
        sponsor_policy_id: impl Into<String>,
    ) -> Result<String> {
        if proof_count < self.config.min_cohort_proofs {
            return Err("proof cohort below minimum proof count".to_string());
        }
        if proof_count > self.config.max_cohort_proofs {
            return Err("proof cohort exceeds max proof count".to_string());
        }
        if output_commitment_count < self.config.min_output_commitments {
            return Err("proof cohort below output commitment floor".to_string());
        }

        let route_bucket = route_bucket.into();
        let sponsor_policy_id = sponsor_policy_id.into();
        let cohort_id = deterministic_id(
            "COHORT-ID",
            &[
                HashPart::U64(self.counters.proof_cohorts + 1),
                HashPart::U64(self.current_height),
                HashPart::Str(&route_bucket),
            ],
        );
        let transcript_root = deterministic_id("TRANSCRIPT", &[HashPart::Str(&cohort_id)]);
        let aggregation_root = deterministic_id("AGGREGATION", &[HashPart::Str(&cohort_id)]);
        let privacy_floor_root = deterministic_id("PRIVACY-FLOOR", &[HashPart::Str(&cohort_id)]);
        let cohort = ProofCohort {
            cohort_id: cohort_id.clone(),
            status: CohortStatus::Open,
            opened_height: self.current_height,
            close_height: self.current_height + self.config.max_window_blocks,
            proof_count,
            output_commitment_count,
            min_ring_size: self.config.min_ring_size,
            transcript_root,
            aggregation_root,
            privacy_floor_root,
            sponsor_policy_id,
            route_bucket,
            expected_rebate_bps: self.config.target_rebate_bps,
            privacy_notes: vec![
                "plain amounts redacted".to_string(),
                "proof bytes omitted".to_string(),
                "ring decoy graph withheld".to_string(),
            ],
        };
        self.proof_cohorts.insert(cohort_id.clone(), cohort);
        self.counters.proof_cohorts = self.proof_cohorts.len() as u64;
        self.record_event(RuntimeEventKind::CohortOpened, &cohort_id, true);
        self.recompute();
        Ok(cohort_id)
    }

    pub fn issue_aggregation_credit(&mut self, cohort_id: &str) -> Result<String> {
        let cohort = self
            .proof_cohorts
            .get_mut(cohort_id)
            .ok_or_else(|| format!("unknown cohort {cohort_id}"))?;
        if !cohort.accepts_intents() {
            return Err("cohort no longer accepts aggregation credit issuance".to_string());
        }
        let credit_units = rebate_units_for(
            cohort.proof_count,
            cohort.output_commitment_count,
            self.config.aggregation_credit_bps,
        );
        let credit_id = deterministic_id(
            "CREDIT-ID",
            &[HashPart::Str(cohort_id), HashPart::U64(credit_units)],
        );
        let credit = AggregationCredit {
            credit_id: credit_id.clone(),
            cohort_id: cohort_id.to_string(),
            status: AggregationCreditStatus::Metered,
            credit_units,
            aggregation_factor_bps: self.config.aggregation_credit_bps,
            proof_count: cohort.proof_count,
            output_commitment_count: cohort.output_commitment_count,
            marginal_fee_saved_piconero: credit_units.saturating_mul(1_000),
            transcript_root: cohort.transcript_root.clone(),
            metering_root: deterministic_id("METERING", &[HashPart::Str(&credit_id)]),
            nullifier_root: deterministic_id("NULLIFIER-ROOT", &[HashPart::Str(&credit_id)]),
            issued_height: self.current_height,
        };
        cohort.status = CohortStatus::CreditIssued;
        self.aggregation_credits.insert(credit_id.clone(), credit);
        self.counters.aggregation_credits = self.aggregation_credits.len() as u64;
        self.record_event(RuntimeEventKind::CreditIssued, &credit_id, true);
        self.recompute();
        Ok(credit_id)
    }

    pub fn queue_rebate_intent(
        &mut self,
        cohort_id: &str,
        credit_id: &str,
        wallet_bucket: impl Into<String>,
        rebate_units: u64,
    ) -> Result<String> {
        let wallet_bucket = wallet_bucket.into();
        let cohort = self
            .proof_cohorts
            .get(cohort_id)
            .ok_or_else(|| format!("unknown cohort {cohort_id}"))?;
        let _credit = self
            .aggregation_credits
            .get(credit_id)
            .ok_or_else(|| format!("unknown credit {credit_id}"))?;
        self.ensure_bucket_not_throttled(&wallet_bucket, rebate_units)?;
        let nullifier = deterministic_id(
            "REBATE-NULLIFIER",
            &[
                HashPart::Str(cohort_id),
                HashPart::Str(credit_id),
                HashPart::Str(&wallet_bucket),
                HashPart::U64(self.counters.rebate_intents + 1),
            ],
        );
        if !self.nullifiers.insert(nullifier.clone()) {
            return Err("duplicate rebate nullifier".to_string());
        }
        let budget_id = self.ensure_redaction_budget(&wallet_bucket)?;
        let intent_id = deterministic_id("REBATE-INTENT-ID", &[HashPart::Str(&nullifier)]);
        let intent = FeeRebateIntent {
            intent_id: intent_id.clone(),
            cohort_id: cohort_id.to_string(),
            credit_id: credit_id.to_string(),
            status: RebateIntentStatus::Payable,
            wallet_bucket: wallet_bucket.clone(),
            route_bucket: cohort.route_bucket.clone(),
            fee_commitment_root: deterministic_id("FEE-COMMITMENT", &[HashPart::Str(&intent_id)]),
            rebate_commitment_root: deterministic_id(
                "REBATE-COMMITMENT",
                &[HashPart::Str(&intent_id), HashPart::U64(rebate_units)],
            ),
            nullifier,
            requested_rebate_bps: self.config.target_rebate_bps,
            rebate_units,
            submitted_height: self.current_height,
            expires_height: self.current_height + self.config.settlement_ttl_blocks,
            sponsor_policy_id: cohort.sponsor_policy_id.clone(),
            redaction_budget_id: budget_id,
        };
        self.counters.open_rebate_units =
            self.counters.open_rebate_units.saturating_add(rebate_units);
        self.rebate_intents.insert(intent_id.clone(), intent);
        self.counters.rebate_intents = self.rebate_intents.len() as u64;
        self.record_event(RuntimeEventKind::IntentQueued, &intent_id, true);
        self.recompute();
        Ok(intent_id)
    }

    pub fn accept_oracle_attestation(
        &mut self,
        oracle_id: impl Into<String>,
        cohort_id: &str,
        credit_id: &str,
    ) -> Result<String> {
        let oracle_id = oracle_id.into();
        let credit = self
            .aggregation_credits
            .get(credit_id)
            .ok_or_else(|| format!("unknown credit {credit_id}"))?;
        if credit.cohort_id != cohort_id {
            return Err("credit does not belong to cohort".to_string());
        }
        let attestation_id = deterministic_id(
            "ORACLE-ATTESTATION-ID",
            &[HashPart::Str(&oracle_id), HashPart::Str(credit_id)],
        );
        let attestation = PqOracleAttestation {
            attestation_id: attestation_id.clone(),
            oracle_id,
            cohort_id: cohort_id.to_string(),
            credit_id: credit_id.to_string(),
            status: OracleAttestationStatus::Accepted,
            pq_security_bits: self.config.target_pq_security_bits,
            attested_height: self.current_height,
            expires_height: self.current_height + self.config.attestation_ttl_blocks,
            statement_root: deterministic_id("ORACLE-STATEMENT", &[HashPart::Str(&attestation_id)]),
            signature_root: deterministic_id("PQ-SIGNATURE", &[HashPart::Str(&attestation_id)]),
            rebate_ceiling_bps: self.config.max_rebate_bps,
            aggregation_credit_units: credit.credit_units,
            observed_fee_saved_piconero: credit.marginal_fee_saved_piconero,
        };
        self.oracle_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.oracle_attestations = self.oracle_attestations.len() as u64;
        self.update_oracle_quorum(cohort_id, credit_id);
        self.record_event(RuntimeEventKind::OracleAttested, &attestation_id, true);
        self.recompute();
        Ok(attestation_id)
    }

    pub fn reserve_sponsor_settlement(
        &mut self,
        sponsor_id: impl Into<String>,
        cohort_id: &str,
    ) -> Result<String> {
        let sponsor_id = sponsor_id.into();
        let cohort = self
            .proof_cohorts
            .get(cohort_id)
            .ok_or_else(|| format!("unknown cohort {cohort_id}"))?;
        let intent_ids = self
            .rebate_intents
            .values()
            .filter(|intent| {
                intent.cohort_id == cohort_id && intent.status.eligible_for_settlement()
            })
            .map(|intent| intent.intent_id.clone())
            .collect::<Vec<_>>();
        if intent_ids.is_empty() {
            return Err("no payable rebate intents for cohort".to_string());
        }
        let total_units = intent_ids
            .iter()
            .filter_map(|id| self.rebate_intents.get(id))
            .map(|intent| intent.rebate_units)
            .sum::<u64>();
        let reserved_piconero = total_units
            .saturating_mul(self.config.sponsor_cover_bps)
            .saturating_div(MAX_BPS);
        let settlement_id = deterministic_id(
            "SPONSOR-SETTLEMENT-ID",
            &[
                HashPart::Str(&sponsor_id),
                HashPart::Str(cohort_id),
                HashPart::U64(total_units),
            ],
        );
        for intent_id in &intent_ids {
            if let Some(intent) = self.rebate_intents.get_mut(intent_id) {
                intent.status = RebateIntentStatus::SponsorReserved;
            }
        }
        let settlement = SponsorSettlement {
            settlement_id: settlement_id.clone(),
            sponsor_id,
            sponsor_policy_id: cohort.sponsor_policy_id.clone(),
            status: SponsorSettlementStatus::Reserved,
            cohort_id: cohort_id.to_string(),
            intent_ids,
            reserved_piconero,
            paid_piconero: 0,
            refunded_piconero: 0,
            settlement_root: deterministic_id(
                "SPONSOR-SETTLEMENT",
                &[
                    HashPart::Str(&settlement_id),
                    HashPart::U64(reserved_piconero),
                ],
            ),
            settlement_height: self.current_height,
            expires_height: self.current_height + self.config.settlement_ttl_blocks,
        };
        self.sponsor_settlements
            .insert(settlement_id.clone(), settlement);
        self.counters.sponsor_settlements = self.sponsor_settlements.len() as u64;
        self.record_event(RuntimeEventKind::SponsorReserved, &settlement_id, true);
        self.recompute();
        Ok(settlement_id)
    }

    pub fn finalize_sponsor_settlement(&mut self, settlement_id: &str) -> Result<()> {
        let settlement = self
            .sponsor_settlements
            .get_mut(settlement_id)
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        if settlement.status != SponsorSettlementStatus::Reserved {
            return Err("settlement is not reserved".to_string());
        }
        let mut paid_units = 0_u64;
        for intent_id in settlement.intent_ids.clone() {
            if let Some(intent) = self.rebate_intents.get_mut(&intent_id) {
                paid_units = paid_units.saturating_add(intent.rebate_units);
                intent.status = RebateIntentStatus::Paid;
            }
        }
        settlement.paid_piconero = paid_units;
        settlement.refunded_piconero = settlement.reserved_piconero.saturating_sub(paid_units);
        settlement.status = SponsorSettlementStatus::Finalized;
        self.counters.open_rebate_units =
            self.counters.open_rebate_units.saturating_sub(paid_units);
        self.counters.settled_rebate_units = self
            .counters
            .settled_rebate_units
            .saturating_add(paid_units);
        if let Some(cohort) = self.proof_cohorts.get_mut(&settlement.cohort_id) {
            cohort.status = CohortStatus::Settled;
        }
        self.record_event(RuntimeEventKind::SettlementFinalized, settlement_id, true);
        self.recompute();
        Ok(())
    }

    pub fn apply_abuse_throttle(
        &mut self,
        bucket_id: impl Into<String>,
        intents_seen: u64,
        rebate_units_seen: u64,
        duplicate_nullifiers: u64,
    ) -> Result<String> {
        let bucket_id = bucket_id.into();
        let status = if duplicate_nullifiers > 0
            || intents_seen > self.config.max_intents_per_bucket
            || rebate_units_seen > self.config.max_rebate_units_per_bucket
        {
            AbuseThrottleStatus::HardLimited
        } else {
            AbuseThrottleStatus::SoftLimited
        };
        let throttle_id = deterministic_id(
            "THROTTLE-ID",
            &[
                HashPart::Str(&bucket_id),
                HashPart::U64(self.current_height),
                HashPart::U64(intents_seen),
                HashPart::U64(rebate_units_seen),
            ],
        );
        let throttle = AbuseThrottle {
            throttle_id: throttle_id.clone(),
            bucket_id,
            status,
            window_start_height: self.current_height,
            window_end_height: self.current_height + self.config.throttle_window_blocks,
            intents_seen,
            rebate_units_seen,
            duplicate_nullifiers,
            rejected_intents: 0,
            throttle_bps: if status == AbuseThrottleStatus::HardLimited {
                MAX_BPS
            } else {
                5_000
            },
            evidence_root: deterministic_id("THROTTLE-EVIDENCE", &[HashPart::Str(&throttle_id)]),
        };
        self.abuse_throttles.insert(throttle_id.clone(), throttle);
        self.counters.abuse_throttles = self.abuse_throttles.len() as u64;
        self.counters.throttled_buckets = self
            .abuse_throttles
            .values()
            .filter(|throttle| throttle.status == AbuseThrottleStatus::HardLimited)
            .count() as u64;
        self.record_event(RuntimeEventKind::ThrottleApplied, &throttle_id, true);
        self.recompute();
        Ok(throttle_id)
    }

    pub fn publish_operator_summary(
        &mut self,
        audience: SummaryAudience,
        cohort_id: &str,
    ) -> Result<String> {
        let cohort = self
            .proof_cohorts
            .get(cohort_id)
            .ok_or_else(|| format!("unknown cohort {cohort_id}"))?;
        let bucket = self.config.operator_bucket_size.max(1);
        let rebate_units = self
            .rebate_intents
            .values()
            .filter(|intent| intent.cohort_id == cohort_id)
            .map(|intent| intent.rebate_units)
            .sum::<u64>();
        let settled_units = self
            .rebate_intents
            .values()
            .filter(|intent| {
                intent.cohort_id == cohort_id && intent.status == RebateIntentStatus::Paid
            })
            .map(|intent| intent.rebate_units)
            .sum::<u64>();
        let throttle_count = self
            .abuse_throttles
            .values()
            .filter(|throttle| throttle.status != AbuseThrottleStatus::Cleared)
            .count() as u64;
        let summary_id = deterministic_id(
            "OPERATOR-SUMMARY-ID",
            &[
                HashPart::Str(cohort_id),
                HashPart::U64(self.current_height),
                HashPart::U64(self.counters.operator_summaries + 1),
            ],
        );
        let summary = OperatorSafeSummary {
            summary_id: summary_id.clone(),
            audience,
            cohort_id: cohort_id.to_string(),
            height: self.current_height,
            bucket_size: bucket,
            proof_count_bucket: round_up_bucket(cohort.proof_count, bucket),
            rebate_units_bucket: round_up_bucket(rebate_units, bucket),
            settled_units_bucket: round_up_bucket(settled_units, bucket),
            throttle_count_bucket: round_up_bucket(throttle_count, bucket),
            public_root: deterministic_id("OPERATOR-SAFE-PUBLIC", &[HashPart::Str(&summary_id)]),
            omitted_fields: vec![
                "wallet_bucket_exact".to_string(),
                "plain_fee_amounts".to_string(),
                "view_keys".to_string(),
                "key_images".to_string(),
                "proof_bytes".to_string(),
                "decoy_graph".to_string(),
            ],
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.record_event(RuntimeEventKind::SummaryPublished, &summary_id, true);
        self.recompute();
        Ok(summary_id)
    }

    fn ensure_bucket_not_throttled(&self, bucket_id: &str, rebate_units: u64) -> Result<()> {
        for throttle in self.abuse_throttles.values() {
            if throttle.bucket_id == bucket_id
                && throttle.window_end_height >= self.current_height
                && throttle.status == AbuseThrottleStatus::HardLimited
            {
                return Err(format!("bucket {bucket_id} is hard limited"));
            }
        }
        if rebate_units > self.config.max_rebate_units_per_bucket {
            return Err("rebate units exceed bucket throttle limit".to_string());
        }
        Ok(())
    }

    fn ensure_redaction_budget(&mut self, owner_bucket: &str) -> Result<String> {
        if let Some(budget) = self.redaction_budgets.values_mut().find(|budget| {
            budget.owner_bucket == owner_bucket
                && budget.status == RedactionBudgetStatus::Open
                && budget.epoch_end_height >= self.current_height
        }) {
            budget.reserved_units = budget.reserved_units.saturating_add(1);
            budget.remaining_units = budget.remaining_units.saturating_sub(1);
            self.counters.redaction_units_reserved =
                self.counters.redaction_units_reserved.saturating_add(1);
            return Ok(budget.budget_id.clone());
        }
        let budget_id = deterministic_id(
            "REDACTION-BUDGET-ID",
            &[
                HashPart::Str(owner_bucket),
                HashPart::U64(self.current_height / self.config.redaction_epoch_blocks.max(1)),
            ],
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            owner_bucket: owner_bucket.to_string(),
            status: RedactionBudgetStatus::Open,
            epoch_start_height: self.current_height,
            epoch_end_height: self.current_height + self.config.redaction_epoch_blocks,
            reserved_units: 1,
            applied_units: 0,
            remaining_units: self.config.max_redaction_units_per_epoch.saturating_sub(1),
            redaction_policy_root: deterministic_id(
                "REDACTION-POLICY",
                &[HashPart::Str(&budget_id), HashPart::Str(PRIVACY_BOUNDARY)],
            ),
        };
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.redaction_units_reserved =
            self.counters.redaction_units_reserved.saturating_add(1);
        self.record_event(RuntimeEventKind::RedactionBudgetApplied, &budget_id, true);
        Ok(budget_id)
    }

    fn update_oracle_quorum(&mut self, cohort_id: &str, credit_id: &str) {
        let accepted = self
            .oracle_attestations
            .values()
            .filter(|attestation| {
                attestation.cohort_id == cohort_id
                    && attestation.credit_id == credit_id
                    && attestation.status.counts_for_quorum()
            })
            .count() as u64;
        let status = if accepted >= 3 {
            OracleAttestationStatus::StrongQuorum
        } else if accepted >= 2 {
            OracleAttestationStatus::Quorum
        } else {
            OracleAttestationStatus::Accepted
        };
        for attestation in self.oracle_attestations.values_mut().filter(|attestation| {
            attestation.cohort_id == cohort_id && attestation.credit_id == credit_id
        }) {
            attestation.status = status;
        }
        if let Some(credit) = self.aggregation_credits.get_mut(credit_id) {
            credit.status = if accepted >= 2 {
                AggregationCreditStatus::OracleAttested
            } else {
                AggregationCreditStatus::Matched
            };
        }
        if let Some(cohort) = self.proof_cohorts.get_mut(cohort_id) {
            cohort.status = if accepted >= 2 {
                CohortStatus::RebateQueued
            } else {
                CohortStatus::Attesting
            };
        }
    }

    fn record_event(&mut self, kind: RuntimeEventKind, subject_id: &str, operator_safe: bool) {
        let event_id = deterministic_id(
            "EVENT-ID",
            &[
                HashPart::U64(self.counters.events + 1),
                HashPart::U64(self.current_height),
                HashPart::Str(subject_id),
            ],
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind,
            height: self.current_height,
            subject_id: subject_id.to_string(),
            detail_root: deterministic_id("EVENT-DETAIL", &[HashPart::Str(subject_id)]),
            operator_safe,
        };
        self.events.insert(event_id, event);
        self.counters.events = self.events.len() as u64;
    }

    fn public_record_without_state_root(&self) -> Value {
        let mut roots = self.roots.clone();
        roots.config_root = value_root("CONFIG", &self.config.public_record());
        roots.proof_cohort_root = map_root(
            "PROOF-COHORTS",
            self.proof_cohorts
                .values()
                .map(ProofCohort::public_record)
                .collect(),
        );
        roots.aggregation_credit_root = map_root(
            "AGGREGATION-CREDITS",
            self.aggregation_credits
                .values()
                .map(AggregationCredit::public_record)
                .collect(),
        );
        roots.rebate_intent_root = map_root(
            "REBATE-INTENTS",
            self.rebate_intents
                .values()
                .map(FeeRebateIntent::public_record)
                .collect(),
        );
        roots.oracle_attestation_root = map_root(
            "ORACLE-ATTESTATIONS",
            self.oracle_attestations
                .values()
                .map(PqOracleAttestation::public_record)
                .collect(),
        );
        roots.sponsor_settlement_root = map_root(
            "SPONSOR-SETTLEMENTS",
            self.sponsor_settlements
                .values()
                .map(SponsorSettlement::public_record)
                .collect(),
        );
        roots.abuse_throttle_root = map_root(
            "ABUSE-THROTTLES",
            self.abuse_throttles
                .values()
                .map(AbuseThrottle::public_record)
                .collect(),
        );
        roots.redaction_budget_root = map_root(
            "REDACTION-BUDGETS",
            self.redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect(),
        );
        roots.operator_summary_root = map_root(
            "OPERATOR-SUMMARIES",
            self.operator_summaries
                .values()
                .map(OperatorSafeSummary::public_record)
                .collect(),
        );
        roots.event_root = map_root(
            "EVENTS",
            self.events
                .values()
                .map(RuntimeEvent::public_record)
                .collect(),
        );
        roots.public_record_root = domain_hash(
            "SERAPHIS-JAMTIS-SCAN-MARKET-PUBLIC-RECORD",
            &[
                HashPart::Str(&roots.config_root),
                HashPart::Str(&roots.proof_cohort_root),
                HashPart::Str(&roots.aggregation_credit_root),
                HashPart::Str(&roots.rebate_intent_root),
                HashPart::Str(&roots.oracle_attestation_root),
                HashPart::Str(&roots.sponsor_settlement_root),
                HashPart::Str(&roots.abuse_throttle_root),
                HashPart::Str(&roots.redaction_budget_root),
                HashPart::Str(&roots.operator_summary_root),
                HashPart::Str(&roots.event_root),
            ],
            32,
        );
        json!({
            "kind": "monero_l2_pq_private_seraphis_jamtis_dual_viewtag_scan_market_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "proof_cohorts": self.proof_cohorts.values().map(ProofCohort::public_record).collect::<Vec<_>>(),
            "aggregation_credits": self.aggregation_credits.values().map(AggregationCredit::public_record).collect::<Vec<_>>(),
            "rebate_intents": self.rebate_intents.values().map(FeeRebateIntent::public_record).collect::<Vec<_>>(),
            "oracle_attestations": self.oracle_attestations.values().map(PqOracleAttestation::public_record).collect::<Vec<_>>(),
            "sponsor_settlements": self.sponsor_settlements.values().map(SponsorSettlement::public_record).collect::<Vec<_>>(),
            "abuse_throttles": self.abuse_throttles.values().map(AbuseThrottle::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSafeSummary::public_record).collect::<Vec<_>>(),
            "events": self.events.values().map(RuntimeEvent::public_record).collect::<Vec<_>>(),
            "nullifier_count": self.nullifiers.len() as u64
        })
    }

    fn recompute(&mut self) {
        self.counters.proof_cohorts = self.proof_cohorts.len() as u64;
        self.counters.aggregation_credits = self.aggregation_credits.len() as u64;
        self.counters.rebate_intents = self.rebate_intents.len() as u64;
        self.counters.oracle_attestations = self.oracle_attestations.len() as u64;
        self.counters.sponsor_settlements = self.sponsor_settlements.len() as u64;
        self.counters.abuse_throttles = self.abuse_throttles.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.events = self.events.len() as u64;
        self.roots.config_root = value_root("CONFIG", &self.config.public_record());
        self.roots.proof_cohort_root = map_root(
            "PROOF-COHORTS",
            self.proof_cohorts
                .values()
                .map(ProofCohort::public_record)
                .collect(),
        );
        self.roots.aggregation_credit_root = map_root(
            "AGGREGATION-CREDITS",
            self.aggregation_credits
                .values()
                .map(AggregationCredit::public_record)
                .collect(),
        );
        self.roots.rebate_intent_root = map_root(
            "REBATE-INTENTS",
            self.rebate_intents
                .values()
                .map(FeeRebateIntent::public_record)
                .collect(),
        );
        self.roots.oracle_attestation_root = map_root(
            "ORACLE-ATTESTATIONS",
            self.oracle_attestations
                .values()
                .map(PqOracleAttestation::public_record)
                .collect(),
        );
        self.roots.sponsor_settlement_root = map_root(
            "SPONSOR-SETTLEMENTS",
            self.sponsor_settlements
                .values()
                .map(SponsorSettlement::public_record)
                .collect(),
        );
        self.roots.abuse_throttle_root = map_root(
            "ABUSE-THROTTLES",
            self.abuse_throttles
                .values()
                .map(AbuseThrottle::public_record)
                .collect(),
        );
        self.roots.redaction_budget_root = map_root(
            "REDACTION-BUDGETS",
            self.redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect(),
        );
        self.roots.operator_summary_root = map_root(
            "OPERATOR-SUMMARIES",
            self.operator_summaries
                .values()
                .map(OperatorSafeSummary::public_record)
                .collect(),
        );
        self.roots.event_root = map_root(
            "EVENTS",
            self.events
                .values()
                .map(RuntimeEvent::public_record)
                .collect(),
        );
        self.roots.public_record_root = value_root(
            "PUBLIC-RECORD",
            &json!({
                "config_root": self.roots.config_root,
                "proof_cohort_root": self.roots.proof_cohort_root,
                "aggregation_credit_root": self.roots.aggregation_credit_root,
                "rebate_intent_root": self.roots.rebate_intent_root,
                "oracle_attestation_root": self.roots.oracle_attestation_root,
                "sponsor_settlement_root": self.roots.sponsor_settlement_root,
                "abuse_throttle_root": self.roots.abuse_throttle_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "operator_summary_root": self.roots.operator_summary_root,
                "event_root": self.roots.event_root
            }),
        );
    }

    fn seed_devnet(&mut self) {
        let cohort_a = self
            .open_proof_cohort(
                128,
                256,
                "route-bucket-mainnet-fee-00",
                "sponsor-policy-core",
            )
            .expect("devnet cohort");
        let credit_a = self
            .issue_aggregation_credit(&cohort_a)
            .expect("devnet credit");
        let _intent_a = self
            .queue_rebate_intent(&cohort_a, &credit_a, "wallet-bucket-000", 512)
            .expect("devnet intent a");
        let _intent_b = self
            .queue_rebate_intent(&cohort_a, &credit_a, "wallet-bucket-001", 384)
            .expect("devnet intent b");
        self.accept_oracle_attestation("oracle-alpha-pq", &cohort_a, &credit_a)
            .expect("oracle alpha");
        self.accept_oracle_attestation("oracle-beta-pq", &cohort_a, &credit_a)
            .expect("oracle beta");
        let settlement = self
            .reserve_sponsor_settlement("sponsor-fee-relay-0", &cohort_a)
            .expect("sponsor settlement");
        self.finalize_sponsor_settlement(&settlement)
            .expect("finalize settlement");
        self.publish_operator_summary(SummaryAudience::Operator, &cohort_a)
            .expect("operator summary");

        let cohort_b = self
            .open_proof_cohort(
                64,
                128,
                "route-bucket-merchant-02",
                "sponsor-policy-merchant",
            )
            .expect("devnet cohort b");
        let credit_b = self
            .issue_aggregation_credit(&cohort_b)
            .expect("devnet credit b");
        self.queue_rebate_intent(&cohort_b, &credit_b, "wallet-bucket-merchant", 192)
            .expect("devnet intent c");
        self.accept_oracle_attestation("oracle-gamma-pq", &cohort_b, &credit_b)
            .expect("oracle gamma");
        self.apply_abuse_throttle(
            "wallet-bucket-watchlist",
            self.config.max_intents_per_bucket + 8,
            self.config.max_rebate_units_per_bucket + 16,
            1,
        )
        .expect("devnet throttle");
        self.publish_operator_summary(SummaryAudience::Public, &cohort_b)
            .expect("public summary");
        self.recompute();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "SERAPHIS-JAMTIS-DUAL-VIEWTAG-SCAN-MARKET-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("SERAPHIS-JAMTIS-SCAN-MARKET-{domain}"), parts, 32)
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("SERAPHIS-JAMTIS-SCAN-MARKET-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(&format!("SERAPHIS-JAMTIS-SCAN-MARKET-{domain}"), &[])
}

pub fn map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("SERAPHIS-JAMTIS-SCAN-MARKET-{domain}"), &records)
}

pub fn rebate_units_for(
    proof_count: u64,
    output_commitment_count: u64,
    aggregation_credit_bps: u64,
) -> u64 {
    proof_count
        .saturating_mul(output_commitment_count.max(1))
        .saturating_mul(aggregation_credit_bps)
        .saturating_div(MAX_BPS)
}

pub fn round_up_bucket(value: u64, bucket: u64) -> u64 {
    if bucket == 0 || value == 0 {
        return value;
    }
    value.div_ceil(bucket).saturating_mul(bucket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_public_record_has_state_root() {
        let state = State::devnet();
        let record = state.public_record();
        assert_eq!(record["state_root"], json!(state.state_root()));
        assert!(state.counters.proof_cohorts >= 2);
        assert!(state.counters.oracle_attestations >= 3);
    }

    #[test]
    fn rebate_unit_metering_is_deterministic() {
        assert_eq!(rebate_units_for(128, 256, 3_500), 11_468);
        assert_eq!(round_up_bucket(65, 64), 128);
    }
}
