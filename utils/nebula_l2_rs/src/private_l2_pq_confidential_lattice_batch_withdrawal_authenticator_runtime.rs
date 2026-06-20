use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_BATCH_WITHDRAWAL_AUTHENTICATOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-lattice-batch-withdrawal-authenticator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_BATCH_WITHDRAWAL_AUTHENTICATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const CHAIN_ID: &str = "nebula-private-l2-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-lattice-batch-withdrawal-authenticator-public-record-v1";
pub const SEALED_BATCH_SUITE: &str = "monero-bridge-sealed-withdrawal-batch-operator-safe-root-v1";
pub const PQ_COHORT_SUITE: &str = "ml-dsa-falcon-slh-dsa-withdrawal-signer-cohort-root-v1";
pub const KEY_IMAGE_NULLIFIER_HINT_SUITE: &str = "ringct-seraphis-key-image-nullifier-hint-root-v1";
pub const AUTHENTICATION_TICKET_SUITE: &str =
    "confidential-withdrawal-authentication-ticket-root-v1";
pub const QUARANTINE_SUITE: &str = "lattice-withdrawal-slashing-quarantine-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str =
    "private-l2-low-fee-withdrawal-authentication-rebate-root-v1";
pub const REDACTION_BUDGET_SUITE: &str = "withdrawal-authenticator-redaction-budget-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_monero_addresses_amounts_key_images_nullifiers_view_keys_or_spend_keys";
pub const DEVNET_L2_HEIGHT: u64 = 2_440_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_812_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_WITHDRAWALS_PER_BATCH: usize = 512;
pub const DEFAULT_AUTH_TICKET_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_BATCH_SEAL_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 50_000;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 12;
pub const DEFAULT_MIN_ANONYMITY_SET: u64 = 65_536;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_COHORTS: usize = 262_144;
pub const MAX_BATCHES: usize = 1_048_576;
pub const MAX_HINTS: usize = 4_194_304;
pub const MAX_TICKETS: usize = 2_097_152;
pub const MAX_QUARANTINES: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalLane {
    RetailBridge,
    LiquidityProvider,
    DefiSettlement,
    EmergencyExit,
}

impl WithdrawalLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailBridge => "retail_bridge",
            Self::LiquidityProvider => "liquidity_provider",
            Self::DefiSettlement => "defi_settlement",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignerFamily {
    MlDsa87,
    Falcon1024,
    SlhDsaShake256f,
    HybridFence,
}

impl PqSignerFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::Falcon1024 => "falcon_1024",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridFence => "hybrid_fence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Candidate,
    Active,
    CoolingDown,
    Quarantined,
    Retired,
}

impl CohortStatus {
    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Active | Self::CoolingDown)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Sealed,
    Authenticating,
    Authenticated,
    Ticketed,
    Settled,
    Disputed,
    Quarantined,
    Rejected,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Authenticating => "authenticating",
            Self::Authenticated => "authenticated",
            Self::Ticketed => "ticketed",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintKind {
    RingCtKeyImage,
    SeraphisNullifier,
    HybridKeyImageNullifier,
    ReplayFence,
}

impl HintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RingCtKeyImage => "ringct_key_image",
            Self::SeraphisNullifier => "seraphis_nullifier",
            Self::HybridKeyImageNullifier => "hybrid_key_image_nullifier",
            Self::ReplayFence => "replay_fence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Reserved,
    Issued,
    Redeemed,
    Expired,
    Revoked,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Issued => "issued",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    InvalidPqQuorum,
    DuplicateNullifierHint,
    BatchSealMismatch,
    TicketReplay,
    RedactionBudgetExceeded,
    FeeRebateAbuse,
    OperatorChallenge,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqQuorum => "invalid_pq_quorum",
            Self::DuplicateNullifierHint => "duplicate_nullifier_hint",
            Self::BatchSealMismatch => "batch_seal_mismatch",
            Self::TicketReplay => "ticket_replay",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::FeeRebateAbuse => "fee_rebate_abuse",
            Self::OperatorChallenge => "operator_challenge",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_pq_security_bits: u16,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_withdrawals_per_batch: usize,
    pub auth_ticket_ttl_blocks: u64,
    pub batch_seal_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub redaction_budget_units: u64,
    pub low_fee_rebate_bps: u64,
    pub min_anonymity_set: u64,
    pub allowed_lanes: BTreeSet<WithdrawalLane>,
    pub allowed_signer_families: BTreeSet<PqSignerFamily>,
    pub require_key_image_nullifier_hints: bool,
    pub require_public_record_redaction: bool,
    pub allow_low_fee_rebates: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_withdrawals_per_batch: DEFAULT_MAX_WITHDRAWALS_PER_BATCH,
            auth_ticket_ttl_blocks: DEFAULT_AUTH_TICKET_TTL_BLOCKS,
            batch_seal_ttl_blocks: DEFAULT_BATCH_SEAL_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            min_anonymity_set: DEFAULT_MIN_ANONYMITY_SET,
            allowed_lanes: BTreeSet::from([
                WithdrawalLane::RetailBridge,
                WithdrawalLane::LiquidityProvider,
                WithdrawalLane::DefiSettlement,
                WithdrawalLane::EmergencyExit,
            ]),
            allowed_signer_families: BTreeSet::from([
                PqSignerFamily::MlDsa87,
                PqSignerFamily::Falcon1024,
                PqSignerFamily::SlhDsaShake256f,
            ]),
            require_key_image_nullifier_hints: true,
            require_public_record_redaction: true,
            allow_low_fee_rebates: true,
        }
    }

    pub fn validate(
        &self,
    ) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<()> {
        require(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version",
        )?;
        require(!self.chain_id.is_empty(), "chain id is required")?;
        require(self.quorum_bps <= MAX_BPS, "quorum exceeds bps scale")?;
        require(
            self.strong_quorum_bps >= self.quorum_bps && self.strong_quorum_bps <= MAX_BPS,
            "strong quorum must dominate quorum",
        )?;
        require(
            self.max_withdrawals_per_batch > 0
                && self.max_withdrawals_per_batch <= DEFAULT_MAX_WITHDRAWALS_PER_BATCH,
            "invalid withdrawal batch size",
        )?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security floor is too low",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "hash_suite": HASH_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "sealed_batch_suite": SEALED_BATCH_SUITE,
            "pq_cohort_suite": PQ_COHORT_SUITE,
            "key_image_nullifier_hint_suite": KEY_IMAGE_NULLIFIER_HINT_SUITE,
            "authentication_ticket_suite": AUTHENTICATION_TICKET_SUITE,
            "quarantine_suite": QUARANTINE_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "redaction_budget_suite": REDACTION_BUDGET_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_bps": self.quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "max_withdrawals_per_batch": self.max_withdrawals_per_batch,
            "auth_ticket_ttl_blocks": self.auth_ticket_ttl_blocks,
            "batch_seal_ttl_blocks": self.batch_seal_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "min_anonymity_set": self.min_anonymity_set,
            "allowed_lanes": self.allowed_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "allowed_signer_families": self.allowed_signer_families.iter().map(|family| family.as_str()).collect::<Vec<_>>(),
            "require_key_image_nullifier_hints": self.require_key_image_nullifier_hints,
            "require_public_record_redaction": self.require_public_record_redaction,
            "allow_low_fee_rebates": self.allow_low_fee_rebates,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub signer_cohorts: u64,
    pub sealed_batches: u64,
    pub key_image_nullifier_hints: u64,
    pub authentication_tickets: u64,
    pub quarantines: u64,
    pub low_fee_rebates: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
    pub authenticated_withdrawals: u64,
    pub quarantined_withdrawals: u64,
    pub total_rebate_micronero: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub signer_cohort_root: String,
    pub sealed_batch_root: String,
    pub key_image_nullifier_hint_root: String,
    pub authentication_ticket_root: String,
    pub quarantine_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignerCohort {
    pub cohort_id: String,
    pub family: PqSignerFamily,
    pub status: CohortStatus,
    pub operator_set_commitment: String,
    pub public_key_root: String,
    pub stake_root: String,
    pub policy_root: String,
    pub signer_count: u64,
    pub aggregate_weight: u64,
    pub pq_security_bits: u16,
    pub active_from_height: u64,
    pub last_heartbeat_height: u64,
}

impl PqSignerCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "family": self.family.as_str(),
            "status": self.status.as_str(),
            "operator_set_commitment": self.operator_set_commitment,
            "public_key_root": self.public_key_root,
            "stake_root": self.stake_root,
            "policy_root": self.policy_root,
            "signer_count": self.signer_count,
            "aggregate_weight": self.aggregate_weight,
            "pq_security_bits": self.pq_security_bits,
            "active_from_height": self.active_from_height,
            "last_heartbeat_height": self.last_heartbeat_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedWithdrawalBatch {
    pub batch_id: String,
    pub lane: WithdrawalLane,
    pub cohort_id: String,
    pub sealed_withdrawal_root: String,
    pub encrypted_destination_root: String,
    pub amount_commitment_root: String,
    pub fee_policy_root: String,
    pub hint_set_root: String,
    pub withdrawal_count: u64,
    pub anonymity_set_size: u64,
    pub fee_paid_micronero: u64,
    pub sealed_height: u64,
    pub expires_height: u64,
    pub status: BatchStatus,
}

impl SealedWithdrawalBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "cohort_id": self.cohort_id,
            "sealed_withdrawal_root": self.sealed_withdrawal_root,
            "encrypted_destination_root": self.encrypted_destination_root,
            "amount_commitment_root": self.amount_commitment_root,
            "fee_policy_root": self.fee_policy_root,
            "hint_set_root": self.hint_set_root,
            "withdrawal_count": self.withdrawal_count,
            "anonymity_set_size": self.anonymity_set_size,
            "fee_paid_micronero": self.fee_paid_micronero,
            "sealed_height": self.sealed_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyImageNullifierHint {
    pub hint_id: String,
    pub batch_id: String,
    pub kind: HintKind,
    pub bucket_tag: String,
    pub hint_commitment_root: String,
    pub decoy_context_root: String,
    pub replay_fence_root: String,
    pub observed_height: u64,
    pub redaction_budget_id: String,
}

impl KeyImageNullifierHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "batch_id": self.batch_id,
            "kind": self.kind.as_str(),
            "bucket_tag": self.bucket_tag,
            "hint_commitment_root": self.hint_commitment_root,
            "decoy_context_root": self.decoy_context_root,
            "replay_fence_root": self.replay_fence_root,
            "observed_height": self.observed_height,
            "redaction_budget_id": self.redaction_budget_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthenticationTicket {
    pub ticket_id: String,
    pub batch_id: String,
    pub cohort_id: String,
    pub auth_transcript_root: String,
    pub pq_signature_root: String,
    pub withdrawal_gate_root: String,
    pub status: TicketStatus,
    pub quorum_bps: u64,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl AuthenticationTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "batch_id": self.batch_id,
            "cohort_id": self.cohort_id,
            "auth_transcript_root": self.auth_transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "withdrawal_gate_root": self.withdrawal_gate_root,
            "status": self.status.as_str(),
            "quorum_bps": self.quorum_bps,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingQuarantine {
    pub quarantine_id: String,
    pub batch_id: String,
    pub offender_commitment: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub penalty_root: String,
    pub quarantined_height: u64,
    pub releases_height: u64,
}

impl SlashingQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "batch_id": self.batch_id,
            "offender_commitment": self.offender_commitment,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "penalty_root": self.penalty_root,
            "quarantined_height": self.quarantined_height,
            "releases_height": self.releases_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeVerificationRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub rebate_commitment: String,
    pub fee_paid_micronero: u64,
    pub rebate_micronero: u64,
    pub issued_height: u64,
}

impl LowFeeVerificationRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub scope_root: String,
    pub allocated_units: u64,
    pub consumed_units: u64,
    pub controller_commitment: String,
    pub expires_height: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub subject_id: String,
    pub kind: String,
    pub payload_root: String,
    pub published_height: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub signer_cohorts: BTreeMap<String, PqSignerCohort>,
    pub sealed_batches: BTreeMap<String, SealedWithdrawalBatch>,
    pub key_image_nullifier_hints: BTreeMap<String, KeyImageNullifierHint>,
    pub authentication_tickets: BTreeMap<String, AuthenticationTicket>,
    pub slashing_quarantines: BTreeMap<String, SlashingQuarantine>,
    pub low_fee_rebates: BTreeMap<String, LowFeeVerificationRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub quarantined_batches: BTreeSet<String>,
}

impl State {
    pub fn new(
        config: Config,
    ) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            signer_cohorts: BTreeMap::new(),
            sealed_batches: BTreeMap::new(),
            key_image_nullifier_hints: BTreeMap::new(),
            authentication_tickets: BTreeMap::new(),
            slashing_quarantines: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            quarantined_batches: BTreeSet::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        let cohort = PqSignerCohort {
            cohort_id: deterministic_id("cohort", &["devnet", "withdrawal", "pq"]),
            family: PqSignerFamily::MlDsa87,
            status: CohortStatus::Active,
            operator_set_commitment: fixed_root("devnet-withdrawal-auth-operators"),
            public_key_root: fixed_root("devnet-withdrawal-auth-pq-public-keys"),
            stake_root: fixed_root("devnet-withdrawal-auth-stakes"),
            policy_root: fixed_root("devnet-withdrawal-auth-policy"),
            signer_count: 17,
            aggregate_weight: 21,
            pq_security_bits: 256,
            active_from_height: DEVNET_L2_HEIGHT,
            last_heartbeat_height: DEVNET_L2_HEIGHT + 12,
        };
        state
            .insert_signer_cohort(cohort.clone())
            .expect("valid cohort");

        let budget = RedactionBudget {
            budget_id: deterministic_id("redaction-budget", &["devnet", "withdrawal", "retail"]),
            scope_root: fixed_root("devnet-retail-withdrawal-redaction-scope"),
            allocated_units: state.config.redaction_budget_units,
            consumed_units: 128,
            controller_commitment: fixed_root("devnet-redaction-controller"),
            expires_height: DEVNET_L2_HEIGHT + state.config.auth_ticket_ttl_blocks,
        };
        state
            .insert_redaction_budget(budget.clone())
            .expect("valid redaction budget");

        let batch = SealedWithdrawalBatch {
            batch_id: deterministic_id("batch", &["devnet", "retail", "0001"]),
            lane: WithdrawalLane::RetailBridge,
            cohort_id: cohort.cohort_id.clone(),
            sealed_withdrawal_root: fixed_root("devnet-sealed-withdrawal-batch-0001"),
            encrypted_destination_root: fixed_root("devnet-encrypted-monero-destinations-0001"),
            amount_commitment_root: fixed_root("devnet-withdrawal-amount-commitments-0001"),
            fee_policy_root: fixed_root("devnet-low-fee-withdrawal-policy"),
            hint_set_root: fixed_root("devnet-key-image-nullifier-hints-0001"),
            withdrawal_count: 64,
            anonymity_set_size: 131_072,
            fee_paid_micronero: 18_000,
            sealed_height: DEVNET_L2_HEIGHT + 18,
            expires_height: DEVNET_L2_HEIGHT + state.config.batch_seal_ttl_blocks,
            status: BatchStatus::Ticketed,
        };
        state
            .insert_sealed_batch(batch.clone())
            .expect("valid batch");

        state
            .insert_key_image_nullifier_hint(KeyImageNullifierHint {
                hint_id: deterministic_id("hint", &[&batch.batch_id, "hybrid"]),
                batch_id: batch.batch_id.clone(),
                kind: HintKind::HybridKeyImageNullifier,
                bucket_tag: "bucket-devnet-retail-4096".to_string(),
                hint_commitment_root: fixed_root("devnet-hybrid-nullifier-hint"),
                decoy_context_root: fixed_root("devnet-hybrid-decoy-context"),
                replay_fence_root: fixed_root("devnet-hybrid-replay-fence"),
                observed_height: DEVNET_L2_HEIGHT + 19,
                redaction_budget_id: budget.budget_id.clone(),
            })
            .expect("valid hint");

        state
            .insert_authentication_ticket(AuthenticationTicket {
                ticket_id: deterministic_id("ticket", &[&batch.batch_id, &cohort.cohort_id]),
                batch_id: batch.batch_id.clone(),
                cohort_id: cohort.cohort_id.clone(),
                auth_transcript_root: fixed_root("devnet-auth-transcript-0001"),
                pq_signature_root: fixed_root("devnet-pq-signature-quorum-0001"),
                withdrawal_gate_root: fixed_root("devnet-withdrawal-gate-0001"),
                status: TicketStatus::Issued,
                quorum_bps: state.config.strong_quorum_bps,
                issued_height: DEVNET_L2_HEIGHT + 24,
                expires_height: DEVNET_L2_HEIGHT + state.config.auth_ticket_ttl_blocks,
            })
            .expect("valid ticket");

        state
            .insert_low_fee_rebate(LowFeeVerificationRebate {
                rebate_id: deterministic_id("rebate", &[&batch.batch_id, "low-fee"]),
                batch_id: batch.batch_id.clone(),
                beneficiary_commitment: fixed_root("devnet-low-fee-beneficiary"),
                rebate_commitment: fixed_root("devnet-low-fee-rebate-note"),
                fee_paid_micronero: batch.fee_paid_micronero,
                rebate_micronero: batch.fee_paid_micronero * state.config.low_fee_rebate_bps
                    / MAX_BPS,
                issued_height: DEVNET_L2_HEIGHT + 25,
            })
            .expect("valid rebate");

        state.publish_record(
            "devnet-public-record",
            &batch.batch_id,
            "sealed_withdrawal_batch",
        );
        state.refresh();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let batch_id = deterministic_id("batch", &["demo", "quarantine", "0002"]);
        state
            .insert_slashing_quarantine(SlashingQuarantine {
                quarantine_id: deterministic_id("quarantine", &[&batch_id, "operator-challenge"]),
                batch_id: batch_id.clone(),
                offender_commitment: fixed_root("demo-offending-cohort-member"),
                reason: QuarantineReason::OperatorChallenge,
                evidence_root: fixed_root("demo-quarantine-evidence"),
                penalty_root: fixed_root("demo-quarantine-penalty"),
                quarantined_height: DEVNET_L2_HEIGHT + 30,
                releases_height: DEVNET_L2_HEIGHT + state.config.quarantine_ttl_blocks,
            })
            .expect("valid quarantine");
        state.refresh();
        state
    }

    pub fn insert_signer_cohort(
        &mut self,
        cohort: PqSignerCohort,
    ) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<()> {
        require(
            self.signer_cohorts.len() < MAX_COHORTS,
            "too many signer cohorts",
        )?;
        require(
            cohort.status.accepts_batches(),
            "cohort cannot authenticate batches",
        )?;
        require(
            cohort.pq_security_bits >= self.config.min_pq_security_bits,
            "cohort pq security below runtime floor",
        )?;
        self.signer_cohorts.insert(cohort.cohort_id.clone(), cohort);
        self.refresh();
        Ok(())
    }

    pub fn insert_sealed_batch(
        &mut self,
        batch: SealedWithdrawalBatch,
    ) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<()> {
        require(
            self.sealed_batches.len() < MAX_BATCHES,
            "too many sealed batches",
        )?;
        require(
            self.config.allowed_lanes.contains(&batch.lane),
            "withdrawal lane is disabled",
        )?;
        require(
            self.signer_cohorts.contains_key(&batch.cohort_id),
            "signer cohort is missing",
        )?;
        require(
            batch.withdrawal_count > 0
                && batch.withdrawal_count as usize <= self.config.max_withdrawals_per_batch,
            "invalid withdrawal count",
        )?;
        require(
            batch.anonymity_set_size >= self.config.min_anonymity_set,
            "anonymity set below runtime floor",
        )?;
        self.sealed_batches.insert(batch.batch_id.clone(), batch);
        self.refresh();
        Ok(())
    }

    pub fn insert_key_image_nullifier_hint(
        &mut self,
        hint: KeyImageNullifierHint,
    ) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<()> {
        require(
            self.key_image_nullifier_hints.len() < MAX_HINTS,
            "too many hints",
        )?;
        require(
            self.sealed_batches.contains_key(&hint.batch_id),
            "hint batch is missing",
        )?;
        require(
            self.redaction_budgets
                .contains_key(&hint.redaction_budget_id),
            "hint redaction budget is missing",
        )?;
        self.key_image_nullifier_hints
            .insert(hint.hint_id.clone(), hint);
        self.refresh();
        Ok(())
    }

    pub fn insert_authentication_ticket(
        &mut self,
        ticket: AuthenticationTicket,
    ) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<()> {
        require(
            self.authentication_tickets.len() < MAX_TICKETS,
            "too many tickets",
        )?;
        require(
            self.sealed_batches.contains_key(&ticket.batch_id),
            "ticket batch is missing",
        )?;
        require(
            self.signer_cohorts.contains_key(&ticket.cohort_id),
            "ticket cohort is missing",
        )?;
        require(
            ticket.quorum_bps >= self.config.quorum_bps && ticket.quorum_bps <= MAX_BPS,
            "ticket quorum is outside policy",
        )?;
        self.authentication_tickets
            .insert(ticket.ticket_id.clone(), ticket);
        self.refresh();
        Ok(())
    }

    pub fn insert_slashing_quarantine(
        &mut self,
        quarantine: SlashingQuarantine,
    ) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<()> {
        require(
            self.slashing_quarantines.len() < MAX_QUARANTINES,
            "too many quarantines",
        )?;
        self.quarantined_batches.insert(quarantine.batch_id.clone());
        self.slashing_quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine);
        self.refresh();
        Ok(())
    }

    pub fn insert_low_fee_rebate(
        &mut self,
        rebate: LowFeeVerificationRebate,
    ) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<()> {
        require(self.low_fee_rebates.len() < MAX_REBATES, "too many rebates")?;
        require(
            self.config.allow_low_fee_rebates,
            "low fee rebates are disabled",
        )?;
        require(
            self.sealed_batches.contains_key(&rebate.batch_id),
            "rebate batch is missing",
        )?;
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh();
        Ok(())
    }

    pub fn insert_redaction_budget(
        &mut self,
        budget: RedactionBudget,
    ) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<()> {
        require(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "too many redaction budgets",
        )?;
        require(
            budget.consumed_units <= budget.allocated_units,
            "redaction budget overspent",
        )?;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
            "signer_cohorts": map_records(&self.signer_cohorts, PqSignerCohort::public_record),
            "sealed_batches": map_records(&self.sealed_batches, SealedWithdrawalBatch::public_record),
            "key_image_nullifier_hints": map_records(&self.key_image_nullifier_hints, KeyImageNullifierHint::public_record),
            "authentication_tickets": map_records(&self.authentication_tickets, AuthenticationTicket::public_record),
            "slashing_quarantines": map_records(&self.slashing_quarantines, SlashingQuarantine::public_record),
            "low_fee_rebates": map_records(&self.low_fee_rebates, LowFeeVerificationRebate::public_record),
            "redaction_budgets": map_records(&self.redaction_budgets, RedactionBudget::public_record),
            "public_records": map_records(&self.public_records, PublicRecord::public_record),
            "quarantined_batches_root": set_root("QUARANTINED-BATCHES", &self.quarantined_batches),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    fn publish_record(&mut self, record_id_hint: &str, subject_id: &str, kind: &str) {
        if self.public_records.len() >= MAX_PUBLIC_RECORDS {
            return;
        }
        let record = PublicRecord {
            record_id: deterministic_id("public-record", &[record_id_hint, subject_id, kind]),
            subject_id: subject_id.to_string(),
            kind: kind.to_string(),
            payload_root: fixed_root(&format!("{record_id_hint}-{subject_id}-{kind}")),
            published_height: self.config.l2_height,
        };
        self.public_records.insert(record.record_id.clone(), record);
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            signer_cohorts: self.signer_cohorts.len() as u64,
            sealed_batches: self.sealed_batches.len() as u64,
            key_image_nullifier_hints: self.key_image_nullifier_hints.len() as u64,
            authentication_tickets: self.authentication_tickets.len() as u64,
            quarantines: self.slashing_quarantines.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            public_records: self.public_records.len() as u64,
            authenticated_withdrawals: self
                .sealed_batches
                .values()
                .filter(|batch| {
                    matches!(
                        batch.status,
                        BatchStatus::Authenticated | BatchStatus::Ticketed | BatchStatus::Settled
                    )
                })
                .map(|batch| batch.withdrawal_count)
                .sum(),
            quarantined_withdrawals: self
                .sealed_batches
                .values()
                .filter(|batch| self.quarantined_batches.contains(&batch.batch_id))
                .map(|batch| batch.withdrawal_count)
                .sum(),
            total_rebate_micronero: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.rebate_micronero)
                .sum(),
        };
        self.roots = Roots {
            config_root: record_root("CONFIG", &self.config.public_record()),
            counters_root: record_root("COUNTERS", &self.counters.public_record()),
            signer_cohort_root: map_root(
                "SIGNER-COHORTS",
                &self.signer_cohorts,
                PqSignerCohort::public_record,
            ),
            sealed_batch_root: map_root(
                "SEALED-BATCHES",
                &self.sealed_batches,
                SealedWithdrawalBatch::public_record,
            ),
            key_image_nullifier_hint_root: map_root(
                "KEY-IMAGE-NULLIFIER-HINTS",
                &self.key_image_nullifier_hints,
                KeyImageNullifierHint::public_record,
            ),
            authentication_ticket_root: map_root(
                "AUTHENTICATION-TICKETS",
                &self.authentication_tickets,
                AuthenticationTicket::public_record,
            ),
            quarantine_root: map_root(
                "SLASHING-QUARANTINES",
                &self.slashing_quarantines,
                SlashingQuarantine::public_record,
            ),
            low_fee_rebate_root: map_root(
                "LOW-FEE-REBATES",
                &self.low_fee_rebates,
                LowFeeVerificationRebate::public_record,
            ),
            redaction_budget_root: map_root(
                "REDACTION-BUDGETS",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            public_record_root: map_root(
                "PUBLIC-RECORDS",
                &self.public_records,
                PublicRecord::public_record,
            ),
            state_root: record_root(
                "STATE-WITHOUT-ROOT",
                &self.public_record_without_state_root(),
            ),
        };
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn fixed_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-LATTICE-BATCH-WITHDRAWAL-AUTHENTICATOR-FIXED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let mut hash_parts = Vec::with_capacity(parts.len() + 2);
    hash_parts.push(HashPart::Str(CHAIN_ID));
    hash_parts.push(HashPart::Str(PROTOCOL_VERSION));
    for part in parts {
        hash_parts.push(HashPart::Str(*part));
    }
    let root = domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-LATTICE-BATCH-WITHDRAWAL-AUTHENTICATOR-ID",
        &hash_parts,
        16,
    );
    format!("{prefix}-{root}")
}

pub fn record_root(domain: &str, record: &Value) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-LATTICE-WITHDRAWAL-AUTH-{domain}"),
        &[record.clone()],
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-LATTICE-WITHDRAWAL-AUTH-{domain}"),
        &[],
    )
}

fn map_root<T, F>(domain: &str, records: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let values = records.values().map(public_record).collect::<Vec<_>>();
    if values.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(
            &format!("PRIVATE-L2-PQ-CONFIDENTIAL-LATTICE-WITHDRAWAL-AUTH-{domain}"),
            &values,
        )
    }
}

fn map_records<T, F>(records: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    records.values().map(public_record).collect()
}

fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let values = records
        .iter()
        .map(|id| json!({ "id": id }))
        .collect::<Vec<_>>();
    if values.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(
            &format!("PRIVATE-L2-PQ-CONFIDENTIAL-LATTICE-WITHDRAWAL-AUTH-{domain}"),
            &values,
        )
    }
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2PqConfidentialLatticeBatchWithdrawalAuthenticatorRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
