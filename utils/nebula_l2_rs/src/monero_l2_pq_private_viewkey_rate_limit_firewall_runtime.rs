use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateViewkeyRateLimitFirewallRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_VIEWKEY_RATE_LIMIT_FIREWALL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-viewkey-rate-limit-firewall-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_VIEWKEY_RATE_LIMIT_FIREWALL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_VIEWKEY_ASSET_ID: &str = "monero-private-viewkey-access";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_024_640;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VIEWKEY_TICKET_SCHEME: &str = "shielded-viewkey-access-ticket-commitment-root-v1";
pub const AUDITOR_POLICY_SCHEME: &str = "viewkey-auditor-policy-capability-root-v1";
pub const PQ_WALLET_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-wallet-viewkey-attestation-v1";
pub const PQ_OPERATOR_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-operator-viewkey-firewall-attestation-v1";
pub const RATE_BUCKET_SCHEME: &str = "privacy-preserving-viewkey-rate-bucket-counter-root-v1";
pub const LOW_FEE_AUDIT_CREDIT_SCHEME: &str = "low-fee-viewkey-audit-credit-sponsorship-root-v1";
pub const ABUSE_QUARANTINE_SCHEME: &str = "viewkey-access-abuse-quarantine-evidence-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "viewkey-redaction-budget-nullifier-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "deterministic-viewkey-firewall-public-record-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_viewkeys_addresses_txids_key_images_wallet_graphs_or_query_payloads";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_POLICY_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_BUCKET_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_MAX_TICKET_QUERIES: u64 = 64;
pub const DEFAULT_MAX_BUCKET_QUERIES: u64 = 256;
pub const DEFAULT_MAX_DISTINCT_ACCOUNTS: u64 = 8;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 4_096;
pub const DEFAULT_LOW_FEE_CREDIT_QUANTA: u64 = 10_000;
pub const DEFAULT_MIN_AUDITOR_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_AUDITOR_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_SUSPICION_THRESHOLD_BPS: u64 = 750;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_OPERATOR_SUMMARY_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Requested,
    Issued,
    Active,
    RateLimited,
    Exhausted,
    Revoked,
    Expired,
    Quarantined,
}

impl TicketStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Issued | Self::Active)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Exhausted | Self::Revoked | Self::Expired | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessScope {
    WalletSync,
    AuditSample,
    ComplianceReview,
    BridgeSettlement,
    RecoveryAssist,
    WatchtowerProbe,
    IncidentResponse,
}

impl AccessScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSync => "wallet_sync",
            Self::AuditSample => "audit_sample",
            Self::ComplianceReview => "compliance_review",
            Self::BridgeSettlement => "bridge_settlement",
            Self::RecoveryAssist => "recovery_assist",
            Self::WatchtowerProbe => "watchtower_probe",
            Self::IncidentResponse => "incident_response",
        }
    }

    pub fn privileged(self) -> bool {
        matches!(
            self,
            Self::ComplianceReview | Self::BridgeSettlement | Self::IncidentResponse
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditorPolicyStatus {
    Draft,
    Active,
    Rotating,
    Suspended,
    Revoked,
    Expired,
}

impl AuditorPolicyStatus {
    pub fn accepts_tickets(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationSubject {
    Wallet,
    Operator,
    Auditor,
    Policy,
    RateBucket,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateBucketStatus {
    Open,
    Warning,
    Throttled,
    CoolingDown,
    Frozen,
    Closed,
}

impl RateBucketStatus {
    pub fn accepts_queries(self) -> bool {
        matches!(self, Self::Open | Self::Warning | Self::CoolingDown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCreditStatus {
    Reserved,
    Applied,
    Settled,
    Exhausted,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseKind {
    QueryBurst,
    DistinctAccountFanout,
    PolicyMismatch,
    RedactionBudgetOverrun,
    ReplayTicket,
    PqAttestationFailure,
    OperatorEquivocation,
    SuspiciousAuditorPattern,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    Investigating,
    Contained,
    Released,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionBudgetStatus {
    Open,
    Reserved,
    Applied,
    Exhausted,
    Frozen,
    Expired,
}

impl RedactionBudgetStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub viewkey_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub ticket_scheme: String,
    pub auditor_policy_scheme: String,
    pub wallet_attestation_scheme: String,
    pub operator_attestation_scheme: String,
    pub rate_bucket_scheme: String,
    pub low_fee_credit_scheme: String,
    pub abuse_quarantine_scheme: String,
    pub redaction_budget_scheme: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub ticket_ttl_blocks: u64,
    pub policy_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub bucket_window_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub max_ticket_queries: u64,
    pub max_bucket_queries: u64,
    pub max_distinct_accounts: u64,
    pub redaction_budget_units: u64,
    pub low_fee_credit_quanta: u64,
    pub min_auditor_quorum_bps: u64,
    pub strong_auditor_quorum_bps: u64,
    pub suspicion_threshold_bps: u64,
    pub max_user_fee_bps: u64,
    pub operator_summary_bucket_size: u64,
    pub created_at_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            viewkey_asset_id: DEVNET_VIEWKEY_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            ticket_scheme: VIEWKEY_TICKET_SCHEME.to_string(),
            auditor_policy_scheme: AUDITOR_POLICY_SCHEME.to_string(),
            wallet_attestation_scheme: PQ_WALLET_ATTESTATION_SCHEME.to_string(),
            operator_attestation_scheme: PQ_OPERATOR_ATTESTATION_SCHEME.to_string(),
            rate_bucket_scheme: RATE_BUCKET_SCHEME.to_string(),
            low_fee_credit_scheme: LOW_FEE_AUDIT_CREDIT_SCHEME.to_string(),
            abuse_quarantine_scheme: ABUSE_QUARANTINE_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            policy_ttl_blocks: DEFAULT_POLICY_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            bucket_window_blocks: DEFAULT_BUCKET_WINDOW_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            max_ticket_queries: DEFAULT_MAX_TICKET_QUERIES,
            max_bucket_queries: DEFAULT_MAX_BUCKET_QUERIES,
            max_distinct_accounts: DEFAULT_MAX_DISTINCT_ACCOUNTS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            low_fee_credit_quanta: DEFAULT_LOW_FEE_CREDIT_QUANTA,
            min_auditor_quorum_bps: DEFAULT_MIN_AUDITOR_QUORUM_BPS,
            strong_auditor_quorum_bps: DEFAULT_STRONG_AUDITOR_QUORUM_BPS,
            suspicion_threshold_bps: DEFAULT_SUSPICION_THRESHOLD_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_summary_bucket_size: DEFAULT_OPERATOR_SUMMARY_BUCKET_SIZE,
            created_at_height: DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.protocol_version == PROTOCOL_VERSION,
            "invalid protocol version",
        )?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "invalid schema version",
        )?;
        ensure(
            self.min_pq_security_bits <= self.target_pq_security_bits,
            "min pq security exceeds target",
        )?;
        ensure(
            self.min_auditor_quorum_bps <= MAX_BPS
                && self.strong_auditor_quorum_bps <= MAX_BPS
                && self.min_auditor_quorum_bps <= self.strong_auditor_quorum_bps,
            "invalid auditor quorum bps",
        )?;
        ensure(self.max_user_fee_bps <= MAX_BPS, "invalid user fee bps")?;
        ensure(
            self.suspicion_threshold_bps <= MAX_BPS,
            "invalid suspicion threshold bps",
        )?;
        ensure(
            self.ticket_ttl_blocks > 0
                && self.policy_ttl_blocks > 0
                && self.attestation_ttl_blocks > 0
                && self.bucket_window_blocks > 0
                && self.quarantine_ttl_blocks > 0,
            "ttl and window values must be nonzero",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "viewkey_asset_id": self.viewkey_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "ticket_scheme": self.ticket_scheme,
            "auditor_policy_scheme": self.auditor_policy_scheme,
            "wallet_attestation_scheme": self.wallet_attestation_scheme,
            "operator_attestation_scheme": self.operator_attestation_scheme,
            "rate_bucket_scheme": self.rate_bucket_scheme,
            "low_fee_credit_scheme": self.low_fee_credit_scheme,
            "abuse_quarantine_scheme": self.abuse_quarantine_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "public_record_scheme": self.public_record_scheme,
            "privacy_boundary": self.privacy_boundary,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "bucket_window_blocks": self.bucket_window_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "max_ticket_queries": self.max_ticket_queries,
            "max_bucket_queries": self.max_bucket_queries,
            "max_distinct_accounts": self.max_distinct_accounts,
            "redaction_budget_units": self.redaction_budget_units,
            "low_fee_credit_quanta": self.low_fee_credit_quanta,
            "min_auditor_quorum_bps": self.min_auditor_quorum_bps,
            "strong_auditor_quorum_bps": self.strong_auditor_quorum_bps,
            "suspicion_threshold_bps": self.suspicion_threshold_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "operator_summary_bucket_size": self.operator_summary_bucket_size,
            "created_at_height": self.created_at_height
        })
    }

    pub fn root(&self) -> String {
        payload_root("VIEWKEY-FIREWALL-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub policies: u64,
    pub tickets: u64,
    pub wallet_attestations: u64,
    pub operator_attestations: u64,
    pub rate_buckets: u64,
    pub access_events: u64,
    pub low_fee_credits: u64,
    pub quarantines: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
    pub active_tickets: u64,
    pub throttled_buckets: u64,
    pub quarantined_subjects: u64,
    pub remaining_credit_quanta: u64,
    pub remaining_redaction_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "policies": self.policies,
            "tickets": self.tickets,
            "wallet_attestations": self.wallet_attestations,
            "operator_attestations": self.operator_attestations,
            "rate_buckets": self.rate_buckets,
            "access_events": self.access_events,
            "low_fee_credits": self.low_fee_credits,
            "quarantines": self.quarantines,
            "redaction_budgets": self.redaction_budgets,
            "public_records": self.public_records,
            "active_tickets": self.active_tickets,
            "throttled_buckets": self.throttled_buckets,
            "quarantined_subjects": self.quarantined_subjects,
            "remaining_credit_quanta": self.remaining_credit_quanta,
            "remaining_redaction_units": self.remaining_redaction_units
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub policy_root: String,
    pub ticket_root: String,
    pub wallet_attestation_root: String,
    pub operator_attestation_root: String,
    pub rate_bucket_root: String,
    pub access_event_root: String,
    pub low_fee_credit_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "policy_root": self.policy_root,
            "ticket_root": self.ticket_root,
            "wallet_attestation_root": self.wallet_attestation_root,
            "operator_attestation_root": self.operator_attestation_root,
            "rate_bucket_root": self.rate_bucket_root,
            "access_event_root": self.access_event_root,
            "low_fee_credit_root": self.low_fee_credit_root,
            "quarantine_root": self.quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditorPolicyRequest {
    pub auditor_id: String,
    pub policy_label: String,
    pub allowed_scopes: BTreeSet<AccessScope>,
    pub jurisdiction_commitment_root: String,
    pub policy_commitment_root: String,
    pub disclosure_rule_root: String,
    pub max_ticket_queries: u64,
    pub max_bucket_queries: u64,
    pub max_distinct_accounts: u64,
    pub min_redaction_budget_units: u64,
    pub min_quorum_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub policy_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditorPolicyRecord {
    pub policy_id: String,
    pub auditor_id: String,
    pub policy_label: String,
    pub allowed_scopes: BTreeSet<AccessScope>,
    pub jurisdiction_commitment_root: String,
    pub policy_commitment_root: String,
    pub disclosure_rule_root: String,
    pub max_ticket_queries: u64,
    pub max_bucket_queries: u64,
    pub max_distinct_accounts: u64,
    pub min_redaction_budget_units: u64,
    pub min_quorum_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub status: AuditorPolicyStatus,
    pub policy_root: String,
}

impl AuditorPolicyRecord {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewkeyTicketRequest {
    pub policy_id: String,
    pub wallet_commitment_root: String,
    pub shielded_account_root: String,
    pub viewkey_capability_root: String,
    pub accessor_commitment_root: String,
    pub scope: AccessScope,
    pub requested_queries: u64,
    pub requested_distinct_accounts: u64,
    pub redaction_budget_units: u64,
    pub low_fee_credit_id: Option<String>,
    pub ticket_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewkeyTicketRecord {
    pub ticket_id: String,
    pub policy_id: String,
    pub wallet_commitment_root: String,
    pub shielded_account_root: String,
    pub viewkey_capability_root: String,
    pub accessor_commitment_root: String,
    pub scope: AccessScope,
    pub requested_queries: u64,
    pub remaining_queries: u64,
    pub requested_distinct_accounts: u64,
    pub redaction_budget_units: u64,
    pub low_fee_credit_id: Option<String>,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: TicketStatus,
    pub ticket_root: String,
}

impl ViewkeyTicketRecord {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestationRequest {
    pub subject: AttestationSubject,
    pub subject_id: String,
    pub attester_id: String,
    pub committee_id: String,
    pub l2_height: u64,
    pub pq_security_bits: u16,
    pub attester_weight_bps: u64,
    pub statement_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub attestation_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub subject: AttestationSubject,
    pub subject_id: String,
    pub attester_id: String,
    pub committee_id: String,
    pub l2_height: u64,
    pub expires_at_height: u64,
    pub pq_security_bits: u16,
    pub attester_weight_bps: u64,
    pub statement_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub status: AttestationStatus,
    pub attestation_root: String,
}

impl PqAttestationRecord {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RateBucketRequest {
    pub policy_id: String,
    pub bucket_label: String,
    pub auditor_group_root: String,
    pub accessor_group_root: String,
    pub scope: AccessScope,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_queries: u64,
    pub max_distinct_accounts: u64,
    pub bucket_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RateBucketRecord {
    pub bucket_id: String,
    pub policy_id: String,
    pub bucket_label: String,
    pub auditor_group_root: String,
    pub accessor_group_root: String,
    pub scope: AccessScope,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_queries: u64,
    pub consumed_queries: u64,
    pub max_distinct_accounts: u64,
    pub distinct_account_nullifier_root: String,
    pub status: RateBucketStatus,
    pub bucket_root: String,
}

impl RateBucketRecord {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessEventRequest {
    pub ticket_id: String,
    pub bucket_id: String,
    pub operator_id: String,
    pub query_commitment_root: String,
    pub result_redaction_root: String,
    pub account_nullifier_root: String,
    pub consumed_queries: u64,
    pub consumed_redaction_units: u64,
    pub fee_quanta: u64,
    pub event_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessEventRecord {
    pub event_id: String,
    pub ticket_id: String,
    pub bucket_id: String,
    pub operator_id: String,
    pub query_commitment_root: String,
    pub result_redaction_root: String,
    pub account_nullifier_root: String,
    pub consumed_queries: u64,
    pub consumed_redaction_units: u64,
    pub fee_quanta: u64,
    pub accepted: bool,
    pub event_root: String,
}

impl AccessEventRecord {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeAuditCreditRequest {
    pub sponsor_id: String,
    pub policy_id: String,
    pub beneficiary_commitment_root: String,
    pub credit_quanta: u64,
    pub max_user_fee_bps: u64,
    pub settlement_root: String,
    pub sponsor_signature_root: String,
    pub credit_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeAuditCreditRecord {
    pub credit_id: String,
    pub sponsor_id: String,
    pub policy_id: String,
    pub beneficiary_commitment_root: String,
    pub credit_quanta: u64,
    pub remaining_quanta: u64,
    pub max_user_fee_bps: u64,
    pub settlement_root: String,
    pub sponsor_signature_root: String,
    pub status: AuditCreditStatus,
    pub credit_root: String,
}

impl LowFeeAuditCreditRecord {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AbuseQuarantineRequest {
    pub subject_id: String,
    pub ticket_id: Option<String>,
    pub bucket_id: Option<String>,
    pub reporter_id: String,
    pub kind: AbuseKind,
    pub evidence_root: String,
    pub suspicion_score_bps: u64,
    pub quarantine_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AbuseQuarantineRecord {
    pub quarantine_id: String,
    pub subject_id: String,
    pub ticket_id: Option<String>,
    pub bucket_id: Option<String>,
    pub reporter_id: String,
    pub kind: AbuseKind,
    pub evidence_root: String,
    pub suspicion_score_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: QuarantineStatus,
    pub quarantine_root: String,
}

impl AbuseQuarantineRecord {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudgetRequest {
    pub ticket_id: String,
    pub policy_id: String,
    pub redactor_id: String,
    pub budget_commitment_root: String,
    pub nullifier_set_root: String,
    pub units: u64,
    pub budget_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudgetRecord {
    pub budget_id: String,
    pub ticket_id: String,
    pub policy_id: String,
    pub redactor_id: String,
    pub budget_commitment_root: String,
    pub nullifier_set_root: String,
    pub units: u64,
    pub remaining_units: u64,
    pub status: RedactionBudgetStatus,
    pub budget_root: String,
}

impl RedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRecordEntry {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub sequence: u64,
}

impl PublicRecordEntry {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub policies: BTreeMap<String, AuditorPolicyRecord>,
    pub tickets: BTreeMap<String, ViewkeyTicketRecord>,
    pub wallet_attestations: BTreeMap<String, PqAttestationRecord>,
    pub operator_attestations: BTreeMap<String, PqAttestationRecord>,
    pub rate_buckets: BTreeMap<String, RateBucketRecord>,
    pub access_events: BTreeMap<String, AccessEventRecord>,
    pub low_fee_credits: BTreeMap<String, LowFeeAuditCreditRecord>,
    pub quarantines: BTreeMap<String, AbuseQuarantineRecord>,
    pub redaction_budgets: BTreeMap<String, RedactionBudgetRecord>,
    pub public_records: BTreeMap<String, PublicRecordEntry>,
    pub sequence: u64,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            policies: BTreeMap::new(),
            tickets: BTreeMap::new(),
            wallet_attestations: BTreeMap::new(),
            operator_attestations: BTreeMap::new(),
            rate_buckets: BTreeMap::new(),
            access_events: BTreeMap::new(),
            low_fee_credits: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            sequence: 0,
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet())?;
        let policy_id = state.register_auditor_policy(AuditorPolicyRequest {
            auditor_id: "auditor-devnet-1".to_string(),
            policy_label: "devnet-wallet-sync-and-audit-sample".to_string(),
            allowed_scopes: BTreeSet::from([AccessScope::WalletSync, AccessScope::AuditSample]),
            jurisdiction_commitment_root: demo_root("jurisdiction", 1),
            policy_commitment_root: demo_root("policy", 1),
            disclosure_rule_root: demo_root("disclosure", 1),
            max_ticket_queries: 64,
            max_bucket_queries: 256,
            max_distinct_accounts: 8,
            min_redaction_budget_units: 1_024,
            min_quorum_bps: DEFAULT_MIN_AUDITOR_QUORUM_BPS,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_POLICY_TTL_BLOCKS,
            policy_nonce: "policy-devnet-1".to_string(),
        })?;
        let credit_id = state.reserve_low_fee_credit(LowFeeAuditCreditRequest {
            sponsor_id: "fee-sponsor-devnet-1".to_string(),
            policy_id: policy_id.clone(),
            beneficiary_commitment_root: demo_root("beneficiary", 1),
            credit_quanta: 2_000,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            settlement_root: demo_root("credit-settlement", 1),
            sponsor_signature_root: demo_root("credit-signature", 1),
            credit_nonce: "credit-devnet-1".to_string(),
        })?;
        let ticket_id = state.issue_ticket(ViewkeyTicketRequest {
            policy_id: policy_id.clone(),
            wallet_commitment_root: demo_root("wallet", 1),
            shielded_account_root: demo_root("account", 1),
            viewkey_capability_root: demo_root("capability", 1),
            accessor_commitment_root: demo_root("accessor", 1),
            scope: AccessScope::WalletSync,
            requested_queries: 24,
            requested_distinct_accounts: 4,
            redaction_budget_units: 1_024,
            low_fee_credit_id: Some(credit_id.clone()),
            ticket_nonce: "ticket-devnet-1".to_string(),
        })?;
        state.record_wallet_attestation(PqAttestationRequest {
            subject: AttestationSubject::Wallet,
            subject_id: ticket_id.clone(),
            attester_id: "wallet-devnet-1".to_string(),
            committee_id: "wallet-attestors-devnet".to_string(),
            l2_height: DEVNET_HEIGHT + 1,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            attester_weight_bps: 4_000,
            statement_root: demo_root("wallet-statement", 1),
            transcript_root: demo_root("wallet-transcript", 1),
            signature_root: demo_root("wallet-signature", 1),
            attestation_nonce: "wallet-attestation-devnet-1".to_string(),
        })?;
        state.record_operator_attestation(PqAttestationRequest {
            subject: AttestationSubject::Operator,
            subject_id: "operator-devnet-1".to_string(),
            attester_id: "operator-devnet-1".to_string(),
            committee_id: "operator-attestors-devnet".to_string(),
            l2_height: DEVNET_HEIGHT + 2,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            attester_weight_bps: 7_000,
            statement_root: demo_root("operator-statement", 1),
            transcript_root: demo_root("operator-transcript", 1),
            signature_root: demo_root("operator-signature", 1),
            attestation_nonce: "operator-attestation-devnet-1".to_string(),
        })?;
        let bucket_id = state.open_rate_bucket(RateBucketRequest {
            policy_id: policy_id.clone(),
            bucket_label: "devnet-wallet-sync-window".to_string(),
            auditor_group_root: demo_root("auditor-group", 1),
            accessor_group_root: demo_root("accessor-group", 1),
            scope: AccessScope::WalletSync,
            window_start_height: DEVNET_HEIGHT,
            window_end_height: DEVNET_HEIGHT + DEFAULT_BUCKET_WINDOW_BLOCKS,
            max_queries: 128,
            max_distinct_accounts: 8,
            bucket_nonce: "bucket-devnet-1".to_string(),
        })?;
        state.reserve_redaction_budget(RedactionBudgetRequest {
            ticket_id: ticket_id.clone(),
            policy_id: policy_id.clone(),
            redactor_id: "redactor-devnet-1".to_string(),
            budget_commitment_root: demo_root("budget", 1),
            nullifier_set_root: demo_root("budget-nullifier", 1),
            units: 1_024,
            budget_nonce: "budget-devnet-1".to_string(),
        })?;
        state.record_access_event(AccessEventRequest {
            ticket_id,
            bucket_id,
            operator_id: "operator-devnet-1".to_string(),
            query_commitment_root: demo_root("query", 1),
            result_redaction_root: demo_root("result-redaction", 1),
            account_nullifier_root: demo_root("account-nullifier", 1),
            consumed_queries: 3,
            consumed_redaction_units: 96,
            fee_quanta: 15,
            event_nonce: "event-devnet-1".to_string(),
        })?;
        Ok(state)
    }

    pub fn demo() -> Result<Self> {
        let mut state = Self::devnet()?;
        let ticket_id = state
            .tickets
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "demo missing ticket".to_string())?;
        let bucket_id = state
            .rate_buckets
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "demo missing bucket".to_string())?;
        state.open_quarantine(AbuseQuarantineRequest {
            subject_id: "accessor-devnet-watchlist".to_string(),
            ticket_id: Some(ticket_id),
            bucket_id: Some(bucket_id),
            reporter_id: "watchtower-devnet-1".to_string(),
            kind: AbuseKind::QueryBurst,
            evidence_root: demo_root("abuse-evidence", 1),
            suspicion_score_bps: 925,
            quarantine_nonce: "quarantine-devnet-1".to_string(),
        })?;
        Ok(state)
    }

    pub fn register_auditor_policy(&mut self, request: AuditorPolicyRequest) -> Result<String> {
        ensure(!request.allowed_scopes.is_empty(), "policy scopes required")?;
        ensure(
            request.valid_from_height < request.valid_until_height,
            "invalid policy validity window",
        )?;
        ensure(
            request.min_quorum_bps >= self.config.min_auditor_quorum_bps
                && request.min_quorum_bps <= self.config.strong_auditor_quorum_bps,
            "policy quorum outside configured bounds",
        )?;
        self.sequence += 1;
        let policy_id = policy_id(self.sequence, &request);
        let policy_root = payload_root(
            "VIEWKEY-AUDITOR-POLICY",
            &json!({
                "policy_id": policy_id,
                "auditor_id": request.auditor_id,
                "policy_commitment_root": request.policy_commitment_root,
                "disclosure_rule_root": request.disclosure_rule_root,
                "allowed_scopes": request.allowed_scopes
            }),
        );
        let record = AuditorPolicyRecord {
            policy_id: policy_id.clone(),
            auditor_id: request.auditor_id,
            policy_label: request.policy_label,
            allowed_scopes: request.allowed_scopes,
            jurisdiction_commitment_root: request.jurisdiction_commitment_root,
            policy_commitment_root: request.policy_commitment_root,
            disclosure_rule_root: request.disclosure_rule_root,
            max_ticket_queries: request
                .max_ticket_queries
                .min(self.config.max_ticket_queries),
            max_bucket_queries: request
                .max_bucket_queries
                .min(self.config.max_bucket_queries),
            max_distinct_accounts: request
                .max_distinct_accounts
                .min(self.config.max_distinct_accounts),
            min_redaction_budget_units: request.min_redaction_budget_units,
            min_quorum_bps: request.min_quorum_bps,
            valid_from_height: request.valid_from_height,
            valid_until_height: request.valid_until_height,
            status: AuditorPolicyStatus::Active,
            policy_root,
        };
        self.policies.insert(policy_id.clone(), record);
        self.publish_public_record("auditor_policy", &policy_id)?;
        Ok(policy_id)
    }

    pub fn issue_ticket(&mut self, request: ViewkeyTicketRequest) -> Result<String> {
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| "unknown policy".to_string())?;
        ensure(policy.status.accepts_tickets(), "policy not active")?;
        ensure(
            policy.allowed_scopes.contains(&request.scope),
            "scope not allowed by policy",
        )?;
        ensure(
            request.requested_queries > 0 && request.requested_queries <= policy.max_ticket_queries,
            "ticket query count outside policy",
        )?;
        ensure(
            request.requested_distinct_accounts <= policy.max_distinct_accounts,
            "distinct account request outside policy",
        )?;
        ensure(
            request.redaction_budget_units >= policy.min_redaction_budget_units,
            "insufficient redaction budget",
        )?;
        if let Some(credit_id) = &request.low_fee_credit_id {
            let credit = self
                .low_fee_credits
                .get(credit_id)
                .ok_or_else(|| "unknown low fee credit".to_string())?;
            ensure(
                credit.policy_id == request.policy_id,
                "low fee credit policy mismatch",
            )?;
        }
        self.sequence += 1;
        let ticket_id = ticket_id(self.sequence, &request);
        let issued_at_height = self.config.created_at_height + self.sequence;
        let ticket_root = payload_root(
            "SHIELDED-VIEWKEY-TICKET",
            &json!({
                "ticket_id": ticket_id,
                "policy_id": request.policy_id,
                "wallet_commitment_root": request.wallet_commitment_root,
                "shielded_account_root": request.shielded_account_root,
                "viewkey_capability_root": request.viewkey_capability_root,
                "accessor_commitment_root": request.accessor_commitment_root,
                "scope": request.scope,
                "requested_queries": request.requested_queries,
                "redaction_budget_units": request.redaction_budget_units
            }),
        );
        let record = ViewkeyTicketRecord {
            ticket_id: ticket_id.clone(),
            policy_id: request.policy_id,
            wallet_commitment_root: request.wallet_commitment_root,
            shielded_account_root: request.shielded_account_root,
            viewkey_capability_root: request.viewkey_capability_root,
            accessor_commitment_root: request.accessor_commitment_root,
            scope: request.scope,
            requested_queries: request.requested_queries,
            remaining_queries: request.requested_queries,
            requested_distinct_accounts: request.requested_distinct_accounts,
            redaction_budget_units: request.redaction_budget_units,
            low_fee_credit_id: request.low_fee_credit_id,
            issued_at_height,
            expires_at_height: issued_at_height + self.config.ticket_ttl_blocks,
            status: TicketStatus::Issued,
            ticket_root,
        };
        self.tickets.insert(ticket_id.clone(), record);
        self.publish_public_record("viewkey_ticket", &ticket_id)?;
        Ok(ticket_id)
    }

    pub fn record_wallet_attestation(&mut self, request: PqAttestationRequest) -> Result<String> {
        ensure(
            request.subject == AttestationSubject::Wallet,
            "wallet attestation subject required",
        )?;
        let id = self.record_attestation(request)?;
        let record = self
            .wallet_attestations
            .get(&id)
            .ok_or_else(|| "wallet attestation not stored".to_string())?;
        ensure(
            record.pq_security_bits >= self.config.min_pq_security_bits,
            "wallet attestation below pq security floor",
        )?;
        Ok(id)
    }

    pub fn record_operator_attestation(&mut self, request: PqAttestationRequest) -> Result<String> {
        ensure(
            request.subject == AttestationSubject::Operator,
            "operator attestation subject required",
        )?;
        let id = self.record_attestation(request)?;
        let record = self
            .operator_attestations
            .get(&id)
            .ok_or_else(|| "operator attestation not stored".to_string())?;
        ensure(
            record.attester_weight_bps >= self.config.min_auditor_quorum_bps,
            "operator attestation lacks quorum weight",
        )?;
        Ok(id)
    }

    pub fn open_rate_bucket(&mut self, request: RateBucketRequest) -> Result<String> {
        ensure(
            self.policies.contains_key(&request.policy_id),
            "unknown policy for bucket",
        )?;
        ensure(
            request.window_start_height < request.window_end_height,
            "invalid bucket window",
        )?;
        ensure(
            request.max_queries > 0 && request.max_queries <= self.config.max_bucket_queries,
            "bucket query limit outside config",
        )?;
        self.sequence += 1;
        let bucket_id = bucket_id(self.sequence, &request);
        let bucket_root = payload_root(
            "VIEWKEY-RATE-BUCKET",
            &json!({
                "bucket_id": bucket_id,
                "policy_id": request.policy_id,
                "scope": request.scope,
                "window_start_height": request.window_start_height,
                "window_end_height": request.window_end_height,
                "max_queries": request.max_queries,
                "max_distinct_accounts": request.max_distinct_accounts
            }),
        );
        let record = RateBucketRecord {
            bucket_id: bucket_id.clone(),
            policy_id: request.policy_id,
            bucket_label: request.bucket_label,
            auditor_group_root: request.auditor_group_root,
            accessor_group_root: request.accessor_group_root,
            scope: request.scope,
            window_start_height: request.window_start_height,
            window_end_height: request.window_end_height,
            max_queries: request.max_queries,
            consumed_queries: 0,
            max_distinct_accounts: request.max_distinct_accounts,
            distinct_account_nullifier_root: empty_root("VIEWKEY-BUCKET-NULLIFIERS"),
            status: RateBucketStatus::Open,
            bucket_root,
        };
        self.rate_buckets.insert(bucket_id.clone(), record);
        self.publish_public_record("rate_bucket", &bucket_id)?;
        Ok(bucket_id)
    }

    pub fn record_access_event(&mut self, request: AccessEventRequest) -> Result<String> {
        let ticket = self
            .tickets
            .get(&request.ticket_id)
            .cloned()
            .ok_or_else(|| "unknown ticket".to_string())?;
        let bucket = self
            .rate_buckets
            .get(&request.bucket_id)
            .cloned()
            .ok_or_else(|| "unknown rate bucket".to_string())?;
        ensure(ticket.status.spendable(), "ticket not spendable")?;
        ensure(
            bucket.status.accepts_queries(),
            "bucket not accepting queries",
        )?;
        ensure(
            ticket.policy_id == bucket.policy_id,
            "ticket and bucket policy mismatch",
        )?;
        ensure(
            ticket.scope == bucket.scope,
            "ticket and bucket scope mismatch",
        )?;
        ensure(
            request.consumed_queries > 0 && request.consumed_queries <= ticket.remaining_queries,
            "ticket query allowance exceeded",
        )?;
        ensure(
            bucket.consumed_queries + request.consumed_queries <= bucket.max_queries,
            "bucket query allowance exceeded",
        )?;
        ensure(
            request.fee_quanta <= self.config.low_fee_credit_quanta,
            "fee quanta outside config",
        )?;
        self.sequence += 1;
        let event_id = event_id(self.sequence, &request);
        let event_root = payload_root(
            "VIEWKEY-ACCESS-EVENT",
            &json!({
                "event_id": event_id,
                "ticket_id": request.ticket_id,
                "bucket_id": request.bucket_id,
                "operator_id": request.operator_id,
                "query_commitment_root": request.query_commitment_root,
                "result_redaction_root": request.result_redaction_root,
                "account_nullifier_root": request.account_nullifier_root,
                "consumed_queries": request.consumed_queries,
                "consumed_redaction_units": request.consumed_redaction_units
            }),
        );
        let record = AccessEventRecord {
            event_id: event_id.clone(),
            ticket_id: request.ticket_id.clone(),
            bucket_id: request.bucket_id.clone(),
            operator_id: request.operator_id,
            query_commitment_root: request.query_commitment_root,
            result_redaction_root: request.result_redaction_root,
            account_nullifier_root: request.account_nullifier_root,
            consumed_queries: request.consumed_queries,
            consumed_redaction_units: request.consumed_redaction_units,
            fee_quanta: request.fee_quanta,
            accepted: true,
            event_root,
        };
        if let Some(ticket) = self.tickets.get_mut(&request.ticket_id) {
            ticket.remaining_queries -= request.consumed_queries;
            ticket.status = if ticket.remaining_queries == 0 {
                TicketStatus::Exhausted
            } else {
                TicketStatus::Active
            };
        }
        if let Some(bucket) = self.rate_buckets.get_mut(&request.bucket_id) {
            bucket.consumed_queries += request.consumed_queries;
            bucket.distinct_account_nullifier_root = payload_root(
                "VIEWKEY-BUCKET-NULLIFIERS",
                &json!([
                    bucket.distinct_account_nullifier_root,
                    record.account_nullifier_root
                ]),
            );
            bucket.status = if bucket.consumed_queries >= bucket.max_queries {
                RateBucketStatus::Throttled
            } else if bucket.consumed_queries * 100 >= bucket.max_queries * 80 {
                RateBucketStatus::Warning
            } else {
                RateBucketStatus::Open
            };
        }
        self.consume_redaction_units(&request.ticket_id, request.consumed_redaction_units)?;
        self.consume_credit(&request.ticket_id, request.fee_quanta)?;
        self.access_events.insert(event_id.clone(), record);
        self.publish_public_record("access_event", &event_id)?;
        Ok(event_id)
    }

    pub fn reserve_low_fee_credit(&mut self, request: LowFeeAuditCreditRequest) -> Result<String> {
        ensure(
            self.policies.contains_key(&request.policy_id),
            "unknown policy for credit",
        )?;
        ensure(request.credit_quanta > 0, "credit quanta required")?;
        ensure(
            request.max_user_fee_bps <= self.config.max_user_fee_bps,
            "user fee exceeds configured maximum",
        )?;
        self.sequence += 1;
        let credit_id = credit_id(self.sequence, &request);
        let credit_root = payload_root(
            "VIEWKEY-LOW-FEE-AUDIT-CREDIT",
            &json!({
                "credit_id": credit_id,
                "sponsor_id": request.sponsor_id,
                "policy_id": request.policy_id,
                "beneficiary_commitment_root": request.beneficiary_commitment_root,
                "credit_quanta": request.credit_quanta,
                "max_user_fee_bps": request.max_user_fee_bps,
                "settlement_root": request.settlement_root
            }),
        );
        let record = LowFeeAuditCreditRecord {
            credit_id: credit_id.clone(),
            sponsor_id: request.sponsor_id,
            policy_id: request.policy_id,
            beneficiary_commitment_root: request.beneficiary_commitment_root,
            credit_quanta: request.credit_quanta,
            remaining_quanta: request.credit_quanta,
            max_user_fee_bps: request.max_user_fee_bps,
            settlement_root: request.settlement_root,
            sponsor_signature_root: request.sponsor_signature_root,
            status: AuditCreditStatus::Reserved,
            credit_root,
        };
        self.low_fee_credits.insert(credit_id.clone(), record);
        self.publish_public_record("low_fee_credit", &credit_id)?;
        Ok(credit_id)
    }

    pub fn open_quarantine(&mut self, request: AbuseQuarantineRequest) -> Result<String> {
        ensure(
            request.suspicion_score_bps <= MAX_BPS,
            "suspicion score exceeds max bps",
        )?;
        self.sequence += 1;
        let quarantine_id = quarantine_id(self.sequence, &request);
        let opened_at_height = self.config.created_at_height + self.sequence;
        let quarantine_root = payload_root(
            "VIEWKEY-ABUSE-QUARANTINE",
            &json!({
                "quarantine_id": quarantine_id,
                "subject_id": request.subject_id,
                "ticket_id": request.ticket_id,
                "bucket_id": request.bucket_id,
                "reporter_id": request.reporter_id,
                "kind": request.kind,
                "evidence_root": request.evidence_root,
                "suspicion_score_bps": request.suspicion_score_bps
            }),
        );
        let record = AbuseQuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            subject_id: request.subject_id,
            ticket_id: request.ticket_id.clone(),
            bucket_id: request.bucket_id.clone(),
            reporter_id: request.reporter_id,
            kind: request.kind,
            evidence_root: request.evidence_root,
            suspicion_score_bps: request.suspicion_score_bps,
            opened_at_height,
            expires_at_height: opened_at_height + self.config.quarantine_ttl_blocks,
            status: QuarantineStatus::Open,
            quarantine_root,
        };
        if let Some(ticket_id) = &request.ticket_id {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Quarantined;
            }
        }
        if let Some(bucket_id) = &request.bucket_id {
            if let Some(bucket) = self.rate_buckets.get_mut(bucket_id) {
                bucket.status = RateBucketStatus::Frozen;
            }
        }
        self.quarantines.insert(quarantine_id.clone(), record);
        self.publish_public_record("abuse_quarantine", &quarantine_id)?;
        Ok(quarantine_id)
    }

    pub fn reserve_redaction_budget(&mut self, request: RedactionBudgetRequest) -> Result<String> {
        ensure(
            self.tickets.contains_key(&request.ticket_id),
            "unknown ticket for budget",
        )?;
        ensure(
            self.policies.contains_key(&request.policy_id),
            "unknown policy for budget",
        )?;
        ensure(request.units > 0, "redaction budget units required")?;
        ensure(
            request.units <= self.config.redaction_budget_units,
            "redaction budget exceeds config",
        )?;
        self.sequence += 1;
        let budget_id = budget_id(self.sequence, &request);
        let budget_root = payload_root(
            "VIEWKEY-REDACTION-BUDGET",
            &json!({
                "budget_id": budget_id,
                "ticket_id": request.ticket_id,
                "policy_id": request.policy_id,
                "redactor_id": request.redactor_id,
                "budget_commitment_root": request.budget_commitment_root,
                "nullifier_set_root": request.nullifier_set_root,
                "units": request.units
            }),
        );
        let record = RedactionBudgetRecord {
            budget_id: budget_id.clone(),
            ticket_id: request.ticket_id,
            policy_id: request.policy_id,
            redactor_id: request.redactor_id,
            budget_commitment_root: request.budget_commitment_root,
            nullifier_set_root: request.nullifier_set_root,
            units: request.units,
            remaining_units: request.units,
            status: RedactionBudgetStatus::Reserved,
            budget_root,
        };
        self.redaction_budgets.insert(budget_id.clone(), record);
        self.publish_public_record("redaction_budget", &budget_id)?;
        Ok(budget_id)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            policies: self.policies.len() as u64,
            tickets: self.tickets.len() as u64,
            wallet_attestations: self.wallet_attestations.len() as u64,
            operator_attestations: self.operator_attestations.len() as u64,
            rate_buckets: self.rate_buckets.len() as u64,
            access_events: self.access_events.len() as u64,
            low_fee_credits: self.low_fee_credits.len() as u64,
            quarantines: self.quarantines.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            public_records: self.public_records.len() as u64,
            active_tickets: self
                .tickets
                .values()
                .filter(|ticket| ticket.status.spendable())
                .count() as u64,
            throttled_buckets: self
                .rate_buckets
                .values()
                .filter(|bucket| {
                    matches!(
                        bucket.status,
                        RateBucketStatus::Throttled | RateBucketStatus::Frozen
                    )
                })
                .count() as u64,
            quarantined_subjects: self
                .quarantines
                .values()
                .filter(|quarantine| {
                    matches!(
                        quarantine.status,
                        QuarantineStatus::Open | QuarantineStatus::Investigating
                    )
                })
                .count() as u64,
            remaining_credit_quanta: self
                .low_fee_credits
                .values()
                .map(|credit| credit.remaining_quanta)
                .sum(),
            remaining_redaction_units: self
                .redaction_budgets
                .values()
                .map(|budget| budget.remaining_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let mut roots = Roots {
            config_root: self.config.root(),
            policy_root: records_root("VIEWKEY-POLICIES", &self.policies),
            ticket_root: records_root("VIEWKEY-TICKETS", &self.tickets),
            wallet_attestation_root: records_root(
                "VIEWKEY-WALLET-ATTESTATIONS",
                &self.wallet_attestations,
            ),
            operator_attestation_root: records_root(
                "VIEWKEY-OPERATOR-ATTESTATIONS",
                &self.operator_attestations,
            ),
            rate_bucket_root: records_root("VIEWKEY-RATE-BUCKETS", &self.rate_buckets),
            access_event_root: records_root("VIEWKEY-ACCESS-EVENTS", &self.access_events),
            low_fee_credit_root: records_root("VIEWKEY-LOW-FEE-CREDITS", &self.low_fee_credits),
            quarantine_root: records_root("VIEWKEY-QUARANTINES", &self.quarantines),
            redaction_budget_root: records_root(
                "VIEWKEY-REDACTION-BUDGETS",
                &self.redaction_budgets,
            ),
            public_record_root: records_root("VIEWKEY-PUBLIC-RECORDS", &self.public_records),
            counters_root: payload_root("VIEWKEY-COUNTERS", &counters.public_record()),
            state_root: String::new(),
        };
        roots.state_root = payload_root(
            "VIEWKEY-FIREWALL-ROOTS",
            &json!({
                "config_root": roots.config_root,
                "policy_root": roots.policy_root,
                "ticket_root": roots.ticket_root,
                "wallet_attestation_root": roots.wallet_attestation_root,
                "operator_attestation_root": roots.operator_attestation_root,
                "rate_bucket_root": roots.rate_bucket_root,
                "access_event_root": roots.access_event_root,
                "low_fee_credit_root": roots.low_fee_credit_root,
                "quarantine_root": roots.quarantine_root,
                "redaction_budget_root": roots.redaction_budget_root,
                "public_record_root": roots.public_record_root,
                "counters_root": roots.counters_root
            }),
        );
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "sequence": self.sequence
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "VIEWKEY-FIREWALL-STATE",
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn record_attestation(&mut self, request: PqAttestationRequest) -> Result<String> {
        ensure(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security below configured floor",
        )?;
        ensure(
            request.attester_weight_bps <= MAX_BPS,
            "attester weight exceeds max bps",
        )?;
        self.sequence += 1;
        let attestation_id = attestation_id(self.sequence, &request);
        let expires_at_height = request.l2_height + self.config.attestation_ttl_blocks;
        let attestation_root = payload_root(
            "VIEWKEY-PQ-ATTESTATION",
            &json!({
                "attestation_id": attestation_id,
                "subject": request.subject,
                "subject_id": request.subject_id,
                "attester_id": request.attester_id,
                "committee_id": request.committee_id,
                "l2_height": request.l2_height,
                "pq_security_bits": request.pq_security_bits,
                "attester_weight_bps": request.attester_weight_bps,
                "statement_root": request.statement_root,
                "transcript_root": request.transcript_root,
                "signature_root": request.signature_root
            }),
        );
        let status = if request.attester_weight_bps >= self.config.strong_auditor_quorum_bps {
            AttestationStatus::StrongQuorum
        } else if request.attester_weight_bps >= self.config.min_auditor_quorum_bps {
            AttestationStatus::Quorum
        } else {
            AttestationStatus::Accepted
        };
        let record = PqAttestationRecord {
            attestation_id: attestation_id.clone(),
            subject: request.subject,
            subject_id: request.subject_id,
            attester_id: request.attester_id,
            committee_id: request.committee_id,
            l2_height: request.l2_height,
            expires_at_height,
            pq_security_bits: request.pq_security_bits,
            attester_weight_bps: request.attester_weight_bps,
            statement_root: request.statement_root,
            transcript_root: request.transcript_root,
            signature_root: request.signature_root,
            status,
            attestation_root,
        };
        match request.subject {
            AttestationSubject::Wallet => {
                self.wallet_attestations
                    .insert(attestation_id.clone(), record);
                self.publish_public_record("wallet_attestation", &attestation_id)?;
            }
            AttestationSubject::Operator => {
                self.operator_attestations
                    .insert(attestation_id.clone(), record);
                self.publish_public_record("operator_attestation", &attestation_id)?;
            }
            _ => return Err("unsupported attestation subject store".to_string()),
        }
        Ok(attestation_id)
    }

    fn consume_redaction_units(&mut self, ticket_id: &str, units: u64) -> Result<()> {
        if units == 0 {
            return Ok(());
        }
        let mut remaining = units;
        for budget in self
            .redaction_budgets
            .values_mut()
            .filter(|budget| budget.ticket_id == ticket_id && budget.status.spendable())
        {
            let debit = budget.remaining_units.min(remaining);
            budget.remaining_units -= debit;
            remaining -= debit;
            budget.status = if budget.remaining_units == 0 {
                RedactionBudgetStatus::Exhausted
            } else {
                RedactionBudgetStatus::Applied
            };
            if remaining == 0 {
                break;
            }
        }
        ensure(remaining == 0, "redaction budget exceeded")
    }

    fn consume_credit(&mut self, ticket_id: &str, quanta: u64) -> Result<()> {
        if quanta == 0 {
            return Ok(());
        }
        let credit_id = self
            .tickets
            .get(ticket_id)
            .and_then(|ticket| ticket.low_fee_credit_id.clone());
        if let Some(credit_id) = credit_id {
            let credit = self
                .low_fee_credits
                .get_mut(&credit_id)
                .ok_or_else(|| "missing linked low fee credit".to_string())?;
            ensure(
                credit.remaining_quanta >= quanta,
                "low fee credit exhausted",
            )?;
            credit.remaining_quanta -= quanta;
            credit.status = if credit.remaining_quanta == 0 {
                AuditCreditStatus::Exhausted
            } else {
                AuditCreditStatus::Applied
            };
        }
        Ok(())
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str) -> Result<String> {
        self.sequence += 1;
        let payload_root = match record_kind {
            "auditor_policy" => self
                .policies
                .get(subject_id)
                .map(|record| payload_root("VIEWKEY-PUBLIC-POLICY", &record.public_record())),
            "viewkey_ticket" => self
                .tickets
                .get(subject_id)
                .map(|record| payload_root("VIEWKEY-PUBLIC-TICKET", &record.public_record())),
            "wallet_attestation" => self.wallet_attestations.get(subject_id).map(|record| {
                payload_root("VIEWKEY-PUBLIC-WALLET-ATTESTATION", &record.public_record())
            }),
            "operator_attestation" => self.operator_attestations.get(subject_id).map(|record| {
                payload_root(
                    "VIEWKEY-PUBLIC-OPERATOR-ATTESTATION",
                    &record.public_record(),
                )
            }),
            "rate_bucket" => self
                .rate_buckets
                .get(subject_id)
                .map(|record| payload_root("VIEWKEY-PUBLIC-BUCKET", &record.public_record())),
            "access_event" => self
                .access_events
                .get(subject_id)
                .map(|record| payload_root("VIEWKEY-PUBLIC-EVENT", &record.public_record())),
            "low_fee_credit" => self
                .low_fee_credits
                .get(subject_id)
                .map(|record| payload_root("VIEWKEY-PUBLIC-CREDIT", &record.public_record())),
            "abuse_quarantine" => self
                .quarantines
                .get(subject_id)
                .map(|record| payload_root("VIEWKEY-PUBLIC-QUARANTINE", &record.public_record())),
            "redaction_budget" => self
                .redaction_budgets
                .get(subject_id)
                .map(|record| payload_root("VIEWKEY-PUBLIC-BUDGET", &record.public_record())),
            _ => None,
        }
        .ok_or_else(|| "missing subject for public record".to_string())?;
        let record_id = public_record_id(self.sequence, record_kind, subject_id, &payload_root);
        let entry = PublicRecordEntry {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            sequence: self.sequence,
        };
        self.public_records.insert(record_id.clone(), entry);
        Ok(record_id)
    }
}

pub fn devnet() -> State {
    State::devnet().expect("devnet viewkey firewall state builds")
}

pub fn demo() -> State {
    State::demo().expect("demo viewkey firewall state builds")
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn records_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records.values().map(record_value).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_value<T: Serialize>(record: &T) -> Value {
    serde_json::to_value(record).expect("record serializes")
}

fn enum_tag<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn policy_id(sequence: u64, request: &AuditorPolicyRequest) -> String {
    domain_hash(
        "VIEWKEY-AUDITOR-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.auditor_id),
            HashPart::Str(&request.policy_commitment_root),
            HashPart::Str(&request.disclosure_rule_root),
            HashPart::Str(&request.policy_nonce),
        ],
        32,
    )
}

fn ticket_id(sequence: u64, request: &ViewkeyTicketRequest) -> String {
    let scope = enum_tag(request.scope);
    domain_hash(
        "SHIELDED-VIEWKEY-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&scope),
            HashPart::Str(&request.wallet_commitment_root),
            HashPart::Str(&request.shielded_account_root),
            HashPart::Str(&request.viewkey_capability_root),
            HashPart::Str(&request.ticket_nonce),
        ],
        32,
    )
}

fn attestation_id(sequence: u64, request: &PqAttestationRequest) -> String {
    let subject = enum_tag(request.subject);
    domain_hash(
        "VIEWKEY-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&subject),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.attester_id),
            HashPart::Str(&request.committee_id),
            HashPart::U64(request.l2_height),
            HashPart::U64(request.pq_security_bits as u64),
            HashPart::Str(&request.statement_root),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

fn bucket_id(sequence: u64, request: &RateBucketRequest) -> String {
    let scope = enum_tag(request.scope);
    domain_hash(
        "VIEWKEY-RATE-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&request.bucket_label),
            HashPart::Str(&scope),
            HashPart::U64(request.window_start_height),
            HashPart::U64(request.window_end_height),
            HashPart::Str(&request.bucket_nonce),
        ],
        32,
    )
}

fn event_id(sequence: u64, request: &AccessEventRequest) -> String {
    domain_hash(
        "VIEWKEY-ACCESS-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.ticket_id),
            HashPart::Str(&request.bucket_id),
            HashPart::Str(&request.operator_id),
            HashPart::Str(&request.query_commitment_root),
            HashPart::Str(&request.result_redaction_root),
            HashPart::Str(&request.event_nonce),
        ],
        32,
    )
}

fn credit_id(sequence: u64, request: &LowFeeAuditCreditRequest) -> String {
    domain_hash(
        "VIEWKEY-LOW-FEE-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&request.beneficiary_commitment_root),
            HashPart::U64(request.credit_quanta),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.credit_nonce),
        ],
        32,
    )
}

fn quarantine_id(sequence: u64, request: &AbuseQuarantineRequest) -> String {
    let kind = enum_tag(request.kind);
    domain_hash(
        "VIEWKEY-ABUSE-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.ticket_id.as_deref().unwrap_or("")),
            HashPart::Str(request.bucket_id.as_deref().unwrap_or("")),
            HashPart::Str(&request.reporter_id),
            HashPart::Str(&kind),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.quarantine_nonce),
        ],
        32,
    )
}

fn budget_id(sequence: u64, request: &RedactionBudgetRequest) -> String {
    domain_hash(
        "VIEWKEY-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.ticket_id),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&request.redactor_id),
            HashPart::Str(&request.budget_commitment_root),
            HashPart::Str(&request.nullifier_set_root),
            HashPart::Str(&request.budget_nonce),
        ],
        32,
    )
}

fn public_record_id(
    sequence: u64,
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
) -> String {
    domain_hash(
        "VIEWKEY-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

fn demo_root(label: &str, sequence: u64) -> String {
    domain_hash(
        "VIEWKEY-FIREWALL-DEMO-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}
