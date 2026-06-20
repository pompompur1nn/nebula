use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractEncryptedMempoolStateAccessRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_MEMPOOL_STATE_ACCESS_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-encrypted-mempool-state-access-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_MEMPOOL_STATE_ACCESS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_ACCESS_TICKET_SUITE: &str =
    "ml-kem-1024+xwing-confidential-contract-state-access-ticket-v1";
pub const CONTRACT_HINT_SUITE: &str = "encrypted-mempool-confidential-contract-read-write-hint-v1";
pub const PQ_ACCESS_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-state-access-attestation-v1";
pub const PRIVACY_BUDGET_SUITE: &str = "contract-encrypted-mempool-state-access-privacy-budget-v1";
pub const FEE_SPONSOR_SUITE: &str = "state-access-confidential-fee-sponsor-v1";
pub const REPLAY_FENCE_SUITE: &str = "mempool-state-access-nullifier-replay-fence-v1";
pub const SETTLEMENT_RECEIPT_SUITE: &str =
    "confidential-contract-state-access-settlement-receipt-v1";
pub const REDACTION_BUDGET_SUITE: &str = "operator-safe-state-access-redaction-budget-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-confidential-state-access-summary-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_184_420;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_754_880;
pub const DEVNET_EPOCH: u64 = 22_117;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_ACCESS_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REPLAY_FENCE_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BASE_ACCESS_FEE_MICRO_UNITS: u128 = 1_100;
pub const DEFAULT_READ_HINT_FEE_MICRO_UNITS: u128 = 160;
pub const DEFAULT_WRITE_HINT_FEE_MICRO_UNITS: u128 = 420;
pub const DEFAULT_SPONSOR_REBATE_BPS: u64 = 850;
pub const DEFAULT_REDACTION_BUDGET_BPS: u64 = 350;
pub const DEFAULT_MAX_ACCESS_TICKETS: usize = 4_194_304;
pub const DEFAULT_MAX_CONTRACT_HINTS: usize = 8_388_608;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_PRIVACY_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_FEE_SPONSORS: usize = 262_144;
pub const DEFAULT_MAX_REPLAY_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_SETTLEMENT_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessClass {
    ReadOnly,
    WriteIntent,
    ReadWrite,
    CrossContractRead,
    CrossContractWrite,
    OracleCallback,
    BridgeReserveCheck,
    LiquidationProbe,
    GovernanceSecret,
    EmergencyRepair,
}

impl AccessClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::WriteIntent => "write_intent",
            Self::ReadWrite => "read_write",
            Self::CrossContractRead => "cross_contract_read",
            Self::CrossContractWrite => "cross_contract_write",
            Self::OracleCallback => "oracle_callback",
            Self::BridgeReserveCheck => "bridge_reserve_check",
            Self::LiquidationProbe => "liquidation_probe",
            Self::GovernanceSecret => "governance_secret",
            Self::EmergencyRepair => "emergency_repair",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::ReadOnly => 64,
            Self::CrossContractRead => 72,
            Self::BridgeReserveCheck => 88,
            Self::OracleCallback => 96,
            Self::LiquidationProbe => 112,
            Self::WriteIntent => 128,
            Self::ReadWrite => 144,
            Self::CrossContractWrite => 160,
            Self::GovernanceSecret => 176,
            Self::EmergencyRepair => 224,
        }
    }

    pub fn writes_state(self) -> bool {
        matches!(
            self,
            Self::WriteIntent
                | Self::ReadWrite
                | Self::CrossContractWrite
                | Self::OracleCallback
                | Self::LiquidationProbe
                | Self::GovernanceSecret
                | Self::EmergencyRepair
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Submitted,
    Encrypted,
    Attested,
    BudgetReserved,
    Sponsored,
    Admitted,
    Settled,
    Expired,
    Rejected,
    Quarantined,
}

impl TicketStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Encrypted
                | Self::Attested
                | Self::BudgetReserved
                | Self::Sponsored
                | Self::Admitted
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Expired | Self::Rejected | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintKind {
    ReadSlot,
    WriteSlot,
    ReadRange,
    WriteRange,
    ReadMerklePath,
    WriteMerklePath,
    FheLookup,
    OracleMirror,
    CrossContractDependency,
    ReplayNullifier,
}

impl HintKind {
    pub fn writes_state(self) -> bool {
        matches!(
            self,
            Self::WriteSlot | Self::WriteRange | Self::WriteMerklePath
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintStatus {
    Proposed,
    Encrypted,
    BoundToTicket,
    Attested,
    Consumed,
    Redacted,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    AccessKeyBinding,
    HintCorrectness,
    BudgetOpening,
    SponsorAuthorization,
    ReplayFenceOpening,
    SettlementInclusion,
    RedactionReview,
    OperatorSummary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Pending,
    Accept,
    Reject,
    Challenge,
    Superseded,
    Revoked,
}

impl AttestationVerdict {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Accept)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    AccessTicket,
    ReadHint,
    WriteHint,
    CrossContractHint,
    ReplayFence,
    SettlementReceipt,
    OperatorSummary,
    EmergencyDisclosure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Reserved,
    PartiallySpent,
    Exhausted,
    RebateQueued,
    Settled,
    Expired,
    Slashed,
}

impl BudgetStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::PartiallySpent)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Proposed,
    Active,
    Reserved,
    RebateQueued,
    Settled,
    Exhausted,
    Suspended,
    Slashed,
}

impl SponsorStatus {
    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active | Self::Reserved | Self::RebateQueued)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Bound,
    Spent,
    Settled,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Included,
    Settled,
    Deferred,
    ReorgProtected,
    Challenged,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    TicketMetadata,
    ContractHint,
    AttestationSignerSet,
    SponsorLink,
    ReplayFence,
    ReceiptPath,
    OperatorSummary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryStatus {
    Draft,
    Published,
    Settled,
    Disputed,
    Redacted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub encrypted_access_ticket_suite: String,
    pub contract_hint_suite: String,
    pub pq_access_attestation_suite: String,
    pub privacy_budget_suite: String,
    pub fee_sponsor_suite: String,
    pub replay_fence_suite: String,
    pub settlement_receipt_suite: String,
    pub redaction_budget_suite: String,
    pub operator_summary_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub access_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub privacy_budget_ttl_blocks: u64,
    pub replay_fence_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub base_access_fee_micro_units: u128,
    pub read_hint_fee_micro_units: u128,
    pub write_hint_fee_micro_units: u128,
    pub sponsor_rebate_bps: u64,
    pub redaction_budget_bps: u64,
    pub max_access_tickets: usize,
    pub max_contract_hints: usize,
    pub max_attestations: usize,
    pub max_privacy_budgets: usize,
    pub max_fee_sponsors: usize,
    pub max_replay_fences: usize,
    pub max_settlement_receipts: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_access_ticket_suite: ENCRYPTED_ACCESS_TICKET_SUITE.to_string(),
            contract_hint_suite: CONTRACT_HINT_SUITE.to_string(),
            pq_access_attestation_suite: PQ_ACCESS_ATTESTATION_SUITE.to_string(),
            privacy_budget_suite: PRIVACY_BUDGET_SUITE.to_string(),
            fee_sponsor_suite: FEE_SPONSOR_SUITE.to_string(),
            replay_fence_suite: REPLAY_FENCE_SUITE.to_string(),
            settlement_receipt_suite: SETTLEMENT_RECEIPT_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            access_ttl_blocks: DEFAULT_ACCESS_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            privacy_budget_ttl_blocks: DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS,
            replay_fence_ttl_blocks: DEFAULT_REPLAY_FENCE_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            base_access_fee_micro_units: DEFAULT_BASE_ACCESS_FEE_MICRO_UNITS,
            read_hint_fee_micro_units: DEFAULT_READ_HINT_FEE_MICRO_UNITS,
            write_hint_fee_micro_units: DEFAULT_WRITE_HINT_FEE_MICRO_UNITS,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            redaction_budget_bps: DEFAULT_REDACTION_BUDGET_BPS,
            max_access_tickets: DEFAULT_MAX_ACCESS_TICKETS,
            max_contract_hints: DEFAULT_MAX_CONTRACT_HINTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_privacy_budgets: DEFAULT_MAX_PRIVACY_BUDGETS,
            max_fee_sponsors: DEFAULT_MAX_FEE_SPONSORS,
            max_replay_fences: DEFAULT_MAX_REPLAY_FENCES,
            max_settlement_receipts: DEFAULT_MAX_SETTLEMENT_RECEIPTS,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub access_tickets: u64,
    pub contract_hints: u64,
    pub pq_attestations: u64,
    pub privacy_budgets: u64,
    pub fee_sponsors: u64,
    pub replay_fences: u64,
    pub settlement_receipts: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub admitted_tickets: u64,
    pub settled_tickets: u64,
    pub rejected_tickets: u64,
    pub sponsored_tickets: u64,
    pub redacted_items: u64,
    pub total_fee_micro_units: u128,
    pub sponsored_fee_micro_units: u128,
    pub privacy_units_reserved: u128,
    pub privacy_units_spent: u128,
}

impl Counters {
    pub fn ticket_acceptance_bps(&self) -> u64 {
        if self.access_tickets == 0 {
            return 0;
        }
        self.admitted_tickets.saturating_mul(MAX_BPS) / self.access_tickets
    }

    pub fn sponsorship_bps(&self) -> u64 {
        if self.access_tickets == 0 {
            return 0;
        }
        self.sponsored_tickets.saturating_mul(MAX_BPS) / self.access_tickets
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub access_ticket_root: String,
    pub contract_hint_root: String,
    pub pq_attestation_root: String,
    pub privacy_budget_root: String,
    pub fee_sponsor_root: String,
    pub replay_fence_root: String,
    pub settlement_receipt_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            access_ticket_root: empty_root("ACCESS-TICKET"),
            contract_hint_root: empty_root("CONTRACT-HINT"),
            pq_attestation_root: empty_root("PQ-ATTESTATION"),
            privacy_budget_root: empty_root("PRIVACY-BUDGET"),
            fee_sponsor_root: empty_root("FEE-SPONSOR"),
            replay_fence_root: empty_root("REPLAY-FENCE"),
            settlement_receipt_root: empty_root("SETTLEMENT-RECEIPT"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            operator_summary_root: empty_root("OPERATOR-SUMMARY"),
            public_record_root: empty_root("PUBLIC-RECORD"),
            state_root: empty_root("STATE"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStateAccessTicket {
    pub ticket_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub access_class: AccessClass,
    pub status: TicketStatus,
    pub encrypted_ticket_root: String,
    pub access_key_commitment: String,
    pub state_namespace_root: String,
    pub requested_read_units: u64,
    pub requested_write_units: u64,
    pub max_fee_micro_units: u128,
    pub sponsor_id: Option<String>,
    pub privacy_budget_id: Option<String>,
    pub replay_fence_id: Option<String>,
    pub hint_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub settlement_receipt_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedStateAccessTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "access_class": self.access_class,
            "status": self.status,
            "encrypted_ticket_root": self.encrypted_ticket_root,
            "access_key_commitment": self.access_key_commitment,
            "state_namespace_root": self.state_namespace_root,
            "requested_read_units": self.requested_read_units,
            "requested_write_units": self.requested_write_units,
            "max_fee_micro_units": self.max_fee_micro_units.to_string(),
            "sponsor_id": self.sponsor_id,
            "privacy_budget_id": self.privacy_budget_id,
            "replay_fence_id": self.replay_fence_id,
            "hint_ids": self.hint_ids,
            "attestation_ids": self.attestation_ids,
            "settlement_receipt_id": self.settlement_receipt_id,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("EncryptedStateAccessTicket", self.public_record())
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractReadWriteHint {
    pub hint_id: String,
    pub ticket_id: String,
    pub contract_id: String,
    pub hint_kind: HintKind,
    pub status: HintStatus,
    pub encrypted_hint_root: String,
    pub slot_commitment_root: String,
    pub access_path_commitment: String,
    pub read_units: u64,
    pub write_units: u64,
    pub conflict_domain: String,
    pub redaction_budget_id: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ContractReadWriteHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "ticket_id": self.ticket_id,
            "contract_id": self.contract_id,
            "hint_kind": self.hint_kind,
            "status": self.status,
            "encrypted_hint_root": self.encrypted_hint_root,
            "slot_commitment_root": self.slot_commitment_root,
            "access_path_commitment": self.access_path_commitment,
            "read_units": self.read_units,
            "write_units": self.write_units,
            "conflict_domain": self.conflict_domain,
            "redaction_budget_id": self.redaction_budget_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("ContractReadWriteHint", self.public_record())
    }

    pub fn fee_units(&self, config: &Config) -> u128 {
        let read_fee = self.read_units as u128 * config.read_hint_fee_micro_units;
        let write_fee = self.write_units as u128 * config.write_hint_fee_micro_units;
        read_fee.saturating_add(write_fee)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAccessAttestation {
    pub attestation_id: String,
    pub ticket_id: String,
    pub contract_id: String,
    pub attestor_id: String,
    pub kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub access_policy_root: String,
    pub privacy_set_size: u64,
    pub security_bits: u16,
    pub signer_weight: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqAccessAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "ticket_id": self.ticket_id,
            "contract_id": self.contract_id,
            "attestor_id": redacted_operator(&self.attestor_id),
            "kind": self.kind,
            "verdict": self.verdict,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "access_policy_root": self.access_policy_root,
            "privacy_set_size": self.privacy_set_size,
            "security_bits": self.security_bits,
            "signer_weight": self.signer_weight,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("PqAccessAttestation", self.public_record())
    }

    pub fn valid_for(&self, config: &Config, height: u64) -> bool {
        self.verdict.accepted()
            && self.security_bits >= config.min_pq_security_bits
            && self.privacy_set_size >= config.min_privacy_set_size
            && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub contract_id: String,
    pub scopes: BTreeSet<BudgetScope>,
    pub status: BudgetStatus,
    pub total_units: u128,
    pub reserved_units: u128,
    pub spent_units: u128,
    pub budget_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "contract_id": self.contract_id,
            "scopes": self.scopes,
            "status": self.status,
            "total_units": self.total_units.to_string(),
            "reserved_units": self.reserved_units.to_string(),
            "spent_units": self.spent_units.to_string(),
            "remaining_units": self.remaining_units().to_string(),
            "budget_root": self.budget_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("PrivacyBudget", self.public_record())
    }

    pub fn remaining_units(&self) -> u128 {
        self.total_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn can_reserve(&self, scope: BudgetScope, units: u128, height: u64) -> bool {
        self.status.spendable()
            && self.scopes.contains(&scope)
            && self.remaining_units() >= units
            && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub contract_id: String,
    pub status: SponsorStatus,
    pub max_fee_micro_units: u128,
    pub reserved_fee_micro_units: u128,
    pub paid_fee_micro_units: u128,
    pub rebate_bps: u64,
    pub sponsor_policy_root: String,
    pub ticket_ids: BTreeSet<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsor {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "contract_id": self.contract_id,
            "status": self.status,
            "max_fee_micro_units": self.max_fee_micro_units.to_string(),
            "reserved_fee_micro_units": self.reserved_fee_micro_units.to_string(),
            "paid_fee_micro_units": self.paid_fee_micro_units.to_string(),
            "remaining_fee_micro_units": self.remaining_fee_micro_units().to_string(),
            "rebate_bps": self.rebate_bps,
            "sponsor_policy_root": self.sponsor_policy_root,
            "ticket_ids": self.ticket_ids,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("FeeSponsor", self.public_record())
    }

    pub fn remaining_fee_micro_units(&self) -> u128 {
        self.max_fee_micro_units
            .saturating_sub(self.reserved_fee_micro_units)
            .saturating_sub(self.paid_fee_micro_units)
    }

    pub fn can_cover(&self, fee: u128, height: u64) -> bool {
        self.status.can_sponsor()
            && self.remaining_fee_micro_units() >= fee
            && self.rebate_bps <= MAX_BPS
            && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub ticket_id: String,
    pub contract_id: String,
    pub nullifier_commitment: String,
    pub status: FenceStatus,
    pub fence_root: String,
    pub access_epoch: u64,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
}

impl ReplayFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "ticket_id": self.ticket_id,
            "contract_id": self.contract_id,
            "nullifier_commitment": self.nullifier_commitment,
            "status": self.status,
            "fence_root": self.fence_root,
            "access_epoch": self.access_epoch,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("ReplayFence", self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub ticket_id: String,
    pub contract_id: String,
    pub status: ReceiptStatus,
    pub settlement_root: String,
    pub state_before_root: String,
    pub state_after_root: String,
    pub consumed_hint_root: String,
    pub replay_fence_root: String,
    pub fee_paid_micro_units: u128,
    pub sponsored_fee_micro_units: u128,
    pub included_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "ticket_id": self.ticket_id,
            "contract_id": self.contract_id,
            "status": self.status,
            "settlement_root": self.settlement_root,
            "state_before_root": self.state_before_root,
            "state_after_root": self.state_after_root,
            "consumed_hint_root": self.consumed_hint_root,
            "replay_fence_root": self.replay_fence_root,
            "fee_paid_micro_units": self.fee_paid_micro_units.to_string(),
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units.to_string(),
            "included_at_height": self.included_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("SettlementReceipt", self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub redaction_budget_id: String,
    pub operator_id: String,
    pub contract_id: String,
    pub epoch: u64,
    pub scopes: BTreeSet<RedactionScope>,
    pub max_redaction_bps: u64,
    pub spent_redaction_bps: u64,
    pub redaction_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_budget_id": self.redaction_budget_id,
            "operator_id": redacted_operator(&self.operator_id),
            "contract_id": self.contract_id,
            "epoch": self.epoch,
            "scopes": self.scopes,
            "max_redaction_bps": self.max_redaction_bps,
            "spent_redaction_bps": self.spent_redaction_bps,
            "remaining_redaction_bps": self.remaining_bps(),
            "redaction_root": self.redaction_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("RedactionBudget", self.public_record())
    }

    pub fn remaining_bps(&self) -> u64 {
        self.max_redaction_bps
            .saturating_sub(self.spent_redaction_bps)
    }

    pub fn can_redact(&self, scope: RedactionScope, charge_bps: u64, height: u64) -> bool {
        self.scopes.contains(&scope)
            && self.remaining_bps() >= charge_bps
            && height <= self.expires_at_height
            && self.max_redaction_bps <= MAX_BPS
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub contract_id: String,
    pub epoch: u64,
    pub status: SummaryStatus,
    pub admitted_ticket_count: u64,
    pub settled_ticket_count: u64,
    pub rejected_ticket_count: u64,
    pub read_hint_count: u64,
    pub write_hint_count: u64,
    pub replay_fence_count: u64,
    pub sponsored_fee_micro_units: u128,
    pub privacy_units_spent: u128,
    pub p50_access_latency_ms: u64,
    pub p95_access_latency_ms: u64,
    pub redacted: bool,
    pub public_summary_root: String,
    pub emitted_at_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": redacted_operator(&self.operator_id),
            "contract_id": self.contract_id,
            "epoch": self.epoch,
            "status": self.status,
            "admitted_ticket_count": self.admitted_ticket_count,
            "settled_ticket_count": self.settled_ticket_count,
            "rejected_ticket_count": self.rejected_ticket_count,
            "read_hint_count": self.read_hint_count,
            "write_hint_count": self.write_hint_count,
            "replay_fence_count": self.replay_fence_count,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units.to_string(),
            "privacy_units_spent": self.privacy_units_spent.to_string(),
            "p50_access_latency_ms": self.p50_access_latency_ms,
            "p95_access_latency_ms": self.p95_access_latency_ms,
            "redacted": self.redacted,
            "public_summary_root": self.public_summary_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn digest(&self) -> String {
        stable_digest("OperatorSummary", self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub access_tickets: BTreeMap<String, EncryptedStateAccessTicket>,
    pub contract_hints: BTreeMap<String, ContractReadWriteHint>,
    pub pq_attestations: BTreeMap<String, PqAccessAttestation>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub fee_sponsors: BTreeMap<String, FeeSponsor>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            l2_height,
            monero_height,
            epoch,
            access_tickets: BTreeMap::new(),
            contract_hints: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            fee_sponsors: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.recompute();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        );
        state.install_devnet_fixture();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "mode": self.config.mode,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "counters": self.counters,
            "roots": {
                "access_ticket_root": self.roots.access_ticket_root,
                "contract_hint_root": self.roots.contract_hint_root,
                "pq_attestation_root": self.roots.pq_attestation_root,
                "privacy_budget_root": self.roots.privacy_budget_root,
                "fee_sponsor_root": self.roots.fee_sponsor_root,
                "replay_fence_root": self.roots.replay_fence_root,
                "settlement_receipt_root": self.roots.settlement_receipt_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "operator_summary_root": self.roots.operator_summary_root,
                "public_record_root": self.roots.public_record_root,
                "state_root": self.roots.state_root,
            },
            "operator_safe": {
                "active_tickets": self.active_ticket_count(),
                "terminal_tickets": self.terminal_ticket_count(),
                "ticket_acceptance_bps": self.counters.ticket_acceptance_bps(),
                "sponsorship_bps": self.counters.sponsorship_bps(),
                "privacy_units_remaining": self.total_privacy_units_remaining().to_string(),
                "sponsor_fee_remaining": self.total_sponsor_fee_remaining().to_string(),
            },
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn submit_ticket(&mut self, mut ticket: EncryptedStateAccessTicket) -> Result<String> {
        ensure!(
            self.access_tickets.len() < self.config.max_access_tickets,
            "access ticket capacity exhausted"
        );
        ensure!(
            !self.access_tickets.contains_key(&ticket.ticket_id),
            "duplicate access ticket {}",
            ticket.ticket_id
        );
        ensure!(
            ticket.expires_at_height > self.l2_height,
            "access ticket {} is already expired",
            ticket.ticket_id
        );
        ticket.status = TicketStatus::Encrypted;
        let id = ticket.ticket_id.clone();
        self.access_tickets.insert(id.clone(), ticket);
        self.recompute();
        Ok(id)
    }

    pub fn add_hint(&mut self, mut hint: ContractReadWriteHint) -> Result<String> {
        ensure!(
            self.contract_hints.len() < self.config.max_contract_hints,
            "contract hint capacity exhausted"
        );
        ensure!(
            !self.contract_hints.contains_key(&hint.hint_id),
            "duplicate contract hint {}",
            hint.hint_id
        );
        ensure!(
            self.access_tickets.contains_key(&hint.ticket_id),
            "missing access ticket {}",
            hint.ticket_id
        );
        ensure!(
            hint.expires_at_height > self.l2_height,
            "contract hint {} is already expired",
            hint.hint_id
        );
        hint.status = HintStatus::BoundToTicket;
        let id = hint.hint_id.clone();
        if let Some(ticket) = self.access_tickets.get_mut(&hint.ticket_id) {
            ticket.hint_ids.insert(id.clone());
        }
        self.contract_hints.insert(id.clone(), hint);
        self.recompute();
        Ok(id)
    }

    pub fn add_attestation(&mut self, attestation: PqAccessAttestation) -> Result<String> {
        ensure!(
            self.pq_attestations.len() < self.config.max_attestations,
            "pq attestation capacity exhausted"
        );
        ensure!(
            !self
                .pq_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate pq attestation {}",
            attestation.attestation_id
        );
        ensure!(
            self.access_tickets.contains_key(&attestation.ticket_id),
            "missing access ticket {}",
            attestation.ticket_id
        );
        ensure!(
            attestation.valid_for(&self.config, self.l2_height),
            "pq attestation {} does not satisfy access policy",
            attestation.attestation_id
        );
        let id = attestation.attestation_id.clone();
        if let Some(ticket) = self.access_tickets.get_mut(&attestation.ticket_id) {
            ticket.status = TicketStatus::Attested;
            ticket.attestation_ids.insert(id.clone());
        }
        self.pq_attestations.insert(id.clone(), attestation);
        self.recompute();
        Ok(id)
    }

    pub fn add_privacy_budget(&mut self, budget: PrivacyBudget) -> Result<String> {
        ensure!(
            self.privacy_budgets.len() < self.config.max_privacy_budgets,
            "privacy budget capacity exhausted"
        );
        ensure!(
            !self.privacy_budgets.contains_key(&budget.budget_id),
            "duplicate privacy budget {}",
            budget.budget_id
        );
        ensure!(
            budget.expires_at_height > self.l2_height,
            "privacy budget {} is expired",
            budget.budget_id
        );
        let id = budget.budget_id.clone();
        self.privacy_budgets.insert(id.clone(), budget);
        self.recompute();
        Ok(id)
    }

    pub fn reserve_privacy_budget(
        &mut self,
        ticket_id: &str,
        budget_id: &str,
        scope: BudgetScope,
        units: u128,
    ) -> Result<()> {
        let budget = self
            .privacy_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("missing privacy budget {budget_id}"))?;
        ensure!(
            budget.can_reserve(scope, units, self.l2_height),
            "privacy budget {budget_id} cannot reserve {units} units"
        );
        let ticket = self
            .access_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("missing access ticket {ticket_id}"))?;
        budget.reserved_units = budget.reserved_units.saturating_add(units);
        budget.status = BudgetStatus::Reserved;
        ticket.privacy_budget_id = Some(budget_id.to_string());
        ticket.status = TicketStatus::BudgetReserved;
        self.recompute();
        Ok(())
    }

    pub fn add_fee_sponsor(&mut self, sponsor: FeeSponsor) -> Result<String> {
        ensure!(
            self.fee_sponsors.len() < self.config.max_fee_sponsors,
            "fee sponsor capacity exhausted"
        );
        ensure!(
            !self.fee_sponsors.contains_key(&sponsor.sponsor_id),
            "duplicate fee sponsor {}",
            sponsor.sponsor_id
        );
        ensure!(
            sponsor.rebate_bps <= MAX_BPS,
            "fee sponsor {} rebate exceeds max bps",
            sponsor.sponsor_id
        );
        let id = sponsor.sponsor_id.clone();
        self.fee_sponsors.insert(id.clone(), sponsor);
        self.recompute();
        Ok(id)
    }

    pub fn sponsor_ticket(&mut self, ticket_id: &str, sponsor_id: &str, fee: u128) -> Result<()> {
        let sponsor = self
            .fee_sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| format!("missing fee sponsor {sponsor_id}"))?;
        ensure!(
            sponsor.can_cover(fee, self.l2_height),
            "fee sponsor {sponsor_id} cannot cover {fee} micro units"
        );
        let ticket = self
            .access_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("missing access ticket {ticket_id}"))?;
        sponsor.reserved_fee_micro_units = sponsor.reserved_fee_micro_units.saturating_add(fee);
        sponsor.ticket_ids.insert(ticket_id.to_string());
        sponsor.status = SponsorStatus::Reserved;
        ticket.sponsor_id = Some(sponsor_id.to_string());
        ticket.status = TicketStatus::Sponsored;
        self.recompute();
        Ok(())
    }

    pub fn add_replay_fence(&mut self, fence: ReplayFence) -> Result<String> {
        ensure!(
            self.replay_fences.len() < self.config.max_replay_fences,
            "replay fence capacity exhausted"
        );
        ensure!(
            !self.replay_fences.contains_key(&fence.fence_id),
            "duplicate replay fence {}",
            fence.fence_id
        );
        ensure!(
            !self
                .replay_fences
                .values()
                .any(
                    |existing| existing.nullifier_commitment == fence.nullifier_commitment
                        && matches!(existing.status, FenceStatus::Bound | FenceStatus::Spent)
                ),
            "replay nullifier already fenced"
        );
        let id = fence.fence_id.clone();
        if let Some(ticket) = self.access_tickets.get_mut(&fence.ticket_id) {
            ticket.replay_fence_id = Some(id.clone());
        }
        self.replay_fences.insert(id.clone(), fence);
        self.recompute();
        Ok(id)
    }

    pub fn settle_ticket(&mut self, receipt: SettlementReceipt) -> Result<String> {
        ensure!(
            self.settlement_receipts.len() < self.config.max_settlement_receipts,
            "settlement receipt capacity exhausted"
        );
        ensure!(
            !self.settlement_receipts.contains_key(&receipt.receipt_id),
            "duplicate settlement receipt {}",
            receipt.receipt_id
        );
        let ticket = self
            .access_tickets
            .get_mut(&receipt.ticket_id)
            .ok_or_else(|| format!("missing access ticket {}", receipt.ticket_id))?;
        ensure!(
            !ticket.status.terminal(),
            "access ticket {} is terminal",
            receipt.ticket_id
        );
        ticket.status = TicketStatus::Settled;
        ticket.settlement_receipt_id = Some(receipt.receipt_id.clone());
        if let Some(fence_id) = ticket.replay_fence_id.clone() {
            if let Some(fence) = self.replay_fences.get_mut(&fence_id) {
                fence.status = FenceStatus::Settled;
            }
        }
        let id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(id.clone(), receipt);
        self.recompute();
        Ok(id)
    }

    pub fn add_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity exhausted"
        );
        ensure!(
            !self
                .redaction_budgets
                .contains_key(&budget.redaction_budget_id),
            "duplicate redaction budget {}",
            budget.redaction_budget_id
        );
        ensure!(
            budget.max_redaction_bps <= MAX_BPS,
            "redaction budget {} exceeds max bps",
            budget.redaction_budget_id
        );
        let id = budget.redaction_budget_id.clone();
        self.redaction_budgets.insert(id.clone(), budget);
        self.recompute();
        Ok(id)
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity exhausted"
        );
        ensure!(
            !self.operator_summaries.contains_key(&summary.summary_id),
            "duplicate operator summary {}",
            summary.summary_id
        );
        let id = summary.summary_id.clone();
        self.operator_summaries.insert(id.clone(), summary);
        self.recompute();
        Ok(id)
    }

    pub fn expire_height(&mut self, height: u64) {
        self.l2_height = height;
        for ticket in self.access_tickets.values_mut() {
            if ticket.active() && ticket.expired_at(height) {
                ticket.status = TicketStatus::Expired;
            }
        }
        for hint in self.contract_hints.values_mut() {
            if height > hint.expires_at_height && !matches!(hint.status, HintStatus::Consumed) {
                hint.status = HintStatus::Expired;
            }
        }
        for fence in self.replay_fences.values_mut() {
            if height > fence.expires_at_height && matches!(fence.status, FenceStatus::Open) {
                fence.status = FenceStatus::Expired;
            }
        }
        self.recompute();
    }

    pub fn recompute(&mut self) {
        self.counters = Counters {
            access_tickets: self.access_tickets.len() as u64,
            contract_hints: self.contract_hints.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            privacy_budgets: self.privacy_budgets.len() as u64,
            fee_sponsors: self.fee_sponsors.len() as u64,
            replay_fences: self.replay_fences.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            admitted_tickets: self.count_tickets(TicketStatus::Admitted),
            settled_tickets: self.count_tickets(TicketStatus::Settled),
            rejected_tickets: self.count_tickets(TicketStatus::Rejected),
            sponsored_tickets: self
                .access_tickets
                .values()
                .filter(|ticket| ticket.sponsor_id.is_some())
                .count() as u64,
            redacted_items: self
                .redaction_budgets
                .values()
                .filter(|budget| budget.spent_redaction_bps > 0)
                .count() as u64,
            total_fee_micro_units: self
                .settlement_receipts
                .values()
                .map(|receipt| receipt.fee_paid_micro_units)
                .sum(),
            sponsored_fee_micro_units: self
                .settlement_receipts
                .values()
                .map(|receipt| receipt.sponsored_fee_micro_units)
                .sum(),
            privacy_units_reserved: self
                .privacy_budgets
                .values()
                .map(|budget| budget.reserved_units)
                .sum(),
            privacy_units_spent: self
                .privacy_budgets
                .values()
                .map(|budget| budget.spent_units)
                .sum(),
        };
        self.roots.access_ticket_root = merkle_root(
            "PRIVATE-L2-STATE-ACCESS:TICKETS",
            &digest_values(self.access_tickets.values()),
        );
        self.roots.contract_hint_root = merkle_root(
            "PRIVATE-L2-STATE-ACCESS:HINTS",
            &digest_values(self.contract_hints.values()),
        );
        self.roots.pq_attestation_root = merkle_root(
            "PRIVATE-L2-STATE-ACCESS:PQ-ATTESTATIONS",
            &digest_values(self.pq_attestations.values()),
        );
        self.roots.privacy_budget_root = merkle_root(
            "PRIVATE-L2-STATE-ACCESS:PRIVACY-BUDGETS",
            &digest_values(self.privacy_budgets.values()),
        );
        self.roots.fee_sponsor_root = merkle_root(
            "PRIVATE-L2-STATE-ACCESS:FEE-SPONSORS",
            &digest_values(self.fee_sponsors.values()),
        );
        self.roots.replay_fence_root = merkle_root(
            "PRIVATE-L2-STATE-ACCESS:REPLAY-FENCES",
            &digest_values(self.replay_fences.values()),
        );
        self.roots.settlement_receipt_root = merkle_root(
            "PRIVATE-L2-STATE-ACCESS:SETTLEMENT-RECEIPTS",
            &digest_values(self.settlement_receipts.values()),
        );
        self.roots.redaction_budget_root = merkle_root(
            "PRIVATE-L2-STATE-ACCESS:REDACTION-BUDGETS",
            &digest_values(self.redaction_budgets.values()),
        );
        self.roots.operator_summary_root = merkle_root(
            "PRIVATE-L2-STATE-ACCESS:OPERATOR-SUMMARIES",
            &digest_values(self.operator_summaries.values()),
        );
        self.roots.public_record_root = stable_digest(
            "PublicRecord",
            json!({
                "protocol_version": self.config.protocol_version,
                "l2_height": self.l2_height,
                "monero_height": self.monero_height,
                "epoch": self.epoch,
                "counters": self.counters,
            }),
        );
        self.roots.state_root = stable_digest(
            "State",
            json!({
                "protocol_version": self.config.protocol_version,
                "schema_version": self.config.schema_version,
                "chain_id": self.config.chain_id,
                "l2_height": self.l2_height,
                "monero_height": self.monero_height,
                "epoch": self.epoch,
                "access_ticket_root": self.roots.access_ticket_root,
                "contract_hint_root": self.roots.contract_hint_root,
                "pq_attestation_root": self.roots.pq_attestation_root,
                "privacy_budget_root": self.roots.privacy_budget_root,
                "fee_sponsor_root": self.roots.fee_sponsor_root,
                "replay_fence_root": self.roots.replay_fence_root,
                "settlement_receipt_root": self.roots.settlement_receipt_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "operator_summary_root": self.roots.operator_summary_root,
                "public_record_root": self.roots.public_record_root,
            }),
        );
    }

    fn install_devnet_fixture(&mut self) {
        let contract_id = "contract-confidential-vault-router";
        let ticket = sample_ticket(
            "ticket-vault-router-0001",
            contract_id,
            AccessClass::ReadWrite,
            self.l2_height,
        );
        let ticket_id = ticket.ticket_id.clone();
        self.submit_ticket(ticket)
            .expect("devnet ticket should install");
        self.add_hint(sample_hint(
            "hint-vault-read-0001",
            &ticket_id,
            contract_id,
            HintKind::ReadMerklePath,
            3,
            0,
            self.l2_height,
        ))
        .expect("devnet read hint should install");
        self.add_hint(sample_hint(
            "hint-vault-write-0001",
            &ticket_id,
            contract_id,
            HintKind::WriteSlot,
            1,
            2,
            self.l2_height,
        ))
        .expect("devnet write hint should install");
        self.add_privacy_budget(sample_privacy_budget(
            "privacy-budget-vault-0001",
            contract_id,
            self.l2_height,
        ))
        .expect("devnet privacy budget should install");
        self.reserve_privacy_budget(
            &ticket_id,
            "privacy-budget-vault-0001",
            BudgetScope::AccessTicket,
            9_600,
        )
        .expect("devnet budget should reserve");
        self.add_fee_sponsor(sample_fee_sponsor(
            "fee-sponsor-vault-0001",
            contract_id,
            self.l2_height,
        ))
        .expect("devnet sponsor should install");
        self.sponsor_ticket(&ticket_id, "fee-sponsor-vault-0001", 4_200)
            .expect("devnet sponsor should reserve");
        self.add_replay_fence(sample_replay_fence(
            "replay-fence-vault-0001",
            &ticket_id,
            contract_id,
            self.epoch,
            self.l2_height,
        ))
        .expect("devnet replay fence should install");
        self.add_attestation(sample_attestation(
            "pq-access-attestation-vault-0001",
            &ticket_id,
            contract_id,
            AttestationKind::AccessKeyBinding,
            self.l2_height,
        ))
        .expect("devnet attestation should install");
        self.add_redaction_budget(sample_redaction_budget(
            "redaction-budget-vault-0001",
            contract_id,
            self.epoch,
            self.l2_height,
        ))
        .expect("devnet redaction budget should install");
        self.settle_ticket(sample_receipt(
            "settlement-receipt-vault-0001",
            &ticket_id,
            contract_id,
            self.l2_height,
        ))
        .expect("devnet receipt should settle");
        self.add_operator_summary(sample_operator_summary(
            "operator-summary-vault-0001",
            contract_id,
            self.epoch,
            self.l2_height,
        ))
        .expect("devnet operator summary should install");
        self.recompute();
    }

    fn count_tickets(&self, status: TicketStatus) -> u64 {
        self.access_tickets
            .values()
            .filter(|ticket| ticket.status == status)
            .count() as u64
    }

    fn active_ticket_count(&self) -> u64 {
        self.access_tickets
            .values()
            .filter(|ticket| ticket.status.active())
            .count() as u64
    }

    fn terminal_ticket_count(&self) -> u64 {
        self.access_tickets
            .values()
            .filter(|ticket| ticket.status.terminal())
            .count() as u64
    }

    fn total_privacy_units_remaining(&self) -> u128 {
        self.privacy_budgets
            .values()
            .map(PrivacyBudget::remaining_units)
            .sum()
    }

    fn total_sponsor_fee_remaining(&self) -> u128 {
        self.fee_sponsors
            .values()
            .map(FeeSponsor::remaining_fee_micro_units)
            .sum()
    }
}

trait Digestible {
    fn digest_value(&self) -> Value;
}

impl Digestible for EncryptedStateAccessTicket {
    fn digest_value(&self) -> Value {
        json!(self.digest())
    }
}

impl Digestible for ContractReadWriteHint {
    fn digest_value(&self) -> Value {
        json!(self.digest())
    }
}

impl Digestible for PqAccessAttestation {
    fn digest_value(&self) -> Value {
        json!(self.digest())
    }
}

impl Digestible for PrivacyBudget {
    fn digest_value(&self) -> Value {
        json!(self.digest())
    }
}

impl Digestible for FeeSponsor {
    fn digest_value(&self) -> Value {
        json!(self.digest())
    }
}

impl Digestible for ReplayFence {
    fn digest_value(&self) -> Value {
        json!(self.digest())
    }
}

impl Digestible for SettlementReceipt {
    fn digest_value(&self) -> Value {
        json!(self.digest())
    }
}

impl Digestible for RedactionBudget {
    fn digest_value(&self) -> Value {
        json!(self.digest())
    }
}

impl Digestible for OperatorSummary {
    fn digest_value(&self) -> Value {
        json!(self.digest())
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

fn digest_values<'a, I, T>(values: I) -> Vec<Value>
where
    I: IntoIterator<Item = &'a T>,
    T: Digestible + 'a,
{
    values
        .into_iter()
        .map(Digestible::digest_value)
        .collect::<Vec<_>>()
}

fn stable_digest(domain: &str, value: Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-MEMPOOL-STATE-ACCESS:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(&value)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-MEMPOOL-STATE-ACCESS:{domain}:EMPTY"
        ),
        &[HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn redacted_operator(operator_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-MEMPOOL-STATE-ACCESS:REDACTED-OPERATOR",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(operator_id)],
        16,
    )
}

fn sample_root(domain: &str, seed: &str) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-MEMPOOL-STATE-ACCESS:SAMPLE:{domain}"
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(seed)],
        32,
    )
}

fn sample_ticket(
    ticket_id: &str,
    contract_id: &str,
    access_class: AccessClass,
    height: u64,
) -> EncryptedStateAccessTicket {
    EncryptedStateAccessTicket {
        ticket_id: ticket_id.to_string(),
        contract_id: contract_id.to_string(),
        caller_commitment: sample_root("caller", ticket_id),
        access_class,
        status: TicketStatus::Submitted,
        encrypted_ticket_root: sample_root("encrypted-ticket", ticket_id),
        access_key_commitment: sample_root("access-key", ticket_id),
        state_namespace_root: sample_root("state-namespace", contract_id),
        requested_read_units: 4,
        requested_write_units: if access_class.writes_state() { 2 } else { 0 },
        max_fee_micro_units: DEFAULT_BASE_ACCESS_FEE_MICRO_UNITS + 4_200,
        sponsor_id: None,
        privacy_budget_id: None,
        replay_fence_id: None,
        hint_ids: BTreeSet::new(),
        attestation_ids: BTreeSet::new(),
        settlement_receipt_id: None,
        submitted_at_height: height.saturating_sub(2),
        expires_at_height: height + DEFAULT_ACCESS_TTL_BLOCKS,
    }
}

fn sample_hint(
    hint_id: &str,
    ticket_id: &str,
    contract_id: &str,
    kind: HintKind,
    read_units: u64,
    write_units: u64,
    height: u64,
) -> ContractReadWriteHint {
    ContractReadWriteHint {
        hint_id: hint_id.to_string(),
        ticket_id: ticket_id.to_string(),
        contract_id: contract_id.to_string(),
        hint_kind: kind,
        status: HintStatus::Proposed,
        encrypted_hint_root: sample_root("encrypted-hint", hint_id),
        slot_commitment_root: sample_root("slot-commitment", hint_id),
        access_path_commitment: sample_root("access-path", hint_id),
        read_units,
        write_units,
        conflict_domain: if kind.writes_state() {
            "vault-router-write-domain".to_string()
        } else {
            "vault-router-read-domain".to_string()
        },
        redaction_budget_id: Some("redaction-budget-vault-0001".to_string()),
        opened_at_height: height.saturating_sub(2),
        expires_at_height: height + DEFAULT_HINT_TTL_BLOCKS,
    }
}

fn sample_attestation(
    attestation_id: &str,
    ticket_id: &str,
    contract_id: &str,
    kind: AttestationKind,
    height: u64,
) -> PqAccessAttestation {
    PqAccessAttestation {
        attestation_id: attestation_id.to_string(),
        ticket_id: ticket_id.to_string(),
        contract_id: contract_id.to_string(),
        attestor_id: "operator-alpha".to_string(),
        kind,
        verdict: AttestationVerdict::Accept,
        pq_signature_root: sample_root("pq-signature", attestation_id),
        transcript_root: sample_root("attestation-transcript", attestation_id),
        access_policy_root: sample_root("access-policy", contract_id),
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        signer_weight: 9,
        issued_at_height: height.saturating_sub(1),
        expires_at_height: height + DEFAULT_ATTESTATION_TTL_BLOCKS,
    }
}

fn sample_privacy_budget(budget_id: &str, contract_id: &str, height: u64) -> PrivacyBudget {
    let mut scopes = BTreeSet::new();
    scopes.insert(BudgetScope::AccessTicket);
    scopes.insert(BudgetScope::ReadHint);
    scopes.insert(BudgetScope::WriteHint);
    scopes.insert(BudgetScope::ReplayFence);
    scopes.insert(BudgetScope::SettlementReceipt);
    PrivacyBudget {
        budget_id: budget_id.to_string(),
        owner_commitment: sample_root("budget-owner", budget_id),
        contract_id: contract_id.to_string(),
        scopes,
        status: BudgetStatus::Open,
        total_units: 1_000_000,
        reserved_units: 0,
        spent_units: 12_800,
        budget_root: sample_root("privacy-budget", budget_id),
        issued_at_height: height.saturating_sub(64),
        expires_at_height: height + DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS,
    }
}

fn sample_fee_sponsor(sponsor_id: &str, contract_id: &str, height: u64) -> FeeSponsor {
    FeeSponsor {
        sponsor_id: sponsor_id.to_string(),
        sponsor_commitment: sample_root("sponsor", sponsor_id),
        contract_id: contract_id.to_string(),
        status: SponsorStatus::Active,
        max_fee_micro_units: 25_000_000,
        reserved_fee_micro_units: 0,
        paid_fee_micro_units: 250_000,
        rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
        sponsor_policy_root: sample_root("sponsor-policy", sponsor_id),
        ticket_ids: BTreeSet::new(),
        opened_at_height: height.saturating_sub(720),
        expires_at_height: height + DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS,
    }
}

fn sample_replay_fence(
    fence_id: &str,
    ticket_id: &str,
    contract_id: &str,
    epoch: u64,
    height: u64,
) -> ReplayFence {
    ReplayFence {
        fence_id: fence_id.to_string(),
        ticket_id: ticket_id.to_string(),
        contract_id: contract_id.to_string(),
        nullifier_commitment: sample_root("nullifier", ticket_id),
        status: FenceStatus::Bound,
        fence_root: sample_root("replay-fence", fence_id),
        access_epoch: epoch,
        first_seen_height: height.saturating_sub(1),
        expires_at_height: height + DEFAULT_REPLAY_FENCE_TTL_BLOCKS,
    }
}

fn sample_receipt(
    receipt_id: &str,
    ticket_id: &str,
    contract_id: &str,
    height: u64,
) -> SettlementReceipt {
    SettlementReceipt {
        receipt_id: receipt_id.to_string(),
        ticket_id: ticket_id.to_string(),
        contract_id: contract_id.to_string(),
        status: ReceiptStatus::Settled,
        settlement_root: sample_root("settlement", receipt_id),
        state_before_root: sample_root("state-before", ticket_id),
        state_after_root: sample_root("state-after", ticket_id),
        consumed_hint_root: sample_root("consumed-hints", ticket_id),
        replay_fence_root: sample_root("receipt-fence", ticket_id),
        fee_paid_micro_units: 4_200,
        sponsored_fee_micro_units: 4_200,
        included_at_height: height,
        finalized_at_height: Some(height + 2),
    }
}

fn sample_redaction_budget(
    budget_id: &str,
    contract_id: &str,
    epoch: u64,
    height: u64,
) -> RedactionBudget {
    let mut scopes = BTreeSet::new();
    scopes.insert(RedactionScope::TicketMetadata);
    scopes.insert(RedactionScope::ContractHint);
    scopes.insert(RedactionScope::SponsorLink);
    scopes.insert(RedactionScope::OperatorSummary);
    RedactionBudget {
        redaction_budget_id: budget_id.to_string(),
        operator_id: "operator-alpha".to_string(),
        contract_id: contract_id.to_string(),
        epoch,
        scopes,
        max_redaction_bps: DEFAULT_REDACTION_BUDGET_BPS,
        spent_redaction_bps: 72,
        redaction_root: sample_root("redaction", budget_id),
        opened_at_height: height.saturating_sub(DEFAULT_REDACTION_EPOCH_BLOCKS / 2),
        expires_at_height: height + DEFAULT_REDACTION_EPOCH_BLOCKS,
    }
}

fn sample_operator_summary(
    summary_id: &str,
    contract_id: &str,
    epoch: u64,
    height: u64,
) -> OperatorSummary {
    OperatorSummary {
        summary_id: summary_id.to_string(),
        operator_id: "operator-alpha".to_string(),
        contract_id: contract_id.to_string(),
        epoch,
        status: SummaryStatus::Published,
        admitted_ticket_count: 1,
        settled_ticket_count: 1,
        rejected_ticket_count: 0,
        read_hint_count: 1,
        write_hint_count: 1,
        replay_fence_count: 1,
        sponsored_fee_micro_units: 4_200,
        privacy_units_spent: 12_800,
        p50_access_latency_ms: 118,
        p95_access_latency_ms: 286,
        redacted: true,
        public_summary_root: sample_root("operator-summary", summary_id),
        emitted_at_height: height,
    }
}
