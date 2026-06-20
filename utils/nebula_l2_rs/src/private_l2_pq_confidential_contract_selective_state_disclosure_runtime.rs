use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SELECTIVE_STATE_DISCLOSURE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-selective-state-disclosure-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SELECTIVE_STATE_DISCLOSURE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_STATE_MANIFEST_SUITE: &str =
    "ml-kem-1024+xwing-encrypted-selective-contract-state-manifest-v1";
pub const DISCLOSURE_TICKET_SUITE: &str =
    "private-l2-confidential-contract-disclosure-ticket-nullifier-v1";
pub const AUDITOR_COHORT_SUITE: &str =
    "private-l2-pq-confidential-auditor-cohort-threshold-root-v1";
pub const FHE_SLOT_COMMITMENT_SUITE: &str =
    "tfhe-selective-state-slot-commitment+redacted-view-tag-v1";
pub const PQ_DISCLOSURE_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-selective-disclosure-attestation-v1";
pub const CALLBACK_FENCE_SUITE: &str = "private-l2-selective-disclosure-callback-fence-v1";
pub const LOW_FEE_DISCLOSURE_REBATE_SUITE: &str =
    "private-l2-low-fee-selective-disclosure-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "selective-contract-state-redaction-budget-v1";
pub const DETERMINISTIC_ROOT_SUITE: &str =
    "deterministic-selective-state-disclosure-roots-and-public-records-v1";
pub const DEVNET_HEIGHT: u64 = 2_244_800;
pub const DEVNET_EPOCH: u64 = 3_118;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_CALLBACK_FENCE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_REDACTIONS_PER_EPOCH: u64 = 32;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8;
pub const DEFAULT_REBATE_CAP_BPS: u64 = 1_500;
pub const DEFAULT_MAX_MANIFEST_BYTES: u64 = 4_194_304;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 8_388_608;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    SlotValue,
    SlotRange,
    EventDerivedState,
    CrossContractInvariant,
    LiquidationProof,
    GovernanceAudit,
    EmergencyRecovery,
    Custom,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Draft,
    Sealed,
    Ticketed,
    PartiallyDisclosed,
    FullyDisclosed,
    Fenced,
    Superseded,
    Quarantined,
    Expired,
}

impl ManifestStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Ticketed | Self::PartiallyDisclosed | Self::FullyDisclosed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Reserved,
    Issued,
    Redeemed,
    Attested,
    Rebated,
    Revoked,
    Expired,
}

impl TicketStatus {
    pub fn redeemable(self) -> bool {
        matches!(self, Self::Reserved | Self::Issued)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Forming,
    Active,
    Rotating,
    Suspended,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FheSlotKind {
    Balance,
    Allowance,
    OrderState,
    RiskVector,
    OracleMemo,
    GovernanceSecret,
    CallbackScratch,
    Custom,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ManifestSeal,
    TicketOpening,
    AuditorCohortQuorum,
    FheSlotDisclosure,
    CallbackFence,
    LowFeeEligibility,
    RedactionBudget,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackFenceStatus {
    Open,
    Armed,
    Triggered,
    Released,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Paid,
    ClawedBack,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub encrypted_state_manifest_suite: String,
    pub disclosure_ticket_suite: String,
    pub auditor_cohort_suite: String,
    pub fhe_slot_commitment_suite: String,
    pub pq_disclosure_attestation_suite: String,
    pub callback_fence_suite: String,
    pub low_fee_disclosure_rebate_suite: String,
    pub redaction_budget_suite: String,
    pub deterministic_root_suite: String,
    pub fee_asset_id: String,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub disclosure_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub callback_fence_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_redactions_per_epoch: u64,
    pub low_fee_target_bps: u64,
    pub rebate_cap_bps: u64,
    pub max_manifest_bytes: u64,
    pub max_public_records: usize,
    pub deterministic_roots_required: bool,
    pub redact_operator_metadata_by_default: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_state_manifest_suite: ENCRYPTED_STATE_MANIFEST_SUITE.to_string(),
            disclosure_ticket_suite: DISCLOSURE_TICKET_SUITE.to_string(),
            auditor_cohort_suite: AUDITOR_COHORT_SUITE.to_string(),
            fhe_slot_commitment_suite: FHE_SLOT_COMMITMENT_SUITE.to_string(),
            pq_disclosure_attestation_suite: PQ_DISCLOSURE_ATTESTATION_SUITE.to_string(),
            callback_fence_suite: CALLBACK_FENCE_SUITE.to_string(),
            low_fee_disclosure_rebate_suite: LOW_FEE_DISCLOSURE_REBATE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            deterministic_root_suite: DETERMINISTIC_ROOT_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            disclosure_ttl_blocks: DEFAULT_DISCLOSURE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            callback_fence_ttl_blocks: DEFAULT_CALLBACK_FENCE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_redactions_per_epoch: DEFAULT_MAX_REDACTIONS_PER_EPOCH,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            rebate_cap_bps: DEFAULT_REBATE_CAP_BPS,
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            deterministic_roots_required: true,
            redact_operator_metadata_by_default: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_selective_state_disclosure_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "encrypted_state_manifest_suite": self.encrypted_state_manifest_suite,
            "disclosure_ticket_suite": self.disclosure_ticket_suite,
            "auditor_cohort_suite": self.auditor_cohort_suite,
            "fhe_slot_commitment_suite": self.fhe_slot_commitment_suite,
            "pq_disclosure_attestation_suite": self.pq_disclosure_attestation_suite,
            "callback_fence_suite": self.callback_fence_suite,
            "low_fee_disclosure_rebate_suite": self.low_fee_disclosure_rebate_suite,
            "redaction_budget_suite": self.redaction_budget_suite,
            "deterministic_root_suite": self.deterministic_root_suite,
            "fee_asset_id": self.fee_asset_id,
            "devnet_height": self.devnet_height,
            "devnet_epoch": self.devnet_epoch,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "callback_fence_ttl_blocks": self.callback_fence_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "max_redactions_per_epoch": self.max_redactions_per_epoch,
            "low_fee_target_bps": self.low_fee_target_bps,
            "rebate_cap_bps": self.rebate_cap_bps,
            "max_manifest_bytes": self.max_manifest_bytes,
            "max_public_records": self.max_public_records,
            "deterministic_roots_required": self.deterministic_roots_required,
            "redact_operator_metadata_by_default": self.redact_operator_metadata_by_default,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub encrypted_manifests_sealed: u64,
    pub disclosure_tickets_issued: u64,
    pub disclosure_tickets_redeemed: u64,
    pub auditor_cohorts_registered: u64,
    pub fhe_slot_commitments_registered: u64,
    pub pq_attestations_accepted: u64,
    pub callback_fences_armed: u64,
    pub low_fee_rebates_earned: u64,
    pub redactions_budgeted: u64,
    pub deterministic_public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub manifest_root: String,
    pub disclosure_ticket_root: String,
    pub auditor_cohort_root: String,
    pub fhe_slot_commitment_root: String,
    pub pq_attestation_root: String,
    pub callback_fence_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            manifest_root: empty_root("MANIFEST"),
            disclosure_ticket_root: empty_root("DISCLOSURE-TICKET"),
            auditor_cohort_root: empty_root("AUDITOR-COHORT"),
            fhe_slot_commitment_root: empty_root("FHE-SLOT-COMMITMENT"),
            pq_attestation_root: empty_root("PQ-ATTESTATION"),
            callback_fence_root: empty_root("CALLBACK-FENCE"),
            low_fee_rebate_root: empty_root("LOW-FEE-REBATE"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            public_record_root: empty_root("PUBLIC-RECORD"),
            counters_root: empty_root("COUNTERS"),
            state_root: empty_root("STATE"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStateManifest {
    pub manifest_id: String,
    pub scope: DisclosureScope,
    pub status: ManifestStatus,
    pub contract_id: String,
    pub namespace_id: String,
    pub encrypted_manifest_root: String,
    pub ciphertext_index_root: String,
    pub disclosure_policy_root: String,
    pub deterministic_state_root: String,
    pub manifest_bytes: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub ticket_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
}

impl EncryptedStateManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_selective_state_manifest",
            "manifest_id": self.manifest_id,
            "scope": self.scope,
            "status": self.status,
            "contract_id": self.contract_id,
            "namespace_id": self.namespace_id,
            "encrypted_manifest_root": self.encrypted_manifest_root,
            "ciphertext_index_root": self.ciphertext_index_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "deterministic_state_root": self.deterministic_state_root,
            "manifest_bytes": self.manifest_bytes,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "ticket_ids": self.ticket_ids,
            "attestation_ids": self.attestation_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosureTicket {
    pub ticket_id: String,
    pub manifest_id: String,
    pub cohort_id: String,
    pub status: TicketStatus,
    pub recipient_commitment: String,
    pub ticket_nullifier_root: String,
    pub disclosed_slot_root: String,
    pub redaction_set_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub low_fee_rebate_id: Option<String>,
}

impl DisclosureTicket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditorCohort {
    pub cohort_id: String,
    pub status: CohortStatus,
    pub cohort_root: String,
    pub threshold_weight: u64,
    pub active_weight: u64,
    pub member_commitments: BTreeSet<String>,
    pub pq_key_set_root: String,
    pub registered_at_height: u64,
}

impl AuditorCohort {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FheSlotCommitment {
    pub slot_id: String,
    pub manifest_id: String,
    pub slot_kind: FheSlotKind,
    pub ciphertext_commitment: String,
    pub opening_commitment_root: String,
    pub access_policy_root: String,
    pub rotation_counter: u64,
    pub committed_at_height: u64,
}

impl FheSlotCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqDisclosureAttestation {
    pub attestation_id: String,
    pub manifest_id: String,
    pub ticket_id: Option<String>,
    pub cohort_id: String,
    pub attestation_kind: AttestationKind,
    pub status: AttestationStatus,
    pub attestor_commitment: String,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub evidence_root: String,
    pub attested_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqDisclosureAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallbackFence {
    pub fence_id: String,
    pub manifest_id: String,
    pub callback_selector_commitment: String,
    pub status: CallbackFenceStatus,
    pub pre_callback_state_root: String,
    pub post_callback_state_root: Option<String>,
    pub fenced_slot_root: String,
    pub armed_at_height: u64,
    pub expires_at_height: u64,
}

impl CallbackFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeDisclosureRebate {
    pub rebate_id: String,
    pub ticket_id: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub baseline_fee: u128,
    pub charged_fee: u128,
    pub rebate_amount: u128,
    pub rebate_bps: u64,
    pub earned_at_height: u64,
}

impl LowFeeDisclosureRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub manifest_id: String,
    pub epoch: u64,
    pub allowed_redactions: u64,
    pub used_redactions: u64,
    pub redaction_policy_root: String,
    pub carry_forward_allowed: bool,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub domain: String,
    pub subject_id: String,
    pub record_root: String,
    pub emitted_at_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub encrypted_state_manifests: BTreeMap<String, EncryptedStateManifest>,
    pub disclosure_tickets: BTreeMap<String, DisclosureTicket>,
    pub auditor_cohorts: BTreeMap<String, AuditorCohort>,
    pub fhe_slot_commitments: BTreeMap<String, FheSlotCommitment>,
    pub pq_disclosure_attestations: BTreeMap<String, PqDisclosureAttestation>,
    pub callback_fences: BTreeMap<String, CallbackFence>,
    pub low_fee_rebates: BTreeMap<String, LowFeeDisclosureRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            encrypted_state_manifests: BTreeMap::new(),
            disclosure_tickets: BTreeMap::new(),
            auditor_cohorts: BTreeMap::new(),
            fhe_slot_commitments: BTreeMap::new(),
            pq_disclosure_attestations: BTreeMap::new(),
            callback_fences: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH);
        state.seed_devnet();
        state
    }

    fn seed_devnet(&mut self) {
        let cohort_id = deterministic_id("DEVNET-COHORT", 1, &json!("auditor-cohort-alpha"));
        let mut members = BTreeSet::new();
        members.insert("auditor:commitment:alpha".to_string());
        members.insert("auditor:commitment:beta".to_string());
        members.insert("auditor:commitment:gamma".to_string());
        self.register_auditor_cohort(AuditorCohort {
            cohort_id: cohort_id.clone(),
            status: CohortStatus::Active,
            cohort_root: deterministic_record_root("DEVNET-COHORT-ROOT", &json!(members)),
            threshold_weight: 2,
            active_weight: 3,
            member_commitments: members,
            pq_key_set_root: deterministic_record_root(
                "DEVNET-PQ-KEY-SET",
                &json!("ml-dsa-devnet-auditors"),
            ),
            registered_at_height: self.height,
        })
        .expect("generated devnet auditor cohort");

        let manifest_id = self
            .seal_manifest(EncryptedStateManifest {
                manifest_id: String::new(),
                scope: DisclosureScope::CrossContractInvariant,
                status: ManifestStatus::Sealed,
                contract_id: "contract:commitment:confidential-perps-vault".to_string(),
                namespace_id: "namespace:commitment:perps-risk".to_string(),
                encrypted_manifest_root: deterministic_record_root(
                    "DEVNET-ENCRYPTED-MANIFEST",
                    &json!("perps-risk-disclosure-manifest"),
                ),
                ciphertext_index_root: deterministic_record_root(
                    "DEVNET-CIPHERTEXT-INDEX",
                    &json!(["margin_slot", "funding_slot", "liquidation_slot"]),
                ),
                disclosure_policy_root: deterministic_record_root(
                    "DEVNET-DISCLOSURE-POLICY",
                    &json!("threshold-auditor-redacted-public"),
                ),
                deterministic_state_root: deterministic_record_root(
                    "DEVNET-STATE-ROOT",
                    &json!("contract-state-root-2444800"),
                ),
                manifest_bytes: 393_216,
                privacy_set_size: self.config.target_privacy_set_size,
                pq_security_bits: self.config.min_pq_security_bits,
                sealed_at_height: self.height,
                expires_at_height: self.height + self.config.disclosure_ttl_blocks,
                ticket_ids: BTreeSet::new(),
                attestation_ids: BTreeSet::new(),
            })
            .expect("generated devnet encrypted state manifest");

        let slot_id = deterministic_id("DEVNET-FHE-SLOT", 1, &json!(&manifest_id));
        self.register_fhe_slot_commitment(FheSlotCommitment {
            slot_id,
            manifest_id: manifest_id.clone(),
            slot_kind: FheSlotKind::RiskVector,
            ciphertext_commitment: deterministic_record_root(
                "DEVNET-FHE-CIPHERTEXT",
                &json!("encrypted-risk-vector"),
            ),
            opening_commitment_root: deterministic_record_root(
                "DEVNET-FHE-OPENING",
                &json!("selective-opening-proof"),
            ),
            access_policy_root: deterministic_record_root(
                "DEVNET-FHE-ACCESS",
                &json!("auditor-cohort-alpha"),
            ),
            rotation_counter: 7,
            committed_at_height: self.height,
        })
        .expect("generated devnet fhe slot commitment");

        let ticket_id = self
            .issue_disclosure_ticket(DisclosureTicket {
                ticket_id: String::new(),
                manifest_id: manifest_id.clone(),
                cohort_id: cohort_id.clone(),
                status: TicketStatus::Issued,
                recipient_commitment: "recipient:commitment:risk-auditor-public".to_string(),
                ticket_nullifier_root: deterministic_record_root(
                    "DEVNET-TICKET-NULLIFIER",
                    &json!("risk-auditor-ticket-nullifier"),
                ),
                disclosed_slot_root: deterministic_record_root(
                    "DEVNET-DISCLOSED-SLOTS",
                    &json!(["risk_vector", "funding_accumulator"]),
                ),
                redaction_set_root: deterministic_record_root(
                    "DEVNET-REDACTION-SET",
                    &json!(["trader_address", "exact_balance"]),
                ),
                issued_at_height: self.height,
                expires_at_height: self.height + self.config.disclosure_ttl_blocks,
                low_fee_rebate_id: None,
            })
            .expect("generated devnet disclosure ticket");

        self.accept_attestation(PqDisclosureAttestation {
            attestation_id: String::new(),
            manifest_id: manifest_id.clone(),
            ticket_id: Some(ticket_id.clone()),
            cohort_id,
            attestation_kind: AttestationKind::FheSlotDisclosure,
            status: AttestationStatus::Accepted,
            attestor_commitment: "attestor:commitment:auditor-alpha".to_string(),
            public_key_commitment: deterministic_record_root(
                "DEVNET-ATTESTOR-PK",
                &json!("ml-dsa-auditor-alpha"),
            ),
            signature_root: deterministic_record_root(
                "DEVNET-ATTESTATION-SIGNATURE",
                &json!("pq-signature-root"),
            ),
            evidence_root: deterministic_record_root(
                "DEVNET-ATTESTATION-EVIDENCE",
                &json!("fhe-opening-evidence"),
            ),
            attested_root: self.roots.fhe_slot_commitment_root.clone(),
            attested_at_height: self.height,
            expires_at_height: self.height + self.config.attestation_ttl_blocks,
        })
        .expect("generated devnet disclosure attestation");

        self.arm_callback_fence(CallbackFence {
            fence_id: String::new(),
            manifest_id: manifest_id.clone(),
            callback_selector_commitment: deterministic_record_root(
                "DEVNET-CALLBACK-SELECTOR",
                &json!("apply_selective_disclosure(bytes32,bytes)"),
            ),
            status: CallbackFenceStatus::Armed,
            pre_callback_state_root: self.roots.manifest_root.clone(),
            post_callback_state_root: None,
            fenced_slot_root: self.roots.fhe_slot_commitment_root.clone(),
            armed_at_height: self.height,
            expires_at_height: self.height + self.config.callback_fence_ttl_blocks,
        })
        .expect("generated devnet callback fence");

        self.register_redaction_budget(RedactionBudget {
            budget_id: String::new(),
            manifest_id: manifest_id.clone(),
            epoch: self.epoch,
            allowed_redactions: 12,
            used_redactions: 4,
            redaction_policy_root: deterministic_record_root(
                "DEVNET-REDACTION-BUDGET-POLICY",
                &json!("mask-identifiers-preserve-solvency-proof"),
            ),
            carry_forward_allowed: false,
        })
        .expect("generated devnet redaction budget");

        self.earn_low_fee_rebate(LowFeeDisclosureRebate {
            rebate_id: String::new(),
            ticket_id,
            status: RebateStatus::Earned,
            fee_asset_id: self.config.fee_asset_id.clone(),
            baseline_fee: 180_000,
            charged_fee: 92_000,
            rebate_amount: 88_000,
            rebate_bps: 488,
            earned_at_height: self.height,
        })
        .expect("generated devnet low fee disclosure rebate");
    }

    pub fn seal_manifest(
        &mut self,
        mut manifest: EncryptedStateManifest,
    ) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<String> {
        required("contract_id", &manifest.contract_id)?;
        required("namespace_id", &manifest.namespace_id)?;
        required("encrypted_manifest_root", &manifest.encrypted_manifest_root)?;
        ensure!(
            manifest.manifest_bytes <= self.config.max_manifest_bytes,
            "manifest exceeds max_manifest_bytes"
        );
        ensure!(
            manifest.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below minimum"
        );
        ensure!(
            manifest.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits below minimum"
        );
        manifest.status = ManifestStatus::Sealed;
        manifest.sealed_at_height = self.height;
        manifest.expires_at_height = self.height + self.config.disclosure_ttl_blocks;
        if manifest.manifest_id.is_empty() {
            manifest.manifest_id = deterministic_id(
                "MANIFEST",
                self.counters.encrypted_manifests_sealed + 1,
                &manifest.public_record(),
            );
        }
        let manifest_id = manifest.manifest_id.clone();
        self.encrypted_state_manifests
            .insert(manifest_id.clone(), manifest);
        self.counters.encrypted_manifests_sealed += 1;
        self.emit_public_record("manifest", &manifest_id);
        self.refresh_roots();
        Ok(manifest_id)
    }

    pub fn issue_disclosure_ticket(
        &mut self,
        mut ticket: DisclosureTicket,
    ) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<String> {
        ensure!(
            self.encrypted_state_manifests
                .contains_key(&ticket.manifest_id),
            "manifest is unknown"
        );
        ensure!(
            self.auditor_cohorts.contains_key(&ticket.cohort_id),
            "auditor cohort is unknown"
        );
        required("recipient_commitment", &ticket.recipient_commitment)?;
        required("ticket_nullifier_root", &ticket.ticket_nullifier_root)?;
        ticket.status = TicketStatus::Issued;
        ticket.issued_at_height = self.height;
        ticket.expires_at_height = self.height + self.config.disclosure_ttl_blocks;
        if ticket.ticket_id.is_empty() {
            ticket.ticket_id = deterministic_id(
                "DISCLOSURE-TICKET",
                self.counters.disclosure_tickets_issued + 1,
                &ticket.public_record(),
            );
        }
        let ticket_id = ticket.ticket_id.clone();
        if let Some(manifest) = self.encrypted_state_manifests.get_mut(&ticket.manifest_id) {
            manifest.status = ManifestStatus::Ticketed;
            manifest.ticket_ids.insert(ticket_id.clone());
        }
        self.disclosure_tickets.insert(ticket_id.clone(), ticket);
        self.counters.disclosure_tickets_issued += 1;
        self.emit_public_record("disclosure_ticket", &ticket_id);
        self.refresh_roots();
        Ok(ticket_id)
    }

    pub fn redeem_ticket(
        &mut self,
        ticket_id: &str,
    ) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<()> {
        let ticket = self
            .disclosure_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
        ensure!(ticket.status.redeemable(), "ticket cannot be redeemed");
        ticket.status = TicketStatus::Redeemed;
        self.counters.disclosure_tickets_redeemed += 1;
        self.emit_public_record("ticket_redeemed", ticket_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_auditor_cohort(
        &mut self,
        mut cohort: AuditorCohort,
    ) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<String> {
        required("cohort_root", &cohort.cohort_root)?;
        required("pq_key_set_root", &cohort.pq_key_set_root)?;
        ensure!(cohort.threshold_weight > 0, "threshold weight is required");
        ensure!(
            cohort.active_weight >= cohort.threshold_weight,
            "active weight below threshold"
        );
        cohort.registered_at_height = self.height;
        if cohort.cohort_id.is_empty() {
            cohort.cohort_id = deterministic_id(
                "AUDITOR-COHORT",
                self.counters.auditor_cohorts_registered + 1,
                &cohort.public_record(),
            );
        }
        let cohort_id = cohort.cohort_id.clone();
        self.auditor_cohorts.insert(cohort_id.clone(), cohort);
        self.counters.auditor_cohorts_registered += 1;
        self.emit_public_record("auditor_cohort", &cohort_id);
        self.refresh_roots();
        Ok(cohort_id)
    }

    pub fn register_fhe_slot_commitment(
        &mut self,
        mut slot: FheSlotCommitment,
    ) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<String> {
        ensure!(
            self.encrypted_state_manifests
                .contains_key(&slot.manifest_id),
            "manifest is unknown"
        );
        required("ciphertext_commitment", &slot.ciphertext_commitment)?;
        required("opening_commitment_root", &slot.opening_commitment_root)?;
        slot.committed_at_height = self.height;
        if slot.slot_id.is_empty() {
            slot.slot_id = deterministic_id(
                "FHE-SLOT",
                self.counters.fhe_slot_commitments_registered + 1,
                &slot.public_record(),
            );
        }
        let slot_id = slot.slot_id.clone();
        self.fhe_slot_commitments.insert(slot_id.clone(), slot);
        self.counters.fhe_slot_commitments_registered += 1;
        self.emit_public_record("fhe_slot_commitment", &slot_id);
        self.refresh_roots();
        Ok(slot_id)
    }

    pub fn accept_attestation(
        &mut self,
        mut attestation: PqDisclosureAttestation,
    ) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<String> {
        ensure!(
            self.encrypted_state_manifests
                .contains_key(&attestation.manifest_id),
            "manifest is unknown"
        );
        ensure!(
            self.auditor_cohorts.contains_key(&attestation.cohort_id),
            "auditor cohort is unknown"
        );
        required("signature_root", &attestation.signature_root)?;
        required("attested_root", &attestation.attested_root)?;
        attestation.status = AttestationStatus::Accepted;
        attestation.attested_at_height = self.height;
        attestation.expires_at_height = self.height + self.config.attestation_ttl_blocks;
        if attestation.attestation_id.is_empty() {
            attestation.attestation_id = deterministic_id(
                "PQ-DISCLOSURE-ATTESTATION",
                self.counters.pq_attestations_accepted + 1,
                &attestation.public_record(),
            );
        }
        let attestation_id = attestation.attestation_id.clone();
        if let Some(manifest) = self
            .encrypted_state_manifests
            .get_mut(&attestation.manifest_id)
        {
            manifest.status = ManifestStatus::PartiallyDisclosed;
            manifest.attestation_ids.insert(attestation_id.clone());
        }
        if let Some(ticket_id) = &attestation.ticket_id {
            if let Some(ticket) = self.disclosure_tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Attested;
            }
        }
        self.pq_disclosure_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations_accepted += 1;
        self.emit_public_record("pq_disclosure_attestation", &attestation_id);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn arm_callback_fence(
        &mut self,
        mut fence: CallbackFence,
    ) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<String> {
        ensure!(
            self.encrypted_state_manifests
                .contains_key(&fence.manifest_id),
            "manifest is unknown"
        );
        required(
            "callback_selector_commitment",
            &fence.callback_selector_commitment,
        )?;
        fence.status = CallbackFenceStatus::Armed;
        fence.armed_at_height = self.height;
        fence.expires_at_height = self.height + self.config.callback_fence_ttl_blocks;
        if fence.fence_id.is_empty() {
            fence.fence_id = deterministic_id(
                "CALLBACK-FENCE",
                self.counters.callback_fences_armed + 1,
                &fence.public_record(),
            );
        }
        let fence_id = fence.fence_id.clone();
        if let Some(manifest) = self.encrypted_state_manifests.get_mut(&fence.manifest_id) {
            manifest.status = ManifestStatus::Fenced;
        }
        self.callback_fences.insert(fence_id.clone(), fence);
        self.counters.callback_fences_armed += 1;
        self.emit_public_record("callback_fence", &fence_id);
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn earn_low_fee_rebate(
        &mut self,
        mut rebate: LowFeeDisclosureRebate,
    ) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<String> {
        ensure!(
            self.disclosure_tickets.contains_key(&rebate.ticket_id),
            "ticket is unknown"
        );
        ensure!(
            rebate.rebate_bps <= self.config.rebate_cap_bps,
            "rebate cap exceeded"
        );
        ensure!(rebate.rebate_bps <= MAX_BPS, "rebate bps out of range");
        rebate.status = RebateStatus::Earned;
        rebate.earned_at_height = self.height;
        if rebate.rebate_id.is_empty() {
            rebate.rebate_id = deterministic_id(
                "LOW-FEE-REBATE",
                self.counters.low_fee_rebates_earned + 1,
                &rebate.public_record(),
            );
        }
        let rebate_id = rebate.rebate_id.clone();
        if let Some(ticket) = self.disclosure_tickets.get_mut(&rebate.ticket_id) {
            ticket.status = TicketStatus::Rebated;
            ticket.low_fee_rebate_id = Some(rebate_id.clone());
        }
        self.low_fee_rebates.insert(rebate_id.clone(), rebate);
        self.counters.low_fee_rebates_earned += 1;
        self.emit_public_record("low_fee_disclosure_rebate", &rebate_id);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn register_redaction_budget(
        &mut self,
        mut budget: RedactionBudget,
    ) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<String> {
        ensure!(
            self.encrypted_state_manifests
                .contains_key(&budget.manifest_id),
            "manifest is unknown"
        );
        ensure!(
            budget.allowed_redactions <= self.config.max_redactions_per_epoch,
            "redaction budget exceeds epoch limit"
        );
        ensure!(
            budget.used_redactions <= budget.allowed_redactions,
            "used redactions exceed allowance"
        );
        if budget.budget_id.is_empty() {
            budget.budget_id = deterministic_id(
                "REDACTION-BUDGET",
                self.counters.redactions_budgeted + 1,
                &budget.public_record(),
            );
        }
        let budget_id = budget.budget_id.clone();
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.redactions_budgeted += 1;
        self.emit_public_record("redaction_budget", &budget_id);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_selective_state_disclosure_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "manifest_root": self.roots.manifest_root,
                "disclosure_ticket_root": self.roots.disclosure_ticket_root,
                "auditor_cohort_root": self.roots.auditor_cohort_root,
                "fhe_slot_commitment_root": self.roots.fhe_slot_commitment_root,
                "pq_attestation_root": self.roots.pq_attestation_root,
                "callback_fence_root": self.roots.callback_fence_root,
                "low_fee_rebate_root": self.roots.low_fee_rebate_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "public_record_root": self.roots.public_record_root,
                "counters_root": self.roots.counters_root,
            },
            "live_manifest_count": self.encrypted_state_manifests.values().filter(|manifest| manifest.status.live()).count(),
            "disclosure_ticket_count": self.disclosure_tickets.len(),
            "auditor_cohort_count": self.auditor_cohorts.len(),
            "fhe_slot_commitment_count": self.fhe_slot_commitments.len(),
            "pq_disclosure_attestation_count": self.pq_disclosure_attestations.len(),
            "callback_fence_count": self.callback_fences.len(),
            "low_fee_rebate_count": self.low_fee_rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "public_records": self.public_records.values().map(DeterministicPublicRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["roots"]["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root =
            deterministic_record_root("SELECTIVE-DISCLOSURE-CONFIG", &self.config.public_record());
        self.roots.manifest_root = public_record_root(
            "MANIFEST",
            &values_record(
                &self.encrypted_state_manifests,
                EncryptedStateManifest::public_record,
            ),
        );
        self.roots.disclosure_ticket_root = public_record_root(
            "DISCLOSURE-TICKET",
            &values_record(&self.disclosure_tickets, DisclosureTicket::public_record),
        );
        self.roots.auditor_cohort_root = public_record_root(
            "AUDITOR-COHORT",
            &values_record(&self.auditor_cohorts, AuditorCohort::public_record),
        );
        self.roots.fhe_slot_commitment_root = public_record_root(
            "FHE-SLOT-COMMITMENT",
            &values_record(&self.fhe_slot_commitments, FheSlotCommitment::public_record),
        );
        self.roots.pq_attestation_root = public_record_root(
            "PQ-ATTESTATION",
            &values_record(
                &self.pq_disclosure_attestations,
                PqDisclosureAttestation::public_record,
            ),
        );
        self.roots.callback_fence_root = public_record_root(
            "CALLBACK-FENCE",
            &values_record(&self.callback_fences, CallbackFence::public_record),
        );
        self.roots.low_fee_rebate_root = public_record_root(
            "LOW-FEE-REBATE",
            &values_record(&self.low_fee_rebates, LowFeeDisclosureRebate::public_record),
        );
        self.roots.redaction_budget_root = public_record_root(
            "REDACTION-BUDGET",
            &values_record(&self.redaction_budgets, RedactionBudget::public_record),
        );
        self.roots.public_record_root = public_record_root(
            "PUBLIC-RECORD",
            &values_record(
                &self.public_records,
                DeterministicPublicRecord::public_record,
            ),
        );
        self.roots.counters_root =
            deterministic_record_root("COUNTERS", &self.counters.public_record());
        self.roots.state_root = self.state_root();
    }

    fn emit_public_record(&mut self, domain: &str, subject_id: &str) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let sequence = self.counters.deterministic_public_records + 1;
        let record_root = deterministic_record_root(
            "PUBLIC-RECORD",
            &json!({
                "domain": domain,
                "subject_id": subject_id,
                "height": self.height,
                "sequence": sequence,
            }),
        );
        let record_id = deterministic_id(
            "PUBLIC-RECORD-ID",
            sequence,
            &json!({
                "domain": domain,
                "subject_id": subject_id,
                "record_root": record_root,
            }),
        );
        self.public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id,
                domain: domain.to_string(),
                subject_id: subject_id.to_string(),
                record_root,
                emitted_at_height: self.height,
            },
        );
        self.counters.deterministic_public_records += 1;
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

pub fn deterministic_id(domain: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SELECTIVE-STATE-DISCLOSURE:{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SELECTIVE-STATE-DISCLOSURE:{domain}-ROOT"),
        records,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SELECTIVE-STATE-DISCLOSURE:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SELECTIVE-STATE-DISCLOSURE:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

fn values_record<T, F>(records: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    records.values().map(public_record).collect()
}

fn required(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialContractSelectiveStateDisclosureRuntimeResult<()> {
    ensure!(!value.trim().is_empty(), "{field} is required");
    Ok(())
}
