use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalDepositLockVectorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_DEPOSIT_LOCK_VECTOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-deposit-lock-vector-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_DEPOSIT_LOCK_VECTOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LOCK_VECTOR_SUITE: &str = "monero-l2-pq-bridge-exit-canonical-deposit-lock-vector-v1";
pub const REDACTION_SUITE: &str = "roots-only-monero-deposit-metadata-redaction-v1";
pub const FINALITY_SUITE: &str = "monero-header-depth-and-reorg-assumption-v1";
pub const WITNESS_QUORUM_SUITE: &str = "pq-watcher-quorum-lock-evidence-v1";
pub const FEE_CAP_SUITE: &str = "forced-exit-canonical-deposit-fee-caps-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_510_400;
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_220_144;
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_REORG_SAFETY_MARGIN: u64 = 6;
pub const DEFAULT_MIN_WITNESS_WEIGHT: u64 = 5;
pub const DEFAULT_EMERGENCY_WITNESS_WEIGHT: u64 = 7;
pub const DEFAULT_MAX_FEE_BPS: u64 = 35;
pub const DEFAULT_LOW_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_OBSERVATION_AGE_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_EXIT_CLAIM_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_MAX_CASES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockCaseKind {
    MatureCanonical,
    PendingDepth,
    ReorgCompetingHeader,
    FeeCapExceeded,
    PrivacyLeak,
    WitnessQuorumGap,
    DuplicateOutput,
    BurnAddressMismatch,
}

impl LockCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MatureCanonical => "mature_canonical",
            Self::PendingDepth => "pending_depth",
            Self::ReorgCompetingHeader => "reorg_competing_header",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::PrivacyLeak => "privacy_leak",
            Self::WitnessQuorumGap => "witness_quorum_gap",
            Self::DuplicateOutput => "duplicate_output",
            Self::BurnAddressMismatch => "burn_address_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockEvidenceStatus {
    Accepted,
    Rejected,
    Watch,
}

impl LockEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Watch => "watch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    Mature,
    Pending,
    ReorgRisk,
}

impl FinalityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mature => "mature",
            Self::Pending => "pending",
            Self::ReorgRisk => "reorg_risk",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    Clean,
    Overexposed,
    MissingCommitment,
}

impl RedactionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Overexposed => "overexposed",
            Self::MissingCommitment => "missing_commitment",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumStatus {
    Satisfied,
    InsufficientWeight,
    ConflictingWitness,
}

impl QuorumStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::InsufficientWeight => "insufficient_weight",
            Self::ConflictingWitness => "conflicting_witness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCapStatus {
    WithinCap,
    LowFeePreferred,
    AboveCap,
}

impl FeeCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WithinCap => "within_cap",
            Self::LowFeePreferred => "low_fee_preferred",
            Self::AboveCap => "above_cap",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub lock_vector_suite: String,
    pub redaction_suite: String,
    pub finality_suite: String,
    pub witness_quorum_suite: String,
    pub fee_cap_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub base_monero_height: u64,
    pub l2_reference_height: u64,
    pub min_confirmations: u64,
    pub reorg_safety_margin: u64,
    pub min_witness_weight: u64,
    pub emergency_witness_weight: u64,
    pub low_fee_bps: u64,
    pub max_fee_bps: u64,
    pub max_observation_age_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub exit_claim_ttl_blocks: u64,
    pub fail_closed_on_reorg_risk: bool,
    pub fail_closed_on_privacy_leak: bool,
    pub production_release_allowed: bool,
    pub max_cases: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            lock_vector_suite: LOCK_VECTOR_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            finality_suite: FINALITY_SUITE.to_string(),
            witness_quorum_suite: WITNESS_QUORUM_SUITE.to_string(),
            fee_cap_suite: FEE_CAP_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            reorg_safety_margin: DEFAULT_REORG_SAFETY_MARGIN,
            min_witness_weight: DEFAULT_MIN_WITNESS_WEIGHT,
            emergency_witness_weight: DEFAULT_EMERGENCY_WITNESS_WEIGHT,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            max_observation_age_blocks: DEFAULT_MAX_OBSERVATION_AGE_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            exit_claim_ttl_blocks: DEFAULT_EXIT_CLAIM_TTL_BLOCKS,
            fail_closed_on_reorg_risk: true,
            fail_closed_on_privacy_leak: true,
            production_release_allowed: false,
            max_cases: DEFAULT_MAX_CASES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "lock_vector_suite": self.lock_vector_suite,
            "redaction_suite": self.redaction_suite,
            "finality_suite": self.finality_suite,
            "witness_quorum_suite": self.witness_quorum_suite,
            "fee_cap_suite": self.fee_cap_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "base_monero_height": self.base_monero_height,
            "l2_reference_height": self.l2_reference_height,
            "min_confirmations": self.min_confirmations,
            "reorg_safety_margin": self.reorg_safety_margin,
            "min_witness_weight": self.min_witness_weight,
            "emergency_witness_weight": self.emergency_witness_weight,
            "low_fee_bps": self.low_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "max_observation_age_blocks": self.max_observation_age_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "exit_claim_ttl_blocks": self.exit_claim_ttl_blocks,
            "fail_closed_on_reorg_risk": self.fail_closed_on_reorg_risk,
            "fail_closed_on_privacy_leak": self.fail_closed_on_privacy_leak,
            "production_release_allowed": self.production_release_allowed,
            "max_cases": self.max_cases,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MoneroLockObservation {
    pub lock_txid: String,
    pub output_index: u64,
    pub output_commitment: String,
    pub amount_commitment_root: String,
    pub depositor_commitment: String,
    pub burn_address_root: String,
    pub view_tag_root: String,
    pub subaddress_root: String,
    pub key_image_hint_root: String,
    pub observed_monero_height: u64,
    pub observed_depth: u64,
    pub ring_member_count: u64,
}

impl MoneroLockObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_txid": self.lock_txid,
            "output_index": self.output_index,
            "output_commitment": self.output_commitment,
            "amount_commitment_root": self.amount_commitment_root,
            "depositor_commitment": self.depositor_commitment,
            "burn_address_root": self.burn_address_root,
            "view_tag_root": self.view_tag_root,
            "subaddress_root": self.subaddress_root,
            "key_image_hint_root": self.key_image_hint_root,
            "observed_monero_height": self.observed_monero_height,
            "observed_depth": self.observed_depth,
            "ring_member_count": self.ring_member_count,
        })
    }

    pub fn root(&self) -> String {
        lock_observation_root(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalityAssumption {
    pub status: FinalityStatus,
    pub canonical_header_hash: String,
    pub competing_header_hash: String,
    pub required_depth: u64,
    pub observed_depth: u64,
    pub reorg_safety_margin: u64,
    pub header_chain_root: String,
    pub reorg_trace_root: String,
    pub assumption_id: String,
}

impl FinalityAssumption {
    pub fn public_record(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "canonical_header_hash": self.canonical_header_hash,
            "competing_header_hash": self.competing_header_hash,
            "required_depth": self.required_depth,
            "observed_depth": self.observed_depth,
            "reorg_safety_margin": self.reorg_safety_margin,
            "header_chain_root": self.header_chain_root,
            "reorg_trace_root": self.reorg_trace_root,
            "assumption_id": self.assumption_id,
        })
    }

    pub fn root(&self) -> String {
        finality_assumption_root(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedaction {
    pub status: RedactionStatus,
    pub privacy_set_size: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub redacted_fields: Vec<String>,
    pub disclosed_fields: Vec<String>,
    pub metadata_commitment_root: String,
    pub redacted_metadata_root: String,
    pub selective_disclosure_root: String,
}

impl PrivacyRedaction {
    pub fn public_record(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "redacted_fields": self.redacted_fields,
            "disclosed_fields": self.disclosed_fields,
            "metadata_commitment_root": self.metadata_commitment_root,
            "redacted_metadata_root": self.redacted_metadata_root,
            "selective_disclosure_root": self.selective_disclosure_root,
        })
    }

    pub fn root(&self) -> String {
        privacy_redaction_root(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessStatement {
    pub witness_id: String,
    pub committee_key_id: String,
    pub weight: u64,
    pub observed_lock_root: String,
    pub header_root: String,
    pub signature_root: String,
    pub attested_at_l2_height: u64,
}

impl WitnessStatement {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "committee_key_id": self.committee_key_id,
            "weight": self.weight,
            "observed_lock_root": self.observed_lock_root,
            "header_root": self.header_root,
            "signature_root": self.signature_root,
            "attested_at_l2_height": self.attested_at_l2_height,
        })
    }

    pub fn root(&self) -> String {
        witness_statement_root(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessQuorum {
    pub status: QuorumStatus,
    pub required_weight: u64,
    pub emergency_weight: u64,
    pub observed_weight: u64,
    pub conflicting_weight: u64,
    pub witness_set_root: String,
    pub statements: Vec<WitnessStatement>,
}

impl WitnessQuorum {
    pub fn public_record(&self) -> Value {
        let statements = self
            .statements
            .iter()
            .map(WitnessStatement::public_record)
            .collect::<Vec<_>>();
        json!({
            "status": self.status.as_str(),
            "required_weight": self.required_weight,
            "emergency_weight": self.emergency_weight,
            "observed_weight": self.observed_weight,
            "conflicting_weight": self.conflicting_weight,
            "witness_set_root": self.witness_set_root,
            "statements": statements,
        })
    }

    pub fn root(&self) -> String {
        witness_quorum_root(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCap {
    pub status: FeeCapStatus,
    pub requested_fee_bps: u64,
    pub low_fee_bps: u64,
    pub max_fee_bps: u64,
    pub sponsor_fee_commitment_root: String,
    pub fee_schedule_root: String,
}

impl FeeCap {
    pub fn public_record(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "requested_fee_bps": self.requested_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_fee_commitment_root": self.sponsor_fee_commitment_root,
            "fee_schedule_root": self.fee_schedule_root,
        })
    }

    pub fn root(&self) -> String {
        fee_cap_root(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CanonicalRoots {
    pub observation_root: String,
    pub finality_root: String,
    pub redaction_root: String,
    pub witness_quorum_root: String,
    pub fee_cap_root: String,
    pub evidence_root: String,
    pub rejection_root: String,
    pub case_root: String,
}

impl CanonicalRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_root": self.observation_root,
            "finality_root": self.finality_root,
            "redaction_root": self.redaction_root,
            "witness_quorum_root": self.witness_quorum_root,
            "fee_cap_root": self.fee_cap_root,
            "evidence_root": self.evidence_root,
            "rejection_root": self.rejection_root,
            "case_root": self.case_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLockCase {
    pub case_id: String,
    pub release_claim_id: String,
    pub kind: LockCaseKind,
    pub evidence_status: LockEvidenceStatus,
    pub observation: MoneroLockObservation,
    pub finality: FinalityAssumption,
    pub redaction: PrivacyRedaction,
    pub quorum: WitnessQuorum,
    pub fee_cap: FeeCap,
    pub acceptance_reason: String,
    pub rejection_code: String,
    pub roots: CanonicalRoots,
}

impl DepositLockCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "release_claim_id": self.release_claim_id,
            "kind": self.kind.as_str(),
            "evidence_status": self.evidence_status.as_str(),
            "observation": self.observation.public_record(),
            "finality": self.finality.public_record(),
            "redaction": self.redaction.public_record(),
            "quorum": self.quorum.public_record(),
            "fee_cap": self.fee_cap.public_record(),
            "acceptance_reason": self.acceptance_reason,
            "rejection_code": self.rejection_code,
            "roots": self.roots.public_record(),
        })
    }

    pub fn root(&self) -> String {
        deposit_lock_case_root(self)
    }

    pub fn accepted(&self) -> bool {
        self.evidence_status == LockEvidenceStatus::Accepted
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub cases: Vec<DepositLockCase>,
    pub accepted_case_ids: Vec<String>,
    pub rejected_case_ids: Vec<String>,
    pub watch_case_ids: Vec<String>,
    pub devnet_data: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, cases: Vec<DepositLockCase>) -> Result<Self> {
        if cases.len() > config.max_cases {
            return Err(format!(
                "case count {} exceeds configured max {}",
                cases.len(),
                config.max_cases
            ));
        }

        let mut seen = BTreeMap::<String, String>::new();
        let mut accepted_case_ids = Vec::new();
        let mut rejected_case_ids = Vec::new();
        let mut watch_case_ids = Vec::new();

        for case in &cases {
            if let Some(existing) = seen.insert(
                case.observation.output_commitment.clone(),
                case.case_id.clone(),
            ) {
                return Err(format!(
                    "duplicate output commitment {} across cases {} and {}",
                    case.observation.output_commitment, existing, case.case_id
                ));
            }
            match case.evidence_status {
                LockEvidenceStatus::Accepted => accepted_case_ids.push(case.case_id.clone()),
                LockEvidenceStatus::Rejected => rejected_case_ids.push(case.case_id.clone()),
                LockEvidenceStatus::Watch => watch_case_ids.push(case.case_id.clone()),
            }
        }

        Ok(Self {
            config,
            cases,
            accepted_case_ids,
            rejected_case_ids,
            watch_case_ids,
            devnet_data: devnet_data(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let cases = self
            .cases
            .iter()
            .map(DepositLockCase::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "cases": cases,
            "accepted_case_ids": self.accepted_case_ids,
            "rejected_case_ids": self.rejected_case_ids,
            "watch_case_ids": self.watch_case_ids,
            "roots": {
                "accepted_root": self.accepted_root(),
                "rejected_root": self.rejected_root(),
                "watch_root": self.watch_root(),
                "case_root": self.case_root(),
                "canonical_lock_vector_root": self.canonical_lock_vector_root(),
                "devnet_data_root": self.devnet_data_root(),
            },
            "devnet_data": self.devnet_data,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-DEPOSIT-LOCK-VECTOR-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn case_root(&self) -> String {
        let records = self
            .cases
            .iter()
            .map(DepositLockCase::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-DEPOSIT-LOCK-VECTOR-CASES",
            &records,
        )
    }

    pub fn accepted_root(&self) -> String {
        vector_root("ACCEPTED", &self.accepted_case_ids)
    }

    pub fn rejected_root(&self) -> String {
        vector_root("REJECTED", &self.rejected_case_ids)
    }

    pub fn watch_root(&self) -> String {
        vector_root("WATCH", &self.watch_case_ids)
    }

    pub fn canonical_lock_vector_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-DEPOSIT-LOCK-VECTOR-ROOT",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.protocol_version),
                HashPart::Str(&self.accepted_root()),
                HashPart::Str(&self.rejected_root()),
                HashPart::Str(&self.watch_root()),
                HashPart::Str(&self.case_root()),
                HashPart::Str(&self.devnet_data_root()),
            ],
            32,
        )
    }

    pub fn devnet_data_root(&self) -> String {
        let records = self
            .devnet_data
            .iter()
            .map(|(key, value)| json!({ "key": key, "value": value }))
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-DEPOSIT-LOCK-VECTOR-DEVNET-DATA",
            &records,
        )
    }

    pub fn accepted_cases(&self) -> Vec<&DepositLockCase> {
        self.cases.iter().filter(|case| case.accepted()).collect()
    }

    pub fn rejected_cases(&self) -> Vec<&DepositLockCase> {
        self.cases
            .iter()
            .filter(|case| case.evidence_status == LockEvidenceStatus::Rejected)
            .collect()
    }

    pub fn case_by_id(&self, case_id: &str) -> Option<&DepositLockCase> {
        self.cases.iter().find(|case| case.case_id == case_id)
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let cases = devnet_cases(&config);
    State::new(config, cases).unwrap_or_else(|err| fallback_state(err))
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn devnet_cases(config: &Config) -> Vec<DepositLockCase> {
    vec![
        build_case(
            config,
            0,
            LockCaseKind::MatureCanonical,
            LockEvidenceStatus::Accepted,
            FinalityStatus::Mature,
            RedactionStatus::Clean,
            QuorumStatus::Satisfied,
            FeeCapStatus::LowFeePreferred,
            "",
        ),
        build_case(
            config,
            1,
            LockCaseKind::PendingDepth,
            LockEvidenceStatus::Watch,
            FinalityStatus::Pending,
            RedactionStatus::Clean,
            QuorumStatus::Satisfied,
            FeeCapStatus::WithinCap,
            "pending_finality_depth",
        ),
        build_case(
            config,
            2,
            LockCaseKind::ReorgCompetingHeader,
            LockEvidenceStatus::Rejected,
            FinalityStatus::ReorgRisk,
            RedactionStatus::Clean,
            QuorumStatus::ConflictingWitness,
            FeeCapStatus::WithinCap,
            "competing_header_above_margin",
        ),
        build_case(
            config,
            3,
            LockCaseKind::FeeCapExceeded,
            LockEvidenceStatus::Rejected,
            FinalityStatus::Mature,
            RedactionStatus::Clean,
            QuorumStatus::Satisfied,
            FeeCapStatus::AboveCap,
            "fee_cap_exceeded",
        ),
        build_case(
            config,
            4,
            LockCaseKind::PrivacyLeak,
            LockEvidenceStatus::Rejected,
            FinalityStatus::Mature,
            RedactionStatus::Overexposed,
            QuorumStatus::Satisfied,
            FeeCapStatus::WithinCap,
            "deposit_metadata_overexposed",
        ),
        build_case(
            config,
            5,
            LockCaseKind::WitnessQuorumGap,
            LockEvidenceStatus::Watch,
            FinalityStatus::Mature,
            RedactionStatus::Clean,
            QuorumStatus::InsufficientWeight,
            FeeCapStatus::WithinCap,
            "witness_weight_below_threshold",
        ),
        build_case(
            config,
            6,
            LockCaseKind::DuplicateOutput,
            LockEvidenceStatus::Rejected,
            FinalityStatus::Mature,
            RedactionStatus::Clean,
            QuorumStatus::Satisfied,
            FeeCapStatus::WithinCap,
            "duplicate_output_claim",
        ),
        build_case(
            config,
            7,
            LockCaseKind::BurnAddressMismatch,
            LockEvidenceStatus::Rejected,
            FinalityStatus::Mature,
            RedactionStatus::MissingCommitment,
            QuorumStatus::Satisfied,
            FeeCapStatus::WithinCap,
            "burn_address_commitment_mismatch",
        ),
    ]
}

pub fn lock_observation_root(observation: &MoneroLockObservation) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-LOCK-OBSERVATION",
        &[
            HashPart::Str(&observation.lock_txid),
            HashPart::U64(observation.output_index),
            HashPart::Str(&observation.output_commitment),
            HashPart::Str(&observation.amount_commitment_root),
            HashPart::Str(&observation.depositor_commitment),
            HashPart::Str(&observation.burn_address_root),
            HashPart::Str(&observation.view_tag_root),
            HashPart::Str(&observation.subaddress_root),
            HashPart::Str(&observation.key_image_hint_root),
            HashPart::U64(observation.observed_monero_height),
            HashPart::U64(observation.observed_depth),
            HashPart::U64(observation.ring_member_count),
        ],
        32,
    )
}

pub fn finality_assumption_root(finality: &FinalityAssumption) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-FINALITY-ASSUMPTION",
        &[
            HashPart::Str(finality.status.as_str()),
            HashPart::Str(&finality.canonical_header_hash),
            HashPart::Str(&finality.competing_header_hash),
            HashPart::U64(finality.required_depth),
            HashPart::U64(finality.observed_depth),
            HashPart::U64(finality.reorg_safety_margin),
            HashPart::Str(&finality.header_chain_root),
            HashPart::Str(&finality.reorg_trace_root),
            HashPart::Str(&finality.assumption_id),
        ],
        32,
    )
}

pub fn privacy_redaction_root(redaction: &PrivacyRedaction) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVACY-REDACTION",
        &[
            HashPart::Str(redaction.status.as_str()),
            HashPart::U64(redaction.privacy_set_size),
            HashPart::U64(redaction.min_privacy_set_size),
            HashPart::U64(redaction.target_privacy_set_size),
            HashPart::Str(&vector_root("REDACTED-FIELDS", &redaction.redacted_fields)),
            HashPart::Str(&vector_root(
                "DISCLOSED-FIELDS",
                &redaction.disclosed_fields,
            )),
            HashPart::Str(&redaction.metadata_commitment_root),
            HashPart::Str(&redaction.redacted_metadata_root),
            HashPart::Str(&redaction.selective_disclosure_root),
        ],
        32,
    )
}

pub fn witness_statement_root(statement: &WitnessStatement) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WITNESS-STATEMENT",
        &[
            HashPart::Str(&statement.witness_id),
            HashPart::Str(&statement.committee_key_id),
            HashPart::U64(statement.weight),
            HashPart::Str(&statement.observed_lock_root),
            HashPart::Str(&statement.header_root),
            HashPart::Str(&statement.signature_root),
            HashPart::U64(statement.attested_at_l2_height),
        ],
        32,
    )
}

pub fn witness_quorum_root(quorum: &WitnessQuorum) -> String {
    let statement_records = quorum
        .statements
        .iter()
        .map(WitnessStatement::public_record)
        .collect::<Vec<_>>();
    let statement_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WITNESS-STATEMENTS",
        &statement_records,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WITNESS-QUORUM",
        &[
            HashPart::Str(quorum.status.as_str()),
            HashPart::U64(quorum.required_weight),
            HashPart::U64(quorum.emergency_weight),
            HashPart::U64(quorum.observed_weight),
            HashPart::U64(quorum.conflicting_weight),
            HashPart::Str(&quorum.witness_set_root),
            HashPart::Str(&statement_root),
        ],
        32,
    )
}

pub fn fee_cap_root(fee_cap: &FeeCap) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-FEE-CAP",
        &[
            HashPart::Str(fee_cap.status.as_str()),
            HashPart::U64(fee_cap.requested_fee_bps),
            HashPart::U64(fee_cap.low_fee_bps),
            HashPart::U64(fee_cap.max_fee_bps),
            HashPart::Str(&fee_cap.sponsor_fee_commitment_root),
            HashPart::Str(&fee_cap.fee_schedule_root),
        ],
        32,
    )
}

pub fn deposit_lock_case_root(case: &DepositLockCase) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-DEPOSIT-LOCK-CASE",
        &[
            HashPart::Str(&case.case_id),
            HashPart::Str(&case.release_claim_id),
            HashPart::Str(case.kind.as_str()),
            HashPart::Str(case.evidence_status.as_str()),
            HashPart::Str(&case.roots.observation_root),
            HashPart::Str(&case.roots.finality_root),
            HashPart::Str(&case.roots.redaction_root),
            HashPart::Str(&case.roots.witness_quorum_root),
            HashPart::Str(&case.roots.fee_cap_root),
            HashPart::Str(&case.roots.evidence_root),
            HashPart::Str(&case.roots.rejection_root),
            HashPart::Str(&case.acceptance_reason),
            HashPart::Str(&case.rejection_code),
        ],
        32,
    )
}

pub fn canonical_evidence_root(
    observation_root: &str,
    finality_root: &str,
    redaction_root: &str,
    quorum_root: &str,
    fee_cap_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-EVIDENCE",
        &[
            HashPart::Str(observation_root),
            HashPart::Str(finality_root),
            HashPart::Str(redaction_root),
            HashPart::Str(quorum_root),
            HashPart::Str(fee_cap_root),
        ],
        32,
    )
}

pub fn rejection_root(
    status: LockEvidenceStatus,
    rejection_code: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-REJECTION",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(rejection_code),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn redacted_metadata_commitment(label: &str, fields: &[&str]) -> String {
    let records = fields
        .iter()
        .map(|field| json!({ "field": field, "policy": "redacted" }))
        .collect::<Vec<_>>();
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REDACTED-METADATA-COMMITMENT",
        &[
            HashPart::Str(label),
            HashPart::Str(&merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-REDACTED-METADATA-FIELDS",
                &records,
            )),
        ],
        32,
    )
}

pub fn vector_root(label: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "label": label, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-DEPOSIT-LOCK-VECTOR-{label}"),
        &records,
    )
}

fn build_case(
    config: &Config,
    index: u64,
    kind: LockCaseKind,
    evidence_status: LockEvidenceStatus,
    finality_status: FinalityStatus,
    redaction_status: RedactionStatus,
    quorum_status: QuorumStatus,
    fee_status: FeeCapStatus,
    rejection_code: &str,
) -> DepositLockCase {
    let label = format!("canonical-lock-case-{index}");
    let lock_txid = domain_hash("MONERO-DEVNET-LOCK-TXID", &[HashPart::Str(&label)], 32);
    let output_commitment = domain_hash(
        "MONERO-DEVNET-LOCK-OUTPUT-COMMITMENT",
        &[HashPart::Str(&label), HashPart::U64(index)],
        32,
    );
    let observed_depth = match finality_status {
        FinalityStatus::Mature => config.min_confirmations + config.reorg_safety_margin + index,
        FinalityStatus::Pending => config.min_confirmations.saturating_sub(3),
        FinalityStatus::ReorgRisk => config.min_confirmations + 1,
    };
    let observation = MoneroLockObservation {
        lock_txid: lock_txid.clone(),
        output_index: index,
        output_commitment: output_commitment.clone(),
        amount_commitment_root: domain_hash(
            "MONERO-DEVNET-AMOUNT-COMMITMENT",
            &[HashPart::Str(&label)],
            32,
        ),
        depositor_commitment: domain_hash(
            "MONERO-DEVNET-DEPOSITOR-COMMITMENT",
            &[HashPart::Str(&label)],
            32,
        ),
        burn_address_root: domain_hash(
            "MONERO-DEVNET-BURN-ADDRESS",
            &[
                HashPart::Str(&label),
                HashPart::Str(match kind {
                    LockCaseKind::BurnAddressMismatch => "mismatch",
                    _ => "canonical",
                }),
            ],
            32,
        ),
        view_tag_root: redacted_metadata_commitment(&format!("{label}-view-tag"), &["view_tag"]),
        subaddress_root: redacted_metadata_commitment(
            &format!("{label}-subaddress"),
            &["major", "minor"],
        ),
        key_image_hint_root: redacted_metadata_commitment(
            &format!("{label}-key-image"),
            &["key_image_hint"],
        ),
        observed_monero_height: config.base_monero_height + index * 11,
        observed_depth,
        ring_member_count: 16 + index,
    };
    let observation_root = observation.root();

    let finality = FinalityAssumption {
        status: finality_status,
        canonical_header_hash: domain_hash(
            "MONERO-DEVNET-CANONICAL-HEADER",
            &[HashPart::Str(&lock_txid), HashPart::U64(observed_depth)],
            32,
        ),
        competing_header_hash: match finality_status {
            FinalityStatus::ReorgRisk => domain_hash(
                "MONERO-DEVNET-COMPETING-HEADER",
                &[HashPart::Str(&lock_txid), HashPart::Str("active")],
                32,
            ),
            _ => merkle_root("MONERO-DEVNET-NO-COMPETING-HEADER", &[]),
        },
        required_depth: config.min_confirmations,
        observed_depth,
        reorg_safety_margin: config.reorg_safety_margin,
        header_chain_root: domain_hash(
            "MONERO-DEVNET-HEADER-CHAIN",
            &[
                HashPart::Str(&lock_txid),
                HashPart::U64(config.base_monero_height),
            ],
            32,
        ),
        reorg_trace_root: domain_hash(
            "MONERO-DEVNET-REORG-TRACE",
            &[
                HashPart::Str(&lock_txid),
                HashPart::Str(finality_status.as_str()),
            ],
            32,
        ),
        assumption_id: domain_hash(
            "MONERO-DEVNET-FINALITY-ASSUMPTION-ID",
            &[
                HashPart::Str(&lock_txid),
                HashPart::Str(finality_status.as_str()),
            ],
            16,
        ),
    };
    let finality_root = finality.root();

    let disclosed_fields = match redaction_status {
        RedactionStatus::Clean => vec!["lock_txid".to_string(), "output_commitment".to_string()],
        RedactionStatus::Overexposed => vec![
            "lock_txid".to_string(),
            "output_commitment".to_string(),
            "subaddress_minor".to_string(),
        ],
        RedactionStatus::MissingCommitment => vec!["lock_txid".to_string()],
    };
    let redacted_fields = vec![
        "amount".to_string(),
        "depositor_account".to_string(),
        "subaddress".to_string(),
        "view_tag".to_string(),
        "key_image_hint".to_string(),
    ];
    let privacy_set_size = match redaction_status {
        RedactionStatus::Clean => config.target_privacy_set_size + index * 256,
        RedactionStatus::Overexposed => config.min_privacy_set_size + 8,
        RedactionStatus::MissingCommitment => config.min_privacy_set_size,
    };
    let redaction = PrivacyRedaction {
        status: redaction_status,
        privacy_set_size,
        min_privacy_set_size: config.min_privacy_set_size,
        target_privacy_set_size: config.target_privacy_set_size,
        redacted_fields,
        disclosed_fields,
        metadata_commitment_root: domain_hash(
            "MONERO-DEVNET-METADATA-COMMITMENT",
            &[HashPart::Str(&label), HashPart::Str(&observation_root)],
            32,
        ),
        redacted_metadata_root: domain_hash(
            "MONERO-DEVNET-REDACTED-METADATA",
            &[
                HashPart::Str(&label),
                HashPart::Str(redaction_status.as_str()),
            ],
            32,
        ),
        selective_disclosure_root: domain_hash(
            "MONERO-DEVNET-SELECTIVE-DISCLOSURE",
            &[
                HashPart::Str(&label),
                HashPart::Str(redaction_status.as_str()),
            ],
            32,
        ),
    };
    let redaction_root = redaction.root();

    let witness_count = match quorum_status {
        QuorumStatus::Satisfied => 4,
        QuorumStatus::InsufficientWeight => 2,
        QuorumStatus::ConflictingWitness => 5,
    };
    let statements = (0..witness_count)
        .map(|witness_index| witness_statement(config, &label, witness_index, &observation_root))
        .collect::<Vec<_>>();
    let observed_weight = statements
        .iter()
        .map(|statement| statement.weight)
        .sum::<u64>();
    let conflicting_weight = match quorum_status {
        QuorumStatus::ConflictingWitness => 3,
        _ => 0,
    };
    let quorum = WitnessQuorum {
        status: quorum_status,
        required_weight: config.min_witness_weight,
        emergency_weight: config.emergency_witness_weight,
        observed_weight,
        conflicting_weight,
        witness_set_root: domain_hash(
            "MONERO-DEVNET-WITNESS-SET",
            &[HashPart::Str(&label), HashPart::Str(quorum_status.as_str())],
            32,
        ),
        statements,
    };
    let witness_quorum_root = quorum.root();

    let requested_fee_bps = match fee_status {
        FeeCapStatus::LowFeePreferred => config.low_fee_bps,
        FeeCapStatus::WithinCap => config.max_fee_bps.saturating_sub(4),
        FeeCapStatus::AboveCap => config.max_fee_bps + 9,
    };
    let fee_cap = FeeCap {
        status: fee_status,
        requested_fee_bps,
        low_fee_bps: config.low_fee_bps,
        max_fee_bps: config.max_fee_bps,
        sponsor_fee_commitment_root: domain_hash(
            "MONERO-DEVNET-SPONSOR-FEE-COMMITMENT",
            &[HashPart::Str(&label), HashPart::U64(requested_fee_bps)],
            32,
        ),
        fee_schedule_root: domain_hash(
            "MONERO-DEVNET-FEE-SCHEDULE",
            &[
                HashPart::U64(config.low_fee_bps),
                HashPart::U64(config.max_fee_bps),
            ],
            32,
        ),
    };
    let fee_cap_root = fee_cap.root();
    let evidence_root = canonical_evidence_root(
        &observation_root,
        &finality_root,
        &redaction_root,
        &witness_quorum_root,
        &fee_cap_root,
    );
    let rejection_root = rejection_root(evidence_status, rejection_code, &evidence_root);
    let case_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-DEPOSIT-LOCK-CASE-ID",
        &[HashPart::Str(&label), HashPart::Str(&evidence_root)],
        16,
    );
    let release_claim_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-DEPOSIT-LOCK-RELEASE-CLAIM",
        &[HashPart::Str(&case_id), HashPart::Str(&output_commitment)],
        16,
    );
    let mut roots = CanonicalRoots {
        observation_root,
        finality_root,
        redaction_root,
        witness_quorum_root,
        fee_cap_root,
        evidence_root,
        rejection_root,
        case_root: String::new(),
    };
    let acceptance_reason = match evidence_status {
        LockEvidenceStatus::Accepted => "canonical_lock_evidence_satisfies_forced_exit_gate",
        LockEvidenceStatus::Watch => "canonical_lock_evidence_requires_more_observation",
        LockEvidenceStatus::Rejected => "canonical_lock_evidence_fails_heavy_gate",
    }
    .to_string();
    let mut case = DepositLockCase {
        case_id,
        release_claim_id,
        kind,
        evidence_status,
        observation,
        finality,
        redaction,
        quorum,
        fee_cap,
        acceptance_reason,
        rejection_code: rejection_code.to_string(),
        roots: roots.clone(),
    };
    roots.case_root = deposit_lock_case_root(&case);
    case.roots = roots;
    case
}

fn witness_statement(
    config: &Config,
    label: &str,
    witness_index: u64,
    observation_root: &str,
) -> WitnessStatement {
    let witness_id = domain_hash(
        "MONERO-DEVNET-WITNESS-ID",
        &[HashPart::Str(label), HashPart::U64(witness_index)],
        16,
    );
    WitnessStatement {
        witness_id: witness_id.clone(),
        committee_key_id: domain_hash(
            "MONERO-DEVNET-WITNESS-COMMITTEE-KEY",
            &[HashPart::Str(&witness_id)],
            16,
        ),
        weight: if witness_index == 0 { 2 } else { 1 },
        observed_lock_root: observation_root.to_string(),
        header_root: domain_hash(
            "MONERO-DEVNET-WITNESS-HEADER-ROOT",
            &[HashPart::Str(label), HashPart::U64(witness_index)],
            32,
        ),
        signature_root: domain_hash(
            "MONERO-DEVNET-WITNESS-SIGNATURE",
            &[HashPart::Str(&witness_id), HashPart::Str(observation_root)],
            32,
        ),
        attested_at_l2_height: config.l2_reference_height + witness_index,
    }
}

fn devnet_data() -> BTreeMap<String, Value> {
    let mut data = BTreeMap::new();
    data.insert(
        "bridge_exit_lane".to_string(),
        json!({
            "name": "pq-forced-exit-heavy-gate",
            "monero_network": DEVNET_MONERO_NETWORK,
            "l2_network": DEVNET_L2_NETWORK,
        }),
    );
    data.insert(
        "canonical_vector_policy".to_string(),
        json!({
            "accepted_inputs": [
                "lock_txid",
                "output_commitment",
                "amount_commitment_root",
                "depositor_commitment",
                "burn_address_root",
                "watcher_quorum_root"
            ],
            "redacted_inputs": [
                "amount",
                "subaddress_major",
                "subaddress_minor",
                "view_tag",
                "key_image_hint",
                "wallet_scan_path"
            ],
            "reorg_policy": "reject_competing_header_after_margin",
            "fee_policy": "reject_above_cap_prefer_low_fee"
        }),
    );
    data.insert(
        "future_heavy_gate_bindings".to_string(),
        json!({
            "proof_public_inputs": [
                "canonical_lock_vector_root",
                "accepted_root",
                "rejected_root",
                "watch_root",
                "state_root"
            ],
            "witness_quorum_suite": WITNESS_QUORUM_SUITE,
            "finality_suite": FINALITY_SUITE,
            "redaction_suite": REDACTION_SUITE
        }),
    );
    data
}

fn fallback_state(reason: String) -> State {
    let config = Config::devnet();
    let mut devnet_data = devnet_data();
    devnet_data.insert(
        "construction_error".to_string(),
        json!({ "reason_root": domain_hash("MONERO-DEVNET-FALLBACK-REASON", &[HashPart::Str(&reason)], 32) }),
    );
    State {
        config,
        cases: Vec::new(),
        accepted_case_ids: Vec::new(),
        rejected_case_ids: Vec::new(),
        watch_case_ids: Vec::new(),
        devnet_data,
    }
}
