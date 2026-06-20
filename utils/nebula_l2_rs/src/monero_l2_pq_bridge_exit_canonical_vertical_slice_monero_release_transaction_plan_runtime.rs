use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceMoneroReleaseTransactionPlanRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_MONERO_RELEASE_TRANSACTION_PLAN_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-monero-release-transaction-plan-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_MONERO_RELEASE_TRANSACTION_PLAN_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PLAN_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-monero-release-transaction-plan-v1";
pub const DEFAULT_NETWORK: &str = "monero-devnet";
pub const DEFAULT_RELEASE_LANE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-release-transaction-lane-devnet-v1";
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 20;
pub const DEFAULT_CONFIRMATION_TARGET: u64 = 28;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u16 = 16;
pub const DEFAULT_MAX_METADATA_BYTES: u64 = 128;
pub const DEFAULT_FEE_CAP_PICONERO: u64 = 18_000_000;
pub const DEFAULT_DUST_THRESHOLD_PICONERO: u64 = 1_000_000;
pub const DEFAULT_MAX_INPUTS: usize = 16;
pub const DEFAULT_MAX_RELEASES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyOutputStatus {
    Mature,
    Pending,
    Frozen,
    Spent,
}

impl CustodyOutputStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mature => "mature",
            Self::Pending => "pending",
            Self::Frozen => "frozen",
            Self::Spent => "spent",
        }
    }

    pub fn selectable(self) -> bool {
        self == Self::Mature
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleasePriority {
    Low,
    Normal,
    High,
    Emergency,
}

impl ReleasePriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_multiplier(self) -> u64 {
        match self {
            Self::Low => 80,
            Self::Normal => 100,
            Self::High => 125,
            Self::Emergency => 150,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangePolicy {
    ReturnToCustody,
    AddToPayout,
    SweepOnly,
}

impl ChangePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReturnToCustody => "return_to_custody",
            Self::AddToPayout => "add_to_payout",
            Self::SweepOnly => "sweep_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReasonKind {
    SourceNotMature,
    SourceFrozen,
    SourceAlreadySpent,
    SourceCommitmentMismatch,
    PayoutCommitmentMissing,
    AmountBucketMismatch,
    InsufficientCustodyValue,
    FeeCapExceeded,
    ChangeBelowDust,
    SweepRequiresExactSpend,
    DecoySetTooSmall,
    MetadataTooLarge,
    ConfirmationTargetTooLow,
    ReceiptRootMissing,
    TooManyInputs,
    PlanDisabled,
}

impl HoldReasonKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceNotMature => "source_not_mature",
            Self::SourceFrozen => "source_frozen",
            Self::SourceAlreadySpent => "source_already_spent",
            Self::SourceCommitmentMismatch => "source_commitment_mismatch",
            Self::PayoutCommitmentMissing => "payout_commitment_missing",
            Self::AmountBucketMismatch => "amount_bucket_mismatch",
            Self::InsufficientCustodyValue => "insufficient_custody_value",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::ChangeBelowDust => "change_below_dust",
            Self::SweepRequiresExactSpend => "sweep_requires_exact_spend",
            Self::DecoySetTooSmall => "decoy_set_too_small",
            Self::MetadataTooLarge => "metadata_too_large",
            Self::ConfirmationTargetTooLow => "confirmation_target_too_low",
            Self::ReceiptRootMissing => "receipt_root_missing",
            Self::TooManyInputs => "too_many_inputs",
            Self::PlanDisabled => "plan_disabled",
        }
    }

    pub fn severity(self) -> HoldSeverity {
        match self {
            Self::PlanDisabled
            | Self::SourceCommitmentMismatch
            | Self::SourceAlreadySpent
            | Self::PayoutCommitmentMissing
            | Self::ReceiptRootMissing => HoldSeverity::Stop,
            Self::InsufficientCustodyValue
            | Self::FeeCapExceeded
            | Self::AmountBucketMismatch
            | Self::SweepRequiresExactSpend
            | Self::TooManyInputs => HoldSeverity::Critical,
            Self::SourceFrozen
            | Self::DecoySetTooSmall
            | Self::MetadataTooLarge
            | Self::ConfirmationTargetTooLow => HoldSeverity::Major,
            Self::SourceNotMature | Self::ChangeBelowDust => HoldSeverity::Watch,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldSeverity {
    Watch,
    Major,
    Critical,
    Stop,
}

impl HoldSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Major => "major",
            Self::Critical => "critical",
            Self::Stop => "stop",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Watch => 1,
            Self::Major => 2,
            Self::Critical => 3,
            Self::Stop => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanDecision {
    Formable,
    Held,
}

impl PlanDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Formable => "formable",
            Self::Held => "held",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub plan_suite: String,
    pub network: String,
    pub release_lane_id: String,
    pub min_confirmations: u64,
    pub confirmation_target: u64,
    pub min_decoy_set_size: u16,
    pub max_metadata_bytes: u64,
    pub fee_cap_piconero: u64,
    pub dust_threshold_piconero: u64,
    pub max_inputs: usize,
    pub max_releases: usize,
    pub planning_enabled: bool,
    pub production_broadcast_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            plan_suite: PLAN_SUITE.to_string(),
            network: DEFAULT_NETWORK.to_string(),
            release_lane_id: DEFAULT_RELEASE_LANE_ID.to_string(),
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            confirmation_target: DEFAULT_CONFIRMATION_TARGET,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
            fee_cap_piconero: DEFAULT_FEE_CAP_PICONERO,
            dust_threshold_piconero: DEFAULT_DUST_THRESHOLD_PICONERO,
            max_inputs: DEFAULT_MAX_INPUTS,
            max_releases: DEFAULT_MAX_RELEASES,
            planning_enabled: true,
            production_broadcast_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "plan_suite": self.plan_suite,
            "network": self.network,
            "release_lane_id": self.release_lane_id,
            "min_confirmations": self.min_confirmations,
            "confirmation_target": self.confirmation_target,
            "min_decoy_set_size": self.min_decoy_set_size,
            "max_metadata_bytes": self.max_metadata_bytes,
            "fee_cap_piconero": self.fee_cap_piconero,
            "dust_threshold_piconero": self.dust_threshold_piconero,
            "max_inputs": self.max_inputs,
            "max_releases": self.max_releases,
            "planning_enabled": self.planning_enabled,
            "production_broadcast_allowed": self.production_broadcast_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CustodyOutput {
    pub output_id: String,
    pub custody_commitment: String,
    pub key_image_commitment: String,
    pub amount_piconero: u64,
    pub amount_bucket_commitment: String,
    pub confirmations: u64,
    pub status: CustodyOutputStatus,
    pub decoy_set_size: u16,
    pub metadata_bytes: u64,
    pub source_receipt_root: String,
}

impl CustodyOutput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        output_id: impl Into<String>,
        custody_commitment: impl Into<String>,
        key_image_commitment: impl Into<String>,
        amount_piconero: u64,
        amount_bucket_commitment: impl Into<String>,
        confirmations: u64,
        status: CustodyOutputStatus,
        decoy_set_size: u16,
        metadata_bytes: u64,
        source_receipt_root: impl Into<String>,
    ) -> Self {
        Self {
            output_id: output_id.into(),
            custody_commitment: custody_commitment.into(),
            key_image_commitment: key_image_commitment.into(),
            amount_piconero,
            amount_bucket_commitment: amount_bucket_commitment.into(),
            confirmations,
            status,
            decoy_set_size,
            metadata_bytes,
            source_receipt_root: source_receipt_root.into(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "output_id": self.output_id,
            "custody_commitment": self.custody_commitment,
            "key_image_commitment": self.key_image_commitment,
            "amount_piconero": self.amount_piconero,
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "confirmations": self.confirmations,
            "status": self.status.as_str(),
            "decoy_set_size": self.decoy_set_size,
            "metadata_bytes": self.metadata_bytes,
            "source_receipt_root": self.source_receipt_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("custody_output", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseIntent {
    pub release_id: String,
    pub exit_claim_id: String,
    pub payout_address_commitment: String,
    pub amount_piconero: u64,
    pub amount_bucket_commitment: String,
    pub fee_cap_piconero: u64,
    pub change_policy: ChangePolicy,
    pub priority: ReleasePriority,
    pub confirmation_target: u64,
    pub required_receipt_roots: BTreeMap<String, String>,
    pub expected_source_commitments: Vec<String>,
}

impl ReleaseIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        release_id: impl Into<String>,
        exit_claim_id: impl Into<String>,
        payout_address_commitment: impl Into<String>,
        amount_piconero: u64,
        amount_bucket_commitment: impl Into<String>,
        fee_cap_piconero: u64,
        change_policy: ChangePolicy,
        priority: ReleasePriority,
        confirmation_target: u64,
        required_receipt_roots: BTreeMap<String, String>,
        expected_source_commitments: Vec<String>,
    ) -> Self {
        Self {
            release_id: release_id.into(),
            exit_claim_id: exit_claim_id.into(),
            payout_address_commitment: payout_address_commitment.into(),
            amount_piconero,
            amount_bucket_commitment: amount_bucket_commitment.into(),
            fee_cap_piconero,
            change_policy,
            priority,
            confirmation_target,
            required_receipt_roots,
            expected_source_commitments,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "release_id": self.release_id,
            "exit_claim_id": self.exit_claim_id,
            "payout_address_commitment": self.payout_address_commitment,
            "amount_piconero": self.amount_piconero,
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "fee_cap_piconero": self.fee_cap_piconero,
            "change_policy": self.change_policy.as_str(),
            "priority": self.priority.as_str(),
            "confirmation_target": self.confirmation_target,
            "required_receipt_roots": self.required_receipt_roots,
            "expected_source_commitments": self.expected_source_commitments,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_intent", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeePolicy {
    pub base_fee_piconero: u64,
    pub per_input_fee_piconero: u64,
    pub per_output_fee_piconero: u64,
    pub metadata_fee_piconero: u64,
}

impl FeePolicy {
    pub fn devnet() -> Self {
        Self {
            base_fee_piconero: 4_000_000,
            per_input_fee_piconero: 1_500_000,
            per_output_fee_piconero: 1_000_000,
            metadata_fee_piconero: 500_000,
        }
    }

    pub fn estimate(
        &self,
        input_count: usize,
        output_count: usize,
        metadata_bytes: u64,
        priority: ReleasePriority,
    ) -> u64 {
        let input_fee = self
            .per_input_fee_piconero
            .saturating_mul(input_count as u64);
        let output_fee = self
            .per_output_fee_piconero
            .saturating_mul(output_count as u64);
        let metadata_chunks = metadata_bytes.saturating_add(31) / 32;
        let metadata_fee = self.metadata_fee_piconero.saturating_mul(metadata_chunks);
        let subtotal = self
            .base_fee_piconero
            .saturating_add(input_fee)
            .saturating_add(output_fee)
            .saturating_add(metadata_fee);
        subtotal.saturating_mul(priority.fee_multiplier()) / 100
    }

    pub fn public_record(&self) -> Value {
        json!({
            "base_fee_piconero": self.base_fee_piconero,
            "per_input_fee_piconero": self.per_input_fee_piconero,
            "per_output_fee_piconero": self.per_output_fee_piconero,
            "metadata_fee_piconero": self.metadata_fee_piconero,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HoldReason {
    pub kind: HoldReasonKind,
    pub severity: HoldSeverity,
    pub subject_id: String,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
}

impl HoldReason {
    pub fn new(
        kind: HoldReasonKind,
        subject_id: impl Into<String>,
        requirement: impl Into<String>,
        observed: impl Into<String>,
    ) -> Self {
        let subject_id = subject_id.into();
        let requirement = requirement.into();
        let observed = observed.into();
        let severity = kind.severity();
        let evidence_root = domain_hash(
            "monero_release_transaction_plan:hold_reason",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::Str(&subject_id),
                HashPart::Str(&requirement),
                HashPart::Str(&observed),
            ],
            32,
        );
        Self {
            kind,
            severity,
            subject_id,
            requirement,
            observed,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "subject_id": self.subject_id,
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlannedInput {
    pub output_id: String,
    pub custody_commitment: String,
    pub key_image_commitment: String,
    pub amount_piconero: u64,
    pub source_receipt_root: String,
}

impl PlannedInput {
    pub fn from_output(output: &CustodyOutput) -> Self {
        Self {
            output_id: output.output_id.clone(),
            custody_commitment: output.custody_commitment.clone(),
            key_image_commitment: output.key_image_commitment.clone(),
            amount_piconero: output.amount_piconero,
            source_receipt_root: output.source_receipt_root.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "output_id": self.output_id,
            "custody_commitment": self.custody_commitment,
            "key_image_commitment": self.key_image_commitment,
            "amount_piconero": self.amount_piconero,
            "source_receipt_root": self.source_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseTransactionPlan {
    pub plan_id: String,
    pub release_id: String,
    pub exit_claim_id: String,
    pub decision: PlanDecision,
    pub inputs: Vec<PlannedInput>,
    pub payout_address_commitment: String,
    pub payout_amount_piconero: u64,
    pub amount_bucket_commitment: String,
    pub estimated_fee_piconero: u64,
    pub fee_cap_piconero: u64,
    pub change_amount_piconero: u64,
    pub change_commitment: String,
    pub confirmation_target: u64,
    pub decoy_set_size: u16,
    pub metadata_bytes: u64,
    pub release_receipt_root: String,
    pub hold_root: String,
    pub input_root: String,
    pub plan_root: String,
    pub broadcast_disabled: bool,
}

impl ReleaseTransactionPlan {
    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "release_id": self.release_id,
            "exit_claim_id": self.exit_claim_id,
            "decision": self.decision.as_str(),
            "inputs": self.inputs.iter().map(PlannedInput::public_record).collect::<Vec<_>>(),
            "payout_address_commitment": self.payout_address_commitment,
            "payout_amount_piconero": self.payout_amount_piconero,
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "estimated_fee_piconero": self.estimated_fee_piconero,
            "fee_cap_piconero": self.fee_cap_piconero,
            "change_amount_piconero": self.change_amount_piconero,
            "change_commitment": self.change_commitment,
            "confirmation_target": self.confirmation_target,
            "decoy_set_size": self.decoy_set_size,
            "metadata_bytes": self.metadata_bytes,
            "release_receipt_root": self.release_receipt_root,
            "hold_root": self.hold_root,
            "input_root": self.input_root,
            "plan_root": self.plan_root,
            "broadcast_disabled": self.broadcast_disabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub fee_policy: FeePolicy,
    pub custody_outputs: BTreeMap<String, CustodyOutput>,
    pub release_intents: BTreeMap<String, ReleaseIntent>,
    pub plans: BTreeMap<String, ReleaseTransactionPlan>,
    pub holds: BTreeMap<String, Vec<HoldReason>>,
}

impl State {
    pub fn new(config: Config, fee_policy: FeePolicy) -> Self {
        Self {
            config,
            fee_policy,
            custody_outputs: BTreeMap::new(),
            release_intents: BTreeMap::new(),
            plans: BTreeMap::new(),
            holds: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), FeePolicy::devnet());
        for output in devnet_outputs() {
            state
                .custody_outputs
                .insert(output.output_id.clone(), output);
        }
        for intent in devnet_release_intents() {
            state
                .release_intents
                .insert(intent.release_id.clone(), intent);
        }
        let release_ids = state.release_intents.keys().cloned().collect::<Vec<_>>();
        for release_id in release_ids {
            let _result = state.plan_release(&release_id);
        }
        state
    }

    pub fn add_custody_output(&mut self, output: CustodyOutput) -> Result<()> {
        if self.custody_outputs.contains_key(&output.output_id) {
            return Err(format!(
                "custody output already exists: {}",
                output.output_id
            ));
        }
        self.custody_outputs
            .insert(output.output_id.clone(), output);
        Ok(())
    }

    pub fn add_release_intent(&mut self, intent: ReleaseIntent) -> Result<()> {
        if self.release_intents.contains_key(&intent.release_id) {
            return Err(format!(
                "release intent already exists: {}",
                intent.release_id
            ));
        }
        self.release_intents
            .insert(intent.release_id.clone(), intent);
        Ok(())
    }

    pub fn plan_release(&mut self, release_id: &str) -> Result<ReleaseTransactionPlan> {
        let intent = match self.release_intents.get(release_id) {
            Some(intent) => intent.clone(),
            None => return Err(format!("unknown release intent: {release_id}")),
        };
        let (selected, holds) = self.select_inputs(&intent);
        let plan = self.build_plan(&intent, selected, &holds);
        self.holds
            .insert(intent.release_id.clone(), holds.iter().cloned().collect());
        self.plans.insert(intent.release_id.clone(), plan.clone());
        Ok(plan)
    }

    pub fn plan_all(&mut self) -> Result<Vec<ReleaseTransactionPlan>> {
        if self.release_intents.len() > self.config.max_releases {
            return Err(format!(
                "release intent count {} exceeds max {}",
                self.release_intents.len(),
                self.config.max_releases
            ));
        }
        let release_ids = self.release_intents.keys().cloned().collect::<Vec<_>>();
        let mut plans = Vec::with_capacity(release_ids.len());
        for release_id in release_ids {
            plans.push(self.plan_release(&release_id)?);
        }
        Ok(plans)
    }

    fn select_inputs(&self, intent: &ReleaseIntent) -> (Vec<CustodyOutput>, Vec<HoldReason>) {
        let mut holds = Vec::new();
        if !self.config.planning_enabled {
            holds.push(HoldReason::new(
                HoldReasonKind::PlanDisabled,
                &intent.release_id,
                "planning enabled",
                "planning disabled",
            ));
        }
        if intent.payout_address_commitment.is_empty() {
            holds.push(HoldReason::new(
                HoldReasonKind::PayoutCommitmentMissing,
                &intent.release_id,
                "non-empty payout address commitment",
                "empty",
            ));
        }
        if intent.confirmation_target < self.config.confirmation_target {
            holds.push(HoldReason::new(
                HoldReasonKind::ConfirmationTargetTooLow,
                &intent.release_id,
                format!("at least {}", self.config.confirmation_target),
                intent.confirmation_target.to_string(),
            ));
        }
        for (name, root) in &intent.required_receipt_roots {
            if root.is_empty() {
                holds.push(HoldReason::new(
                    HoldReasonKind::ReceiptRootMissing,
                    name,
                    "non-empty release receipt root",
                    "empty",
                ));
            }
        }

        let mut selected = Vec::new();
        let mut total = 0_u64;
        let mut expected = intent
            .expected_source_commitments
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        expected.sort();
        for output in self.custody_outputs.values() {
            if !expected.is_empty() && !expected.contains(&output.custody_commitment) {
                continue;
            }
            self.validate_output(intent, output, &mut holds);
            if output.status.selectable()
                && output.confirmations >= self.config.min_confirmations
                && output.decoy_set_size >= self.config.min_decoy_set_size
                && output.metadata_bytes <= self.config.max_metadata_bytes
            {
                selected.push(output.clone());
                total = total.saturating_add(output.amount_piconero);
            }
            if selected.len() >= self.config.max_inputs {
                break;
            }
            let estimated = self.estimate_for(intent, selected.len(), selected_metadata(&selected));
            if total >= intent.amount_piconero.saturating_add(estimated) {
                break;
            }
        }
        if selected.len() > self.config.max_inputs {
            holds.push(HoldReason::new(
                HoldReasonKind::TooManyInputs,
                &intent.release_id,
                format!("at most {}", self.config.max_inputs),
                selected.len().to_string(),
            ));
        }
        if !expected.is_empty() {
            let selected_commitments = selected
                .iter()
                .map(|output| output.custody_commitment.clone())
                .collect::<Vec<_>>();
            for commitment in expected {
                if !selected_commitments.contains(&commitment) {
                    holds.push(HoldReason::new(
                        HoldReasonKind::SourceCommitmentMismatch,
                        &intent.release_id,
                        commitment,
                        "not selected",
                    ));
                }
            }
        }
        (selected, holds)
    }

    fn validate_output(
        &self,
        intent: &ReleaseIntent,
        output: &CustodyOutput,
        holds: &mut Vec<HoldReason>,
    ) {
        match output.status {
            CustodyOutputStatus::Mature => {}
            CustodyOutputStatus::Pending => holds.push(HoldReason::new(
                HoldReasonKind::SourceNotMature,
                &output.output_id,
                format!("{} confirmations", self.config.min_confirmations),
                output.confirmations.to_string(),
            )),
            CustodyOutputStatus::Frozen => holds.push(HoldReason::new(
                HoldReasonKind::SourceFrozen,
                &output.output_id,
                "selectable custody output",
                output.status.as_str(),
            )),
            CustodyOutputStatus::Spent => holds.push(HoldReason::new(
                HoldReasonKind::SourceAlreadySpent,
                &output.output_id,
                "unspent custody output",
                output.status.as_str(),
            )),
        }
        if output.amount_bucket_commitment != intent.amount_bucket_commitment {
            holds.push(HoldReason::new(
                HoldReasonKind::AmountBucketMismatch,
                &output.output_id,
                &intent.amount_bucket_commitment,
                &output.amount_bucket_commitment,
            ));
        }
        if output.decoy_set_size < self.config.min_decoy_set_size {
            holds.push(HoldReason::new(
                HoldReasonKind::DecoySetTooSmall,
                &output.output_id,
                format!("at least {}", self.config.min_decoy_set_size),
                output.decoy_set_size.to_string(),
            ));
        }
        if output.metadata_bytes > self.config.max_metadata_bytes {
            holds.push(HoldReason::new(
                HoldReasonKind::MetadataTooLarge,
                &output.output_id,
                format!("at most {}", self.config.max_metadata_bytes),
                output.metadata_bytes.to_string(),
            ));
        }
    }

    fn estimate_for(&self, intent: &ReleaseIntent, input_count: usize, metadata_bytes: u64) -> u64 {
        let output_count = match intent.change_policy {
            ChangePolicy::AddToPayout | ChangePolicy::SweepOnly => 1,
            ChangePolicy::ReturnToCustody => 2,
        };
        self.fee_policy
            .estimate(input_count, output_count, metadata_bytes, intent.priority)
    }

    fn build_plan(
        &self,
        intent: &ReleaseIntent,
        selected: Vec<CustodyOutput>,
        initial_holds: &[HoldReason],
    ) -> ReleaseTransactionPlan {
        let mut holds = initial_holds.to_vec();
        let total_input = selected
            .iter()
            .map(|output| output.amount_piconero)
            .fold(0_u64, u64::saturating_add);
        let metadata_bytes = selected_metadata(&selected);
        let decoy_set_size = selected
            .iter()
            .map(|output| output.decoy_set_size)
            .min()
            .unwrap_or(0);
        let estimated_fee = self.estimate_for(intent, selected.len(), metadata_bytes);
        let fee_cap = intent.fee_cap_piconero.min(self.config.fee_cap_piconero);
        if estimated_fee > fee_cap {
            holds.push(HoldReason::new(
                HoldReasonKind::FeeCapExceeded,
                &intent.release_id,
                format!("fee at most {}", fee_cap),
                estimated_fee.to_string(),
            ));
        }
        let required = intent.amount_piconero.saturating_add(estimated_fee);
        if total_input < required {
            holds.push(HoldReason::new(
                HoldReasonKind::InsufficientCustodyValue,
                &intent.release_id,
                format!("at least {}", required),
                total_input.to_string(),
            ));
        }
        let change_amount = total_input.saturating_sub(required);
        if change_amount > 0 && change_amount < self.config.dust_threshold_piconero {
            holds.push(HoldReason::new(
                HoldReasonKind::ChangeBelowDust,
                &intent.release_id,
                format!("zero or at least {}", self.config.dust_threshold_piconero),
                change_amount.to_string(),
            ));
        }
        if intent.change_policy == ChangePolicy::SweepOnly && change_amount > 0 {
            holds.push(HoldReason::new(
                HoldReasonKind::SweepRequiresExactSpend,
                &intent.release_id,
                "zero change",
                change_amount.to_string(),
            ));
        }

        let decision = if holds.is_empty() {
            PlanDecision::Formable
        } else {
            PlanDecision::Held
        };
        let planned_inputs = selected
            .iter()
            .map(PlannedInput::from_output)
            .collect::<Vec<_>>();
        let input_root = merkle_root(
            "monero_release_transaction_plan:inputs",
            &planned_inputs
                .iter()
                .map(PlannedInput::public_record)
                .collect::<Vec<_>>(),
        );
        let hold_root = merkle_root(
            "monero_release_transaction_plan:holds",
            &holds
                .iter()
                .map(HoldReason::public_record)
                .collect::<Vec<_>>(),
        );
        let release_receipt_root = release_receipt_root(intent, &input_root, &hold_root);
        let change_commitment = change_commitment(intent, change_amount, &input_root);
        let plan_id = plan_id(
            intent,
            decision,
            &input_root,
            &hold_root,
            &release_receipt_root,
        );
        let plan_root = domain_hash(
            "monero_release_transaction_plan:plan_root",
            &[
                HashPart::Str(&plan_id),
                HashPart::Str(decision.as_str()),
                HashPart::Str(&input_root),
                HashPart::Str(&hold_root),
                HashPart::Str(&release_receipt_root),
                HashPart::U64(estimated_fee),
                HashPart::U64(change_amount),
            ],
            32,
        );

        ReleaseTransactionPlan {
            plan_id,
            release_id: intent.release_id.clone(),
            exit_claim_id: intent.exit_claim_id.clone(),
            decision,
            inputs: planned_inputs,
            payout_address_commitment: intent.payout_address_commitment.clone(),
            payout_amount_piconero: intent.amount_piconero,
            amount_bucket_commitment: intent.amount_bucket_commitment.clone(),
            estimated_fee_piconero: estimated_fee,
            fee_cap_piconero: fee_cap,
            change_amount_piconero: change_amount,
            change_commitment,
            confirmation_target: intent.confirmation_target,
            decoy_set_size,
            metadata_bytes,
            release_receipt_root,
            hold_root,
            input_root,
            plan_root,
            broadcast_disabled: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "fee_policy": self.fee_policy.public_record(),
            "custody_outputs": self.custody_outputs.values().map(CustodyOutput::public_record).collect::<Vec<_>>(),
            "release_intents": self.release_intents.values().map(ReleaseIntent::public_record).collect::<Vec<_>>(),
            "plans": self.plans.values().map(ReleaseTransactionPlan::public_record).collect::<Vec<_>>(),
            "holds": self.holds.iter().map(|(release_id, holds)| json!({
                "release_id": release_id,
                "holds": holds.iter().map(HoldReason::public_record).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }

    pub fn hold_summary(&self) -> BTreeMap<String, u64> {
        let mut summary = BTreeMap::new();
        for holds in self.holds.values() {
            for hold in holds {
                let key = hold.kind.as_str().to_string();
                let entry = summary.entry(key).or_insert(0);
                *entry += 1;
            }
        }
        summary
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero_release_transaction_plan:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn selected_metadata(outputs: &[CustodyOutput]) -> u64 {
    outputs
        .iter()
        .map(|output| output.metadata_bytes)
        .fold(0_u64, u64::saturating_add)
}

fn amount_bucket_commitment(label: &str, low: u64, high: u64) -> String {
    domain_hash(
        "monero_release_transaction_plan:amount_bucket",
        &[
            HashPart::Str(label),
            HashPart::U64(low),
            HashPart::U64(high),
            HashPart::Str(CHAIN_ID),
        ],
        32,
    )
}

fn custody_commitment(seed: &str, amount: u64, index: u64) -> String {
    domain_hash(
        "monero_release_transaction_plan:custody_commitment",
        &[
            HashPart::Str(seed),
            HashPart::U64(amount),
            HashPart::U64(index),
            HashPart::Str(CHAIN_ID),
        ],
        32,
    )
}

fn key_image_commitment(seed: &str, index: u64) -> String {
    domain_hash(
        "monero_release_transaction_plan:key_image_commitment",
        &[
            HashPart::Str(seed),
            HashPart::U64(index),
            HashPart::Str("key-image-not-revealed"),
        ],
        32,
    )
}

fn receipt_root(seed: &str, lane: &str) -> String {
    domain_hash(
        "monero_release_transaction_plan:receipt_root",
        &[
            HashPart::Str(seed),
            HashPart::Str(lane),
            HashPart::Str(CHAIN_ID),
        ],
        32,
    )
}

fn payout_commitment(seed: &str, release_index: u64) -> String {
    domain_hash(
        "monero_release_transaction_plan:payout_address",
        &[
            HashPart::Str(seed),
            HashPart::U64(release_index),
            HashPart::Str("subaddress-commitment"),
        ],
        32,
    )
}

fn release_receipt_root(intent: &ReleaseIntent, input_root: &str, hold_root: &str) -> String {
    let receipt_record = json!({
        "release_id": intent.release_id,
        "exit_claim_id": intent.exit_claim_id,
        "input_root": input_root,
        "hold_root": hold_root,
        "required_receipt_roots": intent.required_receipt_roots,
        "payout_address_commitment": intent.payout_address_commitment,
        "amount_bucket_commitment": intent.amount_bucket_commitment,
    });
    record_root("release_receipt", &receipt_record)
}

fn change_commitment(intent: &ReleaseIntent, change_amount: u64, input_root: &str) -> String {
    domain_hash(
        "monero_release_transaction_plan:change_commitment",
        &[
            HashPart::Str(&intent.release_id),
            HashPart::Str(intent.change_policy.as_str()),
            HashPart::U64(change_amount),
            HashPart::Str(input_root),
        ],
        32,
    )
}

fn plan_id(
    intent: &ReleaseIntent,
    decision: PlanDecision,
    input_root: &str,
    hold_root: &str,
    release_receipt_root: &str,
) -> String {
    domain_hash(
        "monero_release_transaction_plan:plan_id",
        &[
            HashPart::Str(&intent.release_id),
            HashPart::Str(&intent.exit_claim_id),
            HashPart::Str(decision.as_str()),
            HashPart::Str(input_root),
            HashPart::Str(hold_root),
            HashPart::Str(release_receipt_root),
        ],
        32,
    )
}

fn devnet_outputs() -> Vec<CustodyOutput> {
    let bucket_small =
        amount_bucket_commitment("release-bucket-small", 1_000_000_000, 8_000_000_000);
    let bucket_medium =
        amount_bucket_commitment("release-bucket-medium", 8_000_000_001, 20_000_000_000);
    vec![
        CustodyOutput::new(
            "custody-output-devnet-001",
            custody_commitment("custody-a", 7_500_000_000, 1),
            key_image_commitment("custody-a", 1),
            7_500_000_000,
            bucket_small.clone(),
            42,
            CustodyOutputStatus::Mature,
            18,
            64,
            receipt_root("custody-a", "deposit-lock"),
        ),
        CustodyOutput::new(
            "custody-output-devnet-002",
            custody_commitment("custody-b", 6_900_000_000, 2),
            key_image_commitment("custody-b", 2),
            6_900_000_000,
            bucket_small,
            36,
            CustodyOutputStatus::Mature,
            20,
            64,
            receipt_root("custody-b", "private-note"),
        ),
        CustodyOutput::new(
            "custody-output-devnet-003",
            custody_commitment("custody-c", 11_000_000_000, 3),
            key_image_commitment("custody-c", 3),
            11_000_000_000,
            bucket_medium.clone(),
            9,
            CustodyOutputStatus::Pending,
            18,
            64,
            receipt_root("custody-c", "deposit-lock"),
        ),
        CustodyOutput::new(
            "custody-output-devnet-004",
            custody_commitment("custody-d", 10_400_000_000, 4),
            key_image_commitment("custody-d", 4),
            10_400_000_000,
            bucket_medium,
            64,
            CustodyOutputStatus::Frozen,
            14,
            192,
            receipt_root("custody-d", "operator-hold"),
        ),
    ]
}

fn devnet_release_intents() -> Vec<ReleaseIntent> {
    let mut roots_a = BTreeMap::new();
    roots_a.insert(
        "withdrawal_claim".to_string(),
        receipt_root("release-a", "withdrawal-claim"),
    );
    roots_a.insert(
        "pq_authority".to_string(),
        receipt_root("release-a", "pq-authority"),
    );
    let mut roots_b = BTreeMap::new();
    roots_b.insert(
        "withdrawal_claim".to_string(),
        receipt_root("release-b", "withdrawal-claim"),
    );
    roots_b.insert("settlement".to_string(), String::new());
    let bucket_small =
        amount_bucket_commitment("release-bucket-small", 1_000_000_000, 8_000_000_000);
    let bucket_medium =
        amount_bucket_commitment("release-bucket-medium", 8_000_000_001, 20_000_000_000);
    vec![
        ReleaseIntent::new(
            "release-intent-devnet-001",
            "exit-claim-devnet-001",
            payout_commitment("release-a", 1),
            12_000_000_000,
            bucket_small,
            18_000_000,
            ChangePolicy::ReturnToCustody,
            ReleasePriority::Normal,
            DEFAULT_CONFIRMATION_TARGET,
            roots_a,
            vec![],
        ),
        ReleaseIntent::new(
            "release-intent-devnet-002",
            "exit-claim-devnet-002",
            payout_commitment("release-b", 2),
            10_000_000_000,
            bucket_medium,
            9_000_000,
            ChangePolicy::SweepOnly,
            ReleasePriority::High,
            18,
            roots_b,
            vec![custody_commitment("custody-c", 11_000_000_000, 3)],
        ),
    ]
}
