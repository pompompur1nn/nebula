use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialReleaseInstructionRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_RELEASE_INSTRUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-release-instruction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_RELEASE_INSTRUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_INSTRUCTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-adversarial-release-instruction-v1";
pub const DEFAULT_L2_HEIGHT: u64 = 912_480;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_512_064;
pub const DEFAULT_MIN_CUSTODY_WEIGHT: u64 = 67;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 67;
pub const DEFAULT_MONERO_REORG_HOLD_BLOCKS: u64 = 20;
pub const DEFAULT_PRIVACY_METADATA_BUDGET_BITS: u64 = 6;
pub const DEFAULT_RESERVE_FLOOR_PICONERO: u64 = 15_000_000_000_000;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-release-instruction-runtime";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseFailureKind {
    AcceptedExitWithStaleWalletBundle,
    BadCustodyAuthorization,
    TransactionPlanRootMismatch,
    LiquidityShortfall,
    OpenChallenge,
    ReorgSensitiveDepositEvidence,
    ReplayedClaim,
    PrivacyMetadataBreach,
    WatcherCollusion,
}

impl ReleaseFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedExitWithStaleWalletBundle => "accepted_exit_with_stale_wallet_bundle",
            Self::BadCustodyAuthorization => "bad_custody_authorization",
            Self::TransactionPlanRootMismatch => "transaction_plan_root_mismatch",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::OpenChallenge => "open_challenge",
            Self::ReorgSensitiveDepositEvidence => "reorg_sensitive_deposit_evidence",
            Self::ReplayedClaim => "replayed_claim",
            Self::PrivacyMetadataBreach => "privacy_metadata_breach",
            Self::WatcherCollusion => "watcher_collusion",
        }
    }

    pub fn rank(self) -> u64 {
        match self {
            Self::AcceptedExitWithStaleWalletBundle => 1,
            Self::BadCustodyAuthorization => 2,
            Self::TransactionPlanRootMismatch => 3,
            Self::LiquidityShortfall => 4,
            Self::OpenChallenge => 5,
            Self::ReorgSensitiveDepositEvidence => 6,
            Self::ReplayedClaim => 7,
            Self::PrivacyMetadataBreach => 8,
            Self::WatcherCollusion => 9,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardVerdict {
    Pass,
    FailClosed,
    Quarantine,
}

impl GuardVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::FailClosed => "fail_closed",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDisposition {
    ReleasePermitted,
    ReleaseDenied,
    EvidenceQuarantined,
    OperatorActionRequired,
}

impl ReleaseDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleasePermitted => "release_permitted",
            Self::ReleaseDenied => "release_denied",
            Self::EvidenceQuarantined => "evidence_quarantined",
            Self::OperatorActionRequired => "operator_action_required",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub release_instruction_suite: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_custody_weight: u64,
    pub min_watcher_weight: u64,
    pub monero_reorg_hold_blocks: u64,
    pub privacy_metadata_budget_bits: u64,
    pub reserve_floor_piconero: u64,
    pub fail_closed_default: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            release_instruction_suite: RELEASE_INSTRUCTION_SUITE.to_string(),
            l2_height: DEFAULT_L2_HEIGHT,
            monero_height: DEFAULT_MONERO_HEIGHT,
            min_custody_weight: DEFAULT_MIN_CUSTODY_WEIGHT,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            monero_reorg_hold_blocks: DEFAULT_MONERO_REORG_HOLD_BLOCKS,
            privacy_metadata_budget_bits: DEFAULT_PRIVACY_METADATA_BUDGET_BITS,
            reserve_floor_piconero: DEFAULT_RESERVE_FLOOR_PICONERO,
            fail_closed_default: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "release_instruction_suite": self.release_instruction_suite,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "min_custody_weight": self.min_custody_weight,
            "min_watcher_weight": self.min_watcher_weight,
            "monero_reorg_hold_blocks": self.monero_reorg_hold_blocks,
            "privacy_metadata_budget_bits": self.privacy_metadata_budget_bits,
            "reserve_floor_piconero": self.reserve_floor_piconero,
            "fail_closed_default": self.fail_closed_default,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseInstructionCase {
    pub case_id: String,
    pub failure_kind: ReleaseFailureKind,
    pub claim_id: String,
    pub wallet_bundle_id: String,
    pub custody_authorization_id: String,
    pub transaction_plan_root: String,
    pub expected_transaction_plan_root: String,
    pub deposit_anchor_id: String,
    pub claim_amount_piconero: u64,
    pub available_liquidity_piconero: u64,
    pub wallet_bundle_epoch: u64,
    pub canonical_wallet_epoch: u64,
    pub custody_weight: u64,
    pub deposit_confirmations: u64,
    pub open_challenge_count: u64,
    pub prior_nullifier_uses: u64,
    pub metadata_budget_bits: u64,
    pub honest_watcher_weight: u64,
    pub summary: String,
    pub blocked_hazard: String,
    pub evidence_refs: Vec<String>,
    pub case_root: String,
}

impl ReleaseInstructionCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        failure_kind: ReleaseFailureKind,
        claim_id: impl Into<String>,
        wallet_bundle_id: impl Into<String>,
        custody_authorization_id: impl Into<String>,
        transaction_plan_root: impl Into<String>,
        deposit_anchor_id: impl Into<String>,
        claim_amount_piconero: u64,
        available_liquidity_piconero: u64,
        wallet_bundle_epoch: u64,
        canonical_wallet_epoch: u64,
        custody_weight: u64,
        deposit_confirmations: u64,
        open_challenge_count: u64,
        prior_nullifier_uses: u64,
        metadata_budget_bits: u64,
        honest_watcher_weight: u64,
        summary: impl Into<String>,
        blocked_hazard: impl Into<String>,
    ) -> Self {
        let claim_id = claim_id.into();
        let wallet_bundle_id = wallet_bundle_id.into();
        let custody_authorization_id = custody_authorization_id.into();
        let transaction_plan_root = transaction_plan_root.into();
        let expected_transaction_plan_root = if matches!(
            failure_kind,
            ReleaseFailureKind::TransactionPlanRootMismatch
        ) {
            format!("{transaction_plan_root}-canonical")
        } else {
            transaction_plan_root.clone()
        };
        let deposit_anchor_id = deposit_anchor_id.into();
        let summary = summary.into();
        let blocked_hazard = blocked_hazard.into();
        let case_id = case_identifier(failure_kind, &claim_id);
        let evidence_refs = vec![
            format!("claim:{claim_id}"),
            format!("wallet:{wallet_bundle_id}"),
            format!("custody:{custody_authorization_id}"),
            format!("deposit:{deposit_anchor_id}"),
        ];
        let case_root = case_commitment(
            failure_kind,
            &claim_id,
            &wallet_bundle_id,
            &custody_authorization_id,
            &transaction_plan_root,
            &expected_transaction_plan_root,
            &deposit_anchor_id,
            claim_amount_piconero,
            available_liquidity_piconero,
            wallet_bundle_epoch,
            canonical_wallet_epoch,
            custody_weight,
            deposit_confirmations,
            open_challenge_count,
            prior_nullifier_uses,
            metadata_budget_bits,
            honest_watcher_weight,
        );

        Self {
            case_id,
            failure_kind,
            claim_id,
            wallet_bundle_id,
            custody_authorization_id,
            transaction_plan_root,
            expected_transaction_plan_root,
            deposit_anchor_id,
            claim_amount_piconero,
            available_liquidity_piconero,
            wallet_bundle_epoch,
            canonical_wallet_epoch,
            custody_weight,
            deposit_confirmations,
            open_challenge_count,
            prior_nullifier_uses,
            metadata_budget_bits,
            honest_watcher_weight,
            summary,
            blocked_hazard,
            evidence_refs,
            case_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "failure_kind": self.failure_kind.as_str(),
            "claim_id": self.claim_id,
            "wallet_bundle_id": self.wallet_bundle_id,
            "custody_authorization_id": self.custody_authorization_id,
            "transaction_plan_root": self.transaction_plan_root,
            "expected_transaction_plan_root": self.expected_transaction_plan_root,
            "deposit_anchor_id": self.deposit_anchor_id,
            "claim_amount_piconero": self.claim_amount_piconero,
            "available_liquidity_piconero": self.available_liquidity_piconero,
            "wallet_bundle_epoch": self.wallet_bundle_epoch,
            "canonical_wallet_epoch": self.canonical_wallet_epoch,
            "custody_weight": self.custody_weight,
            "deposit_confirmations": self.deposit_confirmations,
            "open_challenge_count": self.open_challenge_count,
            "prior_nullifier_uses": self.prior_nullifier_uses,
            "metadata_budget_bits": self.metadata_budget_bits,
            "honest_watcher_weight": self.honest_watcher_weight,
            "summary": self.summary,
            "blocked_hazard": self.blocked_hazard,
            "evidence_refs": self.evidence_refs,
            "case_root": self.case_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuardEvaluation {
    pub case_id: String,
    pub failure_kind: ReleaseFailureKind,
    pub guard_name: String,
    pub verdict: GuardVerdict,
    pub disposition: ReleaseDisposition,
    pub denied_release: bool,
    pub quarantine_evidence: bool,
    pub operator_action_required: bool,
    pub reason: String,
    pub remediation: String,
    pub evidence_root: String,
    pub evaluation_root: String,
}

impl GuardEvaluation {
    pub fn from_case(config: &Config, case: &ReleaseInstructionCase) -> Self {
        let (
            verdict,
            disposition,
            quarantine_evidence,
            operator_action_required,
            reason,
            remediation,
        ) = guard_outcome(config, case);
        let denied_release = !matches!(disposition, ReleaseDisposition::ReleasePermitted);
        let evidence_root = merkle_root(
            &format!("{DOMAIN}:case-evidence"),
            &case
                .evidence_refs
                .iter()
                .map(|evidence_ref| json!({ "evidence_ref": evidence_ref }))
                .collect::<Vec<_>>(),
        );
        let evaluation_root = evaluation_commitment(
            config,
            case,
            verdict,
            disposition,
            denied_release,
            quarantine_evidence,
            operator_action_required,
            &reason,
            &remediation,
            &evidence_root,
        );

        Self {
            case_id: case.case_id.clone(),
            failure_kind: case.failure_kind,
            guard_name: guard_name(case.failure_kind).to_string(),
            verdict,
            disposition,
            denied_release,
            quarantine_evidence,
            operator_action_required,
            reason,
            remediation,
            evidence_root,
            evaluation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "failure_kind": self.failure_kind.as_str(),
            "guard_name": self.guard_name,
            "verdict": self.verdict.as_str(),
            "disposition": self.disposition.as_str(),
            "denied_release": self.denied_release,
            "quarantine_evidence": self.quarantine_evidence,
            "operator_action_required": self.operator_action_required,
            "reason": self.reason,
            "remediation": self.remediation,
            "evidence_root": self.evidence_root,
            "evaluation_root": self.evaluation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseInstructionSummary {
    pub total_cases: u64,
    pub denied_cases: u64,
    pub quarantined_cases: u64,
    pub operator_action_cases: u64,
    pub permitted_cases: u64,
    pub fail_closed_cases: u64,
    pub all_negative_cases_denied: bool,
    pub production_release_allowed: bool,
    pub summary_root: String,
}

impl ReleaseInstructionSummary {
    pub fn from_evaluations(config: &Config, evaluations: &[GuardEvaluation]) -> Self {
        let total_cases = evaluations.len() as u64;
        let denied_cases = evaluations
            .iter()
            .filter(|item| item.denied_release)
            .count() as u64;
        let quarantined_cases = evaluations
            .iter()
            .filter(|item| item.quarantine_evidence)
            .count() as u64;
        let operator_action_cases = evaluations
            .iter()
            .filter(|item| item.operator_action_required)
            .count() as u64;
        let permitted_cases = evaluations
            .iter()
            .filter(|item| matches!(item.disposition, ReleaseDisposition::ReleasePermitted))
            .count() as u64;
        let fail_closed_cases = evaluations
            .iter()
            .filter(|item| {
                matches!(
                    item.verdict,
                    GuardVerdict::FailClosed | GuardVerdict::Quarantine
                )
            })
            .count() as u64;
        let all_negative_cases_denied = total_cases > 0 && denied_cases == total_cases;
        let production_release_allowed =
            config.production_release_allowed && permitted_cases == total_cases;
        let summary_root = domain_hash(
            &format!("{DOMAIN}:summary-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(total_cases),
                HashPart::U64(denied_cases),
                HashPart::U64(quarantined_cases),
                HashPart::U64(operator_action_cases),
                HashPart::U64(permitted_cases),
                HashPart::U64(fail_closed_cases),
                HashPart::Str(if all_negative_cases_denied {
                    "yes"
                } else {
                    "no"
                }),
                HashPart::Str(if production_release_allowed {
                    "yes"
                } else {
                    "no"
                }),
            ],
            32,
        );
        Self {
            total_cases,
            denied_cases,
            quarantined_cases,
            operator_action_cases,
            permitted_cases,
            fail_closed_cases,
            all_negative_cases_denied,
            production_release_allowed,
            summary_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_cases": self.total_cases,
            "denied_cases": self.denied_cases,
            "quarantined_cases": self.quarantined_cases,
            "operator_action_cases": self.operator_action_cases,
            "permitted_cases": self.permitted_cases,
            "fail_closed_cases": self.fail_closed_cases,
            "all_negative_cases_denied": self.all_negative_cases_denied,
            "production_release_allowed": self.production_release_allowed,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub release_epoch: u64,
    pub l2_batch_id: String,
    pub monero_anchor_height: u64,
    pub cases: Vec<ReleaseInstructionCase>,
    pub evaluations: Vec<GuardEvaluation>,
    pub summary: ReleaseInstructionSummary,
    pub case_index: BTreeMap<String, String>,
    pub failure_index: BTreeMap<String, Vec<String>>,
    pub case_root: String,
    pub evaluation_root: String,
    pub instruction_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let runtime_id = runtime_id();
        let release_epoch = 77;
        let l2_batch_id = "adversarial-release-instruction-devnet-77".to_string();
        let monero_anchor_height = DEFAULT_MONERO_HEIGHT - 13;
        let cases = devnet_cases();
        let evaluations = cases
            .iter()
            .map(|case| GuardEvaluation::from_case(&config, case))
            .collect::<Vec<_>>();
        let summary = ReleaseInstructionSummary::from_evaluations(&config, &evaluations);
        let case_index = build_case_index(&cases);
        let failure_index = build_failure_index(&cases);
        let case_records = cases
            .iter()
            .map(ReleaseInstructionCase::public_record)
            .collect::<Vec<_>>();
        let evaluation_records = evaluations
            .iter()
            .map(GuardEvaluation::public_record)
            .collect::<Vec<_>>();
        let case_root = merkle_root(&format!("{DOMAIN}:cases"), &case_records);
        let evaluation_root = merkle_root(&format!("{DOMAIN}:evaluations"), &evaluation_records);
        let instruction_root = domain_hash(
            &format!("{DOMAIN}:instruction-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&runtime_id),
                HashPart::U64(release_epoch),
                HashPart::Str(&l2_batch_id),
                HashPart::U64(monero_anchor_height),
                HashPart::Str(&case_root),
                HashPart::Str(&evaluation_root),
                HashPart::Str(&summary.summary_root),
            ],
            32,
        );

        Self {
            config,
            runtime_id,
            release_epoch,
            l2_batch_id,
            monero_anchor_height,
            cases,
            evaluations,
            summary,
            case_index,
            failure_index,
            case_root,
            evaluation_root,
            instruction_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let case_records = self
            .cases
            .iter()
            .map(ReleaseInstructionCase::public_record)
            .collect::<Vec<_>>();
        let evaluation_records = self
            .evaluations
            .iter()
            .map(GuardEvaluation::public_record)
            .collect::<Vec<_>>();
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_release_instruction_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "release_instruction_suite": RELEASE_INSTRUCTION_SUITE,
            "runtime_id": self.runtime_id,
            "release_epoch": self.release_epoch,
            "l2_batch_id": self.l2_batch_id,
            "monero_anchor_height": self.monero_anchor_height,
            "config": self.config.public_record(),
            "cases": case_records,
            "evaluations": evaluation_records,
            "summary": self.summary.public_record(),
            "case_index": self.case_index,
            "failure_index": self.failure_index,
            "case_root": self.case_root,
            "evaluation_root": self.evaluation_root,
            "instruction_root": self.instruction_root,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let config_record = self.config.public_record();
        let summary_record = self.summary.public_record();
        domain_hash(
            &format!("{DOMAIN}:state-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::Json(&config_record),
                HashPart::Str(&self.runtime_id),
                HashPart::U64(self.release_epoch),
                HashPart::Str(&self.l2_batch_id),
                HashPart::U64(self.monero_anchor_height),
                HashPart::Str(&self.case_root),
                HashPart::Str(&self.evaluation_root),
                HashPart::Str(&self.instruction_root),
                HashPart::Json(&summary_record),
            ],
            32,
        )
    }

    pub fn evaluate_claim(&self, claim_id: &str) -> Result<&GuardEvaluation> {
        let case_id = match self.case_index.get(claim_id) {
            Some(value) => value,
            None => {
                return Err(format!(
                    "claim {claim_id} is absent from adversarial release instruction runtime"
                ))
            }
        };
        match self
            .evaluations
            .iter()
            .find(|item| &item.case_id == case_id)
        {
            Some(value) => Ok(value),
            None => Err(format!("claim {claim_id} has no guard evaluation")),
        }
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

fn devnet_cases() -> Vec<ReleaseInstructionCase> {
    vec![
        ReleaseInstructionCase::new(
            ReleaseFailureKind::AcceptedExitWithStaleWalletBundle,
            "release-claim-01",
            "wallet-bundle-122",
            "custody-auth-01",
            "tx-plan-root-01",
            "deposit-anchor-01",
            21_000_000_000_000,
            42_000_000_000_000,
            122,
            124,
            72,
            28,
            0,
            0,
            4,
            74,
            "accepted exit references a wallet bundle older than canonical user state",
            "release would spend against a superseded note view",
        ),
        ReleaseInstructionCase::new(
            ReleaseFailureKind::BadCustodyAuthorization,
            "release-claim-02",
            "wallet-bundle-126",
            "custody-auth-02",
            "tx-plan-root-02",
            "deposit-anchor-02",
            24_000_000_000_000,
            44_000_000_000_000,
            126,
            126,
            41,
            27,
            0,
            0,
            5,
            73,
            "custody signer set omits the active threshold key and includes a revoked delegate",
            "release would bypass current vault policy",
        ),
        ReleaseInstructionCase::new(
            ReleaseFailureKind::TransactionPlanRootMismatch,
            "release-claim-03",
            "wallet-bundle-127",
            "custody-auth-03",
            "tx-plan-root-03",
            "deposit-anchor-03",
            26_000_000_000_000,
            45_000_000_000_000,
            127,
            127,
            70,
            26,
            0,
            0,
            5,
            72,
            "release instruction carries a transaction plan root different from the admitted planner root",
            "watchers cannot bind execution to the reviewed transaction plan",
        ),
        ReleaseInstructionCase::new(
            ReleaseFailureKind::LiquidityShortfall,
            "release-claim-04",
            "wallet-bundle-128",
            "custody-auth-04",
            "tx-plan-root-04",
            "deposit-anchor-04",
            27_000_000_000_000,
            12_800_000_000_000,
            128,
            128,
            70,
            25,
            0,
            0,
            5,
            72,
            "available bridge reserve is below the claim amount plus reserve floor",
            "partial release would strand remaining exits",
        ),
        ReleaseInstructionCase::new(
            ReleaseFailureKind::OpenChallenge,
            "release-claim-05",
            "wallet-bundle-129",
            "custody-auth-05",
            "tx-plan-root-05",
            "deposit-anchor-05",
            18_000_000_000_000,
            40_000_000_000_000,
            129,
            129,
            70,
            24,
            1,
            0,
            4,
            71,
            "a live challenge remains inside the dispute window for the release claim",
            "release could finalize before dispute evidence lands",
        ),
        ReleaseInstructionCase::new(
            ReleaseFailureKind::ReorgSensitiveDepositEvidence,
            "release-claim-06",
            "wallet-bundle-130",
            "custody-auth-06",
            "tx-plan-root-06",
            "deposit-anchor-06",
            19_000_000_000_000,
            41_000_000_000_000,
            130,
            130,
            70,
            13,
            0,
            0,
            4,
            70,
            "deposit anchor depth is below the configured Monero reorg hold window",
            "release could depend on a deposit anchor that later disappears",
        ),
        ReleaseInstructionCase::new(
            ReleaseFailureKind::ReplayedClaim,
            "release-claim-07",
            "wallet-bundle-131",
            "custody-auth-07",
            "tx-plan-root-07",
            "deposit-anchor-07",
            20_000_000_000_000,
            43_000_000_000_000,
            131,
            131,
            70,
            23,
            0,
            1,
            5,
            69,
            "claim nullifier was already seen in a prior exit release lane",
            "same private claim could be released twice",
        ),
        ReleaseInstructionCase::new(
            ReleaseFailureKind::PrivacyMetadataBreach,
            "release-claim-08",
            "wallet-bundle-132",
            "custody-auth-08",
            "tx-plan-root-08",
            "deposit-anchor-08",
            22_000_000_000_000,
            44_000_000_000_000,
            132,
            132,
            70,
            22,
            0,
            0,
            11,
            68,
            "release metadata discloses batch shape and wallet timing beyond privacy budget",
            "public release trail could link wallet and Monero output",
        ),
        ReleaseInstructionCase::new(
            ReleaseFailureKind::WatcherCollusion,
            "release-claim-09",
            "wallet-bundle-133",
            "custody-auth-09",
            "tx-plan-root-09",
            "deposit-anchor-09",
            23_000_000_000_000,
            45_000_000_000_000,
            133,
            133,
            70,
            21,
            0,
            0,
            5,
            52,
            "watcher quorum contains equivocation pairs and shared custody operator lineage",
            "colluding watchers could approve a fabricated release view",
        ),
    ]
}

fn guard_outcome(
    config: &Config,
    case: &ReleaseInstructionCase,
) -> (GuardVerdict, ReleaseDisposition, bool, bool, String, String) {
    match case.failure_kind {
        ReleaseFailureKind::AcceptedExitWithStaleWalletBundle => (
            GuardVerdict::FailClosed,
            ReleaseDisposition::ReleaseDenied,
            false,
            true,
            "wallet bundle epoch trails canonical wallet state".to_string(),
            "require a fresh wallet bundle proof before release instruction admission".to_string(),
        ),
        ReleaseFailureKind::BadCustodyAuthorization => (
            GuardVerdict::FailClosed,
            ReleaseDisposition::ReleaseDenied,
            false,
            true,
            format!(
                "custody authorization weight {} is below threshold {}",
                case.custody_weight, config.min_custody_weight
            ),
            "refresh custody authorization under current policy and revoked-key map".to_string(),
        ),
        ReleaseFailureKind::TransactionPlanRootMismatch => (
            GuardVerdict::FailClosed,
            ReleaseDisposition::EvidenceQuarantined,
            true,
            true,
            "transaction plan root differs from canonical planner commitment".to_string(),
            "quarantine plan transcript and rebuild release from admitted root".to_string(),
        ),
        ReleaseFailureKind::LiquidityShortfall => (
            GuardVerdict::FailClosed,
            ReleaseDisposition::OperatorActionRequired,
            false,
            true,
            "available liquidity does not satisfy claim amount plus reserve floor".to_string(),
            "defer release until reserve proof covers claim and floor".to_string(),
        ),
        ReleaseFailureKind::OpenChallenge => (
            GuardVerdict::FailClosed,
            ReleaseDisposition::ReleaseDenied,
            true,
            false,
            "challenge remains open for the release claim".to_string(),
            "wait for challenge resolution and bind disposition into release proof".to_string(),
        ),
        ReleaseFailureKind::ReorgSensitiveDepositEvidence => (
            GuardVerdict::Quarantine,
            ReleaseDisposition::EvidenceQuarantined,
            true,
            false,
            "deposit evidence has not cleared Monero reorg hold window".to_string(),
            "hold release until anchor depth reaches configured confirmation floor".to_string(),
        ),
        ReleaseFailureKind::ReplayedClaim => (
            GuardVerdict::FailClosed,
            ReleaseDisposition::EvidenceQuarantined,
            true,
            true,
            "claim nullifier already appears in release history".to_string(),
            "reject replay and publish duplicate-nullifier evidence bundle".to_string(),
        ),
        ReleaseFailureKind::PrivacyMetadataBreach => (
            GuardVerdict::FailClosed,
            ReleaseDisposition::ReleaseDenied,
            true,
            false,
            "release metadata exceeds configured privacy budget".to_string(),
            "pad batch shape and reissue release instruction under budget".to_string(),
        ),
        ReleaseFailureKind::WatcherCollusion => (
            GuardVerdict::FailClosed,
            ReleaseDisposition::OperatorActionRequired,
            true,
            true,
            format!(
                "honest watcher weight {} is below quorum {}",
                case.honest_watcher_weight, config.min_watcher_weight
            ),
            "remove equivocation weight and request independent watcher quorum".to_string(),
        ),
    }
}

fn build_case_index(cases: &[ReleaseInstructionCase]) -> BTreeMap<String, String> {
    cases
        .iter()
        .map(|case| (case.claim_id.clone(), case.case_id.clone()))
        .collect()
}

fn build_failure_index(cases: &[ReleaseInstructionCase]) -> BTreeMap<String, Vec<String>> {
    let mut index = BTreeMap::<String, Vec<String>>::new();
    for case in cases {
        index
            .entry(case.failure_kind.as_str().to_string())
            .or_default()
            .push(case.case_id.clone());
    }
    index
}

fn guard_name(kind: ReleaseFailureKind) -> &'static str {
    match kind {
        ReleaseFailureKind::AcceptedExitWithStaleWalletBundle => "wallet_bundle_freshness_guard",
        ReleaseFailureKind::BadCustodyAuthorization => "custody_authorization_guard",
        ReleaseFailureKind::TransactionPlanRootMismatch => "transaction_plan_root_guard",
        ReleaseFailureKind::LiquidityShortfall => "liquidity_floor_guard",
        ReleaseFailureKind::OpenChallenge => "challenge_window_guard",
        ReleaseFailureKind::ReorgSensitiveDepositEvidence => "monero_reorg_hold_guard",
        ReleaseFailureKind::ReplayedClaim => "claim_replay_guard",
        ReleaseFailureKind::PrivacyMetadataBreach => "privacy_metadata_budget_guard",
        ReleaseFailureKind::WatcherCollusion => "watcher_collusion_guard",
    }
}

fn runtime_id() -> String {
    domain_hash(
        &format!("{DOMAIN}:runtime-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(SCHEMA_VERSION),
        ],
        16,
    )
}

fn case_identifier(kind: ReleaseFailureKind, claim_id: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:case-id"),
        &[HashPart::Str(kind.as_str()), HashPart::Str(claim_id)],
        12,
    )
}

#[allow(clippy::too_many_arguments)]
fn case_commitment(
    kind: ReleaseFailureKind,
    claim_id: &str,
    wallet_bundle_id: &str,
    custody_authorization_id: &str,
    transaction_plan_root: &str,
    expected_transaction_plan_root: &str,
    deposit_anchor_id: &str,
    claim_amount_piconero: u64,
    available_liquidity_piconero: u64,
    wallet_bundle_epoch: u64,
    canonical_wallet_epoch: u64,
    custody_weight: u64,
    deposit_confirmations: u64,
    open_challenge_count: u64,
    prior_nullifier_uses: u64,
    metadata_budget_bits: u64,
    honest_watcher_weight: u64,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:case-root"),
        &[
            HashPart::Str(kind.as_str()),
            HashPart::U64(kind.rank()),
            HashPart::Str(claim_id),
            HashPart::Str(wallet_bundle_id),
            HashPart::Str(custody_authorization_id),
            HashPart::Str(transaction_plan_root),
            HashPart::Str(expected_transaction_plan_root),
            HashPart::Str(deposit_anchor_id),
            HashPart::U64(claim_amount_piconero),
            HashPart::U64(available_liquidity_piconero),
            HashPart::U64(wallet_bundle_epoch),
            HashPart::U64(canonical_wallet_epoch),
            HashPart::U64(custody_weight),
            HashPart::U64(deposit_confirmations),
            HashPart::U64(open_challenge_count),
            HashPart::U64(prior_nullifier_uses),
            HashPart::U64(metadata_budget_bits),
            HashPart::U64(honest_watcher_weight),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluation_commitment(
    config: &Config,
    case: &ReleaseInstructionCase,
    verdict: GuardVerdict,
    disposition: ReleaseDisposition,
    denied_release: bool,
    quarantine_evidence: bool,
    operator_action_required: bool,
    reason: &str,
    remediation: &str,
    evidence_root: &str,
) -> String {
    let config_record = config.public_record();
    domain_hash(
        &format!("{DOMAIN}:evaluation-root"),
        &[
            HashPart::Json(&config_record),
            HashPart::Str(&case.case_id),
            HashPart::Str(case.failure_kind.as_str()),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(disposition.as_str()),
            HashPart::Str(if denied_release { "yes" } else { "no" }),
            HashPart::Str(if quarantine_evidence { "yes" } else { "no" }),
            HashPart::Str(if operator_action_required {
                "yes"
            } else {
                "no"
            }),
            HashPart::Str(reason),
            HashPart::Str(remediation),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(&format!("{DOMAIN}:{label}"), &[HashPart::Json(record)], 32)
}
