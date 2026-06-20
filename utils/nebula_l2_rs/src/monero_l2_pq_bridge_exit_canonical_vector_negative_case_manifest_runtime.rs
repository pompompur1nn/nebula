use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVectorNegativeCaseManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VECTOR_NEGATIVE_CASE_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vector-negative-case-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VECTOR_NEGATIVE_CASE_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const NEGATIVE_CASE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vector-negative-case-manifest-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_517_200;
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_246_100;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_PQ_SIGNER_EPOCH: u64 = 9;
pub const DEFAULT_REQUIRED_QUORUM_WEIGHT: u64 = 7;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_MAX_EXIT_FEE_BPS: u64 = 35;
pub const DEFAULT_PRIVACY_BUDGET_BITS: u64 = 20;
pub const DEFAULT_MIN_RECONSTRUCTABLE_WALLET_SHARDS: u64 = 3;
pub const DEFAULT_REQUIRED_WALLET_SHARDS: u64 = 5;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NegativeCaseKind {
    ShallowMoneroFinality,
    ReorgedDepositLock,
    StalePqSignerEpoch,
    WeakQuorum,
    BrokenNoteToReceiptLinkage,
    MismatchedSettlementExitClaim,
    PrematureRelease,
    InvalidChallenge,
    NonReconstructableWalletEvidence,
    ExcessiveFee,
    PrivacyBudgetLeak,
    SimulatedProductionRelease,
}

impl NegativeCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShallowMoneroFinality => "shallow_monero_finality",
            Self::ReorgedDepositLock => "reorged_deposit_lock",
            Self::StalePqSignerEpoch => "stale_pq_signer_epoch",
            Self::WeakQuorum => "weak_quorum",
            Self::BrokenNoteToReceiptLinkage => "broken_note_to_receipt_linkage",
            Self::MismatchedSettlementExitClaim => "mismatched_settlement_exit_claim",
            Self::PrematureRelease => "premature_release",
            Self::InvalidChallenge => "invalid_challenge",
            Self::NonReconstructableWalletEvidence => "non_reconstructable_wallet_evidence",
            Self::ExcessiveFee => "excessive_fee",
            Self::PrivacyBudgetLeak => "privacy_budget_leak",
            Self::SimulatedProductionRelease => "simulated_production_release",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ShallowMoneroFinality => "reject when Monero depth is below canonical finality",
            Self::ReorgedDepositLock => "reject when deposit lock is on a reorged branch",
            Self::StalePqSignerEpoch => "reject when PQ signer epoch is stale",
            Self::WeakQuorum => "reject when watcher quorum weight is insufficient",
            Self::BrokenNoteToReceiptLinkage => "reject when note and receipt roots do not link",
            Self::MismatchedSettlementExitClaim => {
                "reject when settlement and exit claim roots disagree"
            }
            Self::PrematureRelease => "reject when release delay has not elapsed",
            Self::InvalidChallenge => "reject when challenge evidence is malformed",
            Self::NonReconstructableWalletEvidence => {
                "reject when wallet evidence cannot be reconstructed"
            }
            Self::ExcessiveFee => "reject when exit fee exceeds canonical cap",
            Self::PrivacyBudgetLeak => "reject when public inputs leak privacy budget",
            Self::SimulatedProductionRelease => "reject simulated production release in devnet",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionSurface {
    MoneroFinalityGate,
    DepositLockCanonicalityGate,
    PqSignerEpochGate,
    WatcherQuorumGate,
    NoteReceiptLinkageGate,
    SettlementClaimBindingGate,
    ReleaseTimelockGate,
    ChallengeValidityGate,
    WalletEvidenceReconstructionGate,
    FeePolicyGate,
    PrivacyBudgetGate,
    ProductionReleaseGate,
}

impl RejectionSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroFinalityGate => "monero_finality_gate",
            Self::DepositLockCanonicalityGate => "deposit_lock_canonicality_gate",
            Self::PqSignerEpochGate => "pq_signer_epoch_gate",
            Self::WatcherQuorumGate => "watcher_quorum_gate",
            Self::NoteReceiptLinkageGate => "note_receipt_linkage_gate",
            Self::SettlementClaimBindingGate => "settlement_claim_binding_gate",
            Self::ReleaseTimelockGate => "release_timelock_gate",
            Self::ChallengeValidityGate => "challenge_validity_gate",
            Self::WalletEvidenceReconstructionGate => "wallet_evidence_reconstruction_gate",
            Self::FeePolicyGate => "fee_policy_gate",
            Self::PrivacyBudgetGate => "privacy_budget_gate",
            Self::ProductionReleaseGate => "production_release_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedAction {
    RejectBeforeProof,
    RejectBeforeSettlement,
    RejectBeforeRelease,
    QuarantineForOperatorReview,
}

impl FailClosedAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RejectBeforeProof => "reject_before_proof",
            Self::RejectBeforeSettlement => "reject_before_settlement",
            Self::RejectBeforeRelease => "reject_before_release",
            Self::QuarantineForOperatorReview => "quarantine_for_operator_review",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub negative_case_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub base_monero_height: u64,
    pub l2_reference_height: u64,
    pub min_monero_confirmations: u64,
    pub min_pq_signer_epoch: u64,
    pub required_quorum_weight: u64,
    pub challenge_window_blocks: u64,
    pub release_delay_blocks: u64,
    pub max_exit_fee_bps: u64,
    pub privacy_budget_bits: u64,
    pub min_reconstructable_wallet_shards: u64,
    pub required_wallet_shards: u64,
    pub allow_production_release_in_devnet: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            negative_case_suite: NEGATIVE_CASE_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            min_pq_signer_epoch: DEFAULT_MIN_PQ_SIGNER_EPOCH,
            required_quorum_weight: DEFAULT_REQUIRED_QUORUM_WEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            max_exit_fee_bps: DEFAULT_MAX_EXIT_FEE_BPS,
            privacy_budget_bits: DEFAULT_PRIVACY_BUDGET_BITS,
            min_reconstructable_wallet_shards: DEFAULT_MIN_RECONSTRUCTABLE_WALLET_SHARDS,
            required_wallet_shards: DEFAULT_REQUIRED_WALLET_SHARDS,
            allow_production_release_in_devnet: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CanonicalVectorNegativeCase {
    pub case_id: String,
    pub kind: NegativeCaseKind,
    pub label: String,
    pub expected_rejection_surface: RejectionSurface,
    pub fail_closed_action: FailClosedAction,
    pub rejection_code: String,
    pub deposit_lock: DepositLockEvidence,
    pub pq_attestation: PqAttestationEvidence,
    pub note_receipt: NoteReceiptEvidence,
    pub settlement: SettlementEvidence,
    pub challenge: ChallengeEvidence,
    pub wallet: WalletEvidence,
    pub fee: FeeEvidence,
    pub privacy: PrivacyEvidence,
    pub release: ReleaseEvidence,
    pub roots: NegativeCaseRoots,
    pub devnet: Value,
}

impl CanonicalVectorNegativeCase {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        negative_case_root(self)
    }

    pub fn rejection_surface_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE-REJECTION-SURFACE",
            &[
                HashPart::Str(self.kind.as_str()),
                HashPart::Str(self.expected_rejection_surface.as_str()),
                HashPart::Str(self.fail_closed_action.as_str()),
                HashPart::Str(&self.rejection_code),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLockEvidence {
    pub lock_txid: String,
    pub output_commitment: String,
    pub canonical_header_hash: String,
    pub competing_header_hash: String,
    pub observed_monero_height: u64,
    pub observed_depth: u64,
    pub required_depth: u64,
    pub reorg_depth: u64,
    pub canonical_branch_weight: u64,
    pub competing_branch_weight: u64,
}

impl DepositLockEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-DEPOSIT-LOCK",
            &[
                HashPart::Str(&self.lock_txid),
                HashPart::Str(&self.output_commitment),
                HashPart::Str(&self.canonical_header_hash),
                HashPart::Str(&self.competing_header_hash),
                HashPart::U64(self.observed_monero_height),
                HashPart::U64(self.observed_depth),
                HashPart::U64(self.required_depth),
                HashPart::U64(self.reorg_depth),
                HashPart::U64(self.canonical_branch_weight),
                HashPart::U64(self.competing_branch_weight),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestationEvidence {
    pub signer_set_root: String,
    pub attestation_root: String,
    pub signer_epoch: u64,
    pub required_epoch: u64,
    pub observed_weight: u64,
    pub required_weight: u64,
    pub transcript_root: String,
}

impl PqAttestationEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-PQ-ATTESTATION",
            &[
                HashPart::Str(&self.signer_set_root),
                HashPart::Str(&self.attestation_root),
                HashPart::U64(self.signer_epoch),
                HashPart::U64(self.required_epoch),
                HashPart::U64(self.observed_weight),
                HashPart::U64(self.required_weight),
                HashPart::Str(&self.transcript_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NoteReceiptEvidence {
    pub note_commitment_root: String,
    pub receipt_root: String,
    pub claimed_link_root: String,
    pub reconstructed_link_root: String,
    pub nullifier_root: String,
}

impl NoteReceiptEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-NOTE-RECEIPT",
            &[
                HashPart::Str(&self.note_commitment_root),
                HashPart::Str(&self.receipt_root),
                HashPart::Str(&self.claimed_link_root),
                HashPart::Str(&self.reconstructed_link_root),
                HashPart::Str(&self.nullifier_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementEvidence {
    pub settlement_root: String,
    pub exit_claim_root: String,
    pub claimed_asset_id: String,
    pub settled_asset_id: String,
    pub claimed_amount_piconero: u64,
    pub settled_amount_piconero: u64,
    pub l2_account_commitment: String,
}

impl SettlementEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-SETTLEMENT",
            &[
                HashPart::Str(&self.settlement_root),
                HashPart::Str(&self.exit_claim_root),
                HashPart::Str(&self.claimed_asset_id),
                HashPart::Str(&self.settled_asset_id),
                HashPart::U64(self.claimed_amount_piconero),
                HashPart::U64(self.settled_amount_piconero),
                HashPart::Str(&self.l2_account_commitment),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeEvidence {
    pub challenge_root: String,
    pub challenged_case_root: String,
    pub challenger_commitment: String,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub bond_units: u64,
    pub valid_bond_units: u64,
}

impl ChallengeEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CHALLENGE",
            &[
                HashPart::Str(&self.challenge_root),
                HashPart::Str(&self.challenged_case_root),
                HashPart::Str(&self.challenger_commitment),
                HashPart::U64(self.opened_at_l2_height),
                HashPart::U64(self.expires_at_l2_height),
                HashPart::U64(self.bond_units),
                HashPart::U64(self.valid_bond_units),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletEvidence {
    pub wallet_evidence_root: String,
    pub shard_set_root: String,
    pub available_shards: u64,
    pub required_shards: u64,
    pub reconstructable_shards: u64,
    pub scan_path_commitment: String,
}

impl WalletEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-WALLET",
            &[
                HashPart::Str(&self.wallet_evidence_root),
                HashPart::Str(&self.shard_set_root),
                HashPart::U64(self.available_shards),
                HashPart::U64(self.required_shards),
                HashPart::U64(self.reconstructable_shards),
                HashPart::Str(&self.scan_path_commitment),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeEvidence {
    pub fee_schedule_root: String,
    pub requested_fee_bps: u64,
    pub max_fee_bps: u64,
    pub fee_recipient_commitment: String,
}

impl FeeEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-FEE",
            &[
                HashPart::Str(&self.fee_schedule_root),
                HashPart::U64(self.requested_fee_bps),
                HashPart::U64(self.max_fee_bps),
                HashPart::Str(&self.fee_recipient_commitment),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyEvidence {
    pub public_input_root: String,
    pub redaction_root: String,
    pub disclosed_budget_bits: u64,
    pub max_budget_bits: u64,
    pub leaked_fields_root: String,
}

impl PrivacyEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-PRIVACY",
            &[
                HashPart::Str(&self.public_input_root),
                HashPart::Str(&self.redaction_root),
                HashPart::U64(self.disclosed_budget_bits),
                HashPart::U64(self.max_budget_bits),
                HashPart::Str(&self.leaked_fields_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseEvidence {
    pub release_root: String,
    pub requested_release_height: u64,
    pub earliest_release_height: u64,
    pub production_release_flag: u64,
    pub devnet_release_guard_root: String,
}

impl ReleaseEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-RELEASE",
            &[
                HashPart::Str(&self.release_root),
                HashPart::U64(self.requested_release_height),
                HashPart::U64(self.earliest_release_height),
                HashPart::U64(self.production_release_flag),
                HashPart::Str(&self.devnet_release_guard_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NegativeCaseRoots {
    pub deposit_lock_root: String,
    pub pq_attestation_root: String,
    pub note_receipt_root: String,
    pub settlement_root: String,
    pub challenge_root: String,
    pub wallet_root: String,
    pub fee_root: String,
    pub privacy_root: String,
    pub release_root: String,
    pub rejection_surface_root: String,
    pub evidence_root: String,
    pub case_root: String,
}

impl NegativeCaseRoots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn evidence_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-ROOTS",
            &[
                json!(self.deposit_lock_root),
                json!(self.pq_attestation_root),
                json!(self.note_receipt_root),
                json!(self.settlement_root),
                json!(self.challenge_root),
                json!(self.wallet_root),
                json!(self.fee_root),
                json!(self.privacy_root),
                json!(self.release_root),
                json!(self.rejection_surface_root),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub cases: Vec<CanonicalVectorNegativeCase>,
    pub case_root: String,
    pub rejection_surface_root: String,
    pub fail_closed_action_root: String,
    pub devnet_data: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, cases: Vec<CanonicalVectorNegativeCase>) -> Result<Self> {
        if cases.is_empty() {
            return Err("negative case manifest requires at least one case".to_string());
        }

        let expected = required_negative_case_kinds();
        for kind in expected {
            if !cases.iter().any(|case| case.kind == kind) {
                return Err(format!("missing negative case {}", kind.as_str()));
            }
        }

        let case_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE-MANIFEST-CASES",
            &cases
                .iter()
                .map(|case| json!(case.roots.case_root))
                .collect::<Vec<_>>(),
        );
        let rejection_surface_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE-MANIFEST-REJECTION-SURFACES",
            &cases
                .iter()
                .map(|case| {
                    json!({
                        "case_id": case.case_id,
                        "kind": case.kind.as_str(),
                        "rejection_surface": case.expected_rejection_surface.as_str(),
                        "rejection_code": case.rejection_code,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let fail_closed_action_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE-MANIFEST-FAIL-CLOSED-ACTIONS",
            &cases
                .iter()
                .map(|case| {
                    json!({
                        "case_id": case.case_id,
                        "action": case.fail_closed_action.as_str(),
                    })
                })
                .collect::<Vec<_>>(),
        );

        Ok(Self {
            config,
            cases,
            case_root,
            rejection_surface_root,
            fail_closed_action_root,
            devnet_data: devnet_data(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let cases = build_devnet_cases(&config);
        Self::new(config, cases).unwrap_or_else(fallback_state)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "case_count": self.cases.len(),
            "cases": self.cases.iter().map(CanonicalVectorNegativeCase::public_record).collect::<Vec<_>>(),
            "case_root": self.case_root,
            "rejection_surface_root": self.rejection_surface_root,
            "fail_closed_action_root": self.fail_closed_action_root,
            "state_root": self.state_root(),
            "devnet_data": self.devnet_data,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE-MANIFEST-STATE",
            &[
                HashPart::Str(&self.config.root()),
                HashPart::Str(&self.case_root),
                HashPart::Str(&self.rejection_surface_root),
                HashPart::Str(&self.fail_closed_action_root),
                HashPart::Str(&merkle_root(
                    "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE-MANIFEST-DEVNET-DATA",
                    &self.devnet_data.values().cloned().collect::<Vec<_>>(),
                )),
            ],
            32,
        )
    }

    pub fn expected_rejections(&self) -> Vec<Value> {
        self.cases
            .iter()
            .map(|case| {
                json!({
                    "case_id": case.case_id,
                    "kind": case.kind.as_str(),
                    "surface": case.expected_rejection_surface.as_str(),
                    "action": case.fail_closed_action.as_str(),
                    "code": case.rejection_code,
                })
            })
            .collect()
    }

    pub fn case_by_kind(&self, kind: NegativeCaseKind) -> Option<&CanonicalVectorNegativeCase> {
        self.cases.iter().find(|case| case.kind == kind)
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

pub fn required_negative_case_kinds() -> Vec<NegativeCaseKind> {
    vec![
        NegativeCaseKind::ShallowMoneroFinality,
        NegativeCaseKind::ReorgedDepositLock,
        NegativeCaseKind::StalePqSignerEpoch,
        NegativeCaseKind::WeakQuorum,
        NegativeCaseKind::BrokenNoteToReceiptLinkage,
        NegativeCaseKind::MismatchedSettlementExitClaim,
        NegativeCaseKind::PrematureRelease,
        NegativeCaseKind::InvalidChallenge,
        NegativeCaseKind::NonReconstructableWalletEvidence,
        NegativeCaseKind::ExcessiveFee,
        NegativeCaseKind::PrivacyBudgetLeak,
        NegativeCaseKind::SimulatedProductionRelease,
    ]
}

pub fn expected_rejection_surface(kind: NegativeCaseKind) -> RejectionSurface {
    match kind {
        NegativeCaseKind::ShallowMoneroFinality => RejectionSurface::MoneroFinalityGate,
        NegativeCaseKind::ReorgedDepositLock => RejectionSurface::DepositLockCanonicalityGate,
        NegativeCaseKind::StalePqSignerEpoch => RejectionSurface::PqSignerEpochGate,
        NegativeCaseKind::WeakQuorum => RejectionSurface::WatcherQuorumGate,
        NegativeCaseKind::BrokenNoteToReceiptLinkage => RejectionSurface::NoteReceiptLinkageGate,
        NegativeCaseKind::MismatchedSettlementExitClaim => {
            RejectionSurface::SettlementClaimBindingGate
        }
        NegativeCaseKind::PrematureRelease => RejectionSurface::ReleaseTimelockGate,
        NegativeCaseKind::InvalidChallenge => RejectionSurface::ChallengeValidityGate,
        NegativeCaseKind::NonReconstructableWalletEvidence => {
            RejectionSurface::WalletEvidenceReconstructionGate
        }
        NegativeCaseKind::ExcessiveFee => RejectionSurface::FeePolicyGate,
        NegativeCaseKind::PrivacyBudgetLeak => RejectionSurface::PrivacyBudgetGate,
        NegativeCaseKind::SimulatedProductionRelease => RejectionSurface::ProductionReleaseGate,
    }
}

pub fn expected_rejection_code(kind: NegativeCaseKind) -> &'static str {
    match kind {
        NegativeCaseKind::ShallowMoneroFinality => "reject_monero_depth_below_finality",
        NegativeCaseKind::ReorgedDepositLock => "reject_reorged_deposit_lock",
        NegativeCaseKind::StalePqSignerEpoch => "reject_stale_pq_signer_epoch",
        NegativeCaseKind::WeakQuorum => "reject_weak_watcher_quorum",
        NegativeCaseKind::BrokenNoteToReceiptLinkage => "reject_broken_note_receipt_linkage",
        NegativeCaseKind::MismatchedSettlementExitClaim => "reject_settlement_exit_claim_mismatch",
        NegativeCaseKind::PrematureRelease => "reject_premature_release",
        NegativeCaseKind::InvalidChallenge => "reject_invalid_challenge",
        NegativeCaseKind::NonReconstructableWalletEvidence => {
            "reject_non_reconstructable_wallet_evidence"
        }
        NegativeCaseKind::ExcessiveFee => "reject_exit_fee_above_cap",
        NegativeCaseKind::PrivacyBudgetLeak => "reject_privacy_budget_leak",
        NegativeCaseKind::SimulatedProductionRelease => "reject_simulated_production_release",
    }
}

fn negative_case_root(case: &CanonicalVectorNegativeCase) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE",
        &[
            HashPart::Str(&case.case_id),
            HashPart::Str(case.kind.as_str()),
            HashPart::Str(case.expected_rejection_surface.as_str()),
            HashPart::Str(case.fail_closed_action.as_str()),
            HashPart::Str(&case.rejection_code),
            HashPart::Str(&case.roots.evidence_root),
        ],
        32,
    )
}

fn build_devnet_cases(config: &Config) -> Vec<CanonicalVectorNegativeCase> {
    required_negative_case_kinds()
        .into_iter()
        .enumerate()
        .map(|(index, kind)| build_case(config, kind, index as u64))
        .collect()
}

fn build_case(
    config: &Config,
    kind: NegativeCaseKind,
    ordinal: u64,
) -> CanonicalVectorNegativeCase {
    let label = format!("{}-{}", kind.as_str(), ordinal);
    let surface = expected_rejection_surface(kind);
    let action = match kind {
        NegativeCaseKind::PrematureRelease | NegativeCaseKind::SimulatedProductionRelease => {
            FailClosedAction::RejectBeforeRelease
        }
        NegativeCaseKind::InvalidChallenge | NegativeCaseKind::PrivacyBudgetLeak => {
            FailClosedAction::QuarantineForOperatorReview
        }
        NegativeCaseKind::MismatchedSettlementExitClaim | NegativeCaseKind::ExcessiveFee => {
            FailClosedAction::RejectBeforeSettlement
        }
        _ => FailClosedAction::RejectBeforeProof,
    };

    let deposit_lock = deposit_lock_evidence(config, kind, &label, ordinal);
    let pq_attestation = pq_attestation_evidence(config, kind, &label, ordinal);
    let note_receipt = note_receipt_evidence(kind, &label);
    let settlement = settlement_evidence(kind, &label, ordinal);
    let challenge = challenge_evidence(config, kind, &label, ordinal);
    let wallet = wallet_evidence(config, kind, &label);
    let fee = fee_evidence(config, kind, &label);
    let privacy = privacy_evidence(config, kind, &label);
    let release = release_evidence(config, kind, &label, ordinal);
    let rejection_code = expected_rejection_code(kind).to_string();

    let mut case = CanonicalVectorNegativeCase {
        case_id: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE-ID",
            &[HashPart::Str(&label), HashPart::Str(&rejection_code)],
            16,
        ),
        kind,
        label: kind.label().to_string(),
        expected_rejection_surface: surface,
        fail_closed_action: action,
        rejection_code,
        deposit_lock,
        pq_attestation,
        note_receipt,
        settlement,
        challenge,
        wallet,
        fee,
        privacy,
        release,
        roots: NegativeCaseRoots::default(),
        devnet: json!({}),
    };

    let rejection_surface_root = case.rejection_surface_root();
    let mut roots = NegativeCaseRoots {
        deposit_lock_root: case.deposit_lock.root(),
        pq_attestation_root: case.pq_attestation.root(),
        note_receipt_root: case.note_receipt.root(),
        settlement_root: case.settlement.root(),
        challenge_root: case.challenge.root(),
        wallet_root: case.wallet.root(),
        fee_root: case.fee.root(),
        privacy_root: case.privacy.root(),
        release_root: case.release.root(),
        rejection_surface_root,
        evidence_root: String::new(),
        case_root: String::new(),
    };
    roots.evidence_root = roots.evidence_root();
    case.roots = roots;
    case.roots.case_root = case.root();
    case.devnet = json!({
        "ordinal": ordinal,
        "monero_network": config.monero_network,
        "l2_network": config.l2_network,
        "deterministic_seed_root": domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CASE-DEVNET-SEED",
            &[HashPart::Str(&label), HashPart::Str(&case.roots.case_root)],
            32,
        ),
        "expected": {
            "must_fail_closed": 1,
            "surface": case.expected_rejection_surface.as_str(),
            "action": case.fail_closed_action.as_str(),
            "rejection_code": case.rejection_code,
        }
    });
    case
}

fn deposit_lock_evidence(
    config: &Config,
    kind: NegativeCaseKind,
    label: &str,
    ordinal: u64,
) -> DepositLockEvidence {
    let lock_txid = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-LOCK-TXID",
        &[HashPart::Str(label)],
        32,
    );
    let observed_depth = match kind {
        NegativeCaseKind::ShallowMoneroFinality => config.min_monero_confirmations - 2,
        _ => config.min_monero_confirmations + 4,
    };
    let reorg_depth = match kind {
        NegativeCaseKind::ReorgedDepositLock => observed_depth + 1,
        _ => 0,
    };
    let canonical_branch_weight = 200 + ordinal;
    let competing_branch_weight = match kind {
        NegativeCaseKind::ReorgedDepositLock => canonical_branch_weight + 6,
        _ => 0,
    };

    DepositLockEvidence {
        lock_txid: lock_txid.clone(),
        output_commitment: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-OUTPUT-COMMITMENT",
            &[HashPart::Str(label), HashPart::U64(ordinal)],
            32,
        ),
        canonical_header_hash: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CANONICAL-HEADER",
            &[HashPart::Str(&lock_txid), HashPart::U64(observed_depth)],
            32,
        ),
        competing_header_hash: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-COMPETING-HEADER",
            &[HashPart::Str(&lock_txid), HashPart::U64(reorg_depth)],
            32,
        ),
        observed_monero_height: config.base_monero_height + ordinal,
        observed_depth,
        required_depth: config.min_monero_confirmations,
        reorg_depth,
        canonical_branch_weight,
        competing_branch_weight,
    }
}

fn pq_attestation_evidence(
    config: &Config,
    kind: NegativeCaseKind,
    label: &str,
    ordinal: u64,
) -> PqAttestationEvidence {
    let signer_epoch = match kind {
        NegativeCaseKind::StalePqSignerEpoch => config.min_pq_signer_epoch - 1,
        _ => config.min_pq_signer_epoch + ordinal,
    };
    let observed_weight = match kind {
        NegativeCaseKind::WeakQuorum => config.required_quorum_weight - 2,
        _ => config.required_quorum_weight + 1,
    };

    PqAttestationEvidence {
        signer_set_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-SIGNER-SET",
            &[HashPart::Str(label), HashPart::U64(signer_epoch)],
            32,
        ),
        attestation_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-ATTESTATION",
            &[HashPart::Str(label), HashPart::U64(observed_weight)],
            32,
        ),
        signer_epoch,
        required_epoch: config.min_pq_signer_epoch,
        observed_weight,
        required_weight: config.required_quorum_weight,
        transcript_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-PQ-TRANSCRIPT",
            &[HashPart::Str(label), HashPart::U64(ordinal)],
            32,
        ),
    }
}

fn note_receipt_evidence(kind: NegativeCaseKind, label: &str) -> NoteReceiptEvidence {
    let note_commitment_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-NOTE-COMMITMENT",
        &[HashPart::Str(label)],
        32,
    );
    let receipt_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-RECEIPT",
        &[HashPart::Str(label)],
        32,
    );
    let reconstructed_link_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-RECONSTRUCTED-LINK",
        &[
            HashPart::Str(&note_commitment_root),
            HashPart::Str(&receipt_root),
        ],
        32,
    );
    let claimed_link_root = match kind {
        NegativeCaseKind::BrokenNoteToReceiptLinkage => domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-BROKEN-LINK",
            &[HashPart::Str(label)],
            32,
        ),
        _ => reconstructed_link_root.clone(),
    };

    NoteReceiptEvidence {
        note_commitment_root,
        receipt_root,
        claimed_link_root,
        reconstructed_link_root,
        nullifier_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-NULLIFIER",
            &[HashPart::Str(label)],
            32,
        ),
    }
}

fn settlement_evidence(kind: NegativeCaseKind, label: &str, ordinal: u64) -> SettlementEvidence {
    let claimed_amount_piconero = 1_250_000_000_000 + ordinal;
    let settled_amount_piconero = match kind {
        NegativeCaseKind::MismatchedSettlementExitClaim => claimed_amount_piconero - 70_000_000,
        _ => claimed_amount_piconero,
    };
    let claimed_asset_id = "xmr.locked.canonical".to_string();
    let settled_asset_id = match kind {
        NegativeCaseKind::MismatchedSettlementExitClaim => "xmr.locked.shadow".to_string(),
        _ => claimed_asset_id.clone(),
    };

    SettlementEvidence {
        settlement_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-SETTLEMENT-ROOT",
            &[HashPart::Str(label), HashPart::U64(settled_amount_piconero)],
            32,
        ),
        exit_claim_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EXIT-CLAIM",
            &[HashPart::Str(label), HashPart::U64(claimed_amount_piconero)],
            32,
        ),
        claimed_asset_id,
        settled_asset_id,
        claimed_amount_piconero,
        settled_amount_piconero,
        l2_account_commitment: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-L2-ACCOUNT",
            &[HashPart::Str(label)],
            32,
        ),
    }
}

fn challenge_evidence(
    config: &Config,
    kind: NegativeCaseKind,
    label: &str,
    ordinal: u64,
) -> ChallengeEvidence {
    let valid_bond_units = 10_000;
    let bond_units = match kind {
        NegativeCaseKind::InvalidChallenge => valid_bond_units - 1,
        _ => valid_bond_units,
    };
    let opened_at_l2_height = config.l2_reference_height + ordinal;
    let expires_at_l2_height = opened_at_l2_height + config.challenge_window_blocks;

    ChallengeEvidence {
        challenge_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CHALLENGE-ROOT",
            &[HashPart::Str(label), HashPart::U64(bond_units)],
            32,
        ),
        challenged_case_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CHALLENGED-CASE",
            &[HashPart::Str(label)],
            32,
        ),
        challenger_commitment: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-CHALLENGER",
            &[HashPart::Str(label)],
            32,
        ),
        opened_at_l2_height,
        expires_at_l2_height,
        bond_units,
        valid_bond_units,
    }
}

fn wallet_evidence(config: &Config, kind: NegativeCaseKind, label: &str) -> WalletEvidence {
    let reconstructable_shards = match kind {
        NegativeCaseKind::NonReconstructableWalletEvidence => {
            config.min_reconstructable_wallet_shards - 1
        }
        _ => config.min_reconstructable_wallet_shards,
    };

    WalletEvidence {
        wallet_evidence_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-WALLET-EVIDENCE",
            &[HashPart::Str(label), HashPart::U64(reconstructable_shards)],
            32,
        ),
        shard_set_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-WALLET-SHARD-SET",
            &[HashPart::Str(label)],
            32,
        ),
        available_shards: config.required_wallet_shards,
        required_shards: config.required_wallet_shards,
        reconstructable_shards,
        scan_path_commitment: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-SCAN-PATH",
            &[HashPart::Str(label)],
            32,
        ),
    }
}

fn fee_evidence(config: &Config, kind: NegativeCaseKind, label: &str) -> FeeEvidence {
    let requested_fee_bps = match kind {
        NegativeCaseKind::ExcessiveFee => config.max_exit_fee_bps + 12,
        _ => config.max_exit_fee_bps - 5,
    };

    FeeEvidence {
        fee_schedule_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-FEE-SCHEDULE",
            &[HashPart::U64(config.max_exit_fee_bps)],
            32,
        ),
        requested_fee_bps,
        max_fee_bps: config.max_exit_fee_bps,
        fee_recipient_commitment: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-FEE-RECIPIENT",
            &[HashPart::Str(label)],
            32,
        ),
    }
}

fn privacy_evidence(config: &Config, kind: NegativeCaseKind, label: &str) -> PrivacyEvidence {
    let disclosed_budget_bits = match kind {
        NegativeCaseKind::PrivacyBudgetLeak => config.privacy_budget_bits + 7,
        _ => config.privacy_budget_bits,
    };

    PrivacyEvidence {
        public_input_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-PUBLIC-INPUT",
            &[HashPart::Str(label), HashPart::U64(disclosed_budget_bits)],
            32,
        ),
        redaction_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-REDACTION",
            &[HashPart::Str(label)],
            32,
        ),
        disclosed_budget_bits,
        max_budget_bits: config.privacy_budget_bits,
        leaked_fields_root: leaked_fields_root(kind, label),
    }
}

fn release_evidence(
    config: &Config,
    kind: NegativeCaseKind,
    label: &str,
    ordinal: u64,
) -> ReleaseEvidence {
    let earliest_release_height =
        config.l2_reference_height + config.release_delay_blocks + ordinal;
    let requested_release_height = match kind {
        NegativeCaseKind::PrematureRelease => earliest_release_height - 3,
        _ => earliest_release_height,
    };
    let production_release_flag = match kind {
        NegativeCaseKind::SimulatedProductionRelease => 1,
        _ => 0,
    };

    ReleaseEvidence {
        release_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-RELEASE-ROOT",
            &[
                HashPart::Str(label),
                HashPart::U64(requested_release_height),
                HashPart::U64(production_release_flag),
            ],
            32,
        ),
        requested_release_height,
        earliest_release_height,
        production_release_flag,
        devnet_release_guard_root: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-DEVNET-RELEASE-GUARD",
            &[
                HashPart::Str(DEVNET_L2_NETWORK),
                HashPart::U64(production_release_flag),
            ],
            32,
        ),
    }
}

fn leaked_fields_root(kind: NegativeCaseKind, label: &str) -> String {
    let fields = match kind {
        NegativeCaseKind::PrivacyBudgetLeak => vec![
            json!("subaddress_index"),
            json!("wallet_scan_epoch"),
            json!("change_output_hint"),
        ],
        _ => vec![json!("none")],
    };
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-LEAKED-FIELDS",
        &[
            HashPart::Str(label),
            HashPart::Str(&merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-LEAKED-FIELDS-LIST",
                &fields,
            )),
        ],
        32,
    )
}

fn devnet_data() -> BTreeMap<String, Value> {
    let mut data = BTreeMap::new();
    data.insert(
        "bridge_exit_lane".to_string(),
        json!({
            "name": "pq-forced-exit-canonical-negative-vector-manifest",
            "monero_network": DEVNET_MONERO_NETWORK,
            "l2_network": DEVNET_L2_NETWORK,
        }),
    );
    data.insert(
        "fail_closed_policy".to_string(),
        json!({
            "rule": "every listed negative vector must be rejected before asset release",
            "accepted_release_count": 0,
            "production_release_allowed": 0,
            "rejection_surfaces": required_negative_case_kinds()
                .into_iter()
                .map(|kind| expected_rejection_surface(kind).as_str())
                .collect::<Vec<_>>(),
        }),
    );
    data.insert(
        "public_record_fields".to_string(),
        json!({
            "roots": [
                "case_root",
                "rejection_surface_root",
                "fail_closed_action_root",
                "state_root"
            ],
            "case_roots": [
                "deposit_lock_root",
                "pq_attestation_root",
                "note_receipt_root",
                "settlement_root",
                "challenge_root",
                "wallet_root",
                "fee_root",
                "privacy_root",
                "release_root"
            ],
        }),
    );
    data
}

fn fallback_state(reason: String) -> State {
    let config = Config::devnet();
    let mut devnet_data = devnet_data();
    devnet_data.insert(
        "construction_error".to_string(),
        json!({
            "reason_root": domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-FALLBACK-REASON",
                &[HashPart::Str(&reason)],
                32,
            )
        }),
    );
    State {
        config,
        cases: Vec::new(),
        case_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-FALLBACK-CASES", &[]),
        rejection_surface_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-FALLBACK-REJECTION-SURFACES",
            &[],
        ),
        fail_closed_action_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-FALLBACK-FAIL-CLOSED-ACTIONS",
            &[],
        ),
        devnet_data,
    }
}
