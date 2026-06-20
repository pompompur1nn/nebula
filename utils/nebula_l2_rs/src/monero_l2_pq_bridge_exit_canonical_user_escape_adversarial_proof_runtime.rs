use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAdversarialProofRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_PROOF_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-proof-runtime-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub challenge_window_blocks: u64,
    pub min_watcher_quorum: u64,
    pub min_liquidity_bps: u64,
    pub max_metadata_fields: u64,
    pub pq_epoch_grace_blocks: u64,
    pub fail_closed_threshold: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            challenge_window_blocks: 720,
            min_watcher_quorum: 5,
            min_liquidity_bps: 10_000,
            max_metadata_fields: 3,
            pq_epoch_grace_blocks: 0,
            fail_closed_threshold: 9,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_watcher_quorum": self.min_watcher_quorum,
            "min_liquidity_bps": self.min_liquidity_bps,
            "max_metadata_fields": self.max_metadata_fields,
            "pq_epoch_grace_blocks": self.pq_epoch_grace_blocks,
            "fail_closed_threshold": self.fail_closed_threshold,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialCaseKind {
    DepositReorg,
    WatcherCollusion,
    SequencerHalt,
    ForgedReceipt,
    StalePqEpoch,
    LiquidityExhaustion,
    MetadataLeak,
    ChallengeBypass,
    WalletRecoveryMismatch,
}

impl AdversarialCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositReorg => "deposit_reorg",
            Self::WatcherCollusion => "watcher_collusion",
            Self::SequencerHalt => "sequencer_halt",
            Self::ForgedReceipt => "forged_receipt",
            Self::StalePqEpoch => "stale_pq_epoch",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::MetadataLeak => "metadata_leak",
            Self::ChallengeBypass => "challenge_bypass",
            Self::WalletRecoveryMismatch => "wallet_recovery_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeDecision {
    Hold,
    Reject,
}

impl EscapeDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_id: String,
    pub case_kind: AdversarialCaseKind,
    pub decision: EscapeDecision,
    pub source: String,
    pub claim: String,
    pub digest: String,
}

impl Evidence {
    pub fn new(
        case_kind: AdversarialCaseKind,
        decision: EscapeDecision,
        source: &str,
        claim: &str,
    ) -> Self {
        let digest = domain_hash(
            "MONERO-L2-PQ-ESCAPE-EVIDENCE-DIGEST",
            &[
                HashPart::Str(MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_PROOF_RUNTIME_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(case_kind.as_str()),
                HashPart::Str(decision.as_str()),
                HashPart::Str(source),
                HashPart::Str(claim),
            ],
            32,
        );
        let evidence_id = domain_hash(
            "MONERO-L2-PQ-ESCAPE-EVIDENCE-ID",
            &[HashPart::Str(&digest)],
            16,
        );

        Self {
            evidence_id,
            case_kind,
            decision,
            source: source.to_string(),
            claim: claim.to_string(),
            digest,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "case_kind": self.case_kind.as_str(),
            "decision": self.decision.as_str(),
            "source": self.source,
            "claim": self.claim,
            "digest": self.digest,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scorecard {
    pub case_kind: AdversarialCaseKind,
    pub hold_evidence_root: String,
    pub reject_evidence_root: String,
    pub invariant_count: u64,
    pub satisfied_invariant_count: u64,
    pub fail_closed_score: u64,
    pub fail_closed: bool,
}

impl Scorecard {
    pub fn public_record(&self) -> Value {
        json!({
            "case_kind": self.case_kind.as_str(),
            "hold_evidence_root": self.hold_evidence_root,
            "reject_evidence_root": self.reject_evidence_root,
            "invariant_count": self.invariant_count,
            "satisfied_invariant_count": self.satisfied_invariant_count,
            "fail_closed_score": self.fail_closed_score,
            "fail_closed": self.fail_closed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialCase {
    pub case_id: String,
    pub kind: AdversarialCaseKind,
    pub package_id: String,
    pub attack_model: String,
    pub hold_evidence: Vec<Evidence>,
    pub reject_evidence: Vec<Evidence>,
    pub scorecard: Scorecard,
}

impl AdversarialCase {
    pub fn new(
        kind: AdversarialCaseKind,
        package_id: &str,
        attack_model: &str,
        hold_claim: &str,
        reject_claim: &str,
        fail_closed_score: u64,
    ) -> Self {
        let hold_evidence = vec![
            Evidence::new(kind, EscapeDecision::Hold, "bridge_guard", hold_claim),
            Evidence::new(
                kind,
                EscapeDecision::Hold,
                "user_escape_package",
                "escape package remains queued and cannot finalize while the adversarial condition is unresolved",
            ),
        ];
        let reject_evidence = vec![
            Evidence::new(kind, EscapeDecision::Reject, "canonicality_checker", reject_claim),
            Evidence::new(
                kind,
                EscapeDecision::Reject,
                "settlement_gate",
                "release path requires fresh canonical proof, quorum evidence, and non-leaking metadata",
            ),
        ];
        let hold_evidence_root = evidence_root(kind, EscapeDecision::Hold, &hold_evidence);
        let reject_evidence_root = evidence_root(kind, EscapeDecision::Reject, &reject_evidence);
        let scorecard = Scorecard {
            case_kind: kind,
            hold_evidence_root,
            reject_evidence_root,
            invariant_count: 9,
            satisfied_invariant_count: fail_closed_score,
            fail_closed_score,
            fail_closed: fail_closed_score >= 9,
        };
        let case_id = domain_hash(
            "MONERO-L2-PQ-ESCAPE-ADVERSARIAL-CASE-ID",
            &[
                HashPart::Str(MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_PROOF_RUNTIME_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(package_id),
                HashPart::Str(&scorecard.hold_evidence_root),
                HashPart::Str(&scorecard.reject_evidence_root),
            ],
            16,
        );

        Self {
            case_id,
            kind,
            package_id: package_id.to_string(),
            attack_model: attack_model.to_string(),
            hold_evidence,
            reject_evidence,
            scorecard,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "package_id": self.package_id,
            "attack_model": self.attack_model,
            "hold_evidence": self
                .hold_evidence
                .iter()
                .map(Evidence::public_record)
                .collect::<Vec<_>>(),
            "reject_evidence": self
                .reject_evidence
                .iter()
                .map(Evidence::public_record)
                .collect::<Vec<_>>(),
            "scorecard": self.scorecard.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub escape_package_id: String,
    pub cases: Vec<AdversarialCase>,
    pub ledger_root: String,
    pub scorecard_root: String,
}

impl State {
    pub fn new(config: Config, escape_package_id: &str, cases: Vec<AdversarialCase>) -> Self {
        let case_records = cases
            .iter()
            .map(AdversarialCase::public_record)
            .collect::<Vec<_>>();
        let score_records = cases
            .iter()
            .map(|case| case.scorecard.public_record())
            .collect::<Vec<_>>();

        Self {
            config,
            escape_package_id: escape_package_id.to_string(),
            cases,
            ledger_root: merkle_root("MONERO-L2-PQ-ESCAPE-ADVERSARIAL-LEDGER", &case_records),
            scorecard_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-ADVERSARIAL-SCORECARD",
                &score_records,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_PROOF_RUNTIME_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "escape_package_id": self.escape_package_id,
            "ledger_root": self.ledger_root,
            "scorecard_root": self.scorecard_root,
            "cases": self
                .cases
                .iter()
                .map(AdversarialCase::public_record)
                .collect::<Vec<_>>(),
            "fail_closed": self.fail_closed(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-ESCAPE-ADVERSARIAL-STATE",
            &[
                HashPart::Str(MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_PROOF_RUNTIME_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }

    pub fn fail_closed(&self) -> bool {
        self.cases.iter().all(|case| case.scorecard.fail_closed)
    }

    pub fn validate(&self) -> Result<String> {
        if self.cases.len() != 9 {
            return Err("escape adversarial ledger must contain exactly nine cases".to_string());
        }
        if !self.fail_closed() {
            return Err("escape adversarial ledger contains a non fail-closed case".to_string());
        }
        Ok(self.state_root())
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let package_id = "devnet-user-escape-package-canonical-pq-v1";
    let cases = vec![
        AdversarialCase::new(
            AdversarialCaseKind::DepositReorg,
            package_id,
            "canonical deposit anchor is displaced by a Monero reorg after the escape package is assembled",
            "deposit output is held until replacement depth exceeds canonical finality",
            "receipt is rejected when the deposit anchor is absent from the current canonical chain",
            9,
        ),
        AdversarialCase::new(
            AdversarialCaseKind::WatcherCollusion,
            package_id,
            "watchers sign a false availability statement for the same user escape package",
            "colluding quorum is held behind independent watcher diversity checks",
            "collusive witness set is rejected when signer entropy and cross roots do not match",
            9,
        ),
        AdversarialCase::new(
            AdversarialCaseKind::SequencerHalt,
            package_id,
            "sequencer stops producing inclusion receipts during the escape challenge window",
            "package remains in forced exit queue with timeout evidence",
            "sequencer fast path is rejected until liveness resumes with canonical timeout proof",
            9,
        ),
        AdversarialCase::new(
            AdversarialCaseKind::ForgedReceipt,
            package_id,
            "attacker submits a forged bridge receipt with a valid looking exit amount",
            "receipt is held for domain separated transcript verification",
            "forged receipt is rejected when transcript root and signer set root diverge",
            9,
        ),
        AdversarialCase::new(
            AdversarialCaseKind::StalePqEpoch,
            package_id,
            "escape package references a post-quantum signer epoch that has expired",
            "stale epoch package is held for fresh key rotation proof",
            "stale post-quantum epoch is rejected before liquidity release",
            9,
        ),
        AdversarialCase::new(
            AdversarialCaseKind::LiquidityExhaustion,
            package_id,
            "bridge reserve is insufficient to satisfy a canonical user escape in full",
            "partial payout is held until reserve proof covers the whole canonical amount",
            "underfunded release is rejected and converted to queued claim evidence",
            9,
        ),
        AdversarialCase::new(
            AdversarialCaseKind::MetadataLeak,
            package_id,
            "escape bundle exposes more wallet metadata than the canonical public package allows",
            "leaking package is held for redaction and nullifier reblinding",
            "metadata leaking route is rejected before publication or watcher gossip",
            9,
        ),
        AdversarialCase::new(
            AdversarialCaseKind::ChallengeBypass,
            package_id,
            "settlement actor attempts to skip the mandatory challenge window",
            "package is held until the full challenge window is witnessed",
            "bypass is rejected when challenge elapsed height is below policy",
            9,
        ),
        AdversarialCase::new(
            AdversarialCaseKind::WalletRecoveryMismatch,
            package_id,
            "wallet recovery key does not match the canonical account recovery commitment",
            "recovery path is held for owner proof and recovery commitment reconciliation",
            "mismatched recovery wallet is rejected before exit ownership transfer",
            9,
        ),
    ];

    State::new(config, package_id, cases)
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn evidence_root(
    kind: AdversarialCaseKind,
    decision: EscapeDecision,
    evidence: &[Evidence],
) -> String {
    let leaves = evidence
        .iter()
        .map(Evidence::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        &format!(
            "MONERO-L2-PQ-ESCAPE-{}-{}-EVIDENCE",
            kind.as_str(),
            decision.as_str()
        ),
        &leaves,
    )
}
