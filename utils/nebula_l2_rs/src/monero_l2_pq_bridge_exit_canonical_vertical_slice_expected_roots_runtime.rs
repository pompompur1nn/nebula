use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceExpectedRootsRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_EXPECTED_ROOTS_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-expected-roots-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_EXPECTED_ROOTS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "2026-06-18.forced-exit.vertical-slice.expected-roots.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";

const DOMAIN: &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-expected-roots-runtime";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub l2_finality_lag_blocks: u64,
    pub monero_reorg_hold_blocks: u64,
    pub forced_exit_challenge_window_blocks: u64,
    pub watcher_quorum: u64,
    pub pq_authority_threshold: u64,
    pub reserve_floor_piconero: u64,
    pub privacy_budget_bits: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            l2_finality_lag_blocks: 12,
            monero_reorg_hold_blocks: 20,
            forced_exit_challenge_window_blocks: 720,
            watcher_quorum: 5,
            pq_authority_threshold: 3,
            reserve_floor_piconero: 18_000_000_000_000,
            privacy_budget_bits: 6,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "l2_finality_lag_blocks": self.l2_finality_lag_blocks,
            "monero_reorg_hold_blocks": self.monero_reorg_hold_blocks,
            "forced_exit_challenge_window_blocks": self.forced_exit_challenge_window_blocks,
            "watcher_quorum": self.watcher_quorum,
            "pq_authority_threshold": self.pq_authority_threshold,
            "reserve_floor_piconero": self.reserve_floor_piconero,
            "privacy_budget_bits": self.privacy_budget_bits
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:config"),
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedRootLane {
    pub lane: String,
    pub sequence: u64,
    pub expected_root: String,
    pub source_artifact: String,
    pub invariant: String,
    pub acceptance_gate: String,
    pub release_blocking: bool,
}

impl ExpectedRootLane {
    pub fn new(
        lane: &str,
        sequence: u64,
        source_artifact: &str,
        invariant: &str,
        acceptance_gate: &str,
        release_blocking: bool,
    ) -> Self {
        let expected_root = expected_lane_root(
            lane,
            sequence,
            source_artifact,
            invariant,
            acceptance_gate,
            release_blocking,
        );

        Self {
            lane: lane.to_string(),
            sequence,
            expected_root,
            source_artifact: source_artifact.to_string(),
            invariant: invariant.to_string(),
            acceptance_gate: acceptance_gate.to_string(),
            release_blocking,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "sequence": self.sequence,
            "expected_root": self.expected_root,
            "source_artifact": self.source_artifact,
            "invariant": self.invariant,
            "acceptance_gate": self.acceptance_gate,
            "release_blocking": self.release_blocking
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:lane"),
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub l2_tip_height: u64,
    pub monero_tip_height: u64,
    pub forced_exit_epoch: u64,
    pub lanes: Vec<ExpectedRootLane>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            runtime_id: format!("{DOMAIN}:devnet"),
            l2_tip_height: 1_260_000,
            monero_tip_height: 3_180_000,
            forced_exit_epoch: 42,
            lanes: devnet_lanes(),
        }
    }

    pub fn public_record(&self) -> Value {
        let lanes = self
            .lanes
            .iter()
            .map(ExpectedRootLane::public_record)
            .collect::<Vec<_>>();

        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runtime_id": self.runtime_id,
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "forced_exit_epoch": self.forced_exit_epoch,
            "config": self.config.public_record(),
            "lane_count": self.lanes.len() as u64,
            "lane_root": self.lane_root(),
            "release_blocker_root": self.release_blocker_root(),
            "lanes": lanes
        })
    }

    pub fn lane_root(&self) -> String {
        let leaves = self
            .lanes
            .iter()
            .map(ExpectedRootLane::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:lanes"), &leaves)
    }

    pub fn release_blocker_root(&self) -> String {
        let blockers = self
            .lanes
            .iter()
            .filter(|lane| lane.release_blocking)
            .map(ExpectedRootLane::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:release-blockers"), &blockers)
    }

    pub fn state_root(&self) -> String {
        let config_record = self.config.public_record();
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(SCHEMA_VERSION),
                HashPart::Json(&config_record),
                HashPart::Str(&self.runtime_id),
                HashPart::U64(self.l2_tip_height),
                HashPart::U64(self.monero_tip_height),
                HashPart::U64(self.forced_exit_epoch),
                HashPart::Str(&self.lane_root()),
                HashPart::Str(&self.release_blocker_root()),
            ],
            32,
        )
    }

    pub fn verify_expected_roots(&self) -> Result<()> {
        for lane in &self.lanes {
            let expected = expected_lane_root(
                &lane.lane,
                lane.sequence,
                &lane.source_artifact,
                &lane.invariant,
                &lane.acceptance_gate,
                lane.release_blocking,
            );
            if lane.expected_root != expected {
                return Err(format!("expected root mismatch for lane {}", lane.lane));
            }
        }
        Ok(())
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

fn devnet_lanes() -> Vec<ExpectedRootLane> {
    vec![
        ExpectedRootLane::new(
            "deposit_lock",
            10,
            "deposit-lock-ledger-root",
            "locked Monero deposits are final before note minting",
            "deposit lock root matches finalized Monero observation set",
            true,
        ),
        ExpectedRootLane::new(
            "note_mint",
            20,
            "note-mint-commitment-root",
            "every minted private note is backed by one finalized deposit lock",
            "mint note root consumes deposit lock root exactly once",
            true,
        ),
        ExpectedRootLane::new(
            "transfer_receipt",
            30,
            "private-transfer-receipt-root",
            "private transfer receipts preserve nullifier uniqueness",
            "transfer receipt root binds sender, receiver, fee, and nullifier set",
            true,
        ),
        ExpectedRootLane::new(
            "contract_receipt",
            40,
            "contract-action-receipt-root",
            "contract receipts expose replayable effects without private metadata",
            "contract receipt root binds call commitment and encrypted effect root",
            true,
        ),
        ExpectedRootLane::new(
            "withdrawal_claim",
            50,
            "withdrawal-claim-root",
            "withdrawal claims consume exit nullifiers once",
            "withdrawal claim root binds owner commitment and piconero amount",
            true,
        ),
        ExpectedRootLane::new(
            "challenge_window",
            60,
            "challenge-dispute-window-root",
            "forced exits remain disputable until the configured challenge window closes",
            "challenge window root binds watcher quorum and expiry height",
            true,
        ),
        ExpectedRootLane::new(
            "adversarial_recovery",
            70,
            "adversarial-recovery-execution-root",
            "receipt withholding and disputed exits fail closed into recovery",
            "recovery root binds hazard class, mitigation step, and watcher attestations",
            true,
        ),
        ExpectedRootLane::new(
            "evidence_acceptance",
            80,
            "evidence-acceptance-root",
            "accepted evidence is canonical, deduplicated, and scope-bound",
            "evidence root binds artifact id, provenance root, and covered invariant",
            true,
        ),
        ExpectedRootLane::new(
            "privacy_budget",
            90,
            "privacy-budget-root",
            "public receipts spend only the configured metadata privacy budget",
            "privacy budget root binds redaction policy and disclosure bit ceiling",
            true,
        ),
        ExpectedRootLane::new(
            "pq_authority",
            100,
            "pq-authority-root",
            "post-quantum authority signatures meet threshold and epoch freshness",
            "PQ authority root binds authority set, threshold, and epoch ttl",
            true,
        ),
        ExpectedRootLane::new(
            "reserve_coverage",
            110,
            "reserve-coverage-root",
            "bridge reserve remains above forced-exit claim coverage floor",
            "reserve coverage root binds locked reserve, pending claims, and floor",
            true,
        ),
        ExpectedRootLane::new(
            "release_blocker",
            120,
            "release-blocker-root",
            "production release is blocked until every vertical slice lane is accepted",
            "release blocker root binds blocking lane set and unresolved evidence count",
            true,
        ),
    ]
}

fn expected_lane_root(
    lane: &str,
    sequence: u64,
    source_artifact: &str,
    invariant: &str,
    acceptance_gate: &str,
    release_blocking: bool,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-lane-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(SCHEMA_VERSION),
            HashPart::Str(lane),
            HashPart::U64(sequence),
            HashPart::Str(source_artifact),
            HashPart::Str(invariant),
            HashPart::Str(acceptance_gate),
            HashPart::Str(if release_blocking {
                "release-blocking"
            } else {
                "non-release-blocking"
            }),
        ],
        32,
    )
}
