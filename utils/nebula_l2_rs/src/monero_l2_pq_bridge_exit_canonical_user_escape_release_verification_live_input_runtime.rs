use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeReleaseVerificationLiveInputRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-release-verification-live-input-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LIVE_INPUT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-release-verification-live-input-v1";
pub const DEFAULT_NETWORK: &str = "devnet";
pub const DEFAULT_ESCAPE_ID: &str = "canonical-user-escape-release-verification-live-devnet-0001";
pub const DEFAULT_HARNESS_ID: &str = "canonical-user-escape-release-verification-harness-devnet-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseVerdict {
    Release,
    Hold,
}

impl ReleaseVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Hold => "hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeWindowState {
    Open,
    Expired,
    Cleared,
    Disputed,
}

impl ChallengeWindowState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Expired => "expired",
            Self::Cleared => "cleared",
            Self::Disputed => "disputed",
        }
    }

    pub fn permits_escape_input(self) -> bool {
        matches!(self, Self::Expired | Self::Cleared)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputReadiness {
    Canonical,
    Blocked,
}

impl InputReadiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub live_input_suite: String,
    pub network: String,
    pub harness_id: String,
    pub min_release_verifier_quorum_weight: u64,
    pub min_pq_custody_quorum_weight: u64,
    pub min_broadcast_confirmations: u64,
    pub min_liquidity_coverage_bps: u64,
    pub challenge_window_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            live_input_suite: LIVE_INPUT_SUITE.to_string(),
            network: DEFAULT_NETWORK.to_string(),
            harness_id: DEFAULT_HARNESS_ID.to_string(),
            min_release_verifier_quorum_weight: 67,
            min_pq_custody_quorum_weight: 67,
            min_broadcast_confirmations: 20,
            min_liquidity_coverage_bps: 10_000,
            challenge_window_blocks: 720,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "live_input_suite": self.live_input_suite,
            "network": self.network,
            "harness_id": self.harness_id,
            "min_release_verifier_quorum_weight": self.min_release_verifier_quorum_weight,
            "min_pq_custody_quorum_weight": self.min_pq_custody_quorum_weight,
            "min_broadcast_confirmations": self.min_broadcast_confirmations,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "challenge_window_blocks": self.challenge_window_blocks
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseVerificationVerdictInput {
    pub escape_id: String,
    pub verdict: ReleaseVerdict,
    pub verifier_set_root: String,
    pub release_verification_manifest_root: String,
    pub evidence_bundle_root: String,
    pub verifier_quorum_weight: u64,
    pub observed_at_l2_height: u64,
}

impl ReleaseVerificationVerdictInput {
    pub fn devnet(config: &Config) -> Self {
        let verifier_set_root = lane_root("release-verifier-set", DEFAULT_ESCAPE_ID);
        let release_verification_manifest_root =
            lane_root("release-verification-manifest", DEFAULT_ESCAPE_ID);
        let evidence_bundle_root = domain_hash(
            "monero-l2-pq-bridge-live-input-release-verdict-evidence",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(DEFAULT_ESCAPE_ID),
                HashPart::Str(&verifier_set_root),
                HashPart::Str(&release_verification_manifest_root),
            ],
            32,
        );

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            verdict: ReleaseVerdict::Release,
            verifier_set_root,
            release_verification_manifest_root,
            evidence_bundle_root,
            verifier_quorum_weight: config.min_release_verifier_quorum_weight,
            observed_at_l2_height: 4_240_016,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.verdict == ReleaseVerdict::Release
            && self.verifier_quorum_weight >= config.min_release_verifier_quorum_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "verdict": self.verdict.as_str(),
            "verifier_set_root": self.verifier_set_root,
            "release_verification_manifest_root": self.release_verification_manifest_root,
            "evidence_bundle_root": self.evidence_bundle_root,
            "verifier_quorum_weight": self.verifier_quorum_weight,
            "observed_at_l2_height": self.observed_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-verification-verdict-input", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqCustodyAttestationInput {
    pub escape_id: String,
    pub custody_attestation_root: String,
    pub custody_authority_root: String,
    pub custody_transcript_root: String,
    pub pq_signature_receipt_root: String,
    pub custody_quorum_weight: u64,
    pub key_epoch: u64,
}

impl PqCustodyAttestationInput {
    pub fn devnet(config: &Config) -> Self {
        let custody_authority_root = lane_root("pq-custody-authority", DEFAULT_ESCAPE_ID);
        let custody_transcript_root = lane_root("pq-custody-transcript", DEFAULT_ESCAPE_ID);
        let pq_signature_receipt_root = lane_root("pq-signature-receipt", DEFAULT_ESCAPE_ID);
        let custody_attestation_root = domain_hash(
            "monero-l2-pq-bridge-live-input-pq-custody-attestation",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(DEFAULT_ESCAPE_ID),
                HashPart::Str(&custody_authority_root),
                HashPart::Str(&custody_transcript_root),
                HashPart::Str(&pq_signature_receipt_root),
            ],
            32,
        );

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            custody_attestation_root,
            custody_authority_root,
            custody_transcript_root,
            pq_signature_receipt_root,
            custody_quorum_weight: config.min_pq_custody_quorum_weight,
            key_epoch: 73,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.custody_quorum_weight >= config.min_pq_custody_quorum_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "custody_attestation_root": self.custody_attestation_root,
            "custody_authority_root": self.custody_authority_root,
            "custody_transcript_root": self.custody_transcript_root,
            "pq_signature_receipt_root": self.pq_signature_receipt_root,
            "custody_quorum_weight": self.custody_quorum_weight,
            "key_epoch": self.key_epoch
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pq-custody-attestation-input", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MoneroBroadcastObservationInput {
    pub escape_id: String,
    pub network: String,
    pub planned_tx_root: String,
    pub observed_tx_root: String,
    pub txid_commitment: String,
    pub watcher_receipt_root: String,
    pub broadcast_height: u64,
    pub observed_height: u64,
    pub confirmations: u64,
}

impl MoneroBroadcastObservationInput {
    pub fn devnet(config: &Config) -> Self {
        let planned_tx_root = lane_root("planned-monero-release-tx", DEFAULT_ESCAPE_ID);
        let observed_height = 3_520_044;
        let broadcast_height = observed_height - config.min_broadcast_confirmations;

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            network: "monero-devnet".to_string(),
            planned_tx_root: planned_tx_root.clone(),
            observed_tx_root: planned_tx_root,
            txid_commitment: lane_root("monero-release-txid", DEFAULT_ESCAPE_ID),
            watcher_receipt_root: lane_root("monero-broadcast-watchers", DEFAULT_ESCAPE_ID),
            broadcast_height,
            observed_height,
            confirmations: observed_height - broadcast_height,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.planned_tx_root == self.observed_tx_root
            && self.confirmations >= config.min_broadcast_confirmations
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "network": self.network,
            "planned_tx_root": self.planned_tx_root,
            "observed_tx_root": self.observed_tx_root,
            "txid_commitment": self.txid_commitment,
            "watcher_receipt_root": self.watcher_receipt_root,
            "broadcast_height": self.broadcast_height,
            "observed_height": self.observed_height,
            "confirmations": self.confirmations
        })
    }

    pub fn state_root(&self) -> String {
        record_root("monero-broadcast-observation-input", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityReleaseEvidenceInput {
    pub escape_id: String,
    pub reserve_snapshot_root: String,
    pub release_allocation_root: String,
    pub fee_receipt_root: String,
    pub coverage_bps: u64,
    pub release_amount_piconero: u64,
    pub observed_at_l2_height: u64,
}

impl LiquidityReleaseEvidenceInput {
    pub fn devnet(config: &Config) -> Self {
        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            reserve_snapshot_root: lane_root("liquidity-reserve-snapshot", DEFAULT_ESCAPE_ID),
            release_allocation_root: lane_root("liquidity-release-allocation", DEFAULT_ESCAPE_ID),
            fee_receipt_root: lane_root("liquidity-release-fee-receipt", DEFAULT_ESCAPE_ID),
            coverage_bps: config.min_liquidity_coverage_bps,
            release_amount_piconero: 2_500_000_000_000,
            observed_at_l2_height: 4_240_018,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.coverage_bps >= config.min_liquidity_coverage_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "release_allocation_root": self.release_allocation_root,
            "fee_receipt_root": self.fee_receipt_root,
            "coverage_bps": self.coverage_bps,
            "release_amount_piconero": self.release_amount_piconero,
            "observed_at_l2_height": self.observed_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        record_root("liquidity-release-evidence-input", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeWindowStatusInput {
    pub escape_id: String,
    pub window_state: ChallengeWindowState,
    pub challenge_set_root: String,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub observed_at_l2_height: u64,
}

impl ChallengeWindowStatusInput {
    pub fn devnet(config: &Config) -> Self {
        let opened_at_l2_height = 4_239_280;
        let expires_at_l2_height = opened_at_l2_height + config.challenge_window_blocks;

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            window_state: ChallengeWindowState::Expired,
            challenge_set_root: empty_set_root("challenge-set"),
            opened_at_l2_height,
            expires_at_l2_height,
            observed_at_l2_height: expires_at_l2_height + 18,
        }
    }

    pub fn accepted(&self) -> bool {
        self.window_state.permits_escape_input()
            && self.observed_at_l2_height >= self.expires_at_l2_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "window_state": self.window_state.as_str(),
            "challenge_set_root": self.challenge_set_root,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "observed_at_l2_height": self.observed_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        record_root("challenge-window-status-input", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CanonicalUserEscapeHarnessInputRecord {
    pub escape_id: String,
    pub harness_id: String,
    pub readiness: InputReadiness,
    pub live_input_root: String,
    pub release_verification_root: String,
    pub pq_custody_root: String,
    pub monero_broadcast_root: String,
    pub liquidity_release_root: String,
    pub challenge_window_root: String,
}

impl CanonicalUserEscapeHarnessInputRecord {
    pub fn from_inputs(
        config: &Config,
        release_verification: &ReleaseVerificationVerdictInput,
        pq_custody: &PqCustodyAttestationInput,
        monero_broadcast: &MoneroBroadcastObservationInput,
        liquidity_release: &LiquidityReleaseEvidenceInput,
        challenge_window: &ChallengeWindowStatusInput,
    ) -> Self {
        let release_verification_root = release_verification.state_root();
        let pq_custody_root = pq_custody.state_root();
        let monero_broadcast_root = monero_broadcast.state_root();
        let liquidity_release_root = liquidity_release.state_root();
        let challenge_window_root = challenge_window.state_root();
        let readiness = if release_verification.accepted(config)
            && pq_custody.accepted(config)
            && monero_broadcast.accepted(config)
            && liquidity_release.accepted(config)
            && challenge_window.accepted()
        {
            InputReadiness::Canonical
        } else {
            InputReadiness::Blocked
        };
        let live_input_root = live_input_root(
            readiness,
            &release_verification_root,
            &pq_custody_root,
            &monero_broadcast_root,
            &liquidity_release_root,
            &challenge_window_root,
        );

        Self {
            escape_id: release_verification.escape_id.clone(),
            harness_id: config.harness_id.clone(),
            readiness,
            live_input_root,
            release_verification_root,
            pq_custody_root,
            monero_broadcast_root,
            liquidity_release_root,
            challenge_window_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "harness_id": self.harness_id,
            "readiness": self.readiness.as_str(),
            "live_input_root": self.live_input_root,
            "release_verification_root": self.release_verification_root,
            "pq_custody_root": self.pq_custody_root,
            "monero_broadcast_root": self.monero_broadcast_root,
            "liquidity_release_root": self.liquidity_release_root,
            "challenge_window_root": self.challenge_window_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "canonical-user-escape-harness-input-record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub release_verification: ReleaseVerificationVerdictInput,
    pub pq_custody: PqCustodyAttestationInput,
    pub monero_broadcast: MoneroBroadcastObservationInput,
    pub liquidity_release: LiquidityReleaseEvidenceInput,
    pub challenge_window: ChallengeWindowStatusInput,
    pub harness_input_record: CanonicalUserEscapeHarnessInputRecord,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let release_verification = ReleaseVerificationVerdictInput::devnet(&config);
        let pq_custody = PqCustodyAttestationInput::devnet(&config);
        let monero_broadcast = MoneroBroadcastObservationInput::devnet(&config);
        let liquidity_release = LiquidityReleaseEvidenceInput::devnet(&config);
        let challenge_window = ChallengeWindowStatusInput::devnet(&config);
        let harness_input_record = CanonicalUserEscapeHarnessInputRecord::from_inputs(
            &config,
            &release_verification,
            &pq_custody,
            &monero_broadcast,
            &liquidity_release,
            &challenge_window,
        );

        Self {
            config,
            release_verification,
            pq_custody,
            monero_broadcast,
            liquidity_release,
            challenge_window,
            harness_input_record,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "live_input_suite": LIVE_INPUT_SUITE,
            "config": self.config.public_record(),
            "release_verification": self.release_verification.public_record(),
            "pq_custody": self.pq_custody.public_record(),
            "monero_broadcast": self.monero_broadcast.public_record(),
            "liquidity_release": self.liquidity_release.public_record(),
            "challenge_window": self.challenge_window.public_record(),
            "harness_input_record": self.harness_input_record.public_record(),
            "input_lane_roots": input_lane_roots(self)
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record_without_state_root())
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

fn input_lane_roots(state: &State) -> Value {
    let records = Vec::from([
        state.release_verification.public_record(),
        state.pq_custody.public_record(),
        state.monero_broadcast.public_record(),
        state.liquidity_release.public_record(),
        state.challenge_window.public_record(),
    ]);

    json!({
        "release_verification_root": state.release_verification.state_root(),
        "pq_custody_root": state.pq_custody.state_root(),
        "monero_broadcast_root": state.monero_broadcast.state_root(),
        "liquidity_release_root": state.liquidity_release.state_root(),
        "challenge_window_root": state.challenge_window.state_root(),
        "canonical_lane_root": merkle_root(
            "monero-l2-pq-bridge-user-escape-release-verification-live-input-lane-root",
            &records
        )
    })
}

fn live_input_root(
    readiness: InputReadiness,
    release_verification_root: &str,
    pq_custody_root: &str,
    monero_broadcast_root: &str,
    liquidity_release_root: &str,
    challenge_window_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-verification-live-input-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(readiness.as_str()),
            HashPart::Str(release_verification_root),
            HashPart::Str(pq_custody_root),
            HashPart::Str(monero_broadcast_root),
            HashPart::Str(liquidity_release_root),
            HashPart::Str(challenge_window_root),
        ],
        32,
    )
}

fn lane_root(kind: &str, escape_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-verification-live-input-lane",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(escape_id),
        ],
        32,
    )
}

fn empty_set_root(kind: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-verification-live-input-empty-set",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-verification-live-input-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
