use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeReleaseVerificationLiveHandlerBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-release-verification-live-handler-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HANDLER_BINDING_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-release-verification-live-handler-binding-v1";
pub const LIVE_INPUT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-release-verification-live-input-v1";
pub const DEFAULT_NETWORK: &str = "devnet";
pub const DEFAULT_ESCAPE_ID: &str = "canonical-user-escape-release-verification-live-devnet-0001";
pub const DEFAULT_HARNESS_ID: &str = "canonical-user-escape-release-verification-harness-devnet-v1";
pub const DEFAULT_HANDLER_SESSION_ID: &str =
    "canonical-user-escape-release-verification-handler-binding-devnet-session-0001";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Bound,
    Rejected,
}

impl BindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerVerdict {
    Release,
    Hold,
}

impl HandlerVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Hold => "hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerOutcome {
    Accepted,
    Rejected,
}

impl HandlerOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeWindowObservationState {
    Open,
    Expired,
    Cleared,
    Disputed,
}

impl ChallengeWindowObservationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Expired => "expired",
            Self::Cleared => "cleared",
            Self::Disputed => "disputed",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Expired | Self::Cleared)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub handler_binding_suite: String,
    pub live_input_suite: String,
    pub network: String,
    pub harness_id: String,
    pub handler_session_id: String,
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
            handler_binding_suite: HANDLER_BINDING_SUITE.to_string(),
            live_input_suite: LIVE_INPUT_SUITE.to_string(),
            network: DEFAULT_NETWORK.to_string(),
            harness_id: DEFAULT_HARNESS_ID.to_string(),
            handler_session_id: DEFAULT_HANDLER_SESSION_ID.to_string(),
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
            "handler_binding_suite": self.handler_binding_suite,
            "live_input_suite": self.live_input_suite,
            "network": self.network,
            "harness_id": self.harness_id,
            "handler_session_id": self.handler_session_id,
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
pub struct LiveInputRecord {
    pub escape_id: String,
    pub release_verification_root: String,
    pub pq_custody_root: String,
    pub monero_broadcast_root: String,
    pub liquidity_release_root: String,
    pub challenge_window_root: String,
    pub live_input_root: String,
}

impl LiveInputRecord {
    pub fn devnet() -> Self {
        let release_verification_root =
            live_input_lane_root("release-verification", DEFAULT_ESCAPE_ID);
        let pq_custody_root = live_input_lane_root("pq-custody", DEFAULT_ESCAPE_ID);
        let monero_broadcast_root = live_input_lane_root("monero-broadcast", DEFAULT_ESCAPE_ID);
        let liquidity_release_root = live_input_lane_root("liquidity-release", DEFAULT_ESCAPE_ID);
        let challenge_window_root = live_input_lane_root("challenge-window", DEFAULT_ESCAPE_ID);
        let live_input_root = domain_hash(
            "monero-l2-pq-bridge-user-escape-release-verification-handler-binding-live-input-root",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(DEFAULT_ESCAPE_ID),
                HashPart::Str(&release_verification_root),
                HashPart::Str(&pq_custody_root),
                HashPart::Str(&monero_broadcast_root),
                HashPart::Str(&liquidity_release_root),
                HashPart::Str(&challenge_window_root),
            ],
            32,
        );

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            release_verification_root,
            pq_custody_root,
            monero_broadcast_root,
            liquidity_release_root,
            challenge_window_root,
            live_input_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "release_verification_root": self.release_verification_root,
            "pq_custody_root": self.pq_custody_root,
            "monero_broadcast_root": self.monero_broadcast_root,
            "liquidity_release_root": self.liquidity_release_root,
            "challenge_window_root": self.challenge_window_root,
            "live_input_root": self.live_input_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live-input-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseVerifierOutputObservation {
    pub escape_id: String,
    pub handler_id: String,
    pub handler_output_root: String,
    pub live_input_root: String,
    pub verdict: HandlerVerdict,
    pub verifier_set_root: String,
    pub verifier_quorum_weight: u64,
    pub evidence_bundle_root: String,
    pub observed_at_l2_height: u64,
}

impl ReleaseVerifierOutputObservation {
    pub fn devnet(config: &Config, live_input: &LiveInputRecord) -> Self {
        let verifier_set_root = handler_lane_root("release-verifier-set", DEFAULT_ESCAPE_ID);
        let evidence_bundle_root =
            handler_lane_root("release-verifier-evidence", DEFAULT_ESCAPE_ID);
        let handler_output_root = domain_hash(
            "monero-l2-pq-bridge-handler-binding-release-verifier-output",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(DEFAULT_ESCAPE_ID),
                HashPart::Str(&live_input.release_verification_root),
                HashPart::Str(&verifier_set_root),
                HashPart::Str(&evidence_bundle_root),
            ],
            32,
        );

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            handler_id: "release-verifier-output-handler-devnet-0001".to_string(),
            handler_output_root,
            live_input_root: live_input.release_verification_root.clone(),
            verdict: HandlerVerdict::Release,
            verifier_set_root,
            verifier_quorum_weight: config.min_release_verifier_quorum_weight,
            evidence_bundle_root,
            observed_at_l2_height: 4_240_016,
        }
    }

    pub fn accepted(&self, config: &Config, live_input: &LiveInputRecord) -> bool {
        self.escape_id == live_input.escape_id
            && self.live_input_root == live_input.release_verification_root
            && self.verdict == HandlerVerdict::Release
            && self.verifier_quorum_weight >= config.min_release_verifier_quorum_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "handler_id": self.handler_id,
            "handler_output_root": self.handler_output_root,
            "live_input_root": self.live_input_root,
            "verdict": self.verdict.as_str(),
            "verifier_set_root": self.verifier_set_root,
            "verifier_quorum_weight": self.verifier_quorum_weight,
            "evidence_bundle_root": self.evidence_bundle_root,
            "observed_at_l2_height": self.observed_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-verifier-output-observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqCustodyAttestationHandlerObservation {
    pub escape_id: String,
    pub handler_id: String,
    pub handler_output_root: String,
    pub live_input_root: String,
    pub custody_attestation_root: String,
    pub custody_authority_root: String,
    pub custody_transcript_root: String,
    pub pq_signature_receipt_root: String,
    pub custody_quorum_weight: u64,
    pub key_epoch: u64,
}

impl PqCustodyAttestationHandlerObservation {
    pub fn devnet(config: &Config, live_input: &LiveInputRecord) -> Self {
        let custody_authority_root = handler_lane_root("pq-custody-authority", DEFAULT_ESCAPE_ID);
        let custody_transcript_root = handler_lane_root("pq-custody-transcript", DEFAULT_ESCAPE_ID);
        let pq_signature_receipt_root =
            handler_lane_root("pq-signature-receipt", DEFAULT_ESCAPE_ID);
        let custody_attestation_root = domain_hash(
            "monero-l2-pq-bridge-handler-binding-pq-custody-attestation",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(DEFAULT_ESCAPE_ID),
                HashPart::Str(&live_input.pq_custody_root),
                HashPart::Str(&custody_authority_root),
                HashPart::Str(&custody_transcript_root),
                HashPart::Str(&pq_signature_receipt_root),
            ],
            32,
        );

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            handler_id: "pq-custody-attestation-handler-devnet-0001".to_string(),
            handler_output_root: custody_attestation_root.clone(),
            live_input_root: live_input.pq_custody_root.clone(),
            custody_attestation_root,
            custody_authority_root,
            custody_transcript_root,
            pq_signature_receipt_root,
            custody_quorum_weight: config.min_pq_custody_quorum_weight,
            key_epoch: 73,
        }
    }

    pub fn accepted(&self, config: &Config, live_input: &LiveInputRecord) -> bool {
        self.escape_id == live_input.escape_id
            && self.live_input_root == live_input.pq_custody_root
            && self.custody_quorum_weight >= config.min_pq_custody_quorum_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "handler_id": self.handler_id,
            "handler_output_root": self.handler_output_root,
            "live_input_root": self.live_input_root,
            "custody_attestation_root": self.custody_attestation_root,
            "custody_authority_root": self.custody_authority_root,
            "custody_transcript_root": self.custody_transcript_root,
            "pq_signature_receipt_root": self.pq_signature_receipt_root,
            "custody_quorum_weight": self.custody_quorum_weight,
            "key_epoch": self.key_epoch
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "pq-custody-attestation-handler-observation",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MoneroBroadcastHandlerObservation {
    pub escape_id: String,
    pub handler_id: String,
    pub handler_output_root: String,
    pub live_input_root: String,
    pub network: String,
    pub planned_tx_root: String,
    pub observed_tx_root: String,
    pub txid_commitment: String,
    pub watcher_receipt_root: String,
    pub broadcast_height: u64,
    pub observed_height: u64,
    pub confirmations: u64,
}

impl MoneroBroadcastHandlerObservation {
    pub fn devnet(config: &Config, live_input: &LiveInputRecord) -> Self {
        let planned_tx_root = handler_lane_root("planned-monero-release-tx", DEFAULT_ESCAPE_ID);
        let observed_height = 3_520_044;
        let broadcast_height = observed_height.saturating_sub(config.min_broadcast_confirmations);
        let watcher_receipt_root =
            handler_lane_root("monero-broadcast-watchers", DEFAULT_ESCAPE_ID);
        let handler_output_root = domain_hash(
            "monero-l2-pq-bridge-handler-binding-monero-broadcast",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(DEFAULT_ESCAPE_ID),
                HashPart::Str(&live_input.monero_broadcast_root),
                HashPart::Str(&planned_tx_root),
                HashPart::Str(&watcher_receipt_root),
            ],
            32,
        );

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            handler_id: "monero-broadcast-handler-devnet-0001".to_string(),
            handler_output_root,
            live_input_root: live_input.monero_broadcast_root.clone(),
            network: "monero-devnet".to_string(),
            planned_tx_root: planned_tx_root.clone(),
            observed_tx_root: planned_tx_root,
            txid_commitment: handler_lane_root("monero-release-txid", DEFAULT_ESCAPE_ID),
            watcher_receipt_root,
            broadcast_height,
            observed_height,
            confirmations: observed_height.saturating_sub(broadcast_height),
        }
    }

    pub fn accepted(&self, config: &Config, live_input: &LiveInputRecord) -> bool {
        self.escape_id == live_input.escape_id
            && self.live_input_root == live_input.monero_broadcast_root
            && self.planned_tx_root == self.observed_tx_root
            && self.confirmations >= config.min_broadcast_confirmations
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "handler_id": self.handler_id,
            "handler_output_root": self.handler_output_root,
            "live_input_root": self.live_input_root,
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
        record_root(
            "monero-broadcast-handler-observation",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityReleaseHandlerObservation {
    pub escape_id: String,
    pub handler_id: String,
    pub handler_output_root: String,
    pub live_input_root: String,
    pub reserve_snapshot_root: String,
    pub release_allocation_root: String,
    pub fee_receipt_root: String,
    pub coverage_bps: u64,
    pub release_amount_piconero: u64,
    pub observed_at_l2_height: u64,
}

impl LiquidityReleaseHandlerObservation {
    pub fn devnet(config: &Config, live_input: &LiveInputRecord) -> Self {
        let reserve_snapshot_root =
            handler_lane_root("liquidity-reserve-snapshot", DEFAULT_ESCAPE_ID);
        let release_allocation_root =
            handler_lane_root("liquidity-release-allocation", DEFAULT_ESCAPE_ID);
        let fee_receipt_root =
            handler_lane_root("liquidity-release-fee-receipt", DEFAULT_ESCAPE_ID);
        let handler_output_root = domain_hash(
            "monero-l2-pq-bridge-handler-binding-liquidity-release",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(DEFAULT_ESCAPE_ID),
                HashPart::Str(&live_input.liquidity_release_root),
                HashPart::Str(&reserve_snapshot_root),
                HashPart::Str(&release_allocation_root),
                HashPart::Str(&fee_receipt_root),
            ],
            32,
        );

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            handler_id: "liquidity-release-handler-devnet-0001".to_string(),
            handler_output_root,
            live_input_root: live_input.liquidity_release_root.clone(),
            reserve_snapshot_root,
            release_allocation_root,
            fee_receipt_root,
            coverage_bps: config.min_liquidity_coverage_bps,
            release_amount_piconero: 2_500_000_000_000,
            observed_at_l2_height: 4_240_018,
        }
    }

    pub fn accepted(&self, config: &Config, live_input: &LiveInputRecord) -> bool {
        self.escape_id == live_input.escape_id
            && self.live_input_root == live_input.liquidity_release_root
            && self.coverage_bps >= config.min_liquidity_coverage_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "handler_id": self.handler_id,
            "handler_output_root": self.handler_output_root,
            "live_input_root": self.live_input_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "release_allocation_root": self.release_allocation_root,
            "fee_receipt_root": self.fee_receipt_root,
            "coverage_bps": self.coverage_bps,
            "release_amount_piconero": self.release_amount_piconero,
            "observed_at_l2_height": self.observed_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "liquidity-release-handler-observation",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeWindowHandlerObservation {
    pub escape_id: String,
    pub handler_id: String,
    pub handler_output_root: String,
    pub live_input_root: String,
    pub window_state: ChallengeWindowObservationState,
    pub challenge_set_root: String,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub observed_at_l2_height: u64,
}

impl ChallengeWindowHandlerObservation {
    pub fn devnet(config: &Config, live_input: &LiveInputRecord) -> Self {
        let opened_at_l2_height = 4_239_280;
        let expires_at_l2_height = opened_at_l2_height + config.challenge_window_blocks;
        let challenge_set_root = empty_set_root("challenge-set");
        let handler_output_root = domain_hash(
            "monero-l2-pq-bridge-handler-binding-challenge-window",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(DEFAULT_ESCAPE_ID),
                HashPart::Str(&live_input.challenge_window_root),
                HashPart::Str(&challenge_set_root),
                HashPart::Int(expires_at_l2_height as i128),
            ],
            32,
        );

        Self {
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            handler_id: "challenge-window-handler-devnet-0001".to_string(),
            handler_output_root,
            live_input_root: live_input.challenge_window_root.clone(),
            window_state: ChallengeWindowObservationState::Expired,
            challenge_set_root,
            opened_at_l2_height,
            expires_at_l2_height,
            observed_at_l2_height: expires_at_l2_height + 18,
        }
    }

    pub fn accepted(&self, live_input: &LiveInputRecord) -> bool {
        self.escape_id == live_input.escape_id
            && self.live_input_root == live_input.challenge_window_root
            && self.window_state.permits_release()
            && self.observed_at_l2_height >= self.expires_at_l2_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "handler_id": self.handler_id,
            "handler_output_root": self.handler_output_root,
            "live_input_root": self.live_input_root,
            "window_state": self.window_state.as_str(),
            "challenge_set_root": self.challenge_set_root,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "observed_at_l2_height": self.observed_at_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "challenge-window-handler-observation",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveHandlerBindingRecord {
    pub escape_id: String,
    pub harness_id: String,
    pub handler_session_id: String,
    pub status: BindingStatus,
    pub live_input_record_root: String,
    pub release_verifier_output_root: String,
    pub pq_custody_attestation_handler_root: String,
    pub monero_broadcast_handler_root: String,
    pub liquidity_release_handler_root: String,
    pub challenge_window_handler_root: String,
    pub binding_root: String,
}

impl LiveHandlerBindingRecord {
    pub fn from_observations(
        config: &Config,
        live_input: &LiveInputRecord,
        release_verifier_output: &ReleaseVerifierOutputObservation,
        pq_custody_attestation: &PqCustodyAttestationHandlerObservation,
        monero_broadcast: &MoneroBroadcastHandlerObservation,
        liquidity_release: &LiquidityReleaseHandlerObservation,
        challenge_window: &ChallengeWindowHandlerObservation,
    ) -> Self {
        let live_input_record_root = live_input.state_root();
        let release_verifier_output_root = release_verifier_output.state_root();
        let pq_custody_attestation_handler_root = pq_custody_attestation.state_root();
        let monero_broadcast_handler_root = monero_broadcast.state_root();
        let liquidity_release_handler_root = liquidity_release.state_root();
        let challenge_window_handler_root = challenge_window.state_root();
        let status = if release_verifier_output.accepted(config, live_input)
            && pq_custody_attestation.accepted(config, live_input)
            && monero_broadcast.accepted(config, live_input)
            && liquidity_release.accepted(config, live_input)
            && challenge_window.accepted(live_input)
        {
            BindingStatus::Bound
        } else {
            BindingStatus::Rejected
        };
        let binding_root = binding_root(
            status,
            &live_input_record_root,
            &release_verifier_output_root,
            &pq_custody_attestation_handler_root,
            &monero_broadcast_handler_root,
            &liquidity_release_handler_root,
            &challenge_window_handler_root,
        );

        Self {
            escape_id: live_input.escape_id.clone(),
            harness_id: config.harness_id.clone(),
            handler_session_id: config.handler_session_id.clone(),
            status,
            live_input_record_root,
            release_verifier_output_root,
            pq_custody_attestation_handler_root,
            monero_broadcast_handler_root,
            liquidity_release_handler_root,
            challenge_window_handler_root,
            binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "harness_id": self.harness_id,
            "handler_session_id": self.handler_session_id,
            "status": self.status.as_str(),
            "live_input_record_root": self.live_input_record_root,
            "release_verifier_output_root": self.release_verifier_output_root,
            "pq_custody_attestation_handler_root": self.pq_custody_attestation_handler_root,
            "monero_broadcast_handler_root": self.monero_broadcast_handler_root,
            "liquidity_release_handler_root": self.liquidity_release_handler_root,
            "challenge_window_handler_root": self.challenge_window_handler_root,
            "binding_root": self.binding_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live-handler-binding-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub live_input: LiveInputRecord,
    pub release_verifier_output: ReleaseVerifierOutputObservation,
    pub pq_custody_attestation: PqCustodyAttestationHandlerObservation,
    pub monero_broadcast: MoneroBroadcastHandlerObservation,
    pub liquidity_release: LiquidityReleaseHandlerObservation,
    pub challenge_window: ChallengeWindowHandlerObservation,
    pub binding_record: LiveHandlerBindingRecord,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let live_input = LiveInputRecord::devnet();
        let release_verifier_output =
            ReleaseVerifierOutputObservation::devnet(&config, &live_input);
        let pq_custody_attestation =
            PqCustodyAttestationHandlerObservation::devnet(&config, &live_input);
        let monero_broadcast = MoneroBroadcastHandlerObservation::devnet(&config, &live_input);
        let liquidity_release = LiquidityReleaseHandlerObservation::devnet(&config, &live_input);
        let challenge_window = ChallengeWindowHandlerObservation::devnet(&config, &live_input);
        let binding_record = LiveHandlerBindingRecord::from_observations(
            &config,
            &live_input,
            &release_verifier_output,
            &pq_custody_attestation,
            &monero_broadcast,
            &liquidity_release,
            &challenge_window,
        );

        Self {
            config,
            live_input,
            release_verifier_output,
            pq_custody_attestation,
            monero_broadcast,
            liquidity_release,
            challenge_window,
            binding_record,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "handler_binding_suite": HANDLER_BINDING_SUITE,
            "live_input_suite": LIVE_INPUT_SUITE,
            "config": self.config.public_record(),
            "live_input": self.live_input.public_record(),
            "release_verifier_output": self.release_verifier_output.public_record(),
            "pq_custody_attestation": self.pq_custody_attestation.public_record(),
            "monero_broadcast": self.monero_broadcast.public_record(),
            "liquidity_release": self.liquidity_release.public_record(),
            "challenge_window": self.challenge_window.public_record(),
            "binding_record": self.binding_record.public_record(),
            "handler_observation_roots": handler_observation_roots(self)
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

fn handler_observation_roots(state: &State) -> Value {
    let records = Vec::from([
        state.release_verifier_output.public_record(),
        state.pq_custody_attestation.public_record(),
        state.monero_broadcast.public_record(),
        state.liquidity_release.public_record(),
        state.challenge_window.public_record(),
    ]);

    json!({
        "release_verifier_output_root": state.release_verifier_output.state_root(),
        "pq_custody_attestation_handler_root": state.pq_custody_attestation.state_root(),
        "monero_broadcast_handler_root": state.monero_broadcast.state_root(),
        "liquidity_release_handler_root": state.liquidity_release.state_root(),
        "challenge_window_handler_root": state.challenge_window.state_root(),
        "canonical_handler_observation_root": merkle_root(
            "monero-l2-pq-bridge-user-escape-release-verification-live-handler-observation-root",
            &records
        )
    })
}

fn binding_root(
    status: BindingStatus,
    live_input_record_root: &str,
    release_verifier_output_root: &str,
    pq_custody_attestation_handler_root: &str,
    monero_broadcast_handler_root: &str,
    liquidity_release_handler_root: &str,
    challenge_window_handler_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-verification-live-handler-binding-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(status.as_str()),
            HashPart::Str(live_input_record_root),
            HashPart::Str(release_verifier_output_root),
            HashPart::Str(pq_custody_attestation_handler_root),
            HashPart::Str(monero_broadcast_handler_root),
            HashPart::Str(liquidity_release_handler_root),
            HashPart::Str(challenge_window_handler_root),
        ],
        32,
    )
}

fn live_input_lane_root(kind: &str, escape_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-verification-live-handler-binding-input-lane",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(LIVE_INPUT_SUITE),
            HashPart::Str(kind),
            HashPart::Str(escape_id),
        ],
        32,
    )
}

fn handler_lane_root(kind: &str, escape_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-verification-live-handler-binding-handler-lane",
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
        "monero-l2-pq-bridge-user-escape-release-verification-live-handler-binding-empty-set",
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
        "monero-l2-pq-bridge-user-escape-release-verification-live-handler-binding-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
