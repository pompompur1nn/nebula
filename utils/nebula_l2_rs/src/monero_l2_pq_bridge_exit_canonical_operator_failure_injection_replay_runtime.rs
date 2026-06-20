use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalOperatorFailureInjectionReplayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_OPERATOR_FAILURE_INJECTION_REPLAY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-operator-failure-injection-replay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_OPERATOR_FAILURE_INJECTION_REPLAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FAILURE_INJECTION_REPLAY_SUITE: &str =
    "canonical-bridge-forced-exit-operator-failure-injection-replay-v1";
pub const DEFAULT_MAX_SEQUENCER_SILENCE_BLOCKS: u64 = 16;
pub const DEFAULT_MAX_RECEIPT_WITHHOLD_BLOCKS: u64 = 8;
pub const DEFAULT_RELEASE_BATCH_GRACE_BLOCKS: u64 = 4;
pub const DEFAULT_MAX_PQ_EPOCH_LAG: u64 = 1;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MAX_COLLUDING_WATCHER_WEIGHT_BPS: u16 = 3_300;
pub const DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS: u16 = 10_000;
pub const DEFAULT_FEE_CAP_BPS: u16 = 8;
pub const DEFAULT_MAX_PUBLIC_METADATA_FIELDS: u16 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    SequencerSilence,
    ReceiptWithholding,
    InvalidReleaseBatch,
    WatcherCollusion,
    StalePqEpoch,
    LiquidityExhaustion,
    FeeGriefing,
    MetadataProbing,
    ForcedExitResponse,
}

impl FailureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerSilence => "sequencer_silence",
            Self::ReceiptWithholding => "receipt_withholding",
            Self::InvalidReleaseBatch => "invalid_release_batch",
            Self::WatcherCollusion => "watcher_collusion",
            Self::StalePqEpoch => "stale_pq_epoch",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::FeeGriefing => "fee_griefing",
            Self::MetadataProbing => "metadata_probing",
            Self::ForcedExitResponse => "forced_exit_response",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForcedExitResponse {
    FailOpenEscapeAvailable,
    FailClosedReleaseRejected,
}

impl ForcedExitResponse {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailOpenEscapeAvailable => "fail_open_escape_available",
            Self::FailClosedReleaseRejected => "fail_closed_release_rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub replay_suite: String,
    pub max_sequencer_silence_blocks: u64,
    pub max_receipt_withhold_blocks: u64,
    pub release_batch_grace_blocks: u64,
    pub max_pq_epoch_lag: u64,
    pub min_watcher_quorum: u64,
    pub max_colluding_watcher_weight_bps: u16,
    pub min_liquidity_coverage_bps: u16,
    pub fee_cap_bps: u16,
    pub max_public_metadata_fields: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            replay_suite: FAILURE_INJECTION_REPLAY_SUITE.to_string(),
            max_sequencer_silence_blocks: DEFAULT_MAX_SEQUENCER_SILENCE_BLOCKS,
            max_receipt_withhold_blocks: DEFAULT_MAX_RECEIPT_WITHHOLD_BLOCKS,
            release_batch_grace_blocks: DEFAULT_RELEASE_BATCH_GRACE_BLOCKS,
            max_pq_epoch_lag: DEFAULT_MAX_PQ_EPOCH_LAG,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            max_colluding_watcher_weight_bps: DEFAULT_MAX_COLLUDING_WATCHER_WEIGHT_BPS,
            min_liquidity_coverage_bps: DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS,
            fee_cap_bps: DEFAULT_FEE_CAP_BPS,
            max_public_metadata_fields: DEFAULT_MAX_PUBLIC_METADATA_FIELDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "replay_suite": self.replay_suite,
            "max_sequencer_silence_blocks": self.max_sequencer_silence_blocks,
            "max_receipt_withhold_blocks": self.max_receipt_withhold_blocks,
            "release_batch_grace_blocks": self.release_batch_grace_blocks,
            "max_pq_epoch_lag": self.max_pq_epoch_lag,
            "min_watcher_quorum": self.min_watcher_quorum,
            "max_colluding_watcher_weight_bps": self.max_colluding_watcher_weight_bps,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "fee_cap_bps": self.fee_cap_bps,
            "max_public_metadata_fields": self.max_public_metadata_fields,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InjectionCase {
    pub case_id: String,
    pub mode: FailureMode,
    pub injected_at_l2_height: u64,
    pub observed_blocks: u64,
    pub watcher_quorum: u64,
    pub colluding_watcher_weight_bps: u16,
    pub pq_epoch: u64,
    pub canonical_pq_epoch: u64,
    pub liquidity_coverage_bps: u16,
    pub fee_bps: u16,
    pub public_metadata_fields: u16,
    pub transcript_root: String,
    pub evidence_root: String,
    pub expected_response: ForcedExitResponse,
    pub user_escape_available: bool,
    pub answer: String,
}

impl InjectionCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "mode": self.mode.as_str(),
            "injected_at_l2_height": self.injected_at_l2_height,
            "observed_blocks": self.observed_blocks,
            "watcher_quorum": self.watcher_quorum,
            "colluding_watcher_weight_bps": self.colluding_watcher_weight_bps,
            "pq_epoch": self.pq_epoch,
            "canonical_pq_epoch": self.canonical_pq_epoch,
            "liquidity_coverage_bps": self.liquidity_coverage_bps,
            "fee_bps": self.fee_bps,
            "public_metadata_fields": self.public_metadata_fields,
            "transcript_root": self.transcript_root,
            "evidence_root": self.evidence_root,
            "expected_response": self.expected_response.as_str(),
            "user_escape_available": self.user_escape_available,
            "answer": self.answer,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("injection_case", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub cases: Vec<InjectionCase>,
    pub escape_available_cases: u64,
    pub fail_open_cases: u64,
    pub fail_closed_cases: u64,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let cases = devnet_cases(&config);
        let escape_available_cases = cases
            .iter()
            .filter(|case| case.user_escape_available)
            .count() as u64;
        let fail_open_cases = cases
            .iter()
            .filter(|case| case.expected_response == ForcedExitResponse::FailOpenEscapeAvailable)
            .count() as u64;
        let fail_closed_cases = cases.len() as u64 - fail_open_cases;

        Self {
            config,
            cases,
            escape_available_cases,
            fail_open_cases,
            fail_closed_cases,
        }
    }

    pub fn public_record(&self) -> Value {
        let case_records: Vec<Value> = self
            .cases
            .iter()
            .map(InjectionCase::public_record)
            .collect();
        json!({
            "config": self.config.public_record(),
            "cases": case_records,
            "case_root": self.case_root(),
            "escape_available_cases": self.escape_available_cases,
            "fail_open_cases": self.fail_open_cases,
            "fail_closed_cases": self.fail_closed_cases,
        })
    }

    pub fn case_root(&self) -> String {
        let records: Vec<Value> = self
            .cases
            .iter()
            .map(InjectionCase::public_record)
            .collect();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-OPERATOR-FAILURE-INJECTION-CASE",
            &records,
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-OPERATOR-FAILURE-INJECTION-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.case_root()),
                HashPart::U64(self.escape_available_cases),
                HashPart::U64(self.fail_open_cases),
                HashPart::U64(self.fail_closed_cases),
            ],
            32,
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

pub fn devnet_cases(config: &Config) -> Vec<InjectionCase> {
    let base_height = 2_404_800;
    let canonical_pq_epoch = 144;
    vec![
        injection_case(
            config,
            FailureMode::SequencerSilence,
            base_height,
            config.max_sequencer_silence_blocks + 5,
            config.min_watcher_quorum,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            11_800,
            4,
            2,
        ),
        injection_case(
            config,
            FailureMode::ReceiptWithholding,
            base_height + 12,
            config.max_receipt_withhold_blocks + 3,
            config.min_watcher_quorum,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            11_200,
            4,
            2,
        ),
        injection_case(
            config,
            FailureMode::InvalidReleaseBatch,
            base_height + 24,
            config.release_batch_grace_blocks,
            config.min_watcher_quorum,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            10_900,
            5,
            2,
        ),
        injection_case(
            config,
            FailureMode::WatcherCollusion,
            base_height + 36,
            3,
            config.min_watcher_quorum,
            config.max_colluding_watcher_weight_bps + 900,
            canonical_pq_epoch,
            canonical_pq_epoch,
            10_700,
            5,
            2,
        ),
        injection_case(
            config,
            FailureMode::StalePqEpoch,
            base_height + 48,
            2,
            config.min_watcher_quorum,
            0,
            canonical_pq_epoch - config.max_pq_epoch_lag - 2,
            canonical_pq_epoch,
            11_500,
            4,
            2,
        ),
        injection_case(
            config,
            FailureMode::LiquidityExhaustion,
            base_height + 60,
            2,
            config.min_watcher_quorum,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            config.min_liquidity_coverage_bps - 1_700,
            4,
            2,
        ),
        injection_case(
            config,
            FailureMode::FeeGriefing,
            base_height + 72,
            2,
            config.min_watcher_quorum,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            10_900,
            config.fee_cap_bps + 37,
            2,
        ),
        injection_case(
            config,
            FailureMode::MetadataProbing,
            base_height + 84,
            2,
            config.min_watcher_quorum,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            11_100,
            4,
            config.max_public_metadata_fields + 6,
        ),
        injection_case(
            config,
            FailureMode::ForcedExitResponse,
            base_height + 96,
            config.max_sequencer_silence_blocks + 1,
            config.min_watcher_quorum,
            0,
            canonical_pq_epoch,
            canonical_pq_epoch,
            10_800,
            4,
            2,
        ),
    ]
}

pub fn injection_case(
    config: &Config,
    mode: FailureMode,
    injected_at_l2_height: u64,
    observed_blocks: u64,
    watcher_quorum: u64,
    colluding_watcher_weight_bps: u16,
    pq_epoch: u64,
    canonical_pq_epoch: u64,
    liquidity_coverage_bps: u16,
    fee_bps: u16,
    public_metadata_fields: u16,
) -> InjectionCase {
    let transcript_root = labeled_root(mode.as_str(), "transcript", injected_at_l2_height);
    let evidence_root = labeled_root(mode.as_str(), "evidence", observed_blocks);
    let expected_response = derive_expected_response(
        config,
        mode,
        observed_blocks,
        watcher_quorum,
        colluding_watcher_weight_bps,
        pq_epoch,
        canonical_pq_epoch,
        liquidity_coverage_bps,
        fee_bps,
        public_metadata_fields,
    );
    let user_escape_available = derive_escape_available(
        mode,
        expected_response,
        observed_blocks,
        config.max_sequencer_silence_blocks,
        liquidity_coverage_bps,
        config.min_liquidity_coverage_bps,
    );
    let case_id = case_id(mode, &transcript_root, &evidence_root);
    let answer = escape_answer(mode, expected_response, user_escape_available);

    InjectionCase {
        case_id,
        mode,
        injected_at_l2_height,
        observed_blocks,
        watcher_quorum,
        colluding_watcher_weight_bps,
        pq_epoch,
        canonical_pq_epoch,
        liquidity_coverage_bps,
        fee_bps,
        public_metadata_fields,
        transcript_root,
        evidence_root,
        expected_response,
        user_escape_available,
        answer,
    }
}

pub fn derive_expected_response(
    config: &Config,
    mode: FailureMode,
    observed_blocks: u64,
    watcher_quorum: u64,
    colluding_watcher_weight_bps: u16,
    pq_epoch: u64,
    canonical_pq_epoch: u64,
    liquidity_coverage_bps: u16,
    fee_bps: u16,
    public_metadata_fields: u16,
) -> ForcedExitResponse {
    let epoch_lag = canonical_pq_epoch.saturating_sub(pq_epoch);
    let fail_closed = watcher_quorum < config.min_watcher_quorum
        || colluding_watcher_weight_bps > config.max_colluding_watcher_weight_bps
        || epoch_lag > config.max_pq_epoch_lag
        || liquidity_coverage_bps < config.min_liquidity_coverage_bps
        || fee_bps > config.fee_cap_bps
        || public_metadata_fields > config.max_public_metadata_fields
        || matches!(
            mode,
            FailureMode::InvalidReleaseBatch
                | FailureMode::WatcherCollusion
                | FailureMode::StalePqEpoch
                | FailureMode::LiquidityExhaustion
                | FailureMode::FeeGriefing
                | FailureMode::MetadataProbing
        );
    if fail_closed {
        return ForcedExitResponse::FailClosedReleaseRejected;
    }
    if matches!(mode, FailureMode::SequencerSilence)
        && observed_blocks > config.max_sequencer_silence_blocks
    {
        return ForcedExitResponse::FailOpenEscapeAvailable;
    }
    if matches!(mode, FailureMode::ReceiptWithholding)
        && observed_blocks > config.max_receipt_withhold_blocks
    {
        return ForcedExitResponse::FailOpenEscapeAvailable;
    }
    ForcedExitResponse::FailOpenEscapeAvailable
}

pub fn derive_escape_available(
    mode: FailureMode,
    expected_response: ForcedExitResponse,
    observed_blocks: u64,
    max_silence_blocks: u64,
    liquidity_coverage_bps: u16,
    min_liquidity_coverage_bps: u16,
) -> bool {
    match expected_response {
        ForcedExitResponse::FailOpenEscapeAvailable => true,
        ForcedExitResponse::FailClosedReleaseRejected => {
            matches!(
                mode,
                FailureMode::InvalidReleaseBatch
                    | FailureMode::WatcherCollusion
                    | FailureMode::StalePqEpoch
                    | FailureMode::FeeGriefing
                    | FailureMode::MetadataProbing
            ) || (mode == FailureMode::LiquidityExhaustion
                && liquidity_coverage_bps < min_liquidity_coverage_bps
                && observed_blocks <= max_silence_blocks)
        }
    }
}

pub fn escape_answer(
    mode: FailureMode,
    expected_response: ForcedExitResponse,
    user_escape_available: bool,
) -> String {
    let availability = if user_escape_available { "yes" } else { "no" };
    format!(
        "{availability}: {} maps to {} under canonical forced-exit replay",
        mode.as_str(),
        expected_response.as_str()
    )
}

pub fn case_id(mode: FailureMode, transcript_root: &str, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-OPERATOR-FAILURE-INJECTION-CASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(mode.as_str()),
            HashPart::Str(transcript_root),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn labeled_root(mode: &str, label: &str, value: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-OPERATOR-FAILURE-INJECTION-LABELED-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(mode),
            HashPart::Str(label),
            HashPart::U64(value),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-OPERATOR-FAILURE-INJECTION-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
