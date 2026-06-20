use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalPrivacyBudgetRegressionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVACY_BUDGET_REGRESSION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-privacy-budget-regression-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVACY_BUDGET_REGRESSION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const REGRESSION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-privacy-budget-regression-v1";
pub const DEVNET_SCENARIO_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-privacy-budget-regression-devnet";
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 48;
pub const DEFAULT_MAX_SCAN_HINT_BITS: u16 = 12;
pub const DEFAULT_MAX_TIMING_CORRELATION_BPS: u16 = 100;
pub const DEFAULT_MAX_RECEIPT_SHARD_DISCLOSURE: u16 = 2;
pub const DEFAULT_MIN_NULLIFIER_ANONYMITY_SET: u64 = 131_072;
pub const DEFAULT_MIN_KEY_IMAGE_SEPARATION_BITS: u16 = 128;
pub const DEFAULT_MIN_WATCHER_QUORUM: u16 = 4;
pub const DEFAULT_MAX_PUBLIC_WATCHER_FIELDS: u16 = 3;
pub const DEFAULT_MAX_PROBES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Watch,
    Block,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Watch => "watch",
            Self::Block => "block",
        }
    }

    pub fn can_force_exit(self) -> bool {
        matches!(self, Self::Pass)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetSurface {
    MetadataLeakUnits,
    ScanHintExposure,
    DepositExitTiming,
    ReceiptShardDisclosure,
    NullifierKeyImageSeparation,
    WatcherQuorumMetadata,
    ForcedExitRegressionVerdict,
}

impl BudgetSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetadataLeakUnits => "metadata_leak_units",
            Self::ScanHintExposure => "scan_hint_exposure",
            Self::DepositExitTiming => "deposit_exit_timing",
            Self::ReceiptShardDisclosure => "receipt_shard_disclosure",
            Self::NullifierKeyImageSeparation => "nullifier_key_image_separation",
            Self::WatcherQuorumMetadata => "watcher_quorum_metadata",
            Self::ForcedExitRegressionVerdict => "forced_exit_regression_verdict",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub regression_suite: String,
    pub scenario_id: String,
    pub metadata_budget_units: u64,
    pub max_scan_hint_bits: u16,
    pub max_timing_correlation_bps: u16,
    pub max_receipt_shard_disclosure: u16,
    pub min_nullifier_anonymity_set: u64,
    pub min_key_image_separation_bits: u16,
    pub min_watcher_quorum: u16,
    pub max_public_watcher_fields: u16,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub max_probes: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            regression_suite: REGRESSION_SUITE.to_string(),
            scenario_id: DEVNET_SCENARIO_ID.to_string(),
            metadata_budget_units: DEFAULT_METADATA_BUDGET_UNITS,
            max_scan_hint_bits: DEFAULT_MAX_SCAN_HINT_BITS,
            max_timing_correlation_bps: DEFAULT_MAX_TIMING_CORRELATION_BPS,
            max_receipt_shard_disclosure: DEFAULT_MAX_RECEIPT_SHARD_DISCLOSURE,
            min_nullifier_anonymity_set: DEFAULT_MIN_NULLIFIER_ANONYMITY_SET,
            min_key_image_separation_bits: DEFAULT_MIN_KEY_IMAGE_SEPARATION_BITS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            max_public_watcher_fields: DEFAULT_MAX_PUBLIC_WATCHER_FIELDS,
            fail_closed: true,
            production_release_allowed: false,
            max_probes: DEFAULT_MAX_PROBES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "regression_suite": self.regression_suite,
            "scenario_id": self.scenario_id,
            "metadata_budget_units": self.metadata_budget_units,
            "max_scan_hint_bits": self.max_scan_hint_bits,
            "max_timing_correlation_bps": self.max_timing_correlation_bps,
            "max_receipt_shard_disclosure": self.max_receipt_shard_disclosure,
            "min_nullifier_anonymity_set": self.min_nullifier_anonymity_set,
            "min_key_image_separation_bits": self.min_key_image_separation_bits,
            "min_watcher_quorum": self.min_watcher_quorum,
            "max_public_watcher_fields": self.max_public_watcher_fields,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
            "max_probes": self.max_probes,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudgetProbe {
    pub probe_id: String,
    pub surface: BudgetSurface,
    pub verdict: Verdict,
    pub metadata_leak_units: u64,
    pub scan_hint_bits: u16,
    pub deposit_height: u64,
    pub exit_height: u64,
    pub timing_correlation_bps: u16,
    pub receipt_shards_disclosed: u16,
    pub nullifier_anonymity_set: u64,
    pub key_image_separation_bits: u16,
    pub watcher_quorum: u16,
    pub public_watcher_fields: u16,
    pub force_exit_path_enabled: bool,
    pub evidence_root: String,
    pub probe_root: String,
}

impl PrivacyBudgetProbe {
    pub fn devnet(config: &Config, surface: BudgetSurface, ordinal: u64) -> Self {
        let deposit_height = 1_660_000 + ordinal * 17;
        let exit_height = deposit_height + 96 + ordinal * 5;
        let metadata_leak_units = metadata_units(surface, ordinal);
        let scan_hint_bits = scan_hint_bits(surface, ordinal);
        let timing_correlation_bps = timing_correlation_bps(surface, ordinal);
        let receipt_shards_disclosed = receipt_shards_disclosed(surface);
        let nullifier_anonymity_set = nullifier_anonymity_set(surface, ordinal);
        let key_image_separation_bits = key_image_separation_bits(surface);
        let watcher_quorum = watcher_quorum(surface, ordinal);
        let public_watcher_fields = public_watcher_fields(surface);
        let force_exit_path_enabled = true;
        let verdict = classify_probe(
            config,
            metadata_leak_units,
            scan_hint_bits,
            timing_correlation_bps,
            receipt_shards_disclosed,
            nullifier_anonymity_set,
            key_image_separation_bits,
            watcher_quorum,
            public_watcher_fields,
            force_exit_path_enabled,
        );
        let evidence_root = evidence_root(
            surface,
            metadata_leak_units,
            scan_hint_bits,
            timing_correlation_bps,
            receipt_shards_disclosed,
            watcher_quorum,
        );
        let probe_id = probe_id(&config.scenario_id, surface, ordinal);
        let probe_root = record_root(
            "probe",
            &json!({
                "probe_id": probe_id,
                "surface": surface.as_str(),
                "verdict": verdict.as_str(),
                "evidence_root": evidence_root,
            }),
        );
        Self {
            probe_id,
            surface,
            verdict,
            metadata_leak_units,
            scan_hint_bits,
            deposit_height,
            exit_height,
            timing_correlation_bps,
            receipt_shards_disclosed,
            nullifier_anonymity_set,
            key_image_separation_bits,
            watcher_quorum,
            public_watcher_fields,
            force_exit_path_enabled,
            evidence_root,
            probe_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "probe_id": self.probe_id,
            "surface": self.surface.as_str(),
            "verdict": self.verdict.as_str(),
            "metadata_leak_units": self.metadata_leak_units,
            "scan_hint_bits": self.scan_hint_bits,
            "deposit_height": self.deposit_height,
            "exit_height": self.exit_height,
            "timing_correlation_bps": self.timing_correlation_bps,
            "receipt_shards_disclosed": self.receipt_shards_disclosed,
            "nullifier_anonymity_set": self.nullifier_anonymity_set,
            "key_image_separation_bits": self.key_image_separation_bits,
            "watcher_quorum": self.watcher_quorum,
            "public_watcher_fields": self.public_watcher_fields,
            "force_exit_path_enabled": self.force_exit_path_enabled,
            "evidence_root": self.evidence_root,
            "probe_root": self.probe_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub probes: Vec<PrivacyBudgetProbe>,
    pub answer: ForceExitPrivacyAnswer,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let surfaces = [
            BudgetSurface::MetadataLeakUnits,
            BudgetSurface::ScanHintExposure,
            BudgetSurface::DepositExitTiming,
            BudgetSurface::ReceiptShardDisclosure,
            BudgetSurface::NullifierKeyImageSeparation,
            BudgetSurface::WatcherQuorumMetadata,
            BudgetSurface::ForcedExitRegressionVerdict,
        ];
        let probes = surfaces
            .iter()
            .enumerate()
            .map(|(index, surface)| PrivacyBudgetProbe::devnet(&config, *surface, index as u64))
            .collect::<Vec<_>>();
        let answer = ForceExitPrivacyAnswer::from_probes(&config, &probes);
        Self {
            config,
            probes,
            answer,
        }
    }

    pub fn public_record(&self) -> Value {
        let probe_records = self
            .probes
            .iter()
            .map(PrivacyBudgetProbe::public_record)
            .collect::<Vec<_>>();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "answer": self.answer.public_record(),
            "roots": {
                "config_root": self.config.state_root(),
                "probe_root": self.probe_root(),
                "answer_root": self.answer.state_root(),
            },
            "probes": probe_records,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "state",
            &json!({
                "config_root": self.config.state_root(),
                "probe_root": self.probe_root(),
                "answer_root": self.answer.state_root(),
            }),
        )
    }

    pub fn probe_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVACY-BUDGET-PROBE-ROOT",
            &self
                .probes
                .iter()
                .map(PrivacyBudgetProbe::public_record)
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForceExitPrivacyAnswer {
    pub can_force_exit_without_unacceptable_metadata: bool,
    pub verdict: Verdict,
    pub fail_closed: bool,
    pub blocking_surfaces: Vec<String>,
    pub watched_surfaces: Vec<String>,
    pub total_metadata_leak_units: u64,
    pub max_scan_hint_bits: u16,
    pub max_timing_correlation_bps: u16,
    pub max_receipt_shards_disclosed: u16,
    pub min_nullifier_anonymity_set: u64,
    pub min_key_image_separation_bits: u16,
    pub min_watcher_quorum: u16,
    pub answer_root: String,
}

impl ForceExitPrivacyAnswer {
    pub fn from_probes(config: &Config, probes: &[PrivacyBudgetProbe]) -> Self {
        let blocking_surfaces = probes
            .iter()
            .filter(|probe| probe.verdict == Verdict::Block)
            .map(|probe| probe.surface.as_str().to_string())
            .collect::<Vec<_>>();
        let watched_surfaces = probes
            .iter()
            .filter(|probe| probe.verdict == Verdict::Watch)
            .map(|probe| probe.surface.as_str().to_string())
            .collect::<Vec<_>>();
        let total_metadata_leak_units = probes
            .iter()
            .map(|probe| probe.metadata_leak_units)
            .sum::<u64>();
        let max_scan_hint_bits = probes
            .iter()
            .map(|probe| probe.scan_hint_bits)
            .max()
            .unwrap_or(0);
        let max_timing_correlation_bps = probes
            .iter()
            .map(|probe| probe.timing_correlation_bps)
            .max()
            .unwrap_or(0);
        let max_receipt_shards_disclosed = probes
            .iter()
            .map(|probe| probe.receipt_shards_disclosed)
            .max()
            .unwrap_or(0);
        let min_nullifier_anonymity_set = probes
            .iter()
            .map(|probe| probe.nullifier_anonymity_set)
            .min()
            .unwrap_or(0);
        let min_key_image_separation_bits = probes
            .iter()
            .map(|probe| probe.key_image_separation_bits)
            .min()
            .unwrap_or(0);
        let min_watcher_quorum = probes
            .iter()
            .map(|probe| probe.watcher_quorum)
            .min()
            .unwrap_or(0);
        let has_unknown = probes.is_empty() || probes.len() > config.max_probes;
        let force_exit_path_enabled = probes.iter().all(|probe| probe.force_exit_path_enabled);
        let aggregate_budget_ok = total_metadata_leak_units <= config.metadata_budget_units;
        let verdict = if !blocking_surfaces.is_empty()
            || !aggregate_budget_ok
            || !force_exit_path_enabled
            || (config.fail_closed && has_unknown)
        {
            Verdict::Block
        } else if !watched_surfaces.is_empty() {
            Verdict::Watch
        } else {
            Verdict::Pass
        };
        let can_force_exit_without_unacceptable_metadata =
            verdict.can_force_exit() && aggregate_budget_ok && force_exit_path_enabled;
        let answer_root = record_root(
            "answer",
            &json!({
                "verdict": verdict.as_str(),
                "can_force_exit_without_unacceptable_metadata": can_force_exit_without_unacceptable_metadata,
                "total_metadata_leak_units": total_metadata_leak_units,
                "blocking_surfaces": blocking_surfaces,
                "watched_surfaces": watched_surfaces,
            }),
        );
        Self {
            can_force_exit_without_unacceptable_metadata,
            verdict,
            fail_closed: config.fail_closed,
            blocking_surfaces,
            watched_surfaces,
            total_metadata_leak_units,
            max_scan_hint_bits,
            max_timing_correlation_bps,
            max_receipt_shards_disclosed,
            min_nullifier_anonymity_set,
            min_key_image_separation_bits,
            min_watcher_quorum,
            answer_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "can_force_exit_without_unacceptable_metadata": self.can_force_exit_without_unacceptable_metadata,
            "verdict": self.verdict.as_str(),
            "fail_closed": self.fail_closed,
            "blocking_surfaces": self.blocking_surfaces,
            "watched_surfaces": self.watched_surfaces,
            "total_metadata_leak_units": self.total_metadata_leak_units,
            "max_scan_hint_bits": self.max_scan_hint_bits,
            "max_timing_correlation_bps": self.max_timing_correlation_bps,
            "max_receipt_shards_disclosed": self.max_receipt_shards_disclosed,
            "min_nullifier_anonymity_set": self.min_nullifier_anonymity_set,
            "min_key_image_separation_bits": self.min_key_image_separation_bits,
            "min_watcher_quorum": self.min_watcher_quorum,
            "answer_root": self.answer_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("force-exit-privacy-answer", &self.public_record())
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

fn classify_probe(
    config: &Config,
    metadata_leak_units: u64,
    scan_hint_bits: u16,
    timing_correlation_bps: u16,
    receipt_shards_disclosed: u16,
    nullifier_anonymity_set: u64,
    key_image_separation_bits: u16,
    watcher_quorum: u16,
    public_watcher_fields: u16,
    force_exit_path_enabled: bool,
) -> Verdict {
    let blocks = metadata_leak_units > config.metadata_budget_units
        || scan_hint_bits > config.max_scan_hint_bits
        || timing_correlation_bps > config.max_timing_correlation_bps
        || receipt_shards_disclosed > config.max_receipt_shard_disclosure
        || nullifier_anonymity_set < config.min_nullifier_anonymity_set
        || key_image_separation_bits < config.min_key_image_separation_bits
        || watcher_quorum < config.min_watcher_quorum
        || public_watcher_fields > config.max_public_watcher_fields
        || !force_exit_path_enabled;
    if blocks {
        Verdict::Block
    } else if metadata_leak_units * 4 >= config.metadata_budget_units * 3 {
        Verdict::Watch
    } else {
        Verdict::Pass
    }
}

fn metadata_units(surface: BudgetSurface, ordinal: u64) -> u64 {
    (match surface {
        BudgetSurface::MetadataLeakUnits => 7,
        BudgetSurface::ScanHintExposure => 5,
        BudgetSurface::DepositExitTiming => 6,
        BudgetSurface::ReceiptShardDisclosure => 4,
        BudgetSurface::NullifierKeyImageSeparation => 3,
        BudgetSurface::WatcherQuorumMetadata => 6,
        BudgetSurface::ForcedExitRegressionVerdict => 5,
    }) + ordinal % 2
}

fn scan_hint_bits(surface: BudgetSurface, ordinal: u64) -> u16 {
    (match surface {
        BudgetSurface::ScanHintExposure => 10,
        BudgetSurface::MetadataLeakUnits => 6,
        BudgetSurface::DepositExitTiming => 4,
        BudgetSurface::ReceiptShardDisclosure => 3,
        BudgetSurface::NullifierKeyImageSeparation => 2,
        BudgetSurface::WatcherQuorumMetadata => 5,
        BudgetSurface::ForcedExitRegressionVerdict => 4,
    }) + (ordinal % 2) as u16
}

fn timing_correlation_bps(surface: BudgetSurface, ordinal: u64) -> u16 {
    (match surface {
        BudgetSurface::DepositExitTiming => 88,
        BudgetSurface::MetadataLeakUnits => 42,
        BudgetSurface::ScanHintExposure => 54,
        BudgetSurface::ReceiptShardDisclosure => 30,
        BudgetSurface::NullifierKeyImageSeparation => 18,
        BudgetSurface::WatcherQuorumMetadata => 45,
        BudgetSurface::ForcedExitRegressionVerdict => 36,
    }) + (ordinal % 3) as u16
}

fn receipt_shards_disclosed(surface: BudgetSurface) -> u16 {
    match surface {
        BudgetSurface::ReceiptShardDisclosure => 2,
        BudgetSurface::WatcherQuorumMetadata => 1,
        _ => 0,
    }
}

fn nullifier_anonymity_set(surface: BudgetSurface, ordinal: u64) -> u64 {
    match surface {
        BudgetSurface::NullifierKeyImageSeparation => 262_144,
        BudgetSurface::ForcedExitRegressionVerdict => 196_608,
        _ => 180_224 + ordinal * 1_024,
    }
}

fn key_image_separation_bits(surface: BudgetSurface) -> u16 {
    match surface {
        BudgetSurface::NullifierKeyImageSeparation => 192,
        _ => 160,
    }
}

fn watcher_quorum(surface: BudgetSurface, ordinal: u64) -> u16 {
    match surface {
        BudgetSurface::WatcherQuorumMetadata => 5,
        _ => 4 + (ordinal % 2) as u16,
    }
}

fn public_watcher_fields(surface: BudgetSurface) -> u16 {
    match surface {
        BudgetSurface::WatcherQuorumMetadata => 3,
        BudgetSurface::ForcedExitRegressionVerdict => 2,
        _ => 1,
    }
}

fn probe_id(scenario_id: &str, surface: BudgetSurface, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVACY-BUDGET-PROBE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scenario_id),
            HashPart::Str(surface.as_str()),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn evidence_root(
    surface: BudgetSurface,
    metadata_leak_units: u64,
    scan_hint_bits: u16,
    timing_correlation_bps: u16,
    receipt_shards_disclosed: u16,
    watcher_quorum: u16,
) -> String {
    record_root(
        "evidence",
        &json!({
            "surface": surface.as_str(),
            "metadata_leak_units": metadata_leak_units,
            "scan_hint_bits": scan_hint_bits,
            "timing_correlation_bps": timing_correlation_bps,
            "receipt_shards_disclosed": receipt_shards_disclosed,
            "watcher_quorum": watcher_quorum,
        }),
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVACY-BUDGET-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
