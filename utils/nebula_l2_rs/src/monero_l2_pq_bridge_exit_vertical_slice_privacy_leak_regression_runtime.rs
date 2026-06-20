use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitVerticalSlicePrivacyLeakRegressionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_PRIVACY_LEAK_REGRESSION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-vertical-slice-privacy-leak-regression-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_PRIVACY_LEAK_REGRESSION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const REGRESSION_SUITE: &str = "monero-l2-pq-bridge-exit-privacy-leak-regression-manifest-v1";
pub const DEVNET_MANIFEST_ID: &str = "monero-l2-pq-bridge-exit-privacy-leak-regression-devnet";
pub const DEFAULT_MIN_PASS_CHECKS: u64 = 8;
pub const DEFAULT_MAX_WATCH_CHECKS: u64 = 2;
pub const DEFAULT_MAX_BLOCK_CHECKS: u64 = 0;
pub const DEFAULT_MAX_TIMING_LINKABILITY_BPS: u16 = 125;
pub const DEFAULT_MAX_AMOUNT_BUCKET_LEAKAGE_BPS: u16 = 100;
pub const DEFAULT_MAX_WALLET_HINT_BITS: u16 = 12;
pub const DEFAULT_MIN_RECEIPT_ROOT_DEPTH: u16 = 32;
pub const DEFAULT_MIN_NULLIFIER_ANONYMITY_SET: u64 = 65_536;
pub const DEFAULT_MIN_WATCHER_EVIDENCE_QUORUM: u16 = 4;
pub const DEFAULT_MAX_FORCED_EXIT_DISCLOSURE_FIELDS: u16 = 5;
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 42;
pub const DEFAULT_MAX_MANIFEST_CHECKS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Watch,
    Block,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Watch => "watch",
            Self::Block => "block",
        }
    }

    pub fn release_compatible(self) -> bool {
        matches!(self, Self::Pass | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakSurface {
    DepositExitTiming,
    AmountBucket,
    WalletScanHint,
    EncryptedReceiptRoot,
    NullifierKeyImage,
    WatcherEvidence,
    ForcedExitDisclosure,
    CrossSurfaceCorrelation,
}

impl LeakSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositExitTiming => "deposit_exit_timing",
            Self::AmountBucket => "amount_bucket",
            Self::WalletScanHint => "wallet_scan_hint",
            Self::EncryptedReceiptRoot => "encrypted_receipt_root",
            Self::NullifierKeyImage => "nullifier_key_image",
            Self::WatcherEvidence => "watcher_evidence",
            Self::ForcedExitDisclosure => "forced_exit_disclosure",
            Self::CrossSurfaceCorrelation => "cross_surface_correlation",
        }
    }

    pub fn metadata_weight(self) -> u64 {
        match self {
            Self::DepositExitTiming => 8,
            Self::AmountBucket => 7,
            Self::WalletScanHint => 6,
            Self::EncryptedReceiptRoot => 5,
            Self::NullifierKeyImage => 9,
            Self::WatcherEvidence => 4,
            Self::ForcedExitDisclosure => 6,
            Self::CrossSurfaceCorrelation => 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureMode {
    RootsOnly,
    BoundedMetadata,
    WatcherChallenge,
    EmergencyForcedExit,
}

impl DisclosureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootsOnly => "roots_only",
            Self::BoundedMetadata => "bounded_metadata",
            Self::WatcherChallenge => "watcher_challenge",
            Self::EmergencyForcedExit => "emergency_forced_exit",
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
    pub manifest_id: String,
    pub min_pass_checks: u64,
    pub max_watch_checks: u64,
    pub max_block_checks: u64,
    pub max_timing_linkability_bps: u16,
    pub max_amount_bucket_leakage_bps: u16,
    pub max_wallet_hint_bits: u16,
    pub min_receipt_root_depth: u16,
    pub min_nullifier_anonymity_set: u64,
    pub min_watcher_evidence_quorum: u16,
    pub max_forced_exit_disclosure_fields: u16,
    pub metadata_budget_units: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_manifest_checks: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            regression_suite: REGRESSION_SUITE.to_string(),
            manifest_id: DEVNET_MANIFEST_ID.to_string(),
            min_pass_checks: DEFAULT_MIN_PASS_CHECKS,
            max_watch_checks: DEFAULT_MAX_WATCH_CHECKS,
            max_block_checks: DEFAULT_MAX_BLOCK_CHECKS,
            max_timing_linkability_bps: DEFAULT_MAX_TIMING_LINKABILITY_BPS,
            max_amount_bucket_leakage_bps: DEFAULT_MAX_AMOUNT_BUCKET_LEAKAGE_BPS,
            max_wallet_hint_bits: DEFAULT_MAX_WALLET_HINT_BITS,
            min_receipt_root_depth: DEFAULT_MIN_RECEIPT_ROOT_DEPTH,
            min_nullifier_anonymity_set: DEFAULT_MIN_NULLIFIER_ANONYMITY_SET,
            min_watcher_evidence_quorum: DEFAULT_MIN_WATCHER_EVIDENCE_QUORUM,
            max_forced_exit_disclosure_fields: DEFAULT_MAX_FORCED_EXIT_DISCLOSURE_FIELDS,
            metadata_budget_units: DEFAULT_METADATA_BUDGET_UNITS,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_manifest_checks: DEFAULT_MAX_MANIFEST_CHECKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "regression_suite": self.regression_suite,
            "manifest_id": self.manifest_id,
            "min_pass_checks": self.min_pass_checks,
            "max_watch_checks": self.max_watch_checks,
            "max_block_checks": self.max_block_checks,
            "max_timing_linkability_bps": self.max_timing_linkability_bps,
            "max_amount_bucket_leakage_bps": self.max_amount_bucket_leakage_bps,
            "max_wallet_hint_bits": self.max_wallet_hint_bits,
            "min_receipt_root_depth": self.min_receipt_root_depth,
            "min_nullifier_anonymity_set": self.min_nullifier_anonymity_set,
            "min_watcher_evidence_quorum": self.min_watcher_evidence_quorum,
            "max_forced_exit_disclosure_fields": self.max_forced_exit_disclosure_fields,
            "metadata_budget_units": self.metadata_budget_units,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_manifest_checks": self.max_manifest_checks,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyLeakProbe {
    pub probe_id: String,
    pub surface: LeakSurface,
    pub status: CheckStatus,
    pub disclosure_mode: DisclosureMode,
    pub deposit_height: u64,
    pub exit_height: u64,
    pub timing_linkability_bps: u16,
    pub amount_bucket_leakage_bps: u16,
    pub wallet_hint_bits: u16,
    pub encrypted_receipt_root_depth: u16,
    pub nullifier_anonymity_set: u64,
    pub watcher_evidence_quorum: u16,
    pub forced_exit_disclosure_fields: u16,
    pub metadata_units: u64,
    pub evidence_root: String,
    pub public_root: String,
}

impl PrivacyLeakProbe {
    pub fn devnet(
        config: &Config,
        surface: LeakSurface,
        disclosure_mode: DisclosureMode,
        ordinal: u64,
    ) -> Self {
        let deposit_height = 1_552_000 + ordinal * 12;
        let exit_height = deposit_height + 72 + ordinal * 3;
        let timing_linkability_bps = timing_score(surface, ordinal);
        let amount_bucket_leakage_bps = amount_score(surface, ordinal);
        let wallet_hint_bits = wallet_hint_bits(surface, ordinal);
        let encrypted_receipt_root_depth = receipt_root_depth(surface);
        let nullifier_anonymity_set = nullifier_anonymity_set(surface, ordinal);
        let watcher_evidence_quorum = watcher_evidence_quorum(surface, ordinal);
        let forced_exit_disclosure_fields = forced_exit_disclosure_fields(disclosure_mode);
        let metadata_units = surface.metadata_weight()
            + u64::from(wallet_hint_bits)
            + u64::from(forced_exit_disclosure_fields);
        let status = classify_probe(
            config,
            timing_linkability_bps,
            amount_bucket_leakage_bps,
            wallet_hint_bits,
            encrypted_receipt_root_depth,
            nullifier_anonymity_set,
            watcher_evidence_quorum,
            forced_exit_disclosure_fields,
            metadata_units,
        );
        let evidence_root = probe_evidence_root(
            surface,
            disclosure_mode,
            deposit_height,
            exit_height,
            timing_linkability_bps,
            amount_bucket_leakage_bps,
            wallet_hint_bits,
        );
        let public_root = probe_public_root(
            status,
            surface,
            disclosure_mode,
            &evidence_root,
            encrypted_receipt_root_depth,
            nullifier_anonymity_set,
            watcher_evidence_quorum,
            metadata_units,
        );
        let probe_id = probe_id(surface, ordinal, &public_root);
        Self {
            probe_id,
            surface,
            status,
            disclosure_mode,
            deposit_height,
            exit_height,
            timing_linkability_bps,
            amount_bucket_leakage_bps,
            wallet_hint_bits,
            encrypted_receipt_root_depth,
            nullifier_anonymity_set,
            watcher_evidence_quorum,
            forced_exit_disclosure_fields,
            metadata_units,
            evidence_root,
            public_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "probe_id": self.probe_id,
            "surface": self.surface.as_str(),
            "status": self.status.as_str(),
            "disclosure_mode": self.disclosure_mode.as_str(),
            "deposit_height": self.deposit_height,
            "exit_height": self.exit_height,
            "timing_linkability_bps": self.timing_linkability_bps,
            "amount_bucket_leakage_bps": self.amount_bucket_leakage_bps,
            "wallet_hint_bits": self.wallet_hint_bits,
            "encrypted_receipt_root_depth": self.encrypted_receipt_root_depth,
            "nullifier_anonymity_set": self.nullifier_anonymity_set,
            "watcher_evidence_quorum": self.watcher_evidence_quorum,
            "forced_exit_disclosure_fields": self.forced_exit_disclosure_fields,
            "metadata_units": self.metadata_units,
            "evidence_root": self.evidence_root,
            "public_root": self.public_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("probe", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetadataBudget {
    pub budget_id: String,
    pub status: CheckStatus,
    pub total_units: u64,
    pub budget_units: u64,
    pub timing_units: u64,
    pub amount_units: u64,
    pub wallet_hint_units: u64,
    pub receipt_root_units: u64,
    pub nullifier_units: u64,
    pub watcher_units: u64,
    pub forced_exit_units: u64,
    pub budget_root: String,
}

impl MetadataBudget {
    pub fn from_probes(config: &Config, probes: &[PrivacyLeakProbe]) -> Self {
        let timing_units = units_for_surface(probes, LeakSurface::DepositExitTiming);
        let amount_units = units_for_surface(probes, LeakSurface::AmountBucket);
        let wallet_hint_units = units_for_surface(probes, LeakSurface::WalletScanHint);
        let receipt_root_units = units_for_surface(probes, LeakSurface::EncryptedReceiptRoot);
        let nullifier_units = units_for_surface(probes, LeakSurface::NullifierKeyImage);
        let watcher_units = units_for_surface(probes, LeakSurface::WatcherEvidence);
        let forced_exit_units = units_for_surface(probes, LeakSurface::ForcedExitDisclosure);
        let total_units = probes
            .iter()
            .map(|probe| probe.metadata_units)
            .max()
            .unwrap_or(0);
        let status = if total_units <= config.metadata_budget_units {
            CheckStatus::Pass
        } else if total_units <= config.metadata_budget_units + 8 {
            CheckStatus::Watch
        } else {
            CheckStatus::Block
        };
        let budget_root = metadata_budget_root(
            status,
            total_units,
            config.metadata_budget_units,
            timing_units,
            amount_units,
            wallet_hint_units,
            receipt_root_units,
            nullifier_units,
            watcher_units,
            forced_exit_units,
        );
        let budget_id = short_id("budget", &budget_root);
        Self {
            budget_id,
            status,
            total_units,
            budget_units: config.metadata_budget_units,
            timing_units,
            amount_units,
            wallet_hint_units,
            receipt_root_units,
            nullifier_units,
            watcher_units,
            forced_exit_units,
            budget_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "status": self.status.as_str(),
            "total_units": self.total_units,
            "budget_units": self.budget_units,
            "timing_units": self.timing_units,
            "amount_units": self.amount_units,
            "wallet_hint_units": self.wallet_hint_units,
            "receipt_root_units": self.receipt_root_units,
            "nullifier_units": self.nullifier_units,
            "watcher_units": self.watcher_units,
            "forced_exit_units": self.forced_exit_units,
            "budget_root": self.budget_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("metadata-budget", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegressionManifest {
    pub manifest_id: String,
    pub status: CheckStatus,
    pub pass_count: u64,
    pub watch_count: u64,
    pub block_count: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub metadata_budget: MetadataBudget,
    pub probe_root: String,
    pub manifest_root: String,
}

impl RegressionManifest {
    pub fn from_probes(config: &Config, probes: &[PrivacyLeakProbe]) -> Self {
        let pass_count = probes
            .iter()
            .filter(|probe| probe.status == CheckStatus::Pass)
            .count() as u64;
        let watch_count = probes
            .iter()
            .filter(|probe| probe.status == CheckStatus::Watch)
            .count() as u64;
        let block_count = probes
            .iter()
            .filter(|probe| probe.status == CheckStatus::Block)
            .count() as u64;
        let metadata_budget = MetadataBudget::from_probes(config, probes);
        let status = classify_manifest(
            config,
            pass_count,
            watch_count,
            block_count,
            metadata_budget.status,
        );
        let probe_root = probes_root(probes);
        let manifest_root = regression_manifest_root(
            &config.manifest_id,
            status,
            pass_count,
            watch_count,
            block_count,
            &probe_root,
            &metadata_budget.budget_root,
            config.cargo_checks_deferred,
            config.production_release_allowed,
        );
        Self {
            manifest_id: config.manifest_id.clone(),
            status,
            pass_count,
            watch_count,
            block_count,
            cargo_checks_deferred: config.cargo_checks_deferred,
            production_release_allowed: config.production_release_allowed,
            metadata_budget,
            probe_root,
            manifest_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "status": self.status.as_str(),
            "pass_count": self.pass_count,
            "watch_count": self.watch_count,
            "block_count": self.block_count,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "metadata_budget": self.metadata_budget.public_record(),
            "probe_root": self.probe_root,
            "manifest_root": self.manifest_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("manifest", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub probes: BTreeMap<String, PrivacyLeakProbe>,
    pub manifest: RegressionManifest,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let probes = devnet_probes(&config);
        let manifest = RegressionManifest::from_probes(&config, &probes);
        let probe_map = probes
            .into_iter()
            .map(|probe| (probe.probe_id.clone(), probe))
            .collect::<BTreeMap<_, _>>();
        let state_root = state_root_for(&config, &probe_map, &manifest);
        Self {
            config,
            probes: probe_map,
            manifest,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let probes = self
            .probes
            .values()
            .map(PrivacyLeakProbe::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "probes": probes,
            "manifest": self.manifest.public_record(),
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_for(&self.config, &self.probes, &self.manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.config.cargo_checks_deferred != true {
            return Err(
                "cargo checks must remain deferred for this regression manifest".to_string(),
            );
        }
        if self.config.production_release_allowed != false {
            return Err("production release must remain blocked by manifest metadata".to_string());
        }
        if self.probes.len() > self.config.max_manifest_checks {
            return Err("privacy leak probe count exceeds configured manifest cap".to_string());
        }
        if self.manifest.block_count > self.config.max_block_checks {
            return Err("blocking privacy leak probe present in manifest".to_string());
        }
        if self.manifest.watch_count > self.config.max_watch_checks {
            return Err("watch privacy leak probe budget exceeded".to_string());
        }
        if self.manifest.pass_count < self.config.min_pass_checks {
            return Err("privacy leak pass floor not reached".to_string());
        }
        if self.manifest.metadata_budget.status == CheckStatus::Block {
            return Err("metadata budget blocks the privacy leak manifest".to_string());
        }
        if self.state_root != self.state_root() {
            return Err("state root does not match canonical public record".to_string());
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

pub fn config_root(config: &Config) -> String {
    config.state_root()
}

pub fn probe_root(probe: &PrivacyLeakProbe) -> String {
    probe.state_root()
}

pub fn manifest_root(manifest: &RegressionManifest) -> String {
    manifest.state_root()
}

pub fn metadata_budget_state_root(metadata_budget: &MetadataBudget) -> String {
    metadata_budget.state_root()
}

pub fn probes_root(probes: &[PrivacyLeakProbe]) -> String {
    let leaves = probes
        .iter()
        .map(PrivacyLeakProbe::public_record)
        .collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-LEAK-PROBES", &leaves)
}

fn devnet_probes(config: &Config) -> Vec<PrivacyLeakProbe> {
    let surfaces = [
        LeakSurface::DepositExitTiming,
        LeakSurface::AmountBucket,
        LeakSurface::WalletScanHint,
        LeakSurface::EncryptedReceiptRoot,
        LeakSurface::NullifierKeyImage,
        LeakSurface::WatcherEvidence,
        LeakSurface::ForcedExitDisclosure,
        LeakSurface::CrossSurfaceCorrelation,
        LeakSurface::DepositExitTiming,
        LeakSurface::NullifierKeyImage,
    ];
    surfaces
        .iter()
        .enumerate()
        .map(|(index, surface)| {
            let mode = match index % 4 {
                0 => DisclosureMode::RootsOnly,
                1 => DisclosureMode::BoundedMetadata,
                2 => DisclosureMode::WatcherChallenge,
                _ => DisclosureMode::EmergencyForcedExit,
            };
            PrivacyLeakProbe::devnet(config, *surface, mode, index as u64)
        })
        .collect()
}

fn classify_probe(
    config: &Config,
    timing_linkability_bps: u16,
    amount_bucket_leakage_bps: u16,
    wallet_hint_bits: u16,
    encrypted_receipt_root_depth: u16,
    nullifier_anonymity_set: u64,
    watcher_evidence_quorum: u16,
    forced_exit_disclosure_fields: u16,
    metadata_units: u64,
) -> CheckStatus {
    let timing_ok = timing_linkability_bps <= config.max_timing_linkability_bps;
    let amount_ok = amount_bucket_leakage_bps <= config.max_amount_bucket_leakage_bps;
    let hint_ok = wallet_hint_bits <= config.max_wallet_hint_bits;
    let receipt_ok = encrypted_receipt_root_depth >= config.min_receipt_root_depth;
    let nullifier_ok = nullifier_anonymity_set >= config.min_nullifier_anonymity_set;
    let watcher_ok = watcher_evidence_quorum >= config.min_watcher_evidence_quorum;
    let forced_exit_ok = forced_exit_disclosure_fields <= config.max_forced_exit_disclosure_fields;
    let budget_ok = metadata_units <= config.metadata_budget_units;
    let passed = [
        timing_ok,
        amount_ok,
        hint_ok,
        receipt_ok,
        nullifier_ok,
        watcher_ok,
        forced_exit_ok,
        budget_ok,
    ]
    .iter()
    .filter(|value| **value)
    .count();
    if passed == 8 {
        CheckStatus::Pass
    } else if passed >= 6 {
        CheckStatus::Watch
    } else {
        CheckStatus::Block
    }
}

fn classify_manifest(
    config: &Config,
    pass_count: u64,
    watch_count: u64,
    block_count: u64,
    budget_status: CheckStatus,
) -> CheckStatus {
    if block_count > config.max_block_checks || budget_status == CheckStatus::Block {
        CheckStatus::Block
    } else if pass_count < config.min_pass_checks || watch_count > config.max_watch_checks {
        CheckStatus::Watch
    } else {
        CheckStatus::Pass
    }
}

fn timing_score(surface: LeakSurface, ordinal: u64) -> u16 {
    match surface {
        LeakSurface::DepositExitTiming => 92 + ordinal as u16,
        LeakSurface::CrossSurfaceCorrelation => 118,
        LeakSurface::ForcedExitDisclosure => 104,
        _ => 72 + (ordinal as u16 % 9),
    }
}

fn amount_score(surface: LeakSurface, ordinal: u64) -> u16 {
    match surface {
        LeakSurface::AmountBucket => 83,
        LeakSurface::CrossSurfaceCorrelation => 96,
        LeakSurface::DepositExitTiming => 76,
        _ => 48 + (ordinal as u16 % 7),
    }
}

fn wallet_hint_bits(surface: LeakSurface, ordinal: u64) -> u16 {
    match surface {
        LeakSurface::WalletScanHint => 10,
        LeakSurface::CrossSurfaceCorrelation => 12,
        LeakSurface::ForcedExitDisclosure => 9,
        _ => 4 + (ordinal as u16 % 3),
    }
}

fn receipt_root_depth(surface: LeakSurface) -> u16 {
    match surface {
        LeakSurface::EncryptedReceiptRoot => 40,
        LeakSurface::CrossSurfaceCorrelation => 36,
        _ => 32,
    }
}

fn nullifier_anonymity_set(surface: LeakSurface, ordinal: u64) -> u64 {
    match surface {
        LeakSurface::NullifierKeyImage => 98_304 + ordinal * 512,
        LeakSurface::CrossSurfaceCorrelation => 81_920,
        _ => 65_536 + ordinal * 256,
    }
}

fn watcher_evidence_quorum(surface: LeakSurface, ordinal: u64) -> u16 {
    match surface {
        LeakSurface::WatcherEvidence => 6,
        LeakSurface::ForcedExitDisclosure => 5,
        _ => 4 + (ordinal as u16 % 2),
    }
}

fn forced_exit_disclosure_fields(mode: DisclosureMode) -> u16 {
    match mode {
        DisclosureMode::RootsOnly => 2,
        DisclosureMode::BoundedMetadata => 4,
        DisclosureMode::WatcherChallenge => 5,
        DisclosureMode::EmergencyForcedExit => 5,
    }
}

fn units_for_surface(probes: &[PrivacyLeakProbe], surface: LeakSurface) -> u64 {
    probes
        .iter()
        .filter(|probe| probe.surface == surface)
        .map(|probe| probe.metadata_units)
        .max()
        .unwrap_or(0)
}

fn state_root_for(
    config: &Config,
    probes: &BTreeMap<String, PrivacyLeakProbe>,
    manifest: &RegressionManifest,
) -> String {
    let probe_records = probes
        .values()
        .map(PrivacyLeakProbe::public_record)
        .collect::<Vec<_>>();
    let probe_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-LEAK-STATE-PROBES",
        &probe_records,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-LEAK-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&probe_root),
            HashPart::Str(&manifest.state_root()),
        ],
        32,
    )
}

fn probe_id(surface: LeakSurface, ordinal: u64, root: &str) -> String {
    format!(
        "privacy-leak-{}-{}-{}",
        surface.as_str(),
        ordinal,
        &root[..12]
    )
}

fn short_id(prefix: &str, root: &str) -> String {
    format!("{prefix}-{}", &root[..16])
}

fn record_root(record_kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-LEAK-RECORD",
        &[HashPart::Str(record_kind), HashPart::Json(record)],
        32,
    )
}

fn probe_evidence_root(
    surface: LeakSurface,
    mode: DisclosureMode,
    deposit_height: u64,
    exit_height: u64,
    timing_linkability_bps: u16,
    amount_bucket_leakage_bps: u16,
    wallet_hint_bits: u16,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-LEAK-EVIDENCE",
        &[
            HashPart::Str(surface.as_str()),
            HashPart::Str(mode.as_str()),
            HashPart::U64(deposit_height),
            HashPart::U64(exit_height),
            HashPart::U64(u64::from(timing_linkability_bps)),
            HashPart::U64(u64::from(amount_bucket_leakage_bps)),
            HashPart::U64(u64::from(wallet_hint_bits)),
        ],
        32,
    )
}

fn probe_public_root(
    status: CheckStatus,
    surface: LeakSurface,
    mode: DisclosureMode,
    evidence_root: &str,
    encrypted_receipt_root_depth: u16,
    nullifier_anonymity_set: u64,
    watcher_evidence_quorum: u16,
    metadata_units: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-LEAK-PROBE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(surface.as_str()),
            HashPart::Str(mode.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(u64::from(encrypted_receipt_root_depth)),
            HashPart::U64(nullifier_anonymity_set),
            HashPart::U64(u64::from(watcher_evidence_quorum)),
            HashPart::U64(metadata_units),
        ],
        32,
    )
}

fn metadata_budget_root(
    status: CheckStatus,
    total_units: u64,
    budget_units: u64,
    timing_units: u64,
    amount_units: u64,
    wallet_hint_units: u64,
    receipt_root_units: u64,
    nullifier_units: u64,
    watcher_units: u64,
    forced_exit_units: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-LEAK-METADATA-BUDGET",
        &[
            HashPart::Str(status.as_str()),
            HashPart::U64(total_units),
            HashPart::U64(budget_units),
            HashPart::U64(timing_units),
            HashPart::U64(amount_units),
            HashPart::U64(wallet_hint_units),
            HashPart::U64(receipt_root_units),
            HashPart::U64(nullifier_units),
            HashPart::U64(watcher_units),
            HashPart::U64(forced_exit_units),
        ],
        32,
    )
}

fn regression_manifest_root(
    manifest_id: &str,
    status: CheckStatus,
    pass_count: u64,
    watch_count: u64,
    block_count: u64,
    probe_root: &str,
    metadata_budget_root: &str,
    cargo_checks_deferred: bool,
    production_release_allowed: bool,
) -> String {
    let release_flags = json!({
        "cargo_checks_deferred": cargo_checks_deferred,
        "production_release_allowed": production_release_allowed,
    });
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-LEAK-MANIFEST",
        &[
            HashPart::Str(manifest_id),
            HashPart::Str(status.as_str()),
            HashPart::U64(pass_count),
            HashPart::U64(watch_count),
            HashPart::U64(block_count),
            HashPart::Str(probe_root),
            HashPart::Str(metadata_budget_root),
            HashPart::Json(&release_flags),
        ],
        32,
    )
}
