use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitSettlementExitClaimFixtureRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_SETTLEMENT_EXIT_CLAIM_FIXTURE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-settlement-exit-claim-fixture-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_SETTLEMENT_EXIT_CLAIM_FIXTURE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FIXTURE_SUITE: &str =
    "monero-private-l2-bridge-exit-settlement-to-exit-claim-fixtures-v1";
pub const RECEIPT_VERIFICATION_SUITE: &str =
    "settlement-receipt-verification-to-exit-claim-binding-v1";
pub const RELEASE_AUTHORIZATION_ROOT_SUITE: &str =
    "pq-release-authorization-roots-for-exit-claim-fixtures-v1";
pub const DISPUTE_WINDOW_ROOT_SUITE: &str =
    "dispute-window-roots-for-settlement-exit-claim-fixtures-v1";
pub const LOW_FEE_RECEIPT_ROOT_SUITE: &str =
    "low-fee-receipt-roots-for-private-bridge-exit-claims-v1";
pub const ENCRYPTED_WALLET_RECEIPT_ROOT_SUITE: &str =
    "encrypted-wallet-receipt-roots-for-exit-claim-fixtures-v1";
pub const DEFAULT_CURRENT_HEIGHT: u64 = 4_260_128;
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u64 = 2;
pub const DEFAULT_REQUIRED_ROOTS: u64 = 5;
pub const DEFAULT_MAX_FIXTURES: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureLane {
    PrivateTransfer,
    ForcedExit,
    LiquidityBackstop,
    EmergencyEscape,
}

impl FixtureLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ForcedExit => "forced_exit",
            Self::LiquidityBackstop => "liquidity_backstop",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStatus {
    ReleaseReady,
    Watch,
    Denied,
}

impl FixtureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseReady => "release_ready",
            Self::Watch => "watch",
            Self::Denied => "denied",
        }
    }

    pub fn allows_claim(self) -> bool {
        matches!(self, Self::ReleaseReady)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialCase {
    None,
    SettlementReceiptMissing,
    SettlementReceiptRootMismatch,
    ReleaseAuthorizationRootMissing,
    DisputeWindowOpen,
    LowFeeReceiptRootMissing,
    FeeAboveCap,
    WalletReceiptRootMissing,
    WalletReceiptNotDecryptable,
    ExitClaimRootMismatch,
    PrivacyFloorNotMet,
    WatcherQuorumMissing,
    MetadataLeakageExceeded,
    DuplicateNullifier,
}

impl DenialCase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SettlementReceiptMissing => "settlement_receipt_missing",
            Self::SettlementReceiptRootMismatch => "settlement_receipt_root_mismatch",
            Self::ReleaseAuthorizationRootMissing => "release_authorization_root_missing",
            Self::DisputeWindowOpen => "dispute_window_open",
            Self::LowFeeReceiptRootMissing => "low_fee_receipt_root_missing",
            Self::FeeAboveCap => "fee_above_cap",
            Self::WalletReceiptRootMissing => "wallet_receipt_root_missing",
            Self::WalletReceiptNotDecryptable => "wallet_receipt_not_decryptable",
            Self::ExitClaimRootMismatch => "exit_claim_root_mismatch",
            Self::PrivacyFloorNotMet => "privacy_floor_not_met",
            Self::WatcherQuorumMissing => "watcher_quorum_missing",
            Self::MetadataLeakageExceeded => "metadata_leakage_exceeded",
            Self::DuplicateNullifier => "duplicate_nullifier",
        }
    }

    pub fn denies(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootBindingKind {
    SettlementReceiptVerification,
    ReleaseAuthorization,
    DisputeWindow,
    LowFeeReceipt,
    EncryptedWalletReceipt,
    ExitClaim,
    DenialCase,
}

impl RootBindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementReceiptVerification => "settlement_receipt_verification",
            Self::ReleaseAuthorization => "release_authorization",
            Self::DisputeWindow => "dispute_window",
            Self::LowFeeReceipt => "low_fee_receipt",
            Self::EncryptedWalletReceipt => "encrypted_wallet_receipt",
            Self::ExitClaim => "exit_claim",
            Self::DenialCase => "denial_case",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub fixture_suite: String,
    pub receipt_verification_suite: String,
    pub release_authorization_root_suite: String,
    pub dispute_window_root_suite: String,
    pub low_fee_receipt_root_suite: String,
    pub encrypted_wallet_receipt_root_suite: String,
    pub current_height: u64,
    pub dispute_window_blocks: u64,
    pub release_delay_blocks: u64,
    pub low_fee_cap_atomic: u128,
    pub min_privacy_set_size: u64,
    pub min_watcher_quorum: u64,
    pub max_metadata_leakage_units: u64,
    pub required_roots: u64,
    pub require_settlement_receipt_verification: bool,
    pub require_release_authorization_root: bool,
    pub require_dispute_window_root: bool,
    pub require_low_fee_receipt_root: bool,
    pub require_encrypted_wallet_receipt_root: bool,
    pub deny_duplicate_nullifiers: bool,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_fixtures: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            fixture_suite: FIXTURE_SUITE.to_string(),
            receipt_verification_suite: RECEIPT_VERIFICATION_SUITE.to_string(),
            release_authorization_root_suite: RELEASE_AUTHORIZATION_ROOT_SUITE.to_string(),
            dispute_window_root_suite: DISPUTE_WINDOW_ROOT_SUITE.to_string(),
            low_fee_receipt_root_suite: LOW_FEE_RECEIPT_ROOT_SUITE.to_string(),
            encrypted_wallet_receipt_root_suite: ENCRYPTED_WALLET_RECEIPT_ROOT_SUITE.to_string(),
            current_height: DEFAULT_CURRENT_HEIGHT,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            required_roots: DEFAULT_REQUIRED_ROOTS,
            require_settlement_receipt_verification: true,
            require_release_authorization_root: true,
            require_dispute_window_root: true,
            require_low_fee_receipt_root: true,
            require_encrypted_wallet_receipt_root: true,
            deny_duplicate_nullifiers: true,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_fixtures: DEFAULT_MAX_FIXTURES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "fixture_suite": self.fixture_suite,
            "receipt_verification_suite": self.receipt_verification_suite,
            "release_authorization_root_suite": self.release_authorization_root_suite,
            "dispute_window_root_suite": self.dispute_window_root_suite,
            "low_fee_receipt_root_suite": self.low_fee_receipt_root_suite,
            "encrypted_wallet_receipt_root_suite": self.encrypted_wallet_receipt_root_suite,
            "current_height": self.current_height,
            "dispute_window_blocks": self.dispute_window_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "low_fee_cap_atomic": self.low_fee_cap_atomic.to_string(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_watcher_quorum": self.min_watcher_quorum,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "required_roots": self.required_roots,
            "require_settlement_receipt_verification": self.require_settlement_receipt_verification,
            "require_release_authorization_root": self.require_release_authorization_root,
            "require_dispute_window_root": self.require_dispute_window_root,
            "require_low_fee_receipt_root": self.require_low_fee_receipt_root,
            "require_encrypted_wallet_receipt_root": self.require_encrypted_wallet_receipt_root,
            "deny_duplicate_nullifiers": self.deny_duplicate_nullifiers,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_fixtures": self.max_fixtures,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceiptFixture {
    pub settlement_id: String,
    pub transfer_id: String,
    pub lane: FixtureLane,
    pub receipt_present: bool,
    pub receipt_verified: bool,
    pub receipt_root: String,
    pub verifier_root: String,
    pub output_commitment_root: String,
    pub nullifier: String,
    pub fee_paid_atomic: u128,
    pub fee_bps: u64,
    pub settlement_height: u64,
    pub watcher_quorum: u64,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u64,
}

impl SettlementReceiptFixture {
    pub fn new(
        transfer_id: &str,
        lane: FixtureLane,
        fee_paid_atomic: u128,
        fee_bps: u64,
        settlement_height: u64,
        watcher_quorum: u64,
        privacy_set_size: u64,
        metadata_leakage_units: u64,
    ) -> Self {
        let nullifier = domain_hash(
            "monero-l2-pq-exit-claim-fixture:nullifier",
            &[HashPart::Str(transfer_id), HashPart::Str(lane.as_str())],
            32,
        );
        let output_commitment_root = output_commitment_root(transfer_id, lane, &nullifier);
        let receipt_root = settlement_receipt_root(
            transfer_id,
            lane,
            &output_commitment_root,
            &nullifier,
            fee_paid_atomic,
            fee_bps,
        );
        let verifier_root = receipt_verifier_root(
            transfer_id,
            &receipt_root,
            settlement_height,
            watcher_quorum,
            privacy_set_size,
        );
        let settlement_id = settlement_fixture_id(transfer_id, &receipt_root);
        Self {
            settlement_id,
            transfer_id: transfer_id.to_string(),
            lane,
            receipt_present: true,
            receipt_verified: true,
            receipt_root,
            verifier_root,
            output_commitment_root,
            nullifier,
            fee_paid_atomic,
            fee_bps,
            settlement_height,
            watcher_quorum,
            privacy_set_size,
            metadata_leakage_units,
        }
    }

    pub fn with_missing_receipt(mut self) -> Self {
        self.receipt_present = false;
        self.receipt_verified = false;
        self.receipt_root = missing_root("settlement_receipt", &self.transfer_id);
        self.verifier_root = missing_root("settlement_receipt_verifier", &self.transfer_id);
        self
    }

    pub fn with_root_mismatch(mut self) -> Self {
        self.verifier_root = domain_hash(
            "monero-l2-pq-exit-claim-fixture:mutated-verifier-root",
            &[
                HashPart::Str(&self.transfer_id),
                HashPart::Str(&self.receipt_root),
            ],
            32,
        );
        self.receipt_verified = false;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "transfer_id": self.transfer_id,
            "lane": self.lane.as_str(),
            "receipt_present": self.receipt_present,
            "receipt_verified": self.receipt_verified,
            "receipt_root": self.receipt_root,
            "verifier_root": self.verifier_root,
            "output_commitment_root": self.output_commitment_root,
            "nullifier": self.nullifier,
            "fee_paid_atomic": self.fee_paid_atomic.to_string(),
            "fee_bps": self.fee_bps,
            "settlement_height": self.settlement_height,
            "watcher_quorum": self.watcher_quorum,
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("settlement_receipt_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimFixture {
    pub claim_id: String,
    pub transfer_id: String,
    pub lane: FixtureLane,
    pub status: FixtureStatus,
    pub denial_case: DenialCase,
    pub settlement_receipt_root: String,
    pub settlement_verifier_root: String,
    pub release_authorization_root: String,
    pub dispute_window_root: String,
    pub low_fee_receipt_root: String,
    pub encrypted_wallet_receipt_root: String,
    pub exit_claim_root: String,
    pub denial_case_root: String,
    pub fixture_root: String,
    pub release_height: u64,
    pub dispute_window_elapsed: bool,
    pub fee_paid_atomic: u128,
    pub fee_bps: u64,
    pub watcher_quorum: u64,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u64,
    pub nullifier: String,
}

impl ExitClaimFixture {
    pub fn from_settlement(
        config: &Config,
        settlement: &SettlementReceiptFixture,
        denial_case: DenialCase,
    ) -> Self {
        let dispute_window_elapsed =
            config.current_height >= settlement.settlement_height + config.dispute_window_blocks;
        let release_height = settlement.settlement_height
            + config.dispute_window_blocks
            + config.release_delay_blocks;
        let release_authorization_root =
            release_authorization_root(config, settlement, denial_case, release_height);
        let dispute_window_root = dispute_window_root(config, settlement, dispute_window_elapsed);
        let low_fee_receipt_root = low_fee_receipt_root(config, settlement);
        let encrypted_wallet_receipt_root =
            encrypted_wallet_receipt_root(config, settlement, denial_case);
        let exit_claim_root = exit_claim_root(
            settlement,
            &release_authorization_root,
            &dispute_window_root,
            &low_fee_receipt_root,
            &encrypted_wallet_receipt_root,
            release_height,
        );
        let denial_case =
            derive_denial_case(config, settlement, denial_case, dispute_window_elapsed);
        let denial_case_root = denial_case_root(denial_case, settlement, &exit_claim_root);
        let status = fixture_status(denial_case, dispute_window_elapsed);
        let fixture_root = fixture_root(
            status,
            denial_case,
            &settlement.receipt_root,
            &settlement.verifier_root,
            &release_authorization_root,
            &dispute_window_root,
            &low_fee_receipt_root,
            &encrypted_wallet_receipt_root,
            &exit_claim_root,
            &denial_case_root,
        );
        let claim_id = exit_claim_id(&settlement.transfer_id, &fixture_root);
        Self {
            claim_id,
            transfer_id: settlement.transfer_id.clone(),
            lane: settlement.lane,
            status,
            denial_case,
            settlement_receipt_root: settlement.receipt_root.clone(),
            settlement_verifier_root: settlement.verifier_root.clone(),
            release_authorization_root,
            dispute_window_root,
            low_fee_receipt_root,
            encrypted_wallet_receipt_root,
            exit_claim_root,
            denial_case_root,
            fixture_root,
            release_height,
            dispute_window_elapsed,
            fee_paid_atomic: settlement.fee_paid_atomic,
            fee_bps: settlement.fee_bps,
            watcher_quorum: settlement.watcher_quorum,
            privacy_set_size: settlement.privacy_set_size,
            metadata_leakage_units: settlement.metadata_leakage_units,
            nullifier: settlement.nullifier.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "transfer_id": self.transfer_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "denial_case": self.denial_case.as_str(),
            "settlement_receipt_root": self.settlement_receipt_root,
            "settlement_verifier_root": self.settlement_verifier_root,
            "release_authorization_root": self.release_authorization_root,
            "dispute_window_root": self.dispute_window_root,
            "low_fee_receipt_root": self.low_fee_receipt_root,
            "encrypted_wallet_receipt_root": self.encrypted_wallet_receipt_root,
            "exit_claim_root": self.exit_claim_root,
            "denial_case_root": self.denial_case_root,
            "fixture_root": self.fixture_root,
            "release_height": self.release_height,
            "dispute_window_elapsed": self.dispute_window_elapsed,
            "fee_paid_atomic": self.fee_paid_atomic.to_string(),
            "fee_bps": self.fee_bps,
            "watcher_quorum": self.watcher_quorum,
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "nullifier": self.nullifier,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("exit_claim_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootBindingReport {
    pub binding_id: String,
    pub kind: RootBindingKind,
    pub root: String,
    pub fixture_count: u64,
    pub release_ready_count: u64,
    pub denied_count: u64,
}

impl RootBindingReport {
    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "kind": self.kind.as_str(),
            "root": self.root,
            "fixture_count": self.fixture_count,
            "release_ready_count": self.release_ready_count,
            "denied_count": self.denied_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("root_binding_report", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub settlement_fixtures: Vec<SettlementReceiptFixture>,
    pub exit_claim_fixtures: Vec<ExitClaimFixture>,
    pub root_bindings: Vec<RootBindingReport>,
    pub denial_case_index: BTreeMap<String, u64>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            settlement_fixtures: Vec::new(),
            exit_claim_fixtures: Vec::new(),
            root_bindings: Vec::new(),
            denial_case_index: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone());
        for settlement in devnet_settlements(&config) {
            let denial_case = seeded_denial_case(&settlement);
            let claim = ExitClaimFixture::from_settlement(&config, &settlement, denial_case);
            state.push_fixture(settlement, claim);
        }
        state.rebuild_root_bindings();
        state
    }

    pub fn push_fixture(&mut self, settlement: SettlementReceiptFixture, claim: ExitClaimFixture) {
        if self.exit_claim_fixtures.len() >= self.config.max_fixtures {
            return;
        }
        let entry = self
            .denial_case_index
            .entry(claim.denial_case.as_str().to_string())
            .or_insert(0);
        *entry += 1;
        self.settlement_fixtures.push(settlement);
        self.exit_claim_fixtures.push(claim);
    }

    pub fn rebuild_root_bindings(&mut self) {
        let fixture_count = self.exit_claim_fixtures.len() as u64;
        let release_ready_count = self.release_ready_count();
        let denied_count = self.denied_count();
        self.root_bindings = vec![
            self.root_binding_report(
                RootBindingKind::SettlementReceiptVerification,
                fixture_count,
                release_ready_count,
                denied_count,
                self.settlement_verification_root(),
            ),
            self.root_binding_report(
                RootBindingKind::ReleaseAuthorization,
                fixture_count,
                release_ready_count,
                denied_count,
                self.release_authorization_root(),
            ),
            self.root_binding_report(
                RootBindingKind::DisputeWindow,
                fixture_count,
                release_ready_count,
                denied_count,
                self.dispute_window_root(),
            ),
            self.root_binding_report(
                RootBindingKind::LowFeeReceipt,
                fixture_count,
                release_ready_count,
                denied_count,
                self.low_fee_receipt_root(),
            ),
            self.root_binding_report(
                RootBindingKind::EncryptedWalletReceipt,
                fixture_count,
                release_ready_count,
                denied_count,
                self.encrypted_wallet_receipt_root(),
            ),
            self.root_binding_report(
                RootBindingKind::ExitClaim,
                fixture_count,
                release_ready_count,
                denied_count,
                self.exit_claim_root(),
            ),
            self.root_binding_report(
                RootBindingKind::DenialCase,
                fixture_count,
                release_ready_count,
                denied_count,
                self.denial_case_root(),
            ),
        ];
    }

    pub fn release_ready_count(&self) -> u64 {
        self.exit_claim_fixtures
            .iter()
            .filter(|fixture| fixture.status.allows_claim())
            .count() as u64
    }

    pub fn denied_count(&self) -> u64 {
        self.exit_claim_fixtures
            .iter()
            .filter(|fixture| fixture.denial_case.denies())
            .count() as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "settlement_fixtures": self
                .settlement_fixtures
                .iter()
                .map(SettlementReceiptFixture::public_record)
                .collect::<Vec<_>>(),
            "exit_claim_fixtures": self
                .exit_claim_fixtures
                .iter()
                .map(ExitClaimFixture::public_record)
                .collect::<Vec<_>>(),
            "root_bindings": self
                .root_bindings
                .iter()
                .map(RootBindingReport::public_record)
                .collect::<Vec<_>>(),
            "denial_case_index": self.denial_case_index,
            "release_ready_count": self.release_ready_count(),
            "denied_count": self.denied_count(),
            "cargo_checks_deferred": self.config.cargo_checks_deferred,
            "production_release_allowed": self.config.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }

    pub fn settlement_verification_root(&self) -> String {
        merkle_root(
            "monero-l2-pq-exit-claim-fixture:settlement-verification-root",
            &self
                .settlement_fixtures
                .iter()
                .map(|fixture| {
                    json!({
                        "settlement_id": fixture.settlement_id,
                        "receipt_root": fixture.receipt_root,
                        "verifier_root": fixture.verifier_root,
                        "receipt_present": fixture.receipt_present,
                        "receipt_verified": fixture.receipt_verified,
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn release_authorization_root(&self) -> String {
        merkle_root(
            "monero-l2-pq-exit-claim-fixture:release-authorization-root",
            &self
                .exit_claim_fixtures
                .iter()
                .map(|fixture| {
                    json!({
                        "claim_id": fixture.claim_id,
                        "release_authorization_root": fixture.release_authorization_root,
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn dispute_window_root(&self) -> String {
        merkle_root(
            "monero-l2-pq-exit-claim-fixture:dispute-window-root",
            &self
                .exit_claim_fixtures
                .iter()
                .map(|fixture| {
                    json!({
                        "claim_id": fixture.claim_id,
                        "dispute_window_root": fixture.dispute_window_root,
                        "dispute_window_elapsed": fixture.dispute_window_elapsed,
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_receipt_root(&self) -> String {
        merkle_root(
            "monero-l2-pq-exit-claim-fixture:low-fee-receipt-root",
            &self
                .exit_claim_fixtures
                .iter()
                .map(|fixture| {
                    json!({
                        "claim_id": fixture.claim_id,
                        "low_fee_receipt_root": fixture.low_fee_receipt_root,
                        "fee_paid_atomic": fixture.fee_paid_atomic.to_string(),
                        "fee_bps": fixture.fee_bps,
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn encrypted_wallet_receipt_root(&self) -> String {
        merkle_root(
            "monero-l2-pq-exit-claim-fixture:encrypted-wallet-receipt-root",
            &self
                .exit_claim_fixtures
                .iter()
                .map(|fixture| {
                    json!({
                        "claim_id": fixture.claim_id,
                        "encrypted_wallet_receipt_root": fixture.encrypted_wallet_receipt_root,
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn exit_claim_root(&self) -> String {
        merkle_root(
            "monero-l2-pq-exit-claim-fixture:exit-claim-root",
            &self
                .exit_claim_fixtures
                .iter()
                .map(|fixture| fixture.public_record())
                .collect::<Vec<_>>(),
        )
    }

    pub fn denial_case_root(&self) -> String {
        merkle_root(
            "monero-l2-pq-exit-claim-fixture:denial-case-root",
            &self
                .exit_claim_fixtures
                .iter()
                .map(|fixture| {
                    json!({
                        "claim_id": fixture.claim_id,
                        "denial_case": fixture.denial_case.as_str(),
                        "denial_case_root": fixture.denial_case_root,
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    fn root_binding_report(
        &self,
        kind: RootBindingKind,
        fixture_count: u64,
        release_ready_count: u64,
        denied_count: u64,
        root: String,
    ) -> RootBindingReport {
        let binding_id = domain_hash(
            "monero-l2-pq-exit-claim-fixture:root-binding-id",
            &[HashPart::Str(kind.as_str()), HashPart::Str(&root)],
            16,
        );
        RootBindingReport {
            binding_id,
            kind,
            root,
            fixture_count,
            release_ready_count,
            denied_count,
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

fn devnet_settlements(config: &Config) -> Vec<SettlementReceiptFixture> {
    vec![
        SettlementReceiptFixture::new(
            "xmr-exit-transfer-0001",
            FixtureLane::PrivateTransfer,
            18_500_000,
            3,
            config.current_height - config.dispute_window_blocks - 80,
            7,
            98_304,
            1,
        ),
        SettlementReceiptFixture::new(
            "xmr-exit-transfer-0002",
            FixtureLane::ForcedExit,
            19_000_000,
            4,
            config.current_height - 240,
            6,
            70_000,
            1,
        ),
        SettlementReceiptFixture::new(
            "xmr-exit-transfer-0003",
            FixtureLane::LiquidityBackstop,
            52_000_000,
            12,
            config.current_height - config.dispute_window_blocks - 96,
            8,
            80_000,
            1,
        ),
        SettlementReceiptFixture::new(
            "xmr-exit-transfer-0004",
            FixtureLane::EmergencyEscape,
            21_000_000,
            5,
            config.current_height - config.dispute_window_blocks - 48,
            4,
            90_000,
            1,
        ),
        SettlementReceiptFixture::new(
            "xmr-exit-transfer-0005",
            FixtureLane::PrivateTransfer,
            17_000_000,
            3,
            config.current_height - config.dispute_window_blocks - 64,
            7,
            32_768,
            1,
        ),
        SettlementReceiptFixture::new(
            "xmr-exit-transfer-0006",
            FixtureLane::ForcedExit,
            18_000_000,
            4,
            config.current_height - config.dispute_window_blocks - 64,
            7,
            80_000,
            5,
        ),
        SettlementReceiptFixture::new(
            "xmr-exit-transfer-0007",
            FixtureLane::PrivateTransfer,
            20_000_000,
            4,
            config.current_height - config.dispute_window_blocks - 64,
            7,
            80_000,
            1,
        )
        .with_missing_receipt(),
        SettlementReceiptFixture::new(
            "xmr-exit-transfer-0008",
            FixtureLane::LiquidityBackstop,
            20_000_000,
            4,
            config.current_height - config.dispute_window_blocks - 64,
            7,
            80_000,
            1,
        )
        .with_root_mismatch(),
    ]
}

fn seeded_denial_case(settlement: &SettlementReceiptFixture) -> DenialCase {
    match settlement.transfer_id.as_str() {
        "xmr-exit-transfer-0002" => DenialCase::DisputeWindowOpen,
        "xmr-exit-transfer-0003" => DenialCase::FeeAboveCap,
        "xmr-exit-transfer-0004" => DenialCase::WatcherQuorumMissing,
        "xmr-exit-transfer-0005" => DenialCase::PrivacyFloorNotMet,
        "xmr-exit-transfer-0006" => DenialCase::MetadataLeakageExceeded,
        "xmr-exit-transfer-0007" => DenialCase::SettlementReceiptMissing,
        "xmr-exit-transfer-0008" => DenialCase::SettlementReceiptRootMismatch,
        _ => DenialCase::None,
    }
}

fn derive_denial_case(
    config: &Config,
    settlement: &SettlementReceiptFixture,
    requested: DenialCase,
    dispute_window_elapsed: bool,
) -> DenialCase {
    if !settlement.receipt_present {
        return DenialCase::SettlementReceiptMissing;
    }
    if !settlement.receipt_verified {
        return DenialCase::SettlementReceiptRootMismatch;
    }
    if !dispute_window_elapsed {
        return DenialCase::DisputeWindowOpen;
    }
    if settlement.fee_paid_atomic > config.low_fee_cap_atomic || settlement.fee_bps > MAX_BPS {
        return DenialCase::FeeAboveCap;
    }
    if settlement.watcher_quorum < config.min_watcher_quorum {
        return DenialCase::WatcherQuorumMissing;
    }
    if settlement.privacy_set_size < config.min_privacy_set_size {
        return DenialCase::PrivacyFloorNotMet;
    }
    if settlement.metadata_leakage_units > config.max_metadata_leakage_units {
        return DenialCase::MetadataLeakageExceeded;
    }
    requested
}

fn fixture_status(denial_case: DenialCase, dispute_window_elapsed: bool) -> FixtureStatus {
    if denial_case.denies() {
        FixtureStatus::Denied
    } else if dispute_window_elapsed {
        FixtureStatus::ReleaseReady
    } else {
        FixtureStatus::Watch
    }
}

fn output_commitment_root(transfer_id: &str, lane: FixtureLane, nullifier: &str) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:output-commitment-root",
        &[
            HashPart::Str(transfer_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

fn settlement_receipt_root(
    transfer_id: &str,
    lane: FixtureLane,
    output_commitment_root: &str,
    nullifier: &str,
    fee_paid_atomic: u128,
    fee_bps: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:settlement-receipt-root",
        &[
            HashPart::Str(transfer_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(output_commitment_root),
            HashPart::Str(nullifier),
            HashPart::Int(fee_paid_atomic as i128),
            HashPart::U64(fee_bps),
        ],
        32,
    )
}

fn receipt_verifier_root(
    transfer_id: &str,
    receipt_root: &str,
    settlement_height: u64,
    watcher_quorum: u64,
    privacy_set_size: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:receipt-verifier-root",
        &[
            HashPart::Str(transfer_id),
            HashPart::Str(receipt_root),
            HashPart::U64(settlement_height),
            HashPart::U64(watcher_quorum),
            HashPart::U64(privacy_set_size),
        ],
        32,
    )
}

fn release_authorization_root(
    config: &Config,
    settlement: &SettlementReceiptFixture,
    denial_case: DenialCase,
    release_height: u64,
) -> String {
    if matches!(denial_case, DenialCase::ReleaseAuthorizationRootMissing) {
        return missing_root("release_authorization", &settlement.transfer_id);
    }
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:release-authorization-root",
        &[
            HashPart::Str(&config.release_authorization_root_suite),
            HashPart::Str(&settlement.transfer_id),
            HashPart::Str(&settlement.verifier_root),
            HashPart::U64(release_height),
        ],
        32,
    )
}

fn dispute_window_root(
    config: &Config,
    settlement: &SettlementReceiptFixture,
    dispute_window_elapsed: bool,
) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:dispute-window-root",
        &[
            HashPart::Str(&config.dispute_window_root_suite),
            HashPart::Str(&settlement.transfer_id),
            HashPart::U64(settlement.settlement_height),
            HashPart::U64(config.dispute_window_blocks),
            HashPart::Str(if dispute_window_elapsed {
                "elapsed"
            } else {
                "open"
            }),
        ],
        32,
    )
}

fn low_fee_receipt_root(config: &Config, settlement: &SettlementReceiptFixture) -> String {
    if settlement.fee_paid_atomic > config.low_fee_cap_atomic {
        return missing_root("low_fee_receipt", &settlement.transfer_id);
    }
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:low-fee-receipt-root",
        &[
            HashPart::Str(&config.low_fee_receipt_root_suite),
            HashPart::Str(&settlement.transfer_id),
            HashPart::Int(settlement.fee_paid_atomic as i128),
            HashPart::Int(config.low_fee_cap_atomic as i128),
            HashPart::U64(settlement.fee_bps),
        ],
        32,
    )
}

fn encrypted_wallet_receipt_root(
    config: &Config,
    settlement: &SettlementReceiptFixture,
    denial_case: DenialCase,
) -> String {
    if matches!(
        denial_case,
        DenialCase::WalletReceiptRootMissing | DenialCase::WalletReceiptNotDecryptable
    ) {
        return missing_root("encrypted_wallet_receipt", &settlement.transfer_id);
    }
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:encrypted-wallet-receipt-root",
        &[
            HashPart::Str(&config.encrypted_wallet_receipt_root_suite),
            HashPart::Str(&settlement.transfer_id),
            HashPart::Str(&settlement.receipt_root),
            HashPart::Str(&settlement.nullifier),
        ],
        32,
    )
}

fn exit_claim_root(
    settlement: &SettlementReceiptFixture,
    release_authorization_root: &str,
    dispute_window_root: &str,
    low_fee_receipt_root: &str,
    encrypted_wallet_receipt_root: &str,
    release_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:exit-claim-root",
        &[
            HashPart::Str(&settlement.transfer_id),
            HashPart::Str(&settlement.receipt_root),
            HashPart::Str(release_authorization_root),
            HashPart::Str(dispute_window_root),
            HashPart::Str(low_fee_receipt_root),
            HashPart::Str(encrypted_wallet_receipt_root),
            HashPart::U64(release_height),
        ],
        32,
    )
}

fn denial_case_root(
    denial_case: DenialCase,
    settlement: &SettlementReceiptFixture,
    exit_claim_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:denial-case-root",
        &[
            HashPart::Str(denial_case.as_str()),
            HashPart::Str(&settlement.transfer_id),
            HashPart::Str(&settlement.receipt_root),
            HashPart::Str(exit_claim_root),
        ],
        32,
    )
}

fn fixture_root(
    status: FixtureStatus,
    denial_case: DenialCase,
    settlement_receipt_root: &str,
    settlement_verifier_root: &str,
    release_authorization_root: &str,
    dispute_window_root: &str,
    low_fee_receipt_root: &str,
    encrypted_wallet_receipt_root: &str,
    exit_claim_root: &str,
    denial_case_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:fixture-root",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(denial_case.as_str()),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(settlement_verifier_root),
            HashPart::Str(release_authorization_root),
            HashPart::Str(dispute_window_root),
            HashPart::Str(low_fee_receipt_root),
            HashPart::Str(encrypted_wallet_receipt_root),
            HashPart::Str(exit_claim_root),
            HashPart::Str(denial_case_root),
        ],
        32,
    )
}

fn settlement_fixture_id(transfer_id: &str, receipt_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:settlement-fixture-id",
        &[HashPart::Str(transfer_id), HashPart::Str(receipt_root)],
        16,
    )
}

fn exit_claim_id(transfer_id: &str, fixture_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:exit-claim-id",
        &[HashPart::Str(transfer_id), HashPart::Str(fixture_root)],
        16,
    )
}

fn missing_root(kind: &str, transfer_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-exit-claim-fixture:missing-root",
        &[HashPart::Str(kind), HashPart::Str(transfer_id)],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-exit-claim-fixture:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}
