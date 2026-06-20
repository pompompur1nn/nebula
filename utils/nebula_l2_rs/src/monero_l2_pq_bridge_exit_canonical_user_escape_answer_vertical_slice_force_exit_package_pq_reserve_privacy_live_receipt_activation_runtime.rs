use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackagePqReservePrivacyLiveReceiptActivationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-pq-reserve-privacy-live-receipt-activation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ACTIVATION_SUITE: &str =
    "monero-l2-pq-bridge-force-exit-package-pq-reserve-privacy-live-receipt-activation-v1";
pub const RECEIPT_SUITE: &str = "monero-l2-pq-bridge-force-exit-package-live-receipt-policy-v1";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BASE_EPOCH: u64 = 78;
pub const DEFAULT_CURRENT_EPOCH: u64 = 86;
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_224_900;
pub const DEFAULT_MIN_PQ_KEY_EPOCH: u64 = 84;
pub const DEFAULT_MAX_STALE_EPOCH_DRIFT: u64 = 2;
pub const DEFAULT_MIN_RESERVE_BPS: u64 = 1_250;
pub const DEFAULT_MIN_RESERVE_FLOOR_ATOMIC: u64 = 15_000_000_000;
pub const DEFAULT_MIN_PRIVACY_REMAINING_BPS: u64 = 2_500;
pub const DEFAULT_MAX_PRIVACY_REGRESSION_BPS: u64 = 400;
pub const DEFAULT_MAX_RECEIPTS: usize = 64;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-pq-reserve-privacy-live-receipt-activation-runtime";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationVerdict {
    Activate,
    Hold,
    Reject,
}

impl ActivationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationHold {
    None,
    StaleEpoch,
    ReserveSlo,
    PrivacyBudgetRegression,
    MissingPqRotation,
    MissingLiveReceipt,
    PackageBinding,
}

impl ActivationHold {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StaleEpoch => "stale_epoch",
            Self::ReserveSlo => "reserve_slo",
            Self::PrivacyBudgetRegression => "privacy_budget_regression",
            Self::MissingPqRotation => "missing_pq_rotation",
            Self::MissingLiveReceipt => "missing_live_receipt",
            Self::PackageBinding => "package_binding",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub activation_suite: String,
    pub receipt_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub base_epoch: u64,
    pub current_epoch: u64,
    pub l2_reference_height: u64,
    pub min_pq_key_epoch: u64,
    pub max_stale_epoch_drift: u64,
    pub min_reserve_bps: u64,
    pub min_reserve_floor_atomic: u64,
    pub min_privacy_remaining_bps: u64,
    pub max_privacy_regression_bps: u64,
    pub require_pq_rotation: bool,
    pub require_live_receipt: bool,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub max_receipts: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            activation_suite: ACTIVATION_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            base_epoch: DEFAULT_BASE_EPOCH,
            current_epoch: DEFAULT_CURRENT_EPOCH,
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            min_pq_key_epoch: DEFAULT_MIN_PQ_KEY_EPOCH,
            max_stale_epoch_drift: DEFAULT_MAX_STALE_EPOCH_DRIFT,
            min_reserve_bps: DEFAULT_MIN_RESERVE_BPS,
            min_reserve_floor_atomic: DEFAULT_MIN_RESERVE_FLOOR_ATOMIC,
            min_privacy_remaining_bps: DEFAULT_MIN_PRIVACY_REMAINING_BPS,
            max_privacy_regression_bps: DEFAULT_MAX_PRIVACY_REGRESSION_BPS,
            require_pq_rotation: true,
            require_live_receipt: true,
            fail_closed: true,
            production_release_allowed: false,
            max_receipts: DEFAULT_MAX_RECEIPTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForceExitPackage {
    pub package_id: String,
    pub user_escape_package_id: String,
    pub force_exit_claim_id: String,
    pub release_policy_id: String,
    pub pq_rotation_root: String,
    pub reserve_policy_root: String,
    pub privacy_policy_root: String,
    pub package_binding_root: String,
    pub package_epoch: u64,
    pub l2_reference_height: u64,
    pub bound_to_release_policy: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqRotationStatus {
    pub rotation_id: String,
    pub key_epoch: u64,
    pub previous_key_commitment: String,
    pub next_key_commitment: String,
    pub rotation_transcript_root: String,
    pub watcher_attestation_root: String,
    pub activated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveLiquidityStatus {
    pub reserve_id: String,
    pub reserved_atomic: u64,
    pub release_liability_atomic: u64,
    pub reserve_bps: u64,
    pub reserve_slo_root: String,
    pub reserve_attestation_root: String,
    pub reserve_slo_met: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudgetStatus {
    pub budget_id: String,
    pub starting_budget_bps: u64,
    pub remaining_budget_bps: u64,
    pub previous_remaining_budget_bps: u64,
    pub regression_bps: u64,
    pub spend_receipt_root: String,
    pub privacy_budget_root: String,
    pub regression_detected: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveReceipt {
    pub receipt_id: String,
    pub feed_id: String,
    pub feed_sequence: u64,
    pub observed_epoch: u64,
    pub live_receipt_root: String,
    pub release_policy_root: String,
    pub reserve_snapshot_root: String,
    pub privacy_snapshot_root: String,
    pub pq_snapshot_root: String,
    pub present: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActivationReceipt {
    pub activation_id: String,
    pub verdict: ActivationVerdict,
    pub hold: ActivationHold,
    pub package: ForceExitPackage,
    pub pq_rotation: PqRotationStatus,
    pub reserve: ReserveLiquidityStatus,
    pub privacy_budget: PrivacyBudgetStatus,
    pub live_receipt: LiveReceipt,
    pub stale_epoch_hold_root: String,
    pub reserve_slo_hold_root: String,
    pub privacy_regression_hold_root: String,
    pub activation_verdict_root: String,
    pub force_exit_release_root: String,
}

impl ActivationReceipt {
    pub fn new(
        config: &Config,
        package: ForceExitPackage,
        pq_rotation: PqRotationStatus,
        reserve: ReserveLiquidityStatus,
        privacy_budget: PrivacyBudgetStatus,
        live_receipt: LiveReceipt,
    ) -> Self {
        let hold = activation_hold(
            config,
            &package,
            &pq_rotation,
            &reserve,
            &privacy_budget,
            &live_receipt,
        );
        let verdict = activation_verdict(config, hold);
        let stale_epoch_hold_root = policy_hold_root(
            "stale-epoch",
            &package.package_id,
            hold,
            &[
                package.package_epoch,
                live_receipt.observed_epoch,
                config.current_epoch,
                config.max_stale_epoch_drift,
            ],
        );
        let reserve_slo_hold_root = policy_hold_root(
            "reserve-slo",
            &package.package_id,
            hold,
            &[
                reserve.reserved_atomic,
                reserve.release_liability_atomic,
                reserve.reserve_bps,
                config.min_reserve_bps,
                config.min_reserve_floor_atomic,
            ],
        );
        let privacy_regression_hold_root = policy_hold_root(
            "privacy-regression",
            &package.package_id,
            hold,
            &[
                privacy_budget.previous_remaining_budget_bps,
                privacy_budget.remaining_budget_bps,
                privacy_budget.regression_bps,
                config.max_privacy_regression_bps,
                config.min_privacy_remaining_bps,
            ],
        );
        let activation_verdict_root = activation_verdict_root(
            verdict,
            hold,
            &package,
            &pq_rotation,
            &reserve,
            &privacy_budget,
            &live_receipt,
            &stale_epoch_hold_root,
            &reserve_slo_hold_root,
            &privacy_regression_hold_root,
        );
        let force_exit_release_root =
            force_exit_release_root(verdict, &package, &live_receipt, &activation_verdict_root);
        let activation_id = domain_hash(
            &format!("{DOMAIN}:activation-id"),
            &[
                HashPart::Str(&package.package_id),
                HashPart::Str(&live_receipt.receipt_id),
                HashPart::Str(&activation_verdict_root),
            ],
            16,
        );

        Self {
            activation_id,
            verdict,
            hold,
            package,
            pq_rotation,
            reserve,
            privacy_budget,
            live_receipt,
            stale_epoch_hold_root,
            reserve_slo_hold_root,
            privacy_regression_hold_root,
            activation_verdict_root,
            force_exit_release_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivationCounters {
    pub total_receipts: u64,
    pub activated: u64,
    pub held: u64,
    pub rejected: u64,
    pub stale_epoch_holds: u64,
    pub reserve_slo_holds: u64,
    pub privacy_budget_regressions: u64,
    pub pq_rotation_holds: u64,
    pub missing_live_receipt_holds: u64,
    pub package_binding_rejections: u64,
}

impl ActivationCounters {
    pub fn from_receipts(receipts: &[ActivationReceipt]) -> Self {
        let mut counters = Self::default();
        for receipt in receipts {
            counters.total_receipts = counters.total_receipts.saturating_add(1);
            match receipt.verdict {
                ActivationVerdict::Activate => {
                    counters.activated = counters.activated.saturating_add(1);
                }
                ActivationVerdict::Hold => {
                    counters.held = counters.held.saturating_add(1);
                }
                ActivationVerdict::Reject => {
                    counters.rejected = counters.rejected.saturating_add(1);
                }
            }
            match receipt.hold {
                ActivationHold::None => {}
                ActivationHold::StaleEpoch => {
                    counters.stale_epoch_holds = counters.stale_epoch_holds.saturating_add(1);
                }
                ActivationHold::ReserveSlo => {
                    counters.reserve_slo_holds = counters.reserve_slo_holds.saturating_add(1);
                }
                ActivationHold::PrivacyBudgetRegression => {
                    counters.privacy_budget_regressions =
                        counters.privacy_budget_regressions.saturating_add(1);
                }
                ActivationHold::MissingPqRotation => {
                    counters.pq_rotation_holds = counters.pq_rotation_holds.saturating_add(1);
                }
                ActivationHold::MissingLiveReceipt => {
                    counters.missing_live_receipt_holds =
                        counters.missing_live_receipt_holds.saturating_add(1);
                }
                ActivationHold::PackageBinding => {
                    counters.package_binding_rejections =
                        counters.package_binding_rejections.saturating_add(1);
                }
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub receipts: Vec<ActivationReceipt>,
    pub counters: ActivationCounters,
    pub activated_ids: Vec<String>,
    pub held_ids: Vec<String>,
    pub rejected_ids: Vec<String>,
}

impl State {
    pub fn new(config: Config, receipts: Vec<ActivationReceipt>) -> Result<Self> {
        if receipts.len() > config.max_receipts {
            return Err(format!(
                "activation receipt count {} exceeds configured max {}",
                receipts.len(),
                config.max_receipts
            ));
        }

        let mut seen_packages = BTreeMap::<String, String>::new();
        let mut activated_ids = Vec::new();
        let mut held_ids = Vec::new();
        let mut rejected_ids = Vec::new();

        for receipt in &receipts {
            if let Some(existing) = seen_packages.insert(
                receipt.package.package_id.clone(),
                receipt.activation_id.clone(),
            ) {
                return Err(format!(
                    "duplicate force-exit package {} conflicts with activation {}",
                    receipt.package.package_id, existing
                ));
            }

            match receipt.verdict {
                ActivationVerdict::Activate => activated_ids.push(receipt.activation_id.clone()),
                ActivationVerdict::Hold => held_ids.push(receipt.activation_id.clone()),
                ActivationVerdict::Reject => rejected_ids.push(receipt.activation_id.clone()),
            }
        }

        let counters = ActivationCounters::from_receipts(&receipts);

        Ok(Self {
            config,
            receipts,
            counters,
            activated_ids,
            held_ids,
            rejected_ids,
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let receipts = self
            .receipts
            .iter()
            .map(ActivationReceipt::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "receipts": receipts,
            "counters": self.counters.public_record(),
            "activated_ids": self.activated_ids,
            "held_ids": self.held_ids,
            "rejected_ids": self.rejected_ids,
            "roots": {
                "config_root": self.config.state_root(),
                "receipt_root": self.receipt_root(),
                "counter_root": self.counters.state_root(),
                "activated_root": vector_root("activated", &self.activated_ids),
                "held_root": vector_root("held", &self.held_ids),
                "rejected_root": vector_root("rejected", &self.rejected_ids),
                "policy_root": self.policy_root(),
            },
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn receipt_root(&self) -> String {
        let records = self
            .receipts
            .iter()
            .map(ActivationReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:receipts"), &records)
    }

    pub fn policy_root(&self) -> String {
        let records = self
            .receipts
            .iter()
            .map(|receipt| {
                json!({
                    "activation_id": receipt.activation_id,
                    "hold": receipt.hold.as_str(),
                    "verdict_root": receipt.activation_verdict_root,
                    "release_root": receipt.force_exit_release_root,
                })
            })
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:policy-roots"), &records)
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let receipts = devnet_activation_receipts(&config);
    match State::new(config, receipts) {
        Ok(state) => state,
        Err(reason) => fallback_state(reason),
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

#[rustfmt::skip]
pub fn devnet_activation_receipts(config: &Config) -> Vec<ActivationReceipt> {
    [(0_u64, ActivationHold::None), (1, ActivationHold::StaleEpoch),
     (2, ActivationHold::ReserveSlo), (3, ActivationHold::PrivacyBudgetRegression),
     (4, ActivationHold::MissingPqRotation), (5, ActivationHold::MissingLiveReceipt),
     (6, ActivationHold::PackageBinding)].iter().map(|(ordinal, intended_hold)| {
        let package = force_exit_package(config, *ordinal, *intended_hold);
        let pq_rotation = pq_rotation_status(config, &package, *ordinal, *intended_hold);
        let reserve = reserve_liquidity_status(config, &package, *ordinal, *intended_hold);
        let privacy_budget = privacy_budget_status(config, &package, *ordinal, *intended_hold);
        let live_receipt = live_receipt(config, &package, *ordinal, *intended_hold);
        ActivationReceipt::new(
            config,
            package,
            pq_rotation,
            reserve,
            privacy_budget,
            live_receipt,
        )
    })
    .collect()
}

#[rustfmt::skip]
fn force_exit_package(config: &Config, ordinal: u64, intended_hold: ActivationHold) -> ForceExitPackage {
    let label = format!("force-exit-pq-reserve-privacy-activation-{ordinal}");
    let user_escape_package_id = short_id("user-escape-package", &label, ordinal);
    let force_exit_claim_id = short_id("force-exit-claim", &label, ordinal);
    let release_policy_id = short_id("release-policy", &label, ordinal);
    let pq_rotation_root = commitment("package-pq-rotation", &label, ordinal);
    let reserve_policy_root = commitment("package-reserve-policy", &label, ordinal);
    let privacy_policy_root = commitment("package-privacy-policy", &label, ordinal);
    let package_epoch = match intended_hold {
        ActivationHold::StaleEpoch => config
            .current_epoch
            .saturating_sub(config.max_stale_epoch_drift.saturating_add(3)),
        _ => config.current_epoch.saturating_sub(1),
    };
    let bound_to_release_policy = intended_hold != ActivationHold::PackageBinding;
    let package_binding_root = domain_hash(
        &format!("{DOMAIN}:package-binding"),
        &[HashPart::Str(&user_escape_package_id), HashPart::Str(&force_exit_claim_id),
          HashPart::Str(&release_policy_id), HashPart::Str(&pq_rotation_root),
          HashPart::Str(&reserve_policy_root), HashPart::Str(&privacy_policy_root),
          HashPart::Str(bool_str(bound_to_release_policy))],
        32,
    );
    let package_id = domain_hash(
        &format!("{DOMAIN}:package-id"),
        &[HashPart::Str(&user_escape_package_id), HashPart::Str(&force_exit_claim_id),
          HashPart::U64(package_epoch), HashPart::Str(&package_binding_root)],
        16,
    );

    ForceExitPackage {
        package_id,
        user_escape_package_id,
        force_exit_claim_id,
        release_policy_id,
        pq_rotation_root,
        reserve_policy_root,
        privacy_policy_root,
        package_binding_root,
        package_epoch,
        l2_reference_height: config.l2_reference_height + ordinal,
        bound_to_release_policy,
    }
}

fn pq_rotation_status(
    config: &Config,
    package: &ForceExitPackage,
    ordinal: u64,
    intended_hold: ActivationHold,
) -> PqRotationStatus {
    let key_epoch = match intended_hold {
        ActivationHold::MissingPqRotation => config.min_pq_key_epoch.saturating_sub(1),
        _ => config.min_pq_key_epoch + ordinal,
    };
    let previous_key_commitment = commitment("previous-pq-key", &package.package_id, ordinal);
    let next_key_commitment = commitment("next-pq-key", &package.package_id, ordinal);
    let rotation_transcript_root = domain_hash(
        &format!("{DOMAIN}:pq-rotation-transcript"),
        &[
            HashPart::Str(&package.package_id),
            HashPart::Str(&previous_key_commitment),
            HashPart::Str(&next_key_commitment),
            HashPart::U64(key_epoch),
        ],
        32,
    );
    let watcher_attestation_root =
        commitment("pq-watcher-attestation", &package.package_id, ordinal);
    let activated = intended_hold != ActivationHold::MissingPqRotation;
    let rotation_id = domain_hash(
        &format!("{DOMAIN}:pq-rotation-id"),
        &[
            HashPart::Str(&package.package_id),
            HashPart::Str(&rotation_transcript_root),
            HashPart::Str(bool_str(activated)),
        ],
        16,
    );

    PqRotationStatus {
        rotation_id,
        key_epoch,
        previous_key_commitment,
        next_key_commitment,
        rotation_transcript_root,
        watcher_attestation_root,
        activated,
    }
}

fn reserve_liquidity_status(
    config: &Config,
    package: &ForceExitPackage,
    ordinal: u64,
    intended_hold: ActivationHold,
) -> ReserveLiquidityStatus {
    let release_liability_atomic = 100_000_000_000_u64.saturating_add(ordinal * 9_000_000_000);
    let good_reserve = config
        .min_reserve_floor_atomic
        .saturating_add(release_liability_atomic.saturating_mul(config.min_reserve_bps) / 10_000)
        .saturating_add(ordinal * 1_000_000);
    let reserved_atomic = match intended_hold {
        ActivationHold::ReserveSlo => good_reserve.saturating_sub(8_500_000_000),
        _ => good_reserve,
    };
    let reserve_bps = if release_liability_atomic == 0 {
        0
    } else {
        reserved_atomic.saturating_mul(10_000) / release_liability_atomic
    };
    let reserve_slo_met =
        reserved_atomic >= config.min_reserve_floor_atomic && reserve_bps >= config.min_reserve_bps;
    let reserve_slo_root = domain_hash(
        &format!("{DOMAIN}:reserve-slo"),
        &[
            HashPart::Str(&package.package_id),
            HashPart::U64(reserved_atomic),
            HashPart::U64(release_liability_atomic),
            HashPart::U64(reserve_bps),
            HashPart::U64(config.min_reserve_bps),
            HashPart::Str(bool_str(reserve_slo_met)),
        ],
        32,
    );
    let reserve_attestation_root = commitment("reserve-attestation", &package.package_id, ordinal);
    let reserve_id = domain_hash(
        &format!("{DOMAIN}:reserve-id"),
        &[
            HashPart::Str(&package.package_id),
            HashPart::Str(&reserve_slo_root),
            HashPart::Str(&reserve_attestation_root),
        ],
        16,
    );

    ReserveLiquidityStatus {
        reserve_id,
        reserved_atomic,
        release_liability_atomic,
        reserve_bps,
        reserve_slo_root,
        reserve_attestation_root,
        reserve_slo_met,
    }
}

fn privacy_budget_status(
    config: &Config,
    package: &ForceExitPackage,
    ordinal: u64,
    intended_hold: ActivationHold,
) -> PrivacyBudgetStatus {
    let starting_budget_bps = 10_000;
    let previous_remaining_budget_bps = 7_500_u64.saturating_sub(ordinal * 250);
    let remaining_budget_bps = match intended_hold {
        ActivationHold::PrivacyBudgetRegression => config.min_privacy_remaining_bps / 2,
        _ => previous_remaining_budget_bps.saturating_sub(125),
    };
    let regression_bps = previous_remaining_budget_bps.saturating_sub(remaining_budget_bps);
    let regression_detected = remaining_budget_bps < config.min_privacy_remaining_bps
        || regression_bps > config.max_privacy_regression_bps;
    let spend_receipt_root = domain_hash(
        &format!("{DOMAIN}:privacy-spend-receipt"),
        &[
            HashPart::Str(&package.package_id),
            HashPart::U64(previous_remaining_budget_bps),
            HashPart::U64(remaining_budget_bps),
            HashPart::U64(regression_bps),
        ],
        32,
    );
    let privacy_budget_root = domain_hash(
        &format!("{DOMAIN}:privacy-budget"),
        &[
            HashPart::Str(&package.package_id),
            HashPart::U64(starting_budget_bps),
            HashPart::U64(remaining_budget_bps),
            HashPart::U64(config.min_privacy_remaining_bps),
            HashPart::Str(bool_str(regression_detected)),
        ],
        32,
    );
    let budget_id = domain_hash(
        &format!("{DOMAIN}:privacy-budget-id"),
        &[
            HashPart::Str(&package.package_id),
            HashPart::Str(&spend_receipt_root),
            HashPart::Str(&privacy_budget_root),
        ],
        16,
    );

    PrivacyBudgetStatus {
        budget_id,
        starting_budget_bps,
        remaining_budget_bps,
        previous_remaining_budget_bps,
        regression_bps,
        spend_receipt_root,
        privacy_budget_root,
        regression_detected,
    }
}

fn live_receipt(
    config: &Config,
    package: &ForceExitPackage,
    ordinal: u64,
    intended_hold: ActivationHold,
) -> LiveReceipt {
    let present = intended_hold != ActivationHold::MissingLiveReceipt;
    let observed_epoch = match intended_hold {
        ActivationHold::StaleEpoch => package.package_epoch,
        _ => config.current_epoch,
    };
    let release_policy_root = domain_hash(
        &format!("{DOMAIN}:receipt-release-policy"),
        &[
            HashPart::Str(&package.release_policy_id),
            HashPart::Str(&package.package_binding_root),
            HashPart::U64(observed_epoch),
        ],
        32,
    );
    let reserve_snapshot_root =
        commitment("receipt-reserve-snapshot", &package.package_id, ordinal);
    let privacy_snapshot_root =
        commitment("receipt-privacy-snapshot", &package.package_id, ordinal);
    let pq_snapshot_root = commitment("receipt-pq-snapshot", &package.package_id, ordinal);
    let live_receipt_root = domain_hash(
        &format!("{DOMAIN}:live-receipt"),
        &[
            HashPart::Str(&package.package_id),
            HashPart::Str(&release_policy_root),
            HashPart::Str(&reserve_snapshot_root),
            HashPart::Str(&privacy_snapshot_root),
            HashPart::Str(&pq_snapshot_root),
            HashPart::U64(observed_epoch),
            HashPart::Str(bool_str(present)),
        ],
        32,
    );
    let receipt_id = domain_hash(
        &format!("{DOMAIN}:receipt-id"),
        &[
            HashPart::Str(&package.package_id),
            HashPart::Str(&live_receipt_root),
            HashPart::U64(ordinal),
        ],
        16,
    );

    LiveReceipt {
        receipt_id,
        feed_id: "devnet-force-exit-release-policy-live-receipts".to_string(),
        feed_sequence: ordinal + 1,
        observed_epoch,
        live_receipt_root,
        release_policy_root,
        reserve_snapshot_root,
        privacy_snapshot_root,
        pq_snapshot_root,
        present,
    }
}

#[rustfmt::skip]
fn activation_hold(
    config: &Config,
    package: &ForceExitPackage,
    pq_rotation: &PqRotationStatus,
    reserve: &ReserveLiquidityStatus,
    privacy_budget: &PrivacyBudgetStatus,
    live_receipt: &LiveReceipt,
) -> ActivationHold {
    let min_epoch = config.current_epoch.saturating_sub(config.max_stale_epoch_drift);
    if !package.bound_to_release_policy { ActivationHold::PackageBinding }
    else if config.require_live_receipt && !live_receipt.present { ActivationHold::MissingLiveReceipt }
    else if package.package_epoch < min_epoch || live_receipt.observed_epoch < min_epoch { ActivationHold::StaleEpoch }
    else if config.require_pq_rotation && (!pq_rotation.activated || pq_rotation.key_epoch < config.min_pq_key_epoch) { ActivationHold::MissingPqRotation }
    else if !reserve.reserve_slo_met { ActivationHold::ReserveSlo }
    else if privacy_budget.regression_detected { ActivationHold::PrivacyBudgetRegression }
    else { ActivationHold::None }
}

#[rustfmt::skip]
fn activation_verdict(config: &Config, hold: ActivationHold) -> ActivationVerdict {
    match hold {
        ActivationHold::None => ActivationVerdict::Activate,
        ActivationHold::PackageBinding if config.fail_closed => ActivationVerdict::Reject,
        ActivationHold::PackageBinding => ActivationVerdict::Hold,
        ActivationHold::StaleEpoch | ActivationHold::ReserveSlo | ActivationHold::PrivacyBudgetRegression
        | ActivationHold::MissingPqRotation | ActivationHold::MissingLiveReceipt => ActivationVerdict::Hold,
    }
}

#[allow(clippy::too_many_arguments)]
#[rustfmt::skip]
fn activation_verdict_root(
    verdict: ActivationVerdict,
    hold: ActivationHold,
    package: &ForceExitPackage,
    pq_rotation: &PqRotationStatus,
    reserve: &ReserveLiquidityStatus,
    privacy_budget: &PrivacyBudgetStatus,
    live_receipt: &LiveReceipt,
    stale_epoch_hold_root: &str,
    reserve_slo_hold_root: &str,
    privacy_regression_hold_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:activation-verdict"),
        &[HashPart::Str(verdict.as_str()), HashPart::Str(hold.as_str()),
          HashPart::Str(&package.package_id), HashPart::Str(&package.package_binding_root),
          HashPart::Str(&pq_rotation.rotation_transcript_root), HashPart::Str(&reserve.reserve_slo_root),
          HashPart::Str(&privacy_budget.privacy_budget_root), HashPart::Str(&live_receipt.live_receipt_root),
          HashPart::Str(stale_epoch_hold_root), HashPart::Str(reserve_slo_hold_root),
          HashPart::Str(privacy_regression_hold_root)],
        32,
    )
}

#[rustfmt::skip]
fn force_exit_release_root(
    verdict: ActivationVerdict,
    package: &ForceExitPackage,
    live_receipt: &LiveReceipt,
    activation_verdict_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:force-exit-release"),
        &[HashPart::Str(verdict.as_str()), HashPart::Str(&package.user_escape_package_id),
          HashPart::Str(&package.force_exit_claim_id), HashPart::Str(&package.release_policy_id),
          HashPart::Str(&live_receipt.live_receipt_root), HashPart::Str(activation_verdict_root)],
        32,
    )
}

fn policy_hold_root(
    label: &str,
    package_id: &str,
    hold: ActivationHold,
    metrics: &[u64],
) -> String {
    let metric_leaves = metrics
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    let metric_root = merkle_root(&format!("{DOMAIN}:{label}:metrics"), &metric_leaves);
    domain_hash(
        &format!("{DOMAIN}:{label}:hold"),
        &[
            HashPart::Str(package_id),
            HashPart::Str(hold.as_str()),
            HashPart::Str(&metric_root),
        ],
        32,
    )
}

fn short_id(label: &str, seed: &str, ordinal: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[HashPart::Str(seed), HashPart::U64(ordinal)],
        16,
    )
}

fn commitment(label: &str, seed: &str, ordinal: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[HashPart::Str(seed), HashPart::U64(ordinal)],
        32,
    )
}

fn vector_root(label: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "label": label, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &leaves)
}

#[rustfmt::skip]
fn record_root(label: &str, record: &Value) -> String {
    domain_hash(&format!("{DOMAIN}:{label}"), &[HashPart::Str(CHAIN_ID), HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)], 32)
}

#[rustfmt::skip]
fn bool_str(value: bool) -> &'static str { if value { "true" } else { "false" } }

fn fallback_state(reason: String) -> State {
    let config = Config::devnet();
    let reason_root = domain_hash(&format!("{DOMAIN}:fallback"), &[HashPart::Str(&reason)], 32);
    let rejected_ids = vec![reason_root];
    State {
        config,
        receipts: Vec::new(),
        counters: ActivationCounters::default(),
        activated_ids: Vec::new(),
        held_ids: Vec::new(),
        rejected_ids,
    }
}
