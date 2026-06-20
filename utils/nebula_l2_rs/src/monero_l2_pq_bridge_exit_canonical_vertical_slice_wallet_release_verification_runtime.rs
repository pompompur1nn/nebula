use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWalletReleaseVerificationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-wallet-release-verification-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_ACTION_FORCE_EXIT: &str = "wallet_release_force_exit";

const DOMAIN: &str = "MONERO-L2-PQ-BRIDGE-WALLET-RELEASE-VERIFICATION";
const DEFAULT_SCAN_START_HEIGHT: u64 = 3_525_600;
const DEFAULT_SCAN_END_HEIGHT: u64 = 3_526_320;
const DEFAULT_PRIVACY_BUDGET_BITS: u64 = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserExitVerdict {
    ForceExitSafe,
    HoldMissingReceipt,
    HoldStaleReceipt,
    HoldReplayedReceipt,
    HoldRootMismatch,
    HoldPrivacyBudgetExceeded,
}

impl UserExitVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForceExitSafe => "force_exit_safe",
            Self::HoldMissingReceipt => "hold_missing_receipt",
            Self::HoldStaleReceipt => "hold_stale_receipt",
            Self::HoldReplayedReceipt => "hold_replayed_receipt",
            Self::HoldRootMismatch => "hold_root_mismatch",
            Self::HoldPrivacyBudgetExceeded => "hold_privacy_budget_exceeded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub scan_start_height: u64,
    pub scan_end_height: u64,
    pub max_privacy_budget_bits: u64,
    pub expected_release_action: String,
    pub fail_closed_default_verdict: UserExitVerdict,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            scan_start_height: DEFAULT_SCAN_START_HEIGHT,
            scan_end_height: DEFAULT_SCAN_END_HEIGHT,
            max_privacy_budget_bits: DEFAULT_PRIVACY_BUDGET_BITS,
            expected_release_action: RELEASE_ACTION_FORCE_EXIT.to_string(),
            fail_closed_default_verdict: UserExitVerdict::HoldMissingReceipt,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "scan_height_window": {
                "start": self.scan_start_height,
                "end": self.scan_end_height
            },
            "max_privacy_budget_bits": self.max_privacy_budget_bits,
            "expected_release_action": self.expected_release_action,
            "fail_closed_default_verdict": self.fail_closed_default_verdict.as_str()
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:config"),
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletVerificationLanes {
    pub wallet_receipt_root: String,
    pub recovery_binding_root: String,
    pub nullifier_linkage_root: String,
    pub user_claim_id: String,
    pub expected_release_action: String,
    pub observed_release_receipt_root: String,
    pub observed_scan_height: u64,
    pub disclosed_privacy_budget_bits: u64,
    pub stale_receipt_hold: bool,
    pub missing_receipt_hold: bool,
    pub replayed_receipt_hold: bool,
}

impl WalletVerificationLanes {
    pub fn devnet() -> Self {
        let user_claim_id = domain_hash(
            &format!("{DOMAIN}:claim-id"),
            &[HashPart::Str("devnet-wallet-release-claim")],
            16,
        );
        let wallet_receipt_root = lane_root("wallet-receipt", &user_claim_id);
        let recovery_binding_root = lane_root("recovery-binding", &user_claim_id);
        let nullifier_linkage_root = lane_root("nullifier-linkage", &user_claim_id);
        let observed_release_receipt_root = release_receipt_root(
            &wallet_receipt_root,
            &recovery_binding_root,
            &nullifier_linkage_root,
            &user_claim_id,
            RELEASE_ACTION_FORCE_EXIT,
        );

        Self {
            wallet_receipt_root,
            recovery_binding_root,
            nullifier_linkage_root,
            user_claim_id,
            expected_release_action: RELEASE_ACTION_FORCE_EXIT.to_string(),
            observed_release_receipt_root,
            observed_scan_height: DEFAULT_SCAN_END_HEIGHT,
            disclosed_privacy_budget_bits: 48,
            stale_receipt_hold: false,
            missing_receipt_hold: false,
            replayed_receipt_hold: false,
        }
    }

    pub fn expected_release_receipt_root(&self) -> String {
        release_receipt_root(
            &self.wallet_receipt_root,
            &self.recovery_binding_root,
            &self.nullifier_linkage_root,
            &self.user_claim_id,
            &self.expected_release_action,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "wallet_receipt_root": self.wallet_receipt_root,
            "recovery_binding_root": self.recovery_binding_root,
            "nullifier_linkage_root": self.nullifier_linkage_root,
            "scan_height": self.observed_scan_height,
            "privacy_budget": {
                "disclosed_bits": self.disclosed_privacy_budget_bits
            },
            "user_claim_id": self.user_claim_id,
            "expected_release_action": self.expected_release_action,
            "observed_release_receipt_root": self.observed_release_receipt_root,
            "holds": {
                "stale_receipt": self.stale_receipt_hold,
                "missing_receipt": self.missing_receipt_hold,
                "replayed_receipt": self.replayed_receipt_hold
            },
            "expected_release_receipt_root": self.expected_release_receipt_root()
        })
    }

    pub fn root(&self) -> String {
        let lane_leaf_root = merkle_root(
            &format!("{DOMAIN}:wallet-verification-lane-leaves"),
            &[
                json!(self.wallet_receipt_root),
                json!(self.recovery_binding_root),
                json!(self.nullifier_linkage_root),
                json!(self.observed_release_receipt_root),
            ],
        );
        domain_hash(
            &format!("{DOMAIN}:wallet-verification-lanes"),
            &[
                HashPart::Json(&self.public_record()),
                HashPart::Str(&lane_leaf_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub lanes: WalletVerificationLanes,
    pub verdict: UserExitVerdict,
    pub verdict_reason: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let lanes = WalletVerificationLanes::devnet();
        let (verdict, verdict_reason) = evaluate_wallet_release(&config, &lanes);

        Self {
            config,
            lanes,
            verdict,
            verdict_reason,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "wallet_verification_lanes": self.lanes.public_record(),
            "lane_roots": {
                "config_root": self.config.root(),
                "verification_root": self.lanes.root()
            },
            "fail_closed": {
                "default_verdict": self.config.fail_closed_default_verdict.as_str(),
                "receipt_required": "true",
                "stale_receipts_rejected": "true",
                "replayed_receipts_rejected": "true"
            },
            "user_exit_verdict": {
                "verdict": self.verdict.as_str(),
                "reason": self.verdict_reason
            }
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[
                HashPart::Str(&self.config.root()),
                HashPart::Str(&self.lanes.root()),
                HashPart::Str(self.verdict.as_str()),
                HashPart::Str(&self.verdict_reason),
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

pub fn verify_wallet_release(
    state: &State,
) -> MoneroL2PqBridgeExitCanonicalVerticalSliceWalletReleaseVerificationRuntimeResult<UserExitVerdict>
{
    let (verdict, reason) = evaluate_wallet_release(&state.config, &state.lanes);
    if verdict == state.verdict {
        Ok(verdict)
    } else {
        Err(format!(
            "wallet release verdict mismatch: recorded={} evaluated={} reason={}",
            state.verdict.as_str(),
            verdict.as_str(),
            reason
        ))
    }
}

fn evaluate_wallet_release(
    config: &Config,
    lanes: &WalletVerificationLanes,
) -> (UserExitVerdict, String) {
    if lanes.missing_receipt_hold {
        return (
            UserExitVerdict::HoldMissingReceipt,
            "observed wallet release receipt is missing".to_string(),
        );
    }
    if lanes.stale_receipt_hold || lanes.observed_scan_height < config.scan_start_height {
        return (
            UserExitVerdict::HoldStaleReceipt,
            "wallet release receipt is outside the accepted scan window".to_string(),
        );
    }
    if lanes.replayed_receipt_hold {
        return (
            UserExitVerdict::HoldReplayedReceipt,
            "wallet release receipt linkage was already used".to_string(),
        );
    }
    if lanes.disclosed_privacy_budget_bits > config.max_privacy_budget_bits {
        return (
            UserExitVerdict::HoldPrivacyBudgetExceeded,
            "wallet evidence discloses more than the allowed privacy budget".to_string(),
        );
    }
    if lanes.expected_release_action != config.expected_release_action {
        return (
            UserExitVerdict::HoldRootMismatch,
            "wallet evidence release action differs from configured force-exit action".to_string(),
        );
    }
    if lanes.observed_release_receipt_root != lanes.expected_release_receipt_root() {
        return (
            UserExitVerdict::HoldRootMismatch,
            "observed release receipt root does not bind all wallet verification lanes".to_string(),
        );
    }
    if lanes.observed_scan_height > config.scan_end_height {
        return (
            UserExitVerdict::HoldStaleReceipt,
            "wallet release receipt was observed after the accepted scan window".to_string(),
        );
    }

    (
        UserExitVerdict::ForceExitSafe,
        "wallet receipt, recovery binding, nullifier linkage, scan window, privacy budget, and release action all match".to_string(),
    )
}

fn lane_root(label: &str, user_claim_id: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-root"),
        &[HashPart::Str(label), HashPart::Str(user_claim_id)],
        32,
    )
}

fn release_receipt_root(
    wallet_receipt_root: &str,
    recovery_binding_root: &str,
    nullifier_linkage_root: &str,
    user_claim_id: &str,
    release_action: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:release-receipt-root"),
        &[
            HashPart::Str(wallet_receipt_root),
            HashPart::Str(recovery_binding_root),
            HashPart::Str(nullifier_linkage_root),
            HashPart::Str(user_claim_id),
            HashPart::Str(release_action),
        ],
        32,
    )
}
