use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeDepositLockProofRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_PROOF_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-proof-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_PROOF_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PROOF_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-proof-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_512_040;
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_224_900;
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_REORG_WINDOW_BLOCKS: u64 = 6;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 5;
pub const DEFAULT_MAX_PROOFS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositLockProofStatus {
    Proven,
    Watch,
    Rejected,
}

impl DepositLockProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedGap {
    None,
    ConfirmationDepth,
    ReorgWindow,
    WatcherQuorum,
    CustodyPolicy,
    WalletClaimBinding,
}

impl FailClosedGap {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ConfirmationDepth => "confirmation_depth",
            Self::ReorgWindow => "reorg_window",
            Self::WatcherQuorum => "watcher_quorum",
            Self::CustodyPolicy => "custody_policy",
            Self::WalletClaimBinding => "wallet_claim_binding",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub proof_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub base_monero_height: u64,
    pub l2_reference_height: u64,
    pub min_confirmations: u64,
    pub reorg_window_blocks: u64,
    pub min_watcher_weight: u64,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub max_proofs: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            proof_suite: PROOF_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            reorg_window_blocks: DEFAULT_REORG_WINDOW_BLOCKS,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            fail_closed: true,
            production_release_allowed: false,
            max_proofs: DEFAULT_MAX_PROOFS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "proof_suite": self.proof_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "base_monero_height": self.base_monero_height,
            "l2_reference_height": self.l2_reference_height,
            "min_confirmations": self.min_confirmations,
            "reorg_window_blocks": self.reorg_window_blocks,
            "min_watcher_weight": self.min_watcher_weight,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
            "max_proofs": self.max_proofs,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLockProof {
    pub proof_id: String,
    pub status: DepositLockProofStatus,
    pub fail_closed_gap: FailClosedGap,
    pub user_escape_package_id: String,
    pub monero_lock_tx_commitment: String,
    pub deposit_address_commitment: String,
    pub amount_commitment: String,
    pub confirmation_root: String,
    pub reorg_window_root: String,
    pub watcher_quorum_root: String,
    pub bridge_custody_policy_root: String,
    pub wallet_claim_binding_root: String,
    pub fail_closed_gap_root: String,
    pub observed_monero_height: u64,
    pub observed_confirmations: u64,
    pub required_confirmations: u64,
    pub reorg_window_blocks: u64,
    pub watcher_weight: u64,
    pub required_watcher_weight: u64,
    pub proof_root: String,
}

impl DepositLockProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "status": self.status.as_str(),
            "fail_closed_gap": self.fail_closed_gap.as_str(),
            "user_escape_package_id": self.user_escape_package_id,
            "monero_lock_tx_commitment": self.monero_lock_tx_commitment,
            "deposit_address_commitment": self.deposit_address_commitment,
            "amount_commitment": self.amount_commitment,
            "confirmation_root": self.confirmation_root,
            "reorg_window_root": self.reorg_window_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "bridge_custody_policy_root": self.bridge_custody_policy_root,
            "wallet_claim_binding_root": self.wallet_claim_binding_root,
            "fail_closed_gap_root": self.fail_closed_gap_root,
            "observed_monero_height": self.observed_monero_height,
            "observed_confirmations": self.observed_confirmations,
            "required_confirmations": self.required_confirmations,
            "reorg_window_blocks": self.reorg_window_blocks,
            "watcher_weight": self.watcher_weight,
            "required_watcher_weight": self.required_watcher_weight,
            "proof_root": self.proof_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-PROOF",
            &[
                HashPart::Str(&self.user_escape_package_id),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(self.fail_closed_gap.as_str()),
                HashPart::Str(&self.monero_lock_tx_commitment),
                HashPart::Str(&self.deposit_address_commitment),
                HashPart::Str(&self.amount_commitment),
                HashPart::Str(&self.confirmation_root),
                HashPart::Str(&self.reorg_window_root),
                HashPart::Str(&self.watcher_quorum_root),
                HashPart::Str(&self.bridge_custody_policy_root),
                HashPart::Str(&self.wallet_claim_binding_root),
                HashPart::Str(&self.fail_closed_gap_root),
                HashPart::U64(self.observed_monero_height),
                HashPart::U64(self.observed_confirmations),
                HashPart::U64(self.required_confirmations),
                HashPart::U64(self.reorg_window_blocks),
                HashPart::U64(self.watcher_weight),
                HashPart::U64(self.required_watcher_weight),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub proofs: Vec<DepositLockProof>,
    pub proven_proof_ids: Vec<String>,
    pub watch_proof_ids: Vec<String>,
    pub rejected_proof_ids: Vec<String>,
    pub devnet_data: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, proofs: Vec<DepositLockProof>) -> Result<Self> {
        if proofs.len() > config.max_proofs {
            return Err(format!(
                "proof count {} exceeds configured max {}",
                proofs.len(),
                config.max_proofs
            ));
        }

        let mut seen = BTreeMap::<String, String>::new();
        let mut proven_proof_ids = Vec::new();
        let mut watch_proof_ids = Vec::new();
        let mut rejected_proof_ids = Vec::new();

        for proof in &proofs {
            if let Some(existing) =
                seen.insert(proof.user_escape_package_id.clone(), proof.proof_id.clone())
            {
                return Err(format!(
                    "duplicate user escape package {} across proofs {} and {}",
                    proof.user_escape_package_id, existing, proof.proof_id
                ));
            }
            match proof.status {
                DepositLockProofStatus::Proven => proven_proof_ids.push(proof.proof_id.clone()),
                DepositLockProofStatus::Watch => watch_proof_ids.push(proof.proof_id.clone()),
                DepositLockProofStatus::Rejected => rejected_proof_ids.push(proof.proof_id.clone()),
            }
        }

        Ok(Self {
            config,
            proofs,
            proven_proof_ids,
            watch_proof_ids,
            rejected_proof_ids,
            devnet_data: devnet_data(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let proofs = self
            .proofs
            .iter()
            .map(DepositLockProof::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "proofs": proofs,
            "proven_proof_ids": self.proven_proof_ids,
            "watch_proof_ids": self.watch_proof_ids,
            "rejected_proof_ids": self.rejected_proof_ids,
            "roots": {
                "config_root": self.config.state_root(),
                "proof_root": self.proof_root(),
                "proven_root": self.proven_root(),
                "watch_root": self.watch_root(),
                "rejected_root": self.rejected_root(),
                "devnet_data_root": self.devnet_data_root(),
            },
            "devnet_data": self.devnet_data,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-PROOF-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn proof_root(&self) -> String {
        let records = self
            .proofs
            .iter()
            .map(DepositLockProof::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-PROOFS",
            &records,
        )
    }

    pub fn proven_root(&self) -> String {
        vector_root("PROVEN", &self.proven_proof_ids)
    }

    pub fn watch_root(&self) -> String {
        vector_root("WATCH", &self.watch_proof_ids)
    }

    pub fn rejected_root(&self) -> String {
        vector_root("REJECTED", &self.rejected_proof_ids)
    }

    pub fn devnet_data_root(&self) -> String {
        let records = self
            .devnet_data
            .iter()
            .map(|(key, value)| json!({ "key": key, "value": value }))
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-PROOF-DEVNET-DATA",
            &records,
        )
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let proofs = devnet_proofs(&config);
    match State::new(config, proofs) {
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

pub fn devnet_proofs(config: &Config) -> Vec<DepositLockProof> {
    vec![
        build_proof(
            config,
            0,
            DepositLockProofStatus::Proven,
            FailClosedGap::None,
        ),
        build_proof(
            config,
            1,
            DepositLockProofStatus::Watch,
            FailClosedGap::ConfirmationDepth,
        ),
        build_proof(
            config,
            2,
            DepositLockProofStatus::Rejected,
            FailClosedGap::WatcherQuorum,
        ),
        build_proof(
            config,
            3,
            DepositLockProofStatus::Rejected,
            FailClosedGap::WalletClaimBinding,
        ),
    ]
}

fn build_proof(
    config: &Config,
    ordinal: u64,
    status: DepositLockProofStatus,
    fail_closed_gap: FailClosedGap,
) -> DepositLockProof {
    let label = format!("user-escape-deposit-lock-proof-{ordinal}");
    let observed_confirmations = match fail_closed_gap {
        FailClosedGap::ConfirmationDepth => config.min_confirmations.saturating_sub(5),
        FailClosedGap::ReorgWindow => config.min_confirmations,
        _ => config.min_confirmations + ordinal,
    };
    let watcher_weight = match fail_closed_gap {
        FailClosedGap::WatcherQuorum => config.min_watcher_weight.saturating_sub(2),
        _ => config.min_watcher_weight + 1,
    };
    let user_escape_package_id = domain_hash(
        "MONERO-DEVNET-USER-ESCAPE-PACKAGE",
        &[HashPart::Str(&label)],
        16,
    );
    let monero_lock_tx_commitment = commitment("MONERO-LOCK-TX", &label, ordinal);
    let deposit_address_commitment = commitment("DEPOSIT-ADDRESS", &label, ordinal);
    let amount_commitment = commitment("AMOUNT", &label, ordinal);
    let confirmation_root = domain_hash(
        "MONERO-DEVNET-CONFIRMATION-WINDOW",
        &[
            HashPart::Str(&monero_lock_tx_commitment),
            HashPart::U64(observed_confirmations),
            HashPart::U64(config.min_confirmations),
        ],
        32,
    );
    let reorg_window_root = domain_hash(
        "MONERO-DEVNET-REORG-WINDOW",
        &[
            HashPart::Str(&monero_lock_tx_commitment),
            HashPart::U64(config.reorg_window_blocks),
            HashPart::Str(fail_closed_gap.as_str()),
        ],
        32,
    );
    let watcher_quorum_root = domain_hash(
        "MONERO-DEVNET-WATCHER-QUORUM",
        &[
            HashPart::Str(&label),
            HashPart::U64(watcher_weight),
            HashPart::U64(config.min_watcher_weight),
        ],
        32,
    );
    let bridge_custody_policy_root = domain_hash(
        "MONERO-DEVNET-BRIDGE-CUSTODY-POLICY",
        &[
            HashPart::Str(&deposit_address_commitment),
            HashPart::Str(match fail_closed_gap {
                FailClosedGap::CustodyPolicy => "gap",
                _ => "satisfied",
            }),
        ],
        32,
    );
    let wallet_claim_binding_root = domain_hash(
        "MONERO-DEVNET-WALLET-CLAIM-BINDING",
        &[
            HashPart::Str(&user_escape_package_id),
            HashPart::Str(&amount_commitment),
            HashPart::Str(match fail_closed_gap {
                FailClosedGap::WalletClaimBinding => "gap",
                _ => "satisfied",
            }),
        ],
        32,
    );
    let fail_closed_gap_root = domain_hash(
        "MONERO-DEVNET-FAIL-CLOSED-GAP",
        &[
            HashPart::Str(fail_closed_gap.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(&user_escape_package_id),
        ],
        32,
    );
    let mut proof = DepositLockProof {
        proof_id: String::new(),
        status,
        fail_closed_gap,
        user_escape_package_id,
        monero_lock_tx_commitment,
        deposit_address_commitment,
        amount_commitment,
        confirmation_root,
        reorg_window_root,
        watcher_quorum_root,
        bridge_custody_policy_root,
        wallet_claim_binding_root,
        fail_closed_gap_root,
        observed_monero_height: config.base_monero_height + ordinal,
        observed_confirmations,
        required_confirmations: config.min_confirmations,
        reorg_window_blocks: config.reorg_window_blocks,
        watcher_weight,
        required_watcher_weight: config.min_watcher_weight,
        proof_root: String::new(),
    };
    proof.proof_root = proof.root();
    proof.proof_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-PROOF-ID",
        &[
            HashPart::Str(&proof.user_escape_package_id),
            HashPart::Str(&proof.proof_root),
        ],
        16,
    );
    proof
}

fn commitment(domain: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        &format!("MONERO-DEVNET-{domain}-COMMITMENT"),
        &[HashPart::Str(label), HashPart::U64(ordinal)],
        32,
    )
}

fn vector_root(label: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "label": label, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-PROOF-{label}"),
        &leaves,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-PROOF-RECORD",
        &[HashPart::Str(label), HashPart::Json(record)],
        32,
    )
}

fn devnet_data() -> BTreeMap<String, Value> {
    let mut data = BTreeMap::new();
    data.insert(
        "public_inputs".to_string(),
        json!({
            "monero_lock_tx_commitment": "rooted-not-raw-tx",
            "deposit_address_commitment": "rooted-not-raw-address",
            "amount_commitment": "pedersen-or-range-proof-bound-root",
            "confirmation_reorg_window": "depth-plus-reorg-margin-root",
            "watcher_quorum": "weighted-pq-attestation-root",
            "bridge_custody_policy_root": "custody-policy-root",
            "wallet_claim_binding_root": "wallet-escape-claim-root",
            "fail_closed_gaps": "explicit-gap-root"
        }),
    );
    data.insert(
        "fail_closed_policy".to_string(),
        json!({
            "missing_confirmation_depth": "watch",
            "reorg_window_gap": "reject",
            "watcher_quorum_gap": "reject",
            "custody_policy_gap": "reject",
            "wallet_claim_binding_gap": "reject"
        }),
    );
    data
}

fn fallback_state(reason: String) -> State {
    let config = Config::devnet();
    let mut devnet_data = devnet_data();
    devnet_data.insert(
        "construction_error".to_string(),
        json!({
            "reason_root": domain_hash(
                "MONERO-DEVNET-USER-ESCAPE-DEPOSIT-LOCK-PROOF-FALLBACK",
                &[HashPart::Str(&reason)],
                32
            )
        }),
    );
    State {
        config,
        proofs: Vec::new(),
        proven_proof_ids: Vec::new(),
        watch_proof_ids: Vec::new(),
        rejected_proof_ids: Vec::new(),
        devnet_data,
    }
}
