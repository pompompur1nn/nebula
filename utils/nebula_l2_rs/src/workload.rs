use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type WorkloadResult<T> = Result<T, String>;

pub const WORKLOAD_PROTOCOL_VERSION: &str = "nebula-l2-workload-v1";
pub const WORKLOAD_DEFAULT_BATCH_SIZE: u64 = 24;
pub const WORKLOAD_DEFAULT_PRIVACY_WEIGHT: u64 = 40;
pub const WORKLOAD_DEFAULT_DEFI_WEIGHT: u64 = 35;
pub const WORKLOAD_DEFAULT_BRIDGE_WEIGHT: u64 = 15;
pub const WORKLOAD_DEFAULT_MAINTENANCE_WEIGHT: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WorkloadIntentKind {
    PrivateTransfer,
    AssetMint,
    AssetBurn,
    AmmSwap,
    AmmLiquidityAdd,
    LendingBorrow,
    LendingRepay,
    ContractCall,
    WasmCall,
    PaymasterSponsoredCall,
    BridgeDeposit,
    BridgeWithdrawal,
    OracleUpdate,
    ProofJob,
}

impl WorkloadIntentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::AssetMint => "asset_mint",
            Self::AssetBurn => "asset_burn",
            Self::AmmSwap => "amm_swap",
            Self::AmmLiquidityAdd => "amm_liquidity_add",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::ContractCall => "contract_call",
            Self::WasmCall => "wasm_call",
            Self::PaymasterSponsoredCall => "paymaster_sponsored_call",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::OracleUpdate => "oracle_update",
            Self::ProofJob => "proof_job",
        }
    }

    pub fn default_fee_class(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "low_fee_privacy",
            Self::BridgeDeposit | Self::BridgeWithdrawal => "low_fee_bridge",
            Self::AmmSwap
            | Self::AmmLiquidityAdd
            | Self::LendingBorrow
            | Self::LendingRepay
            | Self::ContractCall
            | Self::WasmCall
            | Self::PaymasterSponsoredCall => "low_fee_defi",
            Self::AssetMint | Self::AssetBurn | Self::OracleUpdate | Self::ProofJob => "standard",
        }
    }

    pub fn default_privacy_class(&self) -> &'static str {
        match self {
            Self::PrivateTransfer
            | Self::AmmSwap
            | Self::BridgeDeposit
            | Self::BridgeWithdrawal
            | Self::PaymasterSponsoredCall => "shielded",
            Self::ContractCall | Self::WasmCall | Self::LendingBorrow | Self::LendingRepay => {
                "metadata_minimized"
            }
            _ => "public_root_only",
        }
    }

    pub fn default_weight(&self) -> u64 {
        match self {
            Self::PrivateTransfer => 18,
            Self::AmmSwap => 12,
            Self::ContractCall => 10,
            Self::BridgeDeposit => 8,
            Self::BridgeWithdrawal => 7,
            Self::AssetMint => 5,
            Self::AssetBurn => 4,
            Self::AmmLiquidityAdd => 5,
            Self::LendingBorrow => 5,
            Self::LendingRepay => 5,
            Self::WasmCall => 8,
            Self::PaymasterSponsoredCall => 7,
            Self::OracleUpdate => 3,
            Self::ProofJob => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadProfile {
    pub profile_id: String,
    pub profile_name: String,
    pub target_batch_size: u64,
    pub privacy_weight: u64,
    pub defi_weight: u64,
    pub bridge_weight: u64,
    pub maintenance_weight: u64,
    pub low_fee_bias_bps: u64,
    pub max_payload_bytes: u64,
    pub intent_weights: BTreeMap<String, u64>,
}

impl WorkloadProfile {
    pub fn balanced_private_defi() -> Self {
        let mut intent_weights = BTreeMap::new();
        for kind in default_workload_kinds() {
            intent_weights.insert(kind.as_str().to_string(), kind.default_weight());
        }
        let mut profile = Self {
            profile_id: String::new(),
            profile_name: "balanced_private_defi".to_string(),
            target_batch_size: WORKLOAD_DEFAULT_BATCH_SIZE,
            privacy_weight: WORKLOAD_DEFAULT_PRIVACY_WEIGHT,
            defi_weight: WORKLOAD_DEFAULT_DEFI_WEIGHT,
            bridge_weight: WORKLOAD_DEFAULT_BRIDGE_WEIGHT,
            maintenance_weight: WORKLOAD_DEFAULT_MAINTENANCE_WEIGHT,
            low_fee_bias_bps: 8_500,
            max_payload_bytes: 8 * 1024,
            intent_weights,
        };
        profile.profile_id = workload_profile_id(&profile.identity_record());
        profile
    }

    pub fn speed_stress() -> Self {
        let mut profile = Self::balanced_private_defi();
        profile.profile_name = "speed_stress".to_string();
        profile.target_batch_size = 128;
        profile.privacy_weight = 30;
        profile.defi_weight = 45;
        profile.bridge_weight = 10;
        profile.maintenance_weight = 15;
        profile.low_fee_bias_bps = 7_500;
        profile.max_payload_bytes = 4 * 1024;
        profile.profile_id = workload_profile_id(&profile.identity_record());
        profile
    }

    pub fn bridge_heavy() -> Self {
        let mut profile = Self::balanced_private_defi();
        profile.profile_name = "bridge_heavy".to_string();
        profile.target_batch_size = 48;
        profile.privacy_weight = 35;
        profile.defi_weight = 20;
        profile.bridge_weight = 35;
        profile.maintenance_weight = 10;
        profile.low_fee_bias_bps = 9_200;
        profile.profile_id = workload_profile_id(&profile.identity_record());
        profile
    }

    pub fn with_batch_size(mut self, target_batch_size: u64) -> Self {
        self.target_batch_size = target_batch_size.max(1);
        self.profile_id = workload_profile_id(&self.identity_record());
        self
    }

    pub fn weight_for(&self, kind: &WorkloadIntentKind) -> u64 {
        self.intent_weights
            .get(kind.as_str())
            .cloned()
            .unwrap_or_else(|| kind.default_weight())
    }

    pub fn weighted_kinds(&self) -> Vec<WorkloadIntentKind> {
        let mut weighted = Vec::new();
        for kind in default_workload_kinds() {
            let repeat = self.weight_for(&kind).max(1);
            for _ in 0..repeat {
                weighted.push(kind.clone());
            }
        }
        weighted
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "workload_profile",
            "chain_id": CHAIN_ID,
            "workload_protocol_version": WORKLOAD_PROTOCOL_VERSION,
            "profile_name": self.profile_name,
            "target_batch_size": self.target_batch_size,
            "privacy_weight": self.privacy_weight,
            "defi_weight": self.defi_weight,
            "bridge_weight": self.bridge_weight,
            "maintenance_weight": self.maintenance_weight,
            "low_fee_bias_bps": self.low_fee_bias_bps,
            "max_payload_bytes": self.max_payload_bytes,
            "intent_weights": self.intent_weights,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("workload profile public record object");
        object.insert(
            "profile_id".to_string(),
            Value::String(self.profile_id.clone()),
        );
        object.insert(
            "profile_root".to_string(),
            Value::String(self.profile_root()),
        );
        record
    }

    pub fn profile_root(&self) -> String {
        domain_hash(
            "WORKLOAD-PROFILE",
            &[HashPart::Json(&self.identity_record())],
            32,
        )
    }
}

impl Default for WorkloadProfile {
    fn default() -> Self {
        Self::balanced_private_defi()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIntent {
    pub intent_id: String,
    pub kind: WorkloadIntentKind,
    pub sequence: u64,
    pub target_height: u64,
    pub account_commitment: String,
    pub asset_commitment: String,
    pub amount_bucket: String,
    pub fee_class: String,
    pub privacy_class: String,
    pub payload_root: String,
    pub payload_bytes: u64,
    pub low_fee_lane: bool,
    pub requires_bridge: bool,
    pub requires_proof: bool,
    pub deadline_height: u64,
}

impl WorkloadIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: WorkloadIntentKind,
        sequence: u64,
        target_height: u64,
        account_commitment: impl Into<String>,
        asset_commitment: impl Into<String>,
        amount_bucket: impl Into<String>,
        payload: &Value,
        low_fee_lane: bool,
        deadline_height: u64,
    ) -> Self {
        let account_commitment = account_commitment.into();
        let asset_commitment = asset_commitment.into();
        let amount_bucket = amount_bucket.into();
        let fee_class = kind.default_fee_class().to_string();
        let privacy_class = kind.default_privacy_class().to_string();
        let payload_root = workload_payload_root("WORKLOAD-INTENT-PAYLOAD", payload);
        let payload_bytes = serde_json::to_vec(payload)
            .map(|bytes| bytes.len() as u64)
            .unwrap_or_default();
        let requires_bridge = matches!(
            kind,
            WorkloadIntentKind::BridgeDeposit | WorkloadIntentKind::BridgeWithdrawal
        );
        let requires_proof = !matches!(kind, WorkloadIntentKind::OracleUpdate);
        let intent_id = workload_intent_id(
            kind.as_str(),
            sequence,
            target_height,
            &account_commitment,
            &asset_commitment,
            &amount_bucket,
            &payload_root,
        );
        Self {
            intent_id,
            kind,
            sequence,
            target_height,
            account_commitment,
            asset_commitment,
            amount_bucket,
            fee_class,
            privacy_class,
            payload_root,
            payload_bytes,
            low_fee_lane,
            requires_bridge,
            requires_proof,
            deadline_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "workload_intent",
            "chain_id": CHAIN_ID,
            "workload_protocol_version": WORKLOAD_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "intent_kind": self.kind.as_str(),
            "sequence": self.sequence,
            "target_height": self.target_height,
            "account_commitment": self.account_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_bucket": self.amount_bucket,
            "fee_class": self.fee_class,
            "privacy_class": self.privacy_class,
            "payload_root": self.payload_root,
            "payload_bytes": self.payload_bytes,
            "low_fee_lane": self.low_fee_lane,
            "requires_bridge": self.requires_bridge,
            "requires_proof": self.requires_proof,
            "deadline_height": self.deadline_height,
        })
    }

    pub fn intent_root(&self) -> String {
        domain_hash(
            "WORKLOAD-INTENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadBatch {
    pub batch_id: String,
    pub profile_id: String,
    pub height: u64,
    pub batch_sequence: u64,
    pub intent_root: String,
    pub intent_count: u64,
    pub low_fee_count: u64,
    pub bridge_count: u64,
    pub proof_count: u64,
    pub total_payload_bytes: u64,
}

impl WorkloadBatch {
    pub fn new(
        profile: &WorkloadProfile,
        height: u64,
        batch_sequence: u64,
        intents: &[WorkloadIntent],
    ) -> Self {
        let intent_root = workload_intent_root(intents);
        let intent_count = intents.len() as u64;
        let low_fee_count = intents.iter().filter(|intent| intent.low_fee_lane).count() as u64;
        let bridge_count = intents
            .iter()
            .filter(|intent| intent.requires_bridge)
            .count() as u64;
        let proof_count = intents
            .iter()
            .filter(|intent| intent.requires_proof)
            .count() as u64;
        let total_payload_bytes = intents
            .iter()
            .map(|intent| intent.payload_bytes)
            .fold(0_u64, u64::saturating_add);
        let batch_id = workload_batch_id(
            &profile.profile_id,
            height,
            batch_sequence,
            &intent_root,
            intent_count,
        );
        Self {
            batch_id,
            profile_id: profile.profile_id.clone(),
            height,
            batch_sequence,
            intent_root,
            intent_count,
            low_fee_count,
            bridge_count,
            proof_count,
            total_payload_bytes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "workload_batch",
            "chain_id": CHAIN_ID,
            "workload_protocol_version": WORKLOAD_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "profile_id": self.profile_id,
            "height": self.height,
            "batch_sequence": self.batch_sequence,
            "intent_root": self.intent_root,
            "intent_count": self.intent_count,
            "low_fee_count": self.low_fee_count,
            "bridge_count": self.bridge_count,
            "proof_count": self.proof_count,
            "total_payload_bytes": self.total_payload_bytes,
        })
    }

    pub fn batch_root(&self) -> String {
        domain_hash(
            "WORKLOAD-BATCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadPlannerState {
    pub profile: WorkloadProfile,
    pub current_height: u64,
    pub next_sequence: u64,
    pub batches: BTreeMap<String, WorkloadBatch>,
    pub intents: BTreeMap<String, WorkloadIntent>,
}

impl WorkloadPlannerState {
    pub fn new(profile: WorkloadProfile) -> Self {
        Self {
            profile,
            current_height: 0,
            next_sequence: 0,
            batches: BTreeMap::new(),
            intents: BTreeMap::new(),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    pub fn plan_height(&mut self, height: u64) -> WorkloadResult<WorkloadBatch> {
        self.current_height = height;
        let weighted = self.profile.weighted_kinds();
        if weighted.is_empty() {
            return Err("workload profile has no intent kinds".to_string());
        }
        let mut planned = Vec::new();
        for offset in 0..self.profile.target_batch_size {
            let selector = deterministic_selector(height, self.next_sequence, offset);
            let kind = weighted[(selector as usize) % weighted.len()].clone();
            let payload = self.intent_payload(&kind, height, self.next_sequence);
            let low_fee_lane = selector % 10_000 < self.profile.low_fee_bias_bps;
            let intent = WorkloadIntent::new(
                kind,
                self.next_sequence,
                height,
                deterministic_commitment("WORKLOAD-ACCOUNT", height, self.next_sequence),
                deterministic_commitment("WORKLOAD-ASSET", height, selector),
                amount_bucket(selector),
                &payload,
                low_fee_lane,
                height.saturating_add(8),
            );
            self.next_sequence = self.next_sequence.saturating_add(1);
            self.intents
                .insert(intent.intent_id.clone(), intent.clone());
            planned.push(intent);
        }
        let batch = WorkloadBatch::new(&self.profile, height, self.batches.len() as u64, &planned);
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn pending_intents_for_height(&self, height: u64) -> Vec<WorkloadIntent> {
        self.intents
            .values()
            .filter(|intent| intent.target_height <= height && height <= intent.deadline_height)
            .cloned()
            .collect()
    }

    pub fn expire_old_intents(&mut self, height: u64) -> usize {
        let before = self.intents.len();
        self.intents
            .retain(|_, intent| height <= intent.deadline_height);
        before.saturating_sub(self.intents.len())
    }

    pub fn intent_root(&self) -> String {
        workload_intent_root(&self.intents.values().cloned().collect::<Vec<_>>())
    }

    pub fn batch_root(&self) -> String {
        merkle_root(
            "WORKLOAD-BATCH",
            &self
                .batches
                .values()
                .map(WorkloadBatch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "WORKLOAD-PLANNER-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "workload_planner_state",
            "chain_id": CHAIN_ID,
            "workload_protocol_version": WORKLOAD_PROTOCOL_VERSION,
            "profile": self.profile.public_record(),
            "current_height": self.current_height,
            "next_sequence": self.next_sequence,
            "intent_root": self.intent_root(),
            "batch_root": self.batch_root(),
            "intent_count": self.intents.len() as u64,
            "batch_count": self.batches.len() as u64,
        })
    }

    fn intent_payload(&self, kind: &WorkloadIntentKind, height: u64, sequence: u64) -> Value {
        let base = json!({
            "height": height,
            "sequence": sequence,
            "intent_kind": kind.as_str(),
            "privacy": kind.default_privacy_class(),
            "fee_class": kind.default_fee_class(),
        });
        match kind {
            WorkloadIntentKind::PrivateTransfer => json!({
                "base": base,
                "note_commitment": deterministic_commitment("WORKLOAD-NOTE", height, sequence),
                "nullifier_hint": deterministic_commitment("WORKLOAD-NULLIFIER", height, sequence),
            }),
            WorkloadIntentKind::AmmSwap => json!({
                "base": base,
                "pool_commitment": deterministic_commitment("WORKLOAD-AMM-POOL", height, sequence),
                "route_commitment": deterministic_commitment("WORKLOAD-AMM-ROUTE", height, sequence),
            }),
            WorkloadIntentKind::BridgeDeposit | WorkloadIntentKind::BridgeWithdrawal => json!({
                "base": base,
                "monero_tx_commitment": deterministic_commitment("WORKLOAD-MONERO-TX", height, sequence),
                "address_hash": deterministic_commitment("WORKLOAD-MONERO-ADDRESS", height, sequence),
            }),
            WorkloadIntentKind::ContractCall | WorkloadIntentKind::WasmCall => json!({
                "base": base,
                "contract_commitment": deterministic_commitment("WORKLOAD-CONTRACT", height, sequence),
                "args_root": deterministic_commitment("WORKLOAD-CALL-ARGS", height, sequence),
            }),
            _ => json!({
                "base": base,
                "resource_commitment": deterministic_commitment("WORKLOAD-RESOURCE", height, sequence),
            }),
        }
    }
}

impl Default for WorkloadPlannerState {
    fn default() -> Self {
        Self::new(WorkloadProfile::default())
    }
}

pub fn default_workload_kinds() -> Vec<WorkloadIntentKind> {
    vec![
        WorkloadIntentKind::PrivateTransfer,
        WorkloadIntentKind::AssetMint,
        WorkloadIntentKind::AssetBurn,
        WorkloadIntentKind::AmmSwap,
        WorkloadIntentKind::AmmLiquidityAdd,
        WorkloadIntentKind::LendingBorrow,
        WorkloadIntentKind::LendingRepay,
        WorkloadIntentKind::ContractCall,
        WorkloadIntentKind::WasmCall,
        WorkloadIntentKind::PaymasterSponsoredCall,
        WorkloadIntentKind::BridgeDeposit,
        WorkloadIntentKind::BridgeWithdrawal,
        WorkloadIntentKind::OracleUpdate,
        WorkloadIntentKind::ProofJob,
    ]
}

pub fn workload_profile_id(record: &Value) -> String {
    workload_payload_root("WORKLOAD-PROFILE-ID", record)
}

pub fn workload_intent_id(
    kind: &str,
    sequence: u64,
    target_height: u64,
    account_commitment: &str,
    asset_commitment: &str,
    amount_bucket: &str,
    payload_root: &str,
) -> String {
    domain_hash(
        "WORKLOAD-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Int(sequence as i128),
            HashPart::Int(target_height as i128),
            HashPart::Str(account_commitment),
            HashPart::Str(asset_commitment),
            HashPart::Str(amount_bucket),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn workload_batch_id(
    profile_id: &str,
    height: u64,
    batch_sequence: u64,
    intent_root: &str,
    intent_count: u64,
) -> String {
    domain_hash(
        "WORKLOAD-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Int(height as i128),
            HashPart::Int(batch_sequence as i128),
            HashPart::Str(intent_root),
            HashPart::Int(intent_count as i128),
        ],
        32,
    )
}

pub fn workload_intent_root(intents: &[WorkloadIntent]) -> String {
    merkle_root(
        "WORKLOAD-INTENT",
        &intents
            .iter()
            .map(WorkloadIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn workload_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn deterministic_selector(height: u64, sequence: u64, offset: u64) -> u64 {
    let hash = domain_hash(
        "WORKLOAD-DETERMINISTIC-SELECTOR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
            HashPart::Int(offset as i128),
        ],
        8,
    );
    u64::from_str_radix(&hash, 16).unwrap_or_default()
}

pub fn deterministic_commitment(domain: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn amount_bucket(selector: u64) -> String {
    let bucket = match selector % 8 {
        0 => "dust",
        1 => "small",
        2 => "medium",
        3 => "large",
        4 => "defi-small",
        5 => "defi-medium",
        6 => "bridge-small",
        _ => "bridge-large",
    };
    bucket.to_string()
}
