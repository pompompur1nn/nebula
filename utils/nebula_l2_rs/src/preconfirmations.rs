use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PreconfirmationResult<T> = Result<T, String>;

pub const PRECONFIRMATION_PROTOCOL_VERSION: &str = "nebula-preconfirmations-v1";
pub const PRECONFIRMATION_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRECONFIRMATION_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRECONFIRMATION_TRANSCRIPT_HASH: &str = "SHA3-256";
pub const PRECONFIRMATION_DEFAULT_TTL_BLOCKS: u64 = 4;
pub const PRECONFIRMATION_DEFAULT_BATCH_WINDOW_MS: u64 = 150;
pub const PRECONFIRMATION_DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 2;
pub const PRECONFIRMATION_DEFAULT_MAX_BATCH_SIZE: u64 = 512;
pub const PRECONFIRMATION_DEFAULT_MIN_BOND_UNITS: u64 = 100_000;
pub const PRECONFIRMATION_DEFAULT_LOW_FEE_CREDIT_UNITS: u64 = 2_500;
pub const PRECONFIRMATION_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 16;
pub const PRECONFIRMATION_MAX_BPS: u64 = 10_000;
pub const PRECONFIRMATION_STATUS_ACTIVE: &str = "active";
pub const PRECONFIRMATION_STATUS_PENDING: &str = "pending";
pub const PRECONFIRMATION_STATUS_PROMISED: &str = "promised";
pub const PRECONFIRMATION_STATUS_BATCHED: &str = "batched";
pub const PRECONFIRMATION_STATUS_INCLUDED: &str = "included";
pub const PRECONFIRMATION_STATUS_FINALIZED: &str = "finalized";
pub const PRECONFIRMATION_STATUS_EXPIRED: &str = "expired";
pub const PRECONFIRMATION_STATUS_SLASHED: &str = "slashed";
pub const PRECONFIRMATION_STATUS_REJECTED: &str = "rejected";
pub const PRECONFIRMATION_DEVNET_OPERATOR_ID: &str = "devnet-preconf-operator";
pub const PRECONFIRMATION_DEVNET_WATCHTOWER_ID: &str = "devnet-preconf-watchtower";
pub const PRECONFIRMATION_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationLane {
    PrivateTransfer,
    MoneroBridgeDeposit,
    MoneroBridgeWithdrawal,
    TokenMint,
    TokenSwap,
    LendingAction,
    ContractCall,
    StateChannelUpdate,
    ProofSubmission,
    Emergency,
}

impl PreconfirmationLane {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridgeDeposit => "monero_bridge_deposit",
            Self::MoneroBridgeWithdrawal => "monero_bridge_withdrawal",
            Self::TokenMint => "token_mint",
            Self::TokenSwap => "token_swap",
            Self::LendingAction => "lending_action",
            Self::ContractCall => "contract_call",
            Self::StateChannelUpdate => "state_channel_update",
            Self::ProofSubmission => "proof_submission",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_weight(&self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::MoneroBridgeWithdrawal => 8_500,
            Self::MoneroBridgeDeposit => 7_500,
            Self::PrivateTransfer => 7_000,
            Self::StateChannelUpdate => 6_500,
            Self::TokenSwap => 6_000,
            Self::LendingAction => 5_500,
            Self::ContractCall => 5_000,
            Self::TokenMint => 4_500,
            Self::ProofSubmission => 4_000,
        }
    }

    pub fn low_fee_eligible(&self) -> bool {
        !matches!(self, Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationPrivacyMode {
    PublicMetadata,
    PayloadRootOnly,
    EncryptedIntent,
    SealedBid,
    ViewTagOnly,
}

impl PreconfirmationPrivacyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PublicMetadata => "public_metadata",
            Self::PayloadRootOnly => "payload_root_only",
            Self::EncryptedIntent => "encrypted_intent",
            Self::SealedBid => "sealed_bid",
            Self::ViewTagOnly => "view_tag_only",
        }
    }

    pub fn hides_payload(&self) -> bool {
        !matches!(self, Self::PublicMetadata)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationFailureKind {
    Equivocation,
    ExpiredPromise,
    InvalidSignature,
    MissingInclusion,
    BadStateRoot,
    FeeUnderfunded,
    PrivacyLeak,
}

impl PreconfirmationFailureKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::ExpiredPromise => "expired_promise",
            Self::InvalidSignature => "invalid_signature",
            Self::MissingInclusion => "missing_inclusion",
            Self::BadStateRoot => "bad_state_root",
            Self::FeeUnderfunded => "fee_underfunded",
            Self::PrivacyLeak => "privacy_leak",
        }
    }

    pub fn slash_bps(&self) -> u64 {
        match self {
            Self::Equivocation => 10_000,
            Self::PrivacyLeak => 8_000,
            Self::InvalidSignature => 7_500,
            Self::BadStateRoot => 6_000,
            Self::MissingInclusion => 4_000,
            Self::ExpiredPromise => 2_500,
            Self::FeeUnderfunded => 1_500,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationConfig {
    pub protocol_version: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub transcript_hash: String,
    pub ttl_blocks: u64,
    pub batch_window_ms: u64,
    pub finality_delay_blocks: u64,
    pub max_batch_size: u64,
    pub min_operator_bond_units: u64,
    pub default_low_fee_credit_units: u64,
    pub default_privacy_budget_units: u64,
    pub fee_asset_id: String,
    pub metadata_root: String,
}

impl Default for PreconfirmationConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRECONFIRMATION_PROTOCOL_VERSION.to_string(),
            pq_signature_scheme: PRECONFIRMATION_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: PRECONFIRMATION_PQ_KEM_SCHEME.to_string(),
            transcript_hash: PRECONFIRMATION_TRANSCRIPT_HASH.to_string(),
            ttl_blocks: PRECONFIRMATION_DEFAULT_TTL_BLOCKS,
            batch_window_ms: PRECONFIRMATION_DEFAULT_BATCH_WINDOW_MS,
            finality_delay_blocks: PRECONFIRMATION_DEFAULT_FINALITY_DELAY_BLOCKS,
            max_batch_size: PRECONFIRMATION_DEFAULT_MAX_BATCH_SIZE,
            min_operator_bond_units: PRECONFIRMATION_DEFAULT_MIN_BOND_UNITS,
            default_low_fee_credit_units: PRECONFIRMATION_DEFAULT_LOW_FEE_CREDIT_UNITS,
            default_privacy_budget_units: PRECONFIRMATION_DEFAULT_PRIVACY_BUDGET_UNITS,
            fee_asset_id: PRECONFIRMATION_DEVNET_FEE_ASSET_ID.to_string(),
            metadata_root: preconfirmation_payload_root(
                "PRECONFIRMATION-CONFIG-METADATA",
                &json!({
                    "mode": "devnet",
                    "purpose": "fast private UX without replacing final settlement"
                }),
            ),
        }
    }
}

impl PreconfirmationConfig {
    pub fn validate(&self) -> PreconfirmationResult<()> {
        ensure_non_empty(&self.protocol_version, "preconfirmation protocol version")?;
        ensure_non_empty(
            &self.pq_signature_scheme,
            "preconfirmation PQ signature scheme",
        )?;
        ensure_non_empty(&self.pq_kem_scheme, "preconfirmation PQ KEM scheme")?;
        ensure_non_empty(&self.transcript_hash, "preconfirmation transcript hash")?;
        ensure_non_empty(&self.fee_asset_id, "preconfirmation fee asset")?;
        ensure_non_empty(&self.metadata_root, "preconfirmation config metadata root")?;
        if self.ttl_blocks == 0 {
            return Err("preconfirmation ttl cannot be zero".to_string());
        }
        if self.batch_window_ms == 0 {
            return Err("preconfirmation batch window cannot be zero".to_string());
        }
        if self.max_batch_size == 0 {
            return Err("preconfirmation max batch size cannot be zero".to_string());
        }
        if self.finality_delay_blocks == 0 {
            return Err("preconfirmation finality delay cannot be zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "transcript_hash": self.transcript_hash,
            "ttl_blocks": self.ttl_blocks,
            "batch_window_ms": self.batch_window_ms,
            "finality_delay_blocks": self.finality_delay_blocks,
            "max_batch_size": self.max_batch_size,
            "min_operator_bond_units": self.min_operator_bond_units,
            "default_low_fee_credit_units": self.default_low_fee_credit_units,
            "default_privacy_budget_units": self.default_privacy_budget_units,
            "fee_asset_id": self.fee_asset_id,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationOperatorEpoch {
    pub epoch_id: String,
    pub operator_id: String,
    pub pq_public_key_root: String,
    pub vrf_public_key_root: String,
    pub stake_bond_units: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub priority_weight_bps: u64,
    pub committee_root: String,
    pub status: String,
}

impl PreconfirmationOperatorEpoch {
    pub fn new(
        operator_id: &str,
        pq_public_key_root: &str,
        vrf_public_key_root: &str,
        stake_bond_units: u64,
        active_from_height: u64,
        active_until_height: u64,
        priority_weight_bps: u64,
        committee_members: &[String],
    ) -> PreconfirmationResult<Self> {
        ensure_non_empty(operator_id, "preconfirmation operator id")?;
        ensure_non_empty(pq_public_key_root, "preconfirmation operator PQ key")?;
        ensure_non_empty(vrf_public_key_root, "preconfirmation operator VRF key")?;
        validate_bps(priority_weight_bps, "preconfirmation priority weight")?;
        if active_until_height <= active_from_height {
            return Err("preconfirmation operator epoch ends before it starts".to_string());
        }
        let committee_root =
            preconfirmation_string_set_root("PRECONFIRMATION-COMMITTEE", committee_members);
        let epoch_id = preconfirmation_operator_epoch_id(
            operator_id,
            pq_public_key_root,
            active_from_height,
            active_until_height,
            &committee_root,
        );
        Ok(Self {
            epoch_id,
            operator_id: operator_id.to_string(),
            pq_public_key_root: pq_public_key_root.to_string(),
            vrf_public_key_root: vrf_public_key_root.to_string(),
            stake_bond_units,
            active_from_height,
            active_until_height,
            priority_weight_bps,
            committee_root,
            status: PRECONFIRMATION_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn devnet(operator_id: &str, active_from_height: u64) -> PreconfirmationResult<Self> {
        let committee_members = vec![
            operator_id.to_string(),
            PRECONFIRMATION_DEVNET_WATCHTOWER_ID.to_string(),
            "devnet-preconf-auditor".to_string(),
        ];
        Self::new(
            operator_id,
            &preconfirmation_string_root("PRECONFIRMATION-DEVNET-PQ-KEY", operator_id),
            &preconfirmation_string_root("PRECONFIRMATION-DEVNET-VRF-KEY", operator_id),
            PRECONFIRMATION_DEFAULT_MIN_BOND_UNITS.saturating_mul(4),
            active_from_height,
            active_from_height.saturating_add(1_000),
            7_500,
            &committee_members,
        )
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PRECONFIRMATION_STATUS_ACTIVE
            && height >= self.active_from_height
            && height <= self.active_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_operator_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "operator_id": self.operator_id,
            "pq_public_key_root": self.pq_public_key_root,
            "vrf_public_key_root": self.vrf_public_key_root,
            "stake_bond_units": self.stake_bond_units,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "priority_weight_bps": self.priority_weight_bps,
            "committee_root": self.committee_root,
            "status": self.status,
        })
    }

    pub fn epoch_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-OPERATOR-EPOCH", &self.public_record())
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        ensure_non_empty(&self.epoch_id, "preconfirmation epoch id")?;
        ensure_non_empty(&self.operator_id, "preconfirmation epoch operator")?;
        ensure_non_empty(&self.pq_public_key_root, "preconfirmation epoch PQ key")?;
        ensure_non_empty(&self.vrf_public_key_root, "preconfirmation epoch VRF key")?;
        ensure_non_empty(&self.committee_root, "preconfirmation epoch committee")?;
        validate_bps(self.priority_weight_bps, "preconfirmation epoch priority")?;
        if self.active_until_height <= self.active_from_height {
            return Err("preconfirmation epoch ends before it starts".to_string());
        }
        let expected = preconfirmation_operator_epoch_id(
            &self.operator_id,
            &self.pq_public_key_root,
            self.active_from_height,
            self.active_until_height,
            &self.committee_root,
        );
        if self.epoch_id != expected {
            return Err("preconfirmation operator epoch id mismatch".to_string());
        }
        Ok(self.epoch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePreconfirmationIntent {
    pub intent_id: String,
    pub account_commitment: String,
    pub nullifier_root: String,
    pub lane: PreconfirmationLane,
    pub privacy_mode: PreconfirmationPrivacyMode,
    pub encrypted_payload_root: String,
    pub public_metadata_root: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub low_fee_credit_units: u64,
    pub privacy_budget_units: u64,
    pub nonce: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PrivatePreconfirmationIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_commitment: &str,
        nullifier_root: &str,
        lane: PreconfirmationLane,
        privacy_mode: PreconfirmationPrivacyMode,
        encrypted_payload_root: &str,
        public_metadata: &Value,
        fee_asset_id: &str,
        max_fee_units: u64,
        low_fee_credit_units: u64,
        privacy_budget_units: u64,
        nonce: u64,
        submitted_at_height: u64,
        ttl_blocks: u64,
    ) -> PreconfirmationResult<Self> {
        ensure_non_empty(account_commitment, "preconfirmation account commitment")?;
        ensure_non_empty(nullifier_root, "preconfirmation nullifier root")?;
        ensure_non_empty(
            encrypted_payload_root,
            "preconfirmation encrypted payload root",
        )?;
        ensure_non_empty(fee_asset_id, "preconfirmation fee asset")?;
        if max_fee_units == 0 && low_fee_credit_units == 0 {
            return Err("preconfirmation intent needs fee units or credits".to_string());
        }
        let public_metadata_root =
            preconfirmation_payload_root("PRECONFIRMATION-INTENT-METADATA", public_metadata);
        let expires_at_height = submitted_at_height.saturating_add(ttl_blocks.max(1));
        let intent_id = preconfirmation_intent_id(
            account_commitment,
            nullifier_root,
            lane,
            encrypted_payload_root,
            nonce,
            submitted_at_height,
        );
        Ok(Self {
            intent_id,
            account_commitment: account_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            lane,
            privacy_mode,
            encrypted_payload_root: encrypted_payload_root.to_string(),
            public_metadata_root,
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            low_fee_credit_units,
            privacy_budget_units,
            nonce,
            submitted_at_height,
            expires_at_height,
            status: PRECONFIRMATION_STATUS_PENDING.to_string(),
        })
    }

    pub fn devnet(
        label: &str,
        lane: PreconfirmationLane,
        nonce: u64,
        height: u64,
    ) -> PreconfirmationResult<Self> {
        let privacy_mode = if matches!(lane, PreconfirmationLane::TokenSwap) {
            PreconfirmationPrivacyMode::SealedBid
        } else {
            PreconfirmationPrivacyMode::EncryptedIntent
        };
        Self::new(
            &preconfirmation_account_commitment(label),
            &preconfirmation_string_root("PRECONFIRMATION-DEVNET-NULLIFIER", label),
            lane,
            privacy_mode,
            &preconfirmation_string_root("PRECONFIRMATION-DEVNET-ENCRYPTED-PAYLOAD", label),
            &json!({
                "label": label,
                "lane": lane.as_str(),
                "privacy_mode": privacy_mode.as_str(),
            }),
            PRECONFIRMATION_DEVNET_FEE_ASSET_ID,
            2_000_u64.saturating_add(nonce.saturating_mul(100)),
            if lane.low_fee_eligible() {
                PRECONFIRMATION_DEFAULT_LOW_FEE_CREDIT_UNITS
            } else {
                0
            },
            PRECONFIRMATION_DEFAULT_PRIVACY_BUDGET_UNITS,
            nonce,
            height,
            PRECONFIRMATION_DEFAULT_TTL_BLOCKS,
        )
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_preconfirmation_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "account_commitment": self.account_commitment,
            "nullifier_root": self.nullifier_root,
            "lane": self.lane.as_str(),
            "lane_weight": self.lane.default_weight(),
            "privacy_mode": self.privacy_mode.as_str(),
            "hides_payload": self.privacy_mode.hides_payload(),
            "encrypted_payload_root": self.encrypted_payload_root,
            "public_metadata_root": self.public_metadata_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "privacy_budget_units": self.privacy_budget_units,
            "nonce": self.nonce,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn intent_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-INTENT", &self.public_record())
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        ensure_non_empty(&self.intent_id, "preconfirmation intent id")?;
        ensure_non_empty(
            &self.account_commitment,
            "preconfirmation intent account commitment",
        )?;
        ensure_non_empty(
            &self.nullifier_root,
            "preconfirmation intent nullifier root",
        )?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "preconfirmation intent encrypted payload",
        )?;
        ensure_non_empty(
            &self.public_metadata_root,
            "preconfirmation intent metadata root",
        )?;
        ensure_non_empty(&self.fee_asset_id, "preconfirmation intent fee asset")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("preconfirmation intent expires before submission".to_string());
        }
        let expected = preconfirmation_intent_id(
            &self.account_commitment,
            &self.nullifier_root,
            self.lane,
            &self.encrypted_payload_root,
            self.nonce,
            self.submitted_at_height,
        );
        if self.intent_id != expected {
            return Err("preconfirmation intent id mismatch".to_string());
        }
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationPromise {
    pub promise_id: String,
    pub intent_id: String,
    pub operator_epoch_id: String,
    pub promised_state_root: String,
    pub pre_state_root: String,
    pub expected_da_root: String,
    pub max_inclusion_height: u64,
    pub fee_reserved_units: u64,
    pub privacy_budget_reserved_units: u64,
    pub pq_signature_root: String,
    pub issued_at_height: u64,
    pub status: String,
}

impl PreconfirmationPromise {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: &PrivatePreconfirmationIntent,
        operator_epoch: &PreconfirmationOperatorEpoch,
        promised_state_root: &str,
        pre_state_root: &str,
        expected_da_root: &str,
        issued_at_height: u64,
    ) -> PreconfirmationResult<Self> {
        intent.validate()?;
        operator_epoch.validate()?;
        ensure_non_empty(promised_state_root, "preconfirmation promised state root")?;
        ensure_non_empty(pre_state_root, "preconfirmation pre-state root")?;
        ensure_non_empty(expected_da_root, "preconfirmation expected DA root")?;
        if !operator_epoch.is_active_at(issued_at_height) {
            return Err("preconfirmation operator epoch is not active".to_string());
        }
        if issued_at_height > intent.expires_at_height {
            return Err("preconfirmation promise issued after intent expiry".to_string());
        }
        let max_inclusion_height = issued_at_height
            .saturating_add(PRECONFIRMATION_DEFAULT_TTL_BLOCKS)
            .min(intent.expires_at_height);
        let promise_material = preconfirmation_payload_root(
            "PRECONFIRMATION-PROMISE-MATERIAL",
            &json!({
                "intent_id": intent.intent_id,
                "operator_epoch_id": operator_epoch.epoch_id,
                "promised_state_root": promised_state_root,
                "pre_state_root": pre_state_root,
                "expected_da_root": expected_da_root,
                "issued_at_height": issued_at_height,
            }),
        );
        let pq_signature_root = preconfirmation_signature_root(
            &operator_epoch.operator_id,
            &operator_epoch.pq_public_key_root,
            &promise_material,
        );
        let promise_id = preconfirmation_promise_id(
            &intent.intent_id,
            &operator_epoch.epoch_id,
            promised_state_root,
            issued_at_height,
        );
        Ok(Self {
            promise_id,
            intent_id: intent.intent_id.clone(),
            operator_epoch_id: operator_epoch.epoch_id.clone(),
            promised_state_root: promised_state_root.to_string(),
            pre_state_root: pre_state_root.to_string(),
            expected_da_root: expected_da_root.to_string(),
            max_inclusion_height,
            fee_reserved_units: intent.max_fee_units.min(
                intent
                    .max_fee_units
                    .saturating_add(intent.low_fee_credit_units)
                    .max(1),
            ),
            privacy_budget_reserved_units: intent.privacy_budget_units,
            pq_signature_root,
            issued_at_height,
            status: PRECONFIRMATION_STATUS_PROMISED.to_string(),
        })
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.max_inclusion_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_promise",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "promise_id": self.promise_id,
            "intent_id": self.intent_id,
            "operator_epoch_id": self.operator_epoch_id,
            "promised_state_root": self.promised_state_root,
            "pre_state_root": self.pre_state_root,
            "expected_da_root": self.expected_da_root,
            "max_inclusion_height": self.max_inclusion_height,
            "fee_reserved_units": self.fee_reserved_units,
            "privacy_budget_reserved_units": self.privacy_budget_reserved_units,
            "pq_signature_root": self.pq_signature_root,
            "issued_at_height": self.issued_at_height,
            "status": self.status,
        })
    }

    pub fn promise_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-PROMISE", &self.public_record())
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        ensure_non_empty(&self.promise_id, "preconfirmation promise id")?;
        ensure_non_empty(&self.intent_id, "preconfirmation promise intent")?;
        ensure_non_empty(
            &self.operator_epoch_id,
            "preconfirmation promise operator epoch",
        )?;
        ensure_non_empty(
            &self.promised_state_root,
            "preconfirmation promise promised state root",
        )?;
        ensure_non_empty(&self.pre_state_root, "preconfirmation promise pre-state")?;
        ensure_non_empty(
            &self.expected_da_root,
            "preconfirmation promise expected DA",
        )?;
        ensure_non_empty(
            &self.pq_signature_root,
            "preconfirmation promise PQ signature",
        )?;
        if self.max_inclusion_height < self.issued_at_height {
            return Err("preconfirmation promise max inclusion before issue".to_string());
        }
        let expected = preconfirmation_promise_id(
            &self.intent_id,
            &self.operator_epoch_id,
            &self.promised_state_root,
            self.issued_at_height,
        );
        if self.promise_id != expected {
            return Err("preconfirmation promise id mismatch".to_string());
        }
        Ok(self.promise_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationBatch {
    pub batch_id: String,
    pub operator_epoch_id: String,
    pub promise_ids: Vec<String>,
    pub lane_root: String,
    pub intent_root: String,
    pub promise_root: String,
    pub ordering_seed_root: String,
    pub batch_state_root: String,
    pub batch_da_root: String,
    pub low_fee_credit_root: String,
    pub batch_height: u64,
    pub close_height: u64,
    pub status: String,
}

impl PreconfirmationBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_epoch_id: &str,
        promises: &[PreconfirmationPromise],
        intents: &BTreeMap<String, PrivatePreconfirmationIntent>,
        ordering_seed_root: &str,
        batch_state_root: &str,
        batch_da_root: &str,
        low_fee_credit_root: &str,
        batch_height: u64,
        close_height: u64,
    ) -> PreconfirmationResult<Self> {
        ensure_non_empty(operator_epoch_id, "preconfirmation batch operator epoch")?;
        ensure_non_empty(ordering_seed_root, "preconfirmation batch ordering seed")?;
        ensure_non_empty(batch_state_root, "preconfirmation batch state root")?;
        ensure_non_empty(batch_da_root, "preconfirmation batch DA root")?;
        ensure_non_empty(
            low_fee_credit_root,
            "preconfirmation batch low-fee credit root",
        )?;
        if promises.is_empty() {
            return Err("preconfirmation batch cannot be empty".to_string());
        }
        if close_height < batch_height {
            return Err("preconfirmation batch close height before open".to_string());
        }
        let mut promise_ids = Vec::new();
        let mut lane_records = Vec::new();
        let mut intent_records = Vec::new();
        let mut promise_records = Vec::new();
        for promise in promises {
            promise.validate()?;
            let intent = intents
                .get(&promise.intent_id)
                .ok_or_else(|| "preconfirmation batch references unknown intent".to_string())?;
            promise_ids.push(promise.promise_id.clone());
            lane_records.push(json!({
                "promise_id": promise.promise_id,
                "lane": intent.lane.as_str(),
                "weight": intent.lane.default_weight(),
            }));
            intent_records.push(intent.public_record());
            promise_records.push(promise.public_record());
        }
        promise_ids.sort();
        let lane_root = merkle_root("PRECONFIRMATION-BATCH-LANE", &lane_records);
        let intent_root = merkle_root("PRECONFIRMATION-BATCH-INTENT", &intent_records);
        let promise_root = merkle_root("PRECONFIRMATION-BATCH-PROMISE", &promise_records);
        let batch_id = preconfirmation_batch_id(
            operator_epoch_id,
            &promise_root,
            batch_state_root,
            batch_height,
        );
        Ok(Self {
            batch_id,
            operator_epoch_id: operator_epoch_id.to_string(),
            promise_ids,
            lane_root,
            intent_root,
            promise_root,
            ordering_seed_root: ordering_seed_root.to_string(),
            batch_state_root: batch_state_root.to_string(),
            batch_da_root: batch_da_root.to_string(),
            low_fee_credit_root: low_fee_credit_root.to_string(),
            batch_height,
            close_height,
            status: PRECONFIRMATION_STATUS_BATCHED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "operator_epoch_id": self.operator_epoch_id,
            "promise_ids": self.promise_ids,
            "lane_root": self.lane_root,
            "intent_root": self.intent_root,
            "promise_root": self.promise_root,
            "ordering_seed_root": self.ordering_seed_root,
            "batch_state_root": self.batch_state_root,
            "batch_da_root": self.batch_da_root,
            "low_fee_credit_root": self.low_fee_credit_root,
            "batch_height": self.batch_height,
            "close_height": self.close_height,
            "promise_count": self.promise_ids.len() as u64,
            "status": self.status,
        })
    }

    pub fn batch_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-BATCH", &self.public_record())
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        ensure_non_empty(&self.batch_id, "preconfirmation batch id")?;
        ensure_non_empty(&self.operator_epoch_id, "preconfirmation batch operator")?;
        ensure_non_empty(&self.lane_root, "preconfirmation batch lane root")?;
        ensure_non_empty(&self.intent_root, "preconfirmation batch intent root")?;
        ensure_non_empty(&self.promise_root, "preconfirmation batch promise root")?;
        ensure_non_empty(
            &self.ordering_seed_root,
            "preconfirmation batch ordering seed",
        )?;
        ensure_non_empty(&self.batch_state_root, "preconfirmation batch state")?;
        ensure_non_empty(&self.batch_da_root, "preconfirmation batch DA")?;
        ensure_non_empty(
            &self.low_fee_credit_root,
            "preconfirmation batch low-fee credits",
        )?;
        if self.promise_ids.is_empty() {
            return Err("preconfirmation batch has no promises".to_string());
        }
        if self.close_height < self.batch_height {
            return Err("preconfirmation batch close height before batch height".to_string());
        }
        let expected = preconfirmation_batch_id(
            &self.operator_epoch_id,
            &self.promise_root,
            &self.batch_state_root,
            self.batch_height,
        );
        if self.batch_id != expected {
            return Err("preconfirmation batch id mismatch".to_string());
        }
        Ok(self.batch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationFulfillment {
    pub fulfillment_id: String,
    pub promise_id: String,
    pub batch_id: String,
    pub included_block_height: u64,
    pub included_tx_root: String,
    pub final_state_root: String,
    pub final_da_root: String,
    pub inclusion_proof_root: String,
    pub settlement_receipt_root: String,
    pub finalized_at_height: u64,
    pub status: String,
}

impl PreconfirmationFulfillment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        promise_id: &str,
        batch_id: &str,
        included_block_height: u64,
        included_tx_root: &str,
        final_state_root: &str,
        final_da_root: &str,
        inclusion_proof_root: &str,
        settlement_receipt_root: &str,
        finalized_at_height: u64,
    ) -> PreconfirmationResult<Self> {
        ensure_non_empty(promise_id, "preconfirmation fulfillment promise")?;
        ensure_non_empty(batch_id, "preconfirmation fulfillment batch")?;
        ensure_non_empty(included_tx_root, "preconfirmation fulfillment tx root")?;
        ensure_non_empty(final_state_root, "preconfirmation fulfillment state root")?;
        ensure_non_empty(final_da_root, "preconfirmation fulfillment DA root")?;
        ensure_non_empty(
            inclusion_proof_root,
            "preconfirmation fulfillment inclusion proof",
        )?;
        ensure_non_empty(
            settlement_receipt_root,
            "preconfirmation fulfillment settlement receipt",
        )?;
        if finalized_at_height < included_block_height {
            return Err("preconfirmation fulfillment finalized before inclusion".to_string());
        }
        let fulfillment_id = preconfirmation_fulfillment_id(
            promise_id,
            batch_id,
            final_state_root,
            finalized_at_height,
        );
        Ok(Self {
            fulfillment_id,
            promise_id: promise_id.to_string(),
            batch_id: batch_id.to_string(),
            included_block_height,
            included_tx_root: included_tx_root.to_string(),
            final_state_root: final_state_root.to_string(),
            final_da_root: final_da_root.to_string(),
            inclusion_proof_root: inclusion_proof_root.to_string(),
            settlement_receipt_root: settlement_receipt_root.to_string(),
            finalized_at_height,
            status: PRECONFIRMATION_STATUS_FINALIZED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_fulfillment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "fulfillment_id": self.fulfillment_id,
            "promise_id": self.promise_id,
            "batch_id": self.batch_id,
            "included_block_height": self.included_block_height,
            "included_tx_root": self.included_tx_root,
            "final_state_root": self.final_state_root,
            "final_da_root": self.final_da_root,
            "inclusion_proof_root": self.inclusion_proof_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "finalized_at_height": self.finalized_at_height,
            "status": self.status,
        })
    }

    pub fn fulfillment_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-FULFILLMENT", &self.public_record())
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        ensure_non_empty(&self.fulfillment_id, "preconfirmation fulfillment id")?;
        ensure_non_empty(&self.promise_id, "preconfirmation fulfillment promise")?;
        ensure_non_empty(&self.batch_id, "preconfirmation fulfillment batch")?;
        ensure_non_empty(&self.included_tx_root, "preconfirmation fulfillment tx")?;
        ensure_non_empty(&self.final_state_root, "preconfirmation fulfillment state")?;
        ensure_non_empty(&self.final_da_root, "preconfirmation fulfillment DA")?;
        ensure_non_empty(
            &self.inclusion_proof_root,
            "preconfirmation fulfillment proof",
        )?;
        ensure_non_empty(
            &self.settlement_receipt_root,
            "preconfirmation fulfillment receipt",
        )?;
        if self.finalized_at_height < self.included_block_height {
            return Err("preconfirmation fulfillment finalized before inclusion".to_string());
        }
        let expected = preconfirmation_fulfillment_id(
            &self.promise_id,
            &self.batch_id,
            &self.final_state_root,
            self.finalized_at_height,
        );
        if self.fulfillment_id != expected {
            return Err("preconfirmation fulfillment id mismatch".to_string());
        }
        Ok(self.fulfillment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationFeeCredit {
    pub credit_id: String,
    pub account_commitment: String,
    pub sponsor_commitment: String,
    pub lane: PreconfirmationLane,
    pub asset_id: String,
    pub issued_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PreconfirmationFeeCredit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_commitment: &str,
        sponsor_commitment: &str,
        lane: PreconfirmationLane,
        asset_id: &str,
        issued_units: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> PreconfirmationResult<Self> {
        ensure_non_empty(account_commitment, "preconfirmation credit account")?;
        ensure_non_empty(sponsor_commitment, "preconfirmation credit sponsor")?;
        ensure_non_empty(asset_id, "preconfirmation credit asset")?;
        if issued_units == 0 {
            return Err("preconfirmation credit units cannot be zero".to_string());
        }
        let expires_at_height = issued_at_height.saturating_add(ttl_blocks.max(1));
        let credit_id = preconfirmation_fee_credit_id(
            account_commitment,
            sponsor_commitment,
            lane,
            asset_id,
            issued_at_height,
        );
        Ok(Self {
            credit_id,
            account_commitment: account_commitment.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            lane,
            asset_id: asset_id.to_string(),
            issued_units,
            reserved_units: 0,
            spent_units: 0,
            issued_at_height,
            expires_at_height,
            status: PRECONFIRMATION_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn reserve(&mut self, units: u64) -> PreconfirmationResult<String> {
        if self.available_units() < units {
            return Err("preconfirmation fee credit insufficient".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(self.credit_root())
    }

    pub fn spend(&mut self, units: u64) -> PreconfirmationResult<String> {
        if self.reserved_units < units {
            return Err("preconfirmation fee credit spend exceeds reserve".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        if self.available_units() == 0 {
            self.status = PRECONFIRMATION_STATUS_EXPIRED.to_string();
        }
        Ok(self.credit_root())
    }

    pub fn available_units(&self) -> u64 {
        self.issued_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_fee_credit",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "credit_id": self.credit_id,
            "account_commitment": self.account_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "asset_id": self.asset_id,
            "issued_units": self.issued_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn credit_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-FEE-CREDIT", &self.public_record())
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        ensure_non_empty(&self.credit_id, "preconfirmation credit id")?;
        ensure_non_empty(&self.account_commitment, "preconfirmation credit account")?;
        ensure_non_empty(&self.sponsor_commitment, "preconfirmation credit sponsor")?;
        ensure_non_empty(&self.asset_id, "preconfirmation credit asset")?;
        if self.issued_units == 0 {
            return Err("preconfirmation credit issued units cannot be zero".to_string());
        }
        if self.reserved_units.saturating_add(self.spent_units) > self.issued_units {
            return Err("preconfirmation credit overdrawn".to_string());
        }
        let expected = preconfirmation_fee_credit_id(
            &self.account_commitment,
            &self.sponsor_commitment,
            self.lane,
            &self.asset_id,
            self.issued_at_height,
        );
        if self.credit_id != expected {
            return Err("preconfirmation credit id mismatch".to_string());
        }
        Ok(self.credit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationWatchtowerReceipt {
    pub receipt_id: String,
    pub watchtower_id: String,
    pub promise_id: String,
    pub observed_root: String,
    pub observation_height: u64,
    pub latency_ms: u64,
    pub pq_signature_root: String,
    pub status: String,
}

impl PreconfirmationWatchtowerReceipt {
    pub fn new(
        watchtower_id: &str,
        promise_id: &str,
        observed_root: &str,
        observation_height: u64,
        latency_ms: u64,
    ) -> PreconfirmationResult<Self> {
        ensure_non_empty(watchtower_id, "preconfirmation watchtower id")?;
        ensure_non_empty(promise_id, "preconfirmation watchtower promise")?;
        ensure_non_empty(observed_root, "preconfirmation watchtower observed root")?;
        let receipt_id = preconfirmation_watchtower_receipt_id(
            watchtower_id,
            promise_id,
            observed_root,
            observation_height,
        );
        let pq_signature_root = preconfirmation_signature_root(
            watchtower_id,
            &preconfirmation_string_root("PRECONFIRMATION-WATCHTOWER-PQ-KEY", watchtower_id),
            &receipt_id,
        );
        Ok(Self {
            receipt_id,
            watchtower_id: watchtower_id.to_string(),
            promise_id: promise_id.to_string(),
            observed_root: observed_root.to_string(),
            observation_height,
            latency_ms,
            pq_signature_root,
            status: PRECONFIRMATION_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_watchtower_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "watchtower_id": self.watchtower_id,
            "promise_id": self.promise_id,
            "observed_root": self.observed_root,
            "observation_height": self.observation_height,
            "latency_ms": self.latency_ms,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-WATCHTOWER-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        ensure_non_empty(&self.receipt_id, "preconfirmation watchtower receipt id")?;
        ensure_non_empty(&self.watchtower_id, "preconfirmation watchtower id")?;
        ensure_non_empty(&self.promise_id, "preconfirmation watchtower promise")?;
        ensure_non_empty(
            &self.observed_root,
            "preconfirmation watchtower observed root",
        )?;
        ensure_non_empty(
            &self.pq_signature_root,
            "preconfirmation watchtower PQ signature",
        )?;
        let expected = preconfirmation_watchtower_receipt_id(
            &self.watchtower_id,
            &self.promise_id,
            &self.observed_root,
            self.observation_height,
        );
        if self.receipt_id != expected {
            return Err("preconfirmation watchtower receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationSlashEvidence {
    pub evidence_id: String,
    pub failure_kind: PreconfirmationFailureKind,
    pub promise_id: String,
    pub operator_epoch_id: String,
    pub conflicting_root: String,
    pub witness_root: String,
    pub slash_bps: u64,
    pub slash_units: u64,
    pub reported_at_height: u64,
    pub status: String,
}

impl PreconfirmationSlashEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        failure_kind: PreconfirmationFailureKind,
        promise_id: &str,
        operator_epoch_id: &str,
        conflicting_root: &str,
        witness: &Value,
        bonded_units: u64,
        reported_at_height: u64,
    ) -> PreconfirmationResult<Self> {
        ensure_non_empty(promise_id, "preconfirmation slash promise")?;
        ensure_non_empty(operator_epoch_id, "preconfirmation slash operator epoch")?;
        ensure_non_empty(conflicting_root, "preconfirmation slash conflicting root")?;
        let witness_root = preconfirmation_payload_root("PRECONFIRMATION-SLASH-WITNESS", witness);
        let slash_bps = failure_kind.slash_bps();
        let slash_units = mul_bps_floor(bonded_units, slash_bps);
        let evidence_id = preconfirmation_slash_evidence_id(
            failure_kind,
            promise_id,
            operator_epoch_id,
            conflicting_root,
            reported_at_height,
        );
        Ok(Self {
            evidence_id,
            failure_kind,
            promise_id: promise_id.to_string(),
            operator_epoch_id: operator_epoch_id.to_string(),
            conflicting_root: conflicting_root.to_string(),
            witness_root,
            slash_bps,
            slash_units,
            reported_at_height,
            status: PRECONFIRMATION_STATUS_PENDING.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_slash_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "failure_kind": self.failure_kind.as_str(),
            "promise_id": self.promise_id,
            "operator_epoch_id": self.operator_epoch_id,
            "conflicting_root": self.conflicting_root,
            "witness_root": self.witness_root,
            "slash_bps": self.slash_bps,
            "slash_units": self.slash_units,
            "reported_at_height": self.reported_at_height,
            "status": self.status,
        })
    }

    pub fn evidence_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-SLASH-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        ensure_non_empty(&self.evidence_id, "preconfirmation slash evidence id")?;
        ensure_non_empty(&self.promise_id, "preconfirmation slash promise")?;
        ensure_non_empty(
            &self.operator_epoch_id,
            "preconfirmation slash operator epoch",
        )?;
        ensure_non_empty(
            &self.conflicting_root,
            "preconfirmation slash conflicting root",
        )?;
        ensure_non_empty(&self.witness_root, "preconfirmation slash witness root")?;
        validate_bps(self.slash_bps, "preconfirmation slash bps")?;
        let expected = preconfirmation_slash_evidence_id(
            self.failure_kind,
            &self.promise_id,
            &self.operator_epoch_id,
            &self.conflicting_root,
            self.reported_at_height,
        );
        if self.evidence_id != expected {
            return Err("preconfirmation slash evidence id mismatch".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastFinalityCheckpoint {
    pub checkpoint_id: String,
    pub height: u64,
    pub batch_root: String,
    pub promise_root: String,
    pub fulfillment_root: String,
    pub slash_root: String,
    pub operator_epoch_root: String,
    pub pq_signature_root: String,
    pub finalized_height: u64,
    pub status: String,
}

impl FastFinalityCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        batch_root: &str,
        promise_root: &str,
        fulfillment_root: &str,
        slash_root: &str,
        operator_epoch_root: &str,
        signer_id: &str,
        finalized_height: u64,
    ) -> PreconfirmationResult<Self> {
        ensure_non_empty(batch_root, "preconfirmation checkpoint batch root")?;
        ensure_non_empty(promise_root, "preconfirmation checkpoint promise root")?;
        ensure_non_empty(
            fulfillment_root,
            "preconfirmation checkpoint fulfillment root",
        )?;
        ensure_non_empty(slash_root, "preconfirmation checkpoint slash root")?;
        ensure_non_empty(
            operator_epoch_root,
            "preconfirmation checkpoint operator root",
        )?;
        ensure_non_empty(signer_id, "preconfirmation checkpoint signer")?;
        if finalized_height < height {
            return Err("preconfirmation checkpoint finalizes before height".to_string());
        }
        let checkpoint_id = preconfirmation_checkpoint_id(
            height,
            batch_root,
            promise_root,
            fulfillment_root,
            finalized_height,
        );
        let pq_signature_root = preconfirmation_signature_root(
            signer_id,
            &preconfirmation_string_root("PRECONFIRMATION-CHECKPOINT-PQ-KEY", signer_id),
            &checkpoint_id,
        );
        Ok(Self {
            checkpoint_id,
            height,
            batch_root: batch_root.to_string(),
            promise_root: promise_root.to_string(),
            fulfillment_root: fulfillment_root.to_string(),
            slash_root: slash_root.to_string(),
            operator_epoch_root: operator_epoch_root.to_string(),
            pq_signature_root,
            finalized_height,
            status: PRECONFIRMATION_STATUS_FINALIZED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_finality_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "height": self.height,
            "batch_root": self.batch_root,
            "promise_root": self.promise_root,
            "fulfillment_root": self.fulfillment_root,
            "slash_root": self.slash_root,
            "operator_epoch_root": self.operator_epoch_root,
            "pq_signature_root": self.pq_signature_root,
            "finalized_height": self.finalized_height,
            "status": self.status,
        })
    }

    pub fn checkpoint_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-CHECKPOINT", &self.public_record())
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        ensure_non_empty(&self.checkpoint_id, "preconfirmation checkpoint id")?;
        ensure_non_empty(&self.batch_root, "preconfirmation checkpoint batch")?;
        ensure_non_empty(&self.promise_root, "preconfirmation checkpoint promise")?;
        ensure_non_empty(
            &self.fulfillment_root,
            "preconfirmation checkpoint fulfillment",
        )?;
        ensure_non_empty(&self.slash_root, "preconfirmation checkpoint slash")?;
        ensure_non_empty(
            &self.operator_epoch_root,
            "preconfirmation checkpoint operator",
        )?;
        ensure_non_empty(
            &self.pq_signature_root,
            "preconfirmation checkpoint signature",
        )?;
        if self.finalized_height < self.height {
            return Err("preconfirmation checkpoint finalized before height".to_string());
        }
        let expected = preconfirmation_checkpoint_id(
            self.height,
            &self.batch_root,
            &self.promise_root,
            &self.fulfillment_root,
            self.finalized_height,
        );
        if self.checkpoint_id != expected {
            return Err("preconfirmation checkpoint id mismatch".to_string());
        }
        Ok(self.checkpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationRoots {
    pub config_root: String,
    pub operator_epoch_root: String,
    pub intent_root: String,
    pub promise_root: String,
    pub batch_root: String,
    pub fulfillment_root: String,
    pub fee_credit_root: String,
    pub watchtower_receipt_root: String,
    pub slash_evidence_root: String,
    pub checkpoint_root: String,
}

impl PreconfirmationRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "operator_epoch_root": self.operator_epoch_root,
            "intent_root": self.intent_root,
            "promise_root": self.promise_root,
            "batch_root": self.batch_root,
            "fulfillment_root": self.fulfillment_root,
            "fee_credit_root": self.fee_credit_root,
            "watchtower_receipt_root": self.watchtower_receipt_root,
            "slash_evidence_root": self.slash_evidence_root,
            "checkpoint_root": self.checkpoint_root,
        })
    }

    pub fn roots_root(&self) -> String {
        preconfirmation_payload_root("PRECONFIRMATION-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationState {
    pub config: PreconfirmationConfig,
    pub operator_epochs: BTreeMap<String, PreconfirmationOperatorEpoch>,
    pub intents: BTreeMap<String, PrivatePreconfirmationIntent>,
    pub promises: BTreeMap<String, PreconfirmationPromise>,
    pub batches: BTreeMap<String, PreconfirmationBatch>,
    pub fulfillments: BTreeMap<String, PreconfirmationFulfillment>,
    pub fee_credits: BTreeMap<String, PreconfirmationFeeCredit>,
    pub watchtower_receipts: BTreeMap<String, PreconfirmationWatchtowerReceipt>,
    pub slash_evidence: BTreeMap<String, PreconfirmationSlashEvidence>,
    pub checkpoints: BTreeMap<String, FastFinalityCheckpoint>,
    pub height: u64,
}

impl Default for PreconfirmationState {
    fn default() -> Self {
        Self {
            config: PreconfirmationConfig::default(),
            operator_epochs: BTreeMap::new(),
            intents: BTreeMap::new(),
            promises: BTreeMap::new(),
            batches: BTreeMap::new(),
            fulfillments: BTreeMap::new(),
            fee_credits: BTreeMap::new(),
            watchtower_receipts: BTreeMap::new(),
            slash_evidence: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            height: 0,
        }
    }
}

impl PreconfirmationState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet(operator_id: &str) -> PreconfirmationResult<Self> {
        let mut state = Self::new();
        state.set_height(1);
        let epoch = PreconfirmationOperatorEpoch::devnet(operator_id, 0)?;
        let epoch_id = epoch.epoch_id.clone();
        state.insert_operator_epoch(epoch)?;

        let transfer = state.submit_intent(PrivatePreconfirmationIntent::devnet(
            "devnet-alice-private-transfer",
            PreconfirmationLane::PrivateTransfer,
            1,
            1,
        )?)?;
        let swap = state.submit_intent(PrivatePreconfirmationIntent::devnet(
            "devnet-bob-token-swap",
            PreconfirmationLane::TokenSwap,
            2,
            1,
        )?)?;
        let channel = state.submit_intent(PrivatePreconfirmationIntent::devnet(
            "devnet-carol-channel-update",
            PreconfirmationLane::StateChannelUpdate,
            3,
            1,
        )?)?;

        for intent_id in [transfer.clone(), swap.clone(), channel.clone()] {
            let intent = state
                .intents
                .get(&intent_id)
                .ok_or_else(|| "devnet preconfirmation intent missing".to_string())?
                .clone();
            let epoch = state
                .operator_epochs
                .get(&epoch_id)
                .ok_or_else(|| "devnet preconfirmation epoch missing".to_string())?
                .clone();
            let promise = PreconfirmationPromise::new(
                &intent,
                &epoch,
                &preconfirmation_payload_root(
                    "PRECONFIRMATION-DEVNET-PROMISED-STATE",
                    &json!({ "intent_id": intent_id, "height": state.height }),
                ),
                &preconfirmation_payload_root(
                    "PRECONFIRMATION-DEVNET-PRE-STATE",
                    &json!({ "intent_id": intent_id, "height": state.height.saturating_sub(1) }),
                ),
                &preconfirmation_payload_root(
                    "PRECONFIRMATION-DEVNET-DA",
                    &json!({ "intent_id": intent_id, "da": "roots_only" }),
                ),
                state.height,
            )?;
            state.accept_promise(promise)?;
        }

        let transfer_intent = state
            .intents
            .get(&transfer)
            .ok_or_else(|| "devnet transfer intent missing".to_string())?
            .clone();
        let sponsor = preconfirmation_account_commitment("devnet-preconf-sponsor");
        let credit = PreconfirmationFeeCredit::new(
            &transfer_intent.account_commitment,
            &sponsor,
            transfer_intent.lane,
            PRECONFIRMATION_DEVNET_FEE_ASSET_ID,
            PRECONFIRMATION_DEFAULT_LOW_FEE_CREDIT_UNITS.saturating_mul(4),
            state.height,
            40,
        )?;
        state.issue_fee_credit(credit)?;

        let promise_values = state.promises.values().cloned().collect::<Vec<_>>();
        let batch = PreconfirmationBatch::new(
            &epoch_id,
            &promise_values,
            &state.intents,
            &preconfirmation_string_root("PRECONFIRMATION-DEVNET-ORDERING", "batch-1"),
            &preconfirmation_payload_root(
                "PRECONFIRMATION-DEVNET-BATCH-STATE",
                &json!({ "height": state.height, "batch": 1 }),
            ),
            &preconfirmation_payload_root(
                "PRECONFIRMATION-DEVNET-BATCH-DA",
                &json!({ "height": state.height, "batch": 1 }),
            ),
            &state.fee_credit_root(),
            state.height,
            state.height.saturating_add(1),
        )?;
        let batch_id = state.open_batch(batch)?;

        let promise_ids = state.promises.keys().cloned().collect::<Vec<_>>();
        for promise_id in promise_ids {
            let fulfillment = PreconfirmationFulfillment::new(
                &promise_id,
                &batch_id,
                state.height.saturating_add(1),
                &preconfirmation_string_root("PRECONFIRMATION-DEVNET-TX", &promise_id),
                &preconfirmation_string_root("PRECONFIRMATION-DEVNET-FINAL-STATE", &promise_id),
                &preconfirmation_string_root("PRECONFIRMATION-DEVNET-FINAL-DA", &promise_id),
                &preconfirmation_string_root("PRECONFIRMATION-DEVNET-INCLUSION", &promise_id),
                &preconfirmation_string_root("PRECONFIRMATION-DEVNET-RECEIPT", &promise_id),
                state
                    .height
                    .saturating_add(PRECONFIRMATION_DEFAULT_FINALITY_DELAY_BLOCKS),
            )?;
            let fulfillment_root = fulfillment.fulfillment_root();
            state.record_fulfillment(fulfillment)?;
            let receipt = PreconfirmationWatchtowerReceipt::new(
                PRECONFIRMATION_DEVNET_WATCHTOWER_ID,
                &promise_id,
                &fulfillment_root,
                state.height.saturating_add(1),
                90,
            )?;
            state.record_watchtower_receipt(receipt)?;
        }

        let slash = PreconfirmationSlashEvidence::new(
            PreconfirmationFailureKind::ExpiredPromise,
            &preconfirmation_string_root("PRECONFIRMATION-DEVNET-SLASH-PROMISE", "late"),
            &epoch_id,
            &preconfirmation_string_root("PRECONFIRMATION-DEVNET-SLASH-CONFLICT", "late"),
            &json!({"mode": "devnet", "reason": "synthetic expired preconfirmation audit trail"}),
            PRECONFIRMATION_DEFAULT_MIN_BOND_UNITS,
            state.height.saturating_add(2),
        )?;
        state.record_slash_evidence(slash)?;

        let checkpoint = FastFinalityCheckpoint::new(
            state.height.saturating_add(2),
            &state.batch_root(),
            &state.promise_root(),
            &state.fulfillment_root(),
            &state.slash_evidence_root(),
            &state.operator_epoch_root(),
            operator_id,
            state
                .height
                .saturating_add(PRECONFIRMATION_DEFAULT_FINALITY_DELAY_BLOCKS),
        )?;
        state.insert_checkpoint(checkpoint)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for intent in self.intents.values_mut() {
            if intent.is_expired_at(height) && intent.status == PRECONFIRMATION_STATUS_PENDING {
                intent.status = PRECONFIRMATION_STATUS_EXPIRED.to_string();
            }
        }
        for promise in self.promises.values_mut() {
            if promise.is_expired_at(height) && promise.status == PRECONFIRMATION_STATUS_PROMISED {
                promise.status = PRECONFIRMATION_STATUS_EXPIRED.to_string();
            }
        }
        for credit in self.fee_credits.values_mut() {
            if credit.is_expired_at(height) && credit.status == PRECONFIRMATION_STATUS_ACTIVE {
                credit.status = PRECONFIRMATION_STATUS_EXPIRED.to_string();
            }
        }
    }

    pub fn insert_operator_epoch(
        &mut self,
        epoch: PreconfirmationOperatorEpoch,
    ) -> PreconfirmationResult<String> {
        let root = epoch.validate()?;
        self.operator_epochs.insert(epoch.epoch_id.clone(), epoch);
        Ok(root)
    }

    pub fn submit_intent(
        &mut self,
        mut intent: PrivatePreconfirmationIntent,
    ) -> PreconfirmationResult<String> {
        intent.validate()?;
        if intent.is_expired_at(self.height) {
            intent.status = PRECONFIRMATION_STATUS_EXPIRED.to_string();
        }
        let intent_id = intent.intent_id.clone();
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn accept_promise(
        &mut self,
        mut promise: PreconfirmationPromise,
    ) -> PreconfirmationResult<String> {
        let root = promise.validate()?;
        let intent = self
            .intents
            .get_mut(&promise.intent_id)
            .ok_or_else(|| "preconfirmation promise references unknown intent".to_string())?;
        if intent.status == PRECONFIRMATION_STATUS_EXPIRED {
            return Err("preconfirmation promise references expired intent".to_string());
        }
        if !self
            .operator_epochs
            .contains_key(&promise.operator_epoch_id)
        {
            return Err("preconfirmation promise references unknown operator epoch".to_string());
        }
        intent.status = PRECONFIRMATION_STATUS_PROMISED.to_string();
        if promise.is_expired_at(self.height) {
            promise.status = PRECONFIRMATION_STATUS_EXPIRED.to_string();
        }
        let promise_id = promise.promise_id.clone();
        self.promises.insert(promise_id.clone(), promise);
        Ok(root).map(|_| promise_id)
    }

    pub fn open_batch(&mut self, batch: PreconfirmationBatch) -> PreconfirmationResult<String> {
        let root = batch.validate()?;
        for promise_id in &batch.promise_ids {
            let promise = self
                .promises
                .get_mut(promise_id)
                .ok_or_else(|| "preconfirmation batch references unknown promise".to_string())?;
            promise.status = PRECONFIRMATION_STATUS_BATCHED.to_string();
        }
        let batch_id = batch.batch_id.clone();
        self.batches.insert(batch_id.clone(), batch);
        Ok(root).map(|_| batch_id)
    }

    pub fn record_fulfillment(
        &mut self,
        fulfillment: PreconfirmationFulfillment,
    ) -> PreconfirmationResult<String> {
        let root = fulfillment.validate()?;
        let promise = self
            .promises
            .get_mut(&fulfillment.promise_id)
            .ok_or_else(|| "preconfirmation fulfillment references unknown promise".to_string())?;
        if !self.batches.contains_key(&fulfillment.batch_id) {
            return Err("preconfirmation fulfillment references unknown batch".to_string());
        }
        promise.status = PRECONFIRMATION_STATUS_FINALIZED.to_string();
        if let Some(intent) = self.intents.get_mut(&promise.intent_id) {
            intent.status = PRECONFIRMATION_STATUS_INCLUDED.to_string();
        }
        self.fulfillments
            .insert(fulfillment.fulfillment_id.clone(), fulfillment);
        Ok(root)
    }

    pub fn issue_fee_credit(
        &mut self,
        credit: PreconfirmationFeeCredit,
    ) -> PreconfirmationResult<String> {
        let root = credit.validate()?;
        self.fee_credits.insert(credit.credit_id.clone(), credit);
        Ok(root)
    }

    pub fn record_watchtower_receipt(
        &mut self,
        receipt: PreconfirmationWatchtowerReceipt,
    ) -> PreconfirmationResult<String> {
        let root = receipt.validate()?;
        if !self.promises.contains_key(&receipt.promise_id) {
            return Err(
                "preconfirmation watchtower receipt references unknown promise".to_string(),
            );
        }
        self.watchtower_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn record_slash_evidence(
        &mut self,
        mut evidence: PreconfirmationSlashEvidence,
    ) -> PreconfirmationResult<String> {
        let root = evidence.validate()?;
        if let Some(promise) = self.promises.get_mut(&evidence.promise_id) {
            promise.status = PRECONFIRMATION_STATUS_SLASHED.to_string();
        }
        evidence.status = PRECONFIRMATION_STATUS_ACTIVE.to_string();
        self.slash_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(root)
    }

    pub fn insert_checkpoint(
        &mut self,
        checkpoint: FastFinalityCheckpoint,
    ) -> PreconfirmationResult<String> {
        let root = checkpoint.validate()?;
        self.checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint);
        Ok(root)
    }

    pub fn roots(&self) -> PreconfirmationRoots {
        PreconfirmationRoots {
            config_root: self.config.config_root(),
            operator_epoch_root: self.operator_epoch_root(),
            intent_root: self.intent_root(),
            promise_root: self.promise_root(),
            batch_root: self.batch_root(),
            fulfillment_root: self.fulfillment_root(),
            fee_credit_root: self.fee_credit_root(),
            watchtower_receipt_root: self.watchtower_receipt_root(),
            slash_evidence_root: self.slash_evidence_root(),
            checkpoint_root: self.checkpoint_root(),
        }
    }

    pub fn operator_epoch_root(&self) -> String {
        merkle_root(
            "PRECONFIRMATION-OPERATOR-EPOCH-SET",
            &self
                .operator_epochs
                .values()
                .map(PreconfirmationOperatorEpoch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn intent_root(&self) -> String {
        merkle_root(
            "PRECONFIRMATION-INTENT-SET",
            &self
                .intents
                .values()
                .map(PrivatePreconfirmationIntent::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn promise_root(&self) -> String {
        merkle_root(
            "PRECONFIRMATION-PROMISE-SET",
            &self
                .promises
                .values()
                .map(PreconfirmationPromise::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn batch_root(&self) -> String {
        merkle_root(
            "PRECONFIRMATION-BATCH-SET",
            &self
                .batches
                .values()
                .map(PreconfirmationBatch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn fulfillment_root(&self) -> String {
        merkle_root(
            "PRECONFIRMATION-FULFILLMENT-SET",
            &self
                .fulfillments
                .values()
                .map(PreconfirmationFulfillment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn fee_credit_root(&self) -> String {
        merkle_root(
            "PRECONFIRMATION-FEE-CREDIT-SET",
            &self
                .fee_credits
                .values()
                .map(PreconfirmationFeeCredit::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn watchtower_receipt_root(&self) -> String {
        merkle_root(
            "PRECONFIRMATION-WATCHTOWER-RECEIPT-SET",
            &self
                .watchtower_receipts
                .values()
                .map(PreconfirmationWatchtowerReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn slash_evidence_root(&self) -> String {
        merkle_root(
            "PRECONFIRMATION-SLASH-EVIDENCE-SET",
            &self
                .slash_evidence
                .values()
                .map(PreconfirmationSlashEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn checkpoint_root(&self) -> String {
        merkle_root(
            "PRECONFIRMATION-CHECKPOINT-SET",
            &self
                .checkpoints
                .values()
                .map(FastFinalityCheckpoint::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn open_promise_count(&self) -> u64 {
        self.promises
            .values()
            .filter(|promise| {
                matches!(
                    promise.status.as_str(),
                    PRECONFIRMATION_STATUS_PROMISED | PRECONFIRMATION_STATUS_BATCHED
                )
            })
            .count() as u64
    }

    pub fn finalized_promise_count(&self) -> u64 {
        self.promises
            .values()
            .filter(|promise| promise.status == PRECONFIRMATION_STATUS_FINALIZED)
            .count() as u64
    }

    pub fn available_low_fee_credit_units(&self) -> u64 {
        self.fee_credits.values().fold(0_u64, |total, credit| {
            total.saturating_add(credit.available_units())
        })
    }

    pub fn state_root(&self) -> String {
        preconfirmation_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("preconfirmation state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "preconfirmation_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRECONFIRMATION_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "operator_epoch_count": self.operator_epochs.len() as u64,
            "intent_count": self.intents.len() as u64,
            "promise_count": self.promises.len() as u64,
            "open_promise_count": self.open_promise_count(),
            "finalized_promise_count": self.finalized_promise_count(),
            "batch_count": self.batches.len() as u64,
            "fulfillment_count": self.fulfillments.len() as u64,
            "fee_credit_count": self.fee_credits.len() as u64,
            "available_low_fee_credit_units": self.available_low_fee_credit_units(),
            "watchtower_receipt_count": self.watchtower_receipts.len() as u64,
            "slash_evidence_count": self.slash_evidence.len() as u64,
            "checkpoint_count": self.checkpoints.len() as u64,
            "pq_signature_scheme": self.config.pq_signature_scheme,
            "pq_kem_scheme": self.config.pq_kem_scheme,
        })
    }

    pub fn validate(&self) -> PreconfirmationResult<String> {
        self.config.validate()?;
        for epoch in self.operator_epochs.values() {
            epoch.validate()?;
        }
        for intent in self.intents.values() {
            intent.validate()?;
        }
        for promise in self.promises.values() {
            promise.validate()?;
            if !self.intents.contains_key(&promise.intent_id) {
                return Err("preconfirmation promise references missing intent".to_string());
            }
            if !self
                .operator_epochs
                .contains_key(&promise.operator_epoch_id)
            {
                return Err("preconfirmation promise references missing operator epoch".to_string());
            }
        }
        for batch in self.batches.values() {
            batch.validate()?;
            for promise_id in &batch.promise_ids {
                if !self.promises.contains_key(promise_id) {
                    return Err("preconfirmation batch references missing promise".to_string());
                }
            }
        }
        for fulfillment in self.fulfillments.values() {
            fulfillment.validate()?;
            if !self.promises.contains_key(&fulfillment.promise_id) {
                return Err("preconfirmation fulfillment references missing promise".to_string());
            }
            if !self.batches.contains_key(&fulfillment.batch_id) {
                return Err("preconfirmation fulfillment references missing batch".to_string());
            }
        }
        for credit in self.fee_credits.values() {
            credit.validate()?;
        }
        for receipt in self.watchtower_receipts.values() {
            receipt.validate()?;
        }
        for evidence in self.slash_evidence.values() {
            evidence.validate()?;
        }
        for checkpoint in self.checkpoints.values() {
            checkpoint.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn preconfirmation_operator_epoch_id(
    operator_id: &str,
    pq_public_key_root: &str,
    active_from_height: u64,
    active_until_height: u64,
    committee_root: &str,
) -> String {
    domain_hash(
        "PRECONFIRMATION-OPERATOR-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(active_from_height as i128),
            HashPart::Int(active_until_height as i128),
            HashPart::Str(committee_root),
        ],
        32,
    )
}

pub fn preconfirmation_intent_id(
    account_commitment: &str,
    nullifier_root: &str,
    lane: PreconfirmationLane,
    encrypted_payload_root: &str,
    nonce: u64,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PRECONFIRMATION-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(nullifier_root),
            HashPart::Str(lane.as_str()),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(nonce as i128),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn preconfirmation_promise_id(
    intent_id: &str,
    operator_epoch_id: &str,
    promised_state_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRECONFIRMATION-PROMISE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(operator_epoch_id),
            HashPart::Str(promised_state_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn preconfirmation_batch_id(
    operator_epoch_id: &str,
    promise_root: &str,
    batch_state_root: &str,
    batch_height: u64,
) -> String {
    domain_hash(
        "PRECONFIRMATION-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_epoch_id),
            HashPart::Str(promise_root),
            HashPart::Str(batch_state_root),
            HashPart::Int(batch_height as i128),
        ],
        32,
    )
}

pub fn preconfirmation_fulfillment_id(
    promise_id: &str,
    batch_id: &str,
    final_state_root: &str,
    finalized_at_height: u64,
) -> String {
    domain_hash(
        "PRECONFIRMATION-FULFILLMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(promise_id),
            HashPart::Str(batch_id),
            HashPart::Str(final_state_root),
            HashPart::Int(finalized_at_height as i128),
        ],
        32,
    )
}

pub fn preconfirmation_fee_credit_id(
    account_commitment: &str,
    sponsor_commitment: &str,
    lane: PreconfirmationLane,
    asset_id: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRECONFIRMATION-FEE-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(asset_id),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn preconfirmation_watchtower_receipt_id(
    watchtower_id: &str,
    promise_id: &str,
    observed_root: &str,
    observation_height: u64,
) -> String {
    domain_hash(
        "PRECONFIRMATION-WATCHTOWER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watchtower_id),
            HashPart::Str(promise_id),
            HashPart::Str(observed_root),
            HashPart::Int(observation_height as i128),
        ],
        32,
    )
}

pub fn preconfirmation_slash_evidence_id(
    failure_kind: PreconfirmationFailureKind,
    promise_id: &str,
    operator_epoch_id: &str,
    conflicting_root: &str,
    reported_at_height: u64,
) -> String {
    domain_hash(
        "PRECONFIRMATION-SLASH-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(failure_kind.as_str()),
            HashPart::Str(promise_id),
            HashPart::Str(operator_epoch_id),
            HashPart::Str(conflicting_root),
            HashPart::Int(reported_at_height as i128),
        ],
        32,
    )
}

pub fn preconfirmation_checkpoint_id(
    height: u64,
    batch_root: &str,
    promise_root: &str,
    fulfillment_root: &str,
    finalized_height: u64,
) -> String {
    domain_hash(
        "PRECONFIRMATION-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(batch_root),
            HashPart::Str(promise_root),
            HashPart::Str(fulfillment_root),
            HashPart::Int(finalized_height as i128),
        ],
        32,
    )
}

pub fn preconfirmation_account_commitment(label: &str) -> String {
    preconfirmation_string_root("PRECONFIRMATION-ACCOUNT", label)
}

pub fn preconfirmation_signature_root(
    signer_id: &str,
    public_key_root: &str,
    message: &str,
) -> String {
    domain_hash(
        "PRECONFIRMATION-PQ-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRECONFIRMATION_PQ_SIGNATURE_SCHEME),
            HashPart::Str(signer_id),
            HashPart::Str(public_key_root),
            HashPart::Str(message),
        ],
        32,
    )
}

pub fn preconfirmation_state_root_from_record(record: &Value) -> String {
    preconfirmation_payload_root("PRECONFIRMATION-STATE", record)
}

pub fn preconfirmation_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn preconfirmation_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn preconfirmation_string_set_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn mul_bps_floor(units: u64, bps: u64) -> u64 {
    units
        .saturating_mul(bps)
        .saturating_div(PRECONFIRMATION_MAX_BPS)
}

pub fn validate_bps(value: u64, label: &str) -> PreconfirmationResult<()> {
    if value > PRECONFIRMATION_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

pub fn ensure_non_empty(value: &str, label: &str) -> PreconfirmationResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}
