use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateStateTransitionResult<T> = Result<T, String>;

pub const PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION: &str = "nebula-private-state-transition-v1";
pub const PRIVATE_STATE_TRANSITION_PQ_AUTH_SCHEME: &str = "ml-dsa-87-private-transition-auth-v1";
pub const PRIVATE_STATE_TRANSITION_DELTA_ENCRYPTION_SCHEME: &str =
    "xwing-shake256-private-state-delta-v1";
pub const PRIVATE_STATE_TRANSITION_COMMITMENT_SCHEME: &str = "pedersen-poseidon-private-state-v1";
pub const PRIVATE_STATE_TRANSITION_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PRIVATE_STATE_TRANSITION_DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 96;
pub const PRIVATE_STATE_TRANSITION_DEFAULT_AUTH_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_STATE_TRANSITION_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 256;
pub const PRIVATE_STATE_TRANSITION_DEFAULT_MAX_DELTAS: usize = 256;
pub const PRIVATE_STATE_TRANSITION_DEFAULT_MAX_WITNESS_ITEMS: usize = 128;
pub const PRIVATE_STATE_TRANSITION_DEFAULT_MIN_ANONYMITY_SET: u64 = 96;
pub const PRIVATE_STATE_TRANSITION_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PRIVATE_STATE_TRANSITION_DEVNET_HEIGHT: u64 = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    AccountUpdate,
    PrivateTransfer,
    ContractCall,
    StorageWrite,
    TokenMint,
    TokenBurn,
    BridgeSettlement,
    PrivacyBudgetDebit,
}

impl TransitionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountUpdate => "account_update",
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::StorageWrite => "storage_write",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::BridgeSettlement => "bridge_settlement",
            Self::PrivacyBudgetDebit => "privacy_budget_debit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaStatus {
    Pending,
    Witnessed,
    Authorized,
    Included,
    Rejected,
    Expired,
}

impl DeltaStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Witnessed => "witnessed",
            Self::Authorized => "authorized",
            Self::Included => "included",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Pending | Self::Witnessed | Self::Authorized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierCheckpointKind {
    Local,
    Sequencer,
    DaPosted,
    Proved,
    Finalized,
}

impl NullifierCheckpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Sequencer => "sequencer",
            Self::DaPosted => "da_posted",
            Self::Proved => "proved",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentOpeningKind {
    Account,
    TokenBalance,
    ContractStorage,
    PrivacyBudget,
    ReplayTag,
    SponsorBudget,
}

impl CommitmentOpeningKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::TokenBalance => "token_balance",
            Self::ContractStorage => "contract_storage",
            Self::PrivacyBudget => "privacy_budget",
            Self::ReplayTag => "replay_tag",
            Self::SponsorBudget => "sponsor_budget",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessBundleKind {
    Membership,
    NonMembership,
    RangeProof,
    StateDiff,
    ExecutionTrace,
    RecursiveAggregate,
}

impl WitnessBundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Membership => "membership",
            Self::NonMembership => "non_membership",
            Self::RangeProof => "range_proof",
            Self::StateDiff => "state_diff",
            Self::ExecutionTrace => "execution_trace",
            Self::RecursiveAggregate => "recursive_aggregate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationSubject {
    StateDelta,
    WitnessBundle,
    StorageTransition,
    TokenCommitment,
    SponsorReservation,
    InclusionReceipt,
}

impl AuthorizationSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateDelta => "state_delta",
            Self::WitnessBundle => "witness_bundle",
            Self::StorageTransition => "storage_transition",
            Self::TokenCommitment => "token_commitment",
            Self::SponsorReservation => "sponsor_reservation",
            Self::InclusionReceipt => "inclusion_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Pending,
    Accepted,
    Superseded,
    Revoked,
    Expired,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Consumed,
    Slashed,
    Expired,
    Cancelled,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InclusionSurface {
    SequencerBatch,
    DataAvailability,
    RecursiveProof,
    MoneroAnchor,
    SettlementContract,
}

impl InclusionSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerBatch => "sequencer_batch",
            Self::DataAvailability => "data_availability",
            Self::RecursiveProof => "recursive_proof",
            Self::MoneroAnchor => "monero_anchor",
            Self::SettlementContract => "settlement_contract",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub epoch_blocks: u64,
    pub replay_window_blocks: u64,
    pub authorization_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub max_deltas_per_batch: usize,
    pub max_witness_items: usize,
    pub min_anonymity_set: u64,
    pub min_pq_security_bits: u16,
    pub require_pq_authorization: bool,
    pub allow_sponsored_transitions: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION.to_string(),
            epoch_blocks: PRIVATE_STATE_TRANSITION_DEFAULT_EPOCH_BLOCKS,
            replay_window_blocks: PRIVATE_STATE_TRANSITION_DEFAULT_REPLAY_WINDOW_BLOCKS,
            authorization_ttl_blocks: PRIVATE_STATE_TRANSITION_DEFAULT_AUTH_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_STATE_TRANSITION_DEFAULT_RECEIPT_TTL_BLOCKS,
            max_deltas_per_batch: PRIVATE_STATE_TRANSITION_DEFAULT_MAX_DELTAS,
            max_witness_items: PRIVATE_STATE_TRANSITION_DEFAULT_MAX_WITNESS_ITEMS,
            min_anonymity_set: PRIVATE_STATE_TRANSITION_DEFAULT_MIN_ANONYMITY_SET,
            min_pq_security_bits: PRIVATE_STATE_TRANSITION_MIN_PQ_SECURITY_BITS,
            require_pq_authorization: true,
            allow_sponsored_transitions: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: 60,
            replay_window_blocks: 48,
            authorization_ttl_blocks: 32,
            receipt_ttl_blocks: 144,
            max_deltas_per_batch: 128,
            max_witness_items: 96,
            min_anonymity_set: 64,
            min_pq_security_bits: PRIVATE_STATE_TRANSITION_MIN_PQ_SECURITY_BITS,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_state_transition_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "epoch_blocks": self.epoch_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "authorization_ttl_blocks": self.authorization_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "max_deltas_per_batch": self.max_deltas_per_batch,
            "max_witness_items": self.max_witness_items,
            "min_anonymity_set": self.min_anonymity_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "require_pq_authorization": self.require_pq_authorization,
            "allow_sponsored_transitions": self.allow_sponsored_transitions,
            "pq_authorization_scheme": PRIVATE_STATE_TRANSITION_PQ_AUTH_SCHEME,
            "delta_encryption_scheme": PRIVATE_STATE_TRANSITION_DELTA_ENCRYPTION_SCHEME,
            "commitment_scheme": PRIVATE_STATE_TRANSITION_COMMITMENT_SCHEME,
        })
    }

    pub fn config_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        if self.epoch_blocks == 0 {
            return Err("private state transition epoch_blocks must be non-zero".to_string());
        }
        if self.replay_window_blocks == 0 {
            return Err("private state transition replay window must be non-zero".to_string());
        }
        if self.authorization_ttl_blocks == 0 {
            return Err("private state transition authorization ttl must be non-zero".to_string());
        }
        if self.max_deltas_per_batch == 0 {
            return Err("private state transition max deltas must be non-zero".to_string());
        }
        if self.max_witness_items == 0 {
            return Err("private state transition max witness items must be non-zero".to_string());
        }
        if self.min_pq_security_bits < PRIVATE_STATE_TRANSITION_MIN_PQ_SECURITY_BITS {
            return Err("private state transition pq security below minimum".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedStateDelta {
    pub delta_id: String,
    pub transition_kind: TransitionKind,
    pub account_commitment: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub encrypted_delta_root: String,
    pub delta_ciphertext_hash: String,
    pub nullifier_root: String,
    pub commitment_opening_root: String,
    pub witness_bundle_id: Option<String>,
    pub authorization_id: Option<String>,
    pub sponsorship_id: Option<String>,
    pub replay_tag: String,
    pub status: DeltaStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl EncryptedStateDelta {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transition_kind: TransitionKind,
        account_commitment: &str,
        pre_state_root: &str,
        post_state_root: &str,
        encrypted_delta_root: &str,
        delta_ciphertext_hash: &str,
        nullifier_root: &str,
        commitment_opening_root: &str,
        replay_tag: &str,
        opened_at_height: u64,
        expires_at_height: u64,
        metadata: Value,
    ) -> PrivateStateTransitionResult<Self> {
        let delta_id = private_state_transition_delta_id(
            transition_kind,
            account_commitment,
            pre_state_root,
            post_state_root,
            encrypted_delta_root,
            nullifier_root,
            replay_tag,
            opened_at_height,
        );
        let delta = Self {
            delta_id,
            transition_kind,
            account_commitment: account_commitment.to_string(),
            pre_state_root: pre_state_root.to_string(),
            post_state_root: post_state_root.to_string(),
            encrypted_delta_root: encrypted_delta_root.to_string(),
            delta_ciphertext_hash: delta_ciphertext_hash.to_string(),
            nullifier_root: nullifier_root.to_string(),
            commitment_opening_root: commitment_opening_root.to_string(),
            witness_bundle_id: None,
            authorization_id: None,
            sponsorship_id: None,
            replay_tag: replay_tag.to_string(),
            status: DeltaStatus::Pending,
            opened_at_height,
            expires_at_height,
            metadata,
        };
        delta.validate()?;
        Ok(delta)
    }

    pub fn bind_witness(&mut self, witness_bundle_id: &str) -> PrivateStateTransitionResult<()> {
        ensure_non_empty("witness_bundle_id", witness_bundle_id)?;
        self.witness_bundle_id = Some(witness_bundle_id.to_string());
        if self.status == DeltaStatus::Pending {
            self.status = DeltaStatus::Witnessed;
        }
        Ok(())
    }

    pub fn bind_authorization(
        &mut self,
        authorization_id: &str,
    ) -> PrivateStateTransitionResult<()> {
        ensure_non_empty("authorization_id", authorization_id)?;
        self.authorization_id = Some(authorization_id.to_string());
        self.status = DeltaStatus::Authorized;
        Ok(())
    }

    pub fn bind_sponsorship(&mut self, sponsorship_id: &str) -> PrivateStateTransitionResult<()> {
        ensure_non_empty("sponsorship_id", sponsorship_id)?;
        self.sponsorship_id = Some(sponsorship_id.to_string());
        Ok(())
    }

    pub fn included(&mut self) {
        self.status = DeltaStatus::Included;
    }

    pub fn expired_at(&self, height: u64) -> bool {
        self.status.live() && self.expires_at_height < height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_state_delta",
            "delta_id": self.delta_id,
            "transition_kind": self.transition_kind.as_str(),
            "account_commitment": self.account_commitment,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "encrypted_delta_root": self.encrypted_delta_root,
            "delta_ciphertext_hash": self.delta_ciphertext_hash,
            "nullifier_root": self.nullifier_root,
            "commitment_opening_root": self.commitment_opening_root,
            "witness_bundle_id": self.witness_bundle_id,
            "authorization_id": self.authorization_id,
            "sponsorship_id": self.sponsorship_id,
            "replay_tag": self.replay_tag,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn delta_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-ENCRYPTED-DELTA",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("delta_id", &self.delta_id)?;
        ensure_non_empty("account_commitment", &self.account_commitment)?;
        ensure_non_empty("pre_state_root", &self.pre_state_root)?;
        ensure_non_empty("post_state_root", &self.post_state_root)?;
        ensure_non_empty("encrypted_delta_root", &self.encrypted_delta_root)?;
        ensure_non_empty("delta_ciphertext_hash", &self.delta_ciphertext_hash)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("commitment_opening_root", &self.commitment_opening_root)?;
        ensure_non_empty("replay_tag", &self.replay_tag)?;
        ensure_height_window(self.opened_at_height, self.expires_at_height, "state delta")?;
        Ok(self.delta_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierCheckpoint {
    pub checkpoint_id: String,
    pub kind: NullifierCheckpointKind,
    pub nullifier_root: String,
    pub spent_nullifier_count: u64,
    pub delta_root: String,
    pub previous_checkpoint_root: String,
    pub posted_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl NullifierCheckpoint {
    pub fn new(
        kind: NullifierCheckpointKind,
        nullifier_root: &str,
        spent_nullifier_count: u64,
        delta_root: &str,
        previous_checkpoint_root: &str,
        posted_at_height: u64,
    ) -> PrivateStateTransitionResult<Self> {
        let checkpoint_id = private_state_transition_checkpoint_id(
            kind,
            nullifier_root,
            spent_nullifier_count,
            delta_root,
            previous_checkpoint_root,
            posted_at_height,
        );
        let checkpoint = Self {
            checkpoint_id,
            kind,
            nullifier_root: nullifier_root.to_string(),
            spent_nullifier_count,
            delta_root: delta_root.to_string(),
            previous_checkpoint_root: previous_checkpoint_root.to_string(),
            posted_at_height,
            finalized_at_height: None,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nullifier_checkpoint",
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_kind": self.kind.as_str(),
            "nullifier_root": self.nullifier_root,
            "spent_nullifier_count": self.spent_nullifier_count,
            "delta_root": self.delta_root,
            "previous_checkpoint_root": self.previous_checkpoint_root,
            "posted_at_height": self.posted_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }

    pub fn checkpoint_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-NULLIFIER-CHECKPOINT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("checkpoint_id", &self.checkpoint_id)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("delta_root", &self.delta_root)?;
        ensure_non_empty("previous_checkpoint_root", &self.previous_checkpoint_root)?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.posted_at_height {
                return Err("nullifier checkpoint finalized before posting".to_string());
            }
        }
        Ok(self.checkpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentOpening {
    pub opening_id: String,
    pub opening_kind: CommitmentOpeningKind,
    pub commitment: String,
    pub blinding_commitment: String,
    pub value_ciphertext_hash: String,
    pub owner_commitment: String,
    pub asset_id: Option<String>,
    pub slot_id: Option<String>,
    pub opening_proof_root: String,
    pub opened_at_height: u64,
}

impl CommitmentOpening {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        opening_kind: CommitmentOpeningKind,
        commitment: &str,
        blinding_commitment: &str,
        value_ciphertext_hash: &str,
        owner_commitment: &str,
        asset_id: Option<String>,
        slot_id: Option<String>,
        opening_proof_root: &str,
        opened_at_height: u64,
    ) -> PrivateStateTransitionResult<Self> {
        let opening_id = private_state_transition_opening_id(
            opening_kind,
            commitment,
            blinding_commitment,
            owner_commitment,
            asset_id.as_deref().unwrap_or(""),
            slot_id.as_deref().unwrap_or(""),
            opened_at_height,
        );
        let opening = Self {
            opening_id,
            opening_kind,
            commitment: commitment.to_string(),
            blinding_commitment: blinding_commitment.to_string(),
            value_ciphertext_hash: value_ciphertext_hash.to_string(),
            owner_commitment: owner_commitment.to_string(),
            asset_id,
            slot_id,
            opening_proof_root: opening_proof_root.to_string(),
            opened_at_height,
        };
        opening.validate()?;
        Ok(opening)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "commitment_opening",
            "opening_id": self.opening_id,
            "opening_kind": self.opening_kind.as_str(),
            "commitment": self.commitment,
            "blinding_commitment": self.blinding_commitment,
            "value_ciphertext_hash": self.value_ciphertext_hash,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "slot_id": self.slot_id,
            "opening_proof_root": self.opening_proof_root,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn opening_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-COMMITMENT-OPENING",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("opening_id", &self.opening_id)?;
        ensure_non_empty("commitment", &self.commitment)?;
        ensure_non_empty("blinding_commitment", &self.blinding_commitment)?;
        ensure_non_empty("value_ciphertext_hash", &self.value_ciphertext_hash)?;
        ensure_non_empty("owner_commitment", &self.owner_commitment)?;
        ensure_non_empty("opening_proof_root", &self.opening_proof_root)?;
        Ok(self.opening_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessBundle {
    pub bundle_id: String,
    pub bundle_kind: WitnessBundleKind,
    pub delta_id: String,
    pub membership_root: String,
    pub non_membership_root: String,
    pub execution_trace_root: String,
    pub recursive_proof_root: String,
    pub witness_item_count: usize,
    pub anonymity_set_size: u64,
    pub produced_at_height: u64,
    pub producer_commitment: String,
}

impl WitnessBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_kind: WitnessBundleKind,
        delta_id: &str,
        membership_root: &str,
        non_membership_root: &str,
        execution_trace_root: &str,
        recursive_proof_root: &str,
        witness_item_count: usize,
        anonymity_set_size: u64,
        produced_at_height: u64,
        producer_commitment: &str,
    ) -> PrivateStateTransitionResult<Self> {
        let bundle_id = private_state_transition_witness_bundle_id(
            bundle_kind,
            delta_id,
            membership_root,
            non_membership_root,
            recursive_proof_root,
            produced_at_height,
        );
        let bundle = Self {
            bundle_id,
            bundle_kind,
            delta_id: delta_id.to_string(),
            membership_root: membership_root.to_string(),
            non_membership_root: non_membership_root.to_string(),
            execution_trace_root: execution_trace_root.to_string(),
            recursive_proof_root: recursive_proof_root.to_string(),
            witness_item_count,
            anonymity_set_size,
            produced_at_height,
            producer_commitment: producer_commitment.to_string(),
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "witness_bundle",
            "bundle_id": self.bundle_id,
            "bundle_kind": self.bundle_kind.as_str(),
            "delta_id": self.delta_id,
            "membership_root": self.membership_root,
            "non_membership_root": self.non_membership_root,
            "execution_trace_root": self.execution_trace_root,
            "recursive_proof_root": self.recursive_proof_root,
            "witness_item_count": self.witness_item_count,
            "anonymity_set_size": self.anonymity_set_size,
            "produced_at_height": self.produced_at_height,
            "producer_commitment": self.producer_commitment,
        })
    }

    pub fn bundle_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-WITNESS-BUNDLE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("bundle_id", &self.bundle_id)?;
        ensure_non_empty("delta_id", &self.delta_id)?;
        ensure_non_empty("membership_root", &self.membership_root)?;
        ensure_non_empty("non_membership_root", &self.non_membership_root)?;
        ensure_non_empty("execution_trace_root", &self.execution_trace_root)?;
        ensure_non_empty("recursive_proof_root", &self.recursive_proof_root)?;
        ensure_non_empty("producer_commitment", &self.producer_commitment)?;
        if self.witness_item_count == 0 {
            return Err("witness bundle must contain at least one item".to_string());
        }
        Ok(self.bundle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetDebit {
    pub debit_id: String,
    pub account_commitment: String,
    pub budget_epoch: u64,
    pub privacy_class: String,
    pub debit_units: u64,
    pub remaining_budget_commitment: String,
    pub nullifier_root: String,
    pub authorization_id: Option<String>,
    pub debited_at_height: u64,
}

impl PrivacyBudgetDebit {
    pub fn new(
        account_commitment: &str,
        budget_epoch: u64,
        privacy_class: &str,
        debit_units: u64,
        remaining_budget_commitment: &str,
        nullifier_root: &str,
        debited_at_height: u64,
    ) -> PrivateStateTransitionResult<Self> {
        let debit_id = private_state_transition_privacy_debit_id(
            account_commitment,
            budget_epoch,
            privacy_class,
            debit_units,
            nullifier_root,
            debited_at_height,
        );
        let debit = Self {
            debit_id,
            account_commitment: account_commitment.to_string(),
            budget_epoch,
            privacy_class: privacy_class.to_string(),
            debit_units,
            remaining_budget_commitment: remaining_budget_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            authorization_id: None,
            debited_at_height,
        };
        debit.validate()?;
        Ok(debit)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_debit",
            "debit_id": self.debit_id,
            "account_commitment": self.account_commitment,
            "budget_epoch": self.budget_epoch,
            "privacy_class": self.privacy_class,
            "debit_units": self.debit_units,
            "remaining_budget_commitment": self.remaining_budget_commitment,
            "nullifier_root": self.nullifier_root,
            "authorization_id": self.authorization_id,
            "debited_at_height": self.debited_at_height,
        })
    }

    pub fn debit_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-PRIVACY-BUDGET-DEBIT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("debit_id", &self.debit_id)?;
        ensure_non_empty("account_commitment", &self.account_commitment)?;
        ensure_non_empty("privacy_class", &self.privacy_class)?;
        ensure_non_empty(
            "remaining_budget_commitment",
            &self.remaining_budget_commitment,
        )?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        if self.debit_units == 0 {
            return Err("privacy budget debit units must be non-zero".to_string());
        }
        Ok(self.debit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractStorageTransition {
    pub transition_id: String,
    pub contract_commitment: String,
    pub storage_slot_commitment: String,
    pub pre_value_commitment: String,
    pub post_value_commitment: String,
    pub storage_delta_root: String,
    pub access_list_root: String,
    pub execution_receipt_root: String,
    pub applied_at_height: u64,
}

impl ContractStorageTransition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_commitment: &str,
        storage_slot_commitment: &str,
        pre_value_commitment: &str,
        post_value_commitment: &str,
        storage_delta_root: &str,
        access_list_root: &str,
        execution_receipt_root: &str,
        applied_at_height: u64,
    ) -> PrivateStateTransitionResult<Self> {
        let transition_id = private_state_transition_storage_transition_id(
            contract_commitment,
            storage_slot_commitment,
            pre_value_commitment,
            post_value_commitment,
            storage_delta_root,
            applied_at_height,
        );
        let transition = Self {
            transition_id,
            contract_commitment: contract_commitment.to_string(),
            storage_slot_commitment: storage_slot_commitment.to_string(),
            pre_value_commitment: pre_value_commitment.to_string(),
            post_value_commitment: post_value_commitment.to_string(),
            storage_delta_root: storage_delta_root.to_string(),
            access_list_root: access_list_root.to_string(),
            execution_receipt_root: execution_receipt_root.to_string(),
            applied_at_height,
        };
        transition.validate()?;
        Ok(transition)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_storage_transition",
            "transition_id": self.transition_id,
            "contract_commitment": self.contract_commitment,
            "storage_slot_commitment": self.storage_slot_commitment,
            "pre_value_commitment": self.pre_value_commitment,
            "post_value_commitment": self.post_value_commitment,
            "storage_delta_root": self.storage_delta_root,
            "access_list_root": self.access_list_root,
            "execution_receipt_root": self.execution_receipt_root,
            "applied_at_height": self.applied_at_height,
        })
    }

    pub fn transition_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-CONTRACT-STORAGE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("transition_id", &self.transition_id)?;
        ensure_non_empty("contract_commitment", &self.contract_commitment)?;
        ensure_non_empty("storage_slot_commitment", &self.storage_slot_commitment)?;
        ensure_non_empty("pre_value_commitment", &self.pre_value_commitment)?;
        ensure_non_empty("post_value_commitment", &self.post_value_commitment)?;
        ensure_non_empty("storage_delta_root", &self.storage_delta_root)?;
        ensure_non_empty("access_list_root", &self.access_list_root)?;
        ensure_non_empty("execution_receipt_root", &self.execution_receipt_root)?;
        Ok(self.transition_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenBalanceCommitment {
    pub balance_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub pre_balance_commitment: String,
    pub post_balance_commitment: String,
    pub delta_commitment: String,
    pub range_proof_root: String,
    pub balance_nullifier: String,
    pub updated_at_height: u64,
}

impl PrivateTokenBalanceCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        asset_id: &str,
        pre_balance_commitment: &str,
        post_balance_commitment: &str,
        delta_commitment: &str,
        range_proof_root: &str,
        balance_nullifier: &str,
        updated_at_height: u64,
    ) -> PrivateStateTransitionResult<Self> {
        let balance_id = private_state_transition_token_balance_id(
            owner_commitment,
            asset_id,
            pre_balance_commitment,
            post_balance_commitment,
            balance_nullifier,
            updated_at_height,
        );
        let balance = Self {
            balance_id,
            owner_commitment: owner_commitment.to_string(),
            asset_id: asset_id.to_string(),
            pre_balance_commitment: pre_balance_commitment.to_string(),
            post_balance_commitment: post_balance_commitment.to_string(),
            delta_commitment: delta_commitment.to_string(),
            range_proof_root: range_proof_root.to_string(),
            balance_nullifier: balance_nullifier.to_string(),
            updated_at_height,
        };
        balance.validate()?;
        Ok(balance)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_balance_commitment",
            "balance_id": self.balance_id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "pre_balance_commitment": self.pre_balance_commitment,
            "post_balance_commitment": self.post_balance_commitment,
            "delta_commitment": self.delta_commitment,
            "range_proof_root": self.range_proof_root,
            "balance_nullifier": self.balance_nullifier,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn balance_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-TOKEN-BALANCE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("balance_id", &self.balance_id)?;
        ensure_non_empty("owner_commitment", &self.owner_commitment)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("pre_balance_commitment", &self.pre_balance_commitment)?;
        ensure_non_empty("post_balance_commitment", &self.post_balance_commitment)?;
        ensure_non_empty("delta_commitment", &self.delta_commitment)?;
        ensure_non_empty("range_proof_root", &self.range_proof_root)?;
        ensure_non_empty("balance_nullifier", &self.balance_nullifier)?;
        Ok(self.balance_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqTransitionAuthorization {
    pub authorization_id: String,
    pub subject: AuthorizationSubject,
    pub subject_id: String,
    pub subject_root: String,
    pub signer_commitment: String,
    pub public_key_commitment: String,
    pub pq_scheme: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: AuthorizationStatus,
}

impl PqTransitionAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: AuthorizationSubject,
        subject_id: &str,
        subject_root: &str,
        signer_commitment: &str,
        public_key_commitment: &str,
        signature_root: &str,
        transcript_root: &str,
        security_bits: u16,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateStateTransitionResult<Self> {
        let authorization_id = private_state_transition_authorization_id(
            subject,
            subject_id,
            subject_root,
            signer_commitment,
            public_key_commitment,
            signature_root,
            signed_at_height,
        );
        let authorization = Self {
            authorization_id,
            subject,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            signer_commitment: signer_commitment.to_string(),
            public_key_commitment: public_key_commitment.to_string(),
            pq_scheme: PRIVATE_STATE_TRANSITION_PQ_AUTH_SCHEME.to_string(),
            signature_root: signature_root.to_string(),
            transcript_root: transcript_root.to_string(),
            security_bits,
            signed_at_height,
            expires_at_height,
            status: AuthorizationStatus::Accepted,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn expired_at(&self, height: u64) -> bool {
        self.status.usable() && self.expires_at_height < height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_transition_authorization",
            "authorization_id": self.authorization_id,
            "subject": self.subject.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_commitment": self.signer_commitment,
            "public_key_commitment": self.public_key_commitment,
            "pq_scheme": self.pq_scheme,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn authorization_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-PQ-AUTHORIZATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("authorization_id", &self.authorization_id)?;
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("subject_root", &self.subject_root)?;
        ensure_non_empty("signer_commitment", &self.signer_commitment)?;
        ensure_non_empty("public_key_commitment", &self.public_key_commitment)?;
        ensure_non_empty("pq_scheme", &self.pq_scheme)?;
        ensure_non_empty("signature_root", &self.signature_root)?;
        ensure_non_empty("transcript_root", &self.transcript_root)?;
        ensure_height_window(
            self.signed_at_height,
            self.expires_at_height,
            "pq transition authorization",
        )?;
        if self.security_bits < PRIVATE_STATE_TRANSITION_MIN_PQ_SECURITY_BITS {
            return Err("pq transition authorization security below minimum".to_string());
        }
        Ok(self.authorization_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayProtection {
    pub replay_id: String,
    pub replay_tag: String,
    pub scope_root: String,
    pub nullifier_root: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl ReplayProtection {
    pub fn new(
        replay_tag: &str,
        scope_root: &str,
        nullifier_root: &str,
        first_seen_height: u64,
        expires_at_height: u64,
    ) -> PrivateStateTransitionResult<Self> {
        let replay_id = private_state_transition_replay_id(
            replay_tag,
            scope_root,
            nullifier_root,
            first_seen_height,
        );
        let replay = Self {
            replay_id,
            replay_tag: replay_tag.to_string(),
            scope_root: scope_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            first_seen_height,
            expires_at_height,
            consumed: false,
        };
        replay.validate()?;
        Ok(replay)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "replay_protection",
            "replay_id": self.replay_id,
            "replay_tag": self.replay_tag,
            "scope_root": self.scope_root,
            "nullifier_root": self.nullifier_root,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "consumed": self.consumed,
        })
    }

    pub fn replay_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-REPLAY-PROTECTION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("replay_id", &self.replay_id)?;
        ensure_non_empty("replay_tag", &self.replay_tag)?;
        ensure_non_empty("scope_root", &self.scope_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_height_window(
            self.first_seen_height,
            self.expires_at_height,
            "replay protection",
        )?;
        Ok(self.replay_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeTransitionSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub delta_id: String,
    pub max_fee_micro_units: u64,
    pub reserved_fee_micro_units: u64,
    pub reserve_proof_root: String,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeTransitionSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        delta_id: &str,
        max_fee_micro_units: u64,
        reserved_fee_micro_units: u64,
        reserve_proof_root: &str,
        policy_root: &str,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateStateTransitionResult<Self> {
        let sponsorship_id = private_state_transition_sponsorship_id(
            sponsor_commitment,
            delta_id,
            max_fee_micro_units,
            reserved_fee_micro_units,
            reserve_proof_root,
            opened_at_height,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            delta_id: delta_id.to_string(),
            max_fee_micro_units,
            reserved_fee_micro_units,
            reserve_proof_root: reserve_proof_root.to_string(),
            policy_root: policy_root.to_string(),
            opened_at_height,
            expires_at_height,
            status: SponsorshipStatus::Reserved,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn expired_at(&self, height: u64) -> bool {
        self.status.live() && self.expires_at_height < height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_transition_sponsorship",
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "delta_id": self.delta_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "reserved_fee_micro_units": self.reserved_fee_micro_units,
            "reserve_proof_root": self.reserve_proof_root,
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-LOW-FEE-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("sponsorship_id", &self.sponsorship_id)?;
        ensure_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("delta_id", &self.delta_id)?;
        ensure_non_empty("reserve_proof_root", &self.reserve_proof_root)?;
        ensure_non_empty("policy_root", &self.policy_root)?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "low-fee transition sponsorship",
        )?;
        if self.max_fee_micro_units == 0 {
            return Err("low-fee sponsorship max fee must be non-zero".to_string());
        }
        if self.reserved_fee_micro_units > self.max_fee_micro_units {
            return Err("low-fee sponsorship reserves more than max fee".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionReceipt {
    pub receipt_id: String,
    pub surface: InclusionSurface,
    pub delta_id: String,
    pub batch_root: String,
    pub da_root: String,
    pub proof_root: String,
    pub public_input_root: String,
    pub inclusion_height: u64,
    pub expires_at_height: u64,
    pub sequencer_commitment: String,
}

impl InclusionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        surface: InclusionSurface,
        delta_id: &str,
        batch_root: &str,
        da_root: &str,
        proof_root: &str,
        public_input_root: &str,
        inclusion_height: u64,
        expires_at_height: u64,
        sequencer_commitment: &str,
    ) -> PrivateStateTransitionResult<Self> {
        let receipt_id = private_state_transition_inclusion_receipt_id(
            surface,
            delta_id,
            batch_root,
            da_root,
            proof_root,
            inclusion_height,
        );
        let receipt = Self {
            receipt_id,
            surface,
            delta_id: delta_id.to_string(),
            batch_root: batch_root.to_string(),
            da_root: da_root.to_string(),
            proof_root: proof_root.to_string(),
            public_input_root: public_input_root.to_string(),
            inclusion_height,
            expires_at_height,
            sequencer_commitment: sequencer_commitment.to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "inclusion_receipt",
            "receipt_id": self.receipt_id,
            "surface": self.surface.as_str(),
            "delta_id": self.delta_id,
            "batch_root": self.batch_root,
            "da_root": self.da_root,
            "proof_root": self.proof_root,
            "public_input_root": self.public_input_root,
            "inclusion_height": self.inclusion_height,
            "expires_at_height": self.expires_at_height,
            "sequencer_commitment": self.sequencer_commitment,
        })
    }

    pub fn receipt_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-INCLUSION-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("receipt_id", &self.receipt_id)?;
        ensure_non_empty("delta_id", &self.delta_id)?;
        ensure_non_empty("batch_root", &self.batch_root)?;
        ensure_non_empty("da_root", &self.da_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("public_input_root", &self.public_input_root)?;
        ensure_non_empty("sequencer_commitment", &self.sequencer_commitment)?;
        ensure_height_window(
            self.inclusion_height,
            self.expires_at_height,
            "inclusion receipt",
        )?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicTransitionRecord {
    pub record_id: String,
    pub label: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub payload: Value,
}

impl PublicTransitionRecord {
    pub fn new(
        label: &str,
        subject_id: &str,
        subject_root: &str,
        height: u64,
        payload: Value,
    ) -> PrivateStateTransitionResult<Self> {
        let record_id = private_state_transition_public_record_id(
            label,
            subject_id,
            subject_root,
            height,
            &payload,
        );
        let record = Self {
            record_id,
            label: label.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            height,
            payload,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "public_transition_record",
            "record_id": self.record_id,
            "label": self.label,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
            "payload": self.payload,
        })
    }

    pub fn record_root(&self) -> String {
        private_state_transition_payload_root(
            "PRIVATE-STATE-TRANSITION-PUBLIC-RECORD",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        ensure_non_empty("record_id", &self.record_id)?;
        ensure_non_empty("label", &self.label)?;
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("subject_root", &self.subject_root)?;
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub encrypted_delta_root: String,
    pub nullifier_checkpoint_root: String,
    pub commitment_opening_root: String,
    pub witness_bundle_root: String,
    pub privacy_budget_debit_root: String,
    pub contract_storage_transition_root: String,
    pub token_balance_commitment_root: String,
    pub pq_authorization_root: String,
    pub replay_protection_root: String,
    pub sponsorship_root: String,
    pub inclusion_receipt_root: String,
    pub public_record_root: String,
    pub spent_nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_state_transition_roots",
            "config_root": self.config_root,
            "encrypted_delta_root": self.encrypted_delta_root,
            "nullifier_checkpoint_root": self.nullifier_checkpoint_root,
            "commitment_opening_root": self.commitment_opening_root,
            "witness_bundle_root": self.witness_bundle_root,
            "privacy_budget_debit_root": self.privacy_budget_debit_root,
            "contract_storage_transition_root": self.contract_storage_transition_root,
            "token_balance_commitment_root": self.token_balance_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "replay_protection_root": self.replay_protection_root,
            "sponsorship_root": self.sponsorship_root,
            "inclusion_receipt_root": self.inclusion_receipt_root,
            "public_record_root": self.public_record_root,
            "spent_nullifier_root": self.spent_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub encrypted_delta_count: u64,
    pub live_delta_count: u64,
    pub included_delta_count: u64,
    pub nullifier_checkpoint_count: u64,
    pub commitment_opening_count: u64,
    pub witness_bundle_count: u64,
    pub privacy_budget_debit_count: u64,
    pub contract_storage_transition_count: u64,
    pub token_balance_commitment_count: u64,
    pub pq_authorization_count: u64,
    pub usable_pq_authorization_count: u64,
    pub replay_protection_count: u64,
    pub consumed_replay_count: u64,
    pub sponsorship_count: u64,
    pub live_sponsorship_count: u64,
    pub inclusion_receipt_count: u64,
    pub public_record_count: u64,
    pub spent_nullifier_count: u64,
    pub total_privacy_budget_debit_units: u64,
    pub total_reserved_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "encrypted_delta_count": self.encrypted_delta_count,
            "live_delta_count": self.live_delta_count,
            "included_delta_count": self.included_delta_count,
            "nullifier_checkpoint_count": self.nullifier_checkpoint_count,
            "commitment_opening_count": self.commitment_opening_count,
            "witness_bundle_count": self.witness_bundle_count,
            "privacy_budget_debit_count": self.privacy_budget_debit_count,
            "contract_storage_transition_count": self.contract_storage_transition_count,
            "token_balance_commitment_count": self.token_balance_commitment_count,
            "pq_authorization_count": self.pq_authorization_count,
            "usable_pq_authorization_count": self.usable_pq_authorization_count,
            "replay_protection_count": self.replay_protection_count,
            "consumed_replay_count": self.consumed_replay_count,
            "sponsorship_count": self.sponsorship_count,
            "live_sponsorship_count": self.live_sponsorship_count,
            "inclusion_receipt_count": self.inclusion_receipt_count,
            "public_record_count": self.public_record_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "total_privacy_budget_debit_units": self.total_privacy_budget_debit_units,
            "total_reserved_fee_micro_units": self.total_reserved_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub encrypted_deltas: BTreeMap<String, EncryptedStateDelta>,
    pub nullifier_checkpoints: BTreeMap<String, NullifierCheckpoint>,
    pub commitment_openings: BTreeMap<String, CommitmentOpening>,
    pub witness_bundles: BTreeMap<String, WitnessBundle>,
    pub privacy_budget_debits: BTreeMap<String, PrivacyBudgetDebit>,
    pub contract_storage_transitions: BTreeMap<String, ContractStorageTransition>,
    pub token_balance_commitments: BTreeMap<String, PrivateTokenBalanceCommitment>,
    pub pq_authorizations: BTreeMap<String, PqTransitionAuthorization>,
    pub replay_protections: BTreeMap<String, ReplayProtection>,
    pub sponsorships: BTreeMap<String, LowFeeTransitionSponsorship>,
    pub inclusion_receipts: BTreeMap<String, InclusionReceipt>,
    pub public_records: BTreeMap<String, PublicTransitionRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> PrivateStateTransitionResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            encrypted_deltas: BTreeMap::new(),
            nullifier_checkpoints: BTreeMap::new(),
            commitment_openings: BTreeMap::new(),
            witness_bundles: BTreeMap::new(),
            privacy_budget_debits: BTreeMap::new(),
            contract_storage_transitions: BTreeMap::new(),
            token_balance_commitments: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            replay_protections: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            inclusion_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> PrivateStateTransitionResult<Self> {
        let mut state = Self::new(Config::devnet())?;
        state.height = PRIVATE_STATE_TRANSITION_DEVNET_HEIGHT;

        let opening = CommitmentOpening::new(
            CommitmentOpeningKind::Account,
            "commitment:devnet-account-state",
            "blinding:devnet-account-state",
            "ciphertext-hash:devnet-account-state",
            "owner:devnet-account",
            Some("asset:wxmr".to_string()),
            None,
            "opening-proof-root:devnet-account-state",
            state.height,
        )?;
        let opening_root = opening.opening_root();
        state.insert_commitment_opening(opening)?;

        let mut delta = EncryptedStateDelta::new(
            TransitionKind::PrivateTransfer,
            "account-commitment:devnet-alice",
            "pre-state-root:devnet-private-transfer",
            "post-state-root:devnet-private-transfer",
            "encrypted-delta-root:devnet-private-transfer",
            "ciphertext-hash:devnet-private-transfer",
            "nullifier-root:devnet-private-transfer",
            &opening_root,
            "replay-tag:devnet-private-transfer",
            state.height,
            state.height + state.config.replay_window_blocks,
            json!({"lane": "devnet", "memo_ciphertext_hash": "memo-hash:devnet"}),
        )?;

        let replay = ReplayProtection::new(
            &delta.replay_tag,
            "scope-root:devnet-private-transfer",
            &delta.nullifier_root,
            state.height,
            state.height + state.config.replay_window_blocks,
        )?;
        state.insert_replay_protection(replay)?;

        let witness = WitnessBundle::new(
            WitnessBundleKind::RecursiveAggregate,
            &delta.delta_id,
            "membership-root:devnet-private-transfer",
            "non-membership-root:devnet-private-transfer",
            "execution-trace-root:devnet-private-transfer",
            "recursive-proof-root:devnet-private-transfer",
            7,
            state.config.min_anonymity_set,
            state.height + 1,
            "producer:devnet-prover",
        )?;
        delta.bind_witness(&witness.bundle_id)?;
        let witness_root = witness.bundle_root();
        state.insert_witness_bundle(witness)?;

        let auth = PqTransitionAuthorization::new(
            AuthorizationSubject::StateDelta,
            &delta.delta_id,
            &delta.delta_root(),
            "signer:devnet-wallet-pq",
            "pq-public-key-commitment:devnet-wallet",
            "pq-signature-root:devnet-wallet",
            &witness_root,
            state.config.min_pq_security_bits,
            state.height + 1,
            state.height + state.config.authorization_ttl_blocks,
        )?;
        delta.bind_authorization(&auth.authorization_id)?;
        state.insert_pq_authorization(auth)?;

        let sponsorship = LowFeeTransitionSponsorship::new(
            "sponsor:devnet-low-fee",
            &delta.delta_id,
            12_000,
            7_500,
            "reserve-proof-root:devnet-low-fee",
            "policy-root:devnet-low-fee",
            state.height,
            state.height + state.config.authorization_ttl_blocks,
        )?;
        delta.bind_sponsorship(&sponsorship.sponsorship_id)?;
        state.insert_sponsorship(sponsorship)?;

        let delta_id = delta.delta_id.clone();
        state.insert_encrypted_delta(delta)?;

        let storage = ContractStorageTransition::new(
            "contract:devnet-private-amm",
            "slot:devnet-private-amm-reserves",
            "pre-value:devnet-private-amm-reserves",
            "post-value:devnet-private-amm-reserves",
            "storage-delta-root:devnet-private-amm",
            "access-list-root:devnet-private-amm",
            "execution-receipt-root:devnet-private-amm",
            state.height + 2,
        )?;
        state.insert_contract_storage_transition(storage)?;

        let balance = PrivateTokenBalanceCommitment::new(
            "owner:devnet-alice",
            "asset:wxmr",
            "pre-balance:devnet-alice-wxmr",
            "post-balance:devnet-alice-wxmr",
            "delta-balance:devnet-alice-wxmr",
            "range-proof-root:devnet-alice-wxmr",
            "balance-nullifier:devnet-alice-wxmr",
            state.height + 2,
        )?;
        state.insert_token_balance_commitment(balance)?;

        let debit = PrivacyBudgetDebit::new(
            "account-commitment:devnet-alice",
            state.epoch(),
            "transfer",
            3,
            "remaining-budget-commitment:devnet-alice",
            "privacy-budget-nullifier-root:devnet-alice",
            state.height + 2,
        )?;
        state.insert_privacy_budget_debit(debit)?;

        let receipt = InclusionReceipt::new(
            InclusionSurface::DataAvailability,
            &delta_id,
            "batch-root:devnet-private-transfer",
            "da-root:devnet-private-transfer",
            "proof-root:devnet-private-transfer",
            "public-input-root:devnet-private-transfer",
            state.height + 3,
            state.height + state.config.receipt_ttl_blocks,
            "sequencer:devnet",
        )?;
        state.include_delta(&delta_id, receipt)?;

        let checkpoint = NullifierCheckpoint::new(
            NullifierCheckpointKind::DaPosted,
            &state.spent_nullifier_root(),
            state.spent_nullifiers.len() as u64,
            &state.encrypted_delta_root(),
            &private_state_transition_empty_root("PRIVATE-STATE-TRANSITION-GENESIS-CHECKPOINT"),
            state.height + 3,
        )?;
        state.insert_nullifier_checkpoint(checkpoint)?;

        let bootstrap_subject_root = state.state_root();
        state.record_public_record(
            "devnet_private_state_transition_bootstrap",
            &delta_id,
            &bootstrap_subject_root,
            json!({
                "height": state.height,
                "delta_encryption_scheme": PRIVATE_STATE_TRANSITION_DELTA_ENCRYPTION_SCHEME,
                "commitment_scheme": PRIVATE_STATE_TRANSITION_COMMITMENT_SCHEME,
                "pq_authorization_scheme": PRIVATE_STATE_TRANSITION_PQ_AUTH_SCHEME,
            }),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateStateTransitionResult<String> {
        if height < self.height {
            return Err("private state transition height cannot move backwards".to_string());
        }
        self.height = height;
        for delta in self.encrypted_deltas.values_mut() {
            if delta.expired_at(height) {
                delta.status = DeltaStatus::Expired;
            }
        }
        for authorization in self.pq_authorizations.values_mut() {
            if authorization.expired_at(height) {
                authorization.status = AuthorizationStatus::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.expired_at(height) {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn epoch(&self) -> u64 {
        self.height / self.config.epoch_blocks
    }

    pub fn insert_encrypted_delta(
        &mut self,
        delta: EncryptedStateDelta,
    ) -> PrivateStateTransitionResult<String> {
        let root = delta.validate()?;
        if self.encrypted_deltas.len() >= self.config.max_deltas_per_batch {
            return Err("private state transition delta batch is full".to_string());
        }
        if self.spent_nullifiers.contains(&delta.nullifier_root) {
            return Err("private state transition nullifier already spent".to_string());
        }
        if self
            .encrypted_deltas
            .values()
            .any(|known| known.nullifier_root == delta.nullifier_root)
        {
            return Err("duplicate private state transition nullifier root".to_string());
        }
        if self
            .replay_protections
            .values()
            .any(|known| known.replay_tag == delta.replay_tag && known.consumed)
        {
            return Err("private state transition replay tag already consumed".to_string());
        }
        self.encrypted_deltas.insert(delta.delta_id.clone(), delta);
        Ok(root)
    }

    pub fn insert_nullifier_checkpoint(
        &mut self,
        checkpoint: NullifierCheckpoint,
    ) -> PrivateStateTransitionResult<String> {
        let root = checkpoint.validate()?;
        self.nullifier_checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint);
        Ok(root)
    }

    pub fn insert_commitment_opening(
        &mut self,
        opening: CommitmentOpening,
    ) -> PrivateStateTransitionResult<String> {
        let root = opening.validate()?;
        self.commitment_openings
            .insert(opening.opening_id.clone(), opening);
        Ok(root)
    }

    pub fn insert_witness_bundle(
        &mut self,
        bundle: WitnessBundle,
    ) -> PrivateStateTransitionResult<String> {
        let root = bundle.validate()?;
        if bundle.witness_item_count > self.config.max_witness_items {
            return Err("private state transition witness bundle too large".to_string());
        }
        if bundle.anonymity_set_size < self.config.min_anonymity_set {
            return Err("private state transition witness anonymity set too small".to_string());
        }
        self.witness_bundles
            .insert(bundle.bundle_id.clone(), bundle);
        Ok(root)
    }

    pub fn insert_privacy_budget_debit(
        &mut self,
        debit: PrivacyBudgetDebit,
    ) -> PrivateStateTransitionResult<String> {
        let root = debit.validate()?;
        self.privacy_budget_debits
            .insert(debit.debit_id.clone(), debit);
        Ok(root)
    }

    pub fn insert_contract_storage_transition(
        &mut self,
        transition: ContractStorageTransition,
    ) -> PrivateStateTransitionResult<String> {
        let root = transition.validate()?;
        self.contract_storage_transitions
            .insert(transition.transition_id.clone(), transition);
        Ok(root)
    }

    pub fn insert_token_balance_commitment(
        &mut self,
        balance: PrivateTokenBalanceCommitment,
    ) -> PrivateStateTransitionResult<String> {
        let root = balance.validate()?;
        if self
            .token_balance_commitments
            .values()
            .any(|known| known.balance_nullifier == balance.balance_nullifier)
        {
            return Err("duplicate private token balance nullifier".to_string());
        }
        self.token_balance_commitments
            .insert(balance.balance_id.clone(), balance);
        Ok(root)
    }

    pub fn insert_pq_authorization(
        &mut self,
        authorization: PqTransitionAuthorization,
    ) -> PrivateStateTransitionResult<String> {
        let root = authorization.validate()?;
        if authorization.security_bits < self.config.min_pq_security_bits {
            return Err("pq transition authorization below configured security".to_string());
        }
        self.pq_authorizations
            .insert(authorization.authorization_id.clone(), authorization);
        Ok(root)
    }

    pub fn insert_replay_protection(
        &mut self,
        replay: ReplayProtection,
    ) -> PrivateStateTransitionResult<String> {
        let root = replay.validate()?;
        if self
            .replay_protections
            .values()
            .any(|known| known.replay_tag == replay.replay_tag)
        {
            return Err("duplicate private state transition replay tag".to_string());
        }
        self.replay_protections
            .insert(replay.replay_id.clone(), replay);
        Ok(root)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeTransitionSponsorship,
    ) -> PrivateStateTransitionResult<String> {
        let root = sponsorship.validate()?;
        if !self.config.allow_sponsored_transitions {
            return Err("private state transition sponsorship disabled".to_string());
        }
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(root)
    }

    pub fn insert_inclusion_receipt(
        &mut self,
        receipt: InclusionReceipt,
    ) -> PrivateStateTransitionResult<String> {
        let root = receipt.validate()?;
        self.inclusion_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn include_delta(
        &mut self,
        delta_id: &str,
        receipt: InclusionReceipt,
    ) -> PrivateStateTransitionResult<String> {
        if receipt.delta_id != delta_id {
            return Err("inclusion receipt delta mismatch".to_string());
        }
        let root = receipt.validate()?;
        let delta = self
            .encrypted_deltas
            .get_mut(delta_id)
            .ok_or_else(|| format!("private state transition delta not found: {delta_id}"))?;
        delta.included();
        self.spent_nullifiers.insert(delta.nullifier_root.clone());
        if let Some(replay) = self
            .replay_protections
            .values_mut()
            .find(|known| known.replay_tag == delta.replay_tag)
        {
            replay.consumed = true;
        }
        if let Some(sponsorship_id) = &delta.sponsorship_id {
            if let Some(sponsorship) = self.sponsorships.get_mut(sponsorship_id) {
                sponsorship.status = SponsorshipStatus::Consumed;
            }
        }
        self.inclusion_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn record_public_record(
        &mut self,
        label: &str,
        subject_id: &str,
        subject_root: &str,
        payload: Value,
    ) -> PrivateStateTransitionResult<String> {
        let record =
            PublicTransitionRecord::new(label, subject_id, subject_root, self.height, payload)?;
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    pub fn live_delta_ids(&self) -> Vec<String> {
        self.encrypted_deltas
            .values()
            .filter(|delta| delta.status.live())
            .map(|delta| delta.delta_id.clone())
            .collect()
    }

    pub fn included_delta_ids(&self) -> Vec<String> {
        self.encrypted_deltas
            .values()
            .filter(|delta| delta.status == DeltaStatus::Included)
            .map(|delta| delta.delta_id.clone())
            .collect()
    }

    pub fn encrypted_delta_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-DELTA-COLLECTION",
            &self
                .encrypted_deltas
                .values()
                .map(EncryptedStateDelta::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn nullifier_checkpoint_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-NULLIFIER-CHECKPOINT-COLLECTION",
            &self
                .nullifier_checkpoints
                .values()
                .map(NullifierCheckpoint::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn commitment_opening_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-COMMITMENT-OPENING-COLLECTION",
            &self
                .commitment_openings
                .values()
                .map(CommitmentOpening::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn witness_bundle_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-WITNESS-BUNDLE-COLLECTION",
            &self
                .witness_bundles
                .values()
                .map(WitnessBundle::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn privacy_budget_debit_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-PRIVACY-BUDGET-DEBIT-COLLECTION",
            &self
                .privacy_budget_debits
                .values()
                .map(PrivacyBudgetDebit::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn contract_storage_transition_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-CONTRACT-STORAGE-COLLECTION",
            &self
                .contract_storage_transitions
                .values()
                .map(ContractStorageTransition::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn token_balance_commitment_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-TOKEN-BALANCE-COLLECTION",
            &self
                .token_balance_commitments
                .values()
                .map(PrivateTokenBalanceCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_authorization_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-PQ-AUTHORIZATION-COLLECTION",
            &self
                .pq_authorizations
                .values()
                .map(PqTransitionAuthorization::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn replay_protection_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-REPLAY-PROTECTION-COLLECTION",
            &self
                .replay_protections
                .values()
                .map(ReplayProtection::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsorship_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-SPONSORSHIP-COLLECTION",
            &self
                .sponsorships
                .values()
                .map(LowFeeTransitionSponsorship::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn inclusion_receipt_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-INCLUSION-RECEIPT-COLLECTION",
            &self
                .inclusion_receipts
                .values()
                .map(InclusionReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-PUBLIC-RECORD-COLLECTION",
            &self
                .public_records
                .values()
                .map(PublicTransitionRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn spent_nullifier_root(&self) -> String {
        let records = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!({"nullifier_root": nullifier}))
            .collect::<Vec<_>>();
        private_state_transition_collection_root(
            "PRIVATE-STATE-TRANSITION-SPENT-NULLIFIER-COLLECTION",
            &records,
        )
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.config_root(),
            encrypted_delta_root: self.encrypted_delta_root(),
            nullifier_checkpoint_root: self.nullifier_checkpoint_root(),
            commitment_opening_root: self.commitment_opening_root(),
            witness_bundle_root: self.witness_bundle_root(),
            privacy_budget_debit_root: self.privacy_budget_debit_root(),
            contract_storage_transition_root: self.contract_storage_transition_root(),
            token_balance_commitment_root: self.token_balance_commitment_root(),
            pq_authorization_root: self.pq_authorization_root(),
            replay_protection_root: self.replay_protection_root(),
            sponsorship_root: self.sponsorship_root(),
            inclusion_receipt_root: self.inclusion_receipt_root(),
            public_record_root: self.public_record_root(),
            spent_nullifier_root: self.spent_nullifier_root(),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            encrypted_delta_count: self.encrypted_deltas.len() as u64,
            live_delta_count: self
                .encrypted_deltas
                .values()
                .filter(|delta| delta.status.live())
                .count() as u64,
            included_delta_count: self
                .encrypted_deltas
                .values()
                .filter(|delta| delta.status == DeltaStatus::Included)
                .count() as u64,
            nullifier_checkpoint_count: self.nullifier_checkpoints.len() as u64,
            commitment_opening_count: self.commitment_openings.len() as u64,
            witness_bundle_count: self.witness_bundles.len() as u64,
            privacy_budget_debit_count: self.privacy_budget_debits.len() as u64,
            contract_storage_transition_count: self.contract_storage_transitions.len() as u64,
            token_balance_commitment_count: self.token_balance_commitments.len() as u64,
            pq_authorization_count: self.pq_authorizations.len() as u64,
            usable_pq_authorization_count: self
                .pq_authorizations
                .values()
                .filter(|authorization| authorization.status.usable())
                .count() as u64,
            replay_protection_count: self.replay_protections.len() as u64,
            consumed_replay_count: self
                .replay_protections
                .values()
                .filter(|replay| replay.consumed)
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            live_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.live())
                .count() as u64,
            inclusion_receipt_count: self.inclusion_receipts.len() as u64,
            public_record_count: self.public_records.len() as u64,
            spent_nullifier_count: self.spent_nullifiers.len() as u64,
            total_privacy_budget_debit_units: self
                .privacy_budget_debits
                .values()
                .map(|debit| debit.debit_units)
                .sum(),
            total_reserved_fee_micro_units: self
                .sponsorships
                .values()
                .map(|sponsorship| sponsorship.reserved_fee_micro_units)
                .sum(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_state_transition_state",
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "height": self.height,
            "epoch": self.epoch(),
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_delta_ids": self.live_delta_ids(),
            "included_delta_ids": self.included_delta_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        private_state_transition_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateStateTransitionResult<String> {
        self.config.validate()?;

        let mut open_nullifiers = BTreeSet::new();
        let mut replay_tags = BTreeSet::new();
        for delta in self.encrypted_deltas.values() {
            delta.validate()?;
            if !open_nullifiers.insert(delta.nullifier_root.clone()) {
                return Err("duplicate encrypted state delta nullifier root".to_string());
            }
            if !replay_tags.insert(delta.replay_tag.clone()) {
                return Err("duplicate encrypted state delta replay tag".to_string());
            }
            if let Some(witness_bundle_id) = &delta.witness_bundle_id {
                if !self.witness_bundles.contains_key(witness_bundle_id) {
                    return Err(format!(
                        "delta {} references missing witness bundle",
                        delta.delta_id
                    ));
                }
            }
            if self.config.require_pq_authorization {
                let authorization_id = delta.authorization_id.as_ref().ok_or_else(|| {
                    format!("delta {} is missing pq authorization", delta.delta_id)
                })?;
                let authorization =
                    self.pq_authorizations
                        .get(authorization_id)
                        .ok_or_else(|| {
                            format!(
                                "delta {} references missing pq authorization",
                                delta.delta_id
                            )
                        })?;
                if !authorization.status.usable() && delta.status == DeltaStatus::Authorized {
                    return Err(format!(
                        "delta {} authorization is not usable",
                        delta.delta_id
                    ));
                }
            }
            if let Some(sponsorship_id) = &delta.sponsorship_id {
                if !self.sponsorships.contains_key(sponsorship_id) {
                    return Err(format!(
                        "delta {} references missing sponsorship",
                        delta.delta_id
                    ));
                }
            }
        }

        for checkpoint in self.nullifier_checkpoints.values() {
            checkpoint.validate()?;
        }
        for opening in self.commitment_openings.values() {
            opening.validate()?;
        }
        for bundle in self.witness_bundles.values() {
            bundle.validate()?;
            if bundle.witness_item_count > self.config.max_witness_items {
                return Err(format!(
                    "witness bundle {} exceeds max items",
                    bundle.bundle_id
                ));
            }
            if bundle.anonymity_set_size < self.config.min_anonymity_set {
                return Err(format!(
                    "witness bundle {} below anonymity set minimum",
                    bundle.bundle_id
                ));
            }
            if !self.encrypted_deltas.contains_key(&bundle.delta_id) {
                return Err(format!(
                    "witness bundle {} references missing delta",
                    bundle.bundle_id
                ));
            }
        }
        for debit in self.privacy_budget_debits.values() {
            debit.validate()?;
        }
        for transition in self.contract_storage_transitions.values() {
            transition.validate()?;
        }

        let mut balance_nullifiers = BTreeSet::new();
        for balance in self.token_balance_commitments.values() {
            balance.validate()?;
            if !balance_nullifiers.insert(balance.balance_nullifier.clone()) {
                return Err("duplicate token balance nullifier".to_string());
            }
        }
        for authorization in self.pq_authorizations.values() {
            authorization.validate()?;
            if authorization.security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "pq authorization {} below configured security",
                    authorization.authorization_id
                ));
            }
        }

        let mut protected_replay_tags = BTreeSet::new();
        for replay in self.replay_protections.values() {
            replay.validate()?;
            if !protected_replay_tags.insert(replay.replay_tag.clone()) {
                return Err("duplicate replay protection tag".to_string());
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if !self.encrypted_deltas.contains_key(&sponsorship.delta_id) {
                return Err(format!(
                    "sponsorship {} references missing delta",
                    sponsorship.sponsorship_id
                ));
            }
        }
        for receipt in self.inclusion_receipts.values() {
            receipt.validate()?;
            if !self.encrypted_deltas.contains_key(&receipt.delta_id) {
                return Err(format!(
                    "inclusion receipt {} references missing delta",
                    receipt.receipt_id
                ));
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }

        Ok(self.state_root())
    }
}

pub fn private_state_transition_state_root_from_record(record: &Value) -> String {
    private_state_transition_payload_root("PRIVATE-STATE-TRANSITION-STATE-ROOT", record)
}

pub fn private_state_transition_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_state_transition_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_state_transition_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn private_state_transition_collection_root(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

#[allow(clippy::too_many_arguments)]
pub fn private_state_transition_delta_id(
    transition_kind: TransitionKind,
    account_commitment: &str,
    pre_state_root: &str,
    post_state_root: &str,
    encrypted_delta_root: &str,
    nullifier_root: &str,
    replay_tag: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-DELTA-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(transition_kind.as_str()),
            HashPart::Str(account_commitment),
            HashPart::Str(pre_state_root),
            HashPart::Str(post_state_root),
            HashPart::Str(encrypted_delta_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(replay_tag),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_checkpoint_id(
    kind: NullifierCheckpointKind,
    nullifier_root: &str,
    spent_nullifier_count: u64,
    delta_root: &str,
    previous_checkpoint_root: &str,
    posted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-CHECKPOINT-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(nullifier_root),
            HashPart::Int(spent_nullifier_count as i128),
            HashPart::Str(delta_root),
            HashPart::Str(previous_checkpoint_root),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_opening_id(
    opening_kind: CommitmentOpeningKind,
    commitment: &str,
    blinding_commitment: &str,
    owner_commitment: &str,
    asset_id: &str,
    slot_id: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-OPENING-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(opening_kind.as_str()),
            HashPart::Str(commitment),
            HashPart::Str(blinding_commitment),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(slot_id),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_witness_bundle_id(
    bundle_kind: WitnessBundleKind,
    delta_id: &str,
    membership_root: &str,
    non_membership_root: &str,
    recursive_proof_root: &str,
    produced_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-WITNESS-BUNDLE-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(bundle_kind.as_str()),
            HashPart::Str(delta_id),
            HashPart::Str(membership_root),
            HashPart::Str(non_membership_root),
            HashPart::Str(recursive_proof_root),
            HashPart::Int(produced_at_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_privacy_debit_id(
    account_commitment: &str,
    budget_epoch: u64,
    privacy_class: &str,
    debit_units: u64,
    nullifier_root: &str,
    debited_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-PRIVACY-DEBIT-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(account_commitment),
            HashPart::Int(budget_epoch as i128),
            HashPart::Str(privacy_class),
            HashPart::Int(debit_units as i128),
            HashPart::Str(nullifier_root),
            HashPart::Int(debited_at_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_storage_transition_id(
    contract_commitment: &str,
    storage_slot_commitment: &str,
    pre_value_commitment: &str,
    post_value_commitment: &str,
    storage_delta_root: &str,
    applied_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-STORAGE-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(contract_commitment),
            HashPart::Str(storage_slot_commitment),
            HashPart::Str(pre_value_commitment),
            HashPart::Str(post_value_commitment),
            HashPart::Str(storage_delta_root),
            HashPart::Int(applied_at_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_token_balance_id(
    owner_commitment: &str,
    asset_id: &str,
    pre_balance_commitment: &str,
    post_balance_commitment: &str,
    balance_nullifier: &str,
    updated_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-TOKEN-BALANCE-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(pre_balance_commitment),
            HashPart::Str(post_balance_commitment),
            HashPart::Str(balance_nullifier),
            HashPart::Int(updated_at_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_authorization_id(
    subject: AuthorizationSubject,
    subject_id: &str,
    subject_root: &str,
    signer_commitment: &str,
    public_key_commitment: &str,
    signature_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(subject.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signer_commitment),
            HashPart::Str(public_key_commitment),
            HashPart::Str(signature_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_replay_id(
    replay_tag: &str,
    scope_root: &str,
    nullifier_root: &str,
    first_seen_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(replay_tag),
            HashPart::Str(scope_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(first_seen_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_sponsorship_id(
    sponsor_commitment: &str,
    delta_id: &str,
    max_fee_micro_units: u64,
    reserved_fee_micro_units: u64,
    reserve_proof_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-SPONSORSHIP-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(delta_id),
            HashPart::Int(max_fee_micro_units as i128),
            HashPart::Int(reserved_fee_micro_units as i128),
            HashPart::Str(reserve_proof_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_inclusion_receipt_id(
    surface: InclusionSurface,
    delta_id: &str,
    batch_root: &str,
    da_root: &str,
    proof_root: &str,
    inclusion_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-INCLUSION-RECEIPT-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(surface.as_str()),
            HashPart::Str(delta_id),
            HashPart::Str(batch_root),
            HashPart::Str(da_root),
            HashPart::Str(proof_root),
            HashPart::Int(inclusion_height as i128),
        ],
        32,
    )
}

pub fn private_state_transition_public_record_id(
    label: &str,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    payload: &Value,
) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PRIVATE_STATE_TRANSITION_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(height as i128),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn ensure_non_empty(label: &str, value: &str) -> PrivateStateTransitionResult<()> {
    if value.trim().is_empty() {
        return Err(format!(
            "private state transition {label} must be non-empty"
        ));
    }
    Ok(())
}

fn ensure_height_window(
    start_height: u64,
    end_height: u64,
    label: &str,
) -> PrivateStateTransitionResult<()> {
    if end_height < start_height {
        return Err(format!(
            "private state transition {label} end height is before start height"
        ));
    }
    Ok(())
}
