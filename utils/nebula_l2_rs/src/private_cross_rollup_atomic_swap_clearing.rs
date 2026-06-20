use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateCrossRollupAtomicSwapClearingResult<T> = Result<T, String>;

pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PROTOCOL_VERSION: &str =
    "nebula-private-cross-rollup-atomic-swap-clearing-v1";
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PQ_AUTH_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-cross-rollup-swap";
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_DEFAULT_LOCK_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_DEFAULT_CHALLENGE_BLOCKS: u64 = 18;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_BPS: u64 = 10_000;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_ROLLUPS: usize = 64;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_INTENTS: usize = 8_192;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_PAYOUTS: usize = 8_192;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_LOCKS: usize = 16_384;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_SOLVERS: usize = 1_024;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_REBATES: usize = 8_192;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_AUTHORIZATIONS: usize = 16_384;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_CHALLENGES: usize = 2_048;
pub const PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_BATCHES: usize = 2_048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupKind {
    NebulaL2,
    Optimistic,
    Zk,
    Appchain,
    Validium,
    Sovereign,
}

impl RollupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NebulaL2 => "nebula_l2",
            Self::Optimistic => "optimistic",
            Self::Zk => "zk",
            Self::Appchain => "appchain",
            Self::Validium => "validium",
            Self::Sovereign => "sovereign",
        }
    }

    pub fn finality_risk_bps(self) -> u64 {
        match self {
            Self::NebulaL2 => 250,
            Self::Zk => 700,
            Self::Optimistic => 1_400,
            Self::Appchain => 1_800,
            Self::Validium => 2_100,
            Self::Sovereign => 2_400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Encrypted,
    Matched,
    Locked,
    Settling,
    Settled,
    Expired,
    Challenged,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Matched => "matched",
            Self::Locked => "locked",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutStatus {
    Committed,
    Proved,
    Released,
    Reclaimed,
    Disputed,
}

impl PayoutStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Proved => "proved",
            Self::Released => "released",
            Self::Reclaimed => "reclaimed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockStatus {
    Pending,
    Active,
    Claimed,
    Refunded,
    Nullified,
    Challenged,
}

impl LockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Claimed => "claimed",
            Self::Refunded => "refunded",
            Self::Nullified => "nullified",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Open,
    Bonded,
    Reserved,
    Released,
    Slashed,
}

impl EscrowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bonded => "bonded",
            Self::Reserved => "reserved",
            Self::Released => "released",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Offered,
    Reserved,
    Earned,
    Paid,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Earned => "earned",
            Self::Paid => "paid",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationRole {
    Trader,
    Solver,
    Watcher,
    Sequencer,
    SettlementCommittee,
}

impl AuthorizationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trader => "trader",
            Self::Solver => "solver",
            Self::Watcher => "watcher",
            Self::Sequencer => "sequencer",
            Self::SettlementCommittee => "settlement_committee",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
    Resolved,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Attested,
    Executed,
    Reverted,
    Challenged,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Attested => "attested",
            Self::Executed => "executed",
            Self::Reverted => "reverted",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_authorization_suite: String,
    pub chain_id: String,
    pub min_solver_bond_units: u64,
    pub max_solver_fee_bps: u64,
    pub max_rebate_bps: u64,
    pub intent_ttl_blocks: u64,
    pub lock_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub require_monero_payout_commitment: bool,
    pub require_pq_authorization: bool,
    pub allow_low_fee_rebates: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PROTOCOL_VERSION
                .to_string(),
            hash_suite: PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_HASH_SUITE.to_string(),
            pq_authorization_suite: PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PQ_AUTH_SUITE
                .to_string(),
            chain_id: CHAIN_ID.to_string(),
            min_solver_bond_units: 250_000,
            max_solver_fee_bps: 75,
            max_rebate_bps: 250,
            intent_ttl_blocks: PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_DEFAULT_INTENT_TTL_BLOCKS,
            lock_ttl_blocks: PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_DEFAULT_LOCK_TTL_BLOCKS,
            challenge_window_blocks:
                PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_DEFAULT_CHALLENGE_BLOCKS,
            require_monero_payout_commitment: true,
            require_pq_authorization: true,
            allow_low_fee_rebates: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.protocol_version != PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PROTOCOL_VERSION {
            return Err("private cross-rollup atomic swap protocol version mismatch".to_string());
        }
        if self.hash_suite != PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_HASH_SUITE {
            return Err("private cross-rollup atomic swap hash suite mismatch".to_string());
        }
        if self.pq_authorization_suite != PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PQ_AUTH_SUITE {
            return Err("private cross-rollup atomic swap PQ suite mismatch".to_string());
        }
        if self.chain_id.is_empty() {
            return Err("private cross-rollup atomic swap chain id cannot be empty".to_string());
        }
        if self.max_solver_fee_bps > PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_BPS {
            return Err("private cross-rollup atomic swap solver fee exceeds max bps".to_string());
        }
        if self.max_rebate_bps > PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_BPS {
            return Err("private cross-rollup atomic swap rebate exceeds max bps".to_string());
        }
        if self.intent_ttl_blocks == 0 || self.lock_ttl_blocks == 0 {
            return Err("private cross-rollup atomic swap ttl blocks must be positive".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err(
                "private cross-rollup atomic swap challenge window must be positive".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_atomic_swap_clearing_config",
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_authorization_suite": self.pq_authorization_suite,
            "chain_id": self.chain_id,
            "min_solver_bond_units": self.min_solver_bond_units,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "lock_ttl_blocks": self.lock_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "require_monero_payout_commitment": self.require_monero_payout_commitment,
            "require_pq_authorization": self.require_pq_authorization,
            "allow_low_fee_rebates": self.allow_low_fee_rebates,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupEndpoint {
    pub rollup_id: String,
    pub label: String,
    pub kind: RollupKind,
    pub bridge_committee_root: String,
    pub htlc_contract_root: String,
    pub nullifier_registry_root: String,
    pub finality_blocks: u64,
    pub low_fee_lane_enabled: bool,
    pub active: bool,
}

impl RollupEndpoint {
    pub fn new(
        label: &str,
        kind: RollupKind,
        bridge_committee_root: &str,
        htlc_contract_root: &str,
        nullifier_registry_root: &str,
        finality_blocks: u64,
        low_fee_lane_enabled: bool,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<Self> {
        if label.is_empty()
            || bridge_committee_root.is_empty()
            || htlc_contract_root.is_empty()
            || nullifier_registry_root.is_empty()
        {
            return Err("rollup endpoint fields cannot be empty".to_string());
        }
        if finality_blocks == 0 {
            return Err("rollup endpoint finality blocks must be positive".to_string());
        }
        let rollup_id = private_cross_rollup_atomic_swap_clearing_id(
            "ROLLUP",
            &[
                label,
                kind.as_str(),
                htlc_contract_root,
                nullifier_registry_root,
            ],
        );
        Ok(Self {
            rollup_id,
            label: label.to_string(),
            kind,
            bridge_committee_root: bridge_committee_root.to_string(),
            htlc_contract_root: htlc_contract_root.to_string(),
            nullifier_registry_root: nullifier_registry_root.to_string(),
            finality_blocks,
            low_fee_lane_enabled,
            active: true,
        })
    }

    pub fn validate(&self) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.rollup_id.is_empty()
            || self.label.is_empty()
            || self.bridge_committee_root.is_empty()
            || self.htlc_contract_root.is_empty()
            || self.nullifier_registry_root.is_empty()
        {
            return Err("rollup endpoint identifiers cannot be empty".to_string());
        }
        if self.finality_blocks == 0 {
            return Err("rollup endpoint finality blocks must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_endpoint",
            "rollup_id": self.rollup_id,
            "label": self.label,
            "rollup_kind": self.kind.as_str(),
            "finality_risk_bps": self.kind.finality_risk_bps(),
            "bridge_committee_root": self.bridge_committee_root,
            "htlc_contract_root": self.htlc_contract_root,
            "nullifier_registry_root": self.nullifier_registry_root,
            "finality_blocks": self.finality_blocks,
            "low_fee_lane_enabled": self.low_fee_lane_enabled,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_atomic_swap_clearing_payload_root("ROLLUP", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSwapIntent {
    pub intent_id: String,
    pub trader_commitment: String,
    pub source_rollup_id: String,
    pub target_rollup_id: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_commitment: String,
    pub min_amount_out_commitment: String,
    pub encrypted_payload_root: String,
    pub route_hint_root: String,
    pub monero_payout_hint_root: String,
    pub htlc_hash_root: String,
    pub status: IntentStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl EncryptedSwapIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trader_commitment: &str,
        source_rollup_id: &str,
        target_rollup_id: &str,
        asset_in_commitment: &str,
        asset_out_commitment: &str,
        amount_in_commitment: &str,
        min_amount_out_commitment: &str,
        encrypted_payload_root: &str,
        route_hint_root: &str,
        monero_payout_hint_root: &str,
        htlc_hash_root: &str,
        submitted_at_height: u64,
        expires_at_height: u64,
        sequence: u64,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<Self> {
        if trader_commitment.is_empty()
            || source_rollup_id.is_empty()
            || target_rollup_id.is_empty()
            || asset_in_commitment.is_empty()
            || asset_out_commitment.is_empty()
            || amount_in_commitment.is_empty()
            || min_amount_out_commitment.is_empty()
            || encrypted_payload_root.is_empty()
            || route_hint_root.is_empty()
            || htlc_hash_root.is_empty()
        {
            return Err("encrypted swap intent fields cannot be empty".to_string());
        }
        if source_rollup_id == target_rollup_id {
            return Err("encrypted swap intent rollups must differ".to_string());
        }
        if expires_at_height <= submitted_at_height {
            return Err("encrypted swap intent expiry must be after submission".to_string());
        }
        let intent_id = private_cross_rollup_atomic_swap_clearing_id(
            "INTENT",
            &[
                trader_commitment,
                source_rollup_id,
                target_rollup_id,
                encrypted_payload_root,
                htlc_hash_root,
                &sequence.to_string(),
            ],
        );
        Ok(Self {
            intent_id,
            trader_commitment: trader_commitment.to_string(),
            source_rollup_id: source_rollup_id.to_string(),
            target_rollup_id: target_rollup_id.to_string(),
            asset_in_commitment: asset_in_commitment.to_string(),
            asset_out_commitment: asset_out_commitment.to_string(),
            amount_in_commitment: amount_in_commitment.to_string(),
            min_amount_out_commitment: min_amount_out_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            route_hint_root: route_hint_root.to_string(),
            monero_payout_hint_root: monero_payout_hint_root.to_string(),
            htlc_hash_root: htlc_hash_root.to_string(),
            status: IntentStatus::Encrypted,
            submitted_at_height,
            expires_at_height,
            sequence,
        })
    }

    pub fn validate(&self) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.intent_id.is_empty()
            || self.trader_commitment.is_empty()
            || self.source_rollup_id.is_empty()
            || self.target_rollup_id.is_empty()
            || self.asset_in_commitment.is_empty()
            || self.asset_out_commitment.is_empty()
            || self.amount_in_commitment.is_empty()
            || self.min_amount_out_commitment.is_empty()
            || self.encrypted_payload_root.is_empty()
            || self.route_hint_root.is_empty()
            || self.htlc_hash_root.is_empty()
        {
            return Err("encrypted swap intent identifiers cannot be empty".to_string());
        }
        if self.source_rollup_id == self.target_rollup_id {
            return Err("encrypted swap intent rollups must differ".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("encrypted swap intent expiry must be after submission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_swap_intent",
            "intent_id": self.intent_id,
            "trader_commitment": self.trader_commitment,
            "source_rollup_id": self.source_rollup_id,
            "target_rollup_id": self.target_rollup_id,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "min_amount_out_commitment": self.min_amount_out_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "route_hint_root": self.route_hint_root,
            "monero_payout_hint_root": self.monero_payout_hint_root,
            "htlc_hash_root": self.htlc_hash_root,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_atomic_swap_clearing_payload_root("INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPayoutCommitment {
    pub payout_id: String,
    pub intent_id: String,
    pub recipient_commitment: String,
    pub subaddress_commitment: String,
    pub amount_bucket_commitment: String,
    pub tx_key_commitment_root: String,
    pub output_commitment_root: String,
    pub view_tag_root: String,
    pub ring_member_root: String,
    pub unlock_height: u64,
    pub status: PayoutStatus,
}

impl MoneroPayoutCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        recipient_commitment: &str,
        subaddress_commitment: &str,
        amount_bucket_commitment: &str,
        tx_key_commitment_root: &str,
        output_commitment_root: &str,
        view_tag_root: &str,
        ring_member_root: &str,
        unlock_height: u64,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<Self> {
        if intent_id.is_empty()
            || recipient_commitment.is_empty()
            || subaddress_commitment.is_empty()
            || amount_bucket_commitment.is_empty()
            || tx_key_commitment_root.is_empty()
            || output_commitment_root.is_empty()
            || view_tag_root.is_empty()
            || ring_member_root.is_empty()
        {
            return Err("monero payout commitment fields cannot be empty".to_string());
        }
        let payout_id = private_cross_rollup_atomic_swap_clearing_id(
            "MONERO-PAYOUT",
            &[
                intent_id,
                recipient_commitment,
                subaddress_commitment,
                output_commitment_root,
                &unlock_height.to_string(),
            ],
        );
        Ok(Self {
            payout_id,
            intent_id: intent_id.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            subaddress_commitment: subaddress_commitment.to_string(),
            amount_bucket_commitment: amount_bucket_commitment.to_string(),
            tx_key_commitment_root: tx_key_commitment_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            view_tag_root: view_tag_root.to_string(),
            ring_member_root: ring_member_root.to_string(),
            unlock_height,
            status: PayoutStatus::Committed,
        })
    }

    pub fn validate(&self) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.payout_id.is_empty()
            || self.intent_id.is_empty()
            || self.recipient_commitment.is_empty()
            || self.subaddress_commitment.is_empty()
            || self.amount_bucket_commitment.is_empty()
            || self.tx_key_commitment_root.is_empty()
            || self.output_commitment_root.is_empty()
            || self.view_tag_root.is_empty()
            || self.ring_member_root.is_empty()
        {
            return Err("monero payout commitment identifiers cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_payout_commitment",
            "payout_id": self.payout_id,
            "intent_id": self.intent_id,
            "recipient_commitment": self.recipient_commitment,
            "subaddress_commitment": self.subaddress_commitment,
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "tx_key_commitment_root": self.tx_key_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "view_tag_root": self.view_tag_root,
            "ring_member_root": self.ring_member_root,
            "unlock_height": self.unlock_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_atomic_swap_clearing_payload_root(
            "MONERO-PAYOUT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupHtlcLock {
    pub lock_id: String,
    pub intent_id: String,
    pub rollup_id: String,
    pub htlc_commitment_root: String,
    pub nullifier_root: String,
    pub secret_hash_root: String,
    pub refund_commitment_root: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: LockStatus,
}

impl CrossRollupHtlcLock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        rollup_id: &str,
        htlc_commitment_root: &str,
        nullifier_root: &str,
        secret_hash_root: &str,
        refund_commitment_root: &str,
        asset_commitment: &str,
        amount_commitment: &str,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<Self> {
        if intent_id.is_empty()
            || rollup_id.is_empty()
            || htlc_commitment_root.is_empty()
            || nullifier_root.is_empty()
            || secret_hash_root.is_empty()
            || refund_commitment_root.is_empty()
            || asset_commitment.is_empty()
            || amount_commitment.is_empty()
        {
            return Err("cross-rollup htlc lock fields cannot be empty".to_string());
        }
        if expires_at_height <= opened_at_height {
            return Err("cross-rollup htlc lock expiry must be after opening".to_string());
        }
        let lock_id = private_cross_rollup_atomic_swap_clearing_id(
            "HTLC-LOCK",
            &[
                intent_id,
                rollup_id,
                htlc_commitment_root,
                nullifier_root,
                &opened_at_height.to_string(),
            ],
        );
        Ok(Self {
            lock_id,
            intent_id: intent_id.to_string(),
            rollup_id: rollup_id.to_string(),
            htlc_commitment_root: htlc_commitment_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            secret_hash_root: secret_hash_root.to_string(),
            refund_commitment_root: refund_commitment_root.to_string(),
            asset_commitment: asset_commitment.to_string(),
            amount_commitment: amount_commitment.to_string(),
            opened_at_height,
            expires_at_height,
            status: LockStatus::Pending,
        })
    }

    pub fn validate(&self) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.lock_id.is_empty()
            || self.intent_id.is_empty()
            || self.rollup_id.is_empty()
            || self.htlc_commitment_root.is_empty()
            || self.nullifier_root.is_empty()
            || self.secret_hash_root.is_empty()
            || self.refund_commitment_root.is_empty()
            || self.asset_commitment.is_empty()
            || self.amount_commitment.is_empty()
        {
            return Err("cross-rollup htlc lock identifiers cannot be empty".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("cross-rollup htlc lock expiry must be after opening".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_rollup_htlc_lock",
            "lock_id": self.lock_id,
            "intent_id": self.intent_id,
            "rollup_id": self.rollup_id,
            "htlc_commitment_root": self.htlc_commitment_root,
            "nullifier_root": self.nullifier_root,
            "secret_hash_root": self.secret_hash_root,
            "refund_commitment_root": self.refund_commitment_root,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_atomic_swap_clearing_payload_root("HTLC-LOCK", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverEscrow {
    pub solver_id: String,
    pub operator_commitment: String,
    pub pq_identity_root: String,
    pub bond_asset_id: String,
    pub bond_units: u64,
    pub reserved_units: u64,
    pub completed_volume_units: u64,
    pub slash_receipt_root: String,
    pub status: EscrowStatus,
    pub opened_at_height: u64,
}

impl SolverEscrow {
    pub fn new(
        operator_commitment: &str,
        pq_identity_root: &str,
        bond_asset_id: &str,
        bond_units: u64,
        opened_at_height: u64,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<Self> {
        if operator_commitment.is_empty() || pq_identity_root.is_empty() || bond_asset_id.is_empty()
        {
            return Err("solver escrow fields cannot be empty".to_string());
        }
        if bond_units == 0 {
            return Err("solver escrow bond must be positive".to_string());
        }
        let solver_id = private_cross_rollup_atomic_swap_clearing_id(
            "SOLVER",
            &[
                operator_commitment,
                pq_identity_root,
                bond_asset_id,
                &opened_at_height.to_string(),
            ],
        );
        Ok(Self {
            solver_id,
            operator_commitment: operator_commitment.to_string(),
            pq_identity_root: pq_identity_root.to_string(),
            bond_asset_id: bond_asset_id.to_string(),
            bond_units,
            reserved_units: 0,
            completed_volume_units: 0,
            slash_receipt_root: private_cross_rollup_atomic_swap_clearing_empty_root(
                "SOLVER-SLASH",
            ),
            status: EscrowStatus::Bonded,
            opened_at_height,
        })
    }

    pub fn validate(&self, config: &Config) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.solver_id.is_empty()
            || self.operator_commitment.is_empty()
            || self.pq_identity_root.is_empty()
            || self.bond_asset_id.is_empty()
            || self.slash_receipt_root.is_empty()
        {
            return Err("solver escrow identifiers cannot be empty".to_string());
        }
        if self.bond_units < config.min_solver_bond_units {
            return Err("solver escrow bond below configured minimum".to_string());
        }
        if self.reserved_units > self.bond_units {
            return Err("solver escrow reserved units exceed bond".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_escrow",
            "solver_id": self.solver_id,
            "operator_commitment": self.operator_commitment,
            "pq_identity_root": self.pq_identity_root,
            "bond_asset_id": self.bond_asset_id,
            "bond_units": self.bond_units,
            "reserved_units": self.reserved_units,
            "completed_volume_units": self.completed_volume_units,
            "slash_receipt_root": self.slash_receipt_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_atomic_swap_clearing_payload_root("SOLVER", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebateRoute {
    pub rebate_id: String,
    pub intent_id: String,
    pub solver_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub eligible_fee_units: u64,
    pub rebate_bps: u64,
    pub route_commitment_root: String,
    pub sponsor_commitment: String,
    pub status: RebateStatus,
    pub expires_at_height: u64,
}

impl LowFeeRebateRoute {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        solver_id: &str,
        lane_id: &str,
        fee_asset_id: &str,
        eligible_fee_units: u64,
        rebate_bps: u64,
        route_commitment_root: &str,
        sponsor_commitment: &str,
        expires_at_height: u64,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<Self> {
        if intent_id.is_empty()
            || solver_id.is_empty()
            || lane_id.is_empty()
            || fee_asset_id.is_empty()
            || route_commitment_root.is_empty()
            || sponsor_commitment.is_empty()
        {
            return Err("low-fee rebate route fields cannot be empty".to_string());
        }
        if eligible_fee_units == 0 {
            return Err("low-fee rebate route fee units must be positive".to_string());
        }
        if rebate_bps > PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_BPS {
            return Err("low-fee rebate route bps exceeds maximum".to_string());
        }
        let rebate_id = private_cross_rollup_atomic_swap_clearing_id(
            "REBATE",
            &[
                intent_id,
                solver_id,
                lane_id,
                fee_asset_id,
                route_commitment_root,
            ],
        );
        Ok(Self {
            rebate_id,
            intent_id: intent_id.to_string(),
            solver_id: solver_id.to_string(),
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            eligible_fee_units,
            rebate_bps,
            route_commitment_root: route_commitment_root.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            status: RebateStatus::Offered,
            expires_at_height,
        })
    }

    pub fn validate(&self, config: &Config) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.rebate_id.is_empty()
            || self.intent_id.is_empty()
            || self.solver_id.is_empty()
            || self.lane_id.is_empty()
            || self.fee_asset_id.is_empty()
            || self.route_commitment_root.is_empty()
            || self.sponsor_commitment.is_empty()
        {
            return Err("low-fee rebate route identifiers cannot be empty".to_string());
        }
        if self.eligible_fee_units == 0 {
            return Err("low-fee rebate route fee units must be positive".to_string());
        }
        if self.rebate_bps > config.max_rebate_bps {
            return Err("low-fee rebate route bps exceeds configured maximum".to_string());
        }
        if !config.allow_low_fee_rebates {
            return Err("low-fee rebates are disabled".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_rebate_route",
            "rebate_id": self.rebate_id,
            "intent_id": self.intent_id,
            "solver_id": self.solver_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "eligible_fee_units": self.eligible_fee_units,
            "rebate_bps": self.rebate_bps,
            "route_commitment_root": self.route_commitment_root,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_atomic_swap_clearing_payload_root("REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthorization {
    pub authorization_id: String,
    pub role: AuthorizationRole,
    pub subject_id: String,
    pub signer_commitment: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub key_epoch: u64,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub revoked: bool,
}

impl PqAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: AuthorizationRole,
        subject_id: &str,
        signer_commitment: &str,
        transcript_root: &str,
        signature_root: &str,
        key_epoch: u64,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<Self> {
        if subject_id.is_empty()
            || signer_commitment.is_empty()
            || transcript_root.is_empty()
            || signature_root.is_empty()
        {
            return Err("pq authorization fields cannot be empty".to_string());
        }
        if expires_at_height <= signed_at_height {
            return Err("pq authorization expiry must be after signature height".to_string());
        }
        let authorization_id = private_cross_rollup_atomic_swap_clearing_id(
            "PQ-AUTH",
            &[
                role.as_str(),
                subject_id,
                signer_commitment,
                transcript_root,
                signature_root,
                &key_epoch.to_string(),
            ],
        );
        Ok(Self {
            authorization_id,
            role,
            subject_id: subject_id.to_string(),
            signer_commitment: signer_commitment.to_string(),
            transcript_root: transcript_root.to_string(),
            signature_root: signature_root.to_string(),
            key_epoch,
            signed_at_height,
            expires_at_height,
            revoked: false,
        })
    }

    pub fn validate(&self) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.authorization_id.is_empty()
            || self.subject_id.is_empty()
            || self.signer_commitment.is_empty()
            || self.transcript_root.is_empty()
            || self.signature_root.is_empty()
        {
            return Err("pq authorization identifiers cannot be empty".to_string());
        }
        if self.expires_at_height <= self.signed_at_height {
            return Err("pq authorization expiry must be after signature height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_authorization",
            "authorization_id": self.authorization_id,
            "role": self.role.as_str(),
            "subject_id": self.subject_id,
            "signer_commitment": self.signer_commitment,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "key_epoch": self.key_epoch,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "revoked": self.revoked,
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_atomic_swap_clearing_payload_root("PQ-AUTH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeReceipt {
    pub challenge_id: String,
    pub target_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub challenged_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ChallengeStatus,
}

impl ChallengeReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        challenged_root: &str,
        bond_units: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<Self> {
        if target_id.is_empty()
            || challenger_commitment.is_empty()
            || evidence_root.is_empty()
            || challenged_root.is_empty()
        {
            return Err("challenge receipt fields cannot be empty".to_string());
        }
        if bond_units == 0 {
            return Err("challenge receipt bond must be positive".to_string());
        }
        if expires_at_height <= opened_at_height {
            return Err("challenge receipt expiry must be after opening".to_string());
        }
        let challenge_id = private_cross_rollup_atomic_swap_clearing_id(
            "CHALLENGE",
            &[
                target_id,
                challenger_commitment,
                evidence_root,
                challenged_root,
                &opened_at_height.to_string(),
            ],
        );
        Ok(Self {
            challenge_id,
            target_id: target_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            evidence_root: evidence_root.to_string(),
            challenged_root: challenged_root.to_string(),
            bond_units,
            opened_at_height,
            expires_at_height,
            status: ChallengeStatus::Open,
        })
    }

    pub fn validate(&self) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.challenge_id.is_empty()
            || self.target_id.is_empty()
            || self.challenger_commitment.is_empty()
            || self.evidence_root.is_empty()
            || self.challenged_root.is_empty()
        {
            return Err("challenge receipt identifiers cannot be empty".to_string());
        }
        if self.bond_units == 0 {
            return Err("challenge receipt bond must be positive".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("challenge receipt expiry must be after opening".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "challenge_receipt",
            "challenge_id": self.challenge_id,
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "challenged_root": self.challenged_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_atomic_swap_clearing_payload_root("CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub batch_index: u64,
    pub source_rollup_id: String,
    pub target_rollup_id: String,
    pub intent_root: String,
    pub lock_root: String,
    pub payout_root: String,
    pub rebate_root: String,
    pub authorization_root: String,
    pub solver_escrow_root: String,
    pub settlement_call_root: String,
    pub sequencer_commitment: String,
    pub status: BatchStatus,
    pub proposed_at_height: u64,
    pub execute_after_height: u64,
}

impl SettlementBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_index: u64,
        source_rollup_id: &str,
        target_rollup_id: &str,
        intent_root: &str,
        lock_root: &str,
        payout_root: &str,
        rebate_root: &str,
        authorization_root: &str,
        solver_escrow_root: &str,
        settlement_call_root: &str,
        sequencer_commitment: &str,
        proposed_at_height: u64,
        execute_after_height: u64,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<Self> {
        if source_rollup_id.is_empty()
            || target_rollup_id.is_empty()
            || intent_root.is_empty()
            || lock_root.is_empty()
            || payout_root.is_empty()
            || rebate_root.is_empty()
            || authorization_root.is_empty()
            || solver_escrow_root.is_empty()
            || settlement_call_root.is_empty()
            || sequencer_commitment.is_empty()
        {
            return Err("settlement batch fields cannot be empty".to_string());
        }
        if source_rollup_id == target_rollup_id {
            return Err("settlement batch rollups must differ".to_string());
        }
        if execute_after_height < proposed_at_height {
            return Err("settlement batch execution height cannot precede proposal".to_string());
        }
        let batch_id = private_cross_rollup_atomic_swap_clearing_id(
            "BATCH",
            &[
                source_rollup_id,
                target_rollup_id,
                intent_root,
                lock_root,
                &batch_index.to_string(),
            ],
        );
        Ok(Self {
            batch_id,
            batch_index,
            source_rollup_id: source_rollup_id.to_string(),
            target_rollup_id: target_rollup_id.to_string(),
            intent_root: intent_root.to_string(),
            lock_root: lock_root.to_string(),
            payout_root: payout_root.to_string(),
            rebate_root: rebate_root.to_string(),
            authorization_root: authorization_root.to_string(),
            solver_escrow_root: solver_escrow_root.to_string(),
            settlement_call_root: settlement_call_root.to_string(),
            sequencer_commitment: sequencer_commitment.to_string(),
            status: BatchStatus::Proposed,
            proposed_at_height,
            execute_after_height,
        })
    }

    pub fn validate(&self) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if self.batch_id.is_empty()
            || self.source_rollup_id.is_empty()
            || self.target_rollup_id.is_empty()
            || self.intent_root.is_empty()
            || self.lock_root.is_empty()
            || self.payout_root.is_empty()
            || self.rebate_root.is_empty()
            || self.authorization_root.is_empty()
            || self.solver_escrow_root.is_empty()
            || self.settlement_call_root.is_empty()
            || self.sequencer_commitment.is_empty()
        {
            return Err("settlement batch identifiers cannot be empty".to_string());
        }
        if self.source_rollup_id == self.target_rollup_id {
            return Err("settlement batch rollups must differ".to_string());
        }
        if self.execute_after_height < self.proposed_at_height {
            return Err("settlement batch execution height cannot precede proposal".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_batch",
            "batch_id": self.batch_id,
            "batch_index": self.batch_index,
            "source_rollup_id": self.source_rollup_id,
            "target_rollup_id": self.target_rollup_id,
            "intent_root": self.intent_root,
            "lock_root": self.lock_root,
            "payout_root": self.payout_root,
            "rebate_root": self.rebate_root,
            "authorization_root": self.authorization_root,
            "solver_escrow_root": self.solver_escrow_root,
            "settlement_call_root": self.settlement_call_root,
            "sequencer_commitment": self.sequencer_commitment,
            "status": self.status.as_str(),
            "proposed_at_height": self.proposed_at_height,
            "execute_after_height": self.execute_after_height,
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_atomic_swap_clearing_payload_root("BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub rollup_root: String,
    pub encrypted_intent_root: String,
    pub monero_payout_root: String,
    pub cross_rollup_htlc_root: String,
    pub nullifier_root: String,
    pub solver_escrow_root: String,
    pub low_fee_rebate_root: String,
    pub pq_authorization_root: String,
    pub challenge_receipt_root: String,
    pub settlement_batch_root: String,
    pub active_intent_root: String,
    pub open_challenge_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_atomic_swap_clearing_roots",
            "rollup_root": self.rollup_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "monero_payout_root": self.monero_payout_root,
            "cross_rollup_htlc_root": self.cross_rollup_htlc_root,
            "nullifier_root": self.nullifier_root,
            "solver_escrow_root": self.solver_escrow_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "pq_authorization_root": self.pq_authorization_root,
            "challenge_receipt_root": self.challenge_receipt_root,
            "settlement_batch_root": self.settlement_batch_root,
            "active_intent_root": self.active_intent_root,
            "open_challenge_root": self.open_challenge_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub rollup_count: u64,
    pub encrypted_intent_count: u64,
    pub active_intent_count: u64,
    pub monero_payout_count: u64,
    pub htlc_lock_count: u64,
    pub nullifier_count: u64,
    pub solver_count: u64,
    pub low_fee_rebate_count: u64,
    pub pq_authorization_count: u64,
    pub open_challenge_count: u64,
    pub challenge_receipt_count: u64,
    pub settlement_batch_count: u64,
    pub settled_batch_count: u64,
    pub total_solver_bond_units: u64,
    pub total_rebate_fee_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_atomic_swap_clearing_counters",
            "rollup_count": self.rollup_count,
            "encrypted_intent_count": self.encrypted_intent_count,
            "active_intent_count": self.active_intent_count,
            "monero_payout_count": self.monero_payout_count,
            "htlc_lock_count": self.htlc_lock_count,
            "nullifier_count": self.nullifier_count,
            "solver_count": self.solver_count,
            "low_fee_rebate_count": self.low_fee_rebate_count,
            "pq_authorization_count": self.pq_authorization_count,
            "open_challenge_count": self.open_challenge_count,
            "challenge_receipt_count": self.challenge_receipt_count,
            "settlement_batch_count": self.settlement_batch_count,
            "settled_batch_count": self.settled_batch_count,
            "total_solver_bond_units": self.total_solver_bond_units,
            "total_rebate_fee_units": self.total_rebate_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub rollups: BTreeMap<String, RollupEndpoint>,
    pub encrypted_intents: BTreeMap<String, EncryptedSwapIntent>,
    pub monero_payouts: BTreeMap<String, MoneroPayoutCommitment>,
    pub htlc_locks: BTreeMap<String, CrossRollupHtlcLock>,
    pub nullifier_roots: BTreeSet<String>,
    pub solver_escrows: BTreeMap<String, SolverEscrow>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebateRoute>,
    pub pq_authorizations: BTreeMap<String, PqAuthorization>,
    pub challenge_receipts: BTreeMap<String, ChallengeReceipt>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::default();
        let height = 1_000;
        let rollup_a = match RollupEndpoint::new(
            "nebula-private-rollup-a",
            RollupKind::NebulaL2,
            &private_cross_rollup_atomic_swap_clearing_commitment("committee-a", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("htlc-a", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("nullifier-a", 1),
            2,
            true,
        ) {
            Ok(rollup) => rollup,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_rollup(),
        };
        let rollup_b = match RollupEndpoint::new(
            "privacy-zk-rollup-b",
            RollupKind::Zk,
            &private_cross_rollup_atomic_swap_clearing_commitment("committee-b", 2),
            &private_cross_rollup_atomic_swap_clearing_commitment("htlc-b", 2),
            &private_cross_rollup_atomic_swap_clearing_commitment("nullifier-b", 2),
            6,
            true,
        ) {
            Ok(rollup) => rollup,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_rollup(),
        };

        let mut rollups = BTreeMap::new();
        rollups.insert(rollup_a.rollup_id.clone(), rollup_a.clone());
        rollups.insert(rollup_b.rollup_id.clone(), rollup_b.clone());

        let intent = match EncryptedSwapIntent::new(
            &private_cross_rollup_atomic_swap_clearing_commitment("trader", 7),
            &rollup_a.rollup_id,
            &rollup_b.rollup_id,
            &private_cross_rollup_atomic_swap_clearing_commitment("asset-in", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("asset-out", 2),
            &private_cross_rollup_atomic_swap_clearing_commitment("amount-in", 100),
            &private_cross_rollup_atomic_swap_clearing_commitment("min-out", 97),
            &private_cross_rollup_atomic_swap_clearing_commitment("encrypted-payload", 3),
            &private_cross_rollup_atomic_swap_clearing_commitment("route-hint", 4),
            &private_cross_rollup_atomic_swap_clearing_commitment("monero-hint", 5),
            &private_cross_rollup_atomic_swap_clearing_commitment("hashlock", 6),
            height,
            height + config.intent_ttl_blocks,
            1,
        ) {
            Ok(intent) => intent,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_intent(),
        };

        let payout = match MoneroPayoutCommitment::new(
            &intent.intent_id,
            &private_cross_rollup_atomic_swap_clearing_commitment("xmr-recipient", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("xmr-subaddress", 2),
            &private_cross_rollup_atomic_swap_clearing_commitment("xmr-amount-bucket", 3),
            &private_cross_rollup_atomic_swap_clearing_commitment("xmr-tx-key", 4),
            &private_cross_rollup_atomic_swap_clearing_commitment("xmr-output", 5),
            &private_cross_rollup_atomic_swap_clearing_commitment("xmr-view-tag", 6),
            &private_cross_rollup_atomic_swap_clearing_commitment("xmr-ring", 7),
            height + 20,
        ) {
            Ok(payout) => payout,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_payout(),
        };

        let source_lock = match CrossRollupHtlcLock::new(
            &intent.intent_id,
            &rollup_a.rollup_id,
            &private_cross_rollup_atomic_swap_clearing_commitment("source-htlc", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("source-nullifier", 2),
            &intent.htlc_hash_root,
            &private_cross_rollup_atomic_swap_clearing_commitment("source-refund", 3),
            &intent.asset_in_commitment,
            &intent.amount_in_commitment,
            height + 1,
            height + config.lock_ttl_blocks,
        ) {
            Ok(lock) => lock,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_lock(),
        };

        let target_lock = match CrossRollupHtlcLock::new(
            &intent.intent_id,
            &rollup_b.rollup_id,
            &private_cross_rollup_atomic_swap_clearing_commitment("target-htlc", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("target-nullifier", 2),
            &intent.htlc_hash_root,
            &private_cross_rollup_atomic_swap_clearing_commitment("target-refund", 3),
            &intent.asset_out_commitment,
            &intent.min_amount_out_commitment,
            height + 2,
            height + config.lock_ttl_blocks + rollup_b.finality_blocks,
        ) {
            Ok(lock) => lock,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_lock(),
        };

        let solver = match SolverEscrow::new(
            &private_cross_rollup_atomic_swap_clearing_commitment("solver-operator", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("solver-pq", 2),
            "NEBULA",
            config.min_solver_bond_units * 2,
            height,
        ) {
            Ok(solver) => solver,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_solver(),
        };

        let rebate = match LowFeeRebateRoute::new(
            &intent.intent_id,
            &solver.solver_id,
            "low-fee-lane-a-b",
            "NEBULA",
            1_800,
            125,
            &private_cross_rollup_atomic_swap_clearing_commitment("rebate-route", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("rebate-sponsor", 2),
            height + config.intent_ttl_blocks,
        ) {
            Ok(rebate) => rebate,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_rebate(),
        };

        let auth = match PqAuthorization::new(
            AuthorizationRole::Solver,
            &solver.solver_id,
            &solver.operator_commitment,
            &private_cross_rollup_atomic_swap_clearing_commitment("auth-transcript", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("auth-signature", 2),
            1,
            height,
            height + 256,
        ) {
            Ok(auth) => auth,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_authorization(),
        };

        let challenge = match ChallengeReceipt::new(
            &intent.intent_id,
            &private_cross_rollup_atomic_swap_clearing_commitment("watcher", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("evidence", 2),
            &intent.root(),
            10_000,
            height + 3,
            height + 3 + config.challenge_window_blocks,
        ) {
            Ok(challenge) => challenge,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_challenge(),
        };

        let batch = match SettlementBatch::new(
            1,
            &rollup_a.rollup_id,
            &rollup_b.rollup_id,
            &intent.root(),
            &merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-DEVNET-LOCKS",
                &[source_lock.public_record(), target_lock.public_record()],
            ),
            &payout.root(),
            &rebate.root(),
            &auth.root(),
            &solver.root(),
            &private_cross_rollup_atomic_swap_clearing_commitment("settlement-call", 1),
            &private_cross_rollup_atomic_swap_clearing_commitment("sequencer", 1),
            height + 4,
            height + 6,
        ) {
            Ok(batch) => batch,
            Err(_) => private_cross_rollup_atomic_swap_clearing_fallback_batch(),
        };

        let mut encrypted_intents = BTreeMap::new();
        encrypted_intents.insert(intent.intent_id.clone(), intent);
        let mut monero_payouts = BTreeMap::new();
        monero_payouts.insert(payout.payout_id.clone(), payout);
        let mut htlc_locks = BTreeMap::new();
        htlc_locks.insert(source_lock.lock_id.clone(), source_lock.clone());
        htlc_locks.insert(target_lock.lock_id.clone(), target_lock.clone());
        let mut nullifier_roots = BTreeSet::new();
        nullifier_roots.insert(source_lock.nullifier_root);
        nullifier_roots.insert(target_lock.nullifier_root);
        let mut solver_escrows = BTreeMap::new();
        solver_escrows.insert(solver.solver_id.clone(), solver);
        let mut low_fee_rebates = BTreeMap::new();
        low_fee_rebates.insert(rebate.rebate_id.clone(), rebate);
        let mut pq_authorizations = BTreeMap::new();
        pq_authorizations.insert(auth.authorization_id.clone(), auth);
        let mut challenge_receipts = BTreeMap::new();
        challenge_receipts.insert(challenge.challenge_id.clone(), challenge);
        let mut settlement_batches = BTreeMap::new();
        settlement_batches.insert(batch.batch_id.clone(), batch);

        Self {
            height,
            config,
            rollups,
            encrypted_intents,
            monero_payouts,
            htlc_locks,
            nullifier_roots,
            solver_escrows,
            low_fee_rebates,
            pq_authorizations,
            challenge_receipts,
            settlement_batches,
        }
    }

    pub fn validate(&self) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        self.config.validate()?;
        private_cross_rollup_atomic_swap_clearing_check_len(
            self.rollups.len(),
            PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_ROLLUPS,
            "rollups",
        )?;
        private_cross_rollup_atomic_swap_clearing_check_len(
            self.encrypted_intents.len(),
            PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_INTENTS,
            "encrypted intents",
        )?;
        private_cross_rollup_atomic_swap_clearing_check_len(
            self.monero_payouts.len(),
            PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_PAYOUTS,
            "monero payouts",
        )?;
        private_cross_rollup_atomic_swap_clearing_check_len(
            self.htlc_locks.len(),
            PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_LOCKS,
            "htlc locks",
        )?;
        private_cross_rollup_atomic_swap_clearing_check_len(
            self.solver_escrows.len(),
            PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_SOLVERS,
            "solver escrows",
        )?;
        private_cross_rollup_atomic_swap_clearing_check_len(
            self.low_fee_rebates.len(),
            PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_REBATES,
            "low-fee rebates",
        )?;
        private_cross_rollup_atomic_swap_clearing_check_len(
            self.pq_authorizations.len(),
            PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_AUTHORIZATIONS,
            "pq authorizations",
        )?;
        private_cross_rollup_atomic_swap_clearing_check_len(
            self.challenge_receipts.len(),
            PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_CHALLENGES,
            "challenge receipts",
        )?;
        private_cross_rollup_atomic_swap_clearing_check_len(
            self.settlement_batches.len(),
            PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_MAX_BATCHES,
            "settlement batches",
        )?;

        for (key, rollup) in &self.rollups {
            if key != &rollup.rollup_id {
                return Err("rollup map key mismatch".to_string());
            }
            rollup.validate()?;
        }
        for (key, intent) in &self.encrypted_intents {
            if key != &intent.intent_id {
                return Err("encrypted intent map key mismatch".to_string());
            }
            intent.validate()?;
            if !self.rollups.contains_key(&intent.source_rollup_id)
                || !self.rollups.contains_key(&intent.target_rollup_id)
            {
                return Err("encrypted intent references unknown rollup".to_string());
            }
        }
        for (key, payout) in &self.monero_payouts {
            if key != &payout.payout_id {
                return Err("monero payout map key mismatch".to_string());
            }
            payout.validate()?;
            if self.config.require_monero_payout_commitment
                && !self.encrypted_intents.contains_key(&payout.intent_id)
            {
                return Err("monero payout references unknown intent".to_string());
            }
        }
        for (key, lock) in &self.htlc_locks {
            if key != &lock.lock_id {
                return Err("htlc lock map key mismatch".to_string());
            }
            lock.validate()?;
            if !self.encrypted_intents.contains_key(&lock.intent_id) {
                return Err("htlc lock references unknown intent".to_string());
            }
            if !self.rollups.contains_key(&lock.rollup_id) {
                return Err("htlc lock references unknown rollup".to_string());
            }
            if !self.nullifier_roots.contains(&lock.nullifier_root) {
                return Err("htlc lock nullifier is absent from nullifier set".to_string());
            }
        }
        for (key, solver) in &self.solver_escrows {
            if key != &solver.solver_id {
                return Err("solver escrow map key mismatch".to_string());
            }
            solver.validate(&self.config)?;
        }
        for (key, rebate) in &self.low_fee_rebates {
            if key != &rebate.rebate_id {
                return Err("low-fee rebate map key mismatch".to_string());
            }
            rebate.validate(&self.config)?;
            if !self.encrypted_intents.contains_key(&rebate.intent_id) {
                return Err("low-fee rebate references unknown intent".to_string());
            }
            if !self.solver_escrows.contains_key(&rebate.solver_id) {
                return Err("low-fee rebate references unknown solver".to_string());
            }
        }
        for (key, authorization) in &self.pq_authorizations {
            if key != &authorization.authorization_id {
                return Err("pq authorization map key mismatch".to_string());
            }
            authorization.validate()?;
            if self.config.require_pq_authorization && authorization.revoked {
                return Err("required pq authorization cannot be revoked".to_string());
            }
        }
        for (key, challenge) in &self.challenge_receipts {
            if key != &challenge.challenge_id {
                return Err("challenge receipt map key mismatch".to_string());
            }
            challenge.validate()?;
        }
        for (key, batch) in &self.settlement_batches {
            if key != &batch.batch_id {
                return Err("settlement batch map key mismatch".to_string());
            }
            batch.validate()?;
            if !self.rollups.contains_key(&batch.source_rollup_id)
                || !self.rollups.contains_key(&batch.target_rollup_id)
            {
                return Err("settlement batch references unknown rollup".to_string());
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        if height < self.height {
            return Err("private cross-rollup atomic swap height cannot decrease".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn update_height(
        &mut self,
        next_height: u64,
    ) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
        self.set_height(next_height)
    }

    pub fn roots(&self) -> Roots {
        let rollup_leaves = self
            .rollups
            .values()
            .map(RollupEndpoint::public_record)
            .collect::<Vec<_>>();
        let intent_leaves = self
            .encrypted_intents
            .values()
            .map(EncryptedSwapIntent::public_record)
            .collect::<Vec<_>>();
        let payout_leaves = self
            .monero_payouts
            .values()
            .map(MoneroPayoutCommitment::public_record)
            .collect::<Vec<_>>();
        let lock_leaves = self
            .htlc_locks
            .values()
            .map(CrossRollupHtlcLock::public_record)
            .collect::<Vec<_>>();
        let nullifier_leaves = self
            .nullifier_roots
            .iter()
            .map(|root| json!({"kind": "nullifier_root", "root": root}))
            .collect::<Vec<_>>();
        let solver_leaves = self
            .solver_escrows
            .values()
            .map(SolverEscrow::public_record)
            .collect::<Vec<_>>();
        let rebate_leaves = self
            .low_fee_rebates
            .values()
            .map(LowFeeRebateRoute::public_record)
            .collect::<Vec<_>>();
        let authorization_leaves = self
            .pq_authorizations
            .values()
            .map(PqAuthorization::public_record)
            .collect::<Vec<_>>();
        let challenge_leaves = self
            .challenge_receipts
            .values()
            .map(ChallengeReceipt::public_record)
            .collect::<Vec<_>>();
        let batch_leaves = self
            .settlement_batches
            .values()
            .map(SettlementBatch::public_record)
            .collect::<Vec<_>>();
        let active_intent_leaves = self
            .encrypted_intents
            .values()
            .filter(|intent| {
                matches!(
                    intent.status,
                    IntentStatus::Encrypted
                        | IntentStatus::Matched
                        | IntentStatus::Locked
                        | IntentStatus::Settling
                )
            })
            .map(EncryptedSwapIntent::public_record)
            .collect::<Vec<_>>();
        let open_challenge_leaves = self
            .challenge_receipts
            .values()
            .filter(|challenge| challenge.status == ChallengeStatus::Open)
            .map(ChallengeReceipt::public_record)
            .collect::<Vec<_>>();

        Roots {
            rollup_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-ROLLUPS",
                &rollup_leaves,
            ),
            encrypted_intent_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-INTENTS",
                &intent_leaves,
            ),
            monero_payout_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-MONERO-PAYOUTS",
                &payout_leaves,
            ),
            cross_rollup_htlc_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-HTLC-LOCKS",
                &lock_leaves,
            ),
            nullifier_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-NULLIFIERS",
                &nullifier_leaves,
            ),
            solver_escrow_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-SOLVERS",
                &solver_leaves,
            ),
            low_fee_rebate_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-REBATES",
                &rebate_leaves,
            ),
            pq_authorization_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-PQ-AUTHORIZATIONS",
                &authorization_leaves,
            ),
            challenge_receipt_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-CHALLENGES",
                &challenge_leaves,
            ),
            settlement_batch_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-BATCHES",
                &batch_leaves,
            ),
            active_intent_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-ACTIVE-INTENTS",
                &active_intent_leaves,
            ),
            open_challenge_root: merkle_root(
                "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-OPEN-CHALLENGES",
                &open_challenge_leaves,
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            rollup_count: self.rollups.len() as u64,
            encrypted_intent_count: self.encrypted_intents.len() as u64,
            active_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| {
                    matches!(
                        intent.status,
                        IntentStatus::Encrypted
                            | IntentStatus::Matched
                            | IntentStatus::Locked
                            | IntentStatus::Settling
                    )
                })
                .count() as u64,
            monero_payout_count: self.monero_payouts.len() as u64,
            htlc_lock_count: self.htlc_locks.len() as u64,
            nullifier_count: self.nullifier_roots.len() as u64,
            solver_count: self.solver_escrows.len() as u64,
            low_fee_rebate_count: self.low_fee_rebates.len() as u64,
            pq_authorization_count: self.pq_authorizations.len() as u64,
            open_challenge_count: self
                .challenge_receipts
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count() as u64,
            challenge_receipt_count: self.challenge_receipts.len() as u64,
            settlement_batch_count: self.settlement_batches.len() as u64,
            settled_batch_count: self
                .settlement_batches
                .values()
                .filter(|batch| batch.status == BatchStatus::Executed)
                .count() as u64,
            total_solver_bond_units: self
                .solver_escrows
                .values()
                .map(|solver| solver.bond_units)
                .sum(),
            total_rebate_fee_units: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.eligible_fee_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let state_root = root_from_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_cross_rollup_atomic_swap_clearing_state",
            "protocol_version": PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "rollups": self.rollups.iter().map(|(key, value)| {
                json!({"rollup_id": key, "record": value.public_record()})
            }).collect::<Vec<_>>(),
            "encrypted_intents": self.encrypted_intents.iter().map(|(key, value)| {
                json!({"intent_id": key, "record": value.public_record()})
            }).collect::<Vec<_>>(),
            "monero_payouts": self.monero_payouts.iter().map(|(key, value)| {
                json!({"payout_id": key, "record": value.public_record()})
            }).collect::<Vec<_>>(),
            "htlc_locks": self.htlc_locks.iter().map(|(key, value)| {
                json!({"lock_id": key, "record": value.public_record()})
            }).collect::<Vec<_>>(),
            "nullifier_roots": self.nullifier_roots.iter().map(|root| {
                json!({"root": root})
            }).collect::<Vec<_>>(),
            "solver_escrows": self.solver_escrows.iter().map(|(key, value)| {
                json!({"solver_id": key, "record": value.public_record()})
            }).collect::<Vec<_>>(),
            "low_fee_rebates": self.low_fee_rebates.iter().map(|(key, value)| {
                json!({"rebate_id": key, "record": value.public_record()})
            }).collect::<Vec<_>>(),
            "pq_authorizations": self.pq_authorizations.iter().map(|(key, value)| {
                json!({"authorization_id": key, "record": value.public_record()})
            }).collect::<Vec<_>>(),
            "challenge_receipts": self.challenge_receipts.iter().map(|(key, value)| {
                json!({"challenge_id": key, "record": value.public_record()})
            }).collect::<Vec<_>>(),
            "settlement_batches": self.settlement_batches.iter().map(|(key, value)| {
                json!({"batch_id": key, "record": value.public_record()})
            }).collect::<Vec<_>>(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> State {
    State::devnet()
}

fn private_cross_rollup_atomic_swap_clearing_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn private_cross_rollup_atomic_swap_clearing_empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-{domain}-EMPTY"),
        &[],
    )
}

fn private_cross_rollup_atomic_swap_clearing_id(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .enumerate()
        .map(|(index, value)| json!({"index": index as u64, "value": value}))
        .collect::<Vec<_>>();
    let part_root = merkle_root(
        &format!("PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-{domain}-ID-PARTS"),
        &leaves,
    );
    domain_hash(
        &format!("PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-{domain}-ID"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_CROSS_ROLLUP_ATOMIC_SWAP_CLEARING_PROTOCOL_VERSION),
            HashPart::Str(&part_root),
        ],
        32,
    )
}

fn private_cross_rollup_atomic_swap_clearing_commitment(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-CROSS-ROLLUP-ATOMIC-SWAP-CLEARING-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn private_cross_rollup_atomic_swap_clearing_check_len(
    actual: usize,
    max: usize,
    label: &str,
) -> PrivateCrossRollupAtomicSwapClearingResult<()> {
    if actual > max {
        return Err(format!(
            "private cross-rollup atomic swap {label} exceeds max"
        ));
    }
    Ok(())
}

fn private_cross_rollup_atomic_swap_clearing_fallback_rollup() -> RollupEndpoint {
    RollupEndpoint {
        rollup_id: private_cross_rollup_atomic_swap_clearing_id("ROLLUP-FALLBACK", &["rollup"]),
        label: "fallback-rollup".to_string(),
        kind: RollupKind::NebulaL2,
        bridge_committee_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-committee",
            1,
        ),
        htlc_contract_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-htlc",
            1,
        ),
        nullifier_registry_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-nullifier",
            1,
        ),
        finality_blocks: 1,
        low_fee_lane_enabled: true,
        active: true,
    }
}

fn private_cross_rollup_atomic_swap_clearing_fallback_intent() -> EncryptedSwapIntent {
    EncryptedSwapIntent {
        intent_id: private_cross_rollup_atomic_swap_clearing_id("INTENT-FALLBACK", &["intent"]),
        trader_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-trader",
            1,
        ),
        source_rollup_id: private_cross_rollup_atomic_swap_clearing_id("ROLLUP-FALLBACK", &["a"]),
        target_rollup_id: private_cross_rollup_atomic_swap_clearing_id("ROLLUP-FALLBACK", &["b"]),
        asset_in_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-asset-in",
            1,
        ),
        asset_out_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-asset-out",
            1,
        ),
        amount_in_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-amount-in",
            1,
        ),
        min_amount_out_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-min-out",
            1,
        ),
        encrypted_payload_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-payload",
            1,
        ),
        route_hint_root: private_cross_rollup_atomic_swap_clearing_commitment("fallback-route", 1),
        monero_payout_hint_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-monero",
            1,
        ),
        htlc_hash_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-hashlock",
            1,
        ),
        status: IntentStatus::Encrypted,
        submitted_at_height: 1,
        expires_at_height: 2,
        sequence: 1,
    }
}

fn private_cross_rollup_atomic_swap_clearing_fallback_payout() -> MoneroPayoutCommitment {
    MoneroPayoutCommitment {
        payout_id: private_cross_rollup_atomic_swap_clearing_id("PAYOUT-FALLBACK", &["payout"]),
        intent_id: private_cross_rollup_atomic_swap_clearing_id("INTENT-FALLBACK", &["intent"]),
        recipient_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-recipient",
            1,
        ),
        subaddress_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-subaddress",
            1,
        ),
        amount_bucket_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-amount-bucket",
            1,
        ),
        tx_key_commitment_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-tx-key",
            1,
        ),
        output_commitment_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-output",
            1,
        ),
        view_tag_root: private_cross_rollup_atomic_swap_clearing_commitment("fallback-view-tag", 1),
        ring_member_root: private_cross_rollup_atomic_swap_clearing_commitment("fallback-ring", 1),
        unlock_height: 2,
        status: PayoutStatus::Committed,
    }
}

fn private_cross_rollup_atomic_swap_clearing_fallback_lock() -> CrossRollupHtlcLock {
    CrossRollupHtlcLock {
        lock_id: private_cross_rollup_atomic_swap_clearing_id("LOCK-FALLBACK", &["lock"]),
        intent_id: private_cross_rollup_atomic_swap_clearing_id("INTENT-FALLBACK", &["intent"]),
        rollup_id: private_cross_rollup_atomic_swap_clearing_id("ROLLUP-FALLBACK", &["rollup"]),
        htlc_commitment_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-lock",
            1,
        ),
        nullifier_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-nullifier",
            1,
        ),
        secret_hash_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-secret",
            1,
        ),
        refund_commitment_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-refund",
            1,
        ),
        asset_commitment: private_cross_rollup_atomic_swap_clearing_commitment("fallback-asset", 1),
        amount_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-amount",
            1,
        ),
        opened_at_height: 1,
        expires_at_height: 2,
        status: LockStatus::Pending,
    }
}

fn private_cross_rollup_atomic_swap_clearing_fallback_solver() -> SolverEscrow {
    SolverEscrow {
        solver_id: private_cross_rollup_atomic_swap_clearing_id("SOLVER-FALLBACK", &["solver"]),
        operator_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-solver",
            1,
        ),
        pq_identity_root: private_cross_rollup_atomic_swap_clearing_commitment("fallback-pq", 1),
        bond_asset_id: "NEBULA".to_string(),
        bond_units: 250_000,
        reserved_units: 0,
        completed_volume_units: 0,
        slash_receipt_root: private_cross_rollup_atomic_swap_clearing_empty_root("FALLBACK-SLASH"),
        status: EscrowStatus::Bonded,
        opened_at_height: 1,
    }
}

fn private_cross_rollup_atomic_swap_clearing_fallback_rebate() -> LowFeeRebateRoute {
    LowFeeRebateRoute {
        rebate_id: private_cross_rollup_atomic_swap_clearing_id("REBATE-FALLBACK", &["rebate"]),
        intent_id: private_cross_rollup_atomic_swap_clearing_id("INTENT-FALLBACK", &["intent"]),
        solver_id: private_cross_rollup_atomic_swap_clearing_id("SOLVER-FALLBACK", &["solver"]),
        lane_id: "fallback-lane".to_string(),
        fee_asset_id: "NEBULA".to_string(),
        eligible_fee_units: 1,
        rebate_bps: 1,
        route_commitment_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-rebate-route",
            1,
        ),
        sponsor_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-sponsor",
            1,
        ),
        status: RebateStatus::Offered,
        expires_at_height: 2,
    }
}

fn private_cross_rollup_atomic_swap_clearing_fallback_authorization() -> PqAuthorization {
    PqAuthorization {
        authorization_id: private_cross_rollup_atomic_swap_clearing_id("AUTH-FALLBACK", &["auth"]),
        role: AuthorizationRole::Solver,
        subject_id: private_cross_rollup_atomic_swap_clearing_id("SOLVER-FALLBACK", &["solver"]),
        signer_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-signer",
            1,
        ),
        transcript_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-transcript",
            1,
        ),
        signature_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-signature",
            1,
        ),
        key_epoch: 1,
        signed_at_height: 1,
        expires_at_height: 2,
        revoked: false,
    }
}

fn private_cross_rollup_atomic_swap_clearing_fallback_challenge() -> ChallengeReceipt {
    ChallengeReceipt {
        challenge_id: private_cross_rollup_atomic_swap_clearing_id(
            "CHALLENGE-FALLBACK",
            &["challenge"],
        ),
        target_id: private_cross_rollup_atomic_swap_clearing_id("INTENT-FALLBACK", &["intent"]),
        challenger_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-challenger",
            1,
        ),
        evidence_root: private_cross_rollup_atomic_swap_clearing_commitment("fallback-evidence", 1),
        challenged_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-challenged",
            1,
        ),
        bond_units: 1,
        opened_at_height: 1,
        expires_at_height: 2,
        status: ChallengeStatus::Open,
    }
}

fn private_cross_rollup_atomic_swap_clearing_fallback_batch() -> SettlementBatch {
    SettlementBatch {
        batch_id: private_cross_rollup_atomic_swap_clearing_id("BATCH-FALLBACK", &["batch"]),
        batch_index: 1,
        source_rollup_id: private_cross_rollup_atomic_swap_clearing_id("ROLLUP-FALLBACK", &["a"]),
        target_rollup_id: private_cross_rollup_atomic_swap_clearing_id("ROLLUP-FALLBACK", &["b"]),
        intent_root: private_cross_rollup_atomic_swap_clearing_empty_root("FALLBACK-INTENT"),
        lock_root: private_cross_rollup_atomic_swap_clearing_empty_root("FALLBACK-LOCK"),
        payout_root: private_cross_rollup_atomic_swap_clearing_empty_root("FALLBACK-PAYOUT"),
        rebate_root: private_cross_rollup_atomic_swap_clearing_empty_root("FALLBACK-REBATE"),
        authorization_root: private_cross_rollup_atomic_swap_clearing_empty_root("FALLBACK-AUTH"),
        solver_escrow_root: private_cross_rollup_atomic_swap_clearing_empty_root("FALLBACK-SOLVER"),
        settlement_call_root: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-settlement",
            1,
        ),
        sequencer_commitment: private_cross_rollup_atomic_swap_clearing_commitment(
            "fallback-sequencer",
            1,
        ),
        status: BatchStatus::Proposed,
        proposed_at_height: 1,
        execute_after_height: 2,
    }
}
