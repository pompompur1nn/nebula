use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type FastPrivateStateChannelRouterResult<T> = Result<T, String>;

pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-fast-private-state-channel-router-v1";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_SCHEMA_VERSION: &str =
    "fast-private-state-channel-router-state-v1";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_PQ_COSIGN_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-128f-channel-exit-v1";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_ZK_UPDATE_SCHEME: &str =
    "zk-private-state-update-recursive-v1";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_SPONSOR_SCHEME: &str =
    "low-fee-private-channel-sponsorship-v1";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_HOP_SCHEME: &str =
    "cross-rollup-private-channel-hop-v1";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_RECEIPT_SCHEME: &str =
    "private-settlement-receipt-nullifier-v1";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_OPEN_TTL_BLOCKS: u64 = 32;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_UPDATE_TTL_BLOCKS: u64 = 18;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_EXIT_TTL_BLOCKS: u64 = 48;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 10;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_PARTICIPANTS: usize = 8;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_CHANNELS: usize = 4096;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_UPDATES: usize = 65536;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_EXITS: usize = 32768;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_HOPS: usize = 32768;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_SPONSORSHIPS: usize = 32768;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_DISPUTES: usize = 16384;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_RECEIPTS: usize = 65536;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 900;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_HOP_FEE_MICRO_UNITS: u64 = 350;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_SPONSOR_REBATE_BPS: u64 = 7500;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 9500;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_DEVNET_HEIGHT: u64 = 256;
pub const FAST_PRIVATE_STATE_CHANNEL_ROUTER_MAX_BPS: u64 = 10000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    PrivateTransfer,
    DefiSwap,
    TokenVault,
    SmartContractCall,
    MoneroBridgeExit,
    PerpMargin,
    OracleIntent,
    GovernanceAction,
}
impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::DefiSwap => "defi_swap",
            Self::TokenVault => "token_vault",
            Self::SmartContractCall => "smart_contract_call",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::PerpMargin => "perp_margin",
            Self::OracleIntent => "oracle_intent",
            Self::GovernanceAction => "governance_action",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStatus {
    Opening,
    Active,
    Hopping,
    Settling,
    Disputed,
    Closed,
    Expired,
    Cancelled,
}
impl ChannelStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::Hopping => "hopping",
            Self::Settling => "settling",
            Self::Disputed => "disputed",
            Self::Closed => "closed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Expired | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Proposed,
    ZkVerified,
    CoSigned,
    Routed,
    Superseded,
    Challenged,
    Settled,
    Rejected,
}
impl UpdateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ZkVerified => "zk_verified",
            Self::CoSigned => "co_signed",
            Self::Routed => "routed",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    Requested,
    CoSigned,
    ChallengeOpen,
    ReadyToSettle,
    Settled,
    Challenged,
    Slashed,
    Expired,
    Cancelled,
}
impl ExitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::CoSigned => "co_signed",
            Self::ChallengeOpen => "challenge_open",
            Self::ReadyToSettle => "ready_to_settle",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Slashed | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopStatus {
    Quoted,
    Locked,
    Forwarded,
    Acknowledged,
    Settled,
    Challenged,
    Expired,
    Cancelled,
}
impl HopStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Locked => "locked",
            Self::Forwarded => "forwarded",
            Self::Acknowledged => "acknowledged",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Expired | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Reserved,
    Debited,
    Exhausted,
    Paused,
    Closed,
}
impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Debited => "debited",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Closed => "closed",
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Exhausted | Self::Closed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Open,
    EvidencePending,
    ReadyToResolve,
    Resolved,
    Slashed,
    Expired,
}
impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidencePending => "evidence_pending",
            Self::ReadyToResolve => "ready_to_resolve",
            Self::Resolved => "resolved",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Resolved | Self::Slashed | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Finalized,
    Proven,
    Rejected,
    Reorged,
}
impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Finalized => "finalized",
            Self::Proven => "proven",
            Self::Rejected => "rejected",
            Self::Reorged => "reorged",
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Finalized | Self::Proven | Self::Rejected | Self::Reorged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    FullyShielded,
    AmountBucketed,
    SponsorScoped,
    RouteScoped,
    EmergencyScoped,
}
impl PrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::AmountBucketed => "amount_bucketed",
            Self::SponsorScoped => "sponsor_scoped",
            Self::RouteScoped => "route_scoped",
            Self::EmergencyScoped => "emergency_scoped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSpeed {
    LowFee,
    Normal,
    Fast,
    Urgent,
}
impl RouteSpeed {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::Urgent => "urgent",
        }
    }
}

pub trait RouterRecord {
    fn root(&self) -> String;
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_cosign_scheme: String,
    pub zk_update_scheme: String,
    pub sponsor_scheme: String,
    pub hop_scheme: String,
    pub receipt_scheme: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub open_ttl_blocks: u64,
    pub update_ttl_blocks: u64,
    pub exit_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub max_participants: usize,
    pub max_channels: usize,
    pub max_updates: usize,
    pub max_exits: usize,
    pub max_hops: usize,
    pub max_sponsorships: usize,
    pub max_disputes: usize,
    pub max_receipts: usize,
    pub base_fee_micro_units: u64,
    pub hop_fee_micro_units: u64,
    pub sponsor_rebate_bps: u64,
    pub max_sponsor_rebate_bps: u64,
    pub min_pq_security_bits: u64,
    pub min_privacy_set_size: u64,
    pub privacy_policy_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    pub participant_id: String,
    pub spend_commitment: String,
    pub view_commitment: String,
    pub pq_identity_root: String,
    pub weight: u64,
    pub can_initiate_exit: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateChannelOpen {
    pub channel_id: String,
    pub kind: ChannelKind,
    pub status: ChannelStatus,
    pub privacy_mode: PrivacyMode,
    pub opener_commitment: String,
    pub counterparty_commitment: String,
    pub asset_id: String,
    pub balance_commitment: String,
    pub state_commitment: String,
    pub participants: Vec<Participant>,
    pub route_hint_root: String,
    pub sponsor_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkStateUpdate {
    pub update_id: String,
    pub channel_id: String,
    pub status: UpdateStatus,
    pub sequence: u64,
    pub previous_state_root: String,
    pub next_state_root: String,
    pub delta_commitment: String,
    pub proof_root: String,
    pub participant_bitmap: u64,
    pub fee_micro_units: u64,
    pub valid_after_height: u64,
    pub expires_at_height: u64,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqCoSignedExit {
    pub exit_id: String,
    pub channel_id: String,
    pub status: ExitStatus,
    pub sequence: u64,
    pub state_root: String,
    pub exit_commitment: String,
    pub cosignature_root: String,
    pub settlement_address_commitment: String,
    pub fee_commitment: String,
    pub requested_at_height: u64,
    pub challenge_deadline_height: u64,
    pub settle_after_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub channel_id: String,
    pub status: SponsorStatus,
    pub budget_root: String,
    pub max_fee_micro_units: u64,
    pub rebate_bps: u64,
    pub reserved_micro_units: u64,
    pub spent_micro_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossRollupHop {
    pub hop_id: String,
    pub channel_id: String,
    pub status: HopStatus,
    pub source_rollup: String,
    pub target_rollup: String,
    pub bridge_commitment: String,
    pub lock_root: String,
    pub ack_root: String,
    pub fee_micro_units: u64,
    pub opened_at_height: u64,
    pub timeout_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelDispute {
    pub dispute_id: String,
    pub channel_id: String,
    pub target_id: String,
    pub status: DisputeStatus,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub bond_commitment: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub resolved_at_height: u64,
    pub slash_units: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub channel_id: String,
    pub target_id: String,
    pub status: ReceiptStatus,
    pub settlement_root: String,
    pub nullifier_root: String,
    pub fee_paid_micro_units: u64,
    pub settled_at_height: u64,
    pub final_at_height: u64,
    pub receipt_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub channel_root: String,
    pub update_root: String,
    pub exit_root: String,
    pub sponsorship_root: String,
    pub hop_root: String,
    pub dispute_root: String,
    pub receipt_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub channels: usize,
    pub active_channels: usize,
    pub updates: usize,
    pub verified_updates: usize,
    pub exits: usize,
    pub pending_exits: usize,
    pub sponsorships: usize,
    pub active_sponsorships: usize,
    pub hops: usize,
    pub open_hops: usize,
    pub disputes: usize,
    pub open_disputes: usize,
    pub receipts: usize,
    pub finalized_receipts: usize,
    pub total_fees_micro_units: u64,
    pub sponsored_fees_micro_units: u64,
}

fn ensure_non_empty(value: &str, label: &str) -> FastPrivateStateChannelRouterResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_root(value: &str, label: &str) -> FastPrivateStateChannelRouterResult<()> {
    ensure_non_empty(value, label)?;
    if value.len() < 16 {
        return Err(format!("{label} must be a domain root"));
    }
    Ok(())
}

fn checked_deadline(
    start: u64,
    delta: u64,
    label: &str,
) -> FastPrivateStateChannelRouterResult<u64> {
    start
        .checked_add(delta)
        .ok_or_else(|| format!("{label} height overflow"))
}

fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn id_root(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn root_from_record(record: &Value) -> String {
    payload_root("FAST-PRIVATE-STATE-CHANNEL-ROUTER-RECORD", record)
}

impl RouterRecord for Config {
    fn root(&self) -> String {
        payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-CONFIG",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "Config",
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_cosign_scheme": self.pq_cosign_scheme,
            "zk_update_scheme": self.zk_update_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "hop_scheme": self.hop_scheme,
            "receipt_scheme": self.receipt_scheme,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "open_ttl_blocks": self.open_ttl_blocks,
            "update_ttl_blocks": self.update_ttl_blocks,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "max_participants": self.max_participants,
            "max_channels": self.max_channels,
            "max_updates": self.max_updates,
            "max_exits": self.max_exits,
            "max_hops": self.max_hops,
            "max_sponsorships": self.max_sponsorships,
            "max_disputes": self.max_disputes,
            "max_receipts": self.max_receipts,
            "base_fee_micro_units": self.base_fee_micro_units,
            "hop_fee_micro_units": self.hop_fee_micro_units,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }
}

impl RouterRecord for Participant {
    fn root(&self) -> String {
        payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-PARTICIPANT",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "Participant",
            "participant_id": self.participant_id,
            "spend_commitment": self.spend_commitment,
            "view_commitment": self.view_commitment,
            "pq_identity_root": self.pq_identity_root,
            "weight": self.weight,
            "can_initiate_exit": self.can_initiate_exit,
        })
    }
}

impl RouterRecord for PrivateChannelOpen {
    fn root(&self) -> String {
        payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-PRIVATECHANNELOPEN",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "PrivateChannelOpen",
            "channel_id": self.channel_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "opener_commitment": self.opener_commitment,
            "counterparty_commitment": self.counterparty_commitment,
            "asset_id": self.asset_id,
            "balance_commitment": self.balance_commitment,
            "state_commitment": self.state_commitment,
            "participants": self.participants,
            "route_hint_root": self.route_hint_root,
            "sponsor_id": self.sponsor_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

impl RouterRecord for ZkStateUpdate {
    fn root(&self) -> String {
        payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-ZKSTATEUPDATE",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "ZkStateUpdate",
            "update_id": self.update_id,
            "channel_id": self.channel_id,
            "status": self.status.as_str(),
            "sequence": self.sequence,
            "previous_state_root": self.previous_state_root,
            "next_state_root": self.next_state_root,
            "delta_commitment": self.delta_commitment,
            "proof_root": self.proof_root,
            "participant_bitmap": self.participant_bitmap,
            "fee_micro_units": self.fee_micro_units,
            "valid_after_height": self.valid_after_height,
            "expires_at_height": self.expires_at_height,
            "created_at_height": self.created_at_height,
        })
    }
}

impl RouterRecord for PqCoSignedExit {
    fn root(&self) -> String {
        payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-PQCOSIGNEDEXIT",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "PqCoSignedExit",
            "exit_id": self.exit_id,
            "channel_id": self.channel_id,
            "status": self.status.as_str(),
            "sequence": self.sequence,
            "state_root": self.state_root,
            "exit_commitment": self.exit_commitment,
            "cosignature_root": self.cosignature_root,
            "settlement_address_commitment": self.settlement_address_commitment,
            "fee_commitment": self.fee_commitment,
            "requested_at_height": self.requested_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "settle_after_height": self.settle_after_height,
        })
    }
}

impl RouterRecord for RouteSponsorship {
    fn root(&self) -> String {
        payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-ROUTESPONSORSHIP",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "RouteSponsorship",
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "channel_id": self.channel_id,
            "status": self.status.as_str(),
            "budget_root": self.budget_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "reserved_micro_units": self.reserved_micro_units,
            "spent_micro_units": self.spent_micro_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl RouterRecord for CrossRollupHop {
    fn root(&self) -> String {
        payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-CROSSROLLUPHOP",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "CrossRollupHop",
            "hop_id": self.hop_id,
            "channel_id": self.channel_id,
            "status": self.status.as_str(),
            "source_rollup": self.source_rollup,
            "target_rollup": self.target_rollup,
            "bridge_commitment": self.bridge_commitment,
            "lock_root": self.lock_root,
            "ack_root": self.ack_root,
            "fee_micro_units": self.fee_micro_units,
            "opened_at_height": self.opened_at_height,
            "timeout_height": self.timeout_height,
        })
    }
}

impl RouterRecord for ChannelDispute {
    fn root(&self) -> String {
        payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-CHANNELDISPUTE",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "ChannelDispute",
            "dispute_id": self.dispute_id,
            "channel_id": self.channel_id,
            "target_id": self.target_id,
            "status": self.status.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "bond_commitment": self.bond_commitment,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "resolved_at_height": self.resolved_at_height,
            "slash_units": self.slash_units,
        })
    }
}

impl RouterRecord for SettlementReceipt {
    fn root(&self) -> String {
        payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-SETTLEMENTRECEIPT",
            &self.public_record(),
        )
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "SettlementReceipt",
            "receipt_id": self.receipt_id,
            "channel_id": self.channel_id,
            "target_id": self.target_id,
            "status": self.status.as_str(),
            "settlement_root": self.settlement_root,
            "nullifier_root": self.nullifier_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "settled_at_height": self.settled_at_height,
            "final_at_height": self.final_at_height,
            "receipt_index": self.receipt_index,
        })
    }
}

impl Config {
    pub fn devnet() -> FastPrivateStateChannelRouterResult<Self> {
        let privacy_policy_root = string_root(
            "FAST-PRIVATE-STATE-CHANNEL-PRIVACY",
            "public-roots-private-witnesses",
        );
        let mut config = Self {
            config_id: String::new(),
            protocol_version: FAST_PRIVATE_STATE_CHANNEL_ROUTER_PROTOCOL_VERSION.to_string(),
            schema_version: FAST_PRIVATE_STATE_CHANNEL_ROUTER_SCHEMA_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: FAST_PRIVATE_STATE_CHANNEL_ROUTER_HASH_SUITE.to_string(),
            pq_cosign_scheme: FAST_PRIVATE_STATE_CHANNEL_ROUTER_PQ_COSIGN_SCHEME.to_string(),
            zk_update_scheme: FAST_PRIVATE_STATE_CHANNEL_ROUTER_ZK_UPDATE_SCHEME.to_string(),
            sponsor_scheme: FAST_PRIVATE_STATE_CHANNEL_ROUTER_SPONSOR_SCHEME.to_string(),
            hop_scheme: FAST_PRIVATE_STATE_CHANNEL_ROUTER_HOP_SCHEME.to_string(),
            receipt_scheme: FAST_PRIVATE_STATE_CHANNEL_ROUTER_RECEIPT_SCHEME.to_string(),
            monero_network: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEVNET_FEE_ASSET_ID.to_string(),
            open_ttl_blocks: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_OPEN_TTL_BLOCKS,
            update_ttl_blocks: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_UPDATE_TTL_BLOCKS,
            exit_ttl_blocks: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_EXIT_TTL_BLOCKS,
            challenge_window_blocks:
                FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            settlement_finality_blocks:
                FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            max_participants: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_PARTICIPANTS,
            max_channels: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_CHANNELS,
            max_updates: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_UPDATES,
            max_exits: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_EXITS,
            max_hops: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_HOPS,
            max_sponsorships: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_SPONSORSHIPS,
            max_disputes: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_DISPUTES,
            max_receipts: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_RECEIPTS,
            base_fee_micro_units: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_BASE_FEE_MICRO_UNITS,
            hop_fee_micro_units: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_HOP_FEE_MICRO_UNITS,
            sponsor_rebate_bps: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_SPONSOR_REBATE_BPS,
            max_sponsor_rebate_bps:
                FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MAX_SPONSOR_REBATE_BPS,
            min_pq_security_bits: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            privacy_policy_root: privacy_policy_root,
        };
        config.config_id = id_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-CONFIG-ID",
            &[
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&config.schema_version),
                HashPart::Str(&config.chain_id),
            ],
        );
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> FastPrivateStateChannelRouterResult<String> {
        ensure_non_empty(&self.config_id, "config config_id")?;
        ensure_non_empty(&self.protocol_version, "config protocol_version")?;
        ensure_non_empty(&self.schema_version, "config schema_version")?;
        ensure_non_empty(&self.chain_id, "config chain_id")?;
        ensure_non_empty(&self.hash_suite, "config hash_suite")?;
        ensure_non_empty(&self.pq_cosign_scheme, "config pq_cosign_scheme")?;
        ensure_non_empty(&self.zk_update_scheme, "config zk_update_scheme")?;
        ensure_non_empty(&self.sponsor_scheme, "config sponsor_scheme")?;
        ensure_non_empty(&self.hop_scheme, "config hop_scheme")?;
        ensure_non_empty(&self.receipt_scheme, "config receipt_scheme")?;
        ensure_non_empty(&self.monero_network, "config monero_network")?;
        ensure_non_empty(&self.asset_id, "config asset_id")?;
        ensure_non_empty(&self.fee_asset_id, "config fee_asset_id")?;
        ensure_non_empty(&self.privacy_policy_root, "config privacy_policy_root")?;
        if self.protocol_version != FAST_PRIVATE_STATE_CHANNEL_ROUTER_PROTOCOL_VERSION {
            return Err("router protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("router chain id mismatch".to_string());
        }
        if self.open_ttl_blocks == 0 {
            return Err("config open_ttl_blocks must be positive".to_string());
        }
        if self.update_ttl_blocks == 0 {
            return Err("config update_ttl_blocks must be positive".to_string());
        }
        if self.exit_ttl_blocks == 0 {
            return Err("config exit_ttl_blocks must be positive".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("config challenge_window_blocks must be positive".to_string());
        }
        if self.settlement_finality_blocks == 0 {
            return Err("config settlement_finality_blocks must be positive".to_string());
        }
        if self.max_participants == 0 {
            return Err("config max_participants must be positive".to_string());
        }
        if self.max_channels == 0 {
            return Err("config max_channels must be positive".to_string());
        }
        if self.max_updates == 0 {
            return Err("config max_updates must be positive".to_string());
        }
        if self.max_exits == 0 {
            return Err("config max_exits must be positive".to_string());
        }
        if self.max_hops == 0 {
            return Err("config max_hops must be positive".to_string());
        }
        if self.max_sponsorships == 0 {
            return Err("config max_sponsorships must be positive".to_string());
        }
        if self.max_disputes == 0 {
            return Err("config max_disputes must be positive".to_string());
        }
        if self.max_receipts == 0 {
            return Err("config max_receipts must be positive".to_string());
        }
        if self.base_fee_micro_units == 0 {
            return Err("config base_fee_micro_units must be positive".to_string());
        }
        if self.hop_fee_micro_units == 0 {
            return Err("config hop_fee_micro_units must be positive".to_string());
        }
        if self.max_sponsor_rebate_bps == 0 {
            return Err("config max_sponsor_rebate_bps must be positive".to_string());
        }
        if self.min_pq_security_bits == 0 {
            return Err("config min_pq_security_bits must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("config min_privacy_set_size must be positive".to_string());
        }
        if self.sponsor_rebate_bps > FAST_PRIVATE_STATE_CHANNEL_ROUTER_MAX_BPS {
            return Err("sponsor rebate exceeds bps denominator".to_string());
        }
        if self.max_sponsor_rebate_bps > FAST_PRIVATE_STATE_CHANNEL_ROUTER_MAX_BPS {
            return Err("max sponsor rebate exceeds bps denominator".to_string());
        }
        if self.sponsor_rebate_bps > self.max_sponsor_rebate_bps {
            return Err("sponsor rebate exceeds configured max".to_string());
        }
        if self.challenge_window_blocks >= self.exit_ttl_blocks {
            return Err("challenge window must be shorter than exit ttl".to_string());
        }
        Ok(self.root())
    }
}

impl Participant {
    pub fn validate(&self, config: &Config) -> FastPrivateStateChannelRouterResult<String> {
        ensure_non_empty(&self.participant_id, "Participant participant_id")?;
        ensure_root(&self.spend_commitment, "Participant spend_commitment")?;
        ensure_root(&self.view_commitment, "Participant view_commitment")?;
        ensure_root(&self.pq_identity_root, "Participant pq_identity_root")?;
        if self.weight == 0 {
            return Err("participant weight must be positive".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateChannelOpen {
    pub fn validate(&self, config: &Config) -> FastPrivateStateChannelRouterResult<String> {
        ensure_non_empty(&self.channel_id, "PrivateChannelOpen channel_id")?;
        ensure_root(
            &self.opener_commitment,
            "PrivateChannelOpen opener_commitment",
        )?;
        ensure_root(
            &self.counterparty_commitment,
            "PrivateChannelOpen counterparty_commitment",
        )?;
        ensure_non_empty(&self.asset_id, "PrivateChannelOpen asset_id")?;
        ensure_root(
            &self.balance_commitment,
            "PrivateChannelOpen balance_commitment",
        )?;
        ensure_root(
            &self.state_commitment,
            "PrivateChannelOpen state_commitment",
        )?;
        ensure_root(&self.route_hint_root, "PrivateChannelOpen route_hint_root")?;
        ensure_non_empty(&self.sponsor_id, "PrivateChannelOpen sponsor_id")?;
        if self.participants.is_empty() {
            return Err("channel must have participants".to_string());
        }
        if self.participants.len() > config.max_participants {
            return Err("channel participant cap exceeded".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("channel expiry must follow open height".to_string());
        }
        let mut seen = BTreeSet::new();
        for participant in &self.participants {
            participant.validate(config)?;
            if !seen.insert(participant.participant_id.clone()) {
                return Err("duplicate channel participant".to_string());
            }
        }
        Ok(self.root())
    }
}

impl ZkStateUpdate {
    pub fn validate(&self, config: &Config) -> FastPrivateStateChannelRouterResult<String> {
        ensure_non_empty(&self.update_id, "ZkStateUpdate update_id")?;
        ensure_non_empty(&self.channel_id, "ZkStateUpdate channel_id")?;
        ensure_root(
            &self.previous_state_root,
            "ZkStateUpdate previous_state_root",
        )?;
        ensure_root(&self.next_state_root, "ZkStateUpdate next_state_root")?;
        ensure_root(&self.delta_commitment, "ZkStateUpdate delta_commitment")?;
        ensure_root(&self.proof_root, "ZkStateUpdate proof_root")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("update expiry must follow create height".to_string());
        }
        if self.previous_state_root == self.next_state_root {
            return Err("update must change state root".to_string());
        }
        Ok(self.root())
    }
}

impl PqCoSignedExit {
    pub fn validate(&self, config: &Config) -> FastPrivateStateChannelRouterResult<String> {
        ensure_non_empty(&self.exit_id, "PqCoSignedExit exit_id")?;
        ensure_non_empty(&self.channel_id, "PqCoSignedExit channel_id")?;
        ensure_root(&self.state_root, "PqCoSignedExit state_root")?;
        ensure_root(&self.exit_commitment, "PqCoSignedExit exit_commitment")?;
        ensure_root(&self.cosignature_root, "PqCoSignedExit cosignature_root")?;
        ensure_root(
            &self.settlement_address_commitment,
            "PqCoSignedExit settlement_address_commitment",
        )?;
        ensure_root(&self.fee_commitment, "PqCoSignedExit fee_commitment")?;
        if self.challenge_deadline_height <= self.requested_at_height {
            return Err("exit challenge deadline must follow request".to_string());
        }
        if self.settle_after_height < self.challenge_deadline_height {
            return Err("exit settle height must not precede challenge deadline".to_string());
        }
        Ok(self.root())
    }
}

impl RouteSponsorship {
    pub fn validate(&self, config: &Config) -> FastPrivateStateChannelRouterResult<String> {
        ensure_non_empty(&self.sponsorship_id, "RouteSponsorship sponsorship_id")?;
        ensure_non_empty(&self.sponsor_id, "RouteSponsorship sponsor_id")?;
        ensure_non_empty(&self.channel_id, "RouteSponsorship channel_id")?;
        ensure_root(&self.budget_root, "RouteSponsorship budget_root")?;
        if self.rebate_bps > config.max_sponsor_rebate_bps {
            return Err("sponsorship rebate exceeds configured max".to_string());
        }
        if self.spent_micro_units > self.reserved_micro_units {
            return Err("sponsorship spent exceeds reserved".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("sponsorship expiry must follow creation".to_string());
        }
        Ok(self.root())
    }
}

impl CrossRollupHop {
    pub fn validate(&self, config: &Config) -> FastPrivateStateChannelRouterResult<String> {
        ensure_non_empty(&self.hop_id, "CrossRollupHop hop_id")?;
        ensure_non_empty(&self.channel_id, "CrossRollupHop channel_id")?;
        ensure_non_empty(&self.source_rollup, "CrossRollupHop source_rollup")?;
        ensure_non_empty(&self.target_rollup, "CrossRollupHop target_rollup")?;
        ensure_root(&self.bridge_commitment, "CrossRollupHop bridge_commitment")?;
        ensure_root(&self.lock_root, "CrossRollupHop lock_root")?;
        ensure_root(&self.ack_root, "CrossRollupHop ack_root")?;
        if self.source_rollup == self.target_rollup {
            return Err("hop requires distinct rollups".to_string());
        }
        if self.timeout_height <= self.opened_at_height {
            return Err("hop timeout must follow open height".to_string());
        }
        Ok(self.root())
    }
}

impl ChannelDispute {
    pub fn validate(&self, config: &Config) -> FastPrivateStateChannelRouterResult<String> {
        ensure_non_empty(&self.dispute_id, "ChannelDispute dispute_id")?;
        ensure_non_empty(&self.channel_id, "ChannelDispute channel_id")?;
        ensure_non_empty(&self.target_id, "ChannelDispute target_id")?;
        ensure_root(
            &self.challenger_commitment,
            "ChannelDispute challenger_commitment",
        )?;
        ensure_root(&self.evidence_root, "ChannelDispute evidence_root")?;
        ensure_root(&self.bond_commitment, "ChannelDispute bond_commitment")?;
        if self.deadline_height <= self.opened_at_height {
            return Err("dispute deadline must follow open height".to_string());
        }
        Ok(self.root())
    }
}

impl SettlementReceipt {
    pub fn validate(&self, config: &Config) -> FastPrivateStateChannelRouterResult<String> {
        ensure_non_empty(&self.receipt_id, "SettlementReceipt receipt_id")?;
        ensure_non_empty(&self.channel_id, "SettlementReceipt channel_id")?;
        ensure_non_empty(&self.target_id, "SettlementReceipt target_id")?;
        ensure_root(&self.settlement_root, "SettlementReceipt settlement_root")?;
        ensure_root(&self.nullifier_root, "SettlementReceipt nullifier_root")?;
        if self.final_at_height < self.settled_at_height {
            return Err("receipt finality cannot precede settlement".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub channels: BTreeMap<String, PrivateChannelOpen>,
    pub updates: BTreeMap<String, ZkStateUpdate>,
    pub exits: BTreeMap<String, PqCoSignedExit>,
    pub sponsorships: BTreeMap<String, RouteSponsorship>,
    pub hops: BTreeMap<String, CrossRollupHop>,
    pub disputes: BTreeMap<String, ChannelDispute>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub events: Vec<Value>,
}

impl State {
    pub fn devnet() -> FastPrivateStateChannelRouterResult<Self> {
        let config = Config::devnet()?;
        let mut state = Self {
            config,
            height: FAST_PRIVATE_STATE_CHANNEL_ROUTER_DEFAULT_DEVNET_HEIGHT,
            channels: BTreeMap::new(),
            updates: BTreeMap::new(),
            exits: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            hops: BTreeMap::new(),
            disputes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: Vec::new(),
        };
        state.seed_devnet()?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> FastPrivateStateChannelRouterResult<String> {
        self.config.validate()?;
        if self.channels.len() > self.config.max_channels {
            return Err("router channel cap exceeded".to_string());
        }
        if self.updates.len() > self.config.max_updates {
            return Err("router update cap exceeded".to_string());
        }
        if self.exits.len() > self.config.max_exits {
            return Err("router exit cap exceeded".to_string());
        }
        if self.sponsorships.len() > self.config.max_sponsorships {
            return Err("router sponsorship cap exceeded".to_string());
        }
        if self.hops.len() > self.config.max_hops {
            return Err("router hop cap exceeded".to_string());
        }
        if self.disputes.len() > self.config.max_disputes {
            return Err("router dispute cap exceeded".to_string());
        }
        if self.receipts.len() > self.config.max_receipts {
            return Err("router receipt cap exceeded".to_string());
        }
        for (id, record) in &self.channels {
            ensure_non_empty(id, "state channel id")?;
            record.validate(&self.config)?;
        }
        for (id, record) in &self.updates {
            ensure_non_empty(id, "state update id")?;
            record.validate(&self.config)?;
        }
        for (id, record) in &self.exits {
            ensure_non_empty(id, "state exit id")?;
            record.validate(&self.config)?;
        }
        for (id, record) in &self.sponsorships {
            ensure_non_empty(id, "state sponsorship id")?;
            record.validate(&self.config)?;
        }
        for (id, record) in &self.hops {
            ensure_non_empty(id, "state hop id")?;
            record.validate(&self.config)?;
        }
        for (id, record) in &self.disputes {
            ensure_non_empty(id, "state dispute id")?;
            record.validate(&self.config)?;
        }
        for (id, record) in &self.receipts {
            ensure_non_empty(id, "state receipt id")?;
            record.validate(&self.config)?;
        }
        for update in self.updates.values() {
            if !self.channels.contains_key(&update.channel_id) {
                return Err("update references unknown channel".to_string());
            }
        }
        for exit in self.exits.values() {
            if !self.channels.contains_key(&exit.channel_id) {
                return Err("exit references unknown channel".to_string());
            }
        }
        for sponsorship in self.sponsorships.values() {
            if !self.channels.contains_key(&sponsorship.channel_id) {
                return Err("sponsorship references unknown channel".to_string());
            }
        }
        for hop in self.hops.values() {
            if !self.channels.contains_key(&hop.channel_id) {
                return Err("hop references unknown channel".to_string());
            }
        }
        for dispute in self.disputes.values() {
            if !self.channels.contains_key(&dispute.channel_id) {
                return Err("dispute references unknown channel".to_string());
            }
        }
        for receipt in self.receipts.values() {
            if !self.channels.contains_key(&receipt.channel_id) {
                return Err("receipt references unknown channel".to_string());
            }
        }
        Ok(self.state_root())
    }

    pub fn set_height(&mut self, height: u64) -> FastPrivateStateChannelRouterResult<String> {
        self.height = height;
        self.refresh_timeouts()?;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> FastPrivateStateChannelRouterResult<String> {
        if height < self.height {
            return Err("router height cannot move backward".to_string());
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let channel_root = merkle_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-CHANNELS",
            &self
                .channels
                .values()
                .map(RouterRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let update_root = merkle_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-UPDATES",
            &self
                .updates
                .values()
                .map(RouterRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let exit_root = merkle_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-EXITS",
            &self
                .exits
                .values()
                .map(RouterRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsorship_root = merkle_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-SPONSORSHIPS",
            &self
                .sponsorships
                .values()
                .map(RouterRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let hop_root = merkle_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-HOPS",
            &self
                .hops
                .values()
                .map(RouterRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let dispute_root = merkle_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-DISPUTES",
            &self
                .disputes
                .values()
                .map(RouterRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-RECEIPTS",
            &self
                .receipts
                .values()
                .map(RouterRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let public_record = self.public_record_without_state_root(
            &config_root,
            &channel_root,
            &update_root,
            &exit_root,
            &sponsorship_root,
            &hop_root,
            &dispute_root,
            &receipt_root,
        );
        let public_record_root = root_from_record(&public_record);
        let state_root = payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTER-STATE",
            &json!({"config_root":config_root,"channel_root":channel_root,"update_root":update_root,"exit_root":exit_root,"sponsorship_root":sponsorship_root,"hop_root":hop_root,"dispute_root":dispute_root,"receipt_root":receipt_root,"public_record_root":public_record_root,"height":self.height}),
        );
        Roots {
            config_root,
            channel_root,
            update_root,
            exit_root,
            sponsorship_root,
            hop_root,
            dispute_root,
            receipt_root,
            public_record_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        let active_channels = self
            .channels
            .values()
            .filter(|c| {
                matches!(
                    c.status,
                    ChannelStatus::Opening
                        | ChannelStatus::Active
                        | ChannelStatus::Hopping
                        | ChannelStatus::Settling
                        | ChannelStatus::Disputed
                )
            })
            .count();
        let verified_updates = self
            .updates
            .values()
            .filter(|u| {
                matches!(
                    u.status,
                    UpdateStatus::ZkVerified
                        | UpdateStatus::CoSigned
                        | UpdateStatus::Routed
                        | UpdateStatus::Settled
                )
            })
            .count();
        let pending_exits = self
            .exits
            .values()
            .filter(|e| {
                matches!(
                    e.status,
                    ExitStatus::Requested
                        | ExitStatus::CoSigned
                        | ExitStatus::ChallengeOpen
                        | ExitStatus::ReadyToSettle
                        | ExitStatus::Challenged
                )
            })
            .count();
        let active_sponsorships = self
            .sponsorships
            .values()
            .filter(|s| {
                matches!(
                    s.status,
                    SponsorStatus::Active | SponsorStatus::Reserved | SponsorStatus::Debited
                )
            })
            .count();
        let open_hops = self
            .hops
            .values()
            .filter(|h| {
                matches!(
                    h.status,
                    HopStatus::Quoted
                        | HopStatus::Locked
                        | HopStatus::Forwarded
                        | HopStatus::Acknowledged
                        | HopStatus::Challenged
                )
            })
            .count();
        let open_disputes = self
            .disputes
            .values()
            .filter(|d| {
                matches!(
                    d.status,
                    DisputeStatus::Open
                        | DisputeStatus::EvidencePending
                        | DisputeStatus::ReadyToResolve
                )
            })
            .count();
        let finalized_receipts = self
            .receipts
            .values()
            .filter(|r| matches!(r.status, ReceiptStatus::Finalized | ReceiptStatus::Proven))
            .count();
        let total_fees_micro_units = self
            .receipts
            .values()
            .map(|r| r.fee_paid_micro_units)
            .sum::<u64>();
        let sponsored_fees_micro_units = self
            .sponsorships
            .values()
            .map(|s| s.spent_micro_units)
            .sum::<u64>();
        Counters {
            channels: self.channels.len(),
            active_channels,
            updates: self.updates.len(),
            verified_updates,
            exits: self.exits.len(),
            pending_exits,
            sponsorships: self.sponsorships.len(),
            active_sponsorships,
            hops: self.hops.len(),
            open_hops,
            disputes: self.disputes.len(),
            open_disputes,
            receipts: self.receipts.len(),
            finalized_receipts,
            total_fees_micro_units,
            sponsored_fees_micro_units,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({"kind":"fast_private_state_channel_router_state","protocol_version":self.config.protocol_version,"chain_id":self.config.chain_id,"height":self.height,"roots":roots,"counters":self.counters()})
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn open_private_channel(
        &mut self,
        kind: ChannelKind,
        privacy_mode: PrivacyMode,
        opener_commitment: String,
        counterparty_commitment: String,
        balance_commitment: String,
        state_commitment: String,
        participants: Vec<Participant>,
        sponsor_id: String,
    ) -> FastPrivateStateChannelRouterResult<String> {
        if self.channels.len() >= self.config.max_channels {
            return Err("router channel cap reached".to_string());
        }
        let expires_at_height = checked_deadline(
            self.height,
            self.config.open_ttl_blocks,
            "private channel open",
        )?;
        let route_hint_root = payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-ROUTE-HINT",
            &json!({"kind":kind.as_str(),"privacy_mode":privacy_mode.as_str(),"height":self.height,"participants":participants.iter().map(RouterRecord::root).collect::<Vec<_>>() }),
        );
        let nonce = self.channels.len() as u64 + 1;
        let channel_id = id_root(
            "FAST-PRIVATE-STATE-CHANNEL-ID",
            &[
                HashPart::Str(&opener_commitment),
                HashPart::Str(&counterparty_commitment),
                HashPart::Str(&state_commitment),
                HashPart::Int(nonce as i128),
                HashPart::Int(self.height as i128),
            ],
        );
        let channel = PrivateChannelOpen {
            channel_id: channel_id.clone(),
            kind,
            status: ChannelStatus::Opening,
            privacy_mode,
            opener_commitment,
            counterparty_commitment,
            asset_id: self.config.asset_id.clone(),
            balance_commitment,
            state_commitment,
            participants,
            route_hint_root,
            sponsor_id,
            opened_at_height: self.height,
            expires_at_height,
            nonce,
        };
        channel.validate(&self.config)?;
        self.channels.insert(channel_id.clone(), channel);
        self.events.push(
            json!({"event":"private_channel_opened","channel_id":channel_id,"height":self.height}),
        );
        self.validate()?;
        Ok(channel_id)
    }

    pub fn verify_zk_state_update(
        &mut self,
        channel_id: String,
        previous_state_root: String,
        next_state_root: String,
        delta_commitment: String,
        proof_root: String,
        participant_bitmap: u64,
        speed: RouteSpeed,
    ) -> FastPrivateStateChannelRouterResult<String> {
        if self.updates.len() >= self.config.max_updates {
            return Err("router update cap reached".to_string());
        }
        let channel = self
            .channels
            .get(&channel_id)
            .ok_or_else(|| "unknown channel for zk update".to_string())?;
        if !matches!(
            channel.status,
            ChannelStatus::Opening | ChannelStatus::Active | ChannelStatus::Hopping
        ) {
            return Err("channel does not accept updates".to_string());
        }
        let sequence = match self
            .updates
            .values()
            .filter(|update| update.channel_id == channel_id)
            .map(|update| update.sequence)
            .max()
        {
            Some(value) => value.saturating_add(1),
            None => 1,
        };
        let fee_micro_units = self.route_fee_micro_units(speed, 0);
        let expires_at_height =
            checked_deadline(self.height, self.config.update_ttl_blocks, "zk update")?;
        let update_id = id_root(
            "FAST-PRIVATE-STATE-CHANNEL-UPDATE-ID",
            &[
                HashPart::Str(&channel_id),
                HashPart::Str(&previous_state_root),
                HashPart::Str(&next_state_root),
                HashPart::Int(sequence as i128),
            ],
        );
        let update = ZkStateUpdate {
            update_id: update_id.clone(),
            channel_id: channel_id.clone(),
            status: UpdateStatus::ZkVerified,
            sequence,
            previous_state_root,
            next_state_root,
            delta_commitment,
            proof_root,
            participant_bitmap,
            fee_micro_units,
            valid_after_height: self.height,
            expires_at_height,
            created_at_height: self.height,
        };
        update.validate(&self.config)?;
        self.updates.insert(update_id.clone(), update);
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.status = ChannelStatus::Active;
        }
        self.events.push(json!({"event":"zk_state_update_verified","update_id":update_id,"channel_id":channel_id,"height":self.height}));
        self.validate()?;
        Ok(update_id)
    }

    pub fn request_pq_cosigned_exit(
        &mut self,
        channel_id: String,
        state_root: String,
        exit_commitment: String,
        cosignature_root: String,
        settlement_address_commitment: String,
    ) -> FastPrivateStateChannelRouterResult<String> {
        if self.exits.len() >= self.config.max_exits {
            return Err("router exit cap reached".to_string());
        }
        let channel = self
            .channels
            .get(&channel_id)
            .ok_or_else(|| "unknown channel for exit".to_string())?;
        if matches!(
            channel.status,
            ChannelStatus::Closed | ChannelStatus::Expired | ChannelStatus::Cancelled
        ) {
            return Err("channel is not exit eligible".to_string());
        }
        let sequence = match self
            .updates
            .values()
            .filter(|update| update.channel_id == channel_id)
            .map(|update| update.sequence)
            .max()
        {
            Some(value) => value,
            None => 0,
        };
        let fee_commitment = payload_root(
            "FAST-PRIVATE-STATE-CHANNEL-EXIT-FEE",
            &json!({"channel_id":channel_id,"sequence":sequence,"base_fee_micro_units":self.config.base_fee_micro_units,"height":self.height}),
        );
        let challenge_deadline_height = checked_deadline(
            self.height,
            self.config.challenge_window_blocks,
            "pq exit challenge",
        )?;
        let settle_after_height = checked_deadline(
            challenge_deadline_height,
            self.config.settlement_finality_blocks,
            "pq exit finality",
        )?;
        let exit_id = id_root(
            "FAST-PRIVATE-STATE-CHANNEL-EXIT-ID",
            &[
                HashPart::Str(&channel_id),
                HashPart::Str(&state_root),
                HashPart::Str(&exit_commitment),
                HashPart::Int(sequence as i128),
            ],
        );
        let exit = PqCoSignedExit {
            exit_id: exit_id.clone(),
            channel_id: channel_id.clone(),
            status: ExitStatus::CoSigned,
            sequence,
            state_root,
            exit_commitment,
            cosignature_root,
            settlement_address_commitment,
            fee_commitment,
            requested_at_height: self.height,
            challenge_deadline_height,
            settle_after_height,
        };
        exit.validate(&self.config)?;
        self.exits.insert(exit_id.clone(), exit);
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.status = ChannelStatus::Settling;
        }
        self.events.push(json!({"event":"pq_cosigned_exit_requested","exit_id":exit_id,"channel_id":channel_id,"height":self.height}));
        self.validate()?;
        Ok(exit_id)
    }

    pub fn sponsor_low_fee_route(
        &mut self,
        sponsor_id: String,
        channel_id: String,
        budget_root: String,
        max_fee_micro_units: u64,
        rebate_bps: u64,
    ) -> FastPrivateStateChannelRouterResult<String> {
        if self.sponsorships.len() >= self.config.max_sponsorships {
            return Err("router sponsorship cap reached".to_string());
        }
        if !self.channels.contains_key(&channel_id) {
            return Err("unknown channel for sponsorship".to_string());
        }
        let expires_at_height = checked_deadline(
            self.height,
            self.config.update_ttl_blocks,
            "route sponsorship",
        )?;
        let sponsorship_id = id_root(
            "FAST-PRIVATE-STATE-CHANNEL-SPONSORSHIP-ID",
            &[
                HashPart::Str(&sponsor_id),
                HashPart::Str(&channel_id),
                HashPart::Str(&budget_root),
                HashPart::Int(self.height as i128),
            ],
        );
        let sponsorship = RouteSponsorship {
            sponsorship_id: sponsorship_id.clone(),
            sponsor_id,
            channel_id: channel_id.clone(),
            status: SponsorStatus::Reserved,
            budget_root,
            max_fee_micro_units,
            rebate_bps,
            reserved_micro_units: max_fee_micro_units,
            spent_micro_units: 0,
            created_at_height: self.height,
            expires_at_height,
        };
        sponsorship.validate(&self.config)?;
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        self.events.push(json!({"event":"low_fee_route_sponsored","sponsorship_id":sponsorship_id,"channel_id":channel_id,"height":self.height}));
        self.validate()?;
        Ok(sponsorship_id)
    }

    pub fn route_cross_rollup_hop(
        &mut self,
        channel_id: String,
        source_rollup: String,
        target_rollup: String,
        bridge_commitment: String,
        lock_root: String,
    ) -> FastPrivateStateChannelRouterResult<String> {
        if self.hops.len() >= self.config.max_hops {
            return Err("router hop cap reached".to_string());
        }
        if !self.channels.contains_key(&channel_id) {
            return Err("unknown channel for cross-rollup hop".to_string());
        }
        let timeout_height =
            checked_deadline(self.height, self.config.exit_ttl_blocks, "cross rollup hop")?;
        let ack_root = string_root("FAST-PRIVATE-STATE-CHANNEL-HOP-PENDING-ACK", "pending");
        let hop_id = id_root(
            "FAST-PRIVATE-STATE-CHANNEL-HOP-ID",
            &[
                HashPart::Str(&channel_id),
                HashPart::Str(&source_rollup),
                HashPart::Str(&target_rollup),
                HashPart::Str(&lock_root),
                HashPart::Int(self.height as i128),
            ],
        );
        let hop = CrossRollupHop {
            hop_id: hop_id.clone(),
            channel_id: channel_id.clone(),
            status: HopStatus::Locked,
            source_rollup,
            target_rollup,
            bridge_commitment,
            lock_root,
            ack_root,
            fee_micro_units: self.config.hop_fee_micro_units,
            opened_at_height: self.height,
            timeout_height,
        };
        hop.validate(&self.config)?;
        self.hops.insert(hop_id.clone(), hop);
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.status = ChannelStatus::Hopping;
        }
        self.events.push(json!({"event":"cross_rollup_hop_locked","hop_id":hop_id,"channel_id":channel_id,"height":self.height}));
        self.validate()?;
        Ok(hop_id)
    }

    pub fn challenge_channel_target(
        &mut self,
        channel_id: String,
        target_id: String,
        challenger_commitment: String,
        evidence_root: String,
        bond_commitment: String,
    ) -> FastPrivateStateChannelRouterResult<String> {
        if self.disputes.len() >= self.config.max_disputes {
            return Err("router dispute cap reached".to_string());
        }
        if !self.channels.contains_key(&channel_id) {
            return Err("unknown channel for dispute".to_string());
        }
        let deadline_height = checked_deadline(
            self.height,
            self.config.challenge_window_blocks,
            "channel dispute",
        )?;
        let dispute_id = id_root(
            "FAST-PRIVATE-STATE-CHANNEL-DISPUTE-ID",
            &[
                HashPart::Str(&channel_id),
                HashPart::Str(&target_id),
                HashPart::Str(&evidence_root),
                HashPart::Int(self.height as i128),
            ],
        );
        let dispute = ChannelDispute {
            dispute_id: dispute_id.clone(),
            channel_id: channel_id.clone(),
            target_id: target_id.clone(),
            status: DisputeStatus::Open,
            challenger_commitment,
            evidence_root,
            bond_commitment,
            opened_at_height: self.height,
            deadline_height,
            resolved_at_height: 0,
            slash_units: 0,
        };
        dispute.validate(&self.config)?;
        self.disputes.insert(dispute_id.clone(), dispute);
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.status = ChannelStatus::Disputed;
        }
        if let Some(exit) = self.exits.get_mut(&target_id) {
            exit.status = ExitStatus::Challenged;
        }
        if let Some(update) = self.updates.get_mut(&target_id) {
            update.status = UpdateStatus::Challenged;
        }
        if let Some(hop) = self.hops.get_mut(&target_id) {
            hop.status = HopStatus::Challenged;
        }
        self.events.push(json!({"event":"channel_target_challenged","dispute_id":dispute_id,"channel_id":channel_id,"target_id":target_id,"height":self.height}));
        self.validate()?;
        Ok(dispute_id)
    }

    pub fn settle_exit_receipt(
        &mut self,
        exit_id: String,
        settlement_root: String,
        nullifier_root: String,
    ) -> FastPrivateStateChannelRouterResult<String> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("router receipt cap reached".to_string());
        }
        let exit = self
            .exits
            .get(&exit_id)
            .ok_or_else(|| "unknown exit for settlement receipt".to_string())?
            .clone();
        if self.height < exit.settle_after_height {
            return Err("exit is still inside challenge or finality window".to_string());
        }
        if matches!(
            exit.status,
            ExitStatus::Challenged
                | ExitStatus::Slashed
                | ExitStatus::Expired
                | ExitStatus::Cancelled
        ) {
            return Err("exit status is not settlement eligible".to_string());
        }
        let receipt_index = self.receipts.len() as u64 + 1;
        let final_at_height = checked_deadline(
            self.height,
            self.config.settlement_finality_blocks,
            "settlement receipt finality",
        )?;
        let receipt_id = id_root(
            "FAST-PRIVATE-STATE-CHANNEL-RECEIPT-ID",
            &[
                HashPart::Str(&exit.channel_id),
                HashPart::Str(&exit_id),
                HashPart::Str(&settlement_root),
                HashPart::Int(receipt_index as i128),
            ],
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            channel_id: exit.channel_id.clone(),
            target_id: exit_id.clone(),
            status: ReceiptStatus::Pending,
            settlement_root,
            nullifier_root,
            fee_paid_micro_units: self.config.base_fee_micro_units,
            settled_at_height: self.height,
            final_at_height,
            receipt_index,
        };
        receipt.validate(&self.config)?;
        self.receipts.insert(receipt_id.clone(), receipt);
        if let Some(exit_mut) = self.exits.get_mut(&exit_id) {
            exit_mut.status = ExitStatus::Settled;
        }
        if let Some(channel) = self.channels.get_mut(&exit.channel_id) {
            channel.status = ChannelStatus::Closed;
        }
        self.events.push(json!({"event":"settlement_receipt_created","receipt_id":receipt_id,"exit_id":exit_id,"height":self.height}));
        self.validate()?;
        Ok(receipt_id)
    }

    fn route_fee_micro_units(&self, speed: RouteSpeed, hops: u64) -> u64 {
        let multiplier = match speed {
            RouteSpeed::LowFee => 1,
            RouteSpeed::Normal => 2,
            RouteSpeed::Fast => 4,
            RouteSpeed::Urgent => 8,
        };
        self.config
            .base_fee_micro_units
            .saturating_mul(multiplier)
            .saturating_add(self.config.hop_fee_micro_units.saturating_mul(hops))
    }

    fn public_record_without_state_root(
        &self,
        config_root: &str,
        channel_root: &str,
        update_root: &str,
        exit_root: &str,
        sponsorship_root: &str,
        hop_root: &str,
        dispute_root: &str,
        receipt_root: &str,
    ) -> Value {
        json!({"kind":"fast_private_state_channel_router_state_without_state_root","protocol_version":self.config.protocol_version,"chain_id":self.config.chain_id,"height":self.height,"config_root":config_root,"channel_root":channel_root,"update_root":update_root,"exit_root":exit_root,"sponsorship_root":sponsorship_root,"hop_root":hop_root,"dispute_root":dispute_root,"receipt_root":receipt_root,"counters":self.counters()})
    }

    fn refresh_timeouts(&mut self) -> FastPrivateStateChannelRouterResult<()> {
        for channel in self.channels.values_mut() {
            if matches!(
                channel.status,
                ChannelStatus::Opening | ChannelStatus::Active | ChannelStatus::Hopping
            ) && self.height > channel.expires_at_height
            {
                channel.status = ChannelStatus::Expired;
            }
        }
        for update in self.updates.values_mut() {
            if matches!(
                update.status,
                UpdateStatus::Proposed
                    | UpdateStatus::ZkVerified
                    | UpdateStatus::CoSigned
                    | UpdateStatus::Routed
            ) && self.height > update.expires_at_height
            {
                update.status = UpdateStatus::Rejected;
            }
        }
        for exit in self.exits.values_mut() {
            if matches!(exit.status, ExitStatus::CoSigned | ExitStatus::Requested)
                && self.height >= exit.challenge_deadline_height
            {
                exit.status = ExitStatus::ReadyToSettle;
            }
            if !matches!(
                exit.status,
                ExitStatus::Settled
                    | ExitStatus::Challenged
                    | ExitStatus::Slashed
                    | ExitStatus::Cancelled
            ) && self.height
                > exit
                    .settle_after_height
                    .saturating_add(self.config.exit_ttl_blocks)
            {
                exit.status = ExitStatus::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if matches!(
                sponsorship.status,
                SponsorStatus::Active | SponsorStatus::Reserved
            ) && self.height > sponsorship.expires_at_height
            {
                sponsorship.status = SponsorStatus::Exhausted;
            }
        }
        for hop in self.hops.values_mut() {
            if matches!(
                hop.status,
                HopStatus::Quoted
                    | HopStatus::Locked
                    | HopStatus::Forwarded
                    | HopStatus::Acknowledged
            ) && self.height > hop.timeout_height
            {
                hop.status = HopStatus::Expired;
            }
        }
        for dispute in self.disputes.values_mut() {
            if matches!(
                dispute.status,
                DisputeStatus::Open | DisputeStatus::EvidencePending
            ) && self.height >= dispute.deadline_height
            {
                dispute.status = DisputeStatus::ReadyToResolve;
            }
        }
        for receipt in self.receipts.values_mut() {
            if matches!(receipt.status, ReceiptStatus::Pending)
                && self.height >= receipt.final_at_height
            {
                receipt.status = ReceiptStatus::Finalized;
            }
        }
        Ok(())
    }

    fn seed_devnet(&mut self) -> FastPrivateStateChannelRouterResult<()> {
        let alice = Participant {
            participant_id: "alice-devnet".to_string(),
            spend_commitment: string_root("DEVNET-PARTICIPANT-SPEND", "alice"),
            view_commitment: string_root("DEVNET-PARTICIPANT-VIEW", "alice"),
            pq_identity_root: string_root("DEVNET-PARTICIPANT-PQ", "alice"),
            weight: 1,
            can_initiate_exit: true,
        };
        let bob = Participant {
            participant_id: "bob-devnet".to_string(),
            spend_commitment: string_root("DEVNET-PARTICIPANT-SPEND", "bob"),
            view_commitment: string_root("DEVNET-PARTICIPANT-VIEW", "bob"),
            pq_identity_root: string_root("DEVNET-PARTICIPANT-PQ", "bob"),
            weight: 1,
            can_initiate_exit: true,
        };
        let channel_id = self.open_private_channel(
            ChannelKind::SmartContractCall,
            PrivacyMode::FullyShielded,
            string_root("DEVNET-OPEN", "alice"),
            string_root("DEVNET-OPEN", "bob"),
            string_root("DEVNET-BALANCE", "alice-bob"),
            string_root("DEVNET-STATE", "initial"),
            vec![alice, bob],
            "sponsor-devnet".to_string(),
        )?;
        let update_id = self.verify_zk_state_update(
            channel_id.clone(),
            string_root("DEVNET-STATE", "initial"),
            string_root("DEVNET-STATE", "updated"),
            string_root("DEVNET-DELTA", "swap-and-call"),
            string_root("DEVNET-PROOF", "recursive-zk-update"),
            3,
            RouteSpeed::Fast,
        )?;
        let sponsorship_id = self.sponsor_low_fee_route(
            "sponsor-devnet".to_string(),
            channel_id.clone(),
            string_root("DEVNET-SPONSOR-BUDGET", "budget"),
            4_000,
            self.config.sponsor_rebate_bps,
        )?;
        if let Some(sponsorship) = self.sponsorships.get_mut(&sponsorship_id) {
            sponsorship.status = SponsorStatus::Active;
        }
        let hop_id = self.route_cross_rollup_hop(
            channel_id.clone(),
            "nebula-l2-devnet-a".to_string(),
            "nebula-l2-devnet-b".to_string(),
            string_root("DEVNET-HOP-BRIDGE", "bridge"),
            string_root("DEVNET-HOP-LOCK", "lock"),
        )?;
        if let Some(hop) = self.hops.get_mut(&hop_id) {
            hop.status = HopStatus::Acknowledged;
            hop.ack_root = string_root("DEVNET-HOP-ACK", "ack");
        }
        let exit_id = self.request_pq_cosigned_exit(
            channel_id.clone(),
            string_root("DEVNET-STATE", "updated"),
            string_root("DEVNET-EXIT", "exit"),
            string_root("DEVNET-COSIGN", "pq-cosign"),
            string_root("DEVNET-SETTLEMENT-ADDRESS", "stealth"),
        )?;
        if let Some(update) = self.updates.get_mut(&update_id) {
            update.status = UpdateStatus::Settled;
        }
        if let Some(exit) = self.exits.get_mut(&exit_id) {
            exit.status = ExitStatus::ReadyToSettle;
            exit.settle_after_height = self.height;
        }
        let receipt_id = self.settle_exit_receipt(
            exit_id,
            string_root("DEVNET-SETTLEMENT", "settled"),
            string_root("DEVNET-NULLIFIER", "receipt"),
        )?;
        if let Some(receipt) = self.receipts.get_mut(&receipt_id) {
            receipt.status = ReceiptStatus::Finalized;
        }
        Ok(())
    }
}

pub fn devnet() -> FastPrivateStateChannelRouterResult<State> {
    State::devnet()
}

impl Participant {
    pub fn public_record(&self) -> Value {
        <Self as RouterRecord>::public_record(self)
    }
    pub fn root(&self) -> String {
        <Self as RouterRecord>::root(self)
    }
}

impl PrivateChannelOpen {
    pub fn public_record(&self) -> Value {
        <Self as RouterRecord>::public_record(self)
    }
    pub fn root(&self) -> String {
        <Self as RouterRecord>::root(self)
    }
}

impl ZkStateUpdate {
    pub fn public_record(&self) -> Value {
        <Self as RouterRecord>::public_record(self)
    }
    pub fn root(&self) -> String {
        <Self as RouterRecord>::root(self)
    }
}

impl PqCoSignedExit {
    pub fn public_record(&self) -> Value {
        <Self as RouterRecord>::public_record(self)
    }
    pub fn root(&self) -> String {
        <Self as RouterRecord>::root(self)
    }
}

impl RouteSponsorship {
    pub fn public_record(&self) -> Value {
        <Self as RouterRecord>::public_record(self)
    }
    pub fn root(&self) -> String {
        <Self as RouterRecord>::root(self)
    }
}

impl CrossRollupHop {
    pub fn public_record(&self) -> Value {
        <Self as RouterRecord>::public_record(self)
    }
    pub fn root(&self) -> String {
        <Self as RouterRecord>::root(self)
    }
}

impl ChannelDispute {
    pub fn public_record(&self) -> Value {
        <Self as RouterRecord>::public_record(self)
    }
    pub fn root(&self) -> String {
        <Self as RouterRecord>::root(self)
    }
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        <Self as RouterRecord>::public_record(self)
    }
    pub fn root(&self) -> String {
        <Self as RouterRecord>::root(self)
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        <Self as RouterRecord>::public_record(self)
    }
    pub fn root(&self) -> String {
        <Self as RouterRecord>::root(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn devnet_state_validates() {
        let state = devnet();
        assert!(state.is_ok());
    }
}
