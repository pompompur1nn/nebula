use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type StateChannelResult<T> = Result<T, String>;

pub const STATE_CHANNEL_PROTOCOL_VERSION: &str = "nebula-state-channel-v1";
pub const STATE_CHANNEL_PQ_AUTH_SCHEME: &str = "ML-DSA-65";
pub const STATE_CHANNEL_RECOVERY_AUTH_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const STATE_CHANNEL_KEM_SCHEME: &str = "ML-KEM-768";
pub const STATE_CHANNEL_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const STATE_CHANNEL_DEFAULT_UPDATE_TTL_BLOCKS: u64 = 24;
pub const STATE_CHANNEL_DEFAULT_WATCHTOWER_TTL_BLOCKS: u64 = 96;
pub const STATE_CHANNEL_DEFAULT_RELAY_TTL_BLOCKS: u64 = 16;
pub const STATE_CHANNEL_DEFAULT_MAX_PARTICIPANTS: u64 = 8;
pub const STATE_CHANNEL_DEFAULT_MAX_VIRTUAL_HOPS: u64 = 4;
pub const STATE_CHANNEL_DEFAULT_MIN_BOND_UNITS: u64 = 4;
pub const STATE_CHANNEL_DEFAULT_LOW_FEE_CREDITS: u64 = 16;
pub const STATE_CHANNEL_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const STATE_CHANNEL_DEFAULT_SETTLEMENT_ASSET_ID: &str = "wxmr-devnet";
pub const STATE_CHANNEL_MAX_BPS: u64 = 10_000;
pub const STATE_CHANNEL_STATUS_ACTIVE: &str = "active";
pub const STATE_CHANNEL_STATUS_PENDING: &str = "pending";
pub const STATE_CHANNEL_STATUS_OPEN: &str = "open";
pub const STATE_CHANNEL_STATUS_LOCKED: &str = "locked";
pub const STATE_CHANNEL_STATUS_UPDATED: &str = "updated";
pub const STATE_CHANNEL_STATUS_DISPUTED: &str = "disputed";
pub const STATE_CHANNEL_STATUS_CLOSING: &str = "closing";
pub const STATE_CHANNEL_STATUS_SETTLED: &str = "settled";
pub const STATE_CHANNEL_STATUS_EXPIRED: &str = "expired";
pub const STATE_CHANNEL_STATUS_REJECTED: &str = "rejected";
pub const STATE_CHANNEL_STATUS_PAUSED: &str = "paused";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChannelKind {
    Payment,
    PrivatePayment,
    ContractSession,
    AmmSession,
    MoneroSwap,
    VirtualHub,
}

impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Payment => "payment",
            Self::PrivatePayment => "private_payment",
            Self::ContractSession => "contract_session",
            Self::AmmSession => "amm_session",
            Self::MoneroSwap => "monero_swap",
            Self::VirtualHub => "virtual_hub",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChannelVisibility {
    Public,
    CommitmentOnly,
    Encrypted,
    Shielded,
}

impl ChannelVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::CommitmentOnly => "commitment_only",
            Self::Encrypted => "encrypted",
            Self::Shielded => "shielded",
        }
    }

    pub fn private(self) -> bool {
        matches!(self, Self::Encrypted | Self::Shielded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChannelUpdateKind {
    Balance,
    ContractState,
    VirtualRoute,
    FeeRebate,
    WatchtowerRefresh,
    CooperativeClose,
}

impl ChannelUpdateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Balance => "balance",
            Self::ContractState => "contract_state",
            Self::VirtualRoute => "virtual_route",
            Self::FeeRebate => "fee_rebate",
            Self::WatchtowerRefresh => "watchtower_refresh",
            Self::CooperativeClose => "cooperative_close",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChannelDisputeKind {
    StaleUpdate,
    InvalidSignature,
    MissingPreimage,
    CounterpartyOffline,
    WatchtowerEvidence,
    MoneroTimeout,
}

impl ChannelDisputeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleUpdate => "stale_update",
            Self::InvalidSignature => "invalid_signature",
            Self::MissingPreimage => "missing_preimage",
            Self::CounterpartyOffline => "counterparty_offline",
            Self::WatchtowerEvidence => "watchtower_evidence",
            Self::MoneroTimeout => "monero_timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChannelSettlementKind {
    Cooperative,
    ChallengeTimeout,
    MoneroAtomicClose,
    ContractClose,
    WatchtowerRescue,
}

impl ChannelSettlementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cooperative => "cooperative",
            Self::ChallengeTimeout => "challenge_timeout",
            Self::MoneroAtomicClose => "monero_atomic_close",
            Self::ContractClose => "contract_close",
            Self::WatchtowerRescue => "watchtower_rescue",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChannelRelayKind {
    UserPaid,
    LowFeeSponsored,
    WatchtowerSponsored,
    LiquidityProviderSponsored,
}

impl ChannelRelayKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPaid => "user_paid",
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::WatchtowerSponsored => "watchtower_sponsored",
            Self::LiquidityProviderSponsored => "liquidity_provider_sponsored",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub config_id: String,
    pub challenge_window_blocks: u64,
    pub update_ttl_blocks: u64,
    pub watchtower_ttl_blocks: u64,
    pub relay_ttl_blocks: u64,
    pub max_participants: u64,
    pub max_virtual_hops: u64,
    pub min_bond_units: u64,
    pub default_fee_asset_id: String,
    pub pq_auth_scheme: String,
    pub recovery_auth_scheme: String,
    pub kem_scheme: String,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            challenge_window_blocks: STATE_CHANNEL_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            update_ttl_blocks: STATE_CHANNEL_DEFAULT_UPDATE_TTL_BLOCKS,
            watchtower_ttl_blocks: STATE_CHANNEL_DEFAULT_WATCHTOWER_TTL_BLOCKS,
            relay_ttl_blocks: STATE_CHANNEL_DEFAULT_RELAY_TTL_BLOCKS,
            max_participants: STATE_CHANNEL_DEFAULT_MAX_PARTICIPANTS,
            max_virtual_hops: STATE_CHANNEL_DEFAULT_MAX_VIRTUAL_HOPS,
            min_bond_units: STATE_CHANNEL_DEFAULT_MIN_BOND_UNITS,
            default_fee_asset_id: STATE_CHANNEL_DEFAULT_FEE_ASSET_ID.to_string(),
            pq_auth_scheme: STATE_CHANNEL_PQ_AUTH_SCHEME.to_string(),
            recovery_auth_scheme: STATE_CHANNEL_RECOVERY_AUTH_SCHEME.to_string(),
            kem_scheme: STATE_CHANNEL_KEM_SCHEME.to_string(),
        };
        config.config_id = state_channel_config_id(&config.public_record_without_id());
        config
    }
}

impl ChannelConfig {
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "state_channel_config",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "challenge_window_blocks": self.challenge_window_blocks,
            "update_ttl_blocks": self.update_ttl_blocks,
            "watchtower_ttl_blocks": self.watchtower_ttl_blocks,
            "relay_ttl_blocks": self.relay_ttl_blocks,
            "max_participants": self.max_participants,
            "max_virtual_hops": self.max_virtual_hops,
            "min_bond_units": self.min_bond_units,
            "default_fee_asset_id": self.default_fee_asset_id,
            "pq_auth_scheme": self.pq_auth_scheme,
            "recovery_auth_scheme": self.recovery_auth_scheme,
            "kem_scheme": self.kem_scheme,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record
            .as_object_mut()
            .expect("channel config record")
            .insert(
                "config_id".to_string(),
                Value::String(self.config_id.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelParticipant {
    pub participant_id: String,
    pub label: String,
    pub owner_commitment: String,
    pub pq_key_root: String,
    pub recovery_key_root: String,
    pub view_tag_root: String,
    pub role_root: String,
    pub collateral_asset_id: String,
    pub collateral_units: u64,
    pub status: String,
}

impl ChannelParticipant {
    pub fn new(
        label: impl Into<String>,
        owner_hint: &str,
        roles: &[String],
        collateral_asset_id: impl Into<String>,
        collateral_units: u64,
    ) -> StateChannelResult<Self> {
        let label = normalize_label(label.into());
        let collateral_asset_id = collateral_asset_id.into();
        ensure_non_empty(&label, "channel participant label")?;
        ensure_non_empty(owner_hint, "channel participant owner")?;
        ensure_non_empty(&collateral_asset_id, "channel participant asset")?;
        let owner_commitment = state_channel_string_root("CHANNEL-PARTICIPANT-OWNER", owner_hint);
        let pq_key_root = state_channel_string_root("CHANNEL-PARTICIPANT-PQ-KEY", owner_hint);
        let recovery_key_root =
            state_channel_string_root("CHANNEL-PARTICIPANT-RECOVERY-KEY", owner_hint);
        let view_tag_root = state_channel_string_root("CHANNEL-PARTICIPANT-VIEW-TAG", &label);
        let role_root = state_channel_string_set_root("CHANNEL-PARTICIPANT-ROLE", roles);
        let participant_id =
            state_channel_participant_id(&label, &owner_commitment, &pq_key_root, &role_root);
        Ok(Self {
            participant_id,
            label,
            owner_commitment,
            pq_key_root,
            recovery_key_root,
            view_tag_root,
            role_root,
            collateral_asset_id,
            collateral_units,
            status: STATE_CHANNEL_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_participant",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "participant_id": self.participant_id,
            "label": self.label,
            "owner_commitment": self.owner_commitment,
            "pq_key_root": self.pq_key_root,
            "recovery_key_root": self.recovery_key_root,
            "view_tag_root": self.view_tag_root,
            "role_root": self.role_root,
            "collateral_asset_id": self.collateral_asset_id,
            "collateral_units": self.collateral_units,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelPolicy {
    pub policy_id: String,
    pub channel_kind: ChannelKind,
    pub visibility: ChannelVisibility,
    pub asset_root: String,
    pub participant_root: String,
    pub max_update_delta_units: u64,
    pub max_pending_updates: u64,
    pub challenge_window_blocks: u64,
    pub require_watchtower: bool,
    pub monero_close_enabled: bool,
    pub contract_hooks_enabled: bool,
    pub status: String,
}

impl ChannelPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel_kind: ChannelKind,
        visibility: ChannelVisibility,
        asset_ids: &[String],
        participants: &[ChannelParticipant],
        max_update_delta_units: u64,
        max_pending_updates: u64,
        challenge_window_blocks: u64,
        require_watchtower: bool,
        monero_close_enabled: bool,
        contract_hooks_enabled: bool,
    ) -> StateChannelResult<Self> {
        ensure_positive(max_pending_updates, "channel max pending updates")?;
        ensure_positive(challenge_window_blocks, "channel challenge window")?;
        let asset_root = state_channel_string_set_root("CHANNEL-POLICY-ASSET", asset_ids);
        let participant_root = state_channel_participant_root(participants);
        let policy_id = state_channel_policy_id(
            channel_kind,
            visibility,
            &asset_root,
            &participant_root,
            challenge_window_blocks,
        );
        Ok(Self {
            policy_id,
            channel_kind,
            visibility,
            asset_root,
            participant_root,
            max_update_delta_units,
            max_pending_updates,
            challenge_window_blocks,
            require_watchtower,
            monero_close_enabled,
            contract_hooks_enabled,
            status: STATE_CHANNEL_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "channel_kind": self.channel_kind.as_str(),
            "visibility": self.visibility.as_str(),
            "asset_root": self.asset_root,
            "participant_root": self.participant_root,
            "max_update_delta_units": self.max_update_delta_units,
            "max_pending_updates": self.max_pending_updates,
            "challenge_window_blocks": self.challenge_window_blocks,
            "require_watchtower": self.require_watchtower,
            "monero_close_enabled": self.monero_close_enabled,
            "contract_hooks_enabled": self.contract_hooks_enabled,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelOpenRequest {
    pub request_id: String,
    pub channel_kind: ChannelKind,
    pub visibility: ChannelVisibility,
    pub participant_root: String,
    pub policy_id: String,
    pub funding_root: String,
    pub initial_state_root: String,
    pub route_hint_root: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ChannelOpenRequest {
    pub fn new(
        channel_kind: ChannelKind,
        visibility: ChannelVisibility,
        participants: &[ChannelParticipant],
        policy_id: &str,
        funding: &Value,
        initial_state: &Value,
        route_hints: &[String],
        height: u64,
        ttl_blocks: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(policy_id, "channel open policy")?;
        ensure_positive(ttl_blocks, "channel open ttl")?;
        let participant_root = state_channel_participant_root(participants);
        let funding_root = state_channel_payload_root("CHANNEL-OPEN-FUNDING", funding);
        let initial_state_root =
            state_channel_payload_root("CHANNEL-OPEN-INITIAL-STATE", initial_state);
        let route_hint_root = state_channel_string_set_root("CHANNEL-OPEN-ROUTE-HINT", route_hints);
        let request_id = state_channel_open_request_id(
            channel_kind,
            visibility,
            &participant_root,
            policy_id,
            &funding_root,
            height,
        );
        Ok(Self {
            request_id,
            channel_kind,
            visibility,
            participant_root,
            policy_id: policy_id.to_string(),
            funding_root,
            initial_state_root,
            route_hint_root,
            requested_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
            status: STATE_CHANNEL_STATUS_PENDING.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_open_request",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "request_id": self.request_id,
            "channel_kind": self.channel_kind.as_str(),
            "visibility": self.visibility.as_str(),
            "participant_root": self.participant_root,
            "policy_id": self.policy_id,
            "funding_root": self.funding_root,
            "initial_state_root": self.initial_state_root,
            "route_hint_root": self.route_hint_root,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelFundingLock {
    pub lock_id: String,
    pub request_id: String,
    pub participant_id: String,
    pub asset_id: String,
    pub amount_units: u64,
    pub funding_tx_root: String,
    pub monero_anchor_root: String,
    pub locked_at_height: u64,
    pub unlock_after_height: u64,
    pub status: String,
}

impl ChannelFundingLock {
    pub fn new(
        request_id: &str,
        participant_id: &str,
        asset_id: &str,
        amount_units: u64,
        funding_tx: &Value,
        monero_anchor: &Value,
        height: u64,
        challenge_window_blocks: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(request_id, "channel funding request")?;
        ensure_non_empty(participant_id, "channel funding participant")?;
        ensure_non_empty(asset_id, "channel funding asset")?;
        ensure_positive(amount_units, "channel funding amount")?;
        let funding_tx_root = state_channel_payload_root("CHANNEL-FUNDING-TX", funding_tx);
        let monero_anchor_root =
            state_channel_payload_root("CHANNEL-FUNDING-MONERO", monero_anchor);
        let lock_id = state_channel_funding_lock_id(
            request_id,
            participant_id,
            asset_id,
            amount_units,
            &funding_tx_root,
        );
        Ok(Self {
            lock_id,
            request_id: request_id.to_string(),
            participant_id: participant_id.to_string(),
            asset_id: asset_id.to_string(),
            amount_units,
            funding_tx_root,
            monero_anchor_root,
            locked_at_height: height,
            unlock_after_height: height.saturating_add(challenge_window_blocks),
            status: STATE_CHANNEL_STATUS_LOCKED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_funding_lock",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "lock_id": self.lock_id,
            "request_id": self.request_id,
            "participant_id": self.participant_id,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "funding_tx_root": self.funding_tx_root,
            "monero_anchor_root": self.monero_anchor_root,
            "locked_at_height": self.locked_at_height,
            "unlock_after_height": self.unlock_after_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelBalanceCommitment {
    pub balance_id: String,
    pub channel_id: String,
    pub participant_id: String,
    pub asset_id: String,
    pub amount_bucket: u64,
    pub balance_commitment: String,
    pub blinding_root: String,
    pub status: String,
}

impl ChannelBalanceCommitment {
    pub fn new(
        channel_id: &str,
        participant_id: &str,
        asset_id: &str,
        amount_units: u64,
        blinding_hint: &str,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(channel_id, "channel balance channel")?;
        ensure_non_empty(participant_id, "channel balance participant")?;
        ensure_non_empty(asset_id, "channel balance asset")?;
        let amount_bucket = state_channel_amount_bucket(amount_units);
        let balance_commitment = state_channel_payload_root(
            "CHANNEL-BALANCE-COMMITMENT",
            &json!({
                "channel_id": channel_id,
                "participant_id": participant_id,
                "asset_id": asset_id,
                "amount_bucket": amount_bucket,
            }),
        );
        let blinding_root = state_channel_string_root("CHANNEL-BALANCE-BLINDING", blinding_hint);
        let balance_id = state_channel_balance_id(
            channel_id,
            participant_id,
            asset_id,
            amount_bucket,
            &balance_commitment,
        );
        Ok(Self {
            balance_id,
            channel_id: channel_id.to_string(),
            participant_id: participant_id.to_string(),
            asset_id: asset_id.to_string(),
            amount_bucket,
            balance_commitment,
            blinding_root,
            status: STATE_CHANNEL_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_balance_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "balance_id": self.balance_id,
            "channel_id": self.channel_id,
            "participant_id": self.participant_id,
            "asset_id": self.asset_id,
            "amount_bucket": self.amount_bucket,
            "balance_commitment": self.balance_commitment,
            "blinding_root": self.blinding_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelStateUpdate {
    pub update_id: String,
    pub channel_id: String,
    pub update_kind: ChannelUpdateKind,
    pub sequence: u64,
    pub previous_update_id: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub balance_root: String,
    pub contract_delta_root: String,
    pub pq_auth_transcript_root: String,
    pub participant_signature_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ChannelStateUpdate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel_id: &str,
        update_kind: ChannelUpdateKind,
        sequence: u64,
        previous_update_id: &str,
        state_before: &Value,
        state_after: &Value,
        balances: &[ChannelBalanceCommitment],
        contract_delta: &Value,
        participants: &[ChannelParticipant],
        height: u64,
        ttl_blocks: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(channel_id, "channel update channel")?;
        ensure_positive(sequence, "channel update sequence")?;
        let state_root_before = state_channel_payload_root("CHANNEL-STATE-BEFORE", state_before);
        let state_root_after = state_channel_payload_root("CHANNEL-STATE-AFTER", state_after);
        let balance_root = state_channel_balance_root(balances);
        let contract_delta_root =
            state_channel_payload_root("CHANNEL-CONTRACT-DELTA", contract_delta);
        let pq_auth_transcript_root = state_channel_payload_root(
            "CHANNEL-PQ-AUTH-TRANSCRIPT",
            &json!({
                "channel_id": channel_id,
                "sequence": sequence,
                "before": state_root_before,
                "after": state_root_after,
                "scheme": STATE_CHANNEL_PQ_AUTH_SCHEME,
            }),
        );
        let participant_signature_root =
            state_channel_participant_signature_root(participants, sequence);
        let update_id = state_channel_update_id(
            channel_id,
            update_kind,
            sequence,
            previous_update_id,
            &state_root_after,
            &pq_auth_transcript_root,
        );
        Ok(Self {
            update_id,
            channel_id: channel_id.to_string(),
            update_kind,
            sequence,
            previous_update_id: previous_update_id.to_string(),
            state_root_before,
            state_root_after,
            balance_root,
            contract_delta_root,
            pq_auth_transcript_root,
            participant_signature_root,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
            status: STATE_CHANNEL_STATUS_UPDATED.to_string(),
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height && self.status == STATE_CHANNEL_STATUS_UPDATED
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_update",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "update_id": self.update_id,
            "channel_id": self.channel_id,
            "update_kind": self.update_kind.as_str(),
            "sequence": self.sequence,
            "previous_update_id": self.previous_update_id,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "balance_root": self.balance_root,
            "contract_delta_root": self.contract_delta_root,
            "pq_auth_transcript_root": self.pq_auth_transcript_root,
            "participant_signature_root": self.participant_signature_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCheckpoint {
    pub checkpoint_id: String,
    pub channel_id: String,
    pub latest_update_id: String,
    pub latest_sequence: u64,
    pub balance_root: String,
    pub virtual_link_root: String,
    pub watchtower_root: String,
    pub checkpointed_at_height: u64,
    pub status: String,
}

impl ChannelCheckpoint {
    pub fn new(
        channel_id: &str,
        latest_update: &ChannelStateUpdate,
        virtual_links: &[VirtualChannelLink],
        watchtowers: &[ChannelWatchtowerAttestation],
        height: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(channel_id, "channel checkpoint channel")?;
        let virtual_link_root = state_channel_virtual_link_root(virtual_links);
        let watchtower_root = state_channel_watchtower_root(watchtowers);
        let checkpoint_id = state_channel_checkpoint_id(
            channel_id,
            &latest_update.update_id,
            latest_update.sequence,
            &latest_update.balance_root,
            &virtual_link_root,
        );
        Ok(Self {
            checkpoint_id,
            channel_id: channel_id.to_string(),
            latest_update_id: latest_update.update_id.clone(),
            latest_sequence: latest_update.sequence,
            balance_root: latest_update.balance_root.clone(),
            virtual_link_root,
            watchtower_root,
            checkpointed_at_height: height,
            status: STATE_CHANNEL_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "channel_id": self.channel_id,
            "latest_update_id": self.latest_update_id,
            "latest_sequence": self.latest_sequence,
            "balance_root": self.balance_root,
            "virtual_link_root": self.virtual_link_root,
            "watchtower_root": self.watchtower_root,
            "checkpointed_at_height": self.checkpointed_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualChannelLink {
    pub link_id: String,
    pub parent_channel_id: String,
    pub child_channel_id: String,
    pub route_root: String,
    pub hop_count: u64,
    pub liquidity_commitment: String,
    pub expires_at_height: u64,
    pub status: String,
}

impl VirtualChannelLink {
    pub fn new(
        parent_channel_id: &str,
        child_channel_id: &str,
        route_hops: &[String],
        liquidity_hint: &str,
        height: u64,
        ttl_blocks: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(parent_channel_id, "virtual channel parent")?;
        ensure_non_empty(child_channel_id, "virtual channel child")?;
        ensure_positive(ttl_blocks, "virtual channel ttl")?;
        let route_root = state_channel_string_set_root("CHANNEL-VIRTUAL-ROUTE", route_hops);
        let hop_count = route_hops.len() as u64;
        let liquidity_commitment =
            state_channel_string_root("CHANNEL-VIRTUAL-LIQUIDITY", liquidity_hint);
        let link_id = state_channel_virtual_link_id(
            parent_channel_id,
            child_channel_id,
            &route_root,
            &liquidity_commitment,
        );
        Ok(Self {
            link_id,
            parent_channel_id: parent_channel_id.to_string(),
            child_channel_id: child_channel_id.to_string(),
            route_root,
            hop_count,
            liquidity_commitment,
            expires_at_height: height.saturating_add(ttl_blocks),
            status: STATE_CHANNEL_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "virtual_channel_link",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "link_id": self.link_id,
            "parent_channel_id": self.parent_channel_id,
            "child_channel_id": self.child_channel_id,
            "route_root": self.route_root,
            "hop_count": self.hop_count,
            "liquidity_commitment": self.liquidity_commitment,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelDispute {
    pub dispute_id: String,
    pub channel_id: String,
    pub dispute_kind: ChannelDisputeKind,
    pub challenged_update_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub response_due_height: u64,
    pub bond_units: u64,
    pub status: String,
}

impl ChannelDispute {
    pub fn new(
        channel_id: &str,
        dispute_kind: ChannelDisputeKind,
        challenged_update_id: &str,
        challenger_hint: &str,
        evidence: &Value,
        height: u64,
        challenge_window_blocks: u64,
        bond_units: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(channel_id, "channel dispute channel")?;
        ensure_non_empty(challenged_update_id, "channel dispute update")?;
        ensure_non_empty(challenger_hint, "channel dispute challenger")?;
        ensure_positive(challenge_window_blocks, "channel dispute window")?;
        let challenger_commitment =
            state_channel_string_root("CHANNEL-DISPUTE-CHALLENGER", challenger_hint);
        let evidence_root = state_channel_payload_root("CHANNEL-DISPUTE-EVIDENCE", evidence);
        let dispute_id = state_channel_dispute_id(
            channel_id,
            dispute_kind,
            challenged_update_id,
            &challenger_commitment,
            &evidence_root,
        );
        Ok(Self {
            dispute_id,
            channel_id: channel_id.to_string(),
            dispute_kind,
            challenged_update_id: challenged_update_id.to_string(),
            challenger_commitment,
            evidence_root,
            opened_at_height: height,
            response_due_height: height.saturating_add(challenge_window_blocks),
            bond_units,
            status: STATE_CHANNEL_STATUS_DISPUTED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_dispute",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "dispute_id": self.dispute_id,
            "channel_id": self.channel_id,
            "dispute_kind": self.dispute_kind.as_str(),
            "challenged_update_id": self.challenged_update_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "response_due_height": self.response_due_height,
            "bond_units": self.bond_units,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelDisputeResponse {
    pub response_id: String,
    pub dispute_id: String,
    pub respondent_commitment: String,
    pub newer_update_id: String,
    pub newer_sequence: u64,
    pub proof_root: String,
    pub responded_at_height: u64,
    pub status: String,
}

impl ChannelDisputeResponse {
    pub fn new(
        dispute_id: &str,
        respondent_hint: &str,
        newer_update: &ChannelStateUpdate,
        proof: &Value,
        height: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(dispute_id, "channel dispute response dispute")?;
        ensure_non_empty(respondent_hint, "channel dispute response respondent")?;
        let respondent_commitment =
            state_channel_string_root("CHANNEL-DISPUTE-RESPONDENT", respondent_hint);
        let proof_root = state_channel_payload_root("CHANNEL-DISPUTE-RESPONSE-PROOF", proof);
        let response_id = state_channel_dispute_response_id(
            dispute_id,
            &respondent_commitment,
            &newer_update.update_id,
            newer_update.sequence,
            &proof_root,
        );
        Ok(Self {
            response_id,
            dispute_id: dispute_id.to_string(),
            respondent_commitment,
            newer_update_id: newer_update.update_id.clone(),
            newer_sequence: newer_update.sequence,
            proof_root,
            responded_at_height: height,
            status: STATE_CHANNEL_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_dispute_response",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "response_id": self.response_id,
            "dispute_id": self.dispute_id,
            "respondent_commitment": self.respondent_commitment,
            "newer_update_id": self.newer_update_id,
            "newer_sequence": self.newer_sequence,
            "proof_root": self.proof_root,
            "responded_at_height": self.responded_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCloseIntent {
    pub close_id: String,
    pub channel_id: String,
    pub settlement_kind: ChannelSettlementKind,
    pub final_update_id: String,
    pub final_balance_root: String,
    pub monero_close_root: String,
    pub contract_close_root: String,
    pub requested_at_height: u64,
    pub executable_at_height: u64,
    pub status: String,
}

impl ChannelCloseIntent {
    pub fn new(
        channel_id: &str,
        settlement_kind: ChannelSettlementKind,
        final_update: &ChannelStateUpdate,
        monero_close: &Value,
        contract_close: &Value,
        height: u64,
        challenge_window_blocks: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(channel_id, "channel close channel")?;
        let monero_close_root = state_channel_payload_root("CHANNEL-CLOSE-MONERO", monero_close);
        let contract_close_root =
            state_channel_payload_root("CHANNEL-CLOSE-CONTRACT", contract_close);
        let close_id = state_channel_close_intent_id(
            channel_id,
            settlement_kind,
            &final_update.update_id,
            &final_update.balance_root,
            &monero_close_root,
        );
        Ok(Self {
            close_id,
            channel_id: channel_id.to_string(),
            settlement_kind,
            final_update_id: final_update.update_id.clone(),
            final_balance_root: final_update.balance_root.clone(),
            monero_close_root,
            contract_close_root,
            requested_at_height: height,
            executable_at_height: height.saturating_add(challenge_window_blocks),
            status: STATE_CHANNEL_STATUS_CLOSING.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_close_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "close_id": self.close_id,
            "channel_id": self.channel_id,
            "settlement_kind": self.settlement_kind.as_str(),
            "final_update_id": self.final_update_id,
            "final_balance_root": self.final_balance_root,
            "monero_close_root": self.monero_close_root,
            "contract_close_root": self.contract_close_root,
            "requested_at_height": self.requested_at_height,
            "executable_at_height": self.executable_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSettlementReceipt {
    pub receipt_id: String,
    pub close_id: String,
    pub channel_id: String,
    pub settlement_kind: ChannelSettlementKind,
    pub final_balance_root: String,
    pub settlement_tx_root: String,
    pub fee_asset_id: String,
    pub fee_units: u64,
    pub settled_at_height: u64,
    pub status: String,
}

impl ChannelSettlementReceipt {
    pub fn new(
        close: &ChannelCloseIntent,
        settlement_tx: &Value,
        fee_asset_id: &str,
        fee_units: u64,
        height: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(fee_asset_id, "channel settlement fee asset")?;
        let settlement_tx_root = state_channel_payload_root("CHANNEL-SETTLEMENT-TX", settlement_tx);
        let receipt_id =
            state_channel_settlement_receipt_id(&close.close_id, &settlement_tx_root, height);
        Ok(Self {
            receipt_id,
            close_id: close.close_id.clone(),
            channel_id: close.channel_id.clone(),
            settlement_kind: close.settlement_kind,
            final_balance_root: close.final_balance_root.clone(),
            settlement_tx_root,
            fee_asset_id: fee_asset_id.to_string(),
            fee_units,
            settled_at_height: height,
            status: STATE_CHANNEL_STATUS_SETTLED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "close_id": self.close_id,
            "channel_id": self.channel_id,
            "settlement_kind": self.settlement_kind.as_str(),
            "final_balance_root": self.final_balance_root,
            "settlement_tx_root": self.settlement_tx_root,
            "fee_asset_id": self.fee_asset_id,
            "fee_units": self.fee_units,
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRelayTicket {
    pub relay_ticket_id: String,
    pub channel_id: String,
    pub update_id: String,
    pub relay_kind: ChannelRelayKind,
    pub relayer_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub low_fee_credit_units: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ChannelRelayTicket {
    pub fn new(
        channel_id: &str,
        update_id: &str,
        relay_kind: ChannelRelayKind,
        relayer_hint: &str,
        fee_asset_id: &str,
        max_fee_units: u64,
        low_fee_credit_units: u64,
        expires_at_height: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(channel_id, "channel relay channel")?;
        ensure_non_empty(update_id, "channel relay update")?;
        ensure_non_empty(relayer_hint, "channel relay relayer")?;
        ensure_non_empty(fee_asset_id, "channel relay fee asset")?;
        let relayer_commitment = state_channel_string_root("CHANNEL-RELAY-RELAYER", relayer_hint);
        let relay_ticket_id = state_channel_relay_ticket_id(
            channel_id,
            update_id,
            relay_kind,
            &relayer_commitment,
            expires_at_height,
        );
        Ok(Self {
            relay_ticket_id,
            channel_id: channel_id.to_string(),
            update_id: update_id.to_string(),
            relay_kind,
            relayer_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            low_fee_credit_units,
            expires_at_height,
            status: STATE_CHANNEL_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_relay_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "relay_ticket_id": self.relay_ticket_id,
            "channel_id": self.channel_id,
            "update_id": self.update_id,
            "relay_kind": self.relay_kind.as_str(),
            "relayer_commitment": self.relayer_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelWatchtowerAttestation {
    pub attestation_id: String,
    pub channel_id: String,
    pub watchtower_commitment: String,
    pub latest_update_id: String,
    pub latest_sequence: u64,
    pub encrypted_state_root: String,
    pub rescue_policy_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ChannelWatchtowerAttestation {
    pub fn new(
        channel_id: &str,
        watchtower_hint: &str,
        latest_update: &ChannelStateUpdate,
        encrypted_state: &Value,
        rescue_policy: &Value,
        height: u64,
        ttl_blocks: u64,
    ) -> StateChannelResult<Self> {
        ensure_non_empty(channel_id, "channel watchtower channel")?;
        ensure_non_empty(watchtower_hint, "channel watchtower")?;
        let watchtower_commitment =
            state_channel_string_root("CHANNEL-WATCHTOWER", watchtower_hint);
        let encrypted_state_root =
            state_channel_payload_root("CHANNEL-WATCHTOWER-STATE", encrypted_state);
        let rescue_policy_root =
            state_channel_payload_root("CHANNEL-WATCHTOWER-RESCUE", rescue_policy);
        let attestation_id = state_channel_watchtower_attestation_id(
            channel_id,
            &watchtower_commitment,
            &latest_update.update_id,
            latest_update.sequence,
            &encrypted_state_root,
        );
        Ok(Self {
            attestation_id,
            channel_id: channel_id.to_string(),
            watchtower_commitment,
            latest_update_id: latest_update.update_id.clone(),
            latest_sequence: latest_update.sequence,
            encrypted_state_root,
            rescue_policy_root,
            attested_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
            status: STATE_CHANNEL_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_watchtower_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "channel_id": self.channel_id,
            "watchtower_commitment": self.watchtower_commitment,
            "latest_update_id": self.latest_update_id,
            "latest_sequence": self.latest_sequence,
            "encrypted_state_root": self.encrypted_state_root,
            "rescue_policy_root": self.rescue_policy_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRecord {
    pub channel_id: String,
    pub request_id: String,
    pub channel_kind: ChannelKind,
    pub visibility: ChannelVisibility,
    pub participant_root: String,
    pub policy_id: String,
    pub funding_lock_root: String,
    pub latest_update_id: String,
    pub latest_sequence: u64,
    pub checkpoint_root: String,
    pub opened_at_height: u64,
    pub status: String,
}

impl ChannelRecord {
    pub fn open(
        request: &ChannelOpenRequest,
        funding_locks: &[ChannelFundingLock],
        latest_update: &ChannelStateUpdate,
        checkpoint: &ChannelCheckpoint,
        height: u64,
    ) -> Self {
        let funding_lock_root = state_channel_funding_lock_root(funding_locks);
        let checkpoint_root =
            state_channel_payload_root("CHANNEL-CHECKPOINT-ROOT-REF", &checkpoint.public_record());
        let channel_id = state_channel_id(
            &request.request_id,
            &request.participant_root,
            &funding_lock_root,
            &latest_update.update_id,
        );
        Self {
            channel_id,
            request_id: request.request_id.clone(),
            channel_kind: request.channel_kind,
            visibility: request.visibility,
            participant_root: request.participant_root.clone(),
            policy_id: request.policy_id.clone(),
            funding_lock_root,
            latest_update_id: latest_update.update_id.clone(),
            latest_sequence: latest_update.sequence,
            checkpoint_root,
            opened_at_height: height,
            status: STATE_CHANNEL_STATUS_OPEN.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_channel_record",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "channel_id": self.channel_id,
            "request_id": self.request_id,
            "channel_kind": self.channel_kind.as_str(),
            "visibility": self.visibility.as_str(),
            "participant_root": self.participant_root,
            "policy_id": self.policy_id,
            "funding_lock_root": self.funding_lock_root,
            "latest_update_id": self.latest_update_id,
            "latest_sequence": self.latest_sequence,
            "checkpoint_root": self.checkpoint_root,
            "opened_at_height": self.opened_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateChannelState {
    pub height: u64,
    pub config: ChannelConfig,
    pub participants: BTreeMap<String, ChannelParticipant>,
    pub policies: BTreeMap<String, ChannelPolicy>,
    pub open_requests: BTreeMap<String, ChannelOpenRequest>,
    pub funding_locks: BTreeMap<String, ChannelFundingLock>,
    pub channels: BTreeMap<String, ChannelRecord>,
    pub balances: BTreeMap<String, ChannelBalanceCommitment>,
    pub updates: BTreeMap<String, ChannelStateUpdate>,
    pub checkpoints: BTreeMap<String, ChannelCheckpoint>,
    pub virtual_links: BTreeMap<String, VirtualChannelLink>,
    pub disputes: BTreeMap<String, ChannelDispute>,
    pub dispute_responses: BTreeMap<String, ChannelDisputeResponse>,
    pub close_intents: BTreeMap<String, ChannelCloseIntent>,
    pub settlement_receipts: BTreeMap<String, ChannelSettlementReceipt>,
    pub relay_tickets: BTreeMap<String, ChannelRelayTicket>,
    pub watchtower_attestations: BTreeMap<String, ChannelWatchtowerAttestation>,
}

impl StateChannelState {
    pub fn new() -> Self {
        Self {
            config: ChannelConfig::default(),
            ..Self::default()
        }
    }

    pub fn devnet() -> StateChannelResult<Self> {
        let mut state = Self::new();
        state.height = 1;
        let alice = ChannelParticipant::new(
            "alice",
            "devnet-alice-channel-owner",
            &["payer".to_string(), "amm_user".to_string()],
            STATE_CHANNEL_DEFAULT_SETTLEMENT_ASSET_ID,
            100_000,
        )?;
        let bob = ChannelParticipant::new(
            "bob",
            "devnet-bob-channel-owner",
            &["payee".to_string(), "withdrawer".to_string()],
            STATE_CHANNEL_DEFAULT_SETTLEMENT_ASSET_ID,
            100_000,
        )?;
        let tower = ChannelParticipant::new(
            "watchtower",
            "devnet-watchtower-channel-owner",
            &["watchtower".to_string(), "rescue".to_string()],
            STATE_CHANNEL_DEFAULT_SETTLEMENT_ASSET_ID,
            25_000,
        )?;
        let alice_id = state.insert_participant(alice)?;
        let bob_id = state.insert_participant(bob)?;
        let tower_id = state.insert_participant(tower)?;
        let participants = state.participants.values().cloned().collect::<Vec<_>>();
        let policy = ChannelPolicy::new(
            ChannelKind::PrivatePayment,
            ChannelVisibility::Shielded,
            &[
                STATE_CHANNEL_DEFAULT_SETTLEMENT_ASSET_ID.to_string(),
                "usdd-devnet".to_string(),
            ],
            &participants,
            50_000,
            32,
            state.config.challenge_window_blocks,
            true,
            true,
            true,
        )?;
        let policy_id = state.insert_policy(policy)?;
        let request = ChannelOpenRequest::new(
            ChannelKind::PrivatePayment,
            ChannelVisibility::Shielded,
            &participants,
            &policy_id,
            &json!({"funding": "devnet-private-channel", "participants": [alice_id, bob_id, tower_id]}),
            &json!({"balances": "commitments-only", "sequence": 0}),
            &["private-payment".to_string(), "low-fee".to_string()],
            state.height,
            state.config.update_ttl_blocks,
        )?;
        let request_id = state.insert_open_request(request.clone())?;
        let locks = vec![
            ChannelFundingLock::new(
                &request_id,
                &participants[0].participant_id,
                STATE_CHANNEL_DEFAULT_SETTLEMENT_ASSET_ID,
                100_000,
                &json!({"l2_lock": "alice"}),
                &json!({"monero_anchor": "alice-fallback"}),
                state.height,
                state.config.challenge_window_blocks,
            )?,
            ChannelFundingLock::new(
                &request_id,
                &participants[1].participant_id,
                STATE_CHANNEL_DEFAULT_SETTLEMENT_ASSET_ID,
                100_000,
                &json!({"l2_lock": "bob"}),
                &json!({"monero_anchor": "bob-fallback"}),
                state.height,
                state.config.challenge_window_blocks,
            )?,
        ];
        for lock in locks.clone() {
            state.insert_funding_lock(lock)?;
        }
        let temporary_channel_id = state_channel_string_root("CHANNEL-DEVNET-TEMP", &request_id);
        let balances = vec![
            ChannelBalanceCommitment::new(
                &temporary_channel_id,
                &participants[0].participant_id,
                STATE_CHANNEL_DEFAULT_SETTLEMENT_ASSET_ID,
                100_000,
                "alice-balance-blinding",
            )?,
            ChannelBalanceCommitment::new(
                &temporary_channel_id,
                &participants[1].participant_id,
                STATE_CHANNEL_DEFAULT_SETTLEMENT_ASSET_ID,
                100_000,
                "bob-balance-blinding",
            )?,
        ];
        for balance in balances.clone() {
            state.insert_balance(balance)?;
        }
        let update0 = ChannelStateUpdate::new(
            &temporary_channel_id,
            ChannelUpdateKind::Balance,
            1,
            "",
            &json!({"sequence": 0}),
            &json!({"sequence": 1, "payment_bucket": 10_000}),
            &balances,
            &json!({"contract_delta": "none"}),
            &participants,
            state.height,
            state.config.update_ttl_blocks,
        )?;
        state.insert_update(update0.clone())?;
        let tower_attestation = ChannelWatchtowerAttestation::new(
            &temporary_channel_id,
            "devnet-watchtower",
            &update0,
            &json!({"encrypted_state": update0.state_root_after}),
            &json!({"rescue": "submit_latest_update"}),
            state.height,
            state.config.watchtower_ttl_blocks,
        )?;
        state.insert_watchtower_attestation(tower_attestation.clone())?;
        let checkpoint = ChannelCheckpoint::new(
            &temporary_channel_id,
            &update0,
            &[],
            &[tower_attestation.clone()],
            state.height,
        )?;
        state.insert_checkpoint(checkpoint.clone())?;
        let channel = ChannelRecord::open(&request, &locks, &update0, &checkpoint, state.height);
        let real_channel_id = state.insert_channel(channel)?;
        let relay = ChannelRelayTicket::new(
            &real_channel_id,
            &update0.update_id,
            ChannelRelayKind::LowFeeSponsored,
            "devnet-relayer",
            STATE_CHANNEL_DEFAULT_FEE_ASSET_ID,
            3,
            STATE_CHANNEL_DEFAULT_LOW_FEE_CREDITS,
            state.height.saturating_add(state.config.relay_ttl_blocks),
        )?;
        state.insert_relay_ticket(relay)?;
        let vlink = VirtualChannelLink::new(
            &real_channel_id,
            "devnet-amm-session",
            &[
                "alice".to_string(),
                "nebula-hub".to_string(),
                "amm-contract".to_string(),
            ],
            "devnet-virtual-liquidity",
            state.height,
            state.config.update_ttl_blocks,
        )?;
        state.insert_virtual_link(vlink)?;
        let dispute = ChannelDispute::new(
            &real_channel_id,
            ChannelDisputeKind::StaleUpdate,
            &update0.update_id,
            "devnet-watchtower",
            &json!({"stale_sequence": 0, "latest_sequence": 1}),
            state.height,
            state.config.challenge_window_blocks,
            state.config.min_bond_units,
        )?;
        let dispute_id = state.insert_dispute(dispute.clone())?;
        let response = ChannelDisputeResponse::new(
            &dispute_id,
            "devnet-alice",
            &update0,
            &json!({"newer_update_root": update0.state_root_after}),
            state.height,
        )?;
        state.insert_dispute_response(response)?;
        let close = ChannelCloseIntent::new(
            &real_channel_id,
            ChannelSettlementKind::Cooperative,
            &update0,
            &json!({"monero_close": "not-needed"}),
            &json!({"contract_close": "release-balances"}),
            state.height,
            state.config.challenge_window_blocks,
        )?;
        let close_id = state.insert_close_intent(close.clone())?;
        let receipt = ChannelSettlementReceipt::new(
            &close,
            &json!({"settlement": "devnet-cooperative-close"}),
            STATE_CHANNEL_DEFAULT_FEE_ASSET_ID,
            2,
            state.height,
        )?;
        state.insert_settlement_receipt(receipt)?;
        if let Some(close) = state.close_intents.get_mut(&close_id) {
            close.status = STATE_CHANNEL_STATUS_SETTLED.to_string();
        }
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for request in self.open_requests.values_mut() {
            if height > request.expires_at_height && request.status == STATE_CHANNEL_STATUS_PENDING
            {
                request.status = STATE_CHANNEL_STATUS_EXPIRED.to_string();
            }
        }
        for update in self.updates.values_mut() {
            if height > update.expires_at_height && update.status == STATE_CHANNEL_STATUS_UPDATED {
                update.status = STATE_CHANNEL_STATUS_EXPIRED.to_string();
            }
        }
        for ticket in self.relay_tickets.values_mut() {
            if height > ticket.expires_at_height && ticket.status == STATE_CHANNEL_STATUS_ACTIVE {
                ticket.status = STATE_CHANNEL_STATUS_EXPIRED.to_string();
            }
        }
        for attestation in self.watchtower_attestations.values_mut() {
            if height > attestation.expires_at_height
                && attestation.status == STATE_CHANNEL_STATUS_ACTIVE
            {
                attestation.status = STATE_CHANNEL_STATUS_EXPIRED.to_string();
            }
        }
    }

    pub fn insert_participant(
        &mut self,
        participant: ChannelParticipant,
    ) -> StateChannelResult<String> {
        let id = participant.participant_id.clone();
        self.participants.insert(id.clone(), participant);
        Ok(id)
    }

    pub fn insert_policy(&mut self, policy: ChannelPolicy) -> StateChannelResult<String> {
        let id = policy.policy_id.clone();
        self.policies.insert(id.clone(), policy);
        Ok(id)
    }

    pub fn insert_open_request(
        &mut self,
        request: ChannelOpenRequest,
    ) -> StateChannelResult<String> {
        let id = request.request_id.clone();
        self.open_requests.insert(id.clone(), request);
        Ok(id)
    }

    pub fn insert_funding_lock(
        &mut self,
        funding_lock: ChannelFundingLock,
    ) -> StateChannelResult<String> {
        let id = funding_lock.lock_id.clone();
        self.funding_locks.insert(id.clone(), funding_lock);
        Ok(id)
    }

    pub fn insert_channel(&mut self, channel: ChannelRecord) -> StateChannelResult<String> {
        let id = channel.channel_id.clone();
        self.channels.insert(id.clone(), channel);
        Ok(id)
    }

    pub fn insert_balance(
        &mut self,
        balance: ChannelBalanceCommitment,
    ) -> StateChannelResult<String> {
        let id = balance.balance_id.clone();
        self.balances.insert(id.clone(), balance);
        Ok(id)
    }

    pub fn insert_update(&mut self, update: ChannelStateUpdate) -> StateChannelResult<String> {
        let id = update.update_id.clone();
        self.updates.insert(id.clone(), update);
        Ok(id)
    }

    pub fn insert_checkpoint(
        &mut self,
        checkpoint: ChannelCheckpoint,
    ) -> StateChannelResult<String> {
        let id = checkpoint.checkpoint_id.clone();
        self.checkpoints.insert(id.clone(), checkpoint);
        Ok(id)
    }

    pub fn insert_virtual_link(&mut self, link: VirtualChannelLink) -> StateChannelResult<String> {
        let id = link.link_id.clone();
        self.virtual_links.insert(id.clone(), link);
        Ok(id)
    }

    pub fn insert_dispute(&mut self, dispute: ChannelDispute) -> StateChannelResult<String> {
        let id = dispute.dispute_id.clone();
        self.disputes.insert(id.clone(), dispute);
        Ok(id)
    }

    pub fn insert_dispute_response(
        &mut self,
        response: ChannelDisputeResponse,
    ) -> StateChannelResult<String> {
        let id = response.response_id.clone();
        self.dispute_responses.insert(id.clone(), response);
        Ok(id)
    }

    pub fn insert_close_intent(&mut self, close: ChannelCloseIntent) -> StateChannelResult<String> {
        let id = close.close_id.clone();
        self.close_intents.insert(id.clone(), close);
        Ok(id)
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: ChannelSettlementReceipt,
    ) -> StateChannelResult<String> {
        let id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn insert_relay_ticket(
        &mut self,
        ticket: ChannelRelayTicket,
    ) -> StateChannelResult<String> {
        let id = ticket.relay_ticket_id.clone();
        self.relay_tickets.insert(id.clone(), ticket);
        Ok(id)
    }

    pub fn insert_watchtower_attestation(
        &mut self,
        attestation: ChannelWatchtowerAttestation,
    ) -> StateChannelResult<String> {
        let id = attestation.attestation_id.clone();
        self.watchtower_attestations.insert(id.clone(), attestation);
        Ok(id)
    }

    pub fn participant_root(&self) -> String {
        state_channel_participant_root(&self.participants.values().cloned().collect::<Vec<_>>())
    }

    pub fn policy_root(&self) -> String {
        state_channel_policy_root(&self.policies.values().cloned().collect::<Vec<_>>())
    }

    pub fn open_request_root(&self) -> String {
        state_channel_open_request_root(&self.open_requests.values().cloned().collect::<Vec<_>>())
    }

    pub fn funding_lock_root(&self) -> String {
        state_channel_funding_lock_root(&self.funding_locks.values().cloned().collect::<Vec<_>>())
    }

    pub fn channel_root(&self) -> String {
        state_channel_record_root(&self.channels.values().cloned().collect::<Vec<_>>())
    }

    pub fn balance_root(&self) -> String {
        state_channel_balance_root(&self.balances.values().cloned().collect::<Vec<_>>())
    }

    pub fn update_root(&self) -> String {
        state_channel_update_root(&self.updates.values().cloned().collect::<Vec<_>>())
    }

    pub fn checkpoint_root(&self) -> String {
        state_channel_checkpoint_root(&self.checkpoints.values().cloned().collect::<Vec<_>>())
    }

    pub fn virtual_link_root(&self) -> String {
        state_channel_virtual_link_root(&self.virtual_links.values().cloned().collect::<Vec<_>>())
    }

    pub fn dispute_root(&self) -> String {
        state_channel_dispute_root(&self.disputes.values().cloned().collect::<Vec<_>>())
    }

    pub fn dispute_response_root(&self) -> String {
        state_channel_dispute_response_root(
            &self.dispute_responses.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn close_intent_root(&self) -> String {
        state_channel_close_intent_root(&self.close_intents.values().cloned().collect::<Vec<_>>())
    }

    pub fn settlement_receipt_root(&self) -> String {
        state_channel_settlement_receipt_root(
            &self
                .settlement_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn relay_ticket_root(&self) -> String {
        state_channel_relay_ticket_root(&self.relay_tickets.values().cloned().collect::<Vec<_>>())
    }

    pub fn watchtower_root(&self) -> String {
        state_channel_watchtower_root(
            &self
                .watchtower_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn active_channel_count(&self) -> u64 {
        self.channels
            .values()
            .filter(|channel| channel.status == STATE_CHANNEL_STATUS_OPEN)
            .count() as u64
    }

    pub fn pending_dispute_count(&self) -> u64 {
        self.disputes
            .values()
            .filter(|dispute| dispute.status == STATE_CHANNEL_STATUS_DISPUTED)
            .count() as u64
    }

    pub fn state_root(&self) -> String {
        state_channel_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("state channel state record")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "state_channel_state",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_CHANNEL_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "participant_root": self.participant_root(),
            "policy_root": self.policy_root(),
            "open_request_root": self.open_request_root(),
            "funding_lock_root": self.funding_lock_root(),
            "channel_root": self.channel_root(),
            "balance_root": self.balance_root(),
            "update_root": self.update_root(),
            "checkpoint_root": self.checkpoint_root(),
            "virtual_link_root": self.virtual_link_root(),
            "dispute_root": self.dispute_root(),
            "dispute_response_root": self.dispute_response_root(),
            "close_intent_root": self.close_intent_root(),
            "settlement_receipt_root": self.settlement_receipt_root(),
            "relay_ticket_root": self.relay_ticket_root(),
            "watchtower_root": self.watchtower_root(),
            "participant_count": self.participants.len() as u64,
            "channel_count": self.channels.len() as u64,
            "active_channel_count": self.active_channel_count(),
            "update_count": self.updates.len() as u64,
            "virtual_link_count": self.virtual_links.len() as u64,
            "pending_dispute_count": self.pending_dispute_count(),
        })
    }
}

pub fn state_channel_config_id(record: &Value) -> String {
    state_channel_payload_root("STATE-CHANNEL-CONFIG-ID", record)
}

pub fn state_channel_participant_id(
    label: &str,
    owner_commitment: &str,
    pq_key_root: &str,
    role_root: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-PARTICIPANT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(owner_commitment),
            HashPart::Str(pq_key_root),
            HashPart::Str(role_root),
        ],
        32,
    )
}

pub fn state_channel_policy_id(
    channel_kind: ChannelKind,
    visibility: ChannelVisibility,
    asset_root: &str,
    participant_root: &str,
    challenge_window_blocks: u64,
) -> String {
    domain_hash(
        "STATE-CHANNEL-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_kind.as_str()),
            HashPart::Str(visibility.as_str()),
            HashPart::Str(asset_root),
            HashPart::Str(participant_root),
            HashPart::Int(challenge_window_blocks as i128),
        ],
        32,
    )
}

pub fn state_channel_open_request_id(
    channel_kind: ChannelKind,
    visibility: ChannelVisibility,
    participant_root: &str,
    policy_id: &str,
    funding_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "STATE-CHANNEL-OPEN-REQUEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_kind.as_str()),
            HashPart::Str(visibility.as_str()),
            HashPart::Str(participant_root),
            HashPart::Str(policy_id),
            HashPart::Str(funding_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn state_channel_funding_lock_id(
    request_id: &str,
    participant_id: &str,
    asset_id: &str,
    amount_units: u64,
    funding_tx_root: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-FUNDING-LOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_id),
            HashPart::Str(participant_id),
            HashPart::Str(asset_id),
            HashPart::Int(amount_units as i128),
            HashPart::Str(funding_tx_root),
        ],
        32,
    )
}

pub fn state_channel_id(
    request_id: &str,
    participant_root: &str,
    funding_lock_root: &str,
    update_id: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_id),
            HashPart::Str(participant_root),
            HashPart::Str(funding_lock_root),
            HashPart::Str(update_id),
        ],
        32,
    )
}

pub fn state_channel_balance_id(
    channel_id: &str,
    participant_id: &str,
    asset_id: &str,
    amount_bucket: u64,
    balance_commitment: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-BALANCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(participant_id),
            HashPart::Str(asset_id),
            HashPart::Int(amount_bucket as i128),
            HashPart::Str(balance_commitment),
        ],
        32,
    )
}

pub fn state_channel_update_id(
    channel_id: &str,
    update_kind: ChannelUpdateKind,
    sequence: u64,
    previous_update_id: &str,
    state_root_after: &str,
    pq_auth_transcript_root: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-UPDATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(update_kind.as_str()),
            HashPart::Int(sequence as i128),
            HashPart::Str(previous_update_id),
            HashPart::Str(state_root_after),
            HashPart::Str(pq_auth_transcript_root),
        ],
        32,
    )
}

pub fn state_channel_checkpoint_id(
    channel_id: &str,
    update_id: &str,
    sequence: u64,
    balance_root: &str,
    virtual_link_root: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(update_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(balance_root),
            HashPart::Str(virtual_link_root),
        ],
        32,
    )
}

pub fn state_channel_virtual_link_id(
    parent_channel_id: &str,
    child_channel_id: &str,
    route_root: &str,
    liquidity_commitment: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-VIRTUAL-LINK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(parent_channel_id),
            HashPart::Str(child_channel_id),
            HashPart::Str(route_root),
            HashPart::Str(liquidity_commitment),
        ],
        32,
    )
}

pub fn state_channel_dispute_id(
    channel_id: &str,
    dispute_kind: ChannelDisputeKind,
    challenged_update_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-DISPUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(dispute_kind.as_str()),
            HashPart::Str(challenged_update_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn state_channel_dispute_response_id(
    dispute_id: &str,
    respondent_commitment: &str,
    update_id: &str,
    sequence: u64,
    proof_root: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-DISPUTE-RESPONSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dispute_id),
            HashPart::Str(respondent_commitment),
            HashPart::Str(update_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn state_channel_close_intent_id(
    channel_id: &str,
    settlement_kind: ChannelSettlementKind,
    final_update_id: &str,
    balance_root: &str,
    monero_close_root: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-CLOSE-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(settlement_kind.as_str()),
            HashPart::Str(final_update_id),
            HashPart::Str(balance_root),
            HashPart::Str(monero_close_root),
        ],
        32,
    )
}

pub fn state_channel_settlement_receipt_id(
    close_id: &str,
    settlement_tx_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "STATE-CHANNEL-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(close_id),
            HashPart::Str(settlement_tx_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn state_channel_relay_ticket_id(
    channel_id: &str,
    update_id: &str,
    relay_kind: ChannelRelayKind,
    relayer_commitment: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "STATE-CHANNEL-RELAY-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(update_id),
            HashPart::Str(relay_kind.as_str()),
            HashPart::Str(relayer_commitment),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn state_channel_watchtower_attestation_id(
    channel_id: &str,
    watchtower_commitment: &str,
    update_id: &str,
    sequence: u64,
    encrypted_state_root: &str,
) -> String {
    domain_hash(
        "STATE-CHANNEL-WATCHTOWER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(watchtower_commitment),
            HashPart::Str(update_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(encrypted_state_root),
        ],
        32,
    )
}

pub fn state_channel_state_root_from_record(record: &Value) -> String {
    state_channel_payload_root("STATE-CHANNEL-STATE-ROOT", record)
}

pub fn state_channel_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn state_channel_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn state_channel_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_channel_amount_bucket(amount: u64) -> u64 {
    match amount {
        0..=999 => 1_000,
        1_000..=9_999 => 10_000,
        10_000..=99_999 => 100_000,
        100_000..=999_999 => 1_000_000,
        _ => 10_000_000,
    }
}

pub fn state_channel_participant_signature_root(
    participants: &[ChannelParticipant],
    sequence: u64,
) -> String {
    let leaves = participants
        .iter()
        .map(|participant| {
            json!({
                "participant_id": participant.participant_id,
                "pq_key_root": participant.pq_key_root,
                "sequence": sequence,
                "scheme": STATE_CHANNEL_PQ_AUTH_SCHEME,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("STATE-CHANNEL-PARTICIPANT-SIGNATURE", &leaves)
}

pub fn state_channel_participant_root(values: &[ChannelParticipant]) -> String {
    merkle_root(
        "STATE-CHANNEL-PARTICIPANT",
        &values
            .iter()
            .map(ChannelParticipant::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_policy_root(values: &[ChannelPolicy]) -> String {
    merkle_root(
        "STATE-CHANNEL-POLICY",
        &values
            .iter()
            .map(ChannelPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_open_request_root(values: &[ChannelOpenRequest]) -> String {
    merkle_root(
        "STATE-CHANNEL-OPEN-REQUEST",
        &values
            .iter()
            .map(ChannelOpenRequest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_funding_lock_root(values: &[ChannelFundingLock]) -> String {
    merkle_root(
        "STATE-CHANNEL-FUNDING-LOCK",
        &values
            .iter()
            .map(ChannelFundingLock::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_record_root(values: &[ChannelRecord]) -> String {
    merkle_root(
        "STATE-CHANNEL-RECORD",
        &values
            .iter()
            .map(ChannelRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_balance_root(values: &[ChannelBalanceCommitment]) -> String {
    merkle_root(
        "STATE-CHANNEL-BALANCE",
        &values
            .iter()
            .map(ChannelBalanceCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_update_root(values: &[ChannelStateUpdate]) -> String {
    merkle_root(
        "STATE-CHANNEL-UPDATE",
        &values
            .iter()
            .map(ChannelStateUpdate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_checkpoint_root(values: &[ChannelCheckpoint]) -> String {
    merkle_root(
        "STATE-CHANNEL-CHECKPOINT",
        &values
            .iter()
            .map(ChannelCheckpoint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_virtual_link_root(values: &[VirtualChannelLink]) -> String {
    merkle_root(
        "STATE-CHANNEL-VIRTUAL-LINK",
        &values
            .iter()
            .map(VirtualChannelLink::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_dispute_root(values: &[ChannelDispute]) -> String {
    merkle_root(
        "STATE-CHANNEL-DISPUTE",
        &values
            .iter()
            .map(ChannelDispute::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_dispute_response_root(values: &[ChannelDisputeResponse]) -> String {
    merkle_root(
        "STATE-CHANNEL-DISPUTE-RESPONSE",
        &values
            .iter()
            .map(ChannelDisputeResponse::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_close_intent_root(values: &[ChannelCloseIntent]) -> String {
    merkle_root(
        "STATE-CHANNEL-CLOSE-INTENT",
        &values
            .iter()
            .map(ChannelCloseIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_settlement_receipt_root(values: &[ChannelSettlementReceipt]) -> String {
    merkle_root(
        "STATE-CHANNEL-SETTLEMENT-RECEIPT",
        &values
            .iter()
            .map(ChannelSettlementReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_relay_ticket_root(values: &[ChannelRelayTicket]) -> String {
    merkle_root(
        "STATE-CHANNEL-RELAY-TICKET",
        &values
            .iter()
            .map(ChannelRelayTicket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn state_channel_watchtower_root(values: &[ChannelWatchtowerAttestation]) -> String {
    merkle_root(
        "STATE-CHANNEL-WATCHTOWER",
        &values
            .iter()
            .map(ChannelWatchtowerAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

fn normalize_label(value: String) -> String {
    value.trim().replace(' ', "-").to_ascii_lowercase()
}

fn ensure_non_empty(value: &str, field: &str) -> StateChannelResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> StateChannelResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}
