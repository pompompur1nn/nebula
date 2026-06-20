use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateSmartContractStateChannelsResult<T> = Result<T, String>;

pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_PROTOCOL_VERSION: &str =
    "nebula-private-smart-contract-state-channels-v1";
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_SCHEMA_VERSION: &str =
    "private-smart-contract-state-channels-state-v1";
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEVNET_LABEL: &str =
    "devnet-private-smart-contract-state-channels";
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_PQ_SIGNATURE_SCHEME: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-channel-update";
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-canonical-json";
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEFAULT_TIMEOUT_BLOCKS: u64 = 96;
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEFAULT_CHALLENGE_BLOCKS: u64 = 24;
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEFAULT_MAX_PARTICIPANTS: usize = 32;
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEFAULT_MAX_UPDATES_PER_CHANNEL: u64 = 4_096;
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_CHANNELS: usize = 2_048;
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_UPDATES: usize = 32_768;
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_SETTLEMENTS: usize = 8_192;
pub const PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_DISPUTES: usize = 8_192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateChannelKind {
    ContractCall,
    TokenTransfer,
    AmmSwap,
    LendingPosition,
    PerpMargin,
    MoneroBridgeExit,
    OracleUpdate,
    GovernanceVote,
}

impl PrivateChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::AmmSwap => "amm_swap",
            Self::LendingPosition => "lending_position",
            Self::PerpMargin => "perp_margin",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::GovernanceVote => "governance_vote",
        }
    }

    pub fn low_fee_eligible(self) -> bool {
        matches!(
            self,
            Self::TokenTransfer | Self::AmmSwap | Self::MoneroBridgeExit | Self::ContractCall
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateChannelStatus {
    Opening,
    Active,
    Settling,
    Disputed,
    Closed,
    Expired,
}

impl PrivateChannelStatus {
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Opening | Self::Active | Self::Settling | Self::Disputed
        )
    }

    pub fn accepts_updates(self) -> bool {
        matches!(self, Self::Opening | Self::Active)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::Settling => "settling",
            Self::Disputed => "disputed",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelUpdateStatus {
    Proposed,
    CoSigned,
    Superseded,
    Settled,
    Challenged,
    Rejected,
}

impl ChannelUpdateStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Proposed | Self::CoSigned | Self::Challenged)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::CoSigned => "co_signed",
            Self::Superseded => "superseded",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelDisputeStatus {
    Open,
    EvidencePending,
    ReadyToResolve,
    Resolved,
    Slashed,
    Expired,
}

impl ChannelDisputeStatus {
    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Open | Self::EvidencePending | Self::ReadyToResolve
        )
    }

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
}

pub trait PrivateChannelRooted {
    fn root(&self) -> String;
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSmartContractStateChannelsConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub pq_signature_scheme: String,
    pub commitment_scheme: String,
    pub default_timeout_blocks: u64,
    pub default_challenge_blocks: u64,
    pub max_participants_per_channel: usize,
    pub max_updates_per_channel: u64,
    pub low_fee_update_cap_micro_units: u64,
    pub require_all_participant_pq_keys: bool,
    pub privacy_policy_root: String,
}

impl PrivateSmartContractStateChannelsConfig {
    pub fn devnet() -> PrivateSmartContractStateChannelsResult<Self> {
        let privacy_policy_root = private_channel_string_root(
            "PRIVATE-CHANNEL-PRIVACY-POLICY",
            "roots-only-public-state",
        );
        let mut config = Self {
            config_id: String::new(),
            protocol_version: PRIVATE_SMART_CONTRACT_STATE_CHANNELS_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_SMART_CONTRACT_STATE_CHANNELS_SCHEMA_VERSION.to_string(),
            pq_signature_scheme: PRIVATE_SMART_CONTRACT_STATE_CHANNELS_PQ_SIGNATURE_SCHEME
                .to_string(),
            commitment_scheme: PRIVATE_SMART_CONTRACT_STATE_CHANNELS_COMMITMENT_SCHEME.to_string(),
            default_timeout_blocks: PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEFAULT_TIMEOUT_BLOCKS,
            default_challenge_blocks:
                PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEFAULT_CHALLENGE_BLOCKS,
            max_participants_per_channel:
                PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEFAULT_MAX_PARTICIPANTS,
            max_updates_per_channel:
                PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEFAULT_MAX_UPDATES_PER_CHANNEL,
            low_fee_update_cap_micro_units: 1_250,
            require_all_participant_pq_keys: true,
            privacy_policy_root,
        };
        config.config_id =
            private_channel_config_id(&config.protocol_version, &config.schema_version);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(&self.config_id, "private channel config id")?;
        ensure_non_empty(&self.protocol_version, "private channel protocol version")?;
        ensure_non_empty(&self.schema_version, "private channel schema version")?;
        ensure_non_empty(
            &self.pq_signature_scheme,
            "private channel pq signature scheme",
        )?;
        ensure_non_empty(&self.commitment_scheme, "private channel commitment scheme")?;
        ensure_non_empty(
            &self.privacy_policy_root,
            "private channel privacy policy root",
        )?;
        if self.default_timeout_blocks == 0 {
            return Err("private channel timeout must be positive".to_string());
        }
        if self.default_challenge_blocks == 0 {
            return Err("private channel challenge window must be positive".to_string());
        }
        if self.default_challenge_blocks >= self.default_timeout_blocks {
            return Err(
                "private channel challenge window must be shorter than timeout".to_string(),
            );
        }
        if self.max_participants_per_channel == 0 {
            return Err("private channel participant cap must be positive".to_string());
        }
        if self.max_updates_per_channel == 0 {
            return Err("private channel update cap must be positive".to_string());
        }
        let expected = private_channel_config_id(&self.protocol_version, &self.schema_version);
        if self.config_id != expected {
            return Err("private channel config id does not match protocol".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateChannelRooted for PrivateSmartContractStateChannelsConfig {
    fn root(&self) -> String {
        private_channel_payload_root("PRIVATE-CHANNEL-CONFIG", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_smart_contract_state_channels_config",
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "pq_signature_scheme": self.pq_signature_scheme,
            "commitment_scheme": self.commitment_scheme,
            "default_timeout_blocks": self.default_timeout_blocks,
            "default_challenge_blocks": self.default_challenge_blocks,
            "max_participants_per_channel": self.max_participants_per_channel,
            "max_updates_per_channel": self.max_updates_per_channel,
            "low_fee_update_cap_micro_units": self.low_fee_update_cap_micro_units,
            "require_all_participant_pq_keys": self.require_all_participant_pq_keys,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateChannelParticipant {
    pub participant_id: String,
    pub account_commitment: String,
    pub pq_key_commitment: String,
    pub encrypted_view_key_root: String,
    pub stake_commitment_root: String,
    pub can_initiate_settlement: bool,
}

impl PrivateChannelParticipant {
    pub fn new(
        account_label: &str,
        pq_key_label: &str,
        stake_label: &str,
        can_initiate_settlement: bool,
    ) -> PrivateSmartContractStateChannelsResult<Self> {
        ensure_non_empty(account_label, "private channel participant account label")?;
        let account_commitment =
            private_channel_string_root("PRIVATE-CHANNEL-PARTICIPANT-ACCOUNT", account_label);
        let pq_key_commitment =
            private_channel_string_root("PRIVATE-CHANNEL-PARTICIPANT-PQ-KEY", pq_key_label);
        let encrypted_view_key_root =
            private_channel_string_root("PRIVATE-CHANNEL-PARTICIPANT-VIEW", account_label);
        let stake_commitment_root =
            private_channel_string_root("PRIVATE-CHANNEL-PARTICIPANT-STAKE", stake_label);
        let participant_id = private_channel_participant_id(
            &account_commitment,
            &pq_key_commitment,
            &stake_commitment_root,
        );
        let participant = Self {
            participant_id,
            account_commitment,
            pq_key_commitment,
            encrypted_view_key_root,
            stake_commitment_root,
            can_initiate_settlement,
        };
        participant.validate()?;
        Ok(participant)
    }

    pub fn validate(&self) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(&self.participant_id, "private channel participant id")?;
        ensure_non_empty(
            &self.account_commitment,
            "private channel account commitment",
        )?;
        ensure_non_empty(&self.pq_key_commitment, "private channel pq key commitment")?;
        ensure_non_empty(
            &self.encrypted_view_key_root,
            "private channel encrypted view key root",
        )?;
        ensure_non_empty(&self.stake_commitment_root, "private channel stake root")?;
        let expected = private_channel_participant_id(
            &self.account_commitment,
            &self.pq_key_commitment,
            &self.stake_commitment_root,
        );
        if self.participant_id != expected {
            return Err("private channel participant id does not match commitments".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateChannelRooted for PrivateChannelParticipant {
    fn root(&self) -> String {
        private_channel_payload_root("PRIVATE-CHANNEL-PARTICIPANT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_channel_participant",
            "participant_id": self.participant_id,
            "account_commitment": self.account_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "encrypted_view_key_root": self.encrypted_view_key_root,
            "stake_commitment_root": self.stake_commitment_root,
            "can_initiate_settlement": self.can_initiate_settlement,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateContractChannel {
    pub channel_id: String,
    pub channel_kind: PrivateChannelKind,
    pub status: PrivateChannelStatus,
    pub contract_commitment: String,
    pub lane_id: String,
    pub participant_root: String,
    pub participant_ids: BTreeSet<String>,
    pub latest_update_root: String,
    pub collateral_root: String,
    pub fee_budget_root: String,
    pub opened_height: u64,
    pub timeout_height: u64,
    pub update_nonce: u64,
}

impl PrivateContractChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel_kind: PrivateChannelKind,
        contract_label: &str,
        lane_id: &str,
        participants: &[PrivateChannelParticipant],
        collateral_root: &str,
        fee_budget_root: &str,
        opened_height: u64,
        timeout_blocks: u64,
    ) -> PrivateSmartContractStateChannelsResult<Self> {
        ensure_non_empty(contract_label, "private channel contract label")?;
        ensure_non_empty(lane_id, "private channel lane id")?;
        ensure_non_empty(collateral_root, "private channel collateral root")?;
        ensure_non_empty(fee_budget_root, "private channel fee budget root")?;
        if participants.len() < 2 {
            return Err("private channel requires at least two participants".to_string());
        }
        if timeout_blocks == 0 {
            return Err("private channel timeout blocks must be positive".to_string());
        }
        let contract_commitment =
            private_channel_string_root("PRIVATE-CHANNEL-CONTRACT", contract_label);
        let participant_ids = participants
            .iter()
            .map(|participant| participant.participant_id.clone())
            .collect::<BTreeSet<_>>();
        let participant_root = private_channel_values_root(
            "PRIVATE-CHANNEL-PARTICIPANTS",
            &participants
                .iter()
                .map(PrivateChannelParticipant::public_record)
                .collect::<Vec<_>>(),
        );
        let latest_update_root = private_channel_empty_root("PRIVATE-CHANNEL-LATEST-UPDATE");
        let timeout_height = opened_height.saturating_add(timeout_blocks);
        let channel_id = private_contract_channel_id(
            channel_kind,
            &contract_commitment,
            lane_id,
            &participant_root,
            opened_height,
        );
        let channel = Self {
            channel_id,
            channel_kind,
            status: PrivateChannelStatus::Opening,
            contract_commitment,
            lane_id: lane_id.to_string(),
            participant_root,
            participant_ids,
            latest_update_root,
            collateral_root: collateral_root.to_string(),
            fee_budget_root: fee_budget_root.to_string(),
            opened_height,
            timeout_height,
            update_nonce: 0,
        };
        channel.validate()?;
        Ok(channel)
    }

    pub fn activate(&mut self) -> PrivateSmartContractStateChannelsResult<String> {
        if self.status != PrivateChannelStatus::Opening {
            return Err("private channel can only activate from opening".to_string());
        }
        self.status = PrivateChannelStatus::Active;
        Ok(self.root())
    }

    pub fn mark_settling(
        &mut self,
        update_root: &str,
    ) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(update_root, "private channel settlement update root")?;
        if !self.status.is_live() {
            return Err("private channel is not live".to_string());
        }
        self.status = PrivateChannelStatus::Settling;
        self.latest_update_root = update_root.to_string();
        Ok(self.root())
    }

    pub fn mark_disputed(
        &mut self,
        update_root: &str,
    ) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(update_root, "private channel disputed update root")?;
        if !self.status.is_live() {
            return Err("private channel is not live".to_string());
        }
        self.status = PrivateChannelStatus::Disputed;
        self.latest_update_root = update_root.to_string();
        Ok(self.root())
    }

    pub fn close(&mut self, update_root: &str) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(update_root, "private channel closing update root")?;
        self.status = PrivateChannelStatus::Closed;
        self.latest_update_root = update_root.to_string();
        Ok(self.root())
    }

    pub fn validate(&self) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(&self.channel_id, "private channel id")?;
        ensure_non_empty(
            &self.contract_commitment,
            "private channel contract commitment",
        )?;
        ensure_non_empty(&self.lane_id, "private channel lane id")?;
        ensure_non_empty(&self.participant_root, "private channel participant root")?;
        ensure_non_empty(
            &self.latest_update_root,
            "private channel latest update root",
        )?;
        ensure_non_empty(&self.collateral_root, "private channel collateral root")?;
        ensure_non_empty(&self.fee_budget_root, "private channel fee budget root")?;
        if self.participant_ids.len() < 2 {
            return Err("private channel participant set is too small".to_string());
        }
        if self.timeout_height <= self.opened_height {
            return Err("private channel timeout must exceed open height".to_string());
        }
        let expected = private_contract_channel_id(
            self.channel_kind,
            &self.contract_commitment,
            &self.lane_id,
            &self.participant_root,
            self.opened_height,
        );
        if self.channel_id != expected {
            return Err("private channel id does not match opening commitment".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateChannelRooted for PrivateContractChannel {
    fn root(&self) -> String {
        private_channel_payload_root("PRIVATE-CONTRACT-CHANNEL", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_channel",
            "channel_id": self.channel_id,
            "channel_kind": self.channel_kind.as_str(),
            "status": self.status.as_str(),
            "contract_commitment": self.contract_commitment,
            "lane_id": self.lane_id,
            "participant_root": self.participant_root,
            "participant_ids": self.participant_ids.iter().cloned().collect::<Vec<_>>(),
            "latest_update_root": self.latest_update_root,
            "collateral_root": self.collateral_root,
            "fee_budget_root": self.fee_budget_root,
            "opened_height": self.opened_height,
            "timeout_height": self.timeout_height,
            "update_nonce": self.update_nonce,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateChannelUpdate {
    pub update_id: String,
    pub channel_id: String,
    pub status: ChannelUpdateStatus,
    pub nonce: u64,
    pub state_delta_root: String,
    pub encrypted_witness_root: String,
    pub participant_signature_root: String,
    pub fee_micro_units: u64,
    pub proposed_height: u64,
    pub expires_height: u64,
}

impl PrivateChannelUpdate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel_id: &str,
        nonce: u64,
        state_delta_root: &str,
        encrypted_witness_root: &str,
        participant_signature_root: &str,
        fee_micro_units: u64,
        proposed_height: u64,
        ttl_blocks: u64,
    ) -> PrivateSmartContractStateChannelsResult<Self> {
        ensure_non_empty(channel_id, "private channel update channel id")?;
        ensure_non_empty(state_delta_root, "private channel update state delta root")?;
        ensure_non_empty(
            encrypted_witness_root,
            "private channel update witness root",
        )?;
        ensure_non_empty(
            participant_signature_root,
            "private channel update participant signature root",
        )?;
        if ttl_blocks == 0 {
            return Err("private channel update ttl must be positive".to_string());
        }
        let expires_height = proposed_height.saturating_add(ttl_blocks);
        let update_id = private_channel_update_id(
            channel_id,
            nonce,
            state_delta_root,
            encrypted_witness_root,
            participant_signature_root,
        );
        let update = Self {
            update_id,
            channel_id: channel_id.to_string(),
            status: ChannelUpdateStatus::Proposed,
            nonce,
            state_delta_root: state_delta_root.to_string(),
            encrypted_witness_root: encrypted_witness_root.to_string(),
            participant_signature_root: participant_signature_root.to_string(),
            fee_micro_units,
            proposed_height,
            expires_height,
        };
        update.validate()?;
        Ok(update)
    }

    pub fn co_sign(&mut self) -> PrivateSmartContractStateChannelsResult<String> {
        if self.status != ChannelUpdateStatus::Proposed {
            return Err("private channel update can only co-sign from proposed".to_string());
        }
        self.status = ChannelUpdateStatus::CoSigned;
        Ok(self.root())
    }

    pub fn validate(&self) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(&self.update_id, "private channel update id")?;
        ensure_non_empty(&self.channel_id, "private channel update channel id")?;
        ensure_non_empty(
            &self.state_delta_root,
            "private channel update state delta root",
        )?;
        ensure_non_empty(
            &self.encrypted_witness_root,
            "private channel update witness root",
        )?;
        ensure_non_empty(
            &self.participant_signature_root,
            "private channel update signature root",
        )?;
        if self.expires_height <= self.proposed_height {
            return Err("private channel update expiry must exceed proposed height".to_string());
        }
        let expected = private_channel_update_id(
            &self.channel_id,
            self.nonce,
            &self.state_delta_root,
            &self.encrypted_witness_root,
            &self.participant_signature_root,
        );
        if self.update_id != expected {
            return Err("private channel update id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateChannelRooted for PrivateChannelUpdate {
    fn root(&self) -> String {
        private_channel_payload_root("PRIVATE-CHANNEL-UPDATE", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_channel_update",
            "update_id": self.update_id,
            "channel_id": self.channel_id,
            "status": self.status.as_str(),
            "nonce": self.nonce,
            "state_delta_root": self.state_delta_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "participant_signature_root": self.participant_signature_root,
            "fee_micro_units": self.fee_micro_units,
            "proposed_height": self.proposed_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateChannelSettlement {
    pub settlement_id: String,
    pub channel_id: String,
    pub update_id: String,
    pub settlement_root: String,
    pub exit_commitment_root: String,
    pub fee_receipt_root: String,
    pub settlement_height: u64,
}

impl PrivateChannelSettlement {
    pub fn new(
        channel_id: &str,
        update_id: &str,
        settlement_root: &str,
        exit_commitment_root: &str,
        fee_receipt_root: &str,
        settlement_height: u64,
    ) -> PrivateSmartContractStateChannelsResult<Self> {
        ensure_non_empty(channel_id, "private channel settlement channel id")?;
        ensure_non_empty(update_id, "private channel settlement update id")?;
        ensure_non_empty(settlement_root, "private channel settlement root")?;
        ensure_non_empty(exit_commitment_root, "private channel exit commitment root")?;
        ensure_non_empty(fee_receipt_root, "private channel fee receipt root")?;
        let settlement_id = private_channel_settlement_id(
            channel_id,
            update_id,
            settlement_root,
            exit_commitment_root,
            settlement_height,
        );
        let settlement = Self {
            settlement_id,
            channel_id: channel_id.to_string(),
            update_id: update_id.to_string(),
            settlement_root: settlement_root.to_string(),
            exit_commitment_root: exit_commitment_root.to_string(),
            fee_receipt_root: fee_receipt_root.to_string(),
            settlement_height,
        };
        settlement.validate()?;
        Ok(settlement)
    }

    pub fn validate(&self) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(&self.settlement_id, "private channel settlement id")?;
        ensure_non_empty(&self.channel_id, "private channel settlement channel id")?;
        ensure_non_empty(&self.update_id, "private channel settlement update id")?;
        ensure_non_empty(&self.settlement_root, "private channel settlement root")?;
        ensure_non_empty(
            &self.exit_commitment_root,
            "private channel exit commitment root",
        )?;
        ensure_non_empty(&self.fee_receipt_root, "private channel fee receipt root")?;
        let expected = private_channel_settlement_id(
            &self.channel_id,
            &self.update_id,
            &self.settlement_root,
            &self.exit_commitment_root,
            self.settlement_height,
        );
        if self.settlement_id != expected {
            return Err("private channel settlement id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateChannelRooted for PrivateChannelSettlement {
    fn root(&self) -> String {
        private_channel_payload_root("PRIVATE-CHANNEL-SETTLEMENT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_channel_settlement",
            "settlement_id": self.settlement_id,
            "channel_id": self.channel_id,
            "update_id": self.update_id,
            "settlement_root": self.settlement_root,
            "exit_commitment_root": self.exit_commitment_root,
            "fee_receipt_root": self.fee_receipt_root,
            "settlement_height": self.settlement_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateChannelDispute {
    pub dispute_id: String,
    pub channel_id: String,
    pub challenged_update_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub status: ChannelDisputeStatus,
    pub opened_height: u64,
    pub resolve_after_height: u64,
}

impl PrivateChannelDispute {
    pub fn new(
        channel_id: &str,
        challenged_update_id: &str,
        challenger_label: &str,
        evidence_root: &str,
        opened_height: u64,
        challenge_blocks: u64,
    ) -> PrivateSmartContractStateChannelsResult<Self> {
        ensure_non_empty(channel_id, "private channel dispute channel id")?;
        ensure_non_empty(challenged_update_id, "private channel dispute update id")?;
        ensure_non_empty(challenger_label, "private channel dispute challenger")?;
        ensure_non_empty(evidence_root, "private channel dispute evidence root")?;
        if challenge_blocks == 0 {
            return Err("private channel challenge blocks must be positive".to_string());
        }
        let challenger_commitment =
            private_channel_string_root("PRIVATE-CHANNEL-DISPUTE-CHALLENGER", challenger_label);
        let resolve_after_height = opened_height.saturating_add(challenge_blocks);
        let dispute_id = private_channel_dispute_id(
            channel_id,
            challenged_update_id,
            &challenger_commitment,
            evidence_root,
            opened_height,
        );
        let dispute = Self {
            dispute_id,
            channel_id: channel_id.to_string(),
            challenged_update_id: challenged_update_id.to_string(),
            challenger_commitment,
            evidence_root: evidence_root.to_string(),
            status: ChannelDisputeStatus::Open,
            opened_height,
            resolve_after_height,
        };
        dispute.validate()?;
        Ok(dispute)
    }

    pub fn validate(&self) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(&self.dispute_id, "private channel dispute id")?;
        ensure_non_empty(&self.channel_id, "private channel dispute channel id")?;
        ensure_non_empty(
            &self.challenged_update_id,
            "private channel dispute update id",
        )?;
        ensure_non_empty(
            &self.challenger_commitment,
            "private channel dispute challenger",
        )?;
        ensure_non_empty(&self.evidence_root, "private channel dispute evidence root")?;
        if self.resolve_after_height <= self.opened_height {
            return Err(
                "private channel dispute resolve height must exceed open height".to_string(),
            );
        }
        let expected = private_channel_dispute_id(
            &self.channel_id,
            &self.challenged_update_id,
            &self.challenger_commitment,
            &self.evidence_root,
            self.opened_height,
        );
        if self.dispute_id != expected {
            return Err("private channel dispute id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl PrivateChannelRooted for PrivateChannelDispute {
    fn root(&self) -> String {
        private_channel_payload_root("PRIVATE-CHANNEL-DISPUTE", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_channel_dispute",
            "dispute_id": self.dispute_id,
            "channel_id": self.channel_id,
            "challenged_update_id": self.challenged_update_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "resolve_after_height": self.resolve_after_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSmartContractStateChannelsRoots {
    pub config_root: String,
    pub channel_root: String,
    pub update_root: String,
    pub settlement_root: String,
    pub dispute_root: String,
    pub lane_liquidity_root: String,
    pub state_root: String,
}

impl PrivateSmartContractStateChannelsRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "channel_root": self.channel_root,
            "update_root": self.update_root,
            "settlement_root": self.settlement_root,
            "dispute_root": self.dispute_root,
            "lane_liquidity_root": self.lane_liquidity_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSmartContractStateChannelsCounters {
    pub height: u64,
    pub channel_count: u64,
    pub live_channel_count: u64,
    pub update_count: u64,
    pub live_update_count: u64,
    pub settlement_count: u64,
    pub dispute_count: u64,
    pub open_dispute_count: u64,
    pub low_fee_channel_count: u64,
}

impl PrivateSmartContractStateChannelsCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "channel_count": self.channel_count,
            "live_channel_count": self.live_channel_count,
            "update_count": self.update_count,
            "live_update_count": self.live_update_count,
            "settlement_count": self.settlement_count,
            "dispute_count": self.dispute_count,
            "open_dispute_count": self.open_dispute_count,
            "low_fee_channel_count": self.low_fee_channel_count,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSmartContractStateChannelsState {
    pub height: u64,
    pub label: String,
    pub config: PrivateSmartContractStateChannelsConfig,
    pub channels: BTreeMap<String, PrivateContractChannel>,
    pub updates: BTreeMap<String, PrivateChannelUpdate>,
    pub settlements: BTreeMap<String, PrivateChannelSettlement>,
    pub disputes: BTreeMap<String, PrivateChannelDispute>,
}

impl PrivateSmartContractStateChannelsState {
    pub fn new(
        label: &str,
        config: PrivateSmartContractStateChannelsConfig,
    ) -> PrivateSmartContractStateChannelsResult<Self> {
        ensure_non_empty(label, "private smart contract state channels label")?;
        config.validate()?;
        let state = Self {
            height: 0,
            label: label.to_string(),
            config,
            channels: BTreeMap::new(),
            updates: BTreeMap::new(),
            settlements: BTreeMap::new(),
            disputes: BTreeMap::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn devnet() -> PrivateSmartContractStateChannelsResult<Self> {
        let config = PrivateSmartContractStateChannelsConfig::devnet()?;
        let mut state = Self::new(PRIVATE_SMART_CONTRACT_STATE_CHANNELS_DEVNET_LABEL, config)?;
        state.set_height(64)?;
        let alice =
            PrivateChannelParticipant::new("devnet-alice", "devnet-alice-pq", "alice-stake", true)?;
        let bob = PrivateChannelParticipant::new("devnet-bob", "devnet-bob-pq", "bob-stake", true)?;
        let solver = PrivateChannelParticipant::new(
            "devnet-solver",
            "devnet-solver-pq",
            "solver-stake",
            false,
        )?;
        let collateral_root =
            private_channel_string_root("PRIVATE-CHANNEL-DEVNET-COLLATERAL", "xmr+dxmr+dusd");
        let fee_budget_root =
            private_channel_string_root("PRIVATE-CHANNEL-DEVNET-FEE-BUDGET", "low-fee-budget");
        let mut channel = PrivateContractChannel::new(
            PrivateChannelKind::AmmSwap,
            "devnet-private-amm-router",
            "low_fee_private_swap",
            &[alice, bob, solver],
            &collateral_root,
            &fee_budget_root,
            42,
            state.config.default_timeout_blocks,
        )?;
        channel.activate()?;
        let channel_id = channel.channel_id.clone();
        state.add_channel(channel)?;
        let state_delta_root =
            private_channel_string_root("PRIVATE-CHANNEL-DEVNET-DELTA", "swap-state-delta");
        let encrypted_witness_root =
            private_channel_string_root("PRIVATE-CHANNEL-DEVNET-WITNESS", "encrypted-witness");
        let signature_root =
            private_channel_string_root("PRIVATE-CHANNEL-DEVNET-SIGNATURES", "pq-cosignatures");
        let mut update = PrivateChannelUpdate::new(
            &channel_id,
            1,
            &state_delta_root,
            &encrypted_witness_root,
            &signature_root,
            900,
            48,
            state.config.default_timeout_blocks,
        )?;
        update.co_sign()?;
        let update_id = update.update_id.clone();
        let update_root = state.add_update(update)?;
        if let Some(channel) = state.channels.get_mut(&channel_id) {
            channel.mark_settling(&update_root)?;
        }
        let settlement_root =
            private_channel_string_root("PRIVATE-CHANNEL-DEVNET-SETTLEMENT", "settled-batch");
        let exit_commitment_root =
            private_channel_string_root("PRIVATE-CHANNEL-DEVNET-EXIT", "exit-commitments");
        let fee_receipt_root =
            private_channel_string_root("PRIVATE-CHANNEL-DEVNET-FEE", "fee-receipts");
        let settlement = PrivateChannelSettlement::new(
            &channel_id,
            &update_id,
            &settlement_root,
            &exit_commitment_root,
            &fee_receipt_root,
            60,
        )?;
        state.add_settlement(settlement)?;
        let evidence_root =
            private_channel_string_root("PRIVATE-CHANNEL-DEVNET-DISPUTE", "withheld-witness");
        let dispute = PrivateChannelDispute::new(
            &channel_id,
            &update_id,
            "devnet-alice",
            &evidence_root,
            61,
            state.config.default_challenge_blocks,
        )?;
        state.add_dispute(dispute)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateSmartContractStateChannelsResult<String> {
        self.height = height;
        self.validate()
    }

    pub fn add_channel(
        &mut self,
        channel: PrivateContractChannel,
    ) -> PrivateSmartContractStateChannelsResult<String> {
        if self.channels.len() >= PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_CHANNELS {
            return Err("private channel limit reached".to_string());
        }
        if channel.participant_ids.len() > self.config.max_participants_per_channel {
            return Err("private channel participant cap exceeded".to_string());
        }
        channel.validate()?;
        let root = channel.root();
        self.channels.insert(channel.channel_id.clone(), channel);
        Ok(root)
    }

    pub fn add_update(
        &mut self,
        update: PrivateChannelUpdate,
    ) -> PrivateSmartContractStateChannelsResult<String> {
        if self.updates.len() >= PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_UPDATES {
            return Err("private channel update limit reached".to_string());
        }
        let channel = self
            .channels
            .get_mut(&update.channel_id)
            .ok_or_else(|| "private channel update references unknown channel".to_string())?;
        if !channel.status.accepts_updates() {
            return Err("private channel does not accept updates".to_string());
        }
        if update.nonce <= channel.update_nonce {
            return Err("private channel update nonce must advance".to_string());
        }
        if update.nonce > self.config.max_updates_per_channel {
            return Err("private channel update cap exceeded".to_string());
        }
        update.validate()?;
        let root = update.root();
        channel.update_nonce = update.nonce;
        channel.latest_update_root = root.clone();
        self.updates.insert(update.update_id.clone(), update);
        Ok(root)
    }

    pub fn add_settlement(
        &mut self,
        settlement: PrivateChannelSettlement,
    ) -> PrivateSmartContractStateChannelsResult<String> {
        if self.settlements.len() >= PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_SETTLEMENTS {
            return Err("private channel settlement limit reached".to_string());
        }
        let channel = self
            .channels
            .get_mut(&settlement.channel_id)
            .ok_or_else(|| "private channel settlement references unknown channel".to_string())?;
        if !self.updates.contains_key(&settlement.update_id) {
            return Err("private channel settlement references unknown update".to_string());
        }
        settlement.validate()?;
        let root = settlement.root();
        channel.close(&root)?;
        self.settlements
            .insert(settlement.settlement_id.clone(), settlement);
        Ok(root)
    }

    pub fn add_dispute(
        &mut self,
        dispute: PrivateChannelDispute,
    ) -> PrivateSmartContractStateChannelsResult<String> {
        if self.disputes.len() >= PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_DISPUTES {
            return Err("private channel dispute limit reached".to_string());
        }
        let channel = self
            .channels
            .get_mut(&dispute.channel_id)
            .ok_or_else(|| "private channel dispute references unknown channel".to_string())?;
        if !self.updates.contains_key(&dispute.challenged_update_id) {
            return Err("private channel dispute references unknown update".to_string());
        }
        dispute.validate()?;
        let root = dispute.root();
        channel.mark_disputed(&root)?;
        self.disputes.insert(dispute.dispute_id.clone(), dispute);
        Ok(root)
    }

    pub fn active_channel_ids(&self) -> Vec<String> {
        self.channels
            .values()
            .filter(|channel| channel.status.is_live())
            .map(|channel| channel.channel_id.clone())
            .collect()
    }

    pub fn pending_update_ids(&self) -> Vec<String> {
        self.updates
            .values()
            .filter(|update| update.status.live())
            .map(|update| update.update_id.clone())
            .collect()
    }

    pub fn open_dispute_ids(&self) -> Vec<String> {
        self.disputes
            .values()
            .filter(|dispute| dispute.status.open())
            .map(|dispute| dispute.dispute_id.clone())
            .collect()
    }

    pub fn lane_liquidity_map(&self) -> BTreeMap<String, u64> {
        let mut lanes = BTreeMap::new();
        for channel in self.channels.values() {
            let weight = if channel.channel_kind.low_fee_eligible() {
                2
            } else {
                1
            };
            *lanes.entry(channel.lane_id.clone()).or_insert(0) += weight;
        }
        lanes
    }

    pub fn roots(&self) -> PrivateSmartContractStateChannelsRoots {
        let config_root = self.config.root();
        let channel_root = private_channel_map_root("PRIVATE-CHANNELS", &self.channels);
        let update_root = private_channel_map_root("PRIVATE-CHANNEL-UPDATES", &self.updates);
        let settlement_root =
            private_channel_map_root("PRIVATE-CHANNEL-SETTLEMENTS", &self.settlements);
        let dispute_root = private_channel_map_root("PRIVATE-CHANNEL-DISPUTES", &self.disputes);
        let lane_liquidity_root = private_channel_payload_root(
            "PRIVATE-CHANNEL-LANE-LIQUIDITY",
            &json!(self.lane_liquidity_map()),
        );
        let state_root = domain_hash(
            "PRIVATE-SMART-CONTRACT-STATE-CHANNELS-ROOT",
            &[
                HashPart::Str(&self.label),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&channel_root),
                HashPart::Str(&update_root),
                HashPart::Str(&settlement_root),
                HashPart::Str(&dispute_root),
                HashPart::Str(&lane_liquidity_root),
            ],
            32,
        );
        PrivateSmartContractStateChannelsRoots {
            config_root,
            channel_root,
            update_root,
            settlement_root,
            dispute_root,
            lane_liquidity_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateSmartContractStateChannelsCounters {
        PrivateSmartContractStateChannelsCounters {
            height: self.height,
            channel_count: self.channels.len() as u64,
            live_channel_count: self
                .channels
                .values()
                .filter(|channel| channel.status.is_live())
                .count() as u64,
            update_count: self.updates.len() as u64,
            live_update_count: self
                .updates
                .values()
                .filter(|update| update.status.live())
                .count() as u64,
            settlement_count: self.settlements.len() as u64,
            dispute_count: self.disputes.len() as u64,
            open_dispute_count: self
                .disputes
                .values()
                .filter(|dispute| dispute.status.open())
                .count() as u64,
            low_fee_channel_count: self
                .channels
                .values()
                .filter(|channel| channel.channel_kind.low_fee_eligible())
                .count() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_smart_contract_state_channels_state",
            "label": self.label,
            "height": self.height,
            "state_root": self.state_root(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_channel_ids": self.active_channel_ids(),
            "pending_update_ids": self.pending_update_ids(),
            "open_dispute_ids": self.open_dispute_ids(),
            "lane_liquidity_map": self.lane_liquidity_map(),
        })
    }

    pub fn validate(&self) -> PrivateSmartContractStateChannelsResult<String> {
        ensure_non_empty(&self.label, "private smart contract state channels label")?;
        self.config.validate()?;
        if self.channels.len() > PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_CHANNELS {
            return Err("private channel state has too many channels".to_string());
        }
        if self.updates.len() > PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_UPDATES {
            return Err("private channel state has too many updates".to_string());
        }
        if self.settlements.len() > PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_SETTLEMENTS {
            return Err("private channel state has too many settlements".to_string());
        }
        if self.disputes.len() > PRIVATE_SMART_CONTRACT_STATE_CHANNELS_MAX_DISPUTES {
            return Err("private channel state has too many disputes".to_string());
        }
        for channel in self.channels.values() {
            channel.validate()?;
        }
        for update in self.updates.values() {
            update.validate()?;
            if !self.channels.contains_key(&update.channel_id) {
                return Err("private channel update references missing channel".to_string());
            }
        }
        for settlement in self.settlements.values() {
            settlement.validate()?;
            if !self.channels.contains_key(&settlement.channel_id) {
                return Err("private channel settlement references missing channel".to_string());
            }
            if !self.updates.contains_key(&settlement.update_id) {
                return Err("private channel settlement references missing update".to_string());
            }
        }
        for dispute in self.disputes.values() {
            dispute.validate()?;
            if !self.channels.contains_key(&dispute.channel_id) {
                return Err("private channel dispute references missing channel".to_string());
            }
            if !self.updates.contains_key(&dispute.challenged_update_id) {
                return Err("private channel dispute references missing update".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn private_smart_contract_state_channels_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-SMART-CONTRACT-STATE-CHANNELS-STATE-ROOT-FROM-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn private_channel_config_id(protocol_version: &str, schema_version: &str) -> String {
    domain_hash(
        "PRIVATE-CHANNEL-CONFIG-ID",
        &[
            HashPart::Str(protocol_version),
            HashPart::Str(schema_version),
        ],
        24,
    )
}

pub fn private_channel_participant_id(
    account_commitment: &str,
    pq_key_commitment: &str,
    stake_commitment_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-CHANNEL-PARTICIPANT-ID",
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(pq_key_commitment),
            HashPart::Str(stake_commitment_root),
        ],
        24,
    )
}

pub fn private_contract_channel_id(
    channel_kind: PrivateChannelKind,
    contract_commitment: &str,
    lane_id: &str,
    participant_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-CHANNEL-ID",
        &[
            HashPart::Str(channel_kind.as_str()),
            HashPart::Str(contract_commitment),
            HashPart::Str(lane_id),
            HashPart::Str(participant_root),
            HashPart::Int(opened_height as i128),
        ],
        24,
    )
}

pub fn private_channel_update_id(
    channel_id: &str,
    nonce: u64,
    state_delta_root: &str,
    encrypted_witness_root: &str,
    participant_signature_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-CHANNEL-UPDATE-ID",
        &[
            HashPart::Str(channel_id),
            HashPart::Int(nonce as i128),
            HashPart::Str(state_delta_root),
            HashPart::Str(encrypted_witness_root),
            HashPart::Str(participant_signature_root),
        ],
        24,
    )
}

pub fn private_channel_settlement_id(
    channel_id: &str,
    update_id: &str,
    settlement_root: &str,
    exit_commitment_root: &str,
    settlement_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-CHANNEL-SETTLEMENT-ID",
        &[
            HashPart::Str(channel_id),
            HashPart::Str(update_id),
            HashPart::Str(settlement_root),
            HashPart::Str(exit_commitment_root),
            HashPart::Int(settlement_height as i128),
        ],
        24,
    )
}

pub fn private_channel_dispute_id(
    channel_id: &str,
    challenged_update_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-CHANNEL-DISPUTE-ID",
        &[
            HashPart::Str(channel_id),
            HashPart::Str(challenged_update_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_height as i128),
        ],
        24,
    )
}

fn private_channel_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn private_channel_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn private_channel_values_root(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

fn private_channel_empty_root(domain: &str) -> String {
    domain_hash(domain, &[], 32)
}

fn private_channel_map_root<T: PrivateChannelRooted>(
    domain: &str,
    map: &BTreeMap<String, T>,
) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "id": key, "root": value.root() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateSmartContractStateChannelsResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}
