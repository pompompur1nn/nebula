use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ZkCrossContractConfidentialMessageBusResult<T> = Result<T, String>;

pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_PROTOCOL_VERSION: &str =
    "nebula-zk-cross-contract-confidential-message-bus-v1";
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+shake256-cross-contract-confidential-envelope-v1";
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_PROOF_SYSTEM: &str =
    "zk-recursive-cross-contract-confidential-delivery-v1";
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_NULLIFIER_SCHEME: &str =
    "shake256-cross-contract-message-nullifier-lane-v1";
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_AUDIT_SCHEME: &str =
    "selective-disclosure-confidential-message-audit-root-v1";
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_CAPABILITY_SCHEME: &str =
    "zk-contract-capability-filter-commitment-v1";
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEVNET_HEIGHT: u64 = 768;
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_INBOX_TTL_BLOCKS: u64 = 96;
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 144;
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_MAX_BATCH_MESSAGES: usize = 96;
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 750;
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    ShieldedDex,
    PrivateLending,
    ConfidentialPerps,
    TokenBridge,
    PrivateTreasury,
    AccountRecovery,
    OracleRouter,
    GovernanceVault,
    Custom,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedDex => "shielded_dex",
            Self::PrivateLending => "private_lending",
            Self::ConfidentialPerps => "confidential_perps",
            Self::TokenBridge => "token_bridge",
            Self::PrivateTreasury => "private_treasury",
            Self::AccountRecovery => "account_recovery",
            Self::OracleRouter => "oracle_router",
            Self::GovernanceVault => "governance_vault",
            Self::Custom => "custom",
        }
    }

    pub fn privacy_floor(self) -> u64 {
        match self {
            Self::ShieldedDex => 192,
            Self::PrivateLending => 160,
            Self::ConfidentialPerps => 160,
            Self::TokenBridge => 192,
            Self::PrivateTreasury => 256,
            Self::AccountRecovery => 192,
            Self::OracleRouter => 96,
            Self::GovernanceVault => 160,
            Self::Custom => 128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    PrivateCall,
    StateCommitment,
    SettlementNotice,
    LiquidityIntent,
    OracleAnswer,
    RecoveryShare,
    GovernanceSignal,
    CapabilityGrant,
    CapabilityRevoke,
    AuditDisclosure,
}

impl MessageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCall => "private_call",
            Self::StateCommitment => "state_commitment",
            Self::SettlementNotice => "settlement_notice",
            Self::LiquidityIntent => "liquidity_intent",
            Self::OracleAnswer => "oracle_answer",
            Self::RecoveryShare => "recovery_share",
            Self::GovernanceSignal => "governance_signal",
            Self::CapabilityGrant => "capability_grant",
            Self::CapabilityRevoke => "capability_revoke",
            Self::AuditDisclosure => "audit_disclosure",
        }
    }

    pub fn requires_receipt(self) -> bool {
        matches!(
            self,
            Self::PrivateCall
                | Self::SettlementNotice
                | Self::RecoveryShare
                | Self::CapabilityGrant
                | Self::CapabilityRevoke
        )
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::RecoveryShare => 110,
            Self::SettlementNotice => 100,
            Self::PrivateCall => 90,
            Self::CapabilityGrant => 85,
            Self::CapabilityRevoke => 85,
            Self::LiquidityIntent => 80,
            Self::StateCommitment => 70,
            Self::OracleAnswer => 65,
            Self::GovernanceSignal => 50,
            Self::AuditDisclosure => 40,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxStatus {
    Active,
    Throttled,
    Quarantined,
    Retired,
}

impl InboxStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_messages(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Draft,
    Queued,
    Batched,
    Routed,
    Delivered,
    Receipted,
    Expired,
    Rejected,
}

impl EnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Queued => "queued",
            Self::Batched => "batched",
            Self::Routed => "routed",
            Self::Delivered => "delivered",
            Self::Receipted => "receipted",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Queued | Self::Batched | Self::Routed | Self::Delivered
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierLaneStatus {
    Open,
    Sealed,
    Draining,
    Slashed,
}

impl NullifierLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Draining => "draining",
            Self::Slashed => "slashed",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Published,
    Final,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Final => "final",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Published | Self::Final)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofEnvelopeStatus {
    Witnessed,
    Verified,
    Aggregated,
    Challenged,
    Rejected,
}

impl ProofEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Witnessed => "witnessed",
            Self::Verified => "verified",
            Self::Aggregated => "aggregated",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Verified | Self::Aggregated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityMode {
    Allow,
    Deny,
    Metered,
    AuditOnly,
}

impl CapabilityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Metered => "metered",
            Self::AuditOnly => "audit_only",
        }
    }

    pub fn can_route(self) -> bool {
        matches!(self, Self::Allow | Self::Metered | Self::AuditOnly)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub encryption_scheme: String,
    pub proof_system: String,
    pub nullifier_scheme: String,
    pub audit_scheme: String,
    pub capability_scheme: String,
    pub inbox_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub max_batch_messages: usize,
    pub min_privacy_set_size: u64,
    pub max_disclosure_bps: u64,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_PROTOCOL_VERSION
                .to_string(),
            encryption_scheme: ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_ENCRYPTION_SCHEME
                .to_string(),
            proof_system: ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_PROOF_SYSTEM.to_string(),
            nullifier_scheme: ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_NULLIFIER_SCHEME
                .to_string(),
            audit_scheme: ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_AUDIT_SCHEME.to_string(),
            capability_scheme: ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_CAPABILITY_SCHEME
                .to_string(),
            inbox_ttl_blocks: ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_INBOX_TTL_BLOCKS,
            batch_window_blocks:
                ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_BATCH_WINDOW_BLOCKS,
            receipt_ttl_blocks:
                ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_RECEIPT_TTL_BLOCKS,
            max_batch_messages:
                ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_MAX_BATCH_MESSAGES,
            min_privacy_set_size:
                ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_disclosure_bps:
                ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_MAX_DISCLOSURE_BPS,
            min_pq_security_bits:
                ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn validate(&self) -> ZkCrossContractConfidentialMessageBusResult<()> {
        if self.protocol_version != ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_PROTOCOL_VERSION {
            return Err("confidential message bus protocol version mismatch".to_string());
        }
        validate_nonempty("encryption_scheme", &self.encryption_scheme)?;
        validate_nonempty("proof_system", &self.proof_system)?;
        validate_nonempty("nullifier_scheme", &self.nullifier_scheme)?;
        validate_nonempty("audit_scheme", &self.audit_scheme)?;
        validate_nonempty("capability_scheme", &self.capability_scheme)?;
        validate_positive("inbox_ttl_blocks", self.inbox_ttl_blocks)?;
        validate_positive("batch_window_blocks", self.batch_window_blocks)?;
        validate_positive("receipt_ttl_blocks", self.receipt_ttl_blocks)?;
        if self.max_batch_messages == 0 {
            return Err("confidential message bus max_batch_messages must be positive".to_string());
        }
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        validate_bps("max_disclosure_bps", self.max_disclosure_bps)?;
        if self.min_pq_security_bits < 192 {
            return Err("confidential message bus minimum pq security below 192 bits".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "encryption_scheme": self.encryption_scheme,
            "proof_system": self.proof_system,
            "nullifier_scheme": self.nullifier_scheme,
            "audit_scheme": self.audit_scheme,
            "capability_scheme": self.capability_scheme,
            "inbox_ttl_blocks": self.inbox_ttl_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "max_batch_messages": self.max_batch_messages,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_disclosure_bps": self.max_disclosure_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedInbox {
    pub inbox_id: String,
    pub contract_id: String,
    pub domain: ContractDomain,
    pub encryption_key_commitment: String,
    pub read_policy_root: String,
    pub write_policy_root: String,
    pub capability_root: String,
    pub status: InboxStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub message_count: u64,
}

impl EncryptedInbox {
    pub fn new(
        contract_id: &str,
        domain: ContractDomain,
        encryption_key_commitment: &str,
        read_policy_root: &str,
        write_policy_root: &str,
        capability_root: &str,
        opened_at_height: u64,
        config: &Config,
    ) -> ZkCrossContractConfidentialMessageBusResult<Self> {
        validate_nonempty("contract_id", contract_id)?;
        validate_nonempty("encryption_key_commitment", encryption_key_commitment)?;
        validate_nonempty("read_policy_root", read_policy_root)?;
        validate_nonempty("write_policy_root", write_policy_root)?;
        validate_nonempty("capability_root", capability_root)?;
        let expires_at_height = opened_at_height.saturating_add(config.inbox_ttl_blocks);
        let inbox_id = deterministic_id(
            "INBOX-ID",
            &json!({
                "contract_id": contract_id,
                "domain": domain.as_str(),
                "encryption_key_commitment": encryption_key_commitment,
                "read_policy_root": read_policy_root,
                "write_policy_root": write_policy_root,
                "capability_root": capability_root,
                "opened_at_height": opened_at_height,
            }),
        );
        Ok(Self {
            inbox_id,
            contract_id: contract_id.to_string(),
            domain,
            encryption_key_commitment: encryption_key_commitment.to_string(),
            read_policy_root: read_policy_root.to_string(),
            write_policy_root: write_policy_root.to_string(),
            capability_root: capability_root.to_string(),
            status: InboxStatus::Active,
            opened_at_height,
            expires_at_height,
            message_count: 0,
        })
    }

    pub fn validate(&self) -> ZkCrossContractConfidentialMessageBusResult<()> {
        validate_nonempty("inbox_id", &self.inbox_id)?;
        validate_nonempty("contract_id", &self.contract_id)?;
        validate_nonempty("encryption_key_commitment", &self.encryption_key_commitment)?;
        validate_nonempty("read_policy_root", &self.read_policy_root)?;
        validate_nonempty("write_policy_root", &self.write_policy_root)?;
        validate_nonempty("capability_root", &self.capability_root)?;
        validate_window("inbox", self.opened_at_height, self.expires_at_height)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "inbox_id": self.inbox_id,
            "contract_id": self.contract_id,
            "domain": self.domain.as_str(),
            "encryption_key_commitment": self.encryption_key_commitment,
            "read_policy_root": self.read_policy_root,
            "write_policy_root": self.write_policy_root,
            "capability_root": self.capability_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "message_count": self.message_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierLane {
    pub lane_id: String,
    pub inbox_id: String,
    pub lane_label: String,
    pub nullifier_root: String,
    pub spent_nullifier_root: String,
    pub status: NullifierLaneStatus,
    pub opened_at_height: u64,
    pub next_sequence: u64,
    pub consumed_count: u64,
}

impl NullifierLane {
    pub fn new(
        inbox_id: &str,
        lane_label: &str,
        nullifier_root: &str,
        opened_at_height: u64,
    ) -> ZkCrossContractConfidentialMessageBusResult<Self> {
        validate_nonempty("inbox_id", inbox_id)?;
        validate_nonempty("lane_label", lane_label)?;
        validate_nonempty("nullifier_root", nullifier_root)?;
        let spent_nullifier_root = payload_root(
            "NULLIFIER-LANE-SPENT-EMPTY",
            &json!({"lane_label": lane_label}),
        );
        let lane_id = deterministic_id(
            "NULLIFIER-LANE-ID",
            &json!({
                "inbox_id": inbox_id,
                "lane_label": lane_label,
                "nullifier_root": nullifier_root,
                "opened_at_height": opened_at_height,
            }),
        );
        Ok(Self {
            lane_id,
            inbox_id: inbox_id.to_string(),
            lane_label: lane_label.to_string(),
            nullifier_root: nullifier_root.to_string(),
            spent_nullifier_root,
            status: NullifierLaneStatus::Open,
            opened_at_height,
            next_sequence: 0,
            consumed_count: 0,
        })
    }

    pub fn validate(&self) -> ZkCrossContractConfidentialMessageBusResult<()> {
        validate_nonempty("lane_id", &self.lane_id)?;
        validate_nonempty("inbox_id", &self.inbox_id)?;
        validate_nonempty("lane_label", &self.lane_label)?;
        validate_nonempty("nullifier_root", &self.nullifier_root)?;
        validate_nonempty("spent_nullifier_root", &self.spent_nullifier_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "inbox_id": self.inbox_id,
            "lane_label": self.lane_label,
            "nullifier_root": self.nullifier_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "next_sequence": self.next_sequence,
            "consumed_count": self.consumed_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFilter {
    pub filter_id: String,
    pub source_contract_id: String,
    pub target_contract_id: String,
    pub allowed_kinds: Vec<MessageKind>,
    pub mode: CapabilityMode,
    pub metering_root: String,
    pub audit_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl CapabilityFilter {
    pub fn new(
        source_contract_id: &str,
        target_contract_id: &str,
        allowed_kinds: Vec<MessageKind>,
        mode: CapabilityMode,
        metering_root: &str,
        audit_root: &str,
        valid_from_height: u64,
        config: &Config,
    ) -> ZkCrossContractConfidentialMessageBusResult<Self> {
        validate_nonempty("source_contract_id", source_contract_id)?;
        validate_nonempty("target_contract_id", target_contract_id)?;
        validate_nonempty("metering_root", metering_root)?;
        validate_nonempty("audit_root", audit_root)?;
        if allowed_kinds.is_empty() {
            return Err("confidential message bus capability requires message kinds".to_string());
        }
        let valid_until_height = valid_from_height.saturating_add(config.inbox_ttl_blocks);
        let kind_values = allowed_kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        let filter_id = deterministic_id(
            "CAPABILITY-FILTER-ID",
            &json!({
                "source_contract_id": source_contract_id,
                "target_contract_id": target_contract_id,
                "allowed_kinds": kind_values,
                "mode": mode.as_str(),
                "metering_root": metering_root,
                "audit_root": audit_root,
                "valid_from_height": valid_from_height,
            }),
        );
        Ok(Self {
            filter_id,
            source_contract_id: source_contract_id.to_string(),
            target_contract_id: target_contract_id.to_string(),
            allowed_kinds,
            mode,
            metering_root: metering_root.to_string(),
            audit_root: audit_root.to_string(),
            valid_from_height,
            valid_until_height,
        })
    }

    pub fn allows(&self, kind: MessageKind) -> bool {
        self.mode.can_route() && self.allowed_kinds.contains(&kind)
    }

    pub fn validate(&self) -> ZkCrossContractConfidentialMessageBusResult<()> {
        validate_nonempty("filter_id", &self.filter_id)?;
        validate_nonempty("source_contract_id", &self.source_contract_id)?;
        validate_nonempty("target_contract_id", &self.target_contract_id)?;
        validate_nonempty("metering_root", &self.metering_root)?;
        validate_nonempty("audit_root", &self.audit_root)?;
        if self.allowed_kinds.is_empty() {
            return Err("confidential message bus capability kind list empty".to_string());
        }
        validate_window(
            "capability",
            self.valid_from_height,
            self.valid_until_height,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "filter_id": self.filter_id,
            "source_contract_id": self.source_contract_id,
            "target_contract_id": self.target_contract_id,
            "allowed_kinds": self.allowed_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "mode": self.mode.as_str(),
            "metering_root": self.metering_root,
            "audit_root": self.audit_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEnvelope {
    pub proof_id: String,
    pub subject_root: String,
    pub prover_commitment: String,
    pub verifier_key_root: String,
    pub proof_root: String,
    pub public_input_root: String,
    pub privacy_set_size: u64,
    pub status: ProofEnvelopeStatus,
    pub created_at_height: u64,
}

impl ProofEnvelope {
    pub fn new(
        subject_root: &str,
        prover_commitment: &str,
        verifier_key_root: &str,
        public_input_root: &str,
        privacy_set_size: u64,
        status: ProofEnvelopeStatus,
        created_at_height: u64,
        config: &Config,
    ) -> ZkCrossContractConfidentialMessageBusResult<Self> {
        validate_nonempty("subject_root", subject_root)?;
        validate_nonempty("prover_commitment", prover_commitment)?;
        validate_nonempty("verifier_key_root", verifier_key_root)?;
        validate_nonempty("public_input_root", public_input_root)?;
        if privacy_set_size < config.min_privacy_set_size {
            return Err("confidential message bus proof privacy set below floor".to_string());
        }
        let proof_root = payload_root(
            "PROOF-ENVELOPE",
            &json!({
                "subject_root": subject_root,
                "prover_commitment": prover_commitment,
                "verifier_key_root": verifier_key_root,
                "public_input_root": public_input_root,
                "privacy_set_size": privacy_set_size,
                "created_at_height": created_at_height,
            }),
        );
        let proof_id = deterministic_id(
            "PROOF-ENVELOPE-ID",
            &json!({
                "subject_root": subject_root,
                "proof_root": proof_root,
                "created_at_height": created_at_height,
            }),
        );
        Ok(Self {
            proof_id,
            subject_root: subject_root.to_string(),
            prover_commitment: prover_commitment.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            proof_root,
            public_input_root: public_input_root.to_string(),
            privacy_set_size,
            status,
            created_at_height,
        })
    }

    pub fn validate(&self, config: &Config) -> ZkCrossContractConfidentialMessageBusResult<()> {
        validate_nonempty("proof_id", &self.proof_id)?;
        validate_nonempty("subject_root", &self.subject_root)?;
        validate_nonempty("prover_commitment", &self.prover_commitment)?;
        validate_nonempty("verifier_key_root", &self.verifier_key_root)?;
        validate_nonempty("proof_root", &self.proof_root)?;
        validate_nonempty("public_input_root", &self.public_input_root)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("confidential message bus proof privacy set below floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "subject_root": self.subject_root,
            "prover_commitment": self.prover_commitment,
            "verifier_key_root": self.verifier_key_root,
            "proof_root": self.proof_root,
            "public_input_root": self.public_input_root,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub message_id: String,
    pub source_inbox_id: String,
    pub target_inbox_id: String,
    pub lane_id: String,
    pub capability_filter_id: String,
    pub kind: MessageKind,
    pub ciphertext_root: String,
    pub metadata_commitment: String,
    pub replay_nullifier: String,
    pub disclosure_root: String,
    pub priority: u64,
    pub sequence: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: EnvelopeStatus,
}

impl MessageEnvelope {
    pub fn new(
        source_inbox_id: &str,
        target_inbox_id: &str,
        lane_id: &str,
        capability_filter_id: &str,
        kind: MessageKind,
        ciphertext_root: &str,
        metadata_commitment: &str,
        replay_nullifier: &str,
        disclosure_root: &str,
        sequence: u64,
        submitted_at_height: u64,
        config: &Config,
    ) -> ZkCrossContractConfidentialMessageBusResult<Self> {
        validate_nonempty("source_inbox_id", source_inbox_id)?;
        validate_nonempty("target_inbox_id", target_inbox_id)?;
        validate_nonempty("lane_id", lane_id)?;
        validate_nonempty("capability_filter_id", capability_filter_id)?;
        validate_nonempty("ciphertext_root", ciphertext_root)?;
        validate_nonempty("metadata_commitment", metadata_commitment)?;
        validate_nonempty("replay_nullifier", replay_nullifier)?;
        validate_nonempty("disclosure_root", disclosure_root)?;
        let expires_at_height = submitted_at_height.saturating_add(config.inbox_ttl_blocks);
        let priority = kind.default_priority();
        let message_id = deterministic_id(
            "MESSAGE-ID",
            &json!({
                "source_inbox_id": source_inbox_id,
                "target_inbox_id": target_inbox_id,
                "lane_id": lane_id,
                "capability_filter_id": capability_filter_id,
                "kind": kind.as_str(),
                "ciphertext_root": ciphertext_root,
                "metadata_commitment": metadata_commitment,
                "replay_nullifier": replay_nullifier,
                "sequence": sequence,
                "submitted_at_height": submitted_at_height,
            }),
        );
        Ok(Self {
            message_id,
            source_inbox_id: source_inbox_id.to_string(),
            target_inbox_id: target_inbox_id.to_string(),
            lane_id: lane_id.to_string(),
            capability_filter_id: capability_filter_id.to_string(),
            kind,
            ciphertext_root: ciphertext_root.to_string(),
            metadata_commitment: metadata_commitment.to_string(),
            replay_nullifier: replay_nullifier.to_string(),
            disclosure_root: disclosure_root.to_string(),
            priority,
            sequence,
            submitted_at_height,
            expires_at_height,
            status: EnvelopeStatus::Queued,
        })
    }

    pub fn validate(&self) -> ZkCrossContractConfidentialMessageBusResult<()> {
        validate_nonempty("message_id", &self.message_id)?;
        validate_nonempty("source_inbox_id", &self.source_inbox_id)?;
        validate_nonempty("target_inbox_id", &self.target_inbox_id)?;
        validate_nonempty("lane_id", &self.lane_id)?;
        validate_nonempty("capability_filter_id", &self.capability_filter_id)?;
        validate_nonempty("ciphertext_root", &self.ciphertext_root)?;
        validate_nonempty("metadata_commitment", &self.metadata_commitment)?;
        validate_nonempty("replay_nullifier", &self.replay_nullifier)?;
        validate_nonempty("disclosure_root", &self.disclosure_root)?;
        validate_window("message", self.submitted_at_height, self.expires_at_height)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "message_id": self.message_id,
            "source_inbox_id": self.source_inbox_id,
            "target_inbox_id": self.target_inbox_id,
            "lane_id": self.lane_id,
            "capability_filter_id": self.capability_filter_id,
            "kind": self.kind.as_str(),
            "ciphertext_root": self.ciphertext_root,
            "metadata_commitment": self.metadata_commitment,
            "replay_nullifier": self.replay_nullifier,
            "disclosure_root": self.disclosure_root,
            "priority": self.priority,
            "sequence": self.sequence,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayGuard {
    pub guard_id: String,
    pub lane_id: String,
    pub message_id: String,
    pub replay_nullifier: String,
    pub opened_at_height: u64,
    pub consumed: bool,
}

impl ReplayGuard {
    pub fn new(
        lane_id: &str,
        message_id: &str,
        replay_nullifier: &str,
        opened_at_height: u64,
    ) -> ZkCrossContractConfidentialMessageBusResult<Self> {
        validate_nonempty("lane_id", lane_id)?;
        validate_nonempty("message_id", message_id)?;
        validate_nonempty("replay_nullifier", replay_nullifier)?;
        let guard_id = deterministic_id(
            "REPLAY-GUARD-ID",
            &json!({
                "lane_id": lane_id,
                "message_id": message_id,
                "replay_nullifier": replay_nullifier,
                "opened_at_height": opened_at_height,
            }),
        );
        Ok(Self {
            guard_id,
            lane_id: lane_id.to_string(),
            message_id: message_id.to_string(),
            replay_nullifier: replay_nullifier.to_string(),
            opened_at_height,
            consumed: true,
        })
    }

    pub fn validate(&self) -> ZkCrossContractConfidentialMessageBusResult<()> {
        validate_nonempty("guard_id", &self.guard_id)?;
        validate_nonempty("lane_id", &self.lane_id)?;
        validate_nonempty("message_id", &self.message_id)?;
        validate_nonempty("replay_nullifier", &self.replay_nullifier)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "lane_id": self.lane_id,
            "message_id": self.message_id,
            "replay_nullifier": self.replay_nullifier,
            "opened_at_height": self.opened_at_height,
            "consumed": self.consumed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowLatencyBatch {
    pub batch_id: String,
    pub router_committee_id: String,
    pub message_ids: Vec<String>,
    pub message_root: String,
    pub route_hint_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub target_latency_ms: u64,
    pub proof_id: String,
}

impl LowLatencyBatch {
    pub fn new(
        router_committee_id: &str,
        messages: &[MessageEnvelope],
        route_hint_root: &str,
        opened_at_height: u64,
        target_latency_ms: u64,
        proof_id: &str,
        config: &Config,
    ) -> ZkCrossContractConfidentialMessageBusResult<Self> {
        validate_nonempty("router_committee_id", router_committee_id)?;
        validate_nonempty("route_hint_root", route_hint_root)?;
        validate_nonempty("proof_id", proof_id)?;
        validate_positive("target_latency_ms", target_latency_ms)?;
        if messages.is_empty() {
            return Err("confidential message bus batch cannot be empty".to_string());
        }
        if messages.len() > config.max_batch_messages {
            return Err("confidential message bus batch exceeds configured size".to_string());
        }
        let message_records = messages
            .iter()
            .map(MessageEnvelope::public_record)
            .collect::<Vec<_>>();
        let message_root = merkle_root("ZK-CC-CMB:batch:messages", &message_records);
        let sealed_at_height = opened_at_height.saturating_add(config.batch_window_blocks);
        let message_ids = messages
            .iter()
            .map(|message| message.message_id.clone())
            .collect::<Vec<_>>();
        let batch_id = deterministic_id(
            "LOW-LATENCY-BATCH-ID",
            &json!({
                "router_committee_id": router_committee_id,
                "message_root": message_root,
                "route_hint_root": route_hint_root,
                "opened_at_height": opened_at_height,
                "proof_id": proof_id,
            }),
        );
        Ok(Self {
            batch_id,
            router_committee_id: router_committee_id.to_string(),
            message_ids,
            message_root,
            route_hint_root: route_hint_root.to_string(),
            opened_at_height,
            sealed_at_height,
            target_latency_ms,
            proof_id: proof_id.to_string(),
        })
    }

    pub fn validate(&self, config: &Config) -> ZkCrossContractConfidentialMessageBusResult<()> {
        validate_nonempty("batch_id", &self.batch_id)?;
        validate_nonempty("router_committee_id", &self.router_committee_id)?;
        validate_nonempty("message_root", &self.message_root)?;
        validate_nonempty("route_hint_root", &self.route_hint_root)?;
        validate_nonempty("proof_id", &self.proof_id)?;
        validate_positive("target_latency_ms", self.target_latency_ms)?;
        if self.message_ids.is_empty() {
            return Err("confidential message bus batch has no messages".to_string());
        }
        if self.message_ids.len() > config.max_batch_messages {
            return Err("confidential message bus batch exceeds configured size".to_string());
        }
        validate_window("batch", self.opened_at_height, self.sealed_at_height)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "router_committee_id": self.router_committee_id,
            "message_ids": self.message_ids,
            "message_root": self.message_root,
            "route_hint_root": self.route_hint_root,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "target_latency_ms": self.target_latency_ms,
            "proof_id": self.proof_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    pub receipt_id: String,
    pub message_id: String,
    pub batch_id: String,
    pub target_inbox_id: String,
    pub delivery_proof_id: String,
    pub ack_ciphertext_root: String,
    pub delivered_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReceiptStatus,
}

impl DeliveryReceipt {
    pub fn new(
        message_id: &str,
        batch_id: &str,
        target_inbox_id: &str,
        delivery_proof_id: &str,
        ack_ciphertext_root: &str,
        delivered_at_height: u64,
        status: ReceiptStatus,
        config: &Config,
    ) -> ZkCrossContractConfidentialMessageBusResult<Self> {
        validate_nonempty("message_id", message_id)?;
        validate_nonempty("batch_id", batch_id)?;
        validate_nonempty("target_inbox_id", target_inbox_id)?;
        validate_nonempty("delivery_proof_id", delivery_proof_id)?;
        validate_nonempty("ack_ciphertext_root", ack_ciphertext_root)?;
        let expires_at_height = delivered_at_height.saturating_add(config.receipt_ttl_blocks);
        let receipt_id = deterministic_id(
            "DELIVERY-RECEIPT-ID",
            &json!({
                "message_id": message_id,
                "batch_id": batch_id,
                "target_inbox_id": target_inbox_id,
                "delivery_proof_id": delivery_proof_id,
                "ack_ciphertext_root": ack_ciphertext_root,
                "delivered_at_height": delivered_at_height,
            }),
        );
        Ok(Self {
            receipt_id,
            message_id: message_id.to_string(),
            batch_id: batch_id.to_string(),
            target_inbox_id: target_inbox_id.to_string(),
            delivery_proof_id: delivery_proof_id.to_string(),
            ack_ciphertext_root: ack_ciphertext_root.to_string(),
            delivered_at_height,
            expires_at_height,
            status,
        })
    }

    pub fn validate(&self) -> ZkCrossContractConfidentialMessageBusResult<()> {
        validate_nonempty("receipt_id", &self.receipt_id)?;
        validate_nonempty("message_id", &self.message_id)?;
        validate_nonempty("batch_id", &self.batch_id)?;
        validate_nonempty("target_inbox_id", &self.target_inbox_id)?;
        validate_nonempty("delivery_proof_id", &self.delivery_proof_id)?;
        validate_nonempty("ack_ciphertext_root", &self.ack_ciphertext_root)?;
        validate_window("receipt", self.delivered_at_height, self.expires_at_height)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "message_id": self.message_id,
            "batch_id": self.batch_id,
            "target_inbox_id": self.target_inbox_id,
            "delivery_proof_id": self.delivery_proof_id,
            "ack_ciphertext_root": self.ack_ciphertext_root,
            "delivered_at_height": self.delivered_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureAudit {
    pub audit_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub disclosure_root: String,
    pub revealed_field_root: String,
    pub auditor_commitment: String,
    pub max_disclosure_bps: u64,
    pub created_at_height: u64,
}

impl SelectiveDisclosureAudit {
    pub fn new(
        subject_id: &str,
        subject_kind: &str,
        disclosure_root: &str,
        revealed_field_root: &str,
        auditor_commitment: &str,
        max_disclosure_bps: u64,
        created_at_height: u64,
        config: &Config,
    ) -> ZkCrossContractConfidentialMessageBusResult<Self> {
        validate_nonempty("subject_id", subject_id)?;
        validate_nonempty("subject_kind", subject_kind)?;
        validate_nonempty("disclosure_root", disclosure_root)?;
        validate_nonempty("revealed_field_root", revealed_field_root)?;
        validate_nonempty("auditor_commitment", auditor_commitment)?;
        validate_bps("max_disclosure_bps", max_disclosure_bps)?;
        if max_disclosure_bps > config.max_disclosure_bps {
            return Err("confidential message bus audit disclosure exceeds config".to_string());
        }
        let audit_id = deterministic_id(
            "SELECTIVE-DISCLOSURE-AUDIT-ID",
            &json!({
                "subject_id": subject_id,
                "subject_kind": subject_kind,
                "disclosure_root": disclosure_root,
                "revealed_field_root": revealed_field_root,
                "auditor_commitment": auditor_commitment,
                "created_at_height": created_at_height,
            }),
        );
        Ok(Self {
            audit_id,
            subject_id: subject_id.to_string(),
            subject_kind: subject_kind.to_string(),
            disclosure_root: disclosure_root.to_string(),
            revealed_field_root: revealed_field_root.to_string(),
            auditor_commitment: auditor_commitment.to_string(),
            max_disclosure_bps,
            created_at_height,
        })
    }

    pub fn validate(&self, config: &Config) -> ZkCrossContractConfidentialMessageBusResult<()> {
        validate_nonempty("audit_id", &self.audit_id)?;
        validate_nonempty("subject_id", &self.subject_id)?;
        validate_nonempty("subject_kind", &self.subject_kind)?;
        validate_nonempty("disclosure_root", &self.disclosure_root)?;
        validate_nonempty("revealed_field_root", &self.revealed_field_root)?;
        validate_nonempty("auditor_commitment", &self.auditor_commitment)?;
        validate_bps("max_disclosure_bps", self.max_disclosure_bps)?;
        if self.max_disclosure_bps > config.max_disclosure_bps {
            return Err("confidential message bus audit disclosure exceeds config".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "disclosure_root": self.disclosure_root,
            "revealed_field_root": self.revealed_field_root,
            "auditor_commitment": self.auditor_commitment,
            "max_disclosure_bps": self.max_disclosure_bps,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub inbox_root: String,
    pub nullifier_lane_root: String,
    pub capability_filter_root: String,
    pub message_root: String,
    pub replay_guard_root: String,
    pub proof_envelope_root: String,
    pub batch_root: String,
    pub delivery_receipt_root: String,
    pub audit_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "inbox_root": self.inbox_root,
            "nullifier_lane_root": self.nullifier_lane_root,
            "capability_filter_root": self.capability_filter_root,
            "message_root": self.message_root,
            "replay_guard_root": self.replay_guard_root,
            "proof_envelope_root": self.proof_envelope_root,
            "batch_root": self.batch_root,
            "delivery_receipt_root": self.delivery_receipt_root,
            "audit_root": self.audit_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub inbox_count: u64,
    pub active_inbox_count: u64,
    pub nullifier_lane_count: u64,
    pub open_nullifier_lane_count: u64,
    pub capability_filter_count: u64,
    pub routable_capability_count: u64,
    pub message_count: u64,
    pub live_message_count: u64,
    pub replay_guard_count: u64,
    pub proof_envelope_count: u64,
    pub verified_proof_count: u64,
    pub batch_count: u64,
    pub delivery_receipt_count: u64,
    pub accepted_receipt_count: u64,
    pub audit_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "inbox_count": self.inbox_count,
            "active_inbox_count": self.active_inbox_count,
            "nullifier_lane_count": self.nullifier_lane_count,
            "open_nullifier_lane_count": self.open_nullifier_lane_count,
            "capability_filter_count": self.capability_filter_count,
            "routable_capability_count": self.routable_capability_count,
            "message_count": self.message_count,
            "live_message_count": self.live_message_count,
            "replay_guard_count": self.replay_guard_count,
            "proof_envelope_count": self.proof_envelope_count,
            "verified_proof_count": self.verified_proof_count,
            "batch_count": self.batch_count,
            "delivery_receipt_count": self.delivery_receipt_count,
            "accepted_receipt_count": self.accepted_receipt_count,
            "audit_count": self.audit_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub inboxes: BTreeMap<String, EncryptedInbox>,
    pub nullifier_lanes: BTreeMap<String, NullifierLane>,
    pub capability_filters: BTreeMap<String, CapabilityFilter>,
    pub messages: BTreeMap<String, MessageEnvelope>,
    pub replay_guards: BTreeMap<String, ReplayGuard>,
    pub proof_envelopes: BTreeMap<String, ProofEnvelope>,
    pub batches: BTreeMap<String, LowLatencyBatch>,
    pub delivery_receipts: BTreeMap<String, DeliveryReceipt>,
    pub audits: BTreeMap<String, SelectiveDisclosureAudit>,
    pub replay_nullifier_index: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> ZkCrossContractConfidentialMessageBusResult<State> {
        let config = Config::devnet();
        let mut state = State {
            height: ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_DEVNET_HEIGHT,
            config,
            inboxes: BTreeMap::new(),
            nullifier_lanes: BTreeMap::new(),
            capability_filters: BTreeMap::new(),
            messages: BTreeMap::new(),
            replay_guards: BTreeMap::new(),
            proof_envelopes: BTreeMap::new(),
            batches: BTreeMap::new(),
            delivery_receipts: BTreeMap::new(),
            audits: BTreeMap::new(),
            replay_nullifier_index: BTreeSet::new(),
        };

        let swap_inbox = EncryptedInbox::new(
            "shielded-swap-router",
            ContractDomain::ShieldedDex,
            &commitment("inbox-key", "shielded-swap-router"),
            &commitment("read-policy", "swap-router-read"),
            &commitment("write-policy", "swap-router-write"),
            &commitment("capability", "swap-router"),
            state.height,
            &state.config,
        )?;
        let lending_inbox = EncryptedInbox::new(
            "private-lending-vault",
            ContractDomain::PrivateLending,
            &commitment("inbox-key", "private-lending-vault"),
            &commitment("read-policy", "lending-read"),
            &commitment("write-policy", "lending-write"),
            &commitment("capability", "lending-vault"),
            state.height,
            &state.config,
        )?;
        let treasury_inbox = EncryptedInbox::new(
            "confidential-treasury",
            ContractDomain::PrivateTreasury,
            &commitment("inbox-key", "confidential-treasury"),
            &commitment("read-policy", "treasury-read"),
            &commitment("write-policy", "treasury-write"),
            &commitment("capability", "treasury"),
            state.height,
            &state.config,
        )?;

        let swap_inbox_id = swap_inbox.inbox_id.clone();
        let lending_inbox_id = lending_inbox.inbox_id.clone();
        let treasury_inbox_id = treasury_inbox.inbox_id.clone();
        state.insert_inbox(swap_inbox)?;
        state.insert_inbox(lending_inbox)?;
        state.insert_inbox(treasury_inbox)?;

        let swap_lane = NullifierLane::new(
            &swap_inbox_id,
            "swap-to-lending",
            &commitment("nullifier-root", "swap-to-lending"),
            state.height,
        )?;
        let treasury_lane = NullifierLane::new(
            &treasury_inbox_id,
            "treasury-to-swap",
            &commitment("nullifier-root", "treasury-to-swap"),
            state.height,
        )?;
        let swap_lane_id = swap_lane.lane_id.clone();
        let treasury_lane_id = treasury_lane.lane_id.clone();
        state.insert_nullifier_lane(swap_lane)?;
        state.insert_nullifier_lane(treasury_lane)?;

        let swap_to_lending = CapabilityFilter::new(
            "shielded-swap-router",
            "private-lending-vault",
            vec![MessageKind::LiquidityIntent, MessageKind::SettlementNotice],
            CapabilityMode::Metered,
            &commitment("meter", "swap-lending"),
            &commitment("audit", "swap-lending"),
            state.height,
            &state.config,
        )?;
        let treasury_to_swap = CapabilityFilter::new(
            "confidential-treasury",
            "shielded-swap-router",
            vec![MessageKind::PrivateCall, MessageKind::AuditDisclosure],
            CapabilityMode::AuditOnly,
            &commitment("meter", "treasury-swap"),
            &commitment("audit", "treasury-swap"),
            state.height,
            &state.config,
        )?;
        let swap_filter_id = swap_to_lending.filter_id.clone();
        let treasury_filter_id = treasury_to_swap.filter_id.clone();
        state.insert_capability_filter(swap_to_lending)?;
        state.insert_capability_filter(treasury_to_swap)?;

        let message_a = MessageEnvelope::new(
            &swap_inbox_id,
            &lending_inbox_id,
            &swap_lane_id,
            &swap_filter_id,
            MessageKind::LiquidityIntent,
            &commitment("ciphertext", "liquidity-intent-a"),
            &commitment("metadata", "liquidity-intent-a"),
            &commitment("replay-nullifier", "liquidity-intent-a"),
            &commitment("disclosure", "liquidity-intent-a"),
            0,
            state.height,
            &state.config,
        )?;
        let message_b = MessageEnvelope::new(
            &treasury_inbox_id,
            &swap_inbox_id,
            &treasury_lane_id,
            &treasury_filter_id,
            MessageKind::PrivateCall,
            &commitment("ciphertext", "treasury-rebalance-b"),
            &commitment("metadata", "treasury-rebalance-b"),
            &commitment("replay-nullifier", "treasury-rebalance-b"),
            &commitment("disclosure", "treasury-rebalance-b"),
            0,
            state.height,
            &state.config,
        )?;
        let message_a_id = message_a.message_id.clone();
        let message_b_id = message_b.message_id.clone();
        state.insert_message(message_a.clone())?;
        state.insert_message(message_b.clone())?;

        let proof = ProofEnvelope::new(
            &payload_root(
                "BATCH-SUBJECT",
                &json!({"messages": [&message_a_id, &message_b_id]}),
            ),
            &commitment("prover", "devnet-router-committee"),
            &commitment("vk", "confidential-message-router"),
            &commitment("public-input", "batch-a"),
            state.config.min_privacy_set_size.saturating_add(64),
            ProofEnvelopeStatus::Verified,
            state.height,
            &state.config,
        )?;
        let proof_id = proof.proof_id.clone();
        state.insert_proof_envelope(proof)?;

        let batch = LowLatencyBatch::new(
            "devnet-router-committee",
            &[message_a, message_b],
            &commitment("route-hints", "low-latency-a"),
            state.height,
            650,
            &proof_id,
            &state.config,
        )?;
        let batch_id = batch.batch_id.clone();
        state.insert_batch(batch)?;

        state.insert_delivery_receipt(DeliveryReceipt::new(
            &message_a_id,
            &batch_id,
            &lending_inbox_id,
            &proof_id,
            &commitment("ack", "liquidity-intent-a"),
            state.height.saturating_add(1),
            ReceiptStatus::Published,
            &state.config,
        )?)?;
        state.insert_delivery_receipt(DeliveryReceipt::new(
            &message_b_id,
            &batch_id,
            &swap_inbox_id,
            &proof_id,
            &commitment("ack", "treasury-rebalance-b"),
            state.height.saturating_add(1),
            ReceiptStatus::Published,
            &state.config,
        )?)?;
        state.insert_audit(SelectiveDisclosureAudit::new(
            &batch_id,
            "low_latency_batch",
            &commitment("disclosure", "batch-a"),
            &commitment("revealed-fields", "batch-a"),
            &commitment("auditor", "devnet-confidential-auditor"),
            state.config.max_disclosure_bps,
            state.height.saturating_add(1),
            &state.config,
        )?)?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_inbox(
        &mut self,
        inbox: EncryptedInbox,
    ) -> ZkCrossContractConfidentialMessageBusResult<()> {
        inbox.validate()?;
        self.inboxes.insert(inbox.inbox_id.clone(), inbox);
        Ok(())
    }

    pub fn insert_nullifier_lane(
        &mut self,
        lane: NullifierLane,
    ) -> ZkCrossContractConfidentialMessageBusResult<()> {
        lane.validate()?;
        if !self.inboxes.contains_key(&lane.inbox_id) {
            return Err("confidential message bus lane references missing inbox".to_string());
        }
        self.nullifier_lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_capability_filter(
        &mut self,
        filter: CapabilityFilter,
    ) -> ZkCrossContractConfidentialMessageBusResult<()> {
        filter.validate()?;
        self.capability_filters
            .insert(filter.filter_id.clone(), filter);
        Ok(())
    }

    pub fn insert_message(
        &mut self,
        mut message: MessageEnvelope,
    ) -> ZkCrossContractConfidentialMessageBusResult<()> {
        message.validate()?;
        let source_inbox = self.inboxes.get(&message.source_inbox_id).ok_or_else(|| {
            "confidential message bus message references missing source inbox".to_string()
        })?;
        let target_inbox = self.inboxes.get(&message.target_inbox_id).ok_or_else(|| {
            "confidential message bus message references missing target inbox".to_string()
        })?;
        if !source_inbox.status.accepts_messages() || !target_inbox.status.accepts_messages() {
            return Err("confidential message bus inbox does not accept messages".to_string());
        }
        let lane = self
            .nullifier_lanes
            .get_mut(&message.lane_id)
            .ok_or_else(|| {
                "confidential message bus message references missing lane".to_string()
            })?;
        if lane.inbox_id != message.source_inbox_id {
            return Err("confidential message bus message lane source mismatch".to_string());
        }
        if !lane.status.spendable() {
            return Err("confidential message bus lane is not spendable".to_string());
        }
        let filter = self
            .capability_filters
            .get(&message.capability_filter_id)
            .ok_or_else(|| {
                "confidential message bus message references missing capability".to_string()
            })?;
        if !filter.allows(message.kind) {
            return Err(
                "confidential message bus capability does not allow message kind".to_string(),
            );
        }
        if self
            .replay_nullifier_index
            .contains(&message.replay_nullifier)
        {
            return Err("confidential message bus replay nullifier already consumed".to_string());
        }
        self.replay_nullifier_index
            .insert(message.replay_nullifier.clone());
        let guard = ReplayGuard::new(
            &message.lane_id,
            &message.message_id,
            &message.replay_nullifier,
            message.submitted_at_height,
        )?;
        message.status = EnvelopeStatus::Queued;
        lane.next_sequence = lane.next_sequence.saturating_add(1);
        lane.consumed_count = lane.consumed_count.saturating_add(1);
        if let Some(source) = self.inboxes.get_mut(&message.source_inbox_id) {
            source.message_count = source.message_count.saturating_add(1);
        }
        self.replay_guards.insert(guard.guard_id.clone(), guard);
        self.messages.insert(message.message_id.clone(), message);
        Ok(())
    }

    pub fn insert_proof_envelope(
        &mut self,
        proof: ProofEnvelope,
    ) -> ZkCrossContractConfidentialMessageBusResult<()> {
        proof.validate(&self.config)?;
        self.proof_envelopes.insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    pub fn insert_batch(
        &mut self,
        batch: LowLatencyBatch,
    ) -> ZkCrossContractConfidentialMessageBusResult<()> {
        batch.validate(&self.config)?;
        if !self.proof_envelopes.contains_key(&batch.proof_id) {
            return Err("confidential message bus batch references missing proof".to_string());
        }
        for message_id in &batch.message_ids {
            let message = self.messages.get_mut(message_id).ok_or_else(|| {
                "confidential message bus batch references missing message".to_string()
            })?;
            message.status = EnvelopeStatus::Batched;
        }
        self.batches.insert(batch.batch_id.clone(), batch);
        Ok(())
    }

    pub fn insert_delivery_receipt(
        &mut self,
        receipt: DeliveryReceipt,
    ) -> ZkCrossContractConfidentialMessageBusResult<()> {
        receipt.validate()?;
        if !self.messages.contains_key(&receipt.message_id) {
            return Err("confidential message bus receipt references missing message".to_string());
        }
        if !self.batches.contains_key(&receipt.batch_id) {
            return Err("confidential message bus receipt references missing batch".to_string());
        }
        if !self
            .proof_envelopes
            .contains_key(&receipt.delivery_proof_id)
        {
            return Err("confidential message bus receipt references missing proof".to_string());
        }
        if let Some(message) = self.messages.get_mut(&receipt.message_id) {
            message.status = if receipt.status.accepted() {
                EnvelopeStatus::Receipted
            } else {
                EnvelopeStatus::Delivered
            };
        }
        self.delivery_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_audit(
        &mut self,
        audit: SelectiveDisclosureAudit,
    ) -> ZkCrossContractConfidentialMessageBusResult<()> {
        audit.validate(&self.config)?;
        self.audits.insert(audit.audit_id.clone(), audit);
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> ZkCrossContractConfidentialMessageBusResult<()> {
        if height < self.height {
            return Err("confidential message bus height cannot decrease".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn update_height(&mut self, delta: u64) -> ZkCrossContractConfidentialMessageBusResult<()> {
        self.height = self.height.saturating_add(delta);
        Ok(())
    }

    pub fn validate(&self) -> ZkCrossContractConfidentialMessageBusResult<()> {
        self.config.validate()?;
        let mut replay_nullifiers = BTreeSet::new();
        for inbox in self.inboxes.values() {
            inbox.validate()?;
        }
        for lane in self.nullifier_lanes.values() {
            lane.validate()?;
            if !self.inboxes.contains_key(&lane.inbox_id) {
                return Err("confidential message bus lane references missing inbox".to_string());
            }
        }
        for filter in self.capability_filters.values() {
            filter.validate()?;
        }
        for message in self.messages.values() {
            message.validate()?;
            if !self.inboxes.contains_key(&message.source_inbox_id) {
                return Err("confidential message bus message missing source inbox".to_string());
            }
            if !self.inboxes.contains_key(&message.target_inbox_id) {
                return Err("confidential message bus message missing target inbox".to_string());
            }
            if !self.nullifier_lanes.contains_key(&message.lane_id) {
                return Err("confidential message bus message missing lane".to_string());
            }
            let filter = self
                .capability_filters
                .get(&message.capability_filter_id)
                .ok_or_else(|| "confidential message bus message missing capability".to_string())?;
            if !filter.allows(message.kind) {
                return Err("confidential message bus message violates capability".to_string());
            }
            if !replay_nullifiers.insert(message.replay_nullifier.clone()) {
                return Err("confidential message bus duplicate replay nullifier".to_string());
            }
        }
        if replay_nullifiers != self.replay_nullifier_index {
            return Err("confidential message bus replay nullifier index mismatch".to_string());
        }
        for guard in self.replay_guards.values() {
            guard.validate()?;
            if !self.messages.contains_key(&guard.message_id) {
                return Err("confidential message bus guard references missing message".to_string());
            }
        }
        for proof in self.proof_envelopes.values() {
            proof.validate(&self.config)?;
        }
        for batch in self.batches.values() {
            batch.validate(&self.config)?;
            if !self.proof_envelopes.contains_key(&batch.proof_id) {
                return Err("confidential message bus batch references missing proof".to_string());
            }
            for message_id in &batch.message_ids {
                if !self.messages.contains_key(message_id) {
                    return Err(
                        "confidential message bus batch references missing message".to_string()
                    );
                }
            }
        }
        for receipt in self.delivery_receipts.values() {
            receipt.validate()?;
            if !self.messages.contains_key(&receipt.message_id) {
                return Err(
                    "confidential message bus receipt references missing message".to_string(),
                );
            }
            if !self.batches.contains_key(&receipt.batch_id) {
                return Err("confidential message bus receipt references missing batch".to_string());
            }
        }
        for audit in self.audits.values() {
            audit.validate(&self.config)?;
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root("CONFIG", &self.config.public_record()),
            inbox_root: collection_root(
                "INBOXES",
                self.inboxes
                    .values()
                    .map(EncryptedInbox::public_record)
                    .collect(),
            ),
            nullifier_lane_root: collection_root(
                "NULLIFIER-LANES",
                self.nullifier_lanes
                    .values()
                    .map(NullifierLane::public_record)
                    .collect(),
            ),
            capability_filter_root: collection_root(
                "CAPABILITY-FILTERS",
                self.capability_filters
                    .values()
                    .map(CapabilityFilter::public_record)
                    .collect(),
            ),
            message_root: collection_root(
                "MESSAGES",
                self.messages
                    .values()
                    .map(MessageEnvelope::public_record)
                    .collect(),
            ),
            replay_guard_root: collection_root(
                "REPLAY-GUARDS",
                self.replay_guards
                    .values()
                    .map(ReplayGuard::public_record)
                    .collect(),
            ),
            proof_envelope_root: collection_root(
                "PROOF-ENVELOPES",
                self.proof_envelopes
                    .values()
                    .map(ProofEnvelope::public_record)
                    .collect(),
            ),
            batch_root: collection_root(
                "BATCHES",
                self.batches
                    .values()
                    .map(LowLatencyBatch::public_record)
                    .collect(),
            ),
            delivery_receipt_root: collection_root(
                "DELIVERY-RECEIPTS",
                self.delivery_receipts
                    .values()
                    .map(DeliveryReceipt::public_record)
                    .collect(),
            ),
            audit_root: collection_root(
                "AUDITS",
                self.audits
                    .values()
                    .map(SelectiveDisclosureAudit::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            inbox_count: self.inboxes.len() as u64,
            active_inbox_count: self
                .inboxes
                .values()
                .filter(|inbox| inbox.status.accepts_messages())
                .count() as u64,
            nullifier_lane_count: self.nullifier_lanes.len() as u64,
            open_nullifier_lane_count: self
                .nullifier_lanes
                .values()
                .filter(|lane| lane.status.spendable())
                .count() as u64,
            capability_filter_count: self.capability_filters.len() as u64,
            routable_capability_count: self
                .capability_filters
                .values()
                .filter(|filter| filter.mode.can_route())
                .count() as u64,
            message_count: self.messages.len() as u64,
            live_message_count: self
                .messages
                .values()
                .filter(|message| message.status.live())
                .count() as u64,
            replay_guard_count: self.replay_guards.len() as u64,
            proof_envelope_count: self.proof_envelopes.len() as u64,
            verified_proof_count: self
                .proof_envelopes
                .values()
                .filter(|proof| proof.status.usable())
                .count() as u64,
            batch_count: self.batches.len() as u64,
            delivery_receipt_count: self.delivery_receipts.len() as u64,
            accepted_receipt_count: self
                .delivery_receipts
                .values()
                .filter(|receipt| receipt.status.accepted())
                .count() as u64,
            audit_count: self.audits.len() as u64,
        }
    }

    pub fn live_message_ids(&self) -> Vec<String> {
        self.messages
            .values()
            .filter(|message| message.status.live())
            .map(|message| message.message_id.clone())
            .collect()
    }

    pub fn accepted_receipt_ids(&self) -> Vec<String> {
        self.delivery_receipts
            .values()
            .filter(|receipt| receipt.status.accepted())
            .map(|receipt| receipt.receipt_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_cross_contract_confidential_message_bus_state",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_PROTOCOL_VERSION,
            "height": self.height,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_message_ids": self.live_message_ids(),
            "accepted_receipt_ids": self.accepted_receipt_ids(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    stable_hash(
        "ZK-CROSS-CONTRACT-CONFIDENTIAL-MESSAGE-BUS:STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> ZkCrossContractConfidentialMessageBusResult<State> {
    State::devnet()
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    stable_hash(
        &format!("ZK-CROSS-CONTRACT-CONFIDENTIAL-MESSAGE-BUS:{domain}:PAYLOAD"),
        &[
            HashPart::Str(ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn deterministic_id(domain: &str, payload: &Value) -> String {
    stable_hash(
        &format!("ZK-CROSS-CONTRACT-CONFIDENTIAL-MESSAGE-BUS:{domain}"),
        &[
            HashPart::Str(ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn commitment(domain: &str, label: &str) -> String {
    payload_root(
        "DETERMINISTIC-COMMITMENT",
        &json!({
            "domain": domain,
            "label": label,
        }),
    )
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("ZK-CROSS-CONTRACT-CONFIDENTIAL-MESSAGE-BUS:{domain}"),
        &records,
    )
}

fn validate_nonempty(label: &str, value: &str) -> ZkCrossContractConfidentialMessageBusResult<()> {
    if value.trim().is_empty() {
        return Err(format!(
            "confidential message bus {label} must be populated"
        ));
    }
    Ok(())
}

fn validate_positive(label: &str, value: u64) -> ZkCrossContractConfidentialMessageBusResult<()> {
    if value == 0 {
        return Err(format!("confidential message bus {label} must be positive"));
    }
    Ok(())
}

fn validate_bps(label: &str, value: u64) -> ZkCrossContractConfidentialMessageBusResult<()> {
    if value > ZK_CROSS_CONTRACT_CONFIDENTIAL_MESSAGE_BUS_MAX_BPS {
        return Err(format!(
            "confidential message bus {label} exceeds basis-point maximum"
        ));
    }
    Ok(())
}

fn validate_window(
    label: &str,
    start_height: u64,
    end_height: u64,
) -> ZkCrossContractConfidentialMessageBusResult<()> {
    if end_height <= start_height {
        return Err(format!(
            "confidential message bus {label} height window is inverted"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_roots_are_deterministic(
    ) -> ZkCrossContractConfidentialMessageBusResult<()> {
        let state_a = State::devnet()?;
        let state_b = State::devnet()?;
        assert_eq!(state_a.state_root(), state_b.state_root());
        assert_eq!(state_a.counters().inbox_count, 3);
        assert_eq!(state_a.counters().delivery_receipt_count, 2);
        state_a.validate()?;
        Ok(())
    }

    #[test]
    fn height_updates_are_monotonic() -> ZkCrossContractConfidentialMessageBusResult<()> {
        let mut state = State::devnet()?;
        let height = state.height;
        state.update_height(3)?;
        assert_eq!(state.height, height.saturating_add(3));
        assert!(state.set_height(height).is_err());
        Ok(())
    }

    #[test]
    fn replay_guard_rejects_duplicate_nullifier() -> ZkCrossContractConfidentialMessageBusResult<()>
    {
        let mut state = State::devnet()?;
        let existing = state
            .messages
            .values()
            .next()
            .map(|message| message.clone());
        if let Some(message) = existing {
            assert!(state.insert_message(message).is_err());
        }
        Ok(())
    }
}
