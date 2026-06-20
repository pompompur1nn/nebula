use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractPolicyEngineRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractPolicyEngineRuntimeResult<T>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-policy-engine-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEVNET_HEIGHT: u64 = 1_208_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-policy-engine-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+Poseidon2-transcript+AEAD-confidential-policy-rule-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_MONERO_PRIVACY_SUITE: &str =
    "Monero-RingCT-viewtag-nullifier-fence-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MIN_PRIVACY_SET: u64 =
    65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: u64 =
    524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_ENGINE_FEE_BPS:
    u64 = 9;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 =
    6;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_RULE_TTL_BLOCKS: u64 =
    86_400;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS: u64 =
    72;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS:
    u64 = 144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS:
    u64 = 32;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize =
    4_096;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_POLICY_DOMAINS:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_RULES: usize =
    16_777_216;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_TICKETS: usize =
    67_108_864;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 33_554_432;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_RESERVATIONS:
    usize = 16_777_216;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    67_108_864;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_REBATES: usize =
    16_777_216;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_FENCES: usize =
    134_217_728;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDomainKind {
    Wallet,
    Dex,
    Lending,
    Perpetuals,
    Bridge,
    Oracle,
    Governance,
    Token,
    Emergency,
    Custom,
}

impl PolicyDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Bridge => "bridge",
            Self::Oracle => "oracle",
            Self::Governance => "governance",
            Self::Token => "token",
            Self::Emergency => "emergency",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDomainStatus {
    Draft,
    Active,
    Frozen,
    Quarantined,
    Retired,
}

impl PolicyDomainStatus {
    pub fn accepts_rules(self) -> bool {
        matches!(self, Self::Draft | Self::Active)
    }

    pub fn evaluates_tickets(self) -> bool {
        matches!(self, Self::Active | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    ContractAllowlist,
    ContractDenylist,
    MethodSelector,
    SpendLimit,
    RateLimit,
    StateDependency,
    OracleBound,
    SponsorBound,
    PrivacyFloor,
    EmergencyStop,
}

impl RuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractAllowlist => "contract_allowlist",
            Self::ContractDenylist => "contract_denylist",
            Self::MethodSelector => "method_selector",
            Self::SpendLimit => "spend_limit",
            Self::RateLimit => "rate_limit",
            Self::StateDependency => "state_dependency",
            Self::OracleBound => "oracle_bound",
            Self::SponsorBound => "sponsor_bound",
            Self::PrivacyFloor => "privacy_floor",
            Self::EmergencyStop => "emergency_stop",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    Proposed,
    Active,
    Learning,
    Shadow,
    Paused,
    Revoked,
    Expired,
}

impl RuleStatus {
    pub fn participates(self) -> bool {
        matches!(self, Self::Active | Self::Learning | Self::Shadow)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Encrypted,
    Attested,
    Sponsored,
    Batched,
    Authorized,
    Denied,
    Quarantined,
    Settled,
    Expired,
    Cancelled,
}

impl TicketStatus {
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Attested | Self::Sponsored | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    PolicyAuthor,
    ContractAuditor,
    PqSigner,
    PrivacyWitness,
    FeeSponsor,
    EmergencyCouncil,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithWarning,
    NeedsMoreWitnesses,
    Invalid,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationDecision {
    Allow,
    AllowWithLimits,
    RequireSponsor,
    RequireMoreProofs,
    Deny,
    Quarantine,
    DropReplay,
}

impl EvaluationDecision {
    pub fn permits_execution(self) -> bool {
        matches!(self, Self::Allow | Self::AllowWithLimits)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Posted,
    Settled,
    PartiallySettled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn anchors_root(self) -> bool {
        matches!(self, Self::Sealed | Self::Posted | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    BoundToTicket,
    Consumed,
    RebateQueued,
    Released,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    TicketAuthorization,
    TicketDenial,
    SponsorSettlement,
    PolicyRuleUpdate,
    RebateCredit,
    BatchSettlement,
    EmergencyQuarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToPrivacySet,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Reserved,
    Spent,
    Burned,
    Disputed,
    Expired,
}

impl FenceStatus {
    pub fn blocks_replay(self) -> bool {
        matches!(self, Self::Reserved | Self::Spent | Self::Burned)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_suite: String,
    pub encryption_suite: String,
    pub monero_privacy_suite: String,
    pub min_privacy_set: u64,
    pub batch_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub max_engine_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub rule_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub max_batch_items: usize,
    pub max_policy_domains: usize,
    pub max_rules: usize,
    pub max_tickets: usize,
    pub max_attestations: usize,
    pub max_batches: usize,
    pub max_reservations: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_fences: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_HASH_SUITE
                .to_string(),
            pq_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_PQ_SUITE
                .to_string(),
            encryption_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_ENCRYPTION_SUITE
                    .to_string(),
            monero_privacy_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_MONERO_PRIVACY_SUITE
                    .to_string(),
            min_privacy_set:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_engine_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_ENGINE_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            rule_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_RULE_TTL_BLOCKS,
            ticket_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS,
            attestation_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_window_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            max_batch_items:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            max_policy_domains:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_POLICY_DOMAINS,
            max_rules: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_RULES,
            max_tickets:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_TICKETS,
            max_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_batches:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_BATCHES,
            max_reservations:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_receipts:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_REBATES,
            max_fences: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEFAULT_MAX_FENCES,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "encryption_suite": self.encryption_suite,
            "monero_privacy_suite": self.monero_privacy_suite,
            "min_privacy_set": self.min_privacy_set,
            "batch_privacy_set": self.batch_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_engine_fee_bps": self.max_engine_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "rule_ttl_blocks": self.rule_ttl_blocks,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "max_batch_items": self.max_batch_items,
            "max_policy_domains": self.max_policy_domains,
            "max_rules": self.max_rules,
            "max_tickets": self.max_tickets,
            "max_attestations": self.max_attestations,
            "max_batches": self.max_batches,
            "max_reservations": self.max_reservations,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_fences": self.max_fences,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub domains: u64,
    pub encrypted_rules: u64,
    pub authorization_tickets: u64,
    pub committee_attestations: u64,
    pub evaluation_batches: u64,
    pub sponsor_reservations: u64,
    pub settlement_receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub allowed_tickets: u64,
    pub denied_tickets: u64,
    pub quarantined_tickets: u64,
    pub replay_drops: u64,
    pub total_fee_reserved_piconero: u128,
    pub total_fee_spent_piconero: u128,
    pub total_rebate_piconero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "domains": self.domains,
            "encrypted_rules": self.encrypted_rules,
            "authorization_tickets": self.authorization_tickets,
            "committee_attestations": self.committee_attestations,
            "evaluation_batches": self.evaluation_batches,
            "sponsor_reservations": self.sponsor_reservations,
            "settlement_receipts": self.settlement_receipts,
            "rebates": self.rebates,
            "privacy_fences": self.privacy_fences,
            "allowed_tickets": self.allowed_tickets,
            "denied_tickets": self.denied_tickets,
            "quarantined_tickets": self.quarantined_tickets,
            "replay_drops": self.replay_drops,
            "total_fee_reserved_piconero": self.total_fee_reserved_piconero,
            "total_fee_spent_piconero": self.total_fee_spent_piconero,
            "total_rebate_piconero": self.total_rebate_piconero,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub domain_root: String,
    pub encrypted_rule_root: String,
    pub ticket_root: String,
    pub attestation_root: String,
    pub batch_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        Self {
            config_root: domain_hash(
                "PRIVATE-L2-PQ-POLICY-CONFIG",
                &[HashPart::Json(&config.public_record())],
                32,
            ),
            domain_root: merkle_root("PRIVATE-L2-PQ-POLICY-DOMAIN", &[]),
            encrypted_rule_root: merkle_root("PRIVATE-L2-PQ-POLICY-RULE", &[]),
            ticket_root: merkle_root("PRIVATE-L2-PQ-POLICY-TICKET", &[]),
            attestation_root: merkle_root("PRIVATE-L2-PQ-POLICY-ATTESTATION", &[]),
            batch_root: merkle_root("PRIVATE-L2-PQ-POLICY-BATCH", &[]),
            sponsor_reservation_root: merkle_root("PRIVATE-L2-PQ-POLICY-SPONSOR", &[]),
            settlement_receipt_root: merkle_root("PRIVATE-L2-PQ-POLICY-RECEIPT", &[]),
            rebate_root: merkle_root("PRIVATE-L2-PQ-POLICY-REBATE", &[]),
            privacy_fence_root: merkle_root("PRIVATE-L2-PQ-POLICY-FENCE", &[]),
            nullifier_root: merkle_root("PRIVATE-L2-PQ-POLICY-NULLIFIER", &[]),
            event_root: merkle_root("PRIVATE-L2-PQ-POLICY-EVENT", &[]),
            counters_root: domain_hash(
                "PRIVATE-L2-PQ-POLICY-COUNTERS",
                &[HashPart::Json(&Counters::default().public_record())],
                32,
            ),
        }
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-PQ-POLICY-ROOTS",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.domain_root),
                HashPart::Str(&self.encrypted_rule_root),
                HashPart::Str(&self.ticket_root),
                HashPart::Str(&self.attestation_root),
                HashPart::Str(&self.batch_root),
                HashPart::Str(&self.sponsor_reservation_root),
                HashPart::Str(&self.settlement_receipt_root),
                HashPart::Str(&self.rebate_root),
                HashPart::Str(&self.privacy_fence_root),
                HashPart::Str(&self.nullifier_root),
                HashPart::Str(&self.event_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "domain_root": self.domain_root,
            "encrypted_rule_root": self.encrypted_rule_root,
            "ticket_root": self.ticket_root,
            "attestation_root": self.attestation_root,
            "batch_root": self.batch_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyDomain {
    pub domain_id: String,
    pub owner_commitment: String,
    pub kind: PolicyDomainKind,
    pub status: PolicyDomainStatus,
    pub label_hash: String,
    pub contract_scope_root: String,
    pub committee_root: String,
    pub policy_epoch: u64,
    pub min_privacy_set: u64,
    pub max_fee_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: Option<u64>,
    pub metadata_root: String,
}

impl PolicyDomain {
    pub fn public_record(&self) -> Value {
        json!({
            "domain_id": self.domain_id,
            "owner_commitment": self.owner_commitment,
            "kind": self.kind,
            "status": self.status,
            "label_hash": self.label_hash,
            "contract_scope_root": self.contract_scope_root,
            "committee_root": self.committee_root,
            "policy_epoch": self.policy_epoch,
            "min_privacy_set": self.min_privacy_set,
            "max_fee_bps": self.max_fee_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedPolicyRule {
    pub rule_id: String,
    pub domain_id: String,
    pub rule_kind: RuleKind,
    pub status: RuleStatus,
    pub encrypted_rule_root: String,
    pub ciphertext_hash: String,
    pub rule_commitment: String,
    pub policy_tag: String,
    pub priority: u32,
    pub risk_weight: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub version: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub nullifier_domain: String,
    pub attestation_root: String,
}

impl EncryptedPolicyRule {
    pub fn public_record(&self) -> Value {
        json!({
            "rule_id": self.rule_id,
            "domain_id": self.domain_id,
            "rule_kind": self.rule_kind,
            "status": self.status,
            "encrypted_rule_root": self.encrypted_rule_root,
            "ciphertext_hash": self.ciphertext_hash,
            "rule_commitment": self.rule_commitment,
            "policy_tag": self.policy_tag,
            "priority": self.priority,
            "risk_weight": self.risk_weight,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "version": self.version,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "nullifier_domain": self.nullifier_domain,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallAuthorizationTicket {
    pub ticket_id: String,
    pub domain_id: String,
    pub caller_commitment: String,
    pub contract_commitment: String,
    pub method_selector_hash: String,
    pub calldata_root: String,
    pub call_value_commitment: String,
    pub asset_root: String,
    pub capability_root: String,
    pub sponsor_reservation_id: Option<String>,
    pub privacy_fence_id: String,
    pub nullifier: String,
    pub status: TicketStatus,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub max_fee_piconero: u128,
    pub priority_fee_piconero: u128,
}

impl ContractCallAuthorizationTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "domain_id": self.domain_id,
            "caller_commitment": self.caller_commitment,
            "contract_commitment": self.contract_commitment,
            "method_selector_hash": self.method_selector_hash,
            "calldata_root": self.calldata_root,
            "call_value_commitment": self.call_value_commitment,
            "asset_root": self.asset_root,
            "capability_root": self.capability_root,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "privacy_fence_id": self.privacy_fence_id,
            "nullifier": self.nullifier,
            "status": self.status,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "max_fee_piconero": self.max_fee_piconero,
            "priority_fee_piconero": self.priority_fee_piconero,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommitteeAttestation {
    pub attestation_id: String,
    pub domain_id: String,
    pub subject_id: String,
    pub role: CommitteeRole,
    pub verdict: AttestationVerdict,
    pub committee_epoch: u64,
    pub signer_set_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub threshold: u16,
    pub signers: u16,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqCommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "domain_id": self.domain_id,
            "subject_id": self.subject_id,
            "role": self.role,
            "verdict": self.verdict,
            "committee_epoch": self.committee_epoch,
            "signer_set_root": self.signer_set_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "threshold": self.threshold,
            "signers": self.signers,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuleEvaluationBatch {
    pub batch_id: String,
    pub domain_id: String,
    pub status: BatchStatus,
    pub ticket_root: String,
    pub rule_root: String,
    pub decision_root: String,
    pub attestation_root: String,
    pub privacy_fence_root: String,
    pub batch_size: usize,
    pub allowed_count: u64,
    pub denied_count: u64,
    pub quarantined_count: u64,
    pub replay_drop_count: u64,
    pub total_fee_piconero: u128,
    pub rebate_pool_piconero: u128,
    pub sealed_at_height: u64,
    pub settlement_deadline_height: u64,
}

impl RuleEvaluationBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "domain_id": self.domain_id,
            "status": self.status,
            "ticket_root": self.ticket_root,
            "rule_root": self.rule_root,
            "decision_root": self.decision_root,
            "attestation_root": self.attestation_root,
            "privacy_fence_root": self.privacy_fence_root,
            "batch_size": self.batch_size,
            "allowed_count": self.allowed_count,
            "denied_count": self.denied_count,
            "quarantined_count": self.quarantined_count,
            "replay_drop_count": self.replay_drop_count,
            "total_fee_piconero": self.total_fee_piconero,
            "rebate_pool_piconero": self.rebate_pool_piconero,
            "sealed_at_height": self.sealed_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub domain_id: String,
    pub ticket_id: Option<String>,
    pub status: ReservationStatus,
    pub reserved_fee_piconero: u128,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "domain_id": self.domain_id,
            "ticket_id": self.ticket_id,
            "status": self.status,
            "reserved_fee_piconero": self.reserved_fee_piconero,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub ticket_id: String,
    pub domain_id: String,
    pub kind: ReceiptKind,
    pub decision: EvaluationDecision,
    pub execution_root: String,
    pub fee_paid_piconero: u128,
    pub sponsor_paid_piconero: u128,
    pub rebate_id: Option<String>,
    pub post_state_root: String,
    pub monero_anchor_tx_hash: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "ticket_id": self.ticket_id,
            "domain_id": self.domain_id,
            "kind": self.kind,
            "decision": self.decision,
            "execution_root": self.execution_root,
            "fee_paid_piconero": self.fee_paid_piconero,
            "sponsor_paid_piconero": self.sponsor_paid_piconero,
            "rebate_id": self.rebate_id,
            "post_state_root": self.post_state_root,
            "monero_anchor_tx_hash": self.monero_anchor_tx_hash,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub domain_id: String,
    pub beneficiary_commitment: String,
    pub status: RebateStatus,
    pub amount_piconero: u128,
    pub claim_nullifier: String,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "domain_id": self.domain_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "status": self.status,
            "amount_piconero": self.amount_piconero,
            "claim_nullifier": self.claim_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub domain_id: String,
    pub ticket_id: Option<String>,
    pub nullifier: String,
    pub fence_root: String,
    pub status: FenceStatus,
    pub privacy_set_size: u64,
    pub ring_member_root: String,
    pub view_tag_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "domain_id": self.domain_id,
            "ticket_id": self.ticket_id,
            "nullifier": self.nullifier,
            "fence_root": self.fence_root,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "ring_member_root": self.ring_member_root,
            "view_tag_root": self.view_tag_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub domain_id: Option<String>,
    pub payload_root: String,
    pub emitted_at_height: u64,
}

impl PolicyEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "domain_id": self.domain_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub policy_domains: BTreeMap<String, PolicyDomain>,
    pub encrypted_rules: BTreeMap<String, EncryptedPolicyRule>,
    pub authorization_tickets: BTreeMap<String, ContractCallAuthorizationTicket>,
    pub committee_attestations: BTreeMap<String, PqCommitteeAttestation>,
    pub evaluation_batches: BTreeMap<String, RuleEvaluationBatch>,
    pub sponsor_reservations: BTreeMap<String, FeeSponsorReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, Rebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: Vec<PolicyEvent>,
}

pub type Runtime = State;

impl Default for State {
    fn default() -> Self {
        let config = Config::default();
        let roots = Roots::empty(&config);
        Self {
            config,
            counters: Counters::default(),
            roots,
            policy_domains: BTreeMap::new(),
            encrypted_rules: BTreeMap::new(),
            authorization_tickets: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            evaluation_batches: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let height = PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_POLICY_ENGINE_RUNTIME_DEVNET_HEIGHT;
        let dex_domain_id = domain_id("devnet-confidential-dex-policy", 1);
        let bridge_domain_id = domain_id("devnet-monero-bridge-policy", 1);
        let dex_contract_root = payload_root(&json!([
            "dex-router-v4.private",
            "stable-swap-v2.private",
            "confidential-token-vault.private"
        ]));
        let bridge_contract_root = payload_root(&json!([
            "monero-exit-router.private",
            "pq-reserve-attestation.private",
            "fee-sponsor-vault.private"
        ]));
        let committee_root = payload_root(&json!([
            "ml-dsa-87-policy-signer-01",
            "ml-dsa-87-policy-signer-02",
            "slh-dsa-privacy-witness-01",
            "slh-dsa-emergency-council-01"
        ]));
        let dex_domain = PolicyDomain {
            domain_id: dex_domain_id.clone(),
            owner_commitment: commitment("owner", "dex-policy-owner"),
            kind: PolicyDomainKind::Dex,
            status: PolicyDomainStatus::Active,
            label_hash: label_hash("devnet confidential dex policy"),
            contract_scope_root: dex_contract_root,
            committee_root: committee_root.clone(),
            policy_epoch: 1,
            min_privacy_set: state.config.min_privacy_set,
            max_fee_bps: state.config.max_engine_fee_bps,
            created_at_height: height - 4_096,
            expires_at_height: None,
            metadata_root: payload_root(&json!({"lane": "sponsored_low_fee", "risk": "bounded"})),
        };
        let bridge_domain = PolicyDomain {
            domain_id: bridge_domain_id.clone(),
            owner_commitment: commitment("owner", "monero-bridge-policy-owner"),
            kind: PolicyDomainKind::Bridge,
            status: PolicyDomainStatus::Active,
            label_hash: label_hash("devnet monero bridge policy"),
            contract_scope_root: bridge_contract_root,
            committee_root,
            policy_epoch: 1,
            min_privacy_set: state.config.batch_privacy_set,
            max_fee_bps: 7,
            created_at_height: height - 3_840,
            expires_at_height: None,
            metadata_root: payload_root(&json!({"monero_network": "devnet", "privacy": "ringct"})),
        };
        state
            .policy_domains
            .insert(dex_domain.domain_id.clone(), dex_domain);
        state
            .policy_domains
            .insert(bridge_domain.domain_id.clone(), bridge_domain);

        let rule_ids = [
            (
                rule_id(&dex_domain_id, RuleKind::ContractAllowlist, 1),
                dex_domain_id.clone(),
                RuleKind::ContractAllowlist,
                100,
            ),
            (
                rule_id(&dex_domain_id, RuleKind::SpendLimit, 2),
                dex_domain_id.clone(),
                RuleKind::SpendLimit,
                80,
            ),
            (
                rule_id(&bridge_domain_id, RuleKind::PrivacyFloor, 1),
                bridge_domain_id.clone(),
                RuleKind::PrivacyFloor,
                120,
            ),
            (
                rule_id(&bridge_domain_id, RuleKind::SponsorBound, 2),
                bridge_domain_id.clone(),
                RuleKind::SponsorBound,
                70,
            ),
        ];
        for (id, scoped_domain_id, kind, priority) in rule_ids {
            let rule = EncryptedPolicyRule {
                rule_id: id.clone(),
                domain_id: scoped_domain_id.clone(),
                rule_kind: kind,
                status: RuleStatus::Active,
                encrypted_rule_root: encrypted_payload_root("rule", &id),
                ciphertext_hash: ciphertext_hash("policy-rule-ciphertext", &id),
                rule_commitment: commitment("rule", &id),
                policy_tag: tag("policy-tag", kind.as_str()),
                priority,
                risk_weight: u64::from(priority) * 10,
                privacy_floor: if scoped_domain_id == bridge_domain_id {
                    state.config.batch_privacy_set
                } else {
                    state.config.min_privacy_set
                },
                pq_security_bits: state.config.min_pq_security_bits,
                version: 1,
                valid_from_height: height - 512,
                expires_at_height: height + state.config.rule_ttl_blocks,
                nullifier_domain: nullifier_domain(&scoped_domain_id, kind.as_str()),
                attestation_root: merkle_root("PRIVATE-L2-PQ-POLICY-RULE-ATTESTATION", &[]),
            };
            state.encrypted_rules.insert(id, rule);
        }

        let dex_ticket_id = ticket_id(&dex_domain_id, "devnet-dex-ticket-0001", height);
        let bridge_ticket_id = ticket_id(&bridge_domain_id, "devnet-bridge-ticket-0001", height);
        let dex_fence_id = fence_id(&dex_domain_id, "dex-fence-0001");
        let bridge_fence_id = fence_id(&bridge_domain_id, "bridge-fence-0001");
        let dex_reservation_id = reservation_id("sponsor-a", &dex_ticket_id, height);
        let bridge_reservation_id = reservation_id("sponsor-b", &bridge_ticket_id, height);
        let dex_nullifier = nullifier(&dex_domain_id, "dex-ticket-0001");
        let bridge_nullifier = nullifier(&bridge_domain_id, "bridge-ticket-0001");

        let ticket = ContractCallAuthorizationTicket {
            ticket_id: dex_ticket_id.clone(),
            domain_id: dex_domain_id.clone(),
            caller_commitment: commitment("caller", "devnet-alice"),
            contract_commitment: commitment("contract", "dex-router-v4.private"),
            method_selector_hash: selector_hash("swap_exact_private_input"),
            calldata_root: payload_root(&json!({"amount": "hidden", "path": "encrypted"})),
            call_value_commitment: commitment("value", "0"),
            asset_root: payload_root(&json!(["wxmr-devnet", "private-usd-devnet"])),
            capability_root: payload_root(&json!(["token_spend", "private_state_write"])),
            sponsor_reservation_id: Some(dex_reservation_id.clone()),
            privacy_fence_id: dex_fence_id.clone(),
            nullifier: dex_nullifier.clone(),
            status: TicketStatus::Authorized,
            requested_at_height: height - 6,
            expires_at_height: height + state.config.ticket_ttl_blocks,
            max_fee_piconero: 8_000_000,
            priority_fee_piconero: 125_000,
        };
        let bridge_ticket = ContractCallAuthorizationTicket {
            ticket_id: bridge_ticket_id.clone(),
            domain_id: bridge_domain_id.clone(),
            caller_commitment: commitment("caller", "devnet-bob"),
            contract_commitment: commitment("contract", "monero-exit-router.private"),
            method_selector_hash: selector_hash("prove_private_exit"),
            calldata_root: payload_root(&json!({"exit_note": "encrypted", "subaddress": "hidden"})),
            call_value_commitment: commitment("value", "monero-exit-hidden"),
            asset_root: payload_root(&json!(["wxmr-devnet"])),
            capability_root: payload_root(&json!(["bridge_exit", "fee_sponsored"])),
            sponsor_reservation_id: Some(bridge_reservation_id.clone()),
            privacy_fence_id: bridge_fence_id.clone(),
            nullifier: bridge_nullifier.clone(),
            status: TicketStatus::Batched,
            requested_at_height: height - 4,
            expires_at_height: height + state.config.ticket_ttl_blocks,
            max_fee_piconero: 12_000_000,
            priority_fee_piconero: 250_000,
        };
        state
            .authorization_tickets
            .insert(ticket.ticket_id.clone(), ticket);
        state
            .authorization_tickets
            .insert(bridge_ticket.ticket_id.clone(), bridge_ticket);

        for (subject_id, scoped_domain_id, role, verdict) in [
            (
                dex_ticket_id.clone(),
                dex_domain_id.clone(),
                CommitteeRole::PqSigner,
                AttestationVerdict::Valid,
            ),
            (
                bridge_ticket_id.clone(),
                bridge_domain_id.clone(),
                CommitteeRole::PrivacyWitness,
                AttestationVerdict::ValidWithWarning,
            ),
            (
                dex_reservation_id.clone(),
                dex_domain_id.clone(),
                CommitteeRole::FeeSponsor,
                AttestationVerdict::Valid,
            ),
        ] {
            let attestation_id = attestation_id(&scoped_domain_id, &subject_id, role, 1);
            state.committee_attestations.insert(
                attestation_id.clone(),
                PqCommitteeAttestation {
                    attestation_id,
                    domain_id: scoped_domain_id,
                    subject_id,
                    role,
                    verdict,
                    committee_epoch: 1,
                    signer_set_root: payload_root(&json!([
                        "policy-signer-01",
                        "policy-signer-02",
                        "privacy-witness-01"
                    ])),
                    signature_root: encrypted_payload_root("pq-signatures", "devnet"),
                    transcript_root: payload_root(
                        &json!({"fiat_shamir": "shake256", "domain": "policy-engine-devnet"}),
                    ),
                    pq_security_bits: state.config.min_pq_security_bits,
                    threshold: 2,
                    signers: 3,
                    issued_at_height: height - 3,
                    expires_at_height: height + state.config.attestation_ttl_blocks,
                },
            );
        }

        state.sponsor_reservations.insert(
            dex_reservation_id.clone(),
            FeeSponsorReservation {
                reservation_id: dex_reservation_id.clone(),
                sponsor_commitment: commitment("sponsor", "low-fee-sponsor-a"),
                domain_id: dex_domain_id.clone(),
                ticket_id: Some(dex_ticket_id.clone()),
                status: ReservationStatus::Consumed,
                reserved_fee_piconero: 8_000_000,
                max_fee_bps: 6,
                rebate_bps: state.config.target_rebate_bps,
                privacy_set_size: state.config.min_privacy_set,
                created_at_height: height - 8,
                expires_at_height: height + state.config.reservation_ttl_blocks,
            },
        );
        state.sponsor_reservations.insert(
            bridge_reservation_id.clone(),
            FeeSponsorReservation {
                reservation_id: bridge_reservation_id,
                sponsor_commitment: commitment("sponsor", "monero-exit-sponsor-b"),
                domain_id: bridge_domain_id.clone(),
                ticket_id: Some(bridge_ticket_id.clone()),
                status: ReservationStatus::BoundToTicket,
                reserved_fee_piconero: 12_000_000,
                max_fee_bps: 7,
                rebate_bps: state.config.target_rebate_bps,
                privacy_set_size: state.config.batch_privacy_set,
                created_at_height: height - 7,
                expires_at_height: height + state.config.reservation_ttl_blocks,
            },
        );

        state.privacy_fences.insert(
            dex_fence_id.clone(),
            PrivacyFence {
                fence_id: dex_fence_id.clone(),
                domain_id: dex_domain_id.clone(),
                ticket_id: Some(dex_ticket_id.clone()),
                nullifier: dex_nullifier.clone(),
                fence_root: payload_root(&json!({"ring": "dex-devnet", "position": "hidden"})),
                status: FenceStatus::Spent,
                privacy_set_size: state.config.min_privacy_set,
                ring_member_root: payload_root(&json!(["ring-member-root-dex-0001"])),
                view_tag_root: payload_root(&json!(["view-tag-root-dex-0001"])),
                opened_at_height: height - 6,
                expires_at_height: height + state.config.ticket_ttl_blocks,
            },
        );
        state.privacy_fences.insert(
            bridge_fence_id.clone(),
            PrivacyFence {
                fence_id: bridge_fence_id,
                domain_id: bridge_domain_id.clone(),
                ticket_id: Some(bridge_ticket_id.clone()),
                nullifier: bridge_nullifier.clone(),
                fence_root: payload_root(
                    &json!({"ring": "monero-exit-devnet", "position": "hidden"}),
                ),
                status: FenceStatus::Reserved,
                privacy_set_size: state.config.batch_privacy_set,
                ring_member_root: payload_root(&json!(["monero-ring-root-0001"])),
                view_tag_root: payload_root(&json!(["monero-viewtag-root-0001"])),
                opened_at_height: height - 4,
                expires_at_height: height + state.config.ticket_ttl_blocks,
            },
        );
        state.spent_nullifiers.insert(dex_nullifier.clone());

        let ticket_records = values_from_map(&state.authorization_tickets);
        let rule_records = values_from_map(&state.encrypted_rules);
        let attestation_records = values_from_map(&state.committee_attestations);
        let fence_records = values_from_map(&state.privacy_fences);
        let batch_id = batch_id(&dex_domain_id, height, 1);
        state.evaluation_batches.insert(
            batch_id.clone(),
            RuleEvaluationBatch {
                batch_id: batch_id.clone(),
                domain_id: dex_domain_id.clone(),
                status: BatchStatus::Settled,
                ticket_root: merkle_root("PRIVATE-L2-PQ-POLICY-BATCH-TICKET", &ticket_records),
                rule_root: merkle_root("PRIVATE-L2-PQ-POLICY-BATCH-RULE", &rule_records),
                decision_root: payload_root(&json!([
                    {"ticket_id": dex_ticket_id, "decision": "allow"},
                    {"ticket_id": bridge_ticket_id, "decision": "allow_with_limits"}
                ])),
                attestation_root: merkle_root(
                    "PRIVATE-L2-PQ-POLICY-BATCH-ATTESTATION",
                    &attestation_records,
                ),
                privacy_fence_root: merkle_root("PRIVATE-L2-PQ-POLICY-BATCH-FENCE", &fence_records),
                batch_size: 2,
                allowed_count: 2,
                denied_count: 0,
                quarantined_count: 0,
                replay_drop_count: 0,
                total_fee_piconero: 11_000_000,
                rebate_pool_piconero: 660_000,
                sealed_at_height: height - 2,
                settlement_deadline_height: height + state.config.settlement_window_blocks,
            },
        );

        let rebate_id = rebate_id(&dex_domain_id, &batch_id, "alice");
        let receipt_id = receipt_id(&batch_id, "devnet-dex-ticket-0001");
        state.settlement_receipts.insert(
            receipt_id.clone(),
            SettlementReceipt {
                receipt_id: receipt_id.clone(),
                batch_id: batch_id.clone(),
                ticket_id: state
                    .authorization_tickets
                    .keys()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "missing-ticket".to_string()),
                domain_id: dex_domain_id.clone(),
                kind: ReceiptKind::TicketAuthorization,
                decision: EvaluationDecision::Allow,
                execution_root: payload_root(&json!({"gas": "low", "result": "private-success"})),
                fee_paid_piconero: 5_500_000,
                sponsor_paid_piconero: 4_900_000,
                rebate_id: Some(rebate_id.clone()),
                post_state_root: payload_root(
                    &json!({"contract": "dex-router-v4.private", "delta": "hidden"}),
                ),
                monero_anchor_tx_hash: domain_hash(
                    "PRIVATE-L2-PQ-POLICY-MONERO-ANCHOR",
                    &[HashPart::Str("devnet-anchor-0001")],
                    32,
                ),
                settled_at_height: height,
            },
        );
        state.rebates.insert(
            rebate_id.clone(),
            Rebate {
                rebate_id,
                receipt_id,
                domain_id: dex_domain_id.clone(),
                beneficiary_commitment: commitment("beneficiary", "devnet-alice"),
                status: RebateStatus::Claimable,
                amount_piconero: 330_000,
                claim_nullifier: nullifier("rebate", "devnet-alice-0001"),
                privacy_set_size: state.config.min_privacy_set,
                created_at_height: height,
                expires_at_height: height + 720,
            },
        );

        let event_specs: Vec<(&str, String, Option<String>)> = vec![
            (
                "domain_activated",
                bridge_domain_id.clone(),
                Some(bridge_domain_id.clone()),
            ),
            (
                "ticket_authorized",
                "devnet-dex-ticket-0001".to_string(),
                None,
            ),
            ("batch_settled", batch_id, None),
        ];
        for (event_kind, subject_id, event_domain_id) in event_specs {
            let event_id = event_id(event_kind, &subject_id, height);
            state.events.push(PolicyEvent {
                event_id,
                event_kind: event_kind.to_string(),
                subject_id,
                domain_id: event_domain_id,
                payload_root: payload_root(&json!({"height": height, "devnet": true})),
                emitted_at_height: height,
            });
        }

        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": self.config.schema_version,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "policy_domains": values_from_map(&self.policy_domains),
            "encrypted_rules": values_from_map(&self.encrypted_rules),
            "authorization_tickets": values_from_map(&self.authorization_tickets),
            "committee_attestations": values_from_map(&self.committee_attestations),
            "evaluation_batches": values_from_map(&self.evaluation_batches),
            "sponsor_reservations": values_from_map(&self.sponsor_reservations),
            "settlement_receipts": values_from_map(&self.settlement_receipts),
            "rebates": values_from_map(&self.rebates),
            "privacy_fences": values_from_map(&self.privacy_fences),
            "spent_nullifiers": self.spent_nullifiers.iter().collect::<Vec<_>>(),
            "events": self.events.iter().map(PolicyEvent::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            domains: self.policy_domains.len() as u64,
            encrypted_rules: self.encrypted_rules.len() as u64,
            authorization_tickets: self.authorization_tickets.len() as u64,
            committee_attestations: self.committee_attestations.len() as u64,
            evaluation_batches: self.evaluation_batches.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            allowed_tickets: self
                .authorization_tickets
                .values()
                .filter(|ticket| {
                    matches!(
                        ticket.status,
                        TicketStatus::Authorized | TicketStatus::Settled
                    )
                })
                .count() as u64,
            denied_tickets: self
                .authorization_tickets
                .values()
                .filter(|ticket| matches!(ticket.status, TicketStatus::Denied))
                .count() as u64,
            quarantined_tickets: self
                .authorization_tickets
                .values()
                .filter(|ticket| matches!(ticket.status, TicketStatus::Quarantined))
                .count() as u64,
            replay_drops: self
                .evaluation_batches
                .values()
                .map(|batch| batch.replay_drop_count)
                .sum(),
            total_fee_reserved_piconero: self
                .sponsor_reservations
                .values()
                .map(|reservation| reservation.reserved_fee_piconero)
                .sum(),
            total_fee_spent_piconero: self
                .settlement_receipts
                .values()
                .map(|receipt| receipt.fee_paid_piconero)
                .sum(),
            total_rebate_piconero: self
                .rebates
                .values()
                .map(|rebate| rebate.amount_piconero)
                .sum(),
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            config_root: domain_hash(
                "PRIVATE-L2-PQ-POLICY-CONFIG",
                &[HashPart::Json(&self.config.public_record())],
                32,
            ),
            domain_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-DOMAIN",
                &values_from_map(&self.policy_domains),
            ),
            encrypted_rule_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-RULE",
                &values_from_map(&self.encrypted_rules),
            ),
            ticket_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-TICKET",
                &values_from_map(&self.authorization_tickets),
            ),
            attestation_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-ATTESTATION",
                &values_from_map(&self.committee_attestations),
            ),
            batch_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-BATCH",
                &values_from_map(&self.evaluation_batches),
            ),
            sponsor_reservation_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-SPONSOR",
                &values_from_map(&self.sponsor_reservations),
            ),
            settlement_receipt_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-RECEIPT",
                &values_from_map(&self.settlement_receipts),
            ),
            rebate_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-REBATE",
                &values_from_map(&self.rebates),
            ),
            privacy_fence_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-FENCE",
                &values_from_map(&self.privacy_fences),
            ),
            nullifier_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-NULLIFIER",
                &self
                    .spent_nullifiers
                    .iter()
                    .map(|nullifier| json!({"nullifier": nullifier}))
                    .collect::<Vec<_>>(),
            ),
            event_root: merkle_root(
                "PRIVATE-L2-PQ-POLICY-EVENT",
                &self
                    .events
                    .iter()
                    .map(PolicyEvent::public_record)
                    .collect::<Vec<_>>(),
            ),
            counters_root: domain_hash(
                "PRIVATE-L2-PQ-POLICY-COUNTERS",
                &[HashPart::Json(&self.counters.public_record())],
                32,
            ),
        };
    }

    pub fn authorize_ticket(
        &mut self,
        ticket_id: &str,
        decision: EvaluationDecision,
    ) -> Result<()> {
        let ticket = self
            .authorization_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("unknown authorization ticket: {ticket_id}"))?;
        ticket.status = match decision {
            EvaluationDecision::Allow | EvaluationDecision::AllowWithLimits => {
                TicketStatus::Authorized
            }
            EvaluationDecision::Deny => TicketStatus::Denied,
            EvaluationDecision::Quarantine => TicketStatus::Quarantined,
            EvaluationDecision::DropReplay => TicketStatus::Denied,
            EvaluationDecision::RequireSponsor | EvaluationDecision::RequireMoreProofs => {
                TicketStatus::Attested
            }
        };
        if matches!(decision, EvaluationDecision::DropReplay) {
            self.spent_nullifiers.insert(ticket.nullifier.clone());
        }
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        domain_id: Option<String>,
        payload: &Value,
        height: u64,
    ) -> String {
        let id = event_id(event_kind, subject_id, height);
        self.events.push(PolicyEvent {
            event_id: id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            domain_id,
            payload_root: payload_root(payload),
            emitted_at_height: height,
        });
        self.recompute_roots();
        id
    }
}

pub fn payload_root(payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-PAYLOAD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-POLICY-PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-POLICY-STATE", record)
}

pub fn domain_id(label: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-DOMAIN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

pub fn rule_id(domain_id: &str, kind: RuleKind, version: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-RULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(kind.as_str()),
            HashPart::Int(version as i128),
        ],
        32,
    )
}

pub fn ticket_id(domain_id: &str, caller_nonce: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(caller_nonce),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn attestation_id(
    domain_id: &str,
    subject_id: &str,
    role: CommitteeRole,
    epoch: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(subject_id),
            HashPart::Str(match role {
                CommitteeRole::PolicyAuthor => "policy_author",
                CommitteeRole::ContractAuditor => "contract_auditor",
                CommitteeRole::PqSigner => "pq_signer",
                CommitteeRole::PrivacyWitness => "privacy_witness",
                CommitteeRole::FeeSponsor => "fee_sponsor",
                CommitteeRole::EmergencyCouncil => "emergency_council",
            }),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

pub fn batch_id(domain_id: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn reservation_id(sponsor_label: &str, ticket_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::Str(ticket_id),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn receipt_id(batch_id: &str, ticket_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(ticket_id),
        ],
        32,
    )
}

pub fn rebate_id(domain_id: &str, receipt_id: &str, beneficiary_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_label),
        ],
        32,
    )
}

pub fn fence_id(domain_id: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn event_id(event_kind: &str, subject_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn nullifier(domain_id: &str, secret_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(secret_label),
        ],
        32,
    )
}

fn values_from_map<T>(map: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    map.values().map(PublicRecord::as_public_record).collect()
}

pub trait PublicRecord {
    fn as_public_record(&self) -> Value;
}

impl PublicRecord for PolicyDomain {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for EncryptedPolicyRule {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for ContractCallAuthorizationTicket {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PqCommitteeAttestation {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for RuleEvaluationBatch {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for FeeSponsorReservation {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for SettlementReceipt {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for Rebate {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PrivacyFence {
    fn as_public_record(&self) -> Value {
        self.public_record()
    }
}

fn commitment(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn label_hash(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-LABEL",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn encrypted_payload_root(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-ENCRYPTED-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn ciphertext_hash(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-CIPHERTEXT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn tag(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-TAG",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        16,
    )
}

fn selector_hash(selector: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-SELECTOR",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(selector)],
        32,
    )
}

fn nullifier_domain(domain_id: &str, rule_kind: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-POLICY-NULLIFIER-DOMAIN",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(rule_kind),
        ],
        32,
    )
}
