use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialCrossDomainTokenRouterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-domain-token-router-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_DOMAIN_TOKEN_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_RELAY_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const ROUTE_COMMITMENT_SUITE: &str = "confidential-cross-domain-token-route-root-v1";
pub const NETTING_SUITE: &str = "privacy-preserving-cross-domain-token-netting-root-v1";
pub const FEE_SUITE: &str = "low-fee-cross-domain-token-sponsor-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-cross-domain-token-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_ROUTE_MS: u64 = 240;
pub const DEFAULT_MAX_ROUTE_MS: u64 = 900;
pub const DEFAULT_BATCH_WINDOW_SLOTS: u64 = 6;
pub const DEFAULT_ROUTE_TTL_SLOTS: u64 = 72;
pub const DEFAULT_RELAY_QUARANTINE_SLOTS: u64 = 512;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MIN_RELAY_BOND_MICRO_UNITS: u64 = 12_500_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_200;
pub const DEFAULT_MAX_ROUTE_RISK_BPS: u64 = 1_800;
pub const DEFAULT_MAX_NETTING_IMBALANCE_BPS: u64 = 2_500;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_DOMAINS: usize = 262_144;
pub const MAX_TOKEN_PAIRS: usize = 1_048_576;
pub const MAX_ROUTES: usize = 2_097_152;
pub const MAX_TRANSFER_TICKETS: usize = 4_194_304;
pub const MAX_NETTING_BATCHES: usize = 1_048_576;
pub const MAX_RELAY_ATTESTATIONS: usize = 4_194_304;
pub const MAX_FEE_QUOTES: usize = 2_097_152;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_ROUTE_HOPS: usize = 12;
pub const MAX_BATCH_TICKETS: usize = 1024;
pub const DEVNET_EPOCH: u64 = 7_232;
pub const DEVNET_SLOT: u64 = 19;
pub const DEVNET_L2_HEIGHT: u64 = 2_812_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainKind {
    MoneroAnchor,
    NebulaShard,
    SettlementRollup,
    AppChain,
    ContractSubnet,
    LiquidityHub,
    EmergencyExitDomain,
}

impl DomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroAnchor => "monero_anchor",
            Self::NebulaShard => "nebula_shard",
            Self::SettlementRollup => "settlement_rollup",
            Self::AppChain => "app_chain",
            Self::ContractSubnet => "contract_subnet",
            Self::LiquidityHub => "liquidity_hub",
            Self::EmergencyExitDomain => "emergency_exit_domain",
        }
    }

    pub fn base_finality_weight_bps(self) -> u64 {
        match self {
            Self::MoneroAnchor => 10_000,
            Self::SettlementRollup => 9_300,
            Self::NebulaShard => 8_900,
            Self::LiquidityHub => 8_600,
            Self::ContractSubnet => 8_200,
            Self::AppChain => 7_800,
            Self::EmergencyExitDomain => 9_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClass {
    NativeXmr,
    ConfidentialStablecoin,
    ShieldedGovernanceToken,
    SyntheticAsset,
    YieldReceipt,
    LiquidityNote,
    ContractNft,
    FeeCredit,
}

impl TokenClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeXmr => "native_xmr",
            Self::ConfidentialStablecoin => "confidential_stablecoin",
            Self::ShieldedGovernanceToken => "shielded_governance_token",
            Self::SyntheticAsset => "synthetic_asset",
            Self::YieldReceipt => "yield_receipt",
            Self::LiquidityNote => "liquidity_note",
            Self::ContractNft => "contract_nft",
            Self::FeeCredit => "fee_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Proposed,
    Open,
    Attesting,
    Ticketed,
    Netted,
    Settled,
    Rebated,
    Delayed,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayStatus {
    Candidate,
    Active,
    Throttled,
    Quarantined,
    Slashed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferTicketStatus {
    Sealed,
    FeeQuoted,
    RelayAccepted,
    Batched,
    Settled,
    RebateIssued,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignatureVerified,
    SourceLockObserved,
    DestinationMintAuthorized,
    NullifierSetChecked,
    PrivacyFloorSatisfied,
    FeeCapObserved,
    RouteRiskBounded,
    BatchNettingBalanced,
    EmergencyExitAvailable,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignatureVerified => "pq_signature_verified",
            Self::SourceLockObserved => "source_lock_observed",
            Self::DestinationMintAuthorized => "destination_mint_authorized",
            Self::NullifierSetChecked => "nullifier_set_checked",
            Self::PrivacyFloorSatisfied => "privacy_floor_satisfied",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::RouteRiskBounded => "route_risk_bounded",
            Self::BatchNettingBalanced => "batch_netting_balanced",
            Self::EmergencyExitAvailable => "emergency_exit_available",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteDecision {
    Accept,
    AcceptWithDelay,
    RequireMoreRelayQuorum,
    RepriceFee,
    Rebatch,
    QuarantineRelay,
    Reject,
}

impl RouteDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::AcceptWithDelay => "accept_with_delay",
            Self::RequireMoreRelayQuorum => "require_more_relay_quorum",
            Self::RepriceFee => "reprice_fee",
            Self::Rebatch => "rebatch",
            Self::QuarantineRelay => "quarantine_relay",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_relay_suite: String,
    pub route_commitment_suite: String,
    pub netting_suite: String,
    pub fee_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_route_ms: u64,
    pub max_route_ms: u64,
    pub batch_window_slots: u64,
    pub route_ttl_slots: u64,
    pub relay_quarantine_slots: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_relay_bond_micro_units: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_route_risk_bps: u64,
    pub max_netting_imbalance_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_relay_suite: PQ_RELAY_SUITE.to_string(),
            route_commitment_suite: ROUTE_COMMITMENT_SUITE.to_string(),
            netting_suite: NETTING_SUITE.to_string(),
            fee_suite: FEE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_route_ms: DEFAULT_TARGET_ROUTE_MS,
            max_route_ms: DEFAULT_MAX_ROUTE_MS,
            batch_window_slots: DEFAULT_BATCH_WINDOW_SLOTS,
            route_ttl_slots: DEFAULT_ROUTE_TTL_SLOTS,
            relay_quarantine_slots: DEFAULT_RELAY_QUARANTINE_SLOTS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_relay_bond_micro_units: DEFAULT_MIN_RELAY_BOND_MICRO_UNITS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_route_risk_bps: DEFAULT_MAX_ROUTE_RISK_BPS,
            max_netting_imbalance_bps: DEFAULT_MAX_NETTING_IMBALANCE_BPS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.pq_relay_suite, "pq_relay_suite")?;
        ensure_non_empty(&self.route_commitment_suite, "route_commitment_suite")?;
        ensure_non_empty(&self.netting_suite, "netting_suite")?;
        ensure_non_empty(&self.fee_suite, "fee_suite")?;
        ensure_non_empty(&self.redaction_suite, "redaction_suite")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        if self.min_privacy_set_size == 0 {
            return Err("min_privacy_set_size must be non-zero".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target_privacy_set_size must be >= min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below target".to_string());
        }
        if self.target_route_ms == 0 || self.max_route_ms < self.target_route_ms {
            return Err("route latency bounds are invalid".to_string());
        }
        if self.batch_window_slots == 0 {
            return Err("batch_window_slots must be non-zero".to_string());
        }
        if self.route_ttl_slots < self.batch_window_slots {
            return Err("route_ttl_slots must cover at least one batch window".to_string());
        }
        if self.relay_quarantine_slots < self.route_ttl_slots {
            return Err("relay_quarantine_slots must be >= route_ttl_slots".to_string());
        }
        if self.min_relay_bond_micro_units == 0 {
            return Err("min_relay_bond_micro_units must be non-zero".to_string());
        }
        ensure_bps(self.max_user_fee_bps, "max_user_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(
            self.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        ensure_bps(
            self.strong_attestation_quorum_bps,
            "strong_attestation_quorum_bps",
        )?;
        ensure_bps(self.max_route_risk_bps, "max_route_risk_bps")?;
        ensure_bps(self.max_netting_imbalance_bps, "max_netting_imbalance_bps")?;
        if self.strong_attestation_quorum_bps < self.min_attestation_quorum_bps {
            return Err(
                "strong_attestation_quorum_bps must be >= min_attestation_quorum_bps".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub domains: u64,
    pub token_pairs: u64,
    pub relays: u64,
    pub routes: u64,
    pub transfer_tickets: u64,
    pub fee_quotes: u64,
    pub netting_batches: u64,
    pub relay_attestations: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub quarantined_relays: u64,
    pub delayed_routes: u64,
    pub rejected_tickets: u64,
    pub settled_batches: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "domains": self.domains,
            "token_pairs": self.token_pairs,
            "relays": self.relays,
            "routes": self.routes,
            "transfer_tickets": self.transfer_tickets,
            "fee_quotes": self.fee_quotes,
            "netting_batches": self.netting_batches,
            "relay_attestations": self.relay_attestations,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "quarantined_relays": self.quarantined_relays,
            "delayed_routes": self.delayed_routes,
            "rejected_tickets": self.rejected_tickets,
            "settled_batches": self.settled_batches,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub domain_root: String,
    pub token_pair_root: String,
    pub relay_root: String,
    pub route_root: String,
    pub transfer_ticket_root: String,
    pub fee_quote_root: String,
    pub netting_batch_root: String,
    pub relay_attestation_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = domain_hash("cross-domain-token-router:empty-root", &[], 32);
        Self {
            domain_root: empty.clone(),
            token_pair_root: empty.clone(),
            relay_root: empty.clone(),
            route_root: empty.clone(),
            transfer_ticket_root: empty.clone(),
            fee_quote_root: empty.clone(),
            netting_batch_root: empty.clone(),
            relay_attestation_root: empty.clone(),
            rebate_root: empty.clone(),
            redaction_budget_root: empty.clone(),
            operator_summary_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "domain_root": self.domain_root,
            "token_pair_root": self.token_pair_root,
            "relay_root": self.relay_root,
            "route_root": self.route_root,
            "transfer_ticket_root": self.transfer_ticket_root,
            "fee_quote_root": self.fee_quote_root,
            "netting_batch_root": self.netting_batch_root,
            "relay_attestation_root": self.relay_attestation_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Domain {
    pub domain_id: String,
    pub kind: DomainKind,
    pub operator_set_root: String,
    pub finality_root: String,
    pub light_client_root: String,
    pub l2_height: u64,
    pub pq_security_bits: u16,
    pub finality_weight_bps: u64,
    pub accepts_private_tokens: bool,
    pub emergency_exit_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenPair {
    pub pair_id: String,
    pub source_domain_id: String,
    pub destination_domain_id: String,
    pub token_class: TokenClass,
    pub source_asset_commitment: String,
    pub destination_asset_commitment: String,
    pub reserve_root: String,
    pub decimal_shift: i8,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Relay {
    pub relay_id: String,
    pub operator_commitment: String,
    pub pq_verifying_key_root: String,
    pub stake_bond_micro_units: u64,
    pub supported_domain_ids: BTreeSet<String>,
    pub supported_token_classes: BTreeSet<TokenClass>,
    pub status: RelayStatus,
    pub successful_batches: u64,
    pub failed_batches: u64,
    pub quarantine_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Route {
    pub route_id: String,
    pub pair_id: String,
    pub relay_ids: Vec<String>,
    pub hop_domain_ids: Vec<String>,
    pub encrypted_route_root: String,
    pub route_hint_root: String,
    pub max_latency_ms: u64,
    pub max_user_fee_bps: u64,
    pub route_risk_bps: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub status: RouteStatus,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferTicket {
    pub ticket_id: String,
    pub route_id: String,
    pub owner_commitment: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub nullifier_root: String,
    pub amount_commitment: String,
    pub max_fee_micro_units: u64,
    pub quoted_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub submitted_slot: u64,
    pub status: TransferTicketStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeQuote {
    pub quote_id: String,
    pub route_id: String,
    pub ticket_id: String,
    pub relay_id: String,
    pub fee_asset_id: String,
    pub fee_micro_units: u64,
    pub fee_bps: u64,
    pub sponsor_pool_root: String,
    pub valid_until_slot: u64,
    pub rebate_hint_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingBatch {
    pub batch_id: String,
    pub route_id: String,
    pub ticket_ids: Vec<String>,
    pub relay_ids: Vec<String>,
    pub source_lock_root: String,
    pub destination_mint_root: String,
    pub aggregate_nullifier_root: String,
    pub aggregate_output_root: String,
    pub total_fee_micro_units: u64,
    pub imbalance_bps: u64,
    pub opened_slot: u64,
    pub settled_slot: Option<u64>,
    pub status: RouteStatus,
    pub settlement_decision: RouteDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayAttestation {
    pub attestation_id: String,
    pub route_id: String,
    pub batch_id: Option<String>,
    pub relay_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub ticket_id: String,
    pub route_id: String,
    pub fee_quote_id: String,
    pub asset_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub route_id: String,
    pub batch_id: Option<String>,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
    pub route_risk_bps: u64,
    pub ticket_count: u64,
    pub delayed_routes: u64,
    pub settled_batches: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterDomainRequest {
    pub kind: DomainKind,
    pub operator_set_root: String,
    pub finality_root: String,
    pub light_client_root: String,
    pub l2_height: u64,
    pub pq_security_bits: u16,
    pub accepts_private_tokens: bool,
    pub emergency_exit_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterTokenPairRequest {
    pub source_domain_id: String,
    pub destination_domain_id: String,
    pub token_class: TokenClass,
    pub source_asset_commitment: String,
    pub destination_asset_commitment: String,
    pub reserve_root: String,
    pub decimal_shift: i8,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterRelayRequest {
    pub operator_commitment: String,
    pub pq_verifying_key_root: String,
    pub stake_bond_micro_units: u64,
    pub supported_domain_ids: BTreeSet<String>,
    pub supported_token_classes: BTreeSet<TokenClass>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenRouteRequest {
    pub pair_id: String,
    pub relay_ids: Vec<String>,
    pub hop_domain_ids: Vec<String>,
    pub encrypted_route_root: String,
    pub route_hint_root: String,
    pub max_latency_ms: u64,
    pub max_user_fee_bps: u64,
    pub route_risk_bps: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmitTransferTicketRequest {
    pub route_id: String,
    pub owner_commitment: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub nullifier_root: String,
    pub amount_commitment: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuoteFeeRequest {
    pub route_id: String,
    pub ticket_id: String,
    pub relay_id: String,
    pub fee_asset_id: String,
    pub fee_micro_units: u64,
    pub fee_bps: u64,
    pub sponsor_pool_root: String,
    pub valid_until_slot: u64,
    pub rebate_hint_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildNettingBatchRequest {
    pub route_id: String,
    pub ticket_ids: Vec<String>,
    pub relay_ids: Vec<String>,
    pub source_lock_root: String,
    pub destination_mint_root: String,
    pub aggregate_nullifier_root: String,
    pub aggregate_output_root: String,
    pub imbalance_bps: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordRelayAttestationRequest {
    pub route_id: String,
    pub batch_id: Option<String>,
    pub relay_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub settled_slot: u64,
    pub decision: RouteDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub ticket_id: String,
    pub fee_quote_id: String,
    pub asset_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub route_id: String,
    pub batch_id: Option<String>,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub domains: BTreeMap<String, Domain>,
    pub token_pairs: BTreeMap<String, TokenPair>,
    pub relays: BTreeMap<String, Relay>,
    pub routes: BTreeMap<String, Route>,
    pub transfer_tickets: BTreeMap<String, TransferTicket>,
    pub fee_quotes: BTreeMap<String, FeeQuote>,
    pub netting_batches: BTreeMap<String, NettingBatch>,
    pub relay_attestations: BTreeMap<String, RelayAttestation>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default cross-domain token router config is valid")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            domains: BTreeMap::new(),
            token_pairs: BTreeMap::new(),
            relays: BTreeMap::new(),
            routes: BTreeMap::new(),
            transfer_tickets: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            relay_attestations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn register_domain(&mut self, request: RegisterDomainRequest) -> Result<Domain> {
        ensure_capacity(self.domains.len(), MAX_DOMAINS, "domains")?;
        ensure_non_empty(&request.operator_set_root, "operator_set_root")?;
        ensure_non_empty(&request.finality_root, "finality_root")?;
        ensure_non_empty(&request.light_client_root, "light_client_root")?;
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("domain pq security below configured minimum".to_string());
        }
        let finality_weight_bps = request.kind.base_finality_weight_bps();
        let domain_id = stable_id(
            "domain",
            &[
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.operator_set_root),
                HashPart::Str(&request.finality_root),
                HashPart::U64(request.l2_height),
            ],
        );
        let domain = Domain {
            domain_id: domain_id.clone(),
            kind: request.kind,
            operator_set_root: request.operator_set_root,
            finality_root: request.finality_root,
            light_client_root: request.light_client_root,
            l2_height: request.l2_height,
            pq_security_bits: request.pq_security_bits,
            finality_weight_bps,
            accepts_private_tokens: request.accepts_private_tokens,
            emergency_exit_enabled: request.emergency_exit_enabled,
        };
        self.domains.insert(domain_id, domain.clone());
        self.counters.domains = self.domains.len() as u64;
        self.refresh_roots();
        Ok(domain)
    }

    pub fn register_token_pair(&mut self, request: RegisterTokenPairRequest) -> Result<TokenPair> {
        ensure_capacity(self.token_pairs.len(), MAX_TOKEN_PAIRS, "token_pairs")?;
        self.ensure_domain_exists(&request.source_domain_id)?;
        self.ensure_domain_exists(&request.destination_domain_id)?;
        if request.source_domain_id == request.destination_domain_id {
            return Err("source and destination domains must differ".to_string());
        }
        ensure_non_empty(&request.source_asset_commitment, "source_asset_commitment")?;
        ensure_non_empty(
            &request.destination_asset_commitment,
            "destination_asset_commitment",
        )?;
        ensure_non_empty(&request.reserve_root, "reserve_root")?;
        ensure_bps(request.max_fee_bps, "max_fee_bps")?;
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("token pair max fee exceeds configured cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("token pair privacy set below configured minimum".to_string());
        }
        let pair_id = stable_id(
            "token-pair",
            &[
                HashPart::Str(&request.source_domain_id),
                HashPart::Str(&request.destination_domain_id),
                HashPart::Str(request.token_class.as_str()),
                HashPart::Str(&request.source_asset_commitment),
                HashPart::Str(&request.destination_asset_commitment),
            ],
        );
        let pair = TokenPair {
            pair_id: pair_id.clone(),
            source_domain_id: request.source_domain_id,
            destination_domain_id: request.destination_domain_id,
            token_class: request.token_class,
            source_asset_commitment: request.source_asset_commitment,
            destination_asset_commitment: request.destination_asset_commitment,
            reserve_root: request.reserve_root,
            decimal_shift: request.decimal_shift,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            enabled: true,
        };
        self.token_pairs.insert(pair_id, pair.clone());
        self.counters.token_pairs = self.token_pairs.len() as u64;
        self.refresh_roots();
        Ok(pair)
    }

    pub fn register_relay(&mut self, request: RegisterRelayRequest) -> Result<Relay> {
        ensure_capacity(self.relays.len(), MAX_ROUTES, "relays")?;
        ensure_non_empty(&request.operator_commitment, "operator_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        if request.stake_bond_micro_units < self.config.min_relay_bond_micro_units {
            return Err("relay bond below configured minimum".to_string());
        }
        if request.supported_domain_ids.is_empty() {
            return Err("relay must support at least one domain".to_string());
        }
        if request.supported_token_classes.is_empty() {
            return Err("relay must support at least one token class".to_string());
        }
        for domain_id in &request.supported_domain_ids {
            self.ensure_domain_exists(domain_id)?;
        }
        let relay_id = stable_id(
            "relay",
            &[
                HashPart::Str(&request.operator_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::U64(request.stake_bond_micro_units),
            ],
        );
        let relay = Relay {
            relay_id: relay_id.clone(),
            operator_commitment: request.operator_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            stake_bond_micro_units: request.stake_bond_micro_units,
            supported_domain_ids: request.supported_domain_ids,
            supported_token_classes: request.supported_token_classes,
            status: RelayStatus::Active,
            successful_batches: 0,
            failed_batches: 0,
            quarantine_until_slot: 0,
        };
        self.relays.insert(relay_id, relay.clone());
        self.counters.relays = self.relays.len() as u64;
        self.refresh_roots();
        Ok(relay)
    }

    pub fn open_route(&mut self, request: OpenRouteRequest) -> Result<Route> {
        ensure_capacity(self.routes.len(), MAX_ROUTES, "routes")?;
        let pair = self
            .token_pairs
            .get(&request.pair_id)
            .ok_or_else(|| "token pair not found".to_string())?;
        if !pair.enabled {
            return Err("token pair disabled".to_string());
        }
        if request.relay_ids.is_empty() {
            return Err("route requires at least one relay".to_string());
        }
        if request.hop_domain_ids.len() > MAX_ROUTE_HOPS {
            return Err("route has too many hops".to_string());
        }
        if request.max_latency_ms == 0 || request.max_latency_ms > self.config.max_route_ms {
            return Err("route latency exceeds configured bound".to_string());
        }
        ensure_bps(request.max_user_fee_bps, "max_user_fee_bps")?;
        if request.max_user_fee_bps > pair.max_fee_bps {
            return Err("route fee exceeds token pair cap".to_string());
        }
        ensure_bps(request.route_risk_bps, "route_risk_bps")?;
        if request.route_risk_bps > self.config.max_route_risk_bps {
            return Err("route risk exceeds configured bound".to_string());
        }
        ensure_non_empty(&request.encrypted_route_root, "encrypted_route_root")?;
        ensure_non_empty(&request.route_hint_root, "route_hint_root")?;
        for relay_id in &request.relay_ids {
            self.ensure_active_relay_supports(relay_id, pair)?;
        }
        self.ensure_route_hops_cover_pair(&request.hop_domain_ids, pair)?;
        let route_id = stable_id(
            "route",
            &[
                HashPart::Str(&request.pair_id),
                HashPart::Str(&request.encrypted_route_root),
                HashPart::Str(&request.route_hint_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        let route = Route {
            route_id: route_id.clone(),
            pair_id: request.pair_id,
            relay_ids: request.relay_ids,
            hop_domain_ids: request.hop_domain_ids,
            encrypted_route_root: request.encrypted_route_root,
            route_hint_root: request.route_hint_root,
            max_latency_ms: request.max_latency_ms,
            max_user_fee_bps: request.max_user_fee_bps,
            route_risk_bps: request.route_risk_bps,
            opened_slot: request.opened_slot,
            expires_slot: request.opened_slot + self.config.route_ttl_slots,
            status: RouteStatus::Open,
            attestation_quorum_bps: 0,
        };
        self.routes.insert(route_id, route.clone());
        self.counters.routes = self.routes.len() as u64;
        self.refresh_roots();
        Ok(route)
    }

    pub fn admit_transfer_ticket(
        &mut self,
        request: AdmitTransferTicketRequest,
    ) -> Result<TransferTicket> {
        ensure_capacity(
            self.transfer_tickets.len(),
            MAX_TRANSFER_TICKETS,
            "transfer_tickets",
        )?;
        let route = self
            .routes
            .get(&request.route_id)
            .ok_or_else(|| "route not found".to_string())?;
        if !matches!(
            route.status,
            RouteStatus::Open | RouteStatus::Attesting | RouteStatus::Ticketed
        ) {
            return Err("route is not accepting tickets".to_string());
        }
        if request.submitted_slot > route.expires_slot {
            return Err("ticket submitted after route expiry".to_string());
        }
        ensure_non_empty(&request.owner_commitment, "owner_commitment")?;
        ensure_non_empty(&request.input_note_root, "input_note_root")?;
        ensure_non_empty(&request.output_note_root, "output_note_root")?;
        ensure_non_empty(&request.nullifier_root, "nullifier_root")?;
        ensure_non_empty(&request.amount_commitment, "amount_commitment")?;
        if request.max_fee_micro_units == 0 {
            return Err("max_fee_micro_units must be non-zero".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("ticket privacy set below configured minimum".to_string());
        }
        let ticket_id = stable_id(
            "transfer-ticket",
            &[
                HashPart::Str(&request.route_id),
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(&request.nullifier_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        let ticket = TransferTicket {
            ticket_id: ticket_id.clone(),
            route_id: request.route_id.clone(),
            owner_commitment: request.owner_commitment,
            input_note_root: request.input_note_root,
            output_note_root: request.output_note_root,
            nullifier_root: request.nullifier_root,
            amount_commitment: request.amount_commitment,
            max_fee_micro_units: request.max_fee_micro_units,
            quoted_fee_micro_units: 0,
            privacy_set_size: request.privacy_set_size,
            submitted_slot: request.submitted_slot,
            status: TransferTicketStatus::Sealed,
        };
        self.transfer_tickets.insert(ticket_id, ticket.clone());
        if let Some(route) = self.routes.get_mut(&request.route_id) {
            route.status = RouteStatus::Ticketed;
        }
        self.counters.transfer_tickets = self.transfer_tickets.len() as u64;
        self.refresh_roots();
        Ok(ticket)
    }

    pub fn quote_fee(&mut self, request: QuoteFeeRequest) -> Result<FeeQuote> {
        ensure_capacity(self.fee_quotes.len(), MAX_FEE_QUOTES, "fee_quotes")?;
        let route = self
            .routes
            .get(&request.route_id)
            .ok_or_else(|| "route not found".to_string())?;
        if !route
            .relay_ids
            .iter()
            .any(|relay_id| relay_id == &request.relay_id)
        {
            return Err("relay is not assigned to route".to_string());
        }
        let ticket = self
            .transfer_tickets
            .get(&request.ticket_id)
            .ok_or_else(|| "ticket not found".to_string())?;
        if ticket.route_id != request.route_id {
            return Err("ticket belongs to a different route".to_string());
        }
        ensure_non_empty(&request.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        if request.fee_micro_units == 0 {
            return Err("fee_micro_units must be non-zero".to_string());
        }
        if request.fee_micro_units > ticket.max_fee_micro_units {
            return Err("fee exceeds ticket cap".to_string());
        }
        ensure_bps(request.fee_bps, "fee_bps")?;
        if request.fee_bps > route.max_user_fee_bps {
            return Err("fee bps exceeds route cap".to_string());
        }
        ensure_bps(request.rebate_hint_bps, "rebate_hint_bps")?;
        if request.valid_until_slot <= ticket.submitted_slot {
            return Err("fee quote must remain valid beyond submission slot".to_string());
        }
        let quote_id = stable_id(
            "fee-quote",
            &[
                HashPart::Str(&request.route_id),
                HashPart::Str(&request.ticket_id),
                HashPart::Str(&request.relay_id),
                HashPart::U64(request.fee_micro_units),
                HashPart::U64(request.valid_until_slot),
            ],
        );
        let quote = FeeQuote {
            quote_id: quote_id.clone(),
            route_id: request.route_id,
            ticket_id: request.ticket_id.clone(),
            relay_id: request.relay_id,
            fee_asset_id: request.fee_asset_id,
            fee_micro_units: request.fee_micro_units,
            fee_bps: request.fee_bps,
            sponsor_pool_root: request.sponsor_pool_root,
            valid_until_slot: request.valid_until_slot,
            rebate_hint_bps: request.rebate_hint_bps,
        };
        self.fee_quotes.insert(quote_id, quote.clone());
        if let Some(ticket) = self.transfer_tickets.get_mut(&request.ticket_id) {
            ticket.quoted_fee_micro_units = quote.fee_micro_units;
            ticket.status = TransferTicketStatus::FeeQuoted;
        }
        self.counters.fee_quotes = self.fee_quotes.len() as u64;
        self.refresh_roots();
        Ok(quote)
    }

    pub fn build_netting_batch(
        &mut self,
        request: BuildNettingBatchRequest,
    ) -> Result<NettingBatch> {
        ensure_capacity(
            self.netting_batches.len(),
            MAX_NETTING_BATCHES,
            "netting_batches",
        )?;
        if request.ticket_ids.is_empty() {
            return Err("netting batch requires at least one ticket".to_string());
        }
        if request.ticket_ids.len() > MAX_BATCH_TICKETS {
            return Err("netting batch has too many tickets".to_string());
        }
        let route = self
            .routes
            .get(&request.route_id)
            .ok_or_else(|| "route not found".to_string())?;
        for relay_id in &request.relay_ids {
            if !route.relay_ids.iter().any(|assigned| assigned == relay_id) {
                return Err("batch relay is not assigned to route".to_string());
            }
        }
        ensure_non_empty(&request.source_lock_root, "source_lock_root")?;
        ensure_non_empty(&request.destination_mint_root, "destination_mint_root")?;
        ensure_non_empty(
            &request.aggregate_nullifier_root,
            "aggregate_nullifier_root",
        )?;
        ensure_non_empty(&request.aggregate_output_root, "aggregate_output_root")?;
        ensure_bps(request.imbalance_bps, "imbalance_bps")?;
        if request.imbalance_bps > self.config.max_netting_imbalance_bps {
            return Err("netting imbalance exceeds configured bound".to_string());
        }
        let mut total_fee_micro_units = 0_u64;
        for ticket_id in &request.ticket_ids {
            let ticket = self
                .transfer_tickets
                .get(ticket_id)
                .ok_or_else(|| format!("ticket not found: {ticket_id}"))?;
            if ticket.route_id != request.route_id {
                return Err("ticket route does not match batch route".to_string());
            }
            if !matches!(
                ticket.status,
                TransferTicketStatus::FeeQuoted | TransferTicketStatus::RelayAccepted
            ) {
                return Err("ticket is not ready for netting".to_string());
            }
            total_fee_micro_units =
                total_fee_micro_units.saturating_add(ticket.quoted_fee_micro_units);
        }
        let batch_id = stable_id(
            "netting-batch",
            &[
                HashPart::Str(&request.route_id),
                HashPart::Str(&request.source_lock_root),
                HashPart::Str(&request.destination_mint_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        let decision = if request.imbalance_bps == 0 {
            RouteDecision::Accept
        } else if request.imbalance_bps <= self.config.max_netting_imbalance_bps / 2 {
            RouteDecision::AcceptWithDelay
        } else {
            RouteDecision::Rebatch
        };
        let batch = NettingBatch {
            batch_id: batch_id.clone(),
            route_id: request.route_id.clone(),
            ticket_ids: request.ticket_ids.clone(),
            relay_ids: request.relay_ids,
            source_lock_root: request.source_lock_root,
            destination_mint_root: request.destination_mint_root,
            aggregate_nullifier_root: request.aggregate_nullifier_root,
            aggregate_output_root: request.aggregate_output_root,
            total_fee_micro_units,
            imbalance_bps: request.imbalance_bps,
            opened_slot: request.opened_slot,
            settled_slot: None,
            status: RouteStatus::Netted,
            settlement_decision: decision,
        };
        self.netting_batches.insert(batch_id, batch.clone());
        for ticket_id in &request.ticket_ids {
            if let Some(ticket) = self.transfer_tickets.get_mut(ticket_id) {
                ticket.status = TransferTicketStatus::Batched;
            }
        }
        if let Some(route) = self.routes.get_mut(&request.route_id) {
            route.status = RouteStatus::Netted;
        }
        self.counters.netting_batches = self.netting_batches.len() as u64;
        self.refresh_roots();
        Ok(batch)
    }

    pub fn record_relay_attestation(
        &mut self,
        request: RecordRelayAttestationRequest,
    ) -> Result<RelayAttestation> {
        ensure_capacity(
            self.relay_attestations.len(),
            MAX_RELAY_ATTESTATIONS,
            "relay_attestations",
        )?;
        self.ensure_route_exists(&request.route_id)?;
        self.ensure_relay_exists(&request.relay_id)?;
        if let Some(batch_id) = &request.batch_id {
            self.ensure_batch_exists(batch_id)?;
        }
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        if request.quorum_weight_bps < self.config.min_attestation_quorum_bps {
            return Err("relay attestation quorum below configured minimum".to_string());
        }
        let attestation_id = stable_id(
            "relay-attestation",
            &[
                HashPart::Str(&request.route_id),
                HashPart::Str(&request.relay_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.statement_root),
                HashPart::U64(request.observed_slot),
            ],
        );
        let attestation = RelayAttestation {
            attestation_id: attestation_id.clone(),
            route_id: request.route_id.clone(),
            batch_id: request.batch_id,
            relay_id: request.relay_id,
            kind: request.kind,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
        };
        self.relay_attestations
            .insert(attestation_id, attestation.clone());
        if let Some(route) = self.routes.get_mut(&request.route_id) {
            route.status = RouteStatus::Attesting;
            route.attestation_quorum_bps =
                route.attestation_quorum_bps.max(request.quorum_weight_bps);
        }
        self.counters.relay_attestations = self.relay_attestations.len() as u64;
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn settle_batch(&mut self, request: SettleBatchRequest) -> Result<NettingBatch> {
        let batch = self
            .netting_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "batch not found".to_string())?;
        if request.settled_slot < batch.opened_slot {
            return Err("settled_slot must be >= opened_slot".to_string());
        }
        batch.settled_slot = Some(request.settled_slot);
        batch.settlement_decision = request.decision;
        batch.status = match request.decision {
            RouteDecision::Accept | RouteDecision::AcceptWithDelay => RouteStatus::Settled,
            RouteDecision::RequireMoreRelayQuorum | RouteDecision::RepriceFee => {
                RouteStatus::Delayed
            }
            RouteDecision::Rebatch => RouteStatus::Netted,
            RouteDecision::QuarantineRelay | RouteDecision::Reject => RouteStatus::Quarantined,
        };
        for ticket_id in &batch.ticket_ids {
            if let Some(ticket) = self.transfer_tickets.get_mut(ticket_id) {
                ticket.status = match batch.status {
                    RouteStatus::Settled => TransferTicketStatus::Settled,
                    RouteStatus::Delayed => TransferTicketStatus::RelayAccepted,
                    RouteStatus::Quarantined => TransferTicketStatus::Rejected,
                    _ => ticket.status,
                };
            }
        }
        if let Some(route) = self.routes.get_mut(&batch.route_id) {
            route.status = batch.status;
        }
        match batch.status {
            RouteStatus::Settled => {
                self.counters.settled_batches = self.counters.settled_batches.saturating_add(1)
            }
            RouteStatus::Delayed => {
                self.counters.delayed_routes = self.counters.delayed_routes.saturating_add(1)
            }
            RouteStatus::Quarantined => {
                self.counters.rejected_tickets = self.counters.rejected_tickets.saturating_add(1)
            }
            _ => {}
        }
        let updated = batch.clone();
        self.refresh_roots();
        Ok(updated)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<RebateReceipt> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        let ticket = self
            .transfer_tickets
            .get(&request.ticket_id)
            .ok_or_else(|| "ticket not found".to_string())?;
        let quote = self
            .fee_quotes
            .get(&request.fee_quote_id)
            .ok_or_else(|| "fee quote not found".to_string())?;
        if quote.ticket_id != request.ticket_id {
            return Err("rebate quote does not match ticket".to_string());
        }
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.fee_rebate_bps > self.config.target_rebate_bps {
            return Err("rebate bps exceeds configured target".to_string());
        }
        if request.amount_micro_units > quote.fee_micro_units {
            return Err("rebate amount exceeds quoted fee".to_string());
        }
        if request.expires_slot <= request.issued_slot {
            return Err("rebate expiry must be after issue slot".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.ticket_id),
                HashPart::Str(&request.fee_quote_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        let receipt = RebateReceipt {
            rebate_id: rebate_id.clone(),
            ticket_id: request.ticket_id.clone(),
            route_id: ticket.route_id.clone(),
            fee_quote_id: request.fee_quote_id,
            asset_id: request.asset_id,
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        self.rebates.insert(rebate_id, receipt.clone());
        if let Some(ticket) = self.transfer_tickets.get_mut(&request.ticket_id) {
            ticket.status = TransferTicketStatus::RebateIssued;
        }
        if let Some(route) = self.routes.get_mut(&receipt.route_id) {
            route.status = RouteStatus::Rebated;
        }
        self.counters.rebates = self.rebates.len() as u64;
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn publish_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction_budgets",
        )?;
        ensure_non_empty(&request.target_id, "target_id")?;
        if request.public_fields.is_empty() {
            return Err("redaction budget must expose at least one public field".to_string());
        }
        if request.redacted_fields.is_empty() {
            return Err("redaction budget must redact at least one field".to_string());
        }
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("actual_public_bytes exceeds max_public_bytes".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction budget privacy set below configured minimum".to_string());
        }
        let budget_id = stable_id(
            "redaction-budget",
            &[
                HashPart::Str(&request.target_id),
                HashPart::U64(request.max_public_bytes),
                HashPart::U64(request.actual_public_bytes),
            ],
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            target_id: request.target_id,
            public_fields: request.public_fields,
            redacted_fields: request.redacted_fields,
            max_public_bytes: request.max_public_bytes,
            actual_public_bytes: request.actual_public_bytes,
            privacy_set_size: request.privacy_set_size,
        };
        self.redaction_budgets.insert(budget_id, budget.clone());
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.refresh_roots();
        Ok(budget)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator_summaries",
        )?;
        let route = self
            .routes
            .get(&request.route_id)
            .ok_or_else(|| "route not found".to_string())?;
        if let Some(batch_id) = &request.batch_id {
            self.ensure_batch_exists(batch_id)?;
        }
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let ticket_count = self
            .transfer_tickets
            .values()
            .filter(|ticket| ticket.route_id == request.route_id)
            .count() as u64;
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::Str(&request.route_id),
                HashPart::Str(request.batch_id.as_deref().unwrap_or("none")),
                HashPart::U64(ticket_count),
                HashPart::U64(self.operator_summaries.len() as u64),
            ],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            route_id: request.route_id,
            batch_id: request.batch_id,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
            route_risk_bps: route.route_risk_bps,
            ticket_count,
            delayed_routes: self.counters.delayed_routes,
            settled_batches: self.counters.settled_batches,
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.refresh_roots();
        Ok(summary)
    }

    pub fn quarantine_relay(
        &mut self,
        relay_id: &str,
        current_slot: u64,
        reason_root: &str,
    ) -> Result<()> {
        ensure_non_empty(relay_id, "relay_id")?;
        ensure_non_empty(reason_root, "reason_root")?;
        let relay = self
            .relays
            .get_mut(relay_id)
            .ok_or_else(|| "relay not found".to_string())?;
        relay.status = RelayStatus::Quarantined;
        relay.failed_batches = relay.failed_batches.saturating_add(1);
        relay.quarantine_until_slot = current_slot + self.config.relay_quarantine_slots;
        self.counters.quarantined_relays = self.counters.quarantined_relays.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters.domains = self.domains.len() as u64;
        self.counters.token_pairs = self.token_pairs.len() as u64;
        self.counters.relays = self.relays.len() as u64;
        self.counters.routes = self.routes.len() as u64;
        self.counters.transfer_tickets = self.transfer_tickets.len() as u64;
        self.counters.fee_quotes = self.fee_quotes.len() as u64;
        self.counters.netting_batches = self.netting_batches.len() as u64;
        self.counters.relay_attestations = self.relay_attestations.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.roots.domain_root = map_root("cross-domain-token-router:domains", &self.domains);
        self.roots.token_pair_root =
            map_root("cross-domain-token-router:token-pairs", &self.token_pairs);
        self.roots.relay_root = map_root("cross-domain-token-router:relays", &self.relays);
        self.roots.route_root = map_root("cross-domain-token-router:routes", &self.routes);
        self.roots.transfer_ticket_root = map_root(
            "cross-domain-token-router:transfer-tickets",
            &self.transfer_tickets,
        );
        self.roots.fee_quote_root =
            map_root("cross-domain-token-router:fee-quotes", &self.fee_quotes);
        self.roots.netting_batch_root = map_root(
            "cross-domain-token-router:netting-batches",
            &self.netting_batches,
        );
        self.roots.relay_attestation_root = map_root(
            "cross-domain-token-router:relay-attestations",
            &self.relay_attestations,
        );
        self.roots.rebate_root = map_root("cross-domain-token-router:rebates", &self.rebates);
        self.roots.redaction_budget_root = map_root(
            "cross-domain-token-router:redaction-budgets",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "cross-domain-token-router:operator-summaries",
            &self.operator_summaries,
        );
        self.roots.state_root = self.compute_state_root();
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_relay_suite": self.config.pq_relay_suite,
            "route_commitment_suite": self.config.route_commitment_suite,
            "netting_suite": self.config.netting_suite,
            "fee_suite": self.config.fee_suite,
            "redaction_suite": self.config.redaction_suite,
            "l2_height": DEVNET_L2_HEIGHT,
            "epoch": DEVNET_EPOCH,
            "slot": DEVNET_SLOT,
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "domains": self.domains,
            "token_pairs": self.token_pairs,
            "relays": self.relays,
            "routes": self.routes,
            "transfer_tickets": self.transfer_tickets,
            "fee_quotes": self.fee_quotes,
            "netting_batches": self.netting_batches,
            "relay_attestations": self.relay_attestations,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
        })
    }

    fn compute_state_root(&self) -> String {
        let record = json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "domain_root": self.roots.domain_root,
            "token_pair_root": self.roots.token_pair_root,
            "relay_root": self.roots.relay_root,
            "route_root": self.roots.route_root,
            "transfer_ticket_root": self.roots.transfer_ticket_root,
            "fee_quote_root": self.roots.fee_quote_root,
            "netting_batch_root": self.roots.netting_batch_root,
            "relay_attestation_root": self.roots.relay_attestation_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "counters": self.counters.public_record(),
        });
        domain_hash(
            "cross-domain-token-router:state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }

    fn ensure_domain_exists(&self, domain_id: &str) -> Result<()> {
        ensure_non_empty(domain_id, "domain_id")?;
        if !self.domains.contains_key(domain_id) {
            return Err(format!("domain not found: {domain_id}"));
        }
        Ok(())
    }

    fn ensure_route_exists(&self, route_id: &str) -> Result<()> {
        ensure_non_empty(route_id, "route_id")?;
        if !self.routes.contains_key(route_id) {
            return Err(format!("route not found: {route_id}"));
        }
        Ok(())
    }

    fn ensure_relay_exists(&self, relay_id: &str) -> Result<()> {
        ensure_non_empty(relay_id, "relay_id")?;
        if !self.relays.contains_key(relay_id) {
            return Err(format!("relay not found: {relay_id}"));
        }
        Ok(())
    }

    fn ensure_batch_exists(&self, batch_id: &str) -> Result<()> {
        ensure_non_empty(batch_id, "batch_id")?;
        if !self.netting_batches.contains_key(batch_id) {
            return Err(format!("batch not found: {batch_id}"));
        }
        Ok(())
    }

    fn ensure_active_relay_supports(&self, relay_id: &str, pair: &TokenPair) -> Result<()> {
        let relay = self
            .relays
            .get(relay_id)
            .ok_or_else(|| format!("relay not found: {relay_id}"))?;
        if relay.status != RelayStatus::Active {
            return Err("relay is not active".to_string());
        }
        if !relay.supported_domain_ids.contains(&pair.source_domain_id)
            || !relay
                .supported_domain_ids
                .contains(&pair.destination_domain_id)
        {
            return Err("relay does not support token pair domains".to_string());
        }
        if !relay.supported_token_classes.contains(&pair.token_class) {
            return Err("relay does not support token class".to_string());
        }
        Ok(())
    }

    fn ensure_route_hops_cover_pair(&self, hops: &[String], pair: &TokenPair) -> Result<()> {
        if hops.is_empty() {
            return Err("route requires at least one hop".to_string());
        }
        if hops.first() != Some(&pair.source_domain_id) {
            return Err("route first hop must be the source domain".to_string());
        }
        if hops.last() != Some(&pair.destination_domain_id) {
            return Err("route last hop must be the destination domain".to_string());
        }
        for hop in hops {
            self.ensure_domain_exists(hop)?;
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let monero_domain = state
        .register_domain(RegisterDomainRequest {
            kind: DomainKind::MoneroAnchor,
            operator_set_root: sample_hash("operator-set", 1),
            finality_root: sample_hash("monero-finality", 1),
            light_client_root: sample_hash("light-client", 1),
            l2_height: DEVNET_L2_HEIGHT,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            accepts_private_tokens: true,
            emergency_exit_enabled: true,
        })
        .expect("devnet monero domain registered");
    let liquidity_domain = state
        .register_domain(RegisterDomainRequest {
            kind: DomainKind::LiquidityHub,
            operator_set_root: sample_hash("operator-set", 2),
            finality_root: sample_hash("liquidity-finality", 1),
            light_client_root: sample_hash("light-client", 2),
            l2_height: DEVNET_L2_HEIGHT + 1,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            accepts_private_tokens: true,
            emergency_exit_enabled: true,
        })
        .expect("devnet liquidity domain registered");
    let app_domain = state
        .register_domain(RegisterDomainRequest {
            kind: DomainKind::ContractSubnet,
            operator_set_root: sample_hash("operator-set", 3),
            finality_root: sample_hash("contract-finality", 1),
            light_client_root: sample_hash("light-client", 3),
            l2_height: DEVNET_L2_HEIGHT + 3,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            accepts_private_tokens: true,
            emergency_exit_enabled: false,
        })
        .expect("devnet app domain registered");
    let pair = state
        .register_token_pair(RegisterTokenPairRequest {
            source_domain_id: monero_domain.domain_id.clone(),
            destination_domain_id: app_domain.domain_id.clone(),
            token_class: TokenClass::NativeXmr,
            source_asset_commitment: sample_hash("source-asset", 1),
            destination_asset_commitment: sample_hash("destination-asset", 1),
            reserve_root: sample_hash("reserve", 1),
            decimal_shift: 0,
            max_fee_bps: 12,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet token pair registered");
    let relay = state
        .register_relay(RegisterRelayRequest {
            operator_commitment: sample_hash("relay-operator", 1),
            pq_verifying_key_root: sample_hash("pq-key", 1),
            stake_bond_micro_units: DEFAULT_MIN_RELAY_BOND_MICRO_UNITS * 2,
            supported_domain_ids: [
                monero_domain.domain_id.clone(),
                liquidity_domain.domain_id.clone(),
                app_domain.domain_id.clone(),
            ]
            .into_iter()
            .collect(),
            supported_token_classes: [TokenClass::NativeXmr, TokenClass::ConfidentialStablecoin]
                .into_iter()
                .collect(),
        })
        .expect("devnet relay registered");
    let route = state
        .open_route(OpenRouteRequest {
            pair_id: pair.pair_id.clone(),
            relay_ids: vec![relay.relay_id.clone()],
            hop_domain_ids: vec![
                monero_domain.domain_id.clone(),
                liquidity_domain.domain_id,
                app_domain.domain_id,
            ],
            encrypted_route_root: sample_hash("encrypted-route", 1),
            route_hint_root: sample_hash("route-hint", 1),
            max_latency_ms: DEFAULT_TARGET_ROUTE_MS,
            max_user_fee_bps: 10,
            route_risk_bps: 720,
            opened_slot: DEVNET_SLOT,
        })
        .expect("devnet route opened");
    let ticket = state
        .admit_transfer_ticket(AdmitTransferTicketRequest {
            route_id: route.route_id.clone(),
            owner_commitment: sample_hash("owner", 1),
            input_note_root: sample_hash("input-note", 1),
            output_note_root: sample_hash("output-note", 1),
            nullifier_root: sample_hash("nullifier", 1),
            amount_commitment: sample_hash("amount", 1),
            max_fee_micro_units: 20_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            submitted_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet transfer ticket admitted");
    let quote = state
        .quote_fee(QuoteFeeRequest {
            route_id: route.route_id.clone(),
            ticket_id: ticket.ticket_id.clone(),
            relay_id: relay.relay_id.clone(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            fee_micro_units: 4_800,
            fee_bps: 7,
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            valid_until_slot: DEVNET_SLOT + 32,
            rebate_hint_bps: DEFAULT_TARGET_REBATE_BPS,
        })
        .expect("devnet fee quoted");
    state
        .record_relay_attestation(RecordRelayAttestationRequest {
            route_id: route.route_id.clone(),
            batch_id: None,
            relay_id: relay.relay_id.clone(),
            kind: AttestationKind::PqSignatureVerified,
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 2,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet relay attestation recorded");
    let batch = state
        .build_netting_batch(BuildNettingBatchRequest {
            route_id: route.route_id.clone(),
            ticket_ids: vec![ticket.ticket_id.clone()],
            relay_ids: vec![relay.relay_id],
            source_lock_root: sample_hash("source-lock", 1),
            destination_mint_root: sample_hash("destination-mint", 1),
            aggregate_nullifier_root: sample_hash("aggregate-nullifier", 1),
            aggregate_output_root: sample_hash("aggregate-output", 1),
            imbalance_bps: 0,
            opened_slot: DEVNET_SLOT + 3,
        })
        .expect("devnet netting batch built");
    state
        .record_relay_attestation(RecordRelayAttestationRequest {
            route_id: route.route_id.clone(),
            batch_id: Some(batch.batch_id.clone()),
            relay_id: batch
                .relay_ids
                .first()
                .cloned()
                .expect("devnet batch has relay"),
            kind: AttestationKind::BatchNettingBalanced,
            statement_root: sample_hash("batch-statement", 1),
            pq_signature_root: sample_hash("batch-pq-signature", 1),
            observed_slot: DEVNET_SLOT + 4,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet batch attestation recorded");
    state
        .settle_batch(SettleBatchRequest {
            batch_id: batch.batch_id.clone(),
            settled_slot: DEVNET_SLOT + 5,
            decision: RouteDecision::Accept,
        })
        .expect("devnet batch settled");
    state
        .issue_rebate(IssueRebateRequest {
            ticket_id: ticket.ticket_id.clone(),
            fee_quote_id: quote.quote_id,
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            amount_micro_units: 1_200,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 6,
            expires_slot: DEVNET_SLOT + 512,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: batch.batch_id.clone(),
            public_fields: ["batch_id", "route_id", "ticket_count", "imbalance_bps"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            redacted_fields: [
                "owner_commitment",
                "input_note_root",
                "output_note_root",
                "amount_commitment",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: 2_048,
            actual_public_bytes: 816,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            route_id: route.route_id,
            batch_id: Some(batch.batch_id),
            median_fee_bps: 7,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let source_domain = state
        .domains
        .values()
        .find(|domain| domain.kind == DomainKind::MoneroAnchor)
        .cloned()
        .expect("devnet has monero domain");
    let destination_domain = state
        .domains
        .values()
        .find(|domain| domain.kind == DomainKind::ContractSubnet)
        .cloned()
        .expect("devnet has app domain");
    let pair = state
        .register_token_pair(RegisterTokenPairRequest {
            source_domain_id: source_domain.domain_id,
            destination_domain_id: destination_domain.domain_id,
            token_class: TokenClass::ConfidentialStablecoin,
            source_asset_commitment: sample_hash("source-asset", 2),
            destination_asset_commitment: sample_hash("destination-asset", 2),
            reserve_root: sample_hash("reserve", 2),
            decimal_shift: 0,
            max_fee_bps: 10,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("demo stable pair registered");
    let relay_id = state
        .relays
        .keys()
        .next()
        .cloned()
        .expect("devnet has relay");
    let route = state
        .open_route(OpenRouteRequest {
            pair_id: pair.pair_id,
            relay_ids: vec![relay_id],
            hop_domain_ids: vec![pair.source_domain_id.clone(), pair.destination_domain_id],
            encrypted_route_root: sample_hash("encrypted-route", 2),
            route_hint_root: sample_hash("route-hint", 2),
            max_latency_ms: DEFAULT_TARGET_ROUTE_MS + 80,
            max_user_fee_bps: 9,
            route_risk_bps: 980,
            opened_slot: DEVNET_SLOT + 24,
        })
        .expect("demo route opened");
    state
        .admit_transfer_ticket(AdmitTransferTicketRequest {
            route_id: route.route_id,
            owner_commitment: sample_hash("owner", 2),
            input_note_root: sample_hash("input-note", 2),
            output_note_root: sample_hash("output-note", 2),
            nullifier_root: sample_hash("nullifier", 2),
            amount_commitment: sample_hash("amount", 2),
            max_fee_micro_units: 16_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            submitted_slot: DEVNET_SLOT + 25,
        })
        .expect("demo ticket admitted");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!(state.public_record())
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("cross-domain-token-router:{domain}:id"), parts, 24)
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "cross-domain-token-router:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn ensure_non_empty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} must be <= 10000"));
    }
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, name: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{name} capacity exceeded"));
    }
    Ok(())
}
