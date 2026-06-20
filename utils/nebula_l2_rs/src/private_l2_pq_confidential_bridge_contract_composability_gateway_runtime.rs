use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialBridgeContractComposabilityGatewayRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialBridgeContractComposabilityGatewayRuntimeResult<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "private-l2-pq-confidential-bridge-contract-composability-gateway/v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_GATEWAY_ID: &str = "devnet-bridge-contract-composability-gateway";
pub const DEVNET_WRAPPED_XMR_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTHORIZATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-bridge-contract-gateway-v1";
pub const CONFIDENTIAL_DISCLOSURE_SUITE: &str =
    "view-key-selective-disclosure+nullifier-membership+amount-range-v1";
pub const TOKEN_COVENANT_SUITE: &str = "confidential-token-mint-burn-covenant-v1";
pub const CONTRACT_CALLBACK_SUITE: &str = "private-contract-callback-envelope-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-bridge-contract-settlement-batch-v1";
pub const PRECONFIRMATION_SUITE: &str = "fast-private-bridge-contract-preconfirmation-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 10;
pub const DEFAULT_FINALITY_DEPTH: u64 = 8;
pub const DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_PRECONFIRMATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 32;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 1024;
pub const DEFAULT_MAX_FEE_BPS: u64 = 20;
pub const DEFAULT_RISK_SCORE_LIMIT: u16 = 650;
pub const DEFAULT_MAX_VALUE_PER_TICKET_UNITS: u128 = 50_000_000_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    MoneroToL2,
    L2ToMonero,
    ContractCallback,
    Reconciliation,
}

impl BridgeDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroToL2 => "monero_to_l2",
            Self::L2ToMonero => "l2_to_monero",
            Self::ContractCallback => "contract_callback",
            Self::Reconciliation => "reconciliation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Open,
    Preconfirmed,
    CallbackReady,
    Settled,
    Exiting,
    Rejected,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Preconfirmed => "preconfirmed",
            Self::CallbackReady => "callback_ready",
            Self::Settled => "settled",
            Self::Exiting => "exiting",
            Self::Rejected => "rejected",
        }
    }

    pub fn accepts_callback(self) -> bool {
        matches!(self, Self::Open | Self::Preconfirmed | Self::CallbackReady)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenCovenantAction {
    Mint,
    Burn,
    Lock,
    Release,
}

impl TokenCovenantAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Lock => "lock",
            Self::Release => "release",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskDecision {
    Allow,
    Review,
    Hold,
    Reject,
}

impl RiskDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Review => "review",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }

    pub fn is_blocking(self) -> bool {
        matches!(self, Self::Hold | Self::Reject)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    BridgeTicket,
    CallbackEnvelope,
    TokenCovenantCheck,
    PqAuthorization,
    SelectiveDisclosure,
    SettlementBatch,
    PreconfirmationReceipt,
    RiskGate,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeTicket => "bridge_ticket",
            Self::CallbackEnvelope => "callback_envelope",
            Self::TokenCovenantCheck => "token_covenant_check",
            Self::PqAuthorization => "pq_authorization",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::SettlementBatch => "settlement_batch",
            Self::PreconfirmationReceipt => "preconfirmation_receipt",
            Self::RiskGate => "risk_gate",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub gateway_id: String,
    pub monero_network: String,
    pub wrapped_xmr_asset_id: String,
    pub fee_asset_id: String,
    pub min_monero_confirmations: u64,
    pub finality_depth: u64,
    pub min_pq_security_bits: u16,
    pub disclosure_ttl_blocks: u64,
    pub preconfirmation_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub max_batch_items: usize,
    pub max_fee_bps: u64,
    pub risk_score_limit: u16,
    pub max_value_per_ticket_units: u128,
    pub require_pq_authorization: bool,
    pub require_selective_disclosure: bool,
    pub require_contract_callback: bool,
    pub require_low_fee_batching: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            gateway_id: DEVNET_GATEWAY_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            wrapped_xmr_asset_id: DEVNET_WRAPPED_XMR_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            finality_depth: DEFAULT_FINALITY_DEPTH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            disclosure_ttl_blocks: DEFAULT_DISCLOSURE_TTL_BLOCKS,
            preconfirmation_ttl_blocks: DEFAULT_PRECONFIRMATION_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            risk_score_limit: DEFAULT_RISK_SCORE_LIMIT,
            max_value_per_ticket_units: DEFAULT_MAX_VALUE_PER_TICKET_UNITS,
            require_pq_authorization: true,
            require_selective_disclosure: true,
            require_contract_callback: true,
            require_low_fee_batching: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("config.chain_id", &self.chain_id)?;
        ensure_non_empty("config.protocol_version", &self.protocol_version)?;
        ensure_non_empty("config.gateway_id", &self.gateway_id)?;
        ensure_non_empty("config.monero_network", &self.monero_network)?;
        ensure_non_empty("config.wrapped_xmr_asset_id", &self.wrapped_xmr_asset_id)?;
        ensure_capacity("config.max_batch_items", self.max_batch_items)?;
        ensure(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "config.min_pq_security_bits below runtime floor",
        )?;
        ensure(
            self.max_fee_bps <= 10_000,
            "config.max_fee_bps exceeds bps scale",
        )?;
        ensure(
            self.max_value_per_ticket_units > 0,
            "config.max_value_per_ticket_units must be positive",
        )
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_ticket_index: u64,
    pub next_callback_index: u64,
    pub next_covenant_index: u64,
    pub next_authorization_index: u64,
    pub next_disclosure_index: u64,
    pub next_batch_index: u64,
    pub next_preconfirmation_index: u64,
    pub next_risk_gate_index: u64,
    pub public_record_count: u64,
    pub tickets_settled: u64,
    pub tickets_rejected: u64,
    pub total_minted_units: u128,
    pub total_burned_units: u128,
    pub total_fee_units: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_ticket_index: 1,
            next_callback_index: 1,
            next_covenant_index: 1,
            next_authorization_index: 1,
            next_disclosure_index: 1,
            next_batch_index: 1,
            next_preconfirmation_index: 1,
            next_risk_gate_index: 1,
            public_record_count: 0,
            tickets_settled: 0,
            tickets_rejected: 0,
            total_minted_units: 0,
            total_burned_units: 0,
            total_fee_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeTicketRequest {
    pub direction: BridgeDirection,
    pub owner_commitment: String,
    pub monero_txid_root: String,
    pub monero_output_root: String,
    pub l2_account_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub amount_upper_bound_units: u128,
    pub fee_units: u64,
    pub contract_id: String,
    pub callback_selector: String,
    pub encrypted_call_root: String,
    pub nonce: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeTicket {
    pub ticket_id: String,
    pub direction: BridgeDirection,
    pub status: TicketStatus,
    pub owner_commitment: String,
    pub monero_txid_root: String,
    pub monero_output_root: String,
    pub l2_account_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub amount_upper_bound_units: u128,
    pub fee_units: u64,
    pub contract_id: String,
    pub callback_selector: String,
    pub encrypted_call_root: String,
    pub covenant_check_id: String,
    pub authorization_id: String,
    pub risk_gate_id: String,
    pub nonce: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl BridgeTicket {
    pub fn new(request: BridgeTicketRequest, index: u64) -> Result<Self> {
        validate_bridge_ticket_request(&request)?;
        let ticket_id = bridge_ticket_id(&request, index);
        Ok(Self {
            ticket_id,
            direction: request.direction,
            status: TicketStatus::Open,
            owner_commitment: request.owner_commitment,
            monero_txid_root: request.monero_txid_root,
            monero_output_root: request.monero_output_root,
            l2_account_commitment: request.l2_account_commitment,
            asset_id: request.asset_id,
            amount_commitment: request.amount_commitment,
            amount_upper_bound_units: request.amount_upper_bound_units,
            fee_units: request.fee_units,
            contract_id: request.contract_id,
            callback_selector: request.callback_selector,
            encrypted_call_root: request.encrypted_call_root,
            covenant_check_id: String::new(),
            authorization_id: String::new(),
            risk_gate_id: String::new(),
            nonce: request.nonce,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_ticket",
            "ticket_id": self.ticket_id,
            "direction": self.direction.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "monero_txid_root": self.monero_txid_root,
            "monero_output_root": self.monero_output_root,
            "l2_account_commitment": self.l2_account_commitment,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "amount_upper_bound_units": self.amount_upper_bound_units.to_string(),
            "fee_units": self.fee_units,
            "contract_id": self.contract_id,
            "callback_selector": self.callback_selector,
            "encrypted_call_root": self.encrypted_call_root,
            "covenant_check_id": self.covenant_check_id,
            "authorization_id": self.authorization_id,
            "risk_gate_id": self.risk_gate_id,
            "nonce": self.nonce,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-TICKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallbackRequest {
    pub ticket_id: String,
    pub contract_id: String,
    pub callback_selector: String,
    pub encrypted_call_root: String,
    pub callback_state_root: String,
    pub token_delta_root: String,
    pub disclosure_id: String,
    pub gas_limit: u64,
    pub fee_units: u64,
    pub nonce: u64,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallbackEnvelope {
    pub callback_id: String,
    pub ticket_id: String,
    pub contract_id: String,
    pub callback_selector: String,
    pub encrypted_call_root: String,
    pub callback_state_root: String,
    pub token_delta_root: String,
    pub disclosure_id: String,
    pub gas_limit: u64,
    pub fee_units: u64,
    pub nonce: u64,
    pub submitted_at_height: u64,
}

impl ContractCallbackEnvelope {
    pub fn new(request: ContractCallbackRequest, index: u64) -> Result<Self> {
        validate_callback_request(&request)?;
        Ok(Self {
            callback_id: callback_envelope_id(&request, index),
            ticket_id: request.ticket_id,
            contract_id: request.contract_id,
            callback_selector: request.callback_selector,
            encrypted_call_root: request.encrypted_call_root,
            callback_state_root: request.callback_state_root,
            token_delta_root: request.token_delta_root,
            disclosure_id: request.disclosure_id,
            gas_limit: request.gas_limit,
            fee_units: request.fee_units,
            nonce: request.nonce,
            submitted_at_height: request.submitted_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("CONTRACT-CALLBACK-ENVELOPE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenCovenantCheckRequest {
    pub ticket_id: String,
    pub action: TokenCovenantAction,
    pub asset_id: String,
    pub token_policy_root: String,
    pub supply_delta_commitment: String,
    pub authority_commitment: String,
    pub nullifier_root: String,
    pub amount_upper_bound_units: u128,
    pub nonce: u64,
    pub checked_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenCovenantCheck {
    pub check_id: String,
    pub ticket_id: String,
    pub action: TokenCovenantAction,
    pub asset_id: String,
    pub token_policy_root: String,
    pub supply_delta_commitment: String,
    pub authority_commitment: String,
    pub nullifier_root: String,
    pub amount_upper_bound_units: u128,
    pub accepted: bool,
    pub nonce: u64,
    pub checked_at_height: u64,
}

impl TokenCovenantCheck {
    pub fn new(request: TokenCovenantCheckRequest, index: u64, accepted: bool) -> Result<Self> {
        validate_covenant_request(&request)?;
        Ok(Self {
            check_id: token_covenant_check_id(&request, index),
            ticket_id: request.ticket_id,
            action: request.action,
            asset_id: request.asset_id,
            token_policy_root: request.token_policy_root,
            supply_delta_commitment: request.supply_delta_commitment,
            authority_commitment: request.authority_commitment,
            nullifier_root: request.nullifier_root,
            amount_upper_bound_units: request.amount_upper_bound_units,
            accepted,
            nonce: request.nonce,
            checked_at_height: request.checked_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = stable_record(self);
        record["action"] = json!(self.action.as_str());
        record
    }

    pub fn root(&self) -> String {
        payload_root("TOKEN-COVENANT-CHECK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorizationRequest {
    pub subject_id: String,
    pub signer_commitment: String,
    pub committee_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorization {
    pub authorization_id: String,
    pub subject_id: String,
    pub signer_commitment: String,
    pub committee_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub accepted: bool,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl PqAuthorization {
    pub fn new(
        request: PqAuthorizationRequest,
        index: u64,
        min_security_bits: u16,
    ) -> Result<Self> {
        validate_pq_authorization_request(&request, min_security_bits)?;
        Ok(Self {
            authorization_id: pq_authorization_id(&request, index),
            subject_id: request.subject_id,
            signer_commitment: request.signer_commitment,
            committee_root: request.committee_root,
            transcript_root: request.transcript_root,
            signature_root: request.signature_root,
            security_bits: request.security_bits,
            accepted: true,
            valid_from_height: request.valid_from_height,
            expires_at_height: request.expires_at_height,
            nonce: request.nonce,
        })
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("PQ-AUTHORIZATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosureRequest {
    pub subject_id: String,
    pub viewer_commitment: String,
    pub disclosed_fields: BTreeSet<String>,
    pub disclosure_root: String,
    pub view_key_commitment: String,
    pub nullifier_scope_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosure {
    pub disclosure_id: String,
    pub subject_id: String,
    pub viewer_commitment: String,
    pub disclosed_fields: BTreeSet<String>,
    pub disclosure_root: String,
    pub view_key_commitment: String,
    pub nullifier_scope_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl SelectiveDisclosure {
    pub fn new(request: SelectiveDisclosureRequest, index: u64) -> Result<Self> {
        validate_disclosure_request(&request)?;
        Ok(Self {
            disclosure_id: selective_disclosure_id(&request, index),
            subject_id: request.subject_id,
            viewer_commitment: request.viewer_commitment,
            disclosed_fields: request.disclosed_fields,
            disclosure_root: request.disclosure_root,
            view_key_commitment: request.view_key_commitment,
            nullifier_scope_root: request.nullifier_scope_root,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            nonce: request.nonce,
        })
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("SELECTIVE-DISCLOSURE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSettlementBatchRequest {
    pub operator_commitment: String,
    pub ticket_ids: BTreeSet<String>,
    pub callback_ids: BTreeSet<String>,
    pub covenant_check_ids: BTreeSet<String>,
    pub fee_asset_id: String,
    pub aggregate_fee_units: u64,
    pub settlement_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSettlementBatch {
    pub batch_id: String,
    pub operator_commitment: String,
    pub ticket_ids: BTreeSet<String>,
    pub callback_ids: BTreeSet<String>,
    pub covenant_check_ids: BTreeSet<String>,
    pub fee_asset_id: String,
    pub aggregate_fee_units: u64,
    pub settlement_height: u64,
    pub nonce: u64,
}

impl LowFeeSettlementBatch {
    pub fn new(
        request: LowFeeSettlementBatchRequest,
        index: u64,
        max_items: usize,
    ) -> Result<Self> {
        validate_batch_request(&request, max_items)?;
        Ok(Self {
            batch_id: settlement_batch_id(&request, index),
            operator_commitment: request.operator_commitment,
            ticket_ids: request.ticket_ids,
            callback_ids: request.callback_ids,
            covenant_check_ids: request.covenant_check_ids,
            fee_asset_id: request.fee_asset_id,
            aggregate_fee_units: request.aggregate_fee_units,
            settlement_height: request.settlement_height,
            nonce: request.nonce,
        })
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("LOW-FEE-SETTLEMENT-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationReceiptRequest {
    pub ticket_id: String,
    pub batch_id: String,
    pub sequencer_commitment: String,
    pub preconfirm_root: String,
    pub fee_quote_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub ticket_id: String,
    pub batch_id: String,
    pub sequencer_commitment: String,
    pub preconfirm_root: String,
    pub fee_quote_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl PreconfirmationReceipt {
    pub fn new(request: PreconfirmationReceiptRequest, index: u64) -> Result<Self> {
        validate_preconfirmation_request(&request)?;
        Ok(Self {
            receipt_id: preconfirmation_receipt_id(&request, index),
            ticket_id: request.ticket_id,
            batch_id: request.batch_id,
            sequencer_commitment: request.sequencer_commitment,
            preconfirm_root: request.preconfirm_root,
            fee_quote_units: request.fee_quote_units,
            issued_at_height: request.issued_at_height,
            expires_at_height: request.expires_at_height,
            nonce: request.nonce,
        })
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRECONFIRMATION-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskGateRequest {
    pub subject_id: String,
    pub reason_code: String,
    pub risk_score: u16,
    pub limit_units: u128,
    pub exposure_root: String,
    pub reviewer_commitment: String,
    pub evaluated_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskGate {
    pub gate_id: String,
    pub subject_id: String,
    pub reason_code: String,
    pub risk_score: u16,
    pub decision: RiskDecision,
    pub limit_units: u128,
    pub exposure_root: String,
    pub reviewer_commitment: String,
    pub evaluated_at_height: u64,
    pub nonce: u64,
}

impl RiskGate {
    pub fn new(request: RiskGateRequest, index: u64, score_limit: u16) -> Result<Self> {
        validate_risk_gate_request(&request)?;
        let decision = if request.risk_score <= score_limit {
            RiskDecision::Allow
        } else if request.risk_score <= score_limit.saturating_add(100) {
            RiskDecision::Review
        } else if request.risk_score < 900 {
            RiskDecision::Hold
        } else {
            RiskDecision::Reject
        };
        Ok(Self {
            gate_id: risk_gate_id(&request, index),
            subject_id: request.subject_id,
            reason_code: request.reason_code,
            risk_score: request.risk_score,
            decision,
            limit_units: request.limit_units,
            exposure_root: request.exposure_root,
            reviewer_commitment: request.reviewer_commitment,
            evaluated_at_height: request.evaluated_at_height,
            nonce: request.nonce,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = stable_record(self);
        record["decision"] = json!(self.decision.as_str());
        record
    }

    pub fn root(&self) -> String {
        payload_root("RISK-GATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayPublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub payload_root: String,
    pub publisher_commitment: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl GatewayPublicRecord {
    pub fn new(
        record_kind: PublicRecordKind,
        subject_id: String,
        payload_root: String,
        publisher_commitment: String,
        emitted_at_height: u64,
        sequence: u64,
    ) -> Result<Self> {
        ensure_non_empty("public_record.subject_id", &subject_id)?;
        ensure_non_empty("public_record.payload_root", &payload_root)?;
        ensure_non_empty("public_record.publisher_commitment", &publisher_commitment)?;
        let record_id = gateway_public_record_id(
            record_kind,
            &subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        Ok(Self {
            record_id,
            record_kind,
            subject_id,
            payload_root,
            publisher_commitment,
            emitted_at_height,
            sequence,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gateway_public_record",
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "publisher_commitment": self.publisher_commitment,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        payload_root("GATEWAY-PUBLIC-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub ticket_root: String,
    pub callback_root: String,
    pub covenant_root: String,
    pub authorization_root: String,
    pub disclosure_root: String,
    pub settlement_batch_root: String,
    pub preconfirmation_root: String,
    pub risk_gate_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub tickets: BTreeMap<String, BridgeTicket>,
    pub callbacks: BTreeMap<String, ContractCallbackEnvelope>,
    pub covenant_checks: BTreeMap<String, TokenCovenantCheck>,
    pub pq_authorizations: BTreeMap<String, PqAuthorization>,
    pub disclosures: BTreeMap<String, SelectiveDisclosure>,
    pub settlement_batches: BTreeMap<String, LowFeeSettlementBatch>,
    pub preconfirmations: BTreeMap<String, PreconfirmationReceipt>,
    pub risk_gates: BTreeMap<String, RiskGate>,
    pub public_records: BTreeMap<String, GatewayPublicRecord>,
    pub spent_nullifier_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::new(),
            tickets: BTreeMap::new(),
            callbacks: BTreeMap::new(),
            covenant_checks: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            risk_gates: BTreeMap::new(),
            public_records: BTreeMap::new(),
            spent_nullifier_roots: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        Self::new(Config::devnet())
    }

    pub fn demo() -> Result<Self> {
        let mut state = Self::devnet()?;
        let ticket = state.open_bridge_ticket(BridgeTicketRequest::devnet_deposit())?;
        let covenant = state.check_token_covenant(TokenCovenantCheckRequest::devnet_mint(
            &ticket.ticket_id,
            ticket.amount_upper_bound_units,
        ))?;
        let authorization = state.attach_pq_authorization(PqAuthorizationRequest::devnet(
            &ticket.ticket_id,
            ticket.opened_at_height,
        ))?;
        let disclosure = state.open_selective_disclosure(SelectiveDisclosureRequest::devnet(
            &ticket.ticket_id,
            ticket.opened_at_height,
        ))?;
        let risk = state.evaluate_risk_gate(RiskGateRequest::devnet(
            &ticket.ticket_id,
            ticket.amount_upper_bound_units,
            ticket.opened_at_height,
        ))?;
        state.link_ticket_controls(
            &ticket.ticket_id,
            &covenant.check_id,
            &authorization.authorization_id,
            &risk.gate_id,
        )?;
        let callback = state.submit_contract_callback(ContractCallbackRequest::devnet(
            &ticket.ticket_id,
            &disclosure.disclosure_id,
            ticket.opened_at_height + 1,
        ))?;
        let batch = state.create_low_fee_settlement_batch(LowFeeSettlementBatchRequest::devnet(
            &ticket.ticket_id,
            &callback.callback_id,
            &covenant.check_id,
            ticket.opened_at_height + 2,
        ))?;
        state.issue_preconfirmation(PreconfirmationReceiptRequest::devnet(
            &ticket.ticket_id,
            &batch.batch_id,
            ticket.opened_at_height + 3,
        ))?;
        state.mark_ticket_settled(&ticket.ticket_id)?;
        Ok(state)
    }

    pub fn open_bridge_ticket(&mut self, request: BridgeTicketRequest) -> Result<BridgeTicket> {
        self.config.validate()?;
        ensure(
            request.amount_upper_bound_units <= self.config.max_value_per_ticket_units,
            "bridge ticket exceeds configured max value",
        )?;
        ensure(
            request.fee_units
                <= fee_limit_units(request.amount_upper_bound_units, self.config.max_fee_bps),
            "bridge ticket fee exceeds configured bps limit",
        )?;
        let ticket = BridgeTicket::new(request, self.counters.next_ticket_index)?;
        ensure_absent(&self.tickets, "bridge ticket", &ticket.ticket_id)?;
        self.counters.next_ticket_index = self.counters.next_ticket_index.saturating_add(1);
        self.tickets
            .insert(ticket.ticket_id.clone(), ticket.clone());
        self.insert_public_record(
            PublicRecordKind::BridgeTicket,
            ticket.ticket_id.clone(),
            ticket.root(),
            ticket.owner_commitment.clone(),
            ticket.opened_at_height,
        )?;
        Ok(ticket)
    }

    pub fn check_token_covenant(
        &mut self,
        request: TokenCovenantCheckRequest,
    ) -> Result<TokenCovenantCheck> {
        let accepted = !self.spent_nullifier_roots.contains(&request.nullifier_root);
        let check = TokenCovenantCheck::new(request, self.counters.next_covenant_index, accepted)?;
        ensure(accepted, "token covenant nullifier root was already spent")?;
        ensure_absent(
            &self.covenant_checks,
            "token covenant check",
            &check.check_id,
        )?;
        self.spent_nullifier_roots
            .insert(check.nullifier_root.clone());
        self.counters.next_covenant_index = self.counters.next_covenant_index.saturating_add(1);
        match check.action {
            TokenCovenantAction::Mint | TokenCovenantAction::Release => {
                self.counters.total_minted_units = self
                    .counters
                    .total_minted_units
                    .saturating_add(check.amount_upper_bound_units);
            }
            TokenCovenantAction::Burn | TokenCovenantAction::Lock => {
                self.counters.total_burned_units = self
                    .counters
                    .total_burned_units
                    .saturating_add(check.amount_upper_bound_units);
            }
        }
        self.covenant_checks
            .insert(check.check_id.clone(), check.clone());
        self.insert_public_record(
            PublicRecordKind::TokenCovenantCheck,
            check.check_id.clone(),
            check.root(),
            check.authority_commitment.clone(),
            check.checked_at_height,
        )?;
        Ok(check)
    }

    pub fn attach_pq_authorization(
        &mut self,
        request: PqAuthorizationRequest,
    ) -> Result<PqAuthorization> {
        let authorization = PqAuthorization::new(
            request,
            self.counters.next_authorization_index,
            self.config.min_pq_security_bits,
        )?;
        ensure_absent(
            &self.pq_authorizations,
            "pq authorization",
            &authorization.authorization_id,
        )?;
        self.counters.next_authorization_index =
            self.counters.next_authorization_index.saturating_add(1);
        self.pq_authorizations.insert(
            authorization.authorization_id.clone(),
            authorization.clone(),
        );
        self.insert_public_record(
            PublicRecordKind::PqAuthorization,
            authorization.authorization_id.clone(),
            authorization.root(),
            authorization.signer_commitment.clone(),
            authorization.valid_from_height,
        )?;
        Ok(authorization)
    }

    pub fn open_selective_disclosure(
        &mut self,
        request: SelectiveDisclosureRequest,
    ) -> Result<SelectiveDisclosure> {
        let disclosure = SelectiveDisclosure::new(request, self.counters.next_disclosure_index)?;
        ensure_absent(
            &self.disclosures,
            "selective disclosure",
            &disclosure.disclosure_id,
        )?;
        self.counters.next_disclosure_index = self.counters.next_disclosure_index.saturating_add(1);
        self.disclosures
            .insert(disclosure.disclosure_id.clone(), disclosure.clone());
        self.insert_public_record(
            PublicRecordKind::SelectiveDisclosure,
            disclosure.disclosure_id.clone(),
            disclosure.root(),
            disclosure.viewer_commitment.clone(),
            disclosure.opened_at_height,
        )?;
        Ok(disclosure)
    }

    pub fn evaluate_risk_gate(&mut self, request: RiskGateRequest) -> Result<RiskGate> {
        let gate = RiskGate::new(
            request,
            self.counters.next_risk_gate_index,
            self.config.risk_score_limit,
        )?;
        ensure(!gate.decision.is_blocking(), "risk gate blocked subject")?;
        ensure_absent(&self.risk_gates, "risk gate", &gate.gate_id)?;
        self.counters.next_risk_gate_index = self.counters.next_risk_gate_index.saturating_add(1);
        self.risk_gates.insert(gate.gate_id.clone(), gate.clone());
        self.insert_public_record(
            PublicRecordKind::RiskGate,
            gate.gate_id.clone(),
            gate.root(),
            gate.reviewer_commitment.clone(),
            gate.evaluated_at_height,
        )?;
        Ok(gate)
    }

    pub fn link_ticket_controls(
        &mut self,
        ticket_id: &str,
        covenant_check_id: &str,
        authorization_id: &str,
        risk_gate_id: &str,
    ) -> Result<()> {
        ensure_present(
            &self.covenant_checks,
            "token covenant check",
            covenant_check_id,
        )?;
        ensure_present(
            &self.pq_authorizations,
            "pq authorization",
            authorization_id,
        )?;
        ensure_present(&self.risk_gates, "risk gate", risk_gate_id)?;
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("bridge ticket not found: {ticket_id}"))?;
        ticket.covenant_check_id = covenant_check_id.to_string();
        ticket.authorization_id = authorization_id.to_string();
        ticket.risk_gate_id = risk_gate_id.to_string();
        Ok(())
    }

    pub fn submit_contract_callback(
        &mut self,
        request: ContractCallbackRequest,
    ) -> Result<ContractCallbackEnvelope> {
        let ticket = self
            .tickets
            .get(&request.ticket_id)
            .ok_or_else(|| format!("bridge ticket not found: {}", request.ticket_id))?;
        ensure(
            ticket.status.accepts_callback(),
            "bridge ticket status rejects callback",
        )?;
        ensure(
            !self.config.require_selective_disclosure
                || self.disclosures.contains_key(&request.disclosure_id),
            "required selective disclosure is missing",
        )?;
        let callback = ContractCallbackEnvelope::new(request, self.counters.next_callback_index)?;
        ensure_absent(&self.callbacks, "contract callback", &callback.callback_id)?;
        self.counters.next_callback_index = self.counters.next_callback_index.saturating_add(1);
        self.counters.total_fee_units = self
            .counters
            .total_fee_units
            .saturating_add(callback.fee_units as u128);
        self.callbacks
            .insert(callback.callback_id.clone(), callback.clone());
        if let Some(ticket) = self.tickets.get_mut(&callback.ticket_id) {
            ticket.status = TicketStatus::CallbackReady;
        }
        self.insert_public_record(
            PublicRecordKind::CallbackEnvelope,
            callback.callback_id.clone(),
            callback.root(),
            callback.contract_id.clone(),
            callback.submitted_at_height,
        )?;
        Ok(callback)
    }

    pub fn create_low_fee_settlement_batch(
        &mut self,
        request: LowFeeSettlementBatchRequest,
    ) -> Result<LowFeeSettlementBatch> {
        for ticket_id in &request.ticket_ids {
            ensure_present(&self.tickets, "bridge ticket", ticket_id)?;
        }
        for callback_id in &request.callback_ids {
            ensure_present(&self.callbacks, "contract callback", callback_id)?;
        }
        for check_id in &request.covenant_check_ids {
            ensure_present(&self.covenant_checks, "token covenant check", check_id)?;
        }
        let batch = LowFeeSettlementBatch::new(
            request,
            self.counters.next_batch_index,
            self.config.max_batch_items,
        )?;
        ensure_absent(
            &self.settlement_batches,
            "settlement batch",
            &batch.batch_id,
        )?;
        self.counters.next_batch_index = self.counters.next_batch_index.saturating_add(1);
        self.counters.total_fee_units = self
            .counters
            .total_fee_units
            .saturating_add(batch.aggregate_fee_units as u128);
        self.settlement_batches
            .insert(batch.batch_id.clone(), batch.clone());
        self.insert_public_record(
            PublicRecordKind::SettlementBatch,
            batch.batch_id.clone(),
            batch.root(),
            batch.operator_commitment.clone(),
            batch.settlement_height,
        )?;
        Ok(batch)
    }

    pub fn issue_preconfirmation(
        &mut self,
        request: PreconfirmationReceiptRequest,
    ) -> Result<PreconfirmationReceipt> {
        ensure_present(&self.tickets, "bridge ticket", &request.ticket_id)?;
        ensure_present(
            &self.settlement_batches,
            "settlement batch",
            &request.batch_id,
        )?;
        let receipt =
            PreconfirmationReceipt::new(request, self.counters.next_preconfirmation_index)?;
        ensure_absent(
            &self.preconfirmations,
            "preconfirmation",
            &receipt.receipt_id,
        )?;
        self.counters.next_preconfirmation_index =
            self.counters.next_preconfirmation_index.saturating_add(1);
        self.preconfirmations
            .insert(receipt.receipt_id.clone(), receipt.clone());
        if let Some(ticket) = self.tickets.get_mut(&receipt.ticket_id) {
            ticket.status = TicketStatus::Preconfirmed;
        }
        self.insert_public_record(
            PublicRecordKind::PreconfirmationReceipt,
            receipt.receipt_id.clone(),
            receipt.root(),
            receipt.sequencer_commitment.clone(),
            receipt.issued_at_height,
        )?;
        Ok(receipt)
    }

    pub fn mark_ticket_settled(&mut self, ticket_id: &str) -> Result<()> {
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("bridge ticket not found: {ticket_id}"))?;
        ticket.status = TicketStatus::Settled;
        self.counters.tickets_settled = self.counters.tickets_settled.saturating_add(1);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_bridge_contract_composability_gateway_runtime",
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let counters_root = self.counters.root();
        let ticket_root = collection_root(
            "BRIDGE-TICKETS",
            self.tickets.values(),
            BridgeTicket::public_record,
        );
        let callback_root = collection_root(
            "CONTRACT-CALLBACKS",
            self.callbacks.values(),
            ContractCallbackEnvelope::public_record,
        );
        let covenant_root = collection_root(
            "TOKEN-COVENANT-CHECKS",
            self.covenant_checks.values(),
            TokenCovenantCheck::public_record,
        );
        let authorization_root = collection_root(
            "PQ-AUTHORIZATIONS",
            self.pq_authorizations.values(),
            PqAuthorization::public_record,
        );
        let disclosure_root = collection_root(
            "SELECTIVE-DISCLOSURES",
            self.disclosures.values(),
            SelectiveDisclosure::public_record,
        );
        let settlement_batch_root = collection_root(
            "LOW-FEE-SETTLEMENT-BATCHES",
            self.settlement_batches.values(),
            LowFeeSettlementBatch::public_record,
        );
        let preconfirmation_root = collection_root(
            "PRECONFIRMATION-RECEIPTS",
            self.preconfirmations.values(),
            PreconfirmationReceipt::public_record,
        );
        let risk_gate_root = collection_root(
            "RISK-GATES",
            self.risk_gates.values(),
            RiskGate::public_record,
        );
        let public_record_root = collection_root(
            "GATEWAY-PUBLIC-RECORDS",
            self.public_records.values(),
            GatewayPublicRecord::public_record,
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-BRIDGE-CONTRACT-GATEWAY:STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config_root),
                HashPart::Str(&ticket_root),
                HashPart::Str(&callback_root),
                HashPart::Str(&covenant_root),
                HashPart::Str(&authorization_root),
                HashPart::Str(&disclosure_root),
                HashPart::Str(&settlement_batch_root),
                HashPart::Str(&preconfirmation_root),
                HashPart::Str(&risk_gate_root),
                HashPart::Str(&public_record_root),
                HashPart::Str(&counters_root),
            ],
            32,
        );
        Roots {
            config_root,
            ticket_root,
            callback_root,
            covenant_root,
            authorization_root,
            disclosure_root,
            settlement_batch_root,
            preconfirmation_root,
            risk_gate_root,
            public_record_root,
            counters_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn insert_public_record(
        &mut self,
        kind: PublicRecordKind,
        subject_id: String,
        payload_root: String,
        publisher_commitment: String,
        emitted_at_height: u64,
    ) -> Result<GatewayPublicRecord> {
        let sequence = self.counters.public_record_count.saturating_add(1);
        let record = GatewayPublicRecord::new(
            kind,
            subject_id,
            payload_root,
            publisher_commitment,
            emitted_at_height,
            sequence,
        )?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        self.counters.public_record_count = sequence;
        Ok(record)
    }
}

impl BridgeTicketRequest {
    pub fn devnet_deposit() -> Self {
        Self {
            direction: BridgeDirection::MoneroToL2,
            owner_commitment: "devnet-owner-commitment".to_string(),
            monero_txid_root: demo_root("monero-txid"),
            monero_output_root: demo_root("monero-output"),
            l2_account_commitment: "devnet-l2-account-commitment".to_string(),
            asset_id: DEVNET_WRAPPED_XMR_ASSET_ID.to_string(),
            amount_commitment: "devnet-amount-commitment".to_string(),
            amount_upper_bound_units: 2_500_000_000_000,
            fee_units: 1_000_000,
            contract_id: "devnet-private-vault-contract".to_string(),
            callback_selector: "on_private_bridge_deposit".to_string(),
            encrypted_call_root: demo_root("encrypted-call"),
            nonce: 1,
            opened_at_height: 1_552_000,
            expires_at_height: 1_552_288,
        }
    }
}

impl TokenCovenantCheckRequest {
    pub fn devnet_mint(ticket_id: &str, amount_upper_bound_units: u128) -> Self {
        Self {
            ticket_id: ticket_id.to_string(),
            action: TokenCovenantAction::Mint,
            asset_id: DEVNET_WRAPPED_XMR_ASSET_ID.to_string(),
            token_policy_root: demo_root("token-policy"),
            supply_delta_commitment: "devnet-supply-delta-commitment".to_string(),
            authority_commitment: "devnet-token-authority".to_string(),
            nullifier_root: demo_root("mint-nullifier"),
            amount_upper_bound_units,
            nonce: 2,
            checked_at_height: 1_552_001,
        }
    }
}

impl PqAuthorizationRequest {
    pub fn devnet(subject_id: &str, height: u64) -> Self {
        Self {
            subject_id: subject_id.to_string(),
            signer_commitment: "devnet-pq-committee-signer".to_string(),
            committee_root: demo_root("pq-committee"),
            transcript_root: demo_root("pq-transcript"),
            signature_root: demo_root("pq-signature"),
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            valid_from_height: height,
            expires_at_height: height.saturating_add(288),
            nonce: 3,
        }
    }
}

impl SelectiveDisclosureRequest {
    pub fn devnet(subject_id: &str, height: u64) -> Self {
        let mut disclosed_fields = BTreeSet::new();
        disclosed_fields.insert("asset_id".to_string());
        disclosed_fields.insert("amount_upper_bound_units".to_string());
        disclosed_fields.insert("contract_id".to_string());
        Self {
            subject_id: subject_id.to_string(),
            viewer_commitment: "devnet-contract-viewer".to_string(),
            disclosed_fields,
            disclosure_root: demo_root("selective-disclosure"),
            view_key_commitment: "devnet-view-key-commitment".to_string(),
            nullifier_scope_root: demo_root("disclosure-nullifier-scope"),
            opened_at_height: height,
            expires_at_height: height.saturating_add(DEFAULT_DISCLOSURE_TTL_BLOCKS),
            nonce: 4,
        }
    }
}

impl RiskGateRequest {
    pub fn devnet(subject_id: &str, limit_units: u128, height: u64) -> Self {
        Self {
            subject_id: subject_id.to_string(),
            reason_code: "devnet-bridge-contract-composability".to_string(),
            risk_score: 320,
            limit_units,
            exposure_root: demo_root("risk-exposure"),
            reviewer_commitment: "devnet-risk-reviewer".to_string(),
            evaluated_at_height: height,
            nonce: 5,
        }
    }
}

impl ContractCallbackRequest {
    pub fn devnet(ticket_id: &str, disclosure_id: &str, height: u64) -> Self {
        Self {
            ticket_id: ticket_id.to_string(),
            contract_id: "devnet-private-vault-contract".to_string(),
            callback_selector: "on_private_bridge_deposit".to_string(),
            encrypted_call_root: demo_root("callback-encrypted-call"),
            callback_state_root: demo_root("callback-state"),
            token_delta_root: demo_root("callback-token-delta"),
            disclosure_id: disclosure_id.to_string(),
            gas_limit: 1_000_000,
            fee_units: 250_000,
            nonce: 6,
            submitted_at_height: height,
        }
    }
}

impl LowFeeSettlementBatchRequest {
    pub fn devnet(ticket_id: &str, callback_id: &str, check_id: &str, height: u64) -> Self {
        let mut ticket_ids = BTreeSet::new();
        ticket_ids.insert(ticket_id.to_string());
        let mut callback_ids = BTreeSet::new();
        callback_ids.insert(callback_id.to_string());
        let mut covenant_check_ids = BTreeSet::new();
        covenant_check_ids.insert(check_id.to_string());
        Self {
            operator_commitment: "devnet-low-fee-batch-operator".to_string(),
            ticket_ids,
            callback_ids,
            covenant_check_ids,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            aggregate_fee_units: 300_000,
            settlement_height: height,
            nonce: 7,
        }
    }
}

impl PreconfirmationReceiptRequest {
    pub fn devnet(ticket_id: &str, batch_id: &str, height: u64) -> Self {
        Self {
            ticket_id: ticket_id.to_string(),
            batch_id: batch_id.to_string(),
            sequencer_commitment: "devnet-fast-sequencer".to_string(),
            preconfirm_root: demo_root("preconfirmation"),
            fee_quote_units: 300_000,
            issued_at_height: height,
            expires_at_height: height.saturating_add(DEFAULT_PRECONFIRMATION_TTL_BLOCKS),
            nonce: 8,
        }
    }
}

pub fn bridge_ticket_id(request: &BridgeTicketRequest, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-BRIDGE-CONTRACT-GATEWAY:BRIDGE-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.direction.as_str()),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.monero_txid_root),
            HashPart::Str(&request.l2_account_commitment),
            HashPart::Str(&request.asset_id),
            HashPart::Str(&request.contract_id),
            HashPart::Int(request.opened_at_height as i128),
            HashPart::Int(request.nonce as i128),
            HashPart::Int(index as i128),
        ],
        32,
    )
}

pub fn callback_envelope_id(request: &ContractCallbackRequest, index: u64) -> String {
    deterministic_id(
        "CALLBACK-ENVELOPE-ID",
        &request.ticket_id,
        &request.contract_id,
        &request.encrypted_call_root,
        request.submitted_at_height,
        request.nonce,
        index,
    )
}

pub fn token_covenant_check_id(request: &TokenCovenantCheckRequest, index: u64) -> String {
    deterministic_id(
        "TOKEN-COVENANT-CHECK-ID",
        &request.ticket_id,
        request.action.as_str(),
        &request.nullifier_root,
        request.checked_at_height,
        request.nonce,
        index,
    )
}

pub fn pq_authorization_id(request: &PqAuthorizationRequest, index: u64) -> String {
    deterministic_id(
        "PQ-AUTHORIZATION-ID",
        &request.subject_id,
        &request.signer_commitment,
        &request.signature_root,
        request.valid_from_height,
        request.nonce,
        index,
    )
}

pub fn selective_disclosure_id(request: &SelectiveDisclosureRequest, index: u64) -> String {
    deterministic_id(
        "SELECTIVE-DISCLOSURE-ID",
        &request.subject_id,
        &request.viewer_commitment,
        &request.disclosure_root,
        request.opened_at_height,
        request.nonce,
        index,
    )
}

pub fn settlement_batch_id(request: &LowFeeSettlementBatchRequest, index: u64) -> String {
    let ticket_root = set_root("BATCH-TICKET-IDS", &request.ticket_ids);
    deterministic_id(
        "LOW-FEE-SETTLEMENT-BATCH-ID",
        &request.operator_commitment,
        &ticket_root,
        &request.fee_asset_id,
        request.settlement_height,
        request.nonce,
        index,
    )
}

pub fn preconfirmation_receipt_id(request: &PreconfirmationReceiptRequest, index: u64) -> String {
    deterministic_id(
        "PRECONFIRMATION-RECEIPT-ID",
        &request.ticket_id,
        &request.batch_id,
        &request.preconfirm_root,
        request.issued_at_height,
        request.nonce,
        index,
    )
}

pub fn risk_gate_id(request: &RiskGateRequest, index: u64) -> String {
    deterministic_id(
        "RISK-GATE-ID",
        &request.subject_id,
        &request.reason_code,
        &request.exposure_root,
        request.evaluated_at_height,
        request.nonce,
        index,
    )
}

pub fn gateway_public_record_id(
    record_kind: PublicRecordKind,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-BRIDGE-CONTRACT-GATEWAY:PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-BRIDGE-CONTRACT-GATEWAY:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn public_record_root(records: &BTreeMap<String, GatewayPublicRecord>) -> String {
    collection_root(
        "GATEWAY-PUBLIC-RECORDS",
        records.values(),
        GatewayPublicRecord::public_record,
    )
}

fn validate_bridge_ticket_request(request: &BridgeTicketRequest) -> Result<()> {
    ensure_non_empty("bridge_ticket.owner_commitment", &request.owner_commitment)?;
    ensure_non_empty("bridge_ticket.monero_txid_root", &request.monero_txid_root)?;
    ensure_non_empty(
        "bridge_ticket.monero_output_root",
        &request.monero_output_root,
    )?;
    ensure_non_empty(
        "bridge_ticket.l2_account_commitment",
        &request.l2_account_commitment,
    )?;
    ensure_non_empty("bridge_ticket.asset_id", &request.asset_id)?;
    ensure_non_empty(
        "bridge_ticket.amount_commitment",
        &request.amount_commitment,
    )?;
    ensure_non_empty("bridge_ticket.contract_id", &request.contract_id)?;
    ensure_non_empty(
        "bridge_ticket.callback_selector",
        &request.callback_selector,
    )?;
    ensure_non_empty(
        "bridge_ticket.encrypted_call_root",
        &request.encrypted_call_root,
    )?;
    ensure(
        request.amount_upper_bound_units > 0,
        "bridge ticket amount must be positive",
    )?;
    ensure(
        request.expires_at_height > request.opened_at_height,
        "bridge ticket expiry must be after open height",
    )
}

fn validate_callback_request(request: &ContractCallbackRequest) -> Result<()> {
    ensure_non_empty("callback.ticket_id", &request.ticket_id)?;
    ensure_non_empty("callback.contract_id", &request.contract_id)?;
    ensure_non_empty("callback.callback_selector", &request.callback_selector)?;
    ensure_non_empty("callback.encrypted_call_root", &request.encrypted_call_root)?;
    ensure_non_empty("callback.callback_state_root", &request.callback_state_root)?;
    ensure_non_empty("callback.token_delta_root", &request.token_delta_root)?;
    ensure_non_empty("callback.disclosure_id", &request.disclosure_id)?;
    ensure(request.gas_limit > 0, "callback gas limit must be positive")
}

fn validate_covenant_request(request: &TokenCovenantCheckRequest) -> Result<()> {
    ensure_non_empty("covenant.ticket_id", &request.ticket_id)?;
    ensure_non_empty("covenant.asset_id", &request.asset_id)?;
    ensure_non_empty("covenant.token_policy_root", &request.token_policy_root)?;
    ensure_non_empty(
        "covenant.supply_delta_commitment",
        &request.supply_delta_commitment,
    )?;
    ensure_non_empty(
        "covenant.authority_commitment",
        &request.authority_commitment,
    )?;
    ensure_non_empty("covenant.nullifier_root", &request.nullifier_root)?;
    ensure(
        request.amount_upper_bound_units > 0,
        "covenant amount must be positive",
    )
}

fn validate_pq_authorization_request(
    request: &PqAuthorizationRequest,
    min_security_bits: u16,
) -> Result<()> {
    ensure_non_empty("pq_authorization.subject_id", &request.subject_id)?;
    ensure_non_empty(
        "pq_authorization.signer_commitment",
        &request.signer_commitment,
    )?;
    ensure_non_empty("pq_authorization.committee_root", &request.committee_root)?;
    ensure_non_empty("pq_authorization.transcript_root", &request.transcript_root)?;
    ensure_non_empty("pq_authorization.signature_root", &request.signature_root)?;
    ensure(
        request.security_bits >= min_security_bits,
        "pq authorization security bits below configured floor",
    )?;
    ensure(
        request.expires_at_height > request.valid_from_height,
        "pq authorization expiry must be after valid_from height",
    )
}

fn validate_disclosure_request(request: &SelectiveDisclosureRequest) -> Result<()> {
    ensure_non_empty("disclosure.subject_id", &request.subject_id)?;
    ensure_non_empty("disclosure.viewer_commitment", &request.viewer_commitment)?;
    ensure_non_empty("disclosure.disclosure_root", &request.disclosure_root)?;
    ensure_non_empty(
        "disclosure.view_key_commitment",
        &request.view_key_commitment,
    )?;
    ensure_non_empty(
        "disclosure.nullifier_scope_root",
        &request.nullifier_scope_root,
    )?;
    ensure(
        !request.disclosed_fields.is_empty(),
        "disclosure field set is empty",
    )?;
    ensure(
        request.expires_at_height > request.opened_at_height,
        "disclosure expiry must be after open height",
    )
}

fn validate_batch_request(request: &LowFeeSettlementBatchRequest, max_items: usize) -> Result<()> {
    ensure_non_empty(
        "settlement_batch.operator_commitment",
        &request.operator_commitment,
    )?;
    ensure_non_empty("settlement_batch.fee_asset_id", &request.fee_asset_id)?;
    ensure(
        !request.ticket_ids.is_empty(),
        "settlement batch ticket set is empty",
    )?;
    ensure(
        request.ticket_ids.len() <= max_items,
        "settlement batch exceeds configured item limit",
    )
}

fn validate_preconfirmation_request(request: &PreconfirmationReceiptRequest) -> Result<()> {
    ensure_non_empty("preconfirmation.ticket_id", &request.ticket_id)?;
    ensure_non_empty("preconfirmation.batch_id", &request.batch_id)?;
    ensure_non_empty(
        "preconfirmation.sequencer_commitment",
        &request.sequencer_commitment,
    )?;
    ensure_non_empty("preconfirmation.preconfirm_root", &request.preconfirm_root)?;
    ensure(
        request.expires_at_height > request.issued_at_height,
        "preconfirmation expiry must be after issue height",
    )
}

fn validate_risk_gate_request(request: &RiskGateRequest) -> Result<()> {
    ensure_non_empty("risk_gate.subject_id", &request.subject_id)?;
    ensure_non_empty("risk_gate.reason_code", &request.reason_code)?;
    ensure_non_empty("risk_gate.exposure_root", &request.exposure_root)?;
    ensure_non_empty(
        "risk_gate.reviewer_commitment",
        &request.reviewer_commitment,
    )?;
    ensure(request.risk_score <= 1_000, "risk score exceeds scale")?;
    ensure(request.limit_units > 0, "risk limit must be positive")
}

fn deterministic_id(
    domain: &str,
    first: &str,
    second: &str,
    third: &str,
    height: u64,
    nonce: u64,
    index: u64,
) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-BRIDGE-CONTRACT-GATEWAY:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(first),
            HashPart::Str(second),
            HashPart::Str(third),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Int(index as i128),
        ],
        32,
    )
}

fn collection_root<'a, T, I, F>(domain: &str, items: I, mut public_record: F) -> String
where
    I: Iterator<Item = &'a T>,
    F: FnMut(&T) -> Value,
    T: 'a,
{
    let leaves = items.map(|item| public_record(item)).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-BRIDGE-CONTRACT-GATEWAY:{domain}"),
        &leaves,
    )
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-BRIDGE-CONTRACT-GATEWAY:{domain}"),
        &leaves,
    )
}

fn stable_record<T: Serialize>(value: &T) -> Value {
    match serde_json::to_value(value) {
        Ok(record) => record,
        Err(error) => json!({
            "serialization_error": error.to_string(),
        }),
    }
}

fn demo_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-BRIDGE-CONTRACT-GATEWAY:DEMO-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn fee_limit_units(amount_units: u128, max_fee_bps: u64) -> u64 {
    let fee = amount_units.saturating_mul(max_fee_bps as u128) / 10_000;
    if fee > u64::MAX as u128 {
        u64::MAX
    } else {
        fee as u64
    }
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{field} must not be empty"),
    )
}

fn ensure_capacity(field: &str, value: usize) -> Result<()> {
    ensure(value > 0, &format!("{field} must be positive"))
}

fn ensure_absent<T>(map: &BTreeMap<String, T>, label: &str, key: &str) -> Result<()> {
    ensure(
        !map.contains_key(key),
        &format!("{label} already exists: {key}"),
    )
}

fn ensure_present<T>(map: &BTreeMap<String, T>, label: &str, key: &str) -> Result<()> {
    ensure(map.contains_key(key), &format!("{label} not found: {key}"))
}
