use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2MvpIntentGatewayResult<T> = Result<T, String>;

pub const PRIVATE_L2_MVP_INTENT_GATEWAY_PROTOCOL_VERSION: &str =
    "nebula-private-l2-mvp-intent-gateway-v1";
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_PRIVACY_PROOF_SYSTEM: &str =
    "zk-private-intent-envelope-v1";
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MAX_USER_FEE_BPS: u64 = 35;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PRIVACY_SET: u64 = 256;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MAX_LATENCY_BLOCKS: u64 = 2;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MAX_CALLDATA_BYTES: u64 = 16_384;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_REQUEST_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_REQUESTS: usize = 16_384;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_ROUTES: usize = 16_384;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_POLICIES: usize = 128;
pub const PRIVATE_L2_MVP_INTENT_GATEWAY_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentClass {
    PrivateTransfer,
    ConfidentialTokenMint,
    PrivateContractCall,
    PrivateDefiSwap,
    LiquidityProvision,
    ProofAggregation,
    FeeSponsoredExit,
    MoneroExit,
}

impl IntentClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialTokenMint => "confidential_token_mint",
            Self::PrivateContractCall => "private_contract_call",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::LiquidityProvision => "liquidity_provision",
            Self::ProofAggregation => "proof_aggregation",
            Self::FeeSponsoredExit => "fee_sponsored_exit",
            Self::MoneroExit => "monero_exit",
        }
    }

    pub fn requires_contract(self) -> bool {
        matches!(
            self,
            Self::PrivateContractCall
                | Self::PrivateDefiSwap
                | Self::LiquidityProvision
                | Self::ProofAggregation
        )
    }

    pub fn requires_monero_exit(self) -> bool {
        matches!(self, Self::FeeSponsoredExit | Self::MoneroExit)
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::PrivateTransfer => 8,
            Self::ConfidentialTokenMint => 18,
            Self::PrivateContractCall => 28,
            Self::PrivateDefiSwap => 32,
            Self::LiquidityProvision => 30,
            Self::ProofAggregation => 42,
            Self::FeeSponsoredExit => 36,
            Self::MoneroExit => 40,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Accepted,
    Routed,
    Deferred,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Routed => "routed",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLane {
    FastPrivateTransfer,
    PqContractExecution,
    PrivateDefiBatch,
    LowFeeProofMarket,
    MoneroFastExit,
    EmergencyExit,
}

impl RouteLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastPrivateTransfer => "fast_private_transfer",
            Self::PqContractExecution => "pq_contract_execution",
            Self::PrivateDefiBatch => "private_defi_batch",
            Self::LowFeeProofMarket => "low_fee_proof_market",
            Self::MoneroFastExit => "monero_fast_exit",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn for_intent(intent_class: IntentClass) -> Self {
        match intent_class {
            IntentClass::PrivateTransfer => Self::FastPrivateTransfer,
            IntentClass::ConfidentialTokenMint | IntentClass::PrivateContractCall => {
                Self::PqContractExecution
            }
            IntentClass::PrivateDefiSwap | IntentClass::LiquidityProvision => {
                Self::PrivateDefiBatch
            }
            IntentClass::ProofAggregation => Self::LowFeeProofMarket,
            IntentClass::FeeSponsoredExit | IntentClass::MoneroExit => Self::MoneroFastExit,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeePolicy {
    UserPaysLowCap,
    AppSponsor,
    ProofMarketRebate,
    BridgeSubsidy,
    EmergencyWaiver,
}

impl FeePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPaysLowCap => "user_pays_low_cap",
            Self::AppSponsor => "app_sponsor",
            Self::ProofMarketRebate => "proof_market_rebate",
            Self::BridgeSubsidy => "bridge_subsidy",
            Self::EmergencyWaiver => "emergency_waiver",
        }
    }

    pub fn sponsored(self) -> bool {
        !matches!(self, Self::UserPaysLowCap)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub privacy_proof_system: String,
    pub max_user_fee_bps: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
    pub max_latency_blocks: u64,
    pub max_calldata_bytes: u64,
    pub request_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_MVP_INTENT_GATEWAY_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            pq_signature_scheme: PRIVATE_L2_MVP_INTENT_GATEWAY_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_L2_MVP_INTENT_GATEWAY_PQ_KEM_SCHEME.to_string(),
            privacy_proof_system: PRIVATE_L2_MVP_INTENT_GATEWAY_PRIVACY_PROOF_SYSTEM.to_string(),
            max_user_fee_bps: PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set: PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_latency_blocks: PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MAX_LATENCY_BLOCKS,
            max_calldata_bytes: PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MAX_CALLDATA_BYTES,
            request_ttl_blocks: PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_REQUEST_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateL2MvpIntentGatewayResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.pq_signature_scheme.is_empty()
            || self.pq_kem_scheme.is_empty()
            || self.privacy_proof_system.is_empty()
        {
            return Err("private l2 intent gateway suite labels cannot be empty".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_BPS {
            return Err("private l2 intent gateway fee cap cannot exceed 100%".to_string());
        }
        if self.min_privacy_set == 0
            || self.min_pq_security_bits == 0
            || self.max_latency_blocks == 0
            || self.max_calldata_bytes == 0
            || self.request_ttl_blocks == 0
        {
            return Err("private l2 intent gateway thresholds must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_intent_gateway_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "privacy_proof_system": self.privacy_proof_system,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_latency_blocks": self.max_latency_blocks,
            "max_calldata_bytes": self.max_calldata_bytes,
            "request_ttl_blocks": self.request_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    pub policy_id: String,
    pub lane: RouteLane,
    pub label: String,
    pub max_fee_bps: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
    pub max_latency_blocks: u64,
    pub allowed_intents: BTreeSet<IntentClass>,
    pub fee_policy: FeePolicy,
    pub proof_market_root: String,
}

impl AdmissionPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: RouteLane,
        label: &str,
        max_fee_bps: u64,
        min_privacy_set: u64,
        min_pq_security_bits: u64,
        max_latency_blocks: u64,
        allowed_intents: BTreeSet<IntentClass>,
        fee_policy: FeePolicy,
        proof_market: &Value,
    ) -> PrivateL2MvpIntentGatewayResult<Self> {
        if label.is_empty() {
            return Err("private l2 intent gateway policy label cannot be empty".to_string());
        }
        if max_fee_bps > PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_BPS {
            return Err("private l2 intent gateway policy fee cannot exceed 100%".to_string());
        }
        if min_privacy_set == 0 || min_pq_security_bits == 0 || max_latency_blocks == 0 {
            return Err("private l2 intent gateway policy thresholds must be positive".to_string());
        }
        if allowed_intents.is_empty() {
            return Err(
                "private l2 intent gateway policy must allow at least one intent".to_string(),
            );
        }
        let proof_market_root =
            private_l2_mvp_intent_gateway_payload_root("POLICY-PROOF-MARKET", proof_market);
        let policy_id = admission_policy_id(
            lane,
            label,
            max_fee_bps,
            min_privacy_set,
            min_pq_security_bits,
            max_latency_blocks,
            &allowed_intents,
            fee_policy,
            &proof_market_root,
        );
        Ok(Self {
            policy_id,
            lane,
            label: label.to_string(),
            max_fee_bps,
            min_privacy_set,
            min_pq_security_bits,
            max_latency_blocks,
            allowed_intents,
            fee_policy,
            proof_market_root,
        })
    }

    pub fn accepts(&self, request: &PrivateIntentRequest) -> bool {
        self.allowed_intents.contains(&request.intent_class)
            && request.max_fee_bps <= self.max_fee_bps
            && request.privacy_set_size >= self.min_privacy_set
            && request.pq_security_bits >= self.min_pq_security_bits
            && request.target_latency_blocks <= self.max_latency_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_intent_gateway_admission_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_INTENT_GATEWAY_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "lane": self.lane.as_str(),
            "label": self.label,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_latency_blocks": self.max_latency_blocks,
            "allowed_intents": self.allowed_intents.iter().map(|intent| intent.as_str()).collect::<Vec<_>>(),
            "fee_policy": self.fee_policy.as_str(),
            "fee_sponsored": self.fee_policy.sponsored(),
            "proof_market_root": self.proof_market_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentRequest {
    pub request_id: String,
    pub intent_class: IntentClass,
    pub status: IntentStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub app_commitment: String,
    pub account_commitment: String,
    pub payload_root: String,
    pub calldata_root: String,
    pub nullifier_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub max_fee_bps: u64,
    pub target_latency_blocks: u64,
    pub calldata_bytes: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u64,
    pub required_capabilities: BTreeSet<String>,
    pub route_receipt_id: Option<String>,
}

impl PrivateIntentRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_class: IntentClass,
        opened_height: u64,
        ttl_blocks: u64,
        app_label: &str,
        account_label: &str,
        payload: &Value,
        calldata: &Value,
        nullifier: &Value,
        pq_authorization: &Value,
        privacy_proof: &Value,
        max_fee_bps: u64,
        target_latency_blocks: u64,
        calldata_bytes: u64,
        privacy_set_size: u64,
        pq_security_bits: u64,
        required_capabilities: BTreeSet<String>,
    ) -> PrivateL2MvpIntentGatewayResult<Self> {
        if app_label.is_empty() || account_label.is_empty() {
            return Err("private l2 intent gateway labels cannot be empty".to_string());
        }
        if ttl_blocks == 0
            || target_latency_blocks == 0
            || calldata_bytes == 0
            || privacy_set_size == 0
            || pq_security_bits == 0
        {
            return Err(
                "private l2 intent gateway request thresholds must be positive".to_string(),
            );
        }
        if max_fee_bps > PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_BPS {
            return Err("private l2 intent gateway request fee cannot exceed 100%".to_string());
        }
        let app_commitment = private_l2_mvp_intent_gateway_string_root("APP", app_label);
        let account_commitment =
            private_l2_mvp_intent_gateway_string_root("ACCOUNT", account_label);
        let payload_root = private_l2_mvp_intent_gateway_payload_root("PAYLOAD", payload);
        let calldata_root = private_l2_mvp_intent_gateway_payload_root("CALLDATA", calldata);
        let nullifier_root = private_l2_mvp_intent_gateway_payload_root("NULLIFIER", nullifier);
        let pq_authorization_root =
            private_l2_mvp_intent_gateway_payload_root("PQ-AUTHORIZATION", pq_authorization);
        let privacy_proof_root =
            private_l2_mvp_intent_gateway_payload_root("PRIVACY-PROOF", privacy_proof);
        let expires_height = opened_height.saturating_add(ttl_blocks);
        let request_id = private_intent_request_id(
            intent_class,
            opened_height,
            expires_height,
            &app_commitment,
            &account_commitment,
            &payload_root,
            &calldata_root,
            &nullifier_root,
            &pq_authorization_root,
            &privacy_proof_root,
        );
        Ok(Self {
            request_id,
            intent_class,
            status: IntentStatus::Submitted,
            opened_height,
            expires_height,
            app_commitment,
            account_commitment,
            payload_root,
            calldata_root,
            nullifier_root,
            pq_authorization_root,
            privacy_proof_root,
            max_fee_bps,
            target_latency_blocks,
            calldata_bytes,
            privacy_set_size,
            pq_security_bits,
            required_capabilities,
            route_receipt_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_intent_gateway_request",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_INTENT_GATEWAY_PROTOCOL_VERSION,
            "request_id": self.request_id,
            "intent_class": self.intent_class.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "app_commitment": self.app_commitment,
            "account_commitment": self.account_commitment,
            "payload_root": self.payload_root,
            "calldata_root": self.calldata_root,
            "nullifier_root": self.nullifier_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "max_fee_bps": self.max_fee_bps,
            "target_latency_blocks": self.target_latency_blocks,
            "calldata_bytes": self.calldata_bytes,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "required_capabilities": self.required_capabilities.iter().cloned().collect::<Vec<_>>(),
            "route_receipt_id": self.route_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub policy_id: String,
    pub lane: RouteLane,
    pub fee_policy: FeePolicy,
    pub height: u64,
    pub route_weight: u64,
    pub user_fee_bps: u64,
    pub sponsor_commitment: String,
    pub fast_lane_root: String,
    pub flow_root: String,
    pub receipt_book_root: String,
    pub settlement_hint_root: String,
}

impl RouteReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &PrivateIntentRequest,
        policy: &AdmissionPolicy,
        height: u64,
        sponsor_label: &str,
        fast_lane: &Value,
        flow: &Value,
        receipt_book: &Value,
        settlement_hint: &Value,
    ) -> PrivateL2MvpIntentGatewayResult<Self> {
        if sponsor_label.is_empty() {
            return Err("private l2 intent gateway sponsor label cannot be empty".to_string());
        }
        let sponsor_commitment =
            private_l2_mvp_intent_gateway_string_root("SPONSOR", sponsor_label);
        let fast_lane_root =
            private_l2_mvp_intent_gateway_payload_root("ROUTE-FAST-LANE", fast_lane);
        let flow_root = private_l2_mvp_intent_gateway_payload_root("ROUTE-FLOW", flow);
        let receipt_book_root =
            private_l2_mvp_intent_gateway_payload_root("ROUTE-RECEIPT-BOOK", receipt_book);
        let settlement_hint_root =
            private_l2_mvp_intent_gateway_payload_root("ROUTE-SETTLEMENT-HINT", settlement_hint);
        let user_fee_bps = request.max_fee_bps.min(policy.max_fee_bps);
        let route_weight = request
            .intent_class
            .default_weight()
            .saturating_add(request.calldata_bytes / 1_024)
            .saturating_add(request.required_capabilities.len() as u64);
        let receipt_id = route_receipt_id(
            &request.request_id,
            &policy.policy_id,
            policy.lane,
            policy.fee_policy,
            height,
            route_weight,
            user_fee_bps,
            &sponsor_commitment,
            &fast_lane_root,
            &flow_root,
            &receipt_book_root,
            &settlement_hint_root,
        );
        Ok(Self {
            receipt_id,
            request_id: request.request_id.clone(),
            policy_id: policy.policy_id.clone(),
            lane: policy.lane,
            fee_policy: policy.fee_policy,
            height,
            route_weight,
            user_fee_bps,
            sponsor_commitment,
            fast_lane_root,
            flow_root,
            receipt_book_root,
            settlement_hint_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_intent_gateway_route_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_INTENT_GATEWAY_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "policy_id": self.policy_id,
            "lane": self.lane.as_str(),
            "fee_policy": self.fee_policy.as_str(),
            "fee_sponsored": self.fee_policy.sponsored(),
            "height": self.height,
            "route_weight": self.route_weight,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_commitment": self.sponsor_commitment,
            "fast_lane_root": self.fast_lane_root,
            "flow_root": self.flow_root,
            "receipt_book_root": self.receipt_book_root,
            "settlement_hint_root": self.settlement_hint_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub policies: u64,
    pub submitted_requests: u64,
    pub accepted_requests: u64,
    pub routed_requests: u64,
    pub deferred_requests: u64,
    pub rejected_requests: u64,
    pub expired_requests: u64,
    pub sponsored_routes: u64,
    pub total_route_weight: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_intent_gateway_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_INTENT_GATEWAY_PROTOCOL_VERSION,
            "policies": self.policies,
            "submitted_requests": self.submitted_requests,
            "accepted_requests": self.accepted_requests,
            "routed_requests": self.routed_requests,
            "deferred_requests": self.deferred_requests,
            "rejected_requests": self.rejected_requests,
            "expired_requests": self.expired_requests,
            "sponsored_routes": self.sponsored_routes,
            "total_route_weight": self.total_route_weight,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub policy_root: String,
    pub request_root: String,
    pub route_receipt_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        Self {
            config_root: private_l2_mvp_intent_gateway_payload_root(
                "CONFIG",
                &config.public_record(),
            ),
            policy_root: merkle_root("PRIVATE-L2-MVP-INTENT-GATEWAY-POLICIES", &[]),
            request_root: merkle_root("PRIVATE-L2-MVP-INTENT-GATEWAY-REQUESTS", &[]),
            route_receipt_root: merkle_root("PRIVATE-L2-MVP-INTENT-GATEWAY-ROUTES", &[]),
            counter_root: private_l2_mvp_intent_gateway_payload_root(
                "COUNTERS",
                &Counters::default().public_record(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_intent_gateway_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_INTENT_GATEWAY_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "policy_root": self.policy_root,
            "request_root": self.request_root,
            "route_receipt_root": self.route_receipt_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub policies: BTreeMap<String, AdmissionPolicy>,
    pub requests: BTreeMap<String, PrivateIntentRequest>,
    pub route_receipts: BTreeMap<String, RouteReceipt>,
    pub counters: Counters,
    pub roots: Roots,
    pub state_root: String,
}

impl State {
    pub fn new(config: Config, height: u64) -> PrivateL2MvpIntentGatewayResult<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        let mut state = Self {
            config,
            height,
            policies: BTreeMap::new(),
            requests: BTreeMap::new(),
            route_receipts: BTreeMap::new(),
            counters: Counters::default(),
            roots,
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> PrivateL2MvpIntentGatewayResult<Self> {
        let mut state = Self::new(
            Config::devnet(),
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEVNET_HEIGHT,
        )?;
        for policy in devnet_policies()? {
            state.insert_policy(policy)?;
        }
        let request_id = state.submit_request(devnet_private_defi_request(
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEVNET_HEIGHT,
            &state.config,
        )?)?;
        state.route_request(
            &request_id,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEVNET_HEIGHT,
            "devnet-proof-market-sponsor",
            &json!({"lane": "pq_fast_lane_fee_market", "root": "devnet-fast-lane-root"}),
            &json!({"flow": "private_l2_mvp_flow_orchestrator", "root": "devnet-flow-root"}),
            &json!({"receipt_book": "private_l2_flow_receipt_book", "root": "devnet-receipt-root"}),
            &json!({"monero_exit": "devnet-settlement-hint"}),
        )?;
        Ok(state)
    }

    pub fn insert_policy(
        &mut self,
        policy: AdmissionPolicy,
    ) -> PrivateL2MvpIntentGatewayResult<String> {
        if self.policies.len() >= PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_POLICIES {
            return Err("private l2 intent gateway policy capacity exhausted".to_string());
        }
        let policy_id = policy.policy_id.clone();
        if self.policies.insert(policy_id.clone(), policy).is_some() {
            return Err("private l2 intent gateway policy already exists".to_string());
        }
        self.counters.policies = self.counters.policies.saturating_add(1);
        self.refresh();
        Ok(policy_id)
    }

    pub fn submit_request(
        &mut self,
        mut request: PrivateIntentRequest,
    ) -> PrivateL2MvpIntentGatewayResult<String> {
        if self.requests.len() >= PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_REQUESTS {
            return Err("private l2 intent gateway request capacity exhausted".to_string());
        }
        self.validate_request(&request)?;
        let accepted = self
            .policies
            .values()
            .any(|policy| policy.accepts(&request));
        request.status = if accepted {
            IntentStatus::Accepted
        } else {
            IntentStatus::Deferred
        };
        let request_id = request.request_id.clone();
        if self.requests.insert(request_id.clone(), request).is_some() {
            return Err("private l2 intent gateway request already exists".to_string());
        }
        self.counters.submitted_requests = self.counters.submitted_requests.saturating_add(1);
        if accepted {
            self.counters.accepted_requests = self.counters.accepted_requests.saturating_add(1);
        } else {
            self.counters.deferred_requests = self.counters.deferred_requests.saturating_add(1);
        }
        self.refresh();
        Ok(request_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn route_request(
        &mut self,
        request_id: &str,
        height: u64,
        sponsor_label: &str,
        fast_lane: &Value,
        flow: &Value,
        receipt_book: &Value,
        settlement_hint: &Value,
    ) -> PrivateL2MvpIntentGatewayResult<String> {
        if self.route_receipts.len() >= PRIVATE_L2_MVP_INTENT_GATEWAY_MAX_ROUTES {
            return Err("private l2 intent gateway route capacity exhausted".to_string());
        }
        self.height = height;
        let request = self
            .requests
            .get(request_id)
            .ok_or_else(|| "private l2 intent gateway request not found".to_string())?
            .clone();
        if request.status != IntentStatus::Accepted {
            return Err("private l2 intent gateway can only route accepted requests".to_string());
        }
        if request.expires_height < height {
            return Err("private l2 intent gateway request expired".to_string());
        }
        let policy = self
            .policies
            .values()
            .filter(|policy| policy.lane == RouteLane::for_intent(request.intent_class))
            .find(|policy| policy.accepts(&request))
            .cloned()
            .ok_or_else(|| "private l2 intent gateway found no route policy".to_string())?;
        let receipt = RouteReceipt::new(
            &request,
            &policy,
            height,
            sponsor_label,
            fast_lane,
            flow,
            receipt_book,
            settlement_hint,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        if self
            .route_receipts
            .insert(receipt_id.clone(), receipt.clone())
            .is_some()
        {
            return Err("private l2 intent gateway route receipt already exists".to_string());
        }
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| "private l2 intent gateway request not found".to_string())?;
        request.status = IntentStatus::Routed;
        request.route_receipt_id = Some(receipt_id.clone());
        self.counters.routed_requests = self.counters.routed_requests.saturating_add(1);
        if policy.fee_policy.sponsored() {
            self.counters.sponsored_routes = self.counters.sponsored_routes.saturating_add(1);
        }
        self.counters.total_route_weight = self
            .counters
            .total_route_weight
            .saturating_add(receipt.route_weight);
        self.refresh();
        Ok(receipt_id)
    }

    pub fn expire_height(&mut self, height: u64) {
        self.height = height;
        for request in self.requests.values_mut() {
            if !matches!(
                request.status,
                IntentStatus::Routed | IntentStatus::Rejected | IntentStatus::Expired
            ) && request.expires_height < height
            {
                request.status = IntentStatus::Expired;
                self.counters.expired_requests = self.counters.expired_requests.saturating_add(1);
            }
        }
        self.refresh();
    }

    pub fn refresh(&mut self) {
        let policy_records = self
            .policies
            .values()
            .map(AdmissionPolicy::public_record)
            .collect::<Vec<_>>();
        let request_records = self
            .requests
            .values()
            .map(PrivateIntentRequest::public_record)
            .collect::<Vec<_>>();
        let route_records = self
            .route_receipts
            .values()
            .map(RouteReceipt::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: private_l2_mvp_intent_gateway_payload_root(
                "CONFIG",
                &self.config.public_record(),
            ),
            policy_root: merkle_root("PRIVATE-L2-MVP-INTENT-GATEWAY-POLICIES", &policy_records),
            request_root: merkle_root("PRIVATE-L2-MVP-INTENT-GATEWAY-REQUESTS", &request_records),
            route_receipt_root: merkle_root("PRIVATE-L2-MVP-INTENT-GATEWAY-ROUTES", &route_records),
            counter_root: private_l2_mvp_intent_gateway_payload_root(
                "COUNTERS",
                &self.counters.public_record(),
            ),
        };
        self.state_root =
            private_l2_mvp_intent_gateway_payload_root("STATE", &self.public_record_without_root());
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_intent_gateway_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_INTENT_GATEWAY_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root));
            object.insert(
                "policies".to_string(),
                json!(self
                    .policies
                    .values()
                    .map(AdmissionPolicy::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "requests".to_string(),
                json!(self
                    .requests
                    .values()
                    .map(PrivateIntentRequest::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "route_receipts".to_string(),
                json!(self
                    .route_receipts
                    .values()
                    .map(RouteReceipt::public_record)
                    .collect::<Vec<_>>()),
            );
        }
        record
    }

    fn validate_request(
        &mut self,
        request: &PrivateIntentRequest,
    ) -> PrivateL2MvpIntentGatewayResult<()> {
        if request.opened_height > request.expires_height {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 intent gateway request expires before it opens".to_string());
        }
        if request.expires_height.saturating_sub(request.opened_height)
            > self.config.request_ttl_blocks
        {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 intent gateway request ttl exceeds config".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 intent gateway request exceeds low-fee cap".to_string());
        }
        if request.target_latency_blocks > self.config.max_latency_blocks {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 intent gateway request exceeds latency cap".to_string());
        }
        if request.calldata_bytes > self.config.max_calldata_bytes {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 intent gateway request exceeds calldata cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 intent gateway request privacy set too small".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 intent gateway request pq security too small".to_string());
        }
        Ok(())
    }
}

pub fn devnet_policies() -> PrivateL2MvpIntentGatewayResult<Vec<AdmissionPolicy>> {
    Ok(vec![
        AdmissionPolicy::new(
            RouteLane::FastPrivateTransfer,
            "devnet-fast-private-transfer",
            25,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PRIVACY_SET,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS,
            1,
            [IntentClass::PrivateTransfer].into_iter().collect(),
            FeePolicy::UserPaysLowCap,
            &json!({"market": "low_fee_private_transfer"}),
        )?,
        AdmissionPolicy::new(
            RouteLane::PqContractExecution,
            "devnet-pq-contract-execution",
            30,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PRIVACY_SET,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS,
            2,
            [
                IntentClass::ConfidentialTokenMint,
                IntentClass::PrivateContractCall,
            ]
            .into_iter()
            .collect(),
            FeePolicy::AppSponsor,
            &json!({"market": "private_contract_fee_sponsor"}),
        )?,
        AdmissionPolicy::new(
            RouteLane::PrivateDefiBatch,
            "devnet-private-defi-batch",
            35,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PRIVACY_SET,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS,
            2,
            [
                IntentClass::PrivateDefiSwap,
                IntentClass::LiquidityProvision,
            ]
            .into_iter()
            .collect(),
            FeePolicy::ProofMarketRebate,
            &json!({"market": "low_fee_proof_batch_sponsor"}),
        )?,
        AdmissionPolicy::new(
            RouteLane::LowFeeProofMarket,
            "devnet-low-fee-proof-market",
            25,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PRIVACY_SET,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS,
            2,
            [IntentClass::ProofAggregation].into_iter().collect(),
            FeePolicy::ProofMarketRebate,
            &json!({"market": "recursive_pq_proof_market"}),
        )?,
        AdmissionPolicy::new(
            RouteLane::MoneroFastExit,
            "devnet-monero-fast-exit",
            35,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PRIVACY_SET,
            PRIVATE_L2_MVP_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS,
            2,
            [IntentClass::FeeSponsoredExit, IntentClass::MoneroExit]
                .into_iter()
                .collect(),
            FeePolicy::BridgeSubsidy,
            &json!({"market": "monero_pq_fast_exit_settlement_router"}),
        )?,
    ])
}

pub fn devnet_private_defi_request(
    height: u64,
    config: &Config,
) -> PrivateL2MvpIntentGatewayResult<PrivateIntentRequest> {
    PrivateIntentRequest::new(
        IntentClass::PrivateDefiSwap,
        height,
        config.request_ttl_blocks,
        "devnet-private-defi-app",
        "devnet-private-user",
        &json!({
            "action": "mint_contract_swap_exit",
            "asset": "confidential_wrapped_xmr",
            "route": "private_stable_swap",
        }),
        &json!({
            "selector": "swap_exact_private",
            "arguments_root": "devnet-private-arguments-root",
            "state_access": "shielded",
        }),
        &json!({
            "entry_nullifier": format!("devnet-private-defi-nullifier-{height}"),
        }),
        &json!({
            "scheme": PRIVATE_L2_MVP_INTENT_GATEWAY_PQ_SIGNATURE_SCHEME,
            "security_bits": config.min_pq_security_bits,
            "height": height,
        }),
        &json!({
            "proof_system": config.privacy_proof_system,
            "privacy_set_size": config.min_privacy_set.saturating_mul(2),
        }),
        config.max_user_fee_bps.min(20),
        config.max_latency_blocks,
        2_048,
        config.min_privacy_set.saturating_mul(2),
        config.min_pq_security_bits,
        [
            "confidential_token".to_string(),
            "private_contract".to_string(),
            "private_amm".to_string(),
            "low_fee_proof".to_string(),
            "monero_exit".to_string(),
        ]
        .into_iter()
        .collect(),
    )
}

pub fn private_l2_mvp_intent_gateway_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-MVP-INTENT-GATEWAY-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_l2_mvp_intent_gateway_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-MVP-INTENT-GATEWAY-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn admission_policy_id(
    lane: RouteLane,
    label: &str,
    max_fee_bps: u64,
    min_privacy_set: u64,
    min_pq_security_bits: u64,
    max_latency_blocks: u64,
    allowed_intents: &BTreeSet<IntentClass>,
    fee_policy: FeePolicy,
    proof_market_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-INTENT-GATEWAY-POLICY-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(label),
            HashPart::Int(max_fee_bps as i128),
            HashPart::Int(min_privacy_set as i128),
            HashPart::Int(min_pq_security_bits as i128),
            HashPart::Int(max_latency_blocks as i128),
            HashPart::Json(&json!(allowed_intents
                .iter()
                .map(|intent| intent.as_str())
                .collect::<Vec<_>>())),
            HashPart::Str(fee_policy.as_str()),
            HashPart::Str(proof_market_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_intent_request_id(
    intent_class: IntentClass,
    opened_height: u64,
    expires_height: u64,
    app_commitment: &str,
    account_commitment: &str,
    payload_root: &str,
    calldata_root: &str,
    nullifier_root: &str,
    pq_authorization_root: &str,
    privacy_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-INTENT-GATEWAY-REQUEST-ID",
        &[
            HashPart::Str(intent_class.as_str()),
            HashPart::Int(opened_height as i128),
            HashPart::Int(expires_height as i128),
            HashPart::Str(app_commitment),
            HashPart::Str(account_commitment),
            HashPart::Str(payload_root),
            HashPart::Str(calldata_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(privacy_proof_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn route_receipt_id(
    request_id: &str,
    policy_id: &str,
    lane: RouteLane,
    fee_policy: FeePolicy,
    height: u64,
    route_weight: u64,
    user_fee_bps: u64,
    sponsor_commitment: &str,
    fast_lane_root: &str,
    flow_root: &str,
    receipt_book_root: &str,
    settlement_hint_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-INTENT-GATEWAY-ROUTE-ID",
        &[
            HashPart::Str(request_id),
            HashPart::Str(policy_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(fee_policy.as_str()),
            HashPart::Int(height as i128),
            HashPart::Int(route_weight as i128),
            HashPart::Int(user_fee_bps as i128),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fast_lane_root),
            HashPart::Str(flow_root),
            HashPart::Str(receipt_book_root),
            HashPart::Str(settlement_hint_root),
        ],
        32,
    )
}

pub fn root_from_record(record: &Value) -> String {
    private_l2_mvp_intent_gateway_payload_root("RECORD", record)
}

pub fn devnet() -> PrivateL2MvpIntentGatewayResult<State> {
    State::devnet()
}
