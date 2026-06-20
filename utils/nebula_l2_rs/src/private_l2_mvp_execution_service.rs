use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2MvpExecutionServiceResult<T> = Result<T, String>;

pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_PROTOCOL_VERSION: &str =
    "nebula-private-l2-mvp-execution-service-v1";
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_PROOF_SYSTEM: &str =
    "recursive-private-l2-mvp-execution-v1";
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MAX_USER_FEE_BPS: u64 = 35;
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MIN_PRIVACY_SET: u64 = 256;
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MAX_LATENCY_BLOCKS: u64 = 2;
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_MAX_REQUESTS: usize = 16_384;
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_MAX_RECEIPTS: usize = 16_384;
pub const PRIVATE_L2_MVP_EXECUTION_SERVICE_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionServiceClass {
    PrivateTransfer,
    TokenMint,
    ContractCall,
    DefiSwap,
    ProofAggregation,
    MoneroExit,
    FullMvpFlow,
}

impl ExecutionServiceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::TokenMint => "token_mint",
            Self::ContractCall => "contract_call",
            Self::DefiSwap => "defi_swap",
            Self::ProofAggregation => "proof_aggregation",
            Self::MoneroExit => "monero_exit",
            Self::FullMvpFlow => "full_mvp_flow",
        }
    }

    pub fn required_capabilities(self) -> BTreeSet<&'static str> {
        match self {
            Self::PrivateTransfer => ["privacy_pool", "pq_authorization"].into_iter().collect(),
            Self::TokenMint => ["token_registry", "contract_runtime", "pq_authorization"]
                .into_iter()
                .collect(),
            Self::ContractCall => ["contract_runtime", "abi_registry", "pq_authorization"]
                .into_iter()
                .collect(),
            Self::DefiSwap => ["private_amm", "contract_runtime", "low_fee_proofs"]
                .into_iter()
                .collect(),
            Self::ProofAggregation => ["recursive_proofs", "low_fee_sponsor"]
                .into_iter()
                .collect(),
            Self::MoneroExit => ["monero_finality", "exit_liquidity", "pq_authorization"]
                .into_iter()
                .collect(),
            Self::FullMvpFlow => [
                "intent_gateway",
                "abi_registry",
                "private_contract",
                "private_amm",
                "recursive_proofs",
                "monero_finality",
                "receipt_book",
                "low_fee_sponsor",
            ]
            .into_iter()
            .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionServiceStatus {
    Submitted,
    Admitted,
    Executing,
    Settling,
    Settled,
    Rejected,
    Expired,
}

impl ExecutionServiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Admitted => "admitted",
            Self::Executing => "executing",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBindingKind {
    DevnetOnly,
    FastExitCertificate,
    MoneroAnchor,
    EmergencyExit,
}

impl SettlementBindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DevnetOnly => "devnet_only",
            Self::FastExitCertificate => "fast_exit_certificate",
            Self::MoneroAnchor => "monero_anchor",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub proof_system: String,
    pub max_user_fee_bps: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
    pub max_latency_blocks: u64,
    pub settlement_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_MVP_EXECUTION_SERVICE_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            pq_signature_scheme: PRIVATE_L2_MVP_EXECUTION_SERVICE_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_L2_MVP_EXECUTION_SERVICE_PQ_KEM_SCHEME.to_string(),
            proof_system: PRIVATE_L2_MVP_EXECUTION_SERVICE_PROOF_SYSTEM.to_string(),
            max_user_fee_bps: PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set: PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_latency_blocks: PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MAX_LATENCY_BLOCKS,
            settlement_ttl_blocks: PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_SETTLEMENT_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateL2MvpExecutionServiceResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.pq_signature_scheme.is_empty()
            || self.pq_kem_scheme.is_empty()
            || self.proof_system.is_empty()
        {
            return Err("private l2 execution service suite labels cannot be empty".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_MVP_EXECUTION_SERVICE_MAX_BPS {
            return Err("private l2 execution service fee cap cannot exceed 100%".to_string());
        }
        if self.min_privacy_set == 0
            || self.min_pq_security_bits == 0
            || self.max_latency_blocks == 0
            || self.settlement_ttl_blocks == 0
        {
            return Err("private l2 execution service thresholds must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_execution_service_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "proof_system": self.proof_system,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_latency_blocks": self.max_latency_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub request_id: String,
    pub service_class: ExecutionServiceClass,
    pub status: ExecutionServiceStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub gateway_route_root: String,
    pub account_commitment: String,
    pub app_commitment: String,
    pub payload_root: String,
    pub abi_registry_root: String,
    pub fast_lane_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub max_fee_bps: u64,
    pub target_latency_blocks: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u64,
    pub required_capability_root: String,
    pub receipt_id: Option<String>,
}

impl ExecutionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service_class: ExecutionServiceClass,
        opened_height: u64,
        ttl_blocks: u64,
        gateway_route: &Value,
        account_label: &str,
        app_label: &str,
        payload: &Value,
        abi_registry: &Value,
        fast_lane: &Value,
        pq_authorization: &Value,
        privacy_proof: &Value,
        max_fee_bps: u64,
        target_latency_blocks: u64,
        privacy_set_size: u64,
        pq_security_bits: u64,
    ) -> PrivateL2MvpExecutionServiceResult<Self> {
        if ttl_blocks == 0 {
            return Err("private l2 execution service ttl must be positive".to_string());
        }
        if account_label.is_empty() || app_label.is_empty() {
            return Err("private l2 execution service labels cannot be empty".to_string());
        }
        if max_fee_bps > PRIVATE_L2_MVP_EXECUTION_SERVICE_MAX_BPS {
            return Err("private l2 execution service fee cannot exceed 100%".to_string());
        }
        if target_latency_blocks == 0 || privacy_set_size == 0 || pq_security_bits == 0 {
            return Err(
                "private l2 execution service request thresholds must be positive".to_string(),
            );
        }
        let gateway_route_root =
            private_l2_mvp_execution_service_payload_root("GATEWAY-ROUTE", gateway_route);
        let account_commitment =
            private_l2_mvp_execution_service_string_root("ACCOUNT", account_label);
        let app_commitment = private_l2_mvp_execution_service_string_root("APP", app_label);
        let payload_root = private_l2_mvp_execution_service_payload_root("PAYLOAD", payload);
        let abi_registry_root =
            private_l2_mvp_execution_service_payload_root("ABI-REGISTRY", abi_registry);
        let fast_lane_root = private_l2_mvp_execution_service_payload_root("FAST-LANE", fast_lane);
        let pq_authorization_root =
            private_l2_mvp_execution_service_payload_root("PQ-AUTH", pq_authorization);
        let privacy_proof_root =
            private_l2_mvp_execution_service_payload_root("PRIVACY-PROOF", privacy_proof);
        let capabilities = service_class
            .required_capabilities()
            .into_iter()
            .map(|capability| Value::String(capability.to_string()))
            .collect::<Vec<_>>();
        let required_capability_root = merkle_root(
            "PRIVATE-L2-MVP-EXECUTION-SERVICE-CAPABILITIES",
            &capabilities,
        );
        let expires_height = opened_height.saturating_add(ttl_blocks);
        let request_id = execution_request_id(
            service_class,
            opened_height,
            expires_height,
            &gateway_route_root,
            &account_commitment,
            &app_commitment,
            &payload_root,
            &abi_registry_root,
            &fast_lane_root,
            &pq_authorization_root,
            &privacy_proof_root,
        );
        Ok(Self {
            request_id,
            service_class,
            status: ExecutionServiceStatus::Submitted,
            opened_height,
            expires_height,
            gateway_route_root,
            account_commitment,
            app_commitment,
            payload_root,
            abi_registry_root,
            fast_lane_root,
            pq_authorization_root,
            privacy_proof_root,
            max_fee_bps,
            target_latency_blocks,
            privacy_set_size,
            pq_security_bits,
            required_capability_root,
            receipt_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_execution_service_request",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_EXECUTION_SERVICE_PROTOCOL_VERSION,
            "request_id": self.request_id,
            "service_class": self.service_class.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "gateway_route_root": self.gateway_route_root,
            "account_commitment": self.account_commitment,
            "app_commitment": self.app_commitment,
            "payload_root": self.payload_root,
            "abi_registry_root": self.abi_registry_root,
            "fast_lane_root": self.fast_lane_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "max_fee_bps": self.max_fee_bps,
            "target_latency_blocks": self.target_latency_blocks,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "required_capability_root": self.required_capability_root,
            "receipt_id": self.receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub height: u64,
    pub status: ExecutionServiceStatus,
    pub execution_root: String,
    pub token_delta_root: String,
    pub contract_delta_root: String,
    pub amm_delta_root: String,
    pub proof_aggregate_root: String,
    pub fee_sponsor_root: String,
    pub monero_exit_root: String,
    pub receipt_book_root: String,
    pub finality_certificate_root: String,
    pub abi_registry_root: String,
    pub user_fee_bps: u64,
    pub latency_blocks: u64,
}

impl ExecutionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &ExecutionRequest,
        height: u64,
        execution_payload: &Value,
        token_delta: &Value,
        contract_delta: &Value,
        amm_delta: &Value,
        proof_aggregate: &Value,
        fee_sponsor: &Value,
        monero_exit: &Value,
        receipt_book: &Value,
        finality_certificate: &Value,
        abi_registry: &Value,
        user_fee_bps: u64,
        latency_blocks: u64,
    ) -> PrivateL2MvpExecutionServiceResult<Self> {
        if user_fee_bps > PRIVATE_L2_MVP_EXECUTION_SERVICE_MAX_BPS {
            return Err("private l2 execution service receipt fee cannot exceed 100%".to_string());
        }
        if latency_blocks == 0 {
            return Err(
                "private l2 execution service receipt latency must be positive".to_string(),
            );
        }
        let execution_root =
            private_l2_mvp_execution_service_payload_root("EXECUTION", execution_payload);
        let token_delta_root =
            private_l2_mvp_execution_service_payload_root("TOKEN-DELTA", token_delta);
        let contract_delta_root =
            private_l2_mvp_execution_service_payload_root("CONTRACT-DELTA", contract_delta);
        let amm_delta_root = private_l2_mvp_execution_service_payload_root("AMM-DELTA", amm_delta);
        let proof_aggregate_root =
            private_l2_mvp_execution_service_payload_root("PROOF-AGGREGATE", proof_aggregate);
        let fee_sponsor_root =
            private_l2_mvp_execution_service_payload_root("FEE-SPONSOR", fee_sponsor);
        let monero_exit_root =
            private_l2_mvp_execution_service_payload_root("MONERO-EXIT", monero_exit);
        let receipt_book_root =
            private_l2_mvp_execution_service_payload_root("RECEIPT-BOOK", receipt_book);
        let finality_certificate_root = private_l2_mvp_execution_service_payload_root(
            "FINALITY-CERTIFICATE",
            finality_certificate,
        );
        let abi_registry_root =
            private_l2_mvp_execution_service_payload_root("ABI-REGISTRY-RECEIPT", abi_registry);
        let receipt_id = execution_receipt_id(
            &request.request_id,
            height,
            &execution_root,
            &token_delta_root,
            &contract_delta_root,
            &amm_delta_root,
            &proof_aggregate_root,
            &fee_sponsor_root,
            &monero_exit_root,
            &receipt_book_root,
            &finality_certificate_root,
            &abi_registry_root,
        );
        Ok(Self {
            receipt_id,
            request_id: request.request_id.clone(),
            height,
            status: ExecutionServiceStatus::Settled,
            execution_root,
            token_delta_root,
            contract_delta_root,
            amm_delta_root,
            proof_aggregate_root,
            fee_sponsor_root,
            monero_exit_root,
            receipt_book_root,
            finality_certificate_root,
            abi_registry_root,
            user_fee_bps,
            latency_blocks,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_execution_service_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_EXECUTION_SERVICE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "height": self.height,
            "status": self.status.as_str(),
            "execution_root": self.execution_root,
            "token_delta_root": self.token_delta_root,
            "contract_delta_root": self.contract_delta_root,
            "amm_delta_root": self.amm_delta_root,
            "proof_aggregate_root": self.proof_aggregate_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "monero_exit_root": self.monero_exit_root,
            "receipt_book_root": self.receipt_book_root,
            "finality_certificate_root": self.finality_certificate_root,
            "abi_registry_root": self.abi_registry_root,
            "user_fee_bps": self.user_fee_bps,
            "latency_blocks": self.latency_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBinding {
    pub binding_id: String,
    pub receipt_id: String,
    pub binding_kind: SettlementBindingKind,
    pub height: u64,
    pub settlement_root: String,
    pub da_root: String,
    pub nullifier_root: String,
    pub expires_height: u64,
}

impl SettlementBinding {
    pub fn new(
        receipt_id: &str,
        binding_kind: SettlementBindingKind,
        height: u64,
        settlement: &Value,
        da: &Value,
        nullifier: &Value,
        expires_height: u64,
    ) -> PrivateL2MvpExecutionServiceResult<Self> {
        if receipt_id.is_empty() {
            return Err("private l2 execution service receipt id cannot be empty".to_string());
        }
        if expires_height < height {
            return Err(
                "private l2 execution service binding expiry cannot precede height".to_string(),
            );
        }
        let settlement_root =
            private_l2_mvp_execution_service_payload_root("SETTLEMENT", settlement);
        let da_root = private_l2_mvp_execution_service_payload_root("DA", da);
        let nullifier_root = private_l2_mvp_execution_service_payload_root("NULLIFIER", nullifier);
        let binding_id = settlement_binding_id(
            receipt_id,
            binding_kind,
            height,
            &settlement_root,
            &da_root,
            &nullifier_root,
            expires_height,
        );
        Ok(Self {
            binding_id,
            receipt_id: receipt_id.to_string(),
            binding_kind,
            height,
            settlement_root,
            da_root,
            nullifier_root,
            expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_execution_service_settlement_binding",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_EXECUTION_SERVICE_PROTOCOL_VERSION,
            "binding_id": self.binding_id,
            "receipt_id": self.receipt_id,
            "binding_kind": self.binding_kind.as_str(),
            "height": self.height,
            "settlement_root": self.settlement_root,
            "da_root": self.da_root,
            "nullifier_root": self.nullifier_root,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub submitted_requests: u64,
    pub admitted_requests: u64,
    pub executed_receipts: u64,
    pub settlement_bindings: u64,
    pub rejected_requests: u64,
    pub expired_requests: u64,
    pub total_user_fee_bps: u64,
    pub total_latency_blocks: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_execution_service_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_EXECUTION_SERVICE_PROTOCOL_VERSION,
            "submitted_requests": self.submitted_requests,
            "admitted_requests": self.admitted_requests,
            "executed_receipts": self.executed_receipts,
            "settlement_bindings": self.settlement_bindings,
            "rejected_requests": self.rejected_requests,
            "expired_requests": self.expired_requests,
            "total_user_fee_bps": self.total_user_fee_bps,
            "total_latency_blocks": self.total_latency_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub request_root: String,
    pub receipt_root: String,
    pub settlement_binding_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        Self {
            config_root: private_l2_mvp_execution_service_payload_root(
                "CONFIG",
                &config.public_record(),
            ),
            request_root: merkle_root("PRIVATE-L2-MVP-EXECUTION-SERVICE-REQUESTS", &[]),
            receipt_root: merkle_root("PRIVATE-L2-MVP-EXECUTION-SERVICE-RECEIPTS", &[]),
            settlement_binding_root: merkle_root(
                "PRIVATE-L2-MVP-EXECUTION-SERVICE-SETTLEMENT-BINDINGS",
                &[],
            ),
            counter_root: private_l2_mvp_execution_service_payload_root(
                "COUNTERS",
                &Counters::default().public_record(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_execution_service_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_EXECUTION_SERVICE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "request_root": self.request_root,
            "receipt_root": self.receipt_root,
            "settlement_binding_root": self.settlement_binding_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub requests: BTreeMap<String, ExecutionRequest>,
    pub receipts: BTreeMap<String, ExecutionReceipt>,
    pub settlement_bindings: BTreeMap<String, SettlementBinding>,
    pub counters: Counters,
    pub roots: Roots,
    pub state_root: String,
}

impl State {
    pub fn new(config: Config, height: u64) -> PrivateL2MvpExecutionServiceResult<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        let mut state = Self {
            config,
            height,
            requests: BTreeMap::new(),
            receipts: BTreeMap::new(),
            settlement_bindings: BTreeMap::new(),
            counters: Counters::default(),
            roots,
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> PrivateL2MvpExecutionServiceResult<Self> {
        let mut state = Self::new(
            Config::devnet(),
            PRIVATE_L2_MVP_EXECUTION_SERVICE_DEVNET_HEIGHT,
        )?;
        let request = devnet_execution_request(PRIVATE_L2_MVP_EXECUTION_SERVICE_DEVNET_HEIGHT)?;
        let request_id = state.submit_request(request)?;
        let receipt_id = state.execute_request(
            &request_id,
            PRIVATE_L2_MVP_EXECUTION_SERVICE_DEVNET_HEIGHT,
            &json!({"execution": "devnet-full-mvp-flow"}),
            &json!({"token_delta": "devnet-token-root"}),
            &json!({"contract_delta": "devnet-contract-root"}),
            &json!({"amm_delta": "devnet-amm-root"}),
            &json!({"proof_aggregate": "devnet-proof-root"}),
            &json!({"fee_sponsor": "devnet-sponsor-root"}),
            &json!({"monero_exit": "devnet-exit-root"}),
            &json!({"receipt_book": "devnet-receipt-book-root"}),
            &json!({"finality_certificate": "devnet-finality-root"}),
            &json!({"abi_registry": "devnet-abi-root"}),
        )?;
        state.bind_settlement(
            &receipt_id,
            SettlementBindingKind::DevnetOnly,
            PRIVATE_L2_MVP_EXECUTION_SERVICE_DEVNET_HEIGHT,
            &json!({"settlement": "devnet"}),
            &json!({"da": "devnet"}),
            &json!({"nullifier": "devnet"}),
        )?;
        Ok(state)
    }

    pub fn submit_request(
        &mut self,
        mut request: ExecutionRequest,
    ) -> PrivateL2MvpExecutionServiceResult<String> {
        if self.requests.len() >= PRIVATE_L2_MVP_EXECUTION_SERVICE_MAX_REQUESTS {
            return Err("private l2 execution service request capacity exhausted".to_string());
        }
        self.validate_request(&request)?;
        request.status = ExecutionServiceStatus::Admitted;
        let request_id = request.request_id.clone();
        if self.requests.insert(request_id.clone(), request).is_some() {
            return Err("private l2 execution service request already exists".to_string());
        }
        self.counters.submitted_requests = self.counters.submitted_requests.saturating_add(1);
        self.counters.admitted_requests = self.counters.admitted_requests.saturating_add(1);
        self.refresh();
        Ok(request_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_request(
        &mut self,
        request_id: &str,
        height: u64,
        execution_payload: &Value,
        token_delta: &Value,
        contract_delta: &Value,
        amm_delta: &Value,
        proof_aggregate: &Value,
        fee_sponsor: &Value,
        monero_exit: &Value,
        receipt_book: &Value,
        finality_certificate: &Value,
        abi_registry: &Value,
    ) -> PrivateL2MvpExecutionServiceResult<String> {
        if self.receipts.len() >= PRIVATE_L2_MVP_EXECUTION_SERVICE_MAX_RECEIPTS {
            return Err("private l2 execution service receipt capacity exhausted".to_string());
        }
        self.height = height;
        let request = self
            .requests
            .get(request_id)
            .ok_or_else(|| "private l2 execution service request not found".to_string())?
            .clone();
        if request.status.terminal() {
            return Err("private l2 execution service terminal request cannot execute".to_string());
        }
        if request.expires_height < height {
            return Err("private l2 execution service request expired".to_string());
        }
        let receipt = ExecutionReceipt::new(
            &request,
            height,
            execution_payload,
            token_delta,
            contract_delta,
            amm_delta,
            proof_aggregate,
            fee_sponsor,
            monero_exit,
            receipt_book,
            finality_certificate,
            abi_registry,
            request.max_fee_bps.min(self.config.max_user_fee_bps),
            request
                .target_latency_blocks
                .min(self.config.max_latency_blocks),
        )?;
        let receipt_id = receipt.receipt_id.clone();
        if self.receipts.insert(receipt_id.clone(), receipt).is_some() {
            return Err("private l2 execution service receipt already exists".to_string());
        }
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| "private l2 execution service request not found".to_string())?;
        request.status = ExecutionServiceStatus::Settled;
        request.receipt_id = Some(receipt_id.clone());
        self.counters.executed_receipts = self.counters.executed_receipts.saturating_add(1);
        self.counters.total_user_fee_bps = self
            .counters
            .total_user_fee_bps
            .saturating_add(request.max_fee_bps.min(self.config.max_user_fee_bps));
        self.counters.total_latency_blocks = self.counters.total_latency_blocks.saturating_add(
            request
                .target_latency_blocks
                .min(self.config.max_latency_blocks),
        );
        self.refresh();
        Ok(receipt_id)
    }

    pub fn bind_settlement(
        &mut self,
        receipt_id: &str,
        binding_kind: SettlementBindingKind,
        height: u64,
        settlement: &Value,
        da: &Value,
        nullifier: &Value,
    ) -> PrivateL2MvpExecutionServiceResult<String> {
        let _receipt = self
            .receipts
            .get(receipt_id)
            .ok_or_else(|| "private l2 execution service receipt not found".to_string())?;
        let binding = SettlementBinding::new(
            receipt_id,
            binding_kind,
            height,
            settlement,
            da,
            nullifier,
            height.saturating_add(self.config.settlement_ttl_blocks),
        )?;
        let binding_id = binding.binding_id.clone();
        if self
            .settlement_bindings
            .insert(binding_id.clone(), binding)
            .is_some()
        {
            return Err(
                "private l2 execution service settlement binding already exists".to_string(),
            );
        }
        self.counters.settlement_bindings = self.counters.settlement_bindings.saturating_add(1);
        self.refresh();
        Ok(binding_id)
    }

    pub fn refresh(&mut self) {
        let request_records = self
            .requests
            .values()
            .map(ExecutionRequest::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(ExecutionReceipt::public_record)
            .collect::<Vec<_>>();
        let binding_records = self
            .settlement_bindings
            .values()
            .map(SettlementBinding::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: private_l2_mvp_execution_service_payload_root(
                "CONFIG",
                &self.config.public_record(),
            ),
            request_root: merkle_root(
                "PRIVATE-L2-MVP-EXECUTION-SERVICE-REQUESTS",
                &request_records,
            ),
            receipt_root: merkle_root(
                "PRIVATE-L2-MVP-EXECUTION-SERVICE-RECEIPTS",
                &receipt_records,
            ),
            settlement_binding_root: merkle_root(
                "PRIVATE-L2-MVP-EXECUTION-SERVICE-SETTLEMENT-BINDINGS",
                &binding_records,
            ),
            counter_root: private_l2_mvp_execution_service_payload_root(
                "COUNTERS",
                &self.counters.public_record(),
            ),
        };
        self.state_root = private_l2_mvp_execution_service_payload_root(
            "STATE",
            &self.public_record_without_root(),
        );
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_execution_service_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_EXECUTION_SERVICE_PROTOCOL_VERSION,
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
                "requests".to_string(),
                json!(self
                    .requests
                    .values()
                    .map(ExecutionRequest::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "receipts".to_string(),
                json!(self
                    .receipts
                    .values()
                    .map(ExecutionReceipt::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "settlement_bindings".to_string(),
                json!(self
                    .settlement_bindings
                    .values()
                    .map(SettlementBinding::public_record)
                    .collect::<Vec<_>>()),
            );
        }
        record
    }

    fn validate_request(
        &mut self,
        request: &ExecutionRequest,
    ) -> PrivateL2MvpExecutionServiceResult<()> {
        if request.max_fee_bps > self.config.max_user_fee_bps {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 execution service request exceeds fee cap".to_string());
        }
        if request.target_latency_blocks > self.config.max_latency_blocks {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 execution service request exceeds latency cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 execution service request privacy set too small".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
            return Err("private l2 execution service request pq security too small".to_string());
        }
        Ok(())
    }
}

pub fn devnet_execution_request(
    height: u64,
) -> PrivateL2MvpExecutionServiceResult<ExecutionRequest> {
    ExecutionRequest::new(
        ExecutionServiceClass::FullMvpFlow,
        height,
        PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_SETTLEMENT_TTL_BLOCKS,
        &json!({"gateway_route": "devnet-private-l2-route"}),
        "devnet-private-user",
        "devnet-private-defi-app",
        &json!({"payload": "devnet-full-mvp-private-flow"}),
        &json!({"abi_registry": "devnet-private-token-contract-abi-registry"}),
        &json!({"fast_lane": "devnet-pq-fast-lane-fee-market"}),
        &json!({"pq_authorization": "devnet-ml-dsa-87-root"}),
        &json!({"privacy_proof": "devnet-private-l2-proof-root"}),
        PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MAX_USER_FEE_BPS.min(20),
        PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MAX_LATENCY_BLOCKS,
        PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MIN_PRIVACY_SET.saturating_mul(2),
        PRIVATE_L2_MVP_EXECUTION_SERVICE_DEFAULT_MIN_PQ_SECURITY_BITS,
    )
}

pub fn private_l2_mvp_execution_service_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-MVP-EXECUTION-SERVICE-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_l2_mvp_execution_service_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-MVP-EXECUTION-SERVICE-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_request_id(
    service_class: ExecutionServiceClass,
    opened_height: u64,
    expires_height: u64,
    gateway_route_root: &str,
    account_commitment: &str,
    app_commitment: &str,
    payload_root: &str,
    abi_registry_root: &str,
    fast_lane_root: &str,
    pq_authorization_root: &str,
    privacy_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-EXECUTION-SERVICE-REQUEST-ID",
        &[
            HashPart::Str(service_class.as_str()),
            HashPart::Int(opened_height as i128),
            HashPart::Int(expires_height as i128),
            HashPart::Str(gateway_route_root),
            HashPart::Str(account_commitment),
            HashPart::Str(app_commitment),
            HashPart::Str(payload_root),
            HashPart::Str(abi_registry_root),
            HashPart::Str(fast_lane_root),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(privacy_proof_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_receipt_id(
    request_id: &str,
    height: u64,
    execution_root: &str,
    token_delta_root: &str,
    contract_delta_root: &str,
    amm_delta_root: &str,
    proof_aggregate_root: &str,
    fee_sponsor_root: &str,
    monero_exit_root: &str,
    receipt_book_root: &str,
    finality_certificate_root: &str,
    abi_registry_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-EXECUTION-SERVICE-RECEIPT-ID",
        &[
            HashPart::Str(request_id),
            HashPart::Int(height as i128),
            HashPart::Str(execution_root),
            HashPart::Str(token_delta_root),
            HashPart::Str(contract_delta_root),
            HashPart::Str(amm_delta_root),
            HashPart::Str(proof_aggregate_root),
            HashPart::Str(fee_sponsor_root),
            HashPart::Str(monero_exit_root),
            HashPart::Str(receipt_book_root),
            HashPart::Str(finality_certificate_root),
            HashPart::Str(abi_registry_root),
        ],
        32,
    )
}

pub fn settlement_binding_id(
    receipt_id: &str,
    binding_kind: SettlementBindingKind,
    height: u64,
    settlement_root: &str,
    da_root: &str,
    nullifier_root: &str,
    expires_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-EXECUTION-SERVICE-SETTLEMENT-BINDING-ID",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(binding_kind.as_str()),
            HashPart::Int(height as i128),
            HashPart::Str(settlement_root),
            HashPart::Str(da_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(expires_height as i128),
        ],
        32,
    )
}

pub fn root_from_record(record: &Value) -> String {
    private_l2_mvp_execution_service_payload_root("RECORD", record)
}

pub fn devnet() -> PrivateL2MvpExecutionServiceResult<State> {
    State::devnet()
}
