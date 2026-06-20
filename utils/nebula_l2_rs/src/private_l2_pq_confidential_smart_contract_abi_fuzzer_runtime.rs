use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const PROTOCOL_VERSION: &str = "nebula-l2-private-smart-contract-abi-fuzzer-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SMART_CONTRACT_ABI_FUZZER_RUNTIME_VERSION: &str =
    "private-l2-pq-confidential-smart-contract-abi-fuzzer-runtime/0.1.0";

pub type Runtime = State;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub devnet_label: String,
    pub max_calldata_bytes: usize,
    pub max_public_summary_bytes: usize,
    pub max_receipts: usize,
    pub max_events_per_receipt: usize,
    pub min_pq_signature_bytes: usize,
    pub min_pq_public_key_bytes: usize,
    pub require_domain_separator: bool,
    pub allow_debug_contracts: bool,
    pub strict_confidential_shapes: bool,
    pub deployment_gate_level: GateLevel,
    pub gas_buckets: Vec<GasBucket>,
    pub fee_buckets: Vec<FeeBucket>,
    pub allowed_selectors: BTreeSet<String>,
    pub denied_selectors: BTreeSet<String>,
    pub allowed_contract_kinds: BTreeSet<ContractKind>,
    pub callback_policy: CallbackPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum GateLevel {
    Observe,
    Warn,
    Enforce,
    Quarantine,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallbackPolicy {
    DenyAll,
    AllowViewOnly,
    AllowRegisteredPrivateCallbacks,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContractKind {
    Token,
    Amm,
    Lending,
    Perps,
    Router,
    Oracle,
    CallbackSink,
    DeploymentFactory,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GasBucket {
    pub name: String,
    pub min: u64,
    pub max: u64,
    pub regression_limit_bps: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeBucket {
    pub name: String,
    pub min_atomic: u64,
    pub max_atomic: u64,
    pub regression_limit_bps: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub requests_seen: u64,
    pub requests_accepted: u64,
    pub requests_rejected: u64,
    pub deployments_seen: u64,
    pub deployments_accepted: u64,
    pub deployments_rejected: u64,
    pub receipts_recorded: u64,
    pub differential_mismatches: u64,
    pub calldata_shape_failures: u64,
    pub pq_seed_failures: u64,
    pub reentrancy_findings: u64,
    pub callback_privacy_findings: u64,
    pub gas_regressions: u64,
    pub fee_regressions: u64,
    pub safe_gate_rejections: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub request_root: String,
    pub receipt_root: String,
    pub deployment_root: String,
    pub catalog_root: String,
    pub summary_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub catalog: BTreeMap<String, FuzzCase>,
    pub requests: VecDeque<FuzzRequest>,
    pub receipts: Vec<ExecutionReceipt>,
    pub deployments: BTreeMap<String, DeploymentRecord>,
    pub operator_summaries: Vec<OperatorPublicSummary>,
    pub registered_callbacks: BTreeSet<String>,
    pub gas_baselines: BTreeMap<String, u64>,
    pub fee_baselines: BTreeMap<String, u64>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FuzzCase {
    pub id: String,
    pub title: String,
    pub family: FuzzFamily,
    pub contract_kind: ContractKind,
    pub selector: String,
    pub entrypoint: Entrypoint,
    pub calldata_shape: CalldataShape,
    pub pq_seed: PqSignedSeed,
    pub expected_privacy: PrivacyExpectation,
    pub expected_gas_bucket: String,
    pub expected_fee_bucket: String,
    pub tags: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FuzzFamily {
    AbiBoundary,
    ConfidentialShape,
    PqSignature,
    Token,
    Amm,
    Lending,
    Perps,
    Reentrancy,
    CallbackPrivacy,
    GasRegression,
    FeeRegression,
    DifferentialReceipt,
    DeploymentGate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FuzzRequest {
    pub request_id: String,
    pub contract_id: String,
    pub case_id: String,
    pub caller_commitment: String,
    pub entrypoint: Entrypoint,
    pub calldata: ConfidentialCalldata,
    pub pq_seed: PqSignedSeed,
    pub gas_limit: u64,
    pub fee_limit_atomic: u64,
    pub callback: Option<CallbackEnvelope>,
    pub differential_target: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordRequest {
    pub request_id: String,
    pub receipt: ExecutionReceipt,
    pub operator_note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentRequest {
    pub deployment_id: String,
    pub factory_id: String,
    pub contract_kind: ContractKind,
    pub bytecode_commitment: String,
    pub abi_commitment: String,
    pub deployer_commitment: String,
    pub constructor_calldata: ConfidentialCalldata,
    pub pq_seed: PqSignedSeed,
    pub declared_selectors: BTreeSet<String>,
    pub debug_symbols_commitment: Option<String>,
    pub upgrade_authority_commitment: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentRecord {
    pub deployment_id: String,
    pub contract_kind: ContractKind,
    pub accepted: bool,
    pub gate_level: GateLevel,
    pub reasons: Vec<String>,
    pub public_summary: Value,
    pub root_after: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionReceipt {
    pub request_id: String,
    pub contract_id: String,
    pub case_id: String,
    pub selector: String,
    pub status: ReceiptStatus,
    pub gas_used: u64,
    pub fee_charged_atomic: u64,
    pub confidential_state_delta_commitment: String,
    pub receipt_root: String,
    pub event_commitments: Vec<String>,
    pub public_return: PublicReturn,
    pub differential: Option<DifferentialReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceiptStatus {
    Accepted,
    Rejected,
    Reverted,
    Quarantined,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DifferentialReceipt {
    pub target_runtime: String,
    pub local_root: String,
    pub target_root: String,
    pub equivalent: bool,
    pub mismatch_kind: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorPublicSummary {
    pub sequence: u64,
    pub protocol_version: String,
    pub module_version: String,
    pub accepted_requests: u64,
    pub rejected_requests: u64,
    pub accepted_deployments: u64,
    pub rejected_deployments: u64,
    pub findings: BTreeMap<String, u64>,
    pub roots: Roots,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub request_id: Option<String>,
    pub deployment_id: Option<String>,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Entrypoint {
    Token(TokenEntrypoint),
    Amm(AmmEntrypoint),
    Lending(LendingEntrypoint),
    Perps(PerpsEntrypoint),
    Router(RouterEntrypoint),
    Oracle(OracleEntrypoint),
    Factory(FactoryEntrypoint),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenEntrypoint {
    ConfidentialMint,
    ConfidentialBurn,
    ShieldedTransfer,
    ApproveCommitment,
    PermitTransfer,
    RotateViewingKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AmmEntrypoint {
    AddPrivateLiquidity,
    RemovePrivateLiquidity,
    SwapExactInput,
    SwapExactOutput,
    SyncEncryptedReserves,
    CollectPrivateFees,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LendingEntrypoint {
    DepositCollateral,
    WithdrawCollateral,
    BorrowPrivate,
    RepayPrivate,
    LiquidateConfidential,
    RefreshRiskSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PerpsEntrypoint {
    OpenPrivatePosition,
    IncreasePrivatePosition,
    DecreasePrivatePosition,
    ClosePrivatePosition,
    SettleFunding,
    LiquidatePrivatePosition,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RouterEntrypoint {
    MulticallPrivate,
    RoutePrivateSwap,
    RoutePrivateBorrow,
    RoutePrivateHedge,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OracleEntrypoint {
    CommitPrice,
    RevealAggregate,
    RefreshTwap,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FactoryEntrypoint {
    DeployContract,
    RegisterSelector,
    RegisterCallback,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CalldataShape {
    pub min_bytes: usize,
    pub max_bytes: usize,
    pub required_fields: BTreeSet<String>,
    pub forbidden_fields: BTreeSet<String>,
    pub encrypted_fields: BTreeSet<String>,
    pub commitment_fields: BTreeSet<String>,
    pub nullifier_fields: BTreeSet<String>,
    pub allow_public_amounts: bool,
    pub allow_public_addresses: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidentialCalldata {
    pub encoded_len: usize,
    pub domain_separator: String,
    pub selector: String,
    pub fields: BTreeMap<String, CalldataField>,
    pub transcript_commitment: String,
    pub nullifiers: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CalldataField {
    pub visibility: FieldVisibility,
    pub kind: FieldKind,
    pub commitment: String,
    pub byte_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldVisibility {
    Public,
    Confidential,
    CommitmentOnly,
    Nullifier,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldKind {
    Address,
    Amount,
    Price,
    Leverage,
    TokenId,
    PoolId,
    Nonce,
    Deadline,
    Proof,
    Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqSignedSeed {
    pub seed_id: String,
    pub domain: String,
    pub public_key_commitment: String,
    pub public_key_len: usize,
    pub signature_commitment: String,
    pub signature_len: usize,
    pub message_commitment: String,
    pub algorithm: PqAlgorithm,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PqAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaSha2Small,
    SlhDsaShakeSmall,
    HybridEd25519MlDsa65,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyExpectation {
    pub no_public_amounts: bool,
    pub no_public_addresses: bool,
    pub unique_nullifiers: bool,
    pub no_callback_plaintext: bool,
    pub receipt_root_only: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallbackEnvelope {
    pub callback_id: String,
    pub target_contract_id: String,
    pub selector: String,
    pub view_only: bool,
    pub calldata: ConfidentialCalldata,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicReturn {
    pub return_kind: PublicReturnKind,
    pub bytes_commitment: String,
    pub public_fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PublicReturnKind {
    Empty,
    Commitment,
    ReceiptRoot,
    OperatorSummary,
    RejectionCode,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            requests_seen: 0,
            requests_accepted: 0,
            requests_rejected: 0,
            deployments_seen: 0,
            deployments_accepted: 0,
            deployments_rejected: 0,
            receipts_recorded: 0,
            differential_mismatches: 0,
            calldata_shape_failures: 0,
            pq_seed_failures: 0,
            reentrancy_findings: 0,
            callback_privacy_findings: 0,
            gas_regressions: 0,
            fee_regressions: 0,
            safe_gate_rejections: 0,
        }
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            request_root: stable_hash("requests:empty"),
            receipt_root: stable_hash("receipts:empty"),
            deployment_root: stable_hash("deployments:empty"),
            catalog_root: stable_hash("catalog:empty"),
            summary_root: stable_hash("summaries:empty"),
            state_root: stable_hash("state:empty"),
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        let mut allowed_selectors = BTreeSet::new();
        for selector in [
            "token.confidential_mint",
            "token.confidential_burn",
            "token.shielded_transfer",
            "token.approve_commitment",
            "token.permit_transfer",
            "token.rotate_viewing_key",
            "amm.add_private_liquidity",
            "amm.remove_private_liquidity",
            "amm.swap_exact_input",
            "amm.swap_exact_output",
            "amm.sync_encrypted_reserves",
            "amm.collect_private_fees",
            "lending.deposit_collateral",
            "lending.withdraw_collateral",
            "lending.borrow_private",
            "lending.repay_private",
            "lending.liquidate_confidential",
            "lending.refresh_risk_snapshot",
            "perps.open_private_position",
            "perps.increase_private_position",
            "perps.decrease_private_position",
            "perps.close_private_position",
            "perps.settle_funding",
            "perps.liquidate_private_position",
            "router.multicall_private",
            "router.route_private_swap",
            "router.route_private_borrow",
            "router.route_private_hedge",
            "oracle.commit_price",
            "oracle.reveal_aggregate",
            "oracle.refresh_twap",
            "factory.deploy_contract",
            "factory.register_selector",
            "factory.register_callback",
        ] {
            allowed_selectors.insert(selector.to_string());
        }

        let mut allowed_contract_kinds = BTreeSet::new();
        for kind in [
            ContractKind::Token,
            ContractKind::Amm,
            ContractKind::Lending,
            ContractKind::Perps,
            ContractKind::Router,
            ContractKind::Oracle,
            ContractKind::CallbackSink,
            ContractKind::DeploymentFactory,
        ] {
            allowed_contract_kinds.insert(kind);
        }

        Self {
            chain_id: "nebula-devnet-private-l2".to_string(),
            devnet_label: "pq-confidential-smart-contract-abi-fuzzer".to_string(),
            max_calldata_bytes: 16 * 1024,
            max_public_summary_bytes: 4 * 1024,
            max_receipts: 512,
            max_events_per_receipt: 24,
            min_pq_signature_bytes: 2_420,
            min_pq_public_key_bytes: 1_312,
            require_domain_separator: true,
            allow_debug_contracts: false,
            strict_confidential_shapes: true,
            deployment_gate_level: GateLevel::Enforce,
            gas_buckets: default_gas_buckets(),
            fee_buckets: default_fee_buckets(),
            allowed_selectors,
            denied_selectors: BTreeSet::new(),
            allowed_contract_kinds,
            callback_policy: CallbackPolicy::AllowRegisteredPrivateCallbacks,
        }
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let catalog = build_catalog();
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            catalog,
            requests: VecDeque::new(),
            receipts: Vec::new(),
            deployments: BTreeMap::new(),
            operator_summaries: Vec::new(),
            registered_callbacks: BTreeSet::new(),
            gas_baselines: default_gas_baselines(),
            fee_baselines: default_fee_baselines(),
            findings: Vec::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        for case in state
            .catalog
            .values()
            .take(12)
            .cloned()
            .collect::<Vec<FuzzCase>>()
        {
            let request = request_from_case(&case, "demo-contract");
            let _accepted = state.submit_request(request);
        }
        let queued = state.requests.iter().cloned().collect::<Vec<FuzzRequest>>();
        for request in queued {
            let receipt = state.simulate_receipt(&request);
            let record = RecordRequest {
                request_id: request.request_id.clone(),
                receipt,
                operator_note: "demo deterministic receipt".to_string(),
            };
            let _recorded = state.record(record);
        }
        state.emit_operator_summary();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "module_version": PRIVATE_L2_PQ_CONFIDENTIAL_SMART_CONTRACT_ABI_FUZZER_RUNTIME_VERSION,
            "chain_id": self.config.chain_id,
            "counters": self.counters,
            "roots": self.roots,
            "catalog_cases": self.catalog.len(),
            "deployments": self.deployments.len(),
            "registered_callbacks": self.registered_callbacks.len(),
            "summaries": self.operator_summaries,
            "finding_counts": self.finding_counts(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn submit_request(&mut self, request: FuzzRequest) -> bool {
        self.counters.requests_seen = self.counters.requests_seen.saturating_add(1);
        let validation = self.validate_request(&request);
        if validation.is_empty() {
            self.counters.requests_accepted = self.counters.requests_accepted.saturating_add(1);
            self.requests.push_back(request);
            while self.requests.len() > self.config.max_receipts {
                let _old = self.requests.pop_front();
            }
            self.recompute_roots();
            true
        } else {
            self.counters.requests_rejected = self.counters.requests_rejected.saturating_add(1);
            for reason in validation {
                self.push_finding(
                    "request_rejected",
                    Severity::Medium,
                    Some(request.request_id.clone()),
                    None,
                    reason,
                );
            }
            self.recompute_roots();
            false
        }
    }

    pub fn record(&mut self, record: RecordRequest) -> bool {
        let mut accepted = true;
        if record.request_id != record.receipt.request_id {
            accepted = false;
            self.push_finding(
                "receipt_request_mismatch",
                Severity::High,
                Some(record.request_id.clone()),
                None,
                "record request id does not match receipt request id".to_string(),
            );
        }
        if record.receipt.event_commitments.len() > self.config.max_events_per_receipt {
            accepted = false;
            self.push_finding(
                "receipt_event_overflow",
                Severity::Medium,
                Some(record.request_id.clone()),
                None,
                "receipt emits more event commitments than configured limit".to_string(),
            );
        }
        self.inspect_gas_fee_regression(&record.receipt);
        self.inspect_differential(&record.receipt);
        if accepted {
            self.counters.receipts_recorded = self.counters.receipts_recorded.saturating_add(1);
            self.receipts.push(record.receipt);
            while self.receipts.len() > self.config.max_receipts {
                let _removed = self.receipts.remove(0);
            }
        }
        self.recompute_roots();
        accepted
    }

    pub fn deploy(&mut self, request: DeploymentRequest) -> DeploymentRecord {
        self.counters.deployments_seen = self.counters.deployments_seen.saturating_add(1);
        let reasons = self.validate_deployment(&request);
        let accepted = reasons.is_empty();
        if accepted {
            self.counters.deployments_accepted =
                self.counters.deployments_accepted.saturating_add(1);
        } else {
            self.counters.deployments_rejected =
                self.counters.deployments_rejected.saturating_add(1);
            self.counters.safe_gate_rejections =
                self.counters.safe_gate_rejections.saturating_add(1);
        }
        let public_summary = json!({
            "deployment_id": request.deployment_id,
            "factory_id": request.factory_id,
            "contract_kind": request.contract_kind,
            "bytecode_commitment": request.bytecode_commitment,
            "abi_commitment": request.abi_commitment,
            "selector_count": request.declared_selectors.len(),
            "accepted": accepted,
            "reasons": reasons,
        });
        let mut record = DeploymentRecord {
            deployment_id: value_string(&public_summary, "deployment_id"),
            contract_kind: request.contract_kind.clone(),
            accepted,
            gate_level: self.config.deployment_gate_level.clone(),
            reasons: value_vec_strings(&public_summary, "reasons"),
            public_summary,
            root_after: String::new(),
        };
        if !accepted {
            for reason in record.reasons.clone() {
                self.push_finding(
                    "deployment_gate_rejected",
                    Severity::High,
                    None,
                    Some(record.deployment_id.clone()),
                    reason,
                );
            }
        }
        self.deployments
            .insert(record.deployment_id.clone(), record.clone());
        self.recompute_roots();
        record.root_after = self.roots.deployment_root.clone();
        self.deployments
            .insert(record.deployment_id.clone(), record.clone());
        self.recompute_roots();
        record
    }

    pub fn register_callback(&mut self, callback_id: String) -> bool {
        if callback_id.is_empty() {
            self.push_finding(
                "empty_callback_registration",
                Severity::Low,
                None,
                None,
                "empty callback id ignored".to_string(),
            );
            false
        } else {
            self.registered_callbacks.insert(callback_id);
            self.recompute_roots();
            true
        }
    }

    pub fn emit_operator_summary(&mut self) -> OperatorPublicSummary {
        let summary = OperatorPublicSummary {
            sequence: self.operator_summaries.len() as u64,
            protocol_version: PROTOCOL_VERSION.to_string(),
            module_version: PRIVATE_L2_PQ_CONFIDENTIAL_SMART_CONTRACT_ABI_FUZZER_RUNTIME_VERSION
                .to_string(),
            accepted_requests: self.counters.requests_accepted,
            rejected_requests: self.counters.requests_rejected,
            accepted_deployments: self.counters.deployments_accepted,
            rejected_deployments: self.counters.deployments_rejected,
            findings: self.finding_counts(),
            roots: self.roots.clone(),
        };
        self.operator_summaries.push(summary.clone());
        self.recompute_roots();
        summary
    }

    pub fn simulate_receipt(&self, request: &FuzzRequest) -> ExecutionReceipt {
        let base = format!(
            "{}:{}:{}:{}",
            request.request_id,
            request.contract_id,
            request.case_id,
            request.calldata.transcript_commitment
        );
        let gas_used = bucket_midpoint(&self.config.gas_buckets, request.gas_limit);
        let fee_charged_atomic =
            bucket_fee_midpoint(&self.config.fee_buckets, request.fee_limit_atomic);
        ExecutionReceipt {
            request_id: request.request_id.clone(),
            contract_id: request.contract_id.clone(),
            case_id: request.case_id.clone(),
            selector: request.calldata.selector.clone(),
            status: ReceiptStatus::Accepted,
            gas_used,
            fee_charged_atomic,
            confidential_state_delta_commitment: stable_hash(&format!("delta:{base}")),
            receipt_root: stable_hash(&format!("receipt:{base}:{gas_used}:{fee_charged_atomic}")),
            event_commitments: vec![stable_hash(&format!("event:{base}:0"))],
            public_return: PublicReturn {
                return_kind: PublicReturnKind::ReceiptRoot,
                bytes_commitment: stable_hash(&format!("return:{base}")),
                public_fields: BTreeMap::new(),
            },
            differential: Some(DifferentialReceipt {
                target_runtime: "reference-private-l2".to_string(),
                local_root: stable_hash(&format!("local:{base}")),
                target_root: stable_hash(&format!("local:{base}")),
                equivalent: true,
                mismatch_kind: None,
            }),
        }
    }

    fn validate_request(&mut self, request: &FuzzRequest) -> Vec<String> {
        let mut reasons = Vec::new();
        let case = self.catalog.get(&request.case_id).cloned();
        if case.is_none() {
            reasons.push("unknown fuzz case id".to_string());
        }
        if !self
            .config
            .allowed_selectors
            .contains(&request.calldata.selector)
        {
            reasons.push("selector is not allowlisted".to_string());
        }
        if self
            .config
            .denied_selectors
            .contains(&request.calldata.selector)
        {
            reasons.push("selector is explicitly denied".to_string());
        }
        if request.calldata.encoded_len > self.config.max_calldata_bytes {
            reasons.push("calldata exceeds maximum encoded length".to_string());
            self.counters.calldata_shape_failures =
                self.counters.calldata_shape_failures.saturating_add(1);
        }
        if !self.validate_pq_seed(&request.pq_seed) {
            reasons.push("post-quantum seed signature envelope failed policy".to_string());
            self.counters.pq_seed_failures = self.counters.pq_seed_failures.saturating_add(1);
        }
        if let Some(fuzz_case) = case {
            for reason in validate_calldata_shape(
                &request.calldata,
                &fuzz_case.calldata_shape,
                self.config.require_domain_separator,
                self.config.strict_confidential_shapes,
            ) {
                reasons.push(reason);
                self.counters.calldata_shape_failures =
                    self.counters.calldata_shape_failures.saturating_add(1);
            }
            for reason in validate_privacy_expectation(
                &request.calldata,
                request.callback.as_ref(),
                &fuzz_case.expected_privacy,
            ) {
                reasons.push(reason);
                self.counters.callback_privacy_findings =
                    self.counters.callback_privacy_findings.saturating_add(1);
            }
        }
        for reason in self.validate_callback(request.callback.as_ref()) {
            reasons.push(reason);
        }
        if self.detect_reentrancy(request) {
            reasons.push(
                "callback graph indicates reentrancy into same contract selector".to_string(),
            );
            self.counters.reentrancy_findings = self.counters.reentrancy_findings.saturating_add(1);
        }
        reasons
    }

    fn validate_pq_seed(&self, seed: &PqSignedSeed) -> bool {
        !seed.seed_id.is_empty()
            && seed.domain == PROTOCOL_VERSION
            && seed.public_key_len >= self.config.min_pq_public_key_bytes
            && seed.signature_len >= self.config.min_pq_signature_bytes
            && looks_like_commitment(&seed.public_key_commitment)
            && looks_like_commitment(&seed.signature_commitment)
            && looks_like_commitment(&seed.message_commitment)
    }

    fn validate_callback(&self, callback: Option<&CallbackEnvelope>) -> Vec<String> {
        let mut reasons = Vec::new();
        if let Some(envelope) = callback {
            match self.config.callback_policy {
                CallbackPolicy::DenyAll => {
                    reasons.push("callbacks are disabled by policy".to_string());
                }
                CallbackPolicy::AllowViewOnly => {
                    if !envelope.view_only {
                        reasons.push("callback is not view-only".to_string());
                    }
                }
                CallbackPolicy::AllowRegisteredPrivateCallbacks => {
                    if !self.registered_callbacks.contains(&envelope.callback_id) {
                        reasons.push("callback id is not registered".to_string());
                    }
                    if has_public_sensitive_fields(&envelope.calldata) {
                        reasons
                            .push("callback calldata contains public sensitive fields".to_string());
                    }
                }
            }
        }
        reasons
    }

    fn validate_deployment(&self, request: &DeploymentRequest) -> Vec<String> {
        let mut reasons = Vec::new();
        if !self
            .config
            .allowed_contract_kinds
            .contains(&request.contract_kind)
        {
            reasons.push("contract kind is not allowed on this runtime".to_string());
        }
        if !looks_like_commitment(&request.bytecode_commitment) {
            reasons.push("bytecode commitment is malformed".to_string());
        }
        if !looks_like_commitment(&request.abi_commitment) {
            reasons.push("abi commitment is malformed".to_string());
        }
        if !looks_like_commitment(&request.deployer_commitment) {
            reasons.push("deployer commitment is malformed".to_string());
        }
        if !self.validate_pq_seed(&request.pq_seed) {
            reasons.push("deployment pq seed failed policy".to_string());
        }
        if !self.config.allow_debug_contracts && request.debug_symbols_commitment.is_some() {
            reasons.push("debug symbols are not allowed through safe deployment gate".to_string());
        }
        if request.declared_selectors.is_empty() {
            reasons.push("deployment declares no selectors".to_string());
        }
        for selector in &request.declared_selectors {
            if !self.config.allowed_selectors.contains(selector) {
                reasons.push(format!("selector {selector} is not in runtime allowlist"));
            }
            if self.config.denied_selectors.contains(selector) {
                reasons.push(format!("selector {selector} is explicitly denied"));
            }
        }
        for reason in validate_calldata_shape(
            &request.constructor_calldata,
            &deployment_constructor_shape(),
            self.config.require_domain_separator,
            self.config.strict_confidential_shapes,
        ) {
            reasons.push(format!("constructor {reason}"));
        }
        reasons
    }

    fn detect_reentrancy(&self, request: &FuzzRequest) -> bool {
        if let Some(callback) = &request.callback {
            callback.target_contract_id == request.contract_id
                && callback.selector == request.calldata.selector
                && !callback.view_only
        } else {
            false
        }
    }

    fn inspect_gas_fee_regression(&mut self, receipt: &ExecutionReceipt) {
        let gas_key = format!("{}:{}", receipt.case_id, receipt.selector);
        if let Some(baseline) = self.gas_baselines.get(&gas_key) {
            if exceeds_bps(receipt.gas_used, *baseline, 1_500) {
                self.counters.gas_regressions = self.counters.gas_regressions.saturating_add(1);
                self.push_finding(
                    "gas_regression",
                    Severity::Medium,
                    Some(receipt.request_id.clone()),
                    None,
                    format!(
                        "gas used {} exceeds baseline {}",
                        receipt.gas_used, baseline
                    ),
                );
            }
        }
        let fee_key = format!("{}:{}", receipt.case_id, receipt.selector);
        if let Some(baseline) = self.fee_baselines.get(&fee_key) {
            if exceeds_bps(receipt.fee_charged_atomic, *baseline, 1_000) {
                self.counters.fee_regressions = self.counters.fee_regressions.saturating_add(1);
                self.push_finding(
                    "fee_regression",
                    Severity::Medium,
                    Some(receipt.request_id.clone()),
                    None,
                    format!(
                        "fee charged {} exceeds baseline {}",
                        receipt.fee_charged_atomic, baseline
                    ),
                );
            }
        }
    }

    fn inspect_differential(&mut self, receipt: &ExecutionReceipt) {
        if let Some(differential) = &receipt.differential {
            if !differential.equivalent || differential.local_root != differential.target_root {
                self.counters.differential_mismatches =
                    self.counters.differential_mismatches.saturating_add(1);
                self.push_finding(
                    "differential_receipt_root_mismatch",
                    Severity::High,
                    Some(receipt.request_id.clone()),
                    None,
                    format!(
                        "local root {} differs from target root {}",
                        differential.local_root, differential.target_root
                    ),
                );
            }
        }
    }

    fn push_finding(
        &mut self,
        code: &str,
        severity: Severity,
        request_id: Option<String>,
        deployment_id: Option<String>,
        detail: String,
    ) {
        self.findings.push(Finding {
            code: code.to_string(),
            severity,
            request_id,
            deployment_id,
            detail,
        });
    }

    fn finding_counts(&self) -> BTreeMap<String, u64> {
        let mut counts = BTreeMap::new();
        for finding in &self.findings {
            let entry = counts.entry(finding.code.clone()).or_insert(0);
            *entry = (*entry as u64).saturating_add(1);
        }
        counts
    }

    fn recompute_roots(&mut self) {
        self.roots.catalog_root =
            stable_hash(&format!("catalog:{}", catalog_digest(&self.catalog)));
        self.roots.request_root =
            stable_hash(&format!("requests:{}", requests_digest(&self.requests)));
        self.roots.receipt_root =
            stable_hash(&format!("receipts:{}", receipts_digest(&self.receipts)));
        self.roots.deployment_root = stable_hash(&format!(
            "deployments:{}",
            deployments_digest(&self.deployments)
        ));
        self.roots.summary_root = stable_hash(&format!(
            "summaries:{}",
            summaries_digest(&self.operator_summaries)
        ));
        self.roots.state_root = stable_hash(&format!(
            "state:{}:{}:{}:{}:{}:{}:{}",
            self.roots.catalog_root,
            self.roots.request_root,
            self.roots.receipt_root,
            self.roots.deployment_root,
            self.roots.summary_root,
            self.findings.len(),
            self.registered_callbacks.len()
        ));
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record() -> Value {
    State::demo().public_record()
}

pub fn state_root() -> String {
    State::demo().state_root()
}

fn default_gas_buckets() -> Vec<GasBucket> {
    vec![
        GasBucket {
            name: "tiny".to_string(),
            min: 0,
            max: 25_000,
            regression_limit_bps: 800,
        },
        GasBucket {
            name: "small".to_string(),
            min: 25_001,
            max: 90_000,
            regression_limit_bps: 1_000,
        },
        GasBucket {
            name: "medium".to_string(),
            min: 90_001,
            max: 300_000,
            regression_limit_bps: 1_250,
        },
        GasBucket {
            name: "large".to_string(),
            min: 300_001,
            max: 900_000,
            regression_limit_bps: 1_500,
        },
        GasBucket {
            name: "stress".to_string(),
            min: 900_001,
            max: 3_000_000,
            regression_limit_bps: 2_000,
        },
    ]
}

fn default_fee_buckets() -> Vec<FeeBucket> {
    vec![
        FeeBucket {
            name: "dust".to_string(),
            min_atomic: 0,
            max_atomic: 10_000,
            regression_limit_bps: 500,
        },
        FeeBucket {
            name: "retail".to_string(),
            min_atomic: 10_001,
            max_atomic: 250_000,
            regression_limit_bps: 800,
        },
        FeeBucket {
            name: "desk".to_string(),
            min_atomic: 250_001,
            max_atomic: 2_000_000,
            regression_limit_bps: 1_200,
        },
        FeeBucket {
            name: "stress".to_string(),
            min_atomic: 2_000_001,
            max_atomic: 25_000_000,
            regression_limit_bps: 1_500,
        },
    ]
}

fn default_gas_baselines() -> BTreeMap<String, u64> {
    let mut baselines = BTreeMap::new();
    for case in build_catalog().values() {
        let value = match case.expected_gas_bucket.as_str() {
            "tiny" => 18_000,
            "small" => 60_000,
            "medium" => 190_000,
            "large" => 620_000,
            "stress" => 1_700_000,
            _other => 250_000,
        };
        baselines.insert(format!("{}:{}", case.id, case.selector), value);
    }
    baselines
}

fn default_fee_baselines() -> BTreeMap<String, u64> {
    let mut baselines = BTreeMap::new();
    for case in build_catalog().values() {
        let value = match case.expected_fee_bucket.as_str() {
            "dust" => 5_000,
            "retail" => 125_000,
            "desk" => 1_000_000,
            "stress" => 12_500_000,
            _other => 250_000,
        };
        baselines.insert(format!("{}:{}", case.id, case.selector), value);
    }
    baselines
}

fn build_catalog() -> BTreeMap<String, FuzzCase> {
    let mut catalog = BTreeMap::new();
    for case in [
        token_case(
            "token-mint-valid",
            TokenEntrypoint::ConfidentialMint,
            "token.confidential_mint",
            FuzzFamily::Token,
            "medium",
            "retail",
        ),
        token_case(
            "token-burn-nullifier",
            TokenEntrypoint::ConfidentialBurn,
            "token.confidential_burn",
            FuzzFamily::Token,
            "small",
            "retail",
        ),
        token_case(
            "token-transfer-shielded",
            TokenEntrypoint::ShieldedTransfer,
            "token.shielded_transfer",
            FuzzFamily::Token,
            "medium",
            "retail",
        ),
        token_case(
            "token-approve-commitment",
            TokenEntrypoint::ApproveCommitment,
            "token.approve_commitment",
            FuzzFamily::AbiBoundary,
            "small",
            "dust",
        ),
        token_case(
            "token-permit-pq",
            TokenEntrypoint::PermitTransfer,
            "token.permit_transfer",
            FuzzFamily::PqSignature,
            "medium",
            "retail",
        ),
        token_case(
            "token-view-key-rotate",
            TokenEntrypoint::RotateViewingKey,
            "token.rotate_viewing_key",
            FuzzFamily::ConfidentialShape,
            "small",
            "dust",
        ),
        amm_case(
            "amm-add-liquidity",
            AmmEntrypoint::AddPrivateLiquidity,
            "amm.add_private_liquidity",
            FuzzFamily::Amm,
            "large",
            "desk",
        ),
        amm_case(
            "amm-remove-liquidity",
            AmmEntrypoint::RemovePrivateLiquidity,
            "amm.remove_private_liquidity",
            FuzzFamily::Amm,
            "large",
            "desk",
        ),
        amm_case(
            "amm-swap-exact-input",
            AmmEntrypoint::SwapExactInput,
            "amm.swap_exact_input",
            FuzzFamily::Amm,
            "medium",
            "retail",
        ),
        amm_case(
            "amm-swap-exact-output",
            AmmEntrypoint::SwapExactOutput,
            "amm.swap_exact_output",
            FuzzFamily::Amm,
            "medium",
            "retail",
        ),
        amm_case(
            "amm-sync-reserves",
            AmmEntrypoint::SyncEncryptedReserves,
            "amm.sync_encrypted_reserves",
            FuzzFamily::DifferentialReceipt,
            "small",
            "dust",
        ),
        amm_case(
            "amm-collect-fees",
            AmmEntrypoint::CollectPrivateFees,
            "amm.collect_private_fees",
            FuzzFamily::FeeRegression,
            "small",
            "retail",
        ),
        lending_case(
            "lending-deposit",
            LendingEntrypoint::DepositCollateral,
            "lending.deposit_collateral",
            FuzzFamily::Lending,
            "medium",
            "retail",
        ),
        lending_case(
            "lending-withdraw",
            LendingEntrypoint::WithdrawCollateral,
            "lending.withdraw_collateral",
            FuzzFamily::Lending,
            "medium",
            "retail",
        ),
        lending_case(
            "lending-borrow",
            LendingEntrypoint::BorrowPrivate,
            "lending.borrow_private",
            FuzzFamily::Lending,
            "large",
            "desk",
        ),
        lending_case(
            "lending-repay",
            LendingEntrypoint::RepayPrivate,
            "lending.repay_private",
            FuzzFamily::Lending,
            "medium",
            "retail",
        ),
        lending_case(
            "lending-liquidate",
            LendingEntrypoint::LiquidateConfidential,
            "lending.liquidate_confidential",
            FuzzFamily::CallbackPrivacy,
            "stress",
            "desk",
        ),
        lending_case(
            "lending-refresh-risk",
            LendingEntrypoint::RefreshRiskSnapshot,
            "lending.refresh_risk_snapshot",
            FuzzFamily::DifferentialReceipt,
            "small",
            "dust",
        ),
        perps_case(
            "perps-open",
            PerpsEntrypoint::OpenPrivatePosition,
            "perps.open_private_position",
            FuzzFamily::Perps,
            "large",
            "desk",
        ),
        perps_case(
            "perps-increase",
            PerpsEntrypoint::IncreasePrivatePosition,
            "perps.increase_private_position",
            FuzzFamily::Perps,
            "large",
            "desk",
        ),
        perps_case(
            "perps-decrease",
            PerpsEntrypoint::DecreasePrivatePosition,
            "perps.decrease_private_position",
            FuzzFamily::Perps,
            "large",
            "desk",
        ),
        perps_case(
            "perps-close",
            PerpsEntrypoint::ClosePrivatePosition,
            "perps.close_private_position",
            FuzzFamily::Perps,
            "large",
            "desk",
        ),
        perps_case(
            "perps-funding",
            PerpsEntrypoint::SettleFunding,
            "perps.settle_funding",
            FuzzFamily::GasRegression,
            "medium",
            "retail",
        ),
        perps_case(
            "perps-liquidate",
            PerpsEntrypoint::LiquidatePrivatePosition,
            "perps.liquidate_private_position",
            FuzzFamily::Reentrancy,
            "stress",
            "desk",
        ),
        router_case(
            "router-multicall",
            RouterEntrypoint::MulticallPrivate,
            "router.multicall_private",
            FuzzFamily::Reentrancy,
            "stress",
            "stress",
        ),
        router_case(
            "router-swap",
            RouterEntrypoint::RoutePrivateSwap,
            "router.route_private_swap",
            FuzzFamily::CallbackPrivacy,
            "large",
            "desk",
        ),
        router_case(
            "router-borrow",
            RouterEntrypoint::RoutePrivateBorrow,
            "router.route_private_borrow",
            FuzzFamily::CallbackPrivacy,
            "large",
            "desk",
        ),
        router_case(
            "router-hedge",
            RouterEntrypoint::RoutePrivateHedge,
            "router.route_private_hedge",
            FuzzFamily::DifferentialReceipt,
            "stress",
            "stress",
        ),
        oracle_case(
            "oracle-commit-price",
            OracleEntrypoint::CommitPrice,
            "oracle.commit_price",
            FuzzFamily::ConfidentialShape,
            "small",
            "dust",
        ),
        oracle_case(
            "oracle-reveal-aggregate",
            OracleEntrypoint::RevealAggregate,
            "oracle.reveal_aggregate",
            FuzzFamily::DifferentialReceipt,
            "medium",
            "retail",
        ),
        oracle_case(
            "oracle-refresh-twap",
            OracleEntrypoint::RefreshTwap,
            "oracle.refresh_twap",
            FuzzFamily::GasRegression,
            "small",
            "dust",
        ),
        factory_case(
            "factory-deploy",
            FactoryEntrypoint::DeployContract,
            "factory.deploy_contract",
            FuzzFamily::DeploymentGate,
            "large",
            "desk",
        ),
        factory_case(
            "factory-register-selector",
            FactoryEntrypoint::RegisterSelector,
            "factory.register_selector",
            FuzzFamily::DeploymentGate,
            "small",
            "dust",
        ),
        factory_case(
            "factory-register-callback",
            FactoryEntrypoint::RegisterCallback,
            "factory.register_callback",
            FuzzFamily::CallbackPrivacy,
            "small",
            "dust",
        ),
    ] {
        catalog.insert(case.id.clone(), case);
    }
    catalog
}

fn token_case(
    id: &str,
    entrypoint: TokenEntrypoint,
    selector: &str,
    family: FuzzFamily,
    gas: &str,
    fee: &str,
) -> FuzzCase {
    standard_case(
        id,
        family,
        ContractKind::Token,
        selector,
        Entrypoint::Token(entrypoint),
        token_shape(selector),
        gas,
        fee,
        &["token", "confidential-asset", "abi"],
    )
}

fn amm_case(
    id: &str,
    entrypoint: AmmEntrypoint,
    selector: &str,
    family: FuzzFamily,
    gas: &str,
    fee: &str,
) -> FuzzCase {
    standard_case(
        id,
        family,
        ContractKind::Amm,
        selector,
        Entrypoint::Amm(entrypoint),
        amm_shape(selector),
        gas,
        fee,
        &["amm", "encrypted-reserves", "callback"],
    )
}

fn lending_case(
    id: &str,
    entrypoint: LendingEntrypoint,
    selector: &str,
    family: FuzzFamily,
    gas: &str,
    fee: &str,
) -> FuzzCase {
    standard_case(
        id,
        family,
        ContractKind::Lending,
        selector,
        Entrypoint::Lending(entrypoint),
        lending_shape(selector),
        gas,
        fee,
        &["lending", "risk", "private-position"],
    )
}

fn perps_case(
    id: &str,
    entrypoint: PerpsEntrypoint,
    selector: &str,
    family: FuzzFamily,
    gas: &str,
    fee: &str,
) -> FuzzCase {
    standard_case(
        id,
        family,
        ContractKind::Perps,
        selector,
        Entrypoint::Perps(entrypoint),
        perps_shape(selector),
        gas,
        fee,
        &["perps", "margin", "funding"],
    )
}

fn router_case(
    id: &str,
    entrypoint: RouterEntrypoint,
    selector: &str,
    family: FuzzFamily,
    gas: &str,
    fee: &str,
) -> FuzzCase {
    standard_case(
        id,
        family,
        ContractKind::Router,
        selector,
        Entrypoint::Router(entrypoint),
        router_shape(selector),
        gas,
        fee,
        &["router", "multicall", "callback"],
    )
}

fn oracle_case(
    id: &str,
    entrypoint: OracleEntrypoint,
    selector: &str,
    family: FuzzFamily,
    gas: &str,
    fee: &str,
) -> FuzzCase {
    standard_case(
        id,
        family,
        ContractKind::Oracle,
        selector,
        Entrypoint::Oracle(entrypoint),
        oracle_shape(selector),
        gas,
        fee,
        &["oracle", "aggregate", "twap"],
    )
}

fn factory_case(
    id: &str,
    entrypoint: FactoryEntrypoint,
    selector: &str,
    family: FuzzFamily,
    gas: &str,
    fee: &str,
) -> FuzzCase {
    standard_case(
        id,
        family,
        ContractKind::DeploymentFactory,
        selector,
        Entrypoint::Factory(entrypoint),
        deployment_constructor_shape(),
        gas,
        fee,
        &["factory", "safe-deployment", "gate"],
    )
}

fn standard_case(
    id: &str,
    family: FuzzFamily,
    contract_kind: ContractKind,
    selector: &str,
    entrypoint: Entrypoint,
    calldata_shape: CalldataShape,
    gas: &str,
    fee: &str,
    tags: &[&str],
) -> FuzzCase {
    let mut tag_set = BTreeSet::new();
    for tag in tags {
        tag_set.insert((*tag).to_string());
    }
    tag_set.insert(format!("{family:?}").to_lowercase());
    FuzzCase {
        id: id.to_string(),
        title: title_from_id(id),
        family,
        contract_kind,
        selector: selector.to_string(),
        entrypoint,
        calldata_shape,
        pq_seed: seed_for(id),
        expected_privacy: PrivacyExpectation {
            no_public_amounts: true,
            no_public_addresses: true,
            unique_nullifiers: true,
            no_callback_plaintext: true,
            receipt_root_only: true,
        },
        expected_gas_bucket: gas.to_string(),
        expected_fee_bucket: fee.to_string(),
        tags: tag_set,
    }
}

fn token_shape(selector: &str) -> CalldataShape {
    shape(
        160,
        3_200,
        &["asset_id", "amount_ciphertext", "owner_commitment", "nonce"],
        &["public_amount", "public_owner"],
        &["amount_ciphertext"],
        &["asset_id", "owner_commitment"],
        &["spend_nullifier"],
        selector == "token.rotate_viewing_key",
        false,
    )
}

fn amm_shape(_selector: &str) -> CalldataShape {
    shape(
        240,
        5_600,
        &[
            "pool_id",
            "amount_in_ciphertext",
            "min_out_commitment",
            "nonce",
        ],
        &["public_amount", "public_trader"],
        &["amount_in_ciphertext", "path_ciphertext"],
        &["pool_id", "min_out_commitment"],
        &["swap_nullifier"],
        false,
        false,
    )
}

fn lending_shape(_selector: &str) -> CalldataShape {
    shape(
        256,
        6_400,
        &[
            "market_id",
            "account_commitment",
            "amount_ciphertext",
            "risk_proof",
        ],
        &["public_collateral", "public_borrower"],
        &["amount_ciphertext", "risk_proof"],
        &["market_id", "account_commitment"],
        &["position_nullifier"],
        false,
        false,
    )
}

fn perps_shape(_selector: &str) -> CalldataShape {
    shape(
        320,
        8_192,
        &[
            "market_id",
            "position_commitment",
            "margin_ciphertext",
            "leverage_commitment",
            "risk_proof",
        ],
        &["public_margin", "public_trader", "public_leverage"],
        &["margin_ciphertext", "risk_proof"],
        &["market_id", "position_commitment", "leverage_commitment"],
        &["position_nullifier"],
        false,
        false,
    )
}

fn router_shape(_selector: &str) -> CalldataShape {
    shape(
        384,
        12_288,
        &["route_commitment", "hop_count", "aggregate_proof", "nonce"],
        &["public_route", "public_amount", "public_recipient"],
        &["aggregate_proof", "hop_ciphertext"],
        &["route_commitment"],
        &["route_nullifier"],
        false,
        false,
    )
}

fn oracle_shape(_selector: &str) -> CalldataShape {
    shape(
        128,
        4_096,
        &[
            "oracle_set",
            "price_commitment",
            "round_id",
            "signature_bundle",
        ],
        &["public_reporter"],
        &["signature_bundle"],
        &["oracle_set", "price_commitment"],
        &["round_nullifier"],
        true,
        false,
    )
}

fn deployment_constructor_shape() -> CalldataShape {
    shape(
        192,
        10_240,
        &[
            "bytecode_commitment",
            "abi_commitment",
            "deployer_commitment",
            "salt",
        ],
        &["public_deployer", "debug_plaintext"],
        &["constructor_args_ciphertext"],
        &[
            "bytecode_commitment",
            "abi_commitment",
            "deployer_commitment",
        ],
        &["deployment_nullifier"],
        false,
        false,
    )
}

fn shape(
    min_bytes: usize,
    max_bytes: usize,
    required: &[&str],
    forbidden: &[&str],
    encrypted: &[&str],
    commitments: &[&str],
    nullifiers: &[&str],
    allow_public_amounts: bool,
    allow_public_addresses: bool,
) -> CalldataShape {
    CalldataShape {
        min_bytes,
        max_bytes,
        required_fields: set(required),
        forbidden_fields: set(forbidden),
        encrypted_fields: set(encrypted),
        commitment_fields: set(commitments),
        nullifier_fields: set(nullifiers),
        allow_public_amounts,
        allow_public_addresses,
    }
}

fn set(items: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in items {
        out.insert((*item).to_string());
    }
    out
}

fn seed_for(id: &str) -> PqSignedSeed {
    PqSignedSeed {
        seed_id: format!("seed-{id}"),
        domain: PROTOCOL_VERSION.to_string(),
        public_key_commitment: stable_hash(&format!("pq-pk:{id}")),
        public_key_len: 1_312,
        signature_commitment: stable_hash(&format!("pq-sig:{id}")),
        signature_len: 2_420,
        message_commitment: stable_hash(&format!("pq-msg:{id}")),
        algorithm: PqAlgorithm::HybridEd25519MlDsa65,
    }
}

fn request_from_case(case: &FuzzCase, contract_id: &str) -> FuzzRequest {
    let calldata = calldata_from_shape(&case.selector, &case.calldata_shape, &case.id);
    FuzzRequest {
        request_id: stable_hash(&format!("request:{}", case.id)),
        contract_id: contract_id.to_string(),
        case_id: case.id.clone(),
        caller_commitment: stable_hash(&format!("caller:{}", case.id)),
        entrypoint: case.entrypoint.clone(),
        calldata,
        pq_seed: case.pq_seed.clone(),
        gas_limit: match case.expected_gas_bucket.as_str() {
            "tiny" => 25_000,
            "small" => 90_000,
            "medium" => 300_000,
            "large" => 900_000,
            "stress" => 3_000_000,
            _other => 500_000,
        },
        fee_limit_atomic: match case.expected_fee_bucket.as_str() {
            "dust" => 10_000,
            "retail" => 250_000,
            "desk" => 2_000_000,
            "stress" => 25_000_000,
            _other => 500_000,
        },
        callback: None,
        differential_target: Some("reference-private-l2".to_string()),
    }
}

fn calldata_from_shape(selector: &str, shape: &CalldataShape, salt: &str) -> ConfidentialCalldata {
    let mut fields = BTreeMap::new();
    for field in &shape.required_fields {
        let visibility = if shape.encrypted_fields.contains(field) {
            FieldVisibility::Confidential
        } else if shape.nullifier_fields.contains(field) {
            FieldVisibility::Nullifier
        } else {
            FieldVisibility::CommitmentOnly
        };
        let kind = infer_field_kind(field);
        fields.insert(
            field.clone(),
            CalldataField {
                visibility,
                kind,
                commitment: stable_hash(&format!("field:{salt}:{field}")),
                byte_len: 32,
            },
        );
    }
    for field in &shape.encrypted_fields {
        if !fields.contains_key(field) {
            fields.insert(
                field.clone(),
                CalldataField {
                    visibility: FieldVisibility::Confidential,
                    kind: infer_field_kind(field),
                    commitment: stable_hash(&format!("encrypted:{salt}:{field}")),
                    byte_len: 96,
                },
            );
        }
    }
    for field in &shape.nullifier_fields {
        if !fields.contains_key(field) {
            fields.insert(
                field.clone(),
                CalldataField {
                    visibility: FieldVisibility::Nullifier,
                    kind: FieldKind::Nonce,
                    commitment: stable_hash(&format!("nullifier:{salt}:{field}")),
                    byte_len: 32,
                },
            );
        }
    }
    ConfidentialCalldata {
        encoded_len: bounded_len(shape.min_bytes, shape.max_bytes),
        domain_separator: PROTOCOL_VERSION.to_string(),
        selector: selector.to_string(),
        fields,
        transcript_commitment: stable_hash(&format!("transcript:{salt}:{selector}")),
        nullifiers: shape
            .nullifier_fields
            .iter()
            .map(|field| stable_hash(&format!("nf:{salt}:{field}")))
            .collect(),
    }
}

fn infer_field_kind(field: &str) -> FieldKind {
    if field.contains("address") || field.contains("owner") || field.contains("account") {
        FieldKind::Address
    } else if field.contains("amount") || field.contains("margin") || field.contains("collateral") {
        FieldKind::Amount
    } else if field.contains("price") {
        FieldKind::Price
    } else if field.contains("leverage") {
        FieldKind::Leverage
    } else if field.contains("pool") {
        FieldKind::PoolId
    } else if field.contains("market") || field.contains("asset") {
        FieldKind::TokenId
    } else if field.contains("nonce") || field.contains("nullifier") || field.contains("salt") {
        FieldKind::Nonce
    } else if field.contains("deadline") {
        FieldKind::Deadline
    } else if field.contains("proof") || field.contains("signature") {
        FieldKind::Proof
    } else {
        FieldKind::Bytes
    }
}

fn bounded_len(min: usize, max: usize) -> usize {
    let midpoint = min.saturating_add(max).saturating_div(2);
    if midpoint < min {
        min
    } else if midpoint > max {
        max
    } else {
        midpoint
    }
}

fn validate_calldata_shape(
    calldata: &ConfidentialCalldata,
    shape: &CalldataShape,
    require_domain_separator: bool,
    strict: bool,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if calldata.encoded_len < shape.min_bytes {
        reasons.push("calldata is shorter than required minimum".to_string());
    }
    if calldata.encoded_len > shape.max_bytes {
        reasons.push("calldata is longer than shape maximum".to_string());
    }
    if require_domain_separator && calldata.domain_separator != PROTOCOL_VERSION {
        reasons.push("calldata domain separator is missing or mismatched".to_string());
    }
    for field in &shape.required_fields {
        if !calldata.fields.contains_key(field) {
            reasons.push(format!("required calldata field {field} is missing"));
        }
    }
    for field in &shape.forbidden_fields {
        if calldata.fields.contains_key(field) {
            reasons.push(format!("forbidden calldata field {field} is present"));
        }
    }
    for field in &shape.encrypted_fields {
        match calldata.fields.get(field) {
            Some(value) if value.visibility == FieldVisibility::Confidential => {}
            Some(_value) => reasons.push(format!("field {field} must be confidential")),
            None => {
                if strict {
                    reasons.push(format!("encrypted field {field} is absent"));
                }
            }
        }
    }
    for field in &shape.commitment_fields {
        match calldata.fields.get(field) {
            Some(value)
                if value.visibility == FieldVisibility::CommitmentOnly
                    || value.visibility == FieldVisibility::Confidential => {}
            Some(_value) => reasons.push(format!("field {field} must be commitment-bearing")),
            None => {
                if strict {
                    reasons.push(format!("commitment field {field} is absent"));
                }
            }
        }
    }
    for field in &shape.nullifier_fields {
        if !calldata
            .nullifiers
            .iter()
            .any(|item| looks_like_commitment(item))
        {
            reasons.push(format!(
                "nullifier field {field} has no valid nullifier commitment"
            ));
        }
    }
    if !shape.allow_public_amounts && contains_public_kind(calldata, FieldKind::Amount) {
        reasons.push("calldata exposes a public amount".to_string());
    }
    if !shape.allow_public_addresses && contains_public_kind(calldata, FieldKind::Address) {
        reasons.push("calldata exposes a public address".to_string());
    }
    if has_duplicate_nullifier(&calldata.nullifiers) {
        reasons.push("calldata contains duplicate nullifier commitments".to_string());
    }
    for (name, field) in &calldata.fields {
        if !looks_like_commitment(&field.commitment) {
            reasons.push(format!("field {name} commitment is malformed"));
        }
        if field.byte_len == 0 {
            reasons.push(format!("field {name} has empty byte length"));
        }
    }
    reasons
}

fn validate_privacy_expectation(
    calldata: &ConfidentialCalldata,
    callback: Option<&CallbackEnvelope>,
    expected: &PrivacyExpectation,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if expected.no_public_amounts && contains_public_kind(calldata, FieldKind::Amount) {
        reasons.push("privacy expectation forbids public amounts".to_string());
    }
    if expected.no_public_addresses && contains_public_kind(calldata, FieldKind::Address) {
        reasons.push("privacy expectation forbids public addresses".to_string());
    }
    if expected.unique_nullifiers && has_duplicate_nullifier(&calldata.nullifiers) {
        reasons.push("privacy expectation requires unique nullifiers".to_string());
    }
    if expected.no_callback_plaintext {
        if let Some(envelope) = callback {
            if has_public_sensitive_fields(&envelope.calldata) {
                reasons.push("callback leaks sensitive plaintext fields".to_string());
            }
        }
    }
    reasons
}

fn contains_public_kind(calldata: &ConfidentialCalldata, kind: FieldKind) -> bool {
    calldata
        .fields
        .values()
        .any(|field| field.visibility == FieldVisibility::Public && field.kind == kind)
}

fn has_public_sensitive_fields(calldata: &ConfidentialCalldata) -> bool {
    calldata.fields.values().any(|field| {
        field.visibility == FieldVisibility::Public
            && matches!(
                field.kind,
                FieldKind::Address
                    | FieldKind::Amount
                    | FieldKind::Price
                    | FieldKind::Leverage
                    | FieldKind::TokenId
                    | FieldKind::PoolId
            )
    })
}

fn has_duplicate_nullifier(nullifiers: &BTreeSet<String>) -> bool {
    let mut seen = BTreeSet::new();
    for nullifier in nullifiers {
        if !seen.insert(nullifier.clone()) {
            return true;
        }
    }
    false
}

fn looks_like_commitment(value: &str) -> bool {
    value.len() >= 16 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn exceeds_bps(value: u64, baseline: u64, bps: u32) -> bool {
    if baseline == 0 {
        value > 0
    } else {
        let allowed = baseline.saturating_add(baseline.saturating_mul(bps as u64) / 10_000);
        value > allowed
    }
}

fn bucket_midpoint(buckets: &[GasBucket], limit: u64) -> u64 {
    for bucket in buckets {
        if limit >= bucket.min && limit <= bucket.max {
            return bucket.min.saturating_add(bucket.max).saturating_div(2);
        }
    }
    limit.saturating_div(2)
}

fn bucket_fee_midpoint(buckets: &[FeeBucket], limit: u64) -> u64 {
    for bucket in buckets {
        if limit >= bucket.min_atomic && limit <= bucket.max_atomic {
            return bucket
                .min_atomic
                .saturating_add(bucket.max_atomic)
                .saturating_div(2);
        }
    }
    limit.saturating_div(2)
}

fn catalog_digest(catalog: &BTreeMap<String, FuzzCase>) -> String {
    let mut out = String::new();
    for (id, case) in catalog {
        out.push_str(id);
        out.push(':');
        out.push_str(&case.selector);
        out.push(':');
        out.push_str(&format!("{:?}", case.family));
        out.push(';');
    }
    out
}

fn requests_digest(requests: &VecDeque<FuzzRequest>) -> String {
    let mut out = String::new();
    for request in requests {
        out.push_str(&request.request_id);
        out.push(':');
        out.push_str(&request.case_id);
        out.push(':');
        out.push_str(&request.calldata.transcript_commitment);
        out.push(';');
    }
    out
}

fn receipts_digest(receipts: &[ExecutionReceipt]) -> String {
    let mut out = String::new();
    for receipt in receipts {
        out.push_str(&receipt.request_id);
        out.push(':');
        out.push_str(&receipt.receipt_root);
        out.push(':');
        out.push_str(&receipt.confidential_state_delta_commitment);
        out.push(';');
    }
    out
}

fn deployments_digest(deployments: &BTreeMap<String, DeploymentRecord>) -> String {
    let mut out = String::new();
    for (id, deployment) in deployments {
        out.push_str(id);
        out.push(':');
        out.push_str(if deployment.accepted {
            "accepted"
        } else {
            "rejected"
        });
        out.push(':');
        out.push_str(&format!("{:?}", deployment.contract_kind));
        out.push(';');
    }
    out
}

fn summaries_digest(summaries: &[OperatorPublicSummary]) -> String {
    let mut out = String::new();
    for summary in summaries {
        out.push_str(&summary.sequence.to_string());
        out.push(':');
        out.push_str(&summary.roots.state_root);
        out.push(';');
    }
    out
}

fn stable_hash(input: &str) -> String {
    let mut a: u64 = 0x243f_6a88_85a3_08d3;
    let mut b: u64 = 0x1319_8a2e_0370_7344;
    let mut c: u64 = 0xa409_3822_299f_31d0;
    let mut d: u64 = 0x082e_fa98_ec4e_6c89;
    for byte in input.as_bytes() {
        a = a.rotate_left(5) ^ (*byte as u64);
        b = b.wrapping_add(a ^ 0x9e37_79b9_7f4a_7c15);
        c ^= b.rotate_left(17).wrapping_add(*byte as u64);
        d = d.wrapping_mul(0x1000_0000_01b3).wrapping_add(c);
    }
    format!("{a:016x}{b:016x}{c:016x}{d:016x}")
}

fn title_from_id(id: &str) -> String {
    let mut title = String::new();
    for part in id.split('-') {
        if !title.is_empty() {
            title.push(' ');
        }
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            title.push(first.to_ascii_uppercase());
            for ch in chars {
                title.push(ch);
            }
        }
    }
    title
}

fn value_string(value: &Value, key: &str) -> String {
    if let Some(text) = value.get(key).and_then(Value::as_str) {
        text.to_string()
    } else {
        String::new()
    }
}

fn value_vec_strings(value: &Value, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(items) = value.get(key).and_then(Value::as_array) {
        for item in items {
            if let Some(text) = item.as_str() {
                out.push(text.to_string());
            }
        }
    }
    out
}
