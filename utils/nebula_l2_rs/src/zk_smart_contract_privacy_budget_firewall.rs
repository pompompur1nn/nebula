use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ZkSmartContractPrivacyBudgetFirewallResult<T> = Result<T, String>;

pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_PROTOCOL_VERSION: &str =
    "nebula-zk-smart-contract-privacy-budget-firewall-v1";
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_MIN_ANONYMITY_SET: u64 = 128;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_MAX_LEAKAGE_SCORE: u64 = 2_500;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_MAX_EVENT_BUDGET: u64 = 64;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_MAX_DISCLOSURE_BUDGET: u64 = 16;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_FREEZE_TTL_BLOCKS: u64 = 96;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_SCORE: u64 = 10_000;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_CONTRACTS: usize = 1_024;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_CALLS: usize = 4_096;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_POLICIES: usize = 1_024;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_FREEZES: usize = 512;
pub const ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEVNET_HEIGHT: u64 = 82_900;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractPrivacyClass {
    ShieldedTransfer,
    ConfidentialTokenHook,
    PrivateAmm,
    PrivateLending,
    PrivateGovernance,
    BridgeSettlement,
}

impl ContractPrivacyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedTransfer => "shielded_transfer",
            Self::ConfidentialTokenHook => "confidential_token_hook",
            Self::PrivateAmm => "private_amm",
            Self::PrivateLending => "private_lending",
            Self::PrivateGovernance => "private_governance",
            Self::BridgeSettlement => "bridge_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureMode {
    None,
    SelectiveAudit,
    AggregateOnly,
    DelayedEvent,
    EmergencyReveal,
}

impl DisclosureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SelectiveAudit => "selective_audit",
            Self::AggregateOnly => "aggregate_only",
            Self::DelayedEvent => "delayed_event",
            Self::EmergencyReveal => "emergency_reveal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDecision {
    Allow,
    Delay,
    RequireAggregation,
    RequireFreshProof,
    FreezeContract,
}

impl FirewallDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Delay => "delay",
            Self::RequireAggregation => "require_aggregation",
            Self::RequireFreshProof => "require_fresh_proof",
            Self::FreezeContract => "freeze_contract",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub min_anonymity_set: u64,
    pub max_leakage_score: u64,
    pub max_event_budget: u64,
    pub max_disclosure_budget: u64,
    pub freeze_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            min_anonymity_set: ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_MIN_ANONYMITY_SET,
            max_leakage_score: ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_MAX_LEAKAGE_SCORE,
            max_event_budget: ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_MAX_EVENT_BUDGET,
            max_disclosure_budget:
                ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_MAX_DISCLOSURE_BUDGET,
            freeze_ttl_blocks: ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEFAULT_FREEZE_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> ZkSmartContractPrivacyBudgetFirewallResult<()> {
        if self.min_anonymity_set == 0
            || self.max_event_budget == 0
            || self.max_disclosure_budget == 0
            || self.freeze_ttl_blocks == 0
        {
            return Err("privacy firewall limits must be positive".to_string());
        }
        if self.max_leakage_score > ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_SCORE {
            return Err("privacy leakage score cap cannot exceed score scale".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_smart_contract_privacy_budget_firewall_config",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_PROTOCOL_VERSION,
            "min_anonymity_set": self.min_anonymity_set,
            "max_leakage_score": self.max_leakage_score,
            "max_event_budget": self.max_event_budget,
            "max_disclosure_budget": self.max_disclosure_budget,
            "freeze_ttl_blocks": self.freeze_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractPolicy {
    pub policy_id: String,
    pub contract_id: String,
    pub privacy_class: ContractPrivacyClass,
    pub allowed_disclosures: BTreeSet<DisclosureMode>,
    pub event_budget: u64,
    pub disclosure_budget: u64,
    pub min_anonymity_set: u64,
    pub policy_root: String,
}

impl ContractPolicy {
    pub fn new(
        contract_id: &str,
        privacy_class: ContractPrivacyClass,
        allowed_disclosures: BTreeSet<DisclosureMode>,
        event_budget: u64,
        disclosure_budget: u64,
        min_anonymity_set: u64,
        policy: &Value,
    ) -> ZkSmartContractPrivacyBudgetFirewallResult<Self> {
        if contract_id.is_empty() {
            return Err("contract policy contract id cannot be empty".to_string());
        }
        if allowed_disclosures.is_empty() {
            return Err("contract policy disclosures cannot be empty".to_string());
        }
        if event_budget == 0 || disclosure_budget == 0 || min_anonymity_set == 0 {
            return Err("contract policy budgets must be positive".to_string());
        }
        let policy_root =
            zk_smart_contract_privacy_firewall_payload_root("ZK-CONTRACT-PRIVACY-POLICY", policy);
        let policy_id = contract_policy_id(
            contract_id,
            privacy_class,
            &allowed_disclosures,
            event_budget,
            disclosure_budget,
            min_anonymity_set,
            &policy_root,
        );
        Ok(Self {
            policy_id,
            contract_id: contract_id.to_string(),
            privacy_class,
            allowed_disclosures,
            event_budget,
            disclosure_budget,
            min_anonymity_set,
            policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_smart_contract_privacy_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "privacy_class": self.privacy_class.as_str(),
            "allowed_disclosures": self.allowed_disclosures.iter().map(|mode| mode.as_str()).collect::<Vec<_>>(),
            "event_budget": self.event_budget,
            "disclosure_budget": self.disclosure_budget,
            "min_anonymity_set": self.min_anonymity_set,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallBudget {
    pub call_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub calldata_root: String,
    pub event_count: u64,
    pub disclosure_count: u64,
    pub anonymity_set: u64,
    pub leakage_score: u64,
    pub requested_disclosure: DisclosureMode,
    pub submitted_at_height: u64,
}

impl ContractCallBudget {
    pub fn new(
        contract_id: &str,
        caller_commitment: &str,
        calldata: &Value,
        event_count: u64,
        disclosure_count: u64,
        anonymity_set: u64,
        leakage_score: u64,
        requested_disclosure: DisclosureMode,
        submitted_at_height: u64,
    ) -> ZkSmartContractPrivacyBudgetFirewallResult<Self> {
        if contract_id.is_empty() || caller_commitment.is_empty() {
            return Err("contract call budget identifiers cannot be empty".to_string());
        }
        if leakage_score > ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_SCORE {
            return Err("contract call leakage score cannot exceed score scale".to_string());
        }
        let calldata_root = zk_smart_contract_privacy_firewall_payload_root(
            "ZK-CONTRACT-PRIVACY-CALLDATA",
            calldata,
        );
        let call_id = contract_call_budget_id(
            contract_id,
            caller_commitment,
            &calldata_root,
            event_count,
            disclosure_count,
            anonymity_set,
            leakage_score,
            requested_disclosure,
            submitted_at_height,
        );
        Ok(Self {
            call_id,
            contract_id: contract_id.to_string(),
            caller_commitment: caller_commitment.to_string(),
            calldata_root,
            event_count,
            disclosure_count,
            anonymity_set,
            leakage_score,
            requested_disclosure,
            submitted_at_height,
        })
    }

    pub fn decision(
        &self,
        policy: &ContractPolicy,
        config: &Config,
        frozen: bool,
    ) -> FirewallDecision {
        if frozen {
            FirewallDecision::FreezeContract
        } else if self.anonymity_set < config.min_anonymity_set
            || self.anonymity_set < policy.min_anonymity_set
        {
            FirewallDecision::RequireAggregation
        } else if self.leakage_score > config.max_leakage_score {
            FirewallDecision::RequireFreshProof
        } else if self.event_count > policy.event_budget
            || self.event_count > config.max_event_budget
        {
            FirewallDecision::Delay
        } else if self.disclosure_count > policy.disclosure_budget
            || self.disclosure_count > config.max_disclosure_budget
            || !policy
                .allowed_disclosures
                .contains(&self.requested_disclosure)
        {
            FirewallDecision::RequireFreshProof
        } else {
            FirewallDecision::Allow
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_smart_contract_call_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_PROTOCOL_VERSION,
            "call_id": self.call_id,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "calldata_root": self.calldata_root,
            "event_count": self.event_count,
            "disclosure_count": self.disclosure_count,
            "anonymity_set": self.anonymity_set,
            "leakage_score": self.leakage_score,
            "requested_disclosure": self.requested_disclosure.as_str(),
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallReceipt {
    pub receipt_id: String,
    pub call_id: String,
    pub contract_id: String,
    pub decision: FirewallDecision,
    pub reason_root: String,
    pub height: u64,
}

impl FirewallReceipt {
    pub fn new(
        call_id: &str,
        contract_id: &str,
        decision: FirewallDecision,
        reason: &Value,
        height: u64,
    ) -> ZkSmartContractPrivacyBudgetFirewallResult<Self> {
        if call_id.is_empty() || contract_id.is_empty() {
            return Err("firewall receipt identifiers cannot be empty".to_string());
        }
        let reason_root = zk_smart_contract_privacy_firewall_payload_root(
            "ZK-CONTRACT-PRIVACY-DECISION-REASON",
            reason,
        );
        let receipt_id = firewall_receipt_id(call_id, contract_id, decision, &reason_root, height);
        Ok(Self {
            receipt_id,
            call_id: call_id.to_string(),
            contract_id: contract_id.to_string(),
            decision,
            reason_root,
            height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_smart_contract_privacy_firewall_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "call_id": self.call_id,
            "contract_id": self.contract_id,
            "decision": self.decision.as_str(),
            "reason_root": self.reason_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractFreeze {
    pub freeze_id: String,
    pub contract_id: String,
    pub proof_root: String,
    pub reason_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
}

impl ContractFreeze {
    pub fn new(
        contract_id: &str,
        proof: &Value,
        reason: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
    ) -> ZkSmartContractPrivacyBudgetFirewallResult<Self> {
        if contract_id.is_empty() {
            return Err("contract freeze contract id cannot be empty".to_string());
        }
        if expires_at_height <= starts_at_height {
            return Err("contract freeze must expire after it starts".to_string());
        }
        let proof_root = zk_smart_contract_privacy_firewall_payload_root(
            "ZK-CONTRACT-PRIVACY-FREEZE-PROOF",
            proof,
        );
        let reason_root = zk_smart_contract_privacy_firewall_payload_root(
            "ZK-CONTRACT-PRIVACY-FREEZE-REASON",
            reason,
        );
        let freeze_id = contract_freeze_id(
            contract_id,
            &proof_root,
            &reason_root,
            starts_at_height,
            expires_at_height,
        );
        Ok(Self {
            freeze_id,
            contract_id: contract_id.to_string(),
            proof_root,
            reason_root,
            starts_at_height,
            expires_at_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.starts_at_height <= height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_smart_contract_privacy_freeze",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_PROTOCOL_VERSION,
            "freeze_id": self.freeze_id,
            "contract_id": self.contract_id,
            "proof_root": self.proof_root,
            "reason_root": self.reason_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub policy_root: String,
    pub call_root: String,
    pub receipt_root: String,
    pub freeze_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "policy_root": self.policy_root,
            "call_root": self.call_root,
            "receipt_root": self.receipt_root,
            "freeze_root": self.freeze_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub policy_count: u64,
    pub call_count: u64,
    pub receipt_count: u64,
    pub freeze_count: u64,
    pub allowed_count: u64,
    pub delayed_count: u64,
    pub fresh_proof_count: u64,
    pub aggregation_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_count": self.policy_count,
            "call_count": self.call_count,
            "receipt_count": self.receipt_count,
            "freeze_count": self.freeze_count,
            "allowed_count": self.allowed_count,
            "delayed_count": self.delayed_count,
            "fresh_proof_count": self.fresh_proof_count,
            "aggregation_count": self.aggregation_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub policies: BTreeMap<String, ContractPolicy>,
    pub calls: BTreeMap<String, ContractCallBudget>,
    pub receipts: BTreeMap<String, FirewallReceipt>,
    pub freezes: BTreeMap<String, ContractFreeze>,
    pub roots: Roots,
    pub counters: Counters,
    pub state_root: String,
}

impl State {
    pub fn new(height: u64, config: Config) -> ZkSmartContractPrivacyBudgetFirewallResult<Self> {
        config.validate()?;
        let mut state = Self {
            height,
            config,
            policies: BTreeMap::new(),
            calls: BTreeMap::new(),
            receipts: BTreeMap::new(),
            freezes: BTreeMap::new(),
            roots: Roots {
                config_root: String::new(),
                policy_root: String::new(),
                call_root: String::new(),
                receipt_root: String::new(),
                freeze_root: String::new(),
            },
            counters: Counters {
                policy_count: 0,
                call_count: 0,
                receipt_count: 0,
                freeze_count: 0,
                allowed_count: 0,
                delayed_count: 0,
                fresh_proof_count: 0,
                aggregation_count: 0,
            },
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn insert_policy(
        &mut self,
        policy: ContractPolicy,
    ) -> ZkSmartContractPrivacyBudgetFirewallResult<()> {
        if self.policies.len() >= ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_POLICIES {
            return Err("contract policy limit exceeded".to_string());
        }
        if policy.event_budget > self.config.max_event_budget {
            return Err("contract policy event budget exceeds configured cap".to_string());
        }
        if policy.disclosure_budget > self.config.max_disclosure_budget {
            return Err("contract policy disclosure budget exceeds configured cap".to_string());
        }
        self.policies.insert(policy.policy_id.clone(), policy);
        self.refresh();
        Ok(())
    }

    pub fn insert_call(
        &mut self,
        call: ContractCallBudget,
    ) -> ZkSmartContractPrivacyBudgetFirewallResult<()> {
        if self.calls.len() >= ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_CALLS {
            return Err("contract call budget limit exceeded".to_string());
        }
        if self.policy_for_contract(&call.contract_id).is_none() {
            return Err("contract call references contract with no privacy policy".to_string());
        }
        self.calls.insert(call.call_id.clone(), call);
        self.refresh();
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: FirewallReceipt,
    ) -> ZkSmartContractPrivacyBudgetFirewallResult<()> {
        if !self.calls.contains_key(&receipt.call_id) {
            return Err("firewall receipt references unknown call".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.refresh();
        Ok(())
    }

    pub fn insert_freeze(
        &mut self,
        freeze: ContractFreeze,
    ) -> ZkSmartContractPrivacyBudgetFirewallResult<()> {
        if self.freezes.len() >= ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_MAX_FREEZES {
            return Err("contract freeze limit exceeded".to_string());
        }
        self.freezes.insert(freeze.freeze_id.clone(), freeze);
        self.refresh();
        Ok(())
    }

    pub fn policy_for_contract(&self, contract_id: &str) -> Option<&ContractPolicy> {
        self.policies
            .values()
            .find(|policy| policy.contract_id == contract_id)
    }

    pub fn contract_is_frozen(&self, contract_id: &str) -> bool {
        self.freezes
            .values()
            .any(|freeze| freeze.contract_id == contract_id && freeze.active_at(self.height))
    }

    pub fn evaluate_call(
        &self,
        call: &ContractCallBudget,
    ) -> ZkSmartContractPrivacyBudgetFirewallResult<FirewallReceipt> {
        let Some(policy) = self.policy_for_contract(&call.contract_id) else {
            return Err("cannot evaluate call without privacy policy".to_string());
        };
        let frozen = self.contract_is_frozen(&call.contract_id);
        let decision = call.decision(policy, &self.config, frozen);
        FirewallReceipt::new(
            &call.call_id,
            &call.contract_id,
            decision,
            &json!({
                "contract_id": call.contract_id,
                "leakage_score": call.leakage_score,
                "anonymity_set": call.anonymity_set,
                "requested_disclosure": call.requested_disclosure.as_str(),
                "frozen": frozen,
            }),
            self.height,
        )
    }

    pub fn evaluate_pending(&mut self) -> ZkSmartContractPrivacyBudgetFirewallResult<Vec<String>> {
        let mut created = Vec::new();
        let calls = self.calls.values().cloned().collect::<Vec<_>>();
        for call in calls {
            if self
                .receipts
                .values()
                .any(|receipt| receipt.call_id == call.call_id)
            {
                continue;
            }
            let receipt = self.evaluate_call(&call)?;
            created.push(receipt.receipt_id.clone());
            self.insert_receipt(receipt)?;
        }
        Ok(created)
    }

    pub fn refresh(&mut self) {
        self.roots = Roots {
            config_root: zk_smart_contract_privacy_firewall_payload_root(
                "ZK-CONTRACT-PRIVACY-CONFIG",
                &self.config.public_record(),
            ),
            policy_root: contract_policy_root(&self.policies.values().cloned().collect::<Vec<_>>()),
            call_root: contract_call_budget_root(&self.calls.values().cloned().collect::<Vec<_>>()),
            receipt_root: firewall_receipt_root(
                &self.receipts.values().cloned().collect::<Vec<_>>(),
            ),
            freeze_root: contract_freeze_root(&self.freezes.values().cloned().collect::<Vec<_>>()),
        };
        self.counters = Counters {
            policy_count: self.policies.len() as u64,
            call_count: self.calls.len() as u64,
            receipt_count: self.receipts.len() as u64,
            freeze_count: self.freezes.len() as u64,
            allowed_count: self
                .receipts
                .values()
                .filter(|receipt| receipt.decision == FirewallDecision::Allow)
                .count() as u64,
            delayed_count: self
                .receipts
                .values()
                .filter(|receipt| receipt.decision == FirewallDecision::Delay)
                .count() as u64,
            fresh_proof_count: self
                .receipts
                .values()
                .filter(|receipt| receipt.decision == FirewallDecision::RequireFreshProof)
                .count() as u64,
            aggregation_count: self
                .receipts
                .values()
                .filter(|receipt| receipt.decision == FirewallDecision::RequireAggregation)
                .count() as u64,
        };
        self.state_root = root_from_record(&self.public_record_without_state_root());
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "zk_smart_contract_privacy_budget_firewall_state",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_PROTOCOL_VERSION,
            "height": self.height,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }

    pub fn devnet() -> ZkSmartContractPrivacyBudgetFirewallResult<Self> {
        let mut state = Self::new(
            ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEVNET_HEIGHT,
            Config::devnet(),
        )?;
        let mut disclosures = BTreeSet::new();
        disclosures.insert(DisclosureMode::None);
        disclosures.insert(DisclosureMode::AggregateOnly);
        let policy = ContractPolicy::new(
            "private-amm-contract-devnet",
            ContractPrivacyClass::PrivateAmm,
            disclosures,
            32,
            8,
            256,
            &json!({"private_events": true, "cross_contract_leakage": "bounded"}),
        )?;
        state.insert_policy(policy.clone())?;
        state.insert_call(ContractCallBudget::new(
            &policy.contract_id,
            "caller-commitment-a",
            &json!({"selector": "swap_private", "route_root": "route-a"}),
            12,
            3,
            384,
            1_200,
            DisclosureMode::AggregateOnly,
            ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEVNET_HEIGHT,
        )?)?;
        state.insert_call(ContractCallBudget::new(
            &policy.contract_id,
            "caller-commitment-b",
            &json!({"selector": "swap_private", "route_root": "route-b"}),
            80,
            9,
            64,
            3_200,
            DisclosureMode::SelectiveAudit,
            ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_DEVNET_HEIGHT,
        )?)?;
        state.evaluate_pending()?;
        Ok(state)
    }
}

pub fn contract_policy_id(
    contract_id: &str,
    privacy_class: ContractPrivacyClass,
    allowed_disclosures: &BTreeSet<DisclosureMode>,
    event_budget: u64,
    disclosure_budget: u64,
    min_anonymity_set: u64,
    policy_root: &str,
) -> String {
    let disclosures = allowed_disclosures
        .iter()
        .map(|mode| mode.as_str())
        .collect::<Vec<_>>()
        .join(",");
    domain_hash(
        "ZK-CONTRACT-PRIVACY-POLICY-ID",
        &[
            HashPart::Str(ZK_SMART_CONTRACT_PRIVACY_BUDGET_FIREWALL_PROTOCOL_VERSION),
            HashPart::Str(contract_id),
            HashPart::Str(privacy_class.as_str()),
            HashPart::Str(&disclosures),
            HashPart::Int(event_budget as i128),
            HashPart::Int(disclosure_budget as i128),
            HashPart::Int(min_anonymity_set as i128),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn contract_call_budget_id(
    contract_id: &str,
    caller_commitment: &str,
    calldata_root: &str,
    event_count: u64,
    disclosure_count: u64,
    anonymity_set: u64,
    leakage_score: u64,
    requested_disclosure: DisclosureMode,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-PRIVACY-CALL-BUDGET-ID",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(caller_commitment),
            HashPart::Str(calldata_root),
            HashPart::Int(event_count as i128),
            HashPart::Int(disclosure_count as i128),
            HashPart::Int(anonymity_set as i128),
            HashPart::Int(leakage_score as i128),
            HashPart::Str(requested_disclosure.as_str()),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn firewall_receipt_id(
    call_id: &str,
    contract_id: &str,
    decision: FirewallDecision,
    reason_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-PRIVACY-FIREWALL-RECEIPT-ID",
        &[
            HashPart::Str(call_id),
            HashPart::Str(contract_id),
            HashPart::Str(decision.as_str()),
            HashPart::Str(reason_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn contract_freeze_id(
    contract_id: &str,
    proof_root: &str,
    reason_root: &str,
    starts_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-PRIVACY-FREEZE-ID",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(proof_root),
            HashPart::Str(reason_root),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn contract_policy_root(policies: &[ContractPolicy]) -> String {
    let leaves = policies
        .iter()
        .map(ContractPolicy::public_record)
        .collect::<Vec<_>>();
    merkle_root("ZK-CONTRACT-PRIVACY-POLICIES", &leaves)
}

pub fn contract_call_budget_root(calls: &[ContractCallBudget]) -> String {
    let leaves = calls
        .iter()
        .map(ContractCallBudget::public_record)
        .collect::<Vec<_>>();
    merkle_root("ZK-CONTRACT-PRIVACY-CALLS", &leaves)
}

pub fn firewall_receipt_root(receipts: &[FirewallReceipt]) -> String {
    let leaves = receipts
        .iter()
        .map(FirewallReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("ZK-CONTRACT-PRIVACY-RECEIPTS", &leaves)
}

pub fn contract_freeze_root(freezes: &[ContractFreeze]) -> String {
    let leaves = freezes
        .iter()
        .map(ContractFreeze::public_record)
        .collect::<Vec<_>>();
    merkle_root("ZK-CONTRACT-PRIVACY-FREEZES", &leaves)
}

pub fn zk_smart_contract_privacy_firewall_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "ZK-SMART-CONTRACT-PRIVACY-BUDGET-FIREWALL-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> ZkSmartContractPrivacyBudgetFirewallResult<State> {
    State::devnet()
}
