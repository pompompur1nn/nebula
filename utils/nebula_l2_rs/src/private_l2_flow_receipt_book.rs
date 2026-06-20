use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash as stable_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;

pub const PRIVATE_L2_FLOW_RECEIPT_BOOK_PROTOCOL_VERSION: &str =
    "nebula-private-l2-flow-receipt-book-v1";
pub const PRIVATE_L2_FLOW_RECEIPT_BOOK_DEVNET_HEIGHT: u64 = 52_000;
pub const PRIVATE_L2_FLOW_RECEIPT_BOOK_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_L2_FLOW_RECEIPT_BOOK_PQ_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-flow";
pub const PRIVATE_L2_FLOW_RECEIPT_BOOK_PROOF_SUITE: &str = "recursive-pq-zk-private-flow-v1";
pub const PRIVATE_L2_FLOW_RECEIPT_BOOK_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_L2_FLOW_RECEIPT_BOOK_MAX_STAGE_COUNT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStageKind {
    TokenMint,
    ContractCall,
    AmmSwap,
    ProofAggregation,
    FeeSponsorship,
    MoneroExit,
}

impl FlowStageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenMint => "token_mint",
            Self::ContractCall => "contract_call",
            Self::AmmSwap => "amm_swap",
            Self::ProofAggregation => "proof_aggregation",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::MoneroExit => "monero_exit",
        }
    }

    pub fn canonical_order(self) -> u64 {
        match self {
            Self::TokenMint => 10,
            Self::ContractCall => 20,
            Self::AmmSwap => 30,
            Self::ProofAggregation => 40,
            Self::FeeSponsorship => 50,
            Self::MoneroExit => 60,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStatus {
    Open,
    Finalized,
    Rejected,
}

impl FlowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub devnet_height: u64,
    pub min_privacy_set_size: u64,
    pub max_stage_count: usize,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub proof_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            devnet_height: PRIVATE_L2_FLOW_RECEIPT_BOOK_DEVNET_HEIGHT,
            min_privacy_set_size: PRIVATE_L2_FLOW_RECEIPT_BOOK_MIN_PRIVACY_SET_SIZE,
            max_stage_count: PRIVATE_L2_FLOW_RECEIPT_BOOK_MAX_STAGE_COUNT,
            hash_suite: PRIVATE_L2_FLOW_RECEIPT_BOOK_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_FLOW_RECEIPT_BOOK_PQ_AUTH_SUITE.to_string(),
            proof_suite: PRIVATE_L2_FLOW_RECEIPT_BOOK_PROOF_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "devnet_height": self.devnet_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_stage_count": self.max_stage_count,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "proof_suite": self.proof_suite,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_privacy_set_size == 0 || self.max_stage_count == 0 {
            return Err(
                "private flow receipt book privacy and stage limits must be positive".into(),
            );
        }
        if self.hash_suite.is_empty()
            || self.pq_auth_suite.is_empty()
            || self.proof_suite.is_empty()
        {
            return Err("private flow receipt book suite labels must be populated".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub opened_flows: u64,
    pub appended_stages: u64,
    pub finalized_flows: u64,
    pub rejected_flows: u64,
    pub monero_exit_receipts: u64,
    pub sponsored_fee_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "opened_flows": self.opened_flows,
            "appended_stages": self.appended_stages,
            "finalized_flows": self.finalized_flows,
            "rejected_flows": self.rejected_flows,
            "monero_exit_receipts": self.monero_exit_receipts,
            "sponsored_fee_units": self.sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStageReceipt {
    pub stage_id: String,
    pub flow_id: String,
    pub sequence: u64,
    pub kind: FlowStageKind,
    pub action_commitment: String,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub proof_public_input_root: String,
    pub recursive_proof_root: String,
    pub fee_commitment: String,
    pub sponsor_commitment: Option<String>,
    pub monero_anchor_root: Option<String>,
    pub privacy_set_size: u64,
    pub observed_height: u64,
}

impl FlowStageReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flow_id: &str,
        sequence: u64,
        kind: FlowStageKind,
        action_commitment: &str,
        input_nullifier_root: &str,
        output_commitment_root: &str,
        proof_public_input_root: &str,
        recursive_proof_root: &str,
        fee_commitment: &str,
        sponsor_commitment: Option<String>,
        monero_anchor_root: Option<String>,
        privacy_set_size: u64,
        observed_height: u64,
    ) -> Result<Self> {
        require_commitment("flow id", flow_id)?;
        require_commitment("action commitment", action_commitment)?;
        require_commitment("input nullifier root", input_nullifier_root)?;
        require_commitment("output commitment root", output_commitment_root)?;
        require_commitment("proof public input root", proof_public_input_root)?;
        require_commitment("recursive proof root", recursive_proof_root)?;
        require_commitment("fee commitment", fee_commitment)?;

        let stage_id = flow_hash(
            "STAGE-ID",
            &[
                HashPart::Str(flow_id),
                HashPart::Int(sequence as i128),
                HashPart::Str(kind.as_str()),
                HashPart::Str(action_commitment),
            ],
        );
        Ok(Self {
            stage_id,
            flow_id: flow_id.to_string(),
            sequence,
            kind,
            action_commitment: action_commitment.to_string(),
            input_nullifier_root: input_nullifier_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            proof_public_input_root: proof_public_input_root.to_string(),
            recursive_proof_root: recursive_proof_root.to_string(),
            fee_commitment: fee_commitment.to_string(),
            sponsor_commitment,
            monero_anchor_root,
            privacy_set_size,
            observed_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "stage_id": self.stage_id,
            "flow_id": self.flow_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "action_commitment": self.action_commitment,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "proof_public_input_root": self.proof_public_input_root,
            "recursive_proof_root": self.recursive_proof_root,
            "fee_commitment": self.fee_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "monero_anchor_root": self.monero_anchor_root,
            "privacy_set_size": self.privacy_set_size,
            "observed_height": self.observed_height,
            "stage_root": self.stage_root(),
        })
    }

    pub fn stage_root(&self) -> String {
        flow_record_root("STAGE-ROOT", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "stage_id": self.stage_id,
            "flow_id": self.flow_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "action_commitment": self.action_commitment,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "proof_public_input_root": self.proof_public_input_root,
            "recursive_proof_root": self.recursive_proof_root,
            "fee_commitment": self.fee_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "monero_anchor_root": self.monero_anchor_root,
            "privacy_set_size": self.privacy_set_size,
            "observed_height": self.observed_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFlowReceipt {
    pub flow_id: String,
    pub opener_commitment: String,
    pub flow_commitment: String,
    pub entry_nullifier_root: String,
    pub expected_exit_commitment: String,
    pub status: FlowStatus,
    pub opened_height: u64,
    pub finalized_height: Option<u64>,
    pub stages: Vec<FlowStageReceipt>,
    pub final_receipt_root: Option<String>,
}

impl PrivateFlowReceipt {
    pub fn new(
        opener_commitment: &str,
        flow_commitment: &str,
        entry_nullifier_root: &str,
        expected_exit_commitment: &str,
        opened_height: u64,
    ) -> Result<Self> {
        require_commitment("opener commitment", opener_commitment)?;
        require_commitment("flow commitment", flow_commitment)?;
        require_commitment("entry nullifier root", entry_nullifier_root)?;
        require_commitment("expected exit commitment", expected_exit_commitment)?;
        let flow_id = flow_hash(
            "FLOW-ID",
            &[
                HashPart::Str(opener_commitment),
                HashPart::Str(flow_commitment),
                HashPart::Str(entry_nullifier_root),
                HashPart::Int(opened_height as i128),
            ],
        );
        Ok(Self {
            flow_id,
            opener_commitment: opener_commitment.to_string(),
            flow_commitment: flow_commitment.to_string(),
            entry_nullifier_root: entry_nullifier_root.to_string(),
            expected_exit_commitment: expected_exit_commitment.to_string(),
            status: FlowStatus::Open,
            opened_height,
            finalized_height: None,
            stages: Vec::new(),
            final_receipt_root: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "flow_id": self.flow_id,
            "opener_commitment": self.opener_commitment,
            "flow_commitment": self.flow_commitment,
            "entry_nullifier_root": self.entry_nullifier_root,
            "expected_exit_commitment": self.expected_exit_commitment,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "finalized_height": self.finalized_height,
            "stage_count": self.stages.len(),
            "stage_root": self.stage_root(),
            "final_receipt_root": self.final_receipt_root,
            "receipt_root": self.receipt_root(),
        })
    }

    pub fn receipt_root(&self) -> String {
        flow_record_root("FLOW-RECEIPT-ROOT", &self.public_record_without_root())
    }

    pub fn stage_root(&self) -> String {
        let leaves = self
            .stages
            .iter()
            .map(FlowStageReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("PRIVATE-L2-FLOW-STAGES", &leaves)
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "flow_id": self.flow_id,
            "opener_commitment": self.opener_commitment,
            "flow_commitment": self.flow_commitment,
            "entry_nullifier_root": self.entry_nullifier_root,
            "expected_exit_commitment": self.expected_exit_commitment,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "finalized_height": self.finalized_height,
            "stage_count": self.stages.len(),
            "stage_root": self.stage_root(),
            "final_receipt_root": self.final_receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub flows: BTreeMap<String, PrivateFlowReceipt>,
    pub spent_nullifier_roots: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            flows: BTreeMap::new(),
            spent_nullifier_roots: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_public_records();
        state
    }

    pub fn open_flow(
        &mut self,
        opener_commitment: &str,
        flow_commitment: &str,
        entry_nullifier_root: &str,
        expected_exit_commitment: &str,
        opened_height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        if self.spent_nullifier_roots.contains(entry_nullifier_root) {
            return Err("private flow entry nullifier root was already consumed".into());
        }
        let flow = PrivateFlowReceipt::new(
            opener_commitment,
            flow_commitment,
            entry_nullifier_root,
            expected_exit_commitment,
            opened_height,
        )?;
        let flow_id = flow.flow_id.clone();
        self.spent_nullifier_roots
            .insert(entry_nullifier_root.to_string());
        self.flows.insert(flow_id.clone(), flow);
        self.counters.opened_flows += 1;
        self.refresh_public_records();
        Ok(flow_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_stage(
        &mut self,
        flow_id: &str,
        kind: FlowStageKind,
        action_commitment: &str,
        input_nullifier_root: &str,
        output_commitment_root: &str,
        proof_public_input_root: &str,
        recursive_proof_root: &str,
        fee_commitment: &str,
        sponsor_commitment: Option<String>,
        monero_anchor_root: Option<String>,
        privacy_set_size: u64,
        observed_height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("private flow stage privacy set is below configured minimum".into());
        }
        if self.spent_nullifier_roots.contains(input_nullifier_root) {
            return Err("private flow stage input nullifier root was already consumed".into());
        }
        let flow = self
            .flows
            .get_mut(flow_id)
            .ok_or_else(|| "private flow receipt not found".to_string())?;
        if flow.status != FlowStatus::Open {
            return Err("private flow receipt is not open".into());
        }
        if flow.stages.len() >= self.config.max_stage_count {
            return Err("private flow receipt exceeded configured stage limit".into());
        }
        if let Some(previous) = flow.stages.last() {
            if kind.canonical_order() < previous.kind.canonical_order() {
                return Err("private flow stage order cannot move backwards".into());
            }
        }
        if kind == FlowStageKind::MoneroExit && monero_anchor_root.is_none() {
            return Err("monero exit stage requires a Monero anchor root".into());
        }

        let sequence = flow.stages.len() as u64;
        let stage = FlowStageReceipt::new(
            flow_id,
            sequence,
            kind,
            action_commitment,
            input_nullifier_root,
            output_commitment_root,
            proof_public_input_root,
            recursive_proof_root,
            fee_commitment,
            sponsor_commitment,
            monero_anchor_root,
            privacy_set_size,
            observed_height,
        )?;
        let stage_id = stage.stage_id.clone();
        flow.stages.push(stage);
        self.spent_nullifier_roots
            .insert(input_nullifier_root.to_string());
        self.counters.appended_stages += 1;
        if kind == FlowStageKind::FeeSponsorship {
            self.counters.sponsored_fee_units += 1;
        }
        if kind == FlowStageKind::MoneroExit {
            self.counters.monero_exit_receipts += 1;
        }
        self.refresh_public_records();
        Ok(stage_id)
    }

    pub fn finalize_flow(
        &mut self,
        flow_id: &str,
        final_receipt_root: &str,
        finalized_height: u64,
    ) -> Result<String> {
        require_commitment("final receipt root", final_receipt_root)?;
        let flow = self
            .flows
            .get_mut(flow_id)
            .ok_or_else(|| "private flow receipt not found".to_string())?;
        if flow.status != FlowStatus::Open {
            return Err("private flow receipt is not open".into());
        }
        let kinds = flow
            .stages
            .iter()
            .map(|stage| stage.kind)
            .collect::<BTreeSet<_>>();
        for required in [
            FlowStageKind::TokenMint,
            FlowStageKind::ContractCall,
            FlowStageKind::AmmSwap,
            FlowStageKind::ProofAggregation,
            FlowStageKind::FeeSponsorship,
            FlowStageKind::MoneroExit,
        ] {
            if !kinds.contains(&required) {
                return Err(format!(
                    "private flow receipt is missing required {} stage",
                    required.as_str()
                ));
            }
        }
        flow.status = FlowStatus::Finalized;
        flow.finalized_height = Some(finalized_height);
        flow.final_receipt_root = Some(final_receipt_root.to_string());
        self.counters.finalized_flows += 1;
        let receipt_root = flow.receipt_root();
        self.refresh_public_records();
        Ok(receipt_root)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("state record is object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        private_l2_flow_receipt_book_state_root_from_record(&self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        let flow_records = self
            .flows
            .values()
            .map(PrivateFlowReceipt::public_record)
            .collect::<Vec<_>>();
        let public_record_leaves = self
            .public_records
            .iter()
            .map(|(key, value)| json!({"key": key, "record": value}))
            .collect::<Vec<_>>();
        json!({
            "protocol_version": PRIVATE_L2_FLOW_RECEIPT_BOOK_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "flow_count": self.flows.len(),
            "open_flow_count": self.flows.values().filter(|flow| flow.status == FlowStatus::Open).count(),
            "finalized_flow_count": self.flows.values().filter(|flow| flow.status == FlowStatus::Finalized).count(),
            "flow_root": merkle_root("PRIVATE-L2-FLOW-RECEIPTS", &flow_records),
            "nullifier_registry_root": merkle_root(
                "PRIVATE-L2-FLOW-NULLIFIERS",
                &self.spent_nullifier_roots.iter().map(|root| json!(root)).collect::<Vec<_>>(),
            ),
            "public_record_root": merkle_root("PRIVATE-L2-FLOW-PUBLIC-RECORDS", &public_record_leaves),
        })
    }

    fn refresh_public_records(&mut self) {
        self.public_records.clear();
        self.public_records
            .insert("config".to_string(), self.config.public_record());
        self.public_records
            .insert("counters".to_string(), self.counters.public_record());
        for flow in self.flows.values() {
            self.public_records
                .insert(format!("flow:{}", flow.flow_id), flow.public_record());
            for stage in &flow.stages {
                self.public_records.insert(
                    format!("stage:{}:{}", flow.flow_id, stage.sequence),
                    stage.public_record(),
                );
            }
        }
    }
}

pub fn private_l2_flow_receipt_book_state_root_from_record(record: &Value) -> String {
    flow_record_root("STATE-ROOT", record)
}

pub fn private_l2_flow_receipt_book_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_flow_receipt_book_devnet() -> State {
    State::devnet()
}

fn flow_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    stable_hash(&format!("PRIVATE-L2-FLOW-RECEIPT-BOOK:{domain}"), parts, 32)
}

fn flow_record_root(domain: &str, record: &Value) -> String {
    flow_hash(domain, &[HashPart::Json(record)])
}

fn require_commitment(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("private flow {label} must be populated"));
    }
    Ok(())
}
