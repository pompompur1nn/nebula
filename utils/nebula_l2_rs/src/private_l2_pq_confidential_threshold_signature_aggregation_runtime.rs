use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const RUNTIME_NAME: &str = "private_l2_pq_confidential_threshold_signature_aggregation_runtime";
pub const RUNTIME_VERSION: u32 = 1;
pub const DEFAULT_EPOCH: u64 = 7;
pub const DEFAULT_ROUND: u64 = 1;
pub const DEFAULT_CHAIN_ID: u64 = 31337;
pub const DEFAULT_L2_CHAIN_ID: u64 = 731337;
pub const DEFAULT_SHARD_COUNT: u16 = 8;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 16;
pub const DEFAULT_THRESHOLD: u16 = 11;
pub const DEFAULT_WATCHER_THRESHOLD: u16 = 7;
pub const DEFAULT_RELEASE_THRESHOLD: u16 = 9;
pub const DEFAULT_CONTRACT_THRESHOLD: u16 = 8;
pub const DEFAULT_BATCH_VERIFY_LIMIT: u16 = 128;
pub const DEFAULT_MAX_CALL_BYTES: u32 = 4096;
pub const DEFAULT_MAX_MEMO_BYTES: u32 = 512;
pub const DEFAULT_MAX_PROOF_BYTES: u32 = 8192;
pub const DEFAULT_MAX_AGGREGATE_BYTES: u32 = 16384;
pub const DEFAULT_LOW_FEE_MICRONERO: u64 = 1700;
pub const DEFAULT_HIGH_FEE_MICRONERO: u64 = 7700;
pub const DEFAULT_BRIDGE_LIMIT_ATOMIC: u128 = 5_000_000_000_000;
pub const DEFAULT_RELEASE_LIMIT_ATOMIC: u128 = 2_000_000_000_000;
pub const DEFAULT_CALL_LIMIT_ATOMIC: u128 = 250_000_000_000;
pub const ROOT_PREFIX: &str = "nebula:l2:pq-confidential-threshold";
pub const DOMAIN_CONFIG: &str = "config";
pub const DOMAIN_STATE: &str = "state";
pub const DOMAIN_COUNTERS: &str = "counters";
pub const DOMAIN_REQUEST: &str = "request";
pub const DOMAIN_RECORD: &str = "record";
pub const DOMAIN_AGGREGATE: &str = "aggregate";
pub const DOMAIN_RELEASE_GATE: &str = "release-gate";
pub const DOMAIN_BRIDGE_WATCH: &str = "bridge-watch";
pub const DOMAIN_CONTRACT_CALL: &str = "contract-call";
pub const DOMAIN_BATCH_VERIFY: &str = "batch-verify";
pub const DOMAIN_SEQUENCER: &str = "sequencer";
pub const DOMAIN_PUBLIC: &str = "public";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_ACCEPTED: &str = "accepted";
pub const STATUS_REJECTED: &str = "rejected";
pub const STATUS_RELEASED: &str = "released";
pub const STATUS_QUARANTINED: &str = "quarantined";
pub const ROLE_SEQUENCER: &str = "sequencer";
pub const ROLE_WATCHER: &str = "bridge_watcher";
pub const ROLE_CONTRACT: &str = "contract_caller";
pub const ROLE_RELEASE: &str = "release_gate";
pub const ROLE_BATCH: &str = "batch_verifier";
pub const PQ_SCHEME_DILITHIUM: &str = "dilithium5";
pub const PQ_SCHEME_FALCON: &str = "falcon1024";
pub const PQ_SCHEME_SPHINCS: &str = "sphincs-shake-256f";
pub const CONFIDENTIAL_COMMITMENT: &str = "pedersen-plus-viewtag";
pub const NULLIFIER_DOMAIN: &str = "nebula-nullifier-v1";
pub const FEE_CLASS_LOW: &str = "low";
pub const FEE_CLASS_STANDARD: &str = "standard";
pub const FEE_CLASS_RELEASE: &str = "release";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub network: String,
    pub chain_id: u64,
    pub l2_chain_id: u64,
    pub epoch: u64,
    pub round: u64,
    pub shard_count: u16,
    pub committee_size: u16,
    pub sequencer_threshold: u16,
    pub watcher_threshold: u16,
    pub release_threshold: u16,
    pub contract_threshold: u16,
    pub batch_verify_limit: u16,
    pub max_call_bytes: u32,
    pub max_memo_bytes: u32,
    pub max_proof_bytes: u32,
    pub max_aggregate_bytes: u32,
    pub low_fee_micronero: u64,
    pub high_fee_micronero: u64,
    pub bridge_limit_atomic: u128,
    pub release_limit_atomic: u128,
    pub call_limit_atomic: u128,
    pub pq_schemes: Vec<String>,
    pub confidential_commitment: String,
    pub deterministic_salt: String,
    pub allow_release_gate_fast_path: bool,
    pub allow_low_fee_batching: bool,
    pub require_watcher_quorum: bool,
    pub require_contract_receipt: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            network: "devnet".to_string(),
            chain_id: DEFAULT_CHAIN_ID,
            l2_chain_id: DEFAULT_L2_CHAIN_ID,
            epoch: DEFAULT_EPOCH,
            round: DEFAULT_ROUND,
            shard_count: DEFAULT_SHARD_COUNT,
            committee_size: DEFAULT_COMMITTEE_SIZE,
            sequencer_threshold: DEFAULT_THRESHOLD,
            watcher_threshold: DEFAULT_WATCHER_THRESHOLD,
            release_threshold: DEFAULT_RELEASE_THRESHOLD,
            contract_threshold: DEFAULT_CONTRACT_THRESHOLD,
            batch_verify_limit: DEFAULT_BATCH_VERIFY_LIMIT,
            max_call_bytes: DEFAULT_MAX_CALL_BYTES,
            max_memo_bytes: DEFAULT_MAX_MEMO_BYTES,
            max_proof_bytes: DEFAULT_MAX_PROOF_BYTES,
            max_aggregate_bytes: DEFAULT_MAX_AGGREGATE_BYTES,
            low_fee_micronero: DEFAULT_LOW_FEE_MICRONERO,
            high_fee_micronero: DEFAULT_HIGH_FEE_MICRONERO,
            bridge_limit_atomic: DEFAULT_BRIDGE_LIMIT_ATOMIC,
            release_limit_atomic: DEFAULT_RELEASE_LIMIT_ATOMIC,
            call_limit_atomic: DEFAULT_CALL_LIMIT_ATOMIC,
            pq_schemes: vec![
                PQ_SCHEME_DILITHIUM.to_string(),
                PQ_SCHEME_FALCON.to_string(),
                PQ_SCHEME_SPHINCS.to_string(),
            ],
            confidential_commitment: CONFIDENTIAL_COMMITMENT.to_string(),
            deterministic_salt: "devnet-confidential-threshold-salt".to_string(),
            allow_release_gate_fast_path: true,
            allow_low_fee_batching: true,
            require_watcher_quorum: true,
            require_contract_receipt: true,
        }
    }

    pub fn threshold_for_kind(&self, kind: RequestKind) -> u16 {
        match kind {
            RequestKind::SequencerBlock => self.sequencer_threshold,
            RequestKind::BridgeWatch => self.watcher_threshold,
            RequestKind::ContractCall => self.contract_threshold,
            RequestKind::ReleaseGate => self.release_threshold,
            RequestKind::BatchVerify => self.watcher_threshold,
        }
    }

    pub fn root(&self) -> String {
        stable_root(
            DOMAIN_CONFIG,
            &[
                &self.network,
                &self.chain_id.to_string(),
                &self.l2_chain_id.to_string(),
                &self.epoch.to_string(),
                &self.round.to_string(),
                &self.shard_count.to_string(),
                &self.committee_size.to_string(),
                &self.sequencer_threshold.to_string(),
                &self.watcher_threshold.to_string(),
                &self.release_threshold.to_string(),
                &self.contract_threshold.to_string(),
                &self.batch_verify_limit.to_string(),
                &self.max_call_bytes.to_string(),
                &self.max_memo_bytes.to_string(),
                &self.max_proof_bytes.to_string(),
                &self.max_aggregate_bytes.to_string(),
                &self.low_fee_micronero.to_string(),
                &self.high_fee_micronero.to_string(),
                &self.bridge_limit_atomic.to_string(),
                &self.release_limit_atomic.to_string(),
                &self.call_limit_atomic.to_string(),
                &self.pq_schemes.join(","),
                &self.confidential_commitment,
                &self.deterministic_salt,
                &self.allow_release_gate_fast_path.to_string(),
                &self.allow_low_fee_batching.to_string(),
                &self.require_watcher_quorum.to_string(),
                &self.require_contract_receipt.to_string(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum RequestKind {
    SequencerBlock,
    BridgeWatch,
    ContractCall,
    ReleaseGate,
    BatchVerify,
}

impl RequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerBlock => DOMAIN_SEQUENCER,
            Self::BridgeWatch => DOMAIN_BRIDGE_WATCH,
            Self::ContractCall => DOMAIN_CONTRACT_CALL,
            Self::ReleaseGate => DOMAIN_RELEASE_GATE,
            Self::BatchVerify => DOMAIN_BATCH_VERIFY,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub requests: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub quarantined: u64,
    pub release_gates: u64,
    pub bridge_watches: u64,
    pub contract_calls: u64,
    pub sequencer_blocks: u64,
    pub batch_verifications: u64,
    pub aggregate_signatures: u64,
    pub low_fee_batches: u64,
    pub total_fee_micronero: u128,
    pub total_value_atomic: u128,
    pub total_call_bytes: u128,
    pub total_proof_bytes: u128,
}

impl Counters {
    pub fn record_request(&mut self, request: &ThresholdRequest) {
        self.requests = self.requests.saturating_add(1);
        self.total_fee_micronero = self
            .total_fee_micronero
            .saturating_add(request.fee_micronero as u128);
        self.total_value_atomic = self.total_value_atomic.saturating_add(request.value_atomic);
        self.total_call_bytes = self
            .total_call_bytes
            .saturating_add(request.call_bytes as u128);
        self.total_proof_bytes = self
            .total_proof_bytes
            .saturating_add(request.proof_bytes as u128);
        match request.kind {
            RequestKind::SequencerBlock => {
                self.sequencer_blocks = self.sequencer_blocks.saturating_add(1);
            }
            RequestKind::BridgeWatch => {
                self.bridge_watches = self.bridge_watches.saturating_add(1);
            }
            RequestKind::ContractCall => {
                self.contract_calls = self.contract_calls.saturating_add(1);
            }
            RequestKind::ReleaseGate => {
                self.release_gates = self.release_gates.saturating_add(1);
            }
            RequestKind::BatchVerify => {
                self.batch_verifications = self.batch_verifications.saturating_add(1);
            }
        }
    }

    pub fn record_status(&mut self, status: &str) {
        match status {
            STATUS_ACCEPTED | STATUS_RELEASED => {
                self.accepted = self.accepted.saturating_add(1);
            }
            STATUS_REJECTED => {
                self.rejected = self.rejected.saturating_add(1);
            }
            STATUS_QUARANTINED => {
                self.quarantined = self.quarantined.saturating_add(1);
            }
            _ => {}
        }
    }

    pub fn root(&self) -> String {
        stable_root(
            DOMAIN_COUNTERS,
            &[
                &self.requests.to_string(),
                &self.accepted.to_string(),
                &self.rejected.to_string(),
                &self.quarantined.to_string(),
                &self.release_gates.to_string(),
                &self.bridge_watches.to_string(),
                &self.contract_calls.to_string(),
                &self.sequencer_blocks.to_string(),
                &self.batch_verifications.to_string(),
                &self.aggregate_signatures.to_string(),
                &self.low_fee_batches.to_string(),
                &self.total_fee_micronero.to_string(),
                &self.total_value_atomic.to_string(),
                &self.total_call_bytes.to_string(),
                &self.total_proof_bytes.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub committee_root: String,
    pub request_root: String,
    pub record_root: String,
    pub aggregate_root: String,
    pub release_root: String,
    pub watcher_root: String,
    pub contract_root: String,
    pub batch_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn recompute(config: &Config, counters: &Counters, records: &[ThresholdRecord]) -> Self {
        let config_root = config.root();
        let committee_root = committee_root(&config.network, config.epoch, config.committee_size);
        let request_root = list_root(
            DOMAIN_REQUEST,
            records.iter().map(|record| record.request_root.as_str()),
        );
        let record_root = list_root(
            DOMAIN_RECORD,
            records.iter().map(|record| record.record_root.as_str()),
        );
        let aggregate_root = list_root(
            DOMAIN_AGGREGATE,
            records.iter().map(|record| record.aggregate_root.as_str()),
        );
        let release_root = list_root(
            DOMAIN_RELEASE_GATE,
            records
                .iter()
                .filter(|record| record.kind == RequestKind::ReleaseGate)
                .map(|record| record.record_root.as_str()),
        );
        let watcher_root = list_root(
            DOMAIN_BRIDGE_WATCH,
            records
                .iter()
                .filter(|record| record.kind == RequestKind::BridgeWatch)
                .map(|record| record.record_root.as_str()),
        );
        let contract_root = list_root(
            DOMAIN_CONTRACT_CALL,
            records
                .iter()
                .filter(|record| record.kind == RequestKind::ContractCall)
                .map(|record| record.record_root.as_str()),
        );
        let batch_root = list_root(
            DOMAIN_BATCH_VERIFY,
            records
                .iter()
                .filter(|record| record.kind == RequestKind::BatchVerify)
                .map(|record| record.record_root.as_str()),
        );
        let counter_root = counters.root();
        let state_root = stable_root(
            DOMAIN_STATE,
            &[
                &config_root,
                &committee_root,
                &request_root,
                &record_root,
                &aggregate_root,
                &release_root,
                &watcher_root,
                &contract_root,
                &batch_root,
                &counter_root,
            ],
        );
        Self {
            config_root,
            committee_root,
            request_root,
            record_root,
            aggregate_root,
            release_root,
            watcher_root,
            contract_root,
            batch_root,
            counter_root,
            state_root,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdRequest {
    pub id: String,
    pub kind: RequestKind,
    pub shard: u16,
    pub epoch: u64,
    pub round: u64,
    pub account_commitment: String,
    pub nullifier: String,
    pub payload_commitment: String,
    pub memo_commitment: String,
    pub view_tag: String,
    pub destination: String,
    pub contract_selector: String,
    pub value_atomic: u128,
    pub fee_micronero: u64,
    pub call_bytes: u32,
    pub proof_bytes: u32,
    pub requested_signers: Vec<String>,
    pub watcher_attestations: Vec<String>,
    pub release_gate: Option<String>,
}

impl ThresholdRequest {
    pub fn sequencer(id: &str, shard: u16, value_atomic: u128) -> Self {
        Self::new(
            id,
            RequestKind::SequencerBlock,
            shard,
            value_atomic,
            DEFAULT_LOW_FEE_MICRONERO,
            384,
            2048,
        )
    }

    pub fn bridge_watch(id: &str, shard: u16, value_atomic: u128) -> Self {
        Self::new(
            id,
            RequestKind::BridgeWatch,
            shard,
            value_atomic,
            DEFAULT_LOW_FEE_MICRONERO,
            192,
            3072,
        )
    }

    pub fn contract_call(id: &str, shard: u16, value_atomic: u128) -> Self {
        Self::new(
            id,
            RequestKind::ContractCall,
            shard,
            value_atomic,
            DEFAULT_HIGH_FEE_MICRONERO,
            1024,
            4096,
        )
    }

    pub fn release_gate(id: &str, shard: u16, value_atomic: u128) -> Self {
        let mut request = Self::new(
            id,
            RequestKind::ReleaseGate,
            shard,
            value_atomic,
            DEFAULT_HIGH_FEE_MICRONERO,
            160,
            4096,
        );
        request.release_gate = Some(deterministic_label("release", id, shard));
        request
    }

    pub fn batch_verify(id: &str, shard: u16, value_atomic: u128) -> Self {
        Self::new(
            id,
            RequestKind::BatchVerify,
            shard,
            value_atomic,
            DEFAULT_LOW_FEE_MICRONERO,
            256,
            6144,
        )
    }

    pub fn new(
        id: &str,
        kind: RequestKind,
        shard: u16,
        value_atomic: u128,
        fee_micronero: u64,
        call_bytes: u32,
        proof_bytes: u32,
    ) -> Self {
        let signer_count = match kind {
            RequestKind::SequencerBlock => DEFAULT_THRESHOLD,
            RequestKind::BridgeWatch => DEFAULT_WATCHER_THRESHOLD,
            RequestKind::ContractCall => DEFAULT_CONTRACT_THRESHOLD,
            RequestKind::ReleaseGate => DEFAULT_RELEASE_THRESHOLD,
            RequestKind::BatchVerify => DEFAULT_WATCHER_THRESHOLD,
        };
        Self {
            id: id.to_string(),
            kind,
            shard,
            epoch: DEFAULT_EPOCH,
            round: DEFAULT_ROUND,
            account_commitment: deterministic_label("account", id, shard),
            nullifier: deterministic_label(NULLIFIER_DOMAIN, id, shard),
            payload_commitment: deterministic_label("payload", id, shard),
            memo_commitment: deterministic_label("memo", id, shard),
            view_tag: deterministic_label("view", id, shard),
            destination: deterministic_label("destination", id, shard),
            contract_selector: deterministic_label(kind.as_str(), id, shard),
            value_atomic,
            fee_micronero,
            call_bytes,
            proof_bytes,
            requested_signers: signer_set(kind.as_str(), signer_count),
            watcher_attestations: watcher_set(id, shard, DEFAULT_WATCHER_THRESHOLD),
            release_gate: None,
        }
    }

    pub fn root(&self) -> String {
        stable_root(
            DOMAIN_REQUEST,
            &[
                &self.id,
                self.kind.as_str(),
                &self.shard.to_string(),
                &self.epoch.to_string(),
                &self.round.to_string(),
                &self.account_commitment,
                &self.nullifier,
                &self.payload_commitment,
                &self.memo_commitment,
                &self.view_tag,
                &self.destination,
                &self.contract_selector,
                &self.value_atomic.to_string(),
                &self.fee_micronero.to_string(),
                &self.call_bytes.to_string(),
                &self.proof_bytes.to_string(),
                &self.requested_signers.join(","),
                &self.watcher_attestations.join(","),
                match self.release_gate.as_deref() {
                    Some(release_gate) => release_gate,
                    None => "none",
                },
            ],
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureShare {
    pub signer_id: String,
    pub scheme: String,
    pub public_key_commitment: String,
    pub share_commitment: String,
    pub response_commitment: String,
    pub weight: u16,
    pub accepted: bool,
}

impl SignatureShare {
    pub fn deterministic(role: &str, index: u16, request_root: &str, accepted: bool) -> Self {
        let signer_id = format!("{}-{:02}", role, index);
        let scheme = match index % 3 {
            0 => PQ_SCHEME_DILITHIUM,
            1 => PQ_SCHEME_FALCON,
            _ => PQ_SCHEME_SPHINCS,
        };
        Self {
            signer_id: signer_id.clone(),
            scheme: scheme.to_string(),
            public_key_commitment: stable_root("pk", &[role, &index.to_string(), request_root]),
            share_commitment: stable_root("share", &[role, &index.to_string(), request_root]),
            response_commitment: stable_root("response", &[role, &index.to_string(), request_root]),
            weight: 1,
            accepted,
        }
    }

    pub fn root(&self) -> String {
        stable_root(
            "signature-share",
            &[
                &self.signer_id,
                &self.scheme,
                &self.public_key_commitment,
                &self.share_commitment,
                &self.response_commitment,
                &self.weight.to_string(),
                &self.accepted.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateSignature {
    pub request_root: String,
    pub aggregate_root: String,
    pub scheme_mix_root: String,
    pub participant_root: String,
    pub transcript_root: String,
    pub share_count: u16,
    pub threshold: u16,
    pub accepted_weight: u16,
    pub low_fee_batch: bool,
}

impl AggregateSignature {
    pub fn from_shares(
        request: &ThresholdRequest,
        threshold: u16,
        shares: &[SignatureShare],
    ) -> Self {
        let request_root = request.root();
        let participant_root = list_root(
            "participants",
            shares.iter().map(|share| share.signer_id.as_str()),
        );
        let share_roots: Vec<String> = shares.iter().map(SignatureShare::root).collect();
        let transcript_root = list_root("transcript", share_roots.iter().map(String::as_str));
        let scheme_mix_root =
            list_root("schemes", shares.iter().map(|share| share.scheme.as_str()));
        let accepted_weight = shares
            .iter()
            .filter(|share| share.accepted)
            .fold(0u16, |total, share| total.saturating_add(share.weight));
        let low_fee_batch = request.fee_micronero <= DEFAULT_LOW_FEE_MICRONERO
            && matches!(
                request.kind,
                RequestKind::BatchVerify | RequestKind::BridgeWatch | RequestKind::SequencerBlock
            );
        let aggregate_root = stable_root(
            DOMAIN_AGGREGATE,
            &[
                &request_root,
                &participant_root,
                &transcript_root,
                &scheme_mix_root,
                &shares.len().to_string(),
                &threshold.to_string(),
                &accepted_weight.to_string(),
                &low_fee_batch.to_string(),
            ],
        );
        Self {
            request_root,
            aggregate_root,
            scheme_mix_root,
            participant_root,
            transcript_root,
            share_count: saturating_u16(shares.len()),
            threshold,
            accepted_weight,
            low_fee_batch,
        }
    }

    pub fn passes_threshold(&self) -> bool {
        self.accepted_weight >= self.threshold
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdRecord {
    pub request_id: String,
    pub kind: RequestKind,
    pub status: String,
    pub reason: String,
    pub request_root: String,
    pub aggregate_root: String,
    pub record_root: String,
    pub public_audit_root: String,
    pub confidential_receipt_root: String,
    pub fee_class: String,
    pub low_fee_batch: bool,
    pub accepted_weight: u16,
    pub threshold: u16,
    pub shard: u16,
    pub epoch: u64,
    pub round: u64,
}

impl ThresholdRecord {
    pub fn from_decision(
        request: &ThresholdRequest,
        aggregate: &AggregateSignature,
        status: &str,
        reason: &str,
    ) -> Self {
        let request_root = request.root();
        let public_audit_root = stable_root(
            DOMAIN_PUBLIC,
            &[
                &request.id,
                request.kind.as_str(),
                &request.shard.to_string(),
                &request.epoch.to_string(),
                &aggregate.aggregate_root,
                status,
            ],
        );
        let confidential_receipt_root = stable_root(
            "confidential-receipt",
            &[
                &request.account_commitment,
                &request.nullifier,
                &request.payload_commitment,
                &request.memo_commitment,
                &request.view_tag,
                &aggregate.transcript_root,
            ],
        );
        let fee_class = fee_class(request, status).to_string();
        let record_root = stable_root(
            DOMAIN_RECORD,
            &[
                &request.id,
                request.kind.as_str(),
                status,
                reason,
                &request_root,
                &aggregate.aggregate_root,
                &public_audit_root,
                &confidential_receipt_root,
                &fee_class,
                &aggregate.low_fee_batch.to_string(),
                &aggregate.accepted_weight.to_string(),
                &aggregate.threshold.to_string(),
                &request.shard.to_string(),
                &request.epoch.to_string(),
                &request.round.to_string(),
            ],
        );
        Self {
            request_id: request.id.clone(),
            kind: request.kind,
            status: status.to_string(),
            reason: reason.to_string(),
            request_root,
            aggregate_root: aggregate.aggregate_root.clone(),
            record_root,
            public_audit_root,
            confidential_receipt_root,
            fee_class,
            low_fee_batch: aggregate.low_fee_batch,
            accepted_weight: aggregate.accepted_weight,
            threshold: aggregate.threshold,
            shard: request.shard,
            epoch: request.epoch,
            round: request.round,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "kind": self.kind.as_str(),
            "status": self.status,
            "reason": self.reason,
            "request_root": self.request_root,
            "aggregate_root": self.aggregate_root,
            "record_root": self.record_root,
            "public_audit_root": self.public_audit_root,
            "fee_class": self.fee_class,
            "low_fee_batch": self.low_fee_batch,
            "accepted_weight": self.accepted_weight,
            "threshold": self.threshold,
            "shard": self.shard,
            "epoch": self.epoch,
            "round": self.round,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pending: BTreeMap<String, ThresholdRequest>,
    pub records: Vec<ThresholdRecord>,
    pub latest_public_record: Option<Value>,
}

pub type Runtime = State;

impl State {
    pub fn new(config: Config) -> Self {
        let counters = Counters::default();
        let records = Vec::new();
        let roots = Roots::recompute(&config, &counters, &records);
        Self {
            config,
            counters,
            roots,
            pending: BTreeMap::new(),
            records,
            latest_public_record: None,
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn submit(&mut self, request: ThresholdRequest) -> String {
        let request_root = request.root();
        self.counters.record_request(&request);
        self.pending.insert(request.id.clone(), request);
        self.refresh_roots();
        request_root
    }

    pub fn record(&mut self, request_id: &str) -> Option<ThresholdRecord> {
        let request = self.pending.remove(request_id)?;
        let threshold = self.config.threshold_for_kind(request.kind);
        let validation = self.validate(&request);
        let share_count = if validation.acceptable {
            threshold.saturating_add(validation.spare_signers)
        } else {
            threshold.saturating_sub(1)
        };
        let shares = deterministic_shares(
            request.kind.as_str(),
            share_count,
            &request.root(),
            validation.acceptable,
        );
        let aggregate = AggregateSignature::from_shares(&request, threshold, &shares);
        if aggregate.low_fee_batch {
            self.counters.low_fee_batches = self.counters.low_fee_batches.saturating_add(1);
        }
        self.counters.aggregate_signatures = self.counters.aggregate_signatures.saturating_add(1);
        let (status, reason) = decision_status(&validation, &aggregate);
        let record = ThresholdRecord::from_decision(&request, &aggregate, status, reason);
        self.counters.record_status(&record.status);
        self.latest_public_record = Some(record.public_record());
        self.records.push(record.clone());
        self.refresh_roots();
        Some(record)
    }

    pub fn record_all(&mut self) -> Vec<ThresholdRecord> {
        let ids: Vec<String> = self.pending.keys().cloned().collect();
        let mut out = Vec::new();
        for id in ids {
            if let Some(record) = self.record(&id) {
                out.push(record);
            }
        }
        out
    }

    pub fn public_record(&self) -> Value {
        match &self.latest_public_record {
            Some(record) => record.clone(),
            None => json!({
                "runtime": RUNTIME_NAME,
                "version": RUNTIME_VERSION,
                "status": STATUS_PENDING,
                "state_root": self.state_root(),
            }),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots::recompute(&self.config, &self.counters, &self.records);
    }

    pub fn demo() -> Self {
        let mut runtime = Self::devnet();
        let requests = vec![
            ThresholdRequest::sequencer("seq-0001", 0, 44_000_000_000),
            ThresholdRequest::bridge_watch("watch-0001", 1, 880_000_000_000),
            ThresholdRequest::contract_call("call-0001", 2, 42_000_000),
            ThresholdRequest::release_gate("release-0001", 3, 650_000_000_000),
            ThresholdRequest::batch_verify("batch-0001", 4, 12_000_000),
        ];
        for request in requests {
            runtime.submit(request);
        }
        runtime.record_all();
        runtime
    }

    fn validate(&self, request: &ThresholdRequest) -> Validation {
        let mut issues = Vec::new();
        if request.shard >= self.config.shard_count {
            issues.push("shard-out-of-range");
        }
        if request.call_bytes > self.config.max_call_bytes {
            issues.push("call-too-large");
        }
        if request.proof_bytes > self.config.max_proof_bytes {
            issues.push("proof-too-large");
        }
        if request.fee_micronero < self.config.low_fee_micronero {
            issues.push("fee-too-low");
        }
        match request.kind {
            RequestKind::BridgeWatch => {
                if request.value_atomic > self.config.bridge_limit_atomic {
                    issues.push("bridge-limit");
                }
                if self.config.require_watcher_quorum
                    && request.watcher_attestations.len() < self.config.watcher_threshold as usize
                {
                    issues.push("watcher-quorum");
                }
            }
            RequestKind::ContractCall => {
                if request.value_atomic > self.config.call_limit_atomic {
                    issues.push("contract-limit");
                }
                if self.config.require_contract_receipt && request.contract_selector.is_empty() {
                    issues.push("contract-selector");
                }
            }
            RequestKind::ReleaseGate => {
                if request.value_atomic > self.config.release_limit_atomic {
                    issues.push("release-limit");
                }
                if request.release_gate.is_none() {
                    issues.push("release-gate-missing");
                }
            }
            RequestKind::BatchVerify => {
                if request.proof_bytes > self.config.max_proof_bytes
                    || request.call_bytes > self.config.max_call_bytes
                {
                    issues.push("batch-size");
                }
            }
            RequestKind::SequencerBlock => {}
        }
        let acceptable = issues.is_empty();
        let spare_signers = if acceptable { 2 } else { 0 };
        Validation {
            acceptable,
            reason: if issues.is_empty() {
                "threshold-satisfied".to_string()
            } else {
                issues.join(",")
            },
            spare_signers,
        }
    }
}

#[derive(Clone, Debug)]
struct Validation {
    acceptable: bool,
    reason: String,
    spare_signers: u16,
}

pub fn devnet() -> Runtime {
    Runtime::devnet()
}

pub fn demo() -> Runtime {
    Runtime::demo()
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

fn decision_status<'a>(
    validation: &'a Validation,
    aggregate: &AggregateSignature,
) -> (&'a str, &'a str) {
    if validation.acceptable && aggregate.passes_threshold() {
        if aggregate.low_fee_batch {
            (STATUS_ACCEPTED, "low-fee-batched-threshold-satisfied")
        } else {
            (STATUS_ACCEPTED, "threshold-satisfied")
        }
    } else if validation.acceptable {
        (STATUS_QUARANTINED, "threshold-missing")
    } else {
        (STATUS_REJECTED, validation.reason.as_str())
    }
}

fn fee_class(request: &ThresholdRequest, status: &str) -> &'static str {
    if status == STATUS_RELEASED || request.kind == RequestKind::ReleaseGate {
        FEE_CLASS_RELEASE
    } else if request.fee_micronero <= DEFAULT_LOW_FEE_MICRONERO {
        FEE_CLASS_LOW
    } else {
        FEE_CLASS_STANDARD
    }
}

fn deterministic_shares(
    role: &str,
    count: u16,
    request_root: &str,
    accepted: bool,
) -> Vec<SignatureShare> {
    let mut shares = Vec::new();
    for index in 0..count {
        shares.push(SignatureShare::deterministic(
            role,
            index,
            request_root,
            accepted,
        ));
    }
    shares
}

fn signer_set(role: &str, count: u16) -> Vec<String> {
    let mut signers = Vec::new();
    for index in 0..count {
        signers.push(format!("{}-signer-{:02}", role, index));
    }
    signers
}

fn watcher_set(id: &str, shard: u16, count: u16) -> Vec<String> {
    let mut watchers = Vec::new();
    for index in 0..count {
        watchers.push(stable_root(
            "watcher",
            &[id, &shard.to_string(), &index.to_string()],
        ));
    }
    watchers
}

fn deterministic_label(domain: &str, id: &str, shard: u16) -> String {
    stable_root(domain, &[id, &shard.to_string()])
}

fn committee_root(network: &str, epoch: u64, committee_size: u16) -> String {
    let committee = signer_set(&format!("{}-epoch-{}", network, epoch), committee_size);
    list_root("committee", committee.iter().map(String::as_str))
}

fn list_root<'a, I>(domain: &str, values: I) -> String
where
    I: Iterator<Item = &'a str>,
{
    let collected: Vec<&str> = values.collect();
    if collected.is_empty() {
        stable_root(domain, &["empty"])
    } else {
        stable_root(domain, &collected)
    }
}

fn stable_root(domain: &str, parts: &[&str]) -> String {
    let mut acc0: u64 = 0x243f_6a88_85a3_08d3;
    let mut acc1: u64 = 0x1319_8a2e_0370_7344;
    let mut acc2: u64 = 0xa409_3822_299f_31d0;
    let mut acc3: u64 = 0x082e_fa98_ec4e_6c89;
    mix_bytes(
        &mut acc0,
        &mut acc1,
        &mut acc2,
        &mut acc3,
        ROOT_PREFIX.as_bytes(),
    );
    mix_bytes(
        &mut acc0,
        &mut acc1,
        &mut acc2,
        &mut acc3,
        domain.as_bytes(),
    );
    for part in parts {
        mix_bytes(&mut acc0, &mut acc1, &mut acc2, &mut acc3, part.as_bytes());
    }
    format!("drt_{:016x}{:016x}{:016x}{:016x}", acc0, acc1, acc2, acc3)
}

fn mix_bytes(acc0: &mut u64, acc1: &mut u64, acc2: &mut u64, acc3: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        let v = *byte as u64;
        *acc0 = (*acc0).rotate_left(5) ^ v.wrapping_mul(0x1000_0000_01b3);
        *acc1 = (*acc1).rotate_left(7).wrapping_add(*acc0 ^ v);
        *acc2 = (*acc2).rotate_left(11) ^ (*acc1).wrapping_mul(0x9e37_79b1_85eb_ca87);
        *acc3 = (*acc3)
            .rotate_left(13)
            .wrapping_add(*acc2 ^ 0xc2b2_ae3d_27d4_eb4f);
    }
    *acc0 ^= 0xff;
    *acc1 = acc1.wrapping_add(bytes.len() as u64);
    *acc2 ^= acc0.rotate_right(17);
    *acc3 = acc3.wrapping_add(acc1.rotate_right(29));
}

fn saturating_u16(value: usize) -> u16 {
    if value > u16::MAX as usize {
        u16::MAX
    } else {
        value as u16
    }
}

pub const PROTOCOL_PHASES: [&str; 96] = [
    "phase-000-config-anchor",
    "phase-001-committee-snapshot",
    "phase-002-sequencer-intent",
    "phase-003-confidential-account-commitment",
    "phase-004-nullifier-scan",
    "phase-005-viewtag-routing",
    "phase-006-payload-commitment",
    "phase-007-memo-commitment",
    "phase-008-pq-key-advertisement",
    "phase-009-share-request",
    "phase-010-share-response",
    "phase-011-share-weighting",
    "phase-012-dilithium-lane",
    "phase-013-falcon-lane",
    "phase-014-sphincs-lane",
    "phase-015-transcript-merge",
    "phase-016-threshold-count",
    "phase-017-aggregate-build",
    "phase-018-aggregate-proof",
    "phase-019-low-fee-routing",
    "phase-020-batch-open",
    "phase-021-batch-pack",
    "phase-022-batch-verify",
    "phase-023-batch-close",
    "phase-024-watcher-quorum",
    "phase-025-bridge-observation",
    "phase-026-bridge-limit",
    "phase-027-bridge-attestation",
    "phase-028-release-intent",
    "phase-029-release-limit",
    "phase-030-release-gate",
    "phase-031-release-proof",
    "phase-032-contract-selector",
    "phase-033-contract-calldata",
    "phase-034-contract-receipt",
    "phase-035-contract-limit",
    "phase-036-sequencer-block",
    "phase-037-sequencer-order",
    "phase-038-sequencer-root",
    "phase-039-sequencer-finality",
    "phase-040-confidential-receipt",
    "phase-041-public-audit",
    "phase-042-record-root",
    "phase-043-state-root",
    "phase-044-counter-root",
    "phase-045-committee-root",
    "phase-046-request-root",
    "phase-047-aggregate-root",
    "phase-048-release-root",
    "phase-049-watcher-root",
    "phase-050-contract-root",
    "phase-051-batch-root",
    "phase-052-devnet-fixture",
    "phase-053-demo-sequencer",
    "phase-054-demo-watcher",
    "phase-055-demo-contract",
    "phase-056-demo-release",
    "phase-057-demo-batch",
    "phase-058-replay-defense",
    "phase-059-domain-separation",
    "phase-060-deterministic-roots",
    "phase-061-fee-class-low",
    "phase-062-fee-class-standard",
    "phase-063-fee-class-release",
    "phase-064-size-limit-call",
    "phase-065-size-limit-proof",
    "phase-066-size-limit-aggregate",
    "phase-067-shard-limit",
    "phase-068-epoch-binding",
    "phase-069-round-binding",
    "phase-070-fast-path-release",
    "phase-071-conservative-path-release",
    "phase-072-watcher-required",
    "phase-073-contract-receipt-required",
    "phase-074-low-fee-enabled",
    "phase-075-low-fee-disabled",
    "phase-076-accepted-record",
    "phase-077-rejected-record",
    "phase-078-quarantined-record",
    "phase-079-released-record",
    "phase-080-operator-visible",
    "phase-081-user-private",
    "phase-082-bridge-private",
    "phase-083-contract-private",
    "phase-084-sequencer-private",
    "phase-085-threshold-private",
    "phase-086-pq-hybrid-private",
    "phase-087-atomic-value",
    "phase-088-micronero-fee",
    "phase-089-root-ledger",
    "phase-090-record-ledger",
    "phase-091-audit-ledger",
    "phase-092-confidential-ledger",
    "phase-093-runtime-export",
    "phase-094-runtime-demo",
    "phase-095-runtime-public-record",
];

pub const DETERMINISTIC_ROOT_SLOTS: &[&str] = &[
    "root-slot-000-config-network",
    "root-slot-001-config-chain",
    "root-slot-002-config-l2-chain",
    "root-slot-003-config-epoch",
    "root-slot-004-config-round",
    "root-slot-005-config-shards",
    "root-slot-006-config-committee",
    "root-slot-007-config-sequencer-threshold",
    "root-slot-008-config-watcher-threshold",
    "root-slot-009-config-release-threshold",
    "root-slot-010-config-contract-threshold",
    "root-slot-011-config-batch-limit",
    "root-slot-012-config-call-limit",
    "root-slot-013-config-memo-limit",
    "root-slot-014-config-proof-limit",
    "root-slot-015-config-aggregate-limit",
    "root-slot-016-config-low-fee",
    "root-slot-017-config-high-fee",
    "root-slot-018-config-bridge-value",
    "root-slot-019-config-release-value",
    "root-slot-020-config-call-value",
    "root-slot-021-config-schemes",
    "root-slot-022-config-commitment",
    "root-slot-023-config-salt",
    "root-slot-024-config-fast-release",
    "root-slot-025-config-low-fee-batching",
    "root-slot-026-config-watcher-required",
    "root-slot-027-config-receipt-required",
    "root-slot-028-request-id",
    "root-slot-029-request-kind",
    "root-slot-030-request-shard",
    "root-slot-031-request-epoch",
    "root-slot-032-request-round",
    "root-slot-033-request-account",
    "root-slot-034-request-nullifier",
    "root-slot-035-request-payload",
    "root-slot-036-request-memo",
    "root-slot-037-request-viewtag",
    "root-slot-038-request-destination",
    "root-slot-039-request-selector",
    "root-slot-040-request-value",
    "root-slot-041-request-fee",
    "root-slot-042-request-call-bytes",
    "root-slot-043-request-proof-bytes",
    "root-slot-044-request-signers",
    "root-slot-045-request-watchers",
    "root-slot-046-request-release-gate",
    "root-slot-047-share-signer",
    "root-slot-048-share-scheme",
    "root-slot-049-share-public-key",
    "root-slot-050-share-commitment",
    "root-slot-051-share-response",
    "root-slot-052-share-weight",
    "root-slot-053-share-accepted",
    "root-slot-054-aggregate-request",
    "root-slot-055-aggregate-root",
    "root-slot-056-aggregate-scheme-mix",
    "root-slot-057-aggregate-participants",
    "root-slot-058-aggregate-transcript",
    "root-slot-059-aggregate-share-count",
    "root-slot-060-aggregate-threshold",
    "root-slot-061-aggregate-weight",
    "root-slot-062-aggregate-low-fee",
    "root-slot-063-record-id",
    "root-slot-064-record-kind",
    "root-slot-065-record-status",
    "root-slot-066-record-reason",
    "root-slot-067-record-request-root",
    "root-slot-068-record-aggregate-root",
    "root-slot-069-record-root",
    "root-slot-070-record-public-audit",
    "root-slot-071-record-confidential-receipt",
    "root-slot-072-record-fee-class",
    "root-slot-073-record-low-fee",
    "root-slot-074-record-weight",
    "root-slot-075-record-threshold",
    "root-slot-076-record-shard",
    "root-slot-077-record-epoch",
    "root-slot-078-record-round",
    "root-slot-079-counter-requests",
    "root-slot-080-counter-accepted",
    "root-slot-081-counter-rejected",
    "root-slot-082-counter-quarantined",
    "root-slot-083-counter-release-gates",
    "root-slot-084-counter-bridge-watches",
    "root-slot-085-counter-contract-calls",
    "root-slot-086-counter-sequencer-blocks",
    "root-slot-087-counter-batches",
    "root-slot-088-counter-aggregates",
    "root-slot-089-counter-low-fee-batches",
    "root-slot-090-counter-fees",
    "root-slot-091-counter-values",
    "root-slot-092-counter-call-bytes",
    "root-slot-093-counter-proof-bytes",
    "root-slot-094-state-config-root",
    "root-slot-095-state-committee-root",
    "root-slot-096-state-request-root",
    "root-slot-097-state-record-root",
    "root-slot-098-state-aggregate-root",
    "root-slot-099-state-release-root",
    "root-slot-100-state-watcher-root",
    "root-slot-101-state-contract-root",
    "root-slot-102-state-batch-root",
    "root-slot-103-state-counter-root",
    "root-slot-104-state-final-root",
    "root-slot-105-sequencer-domain",
    "root-slot-106-sequencer-order",
    "root-slot-107-sequencer-private-mempool",
    "root-slot-108-sequencer-batch-root",
    "root-slot-109-sequencer-fee-root",
    "root-slot-110-sequencer-proof-root",
    "root-slot-111-sequencer-call-root",
    "root-slot-112-sequencer-release-root",
    "root-slot-113-sequencer-watch-root",
    "root-slot-114-sequencer-finality-root",
    "root-slot-115-watcher-domain",
    "root-slot-116-watcher-quorum",
    "root-slot-117-watcher-bridge-height",
    "root-slot-118-watcher-bridge-tx",
    "root-slot-119-watcher-bridge-output",
    "root-slot-120-watcher-nullifier",
    "root-slot-121-watcher-viewtag",
    "root-slot-122-watcher-attestation",
    "root-slot-123-watcher-limit",
    "root-slot-124-watcher-finality",
    "root-slot-125-contract-domain",
    "root-slot-126-contract-selector",
    "root-slot-127-contract-calldata",
    "root-slot-128-contract-state-key",
    "root-slot-129-contract-state-value",
    "root-slot-130-contract-receipt",
    "root-slot-131-contract-gas-equivalent",
    "root-slot-132-contract-fee",
    "root-slot-133-contract-limit",
    "root-slot-134-contract-finality",
    "root-slot-135-release-domain",
    "root-slot-136-release-gate",
    "root-slot-137-release-intent",
    "root-slot-138-release-value",
    "root-slot-139-release-destination",
    "root-slot-140-release-watcher-root",
    "root-slot-141-release-threshold-root",
    "root-slot-142-release-proof-root",
    "root-slot-143-release-audit-root",
    "root-slot-144-release-finality",
    "root-slot-145-batch-domain",
    "root-slot-146-batch-open",
    "root-slot-147-batch-item",
    "root-slot-148-batch-pack",
    "root-slot-149-batch-proof",
    "root-slot-150-batch-low-fee",
    "root-slot-151-batch-threshold",
    "root-slot-152-batch-transcript",
    "root-slot-153-batch-close",
    "root-slot-154-batch-finality",
    "root-slot-155-pq-domain",
    "root-slot-156-pq-dilithium-key",
    "root-slot-157-pq-dilithium-share",
    "root-slot-158-pq-dilithium-response",
    "root-slot-159-pq-falcon-key",
    "root-slot-160-pq-falcon-share",
    "root-slot-161-pq-falcon-response",
    "root-slot-162-pq-sphincs-key",
    "root-slot-163-pq-sphincs-share",
    "root-slot-164-pq-sphincs-response",
    "root-slot-165-confidential-domain",
    "root-slot-166-confidential-account",
    "root-slot-167-confidential-amount",
    "root-slot-168-confidential-asset",
    "root-slot-169-confidential-memo",
    "root-slot-170-confidential-viewtag",
    "root-slot-171-confidential-nullifier",
    "root-slot-172-confidential-receipt",
    "root-slot-173-confidential-proof",
    "root-slot-174-confidential-audit",
    "root-slot-175-policy-domain",
    "root-slot-176-policy-shard",
    "root-slot-177-policy-epoch",
    "root-slot-178-policy-round",
    "root-slot-179-policy-fee",
    "root-slot-180-policy-value",
    "root-slot-181-policy-size",
    "root-slot-182-policy-threshold",
    "root-slot-183-policy-quorum",
    "root-slot-184-policy-finality",
    "root-slot-185-devnet-domain",
    "root-slot-186-devnet-sequencer",
    "root-slot-187-devnet-watcher",
    "root-slot-188-devnet-contract",
    "root-slot-189-devnet-release",
    "root-slot-190-devnet-batch",
    "root-slot-191-devnet-public-record",
    "root-slot-192-devnet-state-root",
    "root-slot-193-devnet-counter-root",
    "root-slot-194-devnet-demo-root",
    "root-slot-195-runtime-domain",
    "root-slot-196-runtime-name",
    "root-slot-197-runtime-version",
    "root-slot-198-runtime-config",
    "root-slot-199-runtime-state",
    "root-slot-200-runtime-records",
    "root-slot-201-runtime-pending",
    "root-slot-202-runtime-public",
    "root-slot-203-runtime-private",
    "root-slot-204-runtime-export",
    "root-slot-205-guard-domain",
    "root-slot-206-guard-no-randomness",
    "root-slot-207-guard-no-network",
    "root-slot-208-guard-no-thread",
    "root-slot-209-guard-no-time",
    "root-slot-210-guard-deterministic",
    "root-slot-211-guard-saturating",
    "root-slot-212-guard-public-json",
    "root-slot-213-guard-state-root",
    "root-slot-214-guard-demo",
    "root-slot-215-audit-domain",
    "root-slot-216-audit-public-record",
    "root-slot-217-audit-request-root",
    "root-slot-218-audit-record-root",
    "root-slot-219-audit-aggregate-root",
    "root-slot-220-audit-counter-root",
    "root-slot-221-audit-committee-root",
    "root-slot-222-audit-state-root",
    "root-slot-223-audit-status",
    "root-slot-224-audit-reason",
    "root-slot-225-lowfee-domain",
    "root-slot-226-lowfee-sequencer",
    "root-slot-227-lowfee-watcher",
    "root-slot-228-lowfee-batch",
    "root-slot-229-lowfee-aggregate",
    "root-slot-230-lowfee-proof",
    "root-slot-231-lowfee-call",
    "root-slot-232-lowfee-state",
    "root-slot-233-lowfee-counter",
    "root-slot-234-lowfee-finality",
    "root-slot-235-root-lane-000",
    "root-slot-236-root-lane-001",
    "root-slot-237-root-lane-002",
    "root-slot-238-root-lane-003",
    "root-slot-239-root-lane-004",
    "root-slot-240-root-lane-005",
    "root-slot-241-root-lane-006",
    "root-slot-242-root-lane-007",
    "root-slot-243-root-lane-008",
    "root-slot-244-root-lane-009",
    "root-slot-245-root-lane-010",
    "root-slot-246-root-lane-011",
    "root-slot-247-root-lane-012",
    "root-slot-248-root-lane-013",
    "root-slot-249-root-lane-014",
    "root-slot-250-root-lane-015",
    "root-slot-251-root-lane-016",
    "root-slot-252-root-lane-017",
    "root-slot-253-root-lane-018",
    "root-slot-254-root-lane-019",
    "root-slot-255-root-lane-020",
    "root-slot-256-root-lane-021",
    "root-slot-257-root-lane-022",
    "root-slot-258-root-lane-023",
    "root-slot-259-root-lane-024",
    "root-slot-260-root-lane-025",
    "root-slot-261-root-lane-026",
    "root-slot-262-root-lane-027",
    "root-slot-263-root-lane-028",
    "root-slot-264-root-lane-029",
    "root-slot-265-root-lane-030",
    "root-slot-266-root-lane-031",
    "root-slot-267-root-lane-032",
    "root-slot-268-root-lane-033",
    "root-slot-269-root-lane-034",
    "root-slot-270-root-lane-035",
    "root-slot-271-root-lane-036",
    "root-slot-272-root-lane-037",
    "root-slot-273-root-lane-038",
    "root-slot-274-root-lane-039",
    "root-slot-275-root-lane-040",
    "root-slot-276-root-lane-041",
    "root-slot-277-root-lane-042",
    "root-slot-278-root-lane-043",
    "root-slot-279-root-lane-044",
    "root-slot-280-root-lane-045",
    "root-slot-281-root-lane-046",
    "root-slot-282-root-lane-047",
    "root-slot-283-root-lane-048",
    "root-slot-284-root-lane-049",
    "root-slot-285-root-lane-050",
    "root-slot-286-root-lane-051",
    "root-slot-287-root-lane-052",
    "root-slot-288-root-lane-053",
    "root-slot-289-root-lane-054",
    "root-slot-290-root-lane-055",
    "root-slot-291-root-lane-056",
    "root-slot-292-root-lane-057",
    "root-slot-293-root-lane-058",
    "root-slot-294-root-lane-059",
    "root-slot-295-root-lane-060",
    "root-slot-296-root-lane-061",
    "root-slot-297-root-lane-062",
    "root-slot-298-root-lane-063",
    "root-slot-299-root-lane-064",
    "root-slot-300-root-lane-065",
    "root-slot-301-root-lane-066",
    "root-slot-302-root-lane-067",
    "root-slot-303-root-lane-068",
    "root-slot-304-root-lane-069",
    "root-slot-305-root-lane-070",
    "root-slot-306-root-lane-071",
    "root-slot-307-root-lane-072",
    "root-slot-308-root-lane-073",
    "root-slot-309-root-lane-074",
    "root-slot-310-root-lane-075",
    "root-slot-311-root-lane-076",
    "root-slot-312-root-lane-077",
    "root-slot-313-root-lane-078",
    "root-slot-314-root-lane-079",
    "root-slot-315-root-lane-080",
    "root-slot-316-root-lane-081",
    "root-slot-317-root-lane-082",
    "root-slot-318-root-lane-083",
    "root-slot-319-root-lane-084",
    "root-slot-320-root-lane-085",
    "root-slot-321-root-lane-086",
    "root-slot-322-root-lane-087",
    "root-slot-323-root-lane-088",
    "root-slot-324-root-lane-089",
    "root-slot-325-root-lane-090",
    "root-slot-326-root-lane-091",
    "root-slot-327-root-lane-092",
    "root-slot-328-root-lane-093",
    "root-slot-329-root-lane-094",
    "root-slot-330-root-lane-095",
    "root-slot-331-root-lane-096",
    "root-slot-332-root-lane-097",
    "root-slot-333-root-lane-098",
    "root-slot-334-root-lane-099",
    "root-slot-335-root-lane-100",
    "root-slot-336-root-lane-101",
    "root-slot-337-root-lane-102",
    "root-slot-338-root-lane-103",
    "root-slot-339-root-lane-104",
    "root-slot-340-root-lane-105",
    "root-slot-341-root-lane-106",
    "root-slot-342-root-lane-107",
    "root-slot-343-root-lane-108",
    "root-slot-344-root-lane-109",
    "root-slot-345-root-lane-110",
    "root-slot-346-root-lane-111",
    "root-slot-347-root-lane-112",
    "root-slot-348-root-lane-113",
    "root-slot-349-root-lane-114",
    "root-slot-350-root-lane-115",
    "root-slot-351-root-lane-116",
    "root-slot-352-root-lane-117",
    "root-slot-353-root-lane-118",
    "root-slot-354-root-lane-119",
    "root-slot-355-root-lane-120",
    "root-slot-356-root-lane-121",
    "root-slot-357-root-lane-122",
    "root-slot-358-root-lane-123",
    "root-slot-359-root-lane-124",
    "root-slot-360-root-lane-125",
    "root-slot-361-root-lane-126",
    "root-slot-362-root-lane-127",
    "root-slot-363-root-lane-128",
    "root-slot-364-root-lane-129",
    "root-slot-365-root-lane-130",
    "root-slot-366-root-lane-131",
    "root-slot-367-root-lane-132",
    "root-slot-368-root-lane-133",
    "root-slot-369-root-lane-134",
    "root-slot-370-root-lane-135",
    "root-slot-371-root-lane-136",
    "root-slot-372-root-lane-137",
    "root-slot-373-root-lane-138",
    "root-slot-374-root-lane-139",
    "root-slot-375-root-lane-140",
    "root-slot-376-root-lane-141",
    "root-slot-377-root-lane-142",
    "root-slot-378-root-lane-143",
    "root-slot-379-root-lane-144",
    "root-slot-380-root-lane-145",
    "root-slot-381-root-lane-146",
    "root-slot-382-root-lane-147",
    "root-slot-383-root-lane-148",
    "root-slot-384-root-lane-149",
    "root-slot-385-root-lane-150",
    "root-slot-386-root-lane-151",
    "root-slot-387-root-lane-152",
    "root-slot-388-root-lane-153",
    "root-slot-389-root-lane-154",
    "root-slot-390-root-lane-155",
    "root-slot-391-root-lane-156",
    "root-slot-392-root-lane-157",
    "root-slot-393-root-lane-158",
    "root-slot-394-root-lane-159",
    "root-slot-395-root-lane-160",
    "root-slot-396-root-lane-161",
    "root-slot-397-root-lane-162",
    "root-slot-398-root-lane-163",
    "root-slot-399-root-lane-164",
    "root-slot-400-root-lane-165",
    "root-slot-401-root-lane-166",
    "root-slot-402-root-lane-167",
    "root-slot-403-root-lane-168",
    "root-slot-404-root-lane-169",
    "root-slot-405-root-lane-170",
    "root-slot-406-root-lane-171",
    "root-slot-407-root-lane-172",
    "root-slot-408-root-lane-173",
    "root-slot-409-root-lane-174",
    "root-slot-410-root-lane-175",
    "root-slot-411-root-lane-176",
    "root-slot-412-root-lane-177",
    "root-slot-413-root-lane-178",
    "root-slot-414-root-lane-179",
    "root-slot-415-root-lane-180",
    "root-slot-416-root-lane-181",
    "root-slot-417-root-lane-182",
    "root-slot-418-root-lane-183",
    "root-slot-419-root-lane-184",
    "root-slot-420-root-lane-185",
    "root-slot-421-root-lane-186",
    "root-slot-422-root-lane-187",
    "root-slot-423-root-lane-188",
    "root-slot-424-root-lane-189",
    "root-slot-425-root-lane-190",
    "root-slot-426-root-lane-191",
    "root-slot-427-root-lane-192",
    "root-slot-428-root-lane-193",
    "root-slot-429-root-lane-194",
    "root-slot-430-root-lane-195",
    "root-slot-431-root-lane-196",
    "root-slot-432-root-lane-197",
    "root-slot-433-root-lane-198",
    "root-slot-434-root-lane-199",
    "root-slot-435-root-lane-200",
    "root-slot-436-root-lane-201",
    "root-slot-437-root-lane-202",
    "root-slot-438-root-lane-203",
    "root-slot-439-root-lane-204",
    "root-slot-440-root-lane-205",
    "root-slot-441-root-lane-206",
    "root-slot-442-root-lane-207",
    "root-slot-443-root-lane-208",
    "root-slot-444-root-lane-209",
    "root-slot-445-root-lane-210",
    "root-slot-446-root-lane-211",
    "root-slot-447-root-lane-212",
    "root-slot-448-root-lane-213",
    "root-slot-449-root-lane-214",
    "root-slot-450-root-lane-215",
    "root-slot-451-root-lane-216",
    "root-slot-452-root-lane-217",
    "root-slot-453-root-lane-218",
    "root-slot-454-root-lane-219",
    "root-slot-455-root-lane-220",
    "root-slot-456-root-lane-221",
    "root-slot-457-root-lane-222",
    "root-slot-458-root-lane-223",
    "root-slot-459-root-lane-224",
    "root-slot-460-root-lane-225",
    "root-slot-461-root-lane-226",
    "root-slot-462-root-lane-227",
    "root-slot-463-root-lane-228",
    "root-slot-464-root-lane-229",
    "root-slot-465-root-lane-230",
    "root-slot-466-root-lane-231",
    "root-slot-467-root-lane-232",
    "root-slot-468-root-lane-233",
    "root-slot-469-root-lane-234",
    "root-slot-470-root-lane-235",
    "root-slot-471-root-lane-236",
    "root-slot-472-root-lane-237",
    "root-slot-473-root-lane-238",
    "root-slot-474-root-lane-239",
    "root-slot-475-root-lane-240",
    "root-slot-476-root-lane-241",
    "root-slot-477-root-lane-242",
    "root-slot-478-root-lane-243",
    "root-slot-479-root-lane-244",
    "root-slot-480-root-lane-245",
    "root-slot-481-root-lane-246",
    "root-slot-482-root-lane-247",
    "root-slot-483-root-lane-248",
    "root-slot-484-root-lane-249",
    "root-slot-485-root-lane-250",
    "root-slot-486-root-lane-251",
    "root-slot-487-root-lane-252",
    "root-slot-488-root-lane-253",
    "root-slot-489-root-lane-254",
    "root-slot-490-root-lane-255",
    "root-slot-491-root-lane-256",
    "root-slot-492-root-lane-257",
    "root-slot-493-root-lane-258",
    "root-slot-494-root-lane-259",
    "root-slot-495-root-lane-260",
    "root-slot-496-root-lane-261",
    "root-slot-497-root-lane-262",
    "root-slot-498-root-lane-263",
    "root-slot-499-root-lane-264",
    "root-slot-500-root-lane-265",
    "root-slot-501-root-lane-266",
    "root-slot-502-root-lane-267",
    "root-slot-503-root-lane-268",
    "root-slot-504-root-lane-269",
    "root-slot-505-root-lane-270",
    "root-slot-506-root-lane-271",
    "root-slot-507-root-lane-272",
    "root-slot-508-root-lane-273",
    "root-slot-509-root-lane-274",
    "root-slot-510-root-lane-275",
    "root-slot-511-root-lane-276",
    "root-slot-512-root-lane-277",
    "root-slot-513-root-lane-278",
    "root-slot-514-root-lane-279",
    "root-slot-515-root-lane-280",
    "root-slot-516-root-lane-281",
    "root-slot-517-root-lane-282",
    "root-slot-518-root-lane-283",
    "root-slot-519-root-lane-284",
    "root-slot-520-root-lane-285",
    "root-slot-521-root-lane-286",
    "root-slot-522-root-lane-287",
    "root-slot-523-root-lane-288",
    "root-slot-524-root-lane-289",
    "root-slot-525-root-lane-290",
    "root-slot-526-root-lane-291",
    "root-slot-527-root-lane-292",
    "root-slot-528-root-lane-293",
    "root-slot-529-root-lane-294",
    "root-slot-530-root-lane-295",
    "root-slot-531-root-lane-296",
    "root-slot-532-root-lane-297",
    "root-slot-533-root-lane-298",
    "root-slot-534-root-lane-299",
    "root-slot-535-root-lane-300",
    "root-slot-536-root-lane-301",
    "root-slot-537-root-lane-302",
    "root-slot-538-root-lane-303",
    "root-slot-539-root-lane-304",
    "root-slot-540-root-lane-305",
    "root-slot-541-root-lane-306",
    "root-slot-542-root-lane-307",
    "root-slot-543-root-lane-308",
    "root-slot-544-root-lane-309",
    "root-slot-545-root-lane-310",
    "root-slot-546-root-lane-311",
    "root-slot-547-root-lane-312",
    "root-slot-548-root-lane-313",
    "root-slot-549-root-lane-314",
    "root-slot-550-root-lane-315",
    "root-slot-551-root-lane-316",
    "root-slot-552-root-lane-317",
    "root-slot-553-root-lane-318",
    "root-slot-554-root-lane-319",
    "root-slot-555-root-lane-320",
    "root-slot-556-root-lane-321",
    "root-slot-557-root-lane-322",
    "root-slot-558-root-lane-323",
    "root-slot-559-root-lane-324",
    "root-slot-560-root-lane-325",
    "root-slot-561-root-lane-326",
    "root-slot-562-root-lane-327",
    "root-slot-563-root-lane-328",
    "root-slot-564-root-lane-329",
    "root-slot-565-root-lane-330",
    "root-slot-566-root-lane-331",
    "root-slot-567-root-lane-332",
    "root-slot-568-root-lane-333",
    "root-slot-569-root-lane-334",
    "root-slot-570-root-lane-335",
    "root-slot-571-root-lane-336",
    "root-slot-572-root-lane-337",
    "root-slot-573-root-lane-338",
    "root-slot-574-root-lane-339",
    "root-slot-575-root-lane-340",
    "root-slot-576-root-lane-341",
    "root-slot-577-root-lane-342",
    "root-slot-578-root-lane-343",
    "root-slot-579-root-lane-344",
    "root-slot-580-root-lane-345",
    "root-slot-581-root-lane-346",
    "root-slot-582-root-lane-347",
    "root-slot-583-root-lane-348",
    "root-slot-584-root-lane-349",
    "root-slot-585-root-lane-350",
    "root-slot-586-root-lane-351",
    "root-slot-587-root-lane-352",
    "root-slot-588-root-lane-353",
    "root-slot-589-root-lane-354",
    "root-slot-590-root-lane-355",
    "root-slot-591-root-lane-356",
    "root-slot-592-root-lane-357",
    "root-slot-593-root-lane-358",
    "root-slot-594-root-lane-359",
    "root-slot-595-root-lane-360",
    "root-slot-596-root-lane-361",
    "root-slot-597-root-lane-362",
    "root-slot-598-root-lane-363",
    "root-slot-599-root-lane-364",
    "root-slot-600-root-lane-365",
    "root-slot-601-root-lane-366",
    "root-slot-602-root-lane-367",
    "root-slot-603-root-lane-368",
    "root-slot-604-root-lane-369",
    "root-slot-605-root-lane-370",
    "root-slot-606-root-lane-371",
    "root-slot-607-root-lane-372",
    "root-slot-608-root-lane-373",
    "root-slot-609-root-lane-374",
    "root-slot-610-root-lane-375",
    "root-slot-611-root-lane-376",
    "root-slot-612-root-lane-377",
    "root-slot-613-root-lane-378",
    "root-slot-614-root-lane-379",
    "root-slot-615-root-lane-380",
    "root-slot-616-root-lane-381",
    "root-slot-617-root-lane-382",
    "root-slot-618-root-lane-383",
    "root-slot-619-root-lane-384",
    "root-slot-620-root-lane-385",
    "root-slot-621-root-lane-386",
    "root-slot-622-root-lane-387",
    "root-slot-623-root-lane-388",
    "root-slot-624-root-lane-389",
    "root-slot-625-root-lane-390",
    "root-slot-626-root-lane-391",
    "root-slot-627-root-lane-392",
    "root-slot-628-root-lane-393",
    "root-slot-629-root-lane-394",
    "root-slot-630-root-lane-395",
    "root-slot-631-root-lane-396",
    "root-slot-632-root-lane-397",
    "root-slot-633-root-lane-398",
    "root-slot-634-root-lane-399",
    "root-slot-635-root-lane-400",
    "root-slot-636-root-lane-401",
    "root-slot-637-root-lane-402",
    "root-slot-638-root-lane-403",
    "root-slot-639-root-lane-404",
    "root-slot-640-root-lane-405",
    "root-slot-641-root-lane-406",
    "root-slot-642-root-lane-407",
    "root-slot-643-root-lane-408",
    "root-slot-644-root-lane-409",
    "root-slot-645-root-lane-410",
    "root-slot-646-root-lane-411",
    "root-slot-647-root-lane-412",
    "root-slot-648-root-lane-413",
    "root-slot-649-root-lane-414",
    "root-slot-650-root-lane-415",
    "root-slot-651-root-lane-416",
    "root-slot-652-root-lane-417",
    "root-slot-653-root-lane-418",
    "root-slot-654-root-lane-419",
    "root-slot-655-root-lane-420",
    "root-slot-656-root-lane-421",
    "root-slot-657-root-lane-422",
    "root-slot-658-root-lane-423",
    "root-slot-659-root-lane-424",
    "root-slot-660-root-lane-425",
    "root-slot-661-root-lane-426",
    "root-slot-662-root-lane-427",
    "root-slot-663-root-lane-428",
    "root-slot-664-root-lane-429",
    "root-slot-665-root-lane-430",
    "root-slot-666-root-lane-431",
    "root-slot-667-root-lane-432",
    "root-slot-668-root-lane-433",
    "root-slot-669-root-lane-434",
    "root-slot-670-root-lane-435",
    "root-slot-671-root-lane-436",
    "root-slot-672-root-lane-437",
    "root-slot-673-root-lane-438",
    "root-slot-674-root-lane-439",
    "root-slot-675-root-lane-440",
    "root-slot-676-root-lane-441",
    "root-slot-677-root-lane-442",
    "root-slot-678-root-lane-443",
    "root-slot-679-root-lane-444",
    "root-slot-680-root-lane-445",
    "root-slot-681-root-lane-446",
    "root-slot-682-root-lane-447",
    "root-slot-683-root-lane-448",
    "root-slot-684-root-lane-449",
    "root-slot-685-root-lane-450",
    "root-slot-686-root-lane-451",
    "root-slot-687-root-lane-452",
    "root-slot-688-root-lane-453",
    "root-slot-689-root-lane-454",
    "root-slot-690-root-lane-455",
    "root-slot-691-root-lane-456",
    "root-slot-692-root-lane-457",
    "root-slot-693-root-lane-458",
    "root-slot-694-root-lane-459",
    "root-slot-695-root-lane-460",
    "root-slot-696-root-lane-461",
    "root-slot-697-root-lane-462",
    "root-slot-698-root-lane-463",
    "root-slot-699-root-lane-464",
    "root-slot-700-root-lane-465",
    "root-slot-701-root-lane-466",
    "root-slot-702-root-lane-467",
    "root-slot-703-root-lane-468",
    "root-slot-704-root-lane-469",
    "root-slot-705-root-lane-470",
    "root-slot-706-root-lane-471",
    "root-slot-707-root-lane-472",
    "root-slot-708-root-lane-473",
    "root-slot-709-root-lane-474",
    "root-slot-710-root-lane-475",
    "root-slot-711-root-lane-476",
    "root-slot-712-root-lane-477",
    "root-slot-713-root-lane-478",
    "root-slot-714-root-lane-479",
];
