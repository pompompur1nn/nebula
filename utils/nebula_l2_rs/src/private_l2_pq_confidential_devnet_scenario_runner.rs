use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialDevnetScenarioRunnerResult<T> = std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialDevnetScenarioRunnerResult<T>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEVNET_SCENARIO_RUNNER_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-devnet-scenario-runner-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_DEVNET_SCENARIO_RUNNER_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-devnet-scenario-v1";
pub const NOTE_SCHEME: &str = "monero-l2-private-deposit-note-root-v1";
pub const TOKEN_FACTORY_SCHEME: &str = "confidential-token-factory-root-v1";
pub const CONTRACT_CALL_SCHEME: &str = "pq-confidential-contract-call-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-confidential-batch-settlement-root-v1";
pub const PRECONFIRMATION_SCHEME: &str = "fast-confidential-preconfirmation-root-v1";
pub const MONERO_EXIT_SCHEME: &str = "monero-bridge-private-exit-root-v1";
pub const WATCHTOWER_DISPUTE_SCHEME: &str = "watchtower-private-dispute-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_SCENARIO_ID: &str = "private-l2-pq-confidential-devnet-e2e";
pub const DEVNET_HEIGHT: u64 = 1_440_000;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_BRIDGE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MAX_FEE_BPS: u64 = 25;
pub const DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const DEFAULT_FAST_PRECONFIRMATION_MS: u64 = 650;
pub const DEFAULT_SESSION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_EXIT_TTL_BLOCKS: u64 = 1_440;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStepKind {
    PqAccountSessionSetup,
    PrivateDepositNoteMint,
    TokenFactoryIssue,
    ConfidentialTokenTransfer,
    ConfidentialContractCall,
    LowFeeBatchSettlement,
    FastPreconfirmation,
    MoneroBridgeExit,
    WatchtowerDispute,
    ReadinessAssertion,
}

impl ScenarioStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqAccountSessionSetup => "pq_account_session_setup",
            Self::PrivateDepositNoteMint => "private_deposit_note_mint",
            Self::TokenFactoryIssue => "token_factory_issue",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
            Self::ConfidentialContractCall => "confidential_contract_call",
            Self::LowFeeBatchSettlement => "low_fee_batch_settlement",
            Self::FastPreconfirmation => "fast_preconfirmation",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::WatchtowerDispute => "watchtower_dispute",
            Self::ReadinessAssertion => "readiness_assertion",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStatus {
    Draft,
    Running,
    Passed,
    Failed,
}

impl ScenarioStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Running => "running",
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub scenario_id: String,
    pub fee_asset_id: String,
    pub bridge_asset_id: String,
    pub start_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub low_fee_bps: u64,
    pub fast_preconfirmation_ms: u64,
    pub session_ttl_blocks: u64,
    pub exit_ttl_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            scenario_id: DEVNET_SCENARIO_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            bridge_asset_id: DEFAULT_BRIDGE_ASSET_ID.to_string(),
            start_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            fast_preconfirmation_ms: DEFAULT_FAST_PRECONFIRMATION_MS,
            session_ttl_blocks: DEFAULT_SESSION_TTL_BLOCKS,
            exit_ttl_blocks: DEFAULT_EXIT_TTL_BLOCKS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        ensure(!self.l2_network.is_empty(), "l2 network is empty")?;
        ensure(!self.monero_network.is_empty(), "monero network is empty")?;
        ensure(!self.scenario_id.is_empty(), "scenario id is empty")?;
        ensure(!self.fee_asset_id.is_empty(), "fee asset id is empty")?;
        ensure(!self.bridge_asset_id.is_empty(), "bridge asset id is empty")?;
        ensure(self.min_pq_security_bits >= 128, "pq security too low")?;
        ensure(self.min_privacy_set_size > 0, "privacy set is empty")?;
        ensure(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum",
        )?;
        ensure(self.max_fee_bps <= MAX_BPS, "max fee bps above bound")?;
        ensure(
            self.low_fee_bps <= self.max_fee_bps,
            "low fee bps above max",
        )?;
        ensure(
            self.fast_preconfirmation_ms > 0,
            "fast preconfirmation latency is zero",
        )?;
        ensure(self.session_ttl_blocks > 0, "session ttl is zero")?;
        ensure(self.exit_ttl_blocks > 0, "exit ttl is zero")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "bridge_asset_id": self.bridge_asset_id,
            "chain_id": self.chain_id,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "fast_preconfirmation_ms": self.fast_preconfirmation_ms,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": HASH_SUITE,
            "l2_network": self.l2_network,
            "low_fee_bps": self.low_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "monero_network": self.monero_network,
            "protocol_version": PROTOCOL_VERSION,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "scenario_id": self.scenario_id,
            "schema_version": SCHEMA_VERSION,
            "session_ttl_blocks": self.session_ttl_blocks,
            "start_height": self.start_height,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub accounts: u64,
    pub sessions: u64,
    pub deposit_notes: u64,
    pub tokens: u64,
    pub transfers: u64,
    pub contract_calls: u64,
    pub settlements: u64,
    pub preconfirmations: u64,
    pub exits: u64,
    pub disputes: u64,
    pub assertions: u64,
    pub records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "accounts": self.accounts,
            "assertions": self.assertions,
            "contract_calls": self.contract_calls,
            "deposit_notes": self.deposit_notes,
            "disputes": self.disputes,
            "exits": self.exits,
            "preconfirmations": self.preconfirmations,
            "records": self.records,
            "sessions": self.sessions,
            "settlements": self.settlements,
            "tokens": self.tokens,
            "transfers": self.transfers,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub account_root: String,
    pub session_root: String,
    pub deposit_note_root: String,
    pub token_root: String,
    pub transfer_root: String,
    pub contract_call_root: String,
    pub settlement_root: String,
    pub preconfirmation_root: String,
    pub exit_root: String,
    pub dispute_root: String,
    pub readiness_root: String,
    pub scenario_root: String,
    pub public_record_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            account_root: empty_root("ACCOUNTS"),
            session_root: empty_root("SESSIONS"),
            deposit_note_root: empty_root("DEPOSIT-NOTES"),
            token_root: empty_root("TOKENS"),
            transfer_root: empty_root("TRANSFERS"),
            contract_call_root: empty_root("CONTRACT-CALLS"),
            settlement_root: empty_root("SETTLEMENTS"),
            preconfirmation_root: empty_root("PRECONFIRMATIONS"),
            exit_root: empty_root("EXITS"),
            dispute_root: empty_root("DISPUTES"),
            readiness_root: empty_root("READINESS"),
            scenario_root: empty_root("SCENARIOS"),
            public_record_root: empty_root("PUBLIC-RECORDS"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_root": self.account_root,
            "config_root": self.config_root,
            "contract_call_root": self.contract_call_root,
            "deposit_note_root": self.deposit_note_root,
            "dispute_root": self.dispute_root,
            "exit_root": self.exit_root,
            "preconfirmation_root": self.preconfirmation_root,
            "public_record_root": self.public_record_root,
            "readiness_root": self.readiness_root,
            "scenario_root": self.scenario_root,
            "session_root": self.session_root,
            "settlement_root": self.settlement_root,
            "token_root": self.token_root,
            "transfer_root": self.transfer_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAccountSessionRequest {
    pub account_label: String,
    pub owner_commitment: String,
    pub pq_public_key_root: String,
    pub session_policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateDepositNoteMintRequest {
    pub session_id: String,
    pub monero_tx_root: String,
    pub output_commitment_root: String,
    pub view_tag_root: String,
    pub amount_piconero: u64,
    pub minted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenFactoryRequest {
    pub issuer_session_id: String,
    pub symbol: String,
    pub metadata_root: String,
    pub supply_commitment_root: String,
    pub privacy_policy_root: String,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialTransferRequest {
    pub token_id: String,
    pub from_owner_commitment: String,
    pub to_owner_commitment: String,
    pub amount_commitment_root: String,
    pub nullifier_root: String,
    pub transfer_proof_root: String,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialContractCallRequest {
    pub session_id: String,
    pub contract_id: String,
    pub selector_root: String,
    pub encrypted_calldata_root: String,
    pub witness_root: String,
    pub max_fee_piconero: u64,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchSettlementRequest {
    pub coordinator_id: String,
    pub item_roots: Vec<String>,
    pub fee_bps: u64,
    pub proof_root: String,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastPreconfirmationRequest {
    pub subject_id: String,
    pub sequencer_committee_root: String,
    pub attestation_root: String,
    pub latency_ms: u64,
    pub preconfirmed_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroBridgeExitRequest {
    pub session_id: String,
    pub exit_owner_commitment: String,
    pub burn_nullifier_root: String,
    pub monero_subaddress_root: String,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub requested_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerDisputeRequest {
    pub watcher_id: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub disputed_root: String,
    pub bond_piconero: u64,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReadinessAssertionRequest {
    pub assertion_key: String,
    pub subject_root: String,
    pub required: bool,
    pub observed: bool,
    pub checked_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "request", rename_all = "snake_case")]
pub enum ScenarioRequest {
    PqAccountSessionSetup(PqAccountSessionRequest),
    PrivateDepositNoteMint(PrivateDepositNoteMintRequest),
    TokenFactoryIssue(TokenFactoryRequest),
    ConfidentialTokenTransfer(ConfidentialTransferRequest),
    ConfidentialContractCall(ConfidentialContractCallRequest),
    LowFeeBatchSettlement(LowFeeBatchSettlementRequest),
    FastPreconfirmation(FastPreconfirmationRequest),
    MoneroBridgeExit(MoneroBridgeExitRequest),
    WatchtowerDispute(WatchtowerDisputeRequest),
    ReadinessAssertion(ReadinessAssertionRequest),
}

impl ScenarioRequest {
    pub fn kind(&self) -> ScenarioStepKind {
        match self {
            Self::PqAccountSessionSetup(_) => ScenarioStepKind::PqAccountSessionSetup,
            Self::PrivateDepositNoteMint(_) => ScenarioStepKind::PrivateDepositNoteMint,
            Self::TokenFactoryIssue(_) => ScenarioStepKind::TokenFactoryIssue,
            Self::ConfidentialTokenTransfer(_) => ScenarioStepKind::ConfidentialTokenTransfer,
            Self::ConfidentialContractCall(_) => ScenarioStepKind::ConfidentialContractCall,
            Self::LowFeeBatchSettlement(_) => ScenarioStepKind::LowFeeBatchSettlement,
            Self::FastPreconfirmation(_) => ScenarioStepKind::FastPreconfirmation,
            Self::MoneroBridgeExit(_) => ScenarioStepKind::MoneroBridgeExit,
            Self::WatchtowerDispute(_) => ScenarioStepKind::WatchtowerDispute,
            Self::ReadinessAssertion(_) => ScenarioStepKind::ReadinessAssertion,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind().as_str(),
            "request": self,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioStep {
    pub step_id: String,
    pub sequence: u64,
    pub kind: ScenarioStepKind,
    pub request: ScenarioRequest,
    pub result_id: String,
    pub result_root: String,
}

impl ScenarioStep {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "request": self.request.public_record(),
            "result_id": self.result_id,
            "result_root": self.result_root,
            "sequence": self.sequence,
            "step_id": self.step_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Scenario {
    pub scenario_id: String,
    pub status: ScenarioStatus,
    pub steps: Vec<ScenarioStep>,
    pub final_root: String,
}

impl Scenario {
    pub fn public_record(&self) -> Value {
        let steps = self
            .steps
            .iter()
            .map(ScenarioStep::public_record)
            .collect::<Vec<_>>();
        json!({
            "final_root": self.final_root,
            "scenario_id": self.scenario_id,
            "status": self.status.as_str(),
            "steps": steps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountSession {
    pub account_id: String,
    pub session_id: String,
    pub owner_commitment: String,
    pub pq_public_key_root: String,
    pub session_policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl AccountSession {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "expires_at_height": self.expires_at_height,
            "opened_at_height": self.opened_at_height,
            "owner_commitment": self.owner_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "session_id": self.session_id,
            "session_policy_root": self.session_policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioArtifact {
    pub artifact_id: String,
    pub kind: ScenarioStepKind,
    pub subject_id: String,
    pub root: String,
    pub height: u64,
    pub public_payload: Value,
}

impl ScenarioArtifact {
    pub fn public_record(&self) -> Value {
        json!({
            "artifact_id": self.artifact_id,
            "height": self.height,
            "kind": self.kind.as_str(),
            "public_payload": self.public_payload,
            "root": self.root,
            "subject_id": self.subject_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub scenario: Scenario,
    pub sessions: BTreeMap<String, AccountSession>,
    pub artifacts: BTreeMap<String, ScenarioArtifact>,
    pub public_records: BTreeMap<String, Value>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub readiness_failures: BTreeSet<String>,
}

pub type Runtime = State;

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            roots: Roots {
                config_root: record_root("CONFIG", &config.public_record()),
                ..Roots::empty()
            },
            scenario: Scenario {
                scenario_id: config.scenario_id.clone(),
                status: ScenarioStatus::Draft,
                steps: Vec::new(),
                final_root: empty_root("SCENARIO-FINAL"),
            },
            config,
            counters: Counters::default(),
            sessions: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            public_records: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            readiness_failures: BTreeSet::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        Self::new(Config::default())
    }

    pub fn run_demo() -> Result<Self> {
        let mut runtime = Self::devnet()?;
        for request in demo_requests(&runtime.config) {
            runtime.apply_request(request)?;
        }
        runtime.assert_ready()?;
        Ok(runtime)
    }

    pub fn apply_request(&mut self, request: ScenarioRequest) -> Result<ScenarioStep> {
        if self.scenario.status == ScenarioStatus::Draft {
            self.scenario.status = ScenarioStatus::Running;
        }
        ensure(
            self.scenario.status == ScenarioStatus::Running,
            "scenario is not running",
        )?;

        let sequence = self.scenario.steps.len() as u64 + 1;
        let kind = request.kind();
        let (result_id, result_root) = match &request {
            ScenarioRequest::PqAccountSessionSetup(inner) => self.open_session(sequence, inner)?,
            ScenarioRequest::PrivateDepositNoteMint(inner) => {
                self.mint_deposit_note(sequence, inner)?
            }
            ScenarioRequest::TokenFactoryIssue(inner) => self.issue_token(sequence, inner)?,
            ScenarioRequest::ConfidentialTokenTransfer(inner) => {
                self.transfer_token(sequence, inner)?
            }
            ScenarioRequest::ConfidentialContractCall(inner) => {
                self.call_contract(sequence, inner)?
            }
            ScenarioRequest::LowFeeBatchSettlement(inner) => {
                self.settle_low_fee_batch(sequence, inner)?
            }
            ScenarioRequest::FastPreconfirmation(inner) => self.preconfirm(sequence, inner)?,
            ScenarioRequest::MoneroBridgeExit(inner) => self.bridge_exit(sequence, inner)?,
            ScenarioRequest::WatchtowerDispute(inner) => self.open_dispute(sequence, inner)?,
            ScenarioRequest::ReadinessAssertion(inner) => self.record_readiness(sequence, inner)?,
        };
        let step_id = deterministic_id(
            "STEP",
            &[
                HashPart::Str(&self.config.scenario_id),
                HashPart::U64(sequence),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&result_root),
            ],
        );
        let step = ScenarioStep {
            step_id,
            sequence,
            kind,
            request,
            result_id,
            result_root,
        };
        self.scenario.steps.push(step.clone());
        self.counters.records = self.counters.records.saturating_add(1);
        self.public_records
            .insert(step.step_id.clone(), step.public_record());
        self.recompute_roots();
        Ok(step)
    }

    pub fn assert_ready(&mut self) -> Result<()> {
        ensure(self.counters.sessions > 0, "missing pq account session")?;
        ensure(
            self.counters.deposit_notes > 0,
            "missing private deposit note",
        )?;
        ensure(self.counters.tokens > 0, "missing token factory issuance")?;
        ensure(self.counters.transfers > 0, "missing confidential transfer")?;
        ensure(
            self.counters.contract_calls > 0,
            "missing confidential contract call",
        )?;
        ensure(self.counters.settlements > 0, "missing low-fee settlement")?;
        ensure(
            self.counters.preconfirmations > 0,
            "missing fast preconfirmation",
        )?;
        ensure(self.counters.exits > 0, "missing Monero bridge exit")?;
        ensure(self.counters.disputes > 0, "missing watchtower dispute")?;
        ensure(
            self.readiness_failures.is_empty(),
            "readiness assertion failed",
        )?;
        self.scenario.status = ScenarioStatus::Passed;
        self.recompute_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "scenario": self.scenario.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "STATE",
            &json!({
                "config_root": self.roots.config_root,
                "counters": self.counters.public_record(),
                "roots": self.roots.public_record(),
                "scenario_status": self.scenario.status.as_str(),
            }),
        )
    }

    fn open_session(
        &mut self,
        sequence: u64,
        request: &PqAccountSessionRequest,
    ) -> Result<(String, String)> {
        ensure(!request.account_label.is_empty(), "account label is empty")?;
        ensure(
            !request.owner_commitment.is_empty(),
            "owner commitment is empty",
        )?;
        ensure(
            request.expires_at_height > request.opened_at_height,
            "session expires before it opens",
        )?;
        let account_id = deterministic_id(
            "ACCOUNT",
            &[
                HashPart::Str(&request.account_label),
                HashPart::Str(&request.owner_commitment),
            ],
        );
        let session_id = deterministic_id(
            "SESSION",
            &[
                HashPart::Str(&account_id),
                HashPart::Str(&request.pq_public_key_root),
                HashPart::Str(&request.session_policy_root),
                HashPart::U64(sequence),
            ],
        );
        let session = AccountSession {
            account_id,
            session_id: session_id.clone(),
            owner_commitment: request.owner_commitment.clone(),
            pq_public_key_root: request.pq_public_key_root.clone(),
            session_policy_root: request.session_policy_root.clone(),
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
        };
        let root = record_root("SESSION", &session.public_record());
        self.sessions.insert(session_id.clone(), session);
        self.counters.accounts = self.counters.accounts.saturating_add(1);
        self.counters.sessions = self.counters.sessions.saturating_add(1);
        Ok((session_id, root))
    }

    fn mint_deposit_note(
        &mut self,
        sequence: u64,
        request: &PrivateDepositNoteMintRequest,
    ) -> Result<(String, String)> {
        self.require_session(&request.session_id)?;
        ensure(request.amount_piconero > 0, "deposit amount is zero")?;
        let note_id = deterministic_id(
            "DEPOSIT-NOTE",
            &[
                HashPart::Str(&request.session_id),
                HashPart::Str(&request.monero_tx_root),
                HashPart::Str(&request.output_commitment_root),
                HashPart::U64(sequence),
            ],
        );
        let payload = json!({
            "amount_piconero": request.amount_piconero,
            "asset_id": self.config.bridge_asset_id,
            "minted_at_height": request.minted_at_height,
            "monero_network": self.config.monero_network,
            "monero_tx_root": request.monero_tx_root,
            "note_id": note_id,
            "note_scheme": NOTE_SCHEME,
            "output_commitment_root": request.output_commitment_root,
            "session_id": request.session_id,
            "view_tag_root": request.view_tag_root,
        });
        let root = record_root("DEPOSIT-NOTE", &payload);
        self.insert_artifact(
            note_id.clone(),
            ScenarioStepKind::PrivateDepositNoteMint,
            request.session_id.clone(),
            root.clone(),
            request.minted_at_height,
            payload,
        );
        self.counters.deposit_notes = self.counters.deposit_notes.saturating_add(1);
        Ok((note_id, root))
    }

    fn issue_token(
        &mut self,
        sequence: u64,
        request: &TokenFactoryRequest,
    ) -> Result<(String, String)> {
        self.require_session(&request.issuer_session_id)?;
        ensure(!request.symbol.is_empty(), "token symbol is empty")?;
        let token_id = deterministic_id(
            "TOKEN",
            &[
                HashPart::Str(&request.issuer_session_id),
                HashPart::Str(&request.symbol),
                HashPart::Str(&request.supply_commitment_root),
                HashPart::U64(sequence),
            ],
        );
        let payload = json!({
            "issued_at_height": request.issued_at_height,
            "issuer_session_id": request.issuer_session_id,
            "metadata_root": request.metadata_root,
            "privacy_policy_root": request.privacy_policy_root,
            "scheme": TOKEN_FACTORY_SCHEME,
            "supply_commitment_root": request.supply_commitment_root,
            "symbol": request.symbol,
            "token_id": token_id,
        });
        let root = record_root("TOKEN", &payload);
        self.insert_artifact(
            token_id.clone(),
            ScenarioStepKind::TokenFactoryIssue,
            request.issuer_session_id.clone(),
            root.clone(),
            request.issued_at_height,
            payload,
        );
        self.counters.tokens = self.counters.tokens.saturating_add(1);
        Ok((token_id, root))
    }

    fn transfer_token(
        &mut self,
        sequence: u64,
        request: &ConfidentialTransferRequest,
    ) -> Result<(String, String)> {
        ensure(
            self.artifacts.contains_key(&request.token_id),
            "unknown token id",
        )?;
        ensure(
            !self.consumed_nullifiers.contains(&request.nullifier_root),
            "nullifier already consumed",
        )?;
        self.consumed_nullifiers
            .insert(request.nullifier_root.clone());
        let transfer_id = deterministic_id(
            "TRANSFER",
            &[
                HashPart::Str(&request.token_id),
                HashPart::Str(&request.from_owner_commitment),
                HashPart::Str(&request.to_owner_commitment),
                HashPart::Str(&request.nullifier_root),
                HashPart::U64(sequence),
            ],
        );
        let payload = json!({
            "amount_commitment_root": request.amount_commitment_root,
            "from_owner_commitment": request.from_owner_commitment,
            "nullifier_root": request.nullifier_root,
            "submitted_at_height": request.submitted_at_height,
            "to_owner_commitment": request.to_owner_commitment,
            "token_id": request.token_id,
            "transfer_id": transfer_id,
            "transfer_proof_root": request.transfer_proof_root,
        });
        let root = record_root("TRANSFER", &payload);
        self.insert_artifact(
            transfer_id.clone(),
            ScenarioStepKind::ConfidentialTokenTransfer,
            request.token_id.clone(),
            root.clone(),
            request.submitted_at_height,
            payload,
        );
        self.counters.transfers = self.counters.transfers.saturating_add(1);
        Ok((transfer_id, root))
    }

    fn call_contract(
        &mut self,
        sequence: u64,
        request: &ConfidentialContractCallRequest,
    ) -> Result<(String, String)> {
        self.require_session(&request.session_id)?;
        ensure(!request.contract_id.is_empty(), "contract id is empty")?;
        ensure(request.max_fee_piconero > 0, "contract call fee is zero")?;
        let call_id = deterministic_id(
            "CONTRACT-CALL",
            &[
                HashPart::Str(&request.session_id),
                HashPart::Str(&request.contract_id),
                HashPart::Str(&request.selector_root),
                HashPart::Str(&request.encrypted_calldata_root),
                HashPart::U64(sequence),
            ],
        );
        let payload = json!({
            "call_id": call_id,
            "contract_id": request.contract_id,
            "encrypted_calldata_root": request.encrypted_calldata_root,
            "max_fee_piconero": request.max_fee_piconero,
            "scheme": CONTRACT_CALL_SCHEME,
            "selector_root": request.selector_root,
            "session_id": request.session_id,
            "submitted_at_height": request.submitted_at_height,
            "witness_root": request.witness_root,
        });
        let root = record_root("CONTRACT-CALL", &payload);
        self.insert_artifact(
            call_id.clone(),
            ScenarioStepKind::ConfidentialContractCall,
            request.session_id.clone(),
            root.clone(),
            request.submitted_at_height,
            payload,
        );
        self.counters.contract_calls = self.counters.contract_calls.saturating_add(1);
        Ok((call_id, root))
    }

    fn settle_low_fee_batch(
        &mut self,
        sequence: u64,
        request: &LowFeeBatchSettlementRequest,
    ) -> Result<(String, String)> {
        ensure(
            !request.coordinator_id.is_empty(),
            "coordinator id is empty",
        )?;
        ensure(!request.item_roots.is_empty(), "settlement batch is empty")?;
        ensure(
            request.fee_bps <= self.config.low_fee_bps,
            "settlement fee exceeds low-fee cap",
        )?;
        let item_values = request
            .item_roots
            .iter()
            .map(|item| Value::String(item.clone()))
            .collect::<Vec<_>>();
        let item_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEVNET-BATCH-ITEMS",
            &item_values,
        );
        let settlement_id = deterministic_id(
            "LOW-FEE-SETTLEMENT",
            &[
                HashPart::Str(&request.coordinator_id),
                HashPart::Str(&item_root),
                HashPart::U64(request.fee_bps),
                HashPart::U64(sequence),
            ],
        );
        let payload = json!({
            "coordinator_id": request.coordinator_id,
            "fee_bps": request.fee_bps,
            "item_root": item_root,
            "item_roots": request.item_roots,
            "proof_root": request.proof_root,
            "scheme": LOW_FEE_BATCH_SCHEME,
            "settled_at_height": request.settled_at_height,
            "settlement_id": settlement_id,
        });
        let root = record_root("LOW-FEE-SETTLEMENT", &payload);
        self.insert_artifact(
            settlement_id.clone(),
            ScenarioStepKind::LowFeeBatchSettlement,
            request.coordinator_id.clone(),
            root.clone(),
            request.settled_at_height,
            payload,
        );
        self.counters.settlements = self.counters.settlements.saturating_add(1);
        Ok((settlement_id, root))
    }

    fn preconfirm(
        &mut self,
        sequence: u64,
        request: &FastPreconfirmationRequest,
    ) -> Result<(String, String)> {
        ensure(
            !request.subject_id.is_empty(),
            "preconfirmation subject is empty",
        )?;
        ensure(
            request.latency_ms <= self.config.fast_preconfirmation_ms,
            "preconfirmation latency above target",
        )?;
        let preconfirmation_id = deterministic_id(
            "PRECONFIRMATION",
            &[
                HashPart::Str(&request.subject_id),
                HashPart::Str(&request.sequencer_committee_root),
                HashPart::Str(&request.attestation_root),
                HashPart::U64(sequence),
            ],
        );
        let payload = json!({
            "attestation_root": request.attestation_root,
            "latency_ms": request.latency_ms,
            "preconfirmation_id": preconfirmation_id,
            "preconfirmed_at_height": request.preconfirmed_at_height,
            "scheme": PRECONFIRMATION_SCHEME,
            "sequencer_committee_root": request.sequencer_committee_root,
            "subject_id": request.subject_id,
        });
        let root = record_root("PRECONFIRMATION", &payload);
        self.insert_artifact(
            preconfirmation_id.clone(),
            ScenarioStepKind::FastPreconfirmation,
            request.subject_id.clone(),
            root.clone(),
            request.preconfirmed_at_height,
            payload,
        );
        self.counters.preconfirmations = self.counters.preconfirmations.saturating_add(1);
        Ok((preconfirmation_id, root))
    }

    fn bridge_exit(
        &mut self,
        sequence: u64,
        request: &MoneroBridgeExitRequest,
    ) -> Result<(String, String)> {
        self.require_session(&request.session_id)?;
        ensure(
            request.amount_piconero > request.fee_piconero,
            "exit fee consumes amount",
        )?;
        ensure(
            !self
                .consumed_nullifiers
                .contains(&request.burn_nullifier_root),
            "burn nullifier already consumed",
        )?;
        self.consumed_nullifiers
            .insert(request.burn_nullifier_root.clone());
        let exit_id = deterministic_id(
            "MONERO-EXIT",
            &[
                HashPart::Str(&request.session_id),
                HashPart::Str(&request.exit_owner_commitment),
                HashPart::Str(&request.burn_nullifier_root),
                HashPart::U64(sequence),
            ],
        );
        let payload = json!({
            "amount_piconero": request.amount_piconero,
            "asset_id": self.config.bridge_asset_id,
            "burn_nullifier_root": request.burn_nullifier_root,
            "exit_id": exit_id,
            "exit_owner_commitment": request.exit_owner_commitment,
            "fee_piconero": request.fee_piconero,
            "monero_network": self.config.monero_network,
            "monero_subaddress_root": request.monero_subaddress_root,
            "requested_at_height": request.requested_at_height,
            "scheme": MONERO_EXIT_SCHEME,
            "session_id": request.session_id,
        });
        let root = record_root("MONERO-EXIT", &payload);
        self.insert_artifact(
            exit_id.clone(),
            ScenarioStepKind::MoneroBridgeExit,
            request.session_id.clone(),
            root.clone(),
            request.requested_at_height,
            payload,
        );
        self.counters.exits = self.counters.exits.saturating_add(1);
        Ok((exit_id, root))
    }

    fn open_dispute(
        &mut self,
        sequence: u64,
        request: &WatchtowerDisputeRequest,
    ) -> Result<(String, String)> {
        ensure(!request.watcher_id.is_empty(), "watcher id is empty")?;
        ensure(!request.subject_id.is_empty(), "dispute subject is empty")?;
        ensure(request.bond_piconero > 0, "dispute bond is zero")?;
        let dispute_id = deterministic_id(
            "WATCHTOWER-DISPUTE",
            &[
                HashPart::Str(&request.watcher_id),
                HashPart::Str(&request.subject_id),
                HashPart::Str(&request.evidence_root),
                HashPart::U64(sequence),
            ],
        );
        let payload = json!({
            "bond_piconero": request.bond_piconero,
            "disputed_root": request.disputed_root,
            "dispute_id": dispute_id,
            "evidence_root": request.evidence_root,
            "opened_at_height": request.opened_at_height,
            "scheme": WATCHTOWER_DISPUTE_SCHEME,
            "subject_id": request.subject_id,
            "watcher_id": request.watcher_id,
        });
        let root = record_root("WATCHTOWER-DISPUTE", &payload);
        self.insert_artifact(
            dispute_id.clone(),
            ScenarioStepKind::WatchtowerDispute,
            request.subject_id.clone(),
            root.clone(),
            request.opened_at_height,
            payload,
        );
        self.counters.disputes = self.counters.disputes.saturating_add(1);
        Ok((dispute_id, root))
    }

    fn record_readiness(
        &mut self,
        sequence: u64,
        request: &ReadinessAssertionRequest,
    ) -> Result<(String, String)> {
        ensure(
            !request.assertion_key.is_empty(),
            "readiness assertion key is empty",
        )?;
        let assertion_id = deterministic_id(
            "READINESS",
            &[
                HashPart::Str(&request.assertion_key),
                HashPart::Str(&request.subject_root),
                HashPart::U64(sequence),
            ],
        );
        if request.required && !request.observed {
            self.readiness_failures.insert(assertion_id.clone());
        }
        let payload = json!({
            "assertion_id": assertion_id,
            "assertion_key": request.assertion_key,
            "checked_at_height": request.checked_at_height,
            "observed": request.observed,
            "required": request.required,
            "subject_root": request.subject_root,
        });
        let root = record_root("READINESS", &payload);
        self.insert_artifact(
            assertion_id.clone(),
            ScenarioStepKind::ReadinessAssertion,
            request.assertion_key.clone(),
            root.clone(),
            request.checked_at_height,
            payload,
        );
        self.counters.assertions = self.counters.assertions.saturating_add(1);
        Ok((assertion_id, root))
    }

    fn insert_artifact(
        &mut self,
        artifact_id: String,
        kind: ScenarioStepKind,
        subject_id: String,
        root: String,
        height: u64,
        public_payload: Value,
    ) {
        let artifact = ScenarioArtifact {
            artifact_id: artifact_id.clone(),
            kind,
            subject_id,
            root,
            height,
            public_payload,
        };
        self.public_records
            .insert(artifact_id.clone(), artifact.public_record());
        self.artifacts.insert(artifact_id, artifact);
    }

    fn require_session(&self, session_id: &str) -> Result<()> {
        ensure(self.sessions.contains_key(session_id), "unknown session id")
    }

    fn recompute_roots(&mut self) {
        self.roots.account_root = map_root("ACCOUNTS", &self.sessions, |session| {
            json!({
                "account_id": session.account_id,
                "owner_commitment": session.owner_commitment,
            })
        });
        self.roots.session_root =
            map_root("SESSIONS", &self.sessions, AccountSession::public_record);
        self.roots.deposit_note_root = artifact_root(
            &self.artifacts,
            ScenarioStepKind::PrivateDepositNoteMint,
            "DEPOSIT-NOTES",
        );
        self.roots.token_root = artifact_root(
            &self.artifacts,
            ScenarioStepKind::TokenFactoryIssue,
            "TOKENS",
        );
        self.roots.transfer_root = artifact_root(
            &self.artifacts,
            ScenarioStepKind::ConfidentialTokenTransfer,
            "TRANSFERS",
        );
        self.roots.contract_call_root = artifact_root(
            &self.artifacts,
            ScenarioStepKind::ConfidentialContractCall,
            "CONTRACT-CALLS",
        );
        self.roots.settlement_root = artifact_root(
            &self.artifacts,
            ScenarioStepKind::LowFeeBatchSettlement,
            "SETTLEMENTS",
        );
        self.roots.preconfirmation_root = artifact_root(
            &self.artifacts,
            ScenarioStepKind::FastPreconfirmation,
            "PRECONFIRMATIONS",
        );
        self.roots.exit_root =
            artifact_root(&self.artifacts, ScenarioStepKind::MoneroBridgeExit, "EXITS");
        self.roots.dispute_root = artifact_root(
            &self.artifacts,
            ScenarioStepKind::WatchtowerDispute,
            "DISPUTES",
        );
        self.roots.readiness_root = artifact_root(
            &self.artifacts,
            ScenarioStepKind::ReadinessAssertion,
            "READINESS",
        );
        let scenario_steps = self
            .scenario
            .steps
            .iter()
            .map(ScenarioStep::public_record)
            .collect::<Vec<_>>();
        self.roots.scenario_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEVNET-SCENARIO",
            &scenario_steps,
        );
        self.roots.public_record_root =
            map_root("PUBLIC-RECORDS", &self.public_records, Clone::clone);
        self.scenario.final_root = record_root(
            "FINAL",
            &json!({
                "counters": self.counters.public_record(),
                "roots": self.roots.public_record(),
                "status": self.scenario.status.as_str(),
            }),
        );
    }
}

pub fn demo_config() -> Config {
    Config::default()
}

pub fn demo_runtime() -> Result<Runtime> {
    Runtime::run_demo()
}

pub fn demo_requests(config: &Config) -> Vec<ScenarioRequest> {
    let owner_a = root_from_label("DEVNET-OWNER", "alice");
    let owner_b = root_from_label("DEVNET-OWNER", "bob");
    let pq_root = root_from_label("DEVNET-PQ-PUBLIC-KEY", "alice-ml-dsa");
    let policy_root = root_from_label("DEVNET-SESSION-POLICY", "contract-token-bridge");
    let account_id = deterministic_id(
        "ACCOUNT",
        &[HashPart::Str("alice"), HashPart::Str(&owner_a)],
    );
    let session_id = deterministic_id(
        "SESSION",
        &[
            HashPart::Str(&account_id),
            HashPart::Str(&pq_root),
            HashPart::Str(&policy_root),
            HashPart::U64(1),
        ],
    );
    let token_id = deterministic_id(
        "TOKEN",
        &[
            HashPart::Str(&session_id),
            HashPart::Str("dXMR"),
            HashPart::Str(&root_from_label("DEVNET-SUPPLY", "dxmr")),
            HashPart::U64(3),
        ],
    );
    let contract_call_root = record_root(
        "DEMO-CONTRACT-CALL-SUBJECT",
        &json!({"contract": "confidential-swap-vault", "session_id": session_id}),
    );

    vec![
        ScenarioRequest::PqAccountSessionSetup(PqAccountSessionRequest {
            account_label: "alice".to_string(),
            owner_commitment: owner_a.clone(),
            pq_public_key_root: pq_root,
            session_policy_root: policy_root,
            opened_at_height: config.start_height,
            expires_at_height: config
                .start_height
                .saturating_add(config.session_ttl_blocks),
        }),
        ScenarioRequest::PrivateDepositNoteMint(PrivateDepositNoteMintRequest {
            session_id: session_id.clone(),
            monero_tx_root: root_from_label("DEVNET-MONERO-TX", "deposit-0001"),
            output_commitment_root: root_from_label("DEVNET-OUTPUT", "deposit-output-0001"),
            view_tag_root: root_from_label("DEVNET-VIEW-TAG", "deposit-view-tag-0001"),
            amount_piconero: 5_000_000_000,
            minted_at_height: config.start_height.saturating_add(1),
        }),
        ScenarioRequest::TokenFactoryIssue(TokenFactoryRequest {
            issuer_session_id: session_id.clone(),
            symbol: "dXMR".to_string(),
            metadata_root: root_from_label("DEVNET-TOKEN-METADATA", "dxmr"),
            supply_commitment_root: root_from_label("DEVNET-SUPPLY", "dxmr"),
            privacy_policy_root: root_from_label("DEVNET-TOKEN-PRIVACY", "shielded-transfer"),
            issued_at_height: config.start_height.saturating_add(2),
        }),
        ScenarioRequest::ConfidentialTokenTransfer(ConfidentialTransferRequest {
            token_id: token_id.clone(),
            from_owner_commitment: owner_a.clone(),
            to_owner_commitment: owner_b.clone(),
            amount_commitment_root: root_from_label("DEVNET-AMOUNT", "transfer-0001"),
            nullifier_root: root_from_label("DEVNET-NULLIFIER", "transfer-0001"),
            transfer_proof_root: root_from_label("DEVNET-PROOF", "transfer-0001"),
            submitted_at_height: config.start_height.saturating_add(3),
        }),
        ScenarioRequest::ConfidentialContractCall(ConfidentialContractCallRequest {
            session_id: session_id.clone(),
            contract_id: "confidential-swap-vault".to_string(),
            selector_root: root_from_label("DEVNET-SELECTOR", "swap"),
            encrypted_calldata_root: root_from_label("DEVNET-CALLDATA", "swap-call"),
            witness_root: root_from_label("DEVNET-WITNESS", "swap-witness"),
            max_fee_piconero: 20_000,
            submitted_at_height: config.start_height.saturating_add(4),
        }),
        ScenarioRequest::LowFeeBatchSettlement(LowFeeBatchSettlementRequest {
            coordinator_id: "low-fee-batcher-a".to_string(),
            item_roots: vec![
                root_from_label("DEVNET-BATCH-ITEM", "deposit-note"),
                root_from_label("DEVNET-BATCH-ITEM", "token-transfer"),
                contract_call_root.clone(),
            ],
            fee_bps: config.low_fee_bps,
            proof_root: root_from_label("DEVNET-BATCH-PROOF", "batch-0001"),
            settled_at_height: config.start_height.saturating_add(5),
        }),
        ScenarioRequest::FastPreconfirmation(FastPreconfirmationRequest {
            subject_id: "low-fee-batch-0001".to_string(),
            sequencer_committee_root: root_from_label("DEVNET-SEQUENCER-COMMITTEE", "fast-lane"),
            attestation_root: root_from_label("DEVNET-PRECONFIRMATION", "batch-0001"),
            latency_ms: config.fast_preconfirmation_ms.saturating_sub(150),
            preconfirmed_at_height: config.start_height.saturating_add(6),
        }),
        ScenarioRequest::MoneroBridgeExit(MoneroBridgeExitRequest {
            session_id: session_id.clone(),
            exit_owner_commitment: owner_b,
            burn_nullifier_root: root_from_label("DEVNET-BURN-NULLIFIER", "exit-0001"),
            monero_subaddress_root: root_from_label("DEVNET-SUBADDRESS", "bob-exit"),
            amount_piconero: 1_500_000_000,
            fee_piconero: 4_000,
            requested_at_height: config.start_height.saturating_add(7),
        }),
        ScenarioRequest::WatchtowerDispute(WatchtowerDisputeRequest {
            watcher_id: "watchtower-a".to_string(),
            subject_id: "low-fee-batch-0001".to_string(),
            evidence_root: root_from_label("DEVNET-WATCHTOWER-EVIDENCE", "late-da-claim"),
            disputed_root: contract_call_root,
            bond_piconero: 250_000_000,
            opened_at_height: config.start_height.saturating_add(8),
        }),
        ScenarioRequest::ReadinessAssertion(ReadinessAssertionRequest {
            assertion_key: "all-critical-paths-observed".to_string(),
            subject_root: root_from_label("DEVNET-READINESS", "critical-paths"),
            required: true,
            observed: true,
            checked_at_height: config.start_height.saturating_add(9),
        }),
    ]
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-DEVNET-SCENARIO-RUNNER-{domain}"),
        parts,
        32,
    )
}

pub fn root_from_label(domain: &str, label: &str) -> String {
    deterministic_id(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)])
}

pub fn record_root(domain: &str, record: &Value) -> String {
    deterministic_id(domain, &[HashPart::Str(CHAIN_ID), HashPart::Json(record)])
}

pub fn public_record_root(record: &Value) -> String {
    record_root("PUBLIC-RECORD", record)
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-DEVNET-SCENARIO-RUNNER-{domain}"),
        &[],
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, value)| json!({"id": id, "record": record(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-DEVNET-SCENARIO-RUNNER-{domain}"),
        &leaves,
    )
}

fn artifact_root(
    artifacts: &BTreeMap<String, ScenarioArtifact>,
    kind: ScenarioStepKind,
    domain: &str,
) -> String {
    let leaves = artifacts
        .values()
        .filter(|artifact| artifact.kind == kind)
        .map(ScenarioArtifact::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-DEVNET-SCENARIO-RUNNER-{domain}"),
        &leaves,
    )
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
