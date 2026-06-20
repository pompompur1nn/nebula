use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitPrivateNoteStateTransitionContractRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_NOTE_STATE_TRANSITION_CONTRACT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-private-note-state-transition-contract-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_NOTE_STATE_TRANSITION_CONTRACT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_NOTE_CONTRACT_SUITE: &str =
    "monero-l2-pq-private-note-state-transition-contract-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 620_120;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 6;
pub const DEFAULT_MAX_SCAN_HINTS: u64 = 4;
pub const DEFAULT_FORCED_EXIT_LINKS: u64 = 5;
pub const DEFAULT_MAX_RECEIPTS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateActionKind {
    Transfer,
    ContractCall,
    ForcedExitPrepare,
}

impl PrivateActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::ContractCall => "contract_call",
            Self::ForcedExitPrepare => "forced_exit_prepare",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionStatus {
    Accepted,
    Watch,
    Rejected,
}

impl TransitionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Accepted | Self::Watch)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub contract_suite: String,
    pub base_l2_height: u64,
    pub min_privacy_set_size: u64,
    pub metadata_budget_units: u64,
    pub max_scan_hints: u64,
    pub forced_exit_links_required: u64,
    pub receipts_include_payloads: bool,
    pub max_receipts: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            contract_suite: PRIVATE_NOTE_CONTRACT_SUITE.to_string(),
            base_l2_height: DEFAULT_DEVNET_HEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            metadata_budget_units: DEFAULT_METADATA_BUDGET_UNITS,
            max_scan_hints: DEFAULT_MAX_SCAN_HINTS,
            forced_exit_links_required: DEFAULT_FORCED_EXIT_LINKS,
            receipts_include_payloads: false,
            max_receipts: DEFAULT_MAX_RECEIPTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "contract_suite": self.contract_suite,
            "base_l2_height": self.base_l2_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "metadata_budget_units": self.metadata_budget_units,
            "max_scan_hints": self.max_scan_hints,
            "forced_exit_links_required": self.forced_exit_links_required,
            "receipts_include_payloads": self.receipts_include_payloads,
            "max_receipts": self.max_receipts,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositNoteMintRequest {
    pub deposit_lock_id: String,
    pub watcher_certificate_root: String,
    pub owner_view_tag_root: String,
    pub owner_spend_commitment_root: String,
    pub amount_commitment_root: String,
    pub asset_id: String,
    pub l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateActionRequest {
    pub action_kind: PrivateActionKind,
    pub input_note_commitment: String,
    pub output_note_commitment: String,
    pub contract_call_root: String,
    pub encrypted_call_data_root: String,
    pub wallet_scan_hint_root: String,
    pub forced_exit_context_root: String,
    pub metadata_units: u64,
    pub privacy_set_size: u64,
    pub l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositNoteRecord {
    pub note_id: String,
    pub deposit_lock_id: String,
    pub note_commitment: String,
    pub watcher_certificate_root: String,
    pub owner_view_tag_root: String,
    pub owner_spend_commitment_root: String,
    pub amount_commitment_root: String,
    pub asset_id: String,
    pub note_leaf_index: u64,
    pub minted_height: u64,
    pub note_root_after_mint: String,
}

impl DepositNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "deposit_lock_id": self.deposit_lock_id,
            "note_commitment": self.note_commitment,
            "watcher_certificate_root": self.watcher_certificate_root,
            "owner_view_tag_root": self.owner_view_tag_root,
            "owner_spend_commitment_root": self.owner_spend_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "asset_id": self.asset_id,
            "note_leaf_index": self.note_leaf_index,
            "minted_height": self.minted_height,
            "note_root_after_mint": self.note_root_after_mint,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deposit_note", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierKeyImageCommitment {
    pub nullifier_id: String,
    pub key_image_commitment: String,
    pub input_note_commitment: String,
    pub action_domain_root: String,
    pub replay_fence_root: String,
    pub nullifier_leaf_index: u64,
}

impl NullifierKeyImageCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "key_image_commitment": self.key_image_commitment,
            "input_note_commitment": self.input_note_commitment,
            "action_domain_root": self.action_domain_root,
            "replay_fence_root": self.replay_fence_root,
            "nullifier_leaf_index": self.nullifier_leaf_index,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletScanHints {
    pub hint_id: String,
    pub view_tag_root: String,
    pub subaddress_hint_root: String,
    pub receipt_commitment_root: String,
    pub forced_exit_guard_root: String,
    pub committed_hint_count: u64,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
}

impl WalletScanHints {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "view_tag_root": self.view_tag_root,
            "subaddress_hint_root": self.subaddress_hint_root,
            "receipt_commitment_root": self.receipt_commitment_root,
            "forced_exit_guard_root": self.forced_exit_guard_root,
            "committed_hint_count": self.committed_hint_count,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetadataBudgetRecord {
    pub budget_id: String,
    pub used_units: u64,
    pub max_units: u64,
    pub privacy_set_size: u64,
    pub privacy_floor: u64,
    pub metadata_budget_root: String,
}

impl MetadataBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "used_units": self.used_units,
            "max_units": self.max_units,
            "privacy_set_size": self.privacy_set_size,
            "privacy_floor": self.privacy_floor,
            "metadata_budget_root": self.metadata_budget_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitContinuityProof {
    pub proof_id: String,
    pub deposit_note_root: String,
    pub action_receipt_root: String,
    pub nullifier_root: String,
    pub wallet_hint_root: String,
    pub metadata_budget_root: String,
    pub forced_exit_context_root: String,
    pub continuity_root: String,
    pub required_links: u64,
    pub proven_links: u64,
}

impl ForcedExitContinuityProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "deposit_note_root": self.deposit_note_root,
            "action_receipt_root": self.action_receipt_root,
            "nullifier_root": self.nullifier_root,
            "wallet_hint_root": self.wallet_hint_root,
            "metadata_budget_root": self.metadata_budget_root,
            "forced_exit_context_root": self.forced_exit_context_root,
            "continuity_root": self.continuity_root,
            "required_links": self.required_links,
            "proven_links": self.proven_links,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateTransitionReceipt {
    pub receipt_id: String,
    pub status: TransitionStatus,
    pub action_kind: PrivateActionKind,
    pub deposit_note: DepositNoteRecord,
    pub nullifier_commitment: NullifierKeyImageCommitment,
    pub wallet_scan_hints: WalletScanHints,
    pub metadata_budget: MetadataBudgetRecord,
    pub forced_exit_proof: ForcedExitContinuityProof,
    pub output_note_commitment: String,
    pub contract_call_root: String,
    pub encrypted_call_data_root: String,
    pub encrypted_receipt_root: String,
    pub note_root_before: String,
    pub note_root_after: String,
    pub nullifier_root_after: String,
    pub receipt_root: String,
    pub payload: Option<Value>,
}

impl PrivateTransitionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "action_kind": self.action_kind.as_str(),
            "deposit_note": self.deposit_note.public_record(),
            "nullifier_commitment": self.nullifier_commitment.public_record(),
            "wallet_scan_hints": self.wallet_scan_hints.public_record(),
            "metadata_budget": self.metadata_budget.public_record(),
            "forced_exit_proof": self.forced_exit_proof.public_record(),
            "output_note_commitment": self.output_note_commitment,
            "contract_call_root": self.contract_call_root,
            "encrypted_call_data_root": self.encrypted_call_data_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "note_root_before": self.note_root_before,
            "note_root_after": self.note_root_after,
            "nullifier_root_after": self.nullifier_root_after,
            "receipt_root": self.receipt_root,
            "payload": self.payload,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private_transition_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub deposit_notes_minted: u64,
    pub private_actions_applied: u64,
    pub encrypted_receipts_anchored: u64,
    pub nullifiers_committed: u64,
    pub wallet_scan_hints_committed: u64,
    pub metadata_units_used: u64,
    pub forced_exit_proofs_continuous: u64,
    pub receipts_accepted: u64,
    pub receipts_watch: u64,
    pub receipts_rejected: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_notes_minted": self.deposit_notes_minted,
            "private_actions_applied": self.private_actions_applied,
            "encrypted_receipts_anchored": self.encrypted_receipts_anchored,
            "nullifiers_committed": self.nullifiers_committed,
            "wallet_scan_hints_committed": self.wallet_scan_hints_committed,
            "metadata_units_used": self.metadata_units_used,
            "forced_exit_proofs_continuous": self.forced_exit_proofs_continuous,
            "receipts_accepted": self.receipts_accepted,
            "receipts_watch": self.receipts_watch,
            "receipts_rejected": self.receipts_rejected,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub deposit_note_root: String,
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub encrypted_receipt_root: String,
    pub wallet_scan_hint_root: String,
    pub metadata_budget_root: String,
    pub forced_exit_continuity_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let empty = merkle_root(
            "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-EMPTY",
            &[],
        );
        let mut roots = Self {
            config_root: config.state_root(),
            deposit_note_root: empty.clone(),
            note_commitment_root: empty.clone(),
            nullifier_root: empty.clone(),
            encrypted_receipt_root: empty.clone(),
            wallet_scan_hint_root: empty.clone(),
            metadata_budget_root: empty.clone(),
            forced_exit_continuity_root: empty,
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "deposit_note_root": self.deposit_note_root,
            "note_commitment_root": self.note_commitment_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "metadata_budget_root": self.metadata_budget_root,
            "forced_exit_continuity_root": self.forced_exit_continuity_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.deposit_note_root),
                HashPart::Str(&self.note_commitment_root),
                HashPart::Str(&self.nullifier_root),
                HashPart::Str(&self.encrypted_receipt_root),
                HashPart::Str(&self.wallet_scan_hint_root),
                HashPart::Str(&self.metadata_budget_root),
                HashPart::Str(&self.forced_exit_continuity_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub deposit_notes: BTreeMap<String, DepositNoteRecord>,
    pub latest_receipt: Option<PrivateTransitionReceipt>,
    pub receipt_history: Vec<PrivateTransitionReceipt>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            deposit_notes: BTreeMap::new(),
            latest_receipt: None,
            receipt_history: Vec::new(),
            counters,
            roots,
        };
        let deposit = DepositNoteMintRequest {
            deposit_lock_id: fixture_root("devnet-deposit-lock", 0),
            watcher_certificate_root: fixture_root("devnet-watcher-certificate", 0),
            owner_view_tag_root: fixture_root("devnet-owner-view-tag", 0),
            owner_spend_commitment_root: fixture_root("devnet-owner-spend-commitment", 0),
            amount_commitment_root: fixture_root("devnet-amount-commitment", 0),
            asset_id: "wxmr-devnet".to_string(),
            l2_height: DEFAULT_DEVNET_HEIGHT,
        };
        let note = state.mint_deposit_note(deposit);
        let action = PrivateActionRequest {
            action_kind: PrivateActionKind::ForcedExitPrepare,
            input_note_commitment: note.note_commitment,
            output_note_commitment: fixture_root("devnet-output-note", 0),
            contract_call_root: fixture_root("devnet-contract-action", 0),
            encrypted_call_data_root: fixture_root("devnet-encrypted-call-data", 0),
            wallet_scan_hint_root: fixture_root("devnet-wallet-scan-hint", 0),
            forced_exit_context_root: fixture_root("devnet-forced-exit-context", 0),
            metadata_units: 4,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            l2_height: DEFAULT_DEVNET_HEIGHT + 2,
        };
        let _ = state.apply_private_action(action);
        state
    }

    pub fn mint_deposit_note(&mut self, request: DepositNoteMintRequest) -> DepositNoteRecord {
        let note_leaf_index = self.deposit_notes.len() as u64;
        let note_commitment = note_commitment_root(&request, note_leaf_index);
        let note_id = note_id(&request.deposit_lock_id, &note_commitment);
        let mut note = DepositNoteRecord {
            note_id,
            deposit_lock_id: request.deposit_lock_id,
            note_commitment,
            watcher_certificate_root: request.watcher_certificate_root,
            owner_view_tag_root: request.owner_view_tag_root,
            owner_spend_commitment_root: request.owner_spend_commitment_root,
            amount_commitment_root: request.amount_commitment_root,
            asset_id: request.asset_id,
            note_leaf_index,
            minted_height: request.l2_height,
            note_root_after_mint: String::new(),
        };
        let mut note_roots = self
            .deposit_notes
            .values()
            .map(DepositNoteRecord::state_root)
            .map(Value::String)
            .collect::<Vec<_>>();
        note_roots.push(Value::String(note.state_root()));
        note.note_root_after_mint = merkle_root(
            "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-NOTES-AFTER-MINT",
            &note_roots,
        );
        self.deposit_notes
            .insert(note.note_commitment.clone(), note.clone());
        self.counters.deposit_notes_minted += 1;
        self.refresh_roots();
        note
    }

    pub fn apply_private_action(
        &mut self,
        request: PrivateActionRequest,
    ) -> Result<PrivateTransitionReceipt> {
        let deposit_note = self
            .deposit_notes
            .get(&request.input_note_commitment)
            .cloned()
            .ok_or_else(|| "private action requires known input note commitment".to_string())?;
        let note_root_before = self.roots.note_commitment_root.clone();
        let action_domain_root = action_domain_root(&request);
        let nullifier_commitment = nullifier_commitment(
            &request.input_note_commitment,
            &action_domain_root,
            self.counters.nullifiers_committed,
        );
        let wallet_scan_hints = wallet_scan_hints(&self.config, &request, &deposit_note);
        let metadata_budget = metadata_budget(&self.config, &request);
        let encrypted_receipt_root =
            encrypted_receipt_root(&deposit_note, &request, &nullifier_commitment);
        let action_receipt_root = action_receipt_root(
            &encrypted_receipt_root,
            &request.output_note_commitment,
            &request.contract_call_root,
        );
        let forced_exit_proof = forced_exit_proof(
            &self.config,
            &deposit_note,
            &request,
            &nullifier_commitment,
            &wallet_scan_hints,
            &metadata_budget,
            &action_receipt_root,
        );
        let status = transition_status(&self.config, &metadata_budget, &forced_exit_proof);
        let note_root_after = merkle_root(
            "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-NOTE-COMMITMENTS-AFTER-ACTION",
            &[
                Value::String(self.roots.note_commitment_root.clone()),
                Value::String(request.output_note_commitment.clone()),
            ],
        );
        let nullifier_root_after = merkle_root(
            "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-NULLIFIERS-AFTER-ACTION",
            &[
                Value::String(self.roots.nullifier_root.clone()),
                Value::String(nullifier_commitment.nullifier_id.clone()),
            ],
        );
        let receipt_id = receipt_id(&encrypted_receipt_root, self.receipt_history.len() as u64);
        let payload = self.config.receipts_include_payloads.then(|| {
            json!({
                "input_note_commitment": request.input_note_commitment,
                "output_note_commitment": request.output_note_commitment,
                "contract_call_root": request.contract_call_root,
                "encrypted_call_data_root": request.encrypted_call_data_root,
            })
        });
        let mut receipt = PrivateTransitionReceipt {
            receipt_id,
            status,
            action_kind: request.action_kind,
            deposit_note,
            nullifier_commitment,
            wallet_scan_hints,
            metadata_budget,
            forced_exit_proof,
            output_note_commitment: request.output_note_commitment,
            contract_call_root: request.contract_call_root,
            encrypted_call_data_root: request.encrypted_call_data_root,
            encrypted_receipt_root,
            note_root_before,
            note_root_after,
            nullifier_root_after,
            receipt_root: String::new(),
            payload,
        };
        receipt.receipt_root = receipt.state_root();
        self.apply_receipt(receipt.clone());
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        let deposit_notes = self
            .deposit_notes
            .values()
            .map(DepositNoteRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_history = self
            .receipt_history
            .iter()
            .map(PrivateTransitionReceipt::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "deposit_notes": deposit_notes,
            "latest_receipt": self.latest_receipt.as_ref().map(PrivateTransitionReceipt::public_record),
            "receipt_history": receipt_history,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn apply_receipt(&mut self, receipt: PrivateTransitionReceipt) {
        self.counters.private_actions_applied += 1;
        self.counters.encrypted_receipts_anchored += 1;
        self.counters.nullifiers_committed += 1;
        self.counters.wallet_scan_hints_committed += receipt.wallet_scan_hints.committed_hint_count;
        self.counters.metadata_units_used += receipt.metadata_budget.used_units;
        if receipt.forced_exit_proof.proven_links >= receipt.forced_exit_proof.required_links {
            self.counters.forced_exit_proofs_continuous += 1;
        }
        match receipt.status {
            TransitionStatus::Accepted => self.counters.receipts_accepted += 1,
            TransitionStatus::Watch => self.counters.receipts_watch += 1,
            TransitionStatus::Rejected => self.counters.receipts_rejected += 1,
        }
        self.latest_receipt = Some(receipt.clone());
        self.receipt_history.push(receipt);
        if self.receipt_history.len() > self.config.max_receipts {
            let trim = self.receipt_history.len() - self.config.max_receipts;
            self.receipt_history.drain(0..trim);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let deposit_note_roots = self
            .deposit_notes
            .values()
            .map(DepositNoteRecord::state_root)
            .map(Value::String)
            .collect::<Vec<_>>();
        let note_commitments = self
            .deposit_notes
            .values()
            .map(|note| note.note_commitment.clone())
            .map(Value::String)
            .collect::<Vec<_>>();
        let nullifiers = self
            .receipt_history
            .iter()
            .map(|receipt| receipt.nullifier_commitment.nullifier_id.clone())
            .map(Value::String)
            .collect::<Vec<_>>();
        let encrypted_receipts = self
            .receipt_history
            .iter()
            .map(|receipt| receipt.encrypted_receipt_root.clone())
            .map(Value::String)
            .collect::<Vec<_>>();
        let wallet_hints = self
            .receipt_history
            .iter()
            .map(|receipt| receipt.wallet_scan_hints.hint_id.clone())
            .map(Value::String)
            .collect::<Vec<_>>();
        let metadata_budgets = self
            .receipt_history
            .iter()
            .map(|receipt| receipt.metadata_budget.metadata_budget_root.clone())
            .map(Value::String)
            .collect::<Vec<_>>();
        let forced_exit_proofs = self
            .receipt_history
            .iter()
            .map(|receipt| receipt.forced_exit_proof.continuity_root.clone())
            .map(Value::String)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            deposit_note_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-DEPOSIT-NOTES",
                &deposit_note_roots,
            ),
            note_commitment_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-NOTE-COMMITMENTS",
                &note_commitments,
            ),
            nullifier_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-NULLIFIERS",
                &nullifiers,
            ),
            encrypted_receipt_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-ENCRYPTED-RECEIPTS",
                &encrypted_receipts,
            ),
            wallet_scan_hint_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-WALLET-HINTS",
                &wallet_hints,
            ),
            metadata_budget_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-METADATA-BUDGETS",
                &metadata_budgets,
            ),
            forced_exit_continuity_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-FORCED-EXIT-PROOFS",
                &forced_exit_proofs,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn note_commitment_root(request: &DepositNoteMintRequest, note_leaf_index: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-NOTE-COMMITMENT",
        &[
            HashPart::Str(&request.deposit_lock_id),
            HashPart::Str(&request.watcher_certificate_root),
            HashPart::Str(&request.owner_view_tag_root),
            HashPart::Str(&request.owner_spend_commitment_root),
            HashPart::Str(&request.amount_commitment_root),
            HashPart::Str(&request.asset_id),
            HashPart::U64(note_leaf_index),
        ],
        32,
    )
}

fn note_id(deposit_lock_id: &str, note_commitment: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-NOTE-ID",
        &[
            HashPart::Str(deposit_lock_id),
            HashPart::Str(note_commitment),
        ],
        16,
    )
}

fn action_domain_root(request: &PrivateActionRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-ACTION-DOMAIN",
        &[
            HashPart::Str(request.action_kind.as_str()),
            HashPart::Str(&request.input_note_commitment),
            HashPart::Str(&request.output_note_commitment),
            HashPart::Str(&request.contract_call_root),
            HashPart::Str(&request.encrypted_call_data_root),
            HashPart::U64(request.l2_height),
        ],
        32,
    )
}

fn nullifier_commitment(
    input_note_commitment: &str,
    action_domain_root: &str,
    nullifier_leaf_index: u64,
) -> NullifierKeyImageCommitment {
    let replay_fence_root = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-REPLAY-FENCE",
        &[
            HashPart::Str(input_note_commitment),
            HashPart::Str(action_domain_root),
        ],
        32,
    );
    let key_image_commitment = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-KEY-IMAGE",
        &[
            HashPart::Str(input_note_commitment),
            HashPart::Str(&replay_fence_root),
            HashPart::U64(nullifier_leaf_index),
        ],
        32,
    );
    let nullifier_id = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-NULLIFIER-ID",
        &[HashPart::Str(&key_image_commitment)],
        16,
    );
    NullifierKeyImageCommitment {
        nullifier_id,
        key_image_commitment,
        input_note_commitment: input_note_commitment.to_string(),
        action_domain_root: action_domain_root.to_string(),
        replay_fence_root,
        nullifier_leaf_index,
    }
}

fn wallet_scan_hints(
    config: &Config,
    request: &PrivateActionRequest,
    deposit_note: &DepositNoteRecord,
) -> WalletScanHints {
    let committed_hint_count = config.max_scan_hints.min(4);
    let subaddress_hint_root = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-SUBADDRESS-HINT",
        &[
            HashPart::Str(&deposit_note.deposit_lock_id),
            HashPart::Str(&request.wallet_scan_hint_root),
        ],
        32,
    );
    let receipt_commitment_root = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-RECEIPT-COMMITMENT-HINT",
        &[
            HashPart::Str(&request.output_note_commitment),
            HashPart::Str(&request.encrypted_call_data_root),
        ],
        32,
    );
    let forced_exit_guard_root = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-FORCED-EXIT-GUARD-HINT",
        &[
            HashPart::Str(&request.forced_exit_context_root),
            HashPart::Str(&receipt_commitment_root),
        ],
        32,
    );
    let hint_id = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-WALLET-HINT-ID",
        &[
            HashPart::Str(&deposit_note.owner_view_tag_root),
            HashPart::Str(&subaddress_hint_root),
            HashPart::Str(&receipt_commitment_root),
            HashPart::Str(&forced_exit_guard_root),
        ],
        16,
    );
    WalletScanHints {
        hint_id,
        view_tag_root: deposit_note.owner_view_tag_root.clone(),
        subaddress_hint_root,
        receipt_commitment_root,
        forced_exit_guard_root,
        committed_hint_count,
        scan_window_start: request.l2_height,
        scan_window_end: request.l2_height + 96,
    }
}

fn metadata_budget(config: &Config, request: &PrivateActionRequest) -> MetadataBudgetRecord {
    let metadata_budget_root = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-METADATA-BUDGET",
        &[
            HashPart::U64(request.metadata_units),
            HashPart::U64(config.metadata_budget_units),
            HashPart::U64(request.privacy_set_size),
            HashPart::U64(config.min_privacy_set_size),
        ],
        32,
    );
    let budget_id = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-METADATA-BUDGET-ID",
        &[HashPart::Str(&metadata_budget_root)],
        16,
    );
    MetadataBudgetRecord {
        budget_id,
        used_units: request.metadata_units,
        max_units: config.metadata_budget_units,
        privacy_set_size: request.privacy_set_size,
        privacy_floor: config.min_privacy_set_size,
        metadata_budget_root,
    }
}

fn encrypted_receipt_root(
    deposit_note: &DepositNoteRecord,
    request: &PrivateActionRequest,
    nullifier: &NullifierKeyImageCommitment,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-ENCRYPTED-RECEIPT",
        &[
            HashPart::Str(&deposit_note.note_commitment),
            HashPart::Str(&request.output_note_commitment),
            HashPart::Str(&request.encrypted_call_data_root),
            HashPart::Str(&nullifier.key_image_commitment),
        ],
        32,
    )
}

fn action_receipt_root(
    encrypted_receipt_root: &str,
    output_note_commitment: &str,
    contract_call_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-ACTION-RECEIPT",
        &[
            HashPart::Str(encrypted_receipt_root),
            HashPart::Str(output_note_commitment),
            HashPart::Str(contract_call_root),
        ],
        32,
    )
}

fn forced_exit_proof(
    config: &Config,
    deposit_note: &DepositNoteRecord,
    request: &PrivateActionRequest,
    nullifier: &NullifierKeyImageCommitment,
    wallet_hints: &WalletScanHints,
    metadata_budget: &MetadataBudgetRecord,
    action_receipt_root: &str,
) -> ForcedExitContinuityProof {
    let continuity_root = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-FORCED-EXIT-CONTINUITY",
        &[
            HashPart::Str(&deposit_note.note_root_after_mint),
            HashPart::Str(action_receipt_root),
            HashPart::Str(&nullifier.replay_fence_root),
            HashPart::Str(&wallet_hints.forced_exit_guard_root),
            HashPart::Str(&metadata_budget.metadata_budget_root),
            HashPart::Str(&request.forced_exit_context_root),
        ],
        32,
    );
    let proof_id = domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-FORCED-EXIT-PROOF-ID",
        &[HashPart::Str(&continuity_root)],
        16,
    );
    ForcedExitContinuityProof {
        proof_id,
        deposit_note_root: deposit_note.note_root_after_mint.clone(),
        action_receipt_root: action_receipt_root.to_string(),
        nullifier_root: nullifier.replay_fence_root.clone(),
        wallet_hint_root: wallet_hints.forced_exit_guard_root.clone(),
        metadata_budget_root: metadata_budget.metadata_budget_root.clone(),
        forced_exit_context_root: request.forced_exit_context_root.clone(),
        continuity_root,
        required_links: config.forced_exit_links_required,
        proven_links: 5,
    }
}

fn transition_status(
    config: &Config,
    metadata_budget: &MetadataBudgetRecord,
    forced_exit_proof: &ForcedExitContinuityProof,
) -> TransitionStatus {
    if metadata_budget.used_units > metadata_budget.max_units
        || metadata_budget.privacy_set_size < metadata_budget.privacy_floor
    {
        TransitionStatus::Rejected
    } else if forced_exit_proof.proven_links < config.forced_exit_links_required {
        TransitionStatus::Watch
    } else {
        TransitionStatus::Accepted
    }
}

fn receipt_id(encrypted_receipt_root: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-RECEIPT-ID",
        &[
            HashPart::Str(encrypted_receipt_root),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn fixture_root(label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-NOTE-STATE-TRANSITION-CONTRACT-FIXTURE",
        &[HashPart::Str(label), HashPart::U64(ordinal)],
        32,
    )
}
