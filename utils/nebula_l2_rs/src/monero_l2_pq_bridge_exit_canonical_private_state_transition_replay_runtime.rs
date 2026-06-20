use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalPrivateStateTransitionReplayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVATE_STATE_TRANSITION_REPLAY_RUNTIME_PROTOCOL_VERSION:
    &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-private-state-transition-replay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVATE_STATE_TRANSITION_REPLAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const REPLAY_SUITE: &str =
    "monero-l2-pq-canonical-private-state-transition-replay-after-deposit-note-v1";
pub const NOTE_COMMITMENT_SUITE: &str = "monero-deposit-private-note-commitment-root-v1";
pub const NULLIFIER_DOMAIN: &str = "monero-l2-private-nullifier-domain-v1";
pub const KEY_IMAGE_DOMAIN: &str = "monero-l2-private-key-image-domain-v1";
pub const ENCRYPTED_RECEIPT_SUITE: &str = "forced-exit-compatible-encrypted-receipt-root-v1";
pub const ACTION_ROOT_SUITE: &str = "private-transfer-or-contract-action-root-v1";
pub const DEFAULT_DEVNET_L2_HEIGHT: u64 = 744_128;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 6;
pub const DEFAULT_MAX_REPLAY_STEPS: usize = 16;
pub const DEFAULT_FORCED_EXIT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    PrivateTransfer,
    ContractAction,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractAction => "contract_action",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStepKind {
    DepositConfirmed,
    NoteMinted,
    NullifierDerived,
    ActionApplied,
    ReceiptSealed,
    MetadataChecked,
    ForcedExitPrepared,
    Verdict,
}

impl ReplayStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositConfirmed => "deposit_confirmed",
            Self::NoteMinted => "note_minted",
            Self::NullifierDerived => "nullifier_derived",
            Self::ActionApplied => "action_applied",
            Self::ReceiptSealed => "receipt_sealed",
            Self::MetadataChecked => "metadata_checked",
            Self::ForcedExitPrepared => "forced_exit_prepared",
            Self::Verdict => "verdict",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub replay_suite: String,
    pub note_commitment_suite: String,
    pub nullifier_domain: String,
    pub key_image_domain: String,
    pub encrypted_receipt_suite: String,
    pub action_root_suite: String,
    pub base_l2_height: u64,
    pub min_monero_confirmations: u64,
    pub min_privacy_set_size: u64,
    pub metadata_budget_units: u64,
    pub max_replay_steps: usize,
    pub forced_exit_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            replay_suite: REPLAY_SUITE.to_string(),
            note_commitment_suite: NOTE_COMMITMENT_SUITE.to_string(),
            nullifier_domain: NULLIFIER_DOMAIN.to_string(),
            key_image_domain: KEY_IMAGE_DOMAIN.to_string(),
            encrypted_receipt_suite: ENCRYPTED_RECEIPT_SUITE.to_string(),
            action_root_suite: ACTION_ROOT_SUITE.to_string(),
            base_l2_height: DEFAULT_DEVNET_L2_HEIGHT,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            metadata_budget_units: DEFAULT_METADATA_BUDGET_UNITS,
            max_replay_steps: DEFAULT_MAX_REPLAY_STEPS,
            forced_exit_ttl_blocks: DEFAULT_FORCED_EXIT_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "replay_suite": self.replay_suite,
            "suites": {
                "note_commitment": self.note_commitment_suite,
                "nullifier_domain": self.nullifier_domain,
                "key_image_domain": self.key_image_domain,
                "encrypted_receipt": self.encrypted_receipt_suite,
                "action_root": self.action_root_suite,
            },
            "limits": {
                "base_l2_height": self.base_l2_height,
                "min_monero_confirmations": self.min_monero_confirmations,
                "min_privacy_set_size": self.min_privacy_set_size,
                "metadata_budget_units": self.metadata_budget_units,
                "max_replay_steps": self.max_replay_steps,
                "forced_exit_ttl_blocks": self.forced_exit_ttl_blocks,
                "min_pq_security_bits": self.min_pq_security_bits,
            },
        })
    }

    pub fn root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DepositPrivateNote {
    pub deposit_id: String,
    pub monero_txid_root: String,
    pub monero_output_root: String,
    pub amount_commitment_root: String,
    pub owner_view_tag_root: String,
    pub owner_spend_authority_root: String,
    pub note_randomness_root: String,
    pub encrypted_note_root: String,
    pub note_commitment_root: String,
    pub note_tree_root_after_mint: String,
    pub monero_confirmations: u64,
    pub minted_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl DepositPrivateNote {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "monero_txid_root": self.monero_txid_root,
            "monero_output_root": self.monero_output_root,
            "amount_commitment_root": self.amount_commitment_root,
            "owner_view_tag_root": self.owner_view_tag_root,
            "owner_spend_authority_root": self.owner_spend_authority_root,
            "note_randomness_root": self.note_randomness_root,
            "encrypted_note_root": self.encrypted_note_root,
            "note_commitment_root": self.note_commitment_root,
            "note_tree_root_after_mint": self.note_tree_root_after_mint,
            "monero_confirmations": self.monero_confirmations,
            "minted_l2_height": self.minted_l2_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn root(&self) -> String {
        record_root("deposit_private_note", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierKeyImageDomainSeparation {
    pub input_note_commitment_root: String,
    pub replay_domain_root: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub nullifier_key_image_binding_root: String,
    pub duplicate_nullifier_seen: bool,
}

impl NullifierKeyImageDomainSeparation {
    pub fn public_record(&self) -> Value {
        json!({
            "input_note_commitment_root": self.input_note_commitment_root,
            "replay_domain_root": self.replay_domain_root,
            "nullifier_root": self.nullifier_root,
            "key_image_root": self.key_image_root,
            "nullifier_key_image_binding_root": self.nullifier_key_image_binding_root,
            "duplicate_nullifier_seen": self.duplicate_nullifier_seen,
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "nullifier_key_image_domain_separation",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateActionReplay {
    pub action_kind: ActionKind,
    pub input_note_commitment_root: String,
    pub output_note_commitment_root: String,
    pub private_transfer_root: String,
    pub contract_action_root: String,
    pub action_root: String,
    pub action_l2_height: u64,
}

impl PrivateActionReplay {
    pub fn public_record(&self) -> Value {
        json!({
            "action_kind": self.action_kind.as_str(),
            "input_note_commitment_root": self.input_note_commitment_root,
            "output_note_commitment_root": self.output_note_commitment_root,
            "private_transfer_root": self.private_transfer_root,
            "contract_action_root": self.contract_action_root,
            "action_root": self.action_root,
            "action_l2_height": self.action_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("private_action_replay", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedReceiptReplay {
    pub receipt_id: String,
    pub encrypted_receipt_root: String,
    pub receipt_tree_root: String,
    pub wallet_scan_hint_root: String,
    pub forced_exit_recovery_root: String,
    pub payloads_public: bool,
}

impl EncryptedReceiptReplay {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "receipt_tree_root": self.receipt_tree_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "forced_exit_recovery_root": self.forced_exit_recovery_root,
            "payloads_public": self.payloads_public,
        })
    }

    pub fn root(&self) -> String {
        record_root("encrypted_receipt_replay", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataBudgetReplay {
    pub metadata_budget_root: String,
    pub used_units: u64,
    pub budget_units: u64,
    pub privacy_set_size: u64,
    pub privacy_floor: u64,
    pub public_fields: Vec<String>,
}

impl MetadataBudgetReplay {
    pub fn public_record(&self) -> Value {
        json!({
            "metadata_budget_root": self.metadata_budget_root,
            "used_units": self.used_units,
            "budget_units": self.budget_units,
            "privacy_set_size": self.privacy_set_size,
            "privacy_floor": self.privacy_floor,
            "public_fields": self.public_fields,
            "within_budget": self.within_budget(),
        })
    }

    pub fn within_budget(&self) -> bool {
        self.used_units <= self.budget_units && self.privacy_set_size >= self.privacy_floor
    }

    pub fn root(&self) -> String {
        record_root("metadata_budget_replay", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForcedExitCompatibility {
    pub exit_context_root: String,
    pub continuity_root: String,
    pub exit_receipt_root: String,
    pub claim_window_open_l2_height: u64,
    pub claim_window_close_l2_height: u64,
    pub private_spendable: bool,
    pub force_exitable: bool,
}

impl ForcedExitCompatibility {
    pub fn public_record(&self) -> Value {
        json!({
            "exit_context_root": self.exit_context_root,
            "continuity_root": self.continuity_root,
            "exit_receipt_root": self.exit_receipt_root,
            "claim_window_open_l2_height": self.claim_window_open_l2_height,
            "claim_window_close_l2_height": self.claim_window_close_l2_height,
            "private_spendable": self.private_spendable,
            "force_exitable": self.force_exitable,
        })
    }

    pub fn root(&self) -> String {
        record_root("forced_exit_compatibility", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayStep {
    pub ordinal: u64,
    pub step: ReplayStepKind,
    pub record_root: String,
    pub canonical_order_root: String,
    pub accepted: bool,
}

impl ReplayStep {
    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "step": self.step.as_str(),
            "record_root": self.record_root,
            "canonical_order_root": self.canonical_order_root,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub deposit_note: DepositPrivateNote,
    pub nullifier_key_image: NullifierKeyImageDomainSeparation,
    pub action: PrivateActionReplay,
    pub encrypted_receipt: EncryptedReceiptReplay,
    pub metadata_budget: MetadataBudgetReplay,
    pub forced_exit: ForcedExitCompatibility,
    pub replay_steps: Vec<ReplayStep>,
    pub privately_spendable: bool,
    pub force_exitable: bool,
    pub answer: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let deposit_note = devnet_deposit_note(&config);
        let nullifier_key_image = derive_nullifier_key_image(&config, &deposit_note);
        let action = derive_action(&config, &deposit_note);
        let encrypted_receipt =
            derive_encrypted_receipt(&deposit_note, &nullifier_key_image, &action);
        let metadata_budget = derive_metadata_budget(&config, &deposit_note);
        let forced_exit = derive_forced_exit(
            &config,
            &deposit_note,
            &nullifier_key_image,
            &action,
            &encrypted_receipt,
            &metadata_budget,
        );
        let privately_spendable = metadata_budget.within_budget()
            && !nullifier_key_image.duplicate_nullifier_seen
            && deposit_note.monero_confirmations >= config.min_monero_confirmations
            && deposit_note.pq_security_bits >= config.min_pq_security_bits;
        let force_exitable = forced_exit.force_exitable && privately_spendable;
        let replay_steps = replay_steps(
            &deposit_note,
            &nullifier_key_image,
            &action,
            &encrypted_receipt,
            &metadata_budget,
            &forced_exit,
            privately_spendable,
            force_exitable,
        );
        let answer = transition_answer(privately_spendable, force_exitable);
        Self {
            config,
            deposit_note,
            nullifier_key_image,
            action,
            encrypted_receipt,
            metadata_budget,
            forced_exit,
            replay_steps,
            privately_spendable,
            force_exitable,
            answer,
        }
    }

    pub fn public_record(&self) -> Value {
        let replay_steps = self
            .replay_steps
            .iter()
            .map(ReplayStep::public_record)
            .collect::<Vec<_>>();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config_root": self.config.root(),
            "deposit_note_root": self.deposit_note.root(),
            "note_commitment_root": self.deposit_note.note_commitment_root,
            "note_tree_root_after_mint": self.deposit_note.note_tree_root_after_mint,
            "nullifier_key_image_root": self.nullifier_key_image.root(),
            "encrypted_receipt_root": self.encrypted_receipt.encrypted_receipt_root,
            "private_transfer_or_contract_action_root": self.action.action_root,
            "metadata_budget_root": self.metadata_budget.metadata_budget_root,
            "forced_exit_compatibility_root": self.forced_exit.root(),
            "replay_order_root": merkle_root("PRIVATE-STATE-TRANSITION-REPLAY-ORDER", &replay_steps),
            "privately_spendable": self.privately_spendable,
            "force_exitable": self.force_exitable,
            "answer": self.answer,
            "privacy_note": "public replay exposes roots, counters, and compatibility verdicts only",
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-STATE-TRANSITION-REPLAY-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn devnet_deposit_note(config: &Config) -> DepositPrivateNote {
    let deposit_id = short_root("devnet-deposit-id", 0);
    let monero_txid_root = fixture_root("monero-txid", 1);
    let monero_output_root = fixture_root("monero-output", 2);
    let amount_commitment_root = fixture_root("amount-commitment", 3);
    let owner_view_tag_root = fixture_root("owner-view-tag", 4);
    let owner_spend_authority_root = fixture_root("owner-spend-authority", 5);
    let note_randomness_root = fixture_root("note-randomness", 6);
    let encrypted_note_root = fixture_root("encrypted-note", 7);
    let note_commitment_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-NOTE-COMMITMENT",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(&deposit_id),
            HashPart::Str(&monero_txid_root),
            HashPart::Str(&monero_output_root),
            HashPart::Str(&amount_commitment_root),
            HashPart::Str(&owner_view_tag_root),
            HashPart::Str(&owner_spend_authority_root),
            HashPart::Str(&note_randomness_root),
            HashPart::Str(&encrypted_note_root),
        ],
        32,
    );
    let note_tree_root_after_mint = merkle_root(
        "PRIVATE-STATE-TRANSITION-REPLAY-NOTE-TREE",
        &[json!({
            "deposit_id": deposit_id,
            "note_commitment_root": note_commitment_root,
            "minted_l2_height": config.base_l2_height,
        })],
    );
    DepositPrivateNote {
        deposit_id,
        monero_txid_root,
        monero_output_root,
        amount_commitment_root,
        owner_view_tag_root,
        owner_spend_authority_root,
        note_randomness_root,
        encrypted_note_root,
        note_commitment_root,
        note_tree_root_after_mint,
        monero_confirmations: 24,
        minted_l2_height: config.base_l2_height,
        privacy_set_size: 131_072,
        pq_security_bits: 256,
    }
}

fn derive_nullifier_key_image(
    config: &Config,
    note: &DepositPrivateNote,
) -> NullifierKeyImageDomainSeparation {
    let replay_domain_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-DOMAIN",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&note.note_commitment_root),
            HashPart::U64(note.minted_l2_height),
        ],
        32,
    );
    let nullifier_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-NULLIFIER",
        &[
            HashPart::Str(NULLIFIER_DOMAIN),
            HashPart::Str(&note.note_commitment_root),
            HashPart::Str(&replay_domain_root),
        ],
        32,
    );
    let key_image_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-KEY-IMAGE",
        &[
            HashPart::Str(KEY_IMAGE_DOMAIN),
            HashPart::Str(&note.owner_spend_authority_root),
            HashPart::Str(&note.note_randomness_root),
            HashPart::Str(&replay_domain_root),
        ],
        32,
    );
    let nullifier_key_image_binding_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-NULLIFIER-KEY-IMAGE-BINDING",
        &[
            HashPart::Str(&nullifier_root),
            HashPart::Str(&key_image_root),
            HashPart::Str(&replay_domain_root),
        ],
        32,
    );
    NullifierKeyImageDomainSeparation {
        input_note_commitment_root: note.note_commitment_root.clone(),
        replay_domain_root,
        nullifier_root,
        key_image_root,
        nullifier_key_image_binding_root,
        duplicate_nullifier_seen: false,
    }
}

fn derive_action(config: &Config, note: &DepositPrivateNote) -> PrivateActionReplay {
    let output_note_commitment_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-OUTPUT-NOTE",
        &[
            HashPart::Str(&note.note_commitment_root),
            HashPart::Str(&fixture_root("output-note-randomness", 8)),
        ],
        32,
    );
    let private_transfer_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-PRIVATE-TRANSFER",
        &[
            HashPart::Str(&note.note_commitment_root),
            HashPart::Str(&output_note_commitment_root),
            HashPart::Str(&note.amount_commitment_root),
        ],
        32,
    );
    let contract_action_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-CONTRACT-ACTION",
        &[
            HashPart::Str(&output_note_commitment_root),
            HashPart::Str(&fixture_root("private-contract-selector", 9)),
        ],
        32,
    );
    let action_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-ACTION-ROOT",
        &[
            HashPart::Str(ACTION_ROOT_SUITE),
            HashPart::Str(ActionKind::PrivateTransfer.as_str()),
            HashPart::Str(&private_transfer_root),
            HashPart::Str(&contract_action_root),
        ],
        32,
    );
    PrivateActionReplay {
        action_kind: ActionKind::PrivateTransfer,
        input_note_commitment_root: note.note_commitment_root.clone(),
        output_note_commitment_root,
        private_transfer_root,
        contract_action_root,
        action_root,
        action_l2_height: config.base_l2_height + 3,
    }
}

fn derive_encrypted_receipt(
    note: &DepositPrivateNote,
    nullifier: &NullifierKeyImageDomainSeparation,
    action: &PrivateActionReplay,
) -> EncryptedReceiptReplay {
    let wallet_scan_hint_root = fixture_root("wallet-scan-hint", 10);
    let forced_exit_recovery_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-FORCED-EXIT-RECOVERY",
        &[
            HashPart::Str(&note.deposit_id),
            HashPart::Str(&action.output_note_commitment_root),
            HashPart::Str(&wallet_scan_hint_root),
        ],
        32,
    );
    let encrypted_receipt_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-ENCRYPTED-RECEIPT",
        &[
            HashPart::Str(ENCRYPTED_RECEIPT_SUITE),
            HashPart::Str(&nullifier.nullifier_key_image_binding_root),
            HashPart::Str(&action.action_root),
            HashPart::Str(&forced_exit_recovery_root),
        ],
        32,
    );
    let receipt_tree_root = merkle_root(
        "PRIVATE-STATE-TRANSITION-REPLAY-RECEIPT-TREE",
        &[json!({
            "encrypted_receipt_root": encrypted_receipt_root,
            "forced_exit_recovery_root": forced_exit_recovery_root,
        })],
    );
    let receipt_id = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-RECEIPT-ID",
        &[HashPart::Str(&encrypted_receipt_root)],
        16,
    );
    EncryptedReceiptReplay {
        receipt_id,
        encrypted_receipt_root,
        receipt_tree_root,
        wallet_scan_hint_root,
        forced_exit_recovery_root,
        payloads_public: false,
    }
}

fn derive_metadata_budget(config: &Config, note: &DepositPrivateNote) -> MetadataBudgetReplay {
    let public_fields = vec![
        "chain_id".to_string(),
        "l2_height".to_string(),
        "root_commitments".to_string(),
    ];
    let used_units = public_fields.len() as u64;
    let metadata_budget_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-METADATA-BUDGET",
        &[
            HashPart::U64(used_units),
            HashPart::U64(config.metadata_budget_units),
            HashPart::U64(note.privacy_set_size),
            HashPart::U64(config.min_privacy_set_size),
        ],
        32,
    );
    MetadataBudgetReplay {
        metadata_budget_root,
        used_units,
        budget_units: config.metadata_budget_units,
        privacy_set_size: note.privacy_set_size,
        privacy_floor: config.min_privacy_set_size,
        public_fields,
    }
}

fn derive_forced_exit(
    config: &Config,
    note: &DepositPrivateNote,
    nullifier: &NullifierKeyImageDomainSeparation,
    action: &PrivateActionReplay,
    receipt: &EncryptedReceiptReplay,
    metadata_budget: &MetadataBudgetReplay,
) -> ForcedExitCompatibility {
    let exit_context_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-EXIT-CONTEXT",
        &[
            HashPart::Str(&note.deposit_id),
            HashPart::Str(&nullifier.nullifier_root),
            HashPart::Str(&receipt.forced_exit_recovery_root),
        ],
        32,
    );
    let continuity_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-FORCED-EXIT-CONTINUITY",
        &[
            HashPart::Str(&note.note_tree_root_after_mint),
            HashPart::Str(&action.action_root),
            HashPart::Str(&receipt.receipt_tree_root),
            HashPart::Str(&metadata_budget.metadata_budget_root),
            HashPart::Str(&exit_context_root),
        ],
        32,
    );
    let exit_receipt_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-EXIT-RECEIPT",
        &[
            HashPart::Str(&continuity_root),
            HashPart::Str(&receipt.encrypted_receipt_root),
        ],
        32,
    );
    ForcedExitCompatibility {
        exit_context_root,
        continuity_root,
        exit_receipt_root,
        claim_window_open_l2_height: action.action_l2_height,
        claim_window_close_l2_height: action.action_l2_height + config.forced_exit_ttl_blocks,
        private_spendable: metadata_budget.within_budget() && !nullifier.duplicate_nullifier_seen,
        force_exitable: metadata_budget.within_budget() && !receipt.payloads_public,
    }
}

fn replay_steps(
    note: &DepositPrivateNote,
    nullifier: &NullifierKeyImageDomainSeparation,
    action: &PrivateActionReplay,
    receipt: &EncryptedReceiptReplay,
    metadata_budget: &MetadataBudgetReplay,
    forced_exit: &ForcedExitCompatibility,
    privately_spendable: bool,
    force_exitable: bool,
) -> Vec<ReplayStep> {
    let verdict_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-VERDICT",
        &[
            HashPart::Str(if privately_spendable {
                "spendable"
            } else {
                "not-spendable"
            }),
            HashPart::Str(if force_exitable {
                "force-exitable"
            } else {
                "not-force-exitable"
            }),
        ],
        32,
    );
    vec![
        replay_step(0, ReplayStepKind::DepositConfirmed, note.root(), true),
        replay_step(
            1,
            ReplayStepKind::NoteMinted,
            note.note_tree_root_after_mint.clone(),
            true,
        ),
        replay_step(2, ReplayStepKind::NullifierDerived, nullifier.root(), true),
        replay_step(3, ReplayStepKind::ActionApplied, action.root(), true),
        replay_step(4, ReplayStepKind::ReceiptSealed, receipt.root(), true),
        replay_step(
            5,
            ReplayStepKind::MetadataChecked,
            metadata_budget.root(),
            metadata_budget.within_budget(),
        ),
        replay_step(
            6,
            ReplayStepKind::ForcedExitPrepared,
            forced_exit.root(),
            forced_exit.force_exitable,
        ),
        replay_step(
            7,
            ReplayStepKind::Verdict,
            verdict_root,
            privately_spendable && force_exitable,
        ),
    ]
}

fn replay_step(
    ordinal: u64,
    step: ReplayStepKind,
    record_root_value: String,
    accepted: bool,
) -> ReplayStep {
    let canonical_order_root = domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-CANONICAL-ORDER",
        &[
            HashPart::U64(ordinal),
            HashPart::Str(step.as_str()),
            HashPart::Str(&record_root_value),
        ],
        32,
    );
    ReplayStep {
        ordinal,
        step,
        record_root: record_root_value,
        canonical_order_root,
        accepted,
    }
}

fn transition_answer(privately_spendable: bool, force_exitable: bool) -> String {
    match (privately_spendable, force_exitable) {
        (true, true) => {
            "yes: devnet replay keeps the note privately spendable and force-exitable".to_string()
        }
        (true, false) => {
            "partial: devnet replay keeps private spendability but lacks forced-exit continuity"
                .to_string()
        }
        (false, true) => {
            "partial: devnet replay preserves forced-exit evidence but blocks private spendability"
                .to_string()
        }
        (false, false) => {
            "no: devnet replay blocks private spendability and forced-exit compatibility"
                .to_string()
        }
    }
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn fixture_root(label: &str, ordinal: u64) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn short_root(label: &str, ordinal: u64) -> String {
    domain_hash(
        "PRIVATE-STATE-TRANSITION-REPLAY-SHORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        16,
    )
}
