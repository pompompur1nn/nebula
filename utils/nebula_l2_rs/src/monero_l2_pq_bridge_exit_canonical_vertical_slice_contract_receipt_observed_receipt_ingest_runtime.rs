use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceContractReceiptObservedReceiptIngestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-contract-receipt-observed-receipt-ingest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "2026-06-19.contract-receipt.observed-receipt-ingest.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";
pub const INGEST_SUITE: &str = "contract-receipt-observed-root-import-and-conformance-compare-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_FEE_ATOMIC: u64 = 18_000_000;
pub const DEFAULT_MIN_WALLET_REPLAY_DEPTH: u64 = 2;
pub const DEFAULT_RELEASE_HOLD: &str =
    "hold_until_contract_receipt_observed_roots_match_expected_roots";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-contract-receipt-observed-receipt-ingest-runtime";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub ingest_suite: String,
    pub min_pq_security_bits: u16,
    pub max_fee_atomic: u64,
    pub min_wallet_replay_depth: u64,
    pub privacy_surface: String,
    pub import_raw_receipts: bool,
    pub fail_closed: bool,
    pub release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            ingest_suite: INGEST_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            min_wallet_replay_depth: DEFAULT_MIN_WALLET_REPLAY_DEPTH,
            privacy_surface: "root_only_no_contract_payload_or_user_identifier".to_string(),
            import_raw_receipts: false,
            fail_closed: true,
            release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "ingest_suite": self.ingest_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_atomic": self.max_fee_atomic,
            "min_wallet_replay_depth": self.min_wallet_replay_depth,
            "privacy_surface": self.privacy_surface,
            "import_raw_receipts": self.import_raw_receipts,
            "fail_closed": self.fail_closed,
            "release_allowed": self.release_allowed
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedInputReference {
    pub reference_id: String,
    pub sequence: u64,
    pub sealed_input_root: String,
    pub contract_call_commitment_root: String,
    pub note_nullifier_set_root: String,
    pub witness_policy_root: String,
    pub source_runtime: String,
    pub redaction_root: String,
}

impl SealedInputReference {
    pub fn devnet(reference_id: &str, sequence: u64) -> Self {
        Self {
            reference_id: reference_id.to_string(),
            sequence,
            sealed_input_root: scoped_hash("sealed-input-root", reference_id, sequence),
            contract_call_commitment_root: scoped_hash(
                "contract-call-commitment-root",
                reference_id,
                sequence,
            ),
            note_nullifier_set_root: scoped_hash("note-nullifier-set-root", reference_id, sequence),
            witness_policy_root: scoped_hash("witness-policy-root", reference_id, sequence),
            source_runtime: "contract_receipt_gate_execution_receipt_runtime".to_string(),
            redaction_root: scoped_hash("sealed-input-redaction-root", reference_id, sequence),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reference_id": self.reference_id,
            "sequence": self.sequence,
            "sealed_input_root": self.sealed_input_root,
            "contract_call_commitment_root": self.contract_call_commitment_root,
            "note_nullifier_set_root": self.note_nullifier_set_root,
            "witness_policy_root": self.witness_policy_root,
            "source_runtime": self.source_runtime,
            "redaction_root": self.redaction_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("sealed-input-reference", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedEffectRoot {
    pub effect_id: String,
    pub sequence: u64,
    pub ciphertext_root: String,
    pub recipient_commitment_root: String,
    pub effect_type_root: String,
    pub deterministic_nonce_root: String,
    pub privacy_budget_root: String,
}

impl EncryptedEffectRoot {
    pub fn devnet(effect_id: &str, sequence: u64) -> Self {
        Self {
            effect_id: effect_id.to_string(),
            sequence,
            ciphertext_root: scoped_hash("encrypted-effect-ciphertext-root", effect_id, sequence),
            recipient_commitment_root: scoped_hash(
                "encrypted-effect-recipient-commitment-root",
                effect_id,
                sequence,
            ),
            effect_type_root: scoped_hash("encrypted-effect-type-root", effect_id, sequence),
            deterministic_nonce_root: scoped_hash(
                "encrypted-effect-deterministic-nonce-root",
                effect_id,
                sequence,
            ),
            privacy_budget_root: scoped_hash(
                "encrypted-effect-privacy-budget-root",
                effect_id,
                sequence,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "effect_id": self.effect_id,
            "sequence": self.sequence,
            "ciphertext_root": self.ciphertext_root,
            "recipient_commitment_root": self.recipient_commitment_root,
            "effect_type_root": self.effect_type_root,
            "deterministic_nonce_root": self.deterministic_nonce_root,
            "privacy_budget_root": self.privacy_budget_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("encrypted-effect-root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptEmissionRoot {
    pub receipt_id: String,
    pub sequence: u64,
    pub receipt_root: String,
    pub emitted_event_root: String,
    pub wallet_visible_root: String,
    pub operator_visible_root: String,
    pub private_payload_redaction_root: String,
}

impl ReceiptEmissionRoot {
    pub fn devnet(receipt_id: &str, sequence: u64) -> Self {
        let receipt_root = scoped_hash("contract-receipt-root", receipt_id, sequence);
        Self {
            receipt_id: receipt_id.to_string(),
            sequence,
            receipt_root,
            emitted_event_root: scoped_hash(
                "contract-receipt-emitted-event-root",
                receipt_id,
                sequence,
            ),
            wallet_visible_root: scoped_hash("wallet-visible-receipt-root", receipt_id, sequence),
            operator_visible_root: scoped_hash(
                "operator-visible-receipt-root",
                receipt_id,
                sequence,
            ),
            private_payload_redaction_root: scoped_hash(
                "private-payload-redaction-root",
                receipt_id,
                sequence,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "receipt_root": self.receipt_root,
            "emitted_event_root": self.emitted_event_root,
            "wallet_visible_root": self.wallet_visible_root,
            "operator_visible_root": self.operator_visible_root,
            "private_payload_redaction_root": self.private_payload_redaction_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt-emission-root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeBoundEvidence {
    pub fee_id: String,
    pub sequence: u64,
    pub charged_fee_atomic: u64,
    pub max_fee_atomic: u64,
    pub fee_commitment_root: String,
    pub sponsor_policy_root: String,
    pub within_bound: bool,
}

impl FeeBoundEvidence {
    pub fn devnet(fee_id: &str, sequence: u64, max_fee_atomic: u64) -> Self {
        let charged_fee_atomic = 11_000_000 + sequence.saturating_mul(100_000);
        Self {
            fee_id: fee_id.to_string(),
            sequence,
            charged_fee_atomic,
            max_fee_atomic,
            fee_commitment_root: scoped_hash("fee-commitment-root", fee_id, sequence),
            sponsor_policy_root: scoped_hash("fee-sponsor-policy-root", fee_id, sequence),
            within_bound: charged_fee_atomic <= max_fee_atomic,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_id": self.fee_id,
            "sequence": self.sequence,
            "charged_fee_atomic": self.charged_fee_atomic,
            "max_fee_atomic": self.max_fee_atomic,
            "fee_commitment_root": self.fee_commitment_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "within_bound": self.within_bound
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fee-bound-evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSequencerAuthEvidence {
    pub auth_id: String,
    pub sequence: u64,
    pub sequencer_committee_root: String,
    pub pq_signature_root: String,
    pub transcript_binding_root: String,
    pub security_bits: u16,
    pub threshold_met: bool,
}

impl PqSequencerAuthEvidence {
    pub fn devnet(auth_id: &str, sequence: u64, min_security_bits: u16) -> Self {
        Self {
            auth_id: auth_id.to_string(),
            sequence,
            sequencer_committee_root: scoped_hash("pq-sequencer-committee-root", auth_id, sequence),
            pq_signature_root: scoped_hash("pq-sequencer-signature-root", auth_id, sequence),
            transcript_binding_root: scoped_hash(
                "pq-sequencer-transcript-binding-root",
                auth_id,
                sequence,
            ),
            security_bits: min_security_bits,
            threshold_met: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auth_id": self.auth_id,
            "sequence": self.sequence,
            "sequencer_committee_root": self.sequencer_committee_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_binding_root": self.transcript_binding_root,
            "security_bits": self.security_bits,
            "threshold_met": self.threshold_met
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pq-sequencer-auth-evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayabilityEvidence {
    pub replay_id: String,
    pub sequence: u64,
    pub replay_key_root: String,
    pub replay_window_root: String,
    pub wallet_export_root: String,
    pub minimum_depth: u64,
    pub deterministic_replay: bool,
}

impl ReplayabilityEvidence {
    pub fn devnet(replay_id: &str, sequence: u64, minimum_depth: u64) -> Self {
        Self {
            replay_id: replay_id.to_string(),
            sequence,
            replay_key_root: scoped_hash("replay-key-root", replay_id, sequence),
            replay_window_root: scoped_hash("replay-window-root", replay_id, sequence),
            wallet_export_root: scoped_hash("wallet-export-root", replay_id, sequence),
            minimum_depth,
            deterministic_replay: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "replay_id": self.replay_id,
            "sequence": self.sequence,
            "replay_key_root": self.replay_key_root,
            "replay_window_root": self.replay_window_root,
            "wallet_export_root": self.wallet_export_root,
            "minimum_depth": self.minimum_depth,
            "deterministic_replay": self.deterministic_replay
        })
    }

    pub fn state_root(&self) -> String {
        record_root("replayability-evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedReceiptImport {
    pub import_id: String,
    pub sequence: u64,
    pub sealed_input: SealedInputReference,
    pub encrypted_effect: EncryptedEffectRoot,
    pub receipt_emission: ReceiptEmissionRoot,
    pub fee_bound: FeeBoundEvidence,
    pub pq_sequencer_auth: PqSequencerAuthEvidence,
    pub replayability: ReplayabilityEvidence,
    pub observed_root: String,
    pub expected_root: String,
    pub conformance_root: String,
    pub privacy_preserving: bool,
}

impl ObservedReceiptImport {
    pub fn devnet(import_id: &str, sequence: u64, config: &Config) -> Self {
        let sealed_input = SealedInputReference::devnet(import_id, sequence);
        let encrypted_effect = EncryptedEffectRoot::devnet(import_id, sequence);
        let receipt_emission = ReceiptEmissionRoot::devnet(import_id, sequence);
        let fee_bound = FeeBoundEvidence::devnet(import_id, sequence, config.max_fee_atomic);
        let pq_sequencer_auth =
            PqSequencerAuthEvidence::devnet(import_id, sequence, config.min_pq_security_bits);
        let replayability =
            ReplayabilityEvidence::devnet(import_id, sequence, config.min_wallet_replay_depth);
        let observed_root = observed_receipt_root(
            import_id,
            sequence,
            &sealed_input,
            &encrypted_effect,
            &receipt_emission,
            &fee_bound,
            &pq_sequencer_auth,
            &replayability,
        );
        let expected_root = expected_receipt_root(import_id, sequence);
        let conformance_root = compare_root(import_id, sequence, &expected_root, &observed_root);

        Self {
            import_id: import_id.to_string(),
            sequence,
            sealed_input,
            encrypted_effect,
            receipt_emission,
            fee_bound,
            pq_sequencer_auth,
            replayability,
            observed_root,
            expected_root,
            conformance_root,
            privacy_preserving: true,
        }
    }

    pub fn matches_expected(&self) -> bool {
        self.expected_root == self.observed_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "import_id": self.import_id,
            "sequence": self.sequence,
            "sealed_input": self.sealed_input.public_record(),
            "encrypted_effect": self.encrypted_effect.public_record(),
            "receipt_emission": self.receipt_emission.public_record(),
            "fee_bound": self.fee_bound.public_record(),
            "pq_sequencer_auth": self.pq_sequencer_auth.public_record(),
            "replayability": self.replayability.public_record(),
            "observed_root": self.observed_root,
            "expected_root": self.expected_root,
            "conformance_root": self.conformance_root,
            "matches_expected": self.matches_expected(),
            "privacy_preserving": self.privacy_preserving
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observed-receipt-import", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub sequence: u64,
    pub import_id: String,
    pub expected_root: String,
    pub observed_root: String,
    pub mismatch_root: String,
    pub release_blocking: bool,
    pub privacy_note: String,
}

impl MismatchRecord {
    pub fn from_import(import: &ObservedReceiptImport) -> Self {
        let mismatch_id = format!("mismatch-{}", import.import_id);
        let mismatch_root = compare_root(
            &mismatch_id,
            import.sequence,
            &import.expected_root,
            &import.observed_root,
        );
        Self {
            mismatch_id,
            sequence: import.sequence,
            import_id: import.import_id.clone(),
            expected_root: import.expected_root.clone(),
            observed_root: import.observed_root.clone(),
            mismatch_root,
            release_blocking: !import.matches_expected(),
            privacy_note: "root_only_mismatch_no_receipt_payload".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "sequence": self.sequence,
            "import_id": self.import_id,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "mismatch_root": self.mismatch_root,
            "release_blocking": self.release_blocking,
            "privacy_note": self.privacy_note
        })
    }

    pub fn state_root(&self) -> String {
        record_root("mismatch-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub hold_root: String,
    pub reason: String,
    pub mismatch_root: String,
    pub imported_receipt_root: String,
    pub release_allowed: bool,
}

impl ReleaseHold {
    pub fn from_mismatches(
        mismatch_root: &str,
        imported_receipt_root: &str,
        release_allowed: bool,
    ) -> Self {
        let hold_id = DEFAULT_RELEASE_HOLD.to_string();
        let hold_root = domain_hash(
            &format!("{DOMAIN}:release-hold"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&hold_id),
                HashPart::Str(mismatch_root),
                HashPart::Str(imported_receipt_root),
                HashPart::Int(flag_int(release_allowed)),
            ],
            32,
        );

        Self {
            hold_id,
            hold_root,
            reason: "observed_receipt_roots_must_match_expected_conformance_roots".to_string(),
            mismatch_root: mismatch_root.to_string(),
            imported_receipt_root: imported_receipt_root.to_string(),
            release_allowed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "hold_root": self.hold_root,
            "reason": self.reason,
            "mismatch_root": self.mismatch_root,
            "imported_receipt_root": self.imported_receipt_root,
            "release_allowed": self.release_allowed
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-hold", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub forced_exit_epoch: u64,
    pub l2_observed_height: u64,
    pub monero_observed_height: u64,
    pub imports: Vec<ObservedReceiptImport>,
    pub mismatches: Vec<MismatchRecord>,
    pub release_hold: ReleaseHold,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let imports = vec![
            ObservedReceiptImport::devnet("contract-receipt-observed-0", 0, &config),
            ObservedReceiptImport::devnet("contract-receipt-observed-1", 1, &config),
            ObservedReceiptImport::devnet("contract-receipt-observed-2", 2, &config),
        ];
        let mismatches = imports
            .iter()
            .map(MismatchRecord::from_import)
            .collect::<Vec<_>>();
        let imported_receipt_root = merkle_root(
            &format!("{DOMAIN}:imported-receipts"),
            &imports
                .iter()
                .map(ObservedReceiptImport::public_record)
                .collect::<Vec<_>>(),
        );
        let mismatch_root = merkle_root(
            &format!("{DOMAIN}:mismatches"),
            &mismatches
                .iter()
                .map(MismatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let release_hold = ReleaseHold::from_mismatches(
            &mismatch_root,
            &imported_receipt_root,
            config.release_allowed,
        );

        Self {
            config,
            runtime_id: format!("{DOMAIN}:devnet"),
            forced_exit_epoch: 42,
            l2_observed_height: 1_260_096,
            monero_observed_height: 3_180_128,
            imports,
            mismatches,
            release_hold,
        }
    }

    pub fn public_record(&self) -> Value {
        let imports = self
            .imports
            .iter()
            .map(ObservedReceiptImport::public_record)
            .collect::<Vec<_>>();
        let mismatches = self
            .mismatches
            .iter()
            .map(MismatchRecord::public_record)
            .collect::<Vec<_>>();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "ingest_suite": INGEST_SUITE,
            "runtime_id": self.runtime_id,
            "forced_exit_epoch": self.forced_exit_epoch,
            "l2_observed_height": self.l2_observed_height,
            "monero_observed_height": self.monero_observed_height,
            "config": self.config.public_record(),
            "import_count": self.imports.len() as u64,
            "mismatch_count": self.mismatches.iter().filter(|m| m.release_blocking).count() as u64,
            "sealed_input_reference_root": self.sealed_input_root(),
            "encrypted_effect_root": self.encrypted_effect_root(),
            "contract_receipt_emission_root": self.receipt_emission_root(),
            "fee_bound_root": self.fee_bound_root(),
            "pq_sequencer_auth_root": self.pq_sequencer_auth_root(),
            "exit_replayability_root": self.replayability_root(),
            "imported_receipt_root": self.imported_receipt_root(),
            "mismatch_root": self.mismatch_root(),
            "release_hold": self.release_hold.public_record(),
            "state_root": self.state_root(),
            "imports": imports,
            "mismatches": mismatches
        })
    }

    pub fn sealed_input_root(&self) -> String {
        merkle_root(
            &format!("{DOMAIN}:sealed-input-references"),
            &self
                .imports
                .iter()
                .map(|import| import.sealed_input.public_record())
                .collect::<Vec<_>>(),
        )
    }

    pub fn encrypted_effect_root(&self) -> String {
        merkle_root(
            &format!("{DOMAIN}:encrypted-effects"),
            &self
                .imports
                .iter()
                .map(|import| import.encrypted_effect.public_record())
                .collect::<Vec<_>>(),
        )
    }

    pub fn receipt_emission_root(&self) -> String {
        merkle_root(
            &format!("{DOMAIN}:receipt-emissions"),
            &self
                .imports
                .iter()
                .map(|import| import.receipt_emission.public_record())
                .collect::<Vec<_>>(),
        )
    }

    pub fn fee_bound_root(&self) -> String {
        merkle_root(
            &format!("{DOMAIN}:fee-bounds"),
            &self
                .imports
                .iter()
                .map(|import| import.fee_bound.public_record())
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_sequencer_auth_root(&self) -> String {
        merkle_root(
            &format!("{DOMAIN}:pq-sequencer-auth"),
            &self
                .imports
                .iter()
                .map(|import| import.pq_sequencer_auth.public_record())
                .collect::<Vec<_>>(),
        )
    }

    pub fn replayability_root(&self) -> String {
        merkle_root(
            &format!("{DOMAIN}:replayability"),
            &self
                .imports
                .iter()
                .map(|import| import.replayability.public_record())
                .collect::<Vec<_>>(),
        )
    }

    pub fn imported_receipt_root(&self) -> String {
        merkle_root(
            &format!("{DOMAIN}:imported-receipts"),
            &self
                .imports
                .iter()
                .map(ObservedReceiptImport::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn mismatch_root(&self) -> String {
        merkle_root(
            &format!("{DOMAIN}:mismatches"),
            &self
                .mismatches
                .iter()
                .map(MismatchRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(SCHEMA_VERSION),
                HashPart::Str(&self.runtime_id),
                HashPart::Int(self.forced_exit_epoch as i128),
                HashPart::Int(self.l2_observed_height as i128),
                HashPart::Int(self.monero_observed_height as i128),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.sealed_input_root()),
                HashPart::Str(&self.encrypted_effect_root()),
                HashPart::Str(&self.receipt_emission_root()),
                HashPart::Str(&self.fee_bound_root()),
                HashPart::Str(&self.pq_sequencer_auth_root()),
                HashPart::Str(&self.replayability_root()),
                HashPart::Str(&self.imported_receipt_root()),
                HashPart::Str(&self.mismatch_root()),
                HashPart::Str(&self.release_hold.state_root()),
            ],
            32,
        )
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

pub fn ingest_observed_receipt(state: &mut State, import: ObservedReceiptImport) -> Result<String> {
    if !import.privacy_preserving {
        return Err("observed receipt import must expose only root-level public data".to_string());
    }
    if import.fee_bound.charged_fee_atomic > state.config.max_fee_atomic {
        return Err("observed receipt fee exceeds configured bound".to_string());
    }
    if import.pq_sequencer_auth.security_bits < state.config.min_pq_security_bits {
        return Err(
            "observed receipt pq sequencer evidence below configured security bits".to_string(),
        );
    }

    let mismatch = MismatchRecord::from_import(&import);
    state.imports.push(import);
    state.mismatches.push(mismatch);
    state.release_hold = ReleaseHold::from_mismatches(
        &state.mismatch_root(),
        &state.imported_receipt_root(),
        state.config.release_allowed,
    );

    Ok(state.state_root())
}

fn observed_receipt_root(
    import_id: &str,
    sequence: u64,
    sealed_input: &SealedInputReference,
    encrypted_effect: &EncryptedEffectRoot,
    receipt_emission: &ReceiptEmissionRoot,
    fee_bound: &FeeBoundEvidence,
    pq_sequencer_auth: &PqSequencerAuthEvidence,
    replayability: &ReplayabilityEvidence,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:observed-receipt-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(import_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(&sealed_input.state_root()),
            HashPart::Str(&encrypted_effect.state_root()),
            HashPart::Str(&receipt_emission.state_root()),
            HashPart::Str(&fee_bound.state_root()),
            HashPart::Str(&pq_sequencer_auth.state_root()),
            HashPart::Str(&replayability.state_root()),
            HashPart::Int(flag_int(fee_bound.within_bound)),
            HashPart::Int(flag_int(pq_sequencer_auth.threshold_met)),
            HashPart::Int(flag_int(replayability.deterministic_replay)),
        ],
        32,
    )
}

fn expected_receipt_root(import_id: &str, sequence: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-receipt-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(import_id),
            HashPart::Int(sequence as i128),
            HashPart::Str("contract_receipt_gate_receipt_conformance_runtime"),
            HashPart::Str("expected_roots_runtime"),
        ],
        32,
    )
}

fn compare_root(
    import_id: &str,
    sequence: u64,
    expected_root: &str,
    observed_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:compare-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(import_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(expected_root),
            HashPart::Str(observed_root),
            HashPart::Int(flag_int(expected_root == observed_root)),
        ],
        32,
    )
}

fn scoped_hash(label: &str, id: &str, sequence: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(id),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(&format!("{DOMAIN}:{label}"), &[HashPart::Json(record)], 32)
}

fn flag_int(value: bool) -> i128 {
    if value {
        1
    } else {
        0
    }
}
