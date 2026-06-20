use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;

pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePrivateReceiptObservedReceiptIngestRuntimeResult<
    T,
> = Result<T>;

pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-private-receipt-observed-receipt-ingest-runtime/v1";

const ZERO_ROOT_DOMAIN: &str = "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-OBSERVED-INGEST-ZERO";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub runtime_protocol_version: String,
    pub bridge_id: String,
    pub forced_exit_spine_id: String,
    pub conformance_profile_id: String,
    pub min_observer_quorum: u16,
    pub max_metadata_bytes: u32,
    pub max_wallet_hint_count: u16,
    pub max_encrypted_shard_count: u16,
    pub max_fee_cap_piconero: u64,
    pub release_hold_challenge_window: u64,
    pub pq_authorization_required: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            runtime_protocol_version:
                MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            bridge_id: "devnet-monero-l2-pq-bridge".to_string(),
            forced_exit_spine_id: "devnet-forced-exit-spine".to_string(),
            conformance_profile_id: "devnet-private-receipt-conformance".to_string(),
            min_observer_quorum: 2,
            max_metadata_bytes: 384,
            max_wallet_hint_count: 4,
            max_encrypted_shard_count: 8,
            max_fee_cap_piconero: 20_000_000_000,
            release_hold_challenge_window: 72,
            pq_authorization_required: true,
        }
    }

    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-RECEIPT-INGEST-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedReceiptRoot {
    pub receipt_id: String,
    pub expected_private_receipt_root: String,
    pub expected_nullifier_root: String,
    pub expected_commitment_root: String,
    pub expected_action_root: String,
    pub expected_release_policy_root: String,
    pub conformance_case_id: String,
    pub registered_at_height: u64,
}

impl ExpectedReceiptRoot {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-RECEIPT-EXPECTED-ROOT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservedPrivateReceipt {
    pub receipt_id: String,
    pub observer_set_root: String,
    pub observed_private_receipt_root: String,
    pub observed_action_root: String,
    pub observed_at_height: u64,
    pub observation_slot: u64,
    pub import_batch_id: String,
    pub privacy_scope_root: String,
}

impl ObservedPrivateReceipt {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RECEIPT-OBSERVED-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.receipt_id),
                HashPart::Str(&self.observer_set_root),
                HashPart::Str(&self.observed_private_receipt_root),
                HashPart::Str(&self.observed_action_root),
                HashPart::Int(self.observed_at_height as i128),
                HashPart::Int(self.observation_slot as i128),
                HashPart::Str(&self.import_batch_id),
                HashPart::Str(&self.privacy_scope_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NullifierCommitmentEvidence {
    pub receipt_id: String,
    pub nullifier_evidence_root: String,
    pub commitment_evidence_root: String,
    pub spent_key_image_root: String,
    pub output_commitment_root: String,
    pub membership_witness_root: String,
    pub evidence_count: u16,
    pub observed_at_height: u64,
}

impl NullifierCommitmentEvidence {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-RECEIPT-NULLIFIER-COMMITMENT-EVIDENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedReceiptShard {
    pub receipt_id: String,
    pub shard_id: String,
    pub shard_index: u16,
    pub shard_count: u16,
    pub cipher_suite: String,
    pub ciphertext_root: String,
    pub recipient_commitment: String,
    pub key_commitment_root: String,
    pub retention_policy_root: String,
}

impl EncryptedReceiptShard {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-RECEIPT-ENCRYPTED-SHARD", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeCapCheck {
    pub receipt_id: String,
    pub fee_asset: String,
    pub observed_fee_piconero: u64,
    pub cap_piconero: u64,
    pub fee_commitment_root: String,
    pub policy_root: String,
    pub passed: bool,
}

impl FeeCapCheck {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RECEIPT-FEE-CAP-CHECK",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.receipt_id),
                HashPart::Str(&self.fee_asset),
                HashPart::Int(self.observed_fee_piconero as i128),
                HashPart::Int(self.cap_piconero as i128),
                HashPart::Str(&self.fee_commitment_root),
                HashPart::Str(&self.policy_root),
                HashPart::Int(bool_int(self.passed)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletReconstructionHint {
    pub receipt_id: String,
    pub hint_id: String,
    pub hint_kind: String,
    pub hint_commitment_root: String,
    pub encrypted_hint_root: String,
    pub recovery_path_root: String,
    pub disclosure_group_root: String,
}

impl WalletReconstructionHint {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PRIVATE-RECEIPT-WALLET-RECONSTRUCTION-HINT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataBudget {
    pub receipt_id: String,
    pub allowed_bytes: u32,
    pub observed_bytes: u32,
    pub metadata_commitment_root: String,
    pub redaction_policy_root: String,
    pub leakproof: bool,
}

impl MetadataBudget {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RECEIPT-METADATA-BUDGET",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.receipt_id),
                HashPart::Int(self.allowed_bytes as i128),
                HashPart::Int(self.observed_bytes as i128),
                HashPart::Str(&self.metadata_commitment_root),
                HashPart::Str(&self.redaction_policy_root),
                HashPart::Int(bool_int(self.leakproof)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqAuthorizationEvidence {
    pub receipt_id: String,
    pub authorization_id: String,
    pub pq_scheme: String,
    pub public_key_commitment_root: String,
    pub signature_commitment_root: String,
    pub transcript_root: String,
    pub signer_quorum: u16,
    pub valid: bool,
}

impl PqAuthorizationEvidence {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RECEIPT-PQ-AUTHORIZATION-EVIDENCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.receipt_id),
                HashPart::Str(&self.authorization_id),
                HashPart::Str(&self.pq_scheme),
                HashPart::Str(&self.public_key_commitment_root),
                HashPart::Str(&self.signature_commitment_root),
                HashPart::Str(&self.transcript_root),
                HashPart::Int(self.signer_quorum as i128),
                HashPart::Int(bool_int(self.valid)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptMismatch {
    pub receipt_id: String,
    pub mismatch_kind: String,
    pub expected_root: String,
    pub observed_root: String,
    pub severity: String,
    pub hold_required: bool,
    pub detected_at_height: u64,
}

impl ReceiptMismatch {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RECEIPT-MISMATCH",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.receipt_id),
                HashPart::Str(&self.mismatch_kind),
                HashPart::Str(&self.expected_root),
                HashPart::Str(&self.observed_root),
                HashPart::Str(&self.severity),
                HashPart::Int(bool_int(self.hold_required)),
                HashPart::Int(self.detected_at_height as i128),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseHold {
    pub receipt_id: String,
    pub hold_id: String,
    pub reason_root: String,
    pub challenge_deadline_height: u64,
    pub release_after_height: u64,
    pub active: bool,
    pub guard_root: String,
}

impl ReleaseHold {
    pub fn public_record(&self) -> Value {
        record_value(self)
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RECEIPT-RELEASE-HOLD",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.receipt_id),
                HashPart::Str(&self.hold_id),
                HashPart::Str(&self.reason_root),
                HashPart::Int(self.challenge_deadline_height as i128),
                HashPart::Int(self.release_after_height as i128),
                HashPart::Int(bool_int(self.active)),
                HashPart::Str(&self.guard_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub expected_roots: BTreeMap<String, ExpectedReceiptRoot>,
    pub observed_receipts: BTreeMap<String, ObservedPrivateReceipt>,
    pub nullifier_commitment_evidence: BTreeMap<String, NullifierCommitmentEvidence>,
    pub encrypted_receipt_shards: Vec<EncryptedReceiptShard>,
    pub fee_cap_checks: BTreeMap<String, FeeCapCheck>,
    pub wallet_reconstruction_hints: Vec<WalletReconstructionHint>,
    pub metadata_budgets: BTreeMap<String, MetadataBudget>,
    pub pq_authorization_evidence: BTreeMap<String, PqAuthorizationEvidence>,
    pub mismatches: Vec<ReceiptMismatch>,
    pub release_holds: BTreeMap<String, ReleaseHold>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            expected_roots: BTreeMap::new(),
            observed_receipts: BTreeMap::new(),
            nullifier_commitment_evidence: BTreeMap::new(),
            encrypted_receipt_shards: Vec::new(),
            fee_cap_checks: BTreeMap::new(),
            wallet_reconstruction_hints: Vec::new(),
            metadata_budgets: BTreeMap::new(),
            pq_authorization_evidence: BTreeMap::new(),
            mismatches: Vec::new(),
            release_holds: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let receipt_id = "devnet-private-receipt-0001".to_string();
        let expected_private_receipt_root =
            deterministic_root("DEVNET-EXPECTED-PRIVATE-RECEIPT", &receipt_id);
        let expected_nullifier_root = deterministic_root("DEVNET-EXPECTED-NULLIFIER", &receipt_id);
        let expected_commitment_root =
            deterministic_root("DEVNET-EXPECTED-COMMITMENT", &receipt_id);
        let expected_action_root = deterministic_root("DEVNET-EXPECTED-ACTION", &receipt_id);
        let expected_release_policy_root =
            deterministic_root("DEVNET-EXPECTED-RELEASE-POLICY", &receipt_id);

        let expected = ExpectedReceiptRoot {
            receipt_id: receipt_id.clone(),
            expected_private_receipt_root: expected_private_receipt_root.clone(),
            expected_nullifier_root: expected_nullifier_root.clone(),
            expected_commitment_root: expected_commitment_root.clone(),
            expected_action_root: expected_action_root.clone(),
            expected_release_policy_root: expected_release_policy_root.clone(),
            conformance_case_id: "devnet-case-private-receipt-ingest".to_string(),
            registered_at_height: 40,
        };
        state.expected_roots.insert(receipt_id.clone(), expected);

        let observed = ObservedPrivateReceipt {
            receipt_id: receipt_id.clone(),
            observer_set_root: deterministic_root("DEVNET-OBSERVER-SET", "quorum-a"),
            observed_private_receipt_root: expected_private_receipt_root,
            observed_action_root: expected_action_root,
            observed_at_height: 44,
            observation_slot: 1,
            import_batch_id: "devnet-ingest-batch-0001".to_string(),
            privacy_scope_root: deterministic_root("DEVNET-PRIVACY-SCOPE", "bridge-exit"),
        };
        state.observed_receipts.insert(receipt_id.clone(), observed);

        state.nullifier_commitment_evidence.insert(
            receipt_id.clone(),
            NullifierCommitmentEvidence {
                receipt_id: receipt_id.clone(),
                nullifier_evidence_root: expected_nullifier_root,
                commitment_evidence_root: expected_commitment_root,
                spent_key_image_root: deterministic_root("DEVNET-SPENT-KEY-IMAGE", &receipt_id),
                output_commitment_root: deterministic_root("DEVNET-OUTPUT-COMMITMENT", &receipt_id),
                membership_witness_root: deterministic_root(
                    "DEVNET-MEMBERSHIP-WITNESS",
                    &receipt_id,
                ),
                evidence_count: 2,
                observed_at_height: 44,
            },
        );

        state.encrypted_receipt_shards.push(EncryptedReceiptShard {
            receipt_id: receipt_id.clone(),
            shard_id: "devnet-shard-0001-a".to_string(),
            shard_index: 0,
            shard_count: 2,
            cipher_suite: "kyber768-xchacha20poly1305".to_string(),
            ciphertext_root: deterministic_root("DEVNET-CIPHERTEXT", "a"),
            recipient_commitment: deterministic_root("DEVNET-RECIPIENT", "view-a"),
            key_commitment_root: deterministic_root("DEVNET-KEY-COMMITMENT", "a"),
            retention_policy_root: deterministic_root("DEVNET-RETENTION", "short"),
        });
        state.encrypted_receipt_shards.push(EncryptedReceiptShard {
            receipt_id: receipt_id.clone(),
            shard_id: "devnet-shard-0001-b".to_string(),
            shard_index: 1,
            shard_count: 2,
            cipher_suite: "kyber768-xchacha20poly1305".to_string(),
            ciphertext_root: deterministic_root("DEVNET-CIPHERTEXT", "b"),
            recipient_commitment: deterministic_root("DEVNET-RECIPIENT", "view-b"),
            key_commitment_root: deterministic_root("DEVNET-KEY-COMMITMENT", "b"),
            retention_policy_root: deterministic_root("DEVNET-RETENTION", "short"),
        });

        state.fee_cap_checks.insert(
            receipt_id.clone(),
            FeeCapCheck {
                receipt_id: receipt_id.clone(),
                fee_asset: "piconero".to_string(),
                observed_fee_piconero: 4_200_000_000,
                cap_piconero: state.config.max_fee_cap_piconero,
                fee_commitment_root: deterministic_root("DEVNET-FEE-COMMITMENT", &receipt_id),
                policy_root: deterministic_root("DEVNET-FEE-POLICY", "forced-exit"),
                passed: true,
            },
        );

        state
            .wallet_reconstruction_hints
            .push(WalletReconstructionHint {
                receipt_id: receipt_id.clone(),
                hint_id: "devnet-hint-0001".to_string(),
                hint_kind: "view-key-window".to_string(),
                hint_commitment_root: deterministic_root("DEVNET-HINT-COMMITMENT", "window"),
                encrypted_hint_root: deterministic_root("DEVNET-ENCRYPTED-HINT", "window"),
                recovery_path_root: deterministic_root("DEVNET-RECOVERY-PATH", "primary"),
                disclosure_group_root: deterministic_root(
                    "DEVNET-DISCLOSURE-GROUP",
                    "operator-quorum",
                ),
            });

        state.metadata_budgets.insert(
            receipt_id.clone(),
            MetadataBudget {
                receipt_id: receipt_id.clone(),
                allowed_bytes: state.config.max_metadata_bytes,
                observed_bytes: 192,
                metadata_commitment_root: deterministic_root(
                    "DEVNET-METADATA-COMMITMENT",
                    &receipt_id,
                ),
                redaction_policy_root: deterministic_root("DEVNET-REDACTION-POLICY", "minimal"),
                leakproof: true,
            },
        );

        state.pq_authorization_evidence.insert(
            receipt_id.clone(),
            PqAuthorizationEvidence {
                receipt_id: receipt_id.clone(),
                authorization_id: "devnet-pq-auth-0001".to_string(),
                pq_scheme: "dilithium3".to_string(),
                public_key_commitment_root: deterministic_root("DEVNET-PQ-PUBLIC-KEY", "operator"),
                signature_commitment_root: deterministic_root("DEVNET-PQ-SIGNATURE", "operator"),
                transcript_root: deterministic_root("DEVNET-PQ-TRANSCRIPT", &receipt_id),
                signer_quorum: state.config.min_observer_quorum,
                valid: true,
            },
        );

        let hold_id = release_hold_id(&receipt_id, "clean-conformance", 44);
        state.release_holds.insert(
            hold_id.clone(),
            ReleaseHold {
                receipt_id,
                hold_id,
                reason_root: deterministic_root("DEVNET-HOLD-REASON", "conformance-window"),
                challenge_deadline_height: 44 + state.config.release_hold_challenge_window,
                release_after_height: 44 + state.config.release_hold_challenge_window,
                active: false,
                guard_root: expected_release_policy_root,
            },
        );

        state
    }

    pub fn register_expected_root(&mut self, expected: ExpectedReceiptRoot) -> Result<String> {
        require_non_empty("receipt_id", &expected.receipt_id)?;
        let receipt_id = expected.receipt_id.clone();
        let root = expected.root();
        self.expected_roots.insert(receipt_id, expected);
        Ok(root)
    }

    pub fn ingest_observed_receipt(
        &mut self,
        observed: ObservedPrivateReceipt,
    ) -> MoneroL2PqBridgeExitCanonicalVerticalSlicePrivateReceiptObservedReceiptIngestRuntimeResult<
        String,
    >{
        require_non_empty("receipt_id", &observed.receipt_id)?;
        require_non_empty(
            "observed_private_receipt_root",
            &observed.observed_private_receipt_root,
        )?;
        let receipt_id = observed.receipt_id.clone();
        let root = observed.root();
        self.compare_observed_to_expected(&observed)?;
        self.observed_receipts.insert(receipt_id, observed);
        Ok(root)
    }

    pub fn ingest_nullifier_commitment_evidence(
        &mut self,
        evidence: NullifierCommitmentEvidence,
    ) -> Result<String> {
        require_non_empty("receipt_id", &evidence.receipt_id)?;
        let receipt_id = evidence.receipt_id.clone();
        let root = evidence.root();
        if let Some(expected) = self.expected_roots.get(&receipt_id) {
            let expected_nullifier_root = expected.expected_nullifier_root.clone();
            let expected_commitment_root = expected.expected_commitment_root.clone();
            if expected_nullifier_root != evidence.nullifier_evidence_root {
                self.record_mismatch(
                    &receipt_id,
                    "nullifier-root",
                    &expected_nullifier_root,
                    &evidence.nullifier_evidence_root,
                    evidence.observed_at_height,
                );
            }
            if expected_commitment_root != evidence.commitment_evidence_root {
                self.record_mismatch(
                    &receipt_id,
                    "commitment-root",
                    &expected_commitment_root,
                    &evidence.commitment_evidence_root,
                    evidence.observed_at_height,
                );
            }
        }
        self.nullifier_commitment_evidence
            .insert(receipt_id, evidence);
        Ok(root)
    }

    pub fn ingest_encrypted_receipt_shard(
        &mut self,
        shard: EncryptedReceiptShard,
    ) -> Result<String> {
        require_non_empty("receipt_id", &shard.receipt_id)?;
        if shard.shard_count > self.config.max_encrypted_shard_count {
            return Err("encrypted shard count exceeds configured maximum".to_string());
        }
        if shard.shard_index >= shard.shard_count {
            return Err("encrypted shard index must be lower than shard count".to_string());
        }
        let root = shard.root();
        self.encrypted_receipt_shards.push(shard);
        self.encrypted_receipt_shards
            .sort_by(|left, right| shard_sort_key(left).cmp(&shard_sort_key(right)));
        Ok(root)
    }

    pub fn ingest_fee_cap_check(&mut self, mut check: FeeCapCheck) -> Result<String> {
        require_non_empty("receipt_id", &check.receipt_id)?;
        check.cap_piconero = check.cap_piconero.min(self.config.max_fee_cap_piconero);
        check.passed = check.observed_fee_piconero <= check.cap_piconero;
        let receipt_id = check.receipt_id.clone();
        let root = check.root();
        if !check.passed {
            self.record_mismatch(
                &receipt_id,
                "fee-cap",
                &check.cap_piconero.to_string(),
                &check.observed_fee_piconero.to_string(),
                0,
            );
        }
        self.fee_cap_checks.insert(receipt_id, check);
        Ok(root)
    }

    pub fn ingest_wallet_reconstruction_hint(
        &mut self,
        hint: WalletReconstructionHint,
    ) -> Result<String> {
        require_non_empty("receipt_id", &hint.receipt_id)?;
        let existing_count = self
            .wallet_reconstruction_hints
            .iter()
            .filter(|candidate| candidate.receipt_id == hint.receipt_id)
            .count();
        if existing_count >= self.config.max_wallet_hint_count as usize {
            return Err("wallet reconstruction hint count exceeds configured maximum".to_string());
        }
        let root = hint.root();
        self.wallet_reconstruction_hints.push(hint);
        self.wallet_reconstruction_hints
            .sort_by(|left, right| hint_sort_key(left).cmp(&hint_sort_key(right)));
        Ok(root)
    }

    pub fn ingest_metadata_budget(&mut self, mut budget: MetadataBudget) -> Result<String> {
        require_non_empty("receipt_id", &budget.receipt_id)?;
        budget.allowed_bytes = budget.allowed_bytes.min(self.config.max_metadata_bytes);
        budget.leakproof = budget.observed_bytes <= budget.allowed_bytes;
        let receipt_id = budget.receipt_id.clone();
        let root = budget.root();
        if !budget.leakproof {
            self.record_mismatch(
                &receipt_id,
                "metadata-budget",
                &budget.allowed_bytes.to_string(),
                &budget.observed_bytes.to_string(),
                0,
            );
        }
        self.metadata_budgets.insert(receipt_id, budget);
        Ok(root)
    }

    pub fn ingest_pq_authorization_evidence(
        &mut self,
        evidence: PqAuthorizationEvidence,
    ) -> Result<String> {
        require_non_empty("receipt_id", &evidence.receipt_id)?;
        if self.config.pq_authorization_required && !evidence.valid {
            return Err("valid PQ authorization evidence is required".to_string());
        }
        if evidence.signer_quorum < self.config.min_observer_quorum {
            return Err("PQ authorization signer quorum is below configured minimum".to_string());
        }
        let receipt_id = evidence.receipt_id.clone();
        let root = evidence.root();
        self.pq_authorization_evidence.insert(receipt_id, evidence);
        Ok(root)
    }

    pub fn open_release_hold(
        &mut self,
        receipt_id: &str,
        reason_root: &str,
        observed_at_height: u64,
    ) -> Result<String> {
        require_non_empty("receipt_id", receipt_id)?;
        let hold_id = release_hold_id(receipt_id, reason_root, observed_at_height);
        let hold = ReleaseHold {
            receipt_id: receipt_id.to_string(),
            hold_id: hold_id.clone(),
            reason_root: reason_root.to_string(),
            challenge_deadline_height: observed_at_height
                + self.config.release_hold_challenge_window,
            release_after_height: observed_at_height + self.config.release_hold_challenge_window,
            active: true,
            guard_root: self.release_guard_root(receipt_id),
        };
        let root = hold.root();
        self.release_holds.insert(hold_id, hold);
        Ok(root)
    }

    pub fn root_summary(&self) -> Value {
        json!({
            "encrypted_receipt_shard_root": merkle_from_vec("PRIVATE-RECEIPT-ENCRYPTED-SHARD-ROOT", &self.encrypted_receipt_shards, EncryptedReceiptShard::public_record),
            "expected_conformance_root": merkle_from_map("PRIVATE-RECEIPT-EXPECTED-CONFORMANCE-ROOT", &self.expected_roots, ExpectedReceiptRoot::public_record),
            "fee_cap_check_root": merkle_from_map("PRIVATE-RECEIPT-FEE-CAP-CHECK-ROOT", &self.fee_cap_checks, FeeCapCheck::public_record),
            "metadata_budget_root": merkle_from_map("PRIVATE-RECEIPT-METADATA-BUDGET-ROOT", &self.metadata_budgets, MetadataBudget::public_record),
            "mismatch_root": merkle_from_vec("PRIVATE-RECEIPT-MISMATCH-ROOT", &self.mismatches, ReceiptMismatch::public_record),
            "nullifier_commitment_evidence_root": merkle_from_map("PRIVATE-RECEIPT-NULLIFIER-COMMITMENT-EVIDENCE-ROOT", &self.nullifier_commitment_evidence, NullifierCommitmentEvidence::public_record),
            "observed_private_receipt_root": merkle_from_map("PRIVATE-RECEIPT-OBSERVED-RECEIPT-ROOT", &self.observed_receipts, ObservedPrivateReceipt::public_record),
            "pq_authorization_evidence_root": merkle_from_map("PRIVATE-RECEIPT-PQ-AUTHORIZATION-EVIDENCE-ROOT", &self.pq_authorization_evidence, PqAuthorizationEvidence::public_record),
            "release_hold_root": merkle_from_map("PRIVATE-RECEIPT-RELEASE-HOLD-ROOT", &self.release_holds, ReleaseHold::public_record),
            "wallet_reconstruction_hint_root": merkle_from_vec("PRIVATE-RECEIPT-WALLET-RECONSTRUCTION-HINT-ROOT", &self.wallet_reconstruction_hints, WalletReconstructionHint::public_record),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION,
            "roots": self.root_summary(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.root_summary();
        domain_hash(
            "PRIVATE-RECEIPT-OBSERVED-INGEST-RUNTIME-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(
                    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION,
                ),
                HashPart::Str(&self.config.root()),
                HashPart::Json(&roots),
            ],
            32,
        )
    }

    fn compare_observed_to_expected(&mut self, observed: &ObservedPrivateReceipt) -> Result<()> {
        if let Some(expected) = self.expected_roots.get(&observed.receipt_id) {
            let expected_private_receipt_root = expected.expected_private_receipt_root.clone();
            let expected_action_root = expected.expected_action_root.clone();
            if expected_private_receipt_root != observed.observed_private_receipt_root {
                self.record_mismatch(
                    &observed.receipt_id,
                    "private-receipt-root",
                    &expected_private_receipt_root,
                    &observed.observed_private_receipt_root,
                    observed.observed_at_height,
                );
            }
            if expected_action_root != observed.observed_action_root {
                self.record_mismatch(
                    &observed.receipt_id,
                    "action-root",
                    &expected_action_root,
                    &observed.observed_action_root,
                    observed.observed_at_height,
                );
            }
            Ok(())
        } else {
            self.record_mismatch(
                &observed.receipt_id,
                "missing-expected-root",
                &zero_root("missing-expected"),
                &observed.observed_private_receipt_root,
                observed.observed_at_height,
            );
            Ok(())
        }
    }

    fn record_mismatch(
        &mut self,
        receipt_id: &str,
        mismatch_kind: &str,
        expected_root: &str,
        observed_root: &str,
        detected_at_height: u64,
    ) {
        let mismatch = ReceiptMismatch {
            receipt_id: receipt_id.to_string(),
            mismatch_kind: mismatch_kind.to_string(),
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
            severity: "hold".to_string(),
            hold_required: true,
            detected_at_height,
        };
        self.mismatches.push(mismatch);
        self.mismatches
            .sort_by(|left, right| mismatch_sort_key(left).cmp(&mismatch_sort_key(right)));
    }

    fn release_guard_root(&self, receipt_id: &str) -> String {
        if let Some(expected) = self.expected_roots.get(receipt_id) {
            expected.expected_release_policy_root.clone()
        } else {
            zero_root("release-guard")
        }
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

pub fn observed_receipt_id(
    bridge_id: &str,
    import_batch_id: &str,
    private_receipt_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-RECEIPT-OBSERVED-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bridge_id),
            HashPart::Str(import_batch_id),
            HashPart::Str(private_receipt_root),
        ],
        32,
    )
}

pub fn release_hold_id(receipt_id: &str, reason_root: &str, observed_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-RECEIPT-RELEASE-HOLD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(reason_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn receipt_comparison_root(expected_root: &str, observed_root: &str) -> String {
    domain_hash(
        "PRIVATE-RECEIPT-COMPARISON-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(expected_root),
            HashPart::Str(observed_root),
            HashPart::Int((expected_root == observed_root) as i128),
        ],
        32,
    )
}

pub fn metadata_budget_commitment(
    receipt_id: &str,
    allowed_bytes: u32,
    observed_bytes: u32,
    redaction_policy_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-RECEIPT-METADATA-BUDGET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Int(allowed_bytes as i128),
            HashPart::Int(observed_bytes as i128),
            HashPart::Str(redaction_policy_root),
            HashPart::Int((observed_bytes <= allowed_bytes) as i128),
        ],
        32,
    )
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn record_value<T: Serialize>(record: &T) -> Value {
    match serde_json::to_value(record) {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}

fn zero_root(label: &str) -> String {
    domain_hash(ZERO_ROOT_DOMAIN, &[HashPart::Str(label)], 32)
}

fn bool_int(value: bool) -> i128 {
    if value {
        1
    } else {
        0
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn merkle_from_map<T, F>(domain: &str, values: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values.values().map(record).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_from_vec<T, F>(domain: &str, values: &[T], record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values.iter().map(record).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn shard_sort_key(shard: &EncryptedReceiptShard) -> (&str, u16, &str) {
    (&shard.receipt_id, shard.shard_index, &shard.shard_id)
}

fn hint_sort_key(hint: &WalletReconstructionHint) -> (&str, &str) {
    (&hint.receipt_id, &hint.hint_id)
}

fn mismatch_sort_key(mismatch: &ReceiptMismatch) -> (&str, &str, u64, &str) {
    (
        &mismatch.receipt_id,
        &mismatch.mismatch_kind,
        mismatch.detected_at_height,
        &mismatch.observed_root,
    )
}
