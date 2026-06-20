use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqBridgeExitCanonicalWalletClaimExportManifestRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_CLAIM_EXPORT_MANIFEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-wallet-claim-export-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_CLAIM_EXPORT_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-merkle-json-v1";

pub const DEVNET_HEIGHT: u64 = 17_680;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_WALLET_PRIVACY_SET: u64 = 4_096;
pub const DEVNET_MAX_LINKABLE_EXPORT_FIELDS: u64 = 0;
pub const DEVNET_MAX_EXPORTED_TIMING_BUCKETS: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub monero_network: String,
    pub min_privacy_set_size: u64,
    pub max_linkable_export_fields: u64,
    pub max_exported_timing_buckets: u64,
    pub require_operator_free_witnesses: bool,
    pub require_post_quantum_authorization: bool,
    pub require_redacted_receipts: bool,
    pub require_deposit_linkage_commitments_only: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            min_privacy_set_size: DEVNET_WALLET_PRIVACY_SET,
            max_linkable_export_fields: DEVNET_MAX_LINKABLE_EXPORT_FIELDS,
            max_exported_timing_buckets: DEVNET_MAX_EXPORTED_TIMING_BUCKETS,
            require_operator_free_witnesses: true,
            require_post_quantum_authorization: true,
            require_redacted_receipts: true,
            require_deposit_linkage_commitments_only: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "monero_network": self.monero_network,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_linkable_export_fields": self.max_linkable_export_fields,
            "max_exported_timing_buckets": self.max_exported_timing_buckets,
            "require_operator_free_witnesses": self.require_operator_free_witnesses,
            "require_post_quantum_authorization": self.require_post_quantum_authorization,
            "require_redacted_receipts": self.require_redacted_receipts,
            "require_deposit_linkage_commitments_only": self.require_deposit_linkage_commitments_only,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalReceiptShard {
    pub shard_id: String,
    pub receipt_kind: String,
    pub encrypted_receipt_root: String,
    pub wallet_witness_root: String,
    pub operator_dependency: String,
    pub redacted_field_root: String,
    pub local_height: u64,
}

impl LocalReceiptShard {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "receipt_kind": self.receipt_kind,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "wallet_witness_root": self.wallet_witness_root,
            "operator_dependency": self.operator_dependency,
            "redacted_field_root": self.redacted_field_root,
            "local_height": self.local_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanHintCommitment {
    pub hint_id: String,
    pub account_scan_epoch: u64,
    pub encrypted_hint_root: String,
    pub view_tag_commitment_root: String,
    pub decoy_bucket_root: String,
    pub timing_bucket: String,
}

impl ScanHintCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "account_scan_epoch": self.account_scan_epoch,
            "encrypted_hint_root": self.encrypted_hint_root,
            "view_tag_commitment_root": self.view_tag_commitment_root,
            "decoy_bucket_root": self.decoy_bucket_root,
            "timing_bucket": self.timing_bucket,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteNullifierRoots {
    pub note_commitment_root: String,
    pub nullifier_commitment_root: String,
    pub key_image_commitment_root: String,
    pub range_witness_root: String,
    pub membership_witness_root: String,
    pub wallet_only_secret_root: String,
}

impl NoteNullifierRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "note_commitment_root": self.note_commitment_root,
            "nullifier_commitment_root": self.nullifier_commitment_root,
            "key_image_commitment_root": self.key_image_commitment_root,
            "range_witness_root": self.range_witness_root,
            "membership_witness_root": self.membership_witness_root,
            "wallet_only_secret_root": self.wallet_only_secret_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositLinkageRoot {
    pub deposit_set_id: String,
    pub deposit_note_root: String,
    pub linkage_commitment_root: String,
    pub source_txid_commitment_root: String,
    pub export_discloses_txid: bool,
    pub export_discloses_address: bool,
}

impl DepositLinkageRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_set_id": self.deposit_set_id,
            "deposit_note_root": self.deposit_note_root,
            "linkage_commitment_root": self.linkage_commitment_root,
            "source_txid_commitment_root": self.source_txid_commitment_root,
            "export_discloses_txid": self.export_discloses_txid,
            "export_discloses_address": self.export_discloses_address,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRoot {
    pub settlement_id: String,
    pub settlement_receipt_root: String,
    pub bridge_checkpoint_root: String,
    pub withdrawal_queue_root: String,
    pub finalized_height: u64,
    pub operator_signature_required: bool,
}

impl SettlementReceiptRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "settlement_receipt_root": self.settlement_receipt_root,
            "bridge_checkpoint_root": self.bridge_checkpoint_root,
            "withdrawal_queue_root": self.withdrawal_queue_root,
            "finalized_height": self.finalized_height,
            "operator_signature_required": self.operator_signature_required,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWithdrawalAuthorizationMaterial {
    pub authorization_id: String,
    pub algorithm_suite: String,
    pub public_key_commitment_root: String,
    pub signature_commitment_root: String,
    pub transcript_root: String,
    pub replay_fence_root: String,
    pub authorizes_forced_exit_claim: bool,
}

impl PqWithdrawalAuthorizationMaterial {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "algorithm_suite": self.algorithm_suite,
            "public_key_commitment_root": self.public_key_commitment_root,
            "signature_commitment_root": self.signature_commitment_root,
            "transcript_root": self.transcript_root,
            "replay_fence_root": self.replay_fence_root,
            "authorizes_forced_exit_claim": self.authorizes_forced_exit_claim,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionPolicy {
    pub policy_id: String,
    pub exported_fields_root: String,
    pub withheld_fields_root: String,
    pub encrypted_payload_required: bool,
    pub reveal_amount: bool,
    pub reveal_subaddress: bool,
    pub reveal_view_key: bool,
    pub reveal_deposit_txid: bool,
}

impl RedactionPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "exported_fields_root": self.exported_fields_root,
            "withheld_fields_root": self.withheld_fields_root,
            "encrypted_payload_required": self.encrypted_payload_required,
            "reveal_amount": self.reveal_amount,
            "reveal_subaddress": self.reveal_subaddress,
            "reveal_view_key": self.reveal_view_key,
            "reveal_deposit_txid": self.reveal_deposit_txid,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataLeakBudget {
    pub budget_id: String,
    pub privacy_set_size: u64,
    pub linkable_export_fields: u64,
    pub exported_timing_buckets: u64,
    pub address_reuse_disclosed: bool,
    pub operator_correlation_material: bool,
    pub budget_accepted: bool,
}

impl MetadataLeakBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "privacy_set_size": self.privacy_set_size,
            "linkable_export_fields": self.linkable_export_fields,
            "exported_timing_buckets": self.exported_timing_buckets,
            "address_reuse_disclosed": self.address_reuse_disclosed,
            "operator_correlation_material": self.operator_correlation_material,
            "budget_accepted": self.budget_accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPackageRoots {
    pub package_id: String,
    pub manifest_root: String,
    pub local_receipt_shard_root: String,
    pub scan_hint_commitment_root: String,
    pub note_nullifier_root: String,
    pub deposit_linkage_root: String,
    pub settlement_receipt_root: String,
    pub pq_authorization_root: String,
    pub redaction_policy_root: String,
    pub metadata_leak_budget_root: String,
}

impl ExportPackageRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "package_id": self.package_id,
            "manifest_root": self.manifest_root,
            "local_receipt_shard_root": self.local_receipt_shard_root,
            "scan_hint_commitment_root": self.scan_hint_commitment_root,
            "note_nullifier_root": self.note_nullifier_root,
            "deposit_linkage_root": self.deposit_linkage_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "pq_authorization_root": self.pq_authorization_root,
            "redaction_policy_root": self.redaction_policy_root,
            "metadata_leak_budget_root": self.metadata_leak_budget_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimBuilderReadiness {
    pub readiness_id: String,
    pub can_build_without_operator: bool,
    pub unacceptable_metadata_leakage: bool,
    pub has_local_receipts: bool,
    pub has_note_and_nullifier_roots: bool,
    pub has_deposit_linkage_commitments: bool,
    pub has_settlement_receipts: bool,
    pub has_pq_authorization: bool,
    pub redaction_policy_satisfied: bool,
    pub metadata_budget_satisfied: bool,
    pub ready_reason_root: String,
}

impl ClaimBuilderReadiness {
    pub fn public_record(&self) -> Value {
        json!({
            "readiness_id": self.readiness_id,
            "can_build_without_operator": self.can_build_without_operator,
            "unacceptable_metadata_leakage": self.unacceptable_metadata_leakage,
            "has_local_receipts": self.has_local_receipts,
            "has_note_and_nullifier_roots": self.has_note_and_nullifier_roots,
            "has_deposit_linkage_commitments": self.has_deposit_linkage_commitments,
            "has_settlement_receipts": self.has_settlement_receipts,
            "has_pq_authorization": self.has_pq_authorization,
            "redaction_policy_satisfied": self.redaction_policy_satisfied,
            "metadata_budget_satisfied": self.metadata_budget_satisfied,
            "ready_reason_root": self.ready_reason_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub export_height: u64,
    pub wallet_export_context_root: String,
    pub local_receipt_shards: Vec<LocalReceiptShard>,
    pub scan_hint_commitments: Vec<ScanHintCommitment>,
    pub note_nullifier_roots: NoteNullifierRoots,
    pub deposit_linkage_roots: Vec<DepositLinkageRoot>,
    pub settlement_receipt_roots: Vec<SettlementReceiptRoot>,
    pub pq_withdrawal_authorization_material: PqWithdrawalAuthorizationMaterial,
    pub redaction_policy: RedactionPolicy,
    pub metadata_leak_budget: MetadataLeakBudget,
    pub export_package_roots: ExportPackageRoots,
    pub claim_builder_readiness: ClaimBuilderReadiness,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let export_height = DEVNET_HEIGHT;
        let wallet_export_context_root = private_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-EXPORT-CONTEXT",
            "devnet-wallet-local-escape-context-001",
        );
        let local_receipt_shards = vec![
            LocalReceiptShard {
                shard_id: deterministic_id("receipt-shard", "wallet-owned-ingress"),
                receipt_kind: "encrypted_deposit_acceptance".to_string(),
                encrypted_receipt_root: private_root(
                    "MONERO-L2-PQ-BRIDGE-EXIT-ENCRYPTED-RECEIPT",
                    "devnet-encrypted-deposit-acceptance",
                ),
                wallet_witness_root: private_root(
                    "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-WITNESS",
                    "devnet-wallet-witness-ingress",
                ),
                operator_dependency: "none".to_string(),
                redacted_field_root: redacted_root(&["amount", "subaddress", "view_key"]),
                local_height: export_height.saturating_sub(42),
            },
            LocalReceiptShard {
                shard_id: deterministic_id("receipt-shard", "wallet-owned-withdrawal"),
                receipt_kind: "encrypted_withdrawal_intent".to_string(),
                encrypted_receipt_root: private_root(
                    "MONERO-L2-PQ-BRIDGE-EXIT-ENCRYPTED-RECEIPT",
                    "devnet-encrypted-withdrawal-intent",
                ),
                wallet_witness_root: private_root(
                    "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-WITNESS",
                    "devnet-wallet-witness-withdrawal",
                ),
                operator_dependency: "none".to_string(),
                redacted_field_root: redacted_root(&["amount", "destination", "operator_route"]),
                local_height: export_height.saturating_sub(7),
            },
        ];
        let scan_hint_commitments = vec![
            ScanHintCommitment {
                hint_id: deterministic_id("scan-hint", "account-epoch-44"),
                account_scan_epoch: 44,
                encrypted_hint_root: private_root(
                    "MONERO-L2-PQ-BRIDGE-EXIT-ENCRYPTED-SCAN-HINT",
                    "devnet-scan-hint-44",
                ),
                view_tag_commitment_root: private_root(
                    "MONERO-L2-PQ-BRIDGE-EXIT-VIEW-TAG",
                    "devnet-view-tag-bucket-44",
                ),
                decoy_bucket_root: deterministic_id("scan-decoy-bucket", "ring-4096"),
                timing_bucket: "epoch_44_coarse".to_string(),
            },
            ScanHintCommitment {
                hint_id: deterministic_id("scan-hint", "account-epoch-45"),
                account_scan_epoch: 45,
                encrypted_hint_root: private_root(
                    "MONERO-L2-PQ-BRIDGE-EXIT-ENCRYPTED-SCAN-HINT",
                    "devnet-scan-hint-45",
                ),
                view_tag_commitment_root: private_root(
                    "MONERO-L2-PQ-BRIDGE-EXIT-VIEW-TAG",
                    "devnet-view-tag-bucket-45",
                ),
                decoy_bucket_root: deterministic_id("scan-decoy-bucket", "ring-4096"),
                timing_bucket: "epoch_44_coarse".to_string(),
            },
        ];
        let note_nullifier_roots = NoteNullifierRoots {
            note_commitment_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-NOTE-COMMITMENT",
                "devnet-note-commitment-set",
            ),
            nullifier_commitment_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-NULLIFIER-COMMITMENT",
                "devnet-nullifier-set",
            ),
            key_image_commitment_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-KEY-IMAGE-COMMITMENT",
                "devnet-key-image-set",
            ),
            range_witness_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RANGE-WITNESS",
                "devnet-range-witness",
            ),
            membership_witness_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-MEMBERSHIP-WITNESS",
                "devnet-membership-witness",
            ),
            wallet_only_secret_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-ONLY-SECRET",
                "devnet-wallet-only-secret",
            ),
        };
        let deposit_linkage_roots = vec![DepositLinkageRoot {
            deposit_set_id: deterministic_id("deposit-set", "wallet-canonical-claim"),
            deposit_note_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE",
                "devnet-deposit-note",
            ),
            linkage_commitment_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LINKAGE",
                "devnet-deposit-linkage-commitment",
            ),
            source_txid_commitment_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SOURCE-TXID",
                "devnet-source-txid-commitment",
            ),
            export_discloses_txid: false,
            export_discloses_address: false,
        }];
        let settlement_receipt_roots = vec![SettlementReceiptRoot {
            settlement_id: deterministic_id("settlement", "wallet-forced-exit"),
            settlement_receipt_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SETTLEMENT-RECEIPT",
                "devnet-settlement-receipt",
            ),
            bridge_checkpoint_root: deterministic_id("bridge-checkpoint", "withheld-operator-data"),
            withdrawal_queue_root: deterministic_id("withdrawal-queue", "canonical-wallet-claim"),
            finalized_height: export_height.saturating_sub(3),
            operator_signature_required: false,
        }];
        let pq_withdrawal_authorization_material = PqWithdrawalAuthorizationMaterial {
            authorization_id: deterministic_id("pq-withdrawal-authorization", "wallet-auth-001"),
            algorithm_suite: "ml-dsa-87+slh-dsa-shake-256f-hybrid-commitments".to_string(),
            public_key_commitment_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-PQ-PUBLIC-KEY",
                "devnet-pq-public-key",
            ),
            signature_commitment_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-PQ-SIGNATURE",
                "devnet-pq-signature",
            ),
            transcript_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-PQ-TRANSCRIPT",
                "devnet-pq-withdrawal-transcript",
            ),
            replay_fence_root: private_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-PQ-REPLAY-FENCE",
                "devnet-pq-replay-fence",
            ),
            authorizes_forced_exit_claim: true,
        };
        let redaction_policy = RedactionPolicy {
            policy_id: deterministic_id("redaction-policy", "canonical-wallet-forced-exit"),
            exported_fields_root: redacted_root(&[
                "manifest_roots",
                "commitment_roots",
                "encrypted_receipt_roots",
                "coarse_scan_epoch",
            ]),
            withheld_fields_root: redacted_root(&[
                "amount",
                "subaddress",
                "view_key",
                "deposit_txid",
                "destination",
                "operator_route",
            ]),
            encrypted_payload_required: true,
            reveal_amount: false,
            reveal_subaddress: false,
            reveal_view_key: false,
            reveal_deposit_txid: false,
        };
        let metadata_leak_budget = MetadataLeakBudget {
            budget_id: deterministic_id("metadata-leak-budget", "devnet-wallet-escape"),
            privacy_set_size: DEVNET_WALLET_PRIVACY_SET,
            linkable_export_fields: 0,
            exported_timing_buckets: 1,
            address_reuse_disclosed: false,
            operator_correlation_material: false,
            budget_accepted: true,
        };
        let local_receipt_shard_root = record_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-LOCAL-RECEIPT-SHARDS",
            local_receipt_shards
                .iter()
                .map(LocalReceiptShard::public_record)
                .collect(),
        );
        let scan_hint_commitment_root = record_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SCAN-HINT-COMMITMENTS",
            scan_hint_commitments
                .iter()
                .map(ScanHintCommitment::public_record)
                .collect(),
        );
        let note_nullifier_root = record_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NOTE-NULLIFIER-ROOTS",
            &note_nullifier_roots.public_record(),
        );
        let deposit_linkage_root = record_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LINKAGE-ROOTS",
            deposit_linkage_roots
                .iter()
                .map(DepositLinkageRoot::public_record)
                .collect(),
        );
        let settlement_receipt_root = record_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SETTLEMENT-RECEIPT-ROOTS",
            settlement_receipt_roots
                .iter()
                .map(SettlementReceiptRoot::public_record)
                .collect(),
        );
        let pq_authorization_root = record_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORIZATION-MATERIAL",
            &pq_withdrawal_authorization_material.public_record(),
        );
        let redaction_policy_root = record_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-REDACTION-POLICY",
            &redaction_policy.public_record(),
        );
        let metadata_leak_budget_root = record_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-METADATA-LEAK-BUDGET",
            &metadata_leak_budget.public_record(),
        );
        let manifest_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-EXPORT-MANIFEST",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(export_height),
                HashPart::Str(&wallet_export_context_root),
                HashPart::Str(&local_receipt_shard_root),
                HashPart::Str(&scan_hint_commitment_root),
                HashPart::Str(&note_nullifier_root),
                HashPart::Str(&deposit_linkage_root),
                HashPart::Str(&settlement_receipt_root),
                HashPart::Str(&pq_authorization_root),
                HashPart::Str(&redaction_policy_root),
                HashPart::Str(&metadata_leak_budget_root),
            ],
            32,
        );
        let package_id = deterministic_id("export-package", "canonical-wallet-forced-exit");
        let export_package_roots = ExportPackageRoots {
            package_id,
            manifest_root,
            local_receipt_shard_root,
            scan_hint_commitment_root,
            note_nullifier_root,
            deposit_linkage_root,
            settlement_receipt_root,
            pq_authorization_root,
            redaction_policy_root,
            metadata_leak_budget_root,
        };
        let claim_builder_readiness = build_readiness(
            &config,
            &local_receipt_shards,
            &note_nullifier_roots,
            &deposit_linkage_roots,
            &settlement_receipt_roots,
            &pq_withdrawal_authorization_material,
            &redaction_policy,
            &metadata_leak_budget,
        );

        Self {
            config,
            export_height,
            wallet_export_context_root,
            local_receipt_shards,
            scan_hint_commitments,
            note_nullifier_roots,
            deposit_linkage_roots,
            settlement_receipt_roots,
            pq_withdrawal_authorization_material,
            redaction_policy,
            metadata_leak_budget,
            export_package_roots,
            claim_builder_readiness,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "export_height": self.export_height,
            "wallet_export_context_root": self.wallet_export_context_root,
            "config": self.config.public_record(),
            "local_receipt_shards": self.local_receipt_shards
                .iter()
                .map(LocalReceiptShard::public_record)
                .collect::<Vec<Value>>(),
            "scan_hint_commitments": self.scan_hint_commitments
                .iter()
                .map(ScanHintCommitment::public_record)
                .collect::<Vec<Value>>(),
            "note_nullifier_roots": self.note_nullifier_roots.public_record(),
            "deposit_linkage_roots": self.deposit_linkage_roots
                .iter()
                .map(DepositLinkageRoot::public_record)
                .collect::<Vec<Value>>(),
            "settlement_receipt_roots": self.settlement_receipt_roots
                .iter()
                .map(SettlementReceiptRoot::public_record)
                .collect::<Vec<Value>>(),
            "pq_withdrawal_authorization_material": self.pq_withdrawal_authorization_material.public_record(),
            "redaction_policy": self.redaction_policy.public_record(),
            "metadata_leak_budget": self.metadata_leak_budget.public_record(),
            "export_package_roots": self.export_package_roots.public_record(),
            "claim_builder_readiness": self.claim_builder_readiness.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-CLAIM-EXPORT-MANIFEST-STATE",
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(
        &self,
    ) -> MoneroL2PqBridgeExitCanonicalWalletClaimExportManifestRuntimeResult<()> {
        if self.config.chain_id != CHAIN_ID {
            return Err("wallet claim export manifest chain id mismatch".to_string());
        }
        if self.config.protocol_version != PROTOCOL_VERSION {
            return Err("wallet claim export manifest protocol version mismatch".to_string());
        }
        if self.config.schema_version != SCHEMA_VERSION {
            return Err("wallet claim export manifest schema version mismatch".to_string());
        }
        if self.config.hash_suite != HASH_SUITE {
            return Err("wallet claim export manifest hash suite mismatch".to_string());
        }
        if !self.claim_builder_readiness.can_build_without_operator {
            return Err(
                "wallet claim export package still depends on operator cooperation".to_string(),
            );
        }
        if self.claim_builder_readiness.unacceptable_metadata_leakage {
            return Err("wallet claim export package exceeds metadata leak budget".to_string());
        }
        Ok(())
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

fn build_readiness(
    config: &Config,
    local_receipt_shards: &[LocalReceiptShard],
    note_nullifier_roots: &NoteNullifierRoots,
    deposit_linkage_roots: &[DepositLinkageRoot],
    settlement_receipt_roots: &[SettlementReceiptRoot],
    pq_authorization: &PqWithdrawalAuthorizationMaterial,
    redaction_policy: &RedactionPolicy,
    metadata_budget: &MetadataLeakBudget,
) -> ClaimBuilderReadiness {
    let has_local_receipts = !local_receipt_shards.is_empty()
        && local_receipt_shards
            .iter()
            .all(|shard| shard.operator_dependency == "none");
    let has_note_and_nullifier_roots = !note_nullifier_roots.note_commitment_root.is_empty()
        && !note_nullifier_roots.nullifier_commitment_root.is_empty()
        && !note_nullifier_roots.key_image_commitment_root.is_empty()
        && !note_nullifier_roots.membership_witness_root.is_empty();
    let has_deposit_linkage_commitments = !deposit_linkage_roots.is_empty()
        && deposit_linkage_roots
            .iter()
            .all(|root| !root.export_discloses_txid && !root.export_discloses_address);
    let has_settlement_receipts = !settlement_receipt_roots.is_empty()
        && settlement_receipt_roots
            .iter()
            .all(|root| !root.operator_signature_required);
    let has_pq_authorization = pq_authorization.authorizes_forced_exit_claim
        && !pq_authorization.transcript_root.is_empty();
    let redaction_policy_satisfied = redaction_policy.encrypted_payload_required
        && !redaction_policy.reveal_amount
        && !redaction_policy.reveal_subaddress
        && !redaction_policy.reveal_view_key
        && !redaction_policy.reveal_deposit_txid;
    let metadata_budget_satisfied = metadata_budget.budget_accepted
        && metadata_budget.privacy_set_size >= config.min_privacy_set_size
        && metadata_budget.linkable_export_fields <= config.max_linkable_export_fields
        && metadata_budget.exported_timing_buckets <= config.max_exported_timing_buckets
        && !metadata_budget.address_reuse_disclosed
        && !metadata_budget.operator_correlation_material;
    let can_build_without_operator = has_local_receipts
        && has_note_and_nullifier_roots
        && has_deposit_linkage_commitments
        && has_settlement_receipts
        && has_pq_authorization;
    let unacceptable_metadata_leakage = !(redaction_policy_satisfied && metadata_budget_satisfied);
    let ready_reason_root = record_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-BUILDER-READINESS-REASONS",
        &json!({
            "operator_withheld_data_required": !can_build_without_operator,
            "local_receipts_available": has_local_receipts,
            "commitment_witnesses_available": has_note_and_nullifier_roots,
            "deposit_linkage_is_commitment_only": has_deposit_linkage_commitments,
            "settlement_receipts_operator_free": has_settlement_receipts,
            "pq_authorization_present": has_pq_authorization,
            "privacy_budget_satisfied": metadata_budget_satisfied,
            "redaction_policy_satisfied": redaction_policy_satisfied,
        }),
    );

    ClaimBuilderReadiness {
        readiness_id: deterministic_id("claim-builder-readiness", "devnet-wallet-escape-ready"),
        can_build_without_operator,
        unacceptable_metadata_leakage,
        has_local_receipts,
        has_note_and_nullifier_roots,
        has_deposit_linkage_commitments,
        has_settlement_receipts,
        has_pq_authorization,
        redaction_policy_satisfied,
        metadata_budget_satisfied,
        ready_reason_root,
    }
}

fn deterministic_id(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-EXPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn private_root(domain: &str, secret_label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(secret_label),
        ],
        32,
    )
}

fn redacted_root(fields: &[&str]) -> String {
    let leaves = fields
        .iter()
        .map(|field| Value::String((*field).to_string()))
        .collect::<Vec<Value>>();
    merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-REDACTED-FIELDS", &leaves)
}

fn record_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn record_hash(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
