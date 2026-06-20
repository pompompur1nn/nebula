use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqBridgeExitCanonicalWalletExitCliPayloadManifestRuntimeResult<T> =
    Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_EXIT_CLI_PAYLOAD_MANIFEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-wallet-exit-cli-payload-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_EXIT_CLI_PAYLOAD_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-merkle-json-v1";

pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_MANIFEST_HEIGHT: u64 = 18_240;
pub const DEVNET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEVNET_MAX_DISCLOSED_TIMING_BUCKETS: u64 = 1;
pub const DEVNET_MAX_LINKABLE_FIELDS: u64 = 0;
pub const DEVNET_FEE_CAP_ATOMIC: u64 = 30_000_000;
pub const DEVNET_PQ_SECURITY_BITS: u64 = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub monero_network: String,
    pub min_privacy_set_size: u64,
    pub max_disclosed_timing_buckets: u64,
    pub max_linkable_fields: u64,
    pub fee_cap_atomic: u64,
    pub min_pq_security_bits: u64,
    pub require_operator_free_payloads: bool,
    pub require_redacted_exports: bool,
    pub require_commitment_only_identifiers: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            min_privacy_set_size: DEVNET_PRIVACY_SET_SIZE,
            max_disclosed_timing_buckets: DEVNET_MAX_DISCLOSED_TIMING_BUCKETS,
            max_linkable_fields: DEVNET_MAX_LINKABLE_FIELDS,
            fee_cap_atomic: DEVNET_FEE_CAP_ATOMIC,
            min_pq_security_bits: DEVNET_PQ_SECURITY_BITS,
            require_operator_free_payloads: true,
            require_redacted_exports: true,
            require_commitment_only_identifiers: true,
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
            "max_disclosed_timing_buckets": self.max_disclosed_timing_buckets,
            "max_linkable_fields": self.max_linkable_fields,
            "fee_cap_atomic": self.fee_cap_atomic,
            "min_pq_security_bits": self.min_pq_security_bits,
            "require_operator_free_payloads": self.require_operator_free_payloads,
            "require_redacted_exports": self.require_redacted_exports,
            "require_commitment_only_identifiers": self.require_commitment_only_identifiers,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-EXIT-CLI-PAYLOAD-MANIFEST-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliPayloadStage {
    pub stage_id: String,
    pub stage_name: String,
    pub command_family: String,
    pub payload_root: String,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub withheld_metadata_root: String,
    pub operator_cooperation_required: bool,
    pub leaks_sensitive_metadata: bool,
    pub replay_protected: bool,
}

impl CliPayloadStage {
    pub fn public_record(&self) -> Value {
        json!({
            "stage_id": self.stage_id,
            "stage_name": self.stage_name,
            "command_family": self.command_family,
            "payload_root": self.payload_root,
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "withheld_metadata_root": self.withheld_metadata_root,
            "operator_cooperation_required": self.operator_cooperation_required,
            "leaks_sensitive_metadata": self.leaks_sensitive_metadata,
            "replay_protected": self.replay_protected,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-EXIT-CLI-PAYLOAD-STAGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadRootSet {
    pub scan_root: String,
    pub reconstruct_root: String,
    pub claim_build_root: String,
    pub challenge_watch_root: String,
    pub release_verify_root: String,
    pub fee_cap_check_root: String,
    pub pq_authorization_root: String,
    pub export_redaction_root: String,
    pub stage_merkle_root: String,
}

impl PayloadRootSet {
    pub fn from_stages(stages: &[CliPayloadStage]) -> Self {
        let stage_records = stages
            .iter()
            .map(CliPayloadStage::public_record)
            .collect::<Vec<_>>();
        let root_for = |name: &str| {
            stages
                .iter()
                .find(|stage| stage.stage_name == name)
                .map(CliPayloadStage::root)
                .unwrap_or_else(|| merkle_root("WALLET-EXIT-CLI-PAYLOAD-MISSING-STAGE", &[]))
        };

        Self {
            scan_root: root_for("scan"),
            reconstruct_root: root_for("reconstruct"),
            claim_build_root: root_for("claim-build"),
            challenge_watch_root: root_for("challenge-watch"),
            release_verify_root: root_for("release-verify"),
            fee_cap_check_root: root_for("fee-cap-check"),
            pq_authorization_root: root_for("pq-authorization"),
            export_redaction_root: root_for("export-redaction"),
            stage_merkle_root: merkle_root("WALLET-EXIT-CLI-PAYLOAD-STAGES", &stage_records),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scan_root": self.scan_root,
            "reconstruct_root": self.reconstruct_root,
            "claim_build_root": self.claim_build_root,
            "challenge_watch_root": self.challenge_watch_root,
            "release_verify_root": self.release_verify_root,
            "fee_cap_check_root": self.fee_cap_check_root,
            "pq_authorization_root": self.pq_authorization_root,
            "export_redaction_root": self.export_redaction_root,
            "stage_merkle_root": self.stage_merkle_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForceExitCapability {
    pub capability_id: String,
    pub can_force_exit_without_operator: bool,
    pub can_export_without_metadata_leakage: bool,
    pub privacy_set_size: u64,
    pub disclosed_timing_buckets: u64,
    pub linkable_fields: u64,
    pub fee_cap_atomic: u64,
    pub pq_security_bits: u64,
    pub wallet_owned_witness_root: String,
    pub operator_dependency_root: String,
    pub redaction_policy_root: String,
}

impl ForceExitCapability {
    pub fn public_record(&self) -> Value {
        json!({
            "capability_id": self.capability_id,
            "can_force_exit_without_operator": self.can_force_exit_without_operator,
            "can_export_without_metadata_leakage": self.can_export_without_metadata_leakage,
            "privacy_set_size": self.privacy_set_size,
            "disclosed_timing_buckets": self.disclosed_timing_buckets,
            "linkable_fields": self.linkable_fields,
            "fee_cap_atomic": self.fee_cap_atomic,
            "pq_security_bits": self.pq_security_bits,
            "wallet_owned_witness_root": self.wallet_owned_witness_root,
            "operator_dependency_root": self.operator_dependency_root,
            "redaction_policy_root": self.redaction_policy_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "WALLET-EXIT-CLI-PAYLOAD-CAPABILITY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub manifest_id: String,
    pub manifest_height: u64,
    pub payload_roots: PayloadRootSet,
    pub stages: Vec<CliPayloadStage>,
    pub capability: ForceExitCapability,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let stages = devnet_stages();
        let payload_roots = PayloadRootSet::from_stages(&stages);
        let capability = devnet_capability();
        let manifest_id = domain_hash(
            "WALLET-EXIT-CLI-PAYLOAD-MANIFEST-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(DEVNET_MANIFEST_HEIGHT),
                HashPart::Str(&payload_roots.stage_merkle_root),
                HashPart::Str(&capability.root()),
            ],
            32,
        );

        Self {
            config,
            manifest_id,
            manifest_height: DEVNET_MANIFEST_HEIGHT,
            payload_roots,
            stages,
            capability,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": self.config.hash_suite,
            "manifest_id": self.manifest_id,
            "manifest_height": self.manifest_height,
            "config_root": self.config.root(),
            "payload_roots": self.payload_roots.public_record(),
            "stages": self.stages.iter().map(CliPayloadStage::public_record).collect::<Vec<_>>(),
            "capability": self.capability.public_record(),
            "capability_root": self.capability.root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "WALLET-EXIT-CLI-PAYLOAD-MANIFEST-STATE",
            &[HashPart::Json(&self.public_record())],
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

fn devnet_stages() -> Vec<CliPayloadStage> {
    [
        ("scan", "wallet-scan", 0_u64),
        ("reconstruct", "receipt-reconstruct", 1),
        ("claim-build", "forced-exit-claim-build", 2),
        ("challenge-watch", "challenge-window-watch", 3),
        ("release-verify", "custody-release-verify", 4),
        ("fee-cap-check", "exit-fee-cap-check", 5),
        ("pq-authorization", "pq-wallet-authorization", 6),
        ("export-redaction", "metadata-redacted-export", 7),
    ]
    .into_iter()
    .map(|(stage_name, command_family, index)| {
        let stage_id = domain_hash(
            "WALLET-EXIT-CLI-PAYLOAD-STAGE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(stage_name),
                HashPart::U64(index),
            ],
            16,
        );
        let leaf = json!({
            "chain_id": CHAIN_ID,
            "stage_name": stage_name,
            "command_family": command_family,
            "manifest_height": DEVNET_MANIFEST_HEIGHT,
            "input_scope": "commitment-only",
            "output_scope": "encrypted-or-redacted-root-only",
        });
        CliPayloadStage {
            stage_id,
            stage_name: stage_name.to_string(),
            command_family: command_family.to_string(),
            payload_root: domain_hash("WALLET-EXIT-CLI-PAYLOAD-ROOT", &[HashPart::Json(&leaf)], 32),
            input_commitment_root: domain_hash(
                "WALLET-EXIT-CLI-PAYLOAD-INPUT-COMMITMENT",
                &[HashPart::Str(CHAIN_ID), HashPart::Str(stage_name)],
                32,
            ),
            output_commitment_root: domain_hash(
                "WALLET-EXIT-CLI-PAYLOAD-OUTPUT-COMMITMENT",
                &[HashPart::Str(CHAIN_ID), HashPart::Str(stage_name)],
                32,
            ),
            withheld_metadata_root: domain_hash(
                "WALLET-EXIT-CLI-PAYLOAD-WITHHELD-METADATA",
                &[HashPart::Str(CHAIN_ID), HashPart::Str(stage_name)],
                32,
            ),
            operator_cooperation_required: false,
            leaks_sensitive_metadata: false,
            replay_protected: true,
        }
    })
    .collect()
}

fn devnet_capability() -> ForceExitCapability {
    ForceExitCapability {
        capability_id: domain_hash(
            "WALLET-EXIT-CLI-PAYLOAD-CAPABILITY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(DEVNET_MANIFEST_HEIGHT),
            ],
            16,
        ),
        can_force_exit_without_operator: true,
        can_export_without_metadata_leakage: true,
        privacy_set_size: DEVNET_PRIVACY_SET_SIZE,
        disclosed_timing_buckets: DEVNET_MAX_DISCLOSED_TIMING_BUCKETS,
        linkable_fields: DEVNET_MAX_LINKABLE_FIELDS,
        fee_cap_atomic: DEVNET_FEE_CAP_ATOMIC,
        pq_security_bits: DEVNET_PQ_SECURITY_BITS,
        wallet_owned_witness_root: domain_hash(
            "WALLET-EXIT-CLI-PAYLOAD-WALLET-OWNED-WITNESS",
            &[HashPart::Str(CHAIN_ID), HashPart::Str("all-stages")],
            32,
        ),
        operator_dependency_root: merkle_root("WALLET-EXIT-CLI-PAYLOAD-OPERATOR-DEPENDENCY", &[]),
        redaction_policy_root: domain_hash(
            "WALLET-EXIT-CLI-PAYLOAD-REDACTION-POLICY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(DEVNET_MAX_LINKABLE_FIELDS),
                HashPart::U64(DEVNET_MAX_DISCLOSED_TIMING_BUCKETS),
            ],
            32,
        ),
    }
}
