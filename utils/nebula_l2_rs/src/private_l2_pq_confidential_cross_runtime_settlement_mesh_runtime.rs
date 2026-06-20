use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-runtime-settlement-mesh-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const DEFAULT_L2_HEIGHT: u64 = 1_924_000;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_706_000;
pub const DEFAULT_MESH_EPOCH: u64 = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_MANIFESTS_PER_EPOCH: usize = 4_096;
pub const DEFAULT_MAX_PRECONFIRMATION_DELAY_SLOTS: u64 = 8;
pub const DEFAULT_LOW_FEE_CAP_BPS: u64 = 16;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshRuntimeKind {
    MoneroBridge,
    ContractReceiptIndex,
    FeeNetting,
    FastPreconfirmation,
    DefiLiquidity,
    Watchtower,
}

impl MeshRuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::ContractReceiptIndex => "contract_receipt_index",
            Self::FeeNetting => "fee_netting",
            Self::FastPreconfirmation => "fast_preconfirmation",
            Self::DefiLiquidity => "defi_liquidity",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    QuorumAttested,
    Preconfirmed,
    Netted,
    Settled,
    Disputed,
    Slashed,
    Expired,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::QuorumAttested => "quorum_attested",
            Self::Preconfirmed => "preconfirmed",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::QuorumAttested | Self::Preconfirmed | Self::Netted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    BridgeNullifier,
    ReceiptReplay,
    FeeSponsorAbuse,
    ShardConflict,
    LiquiditySlippage,
    ReorgGuard,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeNullifier => "bridge_nullifier",
            Self::ReceiptReplay => "receipt_replay",
            Self::FeeSponsorAbuse => "fee_sponsor_abuse",
            Self::ShardConflict => "shard_conflict",
            Self::LiquiditySlippage => "liquidity_slippage",
            Self::ReorgGuard => "reorg_guard",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    FalseReceiptRoot,
    BadBridgeReserve,
    InvalidPreconfirmation,
    FeeNettingFraud,
    LiquiditySettlementFraud,
    PrivacyFenceViolation,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalseReceiptRoot => "false_receipt_root",
            Self::BadBridgeReserve => "bad_bridge_reserve",
            Self::InvalidPreconfirmation => "invalid_preconfirmation",
            Self::FeeNettingFraud => "fee_netting_fraud",
            Self::LiquiditySettlementFraud => "liquidity_settlement_fraud",
            Self::PrivacyFenceViolation => "privacy_fence_violation",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub mesh_epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_manifests_per_epoch: usize,
    pub max_preconfirmation_delay_slots: u64,
    pub low_fee_cap_bps: u64,
    pub slash_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            mesh_epoch: DEFAULT_MESH_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_manifests_per_epoch: DEFAULT_MAX_MANIFESTS_PER_EPOCH,
            max_preconfirmation_delay_slots: DEFAULT_MAX_PRECONFIRMATION_DELAY_SLOTS,
            low_fee_cap_bps: DEFAULT_LOW_FEE_CAP_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(!self.chain_id.is_empty(), "chain id cannot be empty")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(self.mesh_epoch > 0, "mesh epoch must be positive")?;
        require(
            self.min_pq_security_bits >= 192,
            "pq security bits below floor",
        )?;
        require(
            self.min_privacy_set_size >= 128,
            "privacy set size below floor",
        )?;
        require(
            self.max_manifests_per_epoch > 0,
            "manifest limit must be positive",
        )?;
        require(self.low_fee_cap_bps <= MAX_BPS, "fee cap exceeds max bps")?;
        require(self.slash_bps <= MAX_BPS, "slash bps exceeds max bps")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "mesh_epoch": self.mesh_epoch,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_manifests_per_epoch": self.max_manifests_per_epoch,
            "max_preconfirmation_delay_slots": self.max_preconfirmation_delay_slots,
            "low_fee_cap_bps": self.low_fee_cap_bps,
            "slash_bps": self.slash_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub manifests: u64,
    pub attestations: u64,
    pub fee_nets: u64,
    pub preconfirmations: u64,
    pub liquidity_settlements: u64,
    pub fences: u64,
    pub slashes: u64,
    pub settled_micro_xmr: u64,
    pub rebated_micro_xmr: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "manifests": self.manifests,
            "attestations": self.attestations,
            "fee_nets": self.fee_nets,
            "preconfirmations": self.preconfirmations,
            "liquidity_settlements": self.liquidity_settlements,
            "fences": self.fences,
            "slashes": self.slashes,
            "settled_micro_xmr": self.settled_micro_xmr,
            "rebated_micro_xmr": self.rebated_micro_xmr,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeExecutionManifest {
    pub manifest_id: String,
    pub epoch: u64,
    pub bridge_output_root: String,
    pub subaddress_claim_root: String,
    pub execution_receipt_root: String,
    pub monero_reserve_root: String,
    pub settlement_manifest_root: String,
    pub participant_root: String,
    pub amount_micro_xmr: u64,
    pub privacy_set_size: u64,
    pub status: SettlementStatus,
}

impl BridgeExecutionManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "epoch": self.epoch,
            "bridge_output_root": self.bridge_output_root,
            "subaddress_claim_root": self.subaddress_claim_root,
            "execution_receipt_root": self.execution_receipt_root,
            "monero_reserve_root": self.monero_reserve_root,
            "settlement_manifest_root": self.settlement_manifest_root,
            "participant_root": self.participant_root,
            "amount_micro_xmr": self.amount_micro_xmr,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeAttestation {
    pub attestation_id: String,
    pub manifest_id: String,
    pub runtime_kind: MeshRuntimeKind,
    pub signer_commitment: String,
    pub pq_key_commitment: String,
    pub attested_root: String,
    pub signature_root: String,
    pub weight: u64,
    pub l2_height: u64,
}

impl RuntimeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "manifest_id": self.manifest_id,
            "runtime_kind": self.runtime_kind.as_str(),
            "signer_commitment": self.signer_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "attested_root": self.attested_root,
            "signature_root": self.signature_root,
            "weight": self.weight,
            "l2_height": self.l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeNetSettlement {
    pub fee_net_id: String,
    pub manifest_id: String,
    pub payer_cohort_root: String,
    pub sponsor_root: String,
    pub rebate_coupon_root: String,
    pub fee_asset_root: String,
    pub gross_fee_micro_xmr: u64,
    pub net_fee_micro_xmr: u64,
    pub rebate_micro_xmr: u64,
}

impl FeeNetSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_net_id": self.fee_net_id,
            "manifest_id": self.manifest_id,
            "payer_cohort_root": self.payer_cohort_root,
            "sponsor_root": self.sponsor_root,
            "rebate_coupon_root": self.rebate_coupon_root,
            "fee_asset_root": self.fee_asset_root,
            "gross_fee_micro_xmr": self.gross_fee_micro_xmr,
            "net_fee_micro_xmr": self.net_fee_micro_xmr,
            "rebate_micro_xmr": self.rebate_micro_xmr,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationLink {
    pub preconfirmation_id: String,
    pub manifest_id: String,
    pub shard_group_root: String,
    pub scheduler_attestation_root: String,
    pub witness_locality_root: String,
    pub receipt_root: String,
    pub delay_slots: u64,
    pub l2_height: u64,
}

impl PreconfirmationLink {
    pub fn public_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "manifest_id": self.manifest_id,
            "shard_group_root": self.shard_group_root,
            "scheduler_attestation_root": self.scheduler_attestation_root,
            "witness_locality_root": self.witness_locality_root,
            "receipt_root": self.receipt_root,
            "delay_slots": self.delay_slots,
            "l2_height": self.l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquiditySettlementLink {
    pub liquidity_settlement_id: String,
    pub manifest_id: String,
    pub amm_batch_root: String,
    pub reserve_update_root: String,
    pub bridge_liquidity_root: String,
    pub slippage_bound_root: String,
    pub defi_state_delta_root: String,
    pub settled_micro_xmr: u64,
}

impl LiquiditySettlementLink {
    pub fn public_record(&self) -> Value {
        json!({
            "liquidity_settlement_id": self.liquidity_settlement_id,
            "manifest_id": self.manifest_id,
            "amm_batch_root": self.amm_batch_root,
            "reserve_update_root": self.reserve_update_root,
            "bridge_liquidity_root": self.bridge_liquidity_root,
            "slippage_bound_root": self.slippage_bound_root,
            "defi_state_delta_root": self.defi_state_delta_root,
            "settled_micro_xmr": self.settled_micro_xmr,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub manifest_id: String,
    pub kind: FenceKind,
    pub nullifier_root: String,
    pub encrypted_witness_root: String,
    pub privacy_set_size: u64,
    pub l2_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "manifest_id": self.manifest_id,
            "kind": self.kind.as_str(),
            "nullifier_root": self.nullifier_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "privacy_set_size": self.privacy_set_size,
            "l2_height": self.l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub slashing_id: String,
    pub manifest_id: String,
    pub reason: SlashReason,
    pub offender_commitment: String,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slash_micro_xmr: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "slashing_id": self.slashing_id,
            "manifest_id": self.manifest_id,
            "reason": self.reason.as_str(),
            "offender_commitment": self.offender_commitment,
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "slash_micro_xmr": self.slash_micro_xmr,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub manifest_root: String,
    pub attestation_root: String,
    pub fee_net_root: String,
    pub preconfirmation_root: String,
    pub liquidity_settlement_root: String,
    pub privacy_fence_root: String,
    pub slashing_root: String,
    pub runtime_membership_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_root": self.manifest_root,
            "attestation_root": self.attestation_root,
            "fee_net_root": self.fee_net_root,
            "preconfirmation_root": self.preconfirmation_root,
            "liquidity_settlement_root": self.liquidity_settlement_root,
            "privacy_fence_root": self.privacy_fence_root,
            "slashing_root": self.slashing_root,
            "runtime_membership_root": self.runtime_membership_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub counters: Counters,
    pub runtime_members: BTreeSet<String>,
    pub manifests: BTreeMap<String, BridgeExecutionManifest>,
    pub attestations: BTreeMap<String, RuntimeAttestation>,
    pub fee_nets: BTreeMap<String, FeeNetSettlement>,
    pub preconfirmations: BTreeMap<String, PreconfirmationLink>,
    pub liquidity_settlements: BTreeMap<String, LiquiditySettlementLink>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            l2_height: DEFAULT_L2_HEIGHT,
            monero_height: DEFAULT_MONERO_HEIGHT,
            counters: Counters::default(),
            runtime_members: BTreeSet::new(),
            manifests: BTreeMap::new(),
            attestations: BTreeMap::new(),
            fee_nets: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            liquidity_settlements: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
        };
        for runtime in [
            MeshRuntimeKind::MoneroBridge,
            MeshRuntimeKind::ContractReceiptIndex,
            MeshRuntimeKind::FeeNetting,
            MeshRuntimeKind::FastPreconfirmation,
            MeshRuntimeKind::DefiLiquidity,
            MeshRuntimeKind::Watchtower,
        ] {
            state.runtime_members.insert(runtime.as_str().to_string());
        }
        let manifest = BridgeExecutionManifest {
            manifest_id: mesh_id("MANIFEST", &["devnet", "bridge-execution", "0"]),
            epoch: state.config.mesh_epoch,
            bridge_output_root: root_from_label("BRIDGE-OUTPUT", "devnet-output-batch"),
            subaddress_claim_root: root_from_label("SUBADDRESS-CLAIM", "devnet-subaddress-claims"),
            execution_receipt_root: root_from_label("EXECUTION-RECEIPT", "devnet-receipts"),
            monero_reserve_root: root_from_label("MONERO-RESERVE", "devnet-reserve"),
            settlement_manifest_root: root_from_label("SETTLEMENT-MANIFEST", "devnet-settlement"),
            participant_root: root_from_label("PARTICIPANTS", "devnet-watchers"),
            amount_micro_xmr: 88_000_000,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            status: SettlementStatus::Draft,
        };
        let manifest_id = manifest.manifest_id.clone();
        let _ = state.insert_manifest(manifest);
        let _ = state.attach_attestation(RuntimeAttestation {
            attestation_id: mesh_id("ATTESTATION", &[&manifest_id, "watchtower", "0"]),
            manifest_id: manifest_id.clone(),
            runtime_kind: MeshRuntimeKind::Watchtower,
            signer_commitment: root_from_label("SIGNER", "devnet-watchtower"),
            pq_key_commitment: root_from_label("PQ-KEY", "devnet-watchtower"),
            attested_root: root_from_label("ATTESTED-ROOT", "devnet-bridge-execution"),
            signature_root: root_from_label("PQ-SIGNATURE", "devnet-watchtower"),
            weight: 3,
            l2_height: state.l2_height,
        });
        let _ = state.attach_fee_net(FeeNetSettlement {
            fee_net_id: mesh_id("FEE-NET", &[&manifest_id, "0"]),
            manifest_id: manifest_id.clone(),
            payer_cohort_root: root_from_label("PAYER-COHORT", "devnet"),
            sponsor_root: root_from_label("SPONSOR", "devnet"),
            rebate_coupon_root: root_from_label("REBATE", "devnet"),
            fee_asset_root: root_from_label("FEE-ASSET", "piconero"),
            gross_fee_micro_xmr: 44_000,
            net_fee_micro_xmr: 31_000,
            rebate_micro_xmr: 13_000,
        });
        let _ = state.attach_preconfirmation(PreconfirmationLink {
            preconfirmation_id: mesh_id("PRECONFIRMATION", &[&manifest_id, "0"]),
            manifest_id: manifest_id.clone(),
            shard_group_root: root_from_label("SHARD-GROUP", "devnet-fast"),
            scheduler_attestation_root: root_from_label("SCHEDULER", "devnet-fast"),
            witness_locality_root: root_from_label("WITNESS-LOCALITY", "devnet-fast"),
            receipt_root: root_from_label("PRECONFIRMATION-RECEIPT", "devnet-fast"),
            delay_slots: 2,
            l2_height: state.l2_height,
        });
        let _ = state.attach_liquidity_settlement(LiquiditySettlementLink {
            liquidity_settlement_id: mesh_id("LIQUIDITY", &[&manifest_id, "0"]),
            manifest_id: manifest_id.clone(),
            amm_batch_root: root_from_label("AMM-BATCH", "devnet"),
            reserve_update_root: root_from_label("RESERVE-UPDATE", "devnet"),
            bridge_liquidity_root: root_from_label("BRIDGE-LIQUIDITY", "devnet"),
            slippage_bound_root: root_from_label("SLIPPAGE", "devnet"),
            defi_state_delta_root: root_from_label("DEFI-DELTA", "devnet"),
            settled_micro_xmr: 87_956_000,
        });
        let _ = state.arm_privacy_fence(PrivacyFence {
            fence_id: mesh_id("FENCE", &[&manifest_id, "bridge-nullifier", "0"]),
            manifest_id,
            kind: FenceKind::BridgeNullifier,
            nullifier_root: root_from_label("NULLIFIER", "devnet"),
            encrypted_witness_root: root_from_label("ENCRYPTED-WITNESS", "devnet"),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            l2_height: state.l2_height,
        });
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(self.l2_height > 0, "l2 height must be positive")?;
        require(self.monero_height > 0, "monero height must be positive")
    }

    pub fn roots(&self) -> Roots {
        Roots {
            manifest_root: record_map_root("MESH-MANIFESTS", &self.manifests),
            attestation_root: record_map_root("MESH-ATTESTATIONS", &self.attestations),
            fee_net_root: record_map_root("MESH-FEE-NETS", &self.fee_nets),
            preconfirmation_root: record_map_root("MESH-PRECONFIRMATIONS", &self.preconfirmations),
            liquidity_settlement_root: record_map_root(
                "MESH-LIQUIDITY-SETTLEMENTS",
                &self.liquidity_settlements,
            ),
            privacy_fence_root: record_map_root("MESH-PRIVACY-FENCES", &self.privacy_fences),
            slashing_root: record_map_root("MESH-SLASHING", &self.slashing_evidence),
            runtime_membership_root: string_set_root("MESH-RUNTIME-MEMBERS", &self.runtime_members),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_cross_runtime_settlement_mesh",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn insert_manifest(&mut self, manifest: BridgeExecutionManifest) -> Result<String> {
        self.validate_manifest(&manifest)?;
        require(
            !self.manifests.contains_key(&manifest.manifest_id),
            "manifest already exists",
        )?;
        self.counters.manifests = self.counters.manifests.saturating_add(1);
        self.manifests
            .insert(manifest.manifest_id.clone(), manifest.clone());
        Ok(manifest.manifest_id)
    }

    pub fn attach_attestation(&mut self, attestation: RuntimeAttestation) -> Result<String> {
        require(
            self.manifests.contains_key(&attestation.manifest_id),
            "attestation references unknown manifest",
        )?;
        require(
            attestation.weight > 0,
            "attestation weight must be positive",
        )?;
        require(
            !self.attestations.contains_key(&attestation.attestation_id),
            "attestation already exists",
        )?;
        self.counters.attestations = self.counters.attestations.saturating_add(1);
        if let Some(manifest) = self.manifests.get_mut(&attestation.manifest_id) {
            if manifest.status == SettlementStatus::Draft && self.counters.attestations >= 1 {
                manifest.status = SettlementStatus::QuorumAttested;
            }
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation.attestation_id)
    }

    pub fn attach_fee_net(&mut self, fee_net: FeeNetSettlement) -> Result<String> {
        require(
            self.manifests.contains_key(&fee_net.manifest_id),
            "fee net references unknown manifest",
        )?;
        require(
            fee_net.net_fee_micro_xmr <= fee_net.gross_fee_micro_xmr,
            "net fee exceeds gross fee",
        )?;
        self.counters.fee_nets = self.counters.fee_nets.saturating_add(1);
        self.counters.rebated_micro_xmr = self
            .counters
            .rebated_micro_xmr
            .saturating_add(fee_net.rebate_micro_xmr);
        self.fee_nets
            .insert(fee_net.fee_net_id.clone(), fee_net.clone());
        Ok(fee_net.fee_net_id)
    }

    pub fn attach_preconfirmation(&mut self, link: PreconfirmationLink) -> Result<String> {
        require(
            self.manifests.contains_key(&link.manifest_id),
            "preconfirmation references unknown manifest",
        )?;
        require(
            link.delay_slots <= self.config.max_preconfirmation_delay_slots,
            "preconfirmation delay exceeds config",
        )?;
        self.counters.preconfirmations = self.counters.preconfirmations.saturating_add(1);
        if let Some(manifest) = self.manifests.get_mut(&link.manifest_id) {
            if manifest.status.open() {
                manifest.status = SettlementStatus::Preconfirmed;
            }
        }
        self.preconfirmations
            .insert(link.preconfirmation_id.clone(), link.clone());
        Ok(link.preconfirmation_id)
    }

    pub fn attach_liquidity_settlement(&mut self, link: LiquiditySettlementLink) -> Result<String> {
        require(
            self.manifests.contains_key(&link.manifest_id),
            "liquidity settlement references unknown manifest",
        )?;
        self.counters.liquidity_settlements = self.counters.liquidity_settlements.saturating_add(1);
        self.counters.settled_micro_xmr = self
            .counters
            .settled_micro_xmr
            .saturating_add(link.settled_micro_xmr);
        if let Some(manifest) = self.manifests.get_mut(&link.manifest_id) {
            if manifest.status.open() {
                manifest.status = SettlementStatus::Netted;
            }
        }
        self.liquidity_settlements
            .insert(link.liquidity_settlement_id.clone(), link.clone());
        Ok(link.liquidity_settlement_id)
    }

    pub fn arm_privacy_fence(&mut self, fence: PrivacyFence) -> Result<String> {
        require(
            self.manifests.contains_key(&fence.manifest_id),
            "privacy fence references unknown manifest",
        )?;
        require(
            fence.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below config",
        )?;
        self.counters.fences = self.counters.fences.saturating_add(1);
        self.privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        Ok(fence.fence_id)
    }

    pub fn settle_manifest(&mut self, manifest_id: &str) -> Result<()> {
        let manifest = self
            .manifests
            .get_mut(manifest_id)
            .ok_or_else(|| "unknown manifest".to_string())?;
        require(
            manifest.status.open(),
            "manifest is not open for settlement",
        )?;
        require(
            self.fee_nets
                .values()
                .any(|fee| fee.manifest_id == manifest_id),
            "manifest missing fee net",
        )?;
        require(
            self.preconfirmations
                .values()
                .any(|preconf| preconf.manifest_id == manifest_id),
            "manifest missing preconfirmation",
        )?;
        require(
            self.liquidity_settlements
                .values()
                .any(|liq| liq.manifest_id == manifest_id),
            "manifest missing liquidity settlement",
        )?;
        manifest.status = SettlementStatus::Settled;
        Ok(())
    }

    pub fn record_slashing(&mut self, evidence: SlashingEvidence) -> Result<String> {
        require(
            self.manifests.contains_key(&evidence.manifest_id),
            "slashing references unknown manifest",
        )?;
        require(
            evidence.slash_micro_xmr > 0,
            "slash amount must be positive",
        )?;
        self.counters.slashes = self.counters.slashes.saturating_add(1);
        if let Some(manifest) = self.manifests.get_mut(&evidence.manifest_id) {
            manifest.status = SettlementStatus::Slashed;
        }
        self.slashing_evidence
            .insert(evidence.slashing_id.clone(), evidence.clone());
        Ok(evidence.slashing_id)
    }

    fn validate_manifest(&self, manifest: &BridgeExecutionManifest) -> Result<()> {
        require(!manifest.manifest_id.is_empty(), "manifest id is empty")?;
        require(manifest.epoch > 0, "manifest epoch must be positive")?;
        require(
            manifest.privacy_set_size >= self.config.min_privacy_set_size,
            "manifest privacy set below config",
        )?;
        require(
            self.manifests.len() < self.config.max_manifests_per_epoch,
            "manifest limit reached",
        )
    }
}

pub fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

pub fn mesh_id(domain: &str, parts: &[&str]) -> String {
    let mut hash_parts = Vec::with_capacity(parts.len() + 2);
    hash_parts.push(HashPart::Str(CHAIN_ID));
    hash_parts.push(HashPart::Str(PROTOCOL_VERSION));
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    domain_hash(domain, &hash_parts, 32)
}

pub fn root_from_label(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn root_from_value(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn record_map_root<T>(domain: &str, values: &BTreeMap<String, T>) -> String
where
    T: Serialize,
{
    let leaves = values
        .iter()
        .map(|(key, value)| {
            let value = serde_json::to_value(value).unwrap_or_else(|_| json!({}));
            json!({ "key": key, "value": value })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_value("MESH-STATE-ROOT", record)
}

pub fn manifest_id(epoch: u64, bridge_output_root: &str, receipt_root: &str) -> String {
    mesh_id(
        "MESH-MANIFEST-ID",
        &[&epoch.to_string(), bridge_output_root, receipt_root],
    )
}

pub fn attestation_id(manifest_id: &str, runtime_kind: MeshRuntimeKind, signer: &str) -> String {
    mesh_id(
        "MESH-ATTESTATION-ID",
        &[manifest_id, runtime_kind.as_str(), signer],
    )
}

pub fn fee_net_id(manifest_id: &str, payer_cohort_root: &str, sponsor_root: &str) -> String {
    mesh_id(
        "MESH-FEE-NET-ID",
        &[manifest_id, payer_cohort_root, sponsor_root],
    )
}

pub fn preconfirmation_id(manifest_id: &str, shard_group_root: &str, receipt_root: &str) -> String {
    mesh_id(
        "MESH-PRECONFIRMATION-ID",
        &[manifest_id, shard_group_root, receipt_root],
    )
}

pub fn liquidity_settlement_id(
    manifest_id: &str,
    amm_batch_root: &str,
    reserve_update_root: &str,
) -> String {
    mesh_id(
        "MESH-LIQUIDITY-SETTLEMENT-ID",
        &[manifest_id, amm_batch_root, reserve_update_root],
    )
}

pub fn privacy_fence_id(manifest_id: &str, kind: FenceKind, nullifier_root: &str) -> String {
    mesh_id(
        "MESH-PRIVACY-FENCE-ID",
        &[manifest_id, kind.as_str(), nullifier_root],
    )
}

pub fn slashing_id(manifest_id: &str, reason: SlashReason, evidence_root: &str) -> String {
    mesh_id(
        "MESH-SLASHING-ID",
        &[manifest_id, reason.as_str(), evidence_root],
    )
}
