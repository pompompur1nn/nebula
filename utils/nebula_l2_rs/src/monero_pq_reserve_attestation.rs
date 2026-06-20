use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPqReserveAttestationResult<T> = Result<T, String>;

pub const MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION: &str =
    "nebula-monero-pq-reserve-attestation-v1";
pub const MONERO_PQ_RESERVE_ATTESTATION_DEVNET_HEIGHT: u64 = 288;
pub const MONERO_PQ_RESERVE_ATTESTATION_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_PQ_RESERVE_ATTESTATION_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PQ_RESERVE_ATTESTATION_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_PQ_RESERVE_ATTESTATION_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const MONERO_PQ_RESERVE_ATTESTATION_VIEW_KEY_COMMITMENT_SCHEME: &str =
    "view-key-hash-commitment-v1";
pub const MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_MIN_WATCHTOWER_WEIGHT: u64 = 3;
pub const MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_MIN_CONFIRMATIONS: u64 = 12;
pub const MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 24;
pub const MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_EXIT_TTL_BLOCKS: u64 = 96;
pub const MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 48;
pub const MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_LOW_FEE_BUDGET_PICONERO: u64 = 500_000_000;
pub const MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_MIN_COVERAGE_BPS: u64 = 10_250;
pub const MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_TARGET_COVERAGE_BPS: u64 = 11_000;
pub const MONERO_PQ_RESERVE_ATTESTATION_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqReserveAttestorRole {
    ReserveOperator,
    Watchtower,
    Auditor,
    Sponsor,
    ExitGuardian,
    EmergencyCouncil,
}

impl PqReserveAttestorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveOperator => "reserve_operator",
            Self::Watchtower => "watchtower",
            Self::Auditor => "auditor",
            Self::Sponsor => "sponsor",
            Self::ExitGuardian => "exit_guardian",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqReserveAttestorStatus {
    Pending,
    Active,
    Jailed,
    Rotating,
    Retired,
}

impl PqReserveAttestorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Jailed => "jailed",
            Self::Rotating => "rotating",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveSnapshotStatus {
    Draft,
    Observed,
    Attested,
    Disputed,
    Finalized,
    Superseded,
}

impl ReserveSnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Observed => "observed",
            Self::Attested => "attested",
            Self::Disputed => "disputed",
            Self::Finalized => "finalized",
            Self::Superseded => "superseded",
        }
    }

    pub fn usable_for_exit(self) -> bool {
        matches!(self, Self::Attested | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerAttestationStatus {
    Submitted,
    Accepted,
    Disputed,
    Slashed,
    Expired,
}

impl WatchtowerAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitCoverageStatus {
    Reserved,
    Covered,
    UnderCovered,
    Challenged,
    Released,
    Expired,
}

impl ExitCoverageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Covered => "covered",
            Self::UnderCovered => "under_covered",
            Self::Challenged => "challenged",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Covered | Self::UnderCovered | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeWindowStatus {
    Open,
    EvidenceSubmitted,
    Accepted,
    Rejected,
    Expired,
    Settled,
}

impl DisputeWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Settled => "settled",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceSubmitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Exhausted,
    Expired,
    Slashed,
}

impl ProofSponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    Config,
    ViewKeyCommitment,
    ReserveSnapshot,
    WatchtowerAttestation,
    ExitCoverage,
    DisputeWindow,
    ProofSponsorship,
    StateRoot,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::ViewKeyCommitment => "view_key_commitment",
            Self::ReserveSnapshot => "reserve_snapshot",
            Self::WatchtowerAttestation => "watchtower_attestation",
            Self::ExitCoverage => "exit_coverage",
            Self::DisputeWindow => "dispute_window",
            Self::ProofSponsorship => "proof_sponsorship",
            Self::StateRoot => "state_root",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqReserveAttestationConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub min_watchtower_weight: u64,
    pub min_confirmations: u64,
    pub dispute_window_blocks: u64,
    pub exit_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub default_low_fee_budget_piconero: u64,
    pub min_exit_coverage_bps: u64,
    pub target_exit_coverage_bps: u64,
    pub pq_signature_scheme: String,
    pub view_key_commitment_scheme: String,
}

impl Default for MoneroPqReserveAttestationConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION.to_string(),
            monero_network: MONERO_PQ_RESERVE_ATTESTATION_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_PQ_RESERVE_ATTESTATION_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_PQ_RESERVE_ATTESTATION_DEVNET_FEE_ASSET_ID.to_string(),
            min_watchtower_weight: MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_MIN_WATCHTOWER_WEIGHT,
            min_confirmations: MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_MIN_CONFIRMATIONS,
            dispute_window_blocks: MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_DISPUTE_WINDOW_BLOCKS,
            exit_ttl_blocks: MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_EXIT_TTL_BLOCKS,
            sponsorship_ttl_blocks: MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            default_low_fee_budget_piconero:
                MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_LOW_FEE_BUDGET_PICONERO,
            min_exit_coverage_bps: MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_MIN_COVERAGE_BPS,
            target_exit_coverage_bps: MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_TARGET_COVERAGE_BPS,
            pq_signature_scheme: MONERO_PQ_RESERVE_ATTESTATION_PQ_SIGNATURE_SCHEME.to_string(),
            view_key_commitment_scheme: MONERO_PQ_RESERVE_ATTESTATION_VIEW_KEY_COMMITMENT_SCHEME
                .to_string(),
        };
        config.config_id = monero_pq_reserve_config_id(&config.identity_record());
        config
    }
}

impl MoneroPqReserveAttestationConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_attestation_config_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "min_watchtower_weight": self.min_watchtower_weight,
            "min_confirmations": self.min_confirmations,
            "dispute_window_blocks": self.dispute_window_blocks,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "default_low_fee_budget_piconero": self.default_low_fee_budget_piconero,
            "min_exit_coverage_bps": self.min_exit_coverage_bps,
            "target_exit_coverage_bps": self.target_exit_coverage_bps,
            "pq_signature_scheme": self.pq_signature_scheme,
            "view_key_commitment_scheme": self.view_key_commitment_scheme,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_attestation_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "config_id": self.config_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "min_watchtower_weight": self.min_watchtower_weight,
            "min_confirmations": self.min_confirmations,
            "dispute_window_blocks": self.dispute_window_blocks,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "default_low_fee_budget_piconero": self.default_low_fee_budget_piconero,
            "min_exit_coverage_bps": self.min_exit_coverage_bps,
            "target_exit_coverage_bps": self.target_exit_coverage_bps,
            "pq_signature_scheme": self.pq_signature_scheme,
            "view_key_commitment_scheme": self.view_key_commitment_scheme,
            "config_root": self.config_root(),
        })
    }

    pub fn config_root(&self) -> String {
        monero_pq_reserve_payload_root(
            "MONERO-PQ-RESERVE-ATTESTATION-CONFIG",
            &self.identity_record(),
        )
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        ensure_non_empty(&self.config_id, "monero pq reserve config id")?;
        ensure_non_empty(&self.protocol_version, "monero pq reserve protocol version")?;
        if self.protocol_version != MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION {
            return Err("monero pq reserve protocol version mismatch".to_string());
        }
        ensure_non_empty(&self.monero_network, "monero pq reserve network")?;
        ensure_non_empty(&self.asset_id, "monero pq reserve asset id")?;
        ensure_non_empty(&self.fee_asset_id, "monero pq reserve fee asset id")?;
        ensure_positive(
            self.min_watchtower_weight,
            "monero pq reserve min watchtower weight",
        )?;
        ensure_positive(
            self.min_confirmations,
            "monero pq reserve min confirmations",
        )?;
        ensure_positive(
            self.dispute_window_blocks,
            "monero pq reserve dispute window",
        )?;
        ensure_positive(self.exit_ttl_blocks, "monero pq reserve exit ttl")?;
        ensure_positive(
            self.sponsorship_ttl_blocks,
            "monero pq reserve sponsorship ttl",
        )?;
        ensure_bps(self.min_exit_coverage_bps, "monero pq reserve min coverage")?;
        ensure_bps(
            self.target_exit_coverage_bps,
            "monero pq reserve target coverage",
        )?;
        if self.target_exit_coverage_bps < self.min_exit_coverage_bps {
            return Err("monero pq reserve target coverage below minimum".to_string());
        }
        ensure_non_empty(
            &self.pq_signature_scheme,
            "monero pq reserve signature scheme",
        )?;
        ensure_non_empty(
            &self.view_key_commitment_scheme,
            "monero pq reserve view key commitment scheme",
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReserveAttestor {
    pub attestor_id: String,
    pub label: String,
    pub role: PqReserveAttestorRole,
    pub signature_scheme: String,
    pub public_key_commitment: String,
    pub weight: u64,
    pub registered_height: u64,
    pub retired_height: u64,
    pub slashing_bond_commitment: String,
    pub status: PqReserveAttestorStatus,
}

impl PqReserveAttestor {
    pub fn new(
        label: &str,
        role: PqReserveAttestorRole,
        signature_scheme: &str,
        public_key_label: &str,
        weight: u64,
        registered_height: u64,
    ) -> MoneroPqReserveAttestationResult<Self> {
        ensure_non_empty(label, "monero pq reserve attestor label")?;
        ensure_non_empty(
            signature_scheme,
            "monero pq reserve attestor signature scheme",
        )?;
        ensure_non_empty(public_key_label, "monero pq reserve attestor public key")?;
        ensure_positive(weight, "monero pq reserve attestor weight")?;
        let public_key_commitment = monero_pq_reserve_string_root(
            "MONERO-PQ-RESERVE-ATTESTOR-PUBLIC-KEY",
            public_key_label,
        );
        let slashing_bond_commitment =
            monero_pq_reserve_string_root("MONERO-PQ-RESERVE-ATTESTOR-BOND", label);
        let identity = json!({
            "label": label,
            "role": role.as_str(),
            "signature_scheme": signature_scheme,
            "public_key_commitment": public_key_commitment,
            "registered_height": registered_height,
        });
        let attestor_id = monero_pq_reserve_attestor_id(&identity);
        Ok(Self {
            attestor_id,
            label: label.to_string(),
            role,
            signature_scheme: signature_scheme.to_string(),
            public_key_commitment,
            weight,
            registered_height,
            retired_height: 0,
            slashing_bond_commitment,
            status: PqReserveAttestorStatus::Active,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.can_attest()
            && height >= self.registered_height
            && (self.retired_height == 0 || height <= self.retired_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_attestor",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "attestor_id": self.attestor_id,
            "label": self.label,
            "role": self.role.as_str(),
            "signature_scheme": self.signature_scheme,
            "public_key_commitment": self.public_key_commitment,
            "weight": self.weight,
            "registered_height": self.registered_height,
            "retired_height": self.retired_height,
            "slashing_bond_commitment": self.slashing_bond_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn attestor_root(&self) -> String {
        monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-ATTESTOR", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        ensure_non_empty(&self.attestor_id, "monero pq reserve attestor id")?;
        ensure_non_empty(&self.label, "monero pq reserve attestor label")?;
        ensure_non_empty(
            &self.signature_scheme,
            "monero pq reserve attestor signature scheme",
        )?;
        ensure_non_empty(
            &self.public_key_commitment,
            "monero pq reserve attestor public key commitment",
        )?;
        ensure_positive(self.weight, "monero pq reserve attestor weight")?;
        if self.retired_height != 0 && self.retired_height < self.registered_height {
            return Err("monero pq reserve attestor retired before registration".to_string());
        }
        Ok(self.attestor_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewKeyCommitment {
    pub commitment_id: String,
    pub wallet_label: String,
    pub operator_commitment: String,
    pub view_key_commitment: String,
    pub address_set_root: String,
    pub scan_policy_root: String,
    pub registered_height: u64,
    pub rotation_nonce: u64,
    pub status: String,
}

impl ViewKeyCommitment {
    pub fn new(
        wallet_label: &str,
        operator_label: &str,
        view_key_label: &str,
        addresses: &[String],
        scan_policy_label: &str,
        registered_height: u64,
        rotation_nonce: u64,
    ) -> MoneroPqReserveAttestationResult<Self> {
        ensure_non_empty(wallet_label, "monero pq reserve wallet label")?;
        ensure_non_empty(operator_label, "monero pq reserve operator label")?;
        ensure_non_empty(view_key_label, "monero pq reserve view key label")?;
        ensure_non_empty(scan_policy_label, "monero pq reserve scan policy")?;
        ensure_string_list(addresses, "monero pq reserve address")?;
        let operator_commitment =
            monero_pq_reserve_string_root("MONERO-PQ-RESERVE-OPERATOR", operator_label);
        let view_key_commitment =
            monero_pq_reserve_string_root("MONERO-PQ-RESERVE-VIEW-KEY", view_key_label);
        let address_set_root =
            monero_pq_reserve_string_set_root("MONERO-PQ-RESERVE-ADDRESS-SET", addresses);
        let scan_policy_root =
            monero_pq_reserve_string_root("MONERO-PQ-RESERVE-SCAN-POLICY", scan_policy_label);
        let identity = json!({
            "wallet_label": wallet_label,
            "operator_commitment": operator_commitment,
            "view_key_commitment": view_key_commitment,
            "address_set_root": address_set_root,
            "registered_height": registered_height,
            "rotation_nonce": rotation_nonce,
        });
        let commitment_id = monero_pq_reserve_view_key_commitment_id(&identity);
        Ok(Self {
            commitment_id,
            wallet_label: wallet_label.to_string(),
            operator_commitment,
            view_key_commitment,
            address_set_root,
            scan_policy_root,
            registered_height,
            rotation_nonce,
            status: "active".to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_view_key_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "wallet_label": self.wallet_label,
            "operator_commitment": self.operator_commitment,
            "view_key_commitment": self.view_key_commitment,
            "address_set_root": self.address_set_root,
            "scan_policy_root": self.scan_policy_root,
            "registered_height": self.registered_height,
            "rotation_nonce": self.rotation_nonce,
            "status": self.status,
        })
    }

    pub fn commitment_root(&self) -> String {
        monero_pq_reserve_payload_root(
            "MONERO-PQ-RESERVE-VIEW-KEY-COMMITMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        ensure_non_empty(&self.commitment_id, "monero pq reserve view key id")?;
        ensure_non_empty(&self.wallet_label, "monero pq reserve wallet label")?;
        ensure_non_empty(
            &self.operator_commitment,
            "monero pq reserve operator commitment",
        )?;
        ensure_non_empty(
            &self.view_key_commitment,
            "monero pq reserve view key commitment",
        )?;
        ensure_non_empty(&self.address_set_root, "monero pq reserve address root")?;
        ensure_non_empty(&self.scan_policy_root, "monero pq reserve scan policy root")?;
        ensure_non_empty(&self.status, "monero pq reserve view key status")?;
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSnapshot {
    pub snapshot_id: String,
    pub view_key_commitment_id: String,
    pub monero_network: String,
    pub monero_height: u64,
    pub block_hash: String,
    pub output_set_root: String,
    pub key_image_absence_root: String,
    pub reserve_amount_piconero: u64,
    pub liability_amount_piconero: u64,
    pub exit_reserved_piconero: u64,
    pub coverage_bps: u64,
    pub observed_l2_height: u64,
    pub status: ReserveSnapshotStatus,
}

impl ReserveSnapshot {
    pub fn new(
        view_key_commitment_id: &str,
        monero_network: &str,
        monero_height: u64,
        block_hash: &str,
        output_labels: &[String],
        key_image_absence_labels: &[String],
        reserve_amount_piconero: u64,
        liability_amount_piconero: u64,
        exit_reserved_piconero: u64,
        observed_l2_height: u64,
    ) -> MoneroPqReserveAttestationResult<Self> {
        ensure_non_empty(
            view_key_commitment_id,
            "monero pq reserve snapshot view key id",
        )?;
        ensure_non_empty(monero_network, "monero pq reserve snapshot network")?;
        ensure_positive(monero_height, "monero pq reserve snapshot monero height")?;
        ensure_non_empty(block_hash, "monero pq reserve snapshot block hash")?;
        ensure_string_list(output_labels, "monero pq reserve output")?;
        let output_set_root =
            monero_pq_reserve_string_set_root("MONERO-PQ-RESERVE-OUTPUT-SET", output_labels);
        let key_image_absence_root = monero_pq_reserve_string_set_root(
            "MONERO-PQ-RESERVE-KEY-IMAGE-ABSENCE",
            key_image_absence_labels,
        );
        let coverage_bps = reserve_coverage_bps(
            reserve_amount_piconero.saturating_sub(exit_reserved_piconero),
            liability_amount_piconero,
        );
        let identity = json!({
            "view_key_commitment_id": view_key_commitment_id,
            "monero_network": monero_network,
            "monero_height": monero_height,
            "block_hash": block_hash,
            "output_set_root": output_set_root,
            "key_image_absence_root": key_image_absence_root,
            "observed_l2_height": observed_l2_height,
        });
        let snapshot_id = monero_pq_reserve_snapshot_id(&identity);
        Ok(Self {
            snapshot_id,
            view_key_commitment_id: view_key_commitment_id.to_string(),
            monero_network: monero_network.to_string(),
            monero_height,
            block_hash: block_hash.to_string(),
            output_set_root,
            key_image_absence_root,
            reserve_amount_piconero,
            liability_amount_piconero,
            exit_reserved_piconero,
            coverage_bps,
            observed_l2_height,
            status: ReserveSnapshotStatus::Observed,
        })
    }

    pub fn available_reserve_piconero(&self) -> u64 {
        self.reserve_amount_piconero
            .saturating_sub(self.exit_reserved_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "view_key_commitment_id": self.view_key_commitment_id,
            "monero_network": self.monero_network,
            "monero_height": self.monero_height,
            "block_hash": self.block_hash,
            "output_set_root": self.output_set_root,
            "key_image_absence_root": self.key_image_absence_root,
            "reserve_amount_piconero": self.reserve_amount_piconero,
            "liability_amount_piconero": self.liability_amount_piconero,
            "exit_reserved_piconero": self.exit_reserved_piconero,
            "available_reserve_piconero": self.available_reserve_piconero(),
            "coverage_bps": self.coverage_bps,
            "observed_l2_height": self.observed_l2_height,
            "status": self.status.as_str(),
        })
    }

    pub fn snapshot_root(&self) -> String {
        monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-SNAPSHOT", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        ensure_non_empty(&self.snapshot_id, "monero pq reserve snapshot id")?;
        ensure_non_empty(
            &self.view_key_commitment_id,
            "monero pq reserve snapshot view key id",
        )?;
        ensure_non_empty(&self.monero_network, "monero pq reserve snapshot network")?;
        ensure_positive(
            self.monero_height,
            "monero pq reserve snapshot monero height",
        )?;
        ensure_non_empty(&self.block_hash, "monero pq reserve snapshot block hash")?;
        ensure_non_empty(&self.output_set_root, "monero pq reserve output root")?;
        ensure_non_empty(
            &self.key_image_absence_root,
            "monero pq reserve key image absence root",
        )?;
        let expected = reserve_coverage_bps(
            self.reserve_amount_piconero
                .saturating_sub(self.exit_reserved_piconero),
            self.liability_amount_piconero,
        );
        if self.coverage_bps != expected {
            return Err("monero pq reserve snapshot coverage mismatch".to_string());
        }
        Ok(self.snapshot_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerAttestation {
    pub attestation_id: String,
    pub attestor_id: String,
    pub snapshot_id: String,
    pub snapshot_root: String,
    pub signature_scheme: String,
    pub signature_root: String,
    pub weight: u64,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: WatchtowerAttestationStatus,
}

impl WatchtowerAttestation {
    pub fn new(
        attestor: &PqReserveAttestor,
        snapshot: &ReserveSnapshot,
        signature_material: &str,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroPqReserveAttestationResult<Self> {
        ensure_non_empty(
            signature_material,
            "monero pq reserve attestation signature",
        )?;
        if expires_at_height < signed_at_height {
            return Err("monero pq reserve attestation expires before signature".to_string());
        }
        let snapshot_root = snapshot.snapshot_root();
        let signature_root = monero_pq_reserve_signature_root(
            &attestor.attestor_id,
            PublicRecordKind::ReserveSnapshot.as_str(),
            &snapshot.snapshot_id,
            &snapshot_root,
            signature_material,
        );
        let identity = json!({
            "attestor_id": attestor.attestor_id,
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_root": snapshot_root,
            "signature_root": signature_root,
            "signed_at_height": signed_at_height,
        });
        let attestation_id = monero_pq_reserve_watchtower_attestation_id(&identity);
        Ok(Self {
            attestation_id,
            attestor_id: attestor.attestor_id.clone(),
            snapshot_id: snapshot.snapshot_id.clone(),
            snapshot_root,
            signature_scheme: attestor.signature_scheme.clone(),
            signature_root,
            weight: attestor.weight,
            signed_at_height,
            expires_at_height,
            status: WatchtowerAttestationStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_watchtower_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "attestor_id": self.attestor_id,
            "snapshot_id": self.snapshot_id,
            "snapshot_root": self.snapshot_root,
            "signature_scheme": self.signature_scheme,
            "signature_root": self.signature_root,
            "weight": self.weight,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        monero_pq_reserve_payload_root(
            "MONERO-PQ-RESERVE-WATCHTOWER-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        ensure_non_empty(&self.attestation_id, "monero pq reserve attestation id")?;
        ensure_non_empty(&self.attestor_id, "monero pq reserve attestor id")?;
        ensure_non_empty(&self.snapshot_id, "monero pq reserve attested snapshot id")?;
        ensure_non_empty(
            &self.snapshot_root,
            "monero pq reserve attested snapshot root",
        )?;
        ensure_non_empty(&self.signature_scheme, "monero pq reserve signature scheme")?;
        ensure_non_empty(&self.signature_root, "monero pq reserve signature root")?;
        ensure_positive(self.weight, "monero pq reserve attestation weight")?;
        if self.expires_at_height < self.signed_at_height {
            return Err("monero pq reserve attestation expiration is invalid".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitCoverage {
    pub coverage_id: String,
    pub exit_id: String,
    pub snapshot_id: String,
    pub exit_amount_piconero: u64,
    pub reserved_piconero: u64,
    pub coverage_bps: u64,
    pub opened_height: u64,
    pub expires_at_height: u64,
    pub sponsor_id: Option<String>,
    pub status: ExitCoverageStatus,
}

impl ExitCoverage {
    pub fn new(
        exit_id: &str,
        snapshot_id: &str,
        exit_amount_piconero: u64,
        reserved_piconero: u64,
        opened_height: u64,
        expires_at_height: u64,
        sponsor_id: Option<String>,
    ) -> MoneroPqReserveAttestationResult<Self> {
        ensure_non_empty(exit_id, "monero pq reserve exit id")?;
        ensure_non_empty(snapshot_id, "monero pq reserve exit snapshot id")?;
        ensure_positive(exit_amount_piconero, "monero pq reserve exit amount")?;
        ensure_positive(reserved_piconero, "monero pq reserve exit reserve")?;
        if expires_at_height < opened_height {
            return Err("monero pq reserve exit coverage expires before open".to_string());
        }
        let coverage_bps = reserve_coverage_bps(reserved_piconero, exit_amount_piconero);
        let identity = json!({
            "exit_id": exit_id,
            "snapshot_id": snapshot_id,
            "exit_amount_piconero": exit_amount_piconero,
            "reserved_piconero": reserved_piconero,
            "opened_height": opened_height,
        });
        let coverage_id = monero_pq_reserve_exit_coverage_id(&identity);
        Ok(Self {
            coverage_id,
            exit_id: exit_id.to_string(),
            snapshot_id: snapshot_id.to_string(),
            exit_amount_piconero,
            reserved_piconero,
            coverage_bps,
            opened_height,
            expires_at_height,
            sponsor_id,
            status: if coverage_bps >= MONERO_PQ_RESERVE_ATTESTATION_MAX_BPS {
                ExitCoverageStatus::Covered
            } else {
                ExitCoverageStatus::UnderCovered
            },
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_exit_coverage",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "coverage_id": self.coverage_id,
            "exit_id": self.exit_id,
            "snapshot_id": self.snapshot_id,
            "exit_amount_piconero": self.exit_amount_piconero,
            "reserved_piconero": self.reserved_piconero,
            "coverage_bps": self.coverage_bps,
            "opened_height": self.opened_height,
            "expires_at_height": self.expires_at_height,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
        })
    }

    pub fn coverage_root(&self) -> String {
        monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-EXIT-COVERAGE", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        ensure_non_empty(&self.coverage_id, "monero pq reserve exit coverage id")?;
        ensure_non_empty(&self.exit_id, "monero pq reserve exit id")?;
        ensure_non_empty(&self.snapshot_id, "monero pq reserve exit snapshot id")?;
        ensure_positive(self.exit_amount_piconero, "monero pq reserve exit amount")?;
        ensure_positive(self.reserved_piconero, "monero pq reserve reserved amount")?;
        if self.expires_at_height < self.opened_height {
            return Err("monero pq reserve exit coverage window is invalid".to_string());
        }
        if self.coverage_bps
            != reserve_coverage_bps(self.reserved_piconero, self.exit_amount_piconero)
        {
            return Err("monero pq reserve exit coverage bps mismatch".to_string());
        }
        Ok(self.coverage_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeWindow {
    pub dispute_id: String,
    pub subject_kind: PublicRecordKind,
    pub subject_id: String,
    pub subject_root: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_height: u64,
    pub closes_at_height: u64,
    pub status: DisputeWindowStatus,
}

impl DisputeWindow {
    pub fn new(
        subject_kind: PublicRecordKind,
        subject_id: &str,
        subject_root: &str,
        challenger_label: &str,
        evidence_label: &str,
        opened_height: u64,
        closes_at_height: u64,
    ) -> MoneroPqReserveAttestationResult<Self> {
        ensure_non_empty(subject_id, "monero pq reserve dispute subject id")?;
        ensure_non_empty(subject_root, "monero pq reserve dispute subject root")?;
        ensure_non_empty(challenger_label, "monero pq reserve dispute challenger")?;
        ensure_non_empty(evidence_label, "monero pq reserve dispute evidence")?;
        if closes_at_height < opened_height {
            return Err("monero pq reserve dispute closes before open".to_string());
        }
        let challenger_commitment =
            monero_pq_reserve_string_root("MONERO-PQ-RESERVE-DISPUTE-CHALLENGER", challenger_label);
        let evidence_root =
            monero_pq_reserve_string_root("MONERO-PQ-RESERVE-DISPUTE-EVIDENCE", evidence_label);
        let identity = json!({
            "subject_kind": subject_kind.as_str(),
            "subject_id": subject_id,
            "subject_root": subject_root,
            "challenger_commitment": challenger_commitment,
            "evidence_root": evidence_root,
            "opened_height": opened_height,
        });
        let dispute_id = monero_pq_reserve_dispute_window_id(&identity);
        Ok(Self {
            dispute_id,
            subject_kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            challenger_commitment,
            evidence_root,
            opened_height,
            closes_at_height,
            status: DisputeWindowStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_dispute_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "dispute_id": self.dispute_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "closes_at_height": self.closes_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn dispute_root(&self) -> String {
        monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-DISPUTE-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        ensure_non_empty(&self.dispute_id, "monero pq reserve dispute id")?;
        ensure_non_empty(&self.subject_id, "monero pq reserve dispute subject id")?;
        ensure_non_empty(&self.subject_root, "monero pq reserve dispute subject root")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "monero pq reserve dispute challenger",
        )?;
        ensure_non_empty(&self.evidence_root, "monero pq reserve dispute evidence")?;
        if self.closes_at_height < self.opened_height {
            return Err("monero pq reserve dispute window is invalid".to_string());
        }
        Ok(self.dispute_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_piconero: u64,
    pub spent_piconero: u64,
    pub max_fee_per_proof_piconero: u64,
    pub request_root: String,
    pub start_height: u64,
    pub expires_at_height: u64,
    pub status: ProofSponsorshipStatus,
}

impl LowFeeProofSponsorship {
    pub fn new(
        sponsor_label: &str,
        fee_asset_id: &str,
        budget_piconero: u64,
        max_fee_per_proof_piconero: u64,
        request_labels: &[String],
        start_height: u64,
        expires_at_height: u64,
    ) -> MoneroPqReserveAttestationResult<Self> {
        ensure_non_empty(sponsor_label, "monero pq reserve sponsor label")?;
        ensure_non_empty(fee_asset_id, "monero pq reserve sponsorship fee asset")?;
        ensure_positive(budget_piconero, "monero pq reserve sponsorship budget")?;
        ensure_positive(
            max_fee_per_proof_piconero,
            "monero pq reserve sponsorship max fee",
        )?;
        ensure_string_list(request_labels, "monero pq reserve sponsorship request")?;
        if expires_at_height < start_height {
            return Err("monero pq reserve sponsorship expires before start".to_string());
        }
        let sponsor_commitment =
            monero_pq_reserve_string_root("MONERO-PQ-RESERVE-SPONSOR", sponsor_label);
        let request_root = monero_pq_reserve_string_set_root(
            "MONERO-PQ-RESERVE-SPONSORED-REQUESTS",
            request_labels,
        );
        let identity = json!({
            "sponsor_commitment": sponsor_commitment,
            "fee_asset_id": fee_asset_id,
            "budget_piconero": budget_piconero,
            "max_fee_per_proof_piconero": max_fee_per_proof_piconero,
            "request_root": request_root,
            "start_height": start_height,
        });
        let sponsorship_id = monero_pq_reserve_low_fee_sponsorship_id(&identity);
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            budget_piconero,
            spent_piconero: 0,
            max_fee_per_proof_piconero,
            request_root,
            start_height,
            expires_at_height,
            status: ProofSponsorshipStatus::Offered,
        })
    }

    pub fn remaining_piconero(&self) -> u64 {
        self.budget_piconero.saturating_sub(self.spent_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_low_fee_proof_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "budget_piconero": self.budget_piconero,
            "spent_piconero": self.spent_piconero,
            "remaining_piconero": self.remaining_piconero(),
            "max_fee_per_proof_piconero": self.max_fee_per_proof_piconero,
            "request_root": self.request_root,
            "start_height": self.start_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        monero_pq_reserve_payload_root(
            "MONERO-PQ-RESERVE-LOW-FEE-PROOF-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        ensure_non_empty(&self.sponsorship_id, "monero pq reserve sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "monero pq reserve sponsor")?;
        ensure_non_empty(
            &self.fee_asset_id,
            "monero pq reserve sponsorship fee asset",
        )?;
        ensure_positive(self.budget_piconero, "monero pq reserve sponsorship budget")?;
        ensure_positive(
            self.max_fee_per_proof_piconero,
            "monero pq reserve sponsorship max fee",
        )?;
        ensure_non_empty(&self.request_root, "monero pq reserve sponsorship requests")?;
        if self.spent_piconero > self.budget_piconero {
            return Err("monero pq reserve sponsorship overspent".to_string());
        }
        if self.expires_at_height < self.start_height {
            return Err("monero pq reserve sponsorship window is invalid".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqReservePublicRecord {
    pub record_id: String,
    pub kind: PublicRecordKind,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub publisher_commitment: String,
    pub published_height: u64,
}

impl MoneroPqReservePublicRecord {
    pub fn new(
        kind: PublicRecordKind,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
        publisher_label: &str,
        published_height: u64,
    ) -> MoneroPqReserveAttestationResult<Self> {
        ensure_non_empty(subject_id, "monero pq reserve public record subject id")?;
        ensure_non_empty(subject_root, "monero pq reserve public record subject root")?;
        ensure_non_empty(publisher_label, "monero pq reserve public record publisher")?;
        let payload_root =
            monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-PUBLIC-PAYLOAD", payload);
        let publisher_commitment =
            monero_pq_reserve_string_root("MONERO-PQ-RESERVE-PUBLISHER", publisher_label);
        let identity = json!({
            "kind": kind.as_str(),
            "subject_id": subject_id,
            "subject_root": subject_root,
            "payload_root": payload_root,
            "publisher_commitment": publisher_commitment,
            "published_height": published_height,
        });
        let record_id = monero_pq_reserve_public_record_id(&identity);
        Ok(Self {
            record_id,
            kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_root,
            publisher_commitment,
            published_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "publisher_commitment": self.publisher_commitment,
            "published_height": self.published_height,
        })
    }

    pub fn record_root(&self) -> String {
        monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        ensure_non_empty(&self.record_id, "monero pq reserve public record id")?;
        ensure_non_empty(
            &self.subject_id,
            "monero pq reserve public record subject id",
        )?;
        ensure_non_empty(
            &self.subject_root,
            "monero pq reserve public record subject root",
        )?;
        ensure_non_empty(
            &self.payload_root,
            "monero pq reserve public record payload",
        )?;
        ensure_non_empty(
            &self.publisher_commitment,
            "monero pq reserve public record publisher",
        )?;
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqReserveAttestationRoots {
    pub attestor_root: String,
    pub view_key_commitment_root: String,
    pub reserve_snapshot_root: String,
    pub watchtower_attestation_root: String,
    pub exit_coverage_root: String,
    pub dispute_window_root: String,
    pub low_fee_sponsorship_root: String,
    pub public_record_root: String,
}

impl MoneroPqReserveAttestationRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_attestation_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "attestor_root": self.attestor_root,
            "view_key_commitment_root": self.view_key_commitment_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "exit_coverage_root": self.exit_coverage_root,
            "dispute_window_root": self.dispute_window_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqReserveAttestationCounters {
    pub attestor_count: u64,
    pub active_attestor_count: u64,
    pub view_key_commitment_count: u64,
    pub reserve_snapshot_count: u64,
    pub usable_snapshot_count: u64,
    pub watchtower_attestation_count: u64,
    pub accepted_watchtower_weight: u64,
    pub exit_coverage_count: u64,
    pub open_exit_coverage_count: u64,
    pub dispute_window_count: u64,
    pub open_dispute_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub live_sponsorship_count: u64,
    pub public_record_count: u64,
    pub total_reserve_piconero: u64,
    pub total_liability_piconero: u64,
    pub total_exit_reserved_piconero: u64,
    pub reserve_coverage_bps: u64,
}

impl MoneroPqReserveAttestationCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_attestation_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "attestor_count": self.attestor_count,
            "active_attestor_count": self.active_attestor_count,
            "view_key_commitment_count": self.view_key_commitment_count,
            "reserve_snapshot_count": self.reserve_snapshot_count,
            "usable_snapshot_count": self.usable_snapshot_count,
            "watchtower_attestation_count": self.watchtower_attestation_count,
            "accepted_watchtower_weight": self.accepted_watchtower_weight,
            "exit_coverage_count": self.exit_coverage_count,
            "open_exit_coverage_count": self.open_exit_coverage_count,
            "dispute_window_count": self.dispute_window_count,
            "open_dispute_count": self.open_dispute_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "live_sponsorship_count": self.live_sponsorship_count,
            "public_record_count": self.public_record_count,
            "total_reserve_piconero": self.total_reserve_piconero,
            "total_liability_piconero": self.total_liability_piconero,
            "total_exit_reserved_piconero": self.total_exit_reserved_piconero,
            "reserve_coverage_bps": self.reserve_coverage_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPqReserveAttestationState {
    pub height: u64,
    pub config: MoneroPqReserveAttestationConfig,
    pub attestors: BTreeMap<String, PqReserveAttestor>,
    pub view_key_commitments: BTreeMap<String, ViewKeyCommitment>,
    pub reserve_snapshots: BTreeMap<String, ReserveSnapshot>,
    pub watchtower_attestations: BTreeMap<String, WatchtowerAttestation>,
    pub exit_coverages: BTreeMap<String, ExitCoverage>,
    pub dispute_windows: BTreeMap<String, DisputeWindow>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeProofSponsorship>,
    pub public_records: BTreeMap<String, MoneroPqReservePublicRecord>,
}

impl Default for MoneroPqReserveAttestationState {
    fn default() -> Self {
        Self::new(MoneroPqReserveAttestationConfig::default(), 0)
    }
}

impl MoneroPqReserveAttestationState {
    pub fn new(config: MoneroPqReserveAttestationConfig, height: u64) -> Self {
        Self {
            height,
            config,
            attestors: BTreeMap::new(),
            view_key_commitments: BTreeMap::new(),
            reserve_snapshots: BTreeMap::new(),
            watchtower_attestations: BTreeMap::new(),
            exit_coverages: BTreeMap::new(),
            dispute_windows: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> MoneroPqReserveAttestationResult<Self> {
        let mut state = Self::new(
            MoneroPqReserveAttestationConfig::default(),
            MONERO_PQ_RESERVE_ATTESTATION_DEVNET_HEIGHT,
        );
        let operator = PqReserveAttestor::new(
            "devnet-reserve-operator",
            PqReserveAttestorRole::ReserveOperator,
            MONERO_PQ_RESERVE_ATTESTATION_PQ_SIGNATURE_SCHEME,
            "devnet-reserve-operator-pq-key",
            2,
            1,
        )?;
        let watchtower = PqReserveAttestor::new(
            "devnet-watchtower-a",
            PqReserveAttestorRole::Watchtower,
            MONERO_PQ_RESERVE_ATTESTATION_PQ_SIGNATURE_SCHEME,
            "devnet-watchtower-a-pq-key",
            2,
            1,
        )?;
        let auditor = PqReserveAttestor::new(
            "devnet-auditor-a",
            PqReserveAttestorRole::Auditor,
            MONERO_PQ_RESERVE_ATTESTATION_PQ_SIGNATURE_SCHEME,
            "devnet-auditor-a-pq-key",
            1,
            1,
        )?;
        state.add_attestor(operator.clone())?;
        state.add_attestor(watchtower.clone())?;
        state.add_attestor(auditor.clone())?;

        let addresses = vec![
            "devnet-xmr-reserve-address-a".to_string(),
            "devnet-xmr-reserve-address-b".to_string(),
        ];
        let view_key = ViewKeyCommitment::new(
            "devnet-cold-reserve",
            "devnet-reserve-operator",
            "devnet-view-key-share-root",
            &addresses,
            "scan every devnet block with key-image absence logging",
            12,
            0,
        )?;
        state.add_view_key_commitment(view_key.clone())?;

        let outputs = vec![
            "devnet-output-0001".to_string(),
            "devnet-output-0002".to_string(),
            "devnet-output-0003".to_string(),
        ];
        let absent_key_images = vec![
            "devnet-key-image-absence-0001".to_string(),
            "devnet-key-image-absence-0002".to_string(),
        ];
        let mut snapshot = ReserveSnapshot::new(
            &view_key.commitment_id,
            MONERO_PQ_RESERVE_ATTESTATION_DEVNET_NETWORK,
            1_024,
            "devnet-monero-block-1024",
            &outputs,
            &absent_key_images,
            12_500_000_000_000,
            10_000_000_000_000,
            250_000_000_000,
            state.height,
        )?;
        snapshot.status = ReserveSnapshotStatus::Attested;
        state.add_reserve_snapshot(snapshot.clone())?;

        let attestation = WatchtowerAttestation::new(
            &watchtower,
            &snapshot,
            "devnet-watchtower-a-signature-material",
            state.height,
            state
                .height
                .saturating_add(MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_DISPUTE_WINDOW_BLOCKS),
        )?;
        state.add_watchtower_attestation(attestation)?;

        let sponsorship = LowFeeProofSponsorship::new(
            "devnet-proof-sponsor",
            MONERO_PQ_RESERVE_ATTESTATION_DEVNET_FEE_ASSET_ID,
            MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_LOW_FEE_BUDGET_PICONERO,
            50_000_000,
            &["devnet-reserve-snapshot-proof".to_string()],
            state.height,
            state
                .height
                .saturating_add(MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_SPONSORSHIP_TTL_BLOCKS),
        )?;
        state.add_low_fee_sponsorship(sponsorship.clone())?;

        let exit = ExitCoverage::new(
            "devnet-exit-0001",
            &snapshot.snapshot_id,
            200_000_000_000,
            220_000_000_000,
            state.height,
            state
                .height
                .saturating_add(MONERO_PQ_RESERVE_ATTESTATION_DEFAULT_EXIT_TTL_BLOCKS),
            Some(sponsorship.sponsorship_id),
        )?;
        state.add_exit_coverage(exit)?;

        let record = MoneroPqReservePublicRecord::new(
            PublicRecordKind::StateRoot,
            "devnet-monero-pq-reserve-state",
            &state.state_root(),
            &state.public_record_without_root(),
            "devnet-reserve-operator",
            state.height,
        )?;
        state.add_public_record(record)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn add_attestor(
        &mut self,
        attestor: PqReserveAttestor,
    ) -> MoneroPqReserveAttestationResult<()> {
        attestor.validate()?;
        insert_unique_record(
            &mut self.attestors,
            attestor.attestor_id.clone(),
            attestor,
            "monero pq reserve attestor",
        )
    }

    pub fn add_view_key_commitment(
        &mut self,
        commitment: ViewKeyCommitment,
    ) -> MoneroPqReserveAttestationResult<()> {
        commitment.validate()?;
        insert_unique_record(
            &mut self.view_key_commitments,
            commitment.commitment_id.clone(),
            commitment,
            "monero pq reserve view key commitment",
        )
    }

    pub fn add_reserve_snapshot(
        &mut self,
        snapshot: ReserveSnapshot,
    ) -> MoneroPqReserveAttestationResult<()> {
        snapshot.validate()?;
        if !self
            .view_key_commitments
            .contains_key(&snapshot.view_key_commitment_id)
        {
            return Err("monero pq reserve snapshot references unknown view key".to_string());
        }
        insert_unique_record(
            &mut self.reserve_snapshots,
            snapshot.snapshot_id.clone(),
            snapshot,
            "monero pq reserve snapshot",
        )
    }

    pub fn add_watchtower_attestation(
        &mut self,
        attestation: WatchtowerAttestation,
    ) -> MoneroPqReserveAttestationResult<()> {
        attestation.validate()?;
        if !self.attestors.contains_key(&attestation.attestor_id) {
            return Err("monero pq reserve attestation references unknown attestor".to_string());
        }
        if !self
            .reserve_snapshots
            .contains_key(&attestation.snapshot_id)
        {
            return Err("monero pq reserve attestation references unknown snapshot".to_string());
        }
        insert_unique_record(
            &mut self.watchtower_attestations,
            attestation.attestation_id.clone(),
            attestation,
            "monero pq reserve watchtower attestation",
        )
    }

    pub fn add_exit_coverage(
        &mut self,
        coverage: ExitCoverage,
    ) -> MoneroPqReserveAttestationResult<()> {
        coverage.validate()?;
        if !self.reserve_snapshots.contains_key(&coverage.snapshot_id) {
            return Err("monero pq reserve exit coverage references unknown snapshot".to_string());
        }
        if let Some(sponsor_id) = &coverage.sponsor_id {
            if !self.low_fee_sponsorships.contains_key(sponsor_id) {
                return Err(
                    "monero pq reserve exit coverage references unknown sponsor".to_string()
                );
            }
        }
        insert_unique_record(
            &mut self.exit_coverages,
            coverage.coverage_id.clone(),
            coverage,
            "monero pq reserve exit coverage",
        )
    }

    pub fn add_dispute_window(
        &mut self,
        dispute: DisputeWindow,
    ) -> MoneroPqReserveAttestationResult<()> {
        dispute.validate()?;
        self.ensure_subject_known(dispute.subject_kind, &dispute.subject_id)?;
        insert_unique_record(
            &mut self.dispute_windows,
            dispute.dispute_id.clone(),
            dispute,
            "monero pq reserve dispute",
        )
    }

    pub fn add_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeProofSponsorship,
    ) -> MoneroPqReserveAttestationResult<()> {
        sponsorship.validate()?;
        insert_unique_record(
            &mut self.low_fee_sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship,
            "monero pq reserve sponsorship",
        )
    }

    pub fn add_public_record(
        &mut self,
        record: MoneroPqReservePublicRecord,
    ) -> MoneroPqReserveAttestationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.public_records,
            record.record_id.clone(),
            record,
            "monero pq reserve public record",
        )
    }

    pub fn roots(&self) -> MoneroPqReserveAttestationRoots {
        MoneroPqReserveAttestationRoots {
            attestor_root: monero_pq_reserve_attestor_collection_root(
                &self.attestors.values().cloned().collect::<Vec<_>>(),
            ),
            view_key_commitment_root: monero_pq_reserve_view_key_commitment_collection_root(
                &self
                    .view_key_commitments
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            reserve_snapshot_root: monero_pq_reserve_snapshot_collection_root(
                &self.reserve_snapshots.values().cloned().collect::<Vec<_>>(),
            ),
            watchtower_attestation_root: monero_pq_reserve_watchtower_attestation_collection_root(
                &self
                    .watchtower_attestations
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            exit_coverage_root: monero_pq_reserve_exit_coverage_collection_root(
                &self.exit_coverages.values().cloned().collect::<Vec<_>>(),
            ),
            dispute_window_root: monero_pq_reserve_dispute_window_collection_root(
                &self.dispute_windows.values().cloned().collect::<Vec<_>>(),
            ),
            low_fee_sponsorship_root: monero_pq_reserve_low_fee_sponsorship_collection_root(
                &self
                    .low_fee_sponsorships
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            public_record_root: monero_pq_reserve_public_record_collection_root(
                &self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> MoneroPqReserveAttestationCounters {
        let total_reserve_piconero = self
            .reserve_snapshots
            .values()
            .map(|snapshot| snapshot.reserve_amount_piconero)
            .sum::<u64>();
        let total_liability_piconero = self
            .reserve_snapshots
            .values()
            .map(|snapshot| snapshot.liability_amount_piconero)
            .sum::<u64>();
        let total_exit_reserved_piconero = self
            .reserve_snapshots
            .values()
            .map(|snapshot| snapshot.exit_reserved_piconero)
            .sum::<u64>();
        MoneroPqReserveAttestationCounters {
            attestor_count: self.attestors.len() as u64,
            active_attestor_count: self
                .attestors
                .values()
                .filter(|attestor| attestor.active_at(self.height))
                .count() as u64,
            view_key_commitment_count: self.view_key_commitments.len() as u64,
            reserve_snapshot_count: self.reserve_snapshots.len() as u64,
            usable_snapshot_count: self
                .reserve_snapshots
                .values()
                .filter(|snapshot| snapshot.status.usable_for_exit())
                .count() as u64,
            watchtower_attestation_count: self.watchtower_attestations.len() as u64,
            accepted_watchtower_weight: self
                .watchtower_attestations
                .values()
                .filter(|attestation| attestation.status.counts_for_quorum())
                .map(|attestation| attestation.weight)
                .sum::<u64>(),
            exit_coverage_count: self.exit_coverages.len() as u64,
            open_exit_coverage_count: self
                .exit_coverages
                .values()
                .filter(|coverage| coverage.status.is_open())
                .count() as u64,
            dispute_window_count: self.dispute_windows.len() as u64,
            open_dispute_count: self
                .dispute_windows
                .values()
                .filter(|dispute| dispute.status.is_open())
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            live_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.is_live())
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_reserve_piconero,
            total_liability_piconero,
            total_exit_reserved_piconero,
            reserve_coverage_bps: reserve_coverage_bps(
                total_reserve_piconero.saturating_sub(total_exit_reserved_piconero),
                total_liability_piconero,
            ),
        }
    }

    pub fn state_root(&self) -> String {
        monero_pq_reserve_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_attestation_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn validate(&self) -> MoneroPqReserveAttestationResult<String> {
        self.config.validate()?;
        for attestor in self.attestors.values() {
            attestor.validate()?;
        }
        for commitment in self.view_key_commitments.values() {
            commitment.validate()?;
        }
        for snapshot in self.reserve_snapshots.values() {
            snapshot.validate()?;
            if !self
                .view_key_commitments
                .contains_key(&snapshot.view_key_commitment_id)
            {
                return Err("monero pq reserve snapshot references unknown view key".to_string());
            }
        }
        for attestation in self.watchtower_attestations.values() {
            attestation.validate()?;
            if !self.attestors.contains_key(&attestation.attestor_id) {
                return Err("monero pq reserve attestation references unknown attestor".to_string());
            }
            let snapshot = self
                .reserve_snapshots
                .get(&attestation.snapshot_id)
                .ok_or_else(|| {
                    "monero pq reserve attestation references unknown snapshot".to_string()
                })?;
            if snapshot.snapshot_root() != attestation.snapshot_root {
                return Err("monero pq reserve attestation snapshot root mismatch".to_string());
            }
        }
        for coverage in self.exit_coverages.values() {
            coverage.validate()?;
            if !self.reserve_snapshots.contains_key(&coverage.snapshot_id) {
                return Err(
                    "monero pq reserve exit coverage references unknown snapshot".to_string(),
                );
            }
            if let Some(sponsor_id) = &coverage.sponsor_id {
                if !self.low_fee_sponsorships.contains_key(sponsor_id) {
                    return Err(
                        "monero pq reserve exit coverage references unknown sponsor".to_string()
                    );
                }
            }
        }
        for dispute in self.dispute_windows.values() {
            dispute.validate()?;
            self.ensure_subject_known(dispute.subject_kind, &dispute.subject_id)?;
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        self.validate_watchtower_quorum()?;
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_pq_reserve_attestation_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    fn validate_watchtower_quorum(&self) -> MoneroPqReserveAttestationResult<()> {
        for snapshot in self.reserve_snapshots.values() {
            if !snapshot.status.usable_for_exit() {
                continue;
            }
            let mut seen = BTreeSet::new();
            let mut weight = 0_u64;
            for attestation in self.watchtower_attestations.values() {
                if attestation.snapshot_id != snapshot.snapshot_id
                    || !attestation.status.counts_for_quorum()
                {
                    continue;
                }
                if !seen.insert(attestation.attestor_id.clone()) {
                    return Err("monero pq reserve duplicate watchtower attestation".to_string());
                }
                weight = weight.saturating_add(attestation.weight);
            }
            if weight < self.config.min_watchtower_weight {
                return Err("monero pq reserve watchtower quorum below minimum".to_string());
            }
        }
        Ok(())
    }

    fn ensure_subject_known(
        &self,
        kind: PublicRecordKind,
        subject_id: &str,
    ) -> MoneroPqReserveAttestationResult<()> {
        let exists = match kind {
            PublicRecordKind::Config => self.config.config_id == subject_id,
            PublicRecordKind::ViewKeyCommitment => {
                self.view_key_commitments.contains_key(subject_id)
            }
            PublicRecordKind::ReserveSnapshot => self.reserve_snapshots.contains_key(subject_id),
            PublicRecordKind::WatchtowerAttestation => {
                self.watchtower_attestations.contains_key(subject_id)
            }
            PublicRecordKind::ExitCoverage => self.exit_coverages.contains_key(subject_id),
            PublicRecordKind::DisputeWindow => self.dispute_windows.contains_key(subject_id),
            PublicRecordKind::ProofSponsorship => {
                self.low_fee_sponsorships.contains_key(subject_id)
            }
            PublicRecordKind::StateRoot => subject_id == self.state_root(),
        };
        if exists {
            Ok(())
        } else {
            Err("monero pq reserve subject is unknown".to_string())
        }
    }
}

pub fn monero_pq_reserve_state_root_from_record(record: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-ATTESTATION-STATE", record)
}

pub fn monero_pq_reserve_config_id(payload: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-CONFIG-ID", payload)
}

pub fn monero_pq_reserve_attestor_id(payload: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-ATTESTOR-ID", payload)
}

pub fn monero_pq_reserve_view_key_commitment_id(payload: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-VIEW-KEY-COMMITMENT-ID", payload)
}

pub fn monero_pq_reserve_snapshot_id(payload: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-SNAPSHOT-ID", payload)
}

pub fn monero_pq_reserve_watchtower_attestation_id(payload: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-WATCHTOWER-ATTESTATION-ID", payload)
}

pub fn monero_pq_reserve_exit_coverage_id(payload: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-EXIT-COVERAGE-ID", payload)
}

pub fn monero_pq_reserve_dispute_window_id(payload: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-DISPUTE-WINDOW-ID", payload)
}

pub fn monero_pq_reserve_low_fee_sponsorship_id(payload: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-LOW-FEE-SPONSORSHIP-ID", payload)
}

pub fn monero_pq_reserve_public_record_id(payload: &Value) -> String {
    monero_pq_reserve_payload_root("MONERO-PQ-RESERVE-PUBLIC-RECORD-ID", payload)
}

pub fn monero_pq_reserve_signature_root(
    attestor_id: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    signature_material: &str,
) -> String {
    domain_hash(
        "MONERO-PQ-RESERVE-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION),
            HashPart::Str(attestor_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signature_material),
        ],
        32,
    )
}

pub fn monero_pq_reserve_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_pq_reserve_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_PQ_RESERVE_ATTESTATION_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_pq_reserve_string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

pub fn monero_pq_reserve_attestor_collection_root(records: &[PqReserveAttestor]) -> String {
    keyed_value_root(
        "MONERO-PQ-RESERVE-ATTESTOR-COLLECTION",
        records
            .iter()
            .map(|record| (record.attestor_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_pq_reserve_view_key_commitment_collection_root(
    records: &[ViewKeyCommitment],
) -> String {
    keyed_value_root(
        "MONERO-PQ-RESERVE-VIEW-KEY-COMMITMENT-COLLECTION",
        records
            .iter()
            .map(|record| (record.commitment_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_pq_reserve_snapshot_collection_root(records: &[ReserveSnapshot]) -> String {
    keyed_value_root(
        "MONERO-PQ-RESERVE-SNAPSHOT-COLLECTION",
        records
            .iter()
            .map(|record| (record.snapshot_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_pq_reserve_watchtower_attestation_collection_root(
    records: &[WatchtowerAttestation],
) -> String {
    keyed_value_root(
        "MONERO-PQ-RESERVE-WATCHTOWER-ATTESTATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.attestation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_pq_reserve_exit_coverage_collection_root(records: &[ExitCoverage]) -> String {
    keyed_value_root(
        "MONERO-PQ-RESERVE-EXIT-COVERAGE-COLLECTION",
        records
            .iter()
            .map(|record| (record.coverage_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_pq_reserve_dispute_window_collection_root(records: &[DisputeWindow]) -> String {
    keyed_value_root(
        "MONERO-PQ-RESERVE-DISPUTE-WINDOW-COLLECTION",
        records
            .iter()
            .map(|record| (record.dispute_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_pq_reserve_low_fee_sponsorship_collection_root(
    records: &[LowFeeProofSponsorship],
) -> String {
    keyed_value_root(
        "MONERO-PQ-RESERVE-LOW-FEE-SPONSORSHIP-COLLECTION",
        records
            .iter()
            .map(|record| (record.sponsorship_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_pq_reserve_public_record_collection_root(
    records: &[MoneroPqReservePublicRecord],
) -> String {
    keyed_value_root(
        "MONERO-PQ-RESERVE-PUBLIC-RECORD-COLLECTION",
        records
            .iter()
            .map(|record| (record.record_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn reserve_coverage_bps(reserve_units: u64, liability_units: u64) -> u64 {
    if liability_units == 0 {
        return MONERO_PQ_RESERVE_ATTESTATION_MAX_BPS;
    }
    let result = (reserve_units as u128)
        .saturating_mul(MONERO_PQ_RESERVE_ATTESTATION_MAX_BPS as u128)
        / liability_units as u128;
    result
        .min(MONERO_PQ_RESERVE_ATTESTATION_MAX_BPS as u128)
        .min(u64::MAX as u128) as u64
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, record)| json!({ "key": key, "record": record }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroPqReserveAttestationResult<()> {
    if records.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroPqReserveAttestationResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroPqReserveAttestationResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroPqReserveAttestationResult<()> {
    if value > MONERO_PQ_RESERVE_ATTESTATION_MAX_BPS.saturating_mul(2) {
        Err(format!("{label} is outside supported bps range"))
    } else {
        Ok(())
    }
}

fn ensure_string_list(values: &[String], label: &str) -> MoneroPqReserveAttestationResult<()> {
    if values.is_empty() {
        return Err(format!("{label} list is required"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} list contains duplicates"));
        }
    }
    Ok(())
}
