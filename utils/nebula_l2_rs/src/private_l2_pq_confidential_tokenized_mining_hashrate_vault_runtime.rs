use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialTokenizedMiningHashrateVaultRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialTokenizedMiningHashrateVaultRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINING_HASHRATE_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-mining-hashrate-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINING_HASHRATE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINING_HASHRATE_VAULT_RUNTIME_SCHEMA_VERSION: u64 =
    1;
pub const SCHEMA_VERSION: u64 =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINING_HASHRATE_VAULT_RUNTIME_SCHEMA_VERSION;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-tokenized-mining-hashrate-vault-v1";
pub const PRIVACY_SCHEME: &str =
    "monero-viewtag-stealth-address-nullifier-fence-confidential-hashrate-vault-v1";
pub const CONTRACT_SCHEME: &str =
    "pq-private-smart-contract-tokenized-mining-hashrate-vault-covenant-v1";
pub const ORACLE_SCHEME: &str = "pq-threshold-mining-hashrate-attestation-v1";
pub const LOW_FEE_SCHEME: &str = "recursive-proof-low-fee-hashrate-redemption-rebate-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-pq-confidential-tokenized-mining-hashrate-vault-public-record-v1";

pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_880_000;
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_PAYOUT_ASSET_ID: &str = "asset:xmr-mining-payout-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 18;
pub const DEFAULT_ORACLE_QUORUM: u16 = 7;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 4;
pub const DEFAULT_REDEMPTION_REBATE_BPS: u64 = 6;
pub const DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS: u64 = 1_250;
pub const DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 36;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiningAlgorithm {
    RandomX,
    Sha256,
    Scrypt,
    Blake3Merged,
}

impl MiningAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RandomX => "random_x",
            Self::Sha256 => "sha256",
            Self::Scrypt => "scrypt",
            Self::Blake3Merged => "blake3_merged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Active,
    SubscriptionOnly,
    RedemptionOnly,
    PayoutOnly,
    LiquidityGated,
    Paused,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::SubscriptionOnly => "subscription_only",
            Self::RedemptionOnly => "redemption_only",
            Self::PayoutOnly => "payout_only",
            Self::LiquidityGated => "liquidity_gated",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_subscriptions(self) -> bool {
        matches!(self, Self::Active | Self::SubscriptionOnly)
    }

    pub fn accepts_redemptions(self) -> bool {
        matches!(self, Self::Active | Self::RedemptionOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareClassKind {
    BaseHashrate,
    BoostedHashrate,
    PayoutPriority,
    LiquidityProvider,
    OperatorReserve,
}

impl ShareClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseHashrate => "base_hashrate",
            Self::BoostedHashrate => "boosted_hashrate",
            Self::PayoutPriority => "payout_priority",
            Self::LiquidityProvider => "liquidity_provider",
            Self::OperatorReserve => "operator_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStatus {
    Pending,
    Accepted,
    Netted,
    Settled,
    Rebated,
    Rejected,
    Cancelled,
}

impl FlowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Proposed,
    QuorumAccepted,
    Challenged,
    Stale,
}

impl OracleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::QuorumAccepted => "quorum_accepted",
            Self::Challenged => "challenged",
            Self::Stale => "stale",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub payout_asset_id: String,
    pub pq_auth_suite: String,
    pub privacy_scheme: String,
    pub contract_scheme: String,
    pub oracle_scheme: String,
    pub low_fee_scheme: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub epoch_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub oracle_quorum: u16,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub redemption_rebate_bps: u64,
    pub min_liquidity_coverage_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub operator_view_redaction: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            payout_asset_id: DEVNET_PAYOUT_ASSET_ID.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            privacy_scheme: PRIVACY_SCHEME.to_string(),
            contract_scheme: CONTRACT_SCHEME.to_string(),
            oracle_scheme: ORACLE_SCHEME.to_string(),
            low_fee_scheme: LOW_FEE_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            redemption_rebate_bps: DEFAULT_REDEMPTION_REBATE_BPS,
            min_liquidity_coverage_bps: DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS,
            max_oracle_staleness_blocks: DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            operator_view_redaction: "operator-safe-roots-only-no-subscriber-pii".to_string(),
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub share_classes: u64,
    pub confidential_subscriptions: u64,
    pub epoch_receipts: u64,
    pub payout_commitments: u64,
    pub oracle_attestations: u64,
    pub liquidity_gates: u64,
    pub redemption_rebates: u64,
    pub public_events: u64,
    pub accepted_flows: u64,
    pub rejected_flows: u64,
    pub total_committed_hashrate_th: u64,
    pub total_minted_shares: u64,
    pub total_payout_commitments: u64,
    pub total_rebate_amount: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub share_class_root: String,
    pub subscription_root: String,
    pub epoch_receipt_root: String,
    pub payout_commitment_root: String,
    pub oracle_attestation_root: String,
    pub liquidity_gate_root: String,
    pub redemption_rebate_root: String,
    pub nullifier_root: String,
    pub public_event_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = merkle_root("MINING-HASHRATE-VAULT-EMPTY", &[]);
        Self {
            config_root: empty.clone(),
            vault_root: empty.clone(),
            share_class_root: empty.clone(),
            subscription_root: empty.clone(),
            epoch_receipt_root: empty.clone(),
            payout_commitment_root: empty.clone(),
            oracle_attestation_root: empty.clone(),
            liquidity_gate_root: empty.clone(),
            redemption_rebate_root: empty.clone(),
            nullifier_root: empty.clone(),
            public_event_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultRecord {
    pub vault_id: String,
    pub operator_commitment: String,
    pub facility_commitment_root: String,
    pub payout_address_commitment: String,
    pub algorithm: MiningAlgorithm,
    pub status: VaultStatus,
    pub target_hashrate_th: u64,
    pub committed_hashrate_th: u64,
    pub liquidity_buffer_bps: u64,
    pub policy_root: String,
    pub metadata_root: String,
    pub created_at_height: u64,
}

impl VaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "operator_commitment": self.operator_commitment,
            "facility_commitment_root": self.facility_commitment_root,
            "payout_address_commitment": self.payout_address_commitment,
            "algorithm": self.algorithm.as_str(),
            "status": self.status.as_str(),
            "target_hashrate_th": self.target_hashrate_th,
            "committed_hashrate_th": self.committed_hashrate_th,
            "liquidity_buffer_bps": self.liquidity_buffer_bps,
            "policy_root": self.policy_root,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShareClassRecord {
    pub share_class_id: String,
    pub vault_id: String,
    pub symbol: String,
    pub kind: ShareClassKind,
    pub share_asset_id: String,
    pub hashrate_per_share_th: u64,
    pub supply_cap: u64,
    pub minted_supply: u64,
    pub burned_supply: u64,
    pub transfer_restricted: bool,
    pub metadata_root: String,
}

impl ShareClassRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "share_class_id": self.share_class_id,
            "vault_id": self.vault_id,
            "symbol": self.symbol,
            "kind": self.kind.as_str(),
            "share_asset_id": self.share_asset_id,
            "hashrate_per_share_th": self.hashrate_per_share_th,
            "supply_cap": self.supply_cap,
            "minted_supply": self.minted_supply,
            "burned_supply": self.burned_supply,
            "transfer_restricted": self.transfer_restricted,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialSubscriptionRecord {
    pub subscription_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub subscriber_note_commitment: String,
    pub amount_commitment: String,
    pub minted_share_commitment: String,
    pub nullifier: String,
    pub status: FlowStatus,
    pub fee_commitment: String,
    pub accepted_at_height: u64,
}

impl ConfidentialSubscriptionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "subscription_id": self.subscription_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "subscriber_note_commitment": self.subscriber_note_commitment,
            "amount_commitment": self.amount_commitment,
            "minted_share_commitment": self.minted_share_commitment,
            "nullifier": self.nullifier,
            "status": self.status.as_str(),
            "fee_commitment": self.fee_commitment,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EpochHashrateReceiptRecord {
    pub receipt_id: String,
    pub vault_id: String,
    pub epoch: u64,
    pub observed_hashrate_th: u64,
    pub uptime_bps: u64,
    pub share_accounting_root: String,
    pub pool_nonce_root: String,
    pub receipt_commitment: String,
    pub finalized_at_height: u64,
}

impl EpochHashrateReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PayoutCommitmentRecord {
    pub payout_id: String,
    pub vault_id: String,
    pub epoch: u64,
    pub payout_commitment: String,
    pub allocation_root: String,
    pub fee_commitment: String,
    pub rebate_pool_commitment: String,
    pub settled_at_height: u64,
}

impl PayoutCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleHashrateAttestationRecord {
    pub attestation_id: String,
    pub vault_id: String,
    pub epoch: u64,
    pub oracle_committee_root: String,
    pub observed_hashrate_th: u64,
    pub variance_bps: u64,
    pub quorum_weight: u16,
    pub pq_signature_root: String,
    pub status: OracleStatus,
    pub attested_at_height: u64,
}

impl OracleHashrateAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "vault_id": self.vault_id,
            "epoch": self.epoch,
            "oracle_committee_root": self.oracle_committee_root,
            "observed_hashrate_th": self.observed_hashrate_th,
            "variance_bps": self.variance_bps,
            "quorum_weight": self.quorum_weight,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityGateRecord {
    pub gate_id: String,
    pub vault_id: String,
    pub gate_epoch: u64,
    pub coverage_bps: u64,
    pub available_liquidity_commitment: String,
    pub required_liquidity_commitment: String,
    pub open_redemption: bool,
    pub reason_root: String,
}

impl LiquidityGateRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedemptionRebateRecord {
    pub rebate_id: String,
    pub vault_id: String,
    pub redemption_nullifier: String,
    pub recipient_commitment: String,
    pub fee_paid_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub settled_at_height: u64,
}

impl RedemptionRebateRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicEventRecord {
    pub event_id: String,
    pub event_kind: String,
    pub vault_id: String,
    pub subject_root: String,
    pub emitted_at_height: u64,
}

impl PublicEventRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub vaults: BTreeMap<String, VaultRecord>,
    pub share_classes: BTreeMap<String, ShareClassRecord>,
    pub confidential_subscriptions: BTreeMap<String, ConfidentialSubscriptionRecord>,
    pub epoch_receipts: BTreeMap<String, EpochHashrateReceiptRecord>,
    pub payout_commitments: BTreeMap<String, PayoutCommitmentRecord>,
    pub oracle_attestations: BTreeMap<String, OracleHashrateAttestationRecord>,
    pub liquidity_gates: BTreeMap<String, LiquidityGateRecord>,
    pub redemption_rebates: BTreeMap<String, RedemptionRebateRecord>,
    pub public_events: BTreeMap<String, PublicEventRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            height: DEVNET_HEIGHT,
            counters: Counters::default(),
            roots: Roots::default(),
            vaults: BTreeMap::new(),
            share_classes: BTreeMap::new(),
            confidential_subscriptions: BTreeMap::new(),
            epoch_receipts: BTreeMap::new(),
            payout_commitments: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            liquidity_gates: BTreeMap::new(),
            redemption_rebates: BTreeMap::new(),
            public_events: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = record_root("MINING-HASHRATE-VAULT-CONFIG", &self.config);
        self.roots.vault_root = map_root("MINING-HASHRATE-VAULTS", &self.vaults);
        self.roots.share_class_root =
            map_root("MINING-HASHRATE-VAULT-SHARE-CLASSES", &self.share_classes);
        self.roots.subscription_root = map_root(
            "MINING-HASHRATE-VAULT-CONFIDENTIAL-SUBSCRIPTIONS",
            &self.confidential_subscriptions,
        );
        self.roots.epoch_receipt_root =
            map_root("MINING-HASHRATE-VAULT-EPOCH-RECEIPTS", &self.epoch_receipts);
        self.roots.payout_commitment_root = map_root(
            "MINING-HASHRATE-VAULT-PAYOUT-COMMITMENTS",
            &self.payout_commitments,
        );
        self.roots.oracle_attestation_root = map_root(
            "MINING-HASHRATE-VAULT-ORACLE-ATTESTATIONS",
            &self.oracle_attestations,
        );
        self.roots.liquidity_gate_root = map_root(
            "MINING-HASHRATE-VAULT-LIQUIDITY-GATES",
            &self.liquidity_gates,
        );
        self.roots.redemption_rebate_root = map_root(
            "MINING-HASHRATE-VAULT-REDEMPTION-REBATES",
            &self.redemption_rebates,
        );
        self.roots.nullifier_root = set_root(
            "MINING-HASHRATE-VAULT-SPENT-NULLIFIERS",
            &self.spent_nullifiers,
        );
        self.roots.public_event_root =
            map_root("MINING-HASHRATE-VAULT-PUBLIC-EVENTS", &self.public_events);
        self.roots.state_root = self.state_root();
    }

    pub fn roots_without_state_root(&self) -> Value {
        json!({
            "config_root": self.roots.config_root,
            "vault_root": self.roots.vault_root,
            "share_class_root": self.roots.share_class_root,
            "subscription_root": self.roots.subscription_root,
            "epoch_receipt_root": self.roots.epoch_receipt_root,
            "payout_commitment_root": self.roots.payout_commitment_root,
            "oracle_attestation_root": self.roots.oracle_attestation_root,
            "liquidity_gate_root": self.roots.liquidity_gate_root,
            "redemption_rebate_root": self.roots.redemption_rebate_root,
            "nullifier_root": self.roots.nullifier_root,
            "public_event_root": self.roots.public_event_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MINING-HASHRATE-VAULT-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&self.roots_without_state_root()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "active_vaults": self.vaults.values().filter(|vault| vault.status == VaultStatus::Active).count(),
            "open_liquidity_gates": self.liquidity_gates.values().filter(|gate| gate.open_redemption).count(),
            "quorum_oracle_attestations": self.oracle_attestations.values().filter(|attestation| attestation.status == OracleStatus::QuorumAccepted).count(),
        })
    }

    pub fn insert_vault(&mut self, mut record: VaultRecord) -> Result<VaultRecord> {
        if record.target_hashrate_th == 0 {
            return Err("target hashrate must be non-zero".to_string());
        }
        if record.liquidity_buffer_bps > MAX_BPS {
            return Err("liquidity buffer exceeds max bps".to_string());
        }
        record.vault_id = stable_id("vault", self.counters.vaults + 1, &record.public_record());
        self.counters.vaults += 1;
        self.counters.total_committed_hashrate_th += record.committed_hashrate_th;
        self.vaults.insert(record.vault_id.clone(), record.clone());
        self.emit_event(
            "vault_registered",
            &record.vault_id,
            &record.public_record(),
        );
        self.refresh_roots();
        Ok(record)
    }

    pub fn insert_share_class(&mut self, mut record: ShareClassRecord) -> Result<ShareClassRecord> {
        if !self.vaults.contains_key(&record.vault_id) {
            return Err("unknown vault".to_string());
        }
        if record.hashrate_per_share_th == 0 || record.supply_cap == 0 {
            return Err("share class hashrate and supply cap must be non-zero".to_string());
        }
        record.share_class_id = stable_id(
            "share-class",
            self.counters.share_classes + 1,
            &record.public_record(),
        );
        self.counters.share_classes += 1;
        self.counters.total_minted_shares += record.minted_supply;
        self.share_classes
            .insert(record.share_class_id.clone(), record.clone());
        self.emit_event(
            "share_class_defined",
            &record.vault_id,
            &record.public_record(),
        );
        self.refresh_roots();
        Ok(record)
    }

    pub fn insert_subscription(
        &mut self,
        mut record: ConfidentialSubscriptionRecord,
    ) -> Result<ConfidentialSubscriptionRecord> {
        let vault = self
            .vaults
            .get(&record.vault_id)
            .ok_or_else(|| "unknown vault".to_string())?;
        if !vault.status.accepts_subscriptions() {
            return Err("vault is not accepting subscriptions".to_string());
        }
        if !self.share_classes.contains_key(&record.share_class_id) {
            return Err("unknown share class".to_string());
        }
        if !self.spent_nullifiers.insert(record.nullifier.clone()) {
            return Err("subscription nullifier already spent".to_string());
        }
        record.subscription_id = stable_id(
            "subscription",
            self.counters.confidential_subscriptions + 1,
            &record.public_record(),
        );
        self.counters.confidential_subscriptions += 1;
        self.counters.accepted_flows += u64::from(record.status == FlowStatus::Accepted);
        self.counters.rejected_flows += u64::from(record.status == FlowStatus::Rejected);
        self.confidential_subscriptions
            .insert(record.subscription_id.clone(), record.clone());
        self.emit_event(
            "confidential_subscription",
            &record.vault_id,
            &record.public_record(),
        );
        self.refresh_roots();
        Ok(record)
    }

    pub fn insert_epoch_receipt(
        &mut self,
        mut record: EpochHashrateReceiptRecord,
    ) -> Result<EpochHashrateReceiptRecord> {
        if !self.vaults.contains_key(&record.vault_id) {
            return Err("unknown vault".to_string());
        }
        record.receipt_id = stable_id(
            "epoch-receipt",
            self.counters.epoch_receipts + 1,
            &record.public_record(),
        );
        self.counters.epoch_receipts += 1;
        self.epoch_receipts
            .insert(record.receipt_id.clone(), record.clone());
        self.emit_event(
            "epoch_hashrate_receipt",
            &record.vault_id,
            &record.public_record(),
        );
        self.refresh_roots();
        Ok(record)
    }

    pub fn insert_payout_commitment(
        &mut self,
        mut record: PayoutCommitmentRecord,
    ) -> Result<PayoutCommitmentRecord> {
        if !self.vaults.contains_key(&record.vault_id) {
            return Err("unknown vault".to_string());
        }
        record.payout_id = stable_id(
            "payout-commitment",
            self.counters.payout_commitments + 1,
            &record.public_record(),
        );
        self.counters.payout_commitments += 1;
        self.counters.total_payout_commitments += 1;
        self.payout_commitments
            .insert(record.payout_id.clone(), record.clone());
        self.emit_event(
            "payout_commitment",
            &record.vault_id,
            &record.public_record(),
        );
        self.refresh_roots();
        Ok(record)
    }

    pub fn insert_oracle_attestation(
        &mut self,
        mut record: OracleHashrateAttestationRecord,
    ) -> Result<OracleHashrateAttestationRecord> {
        if record.quorum_weight < self.config.oracle_quorum {
            return Err("oracle quorum not met".to_string());
        }
        record.attestation_id = stable_id(
            "oracle-attestation",
            self.counters.oracle_attestations + 1,
            &record.public_record(),
        );
        self.counters.oracle_attestations += 1;
        self.oracle_attestations
            .insert(record.attestation_id.clone(), record.clone());
        self.emit_event(
            "oracle_hashrate_attestation",
            &record.vault_id,
            &record.public_record(),
        );
        self.refresh_roots();
        Ok(record)
    }

    pub fn insert_liquidity_gate(
        &mut self,
        mut record: LiquidityGateRecord,
    ) -> Result<LiquidityGateRecord> {
        if record.coverage_bps > MAX_BPS {
            return Err("liquidity coverage exceeds max bps".to_string());
        }
        record.gate_id = stable_id(
            "liquidity-gate",
            self.counters.liquidity_gates + 1,
            &record.public_record(),
        );
        self.counters.liquidity_gates += 1;
        self.liquidity_gates
            .insert(record.gate_id.clone(), record.clone());
        self.emit_event("liquidity_gate", &record.vault_id, &record.public_record());
        self.refresh_roots();
        Ok(record)
    }

    pub fn insert_redemption_rebate(
        &mut self,
        mut record: RedemptionRebateRecord,
    ) -> Result<RedemptionRebateRecord> {
        if record.rebate_bps > self.config.redemption_rebate_bps {
            return Err("redemption rebate exceeds configured target".to_string());
        }
        record.rebate_id = stable_id(
            "redemption-rebate",
            self.counters.redemption_rebates + 1,
            &record.public_record(),
        );
        self.counters.redemption_rebates += 1;
        self.counters.total_rebate_amount += 1;
        self.redemption_rebates
            .insert(record.rebate_id.clone(), record.clone());
        self.emit_event(
            "redemption_rebate",
            &record.vault_id,
            &record.public_record(),
        );
        self.refresh_roots();
        Ok(record)
    }

    fn emit_event(&mut self, event_kind: &str, vault_id: &str, subject: &Value) {
        let event_id = stable_id(
            "public-event",
            self.counters.public_events + 1,
            &json!({
                "event_kind": event_kind,
                "vault_id": vault_id,
                "subject": subject,
                "height": self.height,
            }),
        );
        let record = PublicEventRecord {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            vault_id: vault_id.to_string(),
            subject_root: record_root("MINING-HASHRATE-VAULT-PUBLIC-EVENT-SUBJECT", subject),
            emitted_at_height: self.height,
        };
        self.counters.public_events += 1;
        self.public_events.insert(event_id, record);
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = devnet();
    state.height = DEVNET_HEIGHT + 12;
    let vault = state
        .insert_vault(VaultRecord {
            vault_id: String::new(),
            operator_commitment: sample_hash("operator-mining-coop"),
            facility_commitment_root: sample_hash("randomx-facility-cluster"),
            payout_address_commitment: sample_hash("stealth-payout-address"),
            algorithm: MiningAlgorithm::RandomX,
            status: VaultStatus::Active,
            target_hashrate_th: 96_000,
            committed_hashrate_th: 84_500,
            liquidity_buffer_bps: 1_600,
            policy_root: sample_hash("hashrate-vault-policy"),
            metadata_root: sample_hash("hashrate-vault-metadata"),
            created_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("demo vault");
    let share_class = state
        .insert_share_class(ShareClassRecord {
            share_class_id: String::new(),
            vault_id: vault.vault_id.clone(),
            symbol: "dHRXMR-BASE".to_string(),
            kind: ShareClassKind::BaseHashrate,
            share_asset_id: "asset:dhrxmr-base-devnet".to_string(),
            hashrate_per_share_th: 10,
            supply_cap: 9_600,
            minted_supply: 4_800,
            burned_supply: 0,
            transfer_restricted: true,
            metadata_root: sample_hash("base-share-metadata"),
        })
        .expect("demo share class");
    state
        .insert_subscription(ConfidentialSubscriptionRecord {
            subscription_id: String::new(),
            vault_id: vault.vault_id.clone(),
            share_class_id: share_class.share_class_id.clone(),
            subscriber_note_commitment: sample_hash("subscriber-note"),
            amount_commitment: sample_hash("subscription-amount-480-shares"),
            minted_share_commitment: sample_hash("minted-share-commitment"),
            nullifier: sample_hash("subscription-nullifier"),
            status: FlowStatus::Accepted,
            fee_commitment: sample_hash("subscription-fee"),
            accepted_at_height: DEVNET_HEIGHT + 3,
        })
        .expect("demo subscription");
    state
        .insert_oracle_attestation(OracleHashrateAttestationRecord {
            attestation_id: String::new(),
            vault_id: vault.vault_id.clone(),
            epoch: 42,
            oracle_committee_root: sample_hash("oracle-committee"),
            observed_hashrate_th: 83_910,
            variance_bps: 70,
            quorum_weight: DEFAULT_ORACLE_QUORUM,
            pq_signature_root: sample_hash("oracle-pq-signatures"),
            status: OracleStatus::QuorumAccepted,
            attested_at_height: DEVNET_HEIGHT + 8,
        })
        .expect("demo oracle attestation");
    state
        .insert_epoch_receipt(EpochHashrateReceiptRecord {
            receipt_id: String::new(),
            vault_id: vault.vault_id.clone(),
            epoch: 42,
            observed_hashrate_th: 83_910,
            uptime_bps: 9_980,
            share_accounting_root: sample_hash("epoch-share-accounting"),
            pool_nonce_root: sample_hash("pool-nonce-root"),
            receipt_commitment: sample_hash("epoch-receipt-commitment"),
            finalized_at_height: DEVNET_HEIGHT + 9,
        })
        .expect("demo epoch receipt");
    state
        .insert_payout_commitment(PayoutCommitmentRecord {
            payout_id: String::new(),
            vault_id: vault.vault_id.clone(),
            epoch: 42,
            payout_commitment: sample_hash("xmr-payout-commitment"),
            allocation_root: sample_hash("payout-allocation-root"),
            fee_commitment: sample_hash("payout-fee"),
            rebate_pool_commitment: sample_hash("rebate-pool"),
            settled_at_height: DEVNET_HEIGHT + 10,
        })
        .expect("demo payout");
    state
        .insert_liquidity_gate(LiquidityGateRecord {
            gate_id: String::new(),
            vault_id: vault.vault_id.clone(),
            gate_epoch: 42,
            coverage_bps: 1_880,
            available_liquidity_commitment: sample_hash("available-liquidity"),
            required_liquidity_commitment: sample_hash("required-liquidity"),
            open_redemption: true,
            reason_root: sample_hash("liquidity-gate-open"),
        })
        .expect("demo liquidity gate");
    state
        .insert_redemption_rebate(RedemptionRebateRecord {
            rebate_id: String::new(),
            vault_id: vault.vault_id,
            redemption_nullifier: sample_hash("redemption-nullifier"),
            recipient_commitment: sample_hash("rebate-recipient"),
            fee_paid_commitment: sample_hash("redemption-fee-paid"),
            rebate_commitment: sample_hash("redemption-rebate"),
            rebate_bps: DEFAULT_REDEMPTION_REBATE_BPS,
            settled_at_height: DEVNET_HEIGHT + 11,
        })
        .expect("demo redemption rebate");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_pq_confidential_tokenized_mining_hashrate_vault_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn private_l2_pq_confidential_tokenized_mining_hashrate_vault_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn deterministic_root(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("private_l2_pq_confidential_tokenized_mining_hashrate_vault_runtime:{domain}"),
        parts,
        32,
    )
}

pub fn root_from_record<T: Serialize>(domain: &str, value: &T) -> String {
    let value = serde_json::to_value(value).expect("serializable record");
    deterministic_root(domain, &[HashPart::Json(&value)])
}

pub fn record_root<T: Serialize>(domain: &str, value: &T) -> String {
    root_from_record(domain, value)
}

pub fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value_root": record_root("MINING-HASHRATE-VAULT-MAP-ENTRY", value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn stable_id(domain: &str, sequence: u64, record: &Value) -> String {
    deterministic_root(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
    )
}

pub fn sample_hash(label: &str) -> String {
    deterministic_root("demo-fixture", &[HashPart::Str(label)])
}
