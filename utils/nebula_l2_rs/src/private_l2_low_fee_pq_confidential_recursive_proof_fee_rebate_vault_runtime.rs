use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialRecursiveProofFeeRebateVaultRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialRecursiveProofFeeRebateVaultRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_RECURSIVE_PROOF_FEE_REBATE_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-recursive-proof-fee-rebate-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_RECURSIVE_PROOF_FEE_REBATE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LOW_FEE_SCHEME: &str =
    "private-l2-low-fee-confidential-recursive-proof-fee-rebate-vault-v1";
pub const PQ_SPONSOR_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-recursive-proof-sponsor-v1";
pub const PRIVACY_REDACTION_SCHEME: &str =
    "roots-only-redacted-recursive-proof-rebate-vault-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_REBATE_ASSET_ID: &str = "asset:recursive-proof-rebate-credit";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 3;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_600;
pub const DEFAULT_REBATE_BPS: u64 = 7;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_LOT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 16;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET: u64 = 64;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Attested,
    Active,
    Paused,
    Draining,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Pending,
    Attested,
    Open,
    Paused,
    Exhausted,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeClassKind {
    RecursiveTransfer,
    RecursiveContract,
    RecursiveBridgeExit,
    RecursiveStateDiff,
    RecursiveAggregation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LotStatus {
    Sealed,
    PartiallyRedeemed,
    Redeemed,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Allow,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    SponsorPool,
    FeeClass,
    SealedLot,
    Attestation,
    Receipt,
    RouteCap,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub low_fee_scheme: String,
    pub pq_sponsor_attestation_suite: String,
    pub privacy_redaction_scheme: String,
    pub min_pq_security_bits: u16,
    pub low_fee_target_bps: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub route_ttl_blocks: u64,
    pub lot_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub default_privacy_redaction_budget: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            low_fee_scheme: LOW_FEE_SCHEME.to_string(),
            pq_sponsor_attestation_suite: PQ_SPONSOR_ATTESTATION_SUITE.to_string(),
            privacy_redaction_scheme: PRIVACY_REDACTION_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            lot_ttl_blocks: DEFAULT_LOT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            default_privacy_redaction_budget: DEFAULT_PRIVACY_REDACTION_BUDGET,
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

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub rebate_vaults: u64,
    pub sponsor_rebate_pools: u64,
    pub proof_aggregation_fee_classes: u64,
    pub sealed_rebate_lots: u64,
    pub pq_sponsor_attestations: u64,
    pub redemption_receipts: u64,
    pub route_caps: u64,
    pub rebate_accounts: u64,
    pub privacy_redaction_budgets: u64,
    pub redeemed_lots: u64,
    pub rejected_redemptions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub rebate_vault_root: String,
    pub sponsor_rebate_pool_root: String,
    pub proof_aggregation_fee_class_root: String,
    pub sealed_rebate_lot_root: String,
    pub pq_sponsor_attestation_root: String,
    pub redemption_receipt_root: String,
    pub route_cap_root: String,
    pub rebate_accounting_root: String,
    pub privacy_redaction_budget_root: String,
    pub nullifier_root: String,
    pub public_event_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateVault {
    pub id: String,
    pub vault_commitment: String,
    pub sponsor_pool_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub total_capacity_piconero: u64,
    pub reserved_capacity_piconero: u64,
    pub status: VaultStatus,
}

impl RebateVault {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorRebatePool {
    pub id: String,
    pub sponsor_commitment: String,
    pub pool_commitment: String,
    pub available_piconero: u64,
    pub reserved_piconero: u64,
    pub cover_bps: u64,
    pub status: SponsorPoolStatus,
}

impl SponsorRebatePool {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofAggregationFeeClass {
    pub id: String,
    pub kind: FeeClassKind,
    pub class_commitment: String,
    pub base_fee_piconero: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub aggregation_weight: u64,
}

impl ProofAggregationFeeClass {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedRebateLot {
    pub id: String,
    pub vault_id: String,
    pub fee_class_id: String,
    pub lot_commitment: String,
    pub nullifier: String,
    pub sealed_amount_piconero: u64,
    pub redeemed_amount_piconero: u64,
    pub expires_at_height: u64,
    pub status: LotStatus,
}

impl SealedRebateLot {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "vault_id": self.vault_id,
            "fee_class_id": self.fee_class_id,
            "lot_commitment": self.lot_commitment,
            "sealed_amount_piconero": self.sealed_amount_piconero,
            "redeemed_amount_piconero": self.redeemed_amount_piconero,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSponsorAttestation {
    pub id: String,
    pub sponsor_pool_id: String,
    pub attestation_commitment: String,
    pub signer_key_commitment: String,
    pub pq_security_bits: u16,
    pub valid_until_height: u64,
    pub verdict: AttestationVerdict,
}

impl PqSponsorAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedemptionReceipt {
    pub id: String,
    pub lot_id: String,
    pub route_id: String,
    pub receipt_commitment: String,
    pub redeemed_piconero: u64,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub finalized_at_height: u64,
    pub status: ReceiptStatus,
}

impl RedemptionReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteCap {
    pub id: String,
    pub route_commitment: String,
    pub fee_class_id: String,
    pub max_rebate_piconero: u64,
    pub max_user_fee_bps: u64,
    pub expires_at_height: u64,
}

impl RouteCap {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RebateAccounting {
    pub id: String,
    pub sponsor_pool_id: String,
    pub accrued_rebates_piconero: u64,
    pub redeemed_rebates_piconero: u64,
    pub pending_rebates_piconero: u64,
    pub finalized_receipts: u64,
}

impl RebateAccounting {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionBudget {
    pub id: String,
    pub scope: RedactionScope,
    pub subject_commitment: String,
    pub allowed_fields: u64,
    pub spent_fields: u64,
    pub expires_at_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub rebate_vaults: BTreeMap<String, RebateVault>,
    pub sponsor_rebate_pools: BTreeMap<String, SponsorRebatePool>,
    pub proof_aggregation_fee_classes: BTreeMap<String, ProofAggregationFeeClass>,
    pub sealed_rebate_lots: BTreeMap<String, SealedRebateLot>,
    pub pq_sponsor_attestations: BTreeMap<String, PqSponsorAttestation>,
    pub redemption_receipts: BTreeMap<String, RedemptionReceipt>,
    pub route_caps: BTreeMap<String, RouteCap>,
    pub rebate_accounting: BTreeMap<String, RebateAccounting>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub nullifiers: BTreeSet<String>,
    pub public_events: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            current_height: 0,
            counters: Counters::default(),
            roots: Roots::default(),
            rebate_vaults: BTreeMap::new(),
            sponsor_rebate_pools: BTreeMap::new(),
            proof_aggregation_fee_classes: BTreeMap::new(),
            sealed_rebate_lots: BTreeMap::new(),
            pq_sponsor_attestations: BTreeMap::new(),
            redemption_receipts: BTreeMap::new(),
            route_caps: BTreeMap::new(),
            rebate_accounting: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_events: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            current_height: 1_482_000,
            ..Self::default()
        };
        state.install_devnet_fixtures();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        let roots = self.computed_roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn register_sponsor_rebate_pool(
        &mut self,
        sponsor_commitment: impl Into<String>,
        available_piconero: u64,
    ) -> Result<String> {
        let sponsor_commitment = sponsor_commitment.into();
        let id = deterministic_id(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-SPONSOR-POOL-ID",
            &format!(
                "{}:{}",
                sponsor_commitment, self.counters.sponsor_rebate_pools
            ),
        );
        let pool = SponsorRebatePool {
            id: id.clone(),
            sponsor_commitment,
            pool_commitment: deterministic_id("SPONSOR-REBATE-POOL-COMMITMENT", &id),
            available_piconero,
            reserved_piconero: 0,
            cover_bps: self.config.sponsor_cover_bps,
            status: SponsorPoolStatus::Open,
        };
        self.sponsor_rebate_pools.insert(id.clone(), pool.clone());
        self.counters.sponsor_rebate_pools += 1;
        self.emit_public_event("sponsor_rebate_pool", &id, pool.public_record());
        self.refresh_roots();
        Ok(id)
    }

    pub fn add_proof_aggregation_fee_class(
        &mut self,
        kind: FeeClassKind,
        base_fee_piconero: u64,
        aggregation_weight: u64,
    ) -> Result<String> {
        let id = deterministic_id(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-FEE-CLASS-ID",
            &format!("{kind:?}:{}", self.counters.proof_aggregation_fee_classes),
        );
        let fee_class = ProofAggregationFeeClass {
            id: id.clone(),
            kind,
            class_commitment: deterministic_id("PROOF-AGGREGATION-FEE-CLASS-COMMITMENT", &id),
            base_fee_piconero,
            max_user_fee_bps: self.config.max_user_fee_bps,
            rebate_bps: self.config.rebate_bps,
            aggregation_weight,
        };
        self.proof_aggregation_fee_classes
            .insert(id.clone(), fee_class.clone());
        self.counters.proof_aggregation_fee_classes += 1;
        self.emit_public_event(
            "proof_aggregation_fee_class",
            &id,
            fee_class.public_record(),
        );
        self.refresh_roots();
        Ok(id)
    }

    pub fn seal_rebate_lot(
        &mut self,
        vault_id: impl Into<String>,
        fee_class_id: impl Into<String>,
        sealed_amount_piconero: u64,
    ) -> Result<String> {
        let vault_id = vault_id.into();
        let fee_class_id = fee_class_id.into();
        require_key(&self.rebate_vaults, &vault_id, "rebate vault")?;
        require_key(
            &self.proof_aggregation_fee_classes,
            &fee_class_id,
            "proof aggregation fee class",
        )?;
        let id = deterministic_id(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-SEALED-REBATE-LOT-ID",
            &format!(
                "{vault_id}:{fee_class_id}:{}",
                self.counters.sealed_rebate_lots
            ),
        );
        let nullifier = deterministic_id("SEALED-REBATE-LOT-NULLIFIER", &id);
        let lot = SealedRebateLot {
            id: id.clone(),
            vault_id,
            fee_class_id,
            lot_commitment: deterministic_id("SEALED-REBATE-LOT-COMMITMENT", &id),
            nullifier: nullifier.clone(),
            sealed_amount_piconero,
            redeemed_amount_piconero: 0,
            expires_at_height: self.current_height + self.config.lot_ttl_blocks,
            status: LotStatus::Sealed,
        };
        self.nullifiers.insert(nullifier);
        self.sealed_rebate_lots.insert(id.clone(), lot.clone());
        self.counters.sealed_rebate_lots += 1;
        self.emit_public_event("sealed_rebate_lot", &id, lot.public_record());
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_pq_sponsor_attestation(
        &mut self,
        sponsor_pool_id: impl Into<String>,
        signer_key_commitment: impl Into<String>,
        verdict: AttestationVerdict,
    ) -> Result<String> {
        let sponsor_pool_id = sponsor_pool_id.into();
        require_key(&self.sponsor_rebate_pools, &sponsor_pool_id, "sponsor pool")?;
        let id = deterministic_id(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-PQ-SPONSOR-ATTESTATION-ID",
            &format!(
                "{sponsor_pool_id}:{}",
                self.counters.pq_sponsor_attestations
            ),
        );
        let attestation = PqSponsorAttestation {
            id: id.clone(),
            sponsor_pool_id,
            attestation_commitment: deterministic_id("PQ-SPONSOR-ATTESTATION-COMMITMENT", &id),
            signer_key_commitment: signer_key_commitment.into(),
            pq_security_bits: self.config.min_pq_security_bits,
            valid_until_height: self.current_height + self.config.attestation_ttl_blocks,
            verdict,
        };
        self.pq_sponsor_attestations
            .insert(id.clone(), attestation.clone());
        self.counters.pq_sponsor_attestations += 1;
        self.emit_public_event("pq_sponsor_attestation", &id, attestation.public_record());
        self.refresh_roots();
        Ok(id)
    }

    pub fn cap_route(
        &mut self,
        fee_class_id: impl Into<String>,
        route_commitment: impl Into<String>,
        max_rebate_piconero: u64,
    ) -> Result<String> {
        let fee_class_id = fee_class_id.into();
        require_key(
            &self.proof_aggregation_fee_classes,
            &fee_class_id,
            "proof aggregation fee class",
        )?;
        let id = deterministic_id(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-ROUTE-CAP-ID",
            &format!("{fee_class_id}:{}", self.counters.route_caps),
        );
        let cap = RouteCap {
            id: id.clone(),
            route_commitment: route_commitment.into(),
            fee_class_id,
            max_rebate_piconero,
            max_user_fee_bps: self.config.max_user_fee_bps,
            expires_at_height: self.current_height + self.config.route_ttl_blocks,
        };
        self.route_caps.insert(id.clone(), cap.clone());
        self.counters.route_caps += 1;
        self.emit_public_event("route_cap", &id, cap.public_record());
        self.refresh_roots();
        Ok(id)
    }

    pub fn redeem_lot(
        &mut self,
        lot_id: impl Into<String>,
        route_id: impl Into<String>,
        redeemed_piconero: u64,
    ) -> Result<String> {
        let lot_id = lot_id.into();
        let route_id = route_id.into();
        require_key(&self.route_caps, &route_id, "route cap")?;
        let lot = self
            .sealed_rebate_lots
            .get_mut(&lot_id)
            .ok_or_else(|| format!("unknown sealed rebate lot: {lot_id}"))?;
        if !matches!(lot.status, LotStatus::Sealed | LotStatus::PartiallyRedeemed) {
            self.counters.rejected_redemptions += 1;
            return Err(format!("sealed rebate lot is not redeemable: {lot_id}"));
        }
        if lot.redeemed_amount_piconero + redeemed_piconero > lot.sealed_amount_piconero {
            self.counters.rejected_redemptions += 1;
            return Err(format!("sealed rebate lot over redemption: {lot_id}"));
        }
        lot.redeemed_amount_piconero += redeemed_piconero;
        lot.status = if lot.redeemed_amount_piconero == lot.sealed_amount_piconero {
            self.counters.redeemed_lots += 1;
            LotStatus::Redeemed
        } else {
            LotStatus::PartiallyRedeemed
        };
        let id = deterministic_id(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-REDEMPTION-RECEIPT-ID",
            &format!("{lot_id}:{route_id}:{}", self.counters.redemption_receipts),
        );
        let receipt = RedemptionReceipt {
            id: id.clone(),
            lot_id,
            route_id,
            receipt_commitment: deterministic_id("REDEMPTION-RECEIPT-COMMITMENT", &id),
            redeemed_piconero,
            user_fee_bps: self.config.low_fee_target_bps,
            rebate_bps: self.config.rebate_bps,
            finalized_at_height: self.current_height + self.config.receipt_finality_blocks,
            status: ReceiptStatus::Published,
        };
        self.redemption_receipts.insert(id.clone(), receipt.clone());
        self.counters.redemption_receipts += 1;
        self.emit_public_event("redemption_receipt", &id, receipt.public_record());
        self.refresh_roots();
        Ok(id)
    }

    pub fn allocate_privacy_redaction_budget(
        &mut self,
        scope: RedactionScope,
        subject_commitment: impl Into<String>,
    ) -> String {
        let id = deterministic_id(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-PRIVACY-REDACTION-BUDGET-ID",
            &format!("{scope:?}:{}", self.counters.privacy_redaction_budgets),
        );
        let budget = PrivacyRedactionBudget {
            id: id.clone(),
            scope,
            subject_commitment: subject_commitment.into(),
            allowed_fields: self.config.default_privacy_redaction_budget,
            spent_fields: 0,
            expires_at_height: self.current_height + self.config.lot_ttl_blocks,
        };
        self.privacy_redaction_budgets
            .insert(id.clone(), budget.clone());
        self.counters.privacy_redaction_budgets += 1;
        self.emit_public_event("privacy_redaction_budget", &id, budget.public_record());
        self.refresh_roots();
        id
    }

    fn install_devnet_fixtures(&mut self) {
        let pool_id = "devnet-recursive-proof-sponsor-pool".to_string();
        let fee_class_id = "devnet-recursive-aggregation-fee-class".to_string();
        let vault_id = "devnet-recursive-proof-rebate-vault".to_string();
        let lot_id = "devnet-sealed-recursive-proof-rebate-lot".to_string();
        let route_id = "devnet-recursive-proof-route-cap".to_string();

        self.sponsor_rebate_pools.insert(
            pool_id.clone(),
            SponsorRebatePool {
                id: pool_id.clone(),
                sponsor_commitment: "commitment:devnet-sponsor".to_string(),
                pool_commitment: deterministic_id("SPONSOR-REBATE-POOL-COMMITMENT", &pool_id),
                available_piconero: 50_000_000,
                reserved_piconero: 5_000_000,
                cover_bps: self.config.sponsor_cover_bps,
                status: SponsorPoolStatus::Open,
            },
        );
        self.proof_aggregation_fee_classes.insert(
            fee_class_id.clone(),
            ProofAggregationFeeClass {
                id: fee_class_id.clone(),
                kind: FeeClassKind::RecursiveAggregation,
                class_commitment: deterministic_id(
                    "PROOF-AGGREGATION-FEE-CLASS-COMMITMENT",
                    &fee_class_id,
                ),
                base_fee_piconero: 12_500,
                max_user_fee_bps: self.config.max_user_fee_bps,
                rebate_bps: self.config.rebate_bps,
                aggregation_weight: 1_000,
            },
        );
        self.rebate_vaults.insert(
            vault_id.clone(),
            RebateVault {
                id: vault_id.clone(),
                vault_commitment: deterministic_id("REBATE-VAULT-COMMITMENT", &vault_id),
                sponsor_pool_id: pool_id.clone(),
                fee_asset_id: self.config.fee_asset_id.clone(),
                rebate_asset_id: self.config.rebate_asset_id.clone(),
                total_capacity_piconero: 25_000_000,
                reserved_capacity_piconero: 2_500_000,
                status: VaultStatus::Active,
            },
        );
        self.sealed_rebate_lots.insert(
            lot_id.clone(),
            SealedRebateLot {
                id: lot_id.clone(),
                vault_id: vault_id.clone(),
                fee_class_id: fee_class_id.clone(),
                lot_commitment: deterministic_id("SEALED-REBATE-LOT-COMMITMENT", &lot_id),
                nullifier: deterministic_id("SEALED-REBATE-LOT-NULLIFIER", &lot_id),
                sealed_amount_piconero: 250_000,
                redeemed_amount_piconero: 75_000,
                expires_at_height: self.current_height + self.config.lot_ttl_blocks,
                status: LotStatus::PartiallyRedeemed,
            },
        );
        self.route_caps.insert(
            route_id.clone(),
            RouteCap {
                id: route_id.clone(),
                route_commitment: "route:devnet-recursive-proof-aggregation".to_string(),
                fee_class_id: fee_class_id.clone(),
                max_rebate_piconero: 125_000,
                max_user_fee_bps: self.config.max_user_fee_bps,
                expires_at_height: self.current_height + self.config.route_ttl_blocks,
            },
        );
        self.rebate_accounting.insert(
            pool_id.clone(),
            RebateAccounting {
                id: pool_id.clone(),
                sponsor_pool_id: pool_id.clone(),
                accrued_rebates_piconero: 250_000,
                redeemed_rebates_piconero: 75_000,
                pending_rebates_piconero: 175_000,
                finalized_receipts: 1,
            },
        );
        self.pq_sponsor_attestations.insert(
            "devnet-pq-sponsor-attestation".to_string(),
            PqSponsorAttestation {
                id: "devnet-pq-sponsor-attestation".to_string(),
                sponsor_pool_id: pool_id.clone(),
                attestation_commitment: "attestation:devnet-sponsor".to_string(),
                signer_key_commitment: "pq-key:devnet-sponsor".to_string(),
                pq_security_bits: self.config.min_pq_security_bits,
                valid_until_height: self.current_height + self.config.attestation_ttl_blocks,
                verdict: AttestationVerdict::Allow,
            },
        );
        self.redemption_receipts.insert(
            "devnet-redemption-receipt".to_string(),
            RedemptionReceipt {
                id: "devnet-redemption-receipt".to_string(),
                lot_id: lot_id.clone(),
                route_id,
                receipt_commitment: "receipt:devnet-redemption".to_string(),
                redeemed_piconero: 75_000,
                user_fee_bps: self.config.low_fee_target_bps,
                rebate_bps: self.config.rebate_bps,
                finalized_at_height: self.current_height + self.config.receipt_finality_blocks,
                status: ReceiptStatus::Finalized,
            },
        );
        self.privacy_redaction_budgets.insert(
            "devnet-redaction-budget".to_string(),
            PrivacyRedactionBudget {
                id: "devnet-redaction-budget".to_string(),
                scope: RedactionScope::Receipt,
                subject_commitment: "receipt:devnet-redemption".to_string(),
                allowed_fields: self.config.default_privacy_redaction_budget,
                spent_fields: 8,
                expires_at_height: self.current_height + self.config.lot_ttl_blocks,
            },
        );
        self.nullifiers
            .insert(deterministic_id("SEALED-REBATE-LOT-NULLIFIER", &lot_id));
        self.counters = Counters {
            rebate_vaults: self.rebate_vaults.len() as u64,
            sponsor_rebate_pools: self.sponsor_rebate_pools.len() as u64,
            proof_aggregation_fee_classes: self.proof_aggregation_fee_classes.len() as u64,
            sealed_rebate_lots: self.sealed_rebate_lots.len() as u64,
            pq_sponsor_attestations: self.pq_sponsor_attestations.len() as u64,
            redemption_receipts: self.redemption_receipts.len() as u64,
            route_caps: self.route_caps.len() as u64,
            rebate_accounts: self.rebate_accounting.len() as u64,
            privacy_redaction_budgets: self.privacy_redaction_budgets.len() as u64,
            redeemed_lots: 0,
            rejected_redemptions: 0,
        };
        self.emit_public_event(
            "devnet_fixture",
            "recursive_proof_fee_rebate_vault",
            json!({
                "vault_id": vault_id,
                "sponsor_pool_id": pool_id,
                "fee_class_id": fee_class_id,
                "lot_id": lot_id,
            }),
        );
    }

    fn public_record_without_state_root(&self) -> Value {
        let mut roots = self.computed_roots();
        roots.state_root.clear();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    fn computed_roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.state_root(),
            rebate_vault_root: map_root("REBATE-VAULT-ROOT", &self.rebate_vaults, |record| {
                record.public_record()
            }),
            sponsor_rebate_pool_root: map_root(
                "SPONSOR-REBATE-POOL-ROOT",
                &self.sponsor_rebate_pools,
                |record| record.public_record(),
            ),
            proof_aggregation_fee_class_root: map_root(
                "PROOF-AGGREGATION-FEE-CLASS-ROOT",
                &self.proof_aggregation_fee_classes,
                |record| record.public_record(),
            ),
            sealed_rebate_lot_root: map_root(
                "SEALED-REBATE-LOT-ROOT",
                &self.sealed_rebate_lots,
                |record| record.public_record(),
            ),
            pq_sponsor_attestation_root: map_root(
                "PQ-SPONSOR-ATTESTATION-ROOT",
                &self.pq_sponsor_attestations,
                |record| record.public_record(),
            ),
            redemption_receipt_root: map_root(
                "REDEMPTION-RECEIPT-ROOT",
                &self.redemption_receipts,
                |record| record.public_record(),
            ),
            route_cap_root: map_root("ROUTE-CAP-ROOT", &self.route_caps, |record| {
                record.public_record()
            }),
            rebate_accounting_root: map_root(
                "REBATE-ACCOUNTING-ROOT",
                &self.rebate_accounting,
                |record| record.public_record(),
            ),
            privacy_redaction_budget_root: map_root(
                "PRIVACY-REDACTION-BUDGET-ROOT",
                &self.privacy_redaction_budgets,
                |record| record.public_record(),
            ),
            nullifier_root: set_root("SEALED-REBATE-LOT-NULLIFIER-ROOT", &self.nullifiers),
            public_event_root: value_map_root("PUBLIC-EVENT-ROOT", &self.public_events),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": roots.config_root,
                "rebate_vault_root": roots.rebate_vault_root,
                "sponsor_rebate_pool_root": roots.sponsor_rebate_pool_root,
                "proof_aggregation_fee_class_root": roots.proof_aggregation_fee_class_root,
                "sealed_rebate_lot_root": roots.sealed_rebate_lot_root,
                "pq_sponsor_attestation_root": roots.pq_sponsor_attestation_root,
                "redemption_receipt_root": roots.redemption_receipt_root,
                "route_cap_root": roots.route_cap_root,
                "rebate_accounting_root": roots.rebate_accounting_root,
                "privacy_redaction_budget_root": roots.privacy_redaction_budget_root,
                "nullifier_root": roots.nullifier_root,
                "public_event_root": roots.public_event_root,
                "counters_root": roots.counters_root,
                "state_root": "",
            },
        }));
        roots
    }

    fn refresh_roots(&mut self) {
        self.roots = self.computed_roots();
    }

    fn emit_public_event(&mut self, kind: &str, id: &str, record: Value) {
        let event_id = deterministic_id("RECURSIVE-PROOF-REBATE-VAULT-PUBLIC-EVENT", id);
        self.public_events.insert(
            event_id,
            json!({
                "kind": kind,
                "id": id,
                "record": record,
            }),
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-RECURSIVE-PROOF-FEE-REBATE-VAULT-RUNTIME-STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn value_map_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "nullifier": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn deterministic_id(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn require_key<T>(map: &BTreeMap<String, T>, key: &str, label: &str) -> Result<()> {
    if map.contains_key(key) {
        Ok(())
    } else {
        Err(format!("unknown {label}: {key}"))
    }
}
