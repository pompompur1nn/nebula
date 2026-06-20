use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedInvoiceFactoringAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_SCHEMA_VERSION: u64 =
    1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-confidential-invoice-factoring-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_DEVNET_HEIGHT: u64 =
    918_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Draft,
    IssuerAttested,
    DebtorAccepted,
    OracleVerified,
    Tokenized,
    Pooled,
    Matured,
    Settled,
    Defaulted,
    Disputed,
    Cancelled,
}
impl InvoiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::IssuerAttested => "issuer_attested",
            Self::DebtorAccepted => "debtor_accepted",
            Self::OracleVerified => "oracle_verified",
            Self::Tokenized => "tokenized",
            Self::Pooled => "pooled",
            Self::Matured => "matured",
            Self::Settled => "settled",
            Self::Defaulted => "defaulted",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Defaulted | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Bootstrapping,
    Active,
    Sealed,
    MaturityLocked,
    Settling,
    Settled,
    Paused,
}
impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrapping => "bootstrapping",
            Self::Active => "active",
            Self::Sealed => "sealed",
            Self::MaturityLocked => "maturity_locked",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    Issuer,
    Debtor,
    Oracle,
    Insurer,
    Auditor,
    Servicer,
    LiquidityProvider,
}
impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::Debtor => "debtor",
            Self::Oracle => "oracle",
            Self::Insurer => "insurer",
            Self::Auditor => "auditor",
            Self::Servicer => "servicer",
            Self::LiquidityProvider => "liquidity_provider",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub settlement_asset_id: String,
    pub invoice_note_asset_prefix: String,
    pub low_fee_lane: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_invoice_face_value: u128,
    pub max_pool_face_value: u128,
    pub max_discount_bps: u64,
    pub default_haircut_bps: u64,
    pub default_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub maturity_grace_blocks: u64,
    pub invoice_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub max_invoices: usize,
    pub max_pools: usize,
    pub max_attestations: usize,
    pub max_sealed_liquidity_notes: usize,
    pub max_settlements: usize,
    pub max_rebates: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-devnet".to_string(),
            settlement_asset_id: "confidential-usdc-devnet".to_string(),
            invoice_note_asset_prefix: "cinv".to_string(),
            low_fee_lane: "private-l2-invoice-factoring-amm".to_string(),
            min_privacy_set_size: 16_384,
            batch_privacy_set_size: 262_144,
            min_pq_security_bits: 256,
            max_invoice_face_value: 50_000_000_000,
            max_pool_face_value: 2_000_000_000_000,
            max_discount_bps: 2_500,
            default_haircut_bps: 450,
            default_fee_bps: 8,
            target_rebate_bps: 6,
            maturity_grace_blocks: 720,
            invoice_ttl_blocks: 86_400,
            attestation_ttl_blocks: 14_400,
            max_invoices: 4_194_304,
            max_pools: 524_288,
            max_attestations: 8_388_608,
            max_sealed_liquidity_notes: 8_388_608,
            max_settlements: 2_097_152,
            max_rebates: 4_194_304,
        }
    }
}
impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> Result<()> {
        if self.default_fee_bps > self.max_discount_bps {
            return Err("default fee exceeds discount cap".to_string());
        }
        if self.default_haircut_bps
            > PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_MAX_BPS
        {
            return Err("haircut bps exceeds max bps".to_string());
        }
        if self.min_pq_security_bits < 256 {
            return Err("pq security below runtime floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub invoices: u64,
    pub pools: u64,
    pub attestations: u64,
    pub sealed_liquidity_notes: u64,
    pub maturity_settlements: u64,
    pub default_haircuts: u64,
    pub fee_credit_rebates: u64,
    pub nullifiers: u64,
    pub public_records: u64,
    pub operator_summaries: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub invoice_note_root: String,
    pub pool_root: String,
    pub attestation_root: String,
    pub sealed_liquidity_root: String,
    pub settlement_root: String,
    pub haircut_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}
impl Default for Roots {
    fn default() -> Self {
        Self {
            invoice_note_root: empty_root("invoice_notes"),
            pool_root: empty_root("pools"),
            attestation_root: empty_root("attestations"),
            sealed_liquidity_root: empty_root("sealed_liquidity"),
            settlement_root: empty_root("settlements"),
            haircut_root: empty_root("haircuts"),
            rebate_root: empty_root("rebates"),
            nullifier_root: empty_root("nullifiers"),
            operator_summary_root: empty_root("operator_summaries"),
            public_record_root: empty_root("public_records"),
            state_root: empty_root("state"),
        }
    }
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvoiceNoteToken {
    pub invoice_id: String,
    pub note_asset_id: String,
    pub issuer_commitment: String,
    pub debtor_commitment: String,
    pub face_value_commitment: String,
    pub face_value_hint: u128,
    pub maturity_height: u64,
    pub token_supply: u128,
    pub discount_bps: u64,
    pub haircut_bps: u64,
    pub status: InvoiceStatus,
    pub privacy_set_size: u64,
    pub pq_committee_root: String,
    pub encrypted_terms_root: String,
    pub nullifier_root: String,
}
impl InvoiceNoteToken {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "invoice_note_token", "invoice_id": self.invoice_id, "note_asset_id": self.note_asset_id, "issuer_commitment": self.issuer_commitment, "debtor_commitment": self.debtor_commitment, "face_value_commitment": self.face_value_commitment, "face_value_hint_band": value_band(self.face_value_hint), "maturity_height": self.maturity_height, "token_supply": self.token_supply, "discount_bps": self.discount_bps, "haircut_bps": self.haircut_bps, "status": self.status.as_str(), "privacy_set_size": self.privacy_set_size, "pq_committee_root": self.pq_committee_root, "encrypted_terms_root": self.encrypted_terms_root, "nullifier_root": self.nullifier_root })
    }
    pub fn record_root(&self) -> String {
        root_from_record("invoice_note", &self.public_record())
    }
    pub fn advance_status(&mut self, status: InvoiceStatus) -> Result<()> {
        if self.status.terminal() {
            return Err(format!("invoice {} is terminal", self.invoice_id));
        }
        self.status = status;
        Ok(())
    }
    pub fn mature(&mut self, height: u64) -> bool {
        if height >= self.maturity_height && !self.status.terminal() {
            self.status = InvoiceStatus::Matured;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FactoringAmmPool {
    pub pool_id: String,
    pub base_asset_id: String,
    pub note_asset_id: String,
    pub sealed_reserve_commitment: String,
    pub note_reserve_commitment: String,
    pub invariant_commitment: String,
    pub lp_token_commitment: String,
    pub fee_bps: u64,
    pub discount_bps: u64,
    pub maturity_height: u64,
    pub status: PoolStatus,
    pub oracle_price_root: String,
    pub sealed_liquidity_root: String,
    pub collected_fee_credits: u128,
}
impl FactoringAmmPool {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "factoring_amm_pool", "pool_id": self.pool_id, "base_asset_id": self.base_asset_id, "note_asset_id": self.note_asset_id, "sealed_reserve_commitment": self.sealed_reserve_commitment, "note_reserve_commitment": self.note_reserve_commitment, "invariant_commitment": self.invariant_commitment, "lp_token_commitment": self.lp_token_commitment, "fee_bps": self.fee_bps, "discount_bps": self.discount_bps, "maturity_height": self.maturity_height, "status": self.status.as_str(), "oracle_price_root": self.oracle_price_root, "sealed_liquidity_root": self.sealed_liquidity_root, "collected_fee_credit_band": value_band(self.collected_fee_credits) })
    }
    pub fn record_root(&self) -> String {
        root_from_record("pool", &self.public_record())
    }
    pub fn seal(&mut self) {
        self.status = PoolStatus::Sealed;
    }
    pub fn lock_for_maturity(&mut self) {
        self.status = PoolStatus::MaturityLocked;
    }
    pub fn estimate_discounted_value(&self, face_value: u128) -> u128 {
        face_value.saturating_mul((10_000 - self.discount_bps) as u128) / 10_000
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DebtorOracleAttestation {
    pub attestation_id: String,
    pub invoice_id: String,
    pub kind: AttestationKind,
    pub subject_commitment: String,
    pub statement_root: String,
    pub confidence_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub pq_signature_root: String,
    pub selective_disclosure_root: String,
}
impl DebtorOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "debtor_oracle_attestation", "attestation_id": self.attestation_id, "invoice_id": self.invoice_id, "attestation_kind": self.kind.as_str(), "subject_commitment": self.subject_commitment, "statement_root": self.statement_root, "confidence_bps": self.confidence_bps, "issued_at_height": self.issued_at_height, "expires_at_height": self.expires_at_height, "pq_signature_root": self.pq_signature_root, "selective_disclosure_root": self.selective_disclosure_root })
    }
    pub fn record_root(&self) -> String {
        root_from_record("attestation", &self.public_record())
    }
    pub fn valid_at(&self, height: u64) -> bool {
        self.issued_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedLiquidityNote {
    pub liquidity_id: String,
    pub pool_id: String,
    pub provider_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub amount_hint: u128,
    pub fee_credit_commitment: String,
    pub encrypted_position_root: String,
    pub nullifier: String,
    pub opened: bool,
}
impl SealedLiquidityNote {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "sealed_liquidity_note", "liquidity_id": self.liquidity_id, "pool_id": self.pool_id, "provider_commitment": self.provider_commitment, "asset_id": self.asset_id, "amount_commitment": self.amount_commitment, "amount_hint_band": value_band(self.amount_hint), "fee_credit_commitment": self.fee_credit_commitment, "encrypted_position_root": self.encrypted_position_root, "nullifier": self.nullifier, "opened": self.opened })
    }
    pub fn record_root(&self) -> String {
        root_from_record("sealed_liquidity", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaturitySettlement {
    pub settlement_id: String,
    pub pool_id: String,
    pub invoice_id: String,
    pub settled_height: u64,
    pub gross_payment_commitment: String,
    pub investor_payment_commitment: String,
    pub protocol_fee_commitment: String,
    pub defaulted: bool,
    pub haircut_bps: u64,
    pub receipt_root: String,
}
impl MaturitySettlement {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "maturity_settlement", "settlement_id": self.settlement_id, "pool_id": self.pool_id, "invoice_id": self.invoice_id, "settled_height": self.settled_height, "gross_payment_commitment": self.gross_payment_commitment, "investor_payment_commitment": self.investor_payment_commitment, "protocol_fee_commitment": self.protocol_fee_commitment, "defaulted": self.defaulted, "haircut_bps": self.haircut_bps, "receipt_root": self.receipt_root })
    }
    pub fn record_root(&self) -> String {
        root_from_record("settlement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DefaultHaircut {
    pub haircut_id: String,
    pub invoice_id: String,
    pub pool_id: String,
    pub oracle_attestation_id: String,
    pub base_haircut_bps: u64,
    pub stress_haircut_bps: u64,
    pub final_haircut_bps: u64,
    pub reason_code: String,
    pub proof_root: String,
}
impl DefaultHaircut {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "default_haircut", "haircut_id": self.haircut_id, "invoice_id": self.invoice_id, "pool_id": self.pool_id, "oracle_attestation_id": self.oracle_attestation_id, "base_haircut_bps": self.base_haircut_bps, "stress_haircut_bps": self.stress_haircut_bps, "final_haircut_bps": self.final_haircut_bps, "reason_code": self.reason_code, "proof_root": self.proof_root })
    }
    pub fn record_root(&self) -> String {
        root_from_record("haircut", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditRebate {
    pub rebate_id: String,
    pub pool_id: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub fee_credit_commitment: String,
    pub rebate_bps: u64,
    pub applied_height: u64,
    pub receipt_root: String,
}
impl FeeCreditRebate {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "fee_credit_rebate", "rebate_id": self.rebate_id, "pool_id": self.pool_id, "beneficiary_commitment": self.beneficiary_commitment, "asset_id": self.asset_id, "fee_credit_commitment": self.fee_credit_commitment, "rebate_bps": self.rebate_bps, "applied_height": self.applied_height, "receipt_root": self.receipt_root })
    }
    pub fn record_root(&self) -> String {
        root_from_record("rebate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub view_id: String,
    pub subject_id: String,
    pub redaction_level: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
}
impl PrivacyRedaction {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "privacy_redaction", "view_id": self.view_id, "subject_id": self.subject_id, "redaction_level": self.redaction_level, "commitment_root": self.commitment_root, "ciphertext_root": self.ciphertext_root, "nullifier_root": self.nullifier_root, "proof_root": self.proof_root, "effective_height": self.effective_height })
    }
    pub fn record_root(&self) -> String {
        root_from_record("privacy_redaction", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub height: u64,
    pub invoice_count: u64,
    pub pool_count: u64,
    pub sealed_liquidity_count: u64,
    pub maturity_settlement_count: u64,
    pub defaulted_invoice_count: u64,
    pub total_face_value_band: String,
    pub average_discount_bps: u64,
    pub public_record_root: String,
    pub state_root: String,
}
impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        root_from_record("operator_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub invoices: BTreeMap<String, InvoiceNoteToken>,
    pub pools: BTreeMap<String, FactoringAmmPool>,
    pub attestations: BTreeMap<String, DebtorOracleAttestation>,
    pub sealed_liquidity: BTreeMap<String, SealedLiquidityNote>,
    pub settlements: BTreeMap<String, MaturitySettlement>,
    pub default_haircuts: BTreeMap<String, DefaultHaircut>,
    pub fee_credit_rebates: BTreeMap<String, FeeCreditRebate>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            invoices: BTreeMap::new(),
            pools: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sealed_liquidity: BTreeMap::new(),
            settlements: BTreeMap::new(),
            default_haircuts: BTreeMap::new(),
            fee_credit_rebates: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }
}
impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.config.validate().expect("valid devnet config");
        state.seed_devnet();
        state.refresh_roots();
        state
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut map) = record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
    pub fn roots(&self) -> Roots {
        let mut clone = self.clone();
        clone.refresh_roots();
        clone.roots
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({ "protocol_version": PROTOCOL_VERSION, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.roots.public_record(), "invoice_notes": records(self.invoices.values().map(InvoiceNoteToken::public_record)), "pools": records(self.pools.values().map(FactoringAmmPool::public_record)), "attestations": records(self.attestations.values().map(DebtorOracleAttestation::public_record)), "sealed_liquidity": records(self.sealed_liquidity.values().map(SealedLiquidityNote::public_record)), "settlements": records(self.settlements.values().map(MaturitySettlement::public_record)), "default_haircuts": records(self.default_haircuts.values().map(DefaultHaircut::public_record)), "fee_credit_rebates": records(self.fee_credit_rebates.values().map(FeeCreditRebate::public_record)), "privacy_redactions": records(self.privacy_redactions.values().map(PrivacyRedaction::public_record)), "operator_summaries": records(self.operator_summaries.values().map(OperatorSummary::public_record)), "nullifier_root": merkle_root_for_strings("nullifiers", &self.nullifiers), "public_records": records(self.public_records.values().cloned()) })
    }
    pub fn mint_invoice_note(&mut self, mut invoice: InvoiceNoteToken) -> Result<String> {
        self.config.validate()?;
        if self.invoices.len() >= self.config.max_invoices {
            return Err("invoice capacity reached".to_string());
        }
        if invoice.discount_bps > self.config.max_discount_bps {
            return Err("invoice discount exceeds cap".to_string());
        }
        if invoice.privacy_set_size < self.config.min_privacy_set_size {
            return Err("invoice privacy set too small".to_string());
        }
        let id = if invoice.invoice_id.is_empty() {
            deterministic_id(
                "invoice",
                &invoice.public_record(),
                self.counters.invoices + 1,
            )
        } else {
            invoice.invoice_id.clone()
        };
        invoice.invoice_id = id.clone();
        invoice.note_asset_id = format!(
            "{}-{}",
            self.config.invoice_note_asset_prefix,
            short_hash(&id)
        );
        self.record_public(format!("invoice:{id}"), invoice.public_record())?;
        self.invoices.insert(id.clone(), invoice);
        self.counters.invoices = self.invoices.len() as u64;
        self.refresh_roots();
        Ok(id)
    }
    pub fn create_pool(&mut self, mut pool: FactoringAmmPool) -> Result<String> {
        if self.pools.len() >= self.config.max_pools {
            return Err("pool capacity reached".to_string());
        }
        if pool.fee_bps
            > self
                .config
                .default_fee_bps
                .max(self.config.max_discount_bps)
        {
            return Err("pool fee exceeds runtime cap".to_string());
        }
        let id = if pool.pool_id.is_empty() {
            deterministic_id("pool", &pool.public_record(), self.counters.pools + 1)
        } else {
            pool.pool_id.clone()
        };
        pool.pool_id = id.clone();
        self.record_public(format!("pool:{id}"), pool.public_record())?;
        self.pools.insert(id.clone(), pool);
        self.counters.pools = self.pools.len() as u64;
        self.refresh_roots();
        Ok(id)
    }
    pub fn submit_attestation(
        &mut self,
        mut attestation: DebtorOracleAttestation,
    ) -> Result<String> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("attestation capacity reached".to_string());
        }
        if !self.invoices.contains_key(&attestation.invoice_id) {
            return Err("attestation invoice is unknown".to_string());
        }
        let id = if attestation.attestation_id.is_empty() {
            deterministic_id(
                "attestation",
                &attestation.public_record(),
                self.counters.attestations + 1,
            )
        } else {
            attestation.attestation_id.clone()
        };
        attestation.attestation_id = id.clone();
        self.record_public(format!("attestation:{id}"), attestation.public_record())?;
        self.attestations.insert(id.clone(), attestation);
        self.counters.attestations = self.attestations.len() as u64;
        self.refresh_roots();
        Ok(id)
    }
    pub fn seal_liquidity(&mut self, mut note: SealedLiquidityNote) -> Result<String> {
        if self.sealed_liquidity.len() >= self.config.max_sealed_liquidity_notes {
            return Err("sealed liquidity capacity reached".to_string());
        }
        if self.nullifiers.contains(&note.nullifier) {
            return Err("liquidity nullifier already seen".to_string());
        }
        if !self.pools.contains_key(&note.pool_id) {
            return Err("sealed liquidity pool is unknown".to_string());
        }
        let id = if note.liquidity_id.is_empty() {
            deterministic_id(
                "sealed_liquidity",
                &note.public_record(),
                self.counters.sealed_liquidity_notes + 1,
            )
        } else {
            note.liquidity_id.clone()
        };
        note.liquidity_id = id.clone();
        self.nullifiers.insert(note.nullifier.clone());
        self.record_public(format!("sealed_liquidity:{id}"), note.public_record())?;
        self.sealed_liquidity.insert(id.clone(), note);
        self.counters.sealed_liquidity_notes = self.sealed_liquidity.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.refresh_roots();
        Ok(id)
    }
    pub fn apply_default_haircut(&mut self, mut haircut: DefaultHaircut) -> Result<String> {
        if !self.invoices.contains_key(&haircut.invoice_id) {
            return Err("haircut invoice is unknown".to_string());
        }
        if haircut.final_haircut_bps
            > PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_MAX_BPS
        {
            return Err("haircut exceeds max bps".to_string());
        }
        let id = if haircut.haircut_id.is_empty() {
            deterministic_id(
                "haircut",
                &haircut.public_record(),
                self.counters.default_haircuts + 1,
            )
        } else {
            haircut.haircut_id.clone()
        };
        haircut.haircut_id = id.clone();
        if let Some(invoice) = self.invoices.get_mut(&haircut.invoice_id) {
            invoice.haircut_bps = haircut.final_haircut_bps;
            invoice.status = InvoiceStatus::Defaulted;
        }
        self.record_public(format!("haircut:{id}"), haircut.public_record())?;
        self.default_haircuts.insert(id.clone(), haircut);
        self.counters.default_haircuts = self.default_haircuts.len() as u64;
        self.refresh_roots();
        Ok(id)
    }
    pub fn settle_maturity(&mut self, mut settlement: MaturitySettlement) -> Result<String> {
        if self.settlements.len() >= self.config.max_settlements {
            return Err("settlement capacity reached".to_string());
        }
        if !self.pools.contains_key(&settlement.pool_id) {
            return Err("settlement pool is unknown".to_string());
        }
        if !self.invoices.contains_key(&settlement.invoice_id) {
            return Err("settlement invoice is unknown".to_string());
        }
        let id = if settlement.settlement_id.is_empty() {
            deterministic_id(
                "settlement",
                &settlement.public_record(),
                self.counters.maturity_settlements + 1,
            )
        } else {
            settlement.settlement_id.clone()
        };
        settlement.settlement_id = id.clone();
        if let Some(pool) = self.pools.get_mut(&settlement.pool_id) {
            pool.status = PoolStatus::Settled;
        }
        if let Some(invoice) = self.invoices.get_mut(&settlement.invoice_id) {
            invoice.status = if settlement.defaulted {
                InvoiceStatus::Defaulted
            } else {
                InvoiceStatus::Settled
            };
        }
        self.record_public(format!("settlement:{id}"), settlement.public_record())?;
        self.settlements.insert(id.clone(), settlement);
        self.counters.maturity_settlements = self.settlements.len() as u64;
        self.refresh_roots();
        Ok(id)
    }
    pub fn credit_fee_rebate(&mut self, mut rebate: FeeCreditRebate) -> Result<String> {
        if self.fee_credit_rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity reached".to_string());
        }
        if !self.pools.contains_key(&rebate.pool_id) {
            return Err("rebate pool is unknown".to_string());
        }
        let id = if rebate.rebate_id.is_empty() {
            deterministic_id(
                "rebate",
                &rebate.public_record(),
                self.counters.fee_credit_rebates + 1,
            )
        } else {
            rebate.rebate_id.clone()
        };
        rebate.rebate_id = id.clone();
        self.record_public(format!("rebate:{id}"), rebate.public_record())?;
        self.fee_credit_rebates.insert(id.clone(), rebate);
        self.counters.fee_credit_rebates = self.fee_credit_rebates.len() as u64;
        self.refresh_roots();
        Ok(id)
    }
    pub fn redact_private_view(&mut self, redaction: PrivacyRedaction) -> Result<String> {
        let id = redaction.view_id.clone();
        self.record_public(format!("redaction:{id}"), redaction.public_record())?;
        self.privacy_redactions.insert(id.clone(), redaction);
        self.refresh_roots();
        Ok(id)
    }
    pub fn operator_summary(
        &mut self,
        operator_id: impl Into<String>,
        height: u64,
    ) -> OperatorSummary {
        self.refresh_roots();
        let defaulted_invoice_count = self
            .invoices
            .values()
            .filter(|invoice| invoice.status == InvoiceStatus::Defaulted)
            .count() as u64;
        let total_face_value = self
            .invoices
            .values()
            .map(|invoice| invoice.face_value_hint)
            .sum::<u128>();
        let average_discount_bps = if self.invoices.is_empty() {
            0
        } else {
            self.invoices
                .values()
                .map(|invoice| invoice.discount_bps)
                .sum::<u64>()
                / self.invoices.len() as u64
        };
        let summary = OperatorSummary {
            operator_id: operator_id.into(),
            height,
            invoice_count: self.invoices.len() as u64,
            pool_count: self.pools.len() as u64,
            sealed_liquidity_count: self.sealed_liquidity.len() as u64,
            maturity_settlement_count: self.settlements.len() as u64,
            defaulted_invoice_count,
            total_face_value_band: value_band(total_face_value),
            average_discount_bps,
            public_record_root: self.roots.public_record_root.clone(),
            state_root: self.roots.state_root.clone(),
        };
        self.operator_summaries
            .insert(summary.operator_id.clone(), summary.clone());
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.refresh_roots();
        summary
    }
    fn record_public(&mut self, key: String, record: Value) -> Result<()> {
        self.public_records.insert(key, record);
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }
    fn refresh_roots(&mut self) {
        self.counters.invoices = self.invoices.len() as u64;
        self.counters.pools = self.pools.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.sealed_liquidity_notes = self.sealed_liquidity.len() as u64;
        self.counters.maturity_settlements = self.settlements.len() as u64;
        self.counters.default_haircuts = self.default_haircuts.len() as u64;
        self.counters.fee_credit_rebates = self.fee_credit_rebates.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.roots = Roots {
            invoice_note_root: map_root(
                "invoice_notes",
                &self.invoices,
                InvoiceNoteToken::public_record,
            ),
            pool_root: map_root("pools", &self.pools, FactoringAmmPool::public_record),
            attestation_root: map_root(
                "attestations",
                &self.attestations,
                DebtorOracleAttestation::public_record,
            ),
            sealed_liquidity_root: map_root(
                "sealed_liquidity",
                &self.sealed_liquidity,
                SealedLiquidityNote::public_record,
            ),
            settlement_root: map_root(
                "settlements",
                &self.settlements,
                MaturitySettlement::public_record,
            ),
            haircut_root: map_root(
                "haircuts",
                &self.default_haircuts,
                DefaultHaircut::public_record,
            ),
            rebate_root: map_root(
                "rebates",
                &self.fee_credit_rebates,
                FeeCreditRebate::public_record,
            ),
            nullifier_root: merkle_root_for_strings("nullifiers", &self.nullifiers),
            operator_summary_root: map_root(
                "operator_summaries",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            public_record_root: map_value_root("public_records", &self.public_records),
            state_root: empty_root("pending_state"),
        };
        self.roots.state_root = self.state_root();
    }
    fn seed_devnet(&mut self) {
        let invoice = InvoiceNoteToken {
            invoice_id: "devnet-invoice-001".to_string(),
            note_asset_id: "cinv-devnet-001".to_string(),
            issuer_commitment: demo_hash("issuer", 1),
            debtor_commitment: demo_hash("debtor", 1),
            face_value_commitment: demo_hash("face-value", 1),
            face_value_hint: 1_250_000_000,
            maturity_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_DEVNET_HEIGHT
                    + 7_200,
            token_supply: 1_250_000_000,
            discount_bps: 720,
            haircut_bps: self.config.default_haircut_bps,
            status: InvoiceStatus::Tokenized,
            privacy_set_size: self.config.min_privacy_set_size,
            pq_committee_root: demo_hash("pq-committee", 1),
            encrypted_terms_root: demo_hash("encrypted-terms", 1),
            nullifier_root: demo_hash("invoice-nullifiers", 1),
        };
        let pool = FactoringAmmPool {
            pool_id: "devnet-pool-cinv-usdc-001".to_string(),
            base_asset_id: self.config.settlement_asset_id.clone(),
            note_asset_id: invoice.note_asset_id.clone(),
            sealed_reserve_commitment: demo_hash("sealed-reserve", 1),
            note_reserve_commitment: demo_hash("note-reserve", 1),
            invariant_commitment: demo_hash("invariant", 1),
            lp_token_commitment: demo_hash("lp-token", 1),
            fee_bps: self.config.default_fee_bps,
            discount_bps: 720,
            maturity_height: invoice.maturity_height,
            status: PoolStatus::Active,
            oracle_price_root: demo_hash("oracle-price", 1),
            sealed_liquidity_root: demo_hash("sealed-liquidity", 1),
            collected_fee_credits: 7_500_000,
        };
        let attestation = DebtorOracleAttestation {
            attestation_id: "devnet-attestation-debtor-001".to_string(),
            invoice_id: invoice.invoice_id.clone(),
            kind: AttestationKind::Debtor,
            subject_commitment: invoice.debtor_commitment.clone(),
            statement_root: demo_hash("debtor-statement", 1),
            confidence_bps: 9_650,
            issued_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_DEVNET_HEIGHT,
            expires_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_DEVNET_HEIGHT
                    + self.config.attestation_ttl_blocks,
            pq_signature_root: demo_hash("pq-signature", 1),
            selective_disclosure_root: demo_hash("selective-disclosure", 1),
        };
        let liquidity = SealedLiquidityNote {
            liquidity_id: "devnet-liquidity-001".to_string(),
            pool_id: pool.pool_id.clone(),
            provider_commitment: demo_hash("provider", 1),
            asset_id: self.config.settlement_asset_id.clone(),
            amount_commitment: demo_hash("liquidity-amount", 1),
            amount_hint: 900_000_000,
            fee_credit_commitment: demo_hash("fee-credit", 1),
            encrypted_position_root: demo_hash("encrypted-position", 1),
            nullifier: demo_hash("liquidity-nullifier", 1),
            opened: false,
        };
        self.invoices.insert(invoice.invoice_id.clone(), invoice);
        self.pools.insert(pool.pool_id.clone(), pool);
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.nullifiers.insert(liquidity.nullifier.clone());
        self.sealed_liquidity
            .insert(liquidity.liquidity_id.clone(), liquidity);
        let _ = self.redact_private_view(PrivacyRedaction {
            view_id: "devnet-redaction-operator-001".to_string(),
            subject_id: "devnet-invoice-001".to_string(),
            redaction_level: "operator_summary_only".to_string(),
            commitment_root: demo_hash("redaction-commitment", 1),
            ciphertext_root: demo_hash("redaction-ciphertext", 1),
            nullifier_root: demo_hash("redaction-nullifier", 1),
            proof_root: demo_hash("redaction-proof", 1),
            effective_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_DEVNET_HEIGHT,
        });
        self.operator_summary(
            "devnet-operator",
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INVOICE_FACTORING_AMM_RUNTIME_DEVNET_HEIGHT,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvoiceCommitmentView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl InvoiceCommitmentView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "invoice_commitment_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-invoice_commitment_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvoiceCashflowView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl InvoiceCashflowView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "invoice_cashflow_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-invoice_cashflow_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DebtorRiskView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl DebtorRiskView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "debtor_risk_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-debtor_risk_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OraclePriceView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl OraclePriceView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_price_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-oracle_price_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PoolReserveView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl PoolReserveView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pool_reserve_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-pool_reserve_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PoolInvariantView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl PoolInvariantView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pool_invariant_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-pool_invariant_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LpPositionView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl LpPositionView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lp_position_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-lp_position_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl FeeCreditView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_credit_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-fee_credit_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceiptView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl SettlementReceiptView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-settlement_receipt_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DefaultScenarioView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl DefaultScenarioView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "default_scenario_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-default_scenario_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InsurerCoverageView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl InsurerCoverageView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "insurer_coverage_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-insurer_coverage_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServicerActionView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl ServicerActionView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "servicer_action_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-servicer_action_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditorTrailView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl AuditorTrailView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "auditor_trail_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-auditor_trail_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosureView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl SelectiveDisclosureView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "selective_disclosure_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-selective_disclosure_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceMemoView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl ComplianceMemoView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compliance_memo_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-compliance_memo_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaturityBucketView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl MaturityBucketView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "maturity_bucket_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-maturity_bucket_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscountCurveView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl DiscountCurveView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "discount_curve_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-discount_curve_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HaircutPolicyView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl HaircutPolicyView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "haircut_policy_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-haircut_policy_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateEpochView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl RebateEpochView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rebate_epoch_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-rebate_epoch_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierSetView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl NullifierSetView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nullifier_set_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-nullifier_set_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommitteeView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl PqCommitteeView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_committee_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-pq_committee_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedMemoView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedMemoView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_memo_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-encrypted_memo_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchAuctionView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl BatchAuctionView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "batch_auction_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-batch_auction_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeLaneView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeLaneView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_lane_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-low_fee_lane_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyBudgetView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-privacy_budget_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityDepthView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl LiquidityDepthView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_depth_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-liquidity_depth_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvoiceAgingView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl InvoiceAgingView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "invoice_aging_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-invoice_aging_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DebtorConcentrationView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl DebtorConcentrationView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "debtor_concentration_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-debtor_concentration_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CountryRiskView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl CountryRiskView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "country_risk_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-country_risk_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IndustryRiskView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl IndustryRiskView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "industry_risk_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-industry_risk_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaymentRailView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl PaymentRailView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "payment_rail_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-payment_rail_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditInsuranceView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl CreditInsuranceView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "credit_insurance_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-credit_insurance_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisputeCaseView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl DisputeCaseView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dispute_case_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-dispute_case_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryWaterfallView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl RecoveryWaterfallView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recovery_waterfall_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-recovery_waterfall_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveProofView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl ReserveProofView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_proof_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-reserve_proof_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KycRedactionView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl KycRedactionView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "kyc_redaction_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-kyc_redaction_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SanctionsScreenView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl SanctionsScreenView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sanctions_screen_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-sanctions_screen_view",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorRiskView {
    pub view_id: String,
    pub subject_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl OperatorRiskView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_risk_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "private-l2-pq-confidential-tokenized-invoice-factoring-amm-runtime-operator_risk_view",
            &self.public_record(),
        )
    }
}

fn records<I>(records: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    records.into_iter().collect::<Vec<_>>()
}

fn value_band(value: u128) -> String {
    match value {
        0 => "zero".to_string(),
        1..=999_999 => "micro".to_string(),
        1_000_000..=99_999_999 => "small".to_string(),
        100_000_000..=9_999_999_999 => "middle".to_string(),
        10_000_000_000..=999_999_999_999 => "large".to_string(),
        _ => "institutional".to_string(),
    }
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:{domain}:empty"),
        &[HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}
fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:{domain}:record"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}
fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:state-root"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}
pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:public-record-root"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}
fn deterministic_id(domain: &str, record: &Value, sequence: u64) -> String {
    let root = domain_hash(
        &format!("{PROTOCOL_VERSION}:{domain}:id"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
            HashPart::U64(sequence),
        ],
        16,
    );
    format!("{domain}-{root}")
}
fn demo_hash(domain: &str, sequence: u64) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:devnet:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::U64(sequence)],
        32,
    )
}
fn short_hash(value: &str) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:short"),
        &[HashPart::Str(value)],
        6,
    )
}
fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &leaves)
}
fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &leaves)
}
fn merkle_root_for_strings(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &leaves)
}
