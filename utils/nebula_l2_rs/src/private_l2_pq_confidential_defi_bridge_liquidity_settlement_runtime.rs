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
    "nebula-private-l2-pq-confidential-defi-bridge-liquidity-settlement-runtime-v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const CONFIDENTIAL_SETTLEMENT_SUITE: &str =
    "roots-only-confidential-defi-bridge-liquidity-settlement-v1";
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub max_bridge_fee_bps: u64,
    pub max_slippage_bps: u64,
    pub max_price_impact_bps: u64,
    pub min_reserve_ratio_bps: u64,
    pub liquidation_health_floor_bps: u64,
    pub rebate_floor_bps: u64,
    pub batch_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            min_pq_security_bits: 256,
            min_privacy_set_size: 512,
            max_user_fee_bps: 24,
            max_solver_fee_bps: 30,
            max_bridge_fee_bps: 18,
            max_slippage_bps: 80,
            max_price_impact_bps: 150,
            min_reserve_ratio_bps: 8_000,
            liquidation_health_floor_bps: 1_150,
            rebate_floor_bps: 5,
            batch_ttl_blocks: 24,
            settlement_ttl_blocks: 72,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(
            !self.protocol_version.is_empty(),
            "missing protocol version",
        )?;
        require(!self.chain_id.is_empty(), "missing chain id")?;
        require(
            self.min_pq_security_bits >= 192,
            "pq security bits below policy floor",
        )?;
        for (name, value) in [
            ("max_user_fee_bps", self.max_user_fee_bps),
            ("max_solver_fee_bps", self.max_solver_fee_bps),
            ("max_bridge_fee_bps", self.max_bridge_fee_bps),
            ("max_slippage_bps", self.max_slippage_bps),
            ("max_price_impact_bps", self.max_price_impact_bps),
            ("min_reserve_ratio_bps", self.min_reserve_ratio_bps),
            (
                "liquidation_health_floor_bps",
                self.liquidation_health_floor_bps,
            ),
            ("rebate_floor_bps", self.rebate_floor_bps),
        ] {
            require(value <= MAX_BPS, &format!("{name} above bps scale"))?;
        }
        require(
            self.min_privacy_set_size > 0,
            "privacy set must be positive",
        )?;
        require(self.batch_ttl_blocks > 0, "batch ttl must be positive")?;
        require(
            self.settlement_ttl_blocks >= self.batch_ttl_blocks,
            "settlement ttl below batch ttl",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub height: u64,
    pub sequence: u64,
    pub intents: u64,
    pub pools: u64,
    pub routers: u64,
    pub reserve_proofs: u64,
    pub commitments: u64,
    pub batches: u64,
    pub manifests: u64,
    pub rebates: u64,
    pub risk_fences: u64,
    pub nullifier_fences: u64,
    pub slashes: u64,
    pub events: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            height: 1_920_000,
            sequence: 0,
            intents: 0,
            pools: 0,
            routers: 0,
            reserve_proofs: 0,
            commitments: 0,
            batches: 0,
            manifests: 0,
            rebates: 0,
            risk_fences: 0,
            nullifier_fences: 0,
            slashes: 0,
            events: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub intent_root: String,
    pub pool_root: String,
    pub router_root: String,
    pub reserve_proof_root: String,
    pub commitment_root: String,
    pub solver_batch_root: String,
    pub defi_settlement_root: String,
    pub manifest_root: String,
    pub rebate_root: String,
    pub risk_fence_root: String,
    pub nullifier_fence_root: String,
    pub slashing_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Swap,
    BridgeIn,
    BridgeOut,
    AmmThenBridge,
    BridgeThenAmm,
    LiquidationBackstop,
    CrossContractDefi,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Admitted,
    Batched,
    Settled,
    Rebated,
    Fenced,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RouterKind {
    MoneroReserve,
    ConfidentialAmm,
    CrossRollup,
    StableSwap,
    Darkpool,
    Vault,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    BadReserveProof,
    SlippageExceeded,
    MissingLiquidity,
    StaleQuote,
    NullifierReplay,
    DefiRootMismatch,
    BridgeExecutionMismatch,
    LiquidationFenceBreach,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlippageBounds {
    pub max_slippage_bps: u64,
    pub max_price_impact_bps: u64,
    pub min_output_commitment: String,
    pub deadline_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyBounds {
    pub min_privacy_set_size: u64,
    pub decoy_commitment_root: String,
    pub nullifier_domain: String,
    pub view_tag_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateLiquidityIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub kind: IntentKind,
    pub input_asset: String,
    pub output_asset: String,
    pub sealed_amount_commitment: String,
    pub route_hint_commitment: String,
    pub fee_sponsor_id: String,
    pub slippage: SlippageBounds,
    pub privacy: PrivacyBounds,
    pub nullifiers: BTreeSet<String>,
    pub status: IntentStatus,
    pub admitted_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoolReserveCommitment {
    pub pool_id: String,
    pub token_a: String,
    pub token_b: String,
    pub reserve_commitment_a: String,
    pub reserve_commitment_b: String,
    pub fee_bps: u64,
    pub amplification_bps: u64,
    pub invariant_root: String,
    pub oracle_root: String,
    pub updated_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeLiquidityRouter {
    pub router_id: String,
    pub kind: RouterKind,
    pub operator_commitment: String,
    pub supported_assets: BTreeSet<String>,
    pub liquidity_root: String,
    pub quote_root: String,
    pub max_fee_bps: u64,
    pub pq_attestation_root: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MoneroReserveProof {
    pub proof_id: String,
    pub router_id: String,
    pub reserve_commitment: String,
    pub key_image_root: String,
    pub output_set_root: String,
    pub view_key_audit_root: String,
    pub min_confirmations: u64,
    pub reserve_ratio_bps: u64,
    pub monero_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolverBatch {
    pub batch_id: String,
    pub solver_commitment: String,
    pub intent_ids: BTreeSet<String>,
    pub router_ids: BTreeSet<String>,
    pub pool_ids: BTreeSet<String>,
    pub quote_root: String,
    pub route_root: String,
    pub netting_root: String,
    pub expected_surplus_commitment: String,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossContractSettlementRoot {
    pub settlement_id: String,
    pub contract_roots: BTreeMap<String, String>,
    pub call_graph_root: String,
    pub token_delta_root: String,
    pub vault_delta_root: String,
    pub risk_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NettedSettlementManifest {
    pub manifest_id: String,
    pub batch_id: String,
    pub defi_settlement_id: String,
    pub reserve_proof_ids: BTreeSet<String>,
    pub input_nullifier_root: String,
    pub output_note_root: String,
    pub netted_asset_delta_root: String,
    pub bridge_release_root: String,
    pub finality_certificate_root: String,
    pub settled_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeSponsorRebate {
    pub rebate_id: String,
    pub sponsor_id: String,
    pub manifest_id: String,
    pub beneficiary_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub reason_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskFence {
    pub fence_id: String,
    pub subject_id: String,
    pub liquidation_health_bps: u64,
    pub exposure_commitment: String,
    pub oracle_root: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NullifierFence {
    pub nullifier_id: String,
    pub domain: String,
    pub subject_id: String,
    pub seen_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub offender_id: String,
    pub manifest_id: String,
    pub kind: EvidenceKind,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub witness_root: String,
    pub penalty_commitment: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub intents: BTreeMap<String, PrivateLiquidityIntent>,
    pub pools: BTreeMap<String, PoolReserveCommitment>,
    pub routers: BTreeMap<String, BridgeLiquidityRouter>,
    pub reserve_proofs: BTreeMap<String, MoneroReserveProof>,
    pub solver_batches: BTreeMap<String, SolverBatch>,
    pub defi_settlements: BTreeMap<String, CrossContractSettlementRoot>,
    pub manifests: BTreeMap<String, NettedSettlementManifest>,
    pub rebates: BTreeMap<String, FeeSponsorRebate>,
    pub risk_fences: BTreeMap<String, RiskFence>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::devnet(),
            roots: empty_roots(),
            intents: BTreeMap::new(),
            pools: BTreeMap::new(),
            routers: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            solver_batches: BTreeMap::new(),
            defi_settlements: BTreeMap::new(),
            manifests: BTreeMap::new(),
            rebates: BTreeMap::new(),
            risk_fences: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).unwrap_or_else(|error| {
            let fallback = Config {
                protocol_version: format!("{PROTOCOL_VERSION}-{error}"),
                ..Config::devnet()
            };
            Self {
                config: fallback,
                counters: Counters::devnet(),
                roots: empty_roots(),
                intents: BTreeMap::new(),
                pools: BTreeMap::new(),
                routers: BTreeMap::new(),
                reserve_proofs: BTreeMap::new(),
                solver_batches: BTreeMap::new(),
                defi_settlements: BTreeMap::new(),
                manifests: BTreeMap::new(),
                rebates: BTreeMap::new(),
                risk_fences: BTreeMap::new(),
                nullifier_fences: BTreeMap::new(),
                slashing_evidence: BTreeMap::new(),
                spent_nullifiers: BTreeSet::new(),
                events: BTreeMap::new(),
            }
        });

        let pool_id = state
            .upsert_pool(
                "XMR",
                "pUSD",
                "devnet-xmr-reserve-a",
                "devnet-pusd-reserve-b",
                8,
                10_000,
                "devnet-cpamm-invariant",
                "devnet-oracle-root",
            )
            .unwrap_or_else(stable_error_id);
        let router_id = state
            .register_router(
                RouterKind::MoneroReserve,
                "devnet-router-operator",
                ["XMR".to_string(), "pUSD".to_string()]
                    .into_iter()
                    .collect(),
                "devnet-liquidity-root",
                "devnet-quote-root",
                12,
                "devnet-pq-attestation-root",
            )
            .unwrap_or_else(stable_error_id);
        let proof_id = state
            .attest_monero_reserve(
                &router_id,
                "devnet-monero-reserve",
                "devnet-key-image-root",
                "devnet-output-set-root",
                "devnet-view-key-audit-root",
                20,
                9_200,
                3_550_000,
            )
            .unwrap_or_else(stable_error_id);
        let intent_id = state
            .admit_intent(IntentDraft {
                owner_commitment: "devnet-owner".to_string(),
                kind: IntentKind::AmmThenBridge,
                input_asset: "pUSD".to_string(),
                output_asset: "XMR".to_string(),
                sealed_amount_commitment: "devnet-sealed-amount".to_string(),
                route_hint_commitment: "devnet-route-hint".to_string(),
                fee_sponsor_id: "devnet-sponsor".to_string(),
                slippage: SlippageBounds {
                    max_slippage_bps: 45,
                    max_price_impact_bps: 90,
                    min_output_commitment: "devnet-min-output".to_string(),
                    deadline_height: state.counters.height + 32,
                },
                privacy: PrivacyBounds {
                    min_privacy_set_size: 1_024,
                    decoy_commitment_root: "devnet-decoy-root".to_string(),
                    nullifier_domain: "devnet-intent-domain".to_string(),
                    view_tag_root: "devnet-view-tag-root".to_string(),
                },
                nullifiers: ["devnet-nullifier-0".to_string()].into_iter().collect(),
            })
            .unwrap_or_else(stable_error_id);
        let batch_id = state
            .open_solver_batch(
                "devnet-solver",
                [intent_id.clone()].into_iter().collect(),
                [router_id.clone()].into_iter().collect(),
                [pool_id].into_iter().collect(),
                "devnet-quote-root",
                "devnet-route-root",
                "devnet-netting-root",
                "devnet-surplus",
            )
            .unwrap_or_else(stable_error_id);
        let settlement_id = state
            .record_defi_settlement(
                [("swap-vault".to_string(), "devnet-vault-root".to_string())]
                    .into_iter()
                    .collect(),
                "devnet-call-graph",
                "devnet-token-delta",
                "devnet-vault-delta",
                "devnet-risk-root",
            )
            .unwrap_or_else(stable_error_id);
        let manifest_id = state
            .settle_manifest(
                &batch_id,
                &settlement_id,
                [proof_id].into_iter().collect(),
                "devnet-input-nullifiers",
                "devnet-output-notes",
                "devnet-netted-delta",
                "devnet-bridge-release",
                "devnet-finality",
            )
            .unwrap_or_else(stable_error_id);
        let _ = state.issue_rebate(
            "devnet-sponsor",
            &manifest_id,
            "devnet-owner",
            "devnet-rebate",
            7,
            "devnet-rebate-reason",
        );
        state.refresh_roots();
        state
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "hash_suite": HASH_SUITE,
            "pq_suite": PQ_SUITE,
            "confidential_settlement_suite": CONFIDENTIAL_SETTLEMENT_SUITE,
            "counters": self.counters,
            "roots": self.roots,
        })
    }

    pub fn refresh_roots(&mut self) {
        let config_root = record_id("CONFIG", &json!(self.config));
        let counter_root = record_id("COUNTERS", &json!(self.counters));
        let intent_root = map_root("INTENTS", &self.intents);
        let pool_root = map_root("POOLS", &self.pools);
        let router_root = map_root("ROUTERS", &self.routers);
        let reserve_proof_root = map_root("RESERVE-PROOFS", &self.reserve_proofs);
        let commitment_root = merkle_root(
            "PRIVATE-L2-PQ-DEFI-BRIDGE-COMMITMENTS",
            &[json!({
                "pool_root": pool_root,
                "reserve_proof_root": reserve_proof_root,
                "spent_nullifier_root": set_root("SPENT-NULLIFIERS", &self.spent_nullifiers),
            })],
        );
        let solver_batch_root = map_root("SOLVER-BATCHES", &self.solver_batches);
        let defi_settlement_root = map_root("DEFI-SETTLEMENTS", &self.defi_settlements);
        let manifest_root = map_root("MANIFESTS", &self.manifests);
        let rebate_root = map_root("REBATES", &self.rebates);
        let risk_fence_root = map_root("RISK-FENCES", &self.risk_fences);
        let nullifier_fence_root = map_root("NULLIFIER-FENCES", &self.nullifier_fences);
        let slashing_root = map_root("SLASHING", &self.slashing_evidence);
        let event_root = map_root("EVENTS", &self.events);
        let public_record_root = merkle_root(
            "PRIVATE-L2-PQ-DEFI-BRIDGE-PUBLIC-RECORD",
            &[json!({
                "config_root": config_root,
                "counter_root": counter_root,
                "intent_root": intent_root,
                "manifest_root": manifest_root,
                "slashing_root": slashing_root,
            })],
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-DEFI-BRIDGE-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&public_record_root),
                HashPart::Str(&event_root),
            ],
            32,
        );
        self.roots = Roots {
            config_root,
            counter_root,
            intent_root,
            pool_root,
            router_root,
            reserve_proof_root,
            commitment_root,
            solver_batch_root,
            defi_settlement_root,
            manifest_root,
            rebate_root,
            risk_fence_root,
            nullifier_fence_root,
            slashing_root,
            event_root,
            public_record_root,
            state_root,
        };
    }

    pub fn upsert_pool(
        &mut self,
        token_a: &str,
        token_b: &str,
        reserve_commitment_a: &str,
        reserve_commitment_b: &str,
        fee_bps: u64,
        amplification_bps: u64,
        invariant_root: &str,
        oracle_root: &str,
    ) -> Result<String> {
        require(
            fee_bps <= self.config.max_solver_fee_bps,
            "pool fee too high",
        )?;
        let record = json!({
            "token_a": token_a,
            "token_b": token_b,
            "reserve_commitment_a": reserve_commitment_a,
            "reserve_commitment_b": reserve_commitment_b,
            "fee_bps": fee_bps,
            "amplification_bps": amplification_bps,
            "invariant_root": invariant_root,
            "oracle_root": oracle_root,
            "height": self.counters.height,
        });
        let pool_id = deterministic_id("POOL", &record);
        self.pools.insert(
            pool_id.clone(),
            PoolReserveCommitment {
                pool_id: pool_id.clone(),
                token_a: token_a.to_string(),
                token_b: token_b.to_string(),
                reserve_commitment_a: reserve_commitment_a.to_string(),
                reserve_commitment_b: reserve_commitment_b.to_string(),
                fee_bps,
                amplification_bps,
                invariant_root: invariant_root.to_string(),
                oracle_root: oracle_root.to_string(),
                updated_height: self.counters.height,
            },
        );
        self.counters.pools = self.pools.len() as u64;
        self.record_event("pool_upserted", &pool_id);
        Ok(pool_id)
    }

    pub fn register_router(
        &mut self,
        kind: RouterKind,
        operator_commitment: &str,
        supported_assets: BTreeSet<String>,
        liquidity_root: &str,
        quote_root: &str,
        max_fee_bps: u64,
        pq_attestation_root: &str,
    ) -> Result<String> {
        require(!supported_assets.is_empty(), "router supports no assets")?;
        require(
            max_fee_bps <= self.config.max_bridge_fee_bps,
            "router fee too high",
        )?;
        let record = json!({
            "kind": kind,
            "operator_commitment": operator_commitment,
            "supported_assets": supported_assets,
            "liquidity_root": liquidity_root,
            "quote_root": quote_root,
            "max_fee_bps": max_fee_bps,
            "pq_attestation_root": pq_attestation_root,
        });
        let router_id = deterministic_id("ROUTER", &record);
        self.routers.insert(
            router_id.clone(),
            BridgeLiquidityRouter {
                router_id: router_id.clone(),
                kind,
                operator_commitment: operator_commitment.to_string(),
                supported_assets,
                liquidity_root: liquidity_root.to_string(),
                quote_root: quote_root.to_string(),
                max_fee_bps,
                pq_attestation_root: pq_attestation_root.to_string(),
                active: true,
            },
        );
        self.counters.routers = self.routers.len() as u64;
        self.record_event("router_registered", &router_id);
        Ok(router_id)
    }

    pub fn attest_monero_reserve(
        &mut self,
        router_id: &str,
        reserve_commitment: &str,
        key_image_root: &str,
        output_set_root: &str,
        view_key_audit_root: &str,
        min_confirmations: u64,
        reserve_ratio_bps: u64,
        monero_height: u64,
    ) -> Result<String> {
        let router = self
            .routers
            .get(router_id)
            .ok_or_else(|| format!("unknown router {router_id}"))?;
        require(router.active, "router inactive")?;
        require(
            matches!(router.kind, RouterKind::MoneroReserve),
            "router is not monero reserve router",
        )?;
        require(
            reserve_ratio_bps >= self.config.min_reserve_ratio_bps,
            "reserve ratio below floor",
        )?;
        let record = json!({
            "router_id": router_id,
            "reserve_commitment": reserve_commitment,
            "key_image_root": key_image_root,
            "output_set_root": output_set_root,
            "view_key_audit_root": view_key_audit_root,
            "min_confirmations": min_confirmations,
            "reserve_ratio_bps": reserve_ratio_bps,
            "monero_height": monero_height,
        });
        let proof_id = deterministic_id("MONERO-RESERVE-PROOF", &record);
        self.reserve_proofs.insert(
            proof_id.clone(),
            MoneroReserveProof {
                proof_id: proof_id.clone(),
                router_id: router_id.to_string(),
                reserve_commitment: reserve_commitment.to_string(),
                key_image_root: key_image_root.to_string(),
                output_set_root: output_set_root.to_string(),
                view_key_audit_root: view_key_audit_root.to_string(),
                min_confirmations,
                reserve_ratio_bps,
                monero_height,
            },
        );
        self.counters.reserve_proofs = self.reserve_proofs.len() as u64;
        self.record_event("reserve_attested", &proof_id);
        Ok(proof_id)
    }

    pub fn admit_intent(&mut self, draft: IntentDraft) -> Result<String> {
        require(
            draft.slippage.max_slippage_bps <= self.config.max_slippage_bps,
            "intent slippage too high",
        )?;
        require(
            draft.slippage.max_price_impact_bps <= self.config.max_price_impact_bps,
            "intent price impact too high",
        )?;
        require(
            draft.privacy.min_privacy_set_size >= self.config.min_privacy_set_size,
            "intent privacy set too small",
        )?;
        require(
            draft.slippage.deadline_height > self.counters.height,
            "intent deadline expired",
        )?;
        for nullifier in &draft.nullifiers {
            require(
                !self.spent_nullifiers.contains(nullifier),
                "intent nullifier already spent",
            )?;
            require(
                !self.nullifier_fences.contains_key(nullifier),
                "intent nullifier already fenced",
            )?;
        }
        let record = json!({
            "owner_commitment": draft.owner_commitment,
            "kind": draft.kind,
            "input_asset": draft.input_asset,
            "output_asset": draft.output_asset,
            "sealed_amount_commitment": draft.sealed_amount_commitment,
            "route_hint_commitment": draft.route_hint_commitment,
            "fee_sponsor_id": draft.fee_sponsor_id,
            "slippage": draft.slippage,
            "privacy": draft.privacy,
            "nullifiers": draft.nullifiers,
            "height": self.counters.height,
        });
        let intent_id = deterministic_id("PRIVATE-LIQUIDITY-INTENT", &record);
        let draft: IntentDraft = serde_json::from_value(record_value(&record)).map_err(to_err)?;
        self.intents.insert(
            intent_id.clone(),
            PrivateLiquidityIntent {
                intent_id: intent_id.clone(),
                owner_commitment: draft.owner_commitment,
                kind: draft.kind,
                input_asset: draft.input_asset,
                output_asset: draft.output_asset,
                sealed_amount_commitment: draft.sealed_amount_commitment,
                route_hint_commitment: draft.route_hint_commitment,
                fee_sponsor_id: draft.fee_sponsor_id,
                slippage: draft.slippage,
                privacy: draft.privacy,
                nullifiers: draft.nullifiers,
                status: IntentStatus::Admitted,
                admitted_height: self.counters.height,
            },
        );
        self.counters.intents = self.intents.len() as u64;
        self.record_event("intent_admitted", &intent_id);
        Ok(intent_id)
    }

    pub fn open_solver_batch(
        &mut self,
        solver_commitment: &str,
        intent_ids: BTreeSet<String>,
        router_ids: BTreeSet<String>,
        pool_ids: BTreeSet<String>,
        quote_root: &str,
        route_root: &str,
        netting_root: &str,
        expected_surplus_commitment: &str,
    ) -> Result<String> {
        require(!intent_ids.is_empty(), "batch has no intents")?;
        for id in &intent_ids {
            let intent = self
                .intents
                .get(id)
                .ok_or_else(|| format!("unknown intent {id}"))?;
            require(
                intent.status == IntentStatus::Admitted,
                "intent not admitted",
            )?;
            require(
                intent.slippage.deadline_height >= self.counters.height,
                "intent deadline expired",
            )?;
        }
        for id in &router_ids {
            require(self.routers.contains_key(id), "unknown router in batch")?;
        }
        for id in &pool_ids {
            require(self.pools.contains_key(id), "unknown pool in batch")?;
        }
        let expires_height = self.counters.height + self.config.batch_ttl_blocks;
        let record = json!({
            "solver_commitment": solver_commitment,
            "intent_ids": intent_ids,
            "router_ids": router_ids,
            "pool_ids": pool_ids,
            "quote_root": quote_root,
            "route_root": route_root,
            "netting_root": netting_root,
            "expected_surplus_commitment": expected_surplus_commitment,
            "expires_height": expires_height,
        });
        let batch_id = deterministic_id("AMM-SOLVER-BATCH", &record);
        let intent_ids = set_from_record(&record, "intent_ids")?;
        let router_ids = set_from_record(&record, "router_ids")?;
        let pool_ids = set_from_record(&record, "pool_ids")?;
        for id in &intent_ids {
            if let Some(intent) = self.intents.get_mut(id) {
                intent.status = IntentStatus::Batched;
            }
        }
        self.solver_batches.insert(
            batch_id.clone(),
            SolverBatch {
                batch_id: batch_id.clone(),
                solver_commitment: solver_commitment.to_string(),
                intent_ids,
                router_ids,
                pool_ids,
                quote_root: quote_root.to_string(),
                route_root: route_root.to_string(),
                netting_root: netting_root.to_string(),
                expected_surplus_commitment: expected_surplus_commitment.to_string(),
                expires_height,
            },
        );
        self.counters.batches = self.solver_batches.len() as u64;
        self.record_event("solver_batch_opened", &batch_id);
        Ok(batch_id)
    }

    pub fn record_defi_settlement(
        &mut self,
        contract_roots: BTreeMap<String, String>,
        call_graph_root: &str,
        token_delta_root: &str,
        vault_delta_root: &str,
        risk_root: &str,
    ) -> Result<String> {
        require(
            !contract_roots.is_empty(),
            "settlement has no contract roots",
        )?;
        let record = json!({
            "contract_roots": contract_roots,
            "call_graph_root": call_graph_root,
            "token_delta_root": token_delta_root,
            "vault_delta_root": vault_delta_root,
            "risk_root": risk_root,
        });
        let settlement_id = deterministic_id("CROSS-CONTRACT-DEFI-SETTLEMENT", &record);
        let contract_roots = map_from_record(&record, "contract_roots")?;
        self.defi_settlements.insert(
            settlement_id.clone(),
            CrossContractSettlementRoot {
                settlement_id: settlement_id.clone(),
                contract_roots,
                call_graph_root: call_graph_root.to_string(),
                token_delta_root: token_delta_root.to_string(),
                vault_delta_root: vault_delta_root.to_string(),
                risk_root: risk_root.to_string(),
            },
        );
        self.record_event("defi_settlement_recorded", &settlement_id);
        Ok(settlement_id)
    }

    pub fn settle_manifest(
        &mut self,
        batch_id: &str,
        defi_settlement_id: &str,
        reserve_proof_ids: BTreeSet<String>,
        input_nullifier_root: &str,
        output_note_root: &str,
        netted_asset_delta_root: &str,
        bridge_release_root: &str,
        finality_certificate_root: &str,
    ) -> Result<String> {
        let batch = self
            .solver_batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown batch {batch_id}"))?;
        require(
            batch.expires_height >= self.counters.height,
            "batch expired before settlement",
        )?;
        require(
            self.defi_settlements.contains_key(defi_settlement_id),
            "unknown defi settlement",
        )?;
        for id in &reserve_proof_ids {
            require(
                self.reserve_proofs.contains_key(id),
                "unknown reserve proof",
            )?;
        }
        let manifest_record = json!({
            "batch_id": batch_id,
            "defi_settlement_id": defi_settlement_id,
            "reserve_proof_ids": reserve_proof_ids,
            "input_nullifier_root": input_nullifier_root,
            "output_note_root": output_note_root,
            "netted_asset_delta_root": netted_asset_delta_root,
            "bridge_release_root": bridge_release_root,
            "finality_certificate_root": finality_certificate_root,
            "settled_height": self.counters.height,
        });
        let manifest_id = deterministic_id("NETTED-SETTLEMENT-MANIFEST", &manifest_record);
        let reserve_proof_ids = set_from_record(&manifest_record, "reserve_proof_ids")?;
        let intent_ids = batch.intent_ids.clone();
        for id in &intent_ids {
            if let Some(intent) = self.intents.get_mut(id) {
                for nullifier in &intent.nullifiers {
                    self.spent_nullifiers.insert(nullifier.clone());
                }
                intent.status = IntentStatus::Settled;
            }
        }
        self.manifests.insert(
            manifest_id.clone(),
            NettedSettlementManifest {
                manifest_id: manifest_id.clone(),
                batch_id: batch_id.to_string(),
                defi_settlement_id: defi_settlement_id.to_string(),
                reserve_proof_ids,
                input_nullifier_root: input_nullifier_root.to_string(),
                output_note_root: output_note_root.to_string(),
                netted_asset_delta_root: netted_asset_delta_root.to_string(),
                bridge_release_root: bridge_release_root.to_string(),
                finality_certificate_root: finality_certificate_root.to_string(),
                settled_height: self.counters.height,
            },
        );
        self.counters.manifests = self.manifests.len() as u64;
        self.record_event("manifest_settled", &manifest_id);
        Ok(manifest_id)
    }

    pub fn issue_rebate(
        &mut self,
        sponsor_id: &str,
        manifest_id: &str,
        beneficiary_commitment: &str,
        rebate_commitment: &str,
        rebate_bps: u64,
        reason_root: &str,
    ) -> Result<String> {
        require(self.manifests.contains_key(manifest_id), "unknown manifest")?;
        require(
            rebate_bps >= self.config.rebate_floor_bps,
            "rebate below floor",
        )?;
        require(
            rebate_bps <= self.config.max_user_fee_bps,
            "rebate above fee cap",
        )?;
        let record = json!({
            "sponsor_id": sponsor_id,
            "manifest_id": manifest_id,
            "beneficiary_commitment": beneficiary_commitment,
            "rebate_commitment": rebate_commitment,
            "rebate_bps": rebate_bps,
            "reason_root": reason_root,
        });
        let rebate_id = deterministic_id("FEE-SPONSOR-REBATE", &record);
        self.rebates.insert(
            rebate_id.clone(),
            FeeSponsorRebate {
                rebate_id: rebate_id.clone(),
                sponsor_id: sponsor_id.to_string(),
                manifest_id: manifest_id.to_string(),
                beneficiary_commitment: beneficiary_commitment.to_string(),
                rebate_commitment: rebate_commitment.to_string(),
                rebate_bps,
                reason_root: reason_root.to_string(),
            },
        );
        self.counters.rebates = self.rebates.len() as u64;
        self.record_event("rebate_issued", &rebate_id);
        Ok(rebate_id)
    }

    pub fn add_risk_fence(
        &mut self,
        subject_id: &str,
        liquidation_health_bps: u64,
        exposure_commitment: &str,
        oracle_root: &str,
    ) -> Result<String> {
        require(
            liquidation_health_bps >= self.config.liquidation_health_floor_bps,
            "liquidation health below floor",
        )?;
        let record = json!({
            "subject_id": subject_id,
            "liquidation_health_bps": liquidation_health_bps,
            "exposure_commitment": exposure_commitment,
            "oracle_root": oracle_root,
        });
        let fence_id = deterministic_id("LIQUIDATION-RISK-FENCE", &record);
        self.risk_fences.insert(
            fence_id.clone(),
            RiskFence {
                fence_id: fence_id.clone(),
                subject_id: subject_id.to_string(),
                liquidation_health_bps,
                exposure_commitment: exposure_commitment.to_string(),
                oracle_root: oracle_root.to_string(),
                active: true,
            },
        );
        self.counters.risk_fences = self.risk_fences.len() as u64;
        self.record_event("risk_fence_added", &fence_id);
        Ok(fence_id)
    }

    pub fn add_nullifier_fence(
        &mut self,
        domain: &str,
        subject_id: &str,
        nullifier: &str,
    ) -> Result<String> {
        require(
            !self.spent_nullifiers.contains(nullifier),
            "nullifier already spent",
        )?;
        let nullifier_id = deterministic_id(
            "NULLIFIER-FENCE",
            &json!({"domain": domain, "subject_id": subject_id, "nullifier": nullifier}),
        );
        self.nullifier_fences.insert(
            nullifier.to_string(),
            NullifierFence {
                nullifier_id: nullifier_id.clone(),
                domain: domain.to_string(),
                subject_id: subject_id.to_string(),
                seen_height: self.counters.height,
            },
        );
        self.counters.nullifier_fences = self.nullifier_fences.len() as u64;
        self.record_event("nullifier_fenced", &nullifier_id);
        Ok(nullifier_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        offender_id: &str,
        manifest_id: &str,
        kind: EvidenceKind,
        pre_state_root: &str,
        post_state_root: &str,
        witness_root: &str,
        penalty_commitment: &str,
    ) -> Result<String> {
        require(self.manifests.contains_key(manifest_id), "unknown manifest")?;
        let record = json!({
            "offender_id": offender_id,
            "manifest_id": manifest_id,
            "kind": kind,
            "pre_state_root": pre_state_root,
            "post_state_root": post_state_root,
            "witness_root": witness_root,
            "penalty_commitment": penalty_commitment,
        });
        let evidence_id = deterministic_id("SLASHING-EVIDENCE", &record);
        self.slashing_evidence.insert(
            evidence_id.clone(),
            SlashingEvidence {
                evidence_id: evidence_id.clone(),
                offender_id: offender_id.to_string(),
                manifest_id: manifest_id.to_string(),
                kind,
                pre_state_root: pre_state_root.to_string(),
                post_state_root: post_state_root.to_string(),
                witness_root: witness_root.to_string(),
                penalty_commitment: penalty_commitment.to_string(),
                accepted: true,
            },
        );
        self.counters.slashes = self.slashing_evidence.len() as u64;
        self.record_event("slashing_evidence_accepted", &evidence_id);
        Ok(evidence_id)
    }

    fn record_event(&mut self, kind: &str, subject_id: &str) {
        self.counters.sequence = self.counters.sequence.saturating_add(1);
        let event = json!({
            "sequence": self.counters.sequence,
            "height": self.counters.height,
            "kind": kind,
            "subject_id": subject_id,
            "pre_root": self.roots.state_root,
        });
        let event_id = deterministic_id("EVENT", &event);
        self.events.insert(event_id, event);
        self.counters.events = self.events.len() as u64;
        self.refresh_roots();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentDraft {
    pub owner_commitment: String,
    pub kind: IntentKind,
    pub input_asset: String,
    pub output_asset: String,
    pub sealed_amount_commitment: String,
    pub route_hint_commitment: String,
    pub fee_sponsor_id: String,
    pub slippage: SlippageBounds,
    pub privacy: PrivacyBounds,
    pub nullifiers: BTreeSet<String>,
}

pub fn deterministic_id(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-DEFI-BRIDGE-ID-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn record_id(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-DEFI-BRIDGE-RECORD-{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn value_root(domain: &str, values: &[Value]) -> String {
    merkle_root(&format!("PRIVATE-L2-PQ-DEFI-BRIDGE-{domain}"), values)
}

pub fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    value_root(domain, &leaves)
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    value_root(domain, &leaves)
}

pub fn root_bundle(label: &str, roots: &BTreeMap<String, String>) -> String {
    let leaves = roots
        .iter()
        .map(|(key, value)| json!({"name": key, "root": value}))
        .collect::<Vec<_>>();
    value_root(label, &leaves)
}

fn empty_roots() -> Roots {
    let empty = value_root("EMPTY", &[]);
    Roots {
        config_root: empty.clone(),
        counter_root: empty.clone(),
        intent_root: empty.clone(),
        pool_root: empty.clone(),
        router_root: empty.clone(),
        reserve_proof_root: empty.clone(),
        commitment_root: empty.clone(),
        solver_batch_root: empty.clone(),
        defi_settlement_root: empty.clone(),
        manifest_root: empty.clone(),
        rebate_root: empty.clone(),
        risk_fence_root: empty.clone(),
        nullifier_fence_root: empty.clone(),
        slashing_root: empty.clone(),
        event_root: empty.clone(),
        public_record_root: empty.clone(),
        state_root: empty,
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn record_value(value: &Value) -> Value {
    value.clone()
}

fn to_err(error: serde_json::Error) -> String {
    error.to_string()
}

fn stable_error_id(error: String) -> String {
    deterministic_id("DEVNET-ERROR", &json!({"error": error}))
}

fn set_from_record(record: &Value, key: &str) -> Result<BTreeSet<String>> {
    serde_json::from_value(
        record
            .get(key)
            .cloned()
            .ok_or_else(|| format!("missing set field {key}"))?,
    )
    .map_err(to_err)
}

fn map_from_record(record: &Value, key: &str) -> Result<BTreeMap<String, String>> {
    serde_json::from_value(
        record
            .get(key)
            .cloned()
            .ok_or_else(|| format!("missing map field {key}"))?,
    )
    .map_err(to_err)
}
