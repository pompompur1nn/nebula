use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_LIQUIDITY_CONFLICT_RESOLVER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-subaddress-liquidity-conflict-resolver-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SUBADDRESS_LIQUIDITY_CONFLICT_RESOLVER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_RUNTIME_ID: &str =
    "monero-l2-pq-private-subaddress-liquidity-conflict-resolver-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_372_400;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_RESOLVER_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-subaddress-conflict-resolver-v1";
pub const PRIVATE_INTENT_SCHEME: &str =
    "ml-kem-1024-sealed-subaddress-private-liquidity-intent-root-v1";
pub const SUBADDRESS_COHORT_SCHEME: &str =
    "monero-private-subaddress-liquidity-cohort-redacted-root-v1";
pub const DECOY_FLOOR_SCHEME: &str = "monero-conflict-resolver-decoy-floor-root-v1";
pub const SEALED_TICKET_SCHEME: &str = "ml-kem-1024-sealed-liquidity-conflict-ticket-root-v1";
pub const SOLVER_BOND_SCHEME: &str = "pq-private-liquidity-conflict-solver-bond-root-v1";
pub const SETTLEMENT_REBATE_SCHEME: &str = "private-subaddress-conflict-settlement-rebate-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str =
    "operator-safe-liquidity-conflict-redaction-budget-root-v1";
pub const DETERMINISTIC_ROOT_SCHEME: &str =
    "subaddress-liquidity-conflict-resolver-deterministic-root-v1";
pub const REPLAY_DOMAIN: &str =
    "monero-l2-pq-private-subaddress-liquidity-conflict-resolver-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_COHORT_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_TARGET_COHORT_PRIVACY_SET: u64 = 262_144;
pub const DEFAULT_MIN_DECOY_FLOOR: u16 = 48;
pub const DEFAULT_TARGET_DECOY_FLOOR: u16 = 96;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_RESOLUTION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_BOND_LOCK_BLOCKS: u64 = 720;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_REDACTION_BUDGET_PER_EPOCH: u32 = 32;
pub const DEFAULT_MAX_CONFLICT_FEE_BPS: u64 = 18;
pub const DEFAULT_MIN_SOLVER_BOND_PICONERO: u128 = 50_000_000_000;
pub const DEFAULT_MAX_SOLVER_BOND_PICONERO: u128 = 15_000_000_000_000;
pub const DEFAULT_REBATE_BPS: u64 = 7;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MAX_PRIVATE_INTENTS: usize = 65_536;
pub const DEFAULT_MAX_SUBADDRESS_COHORTS: usize = 8_192;
pub const DEFAULT_MAX_DECOY_FLOORS: usize = 65_536;
pub const DEFAULT_MAX_SEALED_TICKETS: usize = 65_536;
pub const DEFAULT_MAX_SOLVER_BONDS: usize = 16_384;
pub const DEFAULT_MAX_RESOLVER_ATTESTATIONS: usize = 65_536;
pub const DEFAULT_MAX_SETTLEMENT_REBATES: usize = 65_536;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 65_536;
pub const DEFAULT_MAX_DETERMINISTIC_CHECKPOINTS: usize = 16_384;

macro_rules! status_enum {
    ($name:ident { $($variant:ident => $label:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }
        }
    };
}

status_enum!(LiquidityIntentKind {
    AddLiquidity => "add_liquidity",
    RemoveLiquidity => "remove_liquidity",
    Rebalance => "rebalance",
    FastExit => "fast_exit",
    DefiRoute => "defi_route",
    EmergencyUnwind => "emergency_unwind",
});

status_enum!(IntentStatus {
    Sealed => "sealed",
    Admitted => "admitted",
    Ticketed => "ticketed",
    Resolving => "resolving",
    Settled => "settled",
    Rebated => "rebated",
    Expired => "expired",
    Rejected => "rejected",
});

status_enum!(CohortStatus {
    Open => "open",
    Saturated => "saturated",
    Resolving => "resolving",
    Quarantined => "quarantined",
    Retired => "retired",
});

status_enum!(ConflictTicketStatus {
    Sealed => "sealed",
    Bonded => "bonded",
    Attested => "attested",
    Settled => "settled",
    Rebated => "rebated",
    Disputed => "disputed",
    Expired => "expired",
    Slashed => "slashed",
});

status_enum!(ConflictClass {
    CohortCapacity => "cohort_capacity",
    DecoyFloorBreach => "decoy_floor_breach",
    LiquidityDoubleSpend => "liquidity_double_spend",
    SolverOverlap => "solver_overlap",
    RebateCollision => "rebate_collision",
    RedactionOverrun => "redaction_overrun",
});

status_enum!(BondStatus {
    Locked => "locked",
    Released => "released",
    Slashed => "slashed",
    Expired => "expired",
});

status_enum!(AttestationRole {
    Resolver => "resolver",
    Solver => "solver",
    Watchtower => "watchtower",
    Auditor => "auditor",
});

status_enum!(AttestationStatus {
    Pending => "pending",
    Accepted => "accepted",
    Superseded => "superseded",
    Rejected => "rejected",
    Slashed => "slashed",
});

status_enum!(RebateStatus {
    Accrued => "accrued",
    Reserved => "reserved",
    Paid => "paid",
    Expired => "expired",
    ClawedBack => "clawed_back",
});

status_enum!(RedactionScope {
    IntentEnvelope => "intent_envelope",
    CohortAggregate => "cohort_aggregate",
    ConflictTicket => "conflict_ticket",
    SolverBond => "solver_bond",
    SettlementRebate => "settlement_rebate",
    OperatorTelemetry => "operator_telemetry",
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub runtime_id: String,
    pub asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub pq_resolver_attestation_suite: String,
    pub private_intent_scheme: String,
    pub subaddress_cohort_scheme: String,
    pub decoy_floor_scheme: String,
    pub sealed_ticket_scheme: String,
    pub solver_bond_scheme: String,
    pub settlement_rebate_scheme: String,
    pub redaction_budget_scheme: String,
    pub deterministic_root_scheme: String,
    pub replay_domain: String,
    pub min_cohort_privacy_set: u64,
    pub target_cohort_privacy_set: u64,
    pub min_decoy_floor: u16,
    pub target_decoy_floor: u16,
    pub min_pq_security_bits: u16,
    pub intent_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub resolution_ttl_blocks: u64,
    pub bond_lock_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub redaction_budget_per_epoch: u32,
    pub max_conflict_fee_bps: u64,
    pub min_solver_bond_piconero: u128,
    pub max_solver_bond_piconero: u128,
    pub rebate_bps: u64,
    pub slash_bps: u64,
    pub max_private_intents: usize,
    pub max_subaddress_cohorts: usize,
    pub max_decoy_floors: usize,
    pub max_sealed_tickets: usize,
    pub max_solver_bonds: usize,
    pub max_resolver_attestations: usize,
    pub max_settlement_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_deterministic_checkpoints: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_resolver_attestation_suite: PQ_RESOLVER_ATTESTATION_SUITE.to_string(),
            private_intent_scheme: PRIVATE_INTENT_SCHEME.to_string(),
            subaddress_cohort_scheme: SUBADDRESS_COHORT_SCHEME.to_string(),
            decoy_floor_scheme: DECOY_FLOOR_SCHEME.to_string(),
            sealed_ticket_scheme: SEALED_TICKET_SCHEME.to_string(),
            solver_bond_scheme: SOLVER_BOND_SCHEME.to_string(),
            settlement_rebate_scheme: SETTLEMENT_REBATE_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            deterministic_root_scheme: DETERMINISTIC_ROOT_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            min_cohort_privacy_set: DEFAULT_MIN_COHORT_PRIVACY_SET,
            target_cohort_privacy_set: DEFAULT_TARGET_COHORT_PRIVACY_SET,
            min_decoy_floor: DEFAULT_MIN_DECOY_FLOOR,
            target_decoy_floor: DEFAULT_TARGET_DECOY_FLOOR,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            resolution_ttl_blocks: DEFAULT_RESOLUTION_TTL_BLOCKS,
            bond_lock_blocks: DEFAULT_BOND_LOCK_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            redaction_budget_per_epoch: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
            max_conflict_fee_bps: DEFAULT_MAX_CONFLICT_FEE_BPS,
            min_solver_bond_piconero: DEFAULT_MIN_SOLVER_BOND_PICONERO,
            max_solver_bond_piconero: DEFAULT_MAX_SOLVER_BOND_PICONERO,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            max_private_intents: DEFAULT_MAX_PRIVATE_INTENTS,
            max_subaddress_cohorts: DEFAULT_MAX_SUBADDRESS_COHORTS,
            max_decoy_floors: DEFAULT_MAX_DECOY_FLOORS,
            max_sealed_tickets: DEFAULT_MAX_SEALED_TICKETS,
            max_solver_bonds: DEFAULT_MAX_SOLVER_BONDS,
            max_resolver_attestations: DEFAULT_MAX_RESOLVER_ATTESTATIONS,
            max_settlement_rebates: DEFAULT_MAX_SETTLEMENT_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_deterministic_checkpoints: DEFAULT_MAX_DETERMINISTIC_CHECKPOINTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "runtime_id": self.runtime_id,
            "asset_id": self.asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": self.hash_suite,
            "pq_resolver_attestation_suite": self.pq_resolver_attestation_suite,
            "private_intent_scheme": self.private_intent_scheme,
            "subaddress_cohort_scheme": self.subaddress_cohort_scheme,
            "decoy_floor_scheme": self.decoy_floor_scheme,
            "sealed_ticket_scheme": self.sealed_ticket_scheme,
            "solver_bond_scheme": self.solver_bond_scheme,
            "settlement_rebate_scheme": self.settlement_rebate_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "deterministic_root_scheme": self.deterministic_root_scheme,
            "replay_domain": self.replay_domain,
            "min_cohort_privacy_set": self.min_cohort_privacy_set,
            "target_cohort_privacy_set": self.target_cohort_privacy_set,
            "min_decoy_floor": self.min_decoy_floor,
            "target_decoy_floor": self.target_decoy_floor,
            "min_pq_security_bits": self.min_pq_security_bits,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "resolution_ttl_blocks": self.resolution_ttl_blocks,
            "bond_lock_blocks": self.bond_lock_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "redaction_budget_per_epoch": self.redaction_budget_per_epoch,
            "max_conflict_fee_bps": self.max_conflict_fee_bps,
            "min_solver_bond_piconero": self.min_solver_bond_piconero.to_string(),
            "max_solver_bond_piconero": self.max_solver_bond_piconero.to_string(),
            "rebate_bps": self.rebate_bps,
            "slash_bps": self.slash_bps,
            "max_private_intents": self.max_private_intents,
            "max_subaddress_cohorts": self.max_subaddress_cohorts,
            "max_decoy_floors": self.max_decoy_floors,
            "max_sealed_tickets": self.max_sealed_tickets,
            "max_solver_bonds": self.max_solver_bonds,
            "max_resolver_attestations": self.max_resolver_attestations,
            "max_settlement_rebates": self.max_settlement_rebates,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_deterministic_checkpoints": self.max_deterministic_checkpoints,
        })
    }

    pub fn validate(
        &self,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unexpected protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unexpected schema version".to_string());
        }
        if self.min_cohort_privacy_set == 0
            || self.target_cohort_privacy_set < self.min_cohort_privacy_set
        {
            return Err("invalid cohort privacy-set bounds".to_string());
        }
        if self.min_decoy_floor == 0 || self.target_decoy_floor < self.min_decoy_floor {
            return Err("invalid decoy floor bounds".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below devnet floor".to_string());
        }
        if self.max_conflict_fee_bps > MAX_BPS
            || self.rebate_bps > MAX_BPS
            || self.slash_bps > MAX_BPS
        {
            return Err("basis-point setting exceeds max".to_string());
        }
        if self.min_solver_bond_piconero == 0
            || self.max_solver_bond_piconero < self.min_solver_bond_piconero
        {
            return Err("invalid solver bond bounds".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub private_intents_admitted: u64,
    pub cohorts_opened: u64,
    pub conflicts_ticketed: u64,
    pub conflicts_settled: u64,
    pub solver_bonds_locked: u64,
    pub solver_bonds_slashed: u64,
    pub pq_attestations_accepted: u64,
    pub settlement_rebates_paid: u64,
    pub decoy_floor_breaches: u64,
    pub redactions_consumed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "private_intents_admitted": self.private_intents_admitted,
            "cohorts_opened": self.cohorts_opened,
            "conflicts_ticketed": self.conflicts_ticketed,
            "conflicts_settled": self.conflicts_settled,
            "solver_bonds_locked": self.solver_bonds_locked,
            "solver_bonds_slashed": self.solver_bonds_slashed,
            "pq_attestations_accepted": self.pq_attestations_accepted,
            "settlement_rebates_paid": self.settlement_rebates_paid,
            "decoy_floor_breaches": self.decoy_floor_breaches,
            "redactions_consumed": self.redactions_consumed,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub private_intent_root: String,
    pub subaddress_cohort_root: String,
    pub decoy_floor_root: String,
    pub sealed_ticket_root: String,
    pub solver_bond_root: String,
    pub resolver_attestation_root: String,
    pub settlement_rebate_root: String,
    pub redaction_budget_root: String,
    pub deterministic_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "private_intent_root": self.private_intent_root,
            "subaddress_cohort_root": self.subaddress_cohort_root,
            "decoy_floor_root": self.decoy_floor_root,
            "sealed_ticket_root": self.sealed_ticket_root,
            "solver_bond_root": self.solver_bond_root,
            "resolver_attestation_root": self.resolver_attestation_root,
            "settlement_rebate_root": self.settlement_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "deterministic_root": self.deterministic_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateLiquidityIntent {
    pub intent_id: String,
    pub intent_kind: LiquidityIntentKind,
    pub status: IntentStatus,
    pub cohort_id: String,
    pub sealed_intent_root: String,
    pub nullifier_root: String,
    pub amount_commitment: String,
    pub min_fill_piconero: u128,
    pub max_fee_bps: u64,
    pub decoy_floor: u16,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl PrivateLiquidityIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "intent_kind": self.intent_kind.as_str(),
            "status": self.status.as_str(),
            "cohort_id": self.cohort_id,
            "sealed_intent_root": self.sealed_intent_root,
            "nullifier_root": self.nullifier_root,
            "amount_commitment": self.amount_commitment,
            "min_fill_piconero": self.min_fill_piconero.to_string(),
            "max_fee_bps": self.max_fee_bps,
            "decoy_floor": self.decoy_floor,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        validate_hash("intent_id", &self.intent_id)?;
        validate_hash("sealed_intent_root", &self.sealed_intent_root)?;
        validate_hash("nullifier_root", &self.nullifier_root)?;
        validate_hash("amount_commitment", &self.amount_commitment)?;
        validate_height_window("intent", self.opened_height, self.expires_height)?;
        if self.max_fee_bps > config.max_conflict_fee_bps {
            return Err("private intent fee exceeds conflict fee cap".to_string());
        }
        if self.decoy_floor < config.min_decoy_floor {
            return Err("private intent decoy floor below minimum".to_string());
        }
        if self.privacy_set_size < config.min_cohort_privacy_set {
            return Err("private intent privacy set below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressCohort {
    pub cohort_id: String,
    pub status: CohortStatus,
    pub subaddress_account: u32,
    pub subaddress_major: u32,
    pub minor_start: u32,
    pub minor_end: u32,
    pub cohort_commitment: String,
    pub encrypted_label_root: String,
    pub aggregate_liquidity_commitment: String,
    pub active_intents: u64,
    pub privacy_set_size: u64,
    pub decoy_floor: u16,
    pub opened_height: u64,
    pub last_resolved_height: u64,
}

impl SubaddressCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "status": self.status.as_str(),
            "subaddress_account": self.subaddress_account,
            "subaddress_major": self.subaddress_major,
            "subaddress_range_width": self.minor_end.saturating_sub(self.minor_start).saturating_add(1),
            "cohort_commitment": self.cohort_commitment,
            "encrypted_label_root": self.encrypted_label_root,
            "aggregate_liquidity_commitment": self.aggregate_liquidity_commitment,
            "active_intents": self.active_intents,
            "privacy_set_size": self.privacy_set_size,
            "decoy_floor": self.decoy_floor,
            "opened_height": self.opened_height,
            "last_resolved_height": self.last_resolved_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        validate_hash("cohort_id", &self.cohort_id)?;
        validate_hash("cohort_commitment", &self.cohort_commitment)?;
        validate_hash("encrypted_label_root", &self.encrypted_label_root)?;
        validate_hash(
            "aggregate_liquidity_commitment",
            &self.aggregate_liquidity_commitment,
        )?;
        if self.minor_end < self.minor_start {
            return Err("subaddress cohort range is inverted".to_string());
        }
        if self.privacy_set_size < config.min_cohort_privacy_set {
            return Err("subaddress cohort privacy set below minimum".to_string());
        }
        if self.decoy_floor < config.min_decoy_floor {
            return Err("subaddress cohort decoy floor below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFloor {
    pub floor_id: String,
    pub cohort_id: String,
    pub floor: u16,
    pub sampled_outputs: u64,
    pub anonymity_set_root: String,
    pub verifier_root: String,
    pub effective_height: u64,
    pub expires_height: u64,
}

impl DecoyFloor {
    pub fn public_record(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "cohort_id": self.cohort_id,
            "floor": self.floor,
            "sampled_outputs": self.sampled_outputs,
            "anonymity_set_root": self.anonymity_set_root,
            "verifier_root": self.verifier_root,
            "effective_height": self.effective_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        validate_hash("floor_id", &self.floor_id)?;
        validate_hash("anonymity_set_root", &self.anonymity_set_root)?;
        validate_hash("verifier_root", &self.verifier_root)?;
        validate_height_window("decoy floor", self.effective_height, self.expires_height)?;
        if self.floor < config.min_decoy_floor {
            return Err("decoy floor below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedConflictTicket {
    pub ticket_id: String,
    pub status: ConflictTicketStatus,
    pub conflict_class: ConflictClass,
    pub cohort_id: String,
    pub intent_ids: BTreeSet<String>,
    pub sealed_ticket_root: String,
    pub evidence_commitment: String,
    pub resolver_hint_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl SealedConflictTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "status": self.status.as_str(),
            "conflict_class": self.conflict_class.as_str(),
            "cohort_id": self.cohort_id,
            "intent_ids": self.intent_ids,
            "sealed_ticket_root": self.sealed_ticket_root,
            "evidence_commitment": self.evidence_commitment,
            "resolver_hint_root": self.resolver_hint_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(
        &self,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        validate_hash("ticket_id", &self.ticket_id)?;
        validate_hash("sealed_ticket_root", &self.sealed_ticket_root)?;
        validate_hash("evidence_commitment", &self.evidence_commitment)?;
        validate_hash("resolver_hint_root", &self.resolver_hint_root)?;
        validate_height_window("sealed ticket", self.opened_height, self.expires_height)?;
        if self.intent_ids.is_empty() {
            return Err("sealed conflict ticket must reference intents".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverBond {
    pub bond_id: String,
    pub ticket_id: String,
    pub solver_id: String,
    pub status: BondStatus,
    pub bond_commitment: String,
    pub amount_piconero: u128,
    pub locked_height: u64,
    pub unlock_height: u64,
}

impl SolverBond {
    pub fn public_record(&self) -> Value {
        json!({
            "bond_id": self.bond_id,
            "ticket_id": self.ticket_id,
            "solver_id": self.solver_id,
            "status": self.status.as_str(),
            "bond_commitment": self.bond_commitment,
            "amount_piconero": self.amount_piconero.to_string(),
            "locked_height": self.locked_height,
            "unlock_height": self.unlock_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        validate_hash("bond_id", &self.bond_id)?;
        validate_hash("solver_id", &self.solver_id)?;
        validate_hash("bond_commitment", &self.bond_commitment)?;
        validate_height_window("solver bond", self.locked_height, self.unlock_height)?;
        if self.amount_piconero < config.min_solver_bond_piconero
            || self.amount_piconero > config.max_solver_bond_piconero
        {
            return Err("solver bond outside configured bounds".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqResolverAttestation {
    pub attestation_id: String,
    pub role: AttestationRole,
    pub status: AttestationStatus,
    pub ticket_id: String,
    pub signer_commitment: String,
    pub pq_public_key_root: String,
    pub resolution_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub attested_height: u64,
}

impl PqResolverAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "ticket_id": self.ticket_id,
            "signer_commitment": self.signer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "resolution_root": self.resolution_root,
            "signature_root": self.signature_root,
            "security_bits": self.security_bits,
            "attested_height": self.attested_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        validate_hash("attestation_id", &self.attestation_id)?;
        validate_hash("signer_commitment", &self.signer_commitment)?;
        validate_hash("pq_public_key_root", &self.pq_public_key_root)?;
        validate_hash("resolution_root", &self.resolution_root)?;
        validate_hash("signature_root", &self.signature_root)?;
        if self.security_bits < config.min_pq_security_bits {
            return Err("resolver attestation below pq security floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRebate {
    pub rebate_id: String,
    pub ticket_id: String,
    pub intent_id: String,
    pub status: RebateStatus,
    pub rebate_commitment: String,
    pub amount_piconero: u128,
    pub rebate_bps: u64,
    pub accrued_height: u64,
    pub expires_height: u64,
}

impl SettlementRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "ticket_id": self.ticket_id,
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "rebate_commitment": self.rebate_commitment,
            "amount_piconero": self.amount_piconero.to_string(),
            "rebate_bps": self.rebate_bps,
            "accrued_height": self.accrued_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        validate_hash("rebate_id", &self.rebate_id)?;
        validate_hash("rebate_commitment", &self.rebate_commitment)?;
        validate_height_window(
            "settlement rebate",
            self.accrued_height,
            self.expires_height,
        )?;
        if self.rebate_bps > config.rebate_bps {
            return Err("settlement rebate exceeds configured rebate bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub scope: RedactionScope,
    pub epoch: u64,
    pub granted: u32,
    pub consumed: u32,
    pub subject_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "scope": self.scope.as_str(),
            "epoch": self.epoch,
            "granted": self.granted,
            "consumed": self.consumed,
            "remaining": self.granted.saturating_sub(self.consumed),
            "subject_root": self.subject_root,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        validate_hash("budget_id", &self.budget_id)?;
        validate_hash("subject_root", &self.subject_root)?;
        if self.granted > config.redaction_budget_per_epoch || self.consumed > self.granted {
            return Err("redaction budget exceeds configured allowance".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicRootCheckpoint {
    pub checkpoint_id: String,
    pub label: String,
    pub source_height: u64,
    pub public_record_root: String,
    pub deterministic_root: String,
}

impl DeterministicRootCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "label": self.label,
            "source_height": self.source_height,
            "public_record_root": self.public_record_root,
            "deterministic_root": self.deterministic_root,
        })
    }

    pub fn validate(
        &self,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("public_record_root", &self.public_record_root)?;
        validate_hash("deterministic_root", &self.deterministic_root)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub private_intents: BTreeMap<String, PrivateLiquidityIntent>,
    pub subaddress_cohorts: BTreeMap<String, SubaddressCohort>,
    pub decoy_floors: BTreeMap<String, DecoyFloor>,
    pub sealed_tickets: BTreeMap<String, SealedConflictTicket>,
    pub solver_bonds: BTreeMap<String, SolverBond>,
    pub resolver_attestations: BTreeMap<String, PqResolverAttestation>,
    pub settlement_rebates: BTreeMap<String, SettlementRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub deterministic_checkpoints: BTreeMap<String, DeterministicRootCheckpoint>,
    pub open_cohort_ids: BTreeSet<String>,
    pub active_ticket_ids: BTreeSet<String>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            current_height: DEVNET_HEIGHT,
            current_epoch: 191,
            private_intents: BTreeMap::new(),
            subaddress_cohorts: BTreeMap::new(),
            decoy_floors: BTreeMap::new(),
            sealed_tickets: BTreeMap::new(),
            solver_bonds: BTreeMap::new(),
            resolver_attestations: BTreeMap::new(),
            settlement_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            deterministic_checkpoints: BTreeMap::new(),
            open_cohort_ids: BTreeSet::new(),
            active_ticket_ids: BTreeSet::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.recompute_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let cohort_id = fixture_hash("cohort", "market-maker-0");
        let intent_a = fixture_hash("intent", "rebalance-add-0");
        let intent_b = fixture_hash("intent", "fast-exit-0");
        let ticket_id = fixture_hash("ticket", "cohort-capacity-0");
        let bond_id = fixture_hash("bond", "solver-0");
        let attestation_id = fixture_hash("attestation", "resolver-0");
        let rebate_id = fixture_hash("rebate", "intent-a-0");
        let budget_id = fixture_hash("budget", "ticket-0");

        state.subaddress_cohorts.insert(
            cohort_id.clone(),
            SubaddressCohort {
                cohort_id: cohort_id.clone(),
                status: CohortStatus::Resolving,
                subaddress_account: 0,
                subaddress_major: 7,
                minor_start: 4_096,
                minor_end: 8_191,
                cohort_commitment: fixture_hash("commitment", "cohort-liquidity"),
                encrypted_label_root: fixture_hash("label", "maker-cohort"),
                aggregate_liquidity_commitment: fixture_hash("liquidity", "aggregate"),
                active_intents: 2,
                privacy_set_size: 278_528,
                decoy_floor: 96,
                opened_height: DEVNET_HEIGHT - 1_200,
                last_resolved_height: DEVNET_HEIGHT - 18,
            },
        );
        state.open_cohort_ids.insert(cohort_id.clone());

        for (intent_id, intent_kind, min_fill_piconero) in [
            (
                intent_a.clone(),
                LiquidityIntentKind::Rebalance,
                3_200_000_000_000_u128,
            ),
            (
                intent_b.clone(),
                LiquidityIntentKind::FastExit,
                880_000_000_000_u128,
            ),
        ] {
            state.private_intents.insert(
                intent_id.clone(),
                PrivateLiquidityIntent {
                    intent_id,
                    intent_kind,
                    status: IntentStatus::Resolving,
                    cohort_id: cohort_id.clone(),
                    sealed_intent_root: fixture_hash("sealed-intent", intent_kind.as_str()),
                    nullifier_root: fixture_hash("nullifier", intent_kind.as_str()),
                    amount_commitment: fixture_hash("amount", intent_kind.as_str()),
                    min_fill_piconero,
                    max_fee_bps: 12,
                    decoy_floor: 96,
                    privacy_set_size: 278_528,
                    opened_height: DEVNET_HEIGHT - 12,
                    expires_height: DEVNET_HEIGHT + DEFAULT_INTENT_TTL_BLOCKS,
                },
            );
        }

        state.decoy_floors.insert(
            fixture_hash("floor", "cohort-0"),
            DecoyFloor {
                floor_id: fixture_hash("floor", "cohort-0"),
                cohort_id: cohort_id.clone(),
                floor: 96,
                sampled_outputs: 294_912,
                anonymity_set_root: fixture_hash("anonymity", "cohort-0"),
                verifier_root: fixture_hash("verifier", "cohort-0"),
                effective_height: DEVNET_HEIGHT - 48,
                expires_height: DEVNET_HEIGHT + DEFAULT_RESOLUTION_TTL_BLOCKS,
            },
        );

        state.sealed_tickets.insert(
            ticket_id.clone(),
            SealedConflictTicket {
                ticket_id: ticket_id.clone(),
                status: ConflictTicketStatus::Attested,
                conflict_class: ConflictClass::CohortCapacity,
                cohort_id: cohort_id.clone(),
                intent_ids: BTreeSet::from([intent_a.clone(), intent_b.clone()]),
                sealed_ticket_root: fixture_hash("sealed-ticket", "capacity-0"),
                evidence_commitment: fixture_hash("evidence", "capacity-0"),
                resolver_hint_root: fixture_hash("hint", "capacity-0"),
                opened_height: DEVNET_HEIGHT - 8,
                expires_height: DEVNET_HEIGHT + DEFAULT_TICKET_TTL_BLOCKS,
            },
        );
        state.active_ticket_ids.insert(ticket_id.clone());

        state.solver_bonds.insert(
            bond_id.clone(),
            SolverBond {
                bond_id,
                ticket_id: ticket_id.clone(),
                solver_id: fixture_hash("solver", "solver-0"),
                status: BondStatus::Locked,
                bond_commitment: fixture_hash("bond-commitment", "solver-0"),
                amount_piconero: 250_000_000_000,
                locked_height: DEVNET_HEIGHT - 6,
                unlock_height: DEVNET_HEIGHT + DEFAULT_BOND_LOCK_BLOCKS,
            },
        );

        state.resolver_attestations.insert(
            attestation_id.clone(),
            PqResolverAttestation {
                attestation_id,
                role: AttestationRole::Resolver,
                status: AttestationStatus::Accepted,
                ticket_id: ticket_id.clone(),
                signer_commitment: fixture_hash("signer", "resolver-0"),
                pq_public_key_root: fixture_hash("pq-key", "resolver-0"),
                resolution_root: fixture_hash("resolution", "capacity-0"),
                signature_root: fixture_hash("signature", "resolver-0"),
                security_bits: 256,
                attested_height: DEVNET_HEIGHT - 5,
            },
        );

        state.settlement_rebates.insert(
            rebate_id.clone(),
            SettlementRebate {
                rebate_id,
                ticket_id: ticket_id.clone(),
                intent_id: intent_a.clone(),
                status: RebateStatus::Reserved,
                rebate_commitment: fixture_hash("rebate-commitment", "intent-a-0"),
                amount_piconero: 22_400_000_000,
                rebate_bps: DEFAULT_REBATE_BPS,
                accrued_height: DEVNET_HEIGHT - 3,
                expires_height: DEVNET_HEIGHT + DEFAULT_REBATE_TTL_BLOCKS,
            },
        );

        state.redaction_budgets.insert(
            budget_id.clone(),
            RedactionBudget {
                budget_id,
                scope: RedactionScope::ConflictTicket,
                epoch: state.current_epoch,
                granted: 12,
                consumed: 3,
                subject_root: fixture_hash("subject", "ticket-0"),
            },
        );

        let checkpoint_id = fixture_hash("checkpoint", "demo-0");
        state.deterministic_checkpoints.insert(
            checkpoint_id.clone(),
            DeterministicRootCheckpoint {
                checkpoint_id,
                label: "demo-conflict-resolution-root".to_string(),
                source_height: DEVNET_HEIGHT,
                public_record_root: fixture_hash("public-record", "demo-0"),
                deterministic_root: fixture_hash("deterministic", "demo-0"),
            },
        );

        state.counters = Counters {
            private_intents_admitted: 2,
            cohorts_opened: 1,
            conflicts_ticketed: 1,
            conflicts_settled: 0,
            solver_bonds_locked: 1,
            solver_bonds_slashed: 0,
            pq_attestations_accepted: 1,
            settlement_rebates_paid: 0,
            decoy_floor_breaches: 0,
            redactions_consumed: 3,
        };
        state.recompute_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "private_intent_root": self.roots.private_intent_root,
                "subaddress_cohort_root": self.roots.subaddress_cohort_root,
                "decoy_floor_root": self.roots.decoy_floor_root,
                "sealed_ticket_root": self.roots.sealed_ticket_root,
                "solver_bond_root": self.roots.solver_bond_root,
                "resolver_attestation_root": self.roots.resolver_attestation_root,
                "settlement_rebate_root": self.roots.settlement_rebate_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "deterministic_root": self.roots.deterministic_root,
                "counters_root": self.roots.counters_root,
            },
            "private_intent_count": self.private_intents.len(),
            "subaddress_cohort_count": self.subaddress_cohorts.len(),
            "decoy_floor_count": self.decoy_floors.len(),
            "sealed_ticket_count": self.sealed_tickets.len(),
            "solver_bond_count": self.solver_bonds.len(),
            "resolver_attestation_count": self.resolver_attestations.len(),
            "settlement_rebate_count": self.settlement_rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "deterministic_checkpoint_count": self.deterministic_checkpoints.len(),
            "open_cohort_ids": self.open_cohort_ids,
            "active_ticket_ids": self.active_ticket_ids,
        })
    }

    pub fn recompute_roots(&mut self) {
        let config_root = record_root("SUBADDRESS-CONFLICT-CONFIG", &self.config.public_record());
        let private_intent_root = map_root(
            "SUBADDRESS-CONFLICT-PRIVATE-INTENTS",
            self.private_intents
                .values()
                .map(PrivateLiquidityIntent::public_record),
        );
        let subaddress_cohort_root = map_root(
            "SUBADDRESS-CONFLICT-COHORTS",
            self.subaddress_cohorts
                .values()
                .map(SubaddressCohort::public_record),
        );
        let decoy_floor_root = map_root(
            "SUBADDRESS-CONFLICT-DECOY-FLOORS",
            self.decoy_floors.values().map(DecoyFloor::public_record),
        );
        let sealed_ticket_root = map_root(
            "SUBADDRESS-CONFLICT-SEALED-TICKETS",
            self.sealed_tickets
                .values()
                .map(SealedConflictTicket::public_record),
        );
        let solver_bond_root = map_root(
            "SUBADDRESS-CONFLICT-SOLVER-BONDS",
            self.solver_bonds.values().map(SolverBond::public_record),
        );
        let resolver_attestation_root = map_root(
            "SUBADDRESS-CONFLICT-RESOLVER-ATTESTATIONS",
            self.resolver_attestations
                .values()
                .map(PqResolverAttestation::public_record),
        );
        let settlement_rebate_root = map_root(
            "SUBADDRESS-CONFLICT-SETTLEMENT-REBATES",
            self.settlement_rebates
                .values()
                .map(SettlementRebate::public_record),
        );
        let redaction_budget_root = map_root(
            "SUBADDRESS-CONFLICT-REDACTION-BUDGETS",
            self.redaction_budgets
                .values()
                .map(RedactionBudget::public_record),
        );
        let deterministic_root = map_root(
            "SUBADDRESS-CONFLICT-DETERMINISTIC-CHECKPOINTS",
            self.deterministic_checkpoints
                .values()
                .map(DeterministicRootCheckpoint::public_record),
        );
        let counters_root = record_root(
            "SUBADDRESS-CONFLICT-COUNTERS",
            &self.counters.public_record(),
        );
        self.roots = Roots {
            config_root,
            private_intent_root,
            subaddress_cohort_root,
            decoy_floor_root,
            sealed_ticket_root,
            solver_bond_root,
            resolver_attestation_root,
            settlement_rebate_root,
            redaction_budget_root,
            deterministic_root,
            counters_root,
            state_root: String::new(),
        };
        self.roots.state_root =
            state_root_from_public_record(&self.public_record_without_state_root());
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn validate(
        &self,
    ) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
        self.config.validate()?;
        if self.private_intents.len() > self.config.max_private_intents {
            return Err("too many private liquidity intents".to_string());
        }
        if self.subaddress_cohorts.len() > self.config.max_subaddress_cohorts {
            return Err("too many subaddress cohorts".to_string());
        }
        if self.decoy_floors.len() > self.config.max_decoy_floors {
            return Err("too many decoy floors".to_string());
        }
        if self.sealed_tickets.len() > self.config.max_sealed_tickets {
            return Err("too many sealed conflict tickets".to_string());
        }
        if self.solver_bonds.len() > self.config.max_solver_bonds {
            return Err("too many solver bonds".to_string());
        }
        if self.resolver_attestations.len() > self.config.max_resolver_attestations {
            return Err("too many resolver attestations".to_string());
        }
        if self.settlement_rebates.len() > self.config.max_settlement_rebates {
            return Err("too many settlement rebates".to_string());
        }
        if self.redaction_budgets.len() > self.config.max_redaction_budgets {
            return Err("too many redaction budgets".to_string());
        }
        for cohort in self.subaddress_cohorts.values() {
            cohort.validate(&self.config)?;
        }
        for intent in self.private_intents.values() {
            intent.validate(&self.config)?;
            if !self.subaddress_cohorts.contains_key(&intent.cohort_id) {
                return Err("private liquidity intent references missing cohort".to_string());
            }
        }
        for floor in self.decoy_floors.values() {
            floor.validate(&self.config)?;
            if !self.subaddress_cohorts.contains_key(&floor.cohort_id) {
                return Err("decoy floor references missing cohort".to_string());
            }
        }
        for ticket in self.sealed_tickets.values() {
            ticket.validate()?;
            if !self.subaddress_cohorts.contains_key(&ticket.cohort_id) {
                return Err("sealed conflict ticket references missing cohort".to_string());
            }
            for intent_id in &ticket.intent_ids {
                if !self.private_intents.contains_key(intent_id) {
                    return Err("sealed conflict ticket references missing intent".to_string());
                }
            }
        }
        for bond in self.solver_bonds.values() {
            bond.validate(&self.config)?;
            if !self.sealed_tickets.contains_key(&bond.ticket_id) {
                return Err("solver bond references missing ticket".to_string());
            }
        }
        for attestation in self.resolver_attestations.values() {
            attestation.validate(&self.config)?;
            if !self.sealed_tickets.contains_key(&attestation.ticket_id) {
                return Err("resolver attestation references missing ticket".to_string());
            }
        }
        for rebate in self.settlement_rebates.values() {
            rebate.validate(&self.config)?;
            if !self.sealed_tickets.contains_key(&rebate.ticket_id) {
                return Err("settlement rebate references missing ticket".to_string());
            }
            if !self.private_intents.contains_key(&rebate.intent_id) {
                return Err("settlement rebate references missing intent".to_string());
            }
        }
        for budget in self.redaction_budgets.values() {
            budget.validate(&self.config)?;
        }
        for checkpoint in self.deterministic_checkpoints.values() {
            checkpoint.validate()?;
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "SUBADDRESS-CONFLICT-PUBLIC-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn validate_height_window(
    label: &str,
    start: u64,
    end: u64,
) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
    if end <= start {
        return Err(format!("{label} height window is empty"));
    }
    Ok(())
}

fn validate_hash(
    label: &str,
    value: &str,
) -> MoneroL2PqPrivateSubaddressLiquidityConflictResolverRuntimeResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a 32-byte hex root"));
    }
    Ok(())
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn fixture_hash(domain: &str, label: &str) -> String {
    domain_hash(
        "SUBADDRESS-CONFLICT-FIXTURE",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_is_deterministic() {
        let a = State::devnet();
        let b = State::devnet();
        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(devnet().state_root(), a.state_root());
    }

    #[test]
    fn demo_validates_and_has_public_state_root() {
        let state = State::demo();
        state.validate().expect("demo fixture validates");
        let record = public_record(&state);
        assert_eq!(state_root(&state), record["state_root"]);
    }
}
