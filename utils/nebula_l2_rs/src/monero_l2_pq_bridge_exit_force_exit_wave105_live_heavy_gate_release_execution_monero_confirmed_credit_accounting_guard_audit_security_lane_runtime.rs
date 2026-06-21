use std::collections::BTreeSet;
use std::fmt;

pub type PublicRecord = AuditSecurityPublicRecord;
pub type Runtime = AuditSecurityLaneRuntime;
pub type Result<T> = std::result::Result<T, AuditSecurityError>;

const MODULE_ID: &str =
    "monero_l2_pq_bridge_exit_force_exit_wave105_live_heavy_gate_release_execution";
const MIN_RELAY_CONFIRMATIONS: u32 = 20;
const MIN_REORG_DEPTH: u32 = 12;
const MIN_DUAL_SIGNOFFS: usize = 2;
const MIN_HEAVY_GATE_EVIDENCE_ITEMS: usize = 3;
const MAX_PRIVACY_DISCLOSURE_SCORE: u16 = 10;
const MIN_PRIVACY_ANONYMITY_SET: u32 = 64;
const MAX_ACCOUNTING_DRIFT_PPM: i64 = 0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub lane_id: String,
    pub release_epoch: u64,
    pub min_relay_confirmations: u32,
    pub min_reorg_depth: u32,
    pub min_dual_signoffs: usize,
    pub min_heavy_gate_evidence_items: usize,
    pub max_privacy_disclosure_score: u16,
    pub min_privacy_anonymity_set: u32,
    pub max_accounting_drift_ppm: i64,
    pub require_live_heavy_gate: bool,
    pub require_pq_authorization: bool,
    pub require_reserve_surplus: bool,
    pub require_fee_rebate_netting: bool,
    pub require_circuit_breaker_clear: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lane_id: "wave105-monero-force-exit-audit-security".to_string(),
            release_epoch: 105,
            min_relay_confirmations: MIN_RELAY_CONFIRMATIONS,
            min_reorg_depth: MIN_REORG_DEPTH,
            min_dual_signoffs: MIN_DUAL_SIGNOFFS,
            min_heavy_gate_evidence_items: MIN_HEAVY_GATE_EVIDENCE_ITEMS,
            max_privacy_disclosure_score: MAX_PRIVACY_DISCLOSURE_SCORE,
            min_privacy_anonymity_set: MIN_PRIVACY_ANONYMITY_SET,
            max_accounting_drift_ppm: MAX_ACCOUNTING_DRIFT_PPM,
            require_live_heavy_gate: true,
            require_pq_authorization: true,
            require_reserve_surplus: true,
            require_fee_rebate_netting: true,
            require_circuit_breaker_clear: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
    pub relay_witness: RelayWitnessEvidence,
    pub reorg_safety: ReorgSafetyEvidence,
    pub accounting: AccountingDeltaEvidence,
    pub beneficiary_privacy: BeneficiaryPrivacyEvidence,
    pub fee_rebate_netting: FeeRebateNettingEvidence,
    pub reserves: ReserveEvidence,
    pub pq_authorization: PqAuthorizationEvidence,
    pub circuit_breakers: CircuitBreakerEvidence,
    pub heavy_gate: HeavyGateEvidence,
    pub signoffs: Vec<SignoffEvidence>,
    pub guard_events: Vec<GuardEvent>,
    pub last_decision: ReleaseDecision,
}

impl Default for State {
    fn default() -> Self {
        let config = Config::default();
        Self {
            config,
            release_credit_allowed: false,
            credit_accounting_allowed: false,
            heavy_gates_ran: false,
            relay_witness: RelayWitnessEvidence::default(),
            reorg_safety: ReorgSafetyEvidence::default(),
            accounting: AccountingDeltaEvidence::default(),
            beneficiary_privacy: BeneficiaryPrivacyEvidence::default(),
            fee_rebate_netting: FeeRebateNettingEvidence::default(),
            reserves: ReserveEvidence::default(),
            pq_authorization: PqAuthorizationEvidence::default(),
            circuit_breakers: CircuitBreakerEvidence::default(),
            heavy_gate: HeavyGateEvidence::default(),
            signoffs: Vec::new(),
            guard_events: vec![GuardEvent::new(
                GuardSeverity::Deny,
                "fail_closed_defaults",
                "release_credit_allowed: false; credit_accounting_allowed: false; heavy_gates_ran: false",
            )],
            last_decision: ReleaseDecision::deny("fail_closed_defaults"),
        }
    }
}

impl State {
    pub fn with_config(config: Config) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn validate_config(&self) -> Result<()> {
        require_non_empty("lane_id", &self.config.lane_id)?;
        require_at_least_u32(
            "min_relay_confirmations",
            self.config.min_relay_confirmations,
            MIN_RELAY_CONFIRMATIONS,
        )?;
        require_at_least_u32(
            "min_reorg_depth",
            self.config.min_reorg_depth,
            MIN_REORG_DEPTH,
        )?;
        require_at_least_usize(
            "min_dual_signoffs",
            self.config.min_dual_signoffs,
            MIN_DUAL_SIGNOFFS,
        )?;
        require_at_least_usize(
            "min_heavy_gate_evidence_items",
            self.config.min_heavy_gate_evidence_items,
            MIN_HEAVY_GATE_EVIDENCE_ITEMS,
        )?;
        require_at_least_u32(
            "min_privacy_anonymity_set",
            self.config.min_privacy_anonymity_set,
            MIN_PRIVACY_ANONYMITY_SET,
        )?;
        Ok(())
    }

    pub fn evaluate(&mut self) -> ReleaseDecision {
        let decision = self.evaluate_read_only();
        self.release_credit_allowed = decision.allowed;
        self.credit_accounting_allowed = decision.allowed;
        self.last_decision = decision.clone();
        if decision.allowed {
            self.guard_events.push(GuardEvent::new(
                GuardSeverity::Accept,
                "release_credit_allowed",
                "all audit/security lane gates accepted",
            ));
        } else {
            self.guard_events.push(GuardEvent::new(
                GuardSeverity::Deny,
                "release_credit_refused",
                &decision.reason,
            ));
        }
        decision
    }

    pub fn evaluate_read_only(&self) -> ReleaseDecision {
        match self.validate_all() {
            Ok(()) => ReleaseDecision::allow("all_required_evidence_bound"),
            Err(error) => ReleaseDecision::deny(error.to_string()),
        }
    }

    pub fn validate_all(&self) -> Result<()> {
        self.validate_config()?;
        self.relay_witness.validate(&self.config)?;
        self.reorg_safety.validate(&self.config)?;
        self.accounting.validate(&self.config)?;
        self.beneficiary_privacy.validate(&self.config)?;
        self.fee_rebate_netting.validate(&self.config)?;
        self.reserves.validate(&self.config)?;
        self.pq_authorization.validate(&self.config)?;
        self.circuit_breakers.validate(&self.config)?;
        self.heavy_gate.validate(&self.config)?;
        validate_dual_signoffs(&self.signoffs, self.config.min_dual_signoffs)?;
        Ok(())
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord::from_state(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayWitnessEvidence {
    pub relay_id: String,
    pub witness_root: String,
    pub monero_txid: String,
    pub confirmed_height: u64,
    pub confirmation_count: u32,
    pub witness_signature_root: String,
    pub relay_observed: bool,
}

impl Default for RelayWitnessEvidence {
    fn default() -> Self {
        Self {
            relay_id: String::new(),
            witness_root: String::new(),
            monero_txid: String::new(),
            confirmed_height: 0,
            confirmation_count: 0,
            witness_signature_root: String::new(),
            relay_observed: false,
        }
    }
}

impl RelayWitnessEvidence {
    pub fn devnet() -> Self {
        Self {
            relay_id: "relay-wave105-audit-security-01".to_string(),
            witness_root: devnet_hash("relay-witness", "confirmed-monero-exit"),
            monero_txid: devnet_hash("monero-txid", "force-exit-release-credit"),
            confirmed_height: 2_105_144,
            confirmation_count: MIN_RELAY_CONFIRMATIONS,
            witness_signature_root: devnet_hash("relay-sig-root", "committee-bound-witness"),
            relay_observed: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("relay_id", &self.relay_id)?;
        require_non_empty("witness_root", &self.witness_root)?;
        require_non_empty("monero_txid", &self.monero_txid)?;
        require_non_empty("witness_signature_root", &self.witness_signature_root)?;
        require_true("relay_observed", self.relay_observed)?;
        require_at_least_u32(
            "confirmation_count",
            self.confirmation_count,
            config.min_relay_confirmations,
        )?;
        require_non_zero_u64("confirmed_height", self.confirmed_height)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgSafetyEvidence {
    pub canonical_tip_root: String,
    pub reorg_window_depth: u32,
    pub competing_fork_count: u32,
    pub finality_checkpoint_root: String,
    pub watchtower_quorum: u16,
    pub watchtower_required: u16,
    pub safe_to_release: bool,
}

impl Default for ReorgSafetyEvidence {
    fn default() -> Self {
        Self {
            canonical_tip_root: String::new(),
            reorg_window_depth: 0,
            competing_fork_count: 0,
            finality_checkpoint_root: String::new(),
            watchtower_quorum: 0,
            watchtower_required: 1,
            safe_to_release: false,
        }
    }
}

impl ReorgSafetyEvidence {
    pub fn devnet() -> Self {
        Self {
            canonical_tip_root: devnet_hash("canonical-tip", "wave105"),
            reorg_window_depth: MIN_REORG_DEPTH,
            competing_fork_count: 0,
            finality_checkpoint_root: devnet_hash("finality-checkpoint", "monero-l2-pq"),
            watchtower_quorum: 5,
            watchtower_required: 4,
            safe_to_release: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("canonical_tip_root", &self.canonical_tip_root)?;
        require_non_empty("finality_checkpoint_root", &self.finality_checkpoint_root)?;
        require_true("safe_to_release", self.safe_to_release)?;
        require_at_least_u32(
            "reorg_window_depth",
            self.reorg_window_depth,
            config.min_reorg_depth,
        )?;
        require_zero_u32("competing_fork_count", self.competing_fork_count)?;
        require_quorum(
            "watchtower",
            self.watchtower_quorum,
            self.watchtower_required,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountingDeltaEvidence {
    pub debit_note_root: String,
    pub credit_note_root: String,
    pub pre_release_liability: i128,
    pub post_release_liability: i128,
    pub requested_credit: i128,
    pub accounted_credit: i128,
    pub drift_ppm: i64,
    pub delta_balanced: bool,
}

impl Default for AccountingDeltaEvidence {
    fn default() -> Self {
        Self {
            debit_note_root: String::new(),
            credit_note_root: String::new(),
            pre_release_liability: 0,
            post_release_liability: 0,
            requested_credit: 0,
            accounted_credit: 0,
            drift_ppm: 1,
            delta_balanced: false,
        }
    }
}

impl AccountingDeltaEvidence {
    pub fn devnet() -> Self {
        Self {
            debit_note_root: devnet_hash("debit-note", "escrow-burn"),
            credit_note_root: devnet_hash("credit-note", "confirmed-beneficiary-credit"),
            pre_release_liability: 5_000_000_000,
            post_release_liability: 4_875_000_000,
            requested_credit: 125_000_000,
            accounted_credit: 125_000_000,
            drift_ppm: 0,
            delta_balanced: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("debit_note_root", &self.debit_note_root)?;
        require_non_empty("credit_note_root", &self.credit_note_root)?;
        require_true("delta_balanced", self.delta_balanced)?;
        require_positive_i128("requested_credit", self.requested_credit)?;
        require_equal_i128(
            "requested_credit",
            self.requested_credit,
            "accounted_credit",
            self.accounted_credit,
        )?;
        require_at_most_i64("drift_ppm", self.drift_ppm, config.max_accounting_drift_ppm)?;
        let planned_post = self.pre_release_liability - self.accounted_credit;
        require_equal_i128(
            "post_release_liability",
            self.post_release_liability,
            "planned_post_release_liability",
            planned_post,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeneficiaryPrivacyEvidence {
    pub beneficiary_commitment: String,
    pub unlinkability_proof_root: String,
    pub view_tag_policy_root: String,
    pub anonymity_set_size: u32,
    pub disclosure_score: u16,
    pub plaintext_beneficiary_present: bool,
    pub privacy_budget_preserved: bool,
}

impl Default for BeneficiaryPrivacyEvidence {
    fn default() -> Self {
        Self {
            beneficiary_commitment: String::new(),
            unlinkability_proof_root: String::new(),
            view_tag_policy_root: String::new(),
            anonymity_set_size: 0,
            disclosure_score: u16::MAX,
            plaintext_beneficiary_present: true,
            privacy_budget_preserved: false,
        }
    }
}

impl BeneficiaryPrivacyEvidence {
    pub fn devnet() -> Self {
        Self {
            beneficiary_commitment: devnet_hash("beneficiary-commitment", "hidden-account"),
            unlinkability_proof_root: devnet_hash("unlinkability", "decoy-ring-bound"),
            view_tag_policy_root: devnet_hash("view-tag-policy", "no-public-beneficiary"),
            anonymity_set_size: MIN_PRIVACY_ANONYMITY_SET,
            disclosure_score: 0,
            plaintext_beneficiary_present: false,
            privacy_budget_preserved: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("beneficiary_commitment", &self.beneficiary_commitment)?;
        require_non_empty("unlinkability_proof_root", &self.unlinkability_proof_root)?;
        require_non_empty("view_tag_policy_root", &self.view_tag_policy_root)?;
        require_at_least_u32(
            "anonymity_set_size",
            self.anonymity_set_size,
            config.min_privacy_anonymity_set,
        )?;
        require_at_most_u16(
            "disclosure_score",
            self.disclosure_score,
            config.max_privacy_disclosure_score,
        )?;
        require_false(
            "plaintext_beneficiary_present",
            self.plaintext_beneficiary_present,
        )?;
        require_true("privacy_budget_preserved", self.privacy_budget_preserved)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeRebateNettingEvidence {
    pub fee_schedule_root: String,
    pub rebate_schedule_root: String,
    pub gross_fee: i128,
    pub rebate: i128,
    pub net_fee: i128,
    pub sponsor_credit: i128,
    pub netting_balanced: bool,
}

impl Default for FeeRebateNettingEvidence {
    fn default() -> Self {
        Self {
            fee_schedule_root: String::new(),
            rebate_schedule_root: String::new(),
            gross_fee: 0,
            rebate: 0,
            net_fee: 0,
            sponsor_credit: 0,
            netting_balanced: false,
        }
    }
}

impl FeeRebateNettingEvidence {
    pub fn devnet() -> Self {
        Self {
            fee_schedule_root: devnet_hash("fee-schedule", "monero-exit-heavy-gate"),
            rebate_schedule_root: devnet_hash("rebate-schedule", "private-l2-release"),
            gross_fee: 1_500_000,
            rebate: 500_000,
            net_fee: 1_000_000,
            sponsor_credit: 0,
            netting_balanced: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if config.require_fee_rebate_netting {
            require_non_empty("fee_schedule_root", &self.fee_schedule_root)?;
            require_non_empty("rebate_schedule_root", &self.rebate_schedule_root)?;
            require_true("netting_balanced", self.netting_balanced)?;
        }
        require_non_negative_i128("gross_fee", self.gross_fee)?;
        require_non_negative_i128("rebate", self.rebate)?;
        require_non_negative_i128("net_fee", self.net_fee)?;
        require_non_negative_i128("sponsor_credit", self.sponsor_credit)?;
        let planned = self.gross_fee - self.rebate - self.sponsor_credit;
        require_equal_i128("net_fee", self.net_fee, "planned_net_fee", planned)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveEvidence {
    pub reserve_root: String,
    pub reserve_asset: String,
    pub available_reserve: i128,
    pub required_reserve: i128,
    pub locked_exit_liability: i128,
    pub reserve_attestor_root: String,
    pub reserve_fresh: bool,
}

impl Default for ReserveEvidence {
    fn default() -> Self {
        Self {
            reserve_root: String::new(),
            reserve_asset: String::new(),
            available_reserve: 0,
            required_reserve: 1,
            locked_exit_liability: 1,
            reserve_attestor_root: String::new(),
            reserve_fresh: false,
        }
    }
}

impl ReserveEvidence {
    pub fn devnet() -> Self {
        Self {
            reserve_root: devnet_hash("reserve-root", "xmr-liquidity"),
            reserve_asset: "pXMR".to_string(),
            available_reserve: 9_000_000_000,
            required_reserve: 5_000_000_000,
            locked_exit_liability: 125_000_000,
            reserve_attestor_root: devnet_hash("reserve-attestor", "watchtower-quorum"),
            reserve_fresh: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if config.require_reserve_surplus {
            require_non_empty("reserve_root", &self.reserve_root)?;
            require_non_empty("reserve_asset", &self.reserve_asset)?;
            require_non_empty("reserve_attestor_root", &self.reserve_attestor_root)?;
            require_true("reserve_fresh", self.reserve_fresh)?;
            require_at_least_i128(
                "available_reserve",
                self.available_reserve,
                "required_reserve",
                self.required_reserve,
            )?;
            require_at_least_i128(
                "available_reserve",
                self.available_reserve,
                "locked_exit_liability",
                self.locked_exit_liability,
            )?;
        }
        require_non_negative_i128("available_reserve", self.available_reserve)?;
        require_positive_i128("required_reserve", self.required_reserve)?;
        require_non_negative_i128("locked_exit_liability", self.locked_exit_liability)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqAuthorizationEvidence {
    pub authorization_root: String,
    pub key_epoch: u64,
    pub committee_root: String,
    pub algorithm_family: PqAlgorithmFamily,
    pub signature_count: u16,
    pub signature_threshold: u16,
    pub replay_protection_nonce: String,
    pub authorization_fresh: bool,
}

impl Default for PqAuthorizationEvidence {
    fn default() -> Self {
        Self {
            authorization_root: String::new(),
            key_epoch: 0,
            committee_root: String::new(),
            algorithm_family: PqAlgorithmFamily::Unknown,
            signature_count: 0,
            signature_threshold: 1,
            replay_protection_nonce: String::new(),
            authorization_fresh: false,
        }
    }
}

impl PqAuthorizationEvidence {
    pub fn devnet() -> Self {
        Self {
            authorization_root: devnet_hash("pq-authorization", "ml-dsa-slh-dsa-release"),
            key_epoch: 105,
            committee_root: devnet_hash("pq-committee", "wave105-release-authority"),
            algorithm_family: PqAlgorithmFamily::HybridMlDsaSlhDsa,
            signature_count: 4,
            signature_threshold: 3,
            replay_protection_nonce: devnet_hash("pq-nonce", "release-credit-accounting"),
            authorization_fresh: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if config.require_pq_authorization {
            require_non_empty("authorization_root", &self.authorization_root)?;
            require_non_empty("committee_root", &self.committee_root)?;
            require_non_empty("replay_protection_nonce", &self.replay_protection_nonce)?;
            require_non_zero_u64("key_epoch", self.key_epoch)?;
            require_true("authorization_fresh", self.authorization_fresh)?;
            require_quorum(
                "pq_signature",
                self.signature_count,
                self.signature_threshold,
            )?;
            require_false(
                "algorithm_family_unknown",
                self.algorithm_family == PqAlgorithmFamily::Unknown,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqAlgorithmFamily {
    Unknown,
    MlDsa,
    SlhDsa,
    Falcon,
    HybridMlDsaSlhDsa,
}

impl fmt::Display for PqAlgorithmFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Unknown => "unknown",
            Self::MlDsa => "ml-dsa",
            Self::SlhDsa => "slh-dsa",
            Self::Falcon => "falcon",
            Self::HybridMlDsaSlhDsa => "hybrid-ml-dsa-slh-dsa",
        };
        formatter.write_str(label)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitBreakerEvidence {
    pub breaker_root: String,
    pub emergency_halt_active: bool,
    pub liquidity_halt_active: bool,
    pub privacy_halt_active: bool,
    pub accounting_halt_active: bool,
    pub governance_override_active: bool,
    pub cleared_by_watchtower: bool,
}

impl Default for CircuitBreakerEvidence {
    fn default() -> Self {
        Self {
            breaker_root: String::new(),
            emergency_halt_active: true,
            liquidity_halt_active: true,
            privacy_halt_active: true,
            accounting_halt_active: true,
            governance_override_active: false,
            cleared_by_watchtower: false,
        }
    }
}

impl CircuitBreakerEvidence {
    pub fn devnet() -> Self {
        Self {
            breaker_root: devnet_hash("circuit-breaker", "all-clear"),
            emergency_halt_active: false,
            liquidity_halt_active: false,
            privacy_halt_active: false,
            accounting_halt_active: false,
            governance_override_active: false,
            cleared_by_watchtower: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if config.require_circuit_breaker_clear {
            require_non_empty("breaker_root", &self.breaker_root)?;
            require_false("emergency_halt_active", self.emergency_halt_active)?;
            require_false("liquidity_halt_active", self.liquidity_halt_active)?;
            require_false("privacy_halt_active", self.privacy_halt_active)?;
            require_false("accounting_halt_active", self.accounting_halt_active)?;
            require_false(
                "governance_override_active",
                self.governance_override_active,
            )?;
            require_true("cleared_by_watchtower", self.cleared_by_watchtower)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeavyGateEvidence {
    pub gate_run_id: String,
    pub live_feed_root: String,
    pub execution_receipt_root: String,
    pub transcript_root: String,
    pub artifacts: Vec<HeavyGateArtifact>,
    pub live_run: bool,
    pub accepted: bool,
}

impl Default for HeavyGateEvidence {
    fn default() -> Self {
        Self {
            gate_run_id: String::new(),
            live_feed_root: String::new(),
            execution_receipt_root: String::new(),
            transcript_root: String::new(),
            artifacts: Vec::new(),
            live_run: false,
            accepted: false,
        }
    }
}

impl HeavyGateEvidence {
    pub fn devnet() -> Self {
        Self {
            gate_run_id: "wave105-live-heavy-gate-release-credit-01".to_string(),
            live_feed_root: devnet_hash("live-feed-root", "monero-confirmed-credit"),
            execution_receipt_root: devnet_hash("execution-receipt", "heavy-gate-pass"),
            transcript_root: devnet_hash("transcript-root", "release-accounting-guard"),
            artifacts: vec![
                HeavyGateArtifact::new("relay-witness-replay", "pass"),
                HeavyGateArtifact::new("reorg-safety-drill", "pass"),
                HeavyGateArtifact::new("reserve-and-privacy-netting", "pass"),
            ],
            live_run: true,
            accepted: true,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if config.require_live_heavy_gate {
            require_non_empty("gate_run_id", &self.gate_run_id)?;
            require_non_empty("live_feed_root", &self.live_feed_root)?;
            require_non_empty("execution_receipt_root", &self.execution_receipt_root)?;
            require_non_empty("transcript_root", &self.transcript_root)?;
            require_true("live_run", self.live_run)?;
            require_true("accepted", self.accepted)?;
            require_at_least_usize(
                "heavy_gate_artifacts",
                self.artifacts.len(),
                config.min_heavy_gate_evidence_items,
            )?;
            for artifact in &self.artifacts {
                artifact.validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeavyGateArtifact {
    pub name: String,
    pub result: String,
    pub evidence_root: String,
}

impl HeavyGateArtifact {
    pub fn new(name: &str, result: &str) -> Self {
        Self {
            name: name.to_string(),
            result: result.to_string(),
            evidence_root: devnet_hash("heavy-gate-artifact", name),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("artifact.name", &self.name)?;
        require_non_empty("artifact.result", &self.result)?;
        require_non_empty("artifact.evidence_root", &self.evidence_root)?;
        require_equal_str("artifact.result", &self.result, "pass")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignoffEvidence {
    pub role: SignoffRole,
    pub signer_id: String,
    pub signoff_root: String,
    pub signed_state_root: String,
    pub accepted: bool,
}

impl SignoffEvidence {
    pub fn new(role: SignoffRole, signer_id: &str, signed_state_root: &str) -> Self {
        Self {
            role,
            signer_id: signer_id.to_string(),
            signoff_root: devnet_hash("signoff", signer_id),
            signed_state_root: signed_state_root.to_string(),
            accepted: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("signer_id", &self.signer_id)?;
        require_non_empty("signoff_root", &self.signoff_root)?;
        require_non_empty("signed_state_root", &self.signed_state_root)?;
        require_true("signoff.accepted", self.accepted)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignoffRole {
    AuditLead,
    SecurityLead,
    ReleaseCaptain,
    BridgeCustodyLead,
    PrivacyLead,
}

impl fmt::Display for SignoffRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::AuditLead => "audit-lead",
            Self::SecurityLead => "security-lead",
            Self::ReleaseCaptain => "release-captain",
            Self::BridgeCustodyLead => "bridge-custody-lead",
            Self::PrivacyLead => "privacy-lead",
        };
        formatter.write_str(label)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardEvent {
    pub severity: GuardSeverity,
    pub code: String,
    pub detail: String,
}

impl GuardEvent {
    pub fn new(severity: GuardSeverity, code: &str, detail: &str) -> Self {
        Self {
            severity,
            code: code.to_string(),
            detail: detail.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardSeverity {
    Accept,
    Deny,
}

impl fmt::Display for GuardSeverity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => formatter.write_str("accept"),
            Self::Deny => formatter.write_str("deny"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseDecision {
    pub allowed: bool,
    pub reason: String,
}

impl ReleaseDecision {
    pub fn allow(reason: &str) -> Self {
        Self {
            allowed: true,
            reason: reason.to_string(),
        }
    }

    pub fn deny<T: Into<String>>(reason: T) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditSecurityPublicRecord {
    pub module_id: String,
    pub lane_id: String,
    pub release_epoch: u64,
    pub release_credit_allowed: bool,
    pub credit_accounting_allowed: bool,
    pub heavy_gates_ran: bool,
    pub state_root: String,
    pub decision_reason: String,
    pub fail_closed_record: String,
    pub evidence_summary: Vec<String>,
}

impl AuditSecurityPublicRecord {
    pub fn from_state(state: &State) -> Self {
        Self {
            module_id: MODULE_ID.to_string(),
            lane_id: state.config.lane_id.clone(),
            release_epoch: state.config.release_epoch,
            release_credit_allowed: state.release_credit_allowed,
            credit_accounting_allowed: state.credit_accounting_allowed,
            heavy_gates_ran: state.heavy_gates_ran,
            state_root: state_root(state),
            decision_reason: state.last_decision.reason.clone(),
            fail_closed_record:
                "release_credit_allowed: false; credit_accounting_allowed: false; heavy_gates_ran: false"
                    .to_string(),
            evidence_summary: evidence_summary(state),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditSecurityLaneRuntime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditSecurityError {
    pub message: String,
}

impl AuditSecurityError {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for AuditSecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AuditSecurityError {}

pub fn devnet() -> Result<State> {
    let state_hint = devnet_hash("state-hint", "pre-signoff");
    let mut state = State::with_config(Config::default());
    state.relay_witness = RelayWitnessEvidence::devnet();
    state.reorg_safety = ReorgSafetyEvidence::devnet();
    state.accounting = AccountingDeltaEvidence::devnet();
    state.beneficiary_privacy = BeneficiaryPrivacyEvidence::devnet();
    state.fee_rebate_netting = FeeRebateNettingEvidence::devnet();
    state.reserves = ReserveEvidence::devnet();
    state.pq_authorization = PqAuthorizationEvidence::devnet();
    state.circuit_breakers = CircuitBreakerEvidence::devnet();
    state.heavy_gate = HeavyGateEvidence::devnet();
    state.heavy_gates_ran = true;
    state.signoffs.push(SignoffEvidence::new(
        SignoffRole::AuditLead,
        "audit-lead-wave105",
        &state_hint,
    ));
    state.signoffs.push(SignoffEvidence::new(
        SignoffRole::SecurityLead,
        "security-lead-wave105",
        &state_hint,
    ));
    state.validate_all()?;
    state.evaluate();
    Ok(state)
}

pub fn public_record(state: &State) -> PublicRecord {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    let mut input = String::new();
    push_pair(&mut input, "module_id", MODULE_ID);
    push_pair(&mut input, "lane_id", &state.config.lane_id);
    push_pair(
        &mut input,
        "release_epoch",
        &state.config.release_epoch.to_string(),
    );
    push_pair(
        &mut input,
        "release_credit_allowed",
        bool_label(state.release_credit_allowed),
    );
    push_pair(
        &mut input,
        "credit_accounting_allowed",
        bool_label(state.credit_accounting_allowed),
    );
    push_pair(
        &mut input,
        "heavy_gates_ran",
        bool_label(state.heavy_gates_ran),
    );
    push_pair(&mut input, "relay_id", &state.relay_witness.relay_id);
    push_pair(
        &mut input,
        "witness_root",
        &state.relay_witness.witness_root,
    );
    push_pair(&mut input, "monero_txid", &state.relay_witness.monero_txid);
    push_pair(
        &mut input,
        "canonical_tip_root",
        &state.reorg_safety.canonical_tip_root,
    );
    push_pair(
        &mut input,
        "debit_note_root",
        &state.accounting.debit_note_root,
    );
    push_pair(
        &mut input,
        "credit_note_root",
        &state.accounting.credit_note_root,
    );
    push_pair(
        &mut input,
        "beneficiary_commitment",
        &state.beneficiary_privacy.beneficiary_commitment,
    );
    push_pair(
        &mut input,
        "fee_schedule_root",
        &state.fee_rebate_netting.fee_schedule_root,
    );
    push_pair(&mut input, "reserve_root", &state.reserves.reserve_root);
    push_pair(
        &mut input,
        "authorization_root",
        &state.pq_authorization.authorization_root,
    );
    push_pair(
        &mut input,
        "breaker_root",
        &state.circuit_breakers.breaker_root,
    );
    push_pair(&mut input, "gate_run_id", &state.heavy_gate.gate_run_id);
    push_pair(&mut input, "decision", &state.last_decision.reason);
    for signoff in &state.signoffs {
        push_pair(&mut input, "signoff_role", &signoff.role.to_string());
        push_pair(&mut input, "signoff_root", &signoff.signoff_root);
    }
    stable_hash("audit-security-state", &input)
}

fn evidence_summary(state: &State) -> Vec<String> {
    vec![
        format!(
            "relay_witness_confirmation:{}:{}",
            state.relay_witness.relay_observed, state.relay_witness.confirmation_count
        ),
        format!(
            "reorg_safety:{}:{}",
            state.reorg_safety.safe_to_release, state.reorg_safety.reorg_window_depth
        ),
        format!(
            "accounting_delta:{}:{}",
            state.accounting.delta_balanced, state.accounting.accounted_credit
        ),
        format!(
            "beneficiary_privacy:{}:{}",
            state.beneficiary_privacy.privacy_budget_preserved,
            state.beneficiary_privacy.anonymity_set_size
        ),
        format!(
            "fee_rebate_netting:{}:{}",
            state.fee_rebate_netting.netting_balanced, state.fee_rebate_netting.net_fee
        ),
        format!(
            "reserves:{}:{}",
            state.reserves.reserve_fresh, state.reserves.available_reserve
        ),
        format!(
            "pq_authorization:{}:{}",
            state.pq_authorization.authorization_fresh, state.pq_authorization.algorithm_family
        ),
        format!(
            "circuit_breakers_clear:{}",
            state.circuit_breakers.cleared_by_watchtower
        ),
        format!(
            "live_heavy_gate:{}:{}",
            state.heavy_gate.live_run,
            state.heavy_gate.artifacts.len()
        ),
        format!("dual_signoffs:{}", state.signoffs.len()),
    ]
}

fn validate_dual_signoffs(signoffs: &[SignoffEvidence], minimum: usize) -> Result<()> {
    let mut roles = BTreeSet::new();
    for signoff in signoffs {
        signoff.validate()?;
        roles.insert(signoff.role.clone());
    }
    if roles.len() < minimum {
        return fail(format!(
            "insufficient distinct signoffs: {} < {}",
            roles.len(),
            minimum
        ));
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return fail(format!("missing required field {}", field));
    }
    Ok(())
}

fn require_true(field: &str, value: bool) -> Result<()> {
    if !value {
        return fail(format!("invalid {}: planned true", field));
    }
    Ok(())
}

fn require_false(field: &str, value: bool) -> Result<()> {
    if value {
        return fail(format!("invalid {}: planned false", field));
    }
    Ok(())
}

fn require_non_zero_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        return fail(format!("invalid {}: planned non-zero value", field));
    }
    Ok(())
}

fn require_zero_u32(field: &str, value: u32) -> Result<()> {
    if value != 0 {
        return fail(format!("invalid {}: planned zero, found {}", field, value));
    }
    Ok(())
}

fn require_at_least_u32(field: &str, actual: u32, minimum: u32) -> Result<()> {
    if actual < minimum {
        return fail(format!("{} below minimum: {} < {}", field, actual, minimum));
    }
    Ok(())
}

fn require_at_least_usize(field: &str, actual: usize, minimum: usize) -> Result<()> {
    if actual < minimum {
        return fail(format!("{} below minimum: {} < {}", field, actual, minimum));
    }
    Ok(())
}

fn require_at_least_i128(
    field: &str,
    actual: i128,
    minimum_field: &str,
    minimum: i128,
) -> Result<()> {
    if actual < minimum {
        return fail(format!(
            "{} below {}: {} < {}",
            field, minimum_field, actual, minimum
        ));
    }
    Ok(())
}

fn require_at_most_u16(field: &str, actual: u16, maximum: u16) -> Result<()> {
    if actual > maximum {
        return fail(format!("{} above maximum: {} > {}", field, actual, maximum));
    }
    Ok(())
}

fn require_at_most_i64(field: &str, actual: i64, maximum: i64) -> Result<()> {
    if actual > maximum {
        return fail(format!("{} above maximum: {} > {}", field, actual, maximum));
    }
    Ok(())
}

fn require_positive_i128(field: &str, value: i128) -> Result<()> {
    if value <= 0 {
        return fail(format!(
            "invalid {}: planned positive value, found {}",
            field, value
        ));
    }
    Ok(())
}

fn require_non_negative_i128(field: &str, value: i128) -> Result<()> {
    if value < 0 {
        return fail(format!(
            "invalid {}: planned non-negative value, found {}",
            field, value
        ));
    }
    Ok(())
}

fn require_equal_i128(left_field: &str, left: i128, right_field: &str, right: i128) -> Result<()> {
    if left != right {
        return fail(format!(
            "{} does not match {}: {} != {}",
            left_field, right_field, left, right
        ));
    }
    Ok(())
}

fn require_quorum(label: &str, count: u16, threshold: u16) -> Result<()> {
    if threshold == 0 {
        return fail(format!(
            "invalid {}_threshold: threshold cannot be zero",
            label
        ));
    }
    if count < threshold {
        return fail(format!(
            "invalid {}_quorum: {} < {}",
            label, count, threshold
        ));
    }
    Ok(())
}

fn require_equal_str(field: &str, actual: &str, planned: &str) -> Result<()> {
    if actual != planned {
        return fail(format!(
            "invalid {}: planned {}, found {}",
            field, planned, actual
        ));
    }
    Ok(())
}

fn fail<T>(message: String) -> Result<T> {
    Err(AuditSecurityError::new(message))
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn push_pair(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push('=');
    out.push_str(value);
    out.push('\n');
}

fn devnet_hash(domain: &str, label: &str) -> String {
    stable_hash(domain, label)
}

fn stable_hash(domain: &str, input: &str) -> String {
    let mut a = 0x243f_6a88_85a3_08d3_u64;
    let mut b = 0x1319_8a2e_0370_7344_u64;
    let mut c = 0xa409_3822_299f_31d0_u64;
    for byte in domain.bytes().chain([b':']).chain(input.bytes()) {
        a ^= u64::from(byte).wrapping_add(0x9e37_79b9_7f4a_7c15);
        a = a.rotate_left(7).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        b ^= a.wrapping_add(u64::from(byte) << 1);
        b = b.rotate_left(11).wrapping_mul(0x94d0_49bb_1331_11eb);
        c ^= b.wrapping_add(a.rotate_right(3));
        c = c.rotate_left(17).wrapping_add(0x2545_f491_4f6c_dd1d);
    }
    format!("{:016x}{:016x}{:016x}", a, b, c)
}
