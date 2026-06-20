use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialAssertionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_ASSERTION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-assertion-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_ASSERTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "2026-06-18.forced-exit.vertical-slice.adversarial-assertions.v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-assertion-runtime";
const REQUIRED_ASSERTION_COUNT: usize = 9;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub l2_finality_lag_blocks: u64,
    pub monero_reorg_hold_blocks: u64,
    pub watcher_quorum: u64,
    pub watcher_fault_limit: u64,
    pub pq_key_ttl_blocks: u64,
    pub receipt_withholding_grace_ms: u64,
    pub reserve_floor_piconero: u64,
    pub liquidity_buffer_piconero: u64,
    pub metadata_privacy_budget_bits: u64,
    pub wallet_recovery_deadline_ms: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            l2_finality_lag_blocks: 12,
            monero_reorg_hold_blocks: 20,
            watcher_quorum: 5,
            watcher_fault_limit: 1,
            pq_key_ttl_blocks: 720,
            receipt_withholding_grace_ms: 45_000,
            reserve_floor_piconero: 18_000_000_000_000,
            liquidity_buffer_piconero: 4_000_000_000_000,
            metadata_privacy_budget_bits: 6,
            wallet_recovery_deadline_ms: 30_000,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "l2_finality_lag_blocks": self.l2_finality_lag_blocks,
            "monero_reorg_hold_blocks": self.monero_reorg_hold_blocks,
            "watcher_quorum": self.watcher_quorum,
            "watcher_fault_limit": self.watcher_fault_limit,
            "pq_key_ttl_blocks": self.pq_key_ttl_blocks,
            "receipt_withholding_grace_ms": self.receipt_withholding_grace_ms,
            "reserve_floor_piconero": self.reserve_floor_piconero,
            "liquidity_buffer_piconero": self.liquidity_buffer_piconero,
            "metadata_privacy_budget_bits": self.metadata_privacy_budget_bits,
            "wallet_recovery_deadline_ms": self.wallet_recovery_deadline_ms
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialSurface {
    SequencerOutage,
    WatcherCollusion,
    MoneroReorg,
    WithheldReceipt,
    StalePqKey,
    ReserveShortfall,
    LiquidityExhaustion,
    MetadataLeak,
    WalletRecovery,
}

impl AdversarialSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerOutage => "sequencer_outage",
            Self::WatcherCollusion => "watcher_collusion",
            Self::MoneroReorg => "monero_reorg",
            Self::WithheldReceipt => "withheld_receipt",
            Self::StalePqKey => "stale_pq_key",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::MetadataLeak => "metadata_leak",
            Self::WalletRecovery => "wallet_recovery",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdversarialAssertion {
    pub ordinal: u64,
    pub surface: AdversarialSurface,
    pub assertion_id: String,
    pub trigger: String,
    pub deterministic_signal: String,
    pub expected_fail_closed_behavior: String,
    pub blocked_hazard: String,
    pub recovery_gate: String,
    pub evidence_refs: Vec<String>,
    pub must_fail_closed: bool,
}

impl AdversarialAssertion {
    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "surface": self.surface.as_str(),
            "assertion_id": self.assertion_id,
            "trigger": self.trigger,
            "deterministic_signal": self.deterministic_signal,
            "expected_fail_closed_behavior": self.expected_fail_closed_behavior,
            "blocked_hazard": self.blocked_hazard,
            "recovery_gate": self.recovery_gate,
            "evidence_refs": self.evidence_refs,
            "must_fail_closed": self.must_fail_closed
        })
    }

    fn assertion_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:assertion-root"),
            &[
                HashPart::U64(self.ordinal),
                HashPart::Str(self.surface.as_str()),
                HashPart::Str(&self.assertion_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub scenario_id: String,
    pub l2_tip_height: u64,
    pub monero_tip_height: u64,
    pub forced_exit_epoch: u64,
    pub assertions: Vec<AdversarialAssertion>,
    pub assertion_root: String,
    pub fail_closed_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let assertions = devnet_assertions();
        let assertion_records = assertions
            .iter()
            .map(AdversarialAssertion::public_record)
            .collect::<Vec<_>>();
        let fail_closed_records = assertions
            .iter()
            .map(|assertion| {
                json!({
                    "assertion_id": assertion.assertion_id,
                    "surface": assertion.surface.as_str(),
                    "expected_fail_closed_behavior": assertion.expected_fail_closed_behavior,
                    "must_fail_closed": assertion.must_fail_closed,
                    "assertion_root": assertion.assertion_root()
                })
            })
            .collect::<Vec<_>>();

        Self {
            config,
            runtime_id: runtime_id(),
            scenario_id: "devnet-canonical-forced-exit-vertical-slice-adversarial-assertions"
                .to_string(),
            l2_tip_height: 88_240,
            monero_tip_height: 3_451_904,
            forced_exit_epoch: 42,
            assertions,
            assertion_root: merkle_root(&format!("{DOMAIN}:assertions"), &assertion_records),
            fail_closed_root: merkle_root(
                &format!("{DOMAIN}:fail-closed-behaviors"),
                &fail_closed_records,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let assertion_records = self
            .assertions
            .iter()
            .map(AdversarialAssertion::public_record)
            .collect::<Vec<_>>();

        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_assertion_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runtime_id": self.runtime_id,
            "scenario_id": self.scenario_id,
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "forced_exit_epoch": self.forced_exit_epoch,
            "config": self.config.public_record(),
            "assertions": assertion_records,
            "assertion_root": self.assertion_root,
            "fail_closed_root": self.fail_closed_root,
            "state_root": self.state_root()
        })
    }

    pub fn state_root(&self) -> String {
        let config_record = self.config.public_record();

        domain_hash(
            &format!("{DOMAIN}:state-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(SCHEMA_VERSION),
                HashPart::Json(&config_record),
                HashPart::Str(&self.runtime_id),
                HashPart::Str(&self.scenario_id),
                HashPart::U64(self.l2_tip_height),
                HashPart::U64(self.monero_tip_height),
                HashPart::U64(self.forced_exit_epoch),
                HashPart::Str(&self.assertion_root),
                HashPart::Str(&self.fail_closed_root),
            ],
            32,
        )
    }

    pub fn assert_fail_closed(&self) -> Result<()> {
        if self.config.chain_id != CHAIN_ID {
            return Err("config chain id must match runtime chain id".to_string());
        }
        if self.assertions.len() != REQUIRED_ASSERTION_COUNT {
            return Err("canonical adversarial assertion set must contain nine cases".to_string());
        }
        if self.assertions.iter().any(|assertion| {
            !assertion.must_fail_closed
                || assertion.expected_fail_closed_behavior.is_empty()
                || assertion.evidence_refs.is_empty()
        }) {
            return Err(
                "every adversarial assertion must encode fail-closed behavior and evidence"
                    .to_string(),
            );
        }
        if self.assertion_root != computed_assertion_root(&self.assertions) {
            return Err("assertion root does not match canonical assertion records".to_string());
        }
        if self.fail_closed_root != computed_fail_closed_root(&self.assertions) {
            return Err("fail-closed root does not match canonical assertion records".to_string());
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

fn runtime_id() -> String {
    domain_hash(
        &format!("{DOMAIN}:runtime-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(SCHEMA_VERSION),
        ],
        16,
    )
}

fn computed_assertion_root(assertions: &[AdversarialAssertion]) -> String {
    let records = assertions
        .iter()
        .map(AdversarialAssertion::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:assertions"), &records)
}

fn computed_fail_closed_root(assertions: &[AdversarialAssertion]) -> String {
    let records = assertions
        .iter()
        .map(|assertion| {
            json!({
                "assertion_id": assertion.assertion_id,
                "surface": assertion.surface.as_str(),
                "expected_fail_closed_behavior": assertion.expected_fail_closed_behavior,
                "must_fail_closed": assertion.must_fail_closed,
                "assertion_root": assertion.assertion_root()
            })
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:fail-closed-behaviors"), &records)
}

fn assertion(
    ordinal: u64,
    surface: AdversarialSurface,
    trigger: &str,
    deterministic_signal: &str,
    expected_fail_closed_behavior: &str,
    blocked_hazard: &str,
    recovery_gate: &str,
    evidence_refs: &[&str],
) -> AdversarialAssertion {
    AdversarialAssertion {
        ordinal,
        surface,
        assertion_id: domain_hash(
            &format!("{DOMAIN}:assertion-id"),
            &[
                HashPart::U64(ordinal),
                HashPart::Str(surface.as_str()),
                HashPart::Str(trigger),
            ],
            16,
        ),
        trigger: trigger.to_string(),
        deterministic_signal: deterministic_signal.to_string(),
        expected_fail_closed_behavior: expected_fail_closed_behavior.to_string(),
        blocked_hazard: blocked_hazard.to_string(),
        recovery_gate: recovery_gate.to_string(),
        evidence_refs: evidence_refs
            .iter()
            .map(|evidence_ref| (*evidence_ref).to_string())
            .collect(),
        must_fail_closed: true,
    }
}

fn devnet_assertions() -> Vec<AdversarialAssertion> {
    vec![
        assertion(
            1,
            AdversarialSurface::SequencerOutage,
            "l2 batch gap exceeds configured finality lag while forced-exit claims are queued",
            "ordered batch root absent for l2 heights 88228 through 88240",
            "halt ordinary release ordering and promote the user forced-exit queue to watcher ordered fallback",
            "operator censorship cannot delay canonical forced-exit admission",
            "forced_exit_liveness_backstop",
            &["l2-gap:88228-88240", "queue-root:forced-exit-devnet-42"],
        ),
        assertion(
            2,
            AdversarialSurface::WatcherCollusion,
            "watcher quorum contains conflicting release attestations for the same exit epoch",
            "equivocation bitmap marks watcher devnet-w2 and devnet-w4 over epoch 42",
            "freeze release authority, slash equivocation evidence, and require honest quorum override",
            "colluding watchers cannot unfreeze an invalid release view",
            "watcher_equivocation_slash_gate",
            &[
                "watcher:devnet-w2:view-a",
                "watcher:devnet-w2:view-b",
                "watcher:devnet-w4:view-b",
            ],
        ),
        assertion(
            3,
            AdversarialSurface::MoneroReorg,
            "monero lock depth drops below the hold window after exit evidence was prepared",
            "anchor parent mismatch at monero height 3451886",
            "quarantine the claim and rebind it to a surviving Monero anchor before settlement",
            "exit release cannot spend against a reorged lock output",
            "monero_anchor_reorg_quarantine",
            &["xmr:3451886:old-anchor", "xmr:3451886:new-anchor"],
        ),
        assertion(
            4,
            AdversarialSurface::WithheldReceipt,
            "release broadcast has no public execution receipt after the withholding grace window",
            "receipt root missing for release devnet-rx-7004 after 45000 ms",
            "invalidate the release path and publish a recovery receipt stub bound to the claim root",
            "operator cannot hide failed release execution from wallet-local recovery",
            "receipt_availability_fail_closed_gate",
            &["release:devnet-rx-7004", "receipt-window:45000ms"],
        ),
        assertion(
            5,
            AdversarialSurface::StalePqKey,
            "post-quantum release authority key age exceeds the configured ttl",
            "authority epoch 128 appears at l2 height 88240 after ttl expiry",
            "reject release authorization and require a fresh PQ authority rotation replay",
            "expired PQ keys cannot authorize forced-exit settlement",
            "pq_authority_epoch_freshness_gate",
            &["pq-authority:epoch-128", "pq-authority:epoch-129"],
        ),
        assertion(
            6,
            AdversarialSurface::ReserveShortfall,
            "reserve accounting falls below the forced-exit floor for the pending exit set",
            "vault reserve is below 18000000000000 piconero floor at epoch 42",
            "freeze new releases and require reserve top-up proof before claim settlement",
            "partial reserve release cannot strand the tail of the forced-exit queue",
            "reserve_floor_accounting_gate",
            &["reserve:devnet-vault-a", "exit-set:epoch-42"],
        ),
        assertion(
            7,
            AdversarialSurface::LiquidityExhaustion,
            "available liquidity cannot cover queued forced-exit releases plus emergency buffer",
            "liquidity buffer is below 4000000000000 piconero after queued release simulation",
            "switch to replenishment scheduling and keep claims ordered without settlement execution",
            "liquidity exhaustion cannot reorder or drop user escape claims",
            "liquidity_backstop_scheduler_gate",
            &["liquidity:devnet-pool-a", "buffer:forced-exit-epoch-42"],
        ),
        assertion(
            8,
            AdversarialSurface::MetadataLeak,
            "forced-exit batch shape exceeds the metadata privacy budget",
            "wallet cluster entropy delta breaches 6 bit disclosure budget",
            "pad or delay the release batch until the privacy budget is restored",
            "forced-exit metadata cannot link wallet activity to a Monero output",
            "metadata_budget_privacy_gate",
            &["privacy-budget:epoch-42", "batch-shape:forced-exit-devnet-42"],
        ),
        assertion(
            9,
            AdversarialSurface::WalletRecovery,
            "wallet recovery export must reconstruct the forced-exit claim without operator data",
            "local claim commitment and audit path derive the same forced-exit public input root",
            "accept only wallet-local recovery evidence and preserve the claim until proof succeeds",
            "user recovery cannot depend on sequencer, watcher, or operator cooperation",
            "wallet_local_recovery_gate",
            &["wallet:devnet-user-17", "claim:forced-exit-17-42"],
        ),
    ]
}
