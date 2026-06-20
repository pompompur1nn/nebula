use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitDepositAdmissionContractRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_DEPOSIT_ADMISSION_CONTRACT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-deposit-admission-contract-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_DEPOSIT_ADMISSION_CONTRACT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEPOSIT_ADMISSION_SUITE: &str = "monero-l2-pq-bridge-exit-deposit-admission-contract-v1";
pub const WATCHER_CERTIFICATE_SUITE: &str =
    "threshold-pq-watchers-monero-lock-admission-certificate-v1";
pub const PRIVACY_SET_SUITE: &str = "roots-only-private-l2-deposit-privacy-set-v1";
pub const LOW_FEE_BOUND_SUITE: &str = "private-l2-low-fee-deposit-admission-bounds-v1";
pub const PQ_CUSTODY_HINT_SUITE: &str = "ml-kem-ml-dsa-slh-dsa-custody-release-hints-v1";
pub const ALWAYS_AVAILABLE_EXIT_SUITE: &str =
    "forced-exit-preconditions-available-before-private-note-mint-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_500_200;
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 5;
pub const DEFAULT_EMERGENCY_WATCHER_WEIGHT: u64 = 7;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_LOW_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_EXIT_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionStatus {
    Admitted,
    Watch,
    Rejected,
}

impl AdmissionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    Mature,
    Pending,
    ReorgRisk,
}

impl FinalityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mature => "mature",
            Self::Pending => "pending",
            Self::ReorgRisk => "reorg_risk",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionGate {
    LockObservation,
    Finality,
    WatcherCertificate,
    PrivacySet,
    LowFeeBound,
    PqCustodyReleaseAuthority,
    AlwaysAvailableExit,
}

impl AdmissionGate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LockObservation => "lock_observation",
            Self::Finality => "finality",
            Self::WatcherCertificate => "watcher_certificate",
            Self::PrivacySet => "privacy_set",
            Self::LowFeeBound => "low_fee_bound",
            Self::PqCustodyReleaseAuthority => "pq_custody_release_authority",
            Self::AlwaysAvailableExit => "always_available_exit",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub admission_suite: String,
    pub watcher_certificate_suite: String,
    pub privacy_set_suite: String,
    pub low_fee_bound_suite: String,
    pub pq_custody_hint_suite: String,
    pub always_available_exit_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub base_monero_height: u64,
    pub min_confirmations: u64,
    pub min_watcher_weight: u64,
    pub emergency_watcher_weight: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub exit_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub fail_closed_on_watcher_gap: bool,
    pub production_release_allowed: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            admission_suite: DEPOSIT_ADMISSION_SUITE.to_string(),
            watcher_certificate_suite: WATCHER_CERTIFICATE_SUITE.to_string(),
            privacy_set_suite: PRIVACY_SET_SUITE.to_string(),
            low_fee_bound_suite: LOW_FEE_BOUND_SUITE.to_string(),
            pq_custody_hint_suite: PQ_CUSTODY_HINT_SUITE.to_string(),
            always_available_exit_suite: ALWAYS_AVAILABLE_EXIT_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            emergency_watcher_weight: DEFAULT_EMERGENCY_WATCHER_WEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            exit_delay_blocks: DEFAULT_EXIT_DELAY_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            fail_closed_on_watcher_gap: true,
            production_release_allowed: false,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "admission_suite": self.admission_suite,
            "watcher_certificate_suite": self.watcher_certificate_suite,
            "privacy_set_suite": self.privacy_set_suite,
            "low_fee_bound_suite": self.low_fee_bound_suite,
            "pq_custody_hint_suite": self.pq_custody_hint_suite,
            "always_available_exit_suite": self.always_available_exit_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "base_monero_height": self.base_monero_height,
            "min_confirmations": self.min_confirmations,
            "min_watcher_weight": self.min_watcher_weight,
            "emergency_watcher_weight": self.emergency_watcher_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "low_fee_bps": self.low_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "exit_delay_blocks": self.exit_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "fail_closed_on_watcher_gap": self.fail_closed_on_watcher_gap,
            "production_release_allowed": self.production_release_allowed,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositAdmissionRequest {
    pub request_id: String,
    pub depositor_commitment: String,
    pub lock_txid: String,
    pub lock_output_commitment: String,
    pub amount_commitment_root: String,
    pub deposit_commitment_root: String,
    pub view_tag_root: String,
    pub subaddress_root: String,
    pub requested_fee_bps: u64,
    pub observed_monero_height: u64,
    pub observed_depth: u64,
    pub watcher_set_root: String,
    pub pq_committee_root: String,
    pub release_claim_id: String,
    pub request_root: String,
}

impl DepositAdmissionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        depositor_commitment: impl Into<String>,
        lock_txid: impl Into<String>,
        lock_output_commitment: impl Into<String>,
        amount_commitment_root: impl Into<String>,
        view_tag_root: impl Into<String>,
        subaddress_root: impl Into<String>,
        requested_fee_bps: u64,
        observed_monero_height: u64,
        observed_depth: u64,
        watcher_set_root: impl Into<String>,
        pq_committee_root: impl Into<String>,
        release_claim_id: impl Into<String>,
    ) -> Self {
        let depositor_commitment = depositor_commitment.into();
        let lock_txid = lock_txid.into();
        let lock_output_commitment = lock_output_commitment.into();
        let amount_commitment_root = amount_commitment_root.into();
        let view_tag_root = view_tag_root.into();
        let subaddress_root = subaddress_root.into();
        let watcher_set_root = watcher_set_root.into();
        let pq_committee_root = pq_committee_root.into();
        let release_claim_id = release_claim_id.into();
        let deposit_commitment_root = deposit_commitment_root(
            &lock_txid,
            &lock_output_commitment,
            &amount_commitment_root,
            &depositor_commitment,
        );
        let request_root = deposit_admission_request_root(
            &depositor_commitment,
            &lock_txid,
            &deposit_commitment_root,
            &view_tag_root,
            &subaddress_root,
            requested_fee_bps,
            observed_monero_height,
            observed_depth,
            &watcher_set_root,
            &pq_committee_root,
            &release_claim_id,
        );
        let request_id = deposit_admission_request_id(&lock_txid, &request_root);
        Self {
            request_id,
            depositor_commitment,
            lock_txid,
            lock_output_commitment,
            amount_commitment_root,
            deposit_commitment_root,
            view_tag_root,
            subaddress_root,
            requested_fee_bps,
            observed_monero_height,
            observed_depth,
            watcher_set_root,
            pq_committee_root,
            release_claim_id,
            request_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "depositor_commitment": self.depositor_commitment,
            "lock_txid": self.lock_txid,
            "lock_output_commitment": self.lock_output_commitment,
            "amount_commitment_root": self.amount_commitment_root,
            "deposit_commitment_root": self.deposit_commitment_root,
            "view_tag_root": self.view_tag_root,
            "subaddress_root": self.subaddress_root,
            "requested_fee_bps": self.requested_fee_bps,
            "observed_monero_height": self.observed_monero_height,
            "observed_depth": self.observed_depth,
            "watcher_set_root": self.watcher_set_root,
            "pq_committee_root": self.pq_committee_root,
            "release_claim_id": self.release_claim_id,
            "request_root": self.request_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deposit_admission_request", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GateRecord {
    pub gate_id: String,
    pub gate: AdmissionGate,
    pub status: AdmissionStatus,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
    pub remediation_hint: String,
    pub gate_root: String,
}

impl GateRecord {
    pub fn new(
        gate: AdmissionGate,
        status: AdmissionStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_root: impl Into<String>,
        remediation_hint: impl Into<String>,
    ) -> Self {
        let requirement = requirement.into();
        let observed = observed.into();
        let evidence_root = evidence_root.into();
        let remediation_hint = remediation_hint.into();
        let gate_root = gate_root(
            gate,
            status,
            &requirement,
            &observed,
            &evidence_root,
            &remediation_hint,
        );
        let gate_id = gate_id(gate, &gate_root);
        Self {
            gate_id,
            gate,
            status,
            requirement,
            observed,
            evidence_root,
            remediation_hint,
            gate_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "gate": self.gate.as_str(),
            "status": self.status.as_str(),
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "remediation_hint": self.remediation_hint,
            "gate_root": self.gate_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("gate_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherCertificate {
    pub certificate_id: String,
    pub status: AdmissionStatus,
    pub watcher_set_root: String,
    pub pq_committee_root: String,
    pub threshold_weight: u64,
    pub observed_weight: u64,
    pub lock_txid: String,
    pub lock_observation_root: String,
    pub finality_root: String,
    pub certificate_root: String,
}

impl WatcherCertificate {
    pub fn from_request(
        config: &Config,
        request: &DepositAdmissionRequest,
        finality_root: &str,
    ) -> Self {
        let observed_weight = if request.observed_depth >= config.min_confirmations {
            config.min_watcher_weight
        } else {
            config.min_watcher_weight.saturating_sub(1)
        };
        let status = if observed_weight >= config.min_watcher_weight {
            AdmissionStatus::Admitted
        } else if config.fail_closed_on_watcher_gap {
            AdmissionStatus::Rejected
        } else {
            AdmissionStatus::Watch
        };
        let lock_observation_root = lock_observation_root(
            &request.lock_txid,
            &request.lock_output_commitment,
            request.observed_monero_height,
            request.observed_depth,
        );
        let certificate_root = watcher_certificate_root(
            status,
            &request.watcher_set_root,
            &request.pq_committee_root,
            config.min_watcher_weight,
            observed_weight,
            &request.lock_txid,
            &lock_observation_root,
            finality_root,
        );
        let certificate_id = watcher_certificate_id(&request.lock_txid, &certificate_root);
        Self {
            certificate_id,
            status,
            watcher_set_root: request.watcher_set_root.clone(),
            pq_committee_root: request.pq_committee_root.clone(),
            threshold_weight: config.min_watcher_weight,
            observed_weight,
            lock_txid: request.lock_txid.clone(),
            lock_observation_root,
            finality_root: finality_root.to_string(),
            certificate_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "certificate_id": self.certificate_id,
            "status": self.status.as_str(),
            "watcher_set_root": self.watcher_set_root,
            "pq_committee_root": self.pq_committee_root,
            "threshold_weight": self.threshold_weight,
            "observed_weight": self.observed_weight,
            "lock_txid": self.lock_txid,
            "lock_observation_root": self.lock_observation_root,
            "finality_root": self.finality_root,
            "certificate_root": self.certificate_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_certificate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdmissionReport {
    pub report_id: String,
    pub request_id: String,
    pub status: AdmissionStatus,
    pub finality_status: FinalityStatus,
    pub gate_root: String,
    pub watcher_certificate_root: String,
    pub privacy_set_root: String,
    pub low_fee_bound_root: String,
    pub pq_custody_release_hint_root: String,
    pub always_available_exit_root: String,
    pub admission_root: String,
    pub remediation_root: String,
    pub admitted_private_note_root: String,
}

impl AdmissionReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "request_id": self.request_id,
            "status": self.status.as_str(),
            "finality_status": self.finality_status.as_str(),
            "gate_root": self.gate_root,
            "watcher_certificate_root": self.watcher_certificate_root,
            "privacy_set_root": self.privacy_set_root,
            "low_fee_bound_root": self.low_fee_bound_root,
            "pq_custody_release_hint_root": self.pq_custody_release_hint_root,
            "always_available_exit_root": self.always_available_exit_root,
            "admission_root": self.admission_root,
            "remediation_root": self.remediation_root,
            "admitted_private_note_root": self.admitted_private_note_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("admission_report", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub requests: u64,
    pub admitted: u64,
    pub watch: u64,
    pub rejected: u64,
    pub gate_records: u64,
    pub watcher_certificates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "requests": self.requests,
            "admitted": self.admitted,
            "watch": self.watch,
            "rejected": self.rejected,
            "gate_records": self.gate_records,
            "watcher_certificates": self.watcher_certificates,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub request_root: String,
    pub gate_root: String,
    pub watcher_certificate_root: String,
    pub report_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "request_root": self.request_root,
            "gate_root": self.gate_root,
            "watcher_certificate_root": self.watcher_certificate_root,
            "report_root": self.report_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        record_root(
            "roots",
            &json!({
                "config_root": self.config_root,
                "request_root": self.request_root,
                "gate_root": self.gate_root,
                "watcher_certificate_root": self.watcher_certificate_root,
                "report_root": self.report_root,
                "counters_root": self.counters_root,
            }),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub requests: BTreeMap<String, DepositAdmissionRequest>,
    pub gates: BTreeMap<String, GateRecord>,
    pub watcher_certificates: BTreeMap<String, WatcherCertificate>,
    pub reports: BTreeMap<String, AdmissionReport>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            requests: BTreeMap::new(),
            gates: BTreeMap::new(),
            watcher_certificates: BTreeMap::new(),
            reports: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let request = DepositAdmissionRequest::new(
            "depositor-commitment-devnet-0",
            "monero-lock-txid-devnet-0",
            "lock-output-commitment-devnet-0",
            "amount-commitment-root-devnet-0",
            "view-tag-root-devnet-0",
            "subaddress-root-devnet-0",
            DEFAULT_LOW_FEE_BPS,
            DEFAULT_BASE_MONERO_HEIGHT + DEFAULT_MIN_CONFIRMATIONS,
            DEFAULT_MIN_CONFIRMATIONS,
            "watcher-set-root-devnet-0",
            "pq-committee-root-devnet-0",
            "release-claim-devnet-0",
        );
        let _ = state.admit_deposit(request);
        state
    }

    pub fn admit_deposit(&mut self, request: DepositAdmissionRequest) -> Result<AdmissionReport> {
        require(
            !self.requests.contains_key(&request.request_id),
            "request already admitted",
        )?;
        require(
            !request.lock_txid.trim().is_empty(),
            "lock_txid is required",
        )?;
        require(
            !request.release_claim_id.trim().is_empty(),
            "release_claim_id is required",
        )?;

        let finality_status = finality_status(&self.config, &request);
        let finality_root = finality_root(
            finality_status,
            request.observed_monero_height,
            request.observed_depth,
            self.config.min_confirmations,
        );
        let certificate = WatcherCertificate::from_request(&self.config, &request, &finality_root);
        let privacy_set_size = deterministic_privacy_set_size(&self.config, &request);
        let privacy_set_root = privacy_set_root(
            privacy_set_size,
            self.config.min_privacy_set_size,
            self.config.target_privacy_set_size,
            &request.view_tag_root,
            &request.subaddress_root,
        );
        let low_fee_bound_root = low_fee_bound_root(
            request.requested_fee_bps,
            self.config.low_fee_bps,
            self.config.max_user_fee_bps,
            &request.deposit_commitment_root,
        );
        let pq_custody_release_hint_root = pq_custody_release_hint_root(
            &request.pq_committee_root,
            &request.release_claim_id,
            &request.deposit_commitment_root,
            &certificate.certificate_root,
        );
        let always_available_exit_root = always_available_exit_root(
            &request.release_claim_id,
            &request.deposit_commitment_root,
            self.config.exit_delay_blocks,
            self.config.challenge_window_blocks,
            &pq_custody_release_hint_root,
        );

        let gates = vec![
            GateRecord::new(
                AdmissionGate::LockObservation,
                admitted_if(!request.lock_output_commitment.trim().is_empty()),
                "non-empty lock output commitment",
                request.lock_output_commitment.clone(),
                request.state_root(),
                "rescan deposit lock watcher adapter input",
            ),
            GateRecord::new(
                AdmissionGate::Finality,
                admitted_if(finality_status == FinalityStatus::Mature),
                format!("minimum depth {}", self.config.min_confirmations),
                format!("observed depth {}", request.observed_depth),
                finality_root.clone(),
                "wait for Monero finality or quarantine reorg candidate",
            ),
            GateRecord::new(
                AdmissionGate::WatcherCertificate,
                certificate.status,
                format!("threshold watcher weight {}", certificate.threshold_weight),
                format!("observed watcher weight {}", certificate.observed_weight),
                certificate.certificate_root.clone(),
                "collect replacement watcher certificate or slash equivocation evidence",
            ),
            GateRecord::new(
                AdmissionGate::PrivacySet,
                admitted_if(privacy_set_size >= self.config.min_privacy_set_size),
                format!("minimum privacy set {}", self.config.min_privacy_set_size),
                format!("privacy set {}", privacy_set_size),
                privacy_set_root.clone(),
                "defer mint until wallet scanner privacy set catches up",
            ),
            GateRecord::new(
                AdmissionGate::LowFeeBound,
                admitted_if(request.requested_fee_bps <= self.config.max_user_fee_bps),
                format!("max user fee bps {}", self.config.max_user_fee_bps),
                format!("requested fee bps {}", request.requested_fee_bps),
                low_fee_bound_root.clone(),
                "route through low-fee remediation or require explicit fee cap acceptance",
            ),
            GateRecord::new(
                AdmissionGate::PqCustodyReleaseAuthority,
                admitted_if(!request.pq_committee_root.trim().is_empty()),
                "PQ committee root present for custody and release authority",
                request.pq_committee_root.clone(),
                pq_custody_release_hint_root.clone(),
                "bind ML-KEM/ML-DSA/SLH-DSA authority hints before mint",
            ),
            GateRecord::new(
                AdmissionGate::AlwaysAvailableExit,
                AdmissionStatus::Admitted,
                "forced exit preconditions available at admission",
                format!(
                    "delay {} challenge {}",
                    self.config.exit_delay_blocks, self.config.challenge_window_blocks
                ),
                always_available_exit_root.clone(),
                "keep exit path armed before private note release",
            ),
        ];

        let status = aggregate_status(&gates);
        let gate_records = gates
            .iter()
            .map(GateRecord::public_record)
            .collect::<Vec<_>>();
        let gate_root = merkle_root("MONERO-L2-PQ-DEPOSIT-ADMISSION-GATES", &gate_records);
        let remediation_root = remediation_root(&gates);
        let admitted_private_note_root = admitted_private_note_root(
            status,
            &request.deposit_commitment_root,
            &certificate.certificate_root,
            &privacy_set_root,
            &always_available_exit_root,
        );
        let admission_root = admission_root(
            status,
            &request.request_root,
            &gate_root,
            &certificate.certificate_root,
            &privacy_set_root,
            &low_fee_bound_root,
            &pq_custody_release_hint_root,
            &always_available_exit_root,
        );
        let report_id = admission_report_id(&request.request_id, &admission_root);
        let report = AdmissionReport {
            report_id,
            request_id: request.request_id.clone(),
            status,
            finality_status,
            gate_root,
            watcher_certificate_root: certificate.certificate_root.clone(),
            privacy_set_root,
            low_fee_bound_root,
            pq_custody_release_hint_root,
            always_available_exit_root,
            admission_root,
            remediation_root,
            admitted_private_note_root,
        };

        self.counters.requests = self.counters.requests.saturating_add(1);
        self.counters.gate_records = self
            .counters
            .gate_records
            .saturating_add(gates.len() as u64);
        self.counters.watcher_certificates = self.counters.watcher_certificates.saturating_add(1);
        match status {
            AdmissionStatus::Admitted => {
                self.counters.admitted = self.counters.admitted.saturating_add(1)
            }
            AdmissionStatus::Watch => self.counters.watch = self.counters.watch.saturating_add(1),
            AdmissionStatus::Rejected => {
                self.counters.rejected = self.counters.rejected.saturating_add(1)
            }
        }

        for gate in gates {
            self.gates.insert(gate.gate_id.clone(), gate);
        }
        self.watcher_certificates
            .insert(certificate.certificate_id.clone(), certificate);
        self.requests.insert(request.request_id.clone(), request);
        self.reports
            .insert(report.report_id.clone(), report.clone());
        trim_reports(&mut self.reports, self.config.max_reports);
        self.refresh_roots();
        Ok(report)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "requests": self.requests.values().map(DepositAdmissionRequest::public_record).collect::<Vec<_>>(),
            "gates": self.gates.values().map(GateRecord::public_record).collect::<Vec<_>>(),
            "watcher_certificates": self.watcher_certificates.values().map(WatcherCertificate::public_record).collect::<Vec<_>>(),
            "reports": self.reports.values().map(AdmissionReport::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        let request_records = self
            .requests
            .values()
            .map(DepositAdmissionRequest::public_record)
            .collect::<Vec<_>>();
        let gate_records = self
            .gates
            .values()
            .map(GateRecord::public_record)
            .collect::<Vec<_>>();
        let certificate_records = self
            .watcher_certificates
            .values()
            .map(WatcherCertificate::public_record)
            .collect::<Vec<_>>();
        let report_records = self
            .reports
            .values()
            .map(AdmissionReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            request_root: merkle_root("MONERO-L2-PQ-DEPOSIT-ADMISSION-REQUESTS", &request_records),
            gate_root: merkle_root("MONERO-L2-PQ-DEPOSIT-ADMISSION-GATE-RECORDS", &gate_records),
            watcher_certificate_root: merkle_root(
                "MONERO-L2-PQ-DEPOSIT-ADMISSION-WATCHER-CERTIFICATES",
                &certificate_records,
            ),
            report_root: merkle_root("MONERO-L2-PQ-DEPOSIT-ADMISSION-REPORTS", &report_records),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

#[allow(clippy::too_many_arguments)]
pub fn deposit_commitment_root(
    lock_txid: &str,
    lock_output_commitment: &str,
    amount_commitment_root: &str,
    depositor_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-DEPOSIT-COMMITMENT-ROOT",
        &[
            HashPart::Str(lock_txid),
            HashPart::Str(lock_output_commitment),
            HashPart::Str(amount_commitment_root),
            HashPart::Str(depositor_commitment),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn deposit_admission_request_root(
    depositor_commitment: &str,
    lock_txid: &str,
    deposit_commitment_root: &str,
    view_tag_root: &str,
    subaddress_root: &str,
    requested_fee_bps: u64,
    observed_monero_height: u64,
    observed_depth: u64,
    watcher_set_root: &str,
    pq_committee_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-REQUEST-ROOT",
        &[
            HashPart::Str(depositor_commitment),
            HashPart::Str(lock_txid),
            HashPart::Str(deposit_commitment_root),
            HashPart::Str(view_tag_root),
            HashPart::Str(subaddress_root),
            HashPart::U64(requested_fee_bps),
            HashPart::U64(observed_monero_height),
            HashPart::U64(observed_depth),
            HashPart::Str(watcher_set_root),
            HashPart::Str(pq_committee_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn deposit_admission_request_id(lock_txid: &str, request_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-REQUEST-ID",
        &[HashPart::Str(lock_txid), HashPart::Str(request_root)],
        32,
    )
}

pub fn lock_observation_root(
    lock_txid: &str,
    lock_output_commitment: &str,
    observed_monero_height: u64,
    observed_depth: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-LOCK-OBSERVATION-ROOT",
        &[
            HashPart::Str(lock_txid),
            HashPart::Str(lock_output_commitment),
            HashPart::U64(observed_monero_height),
            HashPart::U64(observed_depth),
        ],
        32,
    )
}

pub fn finality_root(
    status: FinalityStatus,
    observed_monero_height: u64,
    observed_depth: u64,
    required_depth: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-FINALITY-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::U64(observed_monero_height),
            HashPart::U64(observed_depth),
            HashPart::U64(required_depth),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn watcher_certificate_root(
    status: AdmissionStatus,
    watcher_set_root: &str,
    pq_committee_root: &str,
    threshold_weight: u64,
    observed_weight: u64,
    lock_txid: &str,
    lock_observation_root: &str,
    finality_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-WATCHER-CERTIFICATE-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(watcher_set_root),
            HashPart::Str(pq_committee_root),
            HashPart::U64(threshold_weight),
            HashPart::U64(observed_weight),
            HashPart::Str(lock_txid),
            HashPart::Str(lock_observation_root),
            HashPart::Str(finality_root),
        ],
        32,
    )
}

pub fn watcher_certificate_id(lock_txid: &str, certificate_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-WATCHER-CERTIFICATE-ID",
        &[HashPart::Str(lock_txid), HashPart::Str(certificate_root)],
        32,
    )
}

pub fn privacy_set_root(
    privacy_set_size: u64,
    min_privacy_set_size: u64,
    target_privacy_set_size: u64,
    view_tag_root: &str,
    subaddress_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-PRIVACY-SET-ROOT",
        &[
            HashPart::U64(privacy_set_size),
            HashPart::U64(min_privacy_set_size),
            HashPart::U64(target_privacy_set_size),
            HashPart::Str(view_tag_root),
            HashPart::Str(subaddress_root),
        ],
        32,
    )
}

pub fn low_fee_bound_root(
    requested_fee_bps: u64,
    low_fee_bps: u64,
    max_user_fee_bps: u64,
    deposit_commitment_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-LOW-FEE-BOUND-ROOT",
        &[
            HashPart::U64(requested_fee_bps),
            HashPart::U64(low_fee_bps),
            HashPart::U64(max_user_fee_bps),
            HashPart::Str(deposit_commitment_root),
        ],
        32,
    )
}

pub fn pq_custody_release_hint_root(
    pq_committee_root: &str,
    release_claim_id: &str,
    deposit_commitment_root: &str,
    watcher_certificate_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-PQ-CUSTODY-RELEASE-HINT-ROOT",
        &[
            HashPart::Str(pq_committee_root),
            HashPart::Str(release_claim_id),
            HashPart::Str(deposit_commitment_root),
            HashPart::Str(watcher_certificate_root),
        ],
        32,
    )
}

pub fn always_available_exit_root(
    release_claim_id: &str,
    deposit_commitment_root: &str,
    exit_delay_blocks: u64,
    challenge_window_blocks: u64,
    pq_custody_release_hint_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-ALWAYS-AVAILABLE-EXIT-ROOT",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(deposit_commitment_root),
            HashPart::U64(exit_delay_blocks),
            HashPart::U64(challenge_window_blocks),
            HashPart::Str(pq_custody_release_hint_root),
        ],
        32,
    )
}

pub fn gate_root(
    gate: AdmissionGate,
    status: AdmissionStatus,
    requirement: &str,
    observed: &str,
    evidence_root: &str,
    remediation_hint: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-GATE-ROOT",
        &[
            HashPart::Str(gate.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(requirement),
            HashPart::Str(observed),
            HashPart::Str(evidence_root),
            HashPart::Str(remediation_hint),
        ],
        32,
    )
}

pub fn gate_id(gate: AdmissionGate, gate_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-GATE-ID",
        &[HashPart::Str(gate.as_str()), HashPart::Str(gate_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn admission_root(
    status: AdmissionStatus,
    request_root: &str,
    gate_root: &str,
    watcher_certificate_root: &str,
    privacy_set_root: &str,
    low_fee_bound_root: &str,
    pq_custody_release_hint_root: &str,
    always_available_exit_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(request_root),
            HashPart::Str(gate_root),
            HashPart::Str(watcher_certificate_root),
            HashPart::Str(privacy_set_root),
            HashPart::Str(low_fee_bound_root),
            HashPart::Str(pq_custody_release_hint_root),
            HashPart::Str(always_available_exit_root),
        ],
        32,
    )
}

pub fn admission_report_id(request_id: &str, admission_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-REPORT-ID",
        &[HashPart::Str(request_id), HashPart::Str(admission_root)],
        32,
    )
}

pub fn admitted_private_note_root(
    status: AdmissionStatus,
    deposit_commitment_root: &str,
    watcher_certificate_root: &str,
    privacy_set_root: &str,
    always_available_exit_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-PRIVATE-NOTE-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(deposit_commitment_root),
            HashPart::Str(watcher_certificate_root),
            HashPart::Str(privacy_set_root),
            HashPart::Str(always_available_exit_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-DEPOSIT-ADMISSION-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn finality_status(config: &Config, request: &DepositAdmissionRequest) -> FinalityStatus {
    if request.observed_depth >= config.min_confirmations {
        FinalityStatus::Mature
    } else if request.observed_monero_height < config.base_monero_height {
        FinalityStatus::ReorgRisk
    } else {
        FinalityStatus::Pending
    }
}

fn admitted_if(condition: bool) -> AdmissionStatus {
    if condition {
        AdmissionStatus::Admitted
    } else {
        AdmissionStatus::Watch
    }
}

fn aggregate_status(gates: &[GateRecord]) -> AdmissionStatus {
    if gates
        .iter()
        .any(|gate| gate.status == AdmissionStatus::Rejected)
    {
        AdmissionStatus::Rejected
    } else if gates
        .iter()
        .any(|gate| gate.status == AdmissionStatus::Watch)
    {
        AdmissionStatus::Watch
    } else {
        AdmissionStatus::Admitted
    }
}

fn deterministic_privacy_set_size(config: &Config, request: &DepositAdmissionRequest) -> u64 {
    if request.view_tag_root.trim().is_empty() || request.subaddress_root.trim().is_empty() {
        config.min_privacy_set_size.saturating_sub(1)
    } else {
        config
            .min_privacy_set_size
            .saturating_add(request.observed_depth.saturating_mul(64))
            .min(config.target_privacy_set_size)
    }
}

fn remediation_root(gates: &[GateRecord]) -> String {
    let records = gates
        .iter()
        .filter(|gate| gate.status != AdmissionStatus::Admitted)
        .map(GateRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-DEPOSIT-ADMISSION-REMEDIATION", &records)
}

fn trim_reports(reports: &mut BTreeMap<String, AdmissionReport>, max_reports: usize) {
    while reports.len() > max_reports {
        if let Some(first_key) = reports.keys().next().cloned() {
            reports.remove(&first_key);
        } else {
            break;
        }
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
