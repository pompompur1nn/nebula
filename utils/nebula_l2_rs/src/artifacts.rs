use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    config::ConfigManifest,
    daemon::DaemonStorageCommit,
    devnet::{DevnetRunSummary, DevnetStepReceipt},
    hash::{canonical_json_string, domain_hash, merkle_root, HashPart},
    rpc::RpcResponse,
    storage::StorageState,
    telemetry::TelemetrySnapshot,
    CHAIN_ID,
};

pub type ArtifactResult<T> = Result<T, String>;

pub const ARTIFACT_SCHEMA_VERSION: u64 = 1;
pub const ARTIFACT_PROTOCOL_VERSION: &str = "nebula-l2-artifacts-v1";
pub const ARTIFACT_DEFAULT_LABEL: &str = "artifact";
pub const ARTIFACT_PAYLOAD_KIND_JSON: &str = "json_payload";
pub const ARTIFACT_PAYLOAD_KIND_PUBLIC_RECORD: &str = "public_record";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    JsonPayload,
    DevnetRunSummary,
    DevnetStepReceipt,
    TelemetrySnapshot,
    StorageManifest,
    DaemonStorageCommit,
    ConfigManifest,
    RpcResponse,
    ArtifactBundle,
    ReplayInput,
    ReplayReport,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JsonPayload => "json_payload",
            Self::DevnetRunSummary => "devnet_run_summary",
            Self::DevnetStepReceipt => "devnet_step_receipt",
            Self::TelemetrySnapshot => "telemetry_snapshot",
            Self::StorageManifest => "storage_manifest",
            Self::DaemonStorageCommit => "daemon_storage_commit",
            Self::ConfigManifest => "config_manifest",
            Self::RpcResponse => "rpc_response",
            Self::ArtifactBundle => "artifact_bundle",
            Self::ReplayInput => "replay_input",
            Self::ReplayReport => "replay_report",
        }
    }

    pub fn from_name(name: &str) -> ArtifactResult<Self> {
        match name {
            "json_payload" => Ok(Self::JsonPayload),
            "devnet_run_summary" => Ok(Self::DevnetRunSummary),
            "devnet_step_receipt" => Ok(Self::DevnetStepReceipt),
            "telemetry_snapshot" => Ok(Self::TelemetrySnapshot),
            "storage_manifest" => Ok(Self::StorageManifest),
            "daemon_storage_commit" => Ok(Self::DaemonStorageCommit),
            "config_manifest" => Ok(Self::ConfigManifest),
            "rpc_response" => Ok(Self::RpcResponse),
            "artifact_bundle" => Ok(Self::ArtifactBundle),
            "replay_input" => Ok(Self::ReplayInput),
            "replay_report" => Ok(Self::ReplayReport),
            other => Err(format!("unknown artifact kind: {other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayCheckStatus {
    Pending,
    Matched,
    Missing,
    Mismatched,
    Unexpected,
}

impl ReplayCheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Matched => "matched",
            Self::Missing => "missing",
            Self::Mismatched => "mismatched",
            Self::Unexpected => "unexpected",
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, Self::Matched)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunArtifact {
    pub artifact_id: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub artifact_kind: ArtifactKind,
    pub label: String,
    pub payload_kind: String,
    pub payload_root: String,
    pub payload_bytes: u64,
    pub source_id: Option<String>,
    pub source_root: Option<String>,
    pub run_id: Option<String>,
    pub step_id: Option<String>,
    pub height: Option<u64>,
    pub timestamp_ms: Option<u64>,
    pub metadata_root: String,
    pub provenance_root: String,
}

impl RunArtifact {
    #[allow(clippy::too_many_arguments)]
    pub fn from_roots(
        artifact_kind: ArtifactKind,
        label: impl Into<String>,
        payload_kind: impl Into<String>,
        payload_root: impl Into<String>,
        payload_bytes: u64,
        source_id: Option<String>,
        source_root: Option<String>,
        run_id: Option<String>,
        step_id: Option<String>,
        height: Option<u64>,
        timestamp_ms: Option<u64>,
        metadata_root: impl Into<String>,
    ) -> Self {
        let label = normalize_label(label.into());
        let payload_root = payload_root.into();
        let payload_kind = normalize_label(payload_kind.into());
        let metadata_root = normalize_metadata_root(metadata_root.into());
        let provenance_root = artifact_provenance_root(
            artifact_kind,
            &label,
            &payload_kind,
            source_id.as_deref(),
            source_root.as_deref(),
            run_id.as_deref(),
            step_id.as_deref(),
            height,
            timestamp_ms,
            &metadata_root,
        );
        let artifact_id = artifact_id(artifact_kind, &label, &payload_root, &provenance_root);
        Self {
            artifact_id,
            schema_version: ARTIFACT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            artifact_kind,
            label,
            payload_kind,
            payload_root,
            payload_bytes,
            source_id,
            source_root,
            run_id,
            step_id,
            height,
            timestamp_ms,
            metadata_root,
            provenance_root,
        }
    }

    pub fn from_json_payload(
        artifact_kind: ArtifactKind,
        label: impl Into<String>,
        payload: &Value,
    ) -> Self {
        Self::from_json_payload_with_metadata(artifact_kind, label, payload, &json!({}))
    }

    pub fn from_json_payload_with_metadata(
        artifact_kind: ArtifactKind,
        label: impl Into<String>,
        payload: &Value,
        metadata: &Value,
    ) -> Self {
        let payload_root = artifact_payload_root(artifact_kind, payload);
        Self::from_roots(
            artifact_kind,
            label,
            ARTIFACT_PAYLOAD_KIND_JSON,
            payload_root.clone(),
            canonical_json_bytes(payload),
            None,
            Some(payload_root),
            None,
            None,
            None,
            None,
            artifact_metadata_root(metadata),
        )
    }

    pub fn from_devnet_summary(summary: &DevnetRunSummary) -> Self {
        let record = summary.public_record();
        Self::from_source_record(
            ArtifactKind::DevnetRunSummary,
            "devnet-run-summary",
            Some(summary.summary_id.clone()),
            Some(summary.summary_root()),
            Some(summary.run_id.clone()),
            None,
            Some(summary.final_height),
            None,
            &record,
        )
    }

    pub fn from_step_receipt(receipt: &DevnetStepReceipt) -> Self {
        let record = receipt.public_record();
        Self::from_source_record(
            ArtifactKind::DevnetStepReceipt,
            "devnet-step-receipt",
            Some(receipt.step_id.clone()),
            Some(receipt.receipt_root()),
            Some(receipt.run_id.clone()),
            Some(receipt.step_id.clone()),
            Some(receipt.height),
            Some(receipt.timestamp_ms),
            &record,
        )
    }

    pub fn from_telemetry_snapshot(snapshot: &TelemetrySnapshot) -> Self {
        let record = snapshot.public_record();
        Self::from_source_record(
            ArtifactKind::TelemetrySnapshot,
            "telemetry-snapshot",
            Some(snapshot.snapshot_id.clone()),
            Some(snapshot.snapshot_root()),
            None,
            None,
            Some(snapshot.height),
            Some(snapshot.timestamp_ms),
            &record,
        )
    }

    pub fn from_storage_manifest(storage: &StorageState) -> Self {
        let record = storage.public_record();
        Self::from_source_record(
            ArtifactKind::StorageManifest,
            "storage-manifest",
            storage.latest_snapshot_id(),
            Some(storage.manifest_root()),
            None,
            None,
            None,
            None,
            &record,
        )
    }

    pub fn from_daemon_storage_commit(commit: &DaemonStorageCommit) -> Self {
        let record = commit.public_record();
        Self::from_source_record(
            ArtifactKind::DaemonStorageCommit,
            "daemon-storage-commit",
            Some(commit.commit_id.clone()),
            Some(commit.commit_root()),
            None,
            None,
            Some(commit.block_height),
            Some(commit.created_at_ms),
            &record,
        )
    }

    pub fn from_config_manifest(manifest: &ConfigManifest) -> Self {
        let record = manifest.public_record();
        Self::from_source_record(
            ArtifactKind::ConfigManifest,
            "config-manifest",
            Some(manifest.manifest_root.clone()),
            Some(manifest.root()),
            None,
            None,
            None,
            None,
            &record,
        )
    }

    pub fn from_rpc_response(response: &RpcResponse) -> Self {
        let record = response.public_record();
        Self::from_source_record(
            ArtifactKind::RpcResponse,
            "rpc-response",
            Some(response.response_id.clone()),
            Some(response.root()),
            None,
            None,
            Some(response.produced_at_height),
            None,
            &record,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_source_record(
        artifact_kind: ArtifactKind,
        label: impl Into<String>,
        source_id: Option<String>,
        source_root: Option<String>,
        run_id: Option<String>,
        step_id: Option<String>,
        height: Option<u64>,
        timestamp_ms: Option<u64>,
        record: &Value,
    ) -> Self {
        Self::from_roots(
            artifact_kind,
            label,
            ARTIFACT_PAYLOAD_KIND_PUBLIC_RECORD,
            artifact_payload_root(artifact_kind, record),
            canonical_json_bytes(record),
            source_id,
            source_root,
            run_id,
            step_id,
            height,
            timestamp_ms,
            artifact_metadata_root(&json!({})),
        )
    }

    pub fn expected_provenance_root(&self) -> String {
        artifact_provenance_root(
            self.artifact_kind,
            &self.label,
            &self.payload_kind,
            self.source_id.as_deref(),
            self.source_root.as_deref(),
            self.run_id.as_deref(),
            self.step_id.as_deref(),
            self.height,
            self.timestamp_ms,
            &self.metadata_root,
        )
    }

    pub fn verify_roots(&self) -> bool {
        self.provenance_root == self.expected_provenance_root()
            && self.artifact_id
                == artifact_id(
                    self.artifact_kind,
                    &self.label,
                    &self.payload_root,
                    &self.provenance_root,
                )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "run_artifact",
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "artifact_protocol_version": ARTIFACT_PROTOCOL_VERSION,
            "artifact_id": self.artifact_id,
            "artifact_kind": self.artifact_kind.as_str(),
            "label": self.label,
            "payload_kind": self.payload_kind,
            "payload_root": self.payload_root,
            "payload_bytes": self.payload_bytes,
            "source_id": self.source_id,
            "source_root": self.source_root,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "metadata_root": self.metadata_root,
            "provenance_root": self.provenance_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ARTIFACT-RUN-ARTIFACT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBundle {
    pub bundle_id: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub label: String,
    pub run_id: Option<String>,
    pub artifact_count: u64,
    pub artifact_root: String,
    pub payload_root: String,
    pub provenance_root: String,
    pub kind_root: String,
    pub artifacts: Vec<RunArtifact>,
}

impl ArtifactBundle {
    pub fn empty(label: impl Into<String>, run_id: Option<String>) -> Self {
        Self::from_artifacts(label, run_id, Vec::new()).expect("empty artifact bundle")
    }

    pub fn from_artifacts(
        label: impl Into<String>,
        run_id: Option<String>,
        artifacts: Vec<RunArtifact>,
    ) -> ArtifactResult<Self> {
        ensure_unique_artifacts(&artifacts)?;
        let mut bundle = Self {
            bundle_id: String::new(),
            schema_version: ARTIFACT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            label: normalize_label(label.into()),
            run_id,
            artifact_count: 0,
            artifact_root: String::new(),
            payload_root: String::new(),
            provenance_root: String::new(),
            kind_root: String::new(),
            artifacts: sorted_artifacts(&artifacts),
        };
        bundle.refresh_roots();
        Ok(bundle)
    }

    pub fn add_artifact(&mut self, artifact: RunArtifact) -> ArtifactResult<()> {
        if self
            .artifacts
            .iter()
            .any(|existing| existing.artifact_id == artifact.artifact_id)
        {
            return Err(format!("duplicate artifact id: {}", artifact.artifact_id));
        }
        self.artifacts.push(artifact);
        self.artifacts = sorted_artifacts(&self.artifacts);
        self.refresh_roots();
        Ok(())
    }

    pub fn create_replay_input(&self, label: impl Into<String>) -> ReplayInput {
        ReplayInput::from_bundle(label, self)
    }

    pub fn verify_expected_roots(&self, replay_input: &ReplayInput) -> ReplayReport {
        replay_input.verify_expected_roots(&self.artifacts)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "artifact_bundle",
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "artifact_protocol_version": ARTIFACT_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "label": self.label,
            "run_id": self.run_id,
            "artifact_count": self.artifact_count,
            "artifact_root": self.artifact_root,
            "payload_root": self.payload_root,
            "provenance_root": self.provenance_root,
            "kind_root": self.kind_root,
            "artifacts": self.artifacts.iter().map(RunArtifact::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ARTIFACT-BUNDLE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    fn refresh_roots(&mut self) {
        self.artifacts = sorted_artifacts(&self.artifacts);
        self.artifact_count = self.artifacts.len() as u64;
        self.artifact_root = artifact_records_root("ARTIFACT-BUNDLE-ARTIFACT", &self.artifacts);
        self.payload_root = artifact_payloads_root(&self.artifacts);
        self.provenance_root = artifact_provenances_root(&self.artifacts);
        self.kind_root = artifact_kind_inventory_root(&self.artifacts);
        self.bundle_id = artifact_bundle_id(
            &self.label,
            self.run_id.as_deref().unwrap_or(""),
            &self.artifact_root,
            &self.payload_root,
            &self.provenance_root,
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayExpectation {
    pub expectation_id: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub artifact_id: String,
    pub artifact_kind: ArtifactKind,
    pub label: String,
    pub expected_payload_root: String,
    pub expected_source_root: Option<String>,
    pub expected_provenance_root: String,
    pub expected_artifact_root: String,
    pub run_id: Option<String>,
    pub step_id: Option<String>,
    pub height: Option<u64>,
    pub required: bool,
}

impl ReplayExpectation {
    pub fn from_artifact(artifact: &RunArtifact) -> Self {
        Self::from_artifact_with_required(artifact, true)
    }

    pub fn from_artifact_with_required(artifact: &RunArtifact, required: bool) -> Self {
        let expected_artifact_root = artifact.state_root();
        let expectation_id = replay_expectation_id(
            &artifact.artifact_id,
            &artifact.payload_root,
            artifact.source_root.as_deref().unwrap_or(""),
            &artifact.provenance_root,
            &expected_artifact_root,
        );
        Self {
            expectation_id,
            schema_version: ARTIFACT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            artifact_id: artifact.artifact_id.clone(),
            artifact_kind: artifact.artifact_kind,
            label: artifact.label.clone(),
            expected_payload_root: artifact.payload_root.clone(),
            expected_source_root: artifact.source_root.clone(),
            expected_provenance_root: artifact.provenance_root.clone(),
            expected_artifact_root,
            run_id: artifact.run_id.clone(),
            step_id: artifact.step_id.clone(),
            height: artifact.height,
            required,
        }
    }

    pub fn check_artifact(&self, observed: Option<&RunArtifact>) -> ReplayCheckStatus {
        match observed {
            Some(artifact)
                if artifact.artifact_id == self.artifact_id
                    && artifact.artifact_kind == self.artifact_kind
                    && artifact.payload_root == self.expected_payload_root
                    && artifact.source_root == self.expected_source_root
                    && artifact.provenance_root == self.expected_provenance_root
                    && artifact.state_root() == self.expected_artifact_root =>
            {
                ReplayCheckStatus::Matched
            }
            Some(_) => ReplayCheckStatus::Mismatched,
            None if self.required => ReplayCheckStatus::Missing,
            None => ReplayCheckStatus::Pending,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "replay_expectation",
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "artifact_protocol_version": ARTIFACT_PROTOCOL_VERSION,
            "expectation_id": self.expectation_id,
            "artifact_id": self.artifact_id,
            "artifact_kind": self.artifact_kind.as_str(),
            "label": self.label,
            "expected_payload_root": self.expected_payload_root,
            "expected_source_root": self.expected_source_root,
            "expected_provenance_root": self.expected_provenance_root,
            "expected_artifact_root": self.expected_artifact_root,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "height": self.height,
            "required": self.required,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ARTIFACT-REPLAY-EXPECTATION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayInput {
    pub input_id: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub label: String,
    pub bundle_id: String,
    pub artifact_root: String,
    pub expectation_root: String,
    pub expectations: Vec<ReplayExpectation>,
}

impl ReplayInput {
    pub fn from_bundle(label: impl Into<String>, bundle: &ArtifactBundle) -> Self {
        let expectations = bundle
            .artifacts
            .iter()
            .map(ReplayExpectation::from_artifact)
            .collect::<Vec<_>>();
        Self::from_expectations(
            label,
            bundle.bundle_id.clone(),
            bundle.artifact_root.clone(),
            expectations,
        )
    }

    pub fn from_expectations(
        label: impl Into<String>,
        bundle_id: impl Into<String>,
        artifact_root: impl Into<String>,
        expectations: Vec<ReplayExpectation>,
    ) -> Self {
        let expectations = sorted_expectations(&expectations);
        let expectation_root = expectation_records_root(&expectations);
        let label = normalize_label(label.into());
        let bundle_id = bundle_id.into();
        let artifact_root = artifact_root.into();
        let input_id = replay_input_id(&label, &bundle_id, &expectation_root);
        Self {
            input_id,
            schema_version: ARTIFACT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            label,
            bundle_id,
            artifact_root,
            expectation_root,
            expectations,
        }
    }

    pub fn verify_expected_roots(&self, observed_artifacts: &[RunArtifact]) -> ReplayReport {
        let observed_artifacts = sorted_artifacts(observed_artifacts);
        let observed_by_id = observed_artifacts
            .iter()
            .map(|artifact| (artifact.artifact_id.as_str(), artifact))
            .collect::<BTreeMap<_, _>>();
        let mut seen = BTreeSet::new();
        let mut checks = self
            .expectations
            .iter()
            .map(|expectation| {
                seen.insert(expectation.artifact_id.clone());
                ReplayCheck::from_expectation(
                    expectation,
                    observed_by_id
                        .get(expectation.artifact_id.as_str())
                        .copied(),
                )
            })
            .collect::<Vec<_>>();
        for artifact in &observed_artifacts {
            if !seen.contains(&artifact.artifact_id) {
                checks.push(ReplayCheck::from_unexpected(artifact));
            }
        }
        ReplayReport::from_checks(self, &observed_artifacts, checks)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "replay_input",
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "artifact_protocol_version": ARTIFACT_PROTOCOL_VERSION,
            "input_id": self.input_id,
            "label": self.label,
            "bundle_id": self.bundle_id,
            "artifact_root": self.artifact_root,
            "expectation_root": self.expectation_root,
            "expectations": self.expectations.iter().map(ReplayExpectation::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ARTIFACT-REPLAY-INPUT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCheck {
    pub check_id: String,
    pub expectation_id: Option<String>,
    pub artifact_id: String,
    pub artifact_kind: ArtifactKind,
    pub label: String,
    pub status: ReplayCheckStatus,
    pub expected_payload_root: Option<String>,
    pub observed_payload_root: Option<String>,
    pub expected_source_root: Option<String>,
    pub observed_source_root: Option<String>,
    pub expected_provenance_root: Option<String>,
    pub observed_provenance_root: Option<String>,
    pub expected_artifact_root: Option<String>,
    pub observed_artifact_root: Option<String>,
}

impl ReplayCheck {
    pub fn from_expectation(
        expectation: &ReplayExpectation,
        observed: Option<&RunArtifact>,
    ) -> Self {
        let status = expectation.check_artifact(observed);
        let observed_payload_root = observed.map(|artifact| artifact.payload_root.clone());
        let observed_source_root = observed.and_then(|artifact| artifact.source_root.clone());
        let observed_provenance_root = observed.map(|artifact| artifact.provenance_root.clone());
        let observed_artifact_root = observed.map(RunArtifact::state_root);
        let check_id = replay_check_id(
            Some(&expectation.expectation_id),
            &expectation.artifact_id,
            status,
            Some(&expectation.expected_payload_root),
            observed_payload_root.as_deref(),
        );
        Self {
            check_id,
            expectation_id: Some(expectation.expectation_id.clone()),
            artifact_id: expectation.artifact_id.clone(),
            artifact_kind: expectation.artifact_kind,
            label: expectation.label.clone(),
            status,
            expected_payload_root: Some(expectation.expected_payload_root.clone()),
            observed_payload_root,
            expected_source_root: expectation.expected_source_root.clone(),
            observed_source_root,
            expected_provenance_root: Some(expectation.expected_provenance_root.clone()),
            observed_provenance_root,
            expected_artifact_root: Some(expectation.expected_artifact_root.clone()),
            observed_artifact_root,
        }
    }

    pub fn from_unexpected(artifact: &RunArtifact) -> Self {
        let status = ReplayCheckStatus::Unexpected;
        let observed_artifact_root = artifact.state_root();
        let check_id = replay_check_id(
            None,
            &artifact.artifact_id,
            status,
            None,
            Some(&artifact.payload_root),
        );
        Self {
            check_id,
            expectation_id: None,
            artifact_id: artifact.artifact_id.clone(),
            artifact_kind: artifact.artifact_kind,
            label: artifact.label.clone(),
            status,
            expected_payload_root: None,
            observed_payload_root: Some(artifact.payload_root.clone()),
            expected_source_root: None,
            observed_source_root: artifact.source_root.clone(),
            expected_provenance_root: None,
            observed_provenance_root: Some(artifact.provenance_root.clone()),
            expected_artifact_root: None,
            observed_artifact_root: Some(observed_artifact_root),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "replay_check",
            "chain_id": CHAIN_ID,
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "artifact_protocol_version": ARTIFACT_PROTOCOL_VERSION,
            "check_id": self.check_id,
            "expectation_id": self.expectation_id,
            "artifact_id": self.artifact_id,
            "artifact_kind": self.artifact_kind.as_str(),
            "label": self.label,
            "status": self.status.as_str(),
            "expected_payload_root": self.expected_payload_root,
            "observed_payload_root": self.observed_payload_root,
            "expected_source_root": self.expected_source_root,
            "observed_source_root": self.observed_source_root,
            "expected_provenance_root": self.expected_provenance_root,
            "observed_provenance_root": self.observed_provenance_root,
            "expected_artifact_root": self.expected_artifact_root,
            "observed_artifact_root": self.observed_artifact_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ARTIFACT-REPLAY-CHECK",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayReport {
    pub report_id: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub input_id: String,
    pub bundle_id: String,
    pub status: ReplayCheckStatus,
    pub expectation_root: String,
    pub observed_root: String,
    pub check_root: String,
    pub matched_count: u64,
    pub missing_count: u64,
    pub mismatched_count: u64,
    pub unexpected_count: u64,
    pub checks: Vec<ReplayCheck>,
}

impl ReplayReport {
    pub fn from_checks(
        replay_input: &ReplayInput,
        observed_artifacts: &[RunArtifact],
        checks: Vec<ReplayCheck>,
    ) -> Self {
        let checks = sorted_checks(&checks);
        let matched_count = status_count(&checks, ReplayCheckStatus::Matched);
        let missing_count = status_count(&checks, ReplayCheckStatus::Missing);
        let mismatched_count = status_count(&checks, ReplayCheckStatus::Mismatched);
        let unexpected_count = status_count(&checks, ReplayCheckStatus::Unexpected);
        let status = aggregate_status(
            matched_count,
            missing_count,
            mismatched_count,
            unexpected_count,
        );
        let observed_root = artifact_records_root("ARTIFACT-REPLAY-OBSERVED", observed_artifacts);
        let check_root = check_records_root(&checks);
        let report_id = replay_report_id(&replay_input.input_id, &observed_root, &check_root);
        Self {
            report_id,
            schema_version: ARTIFACT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            input_id: replay_input.input_id.clone(),
            bundle_id: replay_input.bundle_id.clone(),
            status,
            expectation_root: replay_input.expectation_root.clone(),
            observed_root,
            check_root,
            matched_count,
            missing_count,
            mismatched_count,
            unexpected_count,
            checks,
        }
    }

    pub fn is_success(&self) -> bool {
        self.status.is_success()
            && self.missing_count == 0
            && self.mismatched_count == 0
            && self.unexpected_count == 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "replay_report",
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "artifact_protocol_version": ARTIFACT_PROTOCOL_VERSION,
            "report_id": self.report_id,
            "input_id": self.input_id,
            "bundle_id": self.bundle_id,
            "status": self.status.as_str(),
            "expectation_root": self.expectation_root,
            "observed_root": self.observed_root,
            "check_root": self.check_root,
            "matched_count": self.matched_count,
            "missing_count": self.missing_count,
            "mismatched_count": self.mismatched_count,
            "unexpected_count": self.unexpected_count,
            "checks": self.checks.iter().map(ReplayCheck::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ARTIFACT-REPLAY-REPORT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactIndex {
    pub index_id: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub artifact_count: u64,
    pub artifact_ids: Vec<String>,
    pub artifact_root: String,
    pub kind_root: String,
    pub label_root: String,
    pub run_root: String,
    pub by_kind: BTreeMap<String, u64>,
    pub by_run: BTreeMap<String, u64>,
}

impl ArtifactIndex {
    pub fn from_artifacts(artifacts: &[RunArtifact]) -> Self {
        let artifacts = sorted_artifacts(artifacts);
        let artifact_ids = artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.clone())
            .collect::<Vec<_>>();
        let by_kind = count_by_kind(&artifacts);
        let by_run = count_by_run(&artifacts);
        let artifact_root = artifact_records_root("ARTIFACT-INDEX-ARTIFACT", &artifacts);
        let kind_root = map_count_root("ARTIFACT-INDEX-KIND", &by_kind);
        let label_root = label_inventory_root(&artifacts);
        let run_root = map_count_root("ARTIFACT-INDEX-RUN", &by_run);
        let index_id = domain_hash(
            "ARTIFACT-INDEX-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&artifact_root),
                HashPart::Str(&kind_root),
                HashPart::Str(&label_root),
                HashPart::Str(&run_root),
            ],
            32,
        );
        Self {
            index_id,
            schema_version: ARTIFACT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            artifact_count: artifacts.len() as u64,
            artifact_ids,
            artifact_root,
            kind_root,
            label_root,
            run_root,
            by_kind,
            by_run,
        }
    }

    pub fn from_bundle(bundle: &ArtifactBundle) -> Self {
        Self::from_artifacts(&bundle.artifacts)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "artifact_index",
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "artifact_protocol_version": ARTIFACT_PROTOCOL_VERSION,
            "index_id": self.index_id,
            "artifact_count": self.artifact_count,
            "artifact_ids": self.artifact_ids,
            "artifact_root": self.artifact_root,
            "kind_root": self.kind_root,
            "label_root": self.label_root,
            "run_root": self.run_root,
            "by_kind": self.by_kind,
            "by_run": self.by_run,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ARTIFACT-INDEX",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactState {
    pub schema_version: u64,
    pub chain_id: String,
    pub artifacts: BTreeMap<String, RunArtifact>,
    pub bundles: BTreeMap<String, ArtifactBundle>,
    pub replay_inputs: BTreeMap<String, ReplayInput>,
    pub replay_reports: BTreeMap<String, ReplayReport>,
}

impl Default for ArtifactState {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactState {
    pub fn new() -> Self {
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            artifacts: BTreeMap::new(),
            bundles: BTreeMap::new(),
            replay_inputs: BTreeMap::new(),
            replay_reports: BTreeMap::new(),
        }
    }

    pub fn add_artifact(&mut self, artifact: RunArtifact) -> ArtifactResult<String> {
        let artifact_id = artifact.artifact_id.clone();
        if self.artifacts.contains_key(&artifact_id) {
            return Err(format!("duplicate artifact id: {artifact_id}"));
        }
        self.artifacts.insert(artifact_id.clone(), artifact);
        Ok(artifact_id)
    }

    pub fn add_artifacts(&mut self, artifacts: Vec<RunArtifact>) -> ArtifactResult<Vec<String>> {
        let mut added = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            added.push(self.add_artifact(artifact)?);
        }
        Ok(added)
    }

    pub fn add_bundle(&mut self, bundle: ArtifactBundle) -> ArtifactResult<String> {
        let bundle_id = bundle.bundle_id.clone();
        if self.bundles.contains_key(&bundle_id) {
            return Err(format!("duplicate artifact bundle id: {bundle_id}"));
        }
        self.bundles.insert(bundle_id.clone(), bundle);
        Ok(bundle_id)
    }

    pub fn build_bundle(
        &mut self,
        label: impl Into<String>,
        run_id: Option<String>,
    ) -> ArtifactResult<ArtifactBundle> {
        let artifacts = self.artifacts.values().cloned().collect::<Vec<_>>();
        let bundle = ArtifactBundle::from_artifacts(label, run_id, artifacts)?;
        self.bundles
            .insert(bundle.bundle_id.clone(), bundle.clone());
        Ok(bundle)
    }

    pub fn build_bundle_from_ids(
        &mut self,
        label: impl Into<String>,
        run_id: Option<String>,
        artifact_ids: &[String],
    ) -> ArtifactResult<ArtifactBundle> {
        let mut artifacts = Vec::with_capacity(artifact_ids.len());
        for artifact_id in artifact_ids {
            let artifact = self
                .artifacts
                .get(artifact_id)
                .cloned()
                .ok_or_else(|| format!("unknown artifact id: {artifact_id}"))?;
            artifacts.push(artifact);
        }
        let bundle = ArtifactBundle::from_artifacts(label, run_id, artifacts)?;
        self.bundles
            .insert(bundle.bundle_id.clone(), bundle.clone());
        Ok(bundle)
    }

    pub fn create_replay_input(
        &mut self,
        label: impl Into<String>,
        bundle: &ArtifactBundle,
    ) -> ReplayInput {
        let replay_input = bundle.create_replay_input(label);
        self.replay_inputs
            .insert(replay_input.input_id.clone(), replay_input.clone());
        replay_input
    }

    pub fn create_replay_expectations(
        &self,
        artifact_ids: &[String],
    ) -> ArtifactResult<Vec<ReplayExpectation>> {
        let mut expectations = Vec::with_capacity(artifact_ids.len());
        for artifact_id in artifact_ids {
            let artifact = self
                .artifacts
                .get(artifact_id)
                .ok_or_else(|| format!("unknown artifact id: {artifact_id}"))?;
            expectations.push(ReplayExpectation::from_artifact(artifact));
        }
        Ok(sorted_expectations(&expectations))
    }

    pub fn verify_expected_roots(&mut self, replay_input: &ReplayInput) -> ReplayReport {
        let observed = self.artifacts.values().cloned().collect::<Vec<_>>();
        let report = replay_input.verify_expected_roots(&observed);
        self.replay_reports
            .insert(report.report_id.clone(), report.clone());
        report
    }

    pub fn index(&self) -> ArtifactIndex {
        ArtifactIndex::from_artifacts(&self.artifacts.values().cloned().collect::<Vec<_>>())
    }

    pub fn public_record(&self) -> Value {
        let artifact_records = self
            .artifacts
            .values()
            .map(RunArtifact::public_record)
            .collect::<Vec<_>>();
        let bundle_records = self
            .bundles
            .values()
            .map(ArtifactBundle::public_record)
            .collect::<Vec<_>>();
        let replay_input_records = self
            .replay_inputs
            .values()
            .map(ReplayInput::public_record)
            .collect::<Vec<_>>();
        let replay_report_records = self
            .replay_reports
            .values()
            .map(ReplayReport::public_record)
            .collect::<Vec<_>>();
        json!({
            "kind": "artifact_state",
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "artifact_protocol_version": ARTIFACT_PROTOCOL_VERSION,
            "artifact_count": self.artifacts.len() as u64,
            "bundle_count": self.bundles.len() as u64,
            "replay_input_count": self.replay_inputs.len() as u64,
            "replay_report_count": self.replay_reports.len() as u64,
            "artifact_root": merkle_root("ARTIFACT-STATE-ARTIFACT", &artifact_records),
            "bundle_root": merkle_root("ARTIFACT-STATE-BUNDLE", &bundle_records),
            "replay_input_root": merkle_root("ARTIFACT-STATE-REPLAY-INPUT", &replay_input_records),
            "replay_report_root": merkle_root("ARTIFACT-STATE-REPLAY-REPORT", &replay_report_records),
            "index_root": self.index().state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ARTIFACT-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn artifact_id(
    artifact_kind: ArtifactKind,
    label: &str,
    payload_root: &str,
    provenance_root: &str,
) -> String {
    domain_hash(
        "ARTIFACT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(artifact_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(payload_root),
            HashPart::Str(provenance_root),
        ],
        32,
    )
}

pub fn artifact_payload_root(artifact_kind: ArtifactKind, payload: &Value) -> String {
    domain_hash(
        "ARTIFACT-PAYLOAD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(artifact_kind.as_str()),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn artifact_bundle_id(
    label: &str,
    run_id: &str,
    artifact_root: &str,
    payload_root: &str,
    provenance_root: &str,
) -> String {
    domain_hash(
        "ARTIFACT-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(run_id),
            HashPart::Str(artifact_root),
            HashPart::Str(payload_root),
            HashPart::Str(provenance_root),
        ],
        32,
    )
}

pub fn replay_input_id(label: &str, bundle_id: &str, expectation_root: &str) -> String {
    domain_hash(
        "ARTIFACT-REPLAY-INPUT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(bundle_id),
            HashPart::Str(expectation_root),
        ],
        32,
    )
}

pub fn replay_report_id(input_id: &str, observed_root: &str, check_root: &str) -> String {
    domain_hash(
        "ARTIFACT-REPLAY-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(input_id),
            HashPart::Str(observed_root),
            HashPart::Str(check_root),
        ],
        32,
    )
}

pub fn artifact_kind_root(artifact_kind: ArtifactKind) -> String {
    domain_hash(
        "ARTIFACT-KIND-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(artifact_kind.as_str()),
        ],
        32,
    )
}

pub fn artifact_string_root(label: &str, value: &str) -> String {
    domain_hash(
        "ARTIFACT-STRING-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn artifact_metadata_root(metadata: &Value) -> String {
    domain_hash(
        "ARTIFACT-METADATA-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(metadata)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn artifact_provenance_root(
    artifact_kind: ArtifactKind,
    label: &str,
    payload_kind: &str,
    source_id: Option<&str>,
    source_root: Option<&str>,
    run_id: Option<&str>,
    step_id: Option<&str>,
    height: Option<u64>,
    timestamp_ms: Option<u64>,
    metadata_root: &str,
) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "artifact_kind": artifact_kind.as_str(),
        "label": label,
        "payload_kind": payload_kind,
        "source_id": source_id,
        "source_root": source_root,
        "run_id": run_id,
        "step_id": step_id,
        "height": height,
        "timestamp_ms": timestamp_ms,
        "metadata_root": metadata_root,
    });
    domain_hash("ARTIFACT-PROVENANCE-ROOT", &[HashPart::Json(&record)], 32)
}

fn replay_expectation_id(
    artifact_id: &str,
    expected_payload_root: &str,
    expected_source_root: &str,
    expected_provenance_root: &str,
    expected_artifact_root: &str,
) -> String {
    domain_hash(
        "ARTIFACT-REPLAY-EXPECTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(artifact_id),
            HashPart::Str(expected_payload_root),
            HashPart::Str(expected_source_root),
            HashPart::Str(expected_provenance_root),
            HashPart::Str(expected_artifact_root),
        ],
        32,
    )
}

fn replay_check_id(
    expectation_id: Option<&str>,
    artifact_id: &str,
    status: ReplayCheckStatus,
    expected_payload_root: Option<&str>,
    observed_payload_root: Option<&str>,
) -> String {
    domain_hash(
        "ARTIFACT-REPLAY-CHECK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(expectation_id.unwrap_or("")),
            HashPart::Str(artifact_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(expected_payload_root.unwrap_or("")),
            HashPart::Str(observed_payload_root.unwrap_or("")),
        ],
        32,
    )
}

fn normalize_label(label: String) -> String {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        ARTIFACT_DEFAULT_LABEL.to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_metadata_root(metadata_root: String) -> String {
    if metadata_root.trim().is_empty() {
        artifact_metadata_root(&json!({}))
    } else {
        metadata_root
    }
}

fn canonical_json_bytes(payload: &Value) -> u64 {
    canonical_json_string(payload).len() as u64
}

fn ensure_unique_artifacts(artifacts: &[RunArtifact]) -> ArtifactResult<()> {
    let mut seen = BTreeSet::new();
    for artifact in artifacts {
        if !seen.insert(artifact.artifact_id.clone()) {
            return Err(format!("duplicate artifact id: {}", artifact.artifact_id));
        }
    }
    Ok(())
}

fn sorted_artifacts(artifacts: &[RunArtifact]) -> Vec<RunArtifact> {
    let mut artifacts = artifacts.to_vec();
    artifacts.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.artifact_kind.cmp(&right.artifact_kind))
            .then_with(|| left.label.cmp(&right.label))
    });
    artifacts
}

fn sorted_expectations(expectations: &[ReplayExpectation]) -> Vec<ReplayExpectation> {
    let mut expectations = expectations.to_vec();
    expectations.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.expectation_id.cmp(&right.expectation_id))
    });
    expectations
}

fn sorted_checks(checks: &[ReplayCheck]) -> Vec<ReplayCheck> {
    let mut checks = checks.to_vec();
    checks.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.status.as_str().cmp(right.status.as_str()))
            .then_with(|| left.check_id.cmp(&right.check_id))
    });
    checks
}

fn artifact_records_root(domain: &str, artifacts: &[RunArtifact]) -> String {
    let records = sorted_artifacts(artifacts)
        .iter()
        .map(RunArtifact::public_record)
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn artifact_payloads_root(artifacts: &[RunArtifact]) -> String {
    let records = sorted_artifacts(artifacts)
        .iter()
        .map(|artifact| {
            json!({
                "artifact_id": artifact.artifact_id,
                "artifact_kind": artifact.artifact_kind.as_str(),
                "payload_root": artifact.payload_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("ARTIFACT-BUNDLE-PAYLOAD", &records)
}

fn artifact_provenances_root(artifacts: &[RunArtifact]) -> String {
    let records = sorted_artifacts(artifacts)
        .iter()
        .map(|artifact| {
            json!({
                "artifact_id": artifact.artifact_id,
                "artifact_kind": artifact.artifact_kind.as_str(),
                "provenance_root": artifact.provenance_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("ARTIFACT-BUNDLE-PROVENANCE", &records)
}

fn artifact_kind_inventory_root(artifacts: &[RunArtifact]) -> String {
    map_count_root("ARTIFACT-BUNDLE-KIND", &count_by_kind(artifacts))
}

fn expectation_records_root(expectations: &[ReplayExpectation]) -> String {
    let records = sorted_expectations(expectations)
        .iter()
        .map(ReplayExpectation::public_record)
        .collect::<Vec<_>>();
    merkle_root("ARTIFACT-REPLAY-EXPECTATION", &records)
}

fn check_records_root(checks: &[ReplayCheck]) -> String {
    let records = sorted_checks(checks)
        .iter()
        .map(ReplayCheck::public_record)
        .collect::<Vec<_>>();
    merkle_root("ARTIFACT-REPLAY-CHECK", &records)
}

fn count_by_kind(artifacts: &[RunArtifact]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for artifact in artifacts {
        *counts
            .entry(artifact.artifact_kind.as_str().to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn count_by_run(artifacts: &[RunArtifact]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for artifact in artifacts {
        let run_id = artifact.run_id.as_deref().unwrap_or("unscoped").to_string();
        *counts.entry(run_id).or_insert(0) += 1;
    }
    counts
}

fn map_count_root(domain: &str, counts: &BTreeMap<String, u64>) -> String {
    let records = counts
        .iter()
        .map(|(key, count)| json!({ "key": key, "count": count }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn label_inventory_root(artifacts: &[RunArtifact]) -> String {
    let records = sorted_artifacts(artifacts)
        .iter()
        .map(|artifact| {
            json!({
                "artifact_id": artifact.artifact_id,
                "label": artifact.label,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("ARTIFACT-INDEX-LABEL", &records)
}

fn status_count(checks: &[ReplayCheck], status: ReplayCheckStatus) -> u64 {
    checks.iter().filter(|check| check.status == status).count() as u64
}

fn aggregate_status(
    matched_count: u64,
    missing_count: u64,
    mismatched_count: u64,
    unexpected_count: u64,
) -> ReplayCheckStatus {
    if mismatched_count > 0 || unexpected_count > 0 {
        ReplayCheckStatus::Mismatched
    } else if missing_count > 0 {
        ReplayCheckStatus::Missing
    } else if matched_count > 0 {
        ReplayCheckStatus::Matched
    } else {
        ReplayCheckStatus::Pending
    }
}
