use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeForcedExitDryRunWalletHandoffRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_FORCED_EXIT_DRY_RUN_WALLET_HANDOFF_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-forced-exit-dry-run-wallet-handoff-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_FORCED_EXIT_DRY_RUN_WALLET_HANDOFF_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-forced-exit-dry-run-wallet-handoff";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub handoff_suite: String,
    pub wallet_profile: String,
    pub harness_profile: String,
    pub cli_payload_schema: String,
    pub min_command_count: u64,
    pub require_release_held: u64,
    pub require_redacted_export: u64,
    pub require_operator_independent_commands: u64,
    pub require_pq_authorization_command: u64,
    pub max_linkage_fields: u64,
    pub fee_cap_atomic: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            handoff_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-dry-run-wallet-handoff-v1"
                    .to_string(),
            wallet_profile: "canonical-user-escape-wallet-devnet".to_string(),
            harness_profile: "forced-exit-dry-run-harness-devnet".to_string(),
            cli_payload_schema: "roots-only-wallet-cli-payload-v1".to_string(),
            min_command_count: 8,
            require_release_held: 1,
            require_redacted_export: 1,
            require_operator_independent_commands: 1,
            require_pq_authorization_command: 1,
            max_linkage_fields: 0,
            fee_cap_atomic: 30_000_000,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "handoff_suite": self.handoff_suite,
            "wallet_profile": self.wallet_profile,
            "harness_profile": self.harness_profile,
            "cli_payload_schema": self.cli_payload_schema,
            "min_command_count": self.min_command_count,
            "require_release_held": self.require_release_held,
            "require_redacted_export": self.require_redacted_export,
            "require_operator_independent_commands": self.require_operator_independent_commands,
            "require_pq_authorization_command": self.require_pq_authorization_command,
            "max_linkage_fields": self.max_linkage_fields,
            "fee_cap_atomic": self.fee_cap_atomic,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletHandoffStage {
    InspectDryRunVerdict,
    ShowWalletNotice,
    ExportEvidenceBundle,
    BuildClaimCommand,
    PqAuthorizeClaim,
    WatchChallengeWindow,
    EmitHarnessReceipt,
    ReportReleaseHold,
}

impl WalletHandoffStage {
    pub fn ordered() -> [Self; 8] {
        [
            Self::InspectDryRunVerdict,
            Self::ShowWalletNotice,
            Self::ExportEvidenceBundle,
            Self::BuildClaimCommand,
            Self::PqAuthorizeClaim,
            Self::WatchChallengeWindow,
            Self::EmitHarnessReceipt,
            Self::ReportReleaseHold,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::InspectDryRunVerdict => "inspect_dry_run_verdict",
            Self::ShowWalletNotice => "show_wallet_notice",
            Self::ExportEvidenceBundle => "export_evidence_bundle",
            Self::BuildClaimCommand => "build_claim_command",
            Self::PqAuthorizeClaim => "pq_authorize_claim",
            Self::WatchChallengeWindow => "watch_challenge_window",
            Self::EmitHarnessReceipt => "emit_harness_receipt",
            Self::ReportReleaseHold => "report_release_hold",
        }
    }

    pub fn command_name(self) -> &'static str {
        match self {
            Self::InspectDryRunVerdict => "escape-dry-run inspect",
            Self::ShowWalletNotice => "escape-dry-run notice",
            Self::ExportEvidenceBundle => "escape-dry-run export-evidence",
            Self::BuildClaimCommand => "escape-dry-run build-claim",
            Self::PqAuthorizeClaim => "escape-dry-run pq-authorize",
            Self::WatchChallengeWindow => "escape-dry-run watch",
            Self::EmitHarnessReceipt => "escape-dry-run receipt",
            Self::ReportReleaseHold => "escape-dry-run release-hold",
        }
    }

    pub fn command_family(self) -> &'static str {
        match self {
            Self::InspectDryRunVerdict | Self::ShowWalletNotice => "wallet_visibility",
            Self::ExportEvidenceBundle | Self::EmitHarnessReceipt => "harness_export",
            Self::BuildClaimCommand | Self::PqAuthorizeClaim => "forced_exit_claim",
            Self::WatchChallengeWindow | Self::ReportReleaseHold => "release_hold_monitor",
        }
    }

    pub fn requires_pq_authorization(self) -> u64 {
        match self {
            Self::PqAuthorizeClaim => 1,
            Self::InspectDryRunVerdict
            | Self::ShowWalletNotice
            | Self::ExportEvidenceBundle
            | Self::BuildClaimCommand
            | Self::WatchChallengeWindow
            | Self::EmitHarnessReceipt
            | Self::ReportReleaseHold => 0,
        }
    }

    pub fn wallet_visible(self) -> u64 {
        match self {
            Self::InspectDryRunVerdict
            | Self::ShowWalletNotice
            | Self::BuildClaimCommand
            | Self::PqAuthorizeClaim
            | Self::WatchChallengeWindow
            | Self::ReportReleaseHold => 1,
            Self::ExportEvidenceBundle | Self::EmitHarnessReceipt => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunSource {
    pub dry_run_state_root: String,
    pub dry_run_public_record_root: String,
    pub vertical_dry_run_root: String,
    pub evidence_root: String,
    pub transition_root: String,
    pub wallet_action_root: String,
    pub privacy_boundary_root: String,
    pub release_hold_root: String,
    pub decision_root: String,
    pub dry_run_status: String,
    pub release_allowed: u64,
}

impl DryRunSource {
    pub fn devnet() -> Self {
        let dry_run =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_forced_exit_vertical_dry_run_runtime::devnet();
        let dry_run_public_record = dry_run.public_record();

        Self {
            dry_run_state_root: dry_run.state_root(),
            dry_run_public_record_root: record_root(
                "dry-run-public-record",
                &dry_run_public_record,
            ),
            vertical_dry_run_root: dry_run.vertical_dry_run_root,
            evidence_root: dry_run.evidence_root,
            transition_root: dry_run.transition_root,
            wallet_action_root: dry_run.wallet_action_root,
            privacy_boundary_root: dry_run.privacy_boundary_root,
            release_hold_root: dry_run.release_hold_root,
            decision_root: dry_run.decision.decision_root,
            dry_run_status: dry_run.decision.dry_run_status,
            release_allowed: dry_run.decision.release_allowed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "dry_run_state_root": self.dry_run_state_root,
            "dry_run_public_record_root": self.dry_run_public_record_root,
            "vertical_dry_run_root": self.vertical_dry_run_root,
            "evidence_root": self.evidence_root,
            "transition_root": self.transition_root,
            "wallet_action_root": self.wallet_action_root,
            "privacy_boundary_root": self.privacy_boundary_root,
            "release_hold_root": self.release_hold_root,
            "decision_root": self.decision_root,
            "dry_run_status": self.dry_run_status,
            "release_allowed": self.release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("dry-run-source", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletHandoffCommand {
    pub sequence: u64,
    pub stage: WalletHandoffStage,
    pub command_name: String,
    pub command_family: String,
    pub command_template: String,
    pub input_root: String,
    pub output_root: String,
    pub redaction_root: String,
    pub wallet_visible: u64,
    pub operator_cooperation_required: u64,
    pub pq_authorization_required: u64,
    pub linkage_fields_disclosed: u64,
    pub fee_cap_atomic: u64,
    pub command_root: String,
}

impl WalletHandoffCommand {
    pub fn devnet(
        config: &Config,
        source: &DryRunSource,
        stage: WalletHandoffStage,
        sequence: u64,
    ) -> Self {
        let input_root = stage_input_root(stage, source);
        let output_root = stage_output_root(stage, source);
        let redaction_root = stage_redaction_root(stage, source);
        let command_template = command_template(config, source, stage);
        let command_root = domain_hash(
            &format!("{DOMAIN}:command"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Str(stage.as_str()),
                HashPart::Str(stage.command_name()),
                HashPart::Str(stage.command_family()),
                HashPart::Str(&command_template),
                HashPart::Str(&input_root),
                HashPart::Str(&output_root),
                HashPart::Str(&redaction_root),
                HashPart::U64(stage.wallet_visible()),
                HashPart::U64(0),
                HashPart::U64(stage.requires_pq_authorization()),
                HashPart::U64(0),
                HashPart::U64(config.fee_cap_atomic),
            ],
            32,
        );

        Self {
            sequence,
            stage,
            command_name: stage.command_name().to_string(),
            command_family: stage.command_family().to_string(),
            command_template,
            input_root,
            output_root,
            redaction_root,
            wallet_visible: stage.wallet_visible(),
            operator_cooperation_required: 0,
            pq_authorization_required: stage.requires_pq_authorization(),
            linkage_fields_disclosed: 0,
            fee_cap_atomic: config.fee_cap_atomic,
            command_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sequence": self.sequence,
            "stage": self.stage.as_str(),
            "command_name": self.command_name,
            "command_family": self.command_family,
            "command_template": self.command_template,
            "input_root": self.input_root,
            "output_root": self.output_root,
            "redaction_root": self.redaction_root,
            "wallet_visible": self.wallet_visible,
            "operator_cooperation_required": self.operator_cooperation_required,
            "pq_authorization_required": self.pq_authorization_required,
            "linkage_fields_disclosed": self.linkage_fields_disclosed,
            "fee_cap_atomic": self.fee_cap_atomic,
            "command_root": self.command_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletHandoffVerdict {
    pub command_count: u64,
    pub wallet_visible_count: u64,
    pub redacted_export_present: u64,
    pub operator_independent_count: u64,
    pub pq_authorization_present: u64,
    pub release_held: u64,
    pub release_allowed: u64,
    pub linkage_fields_disclosed: u64,
    pub verdict_status: String,
    pub verdict_root: String,
}

impl WalletHandoffVerdict {
    pub fn new(config: &Config, source: &DryRunSource, commands: &[WalletHandoffCommand]) -> Self {
        let command_count = commands.len() as u64;
        let wallet_visible_count = commands
            .iter()
            .filter(|command| command.wallet_visible == 1)
            .count() as u64;
        let redacted_export_present = present_flag(
            commands
                .iter()
                .any(|command| command.stage == WalletHandoffStage::ExportEvidenceBundle),
        );
        let operator_independent_count = commands
            .iter()
            .filter(|command| command.operator_cooperation_required == 0)
            .count() as u64;
        let pq_authorization_present = present_flag(
            commands
                .iter()
                .any(|command| command.pq_authorization_required == 1),
        );
        let release_held = present_flag(source.release_allowed == 0);
        let release_allowed = source.release_allowed;
        let linkage_fields_disclosed = commands
            .iter()
            .map(|command| command.linkage_fields_disclosed)
            .sum::<u64>();
        let verdict_status = if command_count >= config.min_command_count
            && release_held >= config.require_release_held
            && redacted_export_present >= config.require_redacted_export
            && operator_independent_count == command_count
            && pq_authorization_present >= config.require_pq_authorization_command
            && linkage_fields_disclosed <= config.max_linkage_fields
            && release_allowed == 0
        {
            "wallet_handoff_ready_release_held"
        } else {
            "wallet_handoff_gap_release_held"
        }
        .to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.wallet_profile),
                HashPart::Str(&source.dry_run_state_root),
                HashPart::U64(command_count),
                HashPart::U64(wallet_visible_count),
                HashPart::U64(redacted_export_present),
                HashPart::U64(operator_independent_count),
                HashPart::U64(pq_authorization_present),
                HashPart::U64(release_held),
                HashPart::U64(release_allowed),
                HashPart::U64(linkage_fields_disclosed),
                HashPart::Str(&verdict_status),
            ],
            32,
        );

        Self {
            command_count,
            wallet_visible_count,
            redacted_export_present,
            operator_independent_count,
            pq_authorization_present,
            release_held,
            release_allowed,
            linkage_fields_disclosed,
            verdict_status,
            verdict_root,
        }
    }

    pub fn fallback(config: &Config, reason: &str) -> Self {
        let verdict_status = "wallet_handoff_construction_gap_release_held".to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:fallback-verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.wallet_profile),
                HashPart::Str(reason),
                HashPart::Str(&verdict_status),
                HashPart::U64(1),
                HashPart::U64(0),
            ],
            32,
        );

        Self {
            command_count: 0,
            wallet_visible_count: 0,
            redacted_export_present: 0,
            operator_independent_count: 0,
            pq_authorization_present: 0,
            release_held: 1,
            release_allowed: 0,
            linkage_fields_disclosed: 0,
            verdict_status,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "command_count": self.command_count,
            "wallet_visible_count": self.wallet_visible_count,
            "redacted_export_present": self.redacted_export_present,
            "operator_independent_count": self.operator_independent_count,
            "pq_authorization_present": self.pq_authorization_present,
            "release_held": self.release_held,
            "release_allowed": self.release_allowed,
            "linkage_fields_disclosed": self.linkage_fields_disclosed,
            "verdict_status": self.verdict_status,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub source: DryRunSource,
    pub commands: Vec<WalletHandoffCommand>,
    pub verdict: WalletHandoffVerdict,
    pub command_root: String,
    pub wallet_notice_root: String,
    pub redacted_export_root: String,
    pub harness_receipt_root: String,
    pub release_hold_notice_root: String,
    pub wallet_handoff_root: String,
}

impl State {
    pub fn new(config: Config, source: DryRunSource) -> Result<Self> {
        validate_config(&config)?;

        let commands = WalletHandoffStage::ordered()
            .iter()
            .enumerate()
            .map(|(index, stage)| {
                WalletHandoffCommand::devnet(&config, &source, *stage, index as u64 + 1)
            })
            .collect::<Vec<_>>();
        let verdict = WalletHandoffVerdict::new(&config, &source, &commands);
        let command_root = command_vector_root(&commands);
        let wallet_notice_root = wallet_notice_root(&config, &source, &verdict, &command_root);
        let redacted_export_root = redacted_export_root(&config, &source, &commands, &verdict);
        let harness_receipt_root = harness_receipt_root(
            &config,
            &source,
            &verdict,
            &command_root,
            &redacted_export_root,
        );
        let release_hold_notice_root = release_hold_notice_root(
            &config,
            &source,
            &verdict,
            &wallet_notice_root,
            &harness_receipt_root,
        );
        let wallet_handoff_root = wallet_handoff_root(
            &config,
            &source,
            &verdict,
            &command_root,
            &wallet_notice_root,
            &redacted_export_root,
            &harness_receipt_root,
            &release_hold_notice_root,
        );

        Ok(Self {
            config,
            source,
            commands,
            verdict,
            command_root,
            wallet_notice_root,
            redacted_export_root,
            harness_receipt_root,
            release_hold_notice_root,
            wallet_handoff_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::default(), DryRunSource::devnet()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_forced_exit_dry_run_wallet_handoff_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source": self.source.public_record(),
            "command_root": self.command_root,
            "wallet_notice_root": self.wallet_notice_root,
            "redacted_export_root": self.redacted_export_root,
            "harness_receipt_root": self.harness_receipt_root,
            "release_hold_notice_root": self.release_hold_notice_root,
            "wallet_handoff_root": self.wallet_handoff_root,
            "verdict": self.verdict.public_record(),
            "commands": self
                .commands
                .iter()
                .map(WalletHandoffCommand::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "state",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "config_root": self.config.state_root(),
                "source_root": self.source.state_root(),
                "command_root": self.command_root,
                "wallet_notice_root": self.wallet_notice_root,
                "redacted_export_root": self.redacted_export_root,
                "harness_receipt_root": self.harness_receipt_root,
                "release_hold_notice_root": self.release_hold_notice_root,
                "wallet_handoff_root": self.wallet_handoff_root,
                "verdict_root": self.verdict.verdict_root,
            }),
        )
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

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id != CHAIN_ID {
        return Err("config chain id must match crate chain id".to_string());
    }
    if config.min_command_count < WalletHandoffStage::ordered().len() as u64 {
        return Err("minimum command count must cover all wallet handoff stages".to_string());
    }
    if config.require_release_held != 1 {
        return Err("wallet handoff must require release to remain held".to_string());
    }
    if config.max_linkage_fields != 0 {
        return Err("wallet handoff must keep disclosed linkage fields at zero".to_string());
    }
    Ok(())
}

fn stage_input_root(stage: WalletHandoffStage, source: &DryRunSource) -> String {
    match stage {
        WalletHandoffStage::InspectDryRunVerdict => source.dry_run_state_root.clone(),
        WalletHandoffStage::ShowWalletNotice => source.wallet_action_root.clone(),
        WalletHandoffStage::ExportEvidenceBundle => source.evidence_root.clone(),
        WalletHandoffStage::BuildClaimCommand => source.vertical_dry_run_root.clone(),
        WalletHandoffStage::PqAuthorizeClaim => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime::state_root()
        }
        WalletHandoffStage::WatchChallengeWindow => source.transition_root.clone(),
        WalletHandoffStage::EmitHarnessReceipt => source.dry_run_public_record_root.clone(),
        WalletHandoffStage::ReportReleaseHold => source.release_hold_root.clone(),
    }
}

fn stage_output_root(stage: WalletHandoffStage, source: &DryRunSource) -> String {
    domain_hash(
        &format!("{DOMAIN}:stage-output"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(stage.as_str()),
            HashPart::Str(&source.dry_run_state_root),
            HashPart::Str(&source.vertical_dry_run_root),
            HashPart::Str(&source.release_hold_root),
            HashPart::U64(source.release_allowed),
        ],
        32,
    )
}

fn stage_redaction_root(stage: WalletHandoffStage, source: &DryRunSource) -> String {
    domain_hash(
        &format!("{DOMAIN}:stage-redaction"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(stage.as_str()),
            HashPart::Str(&source.privacy_boundary_root),
            HashPart::Str(&source.wallet_action_root),
            HashPart::U64(0),
        ],
        32,
    )
}

fn command_template(config: &Config, source: &DryRunSource, stage: WalletHandoffStage) -> String {
    match stage {
        WalletHandoffStage::InspectDryRunVerdict => format!(
            "nebula-wallet {} --dry-run-root {} --verdict-root {}",
            stage.command_name(),
            source.vertical_dry_run_root,
            source.decision_root
        ),
        WalletHandoffStage::ShowWalletNotice => format!(
            "nebula-wallet {} --wallet-action-root {} --release-hold-root {}",
            stage.command_name(),
            source.wallet_action_root,
            source.release_hold_root
        ),
        WalletHandoffStage::ExportEvidenceBundle => format!(
            "nebula-wallet {} --evidence-root {} --redaction roots-only",
            stage.command_name(),
            source.evidence_root
        ),
        WalletHandoffStage::BuildClaimCommand => format!(
            "nebula-wallet {} --vertical-root {} --fee-cap {}",
            stage.command_name(),
            source.vertical_dry_run_root,
            config.fee_cap_atomic
        ),
        WalletHandoffStage::PqAuthorizeClaim => format!(
            "nebula-wallet {} --release-verification-root {} --scheme ml-dsa-slh-dsa",
            stage.command_name(),
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime::state_root()
        ),
        WalletHandoffStage::WatchChallengeWindow => format!(
            "nebula-wallet {} --transition-root {} --process-feed-root {}",
            stage.command_name(),
            source.transition_root,
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime::state_root()
        ),
        WalletHandoffStage::EmitHarnessReceipt => format!(
            "nebula-wallet {} --public-record-root {} --harness {}",
            stage.command_name(),
            source.dry_run_public_record_root,
            config.harness_profile
        ),
        WalletHandoffStage::ReportReleaseHold => format!(
            "nebula-wallet {} --release-hold-root {} --release-allowed {}",
            stage.command_name(),
            source.release_hold_root,
            source.release_allowed
        ),
    }
}

fn command_vector_root(commands: &[WalletHandoffCommand]) -> String {
    let leaves = commands
        .iter()
        .map(WalletHandoffCommand::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:command-root"), &leaves)
}

fn wallet_notice_root(
    config: &Config,
    source: &DryRunSource,
    verdict: &WalletHandoffVerdict,
    command_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:wallet-notice"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.wallet_profile),
            HashPart::Str(&source.wallet_action_root),
            HashPart::Str(&source.release_hold_root),
            HashPart::Str(command_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_held),
            HashPart::U64(verdict.wallet_visible_count),
        ],
        32,
    )
}

fn redacted_export_root(
    config: &Config,
    source: &DryRunSource,
    commands: &[WalletHandoffCommand],
    verdict: &WalletHandoffVerdict,
) -> String {
    let redaction_leaves = commands
        .iter()
        .map(|command| {
            json!({
                "stage": command.stage.as_str(),
                "redaction_root": command.redaction_root,
                "linkage_fields_disclosed": command.linkage_fields_disclosed,
            })
        })
        .collect::<Vec<_>>();
    let redaction_leaf_root =
        merkle_root(&format!("{DOMAIN}:redaction-leaf-root"), &redaction_leaves);

    domain_hash(
        &format!("{DOMAIN}:redacted-export"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.cli_payload_schema),
            HashPart::Str(&source.evidence_root),
            HashPart::Str(&source.privacy_boundary_root),
            HashPart::Str(&redaction_leaf_root),
            HashPart::U64(verdict.redacted_export_present),
            HashPart::U64(verdict.linkage_fields_disclosed),
        ],
        32,
    )
}

fn harness_receipt_root(
    config: &Config,
    source: &DryRunSource,
    verdict: &WalletHandoffVerdict,
    command_root: &str,
    redacted_export_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:harness-receipt"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.harness_profile),
            HashPart::Str(&source.dry_run_state_root),
            HashPart::Str(&source.vertical_dry_run_root),
            HashPart::Str(command_root),
            HashPart::Str(redacted_export_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_held),
        ],
        32,
    )
}

fn release_hold_notice_root(
    config: &Config,
    source: &DryRunSource,
    verdict: &WalletHandoffVerdict,
    wallet_notice_root: &str,
    harness_receipt_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:release-hold-notice"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.wallet_profile),
            HashPart::Str(&source.release_hold_root),
            HashPart::Str(wallet_notice_root),
            HashPart::Str(harness_receipt_root),
            HashPart::U64(verdict.release_held),
            HashPart::U64(verdict.release_allowed),
        ],
        32,
    )
}

fn wallet_handoff_root(
    config: &Config,
    source: &DryRunSource,
    verdict: &WalletHandoffVerdict,
    command_root: &str,
    wallet_notice_root: &str,
    redacted_export_root: &str,
    harness_receipt_root: &str,
    release_hold_notice_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:wallet-handoff"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.handoff_suite),
            HashPart::Str(&source.dry_run_state_root),
            HashPart::Str(&source.vertical_dry_run_root),
            HashPart::Str(command_root),
            HashPart::Str(wallet_notice_root),
            HashPart::Str(redacted_export_root),
            HashPart::Str(harness_receipt_root),
            HashPart::Str(release_hold_notice_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_allowed),
        ],
        32,
    )
}

fn present_flag(value: bool) -> u64 {
    if value {
        1
    } else {
        0
    }
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:record"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let source = DryRunSource {
        dry_run_state_root: record_root("fallback-dry-run-state", &json!({ "reason": reason })),
        dry_run_public_record_root: record_root(
            "fallback-dry-run-public-record",
            &json!({ "reason": reason }),
        ),
        vertical_dry_run_root: record_root(
            "fallback-vertical-dry-run",
            &json!({ "reason": reason }),
        ),
        evidence_root: record_root("fallback-evidence", &json!({ "reason": reason })),
        transition_root: record_root("fallback-transition", &json!({ "reason": reason })),
        wallet_action_root: record_root("fallback-wallet-action", &json!({ "reason": reason })),
        privacy_boundary_root: record_root(
            "fallback-privacy-boundary",
            &json!({ "reason": reason }),
        ),
        release_hold_root: record_root("fallback-release-hold", &json!({ "reason": reason })),
        decision_root: record_root("fallback-decision", &json!({ "reason": reason })),
        dry_run_status: "fallback_release_held".to_string(),
        release_allowed: 0,
    };
    let commands = Vec::new();
    let verdict = WalletHandoffVerdict::fallback(&config, &reason);
    let command_root = command_vector_root(&commands);
    let wallet_notice_root = wallet_notice_root(&config, &source, &verdict, &command_root);
    let redacted_export_root = redacted_export_root(&config, &source, &commands, &verdict);
    let harness_receipt_root = harness_receipt_root(
        &config,
        &source,
        &verdict,
        &command_root,
        &redacted_export_root,
    );
    let release_hold_notice_root = release_hold_notice_root(
        &config,
        &source,
        &verdict,
        &wallet_notice_root,
        &harness_receipt_root,
    );
    let wallet_handoff_root = wallet_handoff_root(
        &config,
        &source,
        &verdict,
        &command_root,
        &wallet_notice_root,
        &redacted_export_root,
        &harness_receipt_root,
        &release_hold_notice_root,
    );

    State {
        config,
        source,
        commands,
        verdict,
        command_root,
        wallet_notice_root,
        redacted_export_root,
        harness_receipt_root,
        release_hold_notice_root,
        wallet_handoff_root,
    }
}
