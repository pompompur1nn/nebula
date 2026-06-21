use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

pub type Result<T> = std::result::Result<T, Error>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-force-exit-wave89-release-captain-no-go-evidence-archive-pq-reserve-privacy-gate-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "stdlib-default-hasher-domain-separated-v1";
pub const DEFAULT_CHAIN_ID: &str = "nebula-monero-l2-devnet";
pub const DEFAULT_RELEASE_ID: &str = "wave89-force-exit-pq-reserve-privacy-no-go";
pub const DEFAULT_REPLAY_WAVE: u64 = 88;
pub const DEFAULT_ARCHIVE_WAVE: u64 = 89;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PQ_SIGNER_QUORUM: u16 = 4;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 12_500;
pub const DEFAULT_MAX_RESERVE_STALENESS_BLOCKS: u64 = 24;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_LINKAGE_BPS: u64 = 0;
pub const DEFAULT_MAX_METADATA_LEAKAGE_SCORE: u16 = 0;
pub const DEFAULT_MIN_NULLIFIER_DOMAINS: usize = 4;
pub const DEFAULT_MAX_PUBLIC_NOTES: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyField(&'static str),
    DuplicateRecord(String),
    MissingRecord(String),
    InvalidThreshold(&'static str),
    ArchiveSealed,
    ReleaseNotHeld,
    ReleaseAlreadyFinalized,
}

impl Error {
    pub fn as_str(&self) -> &str {
        match self {
            Self::EmptyField(_) => "empty_field",
            Self::DuplicateRecord(_) => "duplicate_record",
            Self::MissingRecord(_) => "missing_record",
            Self::InvalidThreshold(_) => "invalid_threshold",
            Self::ArchiveSealed => "archive_sealed",
            Self::ReleaseNotHeld => "release_not_held",
            Self::ReleaseAlreadyFinalized => "release_already_finalized",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::EmptyField(field) => format!("empty field: {}", field),
            Self::DuplicateRecord(record) => format!("duplicate record: {}", record),
            Self::MissingRecord(record) => format!("missing record: {}", record),
            Self::InvalidThreshold(field) => format!("invalid threshold: {}", field),
            Self::ArchiveSealed => "archive is sealed".to_string(),
            Self::ReleaseNotHeld => "release is not currently held".to_string(),
            Self::ReleaseAlreadyFinalized => "release has already been finalized".to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub chain_id: String,
    pub release_id: String,
    pub replay_wave: u64,
    pub archive_wave: u64,
    pub release_captain: String,
    pub min_pq_security_bits: u16,
    pub min_pq_signer_quorum: u16,
    pub min_reserve_coverage_bps: u64,
    pub max_reserve_staleness_blocks: u64,
    pub min_privacy_set_size: u64,
    pub max_linkage_bps: u64,
    pub max_metadata_leakage_score: u16,
    pub min_nullifier_domains: usize,
    pub fail_closed: bool,
    pub allow_go_with_open_blockers: bool,
    pub max_public_notes: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            release_id: DEFAULT_RELEASE_ID.to_string(),
            replay_wave: DEFAULT_REPLAY_WAVE,
            archive_wave: DEFAULT_ARCHIVE_WAVE,
            release_captain: "release-captain-devnet".to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_pq_signer_quorum: DEFAULT_MIN_PQ_SIGNER_QUORUM,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_reserve_staleness_blocks: DEFAULT_MAX_RESERVE_STALENESS_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_linkage_bps: DEFAULT_MAX_LINKAGE_BPS,
            max_metadata_leakage_score: DEFAULT_MAX_METADATA_LEAKAGE_SCORE,
            min_nullifier_domains: DEFAULT_MIN_NULLIFIER_DOMAINS,
            fail_closed: true,
            allow_go_with_open_blockers: false,
            max_public_notes: DEFAULT_MAX_PUBLIC_NOTES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("release_id", &self.release_id)?;
        require_non_empty("release_captain", &self.release_captain)?;
        if self.replay_wave == 0 {
            return Err(Error::InvalidThreshold("replay_wave"));
        }
        if self.archive_wave <= self.replay_wave {
            return Err(Error::InvalidThreshold("archive_wave"));
        }
        if self.min_pq_security_bits == 0 {
            return Err(Error::InvalidThreshold("min_pq_security_bits"));
        }
        if self.min_pq_signer_quorum == 0 {
            return Err(Error::InvalidThreshold("min_pq_signer_quorum"));
        }
        if self.min_reserve_coverage_bps > MAX_BPS * 4 {
            return Err(Error::InvalidThreshold("min_reserve_coverage_bps"));
        }
        if self.min_privacy_set_size == 0 {
            return Err(Error::InvalidThreshold("min_privacy_set_size"));
        }
        if self.max_linkage_bps > MAX_BPS {
            return Err(Error::InvalidThreshold("max_linkage_bps"));
        }
        if self.min_nullifier_domains == 0 {
            return Err(Error::InvalidThreshold("min_nullifier_domains"));
        }
        if self.max_public_notes == 0 {
            return Err(Error::InvalidThreshold("max_public_notes"));
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Digest {
        let mut builder = DigestBuilder::new("config");
        builder.push_str(PROTOCOL_VERSION);
        builder.push_u64(SCHEMA_VERSION);
        builder.push_str(&self.chain_id);
        builder.push_str(&self.release_id);
        builder.push_u64(self.replay_wave);
        builder.push_u64(self.archive_wave);
        builder.push_str(&self.release_captain);
        builder.push_u64(u64::from(self.min_pq_security_bits));
        builder.push_u64(u64::from(self.min_pq_signer_quorum));
        builder.push_u64(self.min_reserve_coverage_bps);
        builder.push_u64(self.max_reserve_staleness_blocks);
        builder.push_u64(self.min_privacy_set_size);
        builder.push_u64(self.max_linkage_bps);
        builder.push_u64(u64::from(self.max_metadata_leakage_score));
        builder.push_u64(self.min_nullifier_domains as u64);
        builder.push_bool(self.fail_closed);
        builder.push_bool(self.allow_go_with_open_blockers);
        builder.push_u64(self.max_public_notes as u64);
        builder.finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GateDomain {
    PqSignerEpoch,
    ReserveCoverage,
    PrivacyLinkage,
    MetadataRedaction,
    NullifierSeparation,
    ReplayGovernance,
}

impl GateDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignerEpoch => "pq_signer_epoch",
            Self::ReserveCoverage => "reserve_coverage",
            Self::PrivacyLinkage => "privacy_linkage",
            Self::MetadataRedaction => "metadata_redaction",
            Self::NullifierSeparation => "nullifier_separation",
            Self::ReplayGovernance => "replay_governance",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    Info,
    Watch,
    Blocker,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Blocker => "blocker",
            Self::Critical => "critical",
        }
    }

    pub fn holds_release(self) -> bool {
        matches!(self, Self::Blocker | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReplayDecision {
    Go,
    NoGo,
    Hold,
    NeedsEvidence,
}

impl ReplayDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGo => "no_go",
            Self::Hold => "hold",
            Self::NeedsEvidence => "needs_evidence",
        }
    }

    pub fn release_blocking(self) -> bool {
        !matches!(self, Self::Go)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReleaseStatus {
    Draft,
    Held,
    NoGo,
    Go,
    Sealed,
}

impl ReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Held => "held",
            Self::NoGo => "no_go",
            Self::Go => "go",
            Self::Sealed => "sealed",
        }
    }

    pub fn mutable(self) -> bool {
        matches!(self, Self::Draft | Self::Held | Self::NoGo)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PqEpochStatus {
    Pending,
    Active,
    Grace,
    Rotating,
    Revoked,
    Unknown,
}

impl PqEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }

    pub fn acceptable(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReserveStatus {
    Covered,
    UnderCovered,
    Stale,
    Disputed,
    Unknown,
}

impl ReserveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::UnderCovered => "under_covered",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RedactionStatus {
    Clean,
    RootOnly,
    LeaksMetadata,
    ContainsPlaintext,
    Unknown,
}

impl RedactionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::RootOnly => "root_only",
            Self::LeaksMetadata => "leaks_metadata",
            Self::ContainsPlaintext => "contains_plaintext",
            Self::Unknown => "unknown",
        }
    }

    pub fn acceptable(self) -> bool {
        matches!(self, Self::Clean | Self::RootOnly)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Digest {
    pub domain: String,
    pub words: [u64; 4],
}

impl Digest {
    pub fn zero(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            words: [0, 0, 0, 0],
        }
    }

    pub fn to_hex(&self) -> String {
        format!(
            "{:016x}{:016x}{:016x}{:016x}",
            self.words[0], self.words[1], self.words[2], self.words[3]
        )
    }

    pub fn tagged(&self) -> String {
        format!("{}:{}", self.domain, self.to_hex())
    }
}

#[derive(Clone, Debug)]
pub struct DigestBuilder {
    domain: String,
    fields: Vec<String>,
}

impl DigestBuilder {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            fields: Vec::new(),
        }
    }

    pub fn push_str(&mut self, value: &str) {
        self.fields.push(format!("s:{}", value));
    }

    pub fn push_u64(&mut self, value: u64) {
        self.fields.push(format!("u:{}", value));
    }

    pub fn push_i64(&mut self, value: i64) {
        self.fields.push(format!("i:{}", value));
    }

    pub fn push_bool(&mut self, value: bool) {
        self.fields.push(format!("b:{}", value));
    }

    pub fn push_digest(&mut self, digest: &Digest) {
        self.fields.push(format!("d:{}", digest.tagged()));
    }

    pub fn finish(&self) -> Digest {
        let mut words = [0_u64; 4];
        let joined = self.fields.join("|");
        let salts = [
            "nebula-wave89-a",
            "nebula-wave89-b",
            "nebula-wave89-c",
            "nebula-wave89-d",
        ];
        for (index, salt) in salts.iter().enumerate() {
            let mut hasher = DefaultHasher::new();
            PROTOCOL_VERSION.hash(&mut hasher);
            HASH_SUITE.hash(&mut hasher);
            self.domain.hash(&mut hasher);
            salt.hash(&mut hasher);
            joined.hash(&mut hasher);
            words[index] = mix64(hasher.finish(), index as u64);
        }
        Digest {
            domain: self.domain.clone(),
            words,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqEpochRecord {
    pub epoch_id: String,
    pub signer_set_root: Digest,
    pub transcript_root: Digest,
    pub algorithm_family: String,
    pub security_bits: u16,
    pub signer_quorum: u16,
    pub status: PqEpochStatus,
    pub activation_height: u64,
    pub replay_decision: ReplayDecision,
}

impl PqEpochRecord {
    pub fn new(
        epoch_id: &str,
        algorithm_family: &str,
        security_bits: u16,
        signer_quorum: u16,
        status: PqEpochStatus,
        activation_height: u64,
        replay_decision: ReplayDecision,
    ) -> Result<Self> {
        require_non_empty("epoch_id", epoch_id)?;
        require_non_empty("algorithm_family", algorithm_family)?;
        if security_bits == 0 {
            return Err(Error::InvalidThreshold("security_bits"));
        }
        if signer_quorum == 0 {
            return Err(Error::InvalidThreshold("signer_quorum"));
        }
        let signer_set_root = leaf_root("pq_signer_set", &[epoch_id, algorithm_family]);
        let transcript_root = leaf_root("pq_epoch_transcript", &[epoch_id, status.as_str()]);
        Ok(Self {
            epoch_id: epoch_id.to_string(),
            signer_set_root,
            transcript_root,
            algorithm_family: algorithm_family.to_string(),
            security_bits,
            signer_quorum,
            status,
            activation_height,
            replay_decision,
        })
    }

    pub fn blocker(&self, config: &Config) -> Option<Blocker> {
        if self.security_bits < config.min_pq_security_bits {
            return Some(Blocker::new(
                GateDomain::PqSignerEpoch,
                Severity::Critical,
                &format!("pq-security-bits-{}", self.epoch_id),
                "pq epoch security bits below release threshold",
                self.root(),
            ));
        }
        if self.signer_quorum < config.min_pq_signer_quorum {
            return Some(Blocker::new(
                GateDomain::PqSignerEpoch,
                Severity::Blocker,
                &format!("pq-quorum-{}", self.epoch_id),
                "pq signer quorum below release threshold",
                self.root(),
            ));
        }
        if !self.status.acceptable() {
            return Some(Blocker::new(
                GateDomain::PqSignerEpoch,
                Severity::Critical,
                &format!("pq-status-{}", self.epoch_id),
                "pq epoch is not active or grace",
                self.root(),
            ));
        }
        if self.replay_decision.release_blocking() {
            return Some(Blocker::new(
                GateDomain::ReplayGovernance,
                Severity::Blocker,
                &format!("pq-replay-{}", self.epoch_id),
                "wave 88 replay decision did not clear pq epoch",
                self.root(),
            ));
        }
        None
    }

    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("pq_epoch_record");
        builder.push_str(&self.epoch_id);
        builder.push_digest(&self.signer_set_root);
        builder.push_digest(&self.transcript_root);
        builder.push_str(&self.algorithm_family);
        builder.push_u64(u64::from(self.security_bits));
        builder.push_u64(u64::from(self.signer_quorum));
        builder.push_str(self.status.as_str());
        builder.push_u64(self.activation_height);
        builder.push_str(self.replay_decision.as_str());
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveCoverageRecord {
    pub reserve_id: String,
    pub asset: String,
    pub custody_root: Digest,
    pub liability_root: Digest,
    pub coverage_bps: u64,
    pub proof_height: u64,
    pub observed_height: u64,
    pub status: ReserveStatus,
    pub replay_decision: ReplayDecision,
}

impl ReserveCoverageRecord {
    pub fn new(
        reserve_id: &str,
        asset: &str,
        coverage_bps: u64,
        proof_height: u64,
        observed_height: u64,
        status: ReserveStatus,
        replay_decision: ReplayDecision,
    ) -> Result<Self> {
        require_non_empty("reserve_id", reserve_id)?;
        require_non_empty("asset", asset)?;
        let custody_root = leaf_root("reserve_custody", &[reserve_id, asset]);
        let liability_root = leaf_root("reserve_liability", &[reserve_id, status.as_str()]);
        Ok(Self {
            reserve_id: reserve_id.to_string(),
            asset: asset.to_string(),
            custody_root,
            liability_root,
            coverage_bps,
            proof_height,
            observed_height,
            status,
            replay_decision,
        })
    }

    pub fn staleness_blocks(&self) -> u64 {
        self.observed_height.saturating_sub(self.proof_height)
    }

    pub fn blocker(&self, config: &Config) -> Option<Blocker> {
        if self.coverage_bps < config.min_reserve_coverage_bps {
            return Some(Blocker::new(
                GateDomain::ReserveCoverage,
                Severity::Critical,
                &format!("reserve-coverage-{}", self.reserve_id),
                "reserve coverage below release threshold",
                self.root(),
            ));
        }
        if self.staleness_blocks() > config.max_reserve_staleness_blocks {
            return Some(Blocker::new(
                GateDomain::ReserveCoverage,
                Severity::Blocker,
                &format!("reserve-stale-{}", self.reserve_id),
                "reserve proof is stale for go/no-go replay",
                self.root(),
            ));
        }
        if !matches!(self.status, ReserveStatus::Covered) {
            return Some(Blocker::new(
                GateDomain::ReserveCoverage,
                Severity::Critical,
                &format!("reserve-status-{}", self.reserve_id),
                "reserve status is not covered",
                self.root(),
            ));
        }
        if self.replay_decision.release_blocking() {
            return Some(Blocker::new(
                GateDomain::ReplayGovernance,
                Severity::Blocker,
                &format!("reserve-replay-{}", self.reserve_id),
                "wave 88 replay decision did not clear reserve coverage",
                self.root(),
            ));
        }
        None
    }

    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("reserve_coverage_record");
        builder.push_str(&self.reserve_id);
        builder.push_str(&self.asset);
        builder.push_digest(&self.custody_root);
        builder.push_digest(&self.liability_root);
        builder.push_u64(self.coverage_bps);
        builder.push_u64(self.proof_height);
        builder.push_u64(self.observed_height);
        builder.push_str(self.status.as_str());
        builder.push_str(self.replay_decision.as_str());
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyRecord {
    pub record_id: String,
    pub note_commitment_root: Digest,
    pub view_tag_root: Digest,
    pub linkage_root: Digest,
    pub privacy_set_size: u64,
    pub observed_linkage_bps: u64,
    pub replay_decision: ReplayDecision,
}

impl PrivacyRecord {
    pub fn root_only(
        record_id: &str,
        note_commitment_root: Digest,
        view_tag_root: Digest,
        linkage_root: Digest,
        privacy_set_size: u64,
        observed_linkage_bps: u64,
        replay_decision: ReplayDecision,
    ) -> Result<Self> {
        require_non_empty("record_id", record_id)?;
        Ok(Self {
            record_id: record_id.to_string(),
            note_commitment_root,
            view_tag_root,
            linkage_root,
            privacy_set_size,
            observed_linkage_bps,
            replay_decision,
        })
    }

    pub fn devnet(
        record_id: &str,
        privacy_set_size: u64,
        replay_decision: ReplayDecision,
    ) -> Result<Self> {
        Self::root_only(
            record_id,
            leaf_root("note_commitment_root", &[record_id]),
            leaf_root("view_tag_root", &[record_id]),
            leaf_root("linkage_root", &[record_id]),
            privacy_set_size,
            0,
            replay_decision,
        )
    }

    pub fn blocker(&self, config: &Config) -> Option<Blocker> {
        if self.privacy_set_size < config.min_privacy_set_size {
            return Some(Blocker::new(
                GateDomain::PrivacyLinkage,
                Severity::Critical,
                &format!("privacy-set-{}", self.record_id),
                "privacy set size below release threshold",
                self.root(),
            ));
        }
        if self.observed_linkage_bps > config.max_linkage_bps {
            return Some(Blocker::new(
                GateDomain::PrivacyLinkage,
                Severity::Critical,
                &format!("privacy-linkage-{}", self.record_id),
                "observed linkage exceeds fail-closed threshold",
                self.root(),
            ));
        }
        if self.replay_decision.release_blocking() {
            return Some(Blocker::new(
                GateDomain::ReplayGovernance,
                Severity::Blocker,
                &format!("privacy-replay-{}", self.record_id),
                "wave 88 replay decision did not clear privacy linkage",
                self.root(),
            ));
        }
        None
    }

    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("privacy_root_only_record");
        builder.push_str(&self.record_id);
        builder.push_digest(&self.note_commitment_root);
        builder.push_digest(&self.view_tag_root);
        builder.push_digest(&self.linkage_root);
        builder.push_u64(self.privacy_set_size);
        builder.push_u64(self.observed_linkage_bps);
        builder.push_str(self.replay_decision.as_str());
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataRedactionRecord {
    pub record_id: String,
    pub source_artifact_root: Digest,
    pub redacted_artifact_root: Digest,
    pub redaction_manifest_root: Digest,
    pub leakage_score: u16,
    pub status: RedactionStatus,
    pub replay_decision: ReplayDecision,
}

impl MetadataRedactionRecord {
    pub fn new(
        record_id: &str,
        leakage_score: u16,
        status: RedactionStatus,
        replay_decision: ReplayDecision,
    ) -> Result<Self> {
        require_non_empty("record_id", record_id)?;
        Ok(Self {
            record_id: record_id.to_string(),
            source_artifact_root: leaf_root("source_artifact", &[record_id]),
            redacted_artifact_root: leaf_root("redacted_artifact", &[record_id]),
            redaction_manifest_root: leaf_root("redaction_manifest", &[record_id, status.as_str()]),
            leakage_score,
            status,
            replay_decision,
        })
    }

    pub fn blocker(&self, config: &Config) -> Option<Blocker> {
        if self.leakage_score > config.max_metadata_leakage_score {
            return Some(Blocker::new(
                GateDomain::MetadataRedaction,
                Severity::Critical,
                &format!("metadata-leakage-{}", self.record_id),
                "metadata leakage score exceeds threshold",
                self.root(),
            ));
        }
        if !self.status.acceptable() {
            return Some(Blocker::new(
                GateDomain::MetadataRedaction,
                Severity::Critical,
                &format!("metadata-status-{}", self.record_id),
                "metadata artifact is not root-only or clean",
                self.root(),
            ));
        }
        if self.replay_decision.release_blocking() {
            return Some(Blocker::new(
                GateDomain::ReplayGovernance,
                Severity::Blocker,
                &format!("metadata-replay-{}", self.record_id),
                "wave 88 replay decision did not clear redaction",
                self.root(),
            ));
        }
        None
    }

    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("metadata_redaction_record");
        builder.push_str(&self.record_id);
        builder.push_digest(&self.source_artifact_root);
        builder.push_digest(&self.redacted_artifact_root);
        builder.push_digest(&self.redaction_manifest_root);
        builder.push_u64(u64::from(self.leakage_score));
        builder.push_str(self.status.as_str());
        builder.push_str(self.replay_decision.as_str());
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NullifierSeparationRecord {
    pub record_id: String,
    pub domain_roots: BTreeMap<String, Digest>,
    pub collision_root: Digest,
    pub collisions: u64,
    pub replay_decision: ReplayDecision,
}

impl NullifierSeparationRecord {
    pub fn new(
        record_id: &str,
        domains: &[&str],
        collisions: u64,
        replay_decision: ReplayDecision,
    ) -> Result<Self> {
        require_non_empty("record_id", record_id)?;
        let mut domain_roots = BTreeMap::new();
        for domain in domains {
            require_non_empty("nullifier_domain", domain)?;
            domain_roots.insert(
                (*domain).to_string(),
                leaf_root("nullifier_domain", &[record_id, domain]),
            );
        }
        let collision_root =
            leaf_root("nullifier_collision", &[record_id, &collisions.to_string()]);
        Ok(Self {
            record_id: record_id.to_string(),
            domain_roots,
            collision_root,
            collisions,
            replay_decision,
        })
    }

    pub fn blocker(&self, config: &Config) -> Option<Blocker> {
        if self.domain_roots.len() < config.min_nullifier_domains {
            return Some(Blocker::new(
                GateDomain::NullifierSeparation,
                Severity::Critical,
                &format!("nullifier-domains-{}", self.record_id),
                "insufficient separated nullifier domains",
                self.root(),
            ));
        }
        if self.collisions != 0 {
            return Some(Blocker::new(
                GateDomain::NullifierSeparation,
                Severity::Critical,
                &format!("nullifier-collisions-{}", self.record_id),
                "nullifier collision evidence is non-zero",
                self.root(),
            ));
        }
        if self.replay_decision.release_blocking() {
            return Some(Blocker::new(
                GateDomain::ReplayGovernance,
                Severity::Blocker,
                &format!("nullifier-replay-{}", self.record_id),
                "wave 88 replay decision did not clear nullifier separation",
                self.root(),
            ));
        }
        None
    }

    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("nullifier_separation_record");
        builder.push_str(&self.record_id);
        for (domain, root) in &self.domain_roots {
            builder.push_str(domain);
            builder.push_digest(root);
        }
        builder.push_digest(&self.collision_root);
        builder.push_u64(self.collisions);
        builder.push_str(self.replay_decision.as_str());
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayDecisionRecord {
    pub decision_id: String,
    pub domain: GateDomain,
    pub wave: u64,
    pub decision: ReplayDecision,
    pub captain_root: Digest,
    pub evidence_root: Digest,
    pub note: String,
}

impl ReplayDecisionRecord {
    pub fn new(
        decision_id: &str,
        domain: GateDomain,
        wave: u64,
        decision: ReplayDecision,
        captain: &str,
        evidence_root: Digest,
        note: &str,
    ) -> Result<Self> {
        require_non_empty("decision_id", decision_id)?;
        require_non_empty("captain", captain)?;
        require_non_empty("note", note)?;
        Ok(Self {
            decision_id: decision_id.to_string(),
            domain,
            wave,
            decision,
            captain_root: leaf_root("release_captain", &[captain]),
            evidence_root,
            note: note.to_string(),
        })
    }

    pub fn blocker(&self) -> Option<Blocker> {
        if self.decision.release_blocking() {
            Some(Blocker::new(
                self.domain,
                Severity::Blocker,
                &format!("replay-decision-{}", self.decision_id),
                &self.note,
                self.root(),
            ))
        } else {
            None
        }
    }

    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("wave88_replay_decision_record");
        builder.push_str(&self.decision_id);
        builder.push_str(self.domain.as_str());
        builder.push_u64(self.wave);
        builder.push_str(self.decision.as_str());
        builder.push_digest(&self.captain_root);
        builder.push_digest(&self.evidence_root);
        builder.push_str(&self.note);
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blocker {
    pub blocker_id: String,
    pub domain: GateDomain,
    pub severity: Severity,
    pub reason: String,
    pub evidence_root: Digest,
    pub active: bool,
}

impl Blocker {
    pub fn new(
        domain: GateDomain,
        severity: Severity,
        blocker_id: &str,
        reason: &str,
        evidence_root: Digest,
    ) -> Self {
        Self {
            blocker_id: blocker_id.to_string(),
            domain,
            severity,
            reason: reason.to_string(),
            evidence_root,
            active: true,
        }
    }

    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("release_blocker");
        builder.push_str(&self.blocker_id);
        builder.push_str(self.domain.as_str());
        builder.push_str(self.severity.as_str());
        builder.push_str(&self.reason);
        builder.push_digest(&self.evidence_root);
        builder.push_bool(self.active);
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub captain_root: Digest,
    pub reason_root: Digest,
    pub blocker_root: Digest,
    pub status: ReleaseStatus,
    pub opened_height: u64,
    pub closed_height: Option<u64>,
}

impl ReleaseHold {
    pub fn new(
        hold_id: &str,
        captain: &str,
        reason: &str,
        blocker_root: Digest,
        opened_height: u64,
    ) -> Result<Self> {
        require_non_empty("hold_id", hold_id)?;
        require_non_empty("captain", captain)?;
        require_non_empty("reason", reason)?;
        Ok(Self {
            hold_id: hold_id.to_string(),
            captain_root: leaf_root("hold_captain", &[captain]),
            reason_root: leaf_root("hold_reason", &[reason]),
            blocker_root,
            status: ReleaseStatus::Held,
            opened_height,
            closed_height: None,
        })
    }

    pub fn close(&mut self, height: u64, status: ReleaseStatus) {
        self.closed_height = Some(height);
        self.status = status;
    }

    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("release_hold");
        builder.push_str(&self.hold_id);
        builder.push_digest(&self.captain_root);
        builder.push_digest(&self.reason_root);
        builder.push_digest(&self.blocker_root);
        builder.push_str(self.status.as_str());
        builder.push_u64(self.opened_height);
        match self.closed_height {
            Some(height) => builder.push_u64(height),
            None => builder.push_str("open"),
        }
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicArchiveRecord {
    pub release_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub replay_wave: u64,
    pub archive_wave: u64,
    pub release_status: ReleaseStatus,
    pub pq_epoch_root: Digest,
    pub reserve_root: Digest,
    pub privacy_root: Digest,
    pub metadata_root: Digest,
    pub nullifier_root: Digest,
    pub replay_root: Digest,
    pub blocker_root: Digest,
    pub state_root: Digest,
    pub public_notes: Vec<String>,
}

impl PublicArchiveRecord {
    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("public_archive_record");
        builder.push_str(&self.release_id);
        builder.push_str(&self.protocol_version);
        builder.push_u64(self.schema_version);
        builder.push_u64(self.replay_wave);
        builder.push_u64(self.archive_wave);
        builder.push_str(self.release_status.as_str());
        builder.push_digest(&self.pq_epoch_root);
        builder.push_digest(&self.reserve_root);
        builder.push_digest(&self.privacy_root);
        builder.push_digest(&self.metadata_root);
        builder.push_digest(&self.nullifier_root);
        builder.push_digest(&self.replay_root);
        builder.push_digest(&self.blocker_root);
        builder.push_digest(&self.state_root);
        for note in &self.public_notes {
            builder.push_str(note);
        }
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateReport {
    pub release_status: ReleaseStatus,
    pub blocker_count: usize,
    pub critical_count: usize,
    pub fail_closed: bool,
    pub go_allowed: bool,
    pub state_root: Digest,
}

impl GateReport {
    pub fn as_public_line(&self) -> String {
        format!(
            "status={} blockers={} critical={} fail_closed={} go_allowed={} root={}",
            self.release_status.as_str(),
            self.blocker_count,
            self.critical_count,
            self.fail_closed,
            self.go_allowed,
            self.state_root.to_hex()
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub config: Config,
    pub release_status: ReleaseStatus,
    pub pq_epochs: BTreeMap<String, PqEpochRecord>,
    pub reserves: BTreeMap<String, ReserveCoverageRecord>,
    pub privacy_records: BTreeMap<String, PrivacyRecord>,
    pub metadata_records: BTreeMap<String, MetadataRedactionRecord>,
    pub nullifier_records: BTreeMap<String, NullifierSeparationRecord>,
    pub replay_decisions: BTreeMap<String, ReplayDecisionRecord>,
    pub blockers: BTreeMap<String, Blocker>,
    pub holds: BTreeMap<String, ReleaseHold>,
    pub public_notes: Vec<String>,
    pub sealed: bool,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            release_status: ReleaseStatus::Draft,
            pq_epochs: BTreeMap::new(),
            reserves: BTreeMap::new(),
            privacy_records: BTreeMap::new(),
            metadata_records: BTreeMap::new(),
            nullifier_records: BTreeMap::new(),
            replay_decisions: BTreeMap::new(),
            blockers: BTreeMap::new(),
            holds: BTreeMap::new(),
            public_notes: Vec::new(),
            sealed: false,
        })
    }

    pub fn devnet() -> Self {
        let mut state = match Self::new(Config::devnet()) {
            Ok(value) => value,
            Err(_) => Self {
                config: Config::devnet(),
                release_status: ReleaseStatus::Draft,
                pq_epochs: BTreeMap::new(),
                reserves: BTreeMap::new(),
                privacy_records: BTreeMap::new(),
                metadata_records: BTreeMap::new(),
                nullifier_records: BTreeMap::new(),
                replay_decisions: BTreeMap::new(),
                blockers: BTreeMap::new(),
                holds: BTreeMap::new(),
                public_notes: Vec::new(),
                sealed: false,
            },
        };
        let _ = state.add_pq_epoch(
            PqEpochRecord::new(
                "wave88-pq-epoch-main",
                "ml-dsa-slh-dsa-hybrid",
                256,
                5,
                PqEpochStatus::Active,
                1_990_000,
                ReplayDecision::Go,
            )
            .fallback_record("wave88-pq-epoch-main"),
        );
        let _ = state.add_reserve(
            ReserveCoverageRecord::new(
                "wave88-xmr-reserve",
                "xmr",
                12_800,
                1_990_396,
                1_990_400,
                ReserveStatus::Covered,
                ReplayDecision::Go,
            )
            .fallback_record("wave88-xmr-reserve"),
        );
        let _ = state.add_privacy(
            PrivacyRecord::devnet("wave88-root-only-privacy", 65_536, ReplayDecision::Go)
                .fallback_record("wave88-root-only-privacy"),
        );
        let _ = state.add_metadata(
            MetadataRedactionRecord::new(
                "wave88-redaction-manifest",
                0,
                RedactionStatus::RootOnly,
                ReplayDecision::Go,
            )
            .fallback_record("wave88-redaction-manifest"),
        );
        let domains = [
            "exit_claim",
            "private_transfer",
            "reserve_proof",
            "challenge_replay",
        ];
        let _ = state.add_nullifier(
            NullifierSeparationRecord::new(
                "wave88-nullifier-separation",
                &domains,
                0,
                ReplayDecision::Go,
            )
            .fallback_record("wave88-nullifier-separation"),
        );
        let _ = state.add_replay_decision(ReplayDecisionRecord::new(
            "wave88-release-captain-final",
            GateDomain::ReplayGovernance,
            DEFAULT_REPLAY_WAVE,
            ReplayDecision::NoGo,
            "release-captain-devnet",
            leaf_root("wave88_no_go", &["pq-reserve-privacy"]),
            "release remains no-go until archive evidence is sealed and all live blockers stay closed",
        ).fallback_record("wave88-release-captain-final"));
        state.recompute_blockers();
        let _ = state.hold_release(
            "wave89-no-go-hold",
            "release-captain-devnet",
            "wave 89 preserves wave 88 no-go evidence for pq reserve privacy gate",
            1_990_401,
        );
        state
    }

    pub fn add_pq_epoch(&mut self, record: PqEpochRecord) -> Result<()> {
        self.ensure_mutable()?;
        insert_unique(&mut self.pq_epochs, record.epoch_id.clone(), record)?;
        self.recompute_blockers();
        Ok(())
    }

    pub fn add_reserve(&mut self, record: ReserveCoverageRecord) -> Result<()> {
        self.ensure_mutable()?;
        insert_unique(&mut self.reserves, record.reserve_id.clone(), record)?;
        self.recompute_blockers();
        Ok(())
    }

    pub fn add_privacy(&mut self, record: PrivacyRecord) -> Result<()> {
        self.ensure_mutable()?;
        insert_unique(&mut self.privacy_records, record.record_id.clone(), record)?;
        self.recompute_blockers();
        Ok(())
    }

    pub fn add_metadata(&mut self, record: MetadataRedactionRecord) -> Result<()> {
        self.ensure_mutable()?;
        insert_unique(&mut self.metadata_records, record.record_id.clone(), record)?;
        self.recompute_blockers();
        Ok(())
    }

    pub fn add_nullifier(&mut self, record: NullifierSeparationRecord) -> Result<()> {
        self.ensure_mutable()?;
        insert_unique(
            &mut self.nullifier_records,
            record.record_id.clone(),
            record,
        )?;
        self.recompute_blockers();
        Ok(())
    }

    pub fn add_replay_decision(&mut self, record: ReplayDecisionRecord) -> Result<()> {
        self.ensure_mutable()?;
        insert_unique(
            &mut self.replay_decisions,
            record.decision_id.clone(),
            record,
        )?;
        self.recompute_blockers();
        Ok(())
    }

    pub fn add_public_note(&mut self, note: &str) -> Result<()> {
        self.ensure_mutable()?;
        require_non_empty("note", note)?;
        if self.public_notes.len() >= self.config.max_public_notes {
            return Err(Error::InvalidThreshold("max_public_notes"));
        }
        self.public_notes.push(redact_note(note));
        Ok(())
    }

    pub fn hold_release(
        &mut self,
        hold_id: &str,
        captain: &str,
        reason: &str,
        height: u64,
    ) -> Result<()> {
        self.ensure_mutable()?;
        let blocker_root = self.blocker_root();
        let hold = ReleaseHold::new(hold_id, captain, reason, blocker_root, height)?;
        insert_unique(&mut self.holds, hold_id.to_string(), hold)?;
        self.release_status = ReleaseStatus::Held;
        Ok(())
    }

    pub fn force_no_go(&mut self, captain: &str, reason: &str, height: u64) -> Result<()> {
        self.ensure_mutable()?;
        require_non_empty("captain", captain)?;
        require_non_empty("reason", reason)?;
        let hold_id = format!(
            "no-go-{}-{}",
            self.config.archive_wave,
            self.holds.len() + 1
        );
        self.hold_release(&hold_id, captain, reason, height)?;
        self.release_status = ReleaseStatus::NoGo;
        Ok(())
    }

    pub fn evaluate_release(&mut self) -> GateReport {
        self.recompute_blockers();
        let active = self.active_blockers();
        let critical_count = active
            .iter()
            .filter(|b| b.severity == Severity::Critical)
            .count();
        let go_allowed = active.is_empty() && !self.config.fail_closed_gap(self);
        if go_allowed {
            if self.release_status != ReleaseStatus::Sealed {
                self.release_status = ReleaseStatus::Go;
            }
        } else if self.config.fail_closed {
            self.release_status = ReleaseStatus::NoGo;
        } else if self.release_status == ReleaseStatus::Draft {
            self.release_status = ReleaseStatus::Held;
        }
        GateReport {
            release_status: self.release_status,
            blocker_count: active.len(),
            critical_count,
            fail_closed: self.config.fail_closed,
            go_allowed,
            state_root: self.root(),
        }
    }

    pub fn seal_no_go_archive(
        &mut self,
        captain: &str,
        height: u64,
    ) -> Result<PublicArchiveRecord> {
        self.ensure_mutable()?;
        require_non_empty("captain", captain)?;
        let report = self.evaluate_release();
        if report.go_allowed && !self.config.allow_go_with_open_blockers {
            return Err(Error::ReleaseNotHeld);
        }
        for hold in self.holds.values_mut() {
            if hold.closed_height.is_none() {
                hold.close(height, ReleaseStatus::NoGo);
            }
        }
        self.add_public_note(&format!("sealed by {} at height {}", captain, height))?;
        self.release_status = ReleaseStatus::Sealed;
        self.sealed = true;
        Ok(self.public_record())
    }

    pub fn public_record(&self) -> PublicArchiveRecord {
        PublicArchiveRecord {
            release_id: self.config.release_id.clone(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            replay_wave: self.config.replay_wave,
            archive_wave: self.config.archive_wave,
            release_status: self.release_status,
            pq_epoch_root: self.pq_epoch_root(),
            reserve_root: self.reserve_root(),
            privacy_root: self.privacy_root(),
            metadata_root: self.metadata_root(),
            nullifier_root: self.nullifier_root(),
            replay_root: self.replay_root(),
            blocker_root: self.blocker_root(),
            state_root: self.root(),
            public_notes: self.public_notes.clone(),
        }
    }

    pub fn root(&self) -> Digest {
        let mut builder = DigestBuilder::new("wave89_archive_state");
        builder.push_digest(&self.config.fingerprint());
        builder.push_str(self.release_status.as_str());
        builder.push_digest(&self.pq_epoch_root());
        builder.push_digest(&self.reserve_root());
        builder.push_digest(&self.privacy_root());
        builder.push_digest(&self.metadata_root());
        builder.push_digest(&self.nullifier_root());
        builder.push_digest(&self.replay_root());
        builder.push_digest(&self.blocker_root());
        builder.push_digest(&self.hold_root());
        for note in &self.public_notes {
            builder.push_str(note);
        }
        builder.push_bool(self.sealed);
        builder.finish()
    }

    pub fn pq_epoch_root(&self) -> Digest {
        merkleish_root(
            "pq_epoch_root",
            self.pq_epochs.values().map(PqEpochRecord::root).collect(),
        )
    }

    pub fn reserve_root(&self) -> Digest {
        merkleish_root(
            "reserve_root",
            self.reserves
                .values()
                .map(ReserveCoverageRecord::root)
                .collect(),
        )
    }

    pub fn privacy_root(&self) -> Digest {
        merkleish_root(
            "privacy_root",
            self.privacy_records
                .values()
                .map(PrivacyRecord::root)
                .collect(),
        )
    }

    pub fn metadata_root(&self) -> Digest {
        merkleish_root(
            "metadata_root",
            self.metadata_records
                .values()
                .map(MetadataRedactionRecord::root)
                .collect(),
        )
    }

    pub fn nullifier_root(&self) -> Digest {
        merkleish_root(
            "nullifier_root",
            self.nullifier_records
                .values()
                .map(NullifierSeparationRecord::root)
                .collect(),
        )
    }

    pub fn replay_root(&self) -> Digest {
        merkleish_root(
            "replay_root",
            self.replay_decisions
                .values()
                .map(ReplayDecisionRecord::root)
                .collect(),
        )
    }

    pub fn blocker_root(&self) -> Digest {
        merkleish_root(
            "blocker_root",
            self.blockers.values().map(Blocker::root).collect(),
        )
    }

    pub fn hold_root(&self) -> Digest {
        merkleish_root(
            "hold_root",
            self.holds.values().map(ReleaseHold::root).collect(),
        )
    }

    pub fn active_blockers(&self) -> Vec<Blocker> {
        self.blockers
            .values()
            .filter(|blocker| blocker.active)
            .cloned()
            .collect()
    }

    pub fn blocker_domains(&self) -> BTreeSet<GateDomain> {
        self.active_blockers()
            .into_iter()
            .map(|blocker| blocker.domain)
            .collect()
    }

    pub fn recompute_blockers(&mut self) {
        self.blockers.clear();
        let config = self.config.clone();
        let mut gathered = Vec::new();
        for record in self.pq_epochs.values() {
            if let Some(blocker) = record.blocker(&config) {
                gathered.push(blocker);
            }
        }
        for record in self.reserves.values() {
            if let Some(blocker) = record.blocker(&config) {
                gathered.push(blocker);
            }
        }
        for record in self.privacy_records.values() {
            if let Some(blocker) = record.blocker(&config) {
                gathered.push(blocker);
            }
        }
        for record in self.metadata_records.values() {
            if let Some(blocker) = record.blocker(&config) {
                gathered.push(blocker);
            }
        }
        for record in self.nullifier_records.values() {
            if let Some(blocker) = record.blocker(&config) {
                gathered.push(blocker);
            }
        }
        for record in self.replay_decisions.values() {
            if let Some(blocker) = record.blocker() {
                gathered.push(blocker);
            }
        }
        self.add_missing_domain_blockers(&mut gathered);
        for blocker in gathered {
            self.blockers.insert(blocker.blocker_id.clone(), blocker);
        }
    }

    fn add_missing_domain_blockers(&self, gathered: &mut Vec<Blocker>) {
        if self.pq_epochs.is_empty() {
            gathered.push(missing_blocker(
                GateDomain::PqSignerEpoch,
                "missing-pq-epoch",
            ));
        }
        if self.reserves.is_empty() {
            gathered.push(missing_blocker(
                GateDomain::ReserveCoverage,
                "missing-reserve-coverage",
            ));
        }
        if self.privacy_records.is_empty() {
            gathered.push(missing_blocker(
                GateDomain::PrivacyLinkage,
                "missing-privacy-record",
            ));
        }
        if self.metadata_records.is_empty() {
            gathered.push(missing_blocker(
                GateDomain::MetadataRedaction,
                "missing-metadata-redaction",
            ));
        }
        if self.nullifier_records.is_empty() {
            gathered.push(missing_blocker(
                GateDomain::NullifierSeparation,
                "missing-nullifier-separation",
            ));
        }
        if self.replay_decisions.is_empty() {
            gathered.push(missing_blocker(
                GateDomain::ReplayGovernance,
                "missing-wave88-replay-decision",
            ));
        }
    }

    fn ensure_mutable(&self) -> Result<()> {
        if self.sealed || !self.release_status.mutable() {
            Err(Error::ArchiveSealed)
        } else {
            Ok(())
        }
    }
}

pub trait DevnetFallback<T> {
    fn fallback_record(self, id: &str) -> T;
}

impl DevnetFallback<PqEpochRecord> for Result<PqEpochRecord> {
    fn fallback_record(self, id: &str) -> PqEpochRecord {
        match self {
            Ok(record) => record,
            Err(_) => PqEpochRecord {
                epoch_id: id.to_string(),
                signer_set_root: leaf_root("fallback_pq_signer_set", &[id]),
                transcript_root: leaf_root("fallback_pq_transcript", &[id]),
                algorithm_family: "ml-dsa-slh-dsa-hybrid".to_string(),
                security_bits: 256,
                signer_quorum: 5,
                status: PqEpochStatus::Active,
                activation_height: 1,
                replay_decision: ReplayDecision::Go,
            },
        }
    }
}

impl DevnetFallback<ReserveCoverageRecord> for Result<ReserveCoverageRecord> {
    fn fallback_record(self, id: &str) -> ReserveCoverageRecord {
        match self {
            Ok(record) => record,
            Err(_) => ReserveCoverageRecord {
                reserve_id: id.to_string(),
                asset: "xmr".to_string(),
                custody_root: leaf_root("fallback_reserve_custody", &[id]),
                liability_root: leaf_root("fallback_reserve_liability", &[id]),
                coverage_bps: 12_800,
                proof_height: 1,
                observed_height: 1,
                status: ReserveStatus::Covered,
                replay_decision: ReplayDecision::Go,
            },
        }
    }
}

impl DevnetFallback<PrivacyRecord> for Result<PrivacyRecord> {
    fn fallback_record(self, id: &str) -> PrivacyRecord {
        match self {
            Ok(record) => record,
            Err(_) => PrivacyRecord {
                record_id: id.to_string(),
                note_commitment_root: leaf_root("fallback_note_commitment", &[id]),
                view_tag_root: leaf_root("fallback_view_tag", &[id]),
                linkage_root: leaf_root("fallback_linkage", &[id]),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                observed_linkage_bps: 0,
                replay_decision: ReplayDecision::Go,
            },
        }
    }
}

impl DevnetFallback<MetadataRedactionRecord> for Result<MetadataRedactionRecord> {
    fn fallback_record(self, id: &str) -> MetadataRedactionRecord {
        match self {
            Ok(record) => record,
            Err(_) => MetadataRedactionRecord {
                record_id: id.to_string(),
                source_artifact_root: leaf_root("fallback_source", &[id]),
                redacted_artifact_root: leaf_root("fallback_redacted", &[id]),
                redaction_manifest_root: leaf_root("fallback_manifest", &[id]),
                leakage_score: 0,
                status: RedactionStatus::RootOnly,
                replay_decision: ReplayDecision::Go,
            },
        }
    }
}

impl DevnetFallback<NullifierSeparationRecord> for Result<NullifierSeparationRecord> {
    fn fallback_record(self, id: &str) -> NullifierSeparationRecord {
        match self {
            Ok(record) => record,
            Err(_) => {
                let mut domain_roots = BTreeMap::new();
                domain_roots.insert(
                    "exit_claim".to_string(),
                    leaf_root("fallback_nullifier", &[id, "exit_claim"]),
                );
                domain_roots.insert(
                    "private_transfer".to_string(),
                    leaf_root("fallback_nullifier", &[id, "private_transfer"]),
                );
                domain_roots.insert(
                    "reserve_proof".to_string(),
                    leaf_root("fallback_nullifier", &[id, "reserve_proof"]),
                );
                domain_roots.insert(
                    "challenge_replay".to_string(),
                    leaf_root("fallback_nullifier", &[id, "challenge_replay"]),
                );
                NullifierSeparationRecord {
                    record_id: id.to_string(),
                    domain_roots,
                    collision_root: leaf_root("fallback_collision", &[id]),
                    collisions: 0,
                    replay_decision: ReplayDecision::Go,
                }
            }
        }
    }
}

impl DevnetFallback<ReplayDecisionRecord> for Result<ReplayDecisionRecord> {
    fn fallback_record(self, id: &str) -> ReplayDecisionRecord {
        match self {
            Ok(record) => record,
            Err(_) => ReplayDecisionRecord {
                decision_id: id.to_string(),
                domain: GateDomain::ReplayGovernance,
                wave: DEFAULT_REPLAY_WAVE,
                decision: ReplayDecision::NoGo,
                captain_root: leaf_root("fallback_captain", &[id]),
                evidence_root: leaf_root("fallback_evidence", &[id]),
                note: "fallback no-go replay decision".to_string(),
            },
        }
    }
}

impl Config {
    fn fail_closed_gap(&self, state: &State) -> bool {
        if !self.fail_closed {
            return false;
        }
        state.pq_epochs.is_empty()
            || state.reserves.is_empty()
            || state.privacy_records.is_empty()
            || state.metadata_records.is_empty()
            || state.nullifier_records.is_empty()
            || state.replay_decisions.is_empty()
    }
}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn public_record(state: &State) -> PublicArchiveRecord {
    state.public_record()
}

pub fn state_root(state: &State) -> Digest {
    state.root()
}

pub fn evaluate(state: &mut State) -> GateReport {
    state.evaluate_release()
}

pub fn root_hex(state: &State) -> String {
    state.root().to_hex()
}

pub fn public_record_root(state: &State) -> Digest {
    state.public_record().root()
}

fn insert_unique<T>(map: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    if map.contains_key(&key) {
        return Err(Error::DuplicateRecord(key));
    }
    map.insert(key, value);
    Ok(())
}

fn require_non_empty(field: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(Error::EmptyField(field))
    } else {
        Ok(())
    }
}

fn missing_blocker(domain: GateDomain, id: &str) -> Blocker {
    Blocker::new(
        domain,
        Severity::Critical,
        id,
        "required evidence record is absent; release fails closed",
        leaf_root("missing_evidence", &[domain.as_str(), id]),
    )
}

fn redact_note(note: &str) -> String {
    let mut redacted = String::new();
    let mut previous_space = false;
    for ch in note.chars() {
        let safe = if ch.is_ascii_alphanumeric()
            || ch == '-'
            || ch == '_'
            || ch == ':'
            || ch == '.'
            || ch == ' '
        {
            ch
        } else {
            ' '
        };
        if safe == ' ' {
            if !previous_space {
                redacted.push(' ');
            }
            previous_space = true;
        } else {
            redacted.push(safe);
            previous_space = false;
        }
    }
    redacted.trim().to_string()
}

fn leaf_root(domain: &str, values: &[&str]) -> Digest {
    let mut builder = DigestBuilder::new(domain);
    for value in values {
        builder.push_str(value);
    }
    builder.finish()
}

fn merkleish_root(domain: &str, mut leaves: Vec<Digest>) -> Digest {
    if leaves.is_empty() {
        return Digest::zero(domain);
    }
    leaves.sort_by(|left, right| left.tagged().cmp(&right.tagged()));
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut index = 0;
        while index < level.len() {
            let left = &level[index];
            let right = if index + 1 < level.len() {
                &level[index + 1]
            } else {
                &level[index]
            };
            let mut builder = DigestBuilder::new(domain);
            builder.push_digest(left);
            builder.push_digest(right);
            next.push(builder.finish());
            index += 2;
        }
        level = next;
    }
    match level.into_iter().next() {
        Some(root) => root,
        None => Digest::zero(domain),
    }
}

fn mix64(value: u64, salt: u64) -> u64 {
    let mut x = value ^ salt.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}
